const std = @import("std");
const contact_book = @import("../contact_book.zig");
const enr = @import("../enr.zig");
const kbucket = @import("../kbucket.zig");
const types = @import("../types.zig");

const Allocator = std.mem.Allocator;

pub const KnownNode = struct {
    node_id: types.NodeId,
    pubkey: [33]u8,
    addr: types.Address,
    runtime_contact_trusted: bool,
};

pub const ConnectionTransition = union(enum) {
    none,
    connected: types.Address,
    disconnected: types.Address,
};

pub const ConnectionEvent = struct {
    node_id: types.NodeId,
    transition: ConnectionTransition,
};

pub const PeerBook = struct {
    alloc: Allocator,
    local_node_id: types.NodeId,
    routing: kbucket.RoutingTable,
    contacts: contact_book.ContactBook,
    allow_ip4: bool,
    allow_ip6: bool,

    pub fn init(alloc: Allocator, local_node_id: types.NodeId, contact_capacity: usize, allow_ip4: bool, allow_ip6: bool) !PeerBook {
        var routing = try kbucket.RoutingTable.init(alloc, local_node_id);
        errdefer routing.deinit(alloc);
        const contacts = try contact_book.ContactBook.init(alloc, local_node_id, contact_capacity);
        return .{
            .alloc = alloc,
            .local_node_id = local_node_id,
            .routing = routing,
            .contacts = contacts,
            .allow_ip4 = allow_ip4,
            .allow_ip6 = allow_ip6,
        };
    }

    pub fn deinit(self: *PeerBook) void {
        self.contacts.deinit();
        self.routing.deinit(self.alloc);
    }

    pub fn known(self: *const PeerBook, node_id: *const types.NodeId) ?KnownNode {
        if (self.routing.getEntryWithPending(node_id)) |entry| return .{
            .node_id = entry.node_id,
            .pubkey = entry.pubkey,
            .addr = entry.addr,
            .runtime_contact_trusted = entry.runtime_contact_trusted,
        };
        if (self.contacts.get(node_id.*)) |contact| return .{
            .node_id = node_id.*,
            .pubkey = contact.pubkey,
            .addr = contact.addr,
            .runtime_contact_trusted = contact.explicitly_trusted,
        };
        return null;
    }

    pub fn findEnr(self: *const PeerBook, node_id: *const types.NodeId) ?[]const u8 {
        const entry = self.routing.getEntryWithPending(node_id) orelse return null;
        return entry.enrBytes();
    }

    /// Canonical metadata lookup without re-decoding and re-verifying an ENR
    /// already authenticated at ingestion. Routed state wins; when no routed
    /// entry exists, the bucket's single pending replacement is authoritative.
    pub fn knownEnrSeq(self: *const PeerBook, node_id: *const types.NodeId) ?u64 {
        const entry = self.routing.getEntryWithPending(node_id) orelse return null;
        return entry.enr_seq;
    }

    pub fn rememberContact(self: *PeerBook, node_id: types.NodeId, pubkey: ?*const [33]u8, address: types.Address, runtime_contact_trusted: bool) void {
        self.contacts.remember(node_id, pubkey, address, runtime_contact_trusted);
    }

    pub fn addTrusted(self: *PeerBook, node_id: types.NodeId, pubkey: ?*const [33]u8, address: types.Address, raw: ?[]const u8, now_ns: i64) bool {
        if (std.mem.eql(u8, &node_id, &self.local_node_id)) return false;
        if (raw) |bytes| {
            const parsed = enr.decode(bytes) catch return false;
            const advertised = self.addressForEnr(&parsed) orelse return false;
            if (!advertised.eql(&address)) return false;
            var entry = self.entryFromEnr(bytes, advertised, .disconnected, now_ns) orelse return false;
            if (!std.mem.eql(u8, &entry.node_id, &node_id)) return false;
            if (pubkey) |key| if (!std.mem.eql(u8, &entry.pubkey, key)) return false;
            entry.runtime_contact_trusted = true;
            entry.advertised_endpoint_trusted = true;
            entry.raw_enr_relay_eligible = true;
            _ = self.insert(entry);
            return self.trustedRepresentationRetained(node_id, &entry.pubkey, address);
        }
        self.rememberContact(node_id, pubkey, address, true);
        return self.contacts.get(node_id) != null;
    }

    pub fn learnEnr(self: *PeerBook, bytes: []const u8, now_ns: i64) ?types.NodeId {
        const parsed = enr.decode(bytes) catch return null;
        const address = self.addressForEnr(&parsed) orelse return null;
        const entry = self.entryFromEnr(bytes, address, .disconnected, now_ns) orelse return null;
        const node_id = entry.node_id;
        _ = self.insert(entry);
        return if (self.routing.getEntryWithPending(&node_id) != null or self.contacts.get(node_id) != null) node_id else null;
    }

    pub fn addressForEnr(self: *const PeerBook, parsed: *const enr.Enr) ?types.Address {
        const ip4 = parsed.udpAddress4();
        const ip6 = parsed.udpAddress6();
        if (self.allow_ip4 and !self.allow_ip6) return ip4;
        if (self.allow_ip6 and !self.allow_ip4) return ip6;
        if (self.allow_ip4 and self.allow_ip6) return ip4 orelse ip6;
        return null;
    }

    pub fn acceptHandshake(self: *PeerBook, node_id: types.NodeId, pubkey: *const [33]u8, address: types.Address, bytes: ?[]const u8, now_ns: i64) ResponsiveResult {
        if (bytes) |raw| {
            if (self.entryFromEnr(raw, address, .connected, now_ns)) |entry| {
                if (!std.mem.eql(u8, &entry.node_id, &node_id) or !std.mem.eql(u8, &entry.pubkey, pubkey))
                    return .{ .transition = .none, .eviction_candidate = null };
                const was_connected = if (self.routing.getEntry(&node_id)) |existing| existing.status == .connected else false;
                const insertion = self.insert(entry);
                const responsive = self.markResponsive(node_id, address, now_ns, null);
                if (!was_connected) if (self.routing.getEntry(&node_id)) |current| {
                    if (current.status == .connected) return .{
                        .transition = .{ .connected = address },
                        .eviction_candidate = insertion.pending_eviction orelse responsive.eviction_candidate,
                    };
                };
                return .{
                    .transition = .none,
                    .eviction_candidate = insertion.pending_eviction orelse responsive.eviction_candidate,
                };
            }
        }
        self.rememberContact(node_id, pubkey, address, false);
        return self.markResponsive(node_id, address, now_ns, null);
    }

    pub const ResponsiveResult = struct {
        transition: ConnectionTransition,
        eviction_candidate: ?kbucket.Entry,
    };

    pub fn markResponsive(self: *PeerBook, node_id: types.NodeId, address: types.Address, now_ns: i64, completed_key: ?types.RequestKey) ResponsiveResult {
        var entry = (self.routing.getEntryWithPending(&node_id) orelse return .{ .transition = .none, .eviction_candidate = null }).*;
        const was_connected = if (self.routing.getEntry(&node_id)) |current| current.status == .connected else false;
        const endpoint_changed = !entry.addr.eql(&address);
        if (endpoint_changed and entry.runtime_contact_trusted) {
            const new_endpoint_trusted = self.trustedContactRetained(node_id, &entry.pubkey, address);
            if (!new_endpoint_trusted) {
                self.rememberContact(node_id, &entry.pubkey, entry.addr, true);
                if (!self.trustedContactRetained(node_id, &entry.pubkey, entry.addr))
                    return .{ .transition = .none, .eviction_candidate = null };
            }
            entry.runtime_contact_trusted = new_endpoint_trusted;
        }
        entry.addr = address;
        entry.last_seen = now_ns;
        entry.status = .connected;
        if (endpoint_changed) entry.health_request = null;
        if (completed_key) |key| if (entry.health_request) |health_key| {
            if (types.RequestKeyContext.eql(.{}, health_key, key)) entry.health_request = null;
        };
        const parsed = enr.decode(entry.enrBytes()) catch return .{ .transition = .none, .eviction_candidate = null };
        const advertised = switch (address) {
            .ip4 => parsed.udpAddress4(),
            .ip6 => parsed.udpAddress6(),
        };
        const endpoint_proves_raw = if (advertised) |value| value.eql(&address) else false;
        entry.raw_enr_relay_eligible = entry.advertised_endpoint_trusted or
            entry.raw_enr_relay_eligible or endpoint_proves_raw;
        const result = self.routing.insertDetailed(entry);
        self.reconcileContact(entry);
        return .{
            .transition = if (was_connected or self.routing.getEntry(&node_id) == null) .none else .{ .connected = address },
            .eviction_candidate = result.pending_eviction,
        };
    }

    pub const HealthReservationPolicy = enum {
        connected_only,
        /// A genuine full-bucket eviction candidate is normally the oldest
        /// disconnected entry; its liveness probe must still be reservable.
        allow_eviction_candidate,
    };

    /// Pre-send reservation of exact health/eviction probe ownership. Take it
    /// before the datagram can become visible and roll it back with
    /// `cancelHealthRequest` only when the send path fails before commit.
    pub fn armHealthRequest(self: *PeerBook, key: types.RequestKey, policy: HealthReservationPolicy) bool {
        const entry = self.routing.getEntryMutWithPending(&key.endpoint.node_id) orelse return false;
        if (!entry.addr.eql(&key.endpoint.addr)) return false;
        switch (policy) {
            .connected_only => if (entry.status != .connected) return false,
            .allow_eviction_candidate => {},
        }
        if (entry.health_request != null) return false;
        entry.health_request = key;
        return true;
    }

    pub fn cancelHealthRequest(self: *PeerBook, key: types.RequestKey) bool {
        const entry = self.routing.getEntryMutWithPending(&key.endpoint.node_id) orelse return false;
        const health_key = entry.health_request orelse return false;
        if (!types.RequestKeyContext.eql(.{}, health_key, key)) return false;
        entry.health_request = null;
        return true;
    }

    /// The exact eviction candidate proved liveness: keep the incumbent and
    /// drop the bucket's pending replacement.
    pub fn resolveEvictionSuccess(self: *PeerBook, node_id: *const types.NodeId) void {
        const dist = kbucket.logDistance(&self.routing.local_id, node_id) orelse return;
        self.routing.buckets[dist].resolvePendingAgainst(node_id);
    }

    /// The exact eviction probe timed out. Remove the unresponsive candidate
    /// and promote the bucket's pending replacement; returns the promoted
    /// peer's connection event when one entered the table.
    pub fn completeEvictionTimeout(self: *PeerBook, key: types.RequestKey) ?ConnectionEvent {
        const entry = self.routing.getEntryMutWithPending(&key.endpoint.node_id) orelse return null;
        const health_key = entry.health_request orelse return null;
        if (!types.RequestKeyContext.eql(.{}, health_key, key)) return null;
        if (!entry.addr.eql(&key.endpoint.addr)) return null;
        entry.health_request = null;
        const dist = kbucket.logDistance(&self.routing.local_id, &key.endpoint.node_id) orelse return null;
        const bucket = &self.routing.buckets[dist];
        if (entry.status == .connected) {
            // Other authenticated traffic proved liveness while the exact
            // probe was in flight; keep the incumbent, drop the replacement.
            bucket.resolvePendingAgainst(&key.endpoint.node_id);
            return null;
        }
        const pending_before = bucket.pending;
        _ = bucket.remove(&key.endpoint.node_id);
        const pending = (pending_before orelse return null).entry;
        if (bucket.pending != null or pending.status != .connected) return null;
        if (bucket.get(&pending.node_id) == null) return null;
        self.forgetRepresentedContact(&pending.node_id);
        return .{ .node_id = pending.node_id, .transition = .{ .connected = pending.addr } };
    }

    pub fn markDisconnected(self: *PeerBook, key: types.RequestKey, now_ns: i64) ConnectionTransition {
        var entry = (self.routing.getEntryWithPending(&key.endpoint.node_id) orelse return .none).*;
        const health_key = entry.health_request orelse return .none;
        if (!types.RequestKeyContext.eql(.{}, health_key, key)) return .none;
        if (entry.status != .connected) return .none;
        if (!entry.addr.eql(&key.endpoint.addr)) return .none;
        const was_routed = self.routing.getEntry(&key.endpoint.node_id) != null;
        entry.status = .disconnected;
        entry.last_seen = now_ns;
        entry.health_request = null;
        _ = self.routing.insertDetailed(entry);
        return if (was_routed) .{ .disconnected = entry.addr } else .none;
    }

    pub fn connectedCount(self: *const PeerBook) usize {
        var count: usize = 0;
        for (self.routing.buckets) |*bucket| for (bucket.entries[0..bucket.count]) |entry| {
            if (entry.status == .connected) count += 1;
        };
        return count;
    }

    pub fn prune(self: *PeerBook, now_ns: i64, timeout_ms: u64, transitions: []ConnectionEvent) usize {
        var count: usize = 0;
        for (self.routing.buckets) |*bucket| {
            const pending = (bucket.pending orelse continue).entry;
            if (!bucket.applyPendingIfExpired(now_ns, timeout_ms)) continue;
            self.forgetRepresentedContact(&pending.node_id);
            if (pending.status != .connected) continue;
            std.debug.assert(count < transitions.len);
            transitions[count] = .{
                .node_id = pending.node_id,
                .transition = .{ .connected = pending.addr },
            };
            count += 1;
        }
        return count;
    }

    fn entryFromEnr(self: *PeerBook, bytes: []const u8, address: types.Address, status: kbucket.EntryStatus, now_ns: i64) ?kbucket.Entry {
        const parsed = enr.decode(bytes) catch return null;
        const node_id = (parsed.nodeId() catch return null) orelse return null;
        if (std.mem.eql(u8, &node_id, &self.local_node_id)) return null;
        return .{
            .node_id = node_id,
            .pubkey = parsed.pubkey orelse return null,
            .addr = address,
            .enr = enr.RawEnr.init(bytes) catch return null,
            .enr_seq = parsed.seq,
            .last_seen = now_ns,
            .status = status,
        };
    }

    fn insert(self: *PeerBook, incoming: kbucket.Entry) kbucket.InsertOutcome {
        var entry = incoming;
        if (self.contacts.get(entry.node_id)) |contact| {
            if (contact.explicitly_trusted and contact.addr.eql(&entry.addr) and std.mem.eql(u8, &contact.pubkey, &entry.pubkey)) {
                entry.runtime_contact_trusted = true;
                entry.advertised_endpoint_trusted = true;
                entry.raw_enr_relay_eligible = true;
            }
        }
        if (self.routing.getEntryWithPending(&entry.node_id)) |existing| {
            if (existing.enr_seq >= entry.enr_seq) {
                var retained = existing.*;
                if (entry.runtime_contact_trusted and std.mem.eql(u8, &retained.pubkey, &entry.pubkey)) {
                    if (retained.addr.eql(&entry.addr)) retained.runtime_contact_trusted = true;
                    if (entryAdvertisesAddress(&retained, entry.addr)) {
                        retained.advertised_endpoint_trusted = true;
                        retained.raw_enr_relay_eligible = true;
                    }
                    const outcome = self.routing.insertDetailed(retained);
                    self.reconcileContact(retained);
                    return outcome;
                }
                self.reconcileContact(retained);
                return .{ .inserted = self.routing.getEntry(&entry.node_id) != null };
            }
            const runtime_endpoint_unchanged = existing.addr.eql(&entry.addr);
            const advertised_endpoint_unchanged = entryAdvertisesAddress(existing, entry.addr);
            if (existing.runtime_contact_trusted and !runtime_endpoint_unchanged and !entry.runtime_contact_trusted) {
                self.rememberContact(existing.node_id, &existing.pubkey, existing.addr, true);
                if (!self.trustedContactRetained(existing.node_id, &existing.pubkey, existing.addr)) {
                    self.reconcileContact(existing.*);
                    return .{ .inserted = self.routing.getEntry(&entry.node_id) != null };
                }
            }
            entry.runtime_contact_trusted = entry.runtime_contact_trusted or
                (existing.runtime_contact_trusted and runtime_endpoint_unchanged);
            entry.advertised_endpoint_trusted = entry.advertised_endpoint_trusted or
                (existing.advertised_endpoint_trusted and advertised_endpoint_unchanged);
            entry.raw_enr_relay_eligible = entry.advertised_endpoint_trusted or
                entry.raw_enr_relay_eligible or
                (existing.raw_enr_relay_eligible and advertised_endpoint_unchanged);
            entry.next_ping_at_ns = existing.next_ping_at_ns;
            if (existing.status == .connected and entry.status == .disconnected and !entry.runtime_contact_trusted) {
                // Learning a new advertised endpoint is not liveness proof.
                // Keep using the last authenticated address until traffic from
                // the replacement endpoint proves it and promotes relay state.
                // An exact locally configured contact is an independent trust
                // decision for the replacement endpoint and may move directly.
                entry.status = .connected;
                entry.addr = existing.addr;
                entry.last_seen = existing.last_seen;
                if (!runtime_endpoint_unchanged) {
                    entry.runtime_contact_trusted = existing.runtime_contact_trusted;
                }
            }
            if (existing.addr.eql(&entry.addr)) entry.health_request = existing.health_request;
        }
        const outcome = self.routing.insertDetailed(entry);
        self.reconcileContact(entry);
        return outcome;
    }

    fn reconcileContact(self: *PeerBook, entry: kbucket.Entry) void {
        if (self.routing.getEntry(&entry.node_id) != null) {
            self.forgetRepresentedContact(&entry.node_id);
            return;
        }
        self.rememberContact(entry.node_id, &entry.pubkey, entry.addr, entry.runtime_contact_trusted);
    }

    fn forgetRepresentedContact(self: *PeerBook, node_id: *const types.NodeId) void {
        const routed = self.routing.getEntry(node_id) orelse return;
        const contact = self.contacts.get(node_id.*) orelse return;
        if (!contact.addr.eql(&routed.addr) or !std.mem.eql(u8, &contact.pubkey, &routed.pubkey)) return;
        if (contact.explicitly_trusted and !entryAdvertisesAddress(routed, contact.addr)) return;
        if (contact.explicitly_trusted and !routed.runtime_contact_trusted) return;
        self.contacts.forget(node_id.*);
    }

    fn entryAdvertisesAddress(entry: *const kbucket.Entry, address: types.Address) bool {
        const parsed = enr.decode(entry.enrBytes()) catch return false;
        const advertised = switch (address) {
            .ip4 => parsed.udpAddress4(),
            .ip6 => parsed.udpAddress6(),
        };
        return if (advertised) |value| value.eql(&address) else false;
    }

    fn trustedRepresentationRetained(self: *const PeerBook, node_id: types.NodeId, pubkey: *const [33]u8, address: types.Address) bool {
        if (self.routing.getEntry(&node_id)) |entry| {
            if (std.mem.eql(u8, &entry.pubkey, pubkey)) {
                if (entry.runtime_contact_trusted and entry.addr.eql(&address)) return true;
                if (entry.advertised_endpoint_trusted and entryAdvertisesAddress(entry, address)) return true;
            }
        }
        return self.trustedContactRetained(node_id, pubkey, address);
    }

    fn trustedContactRetained(self: *const PeerBook, node_id: types.NodeId, pubkey: *const [33]u8, address: types.Address) bool {
        const contact = self.contacts.get(node_id) orelse return false;
        return contact.explicitly_trusted and contact.addr.eql(&address) and std.mem.eql(u8, &contact.pubkey, pubkey);
    }
};
