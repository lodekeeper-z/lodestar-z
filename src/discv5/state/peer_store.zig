//! Canonical bounded peer identity, contact, ENR, probe, and routing storage.
//! The NodeId map key is an index key only: all peer facts live in PeerRecord.
const std = @import("std");
const enr = @import("../enr.zig");
const types = @import("../types.zig");

pub const PEER_CAPACITY: usize = 6_352;
pub const MAP_CAPACITY: usize = 8_192;
// Exact retention promise: 4096 active routes plus 256 physical pending
// candidates. The 2000 fallback-only peer slots retain no RawEnr.
pub const ENR_CAPACITY: usize = 4_352;
pub const PROBE_CAPACITY: usize = 4_352;
pub const ROUTE_BUCKETS: usize = 256;
pub const K: usize = 16;
pub const BUCKET_PENDING_TIMEOUT_MS: u64 = 60_000;
pub const NONE: u32 = std.math.maxInt(u32);

pub const PeerRef = extern struct {
    index: u32,
    generation: u32,
};

pub const CompactEndpoint = extern struct {
    bytes: [16]u8,
    port: u16,
    family: u8,
    flags: u8,

    pub fn init(value: types.Address) CompactEndpoint {
        return switch (value) {
            .ip4 => |ip4| .{
                .bytes = ip4.bytes ++ ([_]u8{0} ** 12),
                .port = ip4.port,
                .family = 4,
                .flags = 1,
            },
            .ip6 => |ip6| .{ .bytes = ip6.bytes, .port = ip6.port, .family = 6, .flags = 1 },
        };
    }

    pub fn address(self: CompactEndpoint) types.Address {
        return if (self.family == 4)
            .{ .ip4 = .{ .bytes = self.bytes[0..4].*, .port = self.port } }
        else
            .{ .ip6 = .{ .bytes = self.bytes, .port = self.port } };
    }
};

pub const EndpointEvidence = extern struct {
    ip6: CompactEndpoint,
    ip4_bytes: [4]u8,
    ip4_port: u16,
    ip4_flags: u8,
    reserved: u8 = 0,
};

pub const EndpointEvidenceView = struct {
    ip4: CompactEndpoint,
    ip6: CompactEndpoint,
};

const FLAG_OCCUPIED: u32 = 1 << 0;
const FLAG_TRUSTED: u32 = 1 << 1;
const FLAG_CONNECTED: u32 = 1 << 2;
const FLAG_RELAYABLE: u32 = 1 << 3;
const ACTIVE_PIN_SHIFT: u5 = 8;
const PENDING_PIN_SHIFT: u5 = 16;
const PIN_MASK: u32 = 0xff;

pub const PeerRecord = extern struct {
    enr_seq: u64,
    last_seen: i64,
    node_id: types.NodeId,
    enr_index: u32,
    runtime: CompactEndpoint,
    pubkey: [33]u8,
    probe_handle: u32,
    flags: u32,

    pub fn occupied(self: *const PeerRecord) bool {
        return self.flags & FLAG_OCCUPIED != 0;
    }

    pub fn address(self: *const PeerRecord) types.Address {
        return self.runtime.address();
    }

    pub fn activePins(self: *const PeerRecord) u8 {
        return @truncate(self.flags >> ACTIVE_PIN_SHIFT);
    }

    pub fn pendingPins(self: *const PeerRecord) u8 {
        return @truncate(self.flags >> PENDING_PIN_SHIFT);
    }
};

pub const EnrSlot = extern struct {
    generation: u32,
    bytes: [300]u8,
    len: u16,
    present: u8,
    reserved: u8 = 0,
};

pub const CompactRequest = extern struct {
    peer: PeerRef,
    endpoint: CompactEndpoint,
    req_id: [8]u8,
    req_len: u8,
    reserved: [3]u8 = .{0} ** 3,
};

pub const CompactEvictionProbe = extern struct {
    request: CompactRequest,
    incumbent: PeerRef,
    ticket_generation: u64,
};

pub const ProbeState = union(enum(u8)) {
    none,
    health: CompactRequest,
    eviction: CompactEvictionProbe,
};

pub const RouteEntry = extern struct {
    peer: PeerRef,
    routing_recency: i64,
};

pub const PendingRoute = extern struct {
    newcomer: PeerRef,
    incumbent: PeerRef,
    inserted_at: i64,
    ticket_generation: u64,
    probe_handle: u32,
    flags: u32,
};

pub const ProbeRef = extern struct {
    index: u32,
    generation: u32,
};

pub const EvictionTicket = struct {
    incumbent: PeerRef,
    candidate: PeerRef,
    generation: u64,
    probe: ProbeRef,
};

pub const RouteAdmission = struct {
    inserted: bool,
    eviction: ?EvictionTicket = null,
};

pub const CompactBucket = extern struct {
    entries: [K]RouteEntry,
    pending: PendingRoute,
    count: u8,
    first_connected: u8,
    has_pending: u8,
    reserved: u8,
    next_generation: u64,
};

pub const CompactRouting = extern struct {
    local_id: types.NodeId,
    buckets: [ROUTE_BUCKETS]CompactBucket,
};

const PeerMap = extern struct {
    keys: [MAP_CAPACITY]types.NodeId,
    refs: [MAP_CAPACITY]PeerRef,
    controls: [MAP_CAPACITY]u8,
    count: u32,
    tombstones: u32,
};

const Control = extern struct {
    free_slot_head: u32,
    free_slot_count: u32,
    enr_free_head: u32,
    enr_free_count: u32,
    probe_free_head: u32,
    probe_free_count: u32,
    live_peers: u32,
    live_enrs: u32,
    live_probes: u32,
    reserved: u32,
};

const Backing = struct {
    map: PeerMap,
    records: [PEER_CAPACITY]PeerRecord,
    next_ping_at: [PEER_CAPACITY]i64,
    evidence: [PEER_CAPACITY]EndpointEvidence,
    slot_generations: [PEER_CAPACITY]u32,
    free_slots: [PEER_CAPACITY]u32,
    enrs: [ENR_CAPACITY]EnrSlot,
    enr_free: [ENR_CAPACITY]u32,
    probes: [PROBE_CAPACITY]ProbeState,
    probe_generations: [PROBE_CAPACITY]u32,
    probe_free: [PROBE_CAPACITY]u32,
    routing: CompactRouting,
    control: Control,
};

pub const MemoryAccounting = struct {
    map: usize = @sizeOf(PeerMap),
    records: usize = @sizeOf(PeerRecord) * PEER_CAPACITY,
    schedules: usize = @sizeOf(i64) * PEER_CAPACITY,
    evidence: usize = @sizeOf(EndpointEvidence) * PEER_CAPACITY,
    slot_generations: usize = @sizeOf(u32) * PEER_CAPACITY,
    slot_freelist: usize = @sizeOf(u32) * PEER_CAPACITY,
    enr_slots: usize = @sizeOf(EnrSlot) * ENR_CAPACITY,
    enr_freelist: usize = @sizeOf(u32) * ENR_CAPACITY,
    probes: usize = @sizeOf(ProbeState) * PROBE_CAPACITY,
    probe_generations: usize = @sizeOf(u32) * PROBE_CAPACITY,
    probe_freelist: usize = @sizeOf(u32) * PROBE_CAPACITY,
    routing: usize = @sizeOf(CompactRouting),
    control: usize = @sizeOf(Control),
    total: usize = @sizeOf(Backing),
};

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

pub const ResponsiveResult = struct {
    transition: ConnectionTransition,
    eviction_candidate: ?EvictionProbe,
};

pub const EvictionProbe = struct {
    endpoint: types.Endpoint,
    pubkey: [33]u8,
    ticket: EvictionTicket,
};

pub const HealthReservationPolicy = union(enum) {
    connected_only,
    allow_eviction_candidate: EvictionTicket,
};

pub const ProbeSnapshot = struct {
    endpoint: types.Endpoint,
    pubkey: [33]u8,
};

pub const ContactMetricsSnapshot = struct {
    count: usize,
    capacity: usize,
    inserted_total: u64 = 0,
    updated_total: u64 = 0,
    replaced_total: u64 = 0,
    capacity_rejected_total: u64 = 0,
    policy_rejected_total: u64 = 0,
    removed_total: u64 = 0,
};

pub const RouteSnapshot = struct {
    node_id: types.NodeId,
    pubkey: [33]u8,
    addr: types.Address,
    enr_seq: u64,
    enr: ?enr.RawEnr,
    connected: bool,
    relayable: bool,
    runtime_contact_trusted: bool,
    advertised_endpoint_trusted: bool,
    health_request: ?types.RequestKey,
    next_ping_at_ns: i64,
};

pub const PeerStore = struct {
    alloc: std.mem.Allocator,
    backing: *Backing,
    allow_ip4: bool,
    allow_ip6: bool,
    fallback_capacity: usize,
    contact_inserted_total: u64 = 0,
    contact_updated_total: u64 = 0,
    contact_replaced_total: u64 = 0,
    contact_capacity_rejected_total: u64 = 0,
    contact_policy_rejected_total: u64 = 0,
    contact_removed_total: u64 = 0,

    pub fn init(alloc: std.mem.Allocator, local_id: types.NodeId, allow_ip4: bool, allow_ip6: bool) !PeerStore {
        return initWithFallbackCapacity(alloc, local_id, allow_ip4, allow_ip6, PEER_CAPACITY - ROUTE_BUCKETS * K);
    }

    pub fn initWithFallbackCapacity(
        alloc: std.mem.Allocator,
        local_id: types.NodeId,
        allow_ip4: bool,
        allow_ip6: bool,
        fallback_capacity: usize,
    ) !PeerStore {
        std.debug.assert(fallback_capacity > 0);
        std.debug.assert(fallback_capacity <= PEER_CAPACITY - ROUTE_BUCKETS * K);
        const backing = try alloc.create(Backing);
        errdefer alloc.destroy(backing);
        @memset(&backing.map.controls, 0);
        backing.map.count = 0;
        backing.map.tombstones = 0;
        backing.control = .{
            .free_slot_head = 0,
            .free_slot_count = PEER_CAPACITY,
            .enr_free_head = 0,
            .enr_free_count = ENR_CAPACITY,
            .probe_free_head = 0,
            .probe_free_count = PROBE_CAPACITY,
            .live_peers = 0,
            .live_enrs = 0,
            .live_probes = 0,
            .reserved = 0,
        };
        for (&backing.free_slots, 0..) |*slot, index| slot.* = @intCast(index);
        for (&backing.slot_generations) |*generation| generation.* = 1;
        for (&backing.enr_free, 0..) |*slot, index| slot.* = @intCast(index);
        for (&backing.probe_free, 0..) |*slot, index| slot.* = @intCast(index);
        for (&backing.probe_generations) |*generation| generation.* = 1;
        backing.routing.local_id = local_id;
        for (&backing.routing.buckets) |*bucket| bucket.* = .{
            .entries = undefined,
            .pending = undefined,
            .count = 0,
            .first_connected = 0,
            .has_pending = 0,
            .reserved = 0,
            .next_generation = 1,
        };
        return .{
            .alloc = alloc,
            .backing = backing,
            .allow_ip4 = allow_ip4,
            .allow_ip6 = allow_ip6,
            .fallback_capacity = fallback_capacity,
        };
    }

    pub fn deinit(self: *PeerStore) void {
        self.alloc.destroy(self.backing);
        self.* = undefined;
    }

    pub fn remember(self: *PeerStore, node_id: types.NodeId, pubkey: *const [33]u8, address: types.Address, trusted: bool) !PeerRef {
        if (self.lookup(&node_id)) |ref| {
            const record = self.resolveMut(ref).?;
            record.pubkey = pubkey.*;
            record.runtime = .init(address);
            if (trusted) record.flags |= FLAG_TRUSTED;
            return ref;
        }
        if (self.backing.control.free_slot_count == 0) return error.PeerCapacityExceeded;
        const free_position = self.backing.control.free_slot_count - 1;
        const index = self.backing.free_slots[free_position];
        const generation = self.backing.slot_generations[index];
        const ref = PeerRef{ .index = index, .generation = generation };
        try self.mapInsert(node_id, ref);
        self.backing.control.free_slot_count = free_position;
        self.backing.control.live_peers += 1;
        self.backing.records[index] = .{
            .enr_seq = 0,
            .last_seen = 0,
            .node_id = node_id,
            .enr_index = NONE,
            .runtime = .init(address),
            .pubkey = pubkey.*,
            .probe_handle = NONE,
            .flags = FLAG_OCCUPIED | if (trusted) FLAG_TRUSTED else 0,
        };
        self.backing.next_ping_at[index] = 0;
        self.backing.evidence[index] = std.mem.zeroes(EndpointEvidence);
        return ref;
    }

    pub fn count(self: *const PeerStore) usize {
        return self.backing.control.live_peers;
    }

    /// Return a value copy so callers never retain pointers into mutable slot storage.
    pub fn known(self: *const PeerStore, node_id: *const types.NodeId) ?KnownNode {
        const ref = self.lookup(node_id) orelse return null;
        const record = self.resolve(ref) orelse return null;
        return .{
            .node_id = record.node_id,
            .pubkey = record.pubkey,
            .addr = record.address(),
            .runtime_contact_trusted = record.flags & FLAG_TRUSTED != 0,
        };
    }

    pub fn rememberContact(
        self: *PeerStore,
        node_id: types.NodeId,
        pubkey: ?*const [33]u8,
        address: types.Address,
        runtime_contact_trusted: bool,
    ) void {
        if (std.mem.eql(u8, &node_id, &self.backing.routing.local_id)) {
            self.contact_policy_rejected_total +|= 1;
            return;
        }
        const key = pubkey orelse {
            self.contact_policy_rejected_total +|= 1;
            return;
        };
        if (self.lookup(&node_id)) |ref| {
            const record = self.resolveMut(ref).?;
            if (record.flags & FLAG_TRUSTED != 0 and !runtime_contact_trusted) {
                self.contact_policy_rejected_total +|= 1;
                return;
            }
            record.pubkey = key.*;
            record.runtime = .init(address);
            if (runtime_contact_trusted) record.flags |= FLAG_TRUSTED;
            if (!self.routeContains(ref) and !self.pendingContains(ref)) self.contact_updated_total +|= 1;
            return;
        }
        if (self.fallbackCount() >= self.fallback_capacity and !self.evictUntrustedFallback(null)) {
            self.contact_capacity_rejected_total +|= 1;
            return;
        }
        _ = self.remember(node_id, key, address, runtime_contact_trusted) catch {
            self.contact_capacity_rejected_total +|= 1;
            return;
        };
        self.contact_inserted_total +|= 1;
    }

    pub fn addressForEnr(self: *const PeerStore, parsed: *const enr.Enr) ?types.Address {
        const ip4 = parsed.udpAddress4();
        const ip6 = parsed.udpAddress6();
        if (self.allow_ip4 and !self.allow_ip6) return ip4;
        if (self.allow_ip6 and !self.allow_ip4) return ip6;
        if (self.allow_ip4 and self.allow_ip6) return ip4 orelse ip6;
        return null;
    }

    pub fn findEnr(self: *const PeerStore, node_id: *const types.NodeId) ?[]const u8 {
        const ref = self.lookup(node_id) orelse return null;
        return self.enrBytes(ref);
    }

    pub fn knownEnrSeq(self: *const PeerStore, node_id: *const types.NodeId) ?u64 {
        const ref = self.lookup(node_id) orelse return null;
        const record = self.resolve(ref) orelse return null;
        return if (record.enr_index == NONE) null else record.enr_seq;
    }

    pub fn addTrusted(
        self: *PeerStore,
        node_id: types.NodeId,
        pubkey: ?*const [33]u8,
        address: types.Address,
        raw: ?[]const u8,
        now_ns: i64,
    ) bool {
        if (raw) |bytes| {
            const validated = enr.ValidatedEnr.init(bytes) catch return false;
            return self.addValidatedTrustedEnr(node_id, pubkey, address, &validated, now_ns);
        }
        self.rememberContact(node_id, pubkey, address, true);
        return if (self.known(&node_id)) |known_value|
            known_value.runtime_contact_trusted and known_value.addr.eql(&address)
        else
            false;
    }

    pub fn addValidatedTrustedEnr(
        self: *PeerStore,
        node_id: types.NodeId,
        pubkey: ?*const [33]u8,
        address: types.Address,
        validated: *const enr.ValidatedEnr,
        now_ns: i64,
    ) bool {
        if (!std.mem.eql(u8, &node_id, &validated.node_id)) return false;
        const key = validated.parsed.pubkey orelse return false;
        if (pubkey) |expected| if (!std.mem.eql(u8, expected, &key)) return false;
        const advertised = self.addressForEnr(&validated.parsed) orelse return false;
        if (!advertised.eql(&address)) return false;
        return self.retainValidated(validated, address, true, false, now_ns) != null;
    }

    pub fn learnEnr(self: *PeerStore, raw: []const u8, now_ns: i64) ?types.NodeId {
        const validated = enr.ValidatedEnr.init(raw) catch return null;
        return self.learnValidatedEnr(&validated, now_ns);
    }

    pub fn learnValidatedEnr(self: *PeerStore, validated: *const enr.ValidatedEnr, now_ns: i64) ?types.NodeId {
        const address = self.addressForEnr(&validated.parsed) orelse return null;
        return self.retainValidated(validated, address, false, false, now_ns);
    }

    pub fn acceptValidatedHandshake(
        self: *PeerStore,
        node_id: types.NodeId,
        pubkey: *const [33]u8,
        address: types.Address,
        validated: ?*const enr.ValidatedEnr,
        now_ns: i64,
    ) ResponsiveResult {
        if (validated) |value| {
            const validated_key = value.parsed.pubkey orelse return .{ .transition = .none, .eviction_candidate = null };
            if (!std.mem.eql(u8, &value.node_id, &node_id) or !std.mem.eql(u8, &validated_key, pubkey))
                return .{ .transition = .none, .eviction_candidate = null };
            const was_connected = self.routeIsConnected(&node_id) orelse false;
            const admission = self.retainValidated(value, address, false, true, now_ns) orelse
                return .{ .transition = .none, .eviction_candidate = null };
            _ = admission;
            var responsive = self.markResponsive(node_id, address, now_ns, null);
            if (!was_connected and (self.routeIsConnected(&node_id) orelse false))
                responsive.transition = .{ .connected = address };
            return responsive;
        }
        self.rememberContact(node_id, pubkey, address, false);
        return self.markResponsive(node_id, address, now_ns, null);
    }

    pub fn markResponsive(
        self: *PeerStore,
        node_id: types.NodeId,
        address: types.Address,
        now_ns: i64,
        completed_key: ?types.RequestKey,
    ) ResponsiveResult {
        const ref = self.lookup(&node_id) orelse return .{ .transition = .none, .eviction_candidate = null };
        const record = self.resolveMut(ref) orelse return .{ .transition = .none, .eviction_candidate = null };
        const was_connected = isConnected(self, ref);
        const endpoint_changed = !record.address().eql(&address);
        record.runtime = .init(address);
        record.last_seen = now_ns;
        setConnected(record, true);
        if (self.advertisesAddress(ref, address)) record.flags |= FLAG_RELAYABLE;
        if (endpoint_changed) self.cancelStandaloneProbe(ref);
        if (completed_key) |key| _ = self.completeHealthRequest(key);
        if (record.enr_index == NONE) return .{ .transition = .none, .eviction_candidate = null };
        const admission = self.admitRoute(ref, true, now_ns) catch return .{ .transition = .none, .eviction_candidate = null };
        return .{
            .transition = if (!was_connected and self.routeContains(ref)) .{ .connected = address } else .none,
            .eviction_candidate = if (admission.eviction) |ticket| self.evictionProbe(ticket) else null,
        };
    }

    pub fn activeRoute(self: *const PeerStore, node_id: *const types.NodeId) ?RouteSnapshot {
        const ref = self.lookup(node_id) orelse return null;
        if (!self.routeContains(ref)) return null;
        return self.routeSnapshot(ref);
    }

    pub fn routeWithPending(self: *const PeerStore, node_id: *const types.NodeId) ?RouteSnapshot {
        const ref = self.lookup(node_id) orelse return null;
        if (!self.routeContains(ref) and !self.pendingContains(ref)) return null;
        return self.routeSnapshot(ref);
    }

    pub fn setNextPing(self: *PeerStore, node_id: *const types.NodeId, next_ns: i64) bool {
        const ref = self.lookup(node_id) orelse return false;
        if (!self.routeContains(ref) and !self.pendingContains(ref)) return false;
        self.backing.next_ping_at[ref.index] = next_ns;
        return true;
    }

    pub fn collectDueProbes(self: *const PeerStore, now_ns: i64, out: []ProbeSnapshot) usize {
        var count_value: usize = 0;
        for (0..ROUTE_BUCKETS) |distance| {
            count_value += self.collectDueProbesInBucket(@intCast(distance), now_ns, out[count_value..]);
            if (count_value == out.len) break;
        }
        return count_value;
    }

    pub fn collectDueProbesInBucket(self: *const PeerStore, distance: u8, now_ns: i64, out: []ProbeSnapshot) usize {
        var count_value: usize = 0;
        const bucket = &self.backing.routing.buckets[distance];
        for (bucket.entries[0..bucket.count]) |route| {
            const record = self.resolve(route.peer) orelse continue;
            if (!isConnected(self, route.peer) or record.probe_handle != NONE or self.backing.next_ping_at[route.peer.index] > now_ns) continue;
            if (count_value == out.len) return count_value;
            out[count_value] = .{ .endpoint = .{ .node_id = record.node_id, .addr = record.address() }, .pubkey = record.pubkey };
            count_value += 1;
        }
        return count_value;
    }

    pub fn collectConnectedProbes(self: *const PeerStore, out: []ProbeSnapshot) usize {
        return self.collectDueProbes(std.math.maxInt(i64), out);
    }

    pub fn collectBucketRelayable(self: *const PeerStore, distance: u8, out: []enr.RawEnr) usize {
        var count_value: usize = 0;
        const bucket = &self.backing.routing.buckets[distance];
        for (bucket.entries[0..bucket.count]) |route| {
            const record = self.resolve(route.peer) orelse continue;
            if (record.flags & FLAG_RELAYABLE == 0) continue;
            const bytes = self.enrBytes(route.peer) orelse continue;
            if (count_value == out.len) break;
            out[count_value] = enr.RawEnr.init(bytes) catch continue;
            count_value += 1;
        }
        return count_value;
    }

    pub fn connectedCount(self: *const PeerStore) usize {
        var count_value: usize = 0;
        for (&self.backing.routing.buckets) |*bucket| for (bucket.entries[0..bucket.count]) |route| {
            if (isConnected(self, route.peer)) count_value += 1;
        };
        return count_value;
    }

    pub fn contactMetricsSnapshot(self: *const PeerStore) ContactMetricsSnapshot {
        return .{
            .count = self.fallbackCount(),
            .capacity = self.fallback_capacity,
            .inserted_total = self.contact_inserted_total,
            .updated_total = self.contact_updated_total,
            .replaced_total = self.contact_replaced_total,
            .capacity_rejected_total = self.contact_capacity_rejected_total,
            .policy_rejected_total = self.contact_policy_rejected_total,
            .removed_total = self.contact_removed_total,
        };
    }

    pub fn fallbackCount(self: *const PeerStore) usize {
        return self.count() - self.routeCount();
    }

    pub fn healthRequest(self: *const PeerStore, node_id: *const types.NodeId) ?types.RequestKey {
        const route = self.routeWithPending(node_id) orelse return null;
        return route.health_request;
    }

    pub fn routeIsConnected(self: *const PeerStore, node_id: *const types.NodeId) ?bool {
        return (self.routeWithPending(node_id) orelse return null).connected;
    }

    pub fn routeIsRelayable(self: *const PeerStore, node_id: *const types.NodeId) bool {
        return if (self.routeWithPending(node_id)) |route| route.relayable else false;
    }

    pub fn lookup(self: *const PeerStore, node_id: *const types.NodeId) ?PeerRef {
        var index = mapHash(node_id);
        var probes: usize = 0;
        while (probes < MAP_CAPACITY) : ({
            probes += 1;
            index = (index + 1) & (MAP_CAPACITY - 1);
        }) {
            const control = self.backing.map.controls[index];
            if (control == 0) return null;
            if (control == 1 and std.mem.eql(u8, &self.backing.map.keys[index], node_id))
                return self.backing.map.refs[index];
        }
        return null;
    }

    pub fn resolve(self: *const PeerStore, ref: PeerRef) ?*const PeerRecord {
        if (ref.index >= PEER_CAPACITY) return null;
        if (self.backing.slot_generations[ref.index] != ref.generation) return null;
        const record = &self.backing.records[ref.index];
        return if (record.occupied()) record else null;
    }

    pub fn resolveMut(self: *PeerStore, ref: PeerRef) ?*PeerRecord {
        return @constCast(self.resolve(ref));
    }

    pub fn updateAddress(self: *PeerStore, ref: PeerRef, address: types.Address) bool {
        const record = self.resolveMut(ref) orelse return false;
        record.runtime = .init(address);
        return true;
    }

    pub fn setAdvertisedEvidence(self: *PeerStore, ref: PeerRef, address: types.Address, trusted: bool) bool {
        if (self.resolve(ref) == null) return false;
        const evidence = &self.backing.evidence[ref.index];
        switch (address) {
            .ip4 => |ip4| {
                evidence.ip4_bytes = ip4.bytes;
                evidence.ip4_port = ip4.port;
                evidence.ip4_flags = 1 | if (trusted) @as(u8, 2) else 0;
            },
            .ip6 => {
                evidence.ip6 = .init(address);
                if (trusted) evidence.ip6.flags |= 2;
            },
        }
        return true;
    }

    pub fn advertisedEvidence(self: *const PeerStore, ref: PeerRef) ?EndpointEvidenceView {
        if (self.resolve(ref) == null) return null;
        const evidence = &self.backing.evidence[ref.index];
        return .{
            .ip4 = .{
                .bytes = evidence.ip4_bytes ++ ([_]u8{0} ** 12),
                .port = evidence.ip4_port,
                .family = 4,
                .flags = evidence.ip4_flags,
            },
            .ip6 = evidence.ip6,
        };
    }

    pub fn remove(self: *PeerStore, ref: PeerRef) bool {
        const record = self.resolveMut(ref) orelse return false;
        if (record.activePins() != 0 or record.pendingPins() != 0 or record.probe_handle != NONE) return false;
        if (!self.mapRemove(&record.node_id, ref)) return false;
        if (record.enr_index != NONE) self.releaseEnr(record.enr_index);
        record.flags = 0;
        var generation = self.backing.slot_generations[ref.index] +% 1;
        if (generation == 0) generation = 1;
        self.backing.slot_generations[ref.index] = generation;
        const free_position = self.backing.control.free_slot_count;
        self.backing.free_slots[free_position] = ref.index;
        self.backing.control.free_slot_count += 1;
        self.backing.control.live_peers -= 1;
        return true;
    }

    pub fn pinActive(self: *PeerStore, ref: PeerRef) bool {
        const record = self.resolveMut(ref) orelse return false;
        const pin_count = record.activePins();
        if (pin_count == PIN_MASK) return false;
        record.flags += @as(u32, 1) << ACTIVE_PIN_SHIFT;
        return true;
    }

    pub fn unpinActive(self: *PeerStore, ref: PeerRef) bool {
        const record = self.resolveMut(ref) orelse return false;
        if (record.activePins() == 0) return false;
        record.flags -= @as(u32, 1) << ACTIVE_PIN_SHIFT;
        return true;
    }

    pub fn pinPending(self: *PeerStore, ref: PeerRef) bool {
        const record = self.resolveMut(ref) orelse return false;
        const pin_count = record.pendingPins();
        if (pin_count == PIN_MASK) return false;
        record.flags += @as(u32, 1) << PENDING_PIN_SHIFT;
        return true;
    }

    pub fn unpinPending(self: *PeerStore, ref: PeerRef) bool {
        const record = self.resolveMut(ref) orelse return false;
        if (record.pendingPins() == 0) return false;
        record.flags -= @as(u32, 1) << PENDING_PIN_SHIFT;
        return true;
    }

    pub fn putEnr(self: *PeerStore, ref: PeerRef, raw: []const u8, seq: u64) !void {
        if (raw.len > 300) return error.EnrTooLarge;
        const record = self.resolveMut(ref) orelse return error.StalePeerRef;
        if (seq <= record.enr_seq and record.enr_index != NONE) return;
        var index = record.enr_index;
        if (index == NONE) {
            if (self.backing.control.enr_free_count == 0) return error.EnrCapacityExceeded;
            const position = self.backing.control.enr_free_count - 1;
            index = self.backing.enr_free[position];
            self.backing.control.enr_free_count = position;
            self.backing.control.live_enrs += 1;
        }
        const slot = &self.backing.enrs[index];
        @memcpy(slot.bytes[0..raw.len], raw);
        slot.len = @intCast(raw.len);
        slot.present = 1;
        record.enr_index = index;
        record.enr_seq = seq;
    }

    pub fn enrBytes(self: *const PeerStore, ref: PeerRef) ?[]const u8 {
        const record = self.resolve(ref) orelse return null;
        if (record.enr_index == NONE) return null;
        const slot = &self.backing.enrs[record.enr_index];
        if (slot.present == 0) return null;
        return slot.bytes[0..slot.len];
    }

    pub fn admitRoute(self: *PeerStore, ref: PeerRef, connected: bool, now_ns: i64) !RouteAdmission {
        const record = self.resolveMut(ref) orelse return error.StalePeerRef;
        const distance = logDistance(&self.backing.routing.local_id, &record.node_id) orelse return .{ .inserted = false };
        const bucket = &self.backing.routing.buckets[distance];

        if (findRoute(bucket, ref)) |index| {
            _ = removeRouteAt(bucket, index);
            setConnected(record, connected);
            insertRouteOrdered(self, bucket, .{ .peer = ref, .routing_recency = now_ns });
            return .{ .inserted = true };
        }
        if (bucket.has_pending != 0 and peerRefEql(bucket.pending.newcomer, ref)) {
            setConnected(record, connected);
            return .{ .inserted = true };
        }
        setConnected(record, connected);
        if (bucket.count < K) {
            if (!self.pinActive(ref)) return error.PinCapacityExceeded;
            insertRouteOrdered(self, bucket, .{ .peer = ref, .routing_recency = now_ns });
            return .{ .inserted = true };
        }
        if (!connected or bucket.first_connected == 0 or bucket.has_pending != 0)
            return .{ .inserted = false };

        const probe = try self.reserveProbe();
        errdefer self.releaseProbe(probe);
        if (!self.pinPending(ref)) return error.PinCapacityExceeded;
        errdefer std.debug.assert(self.unpinPending(ref));
        const incumbent = bucket.entries[0].peer;
        const generation = bucket.next_generation;
        bucket.next_generation +%= 1;
        if (bucket.next_generation == 0) bucket.next_generation = 1;
        self.backing.probes[probe.index] = .{ .eviction = .{
            .request = .{
                .peer = incumbent,
                .endpoint = self.resolve(incumbent).?.runtime,
                .req_id = [_]u8{0} ** 8,
                .req_len = 0,
            },
            .incumbent = incumbent,
            .ticket_generation = generation,
        } };
        bucket.pending = .{
            .newcomer = ref,
            .incumbent = incumbent,
            .inserted_at = now_ns,
            .ticket_generation = generation,
            .probe_handle = probe.index,
            .flags = 0,
        };
        bucket.has_pending = 1;
        return .{ .inserted = false, .eviction = .{
            .incumbent = incumbent,
            .candidate = ref,
            .generation = generation,
            .probe = probe,
        } };
    }

    pub fn routeContains(self: *const PeerStore, ref: PeerRef) bool {
        const record = self.resolve(ref) orelse return false;
        const distance = logDistance(&self.backing.routing.local_id, &record.node_id) orelse return false;
        return findRoute(&self.backing.routing.buckets[distance], ref) != null;
    }

    pub fn pendingContains(self: *const PeerStore, ref: PeerRef) bool {
        const record = self.resolve(ref) orelse return false;
        const distance = logDistance(&self.backing.routing.local_id, &record.node_id) orelse return false;
        const bucket = &self.backing.routing.buckets[distance];
        return bucket.has_pending != 0 and peerRefEql(bucket.pending.newcomer, ref);
    }

    pub fn removeRoute(self: *PeerStore, ref: PeerRef) bool {
        const record = self.resolve(ref) orelse return false;
        const distance = logDistance(&self.backing.routing.local_id, &record.node_id) orelse return false;
        const bucket = &self.backing.routing.buckets[distance];
        if (bucket.has_pending != 0 and peerRefEql(bucket.pending.newcomer, ref)) {
            const ticket = self.ticketForBucket(bucket) orelse return false;
            self.dropPending(bucket, ticket);
            return true;
        }
        const index = findRoute(bucket, ref) orelse return false;
        _ = removeRouteAt(bucket, index);
        std.debug.assert(self.unpinActive(ref));
        if (bucket.has_pending != 0) {
            const ticket = self.ticketForBucket(bucket) orelse unreachable;
            const inserted_at = bucket.pending.inserted_at;
            self.dropPending(bucket, ticket);
            std.debug.assert(self.pinActive(ticket.candidate));
            insertRouteOrdered(self, bucket, .{ .peer = ticket.candidate, .routing_recency = inserted_at });
        }
        return true;
    }

    pub fn rollbackEviction(self: *PeerStore, ticket: EvictionTicket) bool {
        const bucket = self.bucketForTicket(ticket) orelse return false;
        self.dropPending(bucket, ticket);
        return true;
    }

    pub fn resolveEvictionSuccess(self: *PeerStore, ticket: EvictionTicket) bool {
        const bucket = self.bucketForTicket(ticket) orelse return false;
        if (!self.probeMatchesCurrentEndpoint(ticket)) return false;
        const incumbent = self.resolveMut(ticket.incumbent) orelse return false;
        setConnected(incumbent, true);
        self.dropPending(bucket, ticket);
        return true;
    }

    pub fn completeEvictionTimeout(self: *PeerStore, ticket: EvictionTicket) ?PeerRef {
        const bucket = self.bucketForTicket(ticket) orelse return null;
        if (!self.probeMatchesCurrentEndpoint(ticket)) return null;
        if (isConnected(self, ticket.incumbent)) return null;
        const incumbent_index = findRoute(bucket, ticket.incumbent) orelse return null;
        const inserted_at = bucket.pending.inserted_at;
        _ = removeRouteAt(bucket, incumbent_index);
        std.debug.assert(self.unpinActive(ticket.incumbent));
        self.dropPending(bucket, ticket);
        std.debug.assert(self.pinActive(ticket.candidate));
        insertRouteOrdered(self, bucket, .{ .peer = ticket.candidate, .routing_recency = inserted_at });
        return ticket.candidate;
    }

    pub fn findClosestNodeIds(self: *const PeerStore, target: *const types.NodeId, out: []types.NodeId) usize {
        var result_count: usize = 0;
        if (out.len == 0) return 0;
        for (&self.backing.routing.buckets) |*bucket| {
            for (bucket.entries[0..bucket.count]) |route| {
                const record = self.resolve(route.peer) orelse continue;
                insertClosestNodeId(target, record.node_id, out, &result_count);
            }
        }
        return result_count;
    }

    pub fn routeCount(self: *const PeerStore) usize {
        var total: usize = 0;
        for (&self.backing.routing.buckets) |*bucket| total += bucket.count;
        return total;
    }

    pub fn findClosest(self: *const PeerStore, target: *const types.NodeId, out: []types.NodeId) usize {
        return self.findClosestNodeIds(target, out);
    }

    pub fn currentEvictionTicket(self: *const PeerStore, incumbent_id: *const types.NodeId, generation: u64) ?EvictionTicket {
        const ref = self.lookup(incumbent_id) orelse return null;
        const record = self.resolve(ref) orelse return null;
        const distance = logDistance(&self.backing.routing.local_id, &record.node_id) orelse return null;
        const ticket = self.ticketForBucket(&self.backing.routing.buckets[distance]) orelse return null;
        if (!peerRefEql(ticket.incumbent, ref) or ticket.generation != generation) return null;
        return ticket;
    }

    pub fn armHealthRequest(self: *PeerStore, key: types.RequestKey, policy: HealthReservationPolicy) bool {
        const ref = self.lookup(&key.endpoint.node_id) orelse return false;
        const record = self.resolveMut(ref) orelse return false;
        if (!record.address().eql(&key.endpoint.addr) or record.probe_handle != NONE) return false;
        const probe = switch (policy) {
            .connected_only => blk: {
                if (!self.routeContains(ref) or !isConnected(self, ref)) return false;
                break :blk self.reserveProbe() catch return false;
            },
            .allow_eviction_candidate => |ticket| blk: {
                const bucket = self.bucketForTicket(ticket) orelse return false;
                _ = bucket;
                if (!peerRefEql(ticket.incumbent, ref)) return false;
                break :blk ticket.probe;
            },
        };
        self.backing.probes[probe.index] = switch (policy) {
            .connected_only => .{ .health = compactRequest(ref, key) },
            .allow_eviction_candidate => |ticket| .{ .eviction = .{
                .request = compactRequest(ref, key),
                .incumbent = ticket.incumbent,
                .ticket_generation = ticket.generation,
            } },
        };
        record.probe_handle = probe.index;
        return true;
    }

    pub fn cancelHealthRequest(self: *PeerStore, key: types.RequestKey) bool {
        const ref = self.lookup(&key.endpoint.node_id) orelse return false;
        const record = self.resolveMut(ref) orelse return false;
        if (record.probe_handle == NONE) return false;
        const probe = ProbeRef{ .index = record.probe_handle, .generation = self.backing.probe_generations[record.probe_handle] };
        const request = switch (self.backing.probes[probe.index]) {
            .health => |value| value,
            else => return false,
        };
        if (!requestMatches(request, key)) return false;
        record.probe_handle = NONE;
        self.releaseProbe(probe);
        return true;
    }

    pub fn cancelEvictionRequest(self: *PeerStore, ticket: EvictionTicket, key: types.RequestKey) bool {
        _ = self.bucketForTicket(ticket) orelse return false;
        if (!self.probeRequestMatches(ticket, key)) return false;
        const incumbent = self.resolveMut(ticket.incumbent) orelse return false;
        incumbent.probe_handle = NONE;
        self.backing.probes[ticket.probe.index].eviction.request.req_len = 0;
        return true;
    }

    pub fn markEvictionResponsive(self: *PeerStore, ticket: EvictionTicket, key: types.RequestKey, now_ns: i64) ResponsiveResult {
        if (!self.probeRequestMatches(ticket, key)) return .{ .transition = .none, .eviction_candidate = null };
        return self.markResponsive(key.endpoint.node_id, key.endpoint.addr, now_ns, key);
    }

    pub fn resolveEvictionRequestSuccess(self: *PeerStore, ticket: EvictionTicket, key: types.RequestKey) bool {
        if (!self.probeRequestMatches(ticket, key)) return false;
        return self.resolveEvictionSuccess(ticket);
    }

    pub fn completeEvictionRequestTimeout(self: *PeerStore, ticket: EvictionTicket, key: types.RequestKey) ?ConnectionEvent {
        if (!self.probeRequestMatches(ticket, key)) return null;
        const candidate = self.completeEvictionTimeout(ticket) orelse return null;
        const record = self.resolve(candidate) orelse return null;
        return if (isConnected(self, candidate)) .{ .node_id = record.node_id, .transition = .{ .connected = record.address() } } else null;
    }

    pub fn markDisconnected(self: *PeerStore, key: types.RequestKey, now_ns: i64) ConnectionTransition {
        const ref = self.lookup(&key.endpoint.node_id) orelse return .none;
        if (!self.routeContains(ref) or !isConnected(self, ref)) return .none;
        const record = self.resolveMut(ref) orelse return .none;
        if (!record.address().eql(&key.endpoint.addr) or !self.completeHealthRequest(key)) return .none;
        record.last_seen = now_ns;
        setConnected(record, false);
        const distance = logDistance(&self.backing.routing.local_id, &record.node_id) orelse return .none;
        const bucket = &self.backing.routing.buckets[distance];
        const index = findRoute(bucket, ref) orelse return .none;
        const route = removeRouteAt(bucket, index);
        insertRouteOrdered(self, bucket, route);
        return .{ .disconnected = key.endpoint.addr };
    }

    pub fn prune(self: *PeerStore, now_ns: i64, timeout_ms: u64, transitions: []ConnectionEvent) usize {
        var count_value: usize = 0;
        const timeout_ns: i128 = @as(i128, timeout_ms) * std.time.ns_per_ms;
        for (&self.backing.routing.buckets) |*bucket| {
            if (bucket.has_pending == 0) continue;
            if (@as(i128, now_ns) - @as(i128, bucket.pending.inserted_at) < timeout_ns) continue;
            const ticket = self.ticketForBucket(bucket) orelse continue;
            const promoted = self.completeEvictionTimeout(ticket) orelse continue;
            const record = self.resolve(promoted) orelse continue;
            if (!isConnected(self, promoted) or count_value == transitions.len) continue;
            transitions[count_value] = .{ .node_id = record.node_id, .transition = .{ .connected = record.address() } };
            count_value += 1;
        }
        return count_value;
    }

    pub fn memoryAccounting() MemoryAccounting {
        return .{};
    }

    fn retainValidated(
        self: *PeerStore,
        validated: *const enr.ValidatedEnr,
        runtime_address: types.Address,
        trusted: bool,
        connected: bool,
        now_ns: i64,
    ) ?types.NodeId {
        if (std.mem.eql(u8, &validated.node_id, &self.backing.routing.local_id)) return null;
        const key = validated.parsed.pubkey orelse return null;
        const was_known = self.lookup(&validated.node_id) != null;
        const ref = self.lookup(&validated.node_id) orelse self.remember(validated.node_id, &key, runtime_address, trusted) catch return null;
        var record = self.resolveMut(ref) orelse return null;
        if (!std.mem.eql(u8, &record.pubkey, &key)) return null;
        if (record.enr_index != NONE and record.enr_seq >= validated.parsed.seq) {
            if (trusted) {
                if (validated.parsed.udpAddress4()) |value| _ = self.setAdvertisedEvidence(ref, value, true);
                if (validated.parsed.udpAddress6()) |value| _ = self.setAdvertisedEvidence(ref, value, true);
                record = self.resolveMut(ref) orelse return null;
                if (record.address().eql(&runtime_address)) record.flags |= FLAG_TRUSTED;
                record.flags |= FLAG_RELAYABLE;
            }
            return validated.node_id;
        }
        if (!(record.flags & FLAG_TRUSTED != 0 and !trusted and !record.address().eql(&runtime_address))) {
            record.runtime = .init(runtime_address);
        }
        if (trusted) record.flags |= FLAG_TRUSTED;
        record.last_seen = now_ns;
        if (connected) setConnected(record, true);
        if (validated.parsed.udpAddress4()) |value| _ = self.setAdvertisedEvidence(ref, value, trusted);
        if (validated.parsed.udpAddress6()) |value| _ = self.setAdvertisedEvidence(ref, value, trusted);
        const admission = self.admitRoute(ref, connected, now_ns) catch return null;
        if (!self.routeContains(ref) and self.fallbackCount() > self.fallback_capacity) {
            if (!self.evictUntrustedFallback(ref)) {
                if (admission.eviction) |ticket| _ = self.rollbackEviction(ticket);
                _ = self.remove(ref);
                self.contact_capacity_rejected_total +|= 1;
                return null;
            }
        }
        if (!was_known and !self.routeContains(ref)) self.contact_inserted_total +|= 1;
        // Fallback-only contacts intentionally retain identity and endpoint but
        // not raw ENR bytes. Lookup-local candidates carry the validated ENR
        // for the current lookup without creating a second long-lived owner.
        if (!admission.inserted and admission.eviction == null) return validated.node_id;
        self.putEnr(ref, validated.raw.slice(), validated.parsed.seq) catch {
            if (admission.eviction) |ticket| _ = self.rollbackEviction(ticket) else _ = self.removeRoute(ref);
            return null;
        };
        record = self.resolveMut(ref) orelse return null;
        record.flags &= ~FLAG_RELAYABLE;
        if (trusted or (connected and self.advertisesAddress(ref, runtime_address))) record.flags |= FLAG_RELAYABLE;
        return validated.node_id;
    }

    fn evictUntrustedFallback(self: *PeerStore, protected: ?PeerRef) bool {
        for (0..PEER_CAPACITY) |index| {
            const record = &self.backing.records[index];
            if (!record.occupied() or record.flags & FLAG_TRUSTED != 0) continue;
            const ref = PeerRef{ .index = @intCast(index), .generation = self.backing.slot_generations[index] };
            if (protected) |value| if (peerRefEql(ref, value)) continue;
            if (self.routeContains(ref) or self.pendingContains(ref)) continue;
            if (!self.remove(ref)) continue;
            self.contact_replaced_total +|= 1;
            return true;
        }
        return false;
    }

    fn routeSnapshot(self: *const PeerStore, ref: PeerRef) ?RouteSnapshot {
        const record = self.resolve(ref) orelse return null;
        const raw = if (self.enrBytes(ref)) |bytes| enr.RawEnr.init(bytes) catch null else null;
        const health_request = if (record.probe_handle != NONE) switch (self.backing.probes[record.probe_handle]) {
            .health => |request| requestKeyFromCompact(record.node_id, request),
            .eviction => |probe| if (probe.request.req_len == 0) null else requestKeyFromCompact(record.node_id, probe.request),
            .none => null,
        } else null;
        return .{
            .node_id = record.node_id,
            .pubkey = record.pubkey,
            .addr = record.address(),
            .enr_seq = record.enr_seq,
            .enr = raw,
            .connected = isConnected(self, ref),
            .relayable = record.flags & FLAG_RELAYABLE != 0,
            .runtime_contact_trusted = record.flags & FLAG_TRUSTED != 0,
            .advertised_endpoint_trusted = self.backing.evidence[ref.index].ip4_flags & 2 != 0 or
                self.backing.evidence[ref.index].ip6.flags & 2 != 0,
            .health_request = health_request,
            .next_ping_at_ns = self.backing.next_ping_at[ref.index],
        };
    }

    fn advertisesAddress(self: *const PeerStore, ref: PeerRef, address: types.Address) bool {
        const evidence = self.advertisedEvidence(ref) orelse return false;
        return switch (address) {
            .ip4 => evidence.ip4.flags & 1 != 0 and evidence.ip4.address().eql(&address),
            .ip6 => evidence.ip6.flags & 1 != 0 and evidence.ip6.address().eql(&address),
        };
    }

    fn evictionProbe(self: *const PeerStore, ticket: EvictionTicket) ?EvictionProbe {
        const incumbent = self.resolve(ticket.incumbent) orelse return null;
        return .{
            .endpoint = .{ .node_id = incumbent.node_id, .addr = incumbent.address() },
            .pubkey = incumbent.pubkey,
            .ticket = ticket,
        };
    }

    fn completeHealthRequest(self: *PeerStore, key: types.RequestKey) bool {
        const ref = self.lookup(&key.endpoint.node_id) orelse return false;
        const record = self.resolveMut(ref) orelse return false;
        if (record.probe_handle == NONE) return false;
        const index = record.probe_handle;
        const probe = ProbeRef{ .index = index, .generation = self.backing.probe_generations[index] };
        const matches = switch (self.backing.probes[index]) {
            .health => |request| requestMatches(request, key),
            .eviction => |value| requestMatches(value.request, key),
            .none => false,
        };
        if (!matches) return false;
        if (self.backing.probes[index] == .health) {
            record.probe_handle = NONE;
            self.releaseProbe(probe);
        }
        return true;
    }

    fn cancelStandaloneProbe(self: *PeerStore, ref: PeerRef) void {
        const record = self.resolveMut(ref) orelse return;
        if (record.probe_handle == NONE) return;
        const index = record.probe_handle;
        if (self.backing.probes[index] != .health) return;
        record.probe_handle = NONE;
        self.releaseProbe(.{ .index = index, .generation = self.backing.probe_generations[index] });
    }

    fn probeRequestMatches(self: *const PeerStore, ticket: EvictionTicket, key: types.RequestKey) bool {
        if (self.bucketForTicketConst(ticket) == null) return false;
        const probe = switch (self.backing.probes[ticket.probe.index]) {
            .eviction => |value| value,
            else => return false,
        };
        return requestMatches(probe.request, key);
    }

    fn bucketForTicketConst(self: *const PeerStore, ticket: EvictionTicket) ?*const CompactBucket {
        return @constCast(self).bucketForTicket(ticket);
    }

    fn ticketForBucket(self: *const PeerStore, bucket: *const CompactBucket) ?EvictionTicket {
        if (bucket.has_pending == 0) return null;
        const probe_index = bucket.pending.probe_handle;
        if (probe_index >= PROBE_CAPACITY) return null;
        return .{
            .incumbent = bucket.pending.incumbent,
            .candidate = bucket.pending.newcomer,
            .generation = bucket.pending.ticket_generation,
            .probe = .{
                .index = probe_index,
                .generation = self.backing.probe_generations[probe_index],
            },
        };
    }

    fn bucketForTicket(self: *PeerStore, ticket: EvictionTicket) ?*CompactBucket {
        const incumbent = self.resolve(ticket.incumbent) orelse return null;
        if (self.resolve(ticket.candidate) == null) return null;
        const distance = logDistance(&self.backing.routing.local_id, &incumbent.node_id) orelse return null;
        const bucket = &self.backing.routing.buckets[distance];
        if (bucket.has_pending == 0) return null;
        if (!peerRefEql(bucket.pending.incumbent, ticket.incumbent)) return null;
        if (!peerRefEql(bucket.pending.newcomer, ticket.candidate)) return null;
        if (bucket.pending.ticket_generation != ticket.generation) return null;
        if (bucket.pending.probe_handle != ticket.probe.index) return null;
        if (ticket.probe.index >= PROBE_CAPACITY) return null;
        if (self.backing.probe_generations[ticket.probe.index] != ticket.probe.generation) return null;
        return bucket;
    }

    fn dropPending(self: *PeerStore, bucket: *CompactBucket, ticket: EvictionTicket) void {
        bucket.has_pending = 0;
        if (self.resolveMut(ticket.incumbent)) |incumbent| {
            if (incumbent.probe_handle == ticket.probe.index) incumbent.probe_handle = NONE;
        }
        std.debug.assert(self.unpinPending(ticket.candidate));
        self.releaseProbe(ticket.probe);
    }

    fn probeMatchesCurrentEndpoint(self: *const PeerStore, ticket: EvictionTicket) bool {
        if (ticket.probe.index >= PROBE_CAPACITY) return false;
        if (self.backing.probe_generations[ticket.probe.index] != ticket.probe.generation) return false;
        const probe = switch (self.backing.probes[ticket.probe.index]) {
            .eviction => |value| value,
            else => return false,
        };
        if (!peerRefEql(probe.incumbent, ticket.incumbent) or probe.ticket_generation != ticket.generation) return false;
        const incumbent = self.resolve(ticket.incumbent) orelse return false;
        return compactEndpointEql(probe.request.endpoint, incumbent.runtime);
    }

    fn reserveProbe(self: *PeerStore) !ProbeRef {
        if (self.backing.control.probe_free_count == 0) return error.ProbeCapacityExceeded;
        const position = self.backing.control.probe_free_count - 1;
        const index = self.backing.probe_free[position];
        self.backing.control.probe_free_count = position;
        self.backing.control.live_probes += 1;
        return .{ .index = index, .generation = self.backing.probe_generations[index] };
    }

    fn releaseProbe(self: *PeerStore, probe: ProbeRef) void {
        std.debug.assert(probe.index < PROBE_CAPACITY);
        std.debug.assert(self.backing.probe_generations[probe.index] == probe.generation);
        self.backing.probes[probe.index] = .none;
        var generation = self.backing.probe_generations[probe.index] +% 1;
        if (generation == 0) generation = 1;
        self.backing.probe_generations[probe.index] = generation;
        self.backing.probe_free[self.backing.control.probe_free_count] = probe.index;
        self.backing.control.probe_free_count += 1;
        self.backing.control.live_probes -= 1;
    }

    fn mapInsert(self: *PeerStore, node_id: types.NodeId, ref: PeerRef) !void {
        if (self.backing.map.count >= PEER_CAPACITY) return error.MapCapacityExceeded;
        var index = mapHash(&node_id);
        var first_tombstone: ?usize = null;
        var probes: usize = 0;
        while (probes < MAP_CAPACITY) : ({
            probes += 1;
            index = (index + 1) & (MAP_CAPACITY - 1);
        }) {
            const control = self.backing.map.controls[index];
            if (control == 2 and first_tombstone == null) first_tombstone = index;
            if (control != 0) continue;
            const destination = first_tombstone orelse index;
            if (first_tombstone != null) self.backing.map.tombstones -= 1;
            self.backing.map.controls[destination] = 1;
            self.backing.map.keys[destination] = node_id;
            self.backing.map.refs[destination] = ref;
            self.backing.map.count += 1;
            return;
        }
        return error.MapCapacityExceeded;
    }

    fn mapRemove(self: *PeerStore, node_id: *const types.NodeId, ref: PeerRef) bool {
        var index = mapHash(node_id);
        var probes: usize = 0;
        while (probes < MAP_CAPACITY) : ({
            probes += 1;
            index = (index + 1) & (MAP_CAPACITY - 1);
        }) {
            const control = self.backing.map.controls[index];
            if (control == 0) return false;
            if (control != 1 or !std.mem.eql(u8, &self.backing.map.keys[index], node_id)) continue;
            const mapped = self.backing.map.refs[index];
            if (mapped.index != ref.index or mapped.generation != ref.generation) return false;
            self.backing.map.controls[index] = 2;
            self.backing.map.count -= 1;
            self.backing.map.tombstones += 1;
            return true;
        }
        return false;
    }

    fn releaseEnr(self: *PeerStore, index: u32) void {
        self.backing.enrs[index].present = 0;
        const position = self.backing.control.enr_free_count;
        self.backing.enr_free[position] = index;
        self.backing.control.enr_free_count += 1;
        self.backing.control.live_enrs -= 1;
    }
};

fn peerRefEql(a: PeerRef, b: PeerRef) bool {
    return a.index == b.index and a.generation == b.generation;
}

fn compactEndpointEql(a: CompactEndpoint, b: CompactEndpoint) bool {
    return a.family == b.family and a.port == b.port and std.mem.eql(u8, &a.bytes, &b.bytes);
}

fn compactRequest(ref: PeerRef, key: types.RequestKey) CompactRequest {
    return .{
        .peer = ref,
        .endpoint = .init(key.endpoint.addr),
        .req_id = key.req_id.bytes,
        .req_len = key.req_id.len,
    };
}

fn requestMatches(request: CompactRequest, key: types.RequestKey) bool {
    return peerRefEndpointMatches(request, key.endpoint) and request.req_len == key.req_id.len and
        std.mem.eql(u8, request.req_id[0..request.req_len], key.req_id.bytes[0..key.req_id.len]);
}

fn peerRefEndpointMatches(request: CompactRequest, endpoint: types.Endpoint) bool {
    return compactEndpointEql(request.endpoint, .init(endpoint.addr));
}

fn requestKeyFromCompact(node_id: types.NodeId, request: CompactRequest) types.RequestKey {
    return .{
        .endpoint = .{ .node_id = node_id, .addr = request.endpoint.address() },
        .req_id = .{ .bytes = request.req_id, .len = request.req_len },
    };
}

fn setConnected(record: *PeerRecord, connected: bool) void {
    if (connected) record.flags |= FLAG_CONNECTED else record.flags &= ~FLAG_CONNECTED;
}

fn isConnected(store: *const PeerStore, ref: PeerRef) bool {
    const record = store.resolve(ref) orelse return false;
    return record.flags & FLAG_CONNECTED != 0;
}

fn findRoute(bucket: *const CompactBucket, ref: PeerRef) ?usize {
    for (bucket.entries[0..bucket.count], 0..) |entry, index| {
        if (peerRefEql(entry.peer, ref)) return index;
    }
    return null;
}

fn removeRouteAt(bucket: *CompactBucket, index: usize) RouteEntry {
    const removed = bucket.entries[index];
    if (index + 1 < bucket.count) {
        @memmove(bucket.entries[index .. bucket.count - 1], bucket.entries[index + 1 .. bucket.count]);
    }
    bucket.count -= 1;
    if (index < bucket.first_connected) bucket.first_connected -= 1;
    return removed;
}

fn insertRouteOrdered(store: *const PeerStore, bucket: *CompactBucket, entry: RouteEntry) void {
    std.debug.assert(bucket.count < K);
    if (isConnected(store, entry.peer)) {
        bucket.entries[bucket.count] = entry;
    } else {
        const index = bucket.first_connected;
        if (index < bucket.count) {
            @memmove(bucket.entries[index + 1 .. bucket.count + 1], bucket.entries[index..bucket.count]);
        }
        bucket.entries[index] = entry;
        bucket.first_connected += 1;
    }
    bucket.count += 1;
}

fn insertClosestNodeId(target: *const types.NodeId, candidate: types.NodeId, out: []types.NodeId, count: *usize) void {
    var insert_at = count.*;
    for (out[0..count.*], 0..) |node_id, index| {
        if (distanceLess(target, &candidate, &node_id)) {
            insert_at = index;
            break;
        }
    }
    if (insert_at >= out.len) return;
    const new_count = @min(count.* + 1, out.len);
    if (insert_at + 1 < new_count) {
        @memmove(out[insert_at + 1 .. new_count], out[insert_at .. new_count - 1]);
    }
    out[insert_at] = candidate;
    count.* = new_count;
}

fn distanceLess(target: *const types.NodeId, a: *const types.NodeId, b: *const types.NodeId) bool {
    for (target, a, b) |target_byte, a_byte, b_byte| {
        const a_distance = target_byte ^ a_byte;
        const b_distance = target_byte ^ b_byte;
        if (a_distance != b_distance) return a_distance < b_distance;
    }
    return std.mem.lessThan(u8, a, b);
}

pub fn logDistance(a: *const types.NodeId, b: *const types.NodeId) ?u8 {
    for (a, b, 0..) |ab, bb, index| {
        const xor = ab ^ bb;
        if (xor == 0) continue;
        const bit = @as(u8, 7) - @as(u8, @intCast(@clz(xor)));
        return @as(u8, @intCast((31 - index) * 8)) + bit;
    }
    return null;
}

pub fn xorDistance(a: *const types.NodeId, b: *const types.NodeId) types.NodeId {
    var distance: types.NodeId = undefined;
    for (a, b, &distance) |a_byte, b_byte, *out| out.* = a_byte ^ b_byte;
    return distance;
}

fn mapHash(node_id: *const types.NodeId) usize {
    return @intCast(std.hash.Wyhash.hash(0, node_id) & (MAP_CAPACITY - 1));
}

comptime {
    if (@sizeOf(PeerRecord) > 128) @compileError("PeerRecord exceeds 128-byte gate");
    if (@sizeOf(RouteEntry) > 104) @compileError("RouteEntry exceeds 104-byte gate");
    if ((K - 1) * @sizeOf(RouteEntry) > 1600) @compileError("K=16 shift exceeds 1600-byte gate");
    if (@sizeOf(Backing) > 3_298_126) @compileError("PeerStore exact backing exceeds memory gate");
    if (@sizeOf(enr.RawEnr) < 302) @compileError("RawEnr contract unexpectedly changed");
}
