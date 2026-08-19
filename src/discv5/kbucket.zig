//! Kademlia k-bucket routing table for discv5

const std = @import("std");
const enr_mod = @import("enr.zig");
const NodeId = enr_mod.NodeId;
const Address = std.Io.net.IpAddress;
const RequestKey = @import("types.zig").RequestKey;

pub const K = 16;
pub const NUM_BUCKETS = 256;
pub const BUCKET_PENDING_TIMEOUT_MS: u64 = 60_000;

/// Connectivity state used for bucket ordering and eviction.
pub const EntryStatus = enum {
    connected,
    disconnected,
    pending,
};

pub const Entry = struct {
    node_id: NodeId,
    pubkey: [33]u8 = [_]u8{0} ** 33,
    addr: Address,
    enr: enr_mod.RawEnr = .{},
    enr_seq: u64 = 0,
    advertised_addr4: ?Address = null,
    advertised_addr6: ?Address = null,
    last_seen: i64,
    status: EntryStatus,
    /// Whether the current raw ENR may be relayed in FINDNODE responses.
    /// This proof is tied to that ENR's advertised UDP endpoint.
    raw_enr_relay_eligible: bool = false,
    /// Whether the embedding application explicitly trusted the current raw
    /// ENR's advertised endpoint.
    advertised_endpoint_trusted: bool = false,
    /// Whether the runtime contact in `addr` was explicitly configured. This
    /// is independent of the endpoint advertised by the current raw ENR.
    runtime_contact_trusted: bool = false,
    /// Actor-owned health schedule and the exact maintenance request, if any.
    next_ping_at_ns: i64 = 0,
    health_request: ?RequestKey = null,

    pub fn enrBytes(self: *const Entry) []const u8 {
        return self.enr.slice();
    }

    pub fn relayableEnr(self: *const Entry) ?[]const u8 {
        if (!self.raw_enr_relay_eligible) return null;
        return self.enrBytes();
    }

    pub fn advertisesAddress(self: *const Entry, address: Address) bool {
        const advertised = switch (address) {
            .ip4 => self.advertised_addr4,
            .ip6 => self.advertised_addr6,
        };
        return if (advertised) |value| value.eql(&address) else false;
    }
};

pub const InsertOutcome = struct {
    inserted: bool,
    pending_eviction: ?Entry = null,
};

const PendingReplacement = struct {
    entry: Entry,
    inserted_at_ns: i64,
};

pub const KBucket = struct {
    entries: [K]Entry,
    count: usize,
    first_connected_index: ?usize,
    pending: ?PendingReplacement,

    pub fn init() KBucket {
        return .{
            .entries = undefined,
            .count = 0,
            .first_connected_index = null,
            .pending = null,
        };
    }

    pub fn insert(self: *KBucket, entry: Entry) bool {
        return self.insertDetailed(entry).inserted;
    }

    pub fn insertDetailed(self: *KBucket, entry: Entry) InsertOutcome {
        if (self.pending) |*pending| {
            if (std.mem.eql(u8, &pending.entry.node_id, &entry.node_id)) {
                // Updating the pending node refreshes mutable ENR/session
                // metadata only. The fixed insertion/probe deadline must not
                // restart, or a pending peer could hold the bucket's sole
                // replacement slot indefinitely with periodic traffic.
                pending.entry = entry;
                return .{ .inserted = true };
            }
        }

        for (self.entries[0..self.count], 0..) |existing, i| {
            if (!std.mem.eql(u8, &existing.node_id, &entry.node_id)) continue;
            if (i == 0 and entry.status == .connected) {
                self.pending = null;
            }
            _ = self.removeAt(i);
            self.insertOrdered(entry);
            return .{ .inserted = true };
        }

        if (self.count < K) {
            self.insertOrdered(entry);
            return .{ .inserted = true };
        }

        if (entry.status == .connected or entry.status == .pending) {
            if (self.first_connected_index != 0 and self.pending == null) {
                const pending_eviction = self.entries[0];
                self.pending = .{
                    .entry = entry,
                    .inserted_at_ns = entry.last_seen,
                };
                return .{ .inserted = false, .pending_eviction = pending_eviction };
            }
        }

        return .{ .inserted = false };
    }

    pub fn remove(self: *KBucket, node_id: *const NodeId) bool {
        if (self.pending) |pending| {
            if (std.mem.eql(u8, &pending.entry.node_id, node_id)) {
                self.pending = null;
                return true;
            }
        }

        for (self.entries[0..self.count], 0..) |e, i| {
            if (!std.mem.eql(u8, &e.node_id, node_id)) continue;
            _ = self.removeAt(i);
            self.maybeInsertPending();
            return true;
        }
        return false;
    }

    pub fn get(self: *const KBucket, node_id: *const NodeId) ?*const Entry {
        for (self.entries[0..self.count]) |*entry| {
            if (std.mem.eql(u8, &entry.node_id, node_id)) return entry;
        }
        return null;
    }

    pub fn getWithPending(self: *const KBucket, node_id: *const NodeId) ?*const Entry {
        if (self.get(node_id)) |entry| return entry;
        if (self.pending) |*pending| {
            if (std.mem.eql(u8, &pending.entry.node_id, node_id)) return &pending.entry;
        }
        return null;
    }

    /// Mutable access for actor-owned schedule metadata (`health_request`,
    /// `next_ping_at_ns`). Callers must not change identity, status, or any
    /// ordering-relevant field through this pointer.
    pub fn getMutWithPending(self: *KBucket, node_id: *const NodeId) ?*Entry {
        for (self.entries[0..self.count]) |*entry| {
            if (std.mem.eql(u8, &entry.node_id, node_id)) return entry;
        }
        if (self.pending) |*pending| {
            if (std.mem.eql(u8, &pending.entry.node_id, node_id)) return &pending.entry;
        }
        return null;
    }

    pub fn applyPendingIfExpired(self: *KBucket, now_ns: i64, timeout_ms: u64) bool {
        const pending = self.pending orelse return false;
        const elapsed_ns: i128 = @as(i128, now_ns) - @as(i128, pending.inserted_at_ns);
        const timeout_ns: i128 = @as(i128, timeout_ms) * std.time.ns_per_ms;
        if (elapsed_ns < timeout_ns) return false;

        self.pending = null;

        if (self.count < K) {
            self.insertOrdered(pending.entry);
            return true;
        }

        if (self.first_connected_index == 0) {
            return false;
        }

        _ = self.removeAt(0);
        self.insertOrdered(pending.entry);
        return true;
    }

    /// Drop the pending replacement after its eviction candidate proved
    /// liveness. Kademlia keeps a responsive incumbent over the newcomer.
    pub fn resolvePendingAgainst(self: *KBucket, candidate_id: *const NodeId) void {
        if (self.pending == null) return;
        const entry = self.get(candidate_id) orelse return;
        if (entry.status == .connected) self.pending = null;
    }

    fn maybeInsertPending(self: *KBucket) void {
        if (self.count >= K) return;
        const pending = self.pending orelse return;
        self.pending = null;
        self.insertOrdered(pending.entry);
    }

    fn removeAt(self: *KBucket, index: usize) Entry {
        const removed = self.entries[index];
        if (index + 1 < self.count) {
            @memmove(self.entries[index .. self.count - 1], self.entries[index + 1 .. self.count]);
        }
        self.count -= 1;

        switch (removed.status) {
            .connected => {
                if (self.first_connected_index) |first| {
                    if (first >= self.count) self.first_connected_index = null;
                }
            },
            .disconnected, .pending => {
                if (self.first_connected_index) |*first| {
                    first.* -= 1;
                }
            },
        }

        return removed;
    }

    fn insertOrdered(self: *KBucket, entry: Entry) void {
        switch (entry.status) {
            .connected => {
                self.entries[self.count] = entry;
                if (self.first_connected_index == null) {
                    self.first_connected_index = self.count;
                }
            },
            .disconnected, .pending => {
                const insert_at = self.first_connected_index orelse self.count;
                if (insert_at < self.count) {
                    @memmove(self.entries[insert_at + 1 .. self.count + 1], self.entries[insert_at..self.count]);
                }
                self.entries[insert_at] = entry;
                if (self.first_connected_index) |*first| {
                    first.* += 1;
                }
                self.count += 1;
                return;
            },
        }
        self.count += 1;
    }
};

/// XOR distance bit index: returns 0..255 or null if equal
pub fn logDistance(a: *const NodeId, b: *const NodeId) ?u8 {
    for (a, b, 0..) |ab, bb, i| {
        const xor = ab ^ bb;
        if (xor != 0) {
            const bit = @as(u8, 7) - @as(u8, @intCast(@clz(xor)));
            return @as(u8, @intCast((31 - i) * 8)) + bit;
        }
    }
    return null;
}

/// Raw XOR of two NodeIds
pub fn xorDistance(a: *const NodeId, b: *const NodeId) NodeId {
    var result: NodeId = undefined;
    for (result[0..], a, b) |*r, aa, bb| {
        r.* = aa ^ bb;
    }
    return result;
}

pub const RoutingTable = struct {
    local_id: NodeId,
    buckets: *[NUM_BUCKETS]KBucket,

    pub fn init(alloc: std.mem.Allocator, local_id: NodeId) !RoutingTable {
        const buckets = try alloc.create([NUM_BUCKETS]KBucket);
        for (buckets) |*bucket| {
            bucket.* = KBucket.init();
        }
        return .{
            .local_id = local_id,
            .buckets = buckets,
        };
    }

    pub fn deinit(self: *RoutingTable, alloc: std.mem.Allocator) void {
        alloc.destroy(self.buckets);
        self.* = undefined;
    }

    pub fn insert(self: *RoutingTable, entry: Entry) bool {
        return self.insertDetailed(entry).inserted;
    }

    pub fn insertDetailed(self: *RoutingTable, entry: Entry) InsertOutcome {
        const dist = logDistance(&self.local_id, &entry.node_id) orelse return .{ .inserted = false };
        return self.buckets[dist].insertDetailed(entry);
    }

    pub fn remove(self: *RoutingTable, node_id: *const NodeId) bool {
        const dist = logDistance(&self.local_id, node_id) orelse return false;
        return self.buckets[dist].remove(node_id);
    }

    pub fn getEntry(self: *const RoutingTable, node_id: *const NodeId) ?*const Entry {
        const dist = logDistance(&self.local_id, node_id) orelse return null;
        return self.buckets[dist].get(node_id);
    }

    pub fn getEntryWithPending(self: *const RoutingTable, node_id: *const NodeId) ?*const Entry {
        const dist = logDistance(&self.local_id, node_id) orelse return null;
        return self.buckets[dist].getWithPending(node_id);
    }

    /// Mutable access for actor-owned schedule metadata only; see
    /// `KBucket.getMutWithPending` for the field contract.
    pub fn getEntryMutWithPending(self: *RoutingTable, node_id: *const NodeId) ?*Entry {
        const dist = logDistance(&self.local_id, node_id) orelse return null;
        return self.buckets[dist].getMutWithPending(node_id);
    }

    pub fn findClosestNodeIds(self: *const RoutingTable, target: *const NodeId, comptime n: usize, out: *[n]NodeId) usize {
        var count: usize = 0;
        if (n == 0) return 0;

        for (self.buckets) |*bucket| {
            for (bucket.entries[0..bucket.count]) |e| {
                insertClosestNodeId(target, e.node_id, out[0..], &count);
            }
        }

        return count;
    }

    pub fn getBucket(self: *const RoutingTable, distance: u8) []const Entry {
        return self.buckets[distance].entries[0..self.buckets[distance].count];
    }

    pub fn nodeCount(self: *const RoutingTable) usize {
        var total: usize = 0;
        for (self.buckets) |*b| total += b.count;
        return total;
    }
};

fn insertClosestNodeId(target: *const NodeId, candidate: NodeId, out: []NodeId, count: *usize) void {
    const candidate_distance = xorDistance(target, &candidate);

    var insert_at = count.*;
    for (out[0..count.*], 0..) |node_id, i| {
        const entry_distance = xorDistance(target, &node_id);
        if (std.mem.lessThan(u8, &candidate_distance, &entry_distance)) {
            insert_at = i;
            break;
        }
    }

    if (insert_at >= out.len) return;

    const new_count = if (count.* < out.len) count.* + 1 else count.*;
    if (insert_at + 1 < new_count) {
        @memmove(out[insert_at + 1 .. new_count], out[insert_at .. new_count - 1]);
    }
    out[insert_at] = candidate;
    count.* = new_count;
}
