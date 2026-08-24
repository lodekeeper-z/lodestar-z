const std = @import("std");
const kbucket = @import("kbucket.zig");

const Address = std.Io.net.IpAddress;
const Entry = kbucket.Entry;
const EntryStatus = kbucket.EntryStatus;
const K = kbucket.K;
const KBucket = kbucket.KBucket;
const NodeId = @import("enr.zig").NodeId;
const message = @import("protocol/message.zig");
const types = @import("types.zig");
const RoutingTable = kbucket.RoutingTable;
const logDistance = kbucket.logDistance;

test "kbucket: logDistance" {
    const a: NodeId = [_]u8{0} ** 32;
    var b: NodeId = [_]u8{0} ** 32;

    try std.testing.expect(logDistance(&a, &b) == null);

    b[31] = 1;
    try std.testing.expectEqual(@as(?u8, 0), logDistance(&a, &b));

    b[31] = 0x80;
    try std.testing.expectEqual(@as(?u8, 7), logDistance(&a, &b));

    b = [_]u8{0} ** 32;
    b[0] = 0x80;
    try std.testing.expectEqual(@as(?u8, 255), logDistance(&a, &b));
}

test "kbucket: routing table insert/find" {
    const alloc = std.testing.allocator;
    const local: NodeId = [_]u8{0xaa} ** 32;
    var rt = try RoutingTable.init(alloc, local);
    defer rt.deinit(alloc);

    for (1..10) |i| {
        var node_id: NodeId = [_]u8{0xaa} ** 32;
        node_id[31] = @intCast(i);
        const entry = Entry{
            .node_id = node_id,
            .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0x2328 } },
            .last_seen = 0,
            .status = .connected,
        };
        _ = rt.insert(entry);
    }

    try std.testing.expectEqual(@as(usize, 9), rt.nodeCount());

    const target: NodeId = [_]u8{0xbb} ** 32;
    var out: [5]NodeId = undefined;
    const found = rt.findClosestNodeIds(&target, 5, &out);
    try std.testing.expect(found <= 5);
}

test "kbucket: routing table findClosestNodeIds uses bounded stack storage" {
    const alloc = std.testing.allocator;
    const local: NodeId = [_]u8{0xff} ** 32;
    var rt = try RoutingTable.init(alloc, local);
    defer rt.deinit(alloc);

    for ([_]u8{ 4, 1, 3, 2 }) |last_byte| {
        var node_id: NodeId = [_]u8{0} ** 32;
        node_id[31] = last_byte;
        try std.testing.expect(rt.insert(.{
            .node_id = node_id,
            .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = last_byte } },
            .last_seen = 0,
            .status = .connected,
        }));
    }

    const target: NodeId = [_]u8{0} ** 32;
    var out: [3]NodeId = undefined;
    const found = rt.findClosestNodeIds(&target, 3, &out);

    try std.testing.expectEqual(@as(usize, 3), found);
    try std.testing.expectEqual(@as(u8, 1), out[0][31]);
    try std.testing.expectEqual(@as(u8, 2), out[1][31]);
    try std.testing.expectEqual(@as(u8, 3), out[2][31]);
}

test "kbucket: full bucket stores pending connected entry until timeout" {
    var bucket = KBucket.init();

    for (0..K) |i| {
        var node_id: NodeId = [_]u8{0} ** 32;
        node_id[31] = @intCast(i);
        _ = bucket.insert(Entry{
            .node_id = node_id,
            .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } },
            .last_seen = @intCast(i),
            .status = .disconnected,
        });
    }
    try std.testing.expectEqual(@as(usize, K), bucket.count);

    const inserted = bucket.insert(Entry{
        .node_id = [_]u8{0xff} ** 32,
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 1 } },
        .last_seen = std.time.ns_per_ms,
        .status = .connected,
    });
    try std.testing.expect(!inserted);
    try std.testing.expect(bucket.pending != null);
    try std.testing.expectEqualDeep([_]u8{0xff} ** 32, bucket.pending.?.entry.node_id);

    try std.testing.expect(bucket.applyPendingIfExpired(std.time.ns_per_ms * 2, 1));
    try std.testing.expect(bucket.pending == null);
    try std.testing.expectEqualDeep([_]u8{0xff} ** 32, bucket.entries[K - 1].node_id);
    try std.testing.expectEqual(@as(usize, K), bucket.count);
}

test "kbucket: full bucket does not evict connected peers" {
    var bucket = KBucket.init();

    for (0..K) |i| {
        var node_id: NodeId = [_]u8{0} ** 32;
        node_id[31] = @intCast(i);
        _ = bucket.insert(Entry{
            .node_id = node_id,
            .addr = .{ .ip4 = .{ .bytes = .{ 10, 0, 0, 1 }, .port = 0 } },
            .last_seen = @intCast(i),
            .status = .connected,
        });
    }

    const inserted = bucket.insert(Entry{
        .node_id = [_]u8{0xee} ** 32,
        .addr = .{ .ip4 = .{ .bytes = .{ 10, 0, 0, 2 }, .port = 0 } },
        .last_seen = -1,
        .status = .pending,
    });
    try std.testing.expect(!inserted);
    try std.testing.expect(bucket.pending == null);
}

test "kbucket: updating existing node does not grow bucket" {
    var bucket = KBucket.init();
    const node_id: NodeId = [_]u8{0x42} ** 32;

    try std.testing.expect(bucket.insert(.{
        .node_id = node_id,
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0x2328 } },
        .last_seen = 1,
        .status = .pending,
    }));
    try std.testing.expect(bucket.insert(.{
        .node_id = node_id,
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 2 }, .port = 0x2329 } },
        .last_seen = 2,
        .status = .connected,
    }));

    try std.testing.expectEqual(@as(usize, 1), bucket.count);
    try std.testing.expectEqualDeep(@as(Address, .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 2 }, .port = 0x2329 } }), bucket.entries[0].addr);
    try std.testing.expectEqual(EntryStatus.connected, bucket.entries[0].status);
}

test "kbucket: refreshing the pending node preserves the original eviction deadline" {
    var bucket = KBucket.init();

    for (0..K) |i| {
        var node_id: NodeId = [_]u8{0} ** 32;
        node_id[31] = @intCast(i);
        _ = bucket.insert(Entry{
            .node_id = node_id,
            .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } },
            .last_seen = @intCast(i),
            .status = .disconnected,
        });
    }

    const pending_id: NodeId = [_]u8{0xaa} ** 32;
    const t0: i64 = 1_000;
    const timeout_ms: u64 = 1;
    const timeout_ns: i64 = @intCast(timeout_ms * std.time.ns_per_ms);
    try std.testing.expect(!bucket.insert(.{
        .node_id = pending_id,
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 2 }, .port = 1 } },
        .last_seen = t0,
        .status = .connected,
    }));
    try std.testing.expect(bucket.pending != null);
    try std.testing.expectEqual(t0, bucket.pending.?.inserted_at_ns);

    // Authenticated traffic repeatedly refreshes the pending peer's record
    // just before every expiry; the fixed insertion deadline must not move.
    var refresh_time: i64 = t0;
    for (0..4) |_| {
        refresh_time += @divTrunc(timeout_ns, 2);
        try std.testing.expect(bucket.insert(.{
            .node_id = pending_id,
            .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 2 }, .port = 1 } },
            .last_seen = refresh_time,
            .status = .connected,
        }));
        try std.testing.expectEqual(t0, bucket.pending.?.inserted_at_ns);
        try std.testing.expectEqual(refresh_time, bucket.pending.?.entry.last_seen);
    }

    // Resolution still occurs exactly at t0 + timeout.
    try std.testing.expect(!bucket.applyPendingIfExpired(t0 + timeout_ns - 1, timeout_ms));
    try std.testing.expect(bucket.applyPendingIfExpired(t0 + timeout_ns, timeout_ms));
    try std.testing.expect(bucket.pending == null);
    try std.testing.expectEqualDeep(pending_id, bucket.entries[K - 1].node_id);

    // The pending slot is available again for a later candidate.
    const next_candidate: NodeId = [_]u8{0xbb} ** 32;
    try std.testing.expect(!bucket.insert(.{
        .node_id = next_candidate,
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 3 }, .port = 2 } },
        .last_seen = t0 + timeout_ns + 1,
        .status = .connected,
    }));
    try std.testing.expect(bucket.pending != null);
    try std.testing.expectEqualDeep(next_candidate, bucket.pending.?.entry.node_id);
    try std.testing.expectEqual(t0 + timeout_ns + 1, bucket.pending.?.inserted_at_ns);
}

test "kbucket: ticketed incumbent liveness clears pending replacement" {
    var bucket = KBucket.init();

    for (0..K) |i| {
        var node_id: NodeId = [_]u8{0} ** 32;
        node_id[31] = @intCast(i);
        _ = bucket.insert(Entry{
            .node_id = node_id,
            .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } },
            .last_seen = @intCast(i),
            .status = .disconnected,
        });
    }

    const pending_id: NodeId = [_]u8{0xaa} ** 32;
    const outcome = bucket.insertDetailed(.{
        .node_id = pending_id,
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 2 }, .port = 1 } },
        .last_seen = 100,
        .status = .connected,
    });
    try std.testing.expect(!outcome.inserted);
    const probe = outcome.pending_eviction orelse return error.MissingEvictionProbe;

    const oldest_id = bucket.entries[0].node_id;
    const key = types.RequestKey.init(
        .{ .node_id = oldest_id, .addr = bucket.entries[0].addr },
        try message.ReqId.fromSlice(&.{1}),
    );
    try std.testing.expect(bucket.bindPendingRequest(probe.ticket, key));
    try std.testing.expect(bucket.insert(.{
        .node_id = oldest_id,
        .addr = key.endpoint.addr,
        .last_seen = 101,
        .status = .connected,
    }));
    try std.testing.expect(bucket.resolvePending(probe.ticket, key));

    try std.testing.expect(bucket.pending == null);
    try std.testing.expectEqual(EntryStatus.connected, bucket.entries[K - 1].status);
}

test "kbucket: pending expiry evicts the exact incumbent after reordering" {
    var bucket = KBucket.init();

    for (0..K) |i| {
        var node_id: NodeId = [_]u8{0} ** 32;
        node_id[31] = @intCast(i);
        try std.testing.expect(bucket.insert(.{
            .node_id = node_id,
            .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = @intCast(i) } },
            .last_seen = @intCast(i),
            .status = .disconnected,
        }));
    }

    const incumbent_id = bucket.entries[0].node_id;
    const newcomer_id = [_]u8{0xff} ** 32;
    const inserted_at_ns: i64 = 1_000;
    const outcome = bucket.insertDetailed(.{
        .node_id = newcomer_id,
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 2 }, .port = 9_000 } },
        .last_seen = inserted_at_ns,
        .status = .connected,
    });
    try std.testing.expect(!outcome.inserted);
    try std.testing.expectEqualDeep(incumbent_id, outcome.pending_eviction.?.entry.node_id);

    // Metadata refresh reorders the probed incumbent behind another
    // disconnected peer. Expiry must still remove the peer selected when the
    // replacement ticket was created, never the new entries[0].
    var reordered = bucket.get(&incumbent_id).?.*;
    reordered.last_seen += 1;
    try std.testing.expect(bucket.insert(reordered));
    const unprobed_oldest_id = bucket.entries[0].node_id;
    try std.testing.expect(!std.mem.eql(u8, &unprobed_oldest_id, &incumbent_id));

    try std.testing.expect(bucket.applyPendingIfExpired(inserted_at_ns + std.time.ns_per_ms, 1));
    try std.testing.expect(bucket.get(&incumbent_id) == null);
    try std.testing.expect(bucket.get(&unprobed_oldest_id) != null);
    try std.testing.expect(bucket.get(&newcomer_id) != null);
}
