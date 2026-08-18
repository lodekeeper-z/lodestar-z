const std = @import("std");
const admission = @import("../admission.zig");
const message = @import("../protocol/message.zig");
const book_mod = @import("request_book.zig");
const types = @import("../types.zig");
const config_mod = @import("../config.zig");

const limits = @import("../config.zig").Limits{
    .max_active_requests = 4,
    .max_queued_requests = 4,
    .max_queued_requests_per_endpoint = 2,
};

fn endpoint(last: u8) types.Endpoint {
    return .{
        .node_id = [_]u8{last} ** 32,
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, last }, .port = 9000 } },
    };
}

fn probe(nonce_byte: u8) !book_mod.AwaitingWhoareyou {
    return .{
        .retry_packet = try .init(&.{ 3, 4 }),
        .recovery = .{
            .nonce = [_]u8{nonce_byte} ** 12,
            .dest_pubkey = [_]u8{2} ** 33,
            .plaintext = try .init(&.{ 1, 2 }),
        },
    };
}

test "response waits preserve challenge and pending-key behavior across retries and promotion" {
    var ingress = try admission.IngressAdmission.init(std.testing.allocator, null, limits.max_active_requests);
    defer ingress.deinit();
    var book = try book_mod.RequestBook.init(std.testing.allocator, limits);
    defer book.deinit(&ingress);
    const keys = book_mod.PendingSessionKeys{
        .initiator_key = [_]u8{10} ** 16,
        .recipient_key = [_]u8{11} ** 16,
    };

    const promoted_retry = types.RequestKey.init(endpoint(1), try message.ReqId.fromSlice(&.{1}));
    const promoted_prepared = try book.prepareActive(
        &ingress,
        promoted_retry,
        .api,
        .pong,
        .{ .awaiting_whoareyou = try probe(20) },
        1,
        true,
    );
    book.commitPrepared(promoted_prepared);
    book.commitChallenge(try book.challenge(&([_]u8{20} ** 12), promoted_retry.endpoint.addr), keys, 2);
    try std.testing.expect(book.pendingKeys(promoted_retry.endpoint) != null);
    try std.testing.expectError(error.InvalidChallenge, book.challenge(&([_]u8{20} ** 12), promoted_retry.endpoint.addr));

    var retry_permit = try ingress.acquire(promoted_retry.endpoint.addr, admission.requestPacketBudget(.ping));
    book.commitFreshRetry(promoted_retry, .{ .response = [_]u8{21} ** 12 }, 3, retry_permit.move(), &ingress);
    const retry_pending = book.pendingKeys(promoted_retry.endpoint) orelse return error.MissingPendingKeys;
    try std.testing.expectEqual(keys, retry_pending.keys);
    _ = try book.challenge(&([_]u8{21} ** 12), promoted_retry.endpoint.addr);
    book.promotePending(retry_pending);
    try std.testing.expect(book.pendingKeys(promoted_retry.endpoint) == null);
    _ = try book.challenge(&([_]u8{21} ** 12), promoted_retry.endpoint.addr);

    const confirmed_retry = types.RequestKey.init(endpoint(2), try message.ReqId.fromSlice(&.{2}));
    const confirmed_prepared = try book.prepareActive(
        &ingress,
        confirmed_retry,
        .api,
        .pong,
        .{ .awaiting_whoareyou = try probe(30) },
        1,
        true,
    );
    book.commitPrepared(confirmed_prepared);
    book.commitChallenge(try book.challenge(&([_]u8{30} ** 12), confirmed_retry.endpoint.addr), keys, 2);
    const confirmed_pending = book.pendingKeys(confirmed_retry.endpoint) orelse return error.MissingPendingKeys;
    book.promotePending(confirmed_pending);
    try std.testing.expect(book.pendingKeys(confirmed_retry.endpoint) == null);
    try std.testing.expectError(error.InvalidChallenge, book.challenge(&([_]u8{30} ** 12), confirmed_retry.endpoint.addr));

    var confirmed_permit = try ingress.acquire(confirmed_retry.endpoint.addr, admission.requestPacketBudget(.ping));
    book.commitFreshRetry(confirmed_retry, .{ .response = [_]u8{31} ** 12 }, 3, confirmed_permit.move(), &ingress);
    try std.testing.expect(book.pendingKeys(confirmed_retry.endpoint) == null);
    _ = try book.challenge(&([_]u8{31} ** 12), confirmed_retry.endpoint.addr);
}

test "RequestBook conserves challenge lane active and admission indexes" {
    var ingress = try admission.IngressAdmission.init(std.testing.allocator, null, limits.max_active_requests);
    defer ingress.deinit();
    var book = try book_mod.RequestBook.init(std.testing.allocator, limits);
    defer book.deinit(&ingress);
    const key = types.RequestKey.init(endpoint(1), try message.ReqId.fromSlice(&.{}));
    const prepared = try book.prepareActive(
        &ingress,
        key,
        .api,
        .pong,
        .{ .awaiting_whoareyou = try probe(7) },
        1,
        true,
    );
    book.commitPrepared(prepared);
    book.assertInvariants();
    try std.testing.expectEqual(@as(usize, 1), ingress.permitCount());
    const challenge = try book.challenge(&([_]u8{7} ** 12), key.endpoint.addr);
    book.commitChallenge(challenge, .{
        .initiator_key = [_]u8{10} ** 16,
        .recipient_key = [_]u8{11} ** 16,
    }, 2);
    const pending = book.pendingKeys(key.endpoint) orelse return error.MissingPendingKeys;
    try std.testing.expect(types.RequestKeyContext.eql(.{}, pending.key, key));
    book.promotePending(pending);
    try std.testing.expect(book.pendingKeys(key.endpoint) == null);
    var removed = book.take(key) orelse return error.MissingActiveRequest;
    removed.admission.release(&ingress);
    removed.deinit(std.testing.allocator);
    book.assertInvariants();
    try std.testing.expectEqual(@as(usize, 0), ingress.permitCount());
}

test "WHOAREYOU phase changes preserve the cumulative retry bound" {
    var ingress = try admission.IngressAdmission.init(std.testing.allocator, null, limits.max_active_requests);
    defer ingress.deinit();
    var book = try book_mod.RequestBook.init(std.testing.allocator, limits);
    defer book.deinit(&ingress);
    const key = types.RequestKey.init(endpoint(12), try message.ReqId.fromSlice(&.{1}));
    const prepared = try book.prepareActive(
        &ingress,
        key,
        .api,
        .pong,
        .{ .awaiting_whoareyou = try probe(12) },
        1,
        true,
    );
    book.commitPrepared(prepared);
    book.commitRetry(key, 2);
    try std.testing.expectEqual(@as(u32, 1), book.get(key).?.attempts);

    const challenge = try book.challenge(&([_]u8{12} ** 12), key.endpoint.addr);
    book.commitChallenge(challenge, .{
        .initiator_key = [_]u8{10} ** 16,
        .recipient_key = [_]u8{11} ** 16,
    }, 3);
    try std.testing.expectEqual(@as(u32, 1), book.get(key).?.attempts);

    var removed = book.take(key) orelse return error.MissingActiveRequest;
    removed.admission.release(&ingress);
    removed.deinit(std.testing.allocator);
}

test "RequestBook keeps every request queued xor active in FIFO order" {
    var ingress = try admission.IngressAdmission.init(std.testing.allocator, null, limits.max_active_requests);
    defer ingress.deinit();
    var book = try book_mod.RequestBook.init(std.testing.allocator, limits);
    defer book.deinit(&ingress);
    const peer = endpoint(2);
    const pubkey = [_]u8{3} ** 33;
    const first = try message.ReqId.fromSlice(&.{1});
    const second = try message.ReqId.fromSlice(&.{2});
    try book.queue(try .init(.api, peer, &pubkey, first, .ping, &.{}, &.{1}, 0));
    try book.queue(try .init(.api, peer, &pubkey, second, .ping, &.{}, &.{1}, 0));
    try std.testing.expectEqualSlices(u8, first.slice(), book.firstQueued(peer).?.req_id.slice());
    const prepared = try book.prepareActive(&ingress, .init(peer, first), .api, .pong, .{
        .awaiting_whoareyou = try probe(8),
    }, 0, true);
    book.commitQueued(prepared);
    book.assertInvariants();
    try std.testing.expect(book.firstQueued(peer) == null);
    var removed = book.take(.init(peer, first)).?;
    removed.admission.release(&ingress);
    removed.deinit(std.testing.allocator);
    try std.testing.expectEqualSlices(u8, second.slice(), book.firstQueued(peer).?.req_id.slice());
}

test "RequestBook takes an exact queued request without disturbing lane FIFO" {
    var ingress = try admission.IngressAdmission.init(std.testing.allocator, null, limits.max_active_requests);
    defer ingress.deinit();
    var book = try book_mod.RequestBook.init(std.testing.allocator, limits);
    defer book.deinit(&ingress);
    const peer = endpoint(11);
    const pubkey = [_]u8{4} ** 33;
    const first = try message.ReqId.fromSlice(&.{1});
    const second = try message.ReqId.fromSlice(&.{2});
    try book.queue(try .init(.api, peer, &pubkey, first, .ping, &.{}, &.{1}, 10));
    try book.queue(try .init(.api, peer, &pubkey, second, .ping, &.{}, &.{2}, 10));

    const removed = book.takeQueued(.init(peer, second)) orelse return error.MissingQueuedRequest;
    try std.testing.expectEqualSlices(u8, second.slice(), removed.req_id.slice());
    try std.testing.expectEqual(@as(usize, 1), book.queuedCount());
    try std.testing.expectEqualSlices(u8, first.slice(), book.firstQueued(peer).?.req_id.slice());
    _ = book.takeQueued(.init(peer, first)) orelse return error.MissingFirstRequest;
    try std.testing.expectEqual(@as(usize, 0), book.queuedCount());
    try std.testing.expect(book.firstQueued(peer) == null);
    book.assertInvariants();
}

test "queued expiry removes mixed requests across lanes and preserves live FIFO order" {
    const scan_limits = config_mod.Limits{
        .max_active_requests = 1,
        .max_queued_requests = 24,
        .max_queued_requests_per_endpoint = config_mod.MAX_QUEUED_PER_ENDPOINT,
    };
    var ingress = try admission.IngressAdmission.init(std.testing.allocator, null, 1);
    defer ingress.deinit();
    var book = try book_mod.RequestBook.init(std.testing.allocator, scan_limits);
    defer book.deinit(&ingress);
    const pubkey = [_]u8{4} ** 33;
    const now_ns: i64 = 100;

    for (0..24) |index| {
        const lane = if (index < 16) endpoint(20) else if (index < 21) endpoint(21) else endpoint(22);
        const expired = index < 12 or (index >= 16 and index < 21);
        try book.queue(try .init(
            .api,
            lane,
            &pubkey,
            try message.ReqId.fromSlice(&.{@intCast(index)}),
            .ping,
            &.{},
            &.{1},
            if (expired) now_ns else now_ns + 1,
        ));
    }

    var removed = [_]bool{false} ** 24;
    var removed_count: usize = 0;
    var scan = book_mod.RequestBook.QueuedScan{};
    var keys: [config_mod.MAX_QUEUED_PER_ENDPOINT]types.RequestKey = undefined;
    while (!scan.done) {
        const count = book.collectExpiredQueuedBatch(&keys, now_ns, &scan);
        for (keys[0..count]) |key| {
            const queued = book.takeQueued(key) orelse return error.MissingExpiredQueuedRequest;
            const index = queued.req_id.slice()[0];
            try std.testing.expect(!removed[index]);
            removed[index] = true;
            removed_count += 1;
        }
    }

    try std.testing.expectEqual(@as(usize, 17), removed_count);
    try std.testing.expectEqual(@as(usize, 7), book.queuedCount());
    for (removed, 0..) |was_removed, index| {
        try std.testing.expectEqual(index < 12 or (index >= 16 and index < 21), was_removed);
    }
    for (12..16) |index| {
        const queued = book.takeQueued(.init(endpoint(20), try message.ReqId.fromSlice(&.{@intCast(index)}))) orelse
            return error.MissingLiveQueuedRequest;
        try std.testing.expectEqual(@as(u8, @intCast(index)), queued.req_id.slice()[0]);
    }
    for (21..24) |index| {
        const queued = book.takeQueued(.init(endpoint(22), try message.ReqId.fromSlice(&.{@intCast(index)}))) orelse
            return error.MissingLiveQueuedRequest;
        try std.testing.expectEqual(@as(u8, @intCast(index)), queued.req_id.slice()[0]);
    }
    try std.testing.expectEqual(@as(usize, 0), book.queuedCount());
    book.assertInvariants();
}

test "round robin drain selection reaches lane seventeen while first batch remains" {
    const fair_limits = @import("../config.zig").Limits{
        .max_active_requests = 1,
        .max_queued_requests = 17,
        .max_queued_requests_per_endpoint = 1,
    };
    var ingress = try admission.IngressAdmission.init(std.testing.allocator, null, 1);
    defer ingress.deinit();
    var book = try book_mod.RequestBook.init(std.testing.allocator, fair_limits);
    defer book.deinit(&ingress);
    const pubkey = [_]u8{5} ** 33;
    for (1..18) |last| {
        const peer = endpoint(@intCast(last));
        try book.queue(try .init(
            .api,
            peer,
            &pubkey,
            try message.ReqId.fromSlice(&.{@intCast(last)}),
            .ping,
            &.{},
            &.{1},
            10,
        ));
    }

    var first_batch: [16]types.Endpoint = undefined;
    try std.testing.expectEqual(first_batch.len, book.collectDrainable(&first_batch));
    var selected = [_]bool{false} ** 17;
    for (first_batch) |peer| selected[peer.addr.ip4.bytes[3] - 1] = true;
    var skipped: u8 = 0;
    for (selected, 1..) |was_selected, last| {
        if (!was_selected) skipped = @intCast(last);
    }
    try std.testing.expect(skipped != 0);

    var second_batch: [16]types.Endpoint = undefined;
    try std.testing.expectEqual(second_batch.len, book.collectDrainable(&second_batch));
    var reached_skipped = false;
    for (second_batch) |peer| {
        if (peer.addr.ip4.bytes[3] == skipped) reached_skipped = true;
    }
    try std.testing.expect(reached_skipped);
    try std.testing.expectEqual(@as(usize, 17), book.queuedCount());
}

fn allocationLifecycle(alloc: std.mem.Allocator) !void {
    var ingress = try admission.IngressAdmission.init(alloc, null, limits.max_active_requests);
    defer ingress.deinit();
    var book = try book_mod.RequestBook.init(alloc, limits);
    defer book.deinit(&ingress);
    const key = types.RequestKey.init(endpoint(3), try message.ReqId.fromSlice(&.{1}));
    const prepared = try book.prepareActive(&ingress, key, .api, try book.makeResponse(.findnode, &.{1}), .{
        .awaiting_whoareyou = try probe(9),
    }, 0, true);
    book.commitPrepared(prepared);
    const challenge = try book.challenge(&([_]u8{9} ** 12), key.endpoint.addr);
    book.commitChallenge(challenge, .{
        .initiator_key = [_]u8{6} ** 16,
        .recipient_key = [_]u8{7} ** 16,
    }, 1);
    var removed = book.take(key).?;
    removed.admission.release(&ingress);
    removed.deinit(alloc);
}

test "RequestBook preparation and admission unwind every allocator failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationLifecycle, .{});
}

fn queueAllocationLifecycle(alloc: std.mem.Allocator) !void {
    var ingress = try admission.IngressAdmission.init(alloc, null, limits.max_active_requests);
    defer ingress.deinit();
    var book = try book_mod.RequestBook.init(alloc, limits);
    defer book.deinit(&ingress);
    const peer = endpoint(4);
    const pubkey = [_]u8{8} ** 33;
    try book.queue(try .init(.api, peer, &pubkey, try message.ReqId.fromSlice(&.{1}), .ping, &.{}, &.{1}, 10));
    try book.queue(try .init(.api, peer, &pubkey, try message.ReqId.fromSlice(&.{2}), .ping, &.{}, &.{2}, 10));
    book.assertInvariants();
}

test "RequestBook queue initialization unwinds every allocator failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, queueAllocationLifecycle, .{});
}

fn firstNodesAllocationLifecycle(alloc: std.mem.Allocator) !void {
    var response = book_mod.Response{ .nodes = try .init(alloc, &.{1}) };
    defer response.deinit(alloc);
    const copy = try alloc.dupe(u8, "enr");
    response.nodes.enrs.appendAssumeCapacity(copy);
}

test "first NODES storage allocation has complete failure cleanup" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, firstNodesAllocationLifecycle, .{});
}

test "NODES accumulator reserves the canonical response bound" {
    var accumulator = try book_mod.NodesAccumulator.init(std.testing.allocator, &.{1});
    defer accumulator.deinit(std.testing.allocator);
    try std.testing.expectEqual(book_mod.MAX_NODES_RESPONSE, accumulator.enrs.capacity);
}

test "final NODES completion moves list ownership without allocation" {
    var ingress = try admission.IngressAdmission.init(std.testing.allocator, null, limits.max_active_requests);
    defer ingress.deinit();
    var book = try book_mod.RequestBook.init(std.testing.allocator, limits);
    defer book.deinit(&ingress);
    const key = types.RequestKey.init(endpoint(5), try message.ReqId.fromSlice(&.{1}));
    var response = try book.makeResponse(.findnode, &.{1});
    response.nodes.enrs.appendAssumeCapacity(try std.testing.allocator.dupe(u8, "enr"));
    const prepared = try book.prepareActive(&ingress, key, .api, response, .{
        .awaiting_whoareyou = try probe(10),
    }, 10, true);
    book.commitPrepared(prepared);
    var removed = book.take(key).?;
    var moved = removed.response.nodes.enrs;
    removed.response.nodes.enrs = .empty;
    removed.admission.release(&ingress);
    removed.deinit(std.testing.allocator);
    defer moved.deinit(std.testing.allocator);
    defer for (moved.items) |bytes| std.testing.allocator.free(bytes);
    try std.testing.expectEqualStrings("enr", moved.items[0]);
}

test "challenge preparation and commit remain allocation-free" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    const alloc = failing.allocator();
    var ingress = try admission.IngressAdmission.init(alloc, null, limits.max_active_requests);
    defer ingress.deinit();
    var book = try book_mod.RequestBook.init(alloc, limits);
    defer book.deinit(&ingress);
    failing.fail_index = failing.alloc_index;
    const key = types.RequestKey.init(endpoint(6), try message.ReqId.fromSlice(&.{1}));
    const prepared = try book.prepareActive(&ingress, key, .api, .pong, .{
        .awaiting_whoareyou = try probe(11),
    }, 10, true);
    book.commitPrepared(prepared);
    const challenge = try book.challenge(&([_]u8{11} ** 12), key.endpoint.addr);
    book.commitChallenge(challenge, .{
        .initiator_key = [_]u8{1} ** 16,
        .recipient_key = [_]u8{2} ** 16,
    }, 20);
    try std.testing.expect(!failing.has_induced_failure);
}

test "timed-out active scan visits maximum-capacity table once across bounded batches" {
    const max_active = config_mod.MAX_ACTIVE_REQUESTS;
    const max_limits = config_mod.Limits{
        .max_active_requests = max_active,
        .max_queued_requests = 1,
        .max_queued_requests_per_endpoint = 1,
    };
    var ingress = try admission.IngressAdmission.init(std.testing.allocator, null, max_active);
    defer ingress.deinit();
    var book = try book_mod.RequestBook.init(std.testing.allocator, max_limits);
    defer book.deinit(&ingress);
    const now_ns: i64 = 10_000;

    for (0..max_active) |index| {
        var node_id = [_]u8{0} ** 32;
        std.mem.writeInt(u16, node_id[0..2], @intCast(index), .big);
        const peer = types.Endpoint{
            .node_id = node_id,
            .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = @intCast(10_000 + index) } },
        };
        const req_id = try message.ReqId.fromSlice(&.{});
        const phase = book_mod.Phase{ .awaiting_response = .{
            .recovery = .{
                .nonce = [_]u8{0} ** 12,
                .dest_pubkey = [_]u8{2} ** 33,
                .plaintext = try .init(&.{2}),
            },
            .wait = .session_request,
        } };
        const prepared = try book.prepareActive(&ingress, .init(peer, req_id), .api, .pong, phase, now_ns - 1, false);
        book.commitPrepared(prepared);
    }

    var scan = book_mod.RequestBook.ActiveScan{};
    var expired: usize = 0;
    var keys: [16]types.RequestKey = undefined;
    while (!scan.done) {
        const count = book.collectTimedOutBatch(&keys, now_ns, &scan);
        for (keys[0..count]) |key| {
            var active = book.take(key) orelse return error.MissingActiveRequest;
            active.admission.release(&ingress);
            active.deinit(std.testing.allocator);
            expired += 1;
        }
    }
    try std.testing.expectEqual(max_active, expired);
    try std.testing.expectEqual(@as(usize, 0), book.activeCount());
    try std.testing.expectEqual(book.activeSlotCapacity(), scan.slots_scanned);
}

test "RequestBook shutdown releases active permits and only deinitializes queued intents" {
    var ingress = try admission.IngressAdmission.init(std.testing.allocator, null, limits.max_active_requests);
    defer ingress.deinit();
    var book = try book_mod.RequestBook.init(std.testing.allocator, limits);
    const active_key = types.RequestKey.init(endpoint(7), try message.ReqId.fromSlice(&.{1}));
    const prepared = try book.prepareActive(&ingress, active_key, .api, .pong, .{
        .awaiting_whoareyou = try probe(12),
    }, 10, true);
    book.commitPrepared(prepared);
    const queued_endpoint = endpoint(8);
    const pubkey = [_]u8{8} ** 33;
    try book.queue(try .init(.api, queued_endpoint, &pubkey, try message.ReqId.fromSlice(&.{2}), .ping, &.{}, &.{1}, 10));
    try std.testing.expectEqual(@as(usize, 1), ingress.permitCount());
    book.deinit(&ingress);
    try std.testing.expectEqual(@as(usize, 0), ingress.permitCount());
}

test "lookup finish detaches active and queued requests without cancellation" {
    var ingress = try admission.IngressAdmission.init(std.testing.allocator, null, limits.max_active_requests);
    defer ingress.deinit();
    var book = try book_mod.RequestBook.init(std.testing.allocator, limits);
    defer book.deinit(&ingress);
    const active_key = types.RequestKey.init(endpoint(9), try message.ReqId.fromSlice(&.{1}));
    const prepared = try book.prepareActive(&ingress, active_key, .{ .lookup = 42 }, .pong, .{
        .awaiting_whoareyou = try probe(13),
    }, 10, true);
    book.commitPrepared(prepared);
    const queued_endpoint = endpoint(10);
    const pubkey = [_]u8{9} ** 33;
    try book.queue(try .init(.{ .lookup = 42 }, queued_endpoint, &pubkey, try message.ReqId.fromSlice(&.{2}), .ping, &.{}, &.{1}, 10));

    book.detachLookup(42);
    try std.testing.expectEqual(types.RequestOrigin.detached_lookup, book.get(active_key).?.origin);
    try std.testing.expectEqual(types.RequestOrigin.detached_lookup, book.firstQueued(queued_endpoint).?.origin);
    try std.testing.expectEqual(@as(usize, 1), book.activeCount());
    try std.testing.expectEqual(@as(usize, 1), book.queuedCount());
}
