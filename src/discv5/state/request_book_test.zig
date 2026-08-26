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

fn requestedDistances(distances: []const u16) book_mod.RequestDistances {
    return .fromSlice(distances);
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

fn beginActive(
    book: *book_mod.RequestBook,
    ingress: *admission.IngressAdmission,
    key: types.RequestKey,
    origin: types.RequestOrigin,
    response: book_mod.ResponseExpectation,
    phase: book_mod.Phase,
    deadline_ns: i64,
    establish: bool,
) !void {
    const handle = try book.beginSending(ingress, key, origin, response, phase, deadline_ns, establish, false);
    if (book.completeSending(handle) == null) return error.SendingCompletionRejected;
}

test "FINDNODE correlation stores bounded distance membership" {
    const distances = book_mod.RequestDistances.fromSlice(&.{ 256, 0, 256, 257, 1 });
    try std.testing.expect(distances.contains(0));
    try std.testing.expect(distances.contains(1));
    try std.testing.expect(distances.contains(256));
    try std.testing.expect(!distances.contains(2));
    try std.testing.expect(!distances.contains(257));
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
    try beginActive(
        &book,
        &ingress,
        promoted_retry,
        .api,
        .pong,
        .{ .awaiting_whoareyou = try probe(20) },
        1,
        true,
    );
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
    try beginActive(
        &book,
        &ingress,
        confirmed_retry,
        .api,
        .pong,
        .{ .awaiting_whoareyou = try probe(30) },
        1,
        true,
    );
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
    try beginActive(
        &book,
        &ingress,
        key,
        .api,
        .pong,
        .{ .awaiting_whoareyou = try probe(7) },
        1,
        true,
    );
    book.assertInvariants();
    try std.testing.expectEqual(@as(usize, 1), ingress.permitCount());
    const challenge = try book.challenge(&([_]u8{7} ** 12), key.endpoint.addr);
    book.commitChallenge(challenge, .{
        .initiator_key = [_]u8{10} ** 16,
        .recipient_key = [_]u8{11} ** 16,
    }, 2);
    const pending = book.pendingKeys(key.endpoint) orelse return error.MissingPendingKeys;
    try std.testing.expect(types.RequestKeyContext.eql(.{}, pending.handle.key, key));
    book.promotePending(pending);
    try std.testing.expect(book.pendingKeys(key.endpoint) == null);
    var removed = book.take(key) orelse return error.MissingActiveRequest;
    removed.admission.release(&ingress);
    book.assertInvariants();
    try std.testing.expectEqual(@as(usize, 0), ingress.permitCount());
}

test "WHOAREYOU phase changes preserve the cumulative retry bound" {
    var ingress = try admission.IngressAdmission.init(std.testing.allocator, null, limits.max_active_requests);
    defer ingress.deinit();
    var book = try book_mod.RequestBook.init(std.testing.allocator, limits);
    defer book.deinit(&ingress);
    const key = types.RequestKey.init(endpoint(12), try message.ReqId.fromSlice(&.{1}));
    try beginActive(
        &book,
        &ingress,
        key,
        .api,
        .pong,
        .{ .awaiting_whoareyou = try probe(12) },
        1,
        true,
    );
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
    try book.queue(try .init(.api, peer, &pubkey, first, .ping, &.{ 0, 256, 256 }, &.{1}, 0));
    try book.queue(try .init(.api, peer, &pubkey, second, .ping, &.{}, &.{1}, 0));
    try std.testing.expectEqualSlices(u8, first.slice(), book.firstQueued(peer).?.req_id.slice());
    try std.testing.expect(book.firstQueued(peer).?.requested_distances.contains(0));
    try std.testing.expect(book.firstQueued(peer).?.requested_distances.contains(256));
    try std.testing.expect(!book.firstQueued(peer).?.requested_distances.contains(1));
    const handle = try book.beginSending(&ingress, .init(peer, first), .api, .pong, .{
        .awaiting_whoareyou = try probe(8),
    }, 0, true, true);
    try std.testing.expect(book.completeSending(handle) != null);
    book.assertInvariants();
    try std.testing.expect(book.firstQueued(peer) == null);
    var removed = book.take(.init(peer, first)).?;
    removed.admission.release(&ingress);
    try std.testing.expectEqualSlices(u8, second.slice(), book.firstQueued(peer).?.req_id.slice());
}

test "terminal take consumes sending queued intent and rejects stale completions" {
    var ingress = try admission.IngressAdmission.init(std.testing.allocator, null, limits.max_active_requests);
    defer ingress.deinit();
    var book = try book_mod.RequestBook.init(std.testing.allocator, limits);
    defer book.deinit(&ingress);
    const peer = endpoint(39);
    const pubkey = [_]u8{39} ** 33;
    const req_id = try message.ReqId.fromSlice(&.{1});
    const key = types.RequestKey.init(peer, req_id);
    try book.queue(try .init(.api, peer, &pubkey, req_id, .ping, &.{}, &.{1}, 10));
    const handle = try book.beginSending(&ingress, key, .api, .pong, .{
        .awaiting_whoareyou = try probe(39),
    }, 10, true, true);

    var terminal = book.takeTerminal(key) orelse return error.MissingTerminalRequest;
    try std.testing.expect(terminal == .sending);
    terminal.release(&ingress);
    try std.testing.expectEqual(@as(usize, 0), book.activeCount());
    try std.testing.expectEqual(@as(usize, 0), book.sendingCount());
    try std.testing.expectEqual(@as(usize, 0), book.queuedCount());
    try std.testing.expectEqual(@as(usize, 0), ingress.permitCount());
    try std.testing.expectEqual(@as(usize, 0), book.challenge_by_nonce.count());
    try std.testing.expectEqual(@as(usize, 0), book.lanes.count());
    try std.testing.expect(book.completeSending(handle) == null);
    try std.testing.expect(book.abortSending(handle, &ingress) == null);
    book.assertInvariants();
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
    const requested = requestedDistances(&.{1});
    try beginActive(&book, &ingress, key, .api, book.makeExpectation(.findnode, &requested), .{
        .awaiting_whoareyou = try probe(9),
    }, 0, true);
    const challenge = try book.challenge(&([_]u8{9} ** 12), key.endpoint.addr);
    book.commitChallenge(challenge, .{
        .initiator_key = [_]u8{6} ** 16,
        .recipient_key = [_]u8{7} ** 16,
    }, 1);
    var removed = book.take(key).?;
    removed.admission.release(&ingress);
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

test "NODES response retains canonical requested distances without allocation" {
    var book = try book_mod.RequestBook.init(std.testing.allocator, limits);
    defer book.deinitEmpty();
    const requested = requestedDistances(&.{ 0, 256, 256 });
    const response = book.makeResponse(.findnode, &requested);
    try std.testing.expect(response.nodes.requested_distances.contains(0));
    try std.testing.expect(response.nodes.requested_distances.contains(256));
    try std.testing.expect(!response.nodes.requested_distances.contains(1));
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
    try beginActive(&book, &ingress, key, .api, .pong, .{
        .awaiting_whoareyou = try probe(11),
    }, 10, true);
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
        try beginActive(&book, &ingress, .init(peer, req_id), .api, .pong, phase, now_ns - 1, false);
    }

    var scan = book_mod.RequestBook.ActiveScan{};
    var expired: usize = 0;
    var keys: [16]types.RequestKey = undefined;
    while (!scan.done) {
        const count = book.collectTimedOutBatch(&keys, now_ns, &scan);
        for (keys[0..count]) |key| {
            var active = book.take(key) orelse return error.MissingActiveRequest;
            active.admission.release(&ingress);
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
    try beginActive(&book, &ingress, active_key, .api, .pong, .{
        .awaiting_whoareyou = try probe(12),
    }, 10, true);
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
    try beginActive(&book, &ingress, active_key, .{ .lookup = 42 }, .pong, .{
        .awaiting_whoareyou = try probe(13),
    }, 10, true);
    const queued_endpoint = endpoint(10);
    const pubkey = [_]u8{9} ** 33;
    try book.queue(try .init(.{ .lookup = 42 }, queued_endpoint, &pubkey, try message.ReqId.fromSlice(&.{2}), .ping, &.{}, &.{1}, 10));

    book.detachLookup(42);
    try std.testing.expectEqual(types.RequestOrigin.detached_lookup, book.get(active_key).?.origin);
    try std.testing.expectEqual(types.RequestOrigin.detached_lookup, book.firstQueued(queued_endpoint).?.origin);
    try std.testing.expectEqual(@as(usize, 1), book.activeCount());
    try std.testing.expectEqual(@as(usize, 1), book.queuedCount());
}

test "FINDNODE sending retains compact expectation until successful completion" {
    var ingress = try admission.IngressAdmission.init(std.testing.allocator, null, limits.max_active_requests);
    defer ingress.deinit();
    var book = try book_mod.RequestBook.init(std.testing.allocator, limits);
    defer book.deinit(&ingress);
    const key = types.RequestKey.init(endpoint(19), try message.ReqId.fromSlice(&.{1}));
    const requested = requestedDistances(&.{ 0, 256 });
    const handle = try book.beginSending(&ingress, key, .api, book.makeExpectation(.findnode, &requested), .{
        .awaiting_whoareyou = try probe(19),
    }, 1, true, false);

    const sending = book.getSending(handle) orelse return error.MissingSendingRequest;
    try std.testing.expect(sending == .nodes);
    try std.testing.expect(sending.nodes.contains(0));
    try std.testing.expect(sending.nodes.contains(256));
    try std.testing.expect(book.get(key) == null);

    try std.testing.expect(book.completeSending(handle) != null);
    const active = book.get(key) orelse return error.MissingActiveRequest;
    try std.testing.expect(active.response == .nodes);
    try std.testing.expect(active.response.nodes.requested_distances.contains(0));
    try std.testing.expect(active.response.nodes.requested_distances.contains(256));
}

test "request generation exhaustion leaves admission and indexes unchanged" {
    var ingress = try admission.IngressAdmission.init(std.testing.allocator, null, limits.max_active_requests);
    defer ingress.deinit();
    var book = try book_mod.RequestBook.init(std.testing.allocator, limits);
    defer book.deinit(&ingress);
    book.next_generation = std.math.maxInt(u64);
    const key = types.RequestKey.init(endpoint(20), try message.ReqId.fromSlice(&.{1}));
    const nonce = [_]u8{20} ** 12;

    try std.testing.expectError(error.GenerationExhausted, book.beginSending(&ingress, key, .api, .pong, .{
        .awaiting_whoareyou = try probe(20),
    }, 1, true, false));

    try std.testing.expectEqual(@as(usize, 0), ingress.permitCount());
    try std.testing.expectEqual(@as(usize, 0), book.activeCount());
    try std.testing.expectEqual(@as(usize, 0), book.sendingCount());
    try std.testing.expectEqual(@as(usize, 0), book.queuedCount());
    try std.testing.expect(!book.containsRequest(key));
    try std.testing.expect(!book.hasChallenge(&nonce, key.endpoint.addr));
    try std.testing.expect(!book.shouldQueue(key.endpoint));
    try std.testing.expectEqual(std.math.maxInt(u64), book.next_generation);
}

test "canonical sending rejects duplicate request keys before completion" {
    const sending_limits = config_mod.Limits{
        .max_active_requests = 1,
        .max_queued_requests = 1,
        .max_queued_requests_per_endpoint = 1,
    };
    var ingress = try admission.IngressAdmission.init(std.testing.allocator, null, 2);
    defer ingress.deinit();
    var book = try book_mod.RequestBook.init(std.testing.allocator, sending_limits);
    defer book.deinit(&ingress);
    const key = types.RequestKey.init(endpoint(21), try message.ReqId.fromSlice(&.{1}));
    const first = try book.beginSending(&ingress, key, .api, .pong, .{
        .awaiting_whoareyou = try probe(21),
    }, 1, true, false);
    defer _ = book.abortSending(first, &ingress);

    try std.testing.expectError(error.DuplicateRequest, book.beginSending(&ingress, key, .api, .pong, .{
        .awaiting_whoareyou = try probe(23),
    }, 1, true, false));
    try std.testing.expectEqual(@as(usize, 1), book.sendingCount());
    try std.testing.expectEqual(@as(usize, 1), ingress.permitCount());
}

test "sending request consumes active capacity for a distinct key" {
    const sending_limits = config_mod.Limits{
        .max_active_requests = 1,
        .max_queued_requests = 1,
        .max_queued_requests_per_endpoint = 1,
    };
    var ingress = try admission.IngressAdmission.init(std.testing.allocator, null, 2);
    defer ingress.deinit();
    var book = try book_mod.RequestBook.init(std.testing.allocator, sending_limits);
    defer book.deinit(&ingress);
    const first_key = types.RequestKey.init(endpoint(22), try message.ReqId.fromSlice(&.{1}));
    const first = try book.beginSending(&ingress, first_key, .api, .pong, .{
        .awaiting_whoareyou = try probe(22),
    }, 1, true, false);
    defer _ = book.abortSending(first, &ingress);
    const second_key = types.RequestKey.init(endpoint(23), try message.ReqId.fromSlice(&.{2}));

    try std.testing.expectError(error.TooManyActiveRequests, book.beginSending(&ingress, second_key, .api, .pong, .{
        .awaiting_whoareyou = try probe(23),
    }, 1, true, false));
    try std.testing.expectEqual(@as(usize, 1), book.sendingCount());
    try std.testing.expectEqual(@as(usize, 1), ingress.permitCount());
}

test "canonical sending rejects duplicate challenge nonces before completion" {
    var ingress = try admission.IngressAdmission.init(std.testing.allocator, null, 2);
    defer ingress.deinit();
    var book = try book_mod.RequestBook.init(std.testing.allocator, limits);
    defer book.deinit(&ingress);
    var second_endpoint = endpoint(31);
    second_endpoint.node_id = [_]u8{32} ** 32;
    const first = try book.beginSending(&ingress, .init(endpoint(31), try message.ReqId.fromSlice(&.{1})), .api, .pong, .{
        .awaiting_whoareyou = try probe(31),
    }, 1, true, false);
    defer _ = book.abortSending(first, &ingress);

    try std.testing.expectError(error.DuplicateChallenge, book.beginSending(
        &ingress,
        .init(second_endpoint, try message.ReqId.fromSlice(&.{2})),
        .api,
        .pong,
        .{ .awaiting_whoareyou = try probe(31) },
        1,
        true,
        false,
    ));
    try std.testing.expectEqual(@as(usize, 1), book.sendingCount());
    try std.testing.expectEqual(@as(usize, 1), ingress.permitCount());
}

test "stale challenge handle cannot authorize a reused request key generation" {
    var ingress = try admission.IngressAdmission.init(std.testing.allocator, null, 2);
    defer ingress.deinit();
    var book = try book_mod.RequestBook.init(std.testing.allocator, limits);
    defer book.deinit(&ingress);
    const key = types.RequestKey.init(endpoint(35), try message.ReqId.fromSlice(&.{1}));
    const old = try book.beginSending(&ingress, key, .api, .pong, .{
        .awaiting_whoareyou = try probe(35),
    }, 1, true, false);
    try std.testing.expect(book.abortSending(old, &ingress) != null);
    const current = try book.beginSending(&ingress, key, .api, .pong, .{
        .awaiting_whoareyou = try probe(36),
    }, 1, true, false);
    defer _ = book.abortSending(current, &ingress);
    const nonce = [_]u8{36} ** 12;
    book.challenge_by_nonce.getPtr(.init(key.endpoint.addr, &nonce)).?.* = old;

    try std.testing.expect(!book.canReplaceChallenge(key, &nonce));
}

test "stale lane handle cannot authorize a reused request key generation" {
    var ingress = try admission.IngressAdmission.init(std.testing.allocator, null, 2);
    defer ingress.deinit();
    var book = try book_mod.RequestBook.init(std.testing.allocator, limits);
    defer book.deinit(&ingress);
    const key = types.RequestKey.init(endpoint(37), try message.ReqId.fromSlice(&.{1}));
    const old = try book.beginSending(&ingress, key, .api, .pong, .{
        .awaiting_whoareyou = try probe(37),
    }, 1, true, false);
    try std.testing.expect(book.abortSending(old, &ingress) != null);
    const current = try book.beginSending(&ingress, key, .api, .pong, .{
        .awaiting_whoareyou = try probe(38),
    }, 1, true, false);
    defer _ = book.abortSending(current, &ingress);
    book.lanes.getPtr(key.endpoint).?.establishing = old;

    try std.testing.expect(!book.canEstablish(key));
}

test "stale sending handle cannot mutate a reused request key generation" {
    var ingress = try admission.IngressAdmission.init(std.testing.allocator, null, 2);
    defer ingress.deinit();
    var book = try book_mod.RequestBook.init(std.testing.allocator, limits);
    defer book.deinit(&ingress);
    const key = types.RequestKey.init(endpoint(33), try message.ReqId.fromSlice(&.{1}));
    const old = try book.beginSending(&ingress, key, .api, .pong, .{
        .awaiting_whoareyou = try probe(33),
    }, 1, true, false);
    try std.testing.expect(book.abortSending(old, &ingress) != null);
    const current = try book.beginSending(&ingress, key, .api, .pong, .{
        .awaiting_whoareyou = try probe(34),
    }, 1, true, false);
    try std.testing.expect(old.generation != current.generation);

    try std.testing.expect(book.abortSending(old, &ingress) == null);
    try std.testing.expectEqual(@as(usize, 1), book.sendingCount());
    try std.testing.expectEqual(@as(usize, 1), ingress.permitCount());
    try std.testing.expect(book.completeSending(old) == null);
    try std.testing.expectEqual(@as(usize, 1), book.sendingCount());
    try std.testing.expect(book.completeSending(current) != null);
    try std.testing.expectEqual(@as(usize, 1), book.activeCount());
    var active = book.take(key) orelse return error.MissingActiveRequest;
    active.admission.release(&ingress);
}
