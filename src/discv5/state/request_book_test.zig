const std = @import("std");
const admission = @import("../admission.zig");
const enr = @import("../enr.zig");
const message = @import("../protocol/message.zig");
const book_mod = @import("request_book.zig");
const secp = @import("../secp256k1.zig");
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

fn commitHandshake(
    book: *book_mod.RequestBook,
    preparation: book_mod.ChallengePreparation,
    keys: book_mod.PendingSessionKeys,
    deadline_ns: i64,
) !void {
    const handle = try book.beginHandshake(preparation, keys, deadline_ns);
    _ = book.completeHandshake(handle, .sent) orelse return error.HandshakeCompletionRejected;
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
    try commitHandshake(&book, try book.challenge(&([_]u8{20} ** 12), promoted_retry.endpoint.addr), keys, 2);
    try std.testing.expect(book.pendingKeys(promoted_retry.endpoint) != null);
    try std.testing.expectError(error.InvalidChallenge, book.challenge(&([_]u8{20} ** 12), promoted_retry.endpoint.addr));

    var retry_permit = try ingress.acquire(promoted_retry.endpoint.addr, admission.requestPacketBudget(.ping));
    const promoted_handle = book.handleFor(promoted_retry) orelse return error.MissingActiveRequest;
    const promoted_prepared = try book.prepareFreshRetry(
        promoted_handle,
        try .init(&.{1}),
        .{ .response = [_]u8{21} ** 12 },
        3,
        &retry_permit,
    );
    try std.testing.expect(book.pendingKeys(promoted_retry.endpoint) == null);
    try std.testing.expect(!book.promotePending(book_mod.PendingKeysView{ .handle = .{
        .request = promoted_handle,
        .send_generation = 1,
    }, .keys = keys }));
    _ = book.completeRetry(promoted_prepared.handle, .sent, &ingress) orelse return error.RetryCompletionRejected;
    const retry_pending = book.pendingKeys(promoted_retry.endpoint) orelse return error.MissingPendingKeys;
    try std.testing.expectEqual(keys, retry_pending.keys);
    _ = try book.challenge(&([_]u8{21} ** 12), promoted_retry.endpoint.addr);
    _ = book.promotePending(retry_pending);
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
    try commitHandshake(&book, try book.challenge(&([_]u8{30} ** 12), confirmed_retry.endpoint.addr), keys, 2);
    const confirmed_pending = book.pendingKeys(confirmed_retry.endpoint) orelse return error.MissingPendingKeys;
    _ = book.promotePending(confirmed_pending);
    try std.testing.expect(book.pendingKeys(confirmed_retry.endpoint) == null);
    try std.testing.expectError(error.InvalidChallenge, book.challenge(&([_]u8{30} ** 12), confirmed_retry.endpoint.addr));

    var confirmed_permit = try ingress.acquire(confirmed_retry.endpoint.addr, admission.requestPacketBudget(.ping));
    const confirmed_handle = book.handleFor(confirmed_retry) orelse return error.MissingActiveRequest;
    const confirmed_prepared = try book.prepareFreshRetry(
        confirmed_handle,
        try .init(&.{1}),
        .{ .response = [_]u8{31} ** 12 },
        3,
        &confirmed_permit,
    );
    _ = book.completeRetry(confirmed_prepared.handle, .sent, &ingress) orelse return error.RetryCompletionRejected;
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
    try commitHandshake(&book, challenge, .{
        .initiator_key = [_]u8{10} ** 16,
        .recipient_key = [_]u8{11} ** 16,
    }, 2);
    const pending = book.pendingKeys(key.endpoint) orelse return error.MissingPendingKeys;
    try std.testing.expect(types.RequestKeyContext.eql(.{}, pending.handle.request.key, key));
    _ = book.promotePending(pending);
    try std.testing.expect(book.pendingKeys(key.endpoint) == null);
    var removed = book.take(key) orelse return error.MissingActiveRequest;
    removed.admission.release(&ingress);
    book.assertInvariants();
    try std.testing.expectEqual(@as(usize, 0), ingress.permitCount());
}

test "copied request handshake completion commits exact generation once" {
    var ingress = try admission.IngressAdmission.init(std.testing.allocator, null, limits.max_active_requests);
    defer ingress.deinit();
    var book = try book_mod.RequestBook.init(std.testing.allocator, limits);
    defer book.deinit(&ingress);
    const key = types.RequestKey.init(endpoint(39), try message.ReqId.fromSlice(&.{ 3, 9 }));
    try beginActive(
        &book,
        &ingress,
        key,
        .api,
        .pong,
        .{ .awaiting_whoareyou = try probe(39) },
        1,
        true,
    );
    const preparation = try book.challenge(&([_]u8{39} ** 12), key.endpoint.addr);
    const handle = try book.beginHandshake(preparation, .{
        .initiator_key = [_]u8{10} ** 16,
        .recipient_key = [_]u8{11} ** 16,
    }, 9);
    const copied = handle;

    try std.testing.expectEqual(types.RequestKind.ping, (book.completeHandshake(handle, .sent) orelse return error.HandshakeCompletionRejected).kind);
    try std.testing.expect(book.completeHandshake(copied, .sent) == null);
    const pending = book.pendingKeys(key.endpoint) orelse return error.MissingPendingKeys;
    try std.testing.expectEqual(handle, pending.handle);
    try std.testing.expectEqual(@as(i64, 9), book.get(key).?.deadline_ns);
}

test "large NODES request stays canonical and unchanged across handshake rollback and send" {
    var ingress = try admission.IngressAdmission.init(std.testing.allocator, null, limits.max_active_requests);
    defer ingress.deinit();
    var book = try book_mod.RequestBook.init(std.testing.allocator, limits);
    defer book.deinit(&ingress);
    const key = types.RequestKey.init(endpoint(38), try message.ReqId.fromSlice(&.{ 3, 8 }));
    const distances = requestedDistances(&.{ 1, 256 });
    const recovery = (try probe(38)).recovery;
    try beginActive(&book, &ingress, key, .api, .{ .nodes = distances }, .{ .awaiting_response = .{
        .recovery = recovery,
        .wait = .session_request,
    } }, 4, false);
    const active_before = book.get(key) orelse return error.MissingActiveRequest;
    active_before.attempts = 7;
    active_before.response.nodes.total_responses = 3;
    active_before.response.nodes.responses_received = 1;
    const enr_key = try secp.keyPairFromSecret(&([_]u8{0x38} ** 32));
    var enr_builder = enr.Builder.init(std.testing.allocator, enr_key, 38);
    enr_builder.ip = .{ 127, 0, 0, 38 };
    enr_builder.udp = 9038;
    const raw_enr = try enr_builder.encode();
    defer std.testing.allocator.free(raw_enr);
    active_before.response.nodes.validated_enrs.append(try enr.ValidatedEnr.init(raw_enr));
    const canonical_address = @intFromPtr(active_before);
    const preparation = try book.challenge(&recovery.nonce, key.endpoint.addr);
    const handle = try book.beginHandshake(preparation, .{
        .initiator_key = [_]u8{12} ** 16,
        .recipient_key = [_]u8{13} ** 16,
    }, 99);
    const copied = handle;
    const sending = book_mod.Testing.handshakeCanonicalActive(&book, handle) orelse return error.MissingCanonicalHandshakeRequest;
    try std.testing.expectEqual(canonical_address, @intFromPtr(sending));
    try expectSeededNodesUnchanged(sending, &distances, &recovery, raw_enr);
    try std.testing.expectEqual(@as(i64, 4), sending.deadline_ns);
    try std.testing.expectEqual(@as(u32, 7), sending.attempts);
    try std.testing.expect(book.get(key) == null);
    try std.testing.expect(book.pendingKeys(key.endpoint) == null);
    try std.testing.expectError(error.InvalidChallenge, book.challenge(&recovery.nonce, key.endpoint.addr));
    try std.testing.expectError(error.StaleRequest, book.beginHandshake(preparation, .{
        .initiator_key = [_]u8{1} ** 16,
        .recipient_key = [_]u8{2} ** 16,
    }, 100));
    var timeout_scan = book_mod.RequestBook.ActiveScan{};
    var timed_out: [1]types.RequestKey = undefined;
    try std.testing.expectEqual(@as(usize, 0), book.collectTimedOutBatch(&timed_out, 100, &timeout_scan));
    try std.testing.expect(!book.hasChallenge(&recovery.nonce, key.endpoint.addr));

    try std.testing.expectEqual(types.RequestKind.findnode, (book.completeHandshake(handle, .failed) orelse return error.HandshakeCompletionRejected).kind);
    try std.testing.expect(book.completeHandshake(copied, .sent) == null);
    const restored = book.get(key) orelse return error.MissingRestoredRequest;
    try std.testing.expectEqual(canonical_address, @intFromPtr(restored));
    try expectSeededNodesUnchanged(restored, &distances, &recovery, raw_enr);
    try std.testing.expectEqual(@as(i64, 4), restored.deadline_ns);
    try std.testing.expectEqual(@as(u32, 7), restored.attempts);
    try std.testing.expect(book.hasChallenge(&recovery.nonce, key.endpoint.addr));
    try std.testing.expect(book.canEstablish(key));
    try std.testing.expectEqual(@as(usize, 1), ingress.permitCount());

    const sent = try book.beginHandshake(try book.challenge(&recovery.nonce, key.endpoint.addr), .{
        .initiator_key = [_]u8{14} ** 16,
        .recipient_key = [_]u8{15} ** 16,
    }, 101);
    _ = book.completeHandshake(sent, .sent) orelse return error.HandshakeCompletionRejected;
    const committed = book.get(key) orelse return error.MissingCommittedRequest;
    try std.testing.expectEqual(canonical_address, @intFromPtr(committed));
    try std.testing.expectEqual(@as(u64, 3), committed.response.nodes.total_responses.?);
    try std.testing.expectEqual(@as(u64, 1), committed.response.nodes.responses_received);
    try std.testing.expectEqual(@as(usize, 1), committed.response.nodes.validated_enrs.slice().len);
    try std.testing.expectEqualSlices(u8, raw_enr, committed.response.nodes.validated_enrs.slice()[0].raw.slice());
    try std.testing.expectEqual(@as(u32, 7), committed.attempts);
    try std.testing.expectEqual(@as(i64, 101), committed.deadline_ns);
    try std.testing.expect(committed.phase.awaiting_response.wait == .handshake_sent);
}

fn expectSeededNodesUnchanged(
    active: *const book_mod.ActiveRequest,
    distances: *const book_mod.RequestDistances,
    recovery: *const book_mod.RecoveryState,
    raw_enr: []const u8,
) !void {
    try std.testing.expect(active.response == .nodes);
    try std.testing.expectEqual(@as(u64, 3), active.response.nodes.total_responses.?);
    try std.testing.expectEqual(@as(u64, 1), active.response.nodes.responses_received);
    try std.testing.expectEqual(distances.*, active.response.nodes.requested_distances);
    try std.testing.expectEqual(@as(usize, 1), active.response.nodes.validated_enrs.slice().len);
    try std.testing.expectEqualSlices(u8, raw_enr, active.response.nodes.validated_enrs.slice()[0].raw.slice());
    try std.testing.expect(active.phase == .awaiting_response);
    try std.testing.expect(active.phase.awaiting_response.wait == .session_request);
    try std.testing.expectEqual(recovery.nonce, active.phase.awaiting_response.recovery.nonce);
    try std.testing.expectEqual(recovery.dest_pubkey, active.phase.awaiting_response.recovery.dest_pubkey);
    try std.testing.expectEqualSlices(u8, recovery.plaintext.slice(), active.phase.awaiting_response.recovery.plaintext.slice());
}

test "request handshake generation exhaustion is failure atomic" {
    var ingress = try admission.IngressAdmission.init(std.testing.allocator, null, limits.max_active_requests);
    defer ingress.deinit();
    var book = try book_mod.RequestBook.init(std.testing.allocator, limits);
    defer book.deinit(&ingress);
    const key = types.RequestKey.init(endpoint(37), try message.ReqId.fromSlice(&.{ 3, 7 }));
    try beginActive(&book, &ingress, key, .api, .pong, .{ .awaiting_whoareyou = try probe(37) }, 5, true);
    const preparation = try book.challenge(&([_]u8{37} ** 12), key.endpoint.addr);
    book_mod.Testing.exhaustHandshakeGeneration(&book);

    try std.testing.expectError(error.GenerationExhausted, book.preflightHandshake(preparation));
    try std.testing.expectError(error.GenerationExhausted, book.beginHandshake(preparation, .{
        .initiator_key = [_]u8{14} ** 16,
        .recipient_key = [_]u8{15} ** 16,
    }, 100));
    const active = book.get(key) orelse return error.MissingActiveRequest;
    try std.testing.expectEqual(@as(i64, 5), active.deadline_ns);
    try std.testing.expect(active.phase == .awaiting_whoareyou);
    try std.testing.expect(book.hasChallenge(&([_]u8{37} ** 12), key.endpoint.addr));
    try std.testing.expectEqual(@as(usize, 1), ingress.permitCount());
}

test "stale request candidate cannot promote a newer handshake generation" {
    var ingress = try admission.IngressAdmission.init(std.testing.allocator, null, limits.max_active_requests);
    defer ingress.deinit();
    var book = try book_mod.RequestBook.init(std.testing.allocator, limits);
    defer book.deinit(&ingress);
    const key = types.RequestKey.init(endpoint(36), try message.ReqId.fromSlice(&.{ 3, 6 }));
    try beginActive(&book, &ingress, key, .api, .pong, .{ .awaiting_whoareyou = try probe(36) }, 1, true);
    const first = try book.beginHandshake(try book.challenge(&([_]u8{36} ** 12), key.endpoint.addr), .{
        .initiator_key = [_]u8{16} ** 16,
        .recipient_key = [_]u8{17} ** 16,
    }, 2);
    _ = book.completeHandshake(first, .sent) orelse return error.HandshakeCompletionRejected;
    const stale = book.pendingKeys(key.endpoint) orelse return error.MissingPendingKeys;

    var replacement = try ingress.acquire(key.endpoint.addr, admission.requestPacketBudget(.ping));
    const retry = try book.prepareFreshRetry(first.request, try .init(&.{1}), .{ .response = [_]u8{35} ** 12 }, 3, &replacement);
    _ = book.completeRetry(retry.handle, .sent, &ingress) orelse return error.RetryCompletionRejected;
    const retained = book.pendingKeys(key.endpoint) orelse return error.MissingRetainedPendingKeys;
    try std.testing.expectEqual(first, retained.handle);
    const second = try book.beginHandshake(try book.challenge(&([_]u8{35} ** 12), key.endpoint.addr), .{
        .initiator_key = [_]u8{18} ** 16,
        .recipient_key = [_]u8{19} ** 16,
    }, 4);
    try std.testing.expect(book.completeHandshake(first, .sent) == null);
    try std.testing.expect(book.completeHandshake(first, .failed) == null);
    _ = book.completeHandshake(second, .sent) orelse return error.HandshakeCompletionRejected;

    try std.testing.expect(!book.promotePending(stale));
    try std.testing.expectEqual(second, (book.pendingKeys(key.endpoint) orelse return error.NewCandidateRemoved).handle);
    const exact = book.pendingKeys(key.endpoint) orelse return error.MissingExactCandidate;
    try std.testing.expect(book.promotePending(exact));
    try std.testing.expect(!book.promotePending(exact));
    try std.testing.expect(book.pendingKeys(key.endpoint) == null);
}

test "terminal request handshake cleanup invalidates copies and reused request keys" {
    var ingress = try admission.IngressAdmission.init(std.testing.allocator, null, limits.max_active_requests);
    defer ingress.deinit();
    var book = try book_mod.RequestBook.init(std.testing.allocator, limits);
    defer book.deinit(&ingress);
    const key = types.RequestKey.init(endpoint(35), try message.ReqId.fromSlice(&.{ 3, 5 }));
    try beginActive(&book, &ingress, key, .api, .pong, .{ .awaiting_whoareyou = try probe(34) }, 1, true);
    const old = try book.beginHandshake(try book.challenge(&([_]u8{34} ** 12), key.endpoint.addr), .{
        .initiator_key = [_]u8{20} ** 16,
        .recipient_key = [_]u8{21} ** 16,
    }, 2);
    var terminal = book.takeTerminal(key) orelse return error.MissingTerminalRequest;
    terminal.release(&ingress);
    try std.testing.expectEqual(@as(usize, 0), ingress.permitCount());
    try std.testing.expect(book.completeHandshake(old, .sent) == null);
    try std.testing.expect(book.completeHandshake(old, .failed) == null);

    const replacement = try book.beginSending(&ingress, key, .api, .pong, .{ .awaiting_whoareyou = try probe(33) }, 3, true, false);
    _ = book.completeSending(replacement) orelse return error.SendingCompletionRejected;
    try std.testing.expect(replacement.generation != old.request.generation);
    try std.testing.expect(book.completeHandshake(old, .runtime_stopped) == null);
    try std.testing.expect(book.hasChallenge(&([_]u8{33} ** 12), key.endpoint.addr));
    try std.testing.expectEqual(@as(usize, 1), ingress.permitCount());
}

test "copied retained retry completion commits attempts and deadline once" {
    var ingress = try admission.IngressAdmission.init(std.testing.allocator, null, limits.max_active_requests);
    defer ingress.deinit();
    var book = try book_mod.RequestBook.init(std.testing.allocator, limits);
    defer book.deinit(&ingress);
    const key = types.RequestKey.init(endpoint(40), try message.ReqId.fromSlice(&.{4}));
    const handle = try book.beginSending(
        &ingress,
        key,
        .api,
        .pong,
        .{ .awaiting_whoareyou = try probe(40) },
        1,
        true,
        false,
    );
    _ = book.completeSending(handle) orelse return error.SendingCompletionRejected;

    const canonical_address = @intFromPtr(book.get(key) orelse return error.MissingActiveRequest);
    const prepared = try book.prepareRetainedRetry(handle, 9);
    const armed = book_mod.Testing.retryCanonicalActive(&book, prepared.handle) orelse return error.MissingCanonicalRetryRequest;
    try std.testing.expectEqual(canonical_address, @intFromPtr(armed));
    try std.testing.expect(armed.retry_send != null);
    try std.testing.expect(armed.handshake_send == null);
    const copied = prepared.handle;
    try std.testing.expect((book.completeRetry(prepared.handle, .sent, &ingress) orelse return error.RetryCompletionRejected).kind == .ping);
    try std.testing.expect(book.completeRetry(copied, .sent, &ingress) == null);
    const completed = book.get(key) orelse return error.MissingActiveRequest;
    try std.testing.expectEqual(canonical_address, @intFromPtr(completed));
    try std.testing.expect(completed.retry_send == null);
    try std.testing.expectEqual(@as(u32, 1), completed.attempts);
    try std.testing.expectEqual(@as(i64, 9), completed.deadline_ns);

    const current = try book.prepareRetainedRetry(handle, 10);
    try std.testing.expect(book.completeRetry(copied, .sent, &ingress) == null);
    _ = book.completeRetry(current.handle, .sent, &ingress) orelse return error.RetryCompletionRejected;
    try std.testing.expectEqual(@as(u32, 2), book.get(key).?.attempts);
    try std.testing.expectEqual(@as(i64, 10), book.get(key).?.deadline_ns);
}

test "large multipart NODES accumulator stays canonical across retained retry outcomes" {
    var ingress = try admission.IngressAdmission.init(std.testing.allocator, null, limits.max_active_requests);
    defer ingress.deinit();
    var book = try book_mod.RequestBook.init(std.testing.allocator, limits);
    defer book.deinit(&ingress);
    const key = types.RequestKey.init(endpoint(52), try message.ReqId.fromSlice(&.{ 5, 2 }));
    const distances = requestedDistances(&.{ 1, 17, 256 });
    const handle = try book.beginSending(&ingress, key, .api, .{ .nodes = distances }, .{
        .awaiting_whoareyou = try probe(52),
    }, 1, true, false);
    _ = book.completeSending(handle) orelse return error.SendingCompletionRejected;
    const active = book.get(key) orelse return error.MissingActiveRequest;
    active.response.nodes.total_responses = 7;
    active.response.nodes.responses_received = 2;
    inline for (.{ @as(u8, 0x52), @as(u8, 0x53) }) |secret| {
        const enr_key = try secp.keyPairFromSecret(&([_]u8{secret} ** 32));
        var builder = enr.Builder.init(std.testing.allocator, enr_key, secret);
        builder.ip = .{ 127, 0, 0, secret };
        builder.udp = 9000 + @as(u16, secret);
        const raw = try builder.encode();
        defer std.testing.allocator.free(raw);
        active.response.nodes.validated_enrs.append(try enr.ValidatedEnr.init(raw));
    }
    const canonical_address = @intFromPtr(active);
    const response_fingerprint = active.response;
    const phase_fingerprint = active.phase;
    const permit_fingerprint = active.permitHandle();

    const failed = try book.prepareRetainedRetry(handle, 9);
    _ = book.completeRetry(failed.handle, .failed, &ingress) orelse return error.RetryCompletionRejected;
    const after_failed = book.get(key) orelse return error.MissingActiveRequest;
    try std.testing.expectEqual(canonical_address, @intFromPtr(after_failed));
    try std.testing.expect(std.meta.eql(response_fingerprint, after_failed.response));
    try std.testing.expect(std.meta.eql(phase_fingerprint, after_failed.phase));
    try std.testing.expectEqual(permit_fingerprint, after_failed.permitHandle());
    try std.testing.expectEqual(@as(u32, 1), after_failed.attempts);
    try std.testing.expectEqual(@as(i64, 9), after_failed.deadline_ns);

    const sent = try book.prepareRetainedRetry(handle, 10);
    _ = book.completeRetry(sent.handle, .sent, &ingress) orelse return error.RetryCompletionRejected;
    const after_sent = book.get(key) orelse return error.MissingActiveRequest;
    try std.testing.expectEqual(canonical_address, @intFromPtr(after_sent));
    try std.testing.expect(std.meta.eql(response_fingerprint, after_sent.response));
    try std.testing.expect(std.meta.eql(phase_fingerprint, after_sent.phase));
    try std.testing.expectEqual(permit_fingerprint, after_sent.permitHandle());
    try std.testing.expectEqual(@as(u32, 2), after_sent.attempts);
    try std.testing.expectEqual(@as(i64, 10), after_sent.deadline_ns);
}

test "copied fresh retry success swaps phase permit indexes lane and NODES generation once" {
    var ingress = try admission.IngressAdmission.init(std.testing.allocator, null, limits.max_active_requests);
    defer ingress.deinit();
    var book = try book_mod.RequestBook.init(std.testing.allocator, limits);
    defer book.deinit(&ingress);
    const key = types.RequestKey.init(endpoint(41), try message.ReqId.fromSlice(&.{ 4, 1 }));
    const distances = requestedDistances(&.{ 1, 41, 256 });
    const handle = try book.beginSending(
        &ingress,
        key,
        .api,
        .{ .nodes = distances },
        .{ .awaiting_response = .{
            .recovery = (try probe(41)).recovery,
            .wait = .session_request,
        } },
        1,
        false,
        false,
    );
    _ = book.completeSending(handle) orelse return error.SendingCompletionRejected;
    const before = book.get(key) orelse return error.MissingActiveRequest;
    before.response.nodes.total_responses = 4;
    before.response.nodes.responses_received = 3;
    const canonical_address = @intFromPtr(before);
    const old_permit = before.permitHandle();
    var replacement = try ingress.acquire(key.endpoint.addr, admission.requestPacketBudget(.findnode));
    const replacement_permit = replacement.handle();
    const prepared = try book.prepareFreshRetry(
        handle,
        try .init(&.{ 8, 9 }),
        .{ .probe = .{ .retry_packet = try .init(&.{ 6, 7 }), .nonce = [_]u8{42} ** 12 } },
        9,
        &replacement,
    );
    const armed = book_mod.Testing.retryCanonicalActive(&book, prepared.handle) orelse return error.MissingCanonicalRetryRequest;
    try std.testing.expectEqual(canonical_address, @intFromPtr(armed));
    try std.testing.expect(armed.retry_send != null);
    const copied = prepared.handle;

    _ = book.completeRetry(prepared.handle, .sent, &ingress) orelse return error.RetryCompletionRejected;
    try std.testing.expect(book.completeRetry(copied, .sent, &ingress) == null);
    const active = book.get(key) orelse return error.MissingActiveRequest;
    try std.testing.expectEqual(canonical_address, @intFromPtr(active));
    try std.testing.expect(active.retry_send == null);
    try std.testing.expect(active.phase == .awaiting_whoareyou);
    try std.testing.expectEqualSlices(u8, &([_]u8{42} ** 12), &active.phase.awaiting_whoareyou.recovery.nonce);
    try std.testing.expectEqualSlices(u8, &.{ 6, 7 }, active.phase.awaiting_whoareyou.retry_packet.slice());
    try std.testing.expect(!book.hasChallenge(&([_]u8{41} ** 12), key.endpoint.addr));
    try std.testing.expect(book.hasChallenge(&([_]u8{42} ** 12), key.endpoint.addr));
    try std.testing.expect(book.shouldQueue(key.endpoint));
    try std.testing.expect(!std.meta.eql(old_permit, active.permitHandle()));
    try std.testing.expectEqual(replacement_permit, active.permitHandle());
    try std.testing.expectEqual(@as(usize, 0), active.response.nodes.validated_enrs.slice().len);
    try std.testing.expect(active.response.nodes.total_responses == null);
    try std.testing.expectEqual(@as(u64, 0), active.response.nodes.responses_received);
    try std.testing.expectEqual(distances, active.response.nodes.requested_distances);
    try std.testing.expectEqual(@as(u32, 1), active.attempts);
    try std.testing.expectEqual(@as(i64, 9), active.deadline_ns);
    try std.testing.expectEqual(@as(usize, 1), ingress.permitCount());
}

test "fresh retry failure and runtime stop preserve canonical NODES phase and current permit" {
    var ingress = try admission.IngressAdmission.init(std.testing.allocator, null, limits.max_active_requests);
    defer ingress.deinit();
    var book = try book_mod.RequestBook.init(std.testing.allocator, limits);
    defer book.deinit(&ingress);
    const key = types.RequestKey.init(endpoint(42), try message.ReqId.fromSlice(&.{ 4, 2 }));
    const original_nonce = [_]u8{42} ** 12;
    const distances = requestedDistances(&.{ 2, 42, 256 });
    const handle = try book.beginSending(
        &ingress,
        key,
        .api,
        .{ .nodes = distances },
        .{ .awaiting_response = .{
            .recovery = (try probe(42)).recovery,
            .wait = .session_request,
        } },
        1,
        false,
        false,
    );
    _ = book.completeSending(handle) orelse return error.SendingCompletionRejected;
    const before = book.get(key) orelse return error.MissingActiveRequest;
    before.response.nodes.total_responses = 9;
    before.response.nodes.responses_received = 4;
    const response_fingerprint = before.response;
    const phase_fingerprint = before.phase;
    const permit_fingerprint = before.permitHandle();
    const canonical_address = @intFromPtr(before);

    inline for (.{ book_mod.RetrySendCompletion.failed, book_mod.RetrySendCompletion.runtime_stopped }, 0..) |outcome, index| {
        var replacement = try ingress.acquire(key.endpoint.addr, admission.requestPacketBudget(.findnode));
        const prepared = try book.prepareFreshRetry(
            handle,
            try .init(&.{ 8, 9 }),
            .{ .response = [_]u8{@intCast(43 + index)} ** 12 },
            @intCast(9 + index),
            &replacement,
        );
        const copied = prepared.handle;
        _ = book.completeRetry(prepared.handle, outcome, &ingress) orelse return error.RetryCompletionRejected;
        try std.testing.expect(book.completeRetry(copied, .sent, &ingress) == null);
        const active = book.get(key) orelse return error.MissingActiveRequest;
        try std.testing.expectEqual(canonical_address, @intFromPtr(active));
        try std.testing.expect(std.meta.eql(response_fingerprint, active.response));
        try std.testing.expect(std.meta.eql(phase_fingerprint, active.phase));
        try std.testing.expectEqual(permit_fingerprint, active.permitHandle());
        try std.testing.expectEqualSlices(u8, &original_nonce, &active.phase.awaiting_response.recovery.nonce);
        try std.testing.expectEqual(@as(u32, @intCast(index + 1)), active.attempts);
        try std.testing.expectEqual(@as(i64, @intCast(9 + index)), active.deadline_ns);
        try std.testing.expectEqual(@as(usize, 1), ingress.permitCount());
    }
}

test "reused RequestKey rejects old retained and fresh retry generations" {
    var ingress = try admission.IngressAdmission.init(std.testing.allocator, null, limits.max_active_requests);
    defer ingress.deinit();
    var book = try book_mod.RequestBook.init(std.testing.allocator, limits);
    defer book.deinit(&ingress);
    const key = types.RequestKey.init(endpoint(43), try message.ReqId.fromSlice(&.{ 4, 3 }));

    const first = try book.beginSending(&ingress, key, .api, .pong, .{ .awaiting_whoareyou = try probe(43) }, 1, true, false);
    _ = book.completeSending(first) orelse return error.SendingCompletionRejected;
    const stale_retained = (try book.prepareRetainedRetry(first, 2)).handle;
    var first_terminal = book.takeTerminal(key) orelse return error.MissingActiveRequest;
    first_terminal.release(&ingress);

    const second = try book.beginSending(&ingress, key, .api, .pong, .{ .awaiting_response = .{
        .recovery = (try probe(44)).recovery,
        .wait = .session_request,
    } }, 3, false, false);
    _ = book.completeSending(second) orelse return error.SendingCompletionRejected;
    var replacement = try ingress.acquire(key.endpoint.addr, admission.requestPacketBudget(.ping));
    const stale_fresh = (try book.prepareFreshRetry(
        second,
        try .init(&.{1}),
        .{ .response = [_]u8{45} ** 12 },
        4,
        &replacement,
    )).handle;
    try std.testing.expect(book.completeRetry(stale_retained, .sent, &ingress) == null);
    try std.testing.expectEqual(second.generation, book.handleFor(key).?.generation);
    var second_terminal = book.takeTerminal(key) orelse return error.MissingActiveRequest;
    second_terminal.release(&ingress);

    const third = try book.beginSending(&ingress, key, .api, .pong, .{ .awaiting_whoareyou = try probe(46) }, 5, true, false);
    _ = book.completeSending(third) orelse return error.SendingCompletionRejected;
    const current = (try book.prepareRetainedRetry(third, 6)).handle;
    try std.testing.expect(book.completeRetry(stale_fresh, .sent, &ingress) == null);
    _ = book.completeRetry(current, .sent, &ingress) orelse return error.RetryCompletionRejected;
    const active = book.get(key) orelse return error.MissingActiveRequest;
    try std.testing.expectEqual(third.generation, active.generation);
    try std.testing.expectEqual(@as(u32, 1), active.attempts);
    try std.testing.expectEqual(@as(usize, 1), ingress.permitCount());
}

test "terminalization invalidates fresh retry and releases current and prepared permits once" {
    var ingress = try admission.IngressAdmission.init(std.testing.allocator, null, limits.max_active_requests);
    defer ingress.deinit();
    var book = try book_mod.RequestBook.init(std.testing.allocator, limits);
    defer book.deinit(&ingress);
    const key = types.RequestKey.init(endpoint(47), try message.ReqId.fromSlice(&.{ 4, 7 }));
    const handle = try book.beginSending(&ingress, key, .api, .pong, .{ .awaiting_response = .{
        .recovery = (try probe(47)).recovery,
        .wait = .session_request,
    } }, 1, false, false);
    _ = book.completeSending(handle) orelse return error.SendingCompletionRejected;
    var replacement = try ingress.acquire(key.endpoint.addr, admission.requestPacketBudget(.ping));
    const prepared = try book.prepareFreshRetry(handle, try .init(&.{1}), .{ .response = [_]u8{48} ** 12 }, 2, &replacement);
    try std.testing.expectEqual(@as(usize, 2), ingress.permitCount());

    var terminal = book.takeTerminal(key) orelse return error.MissingActiveRequest;
    terminal.release(&ingress);
    try std.testing.expectEqual(@as(usize, 0), ingress.permitCount());
    try std.testing.expect(book.completeRetry(prepared.handle, .sent, &ingress) == null);
    try std.testing.expectEqual(@as(usize, 0), ingress.permitCount());
}

test "retry generation exhaustion precedes state permit and effect mutation" {
    var ingress = try admission.IngressAdmission.init(std.testing.allocator, null, limits.max_active_requests);
    defer ingress.deinit();
    var book = try book_mod.RequestBook.init(std.testing.allocator, limits);
    defer book.deinit(&ingress);
    const retained_key = types.RequestKey.init(endpoint(49), try message.ReqId.fromSlice(&.{ 4, 9 }));
    const retained = try book.beginSending(&ingress, retained_key, .api, .pong, .{ .awaiting_whoareyou = try probe(49) }, 1, true, false);
    _ = book.completeSending(retained) orelse return error.SendingCompletionRejected;
    book_mod.Testing.exhaustRetryGeneration(&book);
    try std.testing.expectError(error.GenerationExhausted, book.prepareRetainedRetry(retained, 2));
    try std.testing.expectEqual(@as(i64, 1), book.get(retained_key).?.deadline_ns);
    try std.testing.expectEqual(@as(u32, 0), book.get(retained_key).?.attempts);
    try std.testing.expectEqual(@as(usize, 1), ingress.permitCount());

    var terminal = book.takeTerminal(retained_key) orelse return error.MissingActiveRequest;
    terminal.release(&ingress);
    const fresh_key = types.RequestKey.init(endpoint(50), try message.ReqId.fromSlice(&.{ 5, 0 }));
    const fresh = try book.beginSending(&ingress, fresh_key, .api, .pong, .{ .awaiting_response = .{
        .recovery = (try probe(50)).recovery,
        .wait = .session_request,
    } }, 3, false, false);
    _ = book.completeSending(fresh) orelse return error.SendingCompletionRejected;
    try std.testing.expectError(error.GenerationExhausted, book.preflightFreshRetry(fresh));
    try std.testing.expectEqual(@as(i64, 3), book.get(fresh_key).?.deadline_ns);
    try std.testing.expectEqual(@as(u32, 0), book.get(fresh_key).?.attempts);
    try std.testing.expectEqual(@as(usize, 1), ingress.permitCount());
}

test "fresh retry preflight validates exact active awaiting-response generation" {
    var ingress = try admission.IngressAdmission.init(std.testing.allocator, null, limits.max_active_requests);
    defer ingress.deinit();
    var book = try book_mod.RequestBook.init(std.testing.allocator, limits);
    defer book.deinit(&ingress);

    const key = types.RequestKey.init(endpoint(51), try message.ReqId.fromSlice(&.{ 5, 1 }));
    const retained = try book.beginSending(&ingress, key, .api, .pong, .{ .awaiting_whoareyou = try probe(51) }, 1, true, false);
    _ = book.completeSending(retained) orelse return error.SendingCompletionRejected;
    try std.testing.expectError(error.InvalidRetryPhase, book.preflightFreshRetry(retained));
    const stale = types.RequestHandle{ .key = retained.key, .generation = retained.generation + 1 };
    try std.testing.expectError(error.StaleRequest, book.preflightFreshRetry(stale));

    const challenge = try book.challenge(&([_]u8{51} ** 12), key.endpoint.addr);
    try commitHandshake(&book, challenge, .{
        .initiator_key = [_]u8{13} ** 16,
        .recipient_key = [_]u8{14} ** 16,
    }, 2);
    try book.preflightFreshRetry(retained);
    try std.testing.expectEqual(@as(usize, 1), ingress.permitCount());
}

test "retry send substate gates timeout response challenge handshake second retry and lane work" {
    var ingress = try admission.IngressAdmission.init(std.testing.allocator, null, limits.max_active_requests);
    defer ingress.deinit();
    var book = try book_mod.RequestBook.init(std.testing.allocator, limits);
    defer book.deinit(&ingress);
    const peer = endpoint(53);
    const key = types.RequestKey.init(peer, try message.ReqId.fromSlice(&.{ 5, 3 }));
    const distances = requestedDistances(&.{ 1, 53, 256 });
    const recovery = (try probe(53)).recovery;
    const handle = try book.beginSending(&ingress, key, .api, .{ .nodes = distances }, .{ .awaiting_response = .{
        .recovery = recovery,
        .wait = .session_request,
    } }, 1, false, false);
    _ = book.completeSending(handle) orelse return error.SendingCompletionRejected;
    const challenge_preparation = try book.challenge(&recovery.nonce, peer.addr);
    _ = try book.queue(try .init(.api, peer, &([_]u8{2} ** 33), try message.ReqId.fromSlice(&.{ 5, 4 }), .ping, &.{}, &.{1}, 100));
    var replacement = try ingress.acquire(peer.addr, admission.requestPacketBudget(.findnode));
    const prepared = try book.prepareFreshRetry(handle, try .init(&.{ 8, 9 }), .{ .response = [_]u8{54} ** 12 }, 9, &replacement);

    try std.testing.expect(book.get(key) == null);
    try std.testing.expectEqual(@as(usize, 0), book.activeCount());
    try std.testing.expect(book.firstActive() == null);
    try std.testing.expect(!book.hasActiveFindNode(&peer.node_id));
    try std.testing.expectError(error.InvalidChallenge, book.challenge(&recovery.nonce, peer.addr));
    try std.testing.expectError(error.StaleRequest, book.preflightHandshake(challenge_preparation));
    try std.testing.expectError(error.StaleRequest, book.preflightFreshRetry(handle));
    try std.testing.expectError(error.StaleRequest, book.prepareRetainedRetry(handle, 10));
    var another = try ingress.acquire(peer.addr, admission.requestPacketBudget(.findnode));
    defer another.release(&ingress);
    try std.testing.expectError(error.StaleRequest, book.prepareFreshRetry(handle, try .init(&.{1}), .{ .response = [_]u8{55} ** 12 }, 10, &another));
    try std.testing.expect(!book.failRetryPreparation(handle, 10));
    var timeout_scan = book_mod.RequestBook.ActiveScan{};
    var timed_out: [1]types.RequestKey = undefined;
    try std.testing.expectEqual(@as(usize, 0), book.collectTimedOutBatch(&timed_out, 100, &timeout_scan));
    try std.testing.expect(book.firstQueued(peer) == null);
    try std.testing.expect(book.shouldQueue(peer));
    var drainable: [1]types.Endpoint = undefined;
    try std.testing.expectEqual(@as(usize, 0), book.collectDrainable(&drainable));

    _ = book.completeRetry(prepared.handle, .failed, &ingress) orelse return error.RetryCompletionRejected;
    try std.testing.expect(book.get(key) != null);
    try std.testing.expect(book.firstQueued(peer) != null);
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
    const handle = book.handleFor(key) orelse return error.MissingActiveRequest;
    const prepared = try book.prepareRetainedRetry(handle, 2);
    _ = book.completeRetry(prepared.handle, .sent, &ingress) orelse return error.RetryCompletionRejected;
    try std.testing.expectEqual(@as(u32, 1), book.get(key).?.attempts);

    const challenge = try book.challenge(&([_]u8{12} ** 12), key.endpoint.addr);
    try commitHandshake(&book, challenge, .{
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
    _ = try book.queue(try .init(.api, peer, &pubkey, first, .ping, &.{ 0, 256, 256 }, &.{1}, 0));
    _ = try book.queue(try .init(.api, peer, &pubkey, second, .ping, &.{}, &.{1}, 0));
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
    _ = try book.queue(try .init(.api, peer, &pubkey, req_id, .ping, &.{}, &.{1}, 10));
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
    _ = try book.queue(try .init(.api, peer, &pubkey, first, .ping, &.{}, &.{1}, 10));
    _ = try book.queue(try .init(.api, peer, &pubkey, second, .ping, &.{}, &.{2}, 10));

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
        _ = try book.queue(try .init(
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
        _ = try book.queue(try .init(
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
    try commitHandshake(&book, challenge, .{
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
    _ = try book.queue(try .init(.api, peer, &pubkey, try message.ReqId.fromSlice(&.{1}), .ping, &.{}, &.{1}, 10));
    _ = try book.queue(try .init(.api, peer, &pubkey, try message.ReqId.fromSlice(&.{2}), .ping, &.{}, &.{2}, 10));
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
    try commitHandshake(&book, challenge, .{
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
    _ = try book.queue(try .init(.api, queued_endpoint, &pubkey, try message.ReqId.fromSlice(&.{2}), .ping, &.{}, &.{1}, 10));
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
    _ = try book.queue(try .init(.{ .lookup = 42 }, queued_endpoint, &pubkey, try message.ReqId.fromSlice(&.{2}), .ping, &.{}, &.{1}, 10));

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
