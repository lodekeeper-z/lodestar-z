const std = @import("std");
const actor_mod = @import("../actor.zig");
const enr = @import("../enr.zig");
const handshake = @import("../protocol/handshake.zig");
const message = @import("../protocol/message.zig");
const packet = @import("../protocol/packet.zig");
const secp = @import("../secp256k1.zig");
const session_crypto = @import("../protocol/session.zig");
const session_book = @import("../state/session_book.zig");
const request_book = @import("../state/request_book.zig");
const request_results = @import("../request_results.zig");
const response_book = @import("../state/response_book.zig");
const types = @import("../types.zig");
const completion = @import("completion.zig");
const outbound = @import("outbound.zig");
const rpc = @import("rpc.zig");

const Actor = actor_mod.Actor;
const Env = actor_mod.Env;

const MAX_EPHEMERAL_KEY_ATTEMPTS: usize = 32;

const WhoareyouSource = actor_mod.WhoareyouSource;

const RecoveryMaterial = struct {
    endpoint: types.Endpoint,
    dest_pubkey: [33]u8,
    plaintext: types.PacketBytes,
};

/// Fully authenticated ingress value, constructed in place and passed by
/// pointer through expectation checking, state publication, and RPC dispatch.
/// Borrowed message and ENR views point into the current packet/plaintext stack
/// buffers and must not escape this synchronous ingress call.
const AuthenticatedMessage = struct {
    endpoint: types.Endpoint,
    decoded: message.DecodedMessage,
    handshake_enr: ?enr.ValidatedEnr,
};

comptime {
    std.debug.assert(@sizeOf(AuthenticatedMessage) <= 4 * 1024);
}

pub fn handlePacket(actor: *Actor, env: Env, raw: []u8, from: types.Address) void {
    var parsed = packet.decode(raw, &actor.local_node_id) catch return;
    switch (parsed.form) {
        .ordinary => |authdata| handleMessage(actor, env, &parsed, authdata, from),
        .whoareyou => |authdata| handleWhoareyou(actor, env, &parsed, authdata, from),
        .handshake => |authdata| handleHandshake(actor, env, &parsed, authdata, from),
    }
}

fn decryptParsedMessage(
    parsed: *const packet.ParsedPacket,
    read_key: *const [16]u8,
    plaintext_out: *[packet.MAX_PACKET_SIZE]u8,
    ad_out: *[packet.MAX_PACKET_SIZE]u8,
) ?[]u8 {
    return packet.decryptMessageInto(
        plaintext_out,
        ad_out,
        read_key,
        &parsed.static_header.nonce,
        parsed.message_ciphertext,
        &parsed.masking_iv,
        parsed.header_raw,
    ) catch null;
}

fn handleMessage(actor: *Actor, env: Env, parsed: *const packet.DecodedPacket, authdata: packet.OrdinaryAuthdata, from: types.Address) void {
    const endpoint = types.Endpoint{ .node_id = authdata.src_id, .addr = from };
    const now_ns = outbound.nowNs(env.io);

    // Non-mutating pointer: unauthenticated ciphertext must not refresh
    // LRU/TTL recency. Recency is refreshed only after authentication.
    if (actor.sessions.rejectsReplay(endpoint, &parsed.static_header.nonce, now_ns)) return;
    const stable = actor.sessions.peekPtr(endpoint, now_ns);

    var plaintext_buffer: [packet.MAX_PACKET_SIZE]u8 = undefined;
    defer std.crypto.secureZero(u8, &plaintext_buffer);
    var ad_buffer: [packet.MAX_PACKET_SIZE]u8 = undefined;
    if (stable) |stable_value| {
        if (decryptParsedMessage(parsed, &stable_value.recipient_key, &plaintext_buffer, &ad_buffer)) |plaintext| {
            var authenticated_message: AuthenticatedMessage = undefined;
            if (!decodeAuthenticated(&authenticated_message, endpoint, plaintext, null)) return;
            if (!acceptExpectedMessage(actor, env, &authenticated_message)) return;
            switch (actor.sessions.acceptAuthenticated(endpoint, &parsed.static_header.nonce, now_ns)) {
                .accepted => authenticated(actor, env, &authenticated_message),
                .exhausted => if (sendWhoareyou(actor, env, endpoint, &parsed.static_header.nonce))
                    std.debug.assert(actor.sessions.remove(endpoint)),
                .replay, .missing => {},
            }
            return;
        }
    }

    if (actor.requests.pendingKeys(endpoint)) |pending| {
        if (decryptParsedMessage(parsed, &pending.keys.recipient_key, &plaintext_buffer, &ad_buffer)) |plaintext| {
            var authenticated_message: AuthenticatedMessage = undefined;
            if (!decodeAuthenticated(&authenticated_message, endpoint, plaintext, null)) return;
            if (!acceptExpectedMessage(actor, env, &authenticated_message)) return;
            if (@import("builtin").is_test) if (env.pending_promotion_hook) |hook| {
                hook.run(hook.context, actor, pending);
            };
            var accepted = session_book.StableSession{
                .initiator_key = pending.keys.initiator_key,
                .recipient_key = pending.keys.recipient_key,
            };
            std.debug.assert(accepted.seen_nonces.insert(&parsed.static_header.nonce));
            if (!actor.requests.promotePending(pending)) return;
            actor.sessions.put(endpoint, accepted, now_ns);
            authenticated(actor, env, &authenticated_message);
            outbound.drainEndpoint(actor, env, endpoint);
            return;
        }
    }

    if (actor.responses.candidate(endpoint, now_ns)) |candidate| {
        if (decryptParsedMessage(parsed, &candidate.keys.recipient_key, &plaintext_buffer, &ad_buffer)) |plaintext| {
            var authenticated_message: AuthenticatedMessage = undefined;
            if (!decodeAuthenticated(&authenticated_message, endpoint, plaintext, null)) return;
            if (!acceptExpectedMessage(actor, env, &authenticated_message)) return;
            var accepted = session_book.StableSession{
                .initiator_key = candidate.keys.initiator_key,
                .recipient_key = candidate.keys.recipient_key,
            };
            std.debug.assert(accepted.seen_nonces.insert(&parsed.static_header.nonce));
            if (!actor.responses.acceptCandidate(candidate)) return;
            actor.sessions.put(endpoint, accepted, now_ns);
            authenticated(actor, env, &authenticated_message);
            return;
        }
    }
    _ = sendWhoareyou(actor, env, endpoint, &parsed.static_header.nonce);
}

fn decodeAuthenticated(
    out: *AuthenticatedMessage,
    endpoint: types.Endpoint,
    plaintext: []const u8,
    validated_enr: ?*const enr.ValidatedEnr,
) bool {
    message.DecodedMessage.decodeInto(&out.decoded, plaintext) catch return false;
    out.endpoint = endpoint;
    out.handshake_enr = if (validated_enr) |value| value.* else null;
    return true;
}

fn acceptExpectedMessage(actor: *Actor, env: Env, authenticated_message: *const AuthenticatedMessage) bool {
    if (env.expected_credit == null) return true;
    if (!rpc.isExpectedResponse(actor, &authenticated_message.decoded, authenticated_message.endpoint)) return false;
    env.commitExpected();
    return true;
}

fn authenticated(actor: *Actor, env: Env, authenticated_message: *const AuthenticatedMessage) void {
    const endpoint = authenticated_message.endpoint;
    const responsive = actor.peers.markResponsive(endpoint.node_id, endpoint.addr, outbound.nowNs(env.io), null);
    actor.publishConnection(env.outbox, endpoint.node_id, responsive.transition);
    if (responsive.eviction_candidate) |candidate| actor.probeEviction(env, candidate);
    rpc.dispatch(actor, env, &authenticated_message.decoded, endpoint);
}

fn handleWhoareyou(actor: *Actor, env: Env, parsed: *const packet.DecodedPacket, whoareyou: packet.WhoareyouAuthdata, from: types.Address) void {
    // This exact reservation check is intentionally first. A competing
    // challenge must be rejected before key generation, signing, or wire output.
    const now_ns = outbound.nowNs(env.io);
    const source: WhoareyouSource = if (actor.requests.challenge(&parsed.static_header.nonce, from)) |preparation|
        .{ .request = preparation }
    else |err| switch (err) {
        error.InvalidChallenge => .{ .response = actor.responses.challenge(
            from,
            &parsed.static_header.nonce,
            now_ns,
            env.ingress,
        ) orelse return },
        else => return,
    };
    switch (source) {
        .request => |preparation| actor.requests.preflightHandshake(preparation) catch return,
        .response => {},
    }
    env.commitExpected();
    var response_recovery_transferred = false;
    defer if (!response_recovery_transferred) switch (source) {
        .request => {},
        .response => |view| _ = actor.responses.failRecovery(view, env.ingress),
    };
    const recovery: RecoveryMaterial = switch (source) {
        .request => |preparation| .{
            .endpoint = preparation.handle.key.endpoint,
            .dest_pubkey = preparation.recovery.dest_pubkey,
            .plaintext = preparation.recovery.plaintext,
        },
        .response => |view| .{
            .endpoint = view.handle.endpoint,
            .dest_pubkey = view.dest_pubkey,
            .plaintext = types.PacketBytes.init(view.plaintext.slice()) catch unreachable,
        },
    };
    const remote_seq = whoareyou.enr_seq;
    var challenge_data: [packet.WHOAREYOU_CHALLENGE_DATA_SIZE]u8 = undefined;
    @memcpy(challenge_data[0..packet.MASKING_IV_SIZE], &parsed.masking_iv);
    @memcpy(challenge_data[packet.MASKING_IV_SIZE..], parsed.header_raw);

    var candidates = RandomSecretCandidates{ .io = env.io };
    const ephemeral = generateEphemeral(&candidates, null) orelse return;
    const ephemeral_pubkey = secp.compressedPubkey(&ephemeral);
    const keys = session_crypto.deriveKeys(
        &ephemeral,
        &recovery.dest_pubkey,
        &actor.local_node_id,
        &recovery.endpoint.node_id,
        &challenge_data,
    ) catch return;
    const signature = session_crypto.signIdNonce(
        &actor.local_key_pair,
        &challenge_data,
        &ephemeral_pubkey,
        &recovery.endpoint.node_id,
    ) catch return;
    const local_enr: []const u8 = if (actor.local.raw) |*raw| if (remote_seq < actor.local.seq) raw.slice() else &.{} else &.{};
    var authdata_buffer: [handshake.MAX_AUTHDATA_SIZE]u8 = undefined;
    const authdata = handshake.buildAuthdata(
        &authdata_buffer,
        actor.local_node_id,
        &signature,
        &ephemeral_pubkey,
        local_enr,
    ) catch return;
    var nonce: [packet.NONCE_SIZE]u8 = undefined;
    env.io.random(&nonce);
    var masking_iv: [packet.MASKING_IV_SIZE]u8 = undefined;
    env.io.random(&masking_iv);
    var datagram_buffer: [packet.MAX_PACKET_SIZE]u8 = undefined;
    const datagram = packet.encodeMessagePacketInto(&datagram_buffer, .{
        .kind = .handshake,
        .masking_iv = &masking_iv,
        .recipient_node_id = &recovery.endpoint.node_id,
        .nonce = &nonce,
        .authdata = authdata,
        .write_key = &keys.initiator_key,
        .plaintext = recovery.plaintext.slice(),
    }) catch {
        failRequestRecovery(actor, env, source, .packet_too_large);
        return;
    };
    const retained_datagram = types.PacketBytes.init(datagram) catch return;
    const effect: actor_mod.ActorEffect = switch (source) {
        .request => |preparation| blk: {
            const handle = actor.requests.beginHandshake(preparation, .{
                .initiator_key = keys.initiator_key,
                .recipient_key = keys.recipient_key,
            }, outbound.deadlineNs(now_ns, actor.request_timeout_ms)) catch return;
            break :blk .{ .handshake = .{
                .handle = .{ .request = handle },
                .packet = retained_datagram,
            } };
        },
        .response => |view| blk: {
            const handle = actor.responses.beginHandshake(view, .{
                .initiator_key = keys.initiator_key,
                .recipient_key = keys.recipient_key,
            }, now_ns) catch return;
            response_recovery_transferred = true;
            break :blk .{ .handshake = .{
                .handle = .{ .response = handle },
                .packet = retained_datagram,
            } };
        },
    };
    const effects = env.effects orelse unreachable;
    effects.push(effect) catch {
        actor.applyEffectCompletion(env, effect, .failed);
        return;
    };
    response_recovery_transferred = true;
}

fn failRequestRecovery(actor: *Actor, env: Env, source: WhoareyouSource, failure: request_results.RequestSendFailure) void {
    switch (source) {
        .request => |preparation| _ = completion.finish(actor, env, preparation.handle.key, .failure, .{ .send_failure = failure }),
        .response => |view| _ = actor.responses.failRecovery(view, env.ingress),
    }
}

const RandomSecretCandidates = struct {
    io: std.Io,

    fn next(self: *RandomSecretCandidates) [32]u8 {
        var candidate: [32]u8 = undefined;
        self.io.random(&candidate);
        return candidate;
    }
};

fn generateEphemeral(candidates: anytype, attempts_out: ?*usize) ?secp.KeyPair {
    var attempts: usize = 0;
    defer {
        if (attempts_out) |out| out.* = attempts;
    }
    while (attempts < MAX_EPHEMERAL_KEY_ATTEMPTS) {
        const candidate = candidates.next();
        attempts += 1;
        if (secp.keyPairFromSecret(&candidate)) |key_pair| return key_pair else |_| {}
    }
    return null;
}

test "invalid ephemeral candidates exhaust the fixed bound before wire output" {
    const RecordingSender = @import("../test_support/recording_sender.zig").RecordingSender;
    const ZeroCandidates = struct {
        generated: usize = 0,

        fn next(self: *@This()) [32]u8 {
            self.generated += 1;
            return [_]u8{0} ** 32;
        }
    };
    var candidates = ZeroCandidates{};
    var attempts: usize = 0;
    var recording = RecordingSender.init(std.testing.allocator);
    defer recording.deinit();

    try std.testing.expect(generateEphemeral(&candidates, &attempts) == null);
    try std.testing.expectEqual(MAX_EPHEMERAL_KEY_ATTEMPTS, attempts);
    try std.testing.expectEqual(MAX_EPHEMERAL_KEY_ATTEMPTS, candidates.generated);
    try std.testing.expectEqual(@as(usize, 0), recording.datagrams.items.len);
}

fn handleHandshake(actor: *Actor, env: Env, parsed: *const packet.DecodedPacket, authdata: handshake.Authdata, from: types.Address) void {
    const endpoint = types.Endpoint{ .node_id = authdata.src_id, .addr = from };
    const now_ns = outbound.nowNs(env.io);
    const challenge = actor.sessions.peekChallenge(endpoint, now_ns) orelse return;
    if (@import("builtin").is_test) if (env.handshake_challenge_hook) |hook| {
        hook.run(hook.context, actor, env.ingress, challenge);
    };
    const known = actor.peers.known(&endpoint.node_id);
    const validated_enr: ?enr.ValidatedEnr = if (authdata.maybe_enr) |raw| blk: {
        const validated = enr.ValidatedEnr.init(raw) catch return;
        if (!std.mem.eql(u8, &validated.node_id, &endpoint.node_id)) return;
        break :blk validated;
    } else null;
    const supplied_enr_pubkey = if (validated_enr) |*validated| validated.parsed.pubkey orelse return else null;
    const sender_pubkey = if (known) |value|
        value.pubkey
    else
        supplied_enr_pubkey orelse return;
    if (supplied_enr_pubkey) |value| if (!std.mem.eql(u8, &value, &sender_pubkey)) return;
    session_crypto.verifyIdSignature(
        authdata.id_sig,
        &sender_pubkey,
        &challenge.challenge_data,
        authdata.eph_pubkey,
        &actor.local_node_id,
    ) catch return;
    const keys = session_crypto.deriveKeys(
        &actor.local_key_pair,
        authdata.eph_pubkey,
        &endpoint.node_id,
        &actor.local_node_id,
        &challenge.challenge_data,
    ) catch return;
    var plaintext_buffer: [packet.MAX_PACKET_SIZE]u8 = undefined;
    defer std.crypto.secureZero(u8, &plaintext_buffer);
    var ad_buffer: [packet.MAX_PACKET_SIZE]u8 = undefined;
    const plaintext = packet.decryptMessageInto(
        &plaintext_buffer,
        &ad_buffer,
        &keys.initiator_key,
        &parsed.static_header.nonce,
        parsed.message_ciphertext,
        &parsed.masking_iv,
        parsed.header_raw,
    ) catch return;
    var authenticated_message: AuthenticatedMessage = undefined;
    if (!decodeAuthenticated(
        &authenticated_message,
        endpoint,
        plaintext,
        if (validated_enr) |*validated| validated else null,
    )) return;
    env.commitExpected();
    var stable = session_book.StableSession{
        .initiator_key = keys.recipient_key,
        .recipient_key = keys.initiator_key,
    };
    std.debug.assert(stable.seen_nonces.insert(&challenge.triggering_nonce));
    std.debug.assert(stable.seen_nonces.insert(&parsed.static_header.nonce));

    const challenge_removed = actor.sessions.removeChallenge(challenge.handle, env.ingress);
    if (@import("builtin").is_test) {
        if (env.handshake_challenge_hook == null) std.debug.assert(challenge_removed);
    } else std.debug.assert(challenge_removed);
    actor.sessions.put(endpoint, stable, now_ns);
    const responsive = actor.peers.acceptValidatedHandshake(
        endpoint.node_id,
        &sender_pubkey,
        endpoint.addr,
        if (authenticated_message.handshake_enr) |*validated| validated else null,
        now_ns,
    );
    actor.publishConnection(env.outbox, endpoint.node_id, responsive.transition);
    if (responsive.eviction_candidate) |candidate| actor.probeEviction(env, candidate);
    rpc.dispatch(actor, env, &authenticated_message.decoded, endpoint);
}

fn sendWhoareyou(actor: *Actor, env: Env, endpoint: types.Endpoint, request_nonce: *const [12]u8) bool {
    const now_ns = outbound.nowNs(env.io);
    const existing = actor.sessions.preflightChallenge(endpoint, request_nonce, now_ns) catch return false;
    if (existing) |challenge| {
        const effect = actor_mod.ActorEffect{ .whoareyou = .{
            .handle = challenge.handle,
            .packet = challenge.datagram,
        } };
        const effects = env.effects orelse unreachable;
        effects.push(effect) catch return false;
        return true;
    }
    if (!actor.sessions.allowWhoareyou(endpoint.addr, now_ns)) return false;
    var id_nonce: [packet.ID_NONCE_SIZE]u8 = undefined;
    env.io.random(&id_nonce);
    var masking_iv: [packet.MASKING_IV_SIZE]u8 = undefined;
    env.io.random(&masking_iv);
    var challenge_data: [packet.WHOAREYOU_CHALLENGE_DATA_SIZE]u8 = undefined;
    var remote_enr: ?enr.RawEnr = null;
    var remote_seq: u64 = 0;
    if (actor.peers.activeRoute(&endpoint.node_id)) |route| {
        remote_seq = route.enr_seq;
        remote_enr = route.enr;
    }
    var buffer: [packet.WHOAREYOU_CHALLENGE_DATA_SIZE]u8 = undefined;
    const datagram = packet.encodeWhoareyouPacketInto(&buffer, .{
        .masking_iv = &masking_iv,
        .recipient_node_id = &endpoint.node_id,
        .request_nonce = request_nonce,
        .id_nonce = &id_nonce,
        .enr_seq = remote_seq,
    }, &challenge_data) catch return false;
    const retained = types.PacketBytes.init(datagram) catch return false;
    var permit = env.ingress.acquire(
        endpoint.addr,
        @import("../admission.zig").challengePacketBudget(actor.request_retries),
    ) catch return false;
    const handle = actor.sessions.publishChallenge(endpoint, .{
        .challenge_data = challenge_data,
        .triggering_nonce = request_nonce.*,
        .datagram = retained,
        .remote_enr = remote_enr,
        .prepared_at_ns = now_ns,
    }, &permit, env.ingress) catch {
        permit.release(env.ingress);
        return false;
    };
    const effect = actor_mod.ActorEffect{ .whoareyou = .{
        .handle = handle,
        .packet = retained,
    } };
    const effects = env.effects orelse unreachable;
    effects.push(effect) catch {
        actor.applyEffectCompletion(env, effect, .failed);
        return false;
    };
    return true;
}
