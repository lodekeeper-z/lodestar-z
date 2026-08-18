const std = @import("std");
const actor_mod = @import("../actor.zig");
const enr = @import("../enr.zig");
const handshake = @import("../protocol/handshake.zig");
const packet = @import("../protocol/packet.zig");
const secp = @import("../secp256k1.zig");
const session_crypto = @import("../protocol/session.zig");
const session_book = @import("../state/session_book.zig");
const request_book = @import("../state/request_book.zig");
const response_book = @import("../state/response_book.zig");
const types = @import("../types.zig");
const outbound = @import("outbound.zig");
const rpc = @import("rpc.zig");

const Actor = actor_mod.Actor;
const Env = actor_mod.Env;

const MAX_HANDSHAKE_AUTHDATA: usize = 34 + @as(usize, handshake.sig_size) + @as(usize, handshake.eph_key_size) + enr.MAX_ENR_SIZE;
const MAX_EPHEMERAL_KEY_ATTEMPTS: usize = 32;

const WhoareyouSource = union(enum) {
    request: request_book.ChallengePreparation,
    response: response_book.ChallengeView,
};

const RecoveryMaterial = struct {
    endpoint: types.Endpoint,
    dest_pubkey: [33]u8,
    plaintext: types.PacketBytes,
};

pub fn handlePacket(actor: *Actor, env: Env, raw: []u8, from: types.Address) void {
    if (raw.len > packet.MAX_PACKET_SIZE) return;
    var parsed = packet.decode(raw, &actor.local_node_id) catch return;
    switch (parsed.static_header.flag) {
        packet.FLAG_MESSAGE => handleMessage(actor, env, &parsed, from),
        packet.FLAG_WHOAREYOU => handleWhoareyou(actor, env, &parsed, from),
        packet.FLAG_HANDSHAKE => handleHandshake(actor, env, &parsed, from),
        else => {},
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

fn handleMessage(actor: *Actor, env: Env, parsed: *packet.ParsedPacket, from: types.Address) void {
    if (parsed.authdata_raw.len != 32) return;
    const endpoint = types.Endpoint{ .node_id = parsed.authdata_raw[0..32].*, .addr = from };
    const now_ns = outbound.nowNs(env.io);

    // Non-mutating peek: unauthenticated ciphertext must not refresh
    // LRU/TTL recency. Recency is refreshed by the authenticated put below.
    const stable = actor.sessions.peek(endpoint, now_ns);
    if (stable) |stable_value| if (stable_value.seen_nonces.contains(&parsed.static_header.nonce)) return;

    var plaintext_buffer: [packet.MAX_PACKET_SIZE]u8 = undefined;
    var ad_buffer: [packet.MAX_PACKET_SIZE]u8 = undefined;
    if (stable) |stable_value| {
        if (decryptParsedMessage(parsed, &stable_value.recipient_key, &plaintext_buffer, &ad_buffer)) |plaintext| {
            var accepted = stable_value;
            if (!accepted.seen_nonces.insert(&parsed.static_header.nonce)) {
                if (sendWhoareyou(actor, env, endpoint, &parsed.static_header.nonce))
                    std.debug.assert(actor.sessions.remove(endpoint));
                return;
            }
            actor.sessions.put(endpoint, accepted, now_ns);
            authenticated(actor, env, endpoint, plaintext);
            return;
        }
    }

    if (actor.requests.pendingKeys(endpoint)) |pending| {
        if (decryptParsedMessage(parsed, &pending.keys.recipient_key, &plaintext_buffer, &ad_buffer)) |plaintext| {
            var accepted = session_book.StableSession{
                .initiator_key = pending.keys.initiator_key,
                .recipient_key = pending.keys.recipient_key,
            };
            std.debug.assert(accepted.seen_nonces.insert(&parsed.static_header.nonce));
            actor.sessions.put(endpoint, accepted, now_ns);
            actor.requests.promotePending(pending);
            authenticated(actor, env, endpoint, plaintext);
            outbound.drainEndpoint(actor, env, endpoint);
            return;
        }
    }

    if (actor.responses.candidate(endpoint, now_ns)) |candidate| {
        if (decryptParsedMessage(parsed, &candidate.recipient_key, &plaintext_buffer, &ad_buffer)) |plaintext| {
            var accepted = session_book.StableSession{
                .initiator_key = candidate.initiator_key,
                .recipient_key = candidate.recipient_key,
            };
            std.debug.assert(accepted.seen_nonces.insert(&parsed.static_header.nonce));
            std.debug.assert(actor.responses.removeCandidate(endpoint));
            actor.sessions.put(endpoint, accepted, now_ns);
            authenticated(actor, env, endpoint, plaintext);
            return;
        }
    }
    _ = sendWhoareyou(actor, env, endpoint, &parsed.static_header.nonce);
}

fn authenticated(actor: *Actor, env: Env, endpoint: types.Endpoint, plaintext: []const u8) void {
    const responsive = actor.peers.markResponsive(endpoint.node_id, endpoint.addr, outbound.nowNs(env.io), null);
    actor.publishConnection(env.outbox, endpoint.node_id, responsive.transition);
    if (responsive.eviction_candidate) |candidate| actor.probeEviction(env, candidate);
    rpc.dispatch(actor, env, plaintext, endpoint);
}

fn handleWhoareyou(actor: *Actor, env: Env, parsed: *packet.ParsedPacket, from: types.Address) void {
    if (parsed.authdata_raw.len != packet.WHOAREYOU_AUTHDATA_SIZE) return;
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
    const recovery: RecoveryMaterial = switch (source) {
        .request => |preparation| .{
            .endpoint = preparation.key.endpoint,
            .dest_pubkey = preparation.recovery.dest_pubkey,
            .plaintext = preparation.recovery.plaintext,
        },
        .response => |view| .{
            .endpoint = view.endpoint,
            .dest_pubkey = view.dest_pubkey,
            .plaintext = view.plaintext,
        },
    };
    const remote_seq = std.mem.readInt(u64, parsed.authdata_raw[16..24], .big);
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
    var authdata_buffer: [MAX_HANDSHAKE_AUTHDATA]u8 = undefined;
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
    }) catch return;
    env.sender.send(from, datagram) catch return;
    switch (source) {
        .request => |preparation| actor.requests.commitChallenge(preparation, .{
            .initiator_key = keys.initiator_key,
            .recipient_key = keys.recipient_key,
        }, outbound.deadlineNs(outbound.nowNs(env.io), actor.request_timeout_ms)),
        .response => |view| {
            actor.responses.commitCandidate(view, .{
                .initiator_key = keys.initiator_key,
                .recipient_key = keys.recipient_key,
            }, outbound.nowNs(env.io), env.ingress);
        },
    }
    outbound.noteSent(actor, recovery.plaintext.slice());
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

fn handleHandshake(actor: *Actor, env: Env, parsed: *packet.ParsedPacket, from: types.Address) void {
    const authdata = handshake.parseAuthdata(parsed.authdata_raw) catch return;
    const endpoint = types.Endpoint{ .node_id = authdata.src_id, .addr = from };
    const now_ns = outbound.nowNs(env.io);
    const challenge = actor.sessions.peekChallenge(endpoint, now_ns) orelse return;
    const known = actor.peers.known(&endpoint.node_id);
    const sender_pubkey = if (known) |value|
        value.pubkey
    else blk: {
        const raw = authdata.maybe_enr orelse return;
        break :blk handshake.pubkeyFromEnr(raw, endpoint.node_id) catch return;
    };
    var endpoint_verified = false;
    if (authdata.maybe_enr) |raw| {
        handshake.verifyEnrEndpoint(raw, endpoint.node_id, from, actor.allow_unverified_sessions) catch return;
        endpoint_verified = !actor.allow_unverified_sessions;
    } else if (challenge.remote_enr) |*raw| {
        handshake.verifyEnrEndpoint(raw.slice(), endpoint.node_id, from, actor.allow_unverified_sessions) catch return;
        endpoint_verified = !actor.allow_unverified_sessions;
    }
    const runtime_contact_trusted = if (known) |value| value.runtime_contact_trusted and value.addr.eql(&from) else false;
    if (!actor.allow_unverified_sessions and !endpoint_verified and !runtime_contact_trusted) return;
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
    var stable = session_book.StableSession{
        .initiator_key = keys.recipient_key,
        .recipient_key = keys.initiator_key,
    };
    std.debug.assert(stable.seen_nonces.insert(&challenge.triggering_nonce));
    std.debug.assert(stable.seen_nonces.insert(&parsed.static_header.nonce));

    std.debug.assert(actor.sessions.removeChallenge(endpoint, env.ingress));
    actor.sessions.put(endpoint, stable, now_ns);
    const responsive = actor.peers.acceptHandshake(endpoint.node_id, &sender_pubkey, endpoint.addr, authdata.maybe_enr, now_ns);
    actor.publishConnection(env.outbox, endpoint.node_id, responsive.transition);
    if (responsive.eviction_candidate) |candidate| actor.probeEviction(env, candidate);
    rpc.dispatch(actor, env, plaintext, endpoint);
}

fn sendWhoareyou(actor: *Actor, env: Env, endpoint: types.Endpoint, request_nonce: *const [12]u8) bool {
    const now_ns = outbound.nowNs(env.io);
    if (actor.sessions.peekChallenge(endpoint, now_ns)) |challenge| {
        if (!std.mem.eql(u8, &challenge.triggering_nonce, request_nonce)) return false;
        env.sender.send(endpoint.addr, challenge.datagram.slice()) catch return false;
        return true;
    }
    _ = actor.sessions.removeExpiredChallenge(endpoint, now_ns, env.ingress);
    if (!actor.sessions.allowWhoareyou(endpoint.addr, now_ns)) return false;
    var id_nonce: [packet.ID_NONCE_SIZE]u8 = undefined;
    env.io.random(&id_nonce);
    var masking_iv: [packet.MASKING_IV_SIZE]u8 = undefined;
    env.io.random(&masking_iv);
    var challenge_data: [packet.WHOAREYOU_CHALLENGE_DATA_SIZE]u8 = undefined;
    var remote_enr: ?enr.RawEnr = null;
    var remote_seq: u64 = 0;
    if (actor.peers.routing.getEntry(&endpoint.node_id)) |entry| {
        remote_seq = entry.enr_seq;
        remote_enr = entry.enr;
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
    env.sender.send(endpoint.addr, datagram) catch {
        permit.release(env.ingress);
        return false;
    };
    actor.sessions.putChallenge(endpoint, .{
        .challenge_data = challenge_data,
        .triggering_nonce = request_nonce.*,
        .datagram = retained,
        .admission = permit.move(),
        .remote_enr = remote_enr,
    }, now_ns, env.ingress);
    return true;
}
