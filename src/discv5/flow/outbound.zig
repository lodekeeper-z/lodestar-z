const std = @import("std");
const actor_mod = @import("../actor.zig");
const message = @import("../protocol/message.zig");
const metrics = @import("../metrics.zig");
const packet = @import("../protocol/packet.zig");
const request_book = @import("../state/request_book.zig");
const types = @import("../types.zig");
const util = @import("../util.zig");

const Actor = actor_mod.Actor;
const Env = actor_mod.Env;

pub fn prepareTracked(
    actor: *Actor,
    context: actor_mod.TransitionContext,
    endpoint: types.Endpoint,
    dest_pubkey: *const [33]u8,
    req_id: message.ReqId,
    kind: types.RequestKind,
    distances: []const u16,
    plaintext: []const u8,
    origin: types.RequestOrigin,
) !actor_mod.OutboundRequestAction {
    const now_ns = nowNs(context.io);
    if (actor.requests.shouldQueue(endpoint)) {
        // RequestBook.queue is the canonical policy point for which origins
        // may wait behind endpoint establishment (health/eviction never do).
        try actor.requests.queue(try .init(origin, endpoint, dest_pubkey, req_id, kind, distances, plaintext, deadlineNs(now_ns, actor.request_timeout_ms)));
        return .{ .queued = req_id };
    }
    const requested_distances = request_book.RequestDistances.fromSlice(distances);
    return .{ .send = try prepareDispatch(actor, context, endpoint, dest_pubkey, req_id, kind, &requested_distances, plaintext, origin) };
}

pub fn emitPrepared(
    env: Env,
    action: actor_mod.OutboundRequestAction,
) !void {
    const effects = env.request_effects orelse unreachable;
    switch (action) {
        .queued => {},
        .send => |effect| effects.push(.{ .request = effect }) catch {
            effect.abortPreparation(env.ingress);
            return error.TooManyActiveRequests;
        },
    }
}

pub fn drainEndpoint(actor: *Actor, env: Env, endpoint: types.Endpoint) void {
    const queued = actor.requests.firstQueued(endpoint) orelse return;
    const effect = prepareDispatch(
        actor,
        .{ .io = env.io, .ingress = env.ingress },
        queued.endpoint,
        &queued.dest_pubkey,
        queued.req_id,
        queued.kind,
        &queued.requested_distances,
        queued.plaintext.slice(),
        queued.origin,
    ) catch return;
    emitPrepared(env, .{ .send = effect }) catch return;
}

fn prepareDispatch(
    actor: *Actor,
    context: actor_mod.TransitionContext,
    endpoint: types.Endpoint,
    dest_pubkey: *const [33]u8,
    req_id: message.ReqId,
    kind: types.RequestKind,
    requested_distances: *const request_book.RequestDistances,
    plaintext: []const u8,
    origin: types.RequestOrigin,
) !actor_mod.SendDatagramEffect {
    const now_ns = nowNs(context.io);
    var packet_buffer: [packet.MAX_PACKET_SIZE]u8 = undefined;
    const stable = actor.sessions.get(endpoint, now_ns);
    const encoded = if (stable) |session_value|
        try encodeMessage(actor, context.io, &packet_buffer, endpoint.node_id, &session_value.initiator_key, plaintext)
    else
        try encodeProbe(actor, context.io, &packet_buffer, endpoint.node_id, plaintext);
    actor.responses.removeExpired(endpoint.addr, &encoded.nonce, now_ns, context.ingress);
    if (actor.responses.hasLive(endpoint.addr, &encoded.nonce, now_ns)) return error.DuplicateChallenge;

    const recovery = request_book.RecoveryState{
        .nonce = encoded.nonce,
        .dest_pubkey = dest_pubkey.*,
        .plaintext = try .init(plaintext),
    };
    const phase: request_book.Phase = if (stable == null)
        .{ .awaiting_whoareyou = .{ .retry_packet = try .init(encoded.bytes), .recovery = recovery } }
    else
        .{ .awaiting_response = .{ .recovery = recovery, .wait = .session_request } };
    const response = actor.requests.makeExpectation(kind, requested_distances);
    const transient_packet = if (stable == null) null else try types.PacketBytes.init(encoded.bytes);
    const prepared = try actor.requests.prepareActive(
        context.ingress,
        .init(endpoint, req_id),
        origin,
        response,
        phase,
        deadlineNs(now_ns, actor.request_timeout_ms),
        stable == null,
    );
    return .{
        .storage = if (transient_packet) |send_packet|
            .{ .transient = .{ .prepared = prepared, .packet = send_packet } }
        else
            .{ .retained = prepared },
    };
}

pub fn sendResponse(actor: *Actor, env: Env, endpoint: types.Endpoint, plaintext: []const u8) !void {
    const now_ns = nowNs(env.io);
    const stable = actor.sessions.get(endpoint, now_ns) orelse return error.NoSession;
    const known = actor.peers.known(&endpoint.node_id) orelse return error.UnknownPeer;
    if (!known.addr.eql(&endpoint.addr)) return error.EndpointMismatch;
    const retained_plaintext = try types.PacketBytes.init(plaintext);
    var buffer: [packet.MAX_PACKET_SIZE]u8 = undefined;
    var encoded: Encoded = undefined;
    var attempts: usize = 0;
    while (attempts < 32) : (attempts += 1) {
        encoded = try encodeMessage(actor, env.io, &buffer, endpoint.node_id, &stable.initiator_key, plaintext);
        actor.responses.removeExpired(endpoint.addr, &encoded.nonce, now_ns, env.ingress);
        if (!actor.requests.hasChallenge(&encoded.nonce, endpoint.addr) and
            !actor.responses.hasLive(endpoint.addr, &encoded.nonce, now_ns)) break;
    } else return error.NonceGenerationExhausted;
    var permit = try env.ingress.acquire(endpoint.addr, @import("../admission.zig").RESPONSE_RECOVERY_PACKET_BUDGET);
    const effect = actor_mod.ActorEffect{ .response = .{
        .endpoint = endpoint,
        .nonce = encoded.nonce,
        .dest_pubkey = known.pubkey,
        .plaintext = retained_plaintext,
        .packet = try .init(encoded.bytes),
        .admission = permit.move(),
        .prepared_at_ns = now_ns,
    } };
    const effects = env.request_effects orelse unreachable;
    effects.push(effect) catch {
        effect.abortPreparation(env.ingress);
        return error.TooManyActiveRequests;
    };
}

pub const Encoded = struct {
    bytes: []const u8,
    nonce: [packet.NONCE_SIZE]u8,
};

pub fn encodeProbe(actor: *Actor, io: std.Io, out: []u8, node_id: types.NodeId, plaintext: []const u8) !Encoded {
    var fake_key: [16]u8 = undefined;
    io.random(&fake_key);
    return encodeMessage(actor, io, out, node_id, &fake_key, plaintext);
}

pub fn encodeMessage(
    actor: *Actor,
    io: std.Io,
    out: []u8,
    node_id: types.NodeId,
    write_key: *const [16]u8,
    plaintext: []const u8,
) !Encoded {
    var nonce: [packet.NONCE_SIZE]u8 = undefined;
    io.random(&nonce);
    var masking_iv: [packet.MASKING_IV_SIZE]u8 = undefined;
    io.random(&masking_iv);
    const encoded = try packet.encodeMessagePacketInto(out, .{
        .kind = .ordinary,
        .masking_iv = &masking_iv,
        .recipient_node_id = &node_id,
        .nonce = &nonce,
        .authdata = &actor.local_node_id,
        .write_key = write_key,
        .plaintext = plaintext,
    });
    return .{ .bytes = encoded, .nonce = nonce };
}

pub fn noteSent(actor: *Actor, plaintext: []const u8) void {
    if (plaintext.len == 0) return;
    if (metrics.MessageType.fromByte(plaintext[0])) |kind| actor.metrics.incSent(kind);
}

pub fn noteSentRequest(actor: *Actor, kind: types.RequestKind) void {
    actor.metrics.incSent(switch (kind) {
        .ping => .ping,
        .findnode => .findnode,
        .talkreq => .talkreq,
    });
}

pub const nowNs = util.nowNs;
pub const deadlineNs = util.deadlineNs;
