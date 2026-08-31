const std = @import("std");
const builtin = @import("builtin");
const admission = @import("admission.zig");
const addr_votes = @import("service/addr_votes.zig");
const config_mod = @import("config.zig");
const enr = @import("enr.zig");
const events = @import("events.zig");
const completion = @import("flow/completion.zig");
const lookup_mod = @import("service/lookup.zig");
const lookup_results = @import("lookup_results.zig");
const message = @import("protocol/message.zig");
const packet = @import("protocol/packet.zig");
const metrics_mod = @import("metrics.zig");
const outbound = @import("flow/outbound.zig");
const maintenance_flow = @import("flow/maintenance.zig");
const session_flow = @import("flow/session.zig");
const peer_store = @import("state/peer_store.zig");
const public_api = @import("public_api.zig");
const request_book = @import("state/request_book.zig");
const response_book = @import("state/response_book.zig");
const request_results = @import("request_results.zig");
const session_book = @import("state/session_book.zig");
const types = @import("types.zig");

const Allocator = std.mem.Allocator;
pub const MAX_LOOKUPS: usize = config_mod.MAX_LOOKUPS;

const LookupAttempt = struct {
    peer_id: types.NodeId,
    target: types.NodeId,
};

pub const LocalRecord = struct {
    raw: ?enr.RawEnr,
    seq: u64,
};
/// Ephemeral runtime capabilities; Actor never stores this context.
pub const Env = if (builtin.is_test) struct {
    io: std.Io,
    ingress: *admission.IngressAdmission,
    outbox: *events.EventOutbox,
    effects: ?*EffectQueue = null,
    lookup_results: ?*lookup_results.LookupResultOutbox = null,
    request_results: ?*request_results.RequestResultOutbox = null,
    expected_credit: ?*admission.ExpectedCredit = null,
    retry_nonce: ?[packet.NONCE_SIZE]u8 = null,
    response_nonce: ?[packet.NONCE_SIZE]u8 = null,
    response_preparation_attempts: ?*usize = null,
    handshake_preparation_attempts: ?*usize = null,
    handshake_challenge_hook: ?struct {
        context: *anyopaque,
        run: *const fn (*anyopaque, *Actor, *admission.IngressAdmission, session_book.ChallengeView) void,
    } = null,
    pending_promotion_hook: ?struct {
        context: *anyopaque,
        run: *const fn (*anyopaque, *Actor, request_book.PendingKeysView) void,
    } = null,
    response_candidate_hook: ?struct {
        context: *anyopaque,
        run: *const fn (*anyopaque, *Actor, response_book.CandidateView) void,
    } = null,

    pub fn commitExpected(self: Env, target: admission.PermitHandle) bool {
        const credit = self.expected_credit orelse return true;
        return credit.commit(self.ingress, target);
    }
} else struct {
    io: std.Io,
    ingress: *admission.IngressAdmission,
    outbox: *events.EventOutbox,
    effects: ?*EffectQueue = null,
    lookup_results: ?*lookup_results.LookupResultOutbox = null,
    request_results: ?*request_results.RequestResultOutbox = null,
    expected_credit: ?*admission.ExpectedCredit = null,

    pub fn commitExpected(self: Env, target: admission.PermitHandle) bool {
        const credit = self.expected_credit orelse return true;
        return credit.commit(self.ingress, target);
    }
};

/// Capabilities available to a synchronous Actor transition. Cancelable
/// transport execution is intentionally absent and remains Runtime-owned.
pub const TransitionContext = struct {
    io: std.Io,
    ingress: *admission.IngressAdmission,
};

pub const SendCompletion = enum {
    sent,
    failed,
    runtime_stopped,
};

pub const SendDatagramEffect = struct {
    handle: request_book.RequestHandle,
    packet: types.PacketBytes,

    pub fn requestId(self: *const SendDatagramEffect) message.ReqId {
        return self.handle.key.req_id;
    }

    pub fn destination(self: *const SendDatagramEffect) types.Address {
        return self.handle.key.endpoint.addr;
    }

    pub fn packetBytes(self: *const SendDatagramEffect) []const u8 {
        return self.packet.slice();
    }
};

pub const OutboundRequestAction = union(enum) {
    queued: types.RequestHandle,
    send: SendDatagramEffect,

    pub fn handle(self: *const OutboundRequestAction) types.RequestHandle {
        return switch (self.*) {
            .queued => |value| value,
            .send => |effect| effect.handle,
        };
    }

    pub fn requestId(self: *const OutboundRequestAction) message.ReqId {
        return self.handle().key.req_id;
    }
};

pub const ActorEffect = union(enum) {
    request: SendDatagramEffect,
    response: ResponseSendEffect,
    retry: RetrySendEffect,
    handshake: HandshakeSendEffect,
    whoareyou: WhoareyouSendEffect,

    pub fn destination(self: *const ActorEffect) types.Address {
        return switch (self.*) {
            .request => |*effect| effect.destination(),
            .response => |*effect| effect.handle.endpoint.addr,
            .retry => |*effect| effect.handle.request.key.endpoint.addr,
            .handshake => |*effect| switch (effect.handle) {
                .request => |handle| handle.request.key.endpoint.addr,
                .response => |handle| handle.response.endpoint.addr,
            },
            .whoareyou => |*effect| effect.handle.endpoint.addr,
        };
    }

    pub fn packetBytes(self: *const ActorEffect) []const u8 {
        return switch (self.*) {
            .request => |*effect| effect.packetBytes(),
            .response => |*effect| effect.packet.slice(),
            .retry => |*effect| effect.packet.slice(),
            .handshake => |*effect| effect.packet.slice(),
            .whoareyou => |*effect| effect.packet.slice(),
        };
    }

    pub fn requestId(self: *const ActorEffect) message.ReqId {
        return switch (self.*) {
            .request => |*effect| effect.requestId(),
            .response, .retry, .handshake, .whoareyou => unreachable,
        };
    }
};

pub fn CompactSendEffect(comptime Handle: type) type {
    return struct {
        handle: Handle,
        packet: types.PacketBytes,
    };
}

pub const ResponseSendEffect = CompactSendEffect(response_book.ResponseHandle);

pub const RetrySendEffect = CompactSendEffect(request_book.RetryHandle);

pub const WhoareyouSendEffect = CompactSendEffect(session_book.ChallengeHandle);

pub const WhoareyouSource = union(enum) {
    request: request_book.ChallengePreparation,
    response: response_book.ChallengeView,
};

pub const HandshakeHandle = union(enum) {
    request: request_book.HandshakeHandle,
    response: response_book.HandshakeHandle,
};

pub const HandshakeSendEffect = CompactSendEffect(HandshakeHandle);

const staged_response_send_effect_size = 1_376;
const staged_retry_send_effect_size = 1_384;
const request_handshake_handle_size = 96;
const handshake_handle_size = 104;
const handshake_send_effect_size = 1_392;
const challenge_handle_size = 72;
const whoareyou_send_effect_size = 1_360;
const exact_actor_effect_size = 1_400;
/// Production compile-time ceiling for the move-owned Runtime effect FIFO.
pub const MAX_ACTOR_EFFECT_SIZE: usize = 1_536;

comptime {
    if (@sizeOf(ActorEffect) > MAX_ACTOR_EFFECT_SIZE) {
        @compileError("ActorEffect exceeds the production 1536-byte ceiling");
    }
    if (@sizeOf(ActorEffect) != exact_actor_effect_size) {
        @compileError("ActorEffect must remain at the exact 1400-byte compact layout");
    }
    if (@sizeOf(request_book.HandshakeHandle) != request_handshake_handle_size or
        @sizeOf(HandshakeHandle) != handshake_handle_size or
        @typeInfo(HandshakeSendEffect).@"struct".fields.len != 2 or
        !@hasField(HandshakeSendEffect, "handle") or
        !@hasField(HandshakeSendEffect, "packet") or
        @sizeOf(HandshakeSendEffect) != handshake_send_effect_size)
    {
        @compileError("unified handshake effect must remain exact semantic handle plus packet at 1392 bytes");
    }
    if (@sizeOf(session_book.ChallengeHandle) != challenge_handle_size or
        @typeInfo(WhoareyouSendEffect).@"struct".fields.len != 2 or
        !@hasField(WhoareyouSendEffect, "handle") or
        !@hasField(WhoareyouSendEffect, "packet") or
        @sizeOf(WhoareyouSendEffect) != whoareyou_send_effect_size)
    {
        @compileError("WHOAREYOU effect must remain exact challenge handle plus packet at 1360 bytes");
    }
    if (@typeInfo(ResponseSendEffect).@"struct".fields.len != 2 or
        !@hasField(ResponseSendEffect, "handle") or
        !@hasField(ResponseSendEffect, "packet") or
        @sizeOf(ResponseSendEffect) != staged_response_send_effect_size)
    {
        @compileError("response effect must remain handle plus packet bytes at the staged 1376-byte layout");
    }
    if (@typeInfo(RetrySendEffect).@"struct".fields.len != 2 or
        !@hasField(RetrySendEffect, "handle") or
        !@hasField(RetrySendEffect, "packet") or
        @sizeOf(RetrySendEffect) != staged_retry_send_effect_size)
    {
        @compileError("retry effect must remain handle plus packet bytes at the staged 1384-byte layout");
    }
    for (.{ "admission", "permit", "transition", "deadline", "deadline_ns", "kind", "nonce", "probe", "plaintext", "enr", "remote_enr", "key", "keys", "source", "dest_pubkey", "destination", "prepared_at_ns" }) |field| {
        if (@hasField(RetrySendEffect, field)) {
            @compileError("compact retry effect may not regain canonical retry ownership");
        }
        if (@hasField(ResponseSendEffect, field)) {
            @compileError("compact response effect may not regain canonical response ownership");
        }
        if (@hasField(HandshakeSendEffect, field)) {
            @compileError("compact handshake effect may not regain canonical handshake ownership");
        }
        if (@hasField(WhoareyouSendEffect, field)) {
            @compileError("compact WHOAREYOU effect may not regain canonical challenge ownership");
        }
    }
}

/// Runtime-owned bounded output for Actor effects. Actor transitions may
/// append move-owned effects but never execute transport through this queue.
pub const EffectQueue = struct {
    storage: []ActorEffect,
    head: usize = 0,
    len: usize = 0,

    pub fn init(storage: []ActorEffect) EffectQueue {
        std.debug.assert(storage.len > 0);
        return .{ .storage = storage };
    }

    pub fn count(self: *const EffectQueue) usize {
        return self.len;
    }

    pub fn hasCapacity(self: *const EffectQueue) bool {
        return self.len < self.storage.len;
    }

    pub fn push(self: *EffectQueue, effect: ActorEffect) error{Full}!void {
        if (self.len == self.storage.len) return error.Full;
        const index = (self.head + self.len) % self.storage.len;
        self.storage[index] = effect;
        self.len += 1;
    }

    pub fn pop(self: *EffectQueue) ?ActorEffect {
        if (self.len == 0) return null;
        const effect = self.storage[self.head];
        self.head = (self.head + 1) % self.storage.len;
        self.len -= 1;
        return effect;
    }
};

pub const ProbeSnapshot = struct {
    endpoint: types.Endpoint,
    pubkey: [33]u8,
};

pub const Actor = struct {
    alloc: Allocator,
    local_key_pair: @import("secp256k1.zig").KeyPair,
    local_node_id: types.NodeId,
    local: LocalRecord,
    sessions: session_book.SessionBook,
    requests: request_book.RequestBook,
    responses: response_book.ResponseBook,
    peers: peer_store.PeerStore,
    lookups: std.AutoHashMap(u32, lookup_mod.Lookup),
    votes_ip4: addr_votes.AddrVotes,
    votes_ip6: addr_votes.AddrVotes,
    metrics: metrics_mod.ProtocolMetrics = .{},
    limits: config_mod.Limits,
    next_lookup_id: u32 = 1,
    lookup_count: u64 = 0,
    request_timeout_ms: u64,
    request_retries: u32,
    bucket_pending_timeout_ms: u64,
    lookup_config: lookup_mod.Config,
    ping_interval_ms: u64,
    enr_update: bool,
    addr_vote_cooldown_until_ns: i64 = std.math.minInt(i64),

    pub fn init(alloc: Allocator, config: config_mod.Config) !Actor {
        try config.validate();
        const local_node_id = config.localNodeId();
        const local = if (config.local_enr) |raw| blk: {
            const parsed = try enr.decode(raw);
            break :blk LocalRecord{ .raw = try .init(raw), .seq = parsed.seq };
        } else LocalRecord{ .raw = null, .seq = 0 };
        var sessions = try session_book.SessionBook.init(alloc, config);
        errdefer sessions.deinitEmpty(alloc);
        var requests = try request_book.RequestBook.init(alloc, config.limits);
        errdefer requests.deinitEmpty();
        var responses = try response_book.ResponseBook.init(alloc, config);
        errdefer responses.deinitEmpty(alloc);
        var peers = try peer_store.PeerStore.initWithFallbackCapacity(
            alloc,
            local_node_id,
            config.bind_addresses.ip4 != null,
            config.bind_addresses.ip6 != null,
            config.limits.contact_capacity,
        );
        errdefer peers.deinit();
        var lookups = std.AutoHashMap(u32, lookup_mod.Lookup).init(alloc);
        errdefer lookups.deinit();
        try lookups.ensureTotalCapacity(MAX_LOOKUPS);
        return .{
            .alloc = alloc,
            .local_key_pair = config.local_key_pair,
            .local_node_id = local_node_id,
            .local = local,
            .sessions = sessions,
            .requests = requests,
            .responses = responses,
            .peers = peers,
            .lookups = lookups,
            .votes_ip4 = .init(alloc, config.addr_votes_to_update_enr),
            .votes_ip6 = .init(alloc, config.addr_votes_to_update_enr),
            .limits = config.limits,
            .request_timeout_ms = config.request_timeout_ms,
            .request_retries = config.request_retries,
            .bucket_pending_timeout_ms = config.bucket_pending_timeout_ms,
            .lookup_config = .{
                .num_results = config.lookup_num_results,
                .parallelism = config.lookup_parallelism,
                .request_limit = config.lookup_request_limit,
                .timeout_ms = config.lookup_timeout_ms,
            },
            .ping_interval_ms = config.ping_interval_ms,
            .enr_update = config.enr_update,
        };
    }

    pub fn deinit(self: *Actor, ingress: *admission.IngressAdmission) void {
        var iterator = self.lookups.iterator();
        while (iterator.next()) |entry| entry.value_ptr.deinit(self.alloc);
        self.lookups.deinit();
        self.votes_ip4.deinit();
        self.votes_ip6.deinit();
        self.peers.deinit();
        self.responses.deinit(self.alloc, ingress);
        self.requests.deinit(ingress);
        self.sessions.deinit(self.alloc, ingress);
    }

    pub fn handlePacket(self: *Actor, env: Env, raw: []u8, from: types.Address) void {
        session_flow.handlePacket(self, env, raw, from);
    }

    pub fn preparePing(
        self: *Actor,
        context: TransitionContext,
        node_id: types.NodeId,
        origin: types.RequestOrigin,
    ) !OutboundRequestAction {
        const known = self.peers.known(&node_id) orelse return error.UnknownPeer;
        return self.preparePingResolved(context, .{ .node_id = node_id, .addr = known.addr }, &known.pubkey, origin);
    }

    fn preparePingResolved(
        self: *Actor,
        context: TransitionContext,
        endpoint: types.Endpoint,
        pubkey: *const [33]u8,
        origin: types.RequestOrigin,
    ) !OutboundRequestAction {
        const req_id = randomReqId(context.io);
        const ping = message.Ping{ .req_id = req_id, .enr_seq = self.local.seq };
        var buffer: [128]u8 = undefined;
        return outbound.prepareTracked(self, context, endpoint, pubkey, req_id, .ping, &.{}, try ping.encodeInto(&buffer), origin);
    }

    pub fn applyEffectCompletion(
        self: *Actor,
        env: Env,
        effect_value: anytype,
        completion_event: SendCompletion,
    ) void {
        if (@TypeOf(effect_value) == SendDatagramEffect) {
            self.applySendCompletion(env, effect_value, completion_event);
            return;
        }
        const effect: ActorEffect = effect_value;
        switch (effect) {
            .request => |request| self.applySendCompletion(env, request, completion_event),
            .response => |response| {
                if (!self.responses.completeResponseSend(response.handle, switch (completion_event) {
                    .sent => .sent,
                    .failed => .failed,
                    .runtime_stopped => .runtime_stopped,
                }, env.ingress)) return;
                if (completion_event == .sent) {
                    const nonce = response.handle.nonce;
                    const view = self.responses.challenge(response.handle.endpoint.addr, &nonce, outbound.nowNs(env.io), env.ingress) orelse return;
                    outbound.noteSent(self, view.plaintext.slice());
                }
            },
            .retry => |retry| {
                const completed = self.requests.completeRetry(retry.handle, switch (completion_event) {
                    .sent => .sent,
                    .failed => .failed,
                    .runtime_stopped => .runtime_stopped,
                }, env.ingress) orelse return;
                if (completion_event == .sent) outbound.noteSentRequest(self, completed.kind);
            },
            .handshake => |handshake_effect| switch (handshake_effect.handle) {
                .request => |handle| {
                    const completed = self.requests.completeHandshake(handle, switch (completion_event) {
                        .sent => .sent,
                        .failed => .failed,
                        .runtime_stopped => .runtime_stopped,
                    }) orelse return;
                    if (completion_event == .sent) outbound.noteSentRequest(self, completed.kind);
                },
                .response => |handle| {
                    const plaintext = self.responses.handshakePlaintext(handle) orelse return;
                    if (!self.responses.completeHandshake(handle, switch (completion_event) {
                        .sent => .sent,
                        .failed => .failed,
                        .runtime_stopped => .runtime_stopped,
                    }, env.ingress)) return;
                    if (completion_event == .sent) outbound.noteSent(self, plaintext.slice());
                },
            },
            .whoareyou => |whoareyou| {
                _ = self.sessions.completeChallengeSend(whoareyou.handle, switch (completion_event) {
                    .sent => .sent,
                    .failed => .failed,
                    .runtime_stopped => .runtime_stopped,
                }, env.ingress);
            },
        }
    }

    pub fn applySendCompletion(
        self: *Actor,
        env: Env,
        effect_value: anytype,
        completion_event: SendCompletion,
    ) void {
        const effect: SendDatagramEffect = if (@TypeOf(effect_value) == ActorEffect)
            switch (effect_value) {
                .request => |request| request,
            }
        else
            effect_value;
        switch (completion_event) {
            .sent => {
                const completed = self.requests.completeSending(effect.handle) orelse return;
                outbound.noteSentRequest(self, completed.kind);
                self.onRequestSendSuccess(env, completed.key, completed.origin);
                if (self.sessions.get(completed.key.endpoint, outbound.nowNs(env.io)) != null) {
                    outbound.drainEndpoint(self, env, completed.key.endpoint);
                }
            },
            .failed, .runtime_stopped => {
                const aborted = self.requests.abortSending(effect.handle, env.ingress) orelse return;
                if (completion_event == .runtime_stopped) {
                    self.onRequestSendStopped(env, aborted.key, aborted.origin);
                } else {
                    self.onRequestSendFailure(env, aborted.key, aborted.origin);
                }
            },
        }
    }

    fn onRequestSendStopped(self: *Actor, env: Env, key: types.RequestKey, origin: types.RequestOrigin) void {
        switch (origin) {
            .lookup => |id| self.finishLookup(env, id, .runtime_stopped),
            else => self.onRequestSendFailure(env, key, origin),
        }
    }

    fn onRequestSendSuccess(self: *Actor, env: Env, key: types.RequestKey, origin: types.RequestOrigin) void {
        switch (origin) {
            .maintenance => |reason| switch (reason) {
                .health => _ = self.peers.setNextPing(&key.endpoint.node_id, outbound.deadlineNs(outbound.nowNs(env.io), self.ping_interval_ms)),
                .enr_propagation, .enr_refresh => {},
            },
            .api, .reliable_api, .lookup, .detached_lookup, .eviction => {},
        }
    }

    fn onRequestSendFailure(self: *Actor, env: Env, key: types.RequestKey, origin: types.RequestOrigin) void {
        switch (origin) {
            .maintenance => |reason| switch (reason) {
                .health, .enr_propagation => _ = self.peers.cancelHealthRequest(key),
                .enr_refresh => {},
            },
            .eviction => |generation| {
                if (self.peers.currentEvictionTicket(&key.endpoint.node_id, generation)) |ticket| {
                    _ = self.peers.cancelEvictionRequest(ticket, key);
                }
            },
            .lookup => |id| {
                if (self.lookups.getPtr(id)) |lookup| {
                    lookup.onFailure(&key.endpoint.node_id, self.lookup_config);
                } else return;
                self.pumpLookup(env, id);
            },
            .api, .reliable_api, .detached_lookup => {},
        }
    }

    fn sendPingResolved(
        self: *Actor,
        env: Env,
        endpoint: types.Endpoint,
        pubkey: *const [33]u8,
        origin: types.RequestOrigin,
    ) !types.RequestHandle {
        var action = try self.preparePingResolved(.{ .io = env.io, .ingress = env.ingress }, endpoint, pubkey, origin);
        const handle = action.handle();
        try outbound.emitPrepared(self, env, action);
        return handle;
    }

    pub fn prepareFindNode(
        self: *Actor,
        context: TransitionContext,
        node_id: types.NodeId,
        distances: []const u16,
        origin: types.RequestOrigin,
    ) !OutboundRequestAction {
        const known = self.peers.known(&node_id) orelse return error.UnknownPeer;
        return self.prepareFindNodeResolved(context, .{ .node_id = node_id, .addr = known.addr }, &known.pubkey, distances, origin);
    }

    fn prepareFindNodeResolved(
        self: *Actor,
        context: TransitionContext,
        endpoint: types.Endpoint,
        pubkey: *const [33]u8,
        distances: []const u16,
        origin: types.RequestOrigin,
    ) !OutboundRequestAction {
        if (distances.len > types.MAX_OUTBOUND_FINDNODE_DISTANCES) return error.TooManyDistances;
        for (distances) |distance| {
            if (distance > 256) return error.InvalidDistance;
        }
        const req_id = randomReqId(context.io);
        const findnode = message.FindNode{ .req_id = req_id, .distances = distances };
        var buffer: [512]u8 = undefined;
        return outbound.prepareTracked(self, context, endpoint, pubkey, req_id, .findnode, distances, try findnode.encodeInto(&buffer), origin);
    }

    fn sendFindNodeResolved(
        self: *Actor,
        env: Env,
        endpoint: types.Endpoint,
        pubkey: *const [33]u8,
        distances: []const u16,
        origin: types.RequestOrigin,
    ) !types.RequestHandle {
        var action = try self.prepareFindNodeResolved(.{ .io = env.io, .ingress = env.ingress }, endpoint, pubkey, distances, origin);
        const handle = action.handle();
        try outbound.emitPrepared(self, env, action);
        return handle;
    }

    pub fn prepareTalkRequest(
        self: *Actor,
        context: TransitionContext,
        node_id: types.NodeId,
        protocol_name: []const u8,
        request: []const u8,
        origin: types.RequestOrigin,
    ) !OutboundRequestAction {
        const known = self.peers.known(&node_id) orelse return error.UnknownPeer;
        return self.prepareTalkRequestResolved(context, .{ .node_id = node_id, .addr = known.addr }, &known.pubkey, protocol_name, request, origin);
    }

    fn prepareTalkRequestResolved(
        self: *Actor,
        context: TransitionContext,
        endpoint: types.Endpoint,
        pubkey: *const [33]u8,
        protocol_name: []const u8,
        request: []const u8,
        origin: types.RequestOrigin,
    ) !OutboundRequestAction {
        const req_id = randomReqId(context.io);
        const talk = message.TalkReq{ .req_id = req_id, .protocol = protocol_name, .request = request };
        var buffer: [packet.MAX_PACKET_SIZE]u8 = undefined;
        const plaintext = try talk.encodeInto(&buffer);
        if (!packet.ordinaryMessageFits(plaintext.len)) return error.MessageTooLarge;
        return outbound.prepareTracked(self, context, endpoint, pubkey, req_id, .talkreq, &.{}, plaintext, origin);
    }

    fn sendTalkRequestResolved(
        self: *Actor,
        env: Env,
        endpoint: types.Endpoint,
        pubkey: *const [33]u8,
        protocol_name: []const u8,
        request: []const u8,
        origin: types.RequestOrigin,
    ) !types.RequestHandle {
        var action = try self.prepareTalkRequestResolved(.{ .io = env.io, .ingress = env.ingress }, endpoint, pubkey, protocol_name, request, origin);
        const handle = action.handle();
        try outbound.emitPrepared(self, env, action);
        return handle;
    }

    pub fn sendTalkResponse(self: *Actor, env: Env, endpoint: types.Endpoint, req_id: message.ReqId, response: []const u8) !void {
        const talk = message.TalkResp{ .req_id = req_id, .response = response };
        var buffer: [packet.MAX_PACKET_SIZE]u8 = undefined;
        const plaintext = try talk.encodeInto(&buffer);
        if (!packet.ordinaryMessageFits(plaintext.len)) return error.MessageTooLarge;
        try outbound.sendResponse(self, env, endpoint, plaintext);
    }

    pub fn addNode(self: *Actor, node_id: types.NodeId, pubkey: ?*const [33]u8, address: types.Address, raw: ?[]const u8, now_ns: i64) bool {
        return self.peers.addTrusted(node_id, pubkey, address, raw, now_ns);
    }

    pub fn addEnr(self: *Actor, outbox: *events.EventOutbox, raw: []const u8, now_ns: i64) bool {
        const validated = enr.ValidatedEnr.init(raw) catch return false;
        const node_id = validated.node_id;
        const pubkey = validated.parsed.pubkey orelse return false;
        const address = self.peers.addressForEnr(&validated.parsed) orelse return false;
        const previous = if (self.peers.findEnr(&node_id)) |bytes| enr.RawEnr.init(bytes) catch null else null;
        if (!self.peers.addValidatedTrustedEnr(node_id, &pubkey, address, &validated, now_ns)) return false;
        const stored = self.peers.findEnr(&node_id) orelse return false;
        if (!std.mem.eql(u8, stored, raw)) {
            // The routing table already held a same/newer-seq ENR and the
            // local-trust merge succeeded: the node is usable, but nothing
            // was added, so no event is emitted.
            return true;
        }
        if (previous) |value| if (std.mem.eql(u8, value.slice(), raw)) return true;
        const event_raw = self.alloc.dupe(u8, raw) catch {
            outbox.notePayloadDrop(.enr_added);
            return true;
        };
        const previous_raw = if (previous) |value| self.alloc.dupe(u8, value.slice()) catch {
            self.alloc.free(event_raw);
            outbox.notePayloadDrop(.enr_added);
            return true;
        } else null;
        outbox.publish(.{ .enr_added = .{ .node_id = node_id, .addr = address, .enr = event_raw, .replaced_enr = previous_raw } });
        return true;
    }

    pub fn setLocalEnr(self: *Actor, env: Env, raw: []const u8) !void {
        const parsed = try enr.decode(raw);
        const node_id = (parsed.nodeId() catch return error.InvalidEnr) orelse return error.InvalidEnr;
        if (!std.mem.eql(u8, &node_id, &self.local_node_id)) return error.WrongNodeId;
        if (self.local.raw) |*current| if (std.mem.eql(u8, current.slice(), raw)) return;
        if (parsed.seq <= self.local.seq) return error.StaleEnrSeq;
        self.local = .{ .raw = try .init(raw), .seq = parsed.seq };
        self.votes_ip4.clear();
        self.votes_ip6.clear();
        self.addr_vote_cooldown_until_ns = outbound.deadlineNs(addressVoteNowNs(env.io), addr_votes.ENR_UPDATE_COOLDOWN_MS);
        self.publishLocalEnr(env.outbox);
        self.pingAll(env);
    }

    pub fn learnDiscovered(self: *Actor, raw: []const u8, now_ns: i64) ?types.NodeId {
        const validated = enr.ValidatedEnr.init(raw) catch return null;
        return self.learnValidatedDiscovered(&validated, now_ns);
    }

    pub fn learnValidatedDiscovered(self: *Actor, validated: *const enr.ValidatedEnr, now_ns: i64) ?types.NodeId {
        const node_id = self.validatedDiscoveredNodeId(validated) orelse return null;
        if (self.peers.learnValidatedEnr(validated, now_ns) == null) return null;
        return node_id;
    }

    pub fn discoveredNodeId(self: *const Actor, raw: []const u8) ?types.NodeId {
        const validated = enr.ValidatedEnr.init(raw) catch return null;
        return self.validatedDiscoveredNodeId(&validated);
    }

    pub fn validatedDiscoveredNodeId(self: *const Actor, validated: *const enr.ValidatedEnr) ?types.NodeId {
        if (std.mem.eql(u8, &validated.node_id, &self.local_node_id)) return null;
        if (self.peers.addressForEnr(&validated.parsed) == null) return null;
        return validated.node_id;
    }

    pub fn publishDiscovered(self: *Actor, outbox: *events.EventOutbox, raw: enr.RawEnr) void {
        const validated = enr.ValidatedEnr.init(raw.slice()) catch return;
        self.publishValidatedDiscovered(outbox, &validated);
    }

    pub fn publishValidatedDiscovered(self: *Actor, outbox: *events.EventOutbox, validated: *const enr.ValidatedEnr) void {
        _ = self;
        outbox.publish(.{ .discovered_enr = .{ .raw = validated.raw, .enr = validated.parsed } });
    }

    pub fn startLookup(self: *Actor, env: Env, target: types.NodeId) !u32 {
        const result_outbox = env.lookup_results orelse return error.LookupResultPlaneUnavailable;
        if (!result_outbox.claim()) return error.LookupResultReservationMissing;
        if (self.lookups.count() >= MAX_LOOKUPS) return error.TooManyLookups;
        var seeds: [lookup_mod.MAX_RESULTS]types.NodeId = undefined;
        const found = self.peers.findClosest(&target, &seeds);
        const id = self.allocateLookupId() orelse return error.TooManyLookups;
        var lookup = try lookup_mod.Lookup.init(self.alloc, target, seeds[0..found], outbound.nowNs(env.io), self.lookup_config);
        errdefer lookup.deinit(self.alloc);
        lookup.reliable_result = true;
        self.lookups.putAssumeCapacityNoClobber(id, lookup);
        self.lookup_count +|= 1;
        self.pumpLookup(env, id);
        return id;
    }

    pub fn maintenance(self: *Actor, env: Env) void {
        self.maintenanceAt(env, outbound.nowNs(env.io));
    }

    pub fn maintenanceAt(self: *Actor, env: Env, now_real_ns: i64) void {
        maintenance_flow.run(self, env, now_real_ns);
    }

    pub fn cancelRequest(self: *Actor, env: Env, handle: types.RequestHandle) bool {
        const key = handle.key;
        if (self.requests.matchesHandle(handle)) {
            return completion.finish(self, env, key, .canceled, .canceled);
        }
        const queued = self.requests.takeQueuedHandle(handle) orelse return false;
        self.publishRequestTerminal(env, handle, queued.kind, queued.origin, .canceled);
        self.onRequestCancellation(env, key, queued.origin);
        outbound.drainEndpoint(self, env, key.endpoint);
        return true;
    }

    pub fn onRequestCancellation(self: *Actor, env: Env, key: types.RequestKey, origin: types.RequestOrigin) void {
        switch (origin) {
            .lookup => self.onRequestCompletion(env, key, origin, false, &.{}),
            .maintenance => |reason| switch (reason) {
                .health, .enr_propagation => _ = self.peers.cancelHealthRequest(key),
                .enr_refresh => {},
            },
            .eviction => |generation| {
                if (self.peers.currentEvictionTicket(&key.endpoint.node_id, generation)) |ticket| {
                    _ = self.peers.cancelEvictionRequest(ticket, key);
                }
            },
            .api, .reliable_api, .detached_lookup => {},
        }
    }

    pub fn onRequestCompletion(
        self: *Actor,
        env: Env,
        key: types.RequestKey,
        origin: types.RequestOrigin,
        success: bool,
        closer: []const lookup_mod.Candidate,
    ) void {
        if (success) {
            const now_ns = outbound.nowNs(env.io);
            const responsive = switch (origin) {
                .eviction => |generation| if (self.peers.currentEvictionTicket(&key.endpoint.node_id, generation)) |ticket|
                    self.peers.markEvictionResponsive(ticket, key, now_ns)
                else
                    self.peers.markResponsive(key.endpoint.node_id, key.endpoint.addr, now_ns, null),
                else => self.peers.markResponsive(key.endpoint.node_id, key.endpoint.addr, now_ns, key),
            };
            self.publishConnection(env.outbox, key.endpoint.node_id, responsive.transition);
        }
        switch (origin) {
            .lookup => |id| {
                if (self.lookups.getPtr(id)) |lookup| {
                    if (success) lookup.onSuccess(&key.endpoint.node_id, closer, self.lookup_config) else lookup.onFailure(&key.endpoint.node_id, self.lookup_config);
                } else return;
                self.pumpLookup(env, id);
            },
            .maintenance => |reason| switch (reason) {
                .health, .enr_propagation => if (!success) self.publishConnection(env.outbox, key.endpoint.node_id, self.peers.markDisconnected(key, outbound.nowNs(env.io))),
                .enr_refresh => {},
            },
            .eviction => |generation| {
                const ticket = self.peers.currentEvictionTicket(&key.endpoint.node_id, generation) orelse return;
                if (success) {
                    _ = self.peers.resolveEvictionRequestSuccess(ticket, key);
                } else if (self.peers.completeEvictionRequestTimeout(ticket, key)) |event| {
                    self.publishConnection(env.outbox, event.node_id, event.transition);
                }
            },
            .api, .reliable_api => {},
            .detached_lookup => {},
        }
    }

    pub fn publishRequestTerminal(
        self: *Actor,
        env: Env,
        handle: types.RequestHandle,
        kind: types.RequestKind,
        origin: types.RequestOrigin,
        terminal: request_results.RequestTerminal,
    ) void {
        _ = self;
        if (origin != .reliable_api) return;
        switch (terminal) {
            .pong => std.debug.assert(kind == .ping),
            .nodes => std.debug.assert(kind == .findnode),
            .talk_response => std.debug.assert(kind == .talkreq),
            .send_failure, .timeout, .canceled, .runtime_stopped => {},
        }
        const result_outbox = env.request_results orelse unreachable;
        result_outbox.publishAssumeReserved(.{
            .handle = public_api.handleFromInternal(handle),
            .kind = kind,
            .terminal = terminal,
        });
    }

    pub fn finishAllResponses(self: *Actor, ingress: *admission.IngressAdmission) void {
        self.responses.clear(ingress);
    }

    pub fn finishAllRequests(self: *Actor, env: Env) void {
        var request_finished: usize = 0;
        while (request_finished < self.limits.max_active_requests) : (request_finished += 1) {
            const snapshot = self.requests.firstRequest() orelse break;
            _ = completion.finish(self, env, snapshot.key, .shutdown, .runtime_stopped);
        }
        std.debug.assert(self.requests.firstRequest() == null);

        var queued_finished: usize = 0;
        while (queued_finished < self.limits.max_queued_requests) : (queued_finished += 1) {
            const snapshot = self.requests.firstQueuedRequest() orelse break;
            const queued = self.requests.takeQueued(snapshot.key) orelse unreachable;
            std.debug.assert(std.meta.activeTag(queued.origin) != .lookup);
            self.publishRequestTerminal(env, queued.handle(), snapshot.kind, queued.origin, .runtime_stopped);
        }
        std.debug.assert(self.requests.firstQueuedRequest() == null);
    }

    pub fn publishConnection(self: *Actor, outbox: *events.EventOutbox, node_id: types.NodeId, transition: peer_store.ConnectionTransition) void {
        _ = self;
        switch (transition) {
            .none => {},
            .connected => |address| outbox.publish(.{ .peer_connected = .{ .peer_id = node_id, .peer_addr = address } }),
            .disconnected => |address| outbox.publish(.{ .peer_disconnected = .{ .peer_id = node_id, .peer_addr = address } }),
        }
    }

    pub fn metricsSnapshot(self: *const Actor) metrics_mod.MetricsSnapshot {
        const contacts = self.peers.contactMetricsSnapshot();
        const sessions = self.sessions.metricsSnapshot();
        return .{
            .kad_table_size = self.peers.routeCount(),
            .active_session_count = sessions.count,
            .connected_peer_count = self.peers.connectedCount(),
            .lookup_count = self.lookup_count,
            .active_lookup_count = self.lookups.count(),
            .active_request_count = self.requests.activeCount(),
            .queued_request_count = self.requests.queuedCount(),
            .sent_message_count = self.metrics.sent_message_count,
            .rcvd_message_count = self.metrics.rcvd_message_count,
            .contact_count = contacts.count,
            .contact_capacity = contacts.capacity,
            .contact_inserted_total = contacts.inserted_total,
            .contact_updated_total = contacts.updated_total,
            .contact_replaced_total = contacts.replaced_total,
            .contact_capacity_rejected_total = contacts.capacity_rejected_total,
            .contact_policy_rejected_total = contacts.policy_rejected_total,
            .contact_removed_total = contacts.removed_total,
            .session_capacity = sessions.capacity,
            .session_inserted_total = sessions.inserted_total,
            .session_rekeyed_total = sessions.rekeyed_total,
            .session_capacity_reused_total = sessions.capacity_reused_total,
            .session_maintenance_expired_total = sessions.maintenance_expired_total,
            .session_authenticated_refreshed_total = sessions.authenticated_refreshed_total,
            .session_replay_rejected_total = sessions.replay_rejected_total,
            .session_nonce_exhaustion_rejected_total = sessions.nonce_exhaustion_rejected_total,
        };
    }

    pub fn localEnr(self: *const Actor) ?enr.RawEnr {
        return self.local.raw;
    }

    pub fn peerEnr(self: *const Actor, node_id: *const types.NodeId) ?enr.RawEnr {
        const raw = self.peers.findEnr(node_id) orelse return null;
        return enr.RawEnr.init(raw) catch unreachable;
    }

    pub fn localEnrSeq(self: *const Actor) u64 {
        return self.local.seq;
    }

    pub fn maybeRequestEnrUpdate(self: *Actor, env: Env, endpoint: types.Endpoint, advertised_seq: u64) void {
        const known_seq = self.peers.knownEnrSeq(&endpoint.node_id) orelse return;
        if (known_seq >= advertised_seq or self.requests.hasActiveFindNode(&endpoint.node_id)) return;
        const known = self.peers.known(&endpoint.node_id) orelse return;
        _ = self.sendFindNodeResolved(env, endpoint, &known.pubkey, &.{0}, .{ .maintenance = .enr_refresh }) catch {};
    }

    pub fn observeAddressVote(self: *Actor, env: Env, voter: types.Address, observed: types.Address) void {
        self.observeAddressVoteAt(env, voter, observed, addressVoteNowNs(env.io));
    }

    pub fn observeAddressVoteAt(self: *Actor, env: Env, voter: types.Address, observed: types.Address, now_ns: i64) void {
        if (!self.enr_update or self.local.raw == null) return;
        const normalized = normalize(observed);
        if (!validObservedAddress(self, normalized)) return;
        if (now_ns < self.addr_vote_cooldown_until_ns) {
            self.votes_ip4.clear();
            self.votes_ip6.clear();
            return;
        }
        const votes = switch (normalized) {
            .ip4 => &self.votes_ip4,
            .ip6 => &self.votes_ip6,
        };
        const vote_result = votes.addVote(normalize(voter), normalized, now_ns) catch return;
        const winner = switch (vote_result) {
            .duplicate, .recorded => return,
            .winner => |value| value,
        };
        const current = enr.decode(self.local.raw.?.slice()) catch return;
        const current_address = switch (normalized) {
            .ip4 => current.udpAddress4(),
            .ip6 => current.udpAddress6(),
        };
        if (current_address) |value| if (value.eql(&normalized)) {
            votes.commitWinner(winner);
            return;
        };
        if (!self.updateLocalAddress(normalized)) return;
        votes.commitWinner(winner);
        self.votes_ip4.clear();
        self.votes_ip6.clear();
        self.addr_vote_cooldown_until_ns = outbound.deadlineNs(now_ns, addr_votes.ENR_UPDATE_COOLDOWN_MS);
        self.publishLocalEnr(env.outbox);
        self.pingAll(env);
    }

    pub fn probeEviction(self: *Actor, env: Env, probe: peer_store.EvictionProbe) void {
        self.sendEvictionProbe(env, probe) catch return;
    }

    fn sendEvictionProbe(self: *Actor, env: Env, probe: peer_store.EvictionProbe) !void {
        const endpoint = probe.endpoint;
        const req_id = randomReqId(env.io);
        const key = types.RequestKey.init(endpoint, req_id);
        if (!self.peers.armHealthRequest(key, .{ .allow_eviction_candidate = probe.ticket })) return error.ProbeUnavailable;
        const ping = message.Ping{ .req_id = req_id, .enr_seq = self.local.seq };
        var buffer: [128]u8 = undefined;
        const plaintext = ping.encodeInto(&buffer) catch |err| {
            _ = self.peers.cancelEvictionRequest(probe.ticket, key);
            return err;
        };
        const action = outbound.prepareTracked(
            self,
            .{ .io = env.io, .ingress = env.ingress },
            endpoint,
            &probe.pubkey,
            req_id,
            .ping,
            &.{},
            plaintext,
            .{ .eviction = probe.ticket.generation },
        ) catch |err| {
            _ = self.peers.cancelEvictionRequest(probe.ticket, key);
            return err;
        };
        outbound.emitPrepared(self, env, action) catch |err| {
            _ = self.peers.cancelEvictionRequest(probe.ticket, key);
            return err;
        };
    }

    /// Pre-send reservation transaction for health/eviction liveness probes:
    /// reserve exact probe ownership before the packet can become visible,
    /// send, and roll the reservation back only when the send path fails
    /// before the tracked request commits.
    pub fn sendProbe(
        self: *Actor,
        env: Env,
        endpoint: types.Endpoint,
        pubkey: *const [33]u8,
        reason: types.MaintenanceReason,
        policy: peer_store.HealthReservationPolicy,
    ) !message.ReqId {
        std.debug.assert(reason == .health or reason == .enr_propagation);
        const req_id = randomReqId(env.io);
        const key = types.RequestKey.init(endpoint, req_id);
        if (!self.peers.armHealthRequest(key, policy)) return error.ProbeUnavailable;
        const ping = message.Ping{ .req_id = req_id, .enr_seq = self.local.seq };
        var buffer: [128]u8 = undefined;
        const plaintext = ping.encodeInto(&buffer) catch |err| {
            _ = self.peers.cancelHealthRequest(key);
            return err;
        };
        const action = outbound.prepareTracked(
            self,
            .{ .io = env.io, .ingress = env.ingress },
            endpoint,
            pubkey,
            req_id,
            .ping,
            &.{},
            plaintext,
            .{ .maintenance = reason },
        ) catch |err| {
            _ = self.peers.cancelHealthRequest(key);
            return err;
        };
        outbound.emitPrepared(self, env, action) catch |err| {
            _ = self.peers.cancelHealthRequest(key);
            return err;
        };
        return req_id;
    }

    fn pumpLookup(self: *Actor, env: Env, id: u32) void {
        // A candidate can fail synchronously before any request is active. Walk
        // the complete bounded frontier so such failures cannot leave a lookup
        // with no request that could wake it again.
        var attempts: usize = 0;
        while (attempts < lookup_mod.MAX_CANDIDATES) : (attempts += 1) {
            const attempt: LookupAttempt = blk: {
                const lookup = self.lookups.getPtr(id) orelse return;
                lookup.deferred = false;
                const peer_id = lookup.nextPeer(self.lookup_config) orelse break;
                break :blk .{ .peer_id = peer_id, .target = lookup.target };
            };
            const peer_id = attempt.peer_id;
            var distances: [types.MAX_OUTBOUND_FINDNODE_DISTANCES]u16 = undefined;
            const count = lookup_mod.findNodeLogDistances(&attempt.target, &peer_id, @min(self.lookup_config.request_limit, distances.len), &distances);
            const send_result = blk: {
                const lookup = self.lookups.getPtr(id) orelse return;
                if (lookup.localCandidate(&peer_id)) |candidate| {
                    break :blk self.sendFindNodeResolved(
                        env,
                        .{ .node_id = peer_id, .addr = candidate.addr },
                        &candidate.pubkey,
                        distances[0..count],
                        .{ .lookup = id },
                    );
                }
                const known = self.peers.known(&peer_id) orelse {
                    lookup.onFailure(&peer_id, self.lookup_config);
                    continue;
                };
                break :blk self.sendFindNodeResolved(
                    env,
                    .{ .node_id = peer_id, .addr = known.addr },
                    &known.pubkey,
                    distances[0..count],
                    .{ .lookup = id },
                );
            };
            _ = send_result catch |err| {
                if (err == error.Canceled) {
                    self.finishLookup(env, id, .runtime_stopped);
                    return;
                }
                if (isLookupBackpressure(err)) {
                    if (self.lookups.getPtr(id)) |lookup| lookup.onDeferred(&peer_id);
                    break;
                }
                if (self.lookups.getPtr(id)) |lookup| lookup.onFailure(&peer_id, self.lookup_config);
                continue;
            };
        }
        const finished = if (self.lookups.get(id)) |lookup| lookup.state == .finished else false;
        if (finished) self.finishLookup(env, id, .completed);
    }

    pub fn repumpLookups(self: *Actor, env: Env) void {
        var lookup_ids: [MAX_LOOKUPS]u32 = undefined;
        const count = blk: {
            var count: usize = 0;
            var iterator = self.lookups.iterator();
            while (iterator.next()) |entry| {
                if (!entry.value_ptr.deferred) continue;
                std.debug.assert(count < lookup_ids.len);
                lookup_ids[count] = entry.key_ptr.*;
                count += 1;
            }
            break :blk count;
        };
        for (lookup_ids[0..count]) |lookup_id| self.pumpLookup(env, lookup_id);
    }

    fn allocateLookupId(self: *Actor) ?u32 {
        var attempts: usize = 0;
        while (attempts <= MAX_LOOKUPS) : (attempts += 1) {
            const candidate = self.next_lookup_id;
            self.next_lookup_id +%= 1;
            if (self.next_lookup_id == 0) self.next_lookup_id = 1;
            if (!self.lookups.contains(candidate)) return candidate;
        }
        return null;
    }

    pub fn finishLookup(self: *Actor, env: Env, id: u32, reason: lookup_results.LookupTerminalReason) void {
        const lookup = self.lookups.getPtr(id) orelse return;
        var terminal = lookup_results.LookupResult{
            .lookup_id = id,
            .target = lookup.target,
            .reason = reason,
        };
        for (lookup.peers.items) |*peer| {
            if (peer.state != .succeeded or terminal.enrs.slice().len >= self.lookup_config.num_results) continue;
            if (peer.local_candidate) |*candidate| {
                terminal.enrs.append(candidate.raw);
                continue;
            }
            const raw = self.peers.findEnr(&peer.node_id) orelse continue;
            terminal.enrs.append(enr.RawEnr.init(raw) catch unreachable);
        }
        const reliable_result = lookup.reliable_result;
        var removed = self.lookups.fetchRemove(id).?.value;
        self.requests.detachLookup(id);
        removed.deinit(self.alloc);

        if (reliable_result) {
            const result_outbox = env.lookup_results orelse unreachable;
            result_outbox.publishAssumeReserved(terminal);
        }
    }

    pub fn finishAllLookups(self: *Actor, env: Env, reason: lookup_results.LookupTerminalReason) void {
        var lookup_ids: [MAX_LOOKUPS]u32 = undefined;
        const count = blk: {
            var count: usize = 0;
            var iterator = self.lookups.iterator();
            while (iterator.next()) |entry| {
                std.debug.assert(count < lookup_ids.len);
                lookup_ids[count] = entry.key_ptr.*;
                count += 1;
            }
            break :blk count;
        };
        for (lookup_ids[0..count]) |lookup_id| self.finishLookup(env, lookup_id, reason);
    }

    fn updateLocalAddress(self: *Actor, address: types.Address) bool {
        const current = self.local.raw orelse return false;
        const document = enr.ValidatedEnr.init(current.slice()) catch return false;
        const next_seq = std.math.add(u64, @max(document.parsed.seq, self.local.seq), 1) catch return false;
        const replacement = document.withEndpoint(&self.local_key_pair, next_seq, address) catch return false;
        self.local = .{ .raw = replacement, .seq = next_seq };
        return true;
    }

    fn publishLocalEnr(self: *Actor, outbox: *events.EventOutbox) void {
        const raw = self.local.raw orelse return;
        const copy = self.alloc.dupe(u8, raw.slice()) catch {
            outbox.notePayloadDrop(.multiaddr_updated);
            return;
        };
        outbox.publish(.{ .local_enr_updated = .{ .seq = self.local.seq, .enr = copy } });
    }

    fn pingAll(self: *Actor, env: Env) void {
        for (0..peer_store.ROUTE_BUCKETS) |distance| {
            var snapshots: [peer_store.K]peer_store.ProbeSnapshot = undefined;
            const count = self.peers.collectDueProbesInBucket(@intCast(distance), std.math.maxInt(i64), &snapshots);
            for (snapshots[0..count]) |*snapshot| {
                _ = self.sendProbe(env, snapshot.endpoint, &snapshot.pubkey, .enr_propagation, .connected_only) catch continue;
            }
        }
    }
};

/// Tuple-based request construction exists only in test builds so fixtures can
/// exercise transport details without creating a supported production boundary.
pub const Testing = if (builtin.is_test) struct {
    fn actorPtr(value: anytype) *Actor {
        return switch (@TypeOf(value)) {
            *Actor => value,
            **Actor => value.*,
            *const *Actor => value.*,
            else => @compileError("test request helper requires Actor lvalue or pointer"),
        };
    }

    pub fn preparePingResolvedForTest(actor_value: anytype, context: TransitionContext, endpoint: types.Endpoint, pubkey: *const [33]u8, origin: types.RequestOrigin) !OutboundRequestAction {
        return actorPtr(actor_value).preparePingResolved(context, endpoint, pubkey, origin);
    }

    pub fn prepareFindNodeResolvedForTest(actor_value: anytype, context: TransitionContext, endpoint: types.Endpoint, pubkey: *const [33]u8, distances: []const u16, origin: types.RequestOrigin) !OutboundRequestAction {
        return actorPtr(actor_value).prepareFindNodeResolved(context, endpoint, pubkey, distances, origin);
    }

    pub fn prepareTalkRequestResolvedForTest(actor_value: anytype, context: TransitionContext, endpoint: types.Endpoint, pubkey: *const [33]u8, protocol_name: []const u8, request: []const u8, origin: types.RequestOrigin) !OutboundRequestAction {
        return actorPtr(actor_value).prepareTalkRequestResolved(context, endpoint, pubkey, protocol_name, request, origin);
    }

    pub fn sendPingResolvedForTest(actor_value: anytype, env: Env, endpoint: types.Endpoint, pubkey: *const [33]u8, origin: types.RequestOrigin) !types.RequestHandle {
        return actorPtr(actor_value).sendPingResolved(env, endpoint, pubkey, origin);
    }

    pub fn sendFindNodeResolvedForTest(actor_value: anytype, env: Env, endpoint: types.Endpoint, pubkey: *const [33]u8, distances: []const u16, origin: types.RequestOrigin) !types.RequestHandle {
        return actorPtr(actor_value).sendFindNodeResolved(env, endpoint, pubkey, distances, origin);
    }

    pub fn sendTalkRequestResolvedForTest(actor_value: anytype, env: Env, endpoint: types.Endpoint, pubkey: *const [33]u8, protocol_name: []const u8, request: []const u8) !types.RequestHandle {
        return actorPtr(actor_value).sendTalkRequestResolved(env, endpoint, pubkey, protocol_name, request, .api);
    }

    pub fn sendTalkRequestResolvedWithOriginForTest(actor_value: anytype, env: Env, endpoint: types.Endpoint, pubkey: *const [33]u8, protocol_name: []const u8, request: []const u8, origin: types.RequestOrigin) !types.RequestHandle {
        return actorPtr(actor_value).sendTalkRequestResolved(env, endpoint, pubkey, protocol_name, request, origin);
    }
} else struct {};

fn randomReqId(io: std.Io) message.ReqId {
    var id = message.ReqId{ .bytes = [_]u8{0} ** 8, .len = 4 };
    io.random(id.bytes[0..4]);
    return id;
}

fn normalize(address: types.Address) types.Address {
    return switch (address) {
        .ip4 => address,
        .ip6 => |ip6| .fromIp6(ip6),
    };
}

fn addressVoteNowNs(io: std.Io) i64 {
    return @intCast(std.Io.Timestamp.now(io, .awake).toNanoseconds());
}

/// Address votes accept private, documentation, loopback, and other unicast
/// ranges so local/test deployments keep working. Only representations that
/// cannot identify a UDP endpoint are rejected here: zero ports, unspecified
/// addresses, multicast, the IPv4 limited broadcast, and disabled families.
fn validObservedAddress(actor: *const Actor, address: types.Address) bool {
    if (address.getPort() == 0) return false;
    return switch (address) {
        .ip4 => |ip4| actor.peers.allow_ip4 and
            !std.mem.allEqual(u8, &ip4.bytes, 0) and
            !std.mem.allEqual(u8, &ip4.bytes, 0xff) and
            (ip4.bytes[0] & 0xf0) != 0xe0,
        .ip6 => |ip6| actor.peers.allow_ip6 and
            !std.mem.allEqual(u8, &ip6.bytes, 0) and
            ip6.bytes[0] != 0xff,
    };
}

fn isLookupBackpressure(err: anyerror) bool {
    return switch (err) {
        error.TooManyActiveRequests,
        error.TooManyQueuedRequests,
        error.TooManyQueuedRequestsForEndpoint,
        error.TooManyAdmissionPermits,
        => true,
        else => false,
    };
}

test "discv5 actor: integrated effect layouts remain exact" {
    try std.testing.expectEqual(challenge_handle_size, @sizeOf(session_book.ChallengeHandle));
    try std.testing.expectEqual(whoareyou_send_effect_size, @sizeOf(WhoareyouSendEffect));
    try std.testing.expectEqual(@as(usize, 2), @typeInfo(WhoareyouSendEffect).@"struct".fields.len);
    try std.testing.expectEqual(staged_response_send_effect_size, @sizeOf(ResponseSendEffect));
    try std.testing.expectEqual(staged_retry_send_effect_size, @sizeOf(RetrySendEffect));
    try std.testing.expectEqual(@as(usize, 2), @typeInfo(RetrySendEffect).@"struct".fields.len);
    try std.testing.expect(@hasField(RetrySendEffect, "handle"));
    try std.testing.expect(@hasField(RetrySendEffect, "packet"));
    try std.testing.expectEqual(request_handshake_handle_size, @sizeOf(request_book.HandshakeHandle));
    try std.testing.expectEqual(handshake_handle_size, @sizeOf(HandshakeHandle));
    try std.testing.expectEqual(handshake_send_effect_size, @sizeOf(HandshakeSendEffect));
    try std.testing.expectEqual(@as(usize, 2), @typeInfo(HandshakeSendEffect).@"struct".fields.len);
    try std.testing.expectEqual(exact_actor_effect_size, @sizeOf(ActorEffect));
    const request_layout = request_book.RequestBook.layout();
    try std.testing.expectEqual(@as(usize, 96), request_layout.retry_handle);
    try std.testing.expectEqual(@as(usize, 96), request_layout.handshake_handle);
    try std.testing.expectEqual(@as(usize, 40), request_layout.pending_handshake);
    try std.testing.expectEqual(@as(usize, 2_616), request_layout.phase);
    try std.testing.expectEqual(@as(usize, 56), request_layout.handshake_send_state);
    try std.testing.expectEqual(@as(usize, 1_336), request_layout.retry_send_state);
    try std.testing.expectEqual(@as(usize, 11_840), request_layout.active_request);
    try std.testing.expectEqual(@as(usize, 11_848), request_layout.stored_request);
    const expected_request_book_size: usize = if (builtin.mode == .ReleaseFast) 248 else 272;
    try std.testing.expectEqual(expected_request_book_size, request_layout.request_book);
    try std.testing.expectEqual(@as(usize, 1_024), config_mod.MAX_ACTIVE_REQUESTS);
    std.debug.print(
        "REQUEST_SEND_LAYOUT request_handle={} unified_handle={} effect={} actor_effect={} request_book={} pending={} wait={} phase={} handshake_send={} retry_send={} active={} stored={} fifo={}\n",
        .{ request_layout.handshake_handle, @sizeOf(HandshakeHandle), @sizeOf(HandshakeSendEffect), @sizeOf(ActorEffect), request_layout.request_book, request_layout.pending_handshake, request_layout.response_wait, request_layout.phase, request_layout.handshake_send_state, request_layout.retry_send_state, request_layout.active_request, request_layout.stored_request, config_mod.MAX_ACTIVE_REQUESTS },
    );
}

test "discv5 actor: local node ID is derived from the configured key pair" {
    const test_secp = @import("secp256k1.zig");
    const alloc = std.testing.allocator;
    const local_key = try test_secp.keyPairFromSecret(&([_]u8{0x90} ** 32));
    const cfg = config_mod.Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
        .rate_limiter = null,
    };
    var ingress = try admission.IngressAdmission.init(alloc, null, try admission.permitCapacity(cfg.limits));
    defer ingress.deinit();
    var actor = try Actor.init(alloc, cfg);
    defer actor.deinit(&ingress);

    try std.testing.expectEqualSlices(u8, &cfg.localNodeId(), &actor.local_node_id);
}

test "discv5 actor: lookup pump exhausts bounded synchronous candidate failures" {
    const test_secp = @import("secp256k1.zig");
    const RecordingSender = @import("test_support/recording_sender.zig").RecordingSender;
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try test_secp.keyPairFromSecret(&([_]u8{0x91} ** 32));
    const cfg = config_mod.Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
        .rate_limiter = null,
        .limits = .{ .event_capacity = 4, .command_capacity = 4 },
    };
    var ingress = try admission.IngressAdmission.init(alloc, null, try admission.permitCapacity(cfg.limits));
    defer ingress.deinit();
    var outbox = try events.EventOutbox.init(io, alloc, cfg.limits.event_capacity);
    defer outbox.deinit();
    var actor = try Actor.init(alloc, cfg);
    defer actor.deinit(&ingress);
    var recording = RecordingSender.init(alloc);
    defer recording.deinit();
    const env = Env{ .io = io, .ingress = &ingress, .outbox = &outbox };

    const target = [_]u8{0} ** 32;
    var seeds: [lookup_mod.MAX_RESULTS]types.NodeId = undefined;
    for (&seeds, 1..) |*seed, value| {
        seed.* = [_]u8{0} ** 32;
        seed.*[31] = @intCast(value);
    }
    var lookup = try lookup_mod.Lookup.init(alloc, target, &seeds, 0, actor.lookup_config);
    for (lookup_mod.MAX_RESULTS + 1..lookup_mod.MAX_CANDIDATES + 1) |value| {
        var node_id = [_]u8{0} ** 32;
        node_id[31] = @intCast(value);
        lookup.peers.appendAssumeCapacity(.{ .node_id = node_id });
    }
    actor.lookups.putAssumeCapacityNoClobber(1, lookup);

    actor.pumpLookup(env, 1);

    try std.testing.expect(!actor.lookups.contains(1));
    try std.testing.expect(outbox.pop() == null);
}

test "discv5 actor: lookup local backpressure defers until bounded maintenance repump" {
    const test_secp = @import("secp256k1.zig");
    const RecordingSender = @import("test_support/recording_sender.zig").RecordingSender;
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try test_secp.keyPairFromSecret(&([_]u8{0x92} ** 32));
    const blocker_key = try test_secp.keyPairFromSecret(&([_]u8{0x93} ** 32));
    const blocker_pubkey = test_secp.compressedPubkey(&blocker_key);
    const blocker_id = try enr.nodeIdFromCompressedPubkey(&blocker_pubkey);
    const lookup_key = try test_secp.keyPairFromSecret(&([_]u8{0x94} ** 32));
    const lookup_pubkey = test_secp.compressedPubkey(&lookup_key);
    const lookup_peer_id = try enr.nodeIdFromCompressedPubkey(&lookup_pubkey);
    const blocker_endpoint = types.Endpoint{
        .node_id = blocker_id,
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 92 }, .port = 9092 } },
    };
    const lookup_address: types.Address = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 94 }, .port = 9094 } };
    const cfg = config_mod.Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
        .request_retries = 0,
        .lookup_num_results = 1,
        .lookup_parallelism = 1,
        .rate_limiter = null,
        .limits = .{
            .max_active_requests = 1,
            .max_queued_requests = 1,
            .event_capacity = 4,
            .command_capacity = 4,
        },
    };
    var ingress = try admission.IngressAdmission.init(alloc, null, try admission.permitCapacity(cfg.limits));
    defer ingress.deinit();
    var outbox = try events.EventOutbox.init(io, alloc, cfg.limits.event_capacity);
    defer outbox.deinit();
    var actor = try Actor.init(alloc, cfg);
    defer actor.deinit(&ingress);
    var recording = RecordingSender.init(alloc);
    defer recording.deinit();
    var effect_storage: [1]ActorEffect = undefined;
    var effects = EffectQueue.init(&effect_storage);
    const env = Env{ .io = io, .ingress = &ingress, .outbox = &outbox, .effects = &effects };
    try std.testing.expect(actor.addNode(lookup_peer_id, &lookup_pubkey, lookup_address, null, 0));

    const blocker_req_id = try Testing.sendPingResolvedForTest(&actor, env, blocker_endpoint, &blocker_pubkey, .api);
    while (effects.pop()) |effect| {
        recording.sender().send(effect.destination(), effect.packetBytes()) catch |err| {
            actor.applyEffectCompletion(env, effect, .failed);
            return err;
        };
        actor.applyEffectCompletion(env, effect, .sent);
    }
    try std.testing.expectEqual(@as(usize, 1), actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 1), ingress.permitCount());
    try std.testing.expectEqual(@as(usize, 1), recording.datagrams.items.len);

    const lookup_id: u32 = 1;
    const target = [_]u8{0x95} ** 32;
    const lookup = try lookup_mod.Lookup.init(alloc, target, &.{lookup_peer_id}, outbound.nowNs(io), actor.lookup_config);
    actor.lookups.putAssumeCapacityNoClobber(lookup_id, lookup);
    actor.pumpLookup(env, lookup_id);

    const deferred = actor.lookups.getPtr(lookup_id) orelse return error.LookupFinishedUnderBackpressure;
    try std.testing.expectEqual(lookup_mod.State.iterating, deferred.state);
    try std.testing.expectEqual(@as(usize, 0), deferred.num_waiting);
    try std.testing.expect(deferred.deferred);
    try std.testing.expectEqual(lookup_mod.PeerState.not_contacted, deferred.peers.items[0].state);
    try std.testing.expectEqual(@as(usize, 1), actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 1), ingress.permitCount());
    try std.testing.expectEqual(@as(usize, 1), recording.datagrams.items.len);
    try std.testing.expect(outbox.pop() == null);

    try std.testing.expect(actor.cancelRequest(env, blocker_req_id));
    try std.testing.expectEqual(@as(usize, 0), actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 0), ingress.permitCount());

    actor.maintenance(env);
    while (effects.pop()) |effect| {
        recording.sender().send(effect.destination(), effect.packetBytes()) catch |err| {
            actor.applyEffectCompletion(env, effect, .failed);
            return err;
        };
        actor.applyEffectCompletion(env, effect, .sent);
    }
    const dispatched = actor.lookups.getPtr(lookup_id) orelse return error.LookupFinishedBeforeDispatch;
    try std.testing.expectEqual(@as(usize, 1), dispatched.num_waiting);
    try std.testing.expect(!dispatched.deferred);
    try std.testing.expectEqual(lookup_mod.PeerState.waiting, dispatched.peers.items[0].state);
    try std.testing.expectEqual(@as(usize, 1), actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 1), ingress.permitCount());
    try std.testing.expectEqual(@as(usize, 2), recording.datagrams.items.len);

    actor.maintenance(env);
    try std.testing.expectEqual(@as(usize, 1), actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 1), ingress.permitCount());
    try std.testing.expectEqual(@as(usize, 2), recording.datagrams.items.len);

    actor.maintenanceAt(env, std.math.maxInt(i64));
    try std.testing.expectEqual(@as(usize, 0), actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 0), ingress.permitCount());
}

test "discv5 actor: lookup transport failure continues with next candidate" {
    const test_secp = @import("secp256k1.zig");
    const RecordingSender = @import("test_support/recording_sender.zig").RecordingSender;
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try test_secp.keyPairFromSecret(&([_]u8{0x96} ** 32));
    const remote_key_a = try test_secp.keyPairFromSecret(&([_]u8{0x97} ** 32));
    const remote_pubkey_a = test_secp.compressedPubkey(&remote_key_a);
    const remote_id_a = try enr.nodeIdFromCompressedPubkey(&remote_pubkey_a);
    const remote_key_b = try test_secp.keyPairFromSecret(&([_]u8{0x98} ** 32));
    const remote_pubkey_b = test_secp.compressedPubkey(&remote_key_b);
    const remote_id_b = try enr.nodeIdFromCompressedPubkey(&remote_pubkey_b);
    const remote_address_a: types.Address = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 97 }, .port = 9097 } };
    const remote_address_b: types.Address = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 98 }, .port = 9098 } };
    const cfg = config_mod.Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
        .lookup_num_results = 2,
        .lookup_parallelism = 1,
        .rate_limiter = null,
        .limits = .{ .max_active_requests = 1, .max_queued_requests = 1, .event_capacity = 2, .command_capacity = 2 },
    };
    var ingress = try admission.IngressAdmission.init(alloc, null, try admission.permitCapacity(cfg.limits));
    defer ingress.deinit();
    var outbox = try events.EventOutbox.init(io, alloc, cfg.limits.event_capacity);
    defer outbox.deinit();
    var actor = try Actor.init(alloc, cfg);
    defer actor.deinit(&ingress);
    var recording = RecordingSender.init(alloc);
    defer recording.deinit();
    var effect_storage: [1]ActorEffect = undefined;
    var effects = EffectQueue.init(&effect_storage);
    const env = Env{ .io = io, .ingress = &ingress, .outbox = &outbox, .effects = &effects };
    try std.testing.expect(actor.addNode(remote_id_a, &remote_pubkey_a, remote_address_a, null, 0));
    try std.testing.expect(actor.addNode(remote_id_b, &remote_pubkey_b, remote_address_b, null, 0));
    const lookup = try lookup_mod.Lookup.init(
        alloc,
        [_]u8{0x99} ** 32,
        &.{ remote_id_a, remote_id_b },
        outbound.nowNs(io),
        actor.lookup_config,
    );
    actor.lookups.putAssumeCapacityNoClobber(1, lookup);
    defer if (actor.lookups.contains(1)) actor.finishLookup(env, 1, .runtime_stopped);

    actor.pumpLookup(env, 1);
    const first = effects.pop() orelse return error.MissingFirstLookupEffect;
    const failed_destination = first.destination();
    actor.applyEffectCompletion(env, first, .failed);

    const second = effects.pop() orelse return error.MissingSecondLookupEffect;
    try std.testing.expect(!std.meta.eql(failed_destination, second.destination()));
    try recording.sender().send(second.destination(), second.packetBytes());
    actor.applyEffectCompletion(env, second, .sent);

    try std.testing.expect(actor.lookups.contains(1));
    try std.testing.expectEqual(@as(usize, 1), actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 1), ingress.permitCount());
    try std.testing.expectEqual(@as(usize, 1), recording.datagrams.items.len);
    try std.testing.expect(outbox.pop() == null);
}
