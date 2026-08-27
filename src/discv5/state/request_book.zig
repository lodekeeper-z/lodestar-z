const std = @import("std");
const admission_mod = @import("../admission.zig");
const config_mod = @import("../config.zig");
const enr = @import("../enr.zig");
const request_queue = @import("request_queue.zig");
const types = @import("../types.zig");

const Allocator = std.mem.Allocator;
const AdmissionPermit = admission_mod.AdmissionPermit;
pub const RequestHandle = types.RequestHandle;

pub const RetryHandle = struct {
    request: RequestHandle,
    send_generation: u64,
};

pub const HandshakeHandle = struct {
    request: RequestHandle,
    send_generation: u64,
};

pub const HandshakeSendCompletion = enum {
    sent,
    failed,
    runtime_stopped,
};

pub const RetrySendCompletion = enum {
    sent,
    failed,
    runtime_stopped,
};

pub const MAX_NODES_RESPONSE: usize = config_mod.MAX_NODES_RESPONSE;
pub const RequestDistances = request_queue.RequestDistances;

pub const PendingSessionKeys = struct {
    initiator_key: [16]u8,
    recipient_key: [16]u8,
};

pub const PendingHandshake = struct {
    send_generation: u64,
    keys: PendingSessionKeys,
};

pub const RecoveryState = struct {
    nonce: [12]u8,
    dest_pubkey: [33]u8,
    plaintext: types.PacketBytes,
};

pub const AwaitingWhoareyou = struct {
    retry_packet: types.PacketBytes,
    recovery: RecoveryState,
};

pub const AwaitingResponse = struct {
    recovery: RecoveryState,
    wait: ResponseWait,
};

pub const ResponseWait = union(enum) {
    session_request,
    handshake_sent: PendingHandshake,
    handshake_confirmed,
    retry_with_pending_keys: PendingHandshake,

    pub fn canChallenge(self: ResponseWait) bool {
        return switch (self) {
            .session_request, .retry_with_pending_keys => true,
            .handshake_sent, .handshake_confirmed => false,
        };
    }

    pub fn pendingHandshake(self: ResponseWait) ?PendingHandshake {
        return switch (self) {
            .handshake_sent, .retry_with_pending_keys => |pending| pending,
            .session_request, .handshake_confirmed => null,
        };
    }

    pub fn afterPromotion(self: ResponseWait) ResponseWait {
        return switch (self) {
            .handshake_sent => .handshake_confirmed,
            .retry_with_pending_keys => .session_request,
            .session_request, .handshake_confirmed => unreachable,
        };
    }

    pub fn afterFreshRetry(self: ResponseWait) ResponseWait {
        return switch (self) {
            .handshake_sent, .retry_with_pending_keys => |keys| .{ .retry_with_pending_keys = keys },
            .session_request, .handshake_confirmed => .session_request,
        };
    }
};

pub const Phase = union(enum) {
    awaiting_whoareyou: AwaitingWhoareyou,
    awaiting_response: AwaitingResponse,
};

pub const FreshRetryTransition = union(enum) {
    probe: struct {
        retry_packet: types.PacketBytes,
        nonce: [12]u8,
    },
    response: [12]u8,
};

pub const NodesAccumulator = struct {
    validated_enrs: ValidatedEnrList = .{},
    total_responses: ?u64 = null,
    responses_received: u64 = 0,
    requested_distances: RequestDistances,

    pub fn init(requested_distances: *const RequestDistances) NodesAccumulator {
        return .{ .requested_distances = requested_distances.* };
    }

    pub fn resetGeneration(self: *NodesAccumulator) void {
        self.validated_enrs.clear();
        self.total_responses = null;
        self.responses_received = 0;
    }
};

pub const ValidatedEnrList = struct {
    buffer: [MAX_NODES_RESPONSE]enr.ValidatedEnr = undefined,
    len: u8 = 0,

    pub fn slice(self: *const ValidatedEnrList) []const enr.ValidatedEnr {
        return self.buffer[0..self.len];
    }

    pub fn append(self: *ValidatedEnrList, validated: enr.ValidatedEnr) void {
        if (self.len >= self.buffer.len) unreachable;
        self.buffer[self.len] = validated;
        self.len += 1;
    }

    pub fn clear(self: *ValidatedEnrList) void {
        self.len = 0;
    }
};

comptime {
    std.debug.assert(@sizeOf(ValidatedEnrList) <= 9 * 1024);
}

pub const Response = union(enum) {
    pong,
    nodes: NodesAccumulator,
    talkresp,

    pub fn kind(self: *const Response) types.RequestKind {
        return switch (self.*) {
            .pong => .ping,
            .nodes => .findnode,
            .talkresp => .talkreq,
        };
    }
};

/// Compact response fact used to initialize canonical request state.
pub const ResponseExpectation = union(enum) {
    pong,
    nodes: RequestDistances,
    talkresp,

    pub fn kind(self: ResponseExpectation) types.RequestKind {
        return switch (self) {
            .pong => .ping,
            .nodes => .findnode,
            .talkresp => .talkreq,
        };
    }

    fn activate(self: ResponseExpectation) Response {
        return switch (self) {
            .pong => .pong,
            .nodes => |distances| .{ .nodes = .init(&distances) },
            .talkresp => .talkresp,
        };
    }
};

pub const HandshakeSendState = struct {
    send_generation: u64,
    keys: PendingSessionKeys,
    next_deadline_ns: i64,
    prior_establishing: bool,
};

pub const RetrySendState = struct {
    send_generation: u64,
    next_deadline_ns: i64,
    preparation: union(enum) {
        retained,
        fresh: struct {
            transition: FreshRetryTransition,
            admission: AdmissionPermit,
        },
    },
};

pub const ActiveRequest = struct {
    generation: u64,
    origin: types.RequestOrigin,
    response: Response,
    phase: Phase,
    admission: AdmissionPermit,
    deadline_ns: i64,
    attempts: u32 = 0,
    queued_intent: bool,
    handshake_send: ?HandshakeSendState = null,
    retry_send: ?RetrySendState = null,

    pub fn permitHandle(self: *const ActiveRequest) admission_mod.PermitHandle {
        return self.admission.handle();
    }
};

const SendingRequest = struct {
    generation: u64,
    origin: types.RequestOrigin,
    response: ResponseExpectation,
    phase: Phase,
    admission: AdmissionPermit,
    deadline_ns: i64,
    queued_intent: bool,
};

const StoredRequest = union(enum) {
    sending: SendingRequest,
    active: ActiveRequest,
};

pub const TerminalRequest = union(enum) {
    sending: SendingRequest,
    active: ActiveRequest,

    pub fn origin(self: *const TerminalRequest) types.RequestOrigin {
        return switch (self.*) {
            .sending => |request| request.origin,
            .active => |request| request.origin,
        };
    }

    pub fn kind(self: *const TerminalRequest) types.RequestKind {
        return switch (self.*) {
            .sending => |request| request.response.kind(),
            .active => |request| request.response.kind(),
        };
    }

    pub fn handle(self: *const TerminalRequest, key: types.RequestKey) RequestHandle {
        return .{ .key = key, .generation = switch (self.*) {
            .sending => |request| request.generation,
            .active => |request| request.generation,
        } };
    }

    pub fn release(self: *TerminalRequest, admission: *admission_mod.IngressAdmission) void {
        switch (self.*) {
            .sending => |*request| request.admission.release(admission),
            .active => |*request| {
                request.admission.release(admission);
                releasePreparedRetry(request, admission);
            },
        }
    }
};

pub const RetryPreparationView = struct {
    handle: RetryHandle,
    packet: types.PacketBytes,
};

pub const RetryCompletionView = struct {
    kind: types.RequestKind,
};

pub const QueuedRequest = request_queue.QueuedRequest;
const EndpointLane = request_queue.EndpointLane;

const ActiveMap = std.HashMap(types.RequestKey, StoredRequest, types.RequestKeyContext, std.hash_map.default_max_load_percentage);
const LaneMap = std.HashMap(types.Endpoint, EndpointLane, types.EndpointContext, std.hash_map.default_max_load_percentage);

pub const SendCompletionView = struct {
    key: types.RequestKey,
    origin: types.RequestOrigin,
    kind: types.RequestKind,
};

pub const ChallengePreparation = struct {
    handle: RequestHandle,
    recovery: RecoveryState,
    permit: admission_mod.PermitHandle,
};

pub const PendingKeysView = struct {
    handle: HandshakeHandle,
    keys: PendingSessionKeys,
};

pub const RequestBook = struct {
    alloc: Allocator,
    limits: config_mod.Limits,
    active: ActiveMap,
    lanes: LaneMap,
    challenge_by_nonce: std.AutoHashMap(types.ChallengeKey, RequestHandle),
    next_generation: u64 = 1,
    next_retry_generation: u64 = 1,
    next_handshake_generation: u64 = 1,
    queued_total: usize = 0,
    drain_cursor: usize = 0,

    pub const Layout = struct {
        retry_handle: usize,
        handshake_handle: usize,
        pending_handshake: usize,
        response_wait: usize,
        phase: usize,
        handshake_send_state: usize,
        retry_send_state: usize,
        active_request: usize,
        stored_request: usize,
        request_book: usize,
    };

    pub fn layout() Layout {
        return .{
            .retry_handle = @sizeOf(RetryHandle),
            .handshake_handle = @sizeOf(HandshakeHandle),
            .pending_handshake = @sizeOf(PendingHandshake),
            .response_wait = @sizeOf(ResponseWait),
            .phase = @sizeOf(Phase),
            .handshake_send_state = @sizeOf(HandshakeSendState),
            .retry_send_state = @sizeOf(RetrySendState),
            .active_request = @sizeOf(ActiveRequest),
            .stored_request = @sizeOf(StoredRequest),
            .request_book = @sizeOf(RequestBook),
        };
    }

    pub fn init(alloc: Allocator, limits: config_mod.Limits) !RequestBook {
        if (limits.max_active_requests == 0 or limits.max_active_requests > config_mod.MAX_ACTIVE_REQUESTS or
            limits.max_queued_requests == 0 or limits.max_queued_requests > config_mod.MAX_QUEUED_REQUESTS or
            limits.max_queued_requests_per_endpoint == 0 or limits.max_queued_requests_per_endpoint > config_mod.MAX_QUEUED_PER_ENDPOINT) return error.InvalidRequestCapacity;
        const lane_capacity = std.math.add(usize, limits.max_active_requests, limits.max_queued_requests) catch return error.InvalidRequestCapacity;
        var active = ActiveMap.init(alloc);
        errdefer active.deinit();
        try active.ensureTotalCapacity(@intCast(limits.max_active_requests));
        var lanes = LaneMap.init(alloc);
        errdefer lanes.deinit();
        try lanes.ensureTotalCapacity(@intCast(lane_capacity));
        var challenges = std.AutoHashMap(types.ChallengeKey, RequestHandle).init(alloc);
        errdefer challenges.deinit();
        try challenges.ensureTotalCapacity(@intCast(limits.max_active_requests));
        return .{ .alloc = alloc, .limits = limits, .active = active, .lanes = lanes, .challenge_by_nonce = challenges };
    }

    pub fn deinit(self: *RequestBook, admission: *admission_mod.IngressAdmission) void {
        var active = self.active.iterator();
        while (active.next()) |entry| {
            switch (entry.value_ptr.*) {
                .sending => |*request| request.admission.release(admission),
                .active => |*request| {
                    request.admission.release(admission);
                    releasePreparedRetry(request, admission);
                },
            }
        }
        self.active.deinit();
        var lanes = self.lanes.iterator();
        while (lanes.next()) |entry| entry.value_ptr.deinit(self.alloc);
        self.lanes.deinit();
        self.challenge_by_nonce.deinit();
    }

    pub fn deinitEmpty(self: *RequestBook) void {
        std.debug.assert(self.active.count() == 0);
        std.debug.assert(self.queued_total == 0);
        self.active.deinit();
        self.lanes.deinit();
        self.challenge_by_nonce.deinit();
    }

    pub fn makeResponse(self: *RequestBook, kind: types.RequestKind, requested_distances: *const RequestDistances) Response {
        return self.makeExpectation(kind, requested_distances).activate();
    }

    pub fn makeExpectation(_: *RequestBook, kind: types.RequestKind, requested_distances: *const RequestDistances) ResponseExpectation {
        return switch (kind) {
            .ping => .pong,
            .talkreq => .talkresp,
            .findnode => .{ .nodes = requested_distances.* },
        };
    }

    pub fn beginSending(
        self: *RequestBook,
        admission: *admission_mod.IngressAdmission,
        key: types.RequestKey,
        origin: types.RequestOrigin,
        response: ResponseExpectation,
        phase: Phase,
        deadline_ns: i64,
        establish: bool,
        queued_intent: bool,
    ) !RequestHandle {
        return self.beginSendingWithGeneration(admission, key, origin, response, phase, deadline_ns, establish, queued_intent, null);
    }

    pub fn beginSendingQueued(
        self: *RequestBook,
        admission: *admission_mod.IngressAdmission,
        handle: RequestHandle,
        origin: types.RequestOrigin,
        response: ResponseExpectation,
        phase: Phase,
        deadline_ns: i64,
        establish: bool,
    ) !RequestHandle {
        return self.beginSendingWithGeneration(admission, handle.key, origin, response, phase, deadline_ns, establish, true, handle.generation);
    }

    fn beginSendingWithGeneration(
        self: *RequestBook,
        admission: *admission_mod.IngressAdmission,
        key: types.RequestKey,
        origin: types.RequestOrigin,
        response: ResponseExpectation,
        phase: Phase,
        deadline_ns: i64,
        establish: bool,
        queued_intent: bool,
        assigned_generation: ?u64,
    ) !RequestHandle {
        if (self.active.contains(key)) return error.DuplicateRequest;
        if (self.active.count() >= self.limits.max_active_requests) return error.TooManyActiveRequests;
        if (establish) {
            if (self.lanes.get(key.endpoint)) |lane| if (lane.establishing != null) return error.EndpointEstablishing;
        }
        const challenge_index = challengeForPhase(key.endpoint.addr, phase);
        if (challenge_index) |index| if (self.challenge_by_nonce.contains(index)) return error.DuplicateChallenge;
        const handle = if (assigned_generation) |generation|
            RequestHandle{ .key = key, .generation = generation }
        else blk: {
            const next_generation = std.math.add(u64, self.next_generation, 1) catch return error.GenerationExhausted;
            const allocated = RequestHandle{ .key = key, .generation = self.next_generation };
            self.next_generation = next_generation;
            break :blk allocated;
        };
        var permit = try admission.acquire(key.endpoint.addr, admission_mod.requestPacketBudget(response.kind()));
        errdefer permit.release(admission);
        self.active.putAssumeCapacityNoClobber(key, .{ .sending = .{
            .generation = handle.generation,
            .origin = origin,
            .response = response,
            .phase = phase,
            .admission = permit.move(),
            .deadline_ns = deadline_ns,
            .queued_intent = queued_intent,
        } });
        if (challenge_index) |index| self.challenge_by_nonce.putAssumeCapacityNoClobber(index, handle);
        if (establish) self.setEstablishing(handle);
        return handle;
    }

    pub fn completeSending(self: *RequestBook, handle: RequestHandle) ?SendCompletionView {
        const request = self.active.getPtr(handle.key) orelse return null;
        if (request.* != .sending or request.sending.generation != handle.generation) return null;
        const sending = request.sending;
        if (sending.queued_intent) self.discardQueuedIntent(handle.key);
        request.* = .{ .active = .{
            .generation = sending.generation,
            .origin = sending.origin,
            .response = sending.response.activate(),
            .phase = sending.phase,
            .admission = sending.admission,
            .deadline_ns = sending.deadline_ns,
            .queued_intent = false,
        } };
        return .{ .key = handle.key, .origin = sending.origin, .kind = sending.response.kind() };
    }

    pub fn abortSending(
        self: *RequestBook,
        handle: RequestHandle,
        admission: *admission_mod.IngressAdmission,
    ) ?SendCompletionView {
        const current = self.active.get(handle.key) orelse return null;
        if (current != .sending or current.sending.generation != handle.generation) return null;
        var removed = self.active.fetchRemove(handle.key).?.value;
        self.clearIndexes(handle, removed.sending.phase);
        const view = SendCompletionView{ .key = handle.key, .origin = removed.sending.origin, .kind = removed.sending.response.kind() };
        removed.sending.admission.release(admission);
        return view;
    }

    pub fn queue(self: *RequestBook, request_value: QueuedRequest) !RequestHandle {
        var request = request_value;
        switch (request.origin) {
            .maintenance => |reason| switch (reason) {
                .health, .enr_propagation => return error.EndpointBusy,
                .enr_refresh => {},
            },
            .eviction => return error.EndpointBusy,
            .api, .reliable_api, .lookup, .detached_lookup => {},
        }
        const key = types.RequestKey.init(request.endpoint, request.req_id);
        if (self.active.contains(key) or self.containsQueued(key)) return error.DuplicateRequest;
        if (self.queued_total >= self.limits.max_queued_requests) return error.TooManyQueuedRequests;
        const lane = self.lanes.getOrPutAssumeCapacity(request.endpoint);
        if (!lane.found_existing) lane.value_ptr.* = .{};
        errdefer if (!lane.found_existing) {
            var removed = self.lanes.fetchRemove(request.endpoint).?;
            std.debug.assert(removed.value.establishing == null);
            std.debug.assert(removed.value.queued.len() == 0);
            removed.value.deinit(self.alloc);
        };
        if (lane.value_ptr.queued.len() >= self.limits.max_queued_requests_per_endpoint)
            return error.TooManyQueuedRequestsForEndpoint;
        const next_generation = std.math.add(u64, self.next_generation, 1) catch return error.GenerationExhausted;
        request.generation = self.next_generation;
        self.next_generation = next_generation;
        try lane.value_ptr.queued.append(self.alloc, request);
        self.queued_total += 1;
        return request.handle();
    }

    pub fn shouldQueue(self: *const RequestBook, endpoint: types.Endpoint) bool {
        if (self.hasArmedRetryAtEndpoint(endpoint)) return true;
        const lane = self.lanes.get(endpoint) orelse return false;
        return lane.establishing != null or lane.queued.len() != 0;
    }

    pub fn activeCount(self: *const RequestBook) usize {
        var count: usize = 0;
        var requests = self.active.iterator();
        while (requests.next()) |entry| if (entry.value_ptr.* == .active and
            entry.value_ptr.active.handshake_send == null and entry.value_ptr.active.retry_send == null)
        {
            count += 1;
        };
        return count;
    }

    pub fn sendingCount(self: *const RequestBook) usize {
        var count: usize = 0;
        var requests = self.active.iterator();
        while (requests.next()) |entry| if (entry.value_ptr.* == .sending) {
            count += 1;
        };
        return count;
    }

    pub fn queuedCount(self: *const RequestBook) usize {
        return self.queued_total;
    }

    pub const RequestSnapshot = struct {
        key: types.RequestKey,
        kind: types.RequestKind,
    };

    pub fn firstActive(self: *const RequestBook) ?RequestSnapshot {
        var active = self.active.iterator();
        while (active.next()) |entry| {
            if (entry.value_ptr.* != .active or entry.value_ptr.active.handshake_send != null or entry.value_ptr.active.retry_send != null) continue;
            return .{ .key = entry.key_ptr.*, .kind = entry.value_ptr.active.response.kind() };
        }
        return null;
    }

    pub fn firstRequest(self: *const RequestBook) ?RequestSnapshot {
        var requests = self.active.iterator();
        const entry = requests.next() orelse return null;
        return .{ .key = entry.key_ptr.*, .kind = switch (entry.value_ptr.*) {
            .sending => |request| request.response.kind(),
            .active => |request| request.response.kind(),
        } };
    }

    pub fn firstQueuedRequest(self: *const RequestBook) ?RequestSnapshot {
        var lanes = self.lanes.iterator();
        while (lanes.next()) |entry| {
            const queued = entry.value_ptr.queued.first() orelse continue;
            return .{ .key = .init(queued.endpoint, queued.req_id), .kind = queued.kind };
        }
        return null;
    }

    pub fn collectDrainable(self: *RequestBook, endpoints: []types.Endpoint) usize {
        if (endpoints.len == 0 or self.lanes.count() == 0) return 0;
        const capacity = self.lanes.capacity();
        std.debug.assert(capacity > 0);
        const start = @min(self.drain_cursor, capacity - 1);
        var count: usize = 0;
        var pass: usize = 0;
        while (pass < 2) : (pass += 1) {
            if (pass == 1 and start == 0) break;
            var lanes = self.lanes.iterator();
            lanes.index = @intCast(if (pass == 0) start else 0);
            while (lanes.next()) |entry| {
                const position: usize = @intCast(lanes.index - 1);
                if (pass == 1 and position >= start) break;
                if (entry.value_ptr.establishing != null or entry.value_ptr.queued.len() == 0 or
                    self.hasArmedRetryAtEndpoint(entry.key_ptr.*)) continue;
                endpoints[count] = entry.key_ptr.*;
                count += 1;
                if (count == endpoints.len) {
                    self.drain_cursor = @as(usize, @intCast(lanes.index)) % capacity;
                    return count;
                }
            }
        }
        self.drain_cursor = start;
        return count;
    }

    pub fn hasActiveFindNode(self: *const RequestBook, node_id: *const types.NodeId) bool {
        var iterator = self.active.iterator();
        while (iterator.next()) |entry| {
            if (!std.mem.eql(u8, &entry.key_ptr.endpoint.node_id, node_id)) continue;
            if (entry.value_ptr.* == .active and entry.value_ptr.active.handshake_send == null and entry.value_ptr.active.retry_send == null and entry.value_ptr.active.response == .nodes) return true;
        }
        return false;
    }

    pub fn firstQueued(self: *const RequestBook, endpoint: types.Endpoint) ?*const QueuedRequest {
        if (self.hasArmedRetryAtEndpoint(endpoint)) return null;
        const lane = self.lanes.getPtr(endpoint) orelse return null;
        if (lane.establishing != null) return null;
        return lane.queued.first();
    }

    pub fn challenge(self: *RequestBook, nonce: *const [12]u8, from: types.Address) !ChallengePreparation {
        const challenge_key = types.ChallengeKey.init(from, nonce);
        const handle = self.challenge_by_nonce.get(challenge_key) orelse return error.InvalidChallenge;
        const active = self.getActivePtr(handle) orelse return error.InvalidChallenge;
        const recovery = switch (active.phase) {
            .awaiting_whoareyou => |value| value.recovery,
            .awaiting_response => |value| if (value.wait.canChallenge()) value.recovery else return error.InvalidChallenge,
        };
        if (!std.mem.eql(u8, &recovery.nonce, nonce)) return error.InvalidChallenge;
        if (self.lanes.get(handle.key.endpoint)) |lane| {
            if (lane.establishing) |existing| if (!handleEql(existing, handle))
                return error.EndpointEstablishing;
        }
        return .{ .handle = handle, .recovery = recovery, .permit = active.permitHandle() };
    }

    pub fn hasChallenge(self: *const RequestBook, nonce: *const [12]u8, from: types.Address) bool {
        return self.challenge_by_nonce.contains(.init(from, nonce));
    }

    pub fn preflightHandshake(self: *RequestBook, preparation: ChallengePreparation) !void {
        const active = self.getActivePtr(preparation.handle) orelse return error.StaleRequest;
        if (!std.meta.eql(active.permitHandle(), preparation.permit)) return error.StaleRequest;
        const recovery = challengeableRecoveryPtr(&active.phase) orelse return error.InvalidChallenge;
        if (!std.meta.eql(recovery.*, preparation.recovery)) return error.InvalidChallenge;
        const indexed = self.challenge_by_nonce.get(.init(preparation.handle.key.endpoint.addr, &recovery.nonce)) orelse return error.InvalidChallenge;
        if (!handleEql(indexed, preparation.handle)) return error.InvalidChallenge;
        _ = std.math.add(u64, self.next_handshake_generation, 1) catch return error.GenerationExhausted;
    }

    pub fn beginHandshake(
        self: *RequestBook,
        preparation: ChallengePreparation,
        keys: PendingSessionKeys,
        deadline_ns: i64,
    ) !HandshakeHandle {
        try self.preflightHandshake(preparation);
        const request = self.active.getPtr(preparation.handle.key) orelse return error.StaleRequest;
        if (request.* != .active or request.active.generation != preparation.handle.generation or request.active.handshake_send != null or request.active.retry_send != null) return error.StaleRequest;
        const recovery = challengeableRecoveryPtr(&request.active.phase) orelse return error.InvalidChallenge;
        if (!std.meta.eql(recovery.*, preparation.recovery)) return error.InvalidChallenge;
        const indexed = self.challenge_by_nonce.get(.init(preparation.handle.key.endpoint.addr, &recovery.nonce)) orelse return error.InvalidChallenge;
        if (!handleEql(indexed, preparation.handle)) return error.InvalidChallenge;
        const next_generation = std.math.add(u64, self.next_handshake_generation, 1) catch return error.GenerationExhausted;
        const handle = HandshakeHandle{ .request = preparation.handle, .send_generation = self.next_handshake_generation };
        const prior_establishing = if (self.lanes.get(preparation.handle.key.endpoint)) |lane|
            if (lane.establishing) |existing| handleEql(existing, preparation.handle) else false
        else
            false;
        self.next_handshake_generation = next_generation;
        std.debug.assert(self.challenge_by_nonce.remove(.init(preparation.handle.key.endpoint.addr, &preparation.recovery.nonce)));
        request.active.handshake_send = .{
            .send_generation = handle.send_generation,
            .keys = keys,
            .next_deadline_ns = deadline_ns,
            .prior_establishing = prior_establishing,
        };
        self.setEstablishing(preparation.handle);
        return handle;
    }

    pub fn completeHandshake(self: *RequestBook, handle: HandshakeHandle, completion: HandshakeSendCompletion) ?RetryCompletionView {
        const request = self.active.getPtr(handle.request.key) orelse return null;
        if (request.* != .active or request.active.generation != handle.request.generation) return null;
        const sending = request.active.handshake_send orelse return null;
        if (sending.send_generation != handle.send_generation) return null;
        const view = RetryCompletionView{ .kind = request.active.response.kind() };
        if (completion == .sent) {
            const pending = PendingHandshake{ .send_generation = handle.send_generation, .keys = sending.keys };
            switch (request.active.phase) {
                .awaiting_whoareyou => |*whoareyou| {
                    const recovery = whoareyou.recovery;
                    request.active.phase = .{ .awaiting_response = .{
                        .recovery = recovery,
                        .wait = .{ .handshake_sent = pending },
                    } };
                },
                .awaiting_response => |*response| {
                    std.debug.assert(response.wait.canChallenge());
                    response.wait = .{ .handshake_sent = pending };
                },
            }
            request.active.deadline_ns = sending.next_deadline_ns;
            request.active.handshake_send = null;
        } else {
            const recovery = challengeableRecoveryPtr(&request.active.phase) orelse unreachable;
            // beginHandshake removed this exact entry from a map preallocated
            // for every active request. Reinsertion is therefore infallible and
            // is completed before disarming the send, so rollback cannot expose
            // a challengeable request without its nonce index.
            std.debug.assert(!self.challenge_by_nonce.contains(.init(handle.request.key.endpoint.addr, &recovery.nonce)));
            self.challenge_by_nonce.putAssumeCapacityNoClobber(.init(handle.request.key.endpoint.addr, &recovery.nonce), handle.request);
            request.active.handshake_send = null;
            if (!sending.prior_establishing) self.clearEstablishing(handle.request);
        }
        return view;
    }

    pub fn pendingKeys(self: *RequestBook, endpoint: types.Endpoint) ?PendingKeysView {
        const lane = self.lanes.get(endpoint) orelse return null;
        const handle = lane.establishing orelse return null;
        const active = self.getActivePtr(handle) orelse return null;
        const response = switch (active.phase) {
            .awaiting_whoareyou => return null,
            .awaiting_response => |value| value,
        };
        const pending = response.wait.pendingHandshake() orelse return null;
        return .{
            .handle = .{ .request = handle, .send_generation = pending.send_generation },
            .keys = pending.keys,
        };
    }

    pub fn promotePending(self: *RequestBook, view: PendingKeysView) bool {
        const active = self.getActivePtr(view.handle.request) orelse return false;
        switch (active.phase) {
            .awaiting_whoareyou => return false,
            .awaiting_response => |*response| {
                const pending = response.wait.pendingHandshake() orelse return false;
                if (pending.send_generation != view.handle.send_generation) return false;
                response.wait = response.wait.afterPromotion();
            },
        }
        if (self.lanes.getPtr(view.handle.request.key.endpoint)) |lane| {
            if (lane.establishing) |handle| {
                if (handleEql(handle, view.handle.request)) lane.establishing = null;
            }
        }
        self.removeEmptyLane(view.handle.request.key.endpoint);
        return true;
    }

    pub fn matchesPending(self: *RequestBook, view: PendingKeysView) bool {
        const active = self.getActivePtr(view.handle.request) orelse return false;
        const response = switch (active.phase) {
            .awaiting_whoareyou => return false,
            .awaiting_response => |value| value,
        };
        const pending = response.wait.pendingHandshake() orelse return false;
        return pending.send_generation == view.handle.send_generation and std.meta.eql(pending.keys, view.keys);
    }

    pub fn get(self: *RequestBook, key: types.RequestKey) ?*ActiveRequest {
        const request = self.active.getPtr(key) orelse return null;
        if (request.* != .active or request.active.handshake_send != null or request.active.retry_send != null) return null;
        return &request.active;
    }

    pub fn prepareRetainedRetry(self: *RequestBook, handle: RequestHandle, deadline_ns: i64) !RetryPreparationView {
        const request = self.active.getPtr(handle.key) orelse return error.StaleRequest;
        if (request.* != .active or request.active.generation != handle.generation or
            request.active.handshake_send != null or request.active.retry_send != null) return error.StaleRequest;
        const next_generation = std.math.add(u64, self.next_retry_generation, 1) catch return error.GenerationExhausted;
        const packet = switch (request.active.phase) {
            .awaiting_whoareyou => |phase| phase.retry_packet,
            .awaiting_response => return error.InvalidRetryPhase,
        };
        const send_generation = self.next_retry_generation;
        request.active.retry_send = .{
            .send_generation = send_generation,
            .next_deadline_ns = deadline_ns,
            .preparation = .retained,
        };
        self.next_retry_generation = next_generation;
        return .{ .handle = .{ .request = handle, .send_generation = send_generation }, .packet = packet };
    }

    pub fn failRetryPreparation(self: *RequestBook, handle: RequestHandle, deadline_ns: i64) bool {
        const request = self.getActivePtr(handle) orelse return false;
        request.attempts += 1;
        request.deadline_ns = deadline_ns;
        return true;
    }

    pub fn preflightFreshRetry(self: *RequestBook, handle: RequestHandle) !void {
        const request = self.active.getPtr(handle.key) orelse return error.StaleRequest;
        if (request.* != .active or request.active.generation != handle.generation or
            request.active.handshake_send != null or request.active.retry_send != null) return error.StaleRequest;
        if (request.active.phase != .awaiting_response) return error.InvalidRetryPhase;
        _ = std.math.add(u64, self.next_retry_generation, 1) catch return error.GenerationExhausted;
    }

    pub fn prepareFreshRetry(
        self: *RequestBook,
        handle: RequestHandle,
        packet: types.PacketBytes,
        transition: FreshRetryTransition,
        deadline_ns: i64,
        next_admission: *AdmissionPermit,
    ) !RetryPreparationView {
        const request = self.active.getPtr(handle.key) orelse return error.StaleRequest;
        if (request.* != .active or request.active.generation != handle.generation or
            request.active.handshake_send != null or request.active.retry_send != null) return error.StaleRequest;
        if (request.active.phase != .awaiting_response) return error.InvalidRetryPhase;
        const next_generation = std.math.add(u64, self.next_retry_generation, 1) catch return error.GenerationExhausted;
        const send_generation = self.next_retry_generation;
        request.active.retry_send = .{
            .send_generation = send_generation,
            .next_deadline_ns = deadline_ns,
            .preparation = .{ .fresh = .{
                .transition = transition,
                .admission = next_admission.move(),
            } },
        };
        self.next_retry_generation = next_generation;
        return .{ .handle = .{ .request = handle, .send_generation = send_generation }, .packet = packet };
    }

    pub fn completeRetry(
        self: *RequestBook,
        handle: RetryHandle,
        completion: RetrySendCompletion,
        admission: *admission_mod.IngressAdmission,
    ) ?RetryCompletionView {
        const request = self.active.getPtr(handle.request.key) orelse return null;
        if (request.* != .active or request.active.generation != handle.request.generation) return null;
        const canonical = request.active.retry_send orelse return null;
        if (canonical.send_generation != handle.send_generation) return null;

        var sending = canonical;
        request.active.retry_send = null;
        const view = RetryCompletionView{ .kind = request.active.response.kind() };
        switch (sending.preparation) {
            .retained => {},
            .fresh => |*fresh| if (completion == .sent) {
                const response = &request.active.phase.awaiting_response;
                const old_challenge = types.ChallengeKey.init(handle.request.key.endpoint.addr, &response.recovery.nonce);
                if (response.wait.canChallenge()) std.debug.assert(self.challenge_by_nonce.remove(old_challenge));
                const nonce = switch (fresh.transition) {
                    .probe => |probe_retry| probe_retry.nonce,
                    .response => |response_nonce| response_nonce,
                };
                switch (fresh.transition) {
                    .probe => |probe_retry| {
                        var recovery = response.recovery;
                        recovery.nonce = nonce;
                        request.active.phase = .{ .awaiting_whoareyou = .{
                            .retry_packet = probe_retry.retry_packet,
                            .recovery = recovery,
                        } };
                    },
                    .response => {
                        response.recovery.nonce = nonce;
                        response.wait = response.wait.afterFreshRetry();
                    },
                }
                self.challenge_by_nonce.putAssumeCapacityNoClobber(.init(handle.request.key.endpoint.addr, &nonce), handle.request);
                if (fresh.transition == .probe) self.setEstablishing(handle.request);
                switch (request.active.response) {
                    .nodes => |*nodes| nodes.resetGeneration(),
                    .pong, .talkresp => {},
                }
                request.active.admission.release(admission);
                request.active.admission = fresh.admission.move();
            } else {
                fresh.admission.release(admission);
            },
        }
        request.active.deadline_ns = sending.next_deadline_ns;
        request.active.attempts += 1;
        return view;
    }

    pub fn getSending(self: *const RequestBook, handle: RequestHandle) ?ResponseExpectation {
        const request = self.active.get(handle.key) orelse return null;
        if (request != .sending or request.sending.generation != handle.generation) return null;
        return request.sending.response;
    }

    pub fn containsRequest(self: *const RequestBook, key: types.RequestKey) bool {
        return self.active.contains(key);
    }

    pub fn matchesHandle(self: *const RequestBook, handle: RequestHandle) bool {
        const current = self.currentHandle(handle.key) orelse return false;
        return handleEql(current, handle);
    }

    pub fn handleFor(self: *const RequestBook, key: types.RequestKey) ?RequestHandle {
        return self.currentHandle(key);
    }

    pub fn queuedHandleFor(self: *const RequestBook, key: types.RequestKey) ?RequestHandle {
        const lane = self.lanes.get(key.endpoint) orelse return null;
        for (lane.queued.items.items[lane.queued.head..]) |queued| {
            if (types.RequestKeyContext.eql(.{}, queued.handle().key, key)) return queued.handle();
        }
        return null;
    }

    pub const ActiveScan = struct {
        index: usize = 0,
        slots_scanned: usize = 0,
        done: bool = false,
    };

    pub const QueuedScan = struct {
        index: usize = 0,
        done: bool = false,
    };

    pub fn collectExpiredQueuedBatch(self: *const RequestBook, out: []types.RequestKey, now_ns: i64, scan: *QueuedScan) usize {
        std.debug.assert(out.len >= self.limits.max_queued_requests_per_endpoint);
        std.debug.assert(out.len <= config_mod.MAX_QUEUED_REQUESTS);
        if (scan.done) return 0;

        var iterator = self.lanes.iterator();
        iterator.index = @intCast(scan.index);
        var count: usize = 0;
        while (iterator.next()) |entry| {
            const lane_slot: usize = @intCast(iterator.index - 1);
            var expired_count: usize = 0;
            for (entry.value_ptr.queued.items.items[entry.value_ptr.queued.head..]) |queued| {
                if (now_ns >= queued.deadline_ns) expired_count += 1;
            }
            std.debug.assert(expired_count <= self.limits.max_queued_requests_per_endpoint);
            if (expired_count > out.len - count) {
                std.debug.assert(count > 0);
                scan.index = lane_slot;
                return count;
            }
            for (entry.value_ptr.queued.items.items[entry.value_ptr.queued.head..]) |queued| {
                if (now_ns < queued.deadline_ns) continue;
                out[count] = .init(queued.endpoint, queued.req_id);
                count += 1;
            }
            scan.index = iterator.index;
            if (count == out.len) return count;
        }
        scan.index = self.lanes.capacity();
        scan.done = true;
        return count;
    }

    pub fn collectTimedOutBatch(self: *const RequestBook, out: []types.RequestKey, now_ns: i64, scan: *ActiveScan) usize {
        if (scan.done or out.len == 0) return 0;
        const capacity = self.active.capacity();
        var iterator = self.active.iterator();
        iterator.index = @intCast(scan.index);
        var count: usize = 0;
        while (count < out.len) {
            const previous = scan.index;
            const entry = iterator.next() orelse {
                scan.slots_scanned += capacity - previous;
                scan.index = capacity;
                scan.done = true;
                break;
            };
            scan.index = iterator.index;
            scan.slots_scanned += scan.index - previous;
            if (entry.value_ptr.* == .active and entry.value_ptr.active.handshake_send == null and entry.value_ptr.active.retry_send == null and now_ns >= entry.value_ptr.active.deadline_ns) {
                out[count] = entry.key_ptr.*;
                count += 1;
            }
        }
        if (scan.index == capacity) scan.done = true;
        return count;
    }
    pub fn activeSlotCapacity(self: *const RequestBook) usize {
        return self.active.capacity();
    }
    pub fn canReplaceChallenge(self: *const RequestBook, key: types.RequestKey, nonce: *const [12]u8) bool {
        const indexed = self.challenge_by_nonce.get(.init(key.endpoint.addr, nonce)) orelse return true;
        const current = self.currentHandle(key) orelse return false;
        return handleEql(indexed, current);
    }

    pub fn canEstablish(self: *const RequestBook, key: types.RequestKey) bool {
        const lane = self.lanes.get(key.endpoint) orelse return true;
        const establishing = lane.establishing orelse return true;
        const current = self.currentHandle(key) orelse return false;
        return handleEql(establishing, current);
    }

    pub fn takeQueued(self: *RequestBook, key: types.RequestKey) ?QueuedRequest {
        const lane = self.lanes.getPtr(key.endpoint) orelse return null;
        var live_index: usize = 0;
        while (live_index < lane.queued.len()) : (live_index += 1) {
            const absolute = lane.queued.head + live_index;
            const queued = lane.queued.items.items[absolute];
            if (queued.req_id.len != key.req_id.len or !std.mem.eql(u8, queued.req_id.slice(), key.req_id.slice())) continue;
            const removed = lane.queued.items.orderedRemove(absolute);
            std.debug.assert(self.queued_total > 0);
            self.queued_total -= 1;
            if (lane.queued.len() == 0) lane.queued.compact();
            self.removeEmptyLane(key.endpoint);
            return removed;
        }
        return null;
    }

    pub fn takeQueuedHandle(self: *RequestBook, handle: RequestHandle) ?QueuedRequest {
        const lane = self.lanes.getPtr(handle.key.endpoint) orelse return null;
        for (lane.queued.items.items[lane.queued.head..]) |queued| {
            if (queued.generation != handle.generation) continue;
            if (!types.RequestKeyContext.eql(.{}, queued.handle().key, handle.key)) continue;
            return self.takeQueued(handle.key);
        }
        return null;
    }

    pub fn takeTerminal(self: *RequestBook, key: types.RequestKey) ?TerminalRequest {
        const current = self.active.getPtr(key) orelse return null;
        const handle = RequestHandle{ .key = key, .generation = storedGeneration(current) };
        const removed = self.active.fetchRemove(key).?.value;
        switch (removed) {
            .sending => |request| {
                self.clearIndexes(handle, request.phase);
                if (request.queued_intent) self.discardQueuedIntent(key);
            },
            .active => |request| {
                self.clearIndexes(handle, request.phase);
                if (request.queued_intent) self.discardQueuedIntent(key);
            },
        }
        return switch (removed) {
            .sending => |request| .{ .sending = request },
            .active => |request| .{ .active = request },
        };
    }

    pub fn take(self: *RequestBook, key: types.RequestKey) ?ActiveRequest {
        const current = self.active.getPtr(key) orelse return null;
        if (current.* != .active or current.active.handshake_send != null or current.active.retry_send != null) return null;
        return (self.takeTerminal(key) orelse unreachable).active;
    }

    pub fn detachLookup(self: *RequestBook, lookup_id: u32) void {
        var active = self.active.iterator();
        while (active.next()) |entry| switch (entry.value_ptr.*) {
            .sending => |*request| detachOrigin(&request.origin, lookup_id),
            .active => |*request| detachOrigin(&request.origin, lookup_id),
        };
        var lanes = self.lanes.iterator();
        while (lanes.next()) |entry| {
            for (entry.value_ptr.queued.items.items[entry.value_ptr.queued.head..]) |*queued| switch (queued.origin) {
                .lookup => |id| if (id == lookup_id) {
                    queued.origin = .detached_lookup;
                },
                else => {},
            };
        }
    }

    pub fn assertInvariants(self: *const RequestBook) void {
        std.debug.assert(self.active.count() <= self.limits.max_active_requests);
        std.debug.assert(self.queued_total <= self.limits.max_queued_requests);
        var counted: usize = 0;
        var lanes = self.lanes.iterator();
        while (lanes.next()) |entry| {
            counted += entry.value_ptr.queued.len();
            std.debug.assert(entry.value_ptr.queued.len() <= self.limits.max_queued_requests_per_endpoint);
            if (entry.value_ptr.establishing) |handle| {
                std.debug.assert(types.EndpointContext.eql(.{}, handle.key.endpoint, entry.key_ptr.*));
                const request = self.active.getPtr(handle.key) orelse unreachable;
                std.debug.assert(storedGeneration(request) == handle.generation);
            }
            for (entry.value_ptr.queued.items.items[entry.value_ptr.queued.head..]) |queued| {
                const queued_key = types.RequestKey.init(queued.endpoint, queued.req_id);
                std.debug.assert(types.EndpointContext.eql(.{}, queued.endpoint, entry.key_ptr.*));
                if (self.active.get(queued_key)) |request| {
                    std.debug.assert(request == .sending and request.sending.queued_intent);
                }
            }
        }
        std.debug.assert(counted == self.queued_total);
        var challenges = self.challenge_by_nonce.iterator();
        while (challenges.next()) |entry| {
            const handle = entry.value_ptr.*;
            const request = self.active.getPtr(handle.key) orelse unreachable;
            std.debug.assert(storedGeneration(request) == handle.generation);
            const phase = storedPhase(request);
            const expected = challengeForPhase(handle.key.endpoint.addr, phase.*) orelse unreachable;
            std.debug.assert(std.meta.eql(entry.key_ptr.*, expected));
        }
    }

    fn clearEstablishing(self: *RequestBook, handle: RequestHandle) void {
        if (self.lanes.getPtr(handle.key.endpoint)) |lane| if (lane.establishing) |existing| {
            if (handleEql(existing, handle)) lane.establishing = null;
        };
        self.removeEmptyLane(handle.key.endpoint);
    }

    fn setEstablishing(self: *RequestBook, handle: RequestHandle) void {
        const lane = self.lanes.getOrPutAssumeCapacity(handle.key.endpoint);
        if (!lane.found_existing) lane.value_ptr.* = .{};
        std.debug.assert(lane.value_ptr.establishing == null or handleEql(lane.value_ptr.establishing.?, handle));
        lane.value_ptr.establishing = handle;
    }

    fn currentHandle(self: *const RequestBook, key: types.RequestKey) ?RequestHandle {
        const request = self.active.getPtr(key) orelse return null;
        return .{ .key = key, .generation = storedGeneration(request) };
    }

    fn getActivePtr(self: *RequestBook, handle: RequestHandle) ?*ActiveRequest {
        const request = self.active.getPtr(handle.key) orelse return null;
        if (request.* != .active or request.active.generation != handle.generation or request.active.handshake_send != null or request.active.retry_send != null) return null;
        return &request.active;
    }

    fn hasArmedRetryAtEndpoint(self: *const RequestBook, endpoint: types.Endpoint) bool {
        var requests = self.active.iterator();
        while (requests.next()) |entry| {
            if (!types.EndpointContext.eql(.{}, entry.key_ptr.endpoint, endpoint)) continue;
            if (entry.value_ptr.* == .active and entry.value_ptr.active.retry_send != null) return true;
        }
        return false;
    }

    fn containsQueued(self: *const RequestBook, key: types.RequestKey) bool {
        const lane = self.lanes.get(key.endpoint) orelse return false;
        for (lane.queued.items.items[lane.queued.head..]) |queued| {
            if (queued.req_id.len == key.req_id.len and std.mem.eql(u8, queued.req_id.slice(), key.req_id.slice())) return true;
        }
        return false;
    }

    fn discardQueuedIntent(self: *RequestBook, key: types.RequestKey) void {
        const lane = self.lanes.getPtr(key.endpoint) orelse unreachable;
        const queued = lane.queued.first() orelse unreachable;
        std.debug.assert(types.RequestKeyContext.eql(.{}, .init(queued.endpoint, queued.req_id), key));
        lane.queued.discardFirst();
        std.debug.assert(self.queued_total > 0);
        self.queued_total -= 1;
        self.removeEmptyLane(key.endpoint);
    }

    fn clearIndexes(self: *RequestBook, handle: RequestHandle, phase: Phase) void {
        if (challengeForPhase(handle.key.endpoint.addr, phase)) |index| {
            if (self.challenge_by_nonce.get(index)) |indexed| if (handleEql(indexed, handle)) {
                _ = self.challenge_by_nonce.remove(index);
            };
        }
        if (self.lanes.getPtr(handle.key.endpoint)) |lane| if (lane.establishing) |establishing| {
            if (handleEql(establishing, handle)) lane.establishing = null;
        };
        self.removeEmptyLane(handle.key.endpoint);
    }

    fn removeEmptyLane(self: *RequestBook, endpoint: types.Endpoint) void {
        const lane = self.lanes.getPtr(endpoint) orelse return;
        if (lane.establishing != null or lane.queued.len() != 0) return;
        var removed = self.lanes.fetchRemove(endpoint).?.value;
        removed.deinit(self.alloc);
    }
};

fn storedGeneration(request: *const StoredRequest) u64 {
    return switch (request.*) {
        .sending => |value| value.generation,
        .active => |value| value.generation,
    };
}

fn storedPhase(request: *const StoredRequest) *const Phase {
    return switch (request.*) {
        .sending => |*value| &value.phase,
        .active => |*value| &value.phase,
    };
}

fn releasePreparedRetry(active: *ActiveRequest, admission: *admission_mod.IngressAdmission) void {
    const retry = active.retry_send orelse return;
    switch (retry.preparation) {
        .retained => {},
        .fresh => |fresh| {
            var prepared = fresh.admission;
            prepared.release(admission);
        },
    }
    active.retry_send = null;
}

fn detachOrigin(origin: *types.RequestOrigin, lookup_id: u32) void {
    switch (origin.*) {
        .lookup => |id| {
            if (id == lookup_id) origin.* = .detached_lookup;
        },
        else => {},
    }
}

pub const Testing = if (@import("builtin").is_test) struct {
    pub fn exhaustRetryGeneration(book: *RequestBook) void {
        book.next_retry_generation = std.math.maxInt(u64);
    }

    pub fn exhaustHandshakeGeneration(book: *RequestBook) void {
        book.next_handshake_generation = std.math.maxInt(u64);
    }

    pub fn retryCanonicalActive(book: *RequestBook, handle: RetryHandle) ?*ActiveRequest {
        const stored = book.active.getPtr(handle.request.key) orelse return null;
        if (stored.* != .active or stored.active.generation != handle.request.generation) return null;
        const sending = stored.active.retry_send orelse return null;
        if (sending.send_generation != handle.send_generation) return null;
        return &stored.active;
    }

    pub fn handshakeCanonicalActive(book: *RequestBook, handle: HandshakeHandle) ?*ActiveRequest {
        const stored = book.active.getPtr(handle.request.key) orelse return null;
        if (stored.* != .active or stored.active.generation != handle.request.generation) return null;
        const sending = stored.active.handshake_send orelse return null;
        if (sending.send_generation != handle.send_generation) return null;
        return &stored.active;
    }

    /// Replace only the candidate generation after a caller has copied a
    /// pending view. This preserves the request, lane, permit, and response
    /// owner while making that copied view stale at the real auth call site.
    pub fn replacePendingHandshake(
        book: *RequestBook,
        stale: PendingKeysView,
        keys: PendingSessionKeys,
    ) !PendingKeysView {
        const active = book.getActivePtr(stale.handle.request) orelse return error.StaleRequest;
        const response = switch (active.phase) {
            .awaiting_whoareyou => return error.InvalidChallenge,
            .awaiting_response => |*value| value,
        };
        const current = response.wait.pendingHandshake() orelse return error.InvalidChallenge;
        if (current.send_generation != stale.handle.send_generation or !std.meta.eql(current.keys, stale.keys)) {
            return error.StaleRequest;
        }
        const next = std.math.add(u64, book.next_handshake_generation, 1) catch return error.GenerationExhausted;
        const replacement = PendingHandshake{
            .send_generation = book.next_handshake_generation,
            .keys = keys,
        };
        book.next_handshake_generation = next;
        response.wait = switch (response.wait) {
            .handshake_sent => .{ .handshake_sent = replacement },
            .retry_with_pending_keys => .{ .retry_with_pending_keys = replacement },
            .session_request, .handshake_confirmed => unreachable,
        };
        return .{
            .handle = .{
                .request = stale.handle.request,
                .send_generation = replacement.send_generation,
            },
            .keys = keys,
        };
    }

    pub fn handshakeShutdownState(
        book: *const RequestBook,
        handle: HandshakeHandle,
        nonce: *const [12]u8,
    ) struct { active: bool, sending: bool, lane: bool, challenge: bool } {
        const stored = book.active.get(handle.request.key);
        return .{
            .active = stored != null,
            .sending = if (stored) |value| value == .active and
                value.active.generation == handle.request.generation and
                value.active.handshake_send != null and
                value.active.handshake_send.?.send_generation == handle.send_generation else false,
            .lane = if (book.lanes.get(handle.request.key.endpoint)) |lane|
                if (lane.establishing) |owner| handleEql(owner, handle.request) else false
            else
                false,
            .challenge = book.hasChallenge(nonce, handle.request.key.endpoint.addr),
        };
    }
} else struct {};

fn handleEql(a: RequestHandle, b: RequestHandle) bool {
    return a.generation == b.generation and types.RequestKeyContext.eql(.{}, a.key, b.key);
}

fn challengeForPhase(address: types.Address, phase: Phase) ?types.ChallengeKey {
    return switch (phase) {
        .awaiting_whoareyou => |state| .init(address, &state.recovery.nonce),
        .awaiting_response => |response| if (response.wait.canChallenge()) .init(address, &response.recovery.nonce) else null,
    };
}

fn challengeableRecoveryPtr(phase: *const Phase) ?*const RecoveryState {
    return switch (phase.*) {
        .awaiting_whoareyou => |*state| &state.recovery,
        .awaiting_response => |*response| if (response.wait.canChallenge()) &response.recovery else null,
    };
}

test "retry in-flight state is compact canonical active substate" {
    try std.testing.expectEqual(@as(usize, 3), @typeInfo(RetrySendState).@"struct".fields.len);
    try std.testing.expect(@hasField(RetrySendState, "send_generation"));
    try std.testing.expect(@hasField(RetrySendState, "next_deadline_ns"));
    try std.testing.expect(@hasField(RetrySendState, "preparation"));
    try std.testing.expect(!@hasField(RetrySendState, "generation"));
    try std.testing.expect(!@hasField(RetrySendState, "origin"));
    try std.testing.expect(!@hasField(RetrySendState, "response"));
    try std.testing.expect(!@hasField(RetrySendState, "phase"));
    try std.testing.expect(!@hasField(RetrySendState, "attempts"));
    try std.testing.expect(!@hasField(RetrySendState, "queued_intent"));
    inline for (@typeInfo(RetrySendState).@"struct".fields) |field| {
        try std.testing.expect(field.type != ActiveRequest);
        try std.testing.expect(field.type != Phase);
        try std.testing.expect(field.type != Response);
    }
    try std.testing.expect(@hasField(ActiveRequest, "retry_send"));
    try std.testing.expect(!@hasField(StoredRequest, "sending_retry"));
}

test "request handshake in-flight state is compact canonical active substate" {
    try std.testing.expect(@sizeOf(HandshakeSendState) <= 64);
    try std.testing.expectEqual(@as(usize, 4), @typeInfo(HandshakeSendState).@"struct".fields.len);
    try std.testing.expect(@hasField(HandshakeSendState, "send_generation"));
    try std.testing.expect(@hasField(HandshakeSendState, "keys"));
    try std.testing.expect(@hasField(HandshakeSendState, "next_deadline_ns"));
    try std.testing.expect(@hasField(HandshakeSendState, "prior_establishing"));
    try std.testing.expect(!@hasField(HandshakeSendState, "prior"));
    try std.testing.expect(!@hasField(HandshakeSendState, "phase"));
    try std.testing.expect(!@hasField(HandshakeSendState, "response"));
    try std.testing.expect(!@hasField(HandshakeSendState, "recovery"));
    try std.testing.expect(!@hasField(HandshakeSendState, "admission"));
    inline for (@typeInfo(HandshakeSendState).@"struct".fields) |field| {
        try std.testing.expect(field.type != ActiveRequest);
        try std.testing.expect(field.type != Phase);
        try std.testing.expect(field.type != Response);
        try std.testing.expect(field.type != RecoveryState);
        try std.testing.expect(field.type != AdmissionPermit);
    }
    try std.testing.expect(@hasField(ActiveRequest, "handshake_send"));
    try std.testing.expect(!@hasField(StoredRequest, "sending_handshake"));
}
