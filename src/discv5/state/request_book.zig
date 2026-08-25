const std = @import("std");
const admission_mod = @import("../admission.zig");
const config_mod = @import("../config.zig");
const enr = @import("../enr.zig");
const request_queue = @import("request_queue.zig");
const types = @import("../types.zig");

const Allocator = std.mem.Allocator;
const AdmissionPermit = admission_mod.AdmissionPermit;

pub const MAX_NODES_RESPONSE: usize = config_mod.MAX_NODES_RESPONSE;
pub const RequestDistances = request_queue.RequestDistances;

pub const PendingSessionKeys = struct {
    initiator_key: [16]u8,
    recipient_key: [16]u8,
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
    handshake_sent: PendingSessionKeys,
    handshake_confirmed,
    retry_with_pending_keys: PendingSessionKeys,

    pub fn canChallenge(self: ResponseWait) bool {
        return switch (self) {
            .session_request, .retry_with_pending_keys => true,
            .handshake_sent, .handshake_confirmed => false,
        };
    }

    pub fn pendingKeys(self: ResponseWait) ?PendingSessionKeys {
        return switch (self) {
            .handshake_sent, .retry_with_pending_keys => |keys| keys,
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

    pub fn kind(self: Response) types.RequestKind {
        return switch (self) {
            .pong => .ping,
            .nodes => .findnode,
            .talkresp => .talkreq,
        };
    }
};

/// Compact response fact owned while an outbound request is prepared but not
/// yet sent. The large NODES accumulator only becomes real at send commit.
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

pub const ActiveRequest = struct {
    origin: types.RequestOrigin,
    response: Response,
    phase: Phase,
    admission: AdmissionPermit,
    deadline_ns: i64,
    attempts: u32 = 0,
};

pub const QueuedRequest = request_queue.QueuedRequest;
const EndpointLane = request_queue.EndpointLane;

const ActiveMap = std.HashMap(types.RequestKey, ActiveRequest, types.RequestKeyContext, std.hash_map.default_max_load_percentage);
const LaneMap = std.HashMap(types.Endpoint, EndpointLane, types.EndpointContext, std.hash_map.default_max_load_percentage);

pub const PreparedRequest = struct {
    key: types.RequestKey,
    origin: types.RequestOrigin,
    response: ResponseExpectation,
    phase: Phase,
    admission: AdmissionPermit,
    deadline_ns: i64,
    index_challenge: ?types.ChallengeKey,
    establish: bool,

    pub fn abort(self: *PreparedRequest, admission: *admission_mod.IngressAdmission) void {
        self.admission.release(admission);
    }
};

pub const ChallengePreparation = struct {
    key: types.RequestKey,
    recovery: RecoveryState,
};

pub const PendingKeysView = struct {
    key: types.RequestKey,
    keys: PendingSessionKeys,
};

pub const RequestBook = struct {
    alloc: Allocator,
    limits: config_mod.Limits,
    active: ActiveMap,
    lanes: LaneMap,
    challenge_by_nonce: std.AutoHashMap(types.ChallengeKey, types.RequestKey),
    queued_total: usize = 0,
    drain_cursor: usize = 0,

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
        var challenges = std.AutoHashMap(types.ChallengeKey, types.RequestKey).init(alloc);
        errdefer challenges.deinit();
        try challenges.ensureTotalCapacity(@intCast(limits.max_active_requests));
        return .{ .alloc = alloc, .limits = limits, .active = active, .lanes = lanes, .challenge_by_nonce = challenges };
    }

    pub fn deinit(self: *RequestBook, admission: *admission_mod.IngressAdmission) void {
        var active = self.active.iterator();
        while (active.next()) |entry| {
            entry.value_ptr.admission.release(admission);
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

    pub fn prepareActive(
        self: *RequestBook,
        admission: *admission_mod.IngressAdmission,
        key: types.RequestKey,
        origin: types.RequestOrigin,
        response: ResponseExpectation,
        phase: Phase,
        deadline_ns: i64,
        establish: bool,
    ) !PreparedRequest {
        if (self.active.contains(key)) return error.DuplicateRequest;
        if (self.active.count() >= self.limits.max_active_requests) return error.TooManyActiveRequests;
        if (establish) {
            if (self.lanes.get(key.endpoint)) |lane| if (lane.establishing != null) return error.EndpointEstablishing;
        }
        const challenge_index = challengeForPhase(key.endpoint.addr, phase);
        if (challenge_index) |index| if (self.challenge_by_nonce.contains(index)) return error.DuplicateChallenge;
        const permit = try admission.acquire(key.endpoint.addr, admission_mod.requestPacketBudget(response.kind()));
        return .{
            .key = key,
            .origin = origin,
            .response = response,
            .phase = phase,
            .admission = permit,
            .deadline_ns = deadline_ns,
            .index_challenge = challenge_index,
            .establish = establish,
        };
    }

    pub fn commitPrepared(self: *RequestBook, prepared: PreparedRequest) void {
        std.debug.assert(!self.active.contains(prepared.key));
        self.active.putAssumeCapacityNoClobber(prepared.key, .{
            .origin = prepared.origin,
            .response = prepared.response.activate(),
            .phase = prepared.phase,
            .admission = prepared.admission,
            .deadline_ns = prepared.deadline_ns,
        });
        if (prepared.index_challenge) |index| self.challenge_by_nonce.putAssumeCapacityNoClobber(index, prepared.key);
        if (prepared.establish) self.setEstablishing(prepared.key);
    }

    pub fn queue(self: *RequestBook, request: QueuedRequest) !void {
        switch (request.origin) {
            .maintenance => |reason| switch (reason) {
                .health => return error.EndpointBusy,
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
        try lane.value_ptr.queued.append(self.alloc, request);
        self.queued_total += 1;
    }

    pub fn shouldQueue(self: *const RequestBook, endpoint: types.Endpoint) bool {
        const lane = self.lanes.get(endpoint) orelse return false;
        return lane.establishing != null or lane.queued.len() != 0;
    }

    pub fn activeCount(self: *const RequestBook) usize {
        return self.active.count();
    }

    pub fn queuedCount(self: *const RequestBook) usize {
        return self.queued_total;
    }

    pub const ReliableSnapshot = struct {
        key: types.RequestKey,
        kind: types.RequestKind,
    };

    pub fn firstReliableActive(self: *const RequestBook) ?ReliableSnapshot {
        var active = self.active.iterator();
        while (active.next()) |entry| {
            if (entry.value_ptr.origin != .reliable_api) continue;
            return .{ .key = entry.key_ptr.*, .kind = entry.value_ptr.response.kind() };
        }
        return null;
    }

    pub fn firstReliableQueued(self: *const RequestBook) ?ReliableSnapshot {
        var lanes = self.lanes.iterator();
        while (lanes.next()) |entry| {
            for (entry.value_ptr.queued.items.items[entry.value_ptr.queued.head..]) |queued| {
                if (queued.origin != .reliable_api) continue;
                return .{ .key = .init(queued.endpoint, queued.req_id), .kind = queued.kind };
            }
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
                if (entry.value_ptr.establishing != null or entry.value_ptr.queued.len() == 0) continue;
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
            if (entry.value_ptr.response == .nodes) return true;
        }
        return false;
    }

    pub fn firstQueued(self: *const RequestBook, endpoint: types.Endpoint) ?*const QueuedRequest {
        const lane = self.lanes.getPtr(endpoint) orelse return null;
        if (lane.establishing != null) return null;
        return lane.queued.first();
    }

    pub fn commitSent(self: *RequestBook, prepared: PreparedRequest) void {
        if (self.containsQueued(prepared.key)) {
            self.commitQueued(prepared);
        } else {
            self.commitPrepared(prepared);
        }
    }

    pub fn commitQueued(self: *RequestBook, prepared: PreparedRequest) void {
        const lane = self.lanes.getPtr(prepared.key.endpoint) orelse unreachable;
        const queued = lane.queued.first() orelse unreachable;
        std.debug.assert(std.meta.eql(types.RequestKey.init(queued.endpoint, queued.req_id), prepared.key));
        lane.queued.discardFirst();
        std.debug.assert(self.queued_total > 0);
        self.queued_total -= 1;
        self.commitPrepared(prepared);
        self.removeEmptyLane(prepared.key.endpoint);
    }

    pub fn challenge(self: *const RequestBook, nonce: *const [12]u8, from: types.Address) !ChallengePreparation {
        const challenge_key = types.ChallengeKey.init(from, nonce);
        const key = self.challenge_by_nonce.get(challenge_key) orelse return error.InvalidChallenge;
        const active = self.active.get(key) orelse return error.InvalidChallenge;
        const recovery = switch (active.phase) {
            .awaiting_whoareyou => |value| value.recovery,
            .awaiting_response => |value| if (value.wait.canChallenge()) value.recovery else return error.InvalidChallenge,
        };
        if (!std.mem.eql(u8, &recovery.nonce, nonce)) return error.InvalidChallenge;
        if (self.lanes.get(key.endpoint)) |lane| {
            if (lane.establishing) |existing| if (!types.RequestKeyContext.eql(.{}, existing, key))
                return error.EndpointEstablishing;
        }
        return .{ .key = key, .recovery = recovery };
    }

    pub fn hasChallenge(self: *const RequestBook, nonce: *const [12]u8, from: types.Address) bool {
        return self.challenge_by_nonce.contains(.init(from, nonce));
    }

    pub fn commitChallenge(
        self: *RequestBook,
        preparation: ChallengePreparation,
        keys: PendingSessionKeys,
        deadline_ns: i64,
    ) void {
        const active = self.active.getPtr(preparation.key) orelse unreachable;
        active.phase = .{ .awaiting_response = .{
            .recovery = preparation.recovery,
            .wait = .{ .handshake_sent = keys },
        } };
        active.deadline_ns = deadline_ns;
        std.debug.assert(self.challenge_by_nonce.remove(.init(preparation.key.endpoint.addr, &preparation.recovery.nonce)));
        self.setEstablishing(preparation.key);
    }

    pub fn pendingKeys(self: *const RequestBook, endpoint: types.Endpoint) ?PendingKeysView {
        const lane = self.lanes.get(endpoint) orelse return null;
        const key = lane.establishing orelse return null;
        const active = self.active.get(key) orelse return null;
        const response = switch (active.phase) {
            .awaiting_whoareyou => return null,
            .awaiting_response => |value| value,
        };
        return .{ .key = key, .keys = response.wait.pendingKeys() orelse return null };
    }

    pub fn promotePending(self: *RequestBook, view: PendingKeysView) void {
        const active = self.active.getPtr(view.key) orelse return;
        switch (active.phase) {
            .awaiting_whoareyou => return,
            .awaiting_response => |*response| response.wait = response.wait.afterPromotion(),
        }
        if (self.lanes.getPtr(view.key.endpoint)) |lane| {
            if (lane.establishing) |key| {
                if (types.RequestKeyContext.eql(.{}, key, view.key)) lane.establishing = null;
            }
        }
        self.removeEmptyLane(view.key.endpoint);
    }

    pub fn get(self: *RequestBook, key: types.RequestKey) ?*ActiveRequest {
        return self.active.getPtr(key);
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
            if (now_ns >= entry.value_ptr.deadline_ns) {
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
        return types.RequestKeyContext.eql(.{}, indexed, key);
    }

    pub fn canEstablish(self: *const RequestBook, key: types.RequestKey) bool {
        const lane = self.lanes.get(key.endpoint) orelse return true;
        const establishing = lane.establishing orelse return true;
        return types.RequestKeyContext.eql(.{}, establishing, key);
    }

    pub fn commitRetry(self: *RequestBook, key: types.RequestKey, deadline_ns: i64) void {
        const active = self.active.getPtr(key) orelse unreachable;
        active.attempts += 1;
        active.deadline_ns = deadline_ns;
    }

    pub fn commitFreshRetry(
        self: *RequestBook,
        key: types.RequestKey,
        transition: FreshRetryTransition,
        deadline_ns: i64,
        next_admission: AdmissionPermit,
        admission: *admission_mod.IngressAdmission,
    ) void {
        const active = self.active.getPtr(key) orelse unreachable;
        var recovery = switch (active.phase) {
            .awaiting_whoareyou => unreachable,
            .awaiting_response => |response| response.recovery,
        };
        const response_wait = active.phase.awaiting_response.wait;
        if (challengeForPhase(key.endpoint.addr, active.phase)) |old| std.debug.assert(self.challenge_by_nonce.remove(old));
        const nonce = switch (transition) {
            .probe => |probe_retry| probe_retry.nonce,
            .response => |response_nonce| response_nonce,
        };
        recovery.nonce = nonce;
        active.phase = switch (transition) {
            .probe => |probe_retry| .{ .awaiting_whoareyou = .{
                .retry_packet = probe_retry.retry_packet,
                .recovery = recovery,
            } },
            .response => .{ .awaiting_response = .{
                .recovery = recovery,
                .wait = response_wait.afterFreshRetry(),
            } },
        };
        self.challenge_by_nonce.putAssumeCapacityNoClobber(.init(key.endpoint.addr, &nonce), key);
        if (transition == .probe) self.setEstablishing(key);
        switch (active.response) {
            .nodes => |*nodes| nodes.resetGeneration(),
            .pong, .talkresp => {},
        }
        active.attempts += 1;
        active.deadline_ns = deadline_ns;
        var previous_admission = active.admission;
        active.admission = next_admission;
        previous_admission.release(admission);
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

    pub fn take(self: *RequestBook, key: types.RequestKey) ?ActiveRequest {
        const removed = self.active.fetchRemove(key) orelse return null;
        self.clearIndexes(key, &removed.value);
        return removed.value;
    }

    pub fn detachLookup(self: *RequestBook, lookup_id: u32) void {
        var active = self.active.iterator();
        while (active.next()) |entry| switch (entry.value_ptr.origin) {
            .lookup => |id| if (id == lookup_id) {
                entry.value_ptr.origin = .detached_lookup;
            },
            else => {},
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
            if (entry.value_ptr.establishing) |key| {
                std.debug.assert(types.EndpointContext.eql(.{}, key.endpoint, entry.key_ptr.*));
                std.debug.assert(self.active.contains(key));
            }
            for (entry.value_ptr.queued.items.items[entry.value_ptr.queued.head..]) |queued| {
                const queued_key = types.RequestKey.init(queued.endpoint, queued.req_id);
                std.debug.assert(types.EndpointContext.eql(.{}, queued.endpoint, entry.key_ptr.*));
                std.debug.assert(!self.active.contains(queued_key));
            }
        }
        std.debug.assert(counted == self.queued_total);
        var challenges = self.challenge_by_nonce.iterator();
        while (challenges.next()) |entry| {
            const active = self.active.get(entry.value_ptr.*) orelse unreachable;
            const expected = challengeForPhase(entry.value_ptr.endpoint.addr, active.phase) orelse unreachable;
            std.debug.assert(std.meta.eql(entry.key_ptr.*, expected));
        }
    }

    fn setEstablishing(self: *RequestBook, key: types.RequestKey) void {
        const lane = self.lanes.getOrPutAssumeCapacity(key.endpoint);
        if (!lane.found_existing) lane.value_ptr.* = .{};
        std.debug.assert(lane.value_ptr.establishing == null or types.RequestKeyContext.eql(.{}, lane.value_ptr.establishing.?, key));
        lane.value_ptr.establishing = key;
    }

    fn containsQueued(self: *const RequestBook, key: types.RequestKey) bool {
        const lane = self.lanes.get(key.endpoint) orelse return false;
        for (lane.queued.items.items[lane.queued.head..]) |queued| {
            if (queued.req_id.len == key.req_id.len and std.mem.eql(u8, queued.req_id.slice(), key.req_id.slice())) return true;
        }
        return false;
    }

    fn clearIndexes(self: *RequestBook, key: types.RequestKey, active: *const ActiveRequest) void {
        if (challengeForPhase(key.endpoint.addr, active.phase)) |index| _ = self.challenge_by_nonce.remove(index);
        if (self.lanes.getPtr(key.endpoint)) |lane| if (lane.establishing) |establishing| {
            if (types.RequestKeyContext.eql(.{}, establishing, key)) lane.establishing = null;
        };
        self.removeEmptyLane(key.endpoint);
    }

    fn removeEmptyLane(self: *RequestBook, endpoint: types.Endpoint) void {
        const lane = self.lanes.getPtr(endpoint) orelse return;
        if (lane.establishing != null or lane.queued.len() != 0) return;
        var removed = self.lanes.fetchRemove(endpoint).?.value;
        removed.deinit(self.alloc);
    }
};

fn challengeForPhase(address: types.Address, phase: Phase) ?types.ChallengeKey {
    return switch (phase) {
        .awaiting_whoareyou => |state| .init(address, &state.recovery.nonce),
        .awaiting_response => |response| if (response.wait.canChallenge()) .init(address, &response.recovery.nonce) else null,
    };
}
