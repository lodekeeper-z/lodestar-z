const std = @import("std");
const actor_mod = @import("actor.zig");
const admission_mod = @import("admission.zig");
const config_mod = @import("config.zig");
const enr = @import("enr.zig");
const events = @import("events.zig");
const lookup_results = @import("lookup_results.zig");
const message = @import("protocol/message.zig");
const metrics = @import("metrics.zig");
const packet = @import("protocol/packet.zig");
const request_results = @import("request_results.zig");
const transport_mod = @import("transport.zig");
const types = @import("types.zig");
const util = @import("util.zig");

const Allocator = std.mem.Allocator;
const Io = std.Io;
const MAX_RECEIVE_ERROR_BACKOFF_MS: u64 = 100;
const runtime_error = @import("runtime_error.zig");
const InitError = runtime_error.InitError;
const RunError = runtime_error.RunError;
const EventError = runtime_error.EventError;
const CommandError = runtime_error.CommandError;
const EnrAdmissionError = runtime_error.EnrAdmissionError;
const SetLocalEnrError = runtime_error.SetLocalEnrError;
const RequestError = runtime_error.RequestError;
const FindNodeError = runtime_error.FindNodeError;
const TalkRequestError = runtime_error.TalkRequestError;
const TalkResponseError = runtime_error.TalkResponseError;
const LookupError = runtime_error.LookupError;
pub const Error = runtime_error.Error;
pub const LookupResult = lookup_results.LookupResult;
pub const LookupTerminalReason = lookup_results.LookupTerminalReason;
pub const RequestResult = request_results.RequestResult;
pub const RequestTerminal = request_results.RequestTerminal;

const Lifecycle = enum(u8) {
    ready,
    running,
    stopping,
    terminalizing,
    stopped,
};

const RuntimeImpl = struct {
    io: Io,
    allocator: Allocator,
    transport: transport_mod.Transport,
    admission: admission_mod.IngressAdmission,
    outbox: events.EventOutbox,
    lookup_result_outbox: lookup_results.LookupResultOutbox,
    request_result_outbox: request_results.RequestResultOutbox,
    actor: actor_mod.Actor,
    options: config_mod.Options,
    command_queue: Io.Queue(Command),
    command_buffer: []Command,
    group: Io.Group = .init,
    lifecycle: std.atomic.Value(Lifecycle) = .init(.ready),
    terminalized: std.atomic.Value(bool) = .init(false),
    maintenance_due: std.atomic.Value(bool) = .init(false),
    test_command_gate: if (@import("builtin").is_test) ?*Testing.CommandGate else void = if (@import("builtin").is_test) null else {},
    test_cancellation_gate: if (@import("builtin").is_test) ?*Testing.CancellationGate else void = if (@import("builtin").is_test) null else {},

    const EnrAdmissionResult = EnrAdmissionError!bool;
    const SetLocalEnrResult = SetLocalEnrError!void;
    const PingResult = RequestError!message.ReqId;
    const FindNodeResult = FindNodeError!message.ReqId;
    const TalkRequestResult = TalkRequestError!message.ReqId;
    const TalkResponseResult = TalkResponseError!void;
    const LookupStartResult = LookupError!u32;
    const CommandBoolResult = CommandError!bool;
    const MetricsResult = CommandError!metrics.MetricsSnapshot;
    const EnrResult = CommandError!?enr.RawEnr;
    const U64Result = CommandError!u64;
    const EnrAdmissionReply = Io.Queue(EnrAdmissionResult);
    const SetLocalEnrReply = Io.Queue(SetLocalEnrResult);
    const PingReply = Io.Queue(PingResult);
    const FindNodeReply = Io.Queue(FindNodeResult);
    const TalkRequestReply = Io.Queue(TalkRequestResult);
    const TalkResponseReply = Io.Queue(TalkResponseResult);
    const LookupReply = Io.Queue(LookupStartResult);
    const CommandBoolReply = Io.Queue(CommandBoolResult);
    const MetricsReply = Io.Queue(MetricsResult);
    const EnrReply = Io.Queue(EnrResult);
    const U64Reply = Io.Queue(U64Result);

    const Inbound = struct {
        from: types.Address,
        bytes: types.PacketBytes,
        expected: ?admission_mod.ExpectedCredit = null,
    };

    const AddNode = struct {
        node_id: types.NodeId,
        pubkey: ?[33]u8,
        address: types.Address,
        enr: ?[]u8,
        reply: *EnrAdmissionReply,
    };

    const SendPing = struct {
        endpoint: types.Endpoint,
        pubkey: [33]u8,
        enr_seq: u64,
        origin: types.RequestOrigin,
        reply: *PingReply,
    };

    const SendFindNode = struct {
        endpoint: types.Endpoint,
        pubkey: [33]u8,
        distances: [127]u16,
        distances_len: u8,
        origin: types.RequestOrigin,
        reply: *FindNodeReply,
    };

    const SendTalkRequest = struct {
        endpoint: types.Endpoint,
        pubkey: [33]u8,
        protocol_name: []u8,
        request: []u8,
        origin: types.RequestOrigin,
        reply: *TalkRequestReply,
    };

    const Command = union(enum) {
        inbound: Inbound,
        maintenance,
        add_node: AddNode,
        add_enr: struct { enr: []u8, reply: *EnrAdmissionReply },
        set_local_enr: struct { enr: []u8, reply: *SetLocalEnrReply },
        send_ping: SendPing,
        send_findnode: SendFindNode,
        send_talk_request: SendTalkRequest,
        send_talk_response: struct {
            endpoint: types.Endpoint,
            req_id: message.ReqId,
            response: []u8,
            reply: *TalkResponseReply,
        },
        cancel_request: struct { key: types.RequestKey, reply: *CommandBoolReply },
        start_lookup: struct { target: types.NodeId, reply: *LookupReply },
        start_random_lookup: *LookupReply,
        metrics_snapshot: *MetricsReply,
        local_enr: *EnrReply,
        peer_enr: struct { node_id: types.NodeId, reply: *EnrReply },
        local_enr_seq: *U64Reply,
    };

    fn init(io: Io, allocator: Allocator, config: config_mod.Config, options: config_mod.Options) InitError!RuntimeImpl {
        return initRaw(io, allocator, config, options) catch |err| switch (err) {
            error.BindFailed => error.BindFailed,
            error.Canceled => error.Canceled,
            error.InvalidBindAddressFamily => error.InvalidBindAddressFamily,
            error.InvalidCapacity => error.InvalidCapacity,
            error.InvalidEnr => error.InvalidEnr,
            error.InvalidLocalIdentity => error.InvalidLocalIdentity,
            error.InvalidLookupNumResults => error.InvalidLookupNumResults,
            error.InvalidLookupParallelism => error.InvalidLookupParallelism,
            error.InvalidLookupRequestLimit => error.InvalidLookupRequestLimit,
            error.InvalidMaintenanceInterval => error.InvalidMaintenanceInterval,
            error.InvalidRateLimiterCapacity => error.InvalidRateLimiterCapacity,
            error.InvalidRateLimiterQuota => error.InvalidRateLimiterQuota,
            error.InvalidRequestRetries => error.InvalidRequestRetries,
            error.InvalidSessionCapacity => error.InvalidSessionCapacity,
            error.InvalidVoteThreshold => error.InvalidVoteThreshold,
            error.NoBindAddresses => error.NoBindAddresses,
            error.OutOfMemory => error.OutOfMemory,
            error.AdmissionCapacityOverflow,
            error.BufferTooSmall,
            error.CapacityTooLarge,
            error.InvalidAdmissionCapacity,
            error.InvalidContactCapacity,
            error.InvalidEventCapacity,
            error.InvalidLookupResultCapacity,
            error.InvalidPublicKey,
            error.InvalidRequestCapacity,
            error.InvalidRequestResultCapacity,
            error.InvalidSignature,
            error.UnsupportedScheme,
            error.ZeroCapacity,
            => unreachable,
        };
    }

    fn initRaw(io: Io, allocator: Allocator, config: config_mod.Config, options: config_mod.Options) !RuntimeImpl {
        try config.validate();
        try options.validate();
        var transport = try transport_mod.Transport.init(io, config.bind_addresses);
        errdefer transport.deinit();
        var admission = try admission_mod.IngressAdmission.init(allocator, config.rate_limiter, try admission_mod.permitCapacity(config.limits));
        errdefer admission.deinit();
        var outbox = try events.EventOutbox.init(io, allocator, config.limits.event_capacity);
        errdefer outbox.deinit();
        var lookup_result_outbox = try lookup_results.LookupResultOutbox.init(io, allocator, config.limits.lookup_result_capacity);
        errdefer lookup_result_outbox.deinit();
        var request_result_outbox = try request_results.RequestResultOutbox.init(io, allocator, config.limits.request_result_capacity);
        errdefer request_result_outbox.deinit();
        var actor = try actor_mod.Actor.init(allocator, config);
        errdefer actor.deinit(&admission);
        const commands = try allocator.alloc(Command, config.limits.command_capacity);
        return .{
            .io = io,
            .allocator = allocator,
            .transport = transport,
            .admission = admission,
            .outbox = outbox,
            .lookup_result_outbox = lookup_result_outbox,
            .request_result_outbox = request_result_outbox,
            .actor = actor,
            .options = options,
            .command_queue = .init(commands),
            .command_buffer = commands,
        };
    }

    fn deinit(self: *RuntimeImpl) void {
        self.stop();
        std.debug.assert(self.lifecycle.load(.acquire) == .stopped);
        self.outbox.deinit();
        self.lookup_result_outbox.deinit();
        self.request_result_outbox.deinit();
        self.actor.deinit(&self.admission);
        self.admission.deinit();
        self.transport.deinit();
        self.allocator.free(self.command_buffer);
    }

    /// Run the single domain actor on the caller task. The caller schedules
    /// this method in its own group, calls stop, awaits that group, then deinit.
    fn run(self: *RuntimeImpl) (error{ AlreadyRunning, RuntimeStopped } || Io.ConcurrentError || Io.Cancelable)!void {
        if (self.lifecycle.cmpxchgStrong(.ready, .running, .acq_rel, .acquire)) |actual| return switch (actual) {
            .ready => unreachable,
            .running => error.AlreadyRunning,
            .stopping, .terminalizing, .stopped => error.RuntimeStopped,
        };
        defer self.shutdown();
        if (self.transport.ip4 != null) try self.group.concurrent(self.io, receiveLoop, .{ self, types.Address.Family.ip4 });
        if (self.transport.ip6 != null) try self.group.concurrent(self.io, receiveLoop, .{ self, types.Address.Family.ip6 });
        try self.group.concurrent(self.io, maintenanceLoop, .{self});
        self.actorLoop() catch |err| switch (err) {
            error.Canceled => return error.Canceled,
        };
    }

    fn stop(self: *RuntimeImpl) void {
        while (true) switch (self.lifecycle.load(.acquire)) {
            .ready => if (self.lifecycle.cmpxchgWeak(.ready, .terminalizing, .acq_rel, .acquire) == null) {
                self.command_queue.close(self.io);
                self.terminalize();
                self.lifecycle.store(.stopped, .release);
                return;
            },
            .running => if (self.lifecycle.cmpxchgWeak(.running, .stopping, .acq_rel, .acquire) == null) {
                self.command_queue.close(self.io);
                return;
            },
            .stopping, .terminalizing, .stopped => {
                self.command_queue.close(self.io);
                return;
            },
        };
    }

    fn shutdown(self: *RuntimeImpl) void {
        self.command_queue.close(self.io);
        // Commands carry caller-stack reply queues and, in some cases, owned
        // allocations. Intake closure bounds this drain by command capacity;
        // execute accepted commands so neither replies nor ownership dangle.
        self.drainAcceptedCommands();
        self.group.cancel(self.io);
        self.terminalize();
        self.lifecycle.store(.stopped, .release);
    }

    fn terminalize(self: *RuntimeImpl) void {
        if (self.terminalized.swap(true, .acq_rel)) return;
        const env = self.actorEnv();
        self.actor.finishAllReliableRequests(env);
        self.actor.finishAllLookups(env, .runtime_stopped);
        self.request_result_outbox.close();
        self.lookup_result_outbox.close();
        self.outbox.close();
    }

    fn isRunning(self: *const RuntimeImpl) bool {
        return switch (self.lifecycle.load(.acquire)) {
            .running, .stopping => true,
            .ready, .terminalizing, .stopped => false,
        };
    }

    fn isClosed(self: *const RuntimeImpl) bool {
        return self.lifecycle.load(.acquire) == .stopped;
    }

    fn boundAddress(self: *const RuntimeImpl, family: types.Address.Family) ?types.Address {
        return self.transport.boundAddress(family);
    }

    fn nextEvent(self: *RuntimeImpl) (Io.QueueClosedError || Io.Cancelable)!events.Event {
        return self.outbox.next();
    }

    fn popEvent(self: *RuntimeImpl) ?events.Event {
        return self.outbox.pop();
    }

    fn nextLookupResult(self: *RuntimeImpl) (Io.QueueClosedError || Io.Cancelable)!lookup_results.LookupResult {
        return self.lookup_result_outbox.next();
    }

    fn popLookupResult(self: *RuntimeImpl) ?lookup_results.LookupResult {
        return self.lookup_result_outbox.pop();
    }

    fn nextRequestResult(self: *RuntimeImpl) (Io.QueueClosedError || Io.Cancelable)!request_results.RequestResult {
        return self.request_result_outbox.next();
    }

    fn popRequestResult(self: *RuntimeImpl) ?request_results.RequestResult {
        return self.request_result_outbox.pop();
    }

    fn ensureRunning(self: *RuntimeImpl) !void {
        switch (self.lifecycle.load(.acquire)) {
            .ready => return error.RuntimeNotRunning,
            .running => {},
            .stopping, .terminalizing, .stopped => return error.RuntimeStopped,
        }
    }

    pub fn enqueueCommand(self: *RuntimeImpl, command: Command) !void {
        const accepted = try self.command_queue.put(self.io, &.{command}, 0);
        if (accepted == 0) return error.CommandQueueFull;
        std.debug.assert(accepted == 1);
    }

    pub fn actorLoop(self: *RuntimeImpl) Io.Cancelable!void {
        while (true) {
            const command = self.command_queue.getOne(self.io) catch |err| switch (err) {
                error.Closed => return,
                error.Canceled => return error.Canceled,
            };
            try self.handleCommand(command);
        }
    }

    pub fn closeCommandsAndDrainForTesting(self: *RuntimeImpl) void {
        std.debug.assert(@import("builtin").is_test);
        self.command_queue.close(self.io);
        self.drainAcceptedCommands();
    }

    fn drainAcceptedCommands(self: *RuntimeImpl) void {
        const previous_protection = self.io.swapCancelProtection(.blocked);
        defer _ = self.io.swapCancelProtection(previous_protection);
        while (true) {
            const command = self.command_queue.getOneUncancelable(self.io) catch |err| switch (err) {
                error.Closed => return,
            };
            switch (command) {
                .inbound => |value| if (value.expected) |credit_value| {
                    var credit = credit_value;
                    credit.rollback(&self.admission);
                },
                else => self.handleCommand(command) catch |err| switch (err) {
                    error.Canceled => {},
                },
            }
        }
    }

    /// Bind the actor execution context from heap-pinned runtime state.
    /// `Runtime.init` allocates RuntimeImpl on the heap, so these interior
    /// pointers are stable for the lifetime of the dispatch.
    fn actorEnv(self: *RuntimeImpl) actor_mod.Env {
        return .{
            .io = self.io,
            .sender = self.transport.sender(),
            .ingress = &self.admission,
            .outbox = &self.outbox,
            .lookup_results = &self.lookup_result_outbox,
            .request_results = &self.request_result_outbox,
        };
    }

    fn handleCommand(self: *RuntimeImpl, command: Command) Io.Cancelable!void {
        var expected = switch (command) {
            .inbound => |value| value.expected,
            else => null,
        };
        defer if (expected) |*credit| credit.rollback(&self.admission);
        if (@import("builtin").is_test) if (self.test_command_gate) |gate| {
            gate.entered.store(true, .release);
            while (!gate.proceed.load(.acquire)) std.atomic.spinLoopHint();
        };
        if (@import("builtin").is_test) if (self.test_cancellation_gate) |gate| {
            self.test_cancellation_gate = null;
            gate.entered.store(true, .release);
            _ = gate.queue.getOne(self.io) catch |err| switch (err) {
                error.Canceled => {
                    gate.cancellation_observed.store(true, .release);
                    return error.Canceled;
                },
                error.Closed => unreachable,
            };
        };
        var env = self.actorEnv();
        env.expected_credit = if (expected) |*credit| credit else null;
        switch (command) {
            .inbound => |value| {
                var bytes = value.bytes;
                self.actor.handlePacket(env, bytes.bytes[0..bytes.len], value.from);
                self.admission.noteProcessed();
            },
            .maintenance => {
                if (self.maintenance_due.swap(false, .acq_rel)) self.actor.maintenance(env);
            },
            .add_node => |value| {
                defer if (value.enr) |bytes| self.allocator.free(bytes);
                var pubkey = value.pubkey;
                const result = self.actor.addNode(value.node_id, if (pubkey) |*key| key else null, value.address, value.enr, util.nowNs(self.io));
                value.reply.putOneUncancelable(self.io, result) catch {};
            },
            .add_enr => |value| {
                defer self.allocator.free(value.enr);
                value.reply.putOneUncancelable(self.io, self.actor.addEnr(&self.outbox, value.enr, util.nowNs(self.io))) catch {};
            },
            .set_local_enr => |value| {
                defer self.allocator.free(value.enr);
                try replyResult(self.io, value.reply, setLocalEnrResult(&self.actor, env, value.enr));
            },
            .send_ping => |value| try self.handleSendPing(env, value),
            .send_findnode => |value| try self.handleSendFindNode(env, value),
            .send_talk_request => |value| {
                defer self.allocator.free(value.protocol_name);
                defer self.allocator.free(value.request);
                try self.handleSendTalkRequest(env, value);
            },
            .send_talk_response => |value| {
                defer self.allocator.free(value.response);
                try replyResult(self.io, value.reply, sendTalkResponseResult(&self.actor, env, value.endpoint, value.req_id, value.response));
            },
            .cancel_request => |value| value.reply.putOneUncancelable(
                self.io,
                self.actor.cancelRequest(env, value.key),
            ) catch {},
            .start_lookup => |value| try self.handleStartLookup(env, value.target, value.reply),
            .start_random_lookup => |reply| {
                var target: types.NodeId = undefined;
                self.io.random(&target);
                try self.handleStartLookup(env, target, reply);
            },
            .metrics_snapshot => |reply| {
                var snapshot = self.actor.metricsSnapshot();
                const admission = self.admission.snapshot();
                snapshot.rate_limit_hit_ip = admission.rate_limit_hit_ip_total;
                snapshot.rate_limit_hit_total = admission.rate_limit_hit_total;
                snapshot.received_packet_count = admission.received_total;
                snapshot.filtered_packet_count = admission.filtered_total;
                snapshot.processed_packet_count = admission.processed_total;
                snapshot.dropped_event_count = self.outbox.droppedCount();
                snapshot.dropped_event_count_by_kind = self.outbox.droppedEventCounts();
                reply.putOneUncancelable(self.io, snapshot) catch {};
            },
            .local_enr => |reply| reply.putOneUncancelable(self.io, self.actor.localEnr()) catch {},
            .peer_enr => |value| value.reply.putOneUncancelable(self.io, self.actor.peerEnr(&value.node_id)) catch {},
            .local_enr_seq => |reply| reply.putOneUncancelable(self.io, self.actor.localEnrSeq()) catch {},
        }
    }

    fn handleSendPing(self: *RuntimeImpl, env: actor_mod.Env, value: SendPing) Io.Cancelable!void {
        const reliable = value.origin == .reliable_api;
        if (reliable and !self.request_result_outbox.claim()) unreachable;
        const result = sendPingResult(&self.actor, env, value.endpoint, &value.pubkey, value.enr_seq, value.origin);
        if (result) |_| {} else |_| if (reliable) self.request_result_outbox.release();
        try replyResult(self.io, value.reply, result);
    }

    fn handleSendFindNode(self: *RuntimeImpl, env: actor_mod.Env, value: SendFindNode) Io.Cancelable!void {
        const reliable = value.origin == .reliable_api;
        if (reliable and !self.request_result_outbox.claim()) unreachable;
        const result = sendFindNodeResult(&self.actor, env, value.endpoint, &value.pubkey, value.distances[0..value.distances_len], value.origin);
        if (result) |_| {} else |_| if (reliable) self.request_result_outbox.release();
        try replyResult(self.io, value.reply, result);
    }

    fn handleSendTalkRequest(self: *RuntimeImpl, env: actor_mod.Env, value: SendTalkRequest) Io.Cancelable!void {
        const reliable = value.origin == .reliable_api;
        if (reliable and !self.request_result_outbox.claim()) unreachable;
        const result = sendTalkRequestResult(
            &self.actor,
            env,
            value.endpoint,
            &value.pubkey,
            value.protocol_name,
            value.request,
            value.origin,
        );
        if (result) |_| {} else |_| if (reliable) self.request_result_outbox.release();
        try replyResult(self.io, value.reply, result);
    }

    fn handleStartLookup(self: *RuntimeImpl, env: actor_mod.Env, target: types.NodeId, reply: *LookupReply) Io.Cancelable!void {
        const result = startLookupResult(&self.actor, env, target);
        if (result) |_| {} else |_| self.lookup_result_outbox.release();
        try replyResult(self.io, reply, result);
    }

    fn enqueueInbound(
        self: *RuntimeImpl,
        from: types.Address,
        raw: []const u8,
        expected_value: ?admission_mod.ExpectedCredit,
    ) !void {
        var expected = expected_value;
        defer if (expected) |*credit| credit.rollback(&self.admission);
        const bytes = try types.PacketBytes.init(raw);
        var inbound = Inbound{
            .from = from,
            .bytes = bytes,
            .expected = if (expected) |*credit| credit.move() else null,
        };
        self.enqueueCommand(.{ .inbound = inbound }) catch |err| {
            if (inbound.expected) |*credit| credit.rollback(&self.admission);
            return err;
        };
    }

    pub fn enqueueInboundForTesting(
        self: *RuntimeImpl,
        from: types.Address,
        raw: []const u8,
        expected: ?admission_mod.ExpectedCredit,
    ) !void {
        std.debug.assert(@import("builtin").is_test);
        return self.enqueueInbound(from, raw, expected);
    }

    pub fn handleInboundForTesting(
        self: *RuntimeImpl,
        from: types.Address,
        raw: []const u8,
        expected_value: ?admission_mod.ExpectedCredit,
    ) !void {
        std.debug.assert(@import("builtin").is_test);
        var expected = expected_value;
        defer if (expected) |*credit| credit.rollback(&self.admission);
        const bytes = try types.PacketBytes.init(raw);
        return self.handleCommand(.{ .inbound = .{
            .from = from,
            .bytes = bytes,
            .expected = if (expected) |*credit| credit.move() else null,
        } });
    }

    fn receiveLoop(self: *RuntimeImpl, family: types.Address.Family) Io.Cancelable!void {
        if (self.transport.socket(family) == null) return;
        var buffer: [packet.MAX_PACKET_SIZE]u8 = undefined;
        var consecutive_errors: u8 = 0;
        while (self.lifecycle.load(.acquire) == .running) {
            const received = self.transport.receiveInto(family, &buffer) catch |err| switch (err) {
                error.Canceled => return error.Canceled,
                error.MessageOversize => {
                    self.admission.noteTruncated();
                    consecutive_errors = 0;
                    continue;
                },
                error.NoSocketForAddressFamily => return,
                else => {
                    consecutive_errors +|= 1;
                    try Io.sleep(self.io, .fromMilliseconds(@intCast(receiveErrorBackoffMs(consecutive_errors))), .awake);
                    continue;
                },
            };
            consecutive_errors = 0;
            const expected: ?admission_mod.ExpectedCredit = switch (self.admission.admit(received.from, util.nowMs(self.io))) {
                .filtered => continue,
                .ordinary => null,
                .expected => |credit| credit,
            };
            self.enqueueInbound(received.from, received.data, expected) catch |err| switch (err) {
                error.PacketTooLarge, error.CommandQueueFull => continue,
                error.Closed => return,
                error.Canceled => return error.Canceled,
            };
        }
    }

    fn maintenanceLoop(self: *RuntimeImpl) Io.Cancelable!void {
        const interval = @max(self.options.maintenance_interval_ms, 1);
        while (self.lifecycle.load(.acquire) == .running) {
            try Io.sleep(self.io, .fromMilliseconds(@intCast(interval)), .awake);
            self.requestMaintenanceWake() catch |err| switch (err) {
                error.CommandQueueFull => continue,
                error.Closed => return,
                error.Canceled => return error.Canceled,
            };
        }
    }

    pub fn requestMaintenanceWake(self: *RuntimeImpl) !void {
        if (self.maintenance_due.cmpxchgStrong(false, true, .acq_rel, .acquire) != null) return;
        self.enqueueCommand(.maintenance) catch |err| {
            self.maintenance_due.store(false, .release);
            return err;
        };
    }
};

fn setLocalEnrResult(actor: *actor_mod.Actor, env: actor_mod.Env, raw: []const u8) SetLocalEnrError!void {
    return actor.setLocalEnr(env, raw) catch |err| switch (err) {
        error.InvalidEnr => error.InvalidEnr,
        error.InvalidPublicKey => error.InvalidPublicKey,
        error.InvalidSignature => error.InvalidSignature,
        error.OutOfMemory => error.OutOfMemory,
        error.StaleEnrSeq => error.StaleEnrSeq,
        error.UnsupportedScheme => error.UnsupportedScheme,
        error.WrongNodeId => error.WrongNodeId,
        // `enr.decode` declares the encoder-only BufferTooSmall member, but
        // decoding a prechecked, at-most-MAX_ENR_SIZE record never writes to a
        // caller-sized buffer.
        error.BufferTooSmall => unreachable,
    };
}

fn sendPingResult(actor: *actor_mod.Actor, env: actor_mod.Env, endpoint: types.Endpoint, pubkey: *const [33]u8, enr_seq: u64, origin: types.RequestOrigin) RequestError!message.ReqId {
    return actor.sendPing(env, endpoint, pubkey, enr_seq, origin) catch |err| switch (err) {
        error.Canceled => error.Canceled,
        error.DuplicateChallenge => error.DuplicateChallenge,
        error.DuplicateRequest => error.DuplicateRequest,
        error.NoSocketForAddressFamily => error.NoSocketForAddressFamily,
        error.OutOfMemory => error.OutOfMemory,
        error.PermitGenerationExhausted => error.PermitGenerationExhausted,
        error.TooManyActiveRequests => error.TooManyActiveRequests,
        error.TooManyQueuedRequests => error.TooManyQueuedRequests,
        error.TooManyQueuedRequestsForEndpoint => error.TooManyQueuedRequestsForEndpoint,
        error.TransportSendFailed => error.TransportSendFailed,
        error.AdmissionBudgetOverflow,
        error.BufferTooSmall,
        error.DecryptionFailed,
        error.EndpointBusy,
        error.EndpointEstablishing,
        error.InvalidEncoding,
        error.InvalidFlag,
        error.InvalidMessage,
        error.InvalidPacket,
        error.InvalidPacketBudget,
        error.InvalidProtocolId,
        error.MessageOversize,
        error.Overflow,
        error.PacketTooLarge,
        error.TooManyAdmissionPermits,
        error.TooManyDistances,
        error.UnexpectedType,
        error.UnsupportedVersion,
        => unreachable,
    };
}

fn sendFindNodeResult(actor: *actor_mod.Actor, env: actor_mod.Env, endpoint: types.Endpoint, pubkey: *const [33]u8, distances: []const u16, origin: types.RequestOrigin) FindNodeError!message.ReqId {
    return actor.sendFindNode(env, endpoint, pubkey, distances, origin) catch |err| switch (err) {
        error.Canceled => error.Canceled,
        error.DuplicateChallenge => error.DuplicateChallenge,
        error.DuplicateRequest => error.DuplicateRequest,
        error.InvalidDistance => error.InvalidDistance,
        error.NoSocketForAddressFamily => error.NoSocketForAddressFamily,
        error.OutOfMemory => error.OutOfMemory,
        error.PermitGenerationExhausted => error.PermitGenerationExhausted,
        error.TooManyActiveRequests => error.TooManyActiveRequests,
        error.TooManyDistances => error.TooManyDistances,
        error.TooManyQueuedRequests => error.TooManyQueuedRequests,
        error.TooManyQueuedRequestsForEndpoint => error.TooManyQueuedRequestsForEndpoint,
        error.TransportSendFailed => error.TransportSendFailed,
        error.AdmissionBudgetOverflow,
        error.BufferTooSmall,
        error.DecryptionFailed,
        error.EndpointBusy,
        error.EndpointEstablishing,
        error.InvalidEncoding,
        error.InvalidFlag,
        error.InvalidMessage,
        error.InvalidPacket,
        error.InvalidPacketBudget,
        error.InvalidProtocolId,
        error.MessageOversize,
        error.Overflow,
        error.PacketTooLarge,
        error.TooManyAdmissionPermits,
        error.UnexpectedType,
        error.UnsupportedVersion,
        => unreachable,
    };
}

fn sendTalkRequestResult(actor: *actor_mod.Actor, env: actor_mod.Env, endpoint: types.Endpoint, pubkey: *const [33]u8, protocol_name: []const u8, request: []const u8, origin: types.RequestOrigin) TalkRequestError!message.ReqId {
    return actor.sendTalkRequestWithOrigin(env, endpoint, pubkey, protocol_name, request, origin) catch |err| switch (err) {
        // Keep encoder exhaustion normalized in case message layout drifts
        // beyond its packet-sized scratch buffer before the packet preflight.
        error.BufferTooSmall => error.MessageTooLarge,
        error.Canceled => error.Canceled,
        error.DuplicateChallenge => error.DuplicateChallenge,
        error.DuplicateRequest => error.DuplicateRequest,
        error.MessageTooLarge => error.MessageTooLarge,
        error.NoSocketForAddressFamily => error.NoSocketForAddressFamily,
        error.OutOfMemory => error.OutOfMemory,
        error.PermitGenerationExhausted => error.PermitGenerationExhausted,
        error.TooManyActiveRequests => error.TooManyActiveRequests,
        error.TooManyQueuedRequests => error.TooManyQueuedRequests,
        error.TooManyQueuedRequestsForEndpoint => error.TooManyQueuedRequestsForEndpoint,
        error.TransportSendFailed => error.TransportSendFailed,
        error.AdmissionBudgetOverflow,
        error.DecryptionFailed,
        error.EndpointBusy,
        error.EndpointEstablishing,
        error.InvalidEncoding,
        error.InvalidFlag,
        error.InvalidMessage,
        error.InvalidPacket,
        error.InvalidPacketBudget,
        error.InvalidProtocolId,
        error.MessageOversize,
        error.Overflow,
        error.PacketTooLarge,
        error.TooManyAdmissionPermits,
        error.TooManyDistances,
        error.UnexpectedType,
        error.UnsupportedVersion,
        => unreachable,
    };
}

fn sendTalkResponseResult(actor: *actor_mod.Actor, env: actor_mod.Env, endpoint: types.Endpoint, req_id: message.ReqId, response: []const u8) TalkResponseError!void {
    return actor.sendTalkResponse(env, endpoint, req_id, response) catch |err| switch (err) {
        // Keep encoder exhaustion normalized in case message layout drifts
        // beyond its packet-sized scratch buffer before the packet preflight.
        error.BufferTooSmall => error.MessageTooLarge,
        error.Canceled => error.Canceled,
        error.EndpointMismatch => error.EndpointMismatch,
        error.MessageTooLarge => error.MessageTooLarge,
        error.NoSession => error.NoSession,
        error.NoSocketForAddressFamily => error.NoSocketForAddressFamily,
        error.NonceGenerationExhausted => error.NonceGenerationExhausted,
        error.OutOfMemory => error.OutOfMemory,
        error.PermitGenerationExhausted => error.PermitGenerationExhausted,
        error.TransportSendFailed => error.TransportSendFailed,
        error.UnknownPeer => error.UnknownPeer,
        error.AdmissionBudgetOverflow,
        error.DecryptionFailed,
        error.InvalidEncoding,
        error.InvalidFlag,
        error.InvalidMessage,
        error.InvalidPacket,
        error.InvalidPacketBudget,
        error.InvalidProtocolId,
        error.MessageOversize,
        error.Overflow,
        error.PacketTooLarge,
        error.TooManyAdmissionPermits,
        error.UnexpectedType,
        error.UnsupportedVersion,
        => unreachable,
    };
}

fn startLookupResult(actor: *actor_mod.Actor, env: actor_mod.Env, target: types.NodeId) LookupError!u32 {
    return actor.startLookup(env, target) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.TooManyLookups => error.TooManyLookups,
        error.LookupResultPlaneUnavailable,
        error.LookupResultReservationMissing,
        error.InvalidNumResults,
        error.InvalidParallelism,
        error.TooManySeeds,
        => unreachable,
    };
}

fn replyResult(io: std.Io, reply: anytype, result: anytype) std.Io.Cancelable!void {
    reply.putOneUncancelable(io, result) catch {};
    if (result) |_| {} else |err| if (err == error.Canceled) return error.Canceled;
}

pub const Runtime = opaque {
    pub const InitError = runtime_error.InitError;
    pub const RunError = runtime_error.RunError;
    pub const EventError = runtime_error.EventError;
    pub const LookupResultError = runtime_error.LookupResultError;
    pub const RequestResultError = runtime_error.RequestResultError;
    pub const CommandError = runtime_error.CommandError;
    pub const EnrAdmissionError = runtime_error.EnrAdmissionError;
    pub const SetLocalEnrError = runtime_error.SetLocalEnrError;
    pub const RequestError = runtime_error.RequestError;
    pub const FindNodeError = runtime_error.FindNodeError;
    pub const TalkRequestError = runtime_error.TalkRequestError;
    pub const TalkResponseError = runtime_error.TalkResponseError;
    pub const LookupError = runtime_error.LookupError;
    pub const LookupResult = lookup_results.LookupResult;
    pub const LookupTerminalReason = lookup_results.LookupTerminalReason;
    pub const RequestResult = request_results.RequestResult;
    pub const RequestTerminal = request_results.RequestTerminal;
    pub const Error = runtime_error.Error;

    pub fn init(io: Io, allocator: Allocator, config: config_mod.Config, options: config_mod.Options) runtime_error.InitError!*Runtime {
        const storage = try allocator.create(RuntimeImpl);
        errdefer allocator.destroy(storage);
        storage.* = try RuntimeImpl.init(io, allocator, config, options);
        return @ptrCast(storage);
    }

    pub fn deinit(self: *Runtime) void {
        const storage = impl(self);
        const allocator = storage.allocator;
        storage.deinit();
        allocator.destroy(storage);
    }

    pub fn run(self: *Runtime) runtime_error.RunError!void {
        return impl(self).run();
    }

    pub fn stop(self: *Runtime) void {
        impl(self).stop();
    }

    pub fn isRunning(self: *const Runtime) bool {
        return implConst(self).isRunning();
    }

    pub fn isClosed(self: *const Runtime) bool {
        return implConst(self).isClosed();
    }

    pub fn boundAddress(self: *const Runtime, family: types.Address.Family) ?types.Address {
        return implConst(self).boundAddress(family);
    }

    pub fn nextEvent(self: *Runtime) runtime_error.EventError!events.Event {
        return impl(self).nextEvent();
    }

    pub fn popEvent(self: *Runtime) ?events.Event {
        return impl(self).popEvent();
    }

    pub fn nextLookupResult(self: *Runtime) runtime_error.LookupResultError!lookup_results.LookupResult {
        return impl(self).nextLookupResult();
    }

    pub fn popLookupResult(self: *Runtime) ?lookup_results.LookupResult {
        return impl(self).popLookupResult();
    }

    pub fn nextRequestResult(self: *Runtime) runtime_error.RequestResultError!request_results.RequestResult {
        return impl(self).nextRequestResult();
    }

    pub fn popRequestResult(self: *Runtime) ?request_results.RequestResult {
        return impl(self).popRequestResult();
    }

    pub fn addNode(self: *Runtime, node_id: types.NodeId, pubkey: ?*const [33]u8, address: types.Address, enr_bytes: ?[]const u8) runtime_error.EnrAdmissionError!bool {
        const storage = impl(self);
        try storage.ensureRunning();
        if (enr_bytes) |bytes| if (bytes.len > @import("enr.zig").MAX_ENR_SIZE) return error.InvalidEnr;
        var owned: ?[]u8 = if (enr_bytes) |bytes| try storage.allocator.dupe(u8, bytes) else null;
        errdefer if (owned) |bytes| storage.allocator.free(bytes);
        var buffer: [1]RuntimeImpl.EnrAdmissionResult = undefined;
        var reply = RuntimeImpl.EnrAdmissionReply.init(&buffer);
        try storage.enqueueCommand(.{ .add_node = .{
            .node_id = node_id,
            .pubkey = if (pubkey) |key| key.* else null,
            .address = address,
            .enr = owned,
            .reply = &reply,
        } });
        owned = null;
        return try reply.getOneUncancelable(storage.io);
    }

    pub fn addEnr(self: *Runtime, enr_bytes: []const u8) runtime_error.EnrAdmissionError!bool {
        const storage = impl(self);
        try storage.ensureRunning();
        if (enr_bytes.len > @import("enr.zig").MAX_ENR_SIZE) return error.InvalidEnr;
        var owned: ?[]u8 = try storage.allocator.dupe(u8, enr_bytes);
        errdefer if (owned) |bytes| storage.allocator.free(bytes);
        var buffer: [1]RuntimeImpl.EnrAdmissionResult = undefined;
        var reply = RuntimeImpl.EnrAdmissionReply.init(&buffer);
        try storage.enqueueCommand(.{ .add_enr = .{ .enr = owned.?, .reply = &reply } });
        owned = null;
        return try reply.getOneUncancelable(storage.io);
    }

    pub fn setLocalEnr(self: *Runtime, enr_bytes: []const u8) runtime_error.SetLocalEnrError!void {
        const storage = impl(self);
        try storage.ensureRunning();
        if (enr_bytes.len > @import("enr.zig").MAX_ENR_SIZE) return error.InvalidEnr;
        var owned: ?[]u8 = try storage.allocator.dupe(u8, enr_bytes);
        errdefer if (owned) |bytes| storage.allocator.free(bytes);
        var buffer: [1]RuntimeImpl.SetLocalEnrResult = undefined;
        var reply = RuntimeImpl.SetLocalEnrReply.init(&buffer);
        try storage.enqueueCommand(.{ .set_local_enr = .{ .enr = owned.?, .reply = &reply } });
        owned = null;
        return try reply.getOneUncancelable(storage.io);
    }

    pub fn sendPing(self: *Runtime, node_id: types.NodeId, pubkey: *const [33]u8, address: types.Address, enr_seq: u64) runtime_error.RequestError!message.ReqId {
        const storage = impl(self);
        try storage.ensureRunning();
        if (!storage.request_result_outbox.reserve()) return error.RequestResultCapacityExceeded;
        var reservation_transferred = false;
        errdefer if (!reservation_transferred) storage.request_result_outbox.cancelUnclaimed();
        var buffer: [1]RuntimeImpl.PingResult = undefined;
        var reply = RuntimeImpl.PingReply.init(&buffer);
        try storage.enqueueCommand(.{ .send_ping = .{
            .endpoint = .{ .node_id = node_id, .addr = address },
            .pubkey = pubkey.*,
            .enr_seq = enr_seq,
            .origin = .reliable_api,
            .reply = &reply,
        } });
        reservation_transferred = true;
        return try reply.getOneUncancelable(storage.io);
    }

    pub fn sendFindNode(self: *Runtime, node_id: types.NodeId, pubkey: *const [33]u8, address: types.Address, distances: []const u16) runtime_error.FindNodeError!message.ReqId {
        const storage = impl(self);
        try storage.ensureRunning();
        if (distances.len > 127) return error.TooManyDistances;
        for (distances) |distance| {
            if (distance > 256) return error.InvalidDistance;
        }
        if (!storage.request_result_outbox.reserve()) return error.RequestResultCapacityExceeded;
        var reservation_transferred = false;
        errdefer if (!reservation_transferred) storage.request_result_outbox.cancelUnclaimed();
        var copied: [127]u16 = undefined;
        @memcpy(copied[0..distances.len], distances);
        var buffer: [1]RuntimeImpl.FindNodeResult = undefined;
        var reply = RuntimeImpl.FindNodeReply.init(&buffer);
        try storage.enqueueCommand(.{ .send_findnode = .{
            .endpoint = .{ .node_id = node_id, .addr = address },
            .pubkey = pubkey.*,
            .distances = copied,
            .distances_len = @intCast(distances.len),
            .origin = .reliable_api,
            .reply = &reply,
        } });
        reservation_transferred = true;
        return try reply.getOneUncancelable(storage.io);
    }

    pub fn sendTalkRequest(self: *Runtime, node_id: types.NodeId, pubkey: *const [33]u8, address: types.Address, protocol_name: []const u8, request: []const u8) runtime_error.TalkRequestError!message.ReqId {
        const storage = impl(self);
        try storage.ensureRunning();
        const payload_len = std.math.add(usize, protocol_name.len, request.len) catch return error.MessageTooLarge;
        if (payload_len > packet.MAX_PACKET_SIZE) return error.MessageTooLarge;
        if (!storage.request_result_outbox.reserve()) return error.RequestResultCapacityExceeded;
        var reservation_transferred = false;
        errdefer if (!reservation_transferred) storage.request_result_outbox.cancelUnclaimed();
        var protocol_copy: ?[]u8 = try storage.allocator.dupe(u8, protocol_name);
        errdefer if (protocol_copy) |bytes| storage.allocator.free(bytes);
        var request_copy: ?[]u8 = try storage.allocator.dupe(u8, request);
        errdefer if (request_copy) |bytes| storage.allocator.free(bytes);
        var buffer: [1]RuntimeImpl.TalkRequestResult = undefined;
        var reply = RuntimeImpl.TalkRequestReply.init(&buffer);
        try storage.enqueueCommand(.{ .send_talk_request = .{
            .endpoint = .{ .node_id = node_id, .addr = address },
            .pubkey = pubkey.*,
            .protocol_name = protocol_copy.?,
            .request = request_copy.?,
            .origin = .reliable_api,
            .reply = &reply,
        } });
        protocol_copy = null;
        request_copy = null;
        reservation_transferred = true;
        return try reply.getOneUncancelable(storage.io);
    }

    pub fn sendTalkResponse(self: *Runtime, node_id: types.NodeId, address: types.Address, req_id: message.ReqId, response: []const u8) runtime_error.TalkResponseError!void {
        const storage = impl(self);
        try storage.ensureRunning();
        if (response.len > packet.MAX_PACKET_SIZE) return error.MessageTooLarge;
        var owned: ?[]u8 = try storage.allocator.dupe(u8, response);
        errdefer if (owned) |bytes| storage.allocator.free(bytes);
        var buffer: [1]RuntimeImpl.TalkResponseResult = undefined;
        var reply = RuntimeImpl.TalkResponseReply.init(&buffer);
        try storage.enqueueCommand(.{ .send_talk_response = .{
            .endpoint = .{ .node_id = node_id, .addr = address },
            .req_id = req_id,
            .response = owned.?,
            .reply = &reply,
        } });
        owned = null;
        return try reply.getOneUncancelable(storage.io);
    }

    pub fn startLookup(self: *Runtime, target: types.NodeId) runtime_error.LookupError!u32 {
        const storage = impl(self);
        try storage.ensureRunning();
        if (!storage.lookup_result_outbox.reserve()) return error.LookupResultCapacityExceeded;
        var reservation_transferred = false;
        errdefer if (!reservation_transferred) storage.lookup_result_outbox.cancelUnclaimed();
        var buffer: [1]RuntimeImpl.LookupStartResult = undefined;
        var reply = RuntimeImpl.LookupReply.init(&buffer);
        try storage.enqueueCommand(.{ .start_lookup = .{ .target = target, .reply = &reply } });
        reservation_transferred = true;
        return try reply.getOneUncancelable(storage.io);
    }

    pub fn cancelRequest(self: *Runtime, node_id: types.NodeId, address: types.Address, req_id: message.ReqId) runtime_error.CommandError!bool {
        const storage = impl(self);
        try storage.ensureRunning();
        var buffer: [1]RuntimeImpl.CommandBoolResult = undefined;
        var reply = RuntimeImpl.CommandBoolReply.init(&buffer);
        try storage.enqueueCommand(.{ .cancel_request = .{
            .key = .init(.{ .node_id = node_id, .addr = address }, req_id),
            .reply = &reply,
        } });
        return try reply.getOneUncancelable(storage.io);
    }

    pub fn startRandomLookup(self: *Runtime) runtime_error.LookupError!u32 {
        const storage = impl(self);
        try storage.ensureRunning();
        if (!storage.lookup_result_outbox.reserve()) return error.LookupResultCapacityExceeded;
        var reservation_transferred = false;
        errdefer if (!reservation_transferred) storage.lookup_result_outbox.cancelUnclaimed();
        var buffer: [1]RuntimeImpl.LookupStartResult = undefined;
        var reply = RuntimeImpl.LookupReply.init(&buffer);
        try storage.enqueueCommand(.{ .start_random_lookup = &reply });
        reservation_transferred = true;
        return try reply.getOneUncancelable(storage.io);
    }

    pub fn metricsSnapshot(self: *Runtime) runtime_error.CommandError!metrics.MetricsSnapshot {
        const storage = impl(self);
        try storage.ensureRunning();
        var buffer: [1]RuntimeImpl.MetricsResult = undefined;
        var reply = RuntimeImpl.MetricsReply.init(&buffer);
        try storage.enqueueCommand(.{ .metrics_snapshot = &reply });
        return try reply.getOneUncancelable(storage.io);
    }

    pub fn localEnr(self: *Runtime) runtime_error.CommandError!?enr.RawEnr {
        const storage = impl(self);
        try storage.ensureRunning();
        var buffer: [1]RuntimeImpl.EnrResult = undefined;
        var reply = RuntimeImpl.EnrReply.init(&buffer);
        try storage.enqueueCommand(.{ .local_enr = &reply });
        return try reply.getOneUncancelable(storage.io);
    }

    pub fn peerEnr(self: *Runtime, node_id: types.NodeId) runtime_error.CommandError!?enr.RawEnr {
        const storage = impl(self);
        try storage.ensureRunning();
        var buffer: [1]RuntimeImpl.EnrResult = undefined;
        var reply = RuntimeImpl.EnrReply.init(&buffer);
        try storage.enqueueCommand(.{ .peer_enr = .{ .node_id = node_id, .reply = &reply } });
        return try reply.getOneUncancelable(storage.io);
    }

    pub fn localEnrSeq(self: *Runtime) runtime_error.CommandError!u64 {
        const storage = impl(self);
        try storage.ensureRunning();
        var buffer: [1]RuntimeImpl.U64Result = undefined;
        var reply = RuntimeImpl.U64Reply.init(&buffer);
        try storage.enqueueCommand(.{ .local_enr_seq = &reply });
        return try reply.getOneUncancelable(storage.io);
    }

    fn impl(self: *Runtime) *RuntimeImpl {
        return @ptrCast(@alignCast(self));
    }

    fn implConst(self: *const Runtime) *const RuntimeImpl {
        return @ptrCast(@alignCast(self));
    }
};

fn receiveErrorBackoffMs(consecutive_errors: u8) u64 {
    const shift: u3 = @intCast(@min(consecutive_errors -| 1, 7));
    return @min(@as(u64, 1) << shift, MAX_RECEIVE_ERROR_BACKOFF_MS);
}

pub const Testing = @import("runtime_testing.zig").Hooks(Runtime, RuntimeImpl, RuntimeImpl.shutdown, receiveErrorBackoffMs);
