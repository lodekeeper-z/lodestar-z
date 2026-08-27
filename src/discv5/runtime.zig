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
const public_api = @import("public_api.zig");
const request_results = @import("request_results.zig");
const transport_mod = @import("transport.zig");
const types = @import("types.zig");
const util = @import("util.zig");

const Allocator = std.mem.Allocator;
const Io = std.Io;
const MAX_RECEIVE_ERROR_BACKOFF_MS: u64 = 100;
const MAX_ATOMIC_INGRESS_EFFECTS: usize = config_mod.MAX_NODES_RESPONSE_CHUNKS + 1;
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
    control: Io.Event = .unset,
    effect_storage: []actor_mod.ActorEffect,
    effects: actor_mod.EffectQueue,
    group: Io.Group = .init,
    lifecycle: std.atomic.Value(Lifecycle) = .init(.ready),
    terminalized: std.atomic.Value(bool) = .init(false),
    maintenance_due: std.atomic.Value(bool) = .init(false),
    test_command_gate: if (@import("builtin").is_test) ?*Testing.CommandGate else void = if (@import("builtin").is_test) null else {},
    test_cancellation_gate: if (@import("builtin").is_test) ?*Testing.CancellationGate else void = if (@import("builtin").is_test) null else {},

    const EnrAdmissionResult = EnrAdmissionError!bool;
    const SetLocalEnrResult = SetLocalEnrError!void;
    const PingResult = RequestError!public_api.RequestHandle;
    const FindNodeResult = FindNodeError!public_api.RequestHandle;
    const TalkRequestResult = TalkRequestError!public_api.RequestHandle;
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
        node_id: types.NodeId,
        origin: types.RequestOrigin,
        reply: *PingReply,
    };

    const SendFindNode = struct {
        node_id: types.NodeId,
        distances: [types.MAX_OUTBOUND_FINDNODE_DISTANCES]u16,
        distances_len: u8,
        origin: types.RequestOrigin,
        reply: *FindNodeReply,
    };

    const SendTalkRequest = struct {
        node_id: types.NodeId,
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
        cancel_request: struct { handle: types.RequestHandle, reply: *CommandBoolReply },
        start_lookup: struct { target: types.NodeId, reply: *LookupReply },
        start_random_lookup: *LookupReply,
        metrics_snapshot: *MetricsReply,
        local_enr: *EnrReply,
        peer_enr: struct { node_id: types.NodeId, reply: *EnrReply },
        local_enr_seq: *U64Reply,

        fn abort(command: Command, runtime: *RuntimeImpl) void {
            switch (command) {
                .inbound => |value| {
                    var expected = value.expected;
                    if (expected) |*credit| credit.rollback(&runtime.admission);
                },
                .maintenance => runtime.maintenance_due.store(false, .release),
                .add_node => |value| {
                    if (value.enr) |bytes| runtime.allocator.free(bytes);
                    abortReply(runtime.io, value.reply);
                },
                .add_enr => |value| {
                    runtime.allocator.free(value.enr);
                    abortReply(runtime.io, value.reply);
                },
                .set_local_enr => |value| {
                    runtime.allocator.free(value.enr);
                    abortReply(runtime.io, value.reply);
                },
                .send_ping => |value| {
                    if (value.origin == .reliable_api) runtime.request_result_outbox.cancelUnclaimed();
                    abortReply(runtime.io, value.reply);
                },
                .send_findnode => |value| {
                    if (value.origin == .reliable_api) runtime.request_result_outbox.cancelUnclaimed();
                    abortReply(runtime.io, value.reply);
                },
                .send_talk_request => |value| {
                    runtime.allocator.free(value.protocol_name);
                    runtime.allocator.free(value.request);
                    if (value.origin == .reliable_api) runtime.request_result_outbox.cancelUnclaimed();
                    abortReply(runtime.io, value.reply);
                },
                .send_talk_response => |value| {
                    runtime.allocator.free(value.response);
                    abortReply(runtime.io, value.reply);
                },
                .cancel_request => |value| abortReply(runtime.io, value.reply),
                .start_lookup => |value| {
                    runtime.lookup_result_outbox.cancelUnclaimed();
                    abortReply(runtime.io, value.reply);
                },
                .start_random_lookup => |reply| {
                    runtime.lookup_result_outbox.cancelUnclaimed();
                    abortReply(runtime.io, reply);
                },
                .metrics_snapshot => |reply| abortReply(runtime.io, reply),
                .local_enr => |reply| abortReply(runtime.io, reply),
                .peer_enr => |value| abortReply(runtime.io, value.reply),
                .local_enr_seq => |reply| abortReply(runtime.io, reply),
            }
        }
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
            error.ChallengeCapacityOverflow,
            error.InvalidAdmissionCapacity,
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

    /// Request-side effects inject into distinct canonical request slots.
    /// Other producers are atomic per inbound packet; FINDNODE is the maximum:
    /// one eviction probe followed by the bounded multipart NODES response.
    /// Runtime drains the FIFO after every command and pops before completion,
    /// so these bounds are alternatives rather than additive queue residents.
    fn effectCapacity(limits: config_mod.Limits) !usize {
        const permit_capacity = try admission_mod.permitCapacity(limits);
        return @max(limits.max_active_requests, @min(permit_capacity, MAX_ATOMIC_INGRESS_EFFECTS));
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
        errdefer allocator.free(commands);
        const effect_storage = try allocator.alloc(actor_mod.ActorEffect, try effectCapacity(config.limits));
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
            .effect_storage = effect_storage,
            .effects = .init(effect_storage),
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
        self.allocator.free(self.effect_storage);
        self.allocator.free(self.command_buffer);
    }

    /// Run the Runtime-owned driver under a Future held only by this caller.
    /// `stop` signals `control`; this controller is the sole Future cancel/join
    /// owner, so stop never races a caller-side await or a driver-side join.
    fn run(self: *RuntimeImpl) (error{ AlreadyRunning, RuntimeStopped } || Io.ConcurrentError || Io.Cancelable)!void {
        if (self.lifecycle.cmpxchgStrong(.ready, .running, .acq_rel, .acquire)) |actual| return switch (actual) {
            .ready => unreachable,
            .running => error.AlreadyRunning,
            .stopping, .terminalizing, .stopped => error.RuntimeStopped,
        };
        defer self.shutdown();

        var driver_future = self.io.async(driver, .{self});
        var driver_reaped = false;
        defer if (!driver_reaped) driver_future.cancel(self.io) catch {};

        self.control.wait(self.io) catch |err| switch (err) {
            error.Canceled => {
                self.io.recancel();
                return error.Canceled;
            },
        };
        const driver_result = driver_future.cancel(self.io);
        driver_reaped = true;
        driver_result catch |err| switch (err) {
            error.Canceled => if (self.lifecycle.load(.acquire) != .stopping) return error.Canceled,
            error.ConcurrencyUnavailable => return error.ConcurrencyUnavailable,
        };
    }

    fn driver(self: *RuntimeImpl) (Io.ConcurrentError || Io.Cancelable)!void {
        defer self.control.set(self.io);
        defer self.group.cancel(self.io);
        if (self.lifecycle.load(.acquire) != .running) return;
        if (self.transport.ip4 != null) try self.group.concurrent(self.io, receiveLoop, .{ self, types.Address.Family.ip4 });
        if (self.transport.ip6 != null) try self.group.concurrent(self.io, receiveLoop, .{ self, types.Address.Family.ip6 });
        try self.group.concurrent(self.io, maintenanceLoop, .{self});
        try self.actorLoop();
    }

    fn stop(self: *RuntimeImpl) void {
        while (true) switch (self.lifecycle.load(.acquire)) {
            .ready => if (self.lifecycle.cmpxchgWeak(.ready, .terminalizing, .acq_rel, .acquire) == null) {
                self.command_queue.close(self.io);
                self.control.set(self.io);
                self.terminalize();
                self.lifecycle.store(.stopped, .release);
                return;
            },
            .running => if (self.lifecycle.cmpxchgWeak(.running, .stopping, .acq_rel, .acquire) == null) {
                self.command_queue.close(self.io);
                self.control.set(self.io);
                return;
            },
            .stopping, .terminalizing, .stopped => {
                self.command_queue.close(self.io);
                self.control.set(self.io);
                return;
            },
        };
    }

    fn shutdown(self: *RuntimeImpl) void {
        self.command_queue.close(self.io);
        self.control.set(self.io);
        // Commands carry caller-stack reply queues and, in some cases, owned
        // allocations. Intake closure bounds this drain by command capacity;
        // Abort accepted commands so neither replies nor ownership dangle and
        // shutdown performs no new domain or transport work.
        self.drainAcceptedCommands();
        self.terminalize();
        self.lifecycle.store(.stopped, .release);
    }

    fn terminalize(self: *RuntimeImpl) void {
        if (self.terminalized.swap(true, .acq_rel)) return;
        self.abortEffects();
        const env = self.actorEnv();
        // Effect aborts consume exact queued response and challenge generations
        // first. Sweep residual phases only afterward so permits are released
        // exactly once and copied late completions are stale.
        self.actor.finishAllResponses(&self.admission);
        self.actor.sessions.pruneChallenges(std.math.maxInt(i64), &self.admission);
        self.actor.finishAllLookups(env, .runtime_stopped);
        self.actor.finishAllRequests(env);
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
            switch (self.lifecycle.load(.acquire)) {
                .stopping, .terminalizing, .stopped => command.abort(self),
                .ready, .running => try self.handleCommand(command),
            }
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
            command.abort(self);
        }
    }

    /// Bind the actor execution context from heap-pinned runtime state.
    /// `Runtime.init` allocates RuntimeImpl on the heap, so these interior
    /// pointers are stable for the lifetime of the dispatch.
    fn actorEnv(self: *RuntimeImpl) actor_mod.Env {
        return .{
            .io = self.io,
            .ingress = &self.admission,
            .outbox = &self.outbox,
            .effects = &self.effects,
            .lookup_results = &self.lookup_result_outbox,
            .request_results = &self.request_result_outbox,
        };
    }

    fn handleCommand(self: *RuntimeImpl, command: Command) Io.Cancelable!void {
        defer self.abortEffects();
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
            .send_ping => |value| try self.handleSendPing(value),
            .send_findnode => |value| try self.handleSendFindNode(value),
            .send_talk_request => |value| {
                defer self.allocator.free(value.protocol_name);
                defer self.allocator.free(value.request);
                try self.handleSendTalkRequest(value);
            },
            .send_talk_response => |value| {
                defer self.allocator.free(value.response);
                try self.handleSendTalkResponse(env, value);
            },
            .cancel_request => |value| value.reply.putOneUncancelable(
                self.io,
                self.actor.cancelRequest(env, value.handle),
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
        try self.drainEffects();
    }

    fn drainEffects(self: *RuntimeImpl) Io.Cancelable!void {
        while (self.effects.pop()) |effect| {
            executeSendEffect(self, effect) catch |err| switch (err) {
                error.Canceled => return error.Canceled,
                else => continue,
            };
        }
    }

    fn abortEffects(self: *RuntimeImpl) void {
        while (self.effects.pop()) |effect| {
            self.actor.applyEffectCompletion(self.actorEnv(), effect, .runtime_stopped);
        }
    }

    fn handleSendPing(self: *RuntimeImpl, value: SendPing) Io.Cancelable!void {
        const reliable = value.origin == .reliable_api;
        if (reliable and !self.request_result_outbox.claim()) unreachable;
        const result = sendPingResult(self, value.node_id, value.origin);
        if (result) |_| {} else |_| if (reliable) self.request_result_outbox.release();
        try replyResult(self.io, value.reply, result);
    }

    fn handleSendFindNode(self: *RuntimeImpl, value: SendFindNode) Io.Cancelable!void {
        const reliable = value.origin == .reliable_api;
        if (reliable and !self.request_result_outbox.claim()) unreachable;
        const result = sendFindNodeResult(self, value.node_id, value.distances[0..value.distances_len], value.origin);
        if (result) |_| {} else |_| if (reliable) self.request_result_outbox.release();
        try replyResult(self.io, value.reply, result);
    }

    fn handleSendTalkRequest(self: *RuntimeImpl, value: SendTalkRequest) Io.Cancelable!void {
        const reliable = value.origin == .reliable_api;
        if (reliable and !self.request_result_outbox.claim()) unreachable;
        const result = sendTalkRequestResult(
            self,
            value.node_id,
            value.protocol_name,
            value.request,
            value.origin,
        );
        if (result) |_| {} else |_| if (reliable) self.request_result_outbox.release();
        try replyResult(self.io, value.reply, result);
    }

    fn handleSendTalkResponse(self: *RuntimeImpl, env: actor_mod.Env, value: anytype) Io.Cancelable!void {
        const prepared = sendTalkResponseResult(&self.actor, env, value.endpoint, value.req_id, value.response);
        if (prepared) |_| {} else |err| {
            try replyResult(self.io, value.reply, @as(TalkResponseError!void, err));
            return;
        }
        const effect = self.effects.pop() orelse unreachable;
        executeSendEffect(self, effect) catch |err| {
            const result: TalkResponseError!void = switch (err) {
                error.Canceled => error.Canceled,
                error.MessageOversize => error.MessageTooLarge,
                error.NoSocketForAddressFamily => error.NoSocketForAddressFamily,
                error.OutOfMemory => error.OutOfMemory,
                error.TransportSendFailed => error.TransportSendFailed,
            };
            try replyResult(self.io, value.reply, result);
            if (err == error.Canceled) return error.Canceled;
            return;
        };
        try replyResult(self.io, value.reply, @as(TalkResponseError!void, {}));
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

fn executeRequestEffect(runtime: *RuntimeImpl, action_value: actor_mod.OutboundRequestAction) !types.RequestHandle {
    var action = action_value;
    const handle = action.handle();
    switch (action) {
        .queued => return handle,
        .send => |effect| {
            const target_index = runtime.effects.count();
            runtime.effects.push(.{ .request = effect }) catch unreachable;
            for (0..target_index + 1) |index| {
                const queued = runtime.effects.pop() orelse unreachable;
                executeSendEffect(runtime, queued) catch |err| {
                    if (index == target_index or err == error.Canceled) return err;
                    continue;
                };
            }
        },
    }
    return handle;
}

fn executeSendEffect(runtime: *RuntimeImpl, effect: actor_mod.ActorEffect) !void {
    runtime.transport.sender().send(effect.destination(), effect.packetBytes()) catch |err| {
        runtime.actor.applyEffectCompletion(runtime.actorEnv(), effect, if (err == error.Canceled) .runtime_stopped else .failed);
        return err;
    };
    runtime.actor.applyEffectCompletion(runtime.actorEnv(), effect, .sent);
}

fn executePingEffect(runtime: *RuntimeImpl, node_id: types.NodeId, origin: types.RequestOrigin) !types.RequestHandle {
    return executeRequestEffect(runtime, try runtime.actor.preparePing(
        .{ .io = runtime.io, .ingress = &runtime.admission },
        node_id,
        origin,
    ));
}

fn executeFindNodeEffect(runtime: *RuntimeImpl, node_id: types.NodeId, distances: []const u16, origin: types.RequestOrigin) !types.RequestHandle {
    return executeRequestEffect(runtime, try runtime.actor.prepareFindNode(
        .{ .io = runtime.io, .ingress = &runtime.admission },
        node_id,
        distances,
        origin,
    ));
}

fn executeTalkRequestEffect(runtime: *RuntimeImpl, node_id: types.NodeId, protocol_name: []const u8, request: []const u8, origin: types.RequestOrigin) !types.RequestHandle {
    return executeRequestEffect(runtime, try runtime.actor.prepareTalkRequest(
        .{ .io = runtime.io, .ingress = &runtime.admission },
        node_id,
        protocol_name,
        request,
        origin,
    ));
}

fn sendPingResult(runtime: *RuntimeImpl, node_id: types.NodeId, origin: types.RequestOrigin) RequestError!public_api.RequestHandle {
    const handle = executePingEffect(runtime, node_id, origin) catch |err| return switch (err) {
        error.Canceled => error.Canceled,
        error.DuplicateChallenge => error.DuplicateChallenge,
        error.DuplicateRequest => error.DuplicateRequest,
        error.GenerationExhausted => error.GenerationExhausted,
        error.NoSocketForAddressFamily => error.NoSocketForAddressFamily,
        error.UnknownPeer => error.UnknownPeer,
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
    return public_api.handleFromInternal(handle);
}

fn sendFindNodeResult(runtime: *RuntimeImpl, node_id: types.NodeId, distances: []const u16, origin: types.RequestOrigin) FindNodeError!public_api.RequestHandle {
    const handle = executeFindNodeEffect(runtime, node_id, distances, origin) catch |err| return switch (err) {
        error.Canceled => error.Canceled,
        error.DuplicateChallenge => error.DuplicateChallenge,
        error.DuplicateRequest => error.DuplicateRequest,
        error.GenerationExhausted => error.GenerationExhausted,
        error.InvalidDistance => error.InvalidDistance,
        error.NoSocketForAddressFamily => error.NoSocketForAddressFamily,
        error.UnknownPeer => error.UnknownPeer,
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
    return public_api.handleFromInternal(handle);
}

fn sendTalkRequestResult(runtime: *RuntimeImpl, node_id: types.NodeId, protocol_name: []const u8, request: []const u8, origin: types.RequestOrigin) TalkRequestError!public_api.RequestHandle {
    const handle = executeTalkRequestEffect(runtime, node_id, protocol_name, request, origin) catch |err| return switch (err) {
        // Keep encoder exhaustion normalized in case message layout drifts
        // beyond its packet-sized scratch buffer before the packet preflight.
        error.BufferTooSmall => error.MessageTooLarge,
        error.Canceled => error.Canceled,
        error.DuplicateChallenge => error.DuplicateChallenge,
        error.DuplicateRequest => error.DuplicateRequest,
        error.GenerationExhausted => error.GenerationExhausted,
        error.MessageTooLarge => error.MessageTooLarge,
        error.NoSocketForAddressFamily => error.NoSocketForAddressFamily,
        error.UnknownPeer => error.UnknownPeer,
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
    return public_api.handleFromInternal(handle);
}

fn sendTalkResponseResult(actor: *actor_mod.Actor, env: actor_mod.Env, endpoint: types.Endpoint, req_id: message.ReqId, response: []const u8) TalkResponseError!void {
    return actor.sendTalkResponse(env, endpoint, req_id, response) catch |err| switch (err) {
        // Keep encoder exhaustion normalized in case message layout drifts
        // beyond its packet-sized scratch buffer before the packet preflight.
        error.BufferTooSmall => error.MessageTooLarge,
        error.EndpointMismatch => error.EndpointMismatch,
        error.GenerationExhausted => error.GenerationExhausted,
        error.MessageTooLarge => error.MessageTooLarge,
        error.NoSession => error.NoSession,
        error.NonceGenerationExhausted => error.NonceGenerationExhausted,
        error.OutOfMemory => error.OutOfMemory,
        error.PermitGenerationExhausted => error.PermitGenerationExhausted,
        error.TooManyActiveRequests, error.TooManyResponseRecoveries => error.TooManyActiveRequests,
        error.UnknownPeer => error.UnknownPeer,
        else => unreachable,
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

fn abortReply(io: std.Io, reply: anytype) void {
    reply.putOneUncancelable(io, error.RuntimeStopped) catch {};
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
        if (enr_bytes == null) if (pubkey) |key| {
            const derived = enr.nodeIdFromCompressedPubkey(key) catch return error.InvalidPublicKey;
            if (!std.mem.eql(u8, &node_id, &derived)) return error.WrongNodeId;
        };
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

    pub fn sendPing(self: *Runtime, node_id: types.NodeId) runtime_error.RequestError!public_api.RequestHandle {
        const storage = impl(self);
        try storage.ensureRunning();
        if (!storage.request_result_outbox.reserve()) return error.RequestResultCapacityExceeded;
        var reservation_transferred = false;
        errdefer if (!reservation_transferred) storage.request_result_outbox.cancelUnclaimed();
        var buffer: [1]RuntimeImpl.PingResult = undefined;
        var reply = RuntimeImpl.PingReply.init(&buffer);
        try storage.enqueueCommand(.{ .send_ping = .{
            .node_id = node_id,
            .origin = .reliable_api,
            .reply = &reply,
        } });
        reservation_transferred = true;
        return try reply.getOneUncancelable(storage.io);
    }

    pub fn sendFindNode(self: *Runtime, node_id: types.NodeId, distances: []const u16) runtime_error.FindNodeError!public_api.RequestHandle {
        const storage = impl(self);
        try storage.ensureRunning();
        if (distances.len > types.MAX_OUTBOUND_FINDNODE_DISTANCES) return error.TooManyDistances;
        for (distances) |distance| {
            if (distance > 256) return error.InvalidDistance;
        }
        if (!storage.request_result_outbox.reserve()) return error.RequestResultCapacityExceeded;
        var reservation_transferred = false;
        errdefer if (!reservation_transferred) storage.request_result_outbox.cancelUnclaimed();
        var copied: [types.MAX_OUTBOUND_FINDNODE_DISTANCES]u16 = undefined;
        @memcpy(copied[0..distances.len], distances);
        var buffer: [1]RuntimeImpl.FindNodeResult = undefined;
        var reply = RuntimeImpl.FindNodeReply.init(&buffer);
        try storage.enqueueCommand(.{ .send_findnode = .{
            .node_id = node_id,
            .distances = copied,
            .distances_len = @intCast(distances.len),
            .origin = .reliable_api,
            .reply = &reply,
        } });
        reservation_transferred = true;
        return try reply.getOneUncancelable(storage.io);
    }

    pub fn sendTalkRequest(self: *Runtime, node_id: types.NodeId, protocol_name: []const u8, request: []const u8) runtime_error.TalkRequestError!public_api.RequestHandle {
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
            .node_id = node_id,
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

    pub fn sendTalkResponse(self: *Runtime, node_id: types.NodeId, address: types.Address, request_id: []const u8, response: []const u8) runtime_error.TalkResponseError!void {
        const storage = impl(self);
        try storage.ensureRunning();
        const req_id = message.ReqId.fromSlice(request_id) catch return error.InvalidRequestId;
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

    pub fn cancelRequest(self: *Runtime, handle: public_api.RequestHandle) runtime_error.CommandError!bool {
        const storage = impl(self);
        try storage.ensureRunning();
        var buffer: [1]RuntimeImpl.CommandBoolResult = undefined;
        var reply = RuntimeImpl.CommandBoolReply.init(&buffer);
        try storage.enqueueCommand(.{ .cancel_request = .{
            .handle = public_api.handleToInternal(handle),
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
