const std = @import("std");
const actor_mod = @import("actor.zig");
const admission_mod = @import("admission.zig");
const config_mod = @import("config.zig");
const enr = @import("enr.zig");
const events = @import("events.zig");
const message = @import("protocol/message.zig");
const metrics = @import("metrics.zig");
const packet = @import("protocol/packet.zig");
const command_handler = @import("runtime_command_handler.zig");
const transport_mod = @import("transport.zig");
const types = @import("types.zig");

const Allocator = std.mem.Allocator;
const Io = std.Io;
const MAX_RECEIVE_ERROR_BACKOFF_MS: u64 = 100;
pub const Error = @import("runtime_error.zig").Error;

/// Internal implementation behind the opaque `Runtime` handle. Public within
/// the module so the command handler can name an explicit typed contract.
pub const RuntimeImpl = struct {
    io: Io,
    allocator: Allocator,
    transport: transport_mod.Transport,
    admission: admission_mod.IngressAdmission,
    outbox: events.EventOutbox,
    actor: actor_mod.Actor,
    options: config_mod.Options,
    command_queue: Io.Queue(Command),
    command_buffer: []Command,
    group: Io.Group = .init,
    running: std.atomic.Value(bool) = .init(false),
    closed: std.atomic.Value(bool) = .init(false),
    maintenance_due: std.atomic.Value(bool) = .init(false),
    test_command_gate: if (@import("builtin").is_test) ?*Testing.CommandGate else void = if (@import("builtin").is_test) null else {},

    const ReqResult = Error!message.ReqId;
    const IdResult = Error!u32;
    const VoidResult = Error!void;
    const BoolResult = Error!bool;
    const MetricsResult = Error!metrics.MetricsSnapshot;
    const EnrResult = Error!?enr.RawEnr;
    const U64Result = Error!u64;
    const ReqReply = Io.Queue(ReqResult);
    const IdReply = Io.Queue(IdResult);
    const VoidReply = Io.Queue(VoidResult);
    const BoolReply = Io.Queue(BoolResult);
    const MetricsReply = Io.Queue(MetricsResult);
    const EnrReply = Io.Queue(EnrResult);
    const U64Reply = Io.Queue(U64Result);

    const Inbound = struct {
        from: types.Address,
        bytes: types.PacketBytes,
    };

    const AddNode = struct {
        node_id: types.NodeId,
        pubkey: ?[33]u8,
        address: types.Address,
        enr: ?[]u8,
        reply: *BoolReply,
    };

    const SendPing = struct {
        endpoint: types.Endpoint,
        pubkey: [33]u8,
        enr_seq: u64,
        reply: *ReqReply,
    };

    const SendFindNode = struct {
        endpoint: types.Endpoint,
        pubkey: [33]u8,
        distances: [127]u16,
        distances_len: u8,
        reply: *ReqReply,
    };

    pub const Command = union(enum) {
        inbound: Inbound,
        maintenance,
        add_node: AddNode,
        add_enr: struct { enr: []u8, reply: *BoolReply },
        set_local_enr: struct { enr: []u8, reply: *VoidReply },
        send_ping: SendPing,
        send_findnode: SendFindNode,
        send_talk_request: struct {
            endpoint: types.Endpoint,
            pubkey: [33]u8,
            protocol_name: []u8,
            request: []u8,
            reply: *ReqReply,
        },
        send_talk_response: struct {
            endpoint: types.Endpoint,
            req_id: message.ReqId,
            response: []u8,
            reply: *VoidReply,
        },
        cancel_request: struct { key: types.RequestKey, reply: *BoolReply },
        start_lookup: struct { target: types.NodeId, reply: *IdReply },
        start_random_lookup: *IdReply,
        metrics_snapshot: *MetricsReply,
        local_enr: *EnrReply,
        peer_enr: struct { node_id: types.NodeId, reply: *EnrReply },
        local_enr_seq: *U64Reply,
    };

    fn init(io: Io, allocator: Allocator, config: config_mod.Config, options: config_mod.Options) !RuntimeImpl {
        try config.validate();
        try options.validate();
        var transport = try transport_mod.Transport.init(io, config.bind_addresses);
        errdefer transport.deinit();
        var admission = try admission_mod.IngressAdmission.init(allocator, config.rate_limiter, try admission_mod.permitCapacity(config.limits));
        errdefer admission.deinit();
        var outbox = try events.EventOutbox.init(io, allocator, config.limits.event_capacity);
        errdefer outbox.deinit();
        var actor = try actor_mod.Actor.init(allocator, config);
        errdefer actor.deinit(&admission);
        const commands = try allocator.alloc(Command, config.limits.command_capacity);
        return .{
            .io = io,
            .allocator = allocator,
            .transport = transport,
            .admission = admission,
            .outbox = outbox,
            .actor = actor,
            .options = options,
            .command_queue = .init(commands),
            .command_buffer = commands,
        };
    }

    fn deinit(self: *RuntimeImpl) void {
        std.debug.assert(!self.running.load(.acquire));
        self.stop();
        self.outbox.deinit();
        self.actor.deinit(&self.admission);
        self.admission.deinit();
        self.transport.deinit();
        self.allocator.free(self.command_buffer);
    }

    /// Run the single domain actor on the caller task. The caller schedules
    /// this method in its own group, calls stop, awaits that group, then deinit.
    fn run(self: *RuntimeImpl) (error{ AlreadyRunning, RuntimeStopped } || Io.ConcurrentError || Io.Cancelable)!void {
        if (self.closed.load(.acquire)) return error.RuntimeStopped;
        if (self.running.swap(true, .acq_rel)) return error.AlreadyRunning;
        defer self.running.store(false, .release);
        defer self.shutdown();
        if (self.transport.ip4 != null) try self.group.concurrent(self.io, receiveLoop, .{ self, types.Address.Family.ip4 });
        if (self.transport.ip6 != null) try self.group.concurrent(self.io, receiveLoop, .{ self, types.Address.Family.ip6 });
        try self.group.concurrent(self.io, maintenanceLoop, .{self});
        self.actorLoop() catch |err| switch (err) {
            error.Canceled => return error.Canceled,
        };
    }

    fn stop(self: *RuntimeImpl) void {
        self.closed.store(true, .release);
        self.command_queue.close(self.io);
    }

    pub fn shutdown(self: *RuntimeImpl) void {
        self.stop();
        self.drainAcceptedCommands();
        self.group.cancel(self.io);
        self.outbox.close();
    }

    fn isRunning(self: *const RuntimeImpl) bool {
        return self.running.load(.acquire);
    }

    fn isClosed(self: *const RuntimeImpl) bool {
        return self.closed.load(.acquire);
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

    fn addNode(self: *RuntimeImpl, node_id: types.NodeId, pubkey: ?*const [33]u8, address: types.Address, enr_bytes: ?[]const u8) !bool {
        try self.ensureRunning();
        if (enr_bytes) |bytes| if (bytes.len > @import("enr.zig").MAX_ENR_SIZE) return error.InvalidEnr;
        var owned: ?[]u8 = if (enr_bytes) |bytes| try self.allocator.dupe(u8, bytes) else null;
        errdefer if (owned) |bytes| self.allocator.free(bytes);
        var buffer: [1]BoolResult = undefined;
        var reply = BoolReply.init(&buffer);
        try self.enqueueCommand(.{ .add_node = .{
            .node_id = node_id,
            .pubkey = if (pubkey) |key| key.* else null,
            .address = address,
            .enr = owned,
            .reply = &reply,
        } });
        owned = null;
        return try reply.getOneUncancelable(self.io);
    }

    fn addEnr(self: *RuntimeImpl, enr_bytes: []const u8) !bool {
        try self.ensureRunning();
        if (enr_bytes.len > @import("enr.zig").MAX_ENR_SIZE) return error.InvalidEnr;
        var owned: ?[]u8 = try self.allocator.dupe(u8, enr_bytes);
        errdefer if (owned) |bytes| self.allocator.free(bytes);
        var buffer: [1]BoolResult = undefined;
        var reply = BoolReply.init(&buffer);
        try self.enqueueCommand(.{ .add_enr = .{ .enr = owned.?, .reply = &reply } });
        owned = null;
        return try reply.getOneUncancelable(self.io);
    }

    fn setLocalEnr(self: *RuntimeImpl, enr_bytes: []const u8) !void {
        try self.ensureRunning();
        if (enr_bytes.len > @import("enr.zig").MAX_ENR_SIZE) return error.InvalidEnr;
        var owned: ?[]u8 = try self.allocator.dupe(u8, enr_bytes);
        errdefer if (owned) |bytes| self.allocator.free(bytes);
        var buffer: [1]VoidResult = undefined;
        var reply = VoidReply.init(&buffer);
        try self.enqueueCommand(.{ .set_local_enr = .{ .enr = owned.?, .reply = &reply } });
        owned = null;
        return try reply.getOneUncancelable(self.io);
    }

    fn sendPing(self: *RuntimeImpl, node_id: types.NodeId, pubkey: *const [33]u8, address: types.Address, enr_seq: u64) !message.ReqId {
        try self.ensureRunning();
        var buffer: [1]ReqResult = undefined;
        var reply = ReqReply.init(&buffer);
        try self.enqueueCommand(.{ .send_ping = .{
            .endpoint = .{ .node_id = node_id, .addr = address },
            .pubkey = pubkey.*,
            .enr_seq = enr_seq,
            .reply = &reply,
        } });
        return try reply.getOneUncancelable(self.io);
    }

    fn sendFindNode(self: *RuntimeImpl, node_id: types.NodeId, pubkey: *const [33]u8, address: types.Address, distances: []const u16) !message.ReqId {
        try self.ensureRunning();
        if (distances.len > 127) return error.TooManyDistances;
        var copied: [127]u16 = undefined;
        @memcpy(copied[0..distances.len], distances);
        var buffer: [1]ReqResult = undefined;
        var reply = ReqReply.init(&buffer);
        try self.enqueueCommand(.{ .send_findnode = .{
            .endpoint = .{ .node_id = node_id, .addr = address },
            .pubkey = pubkey.*,
            .distances = copied,
            .distances_len = @intCast(distances.len),
            .reply = &reply,
        } });
        return try reply.getOneUncancelable(self.io);
    }

    fn sendTalkRequest(self: *RuntimeImpl, node_id: types.NodeId, pubkey: *const [33]u8, address: types.Address, protocol_name: []const u8, request: []const u8) !message.ReqId {
        try self.ensureRunning();
        const payload_len = std.math.add(usize, protocol_name.len, request.len) catch return error.MessageTooLarge;
        if (payload_len > packet.MAX_PACKET_SIZE) return error.MessageTooLarge;
        var protocol_copy: ?[]u8 = try self.allocator.dupe(u8, protocol_name);
        errdefer if (protocol_copy) |bytes| self.allocator.free(bytes);
        var request_copy: ?[]u8 = try self.allocator.dupe(u8, request);
        errdefer if (request_copy) |bytes| self.allocator.free(bytes);
        var buffer: [1]ReqResult = undefined;
        var reply = ReqReply.init(&buffer);
        try self.enqueueCommand(.{ .send_talk_request = .{
            .endpoint = .{ .node_id = node_id, .addr = address },
            .pubkey = pubkey.*,
            .protocol_name = protocol_copy.?,
            .request = request_copy.?,
            .reply = &reply,
        } });
        protocol_copy = null;
        request_copy = null;
        return try reply.getOneUncancelable(self.io);
    }

    fn sendTalkResponse(self: *RuntimeImpl, node_id: types.NodeId, address: types.Address, req_id: message.ReqId, response: []const u8) !void {
        try self.ensureRunning();
        if (response.len > packet.MAX_PACKET_SIZE) return error.MessageTooLarge;
        var owned: ?[]u8 = try self.allocator.dupe(u8, response);
        errdefer if (owned) |bytes| self.allocator.free(bytes);
        var buffer: [1]VoidResult = undefined;
        var reply = VoidReply.init(&buffer);
        try self.enqueueCommand(.{ .send_talk_response = .{
            .endpoint = .{ .node_id = node_id, .addr = address },
            .req_id = req_id,
            .response = owned.?,
            .reply = &reply,
        } });
        owned = null;
        return try reply.getOneUncancelable(self.io);
    }

    fn startLookup(self: *RuntimeImpl, target: types.NodeId) !u32 {
        try self.ensureRunning();
        var buffer: [1]IdResult = undefined;
        var reply = IdReply.init(&buffer);
        try self.enqueueCommand(.{ .start_lookup = .{ .target = target, .reply = &reply } });
        return try reply.getOneUncancelable(self.io);
    }

    fn cancelRequest(self: *RuntimeImpl, node_id: types.NodeId, address: types.Address, req_id: message.ReqId) !bool {
        try self.ensureRunning();
        var buffer: [1]BoolResult = undefined;
        var reply = BoolReply.init(&buffer);
        try self.enqueueCommand(.{ .cancel_request = .{
            .key = .init(.{ .node_id = node_id, .addr = address }, req_id),
            .reply = &reply,
        } });
        return try reply.getOneUncancelable(self.io);
    }

    fn startRandomLookup(self: *RuntimeImpl) !u32 {
        try self.ensureRunning();
        var buffer: [1]IdResult = undefined;
        var reply = IdReply.init(&buffer);
        try self.enqueueCommand(.{ .start_random_lookup = &reply });
        return try reply.getOneUncancelable(self.io);
    }

    fn metricsSnapshot(self: *RuntimeImpl) !metrics.MetricsSnapshot {
        try self.ensureRunning();
        var buffer: [1]MetricsResult = undefined;
        var reply = MetricsReply.init(&buffer);
        try self.enqueueCommand(.{ .metrics_snapshot = &reply });
        return try reply.getOneUncancelable(self.io);
    }

    fn localEnr(self: *RuntimeImpl) !?enr.RawEnr {
        try self.ensureRunning();
        var buffer: [1]EnrResult = undefined;
        var reply = EnrReply.init(&buffer);
        try self.enqueueCommand(.{ .local_enr = &reply });
        return try reply.getOneUncancelable(self.io);
    }

    fn peerEnr(self: *RuntimeImpl, node_id: types.NodeId) !?enr.RawEnr {
        try self.ensureRunning();
        var buffer: [1]EnrResult = undefined;
        var reply = EnrReply.init(&buffer);
        try self.enqueueCommand(.{ .peer_enr = .{ .node_id = node_id, .reply = &reply } });
        return try reply.getOneUncancelable(self.io);
    }

    fn localEnrSeq(self: *RuntimeImpl) !u64 {
        try self.ensureRunning();
        var buffer: [1]U64Result = undefined;
        var reply = U64Reply.init(&buffer);
        try self.enqueueCommand(.{ .local_enr_seq = &reply });
        return try reply.getOneUncancelable(self.io);
    }

    fn ensureRunning(self: *RuntimeImpl) !void {
        if (self.closed.load(.acquire)) return error.RuntimeStopped;
        if (!self.running.load(.acquire)) return error.RuntimeNotRunning;
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

    pub fn actorLoopForTesting(self: *RuntimeImpl) Io.Cancelable!void {
        defer self.shutdown();
        return self.actorLoop();
    }

    fn drainAcceptedCommands(self: *RuntimeImpl) void {
        const previous_protection = self.io.swapCancelProtection(.blocked);
        defer _ = self.io.swapCancelProtection(previous_protection);
        while (true) {
            const command = self.command_queue.getOneUncancelable(self.io) catch |err| switch (err) {
                error.Closed => return,
            };
            self.handleCommand(command) catch |err| switch (err) {
                error.Canceled => {},
            };
        }
    }

    /// Bind the actor execution context from heap-pinned runtime state.
    /// `Runtime.init` allocates RuntimeImpl on the heap, so these interior
    /// pointers are stable for the lifetime of the dispatch.
    pub fn env(self: *RuntimeImpl) actor_mod.Env {
        return .{
            .io = self.io,
            .sender = self.transport.sender(),
            .ingress = &self.admission,
            .outbox = &self.outbox,
        };
    }

    fn handleCommand(self: *RuntimeImpl, command: Command) Io.Cancelable!void {
        if (@import("builtin").is_test) if (self.test_command_gate) |gate| {
            gate.entered.store(true, .release);
            while (!gate.proceed.load(.acquire)) std.atomic.spinLoopHint();
        };
        return command_handler.handle(self, command);
    }

    fn receiveLoop(self: *RuntimeImpl, family: types.Address.Family) Io.Cancelable!void {
        if (self.transport.socket(family) == null) return;
        var buffer: [packet.MAX_PACKET_SIZE]u8 = undefined;
        var consecutive_errors: u8 = 0;
        while (!self.closed.load(.acquire)) {
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
            if (!self.admission.accept(received.from, nowMs(self.io))) continue;
            const bytes = types.PacketBytes.init(received.data) catch continue;
            self.enqueueCommand(.{ .inbound = .{ .from = received.from, .bytes = bytes } }) catch |err| switch (err) {
                error.CommandQueueFull => continue,
                error.Closed => return,
                error.Canceled => return error.Canceled,
            };
        }
    }

    fn maintenanceLoop(self: *RuntimeImpl) Io.Cancelable!void {
        const interval = @max(self.options.maintenance_interval_ms, 1);
        while (!self.closed.load(.acquire)) {
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

pub const Runtime = opaque {
    pub fn init(io: Io, allocator: Allocator, config: config_mod.Config, options: config_mod.Options) Error!*Runtime {
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

    pub fn run(self: *Runtime) Error!void {
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

    pub fn nextEvent(self: *Runtime) Error!events.Event {
        return impl(self).nextEvent();
    }

    pub fn popEvent(self: *Runtime) ?events.Event {
        return impl(self).popEvent();
    }

    pub fn addNode(self: *Runtime, node_id: types.NodeId, pubkey: ?*const [33]u8, address: types.Address, enr_bytes: ?[]const u8) Error!bool {
        return impl(self).addNode(node_id, pubkey, address, enr_bytes);
    }

    pub fn addEnr(self: *Runtime, enr_bytes: []const u8) Error!bool {
        return impl(self).addEnr(enr_bytes);
    }

    pub fn setLocalEnr(self: *Runtime, enr_bytes: []const u8) Error!void {
        return impl(self).setLocalEnr(enr_bytes);
    }

    pub fn sendPing(self: *Runtime, node_id: types.NodeId, pubkey: *const [33]u8, address: types.Address, enr_seq: u64) Error!message.ReqId {
        return impl(self).sendPing(node_id, pubkey, address, enr_seq);
    }

    pub fn sendFindNode(self: *Runtime, node_id: types.NodeId, pubkey: *const [33]u8, address: types.Address, distances: []const u16) Error!message.ReqId {
        return impl(self).sendFindNode(node_id, pubkey, address, distances);
    }

    pub fn sendTalkRequest(self: *Runtime, node_id: types.NodeId, pubkey: *const [33]u8, address: types.Address, protocol_name: []const u8, request: []const u8) Error!message.ReqId {
        return impl(self).sendTalkRequest(node_id, pubkey, address, protocol_name, request);
    }

    pub fn sendTalkResponse(self: *Runtime, node_id: types.NodeId, address: types.Address, req_id: message.ReqId, response: []const u8) Error!void {
        return impl(self).sendTalkResponse(node_id, address, req_id, response);
    }

    pub fn startLookup(self: *Runtime, target: types.NodeId) Error!u32 {
        return impl(self).startLookup(target);
    }

    pub fn cancelRequest(self: *Runtime, node_id: types.NodeId, address: types.Address, req_id: message.ReqId) Error!bool {
        return impl(self).cancelRequest(node_id, address, req_id);
    }

    pub fn startRandomLookup(self: *Runtime) Error!u32 {
        return impl(self).startRandomLookup();
    }

    pub fn metricsSnapshot(self: *Runtime) Error!metrics.MetricsSnapshot {
        return impl(self).metricsSnapshot();
    }

    pub fn localEnr(self: *Runtime) Error!?enr.RawEnr {
        return impl(self).localEnr();
    }

    pub fn peerEnr(self: *Runtime, node_id: types.NodeId) Error!?enr.RawEnr {
        return impl(self).peerEnr(node_id);
    }

    pub fn localEnrSeq(self: *Runtime) Error!u64 {
        return impl(self).localEnrSeq();
    }

    fn impl(self: *Runtime) *RuntimeImpl {
        return @ptrCast(@alignCast(self));
    }

    fn implConst(self: *const Runtime) *const RuntimeImpl {
        return @ptrCast(@alignCast(self));
    }
};

fn nowMs(io: Io) u64 {
    const value = Io.Timestamp.now(io, .real).toMilliseconds();
    return if (value < 0) 0 else @intCast(value);
}

fn receiveErrorBackoffMs(consecutive_errors: u8) u64 {
    const shift: u3 = @intCast(@min(consecutive_errors -| 1, 7));
    return @min(@as(u64, 1) << shift, MAX_RECEIVE_ERROR_BACKOFF_MS);
}

pub const Testing = @import("runtime_testing.zig").Hooks(Runtime, RuntimeImpl, Error, receiveErrorBackoffMs);
