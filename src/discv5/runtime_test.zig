const std = @import("std");
const config = @import("config.zig");
const enr = @import("enr.zig");
const metrics = @import("metrics.zig");
const packet = @import("protocol/packet.zig");
const runtime_mod = @import("runtime.zig");
const secp = @import("secp256k1.zig");
const transport_mod = @import("transport.zig");
const types = @import("types.zig");

fn runRuntime(runtime: *runtime_mod.Runtime, result: *?anyerror) void {
    runtime.run() catch |err| {
        result.* = err;
    };
}

fn awaitFlag(flag: *const std.atomic.Value(bool), comptime timeout_error: anyerror) !void {
    for (0..10_000) |_| {
        if (flag.load(.acquire)) return;
        try std.Thread.yield();
    }
    return timeout_error;
}

const RunningRuntime = struct {
    io: std.Io,
    runtime: ?*runtime_mod.Runtime = null,
    caller_group: std.Io.Group = .init,
    run_result: ?anyerror = null,
    started: bool = false,
    awaited: bool = false,

    fn init(io: std.Io) RunningRuntime {
        return .{ .io = io };
    }

    fn start(self: *RunningRuntime, runtime: *runtime_mod.Runtime) !void {
        std.debug.assert(self.runtime == null);
        self.runtime = runtime;
        try self.caller_group.concurrent(self.io, runRuntime, .{ runtime, &self.run_result });
        self.started = true;
    }

    fn awaitStarted(self: *RunningRuntime) !void {
        std.debug.assert(self.started);
        const runtime = self.runtime.?;
        for (0..10_000) |_| {
            if (runtime.isRunning()) return;
            try std.Thread.yield();
        }
        return error.RuntimeDidNotStart;
    }

    fn stop(self: *RunningRuntime) void {
        std.debug.assert(self.started and !self.awaited);
        self.runtime.?.stop();
    }

    fn await(self: *RunningRuntime) !void {
        std.debug.assert(self.started and !self.awaited);
        defer self.awaited = true;
        try self.caller_group.await(self.io);
    }

    fn deinit(self: *RunningRuntime) void {
        const runtime = self.runtime orelse return;
        if (self.started and !self.awaited) {
            if (!runtime.isClosed()) runtime.stop();
            self.caller_group.await(self.io) catch {};
            self.awaited = true;
        }
        runtime.deinit();
        self.runtime = null;
    }
};

fn runActorLoop(runtime: *runtime_mod.Runtime, result: *?anyerror) void {
    runtime_mod.Testing.actorLoop(runtime) catch |err| {
        result.* = err;
    };
}

fn awaitBoolReply(io: std.Io, reply: *runtime_mod.Testing.EnrAdmissionReply, observed: *std.atomic.Value(bool)) void {
    const result = reply.getOneUncancelable(io) catch return;
    _ = result catch {};
    observed.store(true, .release);
}

const OwnedCommandProducer = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    runtime: *runtime_mod.Runtime,
    attempted: std.atomic.Value(bool) = .init(false),
    accepted: bool = false,
    completed: bool = false,
    result_error: ?anyerror = null,
};

fn enqueueOwnedCommand(context: *OwnedCommandProducer) void {
    var reply_buffer: [1]runtime_mod.Testing.EnrAdmissionResult = undefined;
    var reply = runtime_mod.Testing.EnrAdmissionReply.init(&reply_buffer);
    const owned = context.allocator.dupe(u8, &.{0xff}) catch |err| {
        context.result_error = err;
        context.attempted.store(true, .release);
        return;
    };
    runtime_mod.Testing.enqueueAddEnr(context.runtime, owned, &reply) catch |err| {
        context.result_error = err;
        context.attempted.store(true, .release);
        return;
    };
    context.accepted = true;
    context.attempted.store(true, .release);
    const result = reply.getOneUncancelable(context.io) catch |err| {
        context.result_error = err;
        return;
    };
    _ = result catch |err| {
        context.result_error = err;
        return;
    };
    context.completed = true;
}

fn initTestRuntime(io: std.Io, alloc: std.mem.Allocator, secret_byte: u8, limits: config.Limits, options: config.Options) !*runtime_mod.Runtime {
    const key_pair = try secp.keyPairFromSecret(&([_]u8{secret_byte} ** 32));
    return runtime_mod.Runtime.init(io, alloc, .{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = key_pair,
        .local_node_id = try enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&key_pair)),
        .rate_limiter = null,
        .limits = limits,
    }, options);
}

fn awaitRequestResult(io: std.Io, runtime: *runtime_mod.Runtime) !runtime_mod.RequestResult {
    for (0..2_000) |_| {
        if (runtime.popRequestResult()) |result| return result;
        try std.Io.sleep(io, .fromMilliseconds(1), .awake);
    }
    return error.MissingRequestResult;
}

fn expectRequestIdentity(result: *const runtime_mod.RequestResult, endpoint: types.Endpoint, req_id: @import("protocol/message.zig").ReqId, kind: types.RequestKind) !void {
    try std.testing.expect(types.RequestKeyContext.eql(.{}, result.key, .init(endpoint, req_id)));
    try std.testing.expectEqual(kind, result.kind);
}

test "Runtime public handle is opaque" {
    switch (@typeInfo(runtime_mod.Runtime)) {
        .@"opaque" => {},
        else => return error.RuntimeIsNotOpaque,
    }
}

const TransportCancellationContext = struct {
    io: std.Io,
    transport: *transport_mod.Transport,
    allow_send: std.atomic.Value(bool) = .init(false),
    send_error: ?anyerror = null,
    next_error: ?anyerror = null,
};

fn consumeCancellationInTransport(context: *TransportCancellationContext) void {
    while (!context.allow_send.load(.acquire)) std.atomic.spinLoopHint();
    context.transport.sender().send(.{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 9 } }, &.{1}) catch |err| {
        context.send_error = err;
    };
    std.Io.sleep(context.io, .fromMilliseconds(1), .awake) catch |err| {
        context.next_error = err;
    };
}

const CancellationObserver = struct {
    io: std.Io,
    queue: std.Io.Queue(u8),
    buffer: [1]u8 = undefined,
    observed: std.atomic.Value(bool) = .init(false),

    fn init(self: *CancellationObserver, io: std.Io) void {
        self.* = .{
            .io = io,
            .queue = undefined,
        };
        self.queue = .init(&self.buffer);
    }

    fn wait(self: *CancellationObserver) void {
        _ = self.queue.getOne(self.io) catch |err| switch (err) {
            error.Canceled => self.observed.store(true, .release),
            error.Closed => unreachable,
        };
    }
};

const CancelTransportContext = struct {
    io: std.Io,
    group: *std.Io.Group,
    completed: std.atomic.Value(bool) = .init(false),
};

fn cancelTransportTask(context: *CancelTransportContext) void {
    context.group.cancel(context.io);
    context.completed.store(true, .release);
}

test "Transport send re-arms consumed runtime cancellation" {
    const alloc = std.testing.allocator;
    var threaded = std.Io.Threaded.init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var transport = try transport_mod.Transport.init(io, .{
        .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } },
    });
    defer transport.deinit();

    var context = TransportCancellationContext{ .io = io, .transport = &transport };
    var group: std.Io.Group = .init;
    var group_started = false;
    var cancel_thread: ?std.Thread = null;
    var cancel_thread_joined = false;
    try group.concurrent(io, consumeCancellationInTransport, .{&context});
    group_started = true;
    defer {
        context.allow_send.store(true, .release);
        if (cancel_thread) |thread| {
            if (!cancel_thread_joined) thread.join();
        } else if (group_started) {
            group.cancel(io);
        }
        if (group_started) group.await(io) catch {};
    }
    var observer: CancellationObserver = undefined;
    observer.init(io);
    try group.concurrent(io, CancellationObserver.wait, .{&observer});
    var cancel_context = CancelTransportContext{ .io = io, .group = &group };
    cancel_thread = try std.Thread.spawn(.{}, cancelTransportTask, .{&cancel_context});
    try awaitFlag(&observer.observed, error.CancellationWasNotObserved);
    context.allow_send.store(true, .release);
    try awaitFlag(&cancel_context.completed, error.CancellationDidNotComplete);
    cancel_thread.?.join();
    cancel_thread_joined = true;
    try group.await(io);
    group_started = false;

    try std.testing.expectEqual(error.Canceled, context.send_error.?);
    try std.testing.expectEqual(error.Canceled, context.next_error.?);
}

const RuntimePingContext = struct {
    runtime: *runtime_mod.Runtime,
    remote_id: types.NodeId,
    remote_pubkey: [33]u8,
    remote_address: types.Address,
    result_error: ?anyerror = null,
};

fn sendRuntimePing(context: *RuntimePingContext) void {
    _ = context.runtime.sendPing(context.remote_id, &context.remote_pubkey, context.remote_address, 0) catch |err| {
        context.result_error = err;
        return;
    };
}

test "Runtime send cancellation closes drains joins and releases command state" {
    const alloc = std.testing.allocator;
    var threaded = std.Io.Threaded.init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x6d} ** 32));
    const local_id = try enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&local_key));
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x6e} ** 32));
    const remote_pubkey = secp.compressedPubkey(&remote_key);
    const remote_id = try enr.nodeIdFromCompressedPubkey(&remote_pubkey);
    const runtime = try runtime_mod.Runtime.init(io, alloc, .{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
        .local_node_id = local_id,
        .rate_limiter = null,
        .limits = .{ .max_active_requests = 2, .max_queued_requests = 2, .event_capacity = 2, .command_capacity = 2 },
    }, .{});
    defer runtime.deinit();
    var gate = transport_mod.Testing.SendGate{};
    runtime_mod.Testing.setSendGate(runtime, &gate);
    var run_error: ?anyerror = null;
    var runtime_group: std.Io.Group = .init;
    var runtime_group_started = false;
    var api_group: std.Io.Group = .init;
    var api_group_started = false;
    var cancel_thread: ?std.Thread = null;
    var cancel_thread_joined = false;
    try runtime_group.concurrent(io, runRuntime, .{ runtime, &run_error });
    runtime_group_started = true;
    defer {
        gate.proceed.store(true, .release);
        if (cancel_thread) |thread| {
            if (!cancel_thread_joined) thread.join();
        } else if (runtime_group_started) {
            runtime_group.cancel(io);
        }
        if (api_group_started) {
            api_group.cancel(io);
            api_group.await(io) catch {};
        }
        if (runtime_group_started) runtime_group.await(io) catch {};
    }
    var observer: CancellationObserver = undefined;
    observer.init(io);
    try runtime_group.concurrent(io, CancellationObserver.wait, .{&observer});
    for (0..10_000) |_| {
        if (runtime.isRunning()) break;
        try std.Thread.yield();
    } else return error.RuntimeDidNotStart;

    var ping_context = RuntimePingContext{
        .runtime = runtime,
        .remote_id = remote_id,
        .remote_pubkey = remote_pubkey,
        .remote_address = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 9399 } },
    };
    try api_group.concurrent(io, sendRuntimePing, .{&ping_context});
    api_group_started = true;
    try awaitFlag(&gate.entered, error.RuntimeDidNotEnter);

    var cancel_context = CancelTransportContext{ .io = io, .group = &runtime_group };
    cancel_thread = try std.Thread.spawn(.{}, cancelTransportTask, .{&cancel_context});
    try awaitFlag(&observer.observed, error.CancellationWasNotObserved);
    gate.proceed.store(true, .release);
    try awaitFlag(&cancel_context.completed, error.CancellationDidNotComplete);
    cancel_thread.?.join();
    cancel_thread_joined = true;
    try api_group.await(io);
    api_group_started = false;
    try runtime_group.await(io);
    runtime_group_started = false;

    try std.testing.expectEqual(error.Canceled, ping_context.result_error.?);
    try std.testing.expectEqual(error.Canceled, run_error.?);
    try std.testing.expect(runtime.isClosed());
    try std.testing.expect(!runtime.isRunning());
    const counts = runtime_mod.Testing.activeAndPermitCount(runtime);
    try std.testing.expectEqual(@as(usize, 0), counts.active);
    try std.testing.expectEqual(@as(usize, 0), counts.permits);
}

test "actor cancellation closes command intake before draining" {
    const alloc = std.testing.allocator;
    var threaded = std.Io.Threaded.init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const runtime = try initTestRuntime(io, alloc, 0x73, .{ .max_active_requests = 4, .max_queued_requests = 4, .event_capacity = 4, .command_capacity = 4 }, .{});
    defer runtime.deinit();
    var gate = runtime_mod.Testing.CommandGate{};
    runtime_mod.Testing.setCommandGate(runtime, &gate);
    try runtime_mod.Testing.putMaintenance(runtime);
    var loop_error: ?anyerror = null;
    var group: std.Io.Group = .init;
    var group_started = false;
    var cancel_thread: ?std.Thread = null;
    var cancel_thread_joined = false;
    try group.concurrent(io, runActorLoop, .{ runtime, &loop_error });
    group_started = true;
    defer {
        gate.proceed.store(true, .release);
        if (cancel_thread) |thread| {
            if (!cancel_thread_joined) thread.join();
        } else if (group_started) {
            group.cancel(io);
        }
        if (group_started) group.await(io) catch {};
    }
    var observer: CancellationObserver = undefined;
    observer.init(io);
    try group.concurrent(io, CancellationObserver.wait, .{&observer});
    try std.testing.expect(!runtime.isClosed());
    try awaitFlag(&gate.entered, error.RuntimeDidNotEnter);
    var cancel_context = CancelTransportContext{ .io = io, .group = &group };
    cancel_thread = try std.Thread.spawn(.{}, cancelTransportTask, .{&cancel_context});
    try awaitFlag(&observer.observed, error.CancellationWasNotObserved);
    gate.proceed.store(true, .release);
    try awaitFlag(&cancel_context.completed, error.CancellationDidNotComplete);
    cancel_thread.?.join();
    cancel_thread_joined = true;
    try group.await(io);
    group_started = false;
    try std.testing.expectEqual(error.Canceled, loop_error.?);
    try std.testing.expect(runtime.isClosed());
    try std.testing.expectError(error.Closed, runtime_mod.Testing.putMaintenance(runtime));
}

test "Runtime cancellation drains accepted owned commands and replies" {
    const alloc = std.testing.allocator;
    var threaded = std.Io.Threaded.init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const runtime = try initTestRuntime(io, alloc, 0x72, .{ .max_active_requests = 4, .max_queued_requests = 4, .event_capacity = 4, .command_capacity = 4 }, .{ .maintenance_interval_ms = 1 });
    defer runtime.deinit();
    var gate: runtime_mod.Testing.CancellationGate = undefined;
    gate.init();
    runtime_mod.Testing.setCancellationGate(runtime, &gate);
    try runtime_mod.Testing.putMaintenance(runtime);
    var reply_buffer: [1]runtime_mod.Testing.EnrAdmissionResult = undefined;
    var reply = runtime_mod.Testing.EnrAdmissionReply.init(&reply_buffer);
    const owned = try alloc.dupe(u8, &.{0xff});
    try runtime_mod.Testing.enqueueAddEnr(runtime, owned, &reply);

    var run_error: ?anyerror = null;
    var reply_observed: std.atomic.Value(bool) = .init(false);
    var caller_group: std.Io.Group = .init;
    var caller_group_started = false;
    var cancel_thread: ?std.Thread = null;
    var cancel_thread_joined = false;
    try caller_group.concurrent(io, runRuntime, .{ runtime, &run_error });
    caller_group_started = true;
    defer {
        gate.release(io);
        if (cancel_thread) |thread| {
            if (!cancel_thread_joined) thread.join();
        } else if (caller_group_started) {
            caller_group.cancel(io);
        }
        if (caller_group_started) caller_group.await(io) catch {};
    }
    try caller_group.concurrent(io, awaitBoolReply, .{ io, &reply, &reply_observed });
    for (0..10_000) |_| {
        if (runtime.isRunning() and gate.entered.load(.acquire)) break;
        try std.Thread.yield();
    } else return error.RuntimeDidNotEnter;
    var cancel_context = CancelTransportContext{ .io = io, .group = &caller_group };
    cancel_thread = try std.Thread.spawn(.{}, cancelTransportTask, .{&cancel_context});
    try awaitFlag(&gate.cancellation_observed, error.CancellationWasNotObserved);
    cancel_thread.?.join();
    cancel_thread_joined = true;
    try caller_group.await(io);
    caller_group_started = false;
    try std.testing.expectEqual(error.Canceled, run_error.?);
    try std.testing.expect(reply_observed.load(.acquire));
    try std.testing.expect(runtime.isClosed());
    try std.testing.expect(!runtime.isRunning());
}

test "Runtime command admission is bounded nonblocking and drains accepted ownership" {
    const alloc = std.testing.allocator;
    var threaded = std.Io.Threaded.init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const command_capacity = 2;
    const producer_count = 8;
    const runtime = try initTestRuntime(io, alloc, 0x7f, .{
        .max_active_requests = 2,
        .max_queued_requests = 2,
        .event_capacity = 2,
        .command_capacity = command_capacity,
    }, .{ .maintenance_interval_ms = 60_000 });
    defer runtime.deinit();
    var gate = runtime_mod.Testing.CommandGate{};
    runtime_mod.Testing.setCommandGate(runtime, &gate);
    try runtime_mod.Testing.putMaintenance(runtime);

    var run_error: ?anyerror = null;
    var runtime_group: std.Io.Group = .init;
    var runtime_group_started = false;
    var runtime_group_awaited = false;
    var producer_group: std.Io.Group = .init;
    var producer_group_started = false;
    var producer_group_awaited = false;
    try runtime_group.concurrent(io, runRuntime, .{ runtime, &run_error });
    runtime_group_started = true;
    defer {
        gate.proceed.store(true, .release);
        if (runtime_group_started and !runtime_group_awaited) runtime.stop();
        if (producer_group_started and !producer_group_awaited) {
            producer_group.await(io) catch {};
            producer_group_started = false;
            producer_group_awaited = true;
        }
        if (runtime_group_started and !runtime_group_awaited) {
            runtime_group.await(io) catch {};
            runtime_group_started = false;
            runtime_group_awaited = true;
        }
    }
    for (0..10_000) |_| {
        if (gate.entered.load(.acquire)) break;
        try std.Thread.yield();
    } else return error.RuntimeDidNotEnter;

    var producers: [producer_count]OwnedCommandProducer = undefined;
    for (&producers) |*producer| {
        producer.* = .{ .io = io, .allocator = alloc, .runtime = runtime };
        try producer_group.concurrent(io, enqueueOwnedCommand, .{producer});
        producer_group_started = true;
    }
    for (0..10_000) |_| {
        var attempted: usize = 0;
        for (&producers) |*producer| if (producer.attempted.load(.acquire)) {
            attempted += 1;
        };
        if (attempted == producer_count) break;
        try std.Thread.yield();
    } else return error.ProducersDidNotAttempt;

    var accepted: usize = 0;
    for (&producers) |*producer| if (producer.accepted) {
        accepted += 1;
    };
    try std.testing.expectEqual(@as(usize, command_capacity), accepted);
    runtime.stop();
    gate.proceed.store(true, .release);
    try producer_group.await(io);
    producer_group_started = false;
    producer_group_awaited = true;
    try runtime_group.await(io);
    runtime_group_started = false;
    runtime_group_awaited = true;

    for (&producers) |*producer| {
        if (producer.accepted) {
            try std.testing.expect(producer.completed);
            try std.testing.expect(producer.result_error == null);
        } else {
            try std.testing.expectEqual(error.CommandQueueFull, producer.result_error.?);
        }
    }
    try std.testing.expect(run_error == null);
    const counts = runtime_mod.Testing.activeAndPermitCount(runtime);
    try std.testing.expectEqual(@as(usize, 0), counts.active);
    try std.testing.expectEqual(@as(usize, 0), counts.permits);
}

test "repeated maintenance wake is coalesced and stale queued wake is harmless" {
    const alloc = std.testing.allocator;
    var threaded = std.Io.Threaded.init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x79} ** 32));
    const local_id = try enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&local_key));
    const runtime = try runtime_mod.Runtime.init(io, alloc, .{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
        .local_node_id = local_id,
        .request_timeout_ms = 0,
        .request_retries = 0,
        .rate_limiter = null,
        .limits = .{
            .max_active_requests = 4,
            .max_queued_requests = 4,
            .event_capacity = 4,
            .command_capacity = 2,
        },
    }, .{ .maintenance_interval_ms = 60_000 });
    var running = RunningRuntime.init(io);
    defer running.deinit();
    try running.start(runtime);
    try running.awaitStarted();

    const first_key = try secp.keyPairFromSecret(&([_]u8{0x7a} ** 32));
    const first_pubkey = secp.compressedPubkey(&first_key);
    const first_id = try enr.nodeIdFromCompressedPubkey(&first_pubkey);
    const first_address = types.Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 10 }, .port = 19079 } };
    _ = try runtime.sendPing(first_id, &first_pubkey, first_address, 0);
    const initial_counts = runtime_mod.Testing.activeAndPermitCount(runtime);
    try std.testing.expectEqual(@as(usize, 1), initial_counts.active);
    try std.testing.expectEqual(@as(usize, 1), initial_counts.permits);

    var gate = runtime_mod.Testing.CommandGate{};
    defer gate.proceed.store(true, .release);
    runtime_mod.Testing.setCommandGate(runtime, &gate);
    var blocker_buffer: [1]runtime_mod.Testing.EnrAdmissionResult = undefined;
    var blocker_reply = runtime_mod.Testing.EnrAdmissionReply.init(&blocker_buffer);
    try runtime_mod.Testing.enqueueAddEnr(runtime, try alloc.dupe(u8, &.{0xff}), &blocker_reply);
    for (0..10_000) |_| {
        if (gate.entered.load(.acquire)) break;
        try std.Thread.yield();
    } else return error.RuntimeDidNotEnter;

    const second_key = try secp.keyPairFromSecret(&([_]u8{0x7b} ** 32));
    const second_pubkey = secp.compressedPubkey(&second_key);
    const second_id = try enr.nodeIdFromCompressedPubkey(&second_pubkey);
    const second_endpoint = types.Endpoint{
        .node_id = second_id,
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 11 }, .port = 19080 } },
    };
    var ping_buffer: [1]runtime_mod.Testing.PingResult = undefined;
    var ping_reply = runtime_mod.Testing.PingReply.init(&ping_buffer);
    try runtime_mod.Testing.enqueueSendPing(runtime, second_endpoint, second_pubkey, &ping_reply);
    try runtime_mod.Testing.putMaintenance(runtime);
    try runtime_mod.Testing.putMaintenance(runtime);

    gate.proceed.store(true, .release);
    const blocker_result = try blocker_reply.getOneUncancelable(io);
    try std.testing.expect(!(try blocker_result));
    const ping_result = try ping_reply.getOneUncancelable(io);
    _ = try ping_result;
    var barrier_buffer: [1]runtime_mod.Testing.EnrAdmissionResult = undefined;
    var barrier_reply = runtime_mod.Testing.EnrAdmissionReply.init(&barrier_buffer);
    try runtime_mod.Testing.enqueueAddEnr(runtime, try alloc.dupe(u8, &.{0xff}), &barrier_reply);
    const barrier_result = try barrier_reply.getOneUncancelable(io);
    try std.testing.expect(!(try barrier_result));

    const counts = runtime_mod.Testing.activeAndPermitCount(runtime);
    try std.testing.expectEqual(@as(usize, 0), counts.active);
    try std.testing.expectEqual(@as(usize, 0), counts.permits);
    var saw_first = false;
    var saw_second = false;
    for (0..2) |_| {
        const result = runtime.popRequestResult() orelse return error.MissingTimeoutResult;
        try std.testing.expect(result.terminal == .timeout);
        try std.testing.expectEqual(types.RequestKind.ping, result.kind);
        if (std.mem.eql(u8, &first_id, &result.key.endpoint.node_id)) saw_first = true;
        if (std.mem.eql(u8, &second_id, &result.key.endpoint.node_id)) saw_second = true;
    }
    try std.testing.expect(saw_first);
    try std.testing.expect(saw_second);
    try std.testing.expect(runtime.popEvent() == null);

    try runtime_mod.Testing.enqueueStaleMaintenance(runtime);
    var stale_barrier_buffer: [1]runtime_mod.Testing.EnrAdmissionResult = undefined;
    var stale_barrier_reply = runtime_mod.Testing.EnrAdmissionReply.init(&stale_barrier_buffer);
    try runtime_mod.Testing.enqueueAddEnr(runtime, try alloc.dupe(u8, &.{0xff}), &stale_barrier_reply);
    const stale_barrier_result = try stale_barrier_reply.getOneUncancelable(io);
    try std.testing.expect(!(try stale_barrier_result));
    try std.testing.expect(runtime.popEvent() == null);

    running.stop();
    try running.await();
    try std.testing.expect(running.run_result == null);
}

test "failed maintenance enqueue rolls back pending state for retry" {
    const alloc = std.testing.allocator;
    var threaded = std.Io.Threaded.init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x7c} ** 32));
    const runtime = try runtime_mod.Runtime.init(io, alloc, .{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
        .local_node_id = try enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&local_key)),
        .request_timeout_ms = 0,
        .request_retries = 0,
        .rate_limiter = null,
        .limits = .{
            .max_active_requests = 2,
            .max_queued_requests = 2,
            .event_capacity = 2,
            .command_capacity = 1,
        },
    }, .{ .maintenance_interval_ms = 60_000 });
    defer runtime.deinit();

    var first_buffer: [1]runtime_mod.Testing.EnrAdmissionResult = undefined;
    var first_reply = runtime_mod.Testing.EnrAdmissionReply.init(&first_buffer);
    try runtime_mod.Testing.enqueueAddEnr(runtime, try alloc.dupe(u8, &.{0xff}), &first_reply);
    var gate = runtime_mod.Testing.CommandGate{};
    defer gate.proceed.store(true, .release);
    runtime_mod.Testing.setCommandGate(runtime, &gate);
    var loop_error: ?anyerror = null;
    var loop_group: std.Io.Group = .init;
    var loop_awaited = false;
    defer if (!loop_awaited) {
        gate.proceed.store(true, .release);
        runtime.stop();
        loop_group.await(io) catch {};
    };
    try loop_group.concurrent(io, runActorLoop, .{ runtime, &loop_error });
    for (0..10_000) |_| {
        if (gate.entered.load(.acquire)) break;
        try std.Thread.yield();
    } else return error.RuntimeDidNotEnter;

    var second_buffer: [1]runtime_mod.Testing.EnrAdmissionResult = undefined;
    var second_reply = runtime_mod.Testing.EnrAdmissionReply.init(&second_buffer);
    try runtime_mod.Testing.enqueueAddEnr(runtime, try alloc.dupe(u8, &.{0xff}), &second_reply);
    try std.testing.expectError(error.CommandQueueFull, runtime_mod.Testing.putMaintenance(runtime));
    try std.testing.expectError(error.CommandQueueFull, runtime_mod.Testing.putMaintenance(runtime));

    gate.proceed.store(true, .release);
    const first_result = try first_reply.getOneUncancelable(io);
    try std.testing.expect(!(try first_result));
    const second_result = try second_reply.getOneUncancelable(io);
    try std.testing.expect(!(try second_result));
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x7d} ** 32));
    const remote_pubkey = secp.compressedPubkey(&remote_key);
    const remote_id = try enr.nodeIdFromCompressedPubkey(&remote_pubkey);
    var ping_buffer: [1]runtime_mod.Testing.PingResult = undefined;
    var ping_reply = runtime_mod.Testing.PingReply.init(&ping_buffer);
    try runtime_mod.Testing.enqueueSendPing(runtime, .{
        .node_id = remote_id,
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 12 }, .port = 19081 } },
    }, remote_pubkey, &ping_reply);
    _ = try (try ping_reply.getOneUncancelable(io));
    try runtime_mod.Testing.putMaintenance(runtime);
    var barrier_buffer: [1]runtime_mod.Testing.EnrAdmissionResult = undefined;
    var barrier_reply = runtime_mod.Testing.EnrAdmissionReply.init(&barrier_buffer);
    for (0..10_000) |_| {
        runtime_mod.Testing.enqueueAddEnr(runtime, try alloc.dupe(u8, &.{0xff}), &barrier_reply) catch |err| switch (err) {
            error.CommandQueueFull => {
                try std.Thread.yield();
                continue;
            },
            else => return err,
        };
        break;
    } else return error.MaintenanceDidNotRun;
    const barrier_result = try barrier_reply.getOneUncancelable(io);
    try std.testing.expect(!(try barrier_result));
    const timeout_result = runtime.popRequestResult() orelse return error.MissingTimeoutResult;
    try std.testing.expect(timeout_result.terminal == .timeout);
    try std.testing.expectEqualSlices(u8, &remote_id, &timeout_result.key.endpoint.node_id);

    runtime.stop();
    try loop_group.await(io);
    loop_awaited = true;
    try std.testing.expect(loop_error == null);
}

test "normal stop drains accepted owned commands and replies" {
    const alloc = std.testing.allocator;
    var threaded = std.Io.Threaded.init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const runtime = try initTestRuntime(io, alloc, 0x76, .{ .max_active_requests = 2, .max_queued_requests = 2, .event_capacity = 2, .command_capacity = 2 }, .{});
    defer runtime.deinit();
    var reply_buffer: [1]runtime_mod.Testing.EnrAdmissionResult = undefined;
    var reply = runtime_mod.Testing.EnrAdmissionReply.init(&reply_buffer);
    try runtime_mod.Testing.enqueueAddEnr(runtime, try alloc.dupe(u8, &.{0xff}), &reply);
    runtime.stop();
    try runtime_mod.Testing.actorLoop(runtime);
    const result = try reply.getOneUncancelable(io);
    try std.testing.expect(!(try result));
}

test "reliable lookup results survive a full event outbox and release capacity on take" {
    const alloc = std.testing.allocator;
    var threaded = std.Io.Threaded.init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const runtime = try initTestRuntime(io, alloc, 0x81, .{
        .max_active_requests = 2,
        .max_queued_requests = 2,
        .event_capacity = 1,
        .command_capacity = 4,
        .lookup_result_capacity = 1,
    }, .{ .maintenance_interval_ms = 60_000 });
    var running = RunningRuntime.init(io);
    defer running.deinit();
    try running.start(runtime);
    try running.awaitStarted();

    const local_key = try secp.keyPairFromSecret(&([_]u8{0x81} ** 32));
    var local_builder = enr.Builder.init(alloc, local_key, 1);
    const local_enr = try local_builder.encode();
    defer alloc.free(local_enr);
    try runtime.setLocalEnr(local_enr);

    const first_target = [_]u8{0x82} ** 32;
    const first_id = try runtime.startLookup(first_target);
    try std.testing.expectError(error.LookupResultCapacityExceeded, runtime.startLookup([_]u8{0x83} ** 32));

    const snapshot = try runtime.metricsSnapshot();
    try std.testing.expectEqual(@as(u64, 1), snapshot.lookup_count);
    try std.testing.expectEqual(@as(usize, 0), snapshot.active_lookup_count);
    try std.testing.expectEqual(@as(u64, 0), snapshot.dropped_event_count);
    var classified_total: u64 = 0;
    for (snapshot.dropped_event_count_by_kind) |count| classified_total += count;
    try std.testing.expectEqual(snapshot.dropped_event_count, classified_total);
    const repeated_snapshot = try runtime.metricsSnapshot();
    try std.testing.expectEqual(snapshot, repeated_snapshot);

    var blocker = runtime.popEvent() orelse return error.MissingOutboxBlocker;
    defer blocker.deinit(alloc);
    try std.testing.expect(blocker == .local_enr_updated);
    try std.testing.expect(runtime.popEvent() == null);

    const first = runtime.popLookupResult() orelse return error.MissingLookupResult;
    try std.testing.expectEqual(first_id, first.lookup_id);
    try std.testing.expectEqualSlices(u8, &first_target, &first.target);
    try std.testing.expectEqual(runtime_mod.LookupTerminalReason.completed, first.reason);
    try std.testing.expectEqual(@as(usize, 0), first.enrs.slice().len);
    try std.testing.expect(runtime.popLookupResult() == null);

    const second_id = try runtime.startLookup([_]u8{0x84} ** 32);
    try std.testing.expectError(error.LookupResultCapacityExceeded, runtime.startLookup([_]u8{0x85} ** 32));
    const second = try runtime.nextLookupResult();
    try std.testing.expectEqual(second_id, second.lookup_id);
    try std.testing.expectEqual(runtime_mod.LookupTerminalReason.completed, second.reason);

    const third_id = try runtime.startLookup([_]u8{0x86} ** 32);
    const third = runtime.popLookupResult() orelse return error.MissingLookupResult;
    try std.testing.expectEqual(third_id, third.lookup_id);

    running.stop();
    try running.await();
    try std.testing.expect(running.run_result == null);
    try std.testing.expectError(error.Closed, runtime.nextLookupResult());
}

test "lookup result capacity rejects before actor insertion or network work and shutdown is terminal" {
    const alloc = std.testing.allocator;
    var threaded = std.Io.Threaded.init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const runtime = try initTestRuntime(io, alloc, 0x87, .{
        .max_active_requests = 2,
        .max_queued_requests = 2,
        .event_capacity = 4,
        .command_capacity = 4,
        .lookup_result_capacity = 1,
    }, .{ .maintenance_interval_ms = 60_000 });
    var running = RunningRuntime.init(io);
    defer running.deinit();
    try running.start(runtime);
    try running.awaitStarted();

    const first_id = try runtime.startLookup([_]u8{0x88} ** 32);
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x89} ** 32));
    const remote_pubkey = secp.compressedPubkey(&remote_key);
    const remote_id = try enr.nodeIdFromCompressedPubkey(&remote_pubkey);
    const remote_address: types.Address = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 89 }, .port = 9089 } };
    var remote_builder = enr.Builder.init(alloc, remote_key, 1);
    remote_builder.ip = .{ 127, 0, 0, 89 };
    remote_builder.udp = 9089;
    const remote_enr = try remote_builder.encode();
    defer alloc.free(remote_enr);
    try std.testing.expect(try runtime.addNode(remote_id, &remote_pubkey, remote_address, remote_enr));

    const network_target = [_]u8{0x8a} ** 32;
    try std.testing.expectError(error.LookupResultCapacityExceeded, runtime.startLookup(network_target));
    var snapshot = try runtime.metricsSnapshot();
    try std.testing.expectEqual(@as(u64, 1), snapshot.lookup_count);
    try std.testing.expectEqual(@as(usize, 0), snapshot.active_lookup_count);
    try std.testing.expectEqual(@as(u64, 0), snapshot.sentMessageCount(metrics.MessageType.findnode));

    const first = runtime.popLookupResult() orelse return error.MissingLookupResult;
    try std.testing.expectEqual(first_id, first.lookup_id);
    const active_id = try runtime.startLookup(network_target);
    snapshot = try runtime.metricsSnapshot();
    try std.testing.expectEqual(@as(u64, 2), snapshot.lookup_count);
    try std.testing.expectEqual(@as(usize, 1), snapshot.active_lookup_count);
    try std.testing.expectEqual(@as(u64, 1), snapshot.sentMessageCount(metrics.MessageType.findnode));

    running.stop();
    try running.await();
    try std.testing.expect(running.run_result == null);
    const stopped = runtime.popLookupResult() orelse return error.MissingShutdownLookupResult;
    try std.testing.expectEqual(active_id, stopped.lookup_id);
    try std.testing.expectEqualSlices(u8, &network_target, &stopped.target);
    try std.testing.expectEqual(runtime_mod.LookupTerminalReason.runtime_stopped, stopped.reason);
    try std.testing.expect(runtime.popLookupResult() == null);
}

test "lookup timeout publishes a reliable timed out terminal result" {
    const alloc = std.testing.allocator;
    var threaded = std.Io.Threaded.init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x8b} ** 32));
    const runtime = try runtime_mod.Runtime.init(io, alloc, .{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
        .local_node_id = try enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&local_key)),
        .lookup_timeout_ms = 0,
        .rate_limiter = null,
        .limits = .{
            .max_active_requests = 2,
            .max_queued_requests = 2,
            .event_capacity = 2,
            .command_capacity = 4,
            .lookup_result_capacity = 1,
        },
    }, .{ .maintenance_interval_ms = 60_000 });
    var running = RunningRuntime.init(io);
    defer running.deinit();
    try running.start(runtime);
    try running.awaitStarted();

    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x8c} ** 32));
    const remote_pubkey = secp.compressedPubkey(&remote_key);
    const remote_id = try enr.nodeIdFromCompressedPubkey(&remote_pubkey);
    const remote_address: types.Address = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 140 }, .port = 9140 } };
    var remote_builder = enr.Builder.init(alloc, remote_key, 1);
    remote_builder.ip = .{ 127, 0, 0, 140 };
    remote_builder.udp = 9140;
    const remote_enr = try remote_builder.encode();
    defer alloc.free(remote_enr);
    try std.testing.expect(try runtime.addNode(remote_id, &remote_pubkey, remote_address, remote_enr));
    const lookup_id = try runtime.startLookup([_]u8{0x8d} ** 32);
    try runtime_mod.Testing.putMaintenance(runtime);
    const snapshot = try runtime.metricsSnapshot();
    try std.testing.expectEqual(@as(usize, 0), snapshot.active_lookup_count);

    const result = runtime.popLookupResult() orelse return error.MissingTimedOutLookupResult;
    try std.testing.expectEqual(lookup_id, result.lookup_id);
    try std.testing.expectEqual(runtime_mod.LookupTerminalReason.timed_out, result.reason);
}

fn errorSetOf(comptime function: anytype) type {
    const return_type = @typeInfo(@TypeOf(function)).@"fn".return_type.?;
    return @typeInfo(return_type).error_union.error_set;
}

fn expectErrorSet(comptime function: anytype, comptime expected: type) void {
    const actual = errorSetOf(function);
    if (actual == anyerror) @compileError("public Runtime API leaks anyerror");
    if (actual != expected) @compileError("unexpected Runtime API error set");
}

test "public Runtime APIs expose exact operation error contracts" {
    comptime {
        expectErrorSet(runtime_mod.Runtime.init, runtime_mod.Runtime.InitError);
        expectErrorSet(runtime_mod.Runtime.run, runtime_mod.Runtime.RunError);
        expectErrorSet(runtime_mod.Runtime.nextEvent, runtime_mod.Runtime.EventError);
        expectErrorSet(runtime_mod.Runtime.nextLookupResult, runtime_mod.Runtime.LookupResultError);
        expectErrorSet(runtime_mod.Runtime.nextRequestResult, runtime_mod.Runtime.RequestResultError);
        expectErrorSet(runtime_mod.Runtime.addNode, runtime_mod.Runtime.EnrAdmissionError);
        expectErrorSet(runtime_mod.Runtime.addEnr, runtime_mod.Runtime.EnrAdmissionError);
        expectErrorSet(runtime_mod.Runtime.setLocalEnr, runtime_mod.Runtime.SetLocalEnrError);
        expectErrorSet(runtime_mod.Runtime.sendPing, runtime_mod.Runtime.RequestError);
        expectErrorSet(runtime_mod.Runtime.sendFindNode, runtime_mod.Runtime.FindNodeError);
        expectErrorSet(runtime_mod.Runtime.sendTalkRequest, runtime_mod.Runtime.TalkRequestError);
        expectErrorSet(runtime_mod.Runtime.sendTalkResponse, runtime_mod.Runtime.TalkResponseError);
        expectErrorSet(runtime_mod.Runtime.startLookup, runtime_mod.Runtime.LookupError);
        expectErrorSet(runtime_mod.Runtime.cancelRequest, runtime_mod.Runtime.CommandError);
        expectErrorSet(runtime_mod.Runtime.startRandomLookup, runtime_mod.Runtime.LookupError);
        expectErrorSet(runtime_mod.Runtime.metricsSnapshot, runtime_mod.Runtime.CommandError);
        expectErrorSet(runtime_mod.Runtime.localEnr, runtime_mod.Runtime.CommandError);
        expectErrorSet(runtime_mod.Runtime.peerEnr, runtime_mod.Runtime.CommandError);
        expectErrorSet(runtime_mod.Runtime.localEnrSeq, runtime_mod.Runtime.CommandError);
    }
}

test "request result capacity rejects before actor work and pop releases one slot" {
    const alloc = std.testing.allocator;
    var threaded = std.Io.Threaded.init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const runtime = try initTestRuntime(io, alloc, 0x91, .{
        .max_active_requests = 2,
        .max_queued_requests = 2,
        .event_capacity = 2,
        .command_capacity = 4,
        .request_result_capacity = 1,
    }, .{ .maintenance_interval_ms = 60_000 });
    var running = RunningRuntime.init(io);
    defer running.deinit();
    try running.start(runtime);
    try running.awaitStarted();

    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x92} ** 32));
    const remote_pubkey = secp.compressedPubkey(&remote_key);
    const remote_id = try enr.nodeIdFromCompressedPubkey(&remote_pubkey);
    const endpoint = types.Endpoint{
        .node_id = remote_id,
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 92 }, .port = 9092 } },
    };
    const first_id = try runtime.sendPing(remote_id, &remote_pubkey, endpoint.addr, 0);
    try std.testing.expectError(error.RequestResultCapacityExceeded, runtime.sendPing(remote_id, &remote_pubkey, endpoint.addr, 1));
    var counts = runtime_mod.Testing.activeQueuedAndPermitCount(runtime);
    try std.testing.expectEqual(@as(usize, 1), counts.active);
    try std.testing.expectEqual(@as(usize, 0), counts.queued);
    try std.testing.expectEqual(@as(usize, 1), counts.permits);
    var snapshot = try runtime.metricsSnapshot();
    try std.testing.expectEqual(@as(u64, 1), snapshot.sentMessageCount(.ping));

    try std.testing.expect(try runtime.cancelRequest(remote_id, endpoint.addr, first_id));
    try std.testing.expectError(error.RequestResultCapacityExceeded, runtime.sendPing(remote_id, &remote_pubkey, endpoint.addr, 2));
    const canceled = runtime.popRequestResult() orelse return error.MissingCanceledRequestResult;
    try expectRequestIdentity(&canceled, endpoint, first_id, .ping);
    try std.testing.expect(canceled.terminal == .canceled);
    try std.testing.expect(runtime.popRequestResult() == null);

    const second_id = try runtime.sendPing(remote_id, &remote_pubkey, endpoint.addr, 3);
    try std.testing.expect(try runtime.cancelRequest(remote_id, endpoint.addr, second_id));
    const second = try runtime.nextRequestResult();
    try expectRequestIdentity(&second, endpoint, second_id, .ping);
    try std.testing.expect(second.terminal == .canceled);
    try std.testing.expect(runtime.popRequestResult() == null);
    counts = runtime_mod.Testing.activeQueuedAndPermitCount(runtime);
    try std.testing.expectEqual(@as(usize, 0), counts.active);
    try std.testing.expectEqual(@as(usize, 0), counts.queued);
    try std.testing.expectEqual(@as(usize, 0), counts.permits);
    snapshot = try runtime.metricsSnapshot();
    try std.testing.expectEqual(@as(u64, 2), snapshot.sentMessageCount(.ping));

    running.stop();
    try running.await();
}

test "reliable request results cover active and queued cancellation exactly once" {
    const alloc = std.testing.allocator;
    var threaded = std.Io.Threaded.init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const runtime = try initTestRuntime(io, alloc, 0x93, .{
        .max_active_requests = 2,
        .max_queued_requests = 2,
        .max_queued_requests_per_endpoint = 2,
        .event_capacity = 2,
        .command_capacity = 4,
        .request_result_capacity = 2,
    }, .{ .maintenance_interval_ms = 60_000 });
    var running = RunningRuntime.init(io);
    defer running.deinit();
    try running.start(runtime);
    try running.awaitStarted();

    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x94} ** 32));
    const remote_pubkey = secp.compressedPubkey(&remote_key);
    const endpoint = types.Endpoint{
        .node_id = try enr.nodeIdFromCompressedPubkey(&remote_pubkey),
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 94 }, .port = 9094 } },
    };
    const active_id = try runtime.sendPing(endpoint.node_id, &remote_pubkey, endpoint.addr, 0);
    const queued_id = try runtime.sendTalkRequest(endpoint.node_id, &remote_pubkey, endpoint.addr, "proto", "queued");
    var counts = runtime_mod.Testing.activeQueuedAndPermitCount(runtime);
    try std.testing.expectEqual(@as(usize, 1), counts.active);
    try std.testing.expectEqual(@as(usize, 1), counts.queued);
    try std.testing.expectEqual(@as(usize, 1), counts.permits);

    try std.testing.expect(try runtime.cancelRequest(endpoint.node_id, endpoint.addr, queued_id));
    try std.testing.expect(try runtime.cancelRequest(endpoint.node_id, endpoint.addr, active_id));
    const first = runtime.popRequestResult() orelse return error.MissingCanceledRequestResult;
    const second = runtime.popRequestResult() orelse return error.MissingCanceledRequestResult;
    try std.testing.expect(first.terminal == .canceled);
    try std.testing.expect(second.terminal == .canceled);
    var saw_active = false;
    var saw_queued = false;
    for ([_]runtime_mod.RequestResult{ first, second }) |result| {
        if (types.RequestKeyContext.eql(.{}, result.key, .init(endpoint, active_id))) {
            try std.testing.expectEqual(types.RequestKind.ping, result.kind);
            saw_active = true;
        } else if (types.RequestKeyContext.eql(.{}, result.key, .init(endpoint, queued_id))) {
            try std.testing.expectEqual(types.RequestKind.talkreq, result.kind);
            saw_queued = true;
        } else return error.UnexpectedRequestResult;
    }
    try std.testing.expect(saw_active and saw_queued);
    try std.testing.expect(runtime.popRequestResult() == null);
    try std.testing.expect(!try runtime.cancelRequest(endpoint.node_id, endpoint.addr, active_id));
    try std.testing.expect(!try runtime.cancelRequest(endpoint.node_id, endpoint.addr, queued_id));
    counts = runtime_mod.Testing.activeQueuedAndPermitCount(runtime);
    try std.testing.expectEqual(@as(usize, 0), counts.active);
    try std.testing.expectEqual(@as(usize, 0), counts.queued);
    try std.testing.expectEqual(@as(usize, 0), counts.permits);

    running.stop();
    try running.await();
}

test "request timeout publishes one reliable terminal result" {
    const alloc = std.testing.allocator;
    var threaded = std.Io.Threaded.init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x95} ** 32));
    const runtime = try runtime_mod.Runtime.init(io, alloc, .{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
        .local_node_id = try enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&local_key)),
        .request_timeout_ms = 0,
        .request_retries = 0,
        .rate_limiter = null,
        .limits = .{
            .max_active_requests = 1,
            .max_queued_requests = 1,
            .event_capacity = 2,
            .command_capacity = 4,
            .request_result_capacity = 1,
        },
    }, .{ .maintenance_interval_ms = 60_000 });
    var running = RunningRuntime.init(io);
    defer running.deinit();
    try running.start(runtime);
    try running.awaitStarted();

    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x96} ** 32));
    const remote_pubkey = secp.compressedPubkey(&remote_key);
    const endpoint = types.Endpoint{
        .node_id = try enr.nodeIdFromCompressedPubkey(&remote_pubkey),
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 96 }, .port = 9096 } },
    };
    const req_id = try runtime.sendFindNode(endpoint.node_id, &remote_pubkey, endpoint.addr, &.{1});
    try runtime_mod.Testing.putMaintenance(runtime);
    _ = try runtime.metricsSnapshot();
    const result = runtime.popRequestResult() orelse return error.MissingTimeoutRequestResult;
    try expectRequestIdentity(&result, endpoint, req_id, .findnode);
    try std.testing.expect(result.terminal == .timeout);
    try std.testing.expect(runtime.popRequestResult() == null);
    const counts = runtime_mod.Testing.activeQueuedAndPermitCount(runtime);
    try std.testing.expectEqual(@as(usize, 0), counts.active);
    try std.testing.expectEqual(@as(usize, 0), counts.queued);
    try std.testing.expectEqual(@as(usize, 0), counts.permits);

    running.stop();
    try running.await();
}

test "Runtime shutdown terminates active and queued reliable requests" {
    const alloc = std.testing.allocator;
    var threaded = std.Io.Threaded.init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const runtime = try initTestRuntime(io, alloc, 0x97, .{
        .max_active_requests = 2,
        .max_queued_requests = 2,
        .max_queued_requests_per_endpoint = 2,
        .event_capacity = 2,
        .command_capacity = 4,
        .request_result_capacity = 2,
    }, .{ .maintenance_interval_ms = 60_000 });
    var running = RunningRuntime.init(io);
    defer running.deinit();
    try running.start(runtime);
    try running.awaitStarted();

    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x98} ** 32));
    const remote_pubkey = secp.compressedPubkey(&remote_key);
    const endpoint = types.Endpoint{
        .node_id = try enr.nodeIdFromCompressedPubkey(&remote_pubkey),
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 98 }, .port = 9098 } },
    };
    const active_id = try runtime.sendPing(endpoint.node_id, &remote_pubkey, endpoint.addr, 0);
    const queued_id = try runtime.sendFindNode(endpoint.node_id, &remote_pubkey, endpoint.addr, &.{1});
    const before = runtime_mod.Testing.activeQueuedAndPermitCount(runtime);
    try std.testing.expectEqual(@as(usize, 1), before.active);
    try std.testing.expectEqual(@as(usize, 1), before.queued);
    try std.testing.expectEqual(@as(usize, 1), before.permits);

    running.stop();
    try running.await();
    const first = runtime.popRequestResult() orelse return error.MissingShutdownRequestResult;
    const second = runtime.popRequestResult() orelse return error.MissingShutdownRequestResult;
    try std.testing.expect(first.terminal == .runtime_stopped);
    try std.testing.expect(second.terminal == .runtime_stopped);
    var saw_active = false;
    var saw_queued = false;
    for ([_]runtime_mod.RequestResult{ first, second }) |result| {
        if (types.RequestKeyContext.eql(.{}, result.key, .init(endpoint, active_id))) {
            try std.testing.expectEqual(types.RequestKind.ping, result.kind);
            saw_active = true;
        } else if (types.RequestKeyContext.eql(.{}, result.key, .init(endpoint, queued_id))) {
            try std.testing.expectEqual(types.RequestKind.findnode, result.kind);
            saw_queued = true;
        } else return error.UnexpectedRequestResult;
    }
    try std.testing.expect(saw_active and saw_queued);
    try std.testing.expect(runtime.popRequestResult() == null);
    try std.testing.expectError(error.Closed, runtime.nextRequestResult());
    const after = runtime_mod.Testing.activeQueuedAndPermitCount(runtime);
    try std.testing.expectEqual(@as(usize, 0), after.active);
    try std.testing.expectEqual(@as(usize, 0), after.queued);
    try std.testing.expectEqual(@as(usize, 0), after.permits);
}

test "request result reservation rolls back on actor send error" {
    const alloc = std.testing.allocator;
    var threaded = std.Io.Threaded.init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const runtime = try initTestRuntime(io, alloc, 0x99, .{
        .max_active_requests = 1,
        .max_queued_requests = 1,
        .event_capacity = 1,
        .command_capacity = 2,
        .request_result_capacity = 1,
    }, .{ .maintenance_interval_ms = 60_000 });
    var running = RunningRuntime.init(io);
    defer running.deinit();
    try running.start(runtime);
    try running.awaitStarted();

    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x9a} ** 32));
    const remote_pubkey = secp.compressedPubkey(&remote_key);
    const remote_id = try enr.nodeIdFromCompressedPubkey(&remote_pubkey);
    const unavailable = types.Address{ .ip6 = .{ .bytes = [_]u8{0} ** 15 ++ .{1}, .port = 9099 } };
    try std.testing.expectError(error.NoSocketForAddressFamily, runtime.sendPing(remote_id, &remote_pubkey, unavailable, 0));
    try std.testing.expect(runtime.popRequestResult() == null);

    const available = types.Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 99 }, .port = 9099 } };
    const req_id = try runtime.sendPing(remote_id, &remote_pubkey, available, 0);
    try std.testing.expect(try runtime.cancelRequest(remote_id, available, req_id));
    const result = runtime.popRequestResult() orelse return error.MissingCanceledRequestResult;
    try std.testing.expect(result.terminal == .canceled);
    const counts = runtime_mod.Testing.activeQueuedAndPermitCount(runtime);
    try std.testing.expectEqual(@as(usize, 0), counts.active);
    try std.testing.expectEqual(@as(usize, 0), counts.permits);

    running.stop();
    try running.await();
}

test "request result reservation rolls back when command enqueue is full" {
    const alloc = std.testing.allocator;
    var threaded = std.Io.Threaded.init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const runtime = try initTestRuntime(io, alloc, 0x9b, .{
        .max_active_requests = 1,
        .max_queued_requests = 1,
        .event_capacity = 1,
        .command_capacity = 1,
        .request_result_capacity = 1,
    }, .{ .maintenance_interval_ms = 60_000 });
    var running = RunningRuntime.init(io);
    defer running.deinit();
    try running.start(runtime);
    try running.awaitStarted();

    var gate = runtime_mod.Testing.CommandGate{};
    runtime_mod.Testing.setCommandGate(runtime, &gate);
    var blocker_buffer: [1]runtime_mod.Testing.EnrAdmissionResult = undefined;
    var blocker_reply = runtime_mod.Testing.EnrAdmissionReply.init(&blocker_buffer);
    try runtime_mod.Testing.enqueueAddEnr(runtime, try alloc.dupe(u8, &.{0xff}), &blocker_reply);
    try awaitFlag(&gate.entered, error.RuntimeDidNotEnter);
    var queued_buffer: [1]runtime_mod.Testing.EnrAdmissionResult = undefined;
    var queued_reply = runtime_mod.Testing.EnrAdmissionReply.init(&queued_buffer);
    try runtime_mod.Testing.enqueueAddEnr(runtime, try alloc.dupe(u8, &.{0xfe}), &queued_reply);

    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x9c} ** 32));
    const remote_pubkey = secp.compressedPubkey(&remote_key);
    const remote_id = try enr.nodeIdFromCompressedPubkey(&remote_pubkey);
    const address = types.Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 100 }, .port = 9100 } };
    try std.testing.expectError(error.CommandQueueFull, runtime.sendPing(remote_id, &remote_pubkey, address, 0));
    try std.testing.expect(runtime.popRequestResult() == null);

    gate.proceed.store(true, .release);
    const blocker_result = try blocker_reply.getOneUncancelable(io);
    _ = try blocker_result;
    const queued_result = try queued_reply.getOneUncancelable(io);
    _ = try queued_result;
    const req_id = try runtime.sendPing(remote_id, &remote_pubkey, address, 1);
    try std.testing.expect(try runtime.cancelRequest(remote_id, address, req_id));
    const result = runtime.popRequestResult() orelse return error.MissingCanceledRequestResult;
    try std.testing.expect(result.terminal == .canceled);
    const counts = runtime_mod.Testing.activeQueuedAndPermitCount(runtime);
    try std.testing.expectEqual(@as(usize, 0), counts.active);
    try std.testing.expectEqual(@as(usize, 0), counts.permits);

    running.stop();
    try running.await();
}

test "running Runtime rejects oversized TALK before queued ownership admission" {
    const alloc = std.testing.allocator;
    var threaded = std.Io.Threaded.init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const runtime = try initTestRuntime(io, alloc, 0x73, .{
        .max_active_requests = 2,
        .max_queued_requests = 2,
        .event_capacity = 2,
        .command_capacity = 2,
    }, .{ .maintenance_interval_ms = 60_000 });
    var running = RunningRuntime.init(io);
    defer running.deinit();
    try running.start(runtime);
    try running.awaitStarted();

    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x74} ** 32));
    const remote_pubkey = secp.compressedPubkey(&remote_key);
    const remote_id = try enr.nodeIdFromCompressedPubkey(&remote_pubkey);
    const address = types.Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 19074 } };

    const ping_req_id = try runtime.sendPing(remote_id, &remote_pubkey, address, 0);
    var counts = runtime_mod.Testing.activeQueuedAndPermitCount(runtime);
    try std.testing.expectEqual(@as(usize, 1), counts.active);
    try std.testing.expectEqual(@as(usize, 0), counts.queued);
    try std.testing.expectEqual(@as(usize, 1), counts.permits);

    const protocol = [_]u8{0x01};
    const request = [_]u8{0x02} ** 1_200;
    try std.testing.expect(protocol.len + request.len <= packet.MAX_PACKET_SIZE);
    try std.testing.expectError(error.MessageTooLarge, runtime.sendTalkRequest(remote_id, &remote_pubkey, address, &protocol, &request));

    const response = [_]u8{0x03} ** 1_200;
    try std.testing.expect(response.len <= packet.MAX_PACKET_SIZE);
    try std.testing.expectError(error.MessageTooLarge, runtime.sendTalkResponse(remote_id, address, .{ .bytes = [_]u8{0x04} ** 8, .len = 8 }, &response));

    counts = runtime_mod.Testing.activeQueuedAndPermitCount(runtime);
    try std.testing.expectEqual(@as(usize, 1), counts.active);
    try std.testing.expectEqual(@as(usize, 0), counts.queued);
    try std.testing.expectEqual(@as(usize, 1), counts.permits);
    const snapshot = try runtime.metricsSnapshot();
    try std.testing.expectEqual(@as(usize, 1), snapshot.active_request_count);
    try std.testing.expectEqual(@as(usize, 0), snapshot.queued_request_count);
    try std.testing.expectEqual(@as(u64, 1), snapshot.sentMessageCount(metrics.MessageType.ping));
    try std.testing.expectEqual(@as(u64, 0), snapshot.sentMessageCount(metrics.MessageType.talkreq));

    try std.testing.expect(try runtime.cancelRequest(remote_id, address, ping_req_id));
    counts = runtime_mod.Testing.activeQueuedAndPermitCount(runtime);
    try std.testing.expectEqual(@as(usize, 0), counts.active);
    try std.testing.expectEqual(@as(usize, 0), counts.queued);
    try std.testing.expectEqual(@as(usize, 0), counts.permits);
    const cancelled_snapshot = try runtime.metricsSnapshot();
    try std.testing.expectEqual(@as(usize, 0), cancelled_snapshot.active_request_count);
    try std.testing.expectEqual(@as(usize, 0), cancelled_snapshot.queued_request_count);

    running.stop();
    try running.await();
    try std.testing.expect(running.run_result == null);
}

test "running Runtime rejects exactly 128 FINDNODE distances before request admission" {
    const alloc = std.testing.allocator;
    var threaded = std.Io.Threaded.init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const runtime = try initTestRuntime(io, alloc, 0x75, .{
        .max_active_requests = 2,
        .max_queued_requests = 2,
        .event_capacity = 2,
        .command_capacity = 2,
    }, .{ .maintenance_interval_ms = 60_000 });
    var running = RunningRuntime.init(io);
    defer running.deinit();
    try running.start(runtime);
    try running.awaitStarted();

    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x76} ** 32));
    const remote_pubkey = secp.compressedPubkey(&remote_key);
    const remote_id = try enr.nodeIdFromCompressedPubkey(&remote_pubkey);
    const address = types.Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 19075 } };
    const distances = [_]u16{1} ** 128;

    var counts = runtime_mod.Testing.activeQueuedAndPermitCount(runtime);
    try std.testing.expectEqual(@as(usize, 0), counts.active);
    try std.testing.expectEqual(@as(usize, 0), counts.queued);
    try std.testing.expectEqual(@as(usize, 0), counts.permits);
    var snapshot = try runtime.metricsSnapshot();
    try std.testing.expectEqual(@as(u64, 0), snapshot.sentMessageCount(.findnode));

    try std.testing.expectError(error.TooManyDistances, runtime.sendFindNode(remote_id, &remote_pubkey, address, &distances));

    counts = runtime_mod.Testing.activeQueuedAndPermitCount(runtime);
    try std.testing.expectEqual(@as(usize, 0), counts.active);
    try std.testing.expectEqual(@as(usize, 0), counts.queued);
    try std.testing.expectEqual(@as(usize, 0), counts.permits);
    snapshot = try runtime.metricsSnapshot();
    try std.testing.expectEqual(@as(u64, 0), snapshot.sentMessageCount(.findnode));

    running.stop();
    try running.await();
    try std.testing.expect(running.run_result == null);
}

test "persistent receive errors use bounded backoff" {
    const expected = [_]u64{ 1, 2, 4, 8, 16, 32, 64, 100 };
    for (expected, 1..) |delay_ms, consecutive_errors| {
        try std.testing.expectEqual(delay_ms, runtime_mod.Testing.receiveBackoff(@intCast(consecutive_errors)));
    }
    try std.testing.expectEqual(@as(u64, 100), runtime_mod.Testing.receiveBackoff(std.math.maxInt(u8)));
}

test "Runtime exposes named request cancellation" {
    const alloc = std.testing.allocator;
    var threaded = std.Io.Threaded.init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x74} ** 32));
    const local_id = try enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&local_key));
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x75} ** 32));
    const remote_pubkey = secp.compressedPubkey(&remote_key);
    const remote_id = try enr.nodeIdFromCompressedPubkey(&remote_pubkey);
    const runtime = try runtime_mod.Runtime.init(io, alloc, config.Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
        .local_node_id = local_id,
        .rate_limiter = null,
        .limits = .{ .max_active_requests = 4, .max_queued_requests = 4, .event_capacity = 4, .command_capacity = 4 },
    }, .{});
    var running = RunningRuntime.init(io);
    defer running.deinit();
    try running.start(runtime);
    try running.awaitStarted();

    const address = @import("types.zig").Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 19075 } };
    const req_id = try runtime.sendPing(remote_id, &remote_pubkey, address, 0);
    try std.testing.expect(try runtime.cancelRequest(remote_id, address, req_id));
    try std.testing.expect(!try runtime.cancelRequest(remote_id, address, req_id));
    running.stop();
    try running.await();
    try std.testing.expect(running.run_result == null);
}

test "Runtime actor queries return authoritative local and peer ENR snapshots" {
    const alloc = std.testing.allocator;
    var threaded = std.Io.Threaded.init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x66} ** 32));
    const local_id = try enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&local_key));
    var initial_builder = enr.Builder.init(alloc, local_key, 1);
    initial_builder.ip = .{ 127, 0, 0, 1 };
    initial_builder.udp = 19066;
    const initial_enr = try initial_builder.encode();
    defer alloc.free(initial_enr);
    const runtime = try runtime_mod.Runtime.init(io, alloc, .{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
        .local_node_id = local_id,
        .local_enr = initial_enr,
        .rate_limiter = null,
        .limits = .{ .max_active_requests = 4, .max_queued_requests = 4, .event_capacity = 8, .command_capacity = 4 },
    }, .{ .maintenance_interval_ms = 60_000 });
    var running = RunningRuntime.init(io);
    defer running.deinit();
    try running.start(runtime);
    try running.awaitStarted();

    const initial_snapshot = (try runtime.localEnr()) orelse return error.MissingLocalEnr;
    try std.testing.expectEqualSlices(u8, initial_enr, initial_snapshot.slice());
    try std.testing.expectEqual(@as(u64, 1), try runtime.localEnrSeq());

    var replacement_builder = enr.Builder.init(alloc, local_key, 2);
    replacement_builder.ip = .{ 127, 0, 0, 1 };
    replacement_builder.udp = 19067;
    const replacement_enr = try replacement_builder.encode();
    defer alloc.free(replacement_enr);
    try runtime.setLocalEnr(replacement_enr);
    const replacement_snapshot = (try runtime.localEnr()) orelse return error.MissingReplacementEnr;
    try std.testing.expectEqualSlices(u8, replacement_enr, replacement_snapshot.slice());
    try std.testing.expectEqual(@as(u64, 2), try runtime.localEnrSeq());

    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x67} ** 32));
    var remote_builder = enr.Builder.init(alloc, remote_key, 1);
    remote_builder.ip = .{ 127, 0, 0, 2 };
    remote_builder.udp = 19068;
    const remote_enr = try remote_builder.encode();
    defer alloc.free(remote_enr);
    const remote_id = (try (try enr.decode(remote_enr)).nodeId()).?;
    try std.testing.expect(try runtime.addEnr(remote_enr));
    const peer_snapshot = (try runtime.peerEnr(remote_id)) orelse return error.MissingPeerEnr;
    try std.testing.expectEqualSlices(u8, remote_enr, peer_snapshot.slice());
    try std.testing.expect((try runtime.peerEnr([_]u8{0xee} ** 32)) == null);

    running.stop();
    try running.await();
    try std.testing.expect(running.run_result == null);
}

test "Runtime follows run stop caller-await deinit lifecycle" {
    const alloc = std.testing.allocator;
    var threaded = std.Io.Threaded.init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const key_pair = try secp.keyPairFromSecret(&([_]u8{0x71} ** 32));
    const node_id = try enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&key_pair));
    const runtime = try runtime_mod.Runtime.init(io, alloc, config.Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = key_pair,
        .local_node_id = node_id,
        .rate_limiter = null,
        .limits = .{ .max_active_requests = 4, .max_queued_requests = 4, .event_capacity = 4, .command_capacity = 4 },
    }, .{ .maintenance_interval_ms = 1 });
    var run_error: ?anyerror = null;
    var caller_group: std.Io.Group = .init;
    try caller_group.concurrent(io, runRuntime, .{ runtime, &run_error });

    var observed_running = false;
    for (0..10_000) |_| {
        if (runtime.isRunning()) {
            observed_running = true;
            break;
        }
        try std.Thread.yield();
    }
    try std.testing.expect(observed_running);
    _ = try runtime.metricsSnapshot();
    runtime.stop();
    try caller_group.await(io);
    try std.testing.expect(run_error == null);
    try std.testing.expect(runtime.isClosed());
    try std.testing.expect(!runtime.isRunning());
    runtime.deinit();
}

fn runtimeInitializationLifecycle(alloc: std.mem.Allocator) !void {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const key_pair = try secp.keyPairFromSecret(&([_]u8{0x6f} ** 32));
    const node_id = try enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&key_pair));
    const runtime = try runtime_mod.Runtime.init(threaded.io(), alloc, .{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = key_pair,
        .local_node_id = node_id,
        .rate_limiter = null,
        .limits = .{ .max_active_requests = 2, .max_queued_requests = 2, .event_capacity = 2, .command_capacity = 2 },
    }, .{});
    runtime.deinit();
}

test "Runtime partial initialization cleans up every allocator failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, runtimeInitializationLifecycle, .{});
}

test "full EventOutbox cannot lose reliable pong nodes or talk response payloads" {
    const alloc = std.testing.allocator;
    var threaded = std.Io.Threaded.init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const key_a = try secp.keyPairFromSecret(&([_]u8{0xa1} ** 32));
    const pubkey_a = secp.compressedPubkey(&key_a);
    const id_a = try enr.nodeIdFromCompressedPubkey(&pubkey_a);
    const key_b = try secp.keyPairFromSecret(&([_]u8{0xa2} ** 32));
    const pubkey_b = secp.compressedPubkey(&key_b);
    const id_b = try enr.nodeIdFromCompressedPubkey(&pubkey_b);
    const limits_a = config.Limits{
        .max_active_requests = 2,
        .max_queued_requests = 2,
        .event_capacity = 1,
        .command_capacity = 8,
        .request_result_capacity = 1,
    };
    const limits_b = config.Limits{
        .max_active_requests = 2,
        .max_queued_requests = 2,
        .event_capacity = 8,
        .command_capacity = 8,
        .request_result_capacity = 1,
    };
    const runtime_a = try runtime_mod.Runtime.init(io, alloc, .{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = key_a,
        .local_node_id = id_a,
        .rate_limiter = null,
        .limits = limits_a,
    }, .{ .maintenance_interval_ms = 60_000 });
    var running_a = RunningRuntime.init(io);
    defer running_a.deinit();
    try running_a.start(runtime_a);
    const runtime_b = try runtime_mod.Runtime.init(io, alloc, .{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = key_b,
        .local_node_id = id_b,
        .rate_limiter = null,
        .limits = limits_b,
    }, .{ .maintenance_interval_ms = 60_000 });
    var running_b = RunningRuntime.init(io);
    defer running_b.deinit();
    try running_b.start(runtime_b);
    try running_a.awaitStarted();
    try running_b.awaitStarted();
    const address_a = runtime_a.boundAddress(.ip4) orelse return error.MissingBoundAddress;
    const address_b = runtime_b.boundAddress(.ip4) orelse return error.MissingBoundAddress;
    const endpoint_b = types.Endpoint{ .node_id = id_b, .addr = address_b };

    var builder_a = enr.Builder.init(alloc, key_a, 1);
    builder_a.ip = address_a.ip4.bytes;
    builder_a.udp = address_a.ip4.port;
    const local_enr_a = try builder_a.encode();
    defer alloc.free(local_enr_a);
    try runtime_a.setLocalEnr(local_enr_a);
    var builder_b = enr.Builder.init(alloc, key_b, 1);
    builder_b.ip = address_b.ip4.bytes;
    builder_b.udp = address_b.ip4.port;
    const local_enr_b = try builder_b.encode();
    defer alloc.free(local_enr_b);
    try runtime_b.setLocalEnr(local_enr_b);
    var local_b_event = runtime_b.popEvent() orelse return error.MissingLocalEnrEvent;
    local_b_event.deinit(alloc);
    try std.testing.expect(try runtime_a.addNode(id_b, &pubkey_b, address_b, local_enr_b));
    try std.testing.expect(try runtime_b.addNode(id_a, &pubkey_a, address_a, local_enr_a));

    const ping_id = try runtime_a.sendPing(id_b, &pubkey_b, address_b, 0);
    const pong_result = try awaitRequestResult(io, runtime_a);
    try expectRequestIdentity(&pong_result, endpoint_b, ping_id, .ping);
    try std.testing.expect(pong_result.terminal == .pong);
    try std.testing.expectEqual(@as(u64, 1), pong_result.terminal.pong.enr_seq);
    try std.testing.expectEqual(address_a.getPort(), pong_result.terminal.pong.recipient_port);

    const findnode_id = try runtime_a.sendFindNode(id_b, &pubkey_b, address_b, &.{0});
    const nodes_result = try awaitRequestResult(io, runtime_a);
    try expectRequestIdentity(&nodes_result, endpoint_b, findnode_id, .findnode);
    try std.testing.expect(nodes_result.terminal == .nodes);
    try std.testing.expectEqual(@as(usize, 1), nodes_result.terminal.nodes.slice().len);
    try std.testing.expectEqualSlices(u8, local_enr_b, nodes_result.terminal.nodes.slice()[0].slice());

    const talk_id = try runtime_a.sendTalkRequest(id_b, &pubkey_b, address_b, "test", "request");
    var response_sent = false;
    for (0..2_000) |_| {
        while (runtime_b.popEvent()) |event_value| {
            var event = event_value;
            defer event.deinit(alloc);
            if (event == .talkreq and std.mem.eql(u8, event.talkreq.req_id.slice(), talk_id.slice())) {
                try runtime_b.sendTalkResponse(id_a, address_a, event.talkreq.req_id, "response bytes");
                response_sent = true;
            }
        }
        if (response_sent) break;
        try std.Io.sleep(io, .fromMilliseconds(1), .awake);
    }
    try std.testing.expect(response_sent);
    const talk_result = try awaitRequestResult(io, runtime_a);
    try expectRequestIdentity(&talk_result, endpoint_b, talk_id, .talkreq);
    try std.testing.expect(talk_result.terminal == .talk_response);
    try std.testing.expectEqualSlices(u8, "response bytes", talk_result.terminal.talk_response.slice());
    try std.testing.expect(runtime_a.popRequestResult() == null);

    const snapshot = try runtime_a.metricsSnapshot();
    try std.testing.expect(snapshot.dropped_event_count >= 1);
    try std.testing.expectEqual(@as(u64, 1), snapshot.droppedEventCount(.talk_resp_received));
    var blocker = runtime_a.popEvent() orelse return error.MissingEventOutboxBlocker;
    defer blocker.deinit(alloc);
    try std.testing.expect(blocker == .local_enr_updated);
    try std.testing.expect(runtime_a.popEvent() == null);
    const counts = runtime_mod.Testing.activeQueuedAndPermitCount(runtime_a);
    try std.testing.expectEqual(@as(usize, 0), counts.active);
    try std.testing.expectEqual(@as(usize, 0), counts.queued);
    try std.testing.expectEqual(@as(usize, 0), counts.permits);

    running_a.stop();
    running_b.stop();
    try running_a.await();
    try running_b.await();
    try std.testing.expectError(error.Closed, runtime_a.nextRequestResult());
}

test "two live Runtime sockets complete strict handshake and PING lifecycle" {
    const alloc = std.testing.allocator;
    var threaded = std.Io.Threaded.init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const key_a = try secp.keyPairFromSecret(&([_]u8{0x80} ** 32));
    const pubkey_a = secp.compressedPubkey(&key_a);
    const id_a = try enr.nodeIdFromCompressedPubkey(&pubkey_a);
    const key_b = try secp.keyPairFromSecret(&([_]u8{0x81} ** 32));
    const pubkey_b = secp.compressedPubkey(&key_b);
    const id_b = try enr.nodeIdFromCompressedPubkey(&pubkey_b);
    const limits = config.Limits{ .max_active_requests = 4, .max_queued_requests = 4, .event_capacity = 16, .command_capacity = 8 };
    const runtime_a = try runtime_mod.Runtime.init(io, alloc, .{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = key_a,
        .local_node_id = id_a,
        .rate_limiter = null,
        .limits = limits,
    }, .{ .maintenance_interval_ms = 10 });
    var running_a = RunningRuntime.init(io);
    defer running_a.deinit();
    try running_a.start(runtime_a);
    const runtime_b = try runtime_mod.Runtime.init(io, alloc, .{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = key_b,
        .local_node_id = id_b,
        .rate_limiter = null,
        .limits = limits,
    }, .{ .maintenance_interval_ms = 10 });
    var running_b = RunningRuntime.init(io);
    defer running_b.deinit();
    try running_b.start(runtime_b);
    const address_a = runtime_a.boundAddress(.ip4) orelse return error.MissingBoundAddress;
    const address_b = runtime_b.boundAddress(.ip4) orelse return error.MissingBoundAddress;
    try running_a.awaitStarted();
    try running_b.awaitStarted();

    try std.testing.expect(try runtime_a.addNode(id_b, &pubkey_b, address_b, null));
    try std.testing.expect(try runtime_b.addNode(id_a, &pubkey_a, address_a, null));
    const req_id = try runtime_a.sendPing(id_b, &pubkey_b, address_b, 0);
    const pong_result = try awaitRequestResult(io, runtime_a);
    try std.testing.expect(types.RequestKeyContext.eql(.{}, pong_result.key, .init(.{ .node_id = id_b, .addr = address_b }, req_id)));
    try std.testing.expectEqual(types.RequestKind.ping, pong_result.kind);
    try std.testing.expect(pong_result.terminal == .pong);

    running_a.stop();
    running_b.stop();
    try running_a.await();
    try running_b.await();
    const stopped_a = runtime_a.isClosed() and !runtime_a.isRunning();
    const stopped_b = runtime_b.isClosed() and !runtime_b.isRunning();
    try std.testing.expect(running_a.run_result == null);
    try std.testing.expect(running_b.run_result == null);
    try std.testing.expect(stopped_a and stopped_b);
}
