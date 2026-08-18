const std = @import("std");
const message = @import("protocol/message.zig");
const runtime_error = @import("runtime_error.zig");
const transport = @import("transport.zig");
const types = @import("types.zig");

pub fn Hooks(comptime Runtime: type, comptime RuntimeImpl: type, comptime receive_backoff: anytype) type {
    return if (@import("builtin").is_test) struct {
        pub const CommandGate = struct {
            entered: std.atomic.Value(bool) = .init(false),
            proceed: std.atomic.Value(bool) = .init(false),
        };
        pub const CancellationGate = struct {
            queue: std.Io.Queue(u8),
            buffer: [1]u8 = undefined,
            entered: std.atomic.Value(bool) = .init(false),
            cancellation_observed: std.atomic.Value(bool) = .init(false),

            pub fn init(self: *CancellationGate) void {
                self.* = .{ .queue = undefined };
                self.queue = .init(&self.buffer);
            }

            pub fn release(self: *CancellationGate, io: std.Io) void {
                if (self.cancellation_observed.load(.acquire)) return;
                self.queue.putOneUncancelable(io, 0) catch unreachable;
            }
        };
        pub const EnrAdmissionResult = runtime_error.EnrAdmissionError!bool;
        pub const EnrAdmissionReply = std.Io.Queue(EnrAdmissionResult);
        pub const PingResult = runtime_error.RequestError!message.ReqId;
        pub const PingReply = std.Io.Queue(PingResult);

        pub fn actorLoop(runtime: *Runtime) std.Io.Cancelable!void {
            return impl(runtime).actorLoopForTesting();
        }

        pub fn enqueueAddEnr(runtime: *Runtime, bytes: []u8, reply: *EnrAdmissionReply) !void {
            const storage = impl(runtime);
            errdefer storage.allocator.free(bytes);
            try storage.enqueueCommand(.{ .add_enr = .{ .enr = bytes, .reply = reply } });
        }

        pub fn enqueueSendPing(runtime: *Runtime, endpoint: types.Endpoint, pubkey: [33]u8, reply: *PingReply) !void {
            try impl(runtime).enqueueCommand(.{ .send_ping = .{
                .endpoint = endpoint,
                .pubkey = pubkey,
                .enr_seq = 0,
                .reply = reply,
            } });
        }

        pub fn putMaintenance(runtime: *Runtime) !void {
            try impl(runtime).requestMaintenanceWake();
        }

        pub fn enqueueStaleMaintenance(runtime: *Runtime) !void {
            try impl(runtime).enqueueCommand(.maintenance);
        }

        pub fn setCommandGate(runtime: *Runtime, gate: ?*CommandGate) void {
            impl(runtime).test_command_gate = gate;
        }

        pub fn setCancellationGate(runtime: *Runtime, gate: ?*CancellationGate) void {
            impl(runtime).test_cancellation_gate = gate;
        }

        pub fn setSendGate(runtime: *Runtime, gate: ?*transport.Testing.SendGate) void {
            transport.Testing.setSendGate(&impl(runtime).transport, gate);
        }

        pub fn activeAndPermitCount(runtime: *Runtime) struct { active: usize, permits: usize } {
            const counts = activeQueuedAndPermitCount(runtime);
            return .{ .active = counts.active, .permits = counts.permits };
        }

        pub fn activeQueuedAndPermitCount(runtime: *Runtime) struct { active: usize, queued: usize, permits: usize } {
            const storage = impl(runtime);
            return .{
                .active = storage.actor.requests.activeCount(),
                .queued = storage.actor.requests.queuedCount(),
                .permits = storage.admission.permitCount(),
            };
        }

        pub fn receiveBackoff(consecutive_errors: u8) u64 {
            return receive_backoff(consecutive_errors);
        }

        fn impl(runtime: *Runtime) *RuntimeImpl {
            return @ptrCast(@alignCast(runtime));
        }
    } else struct {};
}
