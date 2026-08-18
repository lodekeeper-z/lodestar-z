const std = @import("std");
const message = @import("protocol/message.zig");
const transport = @import("transport.zig");
const types = @import("types.zig");

pub fn Hooks(comptime Runtime: type, comptime RuntimeImpl: type, comptime RuntimeError: type, comptime receive_backoff: anytype) type {
    return if (@import("builtin").is_test) struct {
        pub const CommandGate = struct {
            entered: std.atomic.Value(bool) = .init(false),
            proceed: std.atomic.Value(bool) = .init(false),
        };
        pub const BoolResult = RuntimeError!bool;
        pub const BoolReply = std.Io.Queue(BoolResult);
        pub const ReqResult = RuntimeError!message.ReqId;
        pub const ReqReply = std.Io.Queue(ReqResult);

        pub fn actorLoop(runtime: *Runtime) std.Io.Cancelable!void {
            return impl(runtime).actorLoopForTesting();
        }

        pub fn enqueueAddEnr(runtime: *Runtime, bytes: []u8, reply: *BoolReply) !void {
            const storage = impl(runtime);
            errdefer storage.allocator.free(bytes);
            try storage.enqueueCommand(.{ .add_enr = .{ .enr = bytes, .reply = reply } });
        }

        pub fn enqueueSendPing(runtime: *Runtime, endpoint: types.Endpoint, pubkey: [33]u8, reply: *ReqReply) !void {
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

        pub fn setCommandGate(runtime: *Runtime, gate: ?*CommandGate) void {
            impl(runtime).test_command_gate = gate;
        }

        pub fn setSendGate(runtime: *Runtime, gate: ?*transport.Testing.SendGate) void {
            transport.Testing.setSendGate(&impl(runtime).transport, gate);
        }

        pub fn activeAndPermitCount(runtime: *Runtime) struct { active: usize, permits: usize } {
            const storage = impl(runtime);
            return .{ .active = storage.actor.requests.activeCount(), .permits = storage.admission.permitCount() };
        }

        pub fn receiveBackoff(consecutive_errors: u8) u64 {
            return receive_backoff(consecutive_errors);
        }

        fn impl(runtime: *Runtime) *RuntimeImpl {
            return @ptrCast(@alignCast(runtime));
        }
    } else struct {};
}
