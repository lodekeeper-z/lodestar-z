const std = @import("std");
const transport = @import("../transport.zig");
const types = @import("../types.zig");

pub const RecordingSender = struct {
    const Datagram = struct {
        address: types.Address,
        bytes: types.PacketBytes,
    };

    datagrams: std.ArrayListUnmanaged(Datagram) = .empty,
    allocator: std.mem.Allocator,
    fail_next: bool = false,

    pub fn init(allocator: std.mem.Allocator) RecordingSender {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *RecordingSender) void {
        self.datagrams.deinit(self.allocator);
    }

    pub fn sender(self: *RecordingSender) transport.Sender {
        return .{ .context = self, .send_fn = recordErased };
    }

    fn recordErased(context: *anyopaque, address: types.Address, bytes: []const u8) transport.SendError!void {
        const self: *RecordingSender = @ptrCast(@alignCast(context));
        if (self.fail_next) {
            self.fail_next = false;
            return error.TransportSendFailed;
        }
        const copy = types.PacketBytes.init(bytes) catch return error.MessageOversize;
        try self.datagrams.append(self.allocator, .{ .address = address, .bytes = copy });
    }
};
