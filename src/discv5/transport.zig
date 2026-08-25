const std = @import("std");
const net = std.Io.net;
const builtin = @import("builtin");
const config = @import("config.zig");
const packet = @import("protocol/packet.zig");
const types = @import("types.zig");
const util = @import("util.zig");

const Io = std.Io;
const Socket = Io.net.Socket;

pub const InitError = error{ Canceled, BindFailed };
pub const SendError = error{
    Canceled,
    MessageOversize,
    NoSocketForAddressFamily,
    OutOfMemory,
    TransportSendFailed,
};

pub const Sender = struct {
    context: *anyopaque,
    send_fn: *const fn (*anyopaque, types.Address, []const u8) SendError!void,

    pub fn send(self: Sender, address: types.Address, bytes: []const u8) SendError!void {
        return self.send_fn(self.context, address, bytes);
    }
};

pub const Transport = struct {
    io: Io,
    ip4: ?Socket = null,
    ip6: ?Socket = null,
    test_send_gate: if (builtin.is_test) ?*Testing.SendGate else void = if (builtin.is_test) null else {},

    pub fn init(io: Io, addresses: config.BindAddresses) InitError!Transport {
        var ip4: ?Socket = null;
        errdefer if (ip4) |*value| value.close(io);
        if (addresses.ip4) |address| ip4 = try bindSocket(io, address);
        var ip6: ?Socket = null;
        errdefer if (ip6) |*value| value.close(io);
        if (addresses.ip6) |address| ip6 = try bindSocket(io, address);
        return .{ .io = io, .ip4 = ip4, .ip6 = ip6 };
    }

    pub fn deinit(self: *Transport) void {
        if (self.ip4) |*value| value.close(self.io);
        if (self.ip6) |*value| value.close(self.io);
    }

    pub fn socket(self: *Transport, family: types.Address.Family) ?*Socket {
        return switch (family) {
            .ip4 => if (self.ip4) |*value| value else null,
            .ip6 => if (self.ip6) |*value| value else null,
        };
    }

    pub fn boundAddress(self: *const Transport, family: types.Address.Family) ?types.Address {
        return switch (family) {
            .ip4 => if (self.ip4) |value| value.address else null,
            .ip6 => if (self.ip6) |value| value.address else null,
        };
    }

    pub fn sender(self: *Transport) Sender {
        return .{ .context = self, .send_fn = sendErased };
    }

    pub const ReceiveError = net.Socket.ReceiveError || error{
        MessageOversize,
        NoSocketForAddressFamily,
    };

    pub fn receiveInto(self: *Transport, family: types.Address.Family, buffer: []u8) ReceiveError!net.IncomingMessage {
        const bound_socket = self.socket(family) orelse return error.NoSocketForAddressFamily;
        const incoming = try bound_socket.receive(self.io, buffer);
        if (incoming.flags.trunc) return error.MessageOversize;
        return incoming;
    }

    fn sendErased(context: *anyopaque, address: types.Address, bytes: []const u8) SendError!void {
        const self: *Transport = @ptrCast(@alignCast(context));
        if (builtin.is_test) if (self.test_send_gate) |gate| {
            if (!gate.entered.load(.acquire)) gate.first_destination = address;
            gate.entered.store(true, .release);
            if (gate.cancelable) {
                while (!gate.proceed.load(.acquire)) {
                    Io.sleep(self.io, .fromMilliseconds(1), .awake) catch |err| switch (err) {
                        error.Canceled => {
                            gate.cancellation_observed.store(true, .release);
                            self.io.recancel();
                            return error.Canceled;
                        },
                    };
                }
            } else {
                while (!gate.proceed.load(.acquire)) std.atomic.spinLoopHint();
            }
        };
        const socket_value = self.socket(switch (address) {
            .ip4 => .ip4,
            .ip6 => .ip6,
        }) orelse return error.NoSocketForAddressFamily;
        socket_value.send(self.io, &address, bytes) catch |err| switch (err) {
            error.Canceled => {
                self.io.recancel();
                return error.Canceled;
            },
            error.MessageOversize => return error.MessageOversize,
            else => return error.TransportSendFailed,
        };
    }
};

fn bindSocket(io: Io, address: types.Address) InitError!Socket {
    return util.bindDatagramSocket(io, address) catch |err| switch (err) {
        error.Canceled => error.Canceled,
        else => error.BindFailed,
    };
}

pub const Testing = if (builtin.is_test) struct {
    pub const SendGate = struct {
        entered: std.atomic.Value(bool) = .init(false),
        proceed: std.atomic.Value(bool) = .init(false),
        cancellation_observed: std.atomic.Value(bool) = .init(false),
        cancelable: bool = false,
        first_destination: ?types.Address = null,
    };

    pub fn setSendGate(transport: *Transport, gate: ?*SendGate) void {
        transport.test_send_gate = gate;
    }
} else struct {};

test "transport accepts the exact packet bound and rejects a truncated datagram" {
    const alloc = std.testing.allocator;
    var threaded = std.Io.Threaded.init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var receiver = try Transport.init(io, .{
        .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } },
    });
    defer receiver.deinit();
    var sender = try Transport.init(io, .{
        .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } },
    });
    defer sender.deinit();
    const destination = receiver.boundAddress(.ip4) orelse return error.MissingBoundAddress;
    const exact = [_]u8{0x5a} ** packet.MAX_PACKET_SIZE;
    const oversized = exact ++ .{0xa5};
    var buffer: [packet.MAX_PACKET_SIZE]u8 = undefined;

    try sender.sender().send(destination, &exact);
    const accepted = try receiver.receiveInto(.ip4, &buffer);
    try std.testing.expectEqual(@as(usize, packet.MAX_PACKET_SIZE), accepted.data.len);
    try std.testing.expectEqualSlices(u8, &exact, accepted.data);

    try sender.sender().send(destination, &oversized);
    try std.testing.expectError(error.MessageOversize, receiver.receiveInto(.ip4, &buffer));
}
