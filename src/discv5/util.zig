//! Small cross-cutting helpers shared by the discv5 protocol and service layers.

const std = @import("std");
const Io = std.Io;
const net = Io.net;
const Address = net.IpAddress;

/// Bind a UDP (datagram) socket to `address`, restricting IPv6 sockets to v6-only.
pub fn bindDatagramSocket(io: Io, address: Address) !net.Socket {
    return try net.IpAddress.bind(&address, io, .{
        .mode = .dgram,
        .ip6_only = switch (address) {
            .ip4 => false,
            .ip6 => true,
        },
    });
}

/// Current monotonic awake-clock time in nanoseconds.
pub fn nowNs(io: Io) i64 {
    return @intCast(Io.Timestamp.now(io, .awake).toNanoseconds());
}

/// Current monotonic awake-clock time in milliseconds (clamped at 0).
pub fn nowMs(io: Io) u64 {
    const ms = Io.Timestamp.now(io, .awake).toMilliseconds();
    return if (ms < 0) 0 else @intCast(ms);
}

pub fn deadlineNs(now_ns: i64, timeout_ms: u64) i64 {
    const deadline = @as(i128, now_ns) + @as(i128, timeout_ms) * std.time.ns_per_ms;
    return if (deadline > std.math.maxInt(i64)) std.math.maxInt(i64) else @intCast(deadline);
}

test "protocol time uses the monotonic awake clock" {
    const FakeClock = struct {
        fn now(_: ?*anyopaque, clock: Io.Clock) Io.Timestamp {
            const milliseconds: i96 = if (clock == .awake) 222 else 111;
            return Io.Timestamp.fromNanoseconds(milliseconds * std.time.ns_per_ms);
        }

        const vtable: Io.VTable = blk: {
            var value: Io.VTable = undefined;
            value.now = now;
            break :blk value;
        };
    };
    const io = Io{ .userdata = null, .vtable = &FakeClock.vtable };

    try std.testing.expectEqual(@as(i64, 222 * std.time.ns_per_ms), nowNs(io));
    try std.testing.expectEqual(@as(u64, 222), nowMs(io));
}
