const message = @import("protocol/message.zig");
const types = @import("types.zig");

/// A structurally bounded Discovery v5 request identifier.
///
/// Each tag fixes the payload length, so ordinary construction cannot create a
/// request ID longer than the protocol's eight-byte maximum.
pub const RequestId = union(enum) {
    empty: [0]u8,
    one: [1]u8,
    two: [2]u8,
    three: [3]u8,
    four: [4]u8,
    five: [5]u8,
    six: [6]u8,
    seven: [7]u8,
    eight: [8]u8,

    pub fn fromSlice(bytes: []const u8) error{InvalidRequestId}!RequestId {
        return switch (bytes.len) {
            0 => .{ .empty = .{} },
            1 => .{ .one = bytes[0..1].* },
            2 => .{ .two = bytes[0..2].* },
            3 => .{ .three = bytes[0..3].* },
            4 => .{ .four = bytes[0..4].* },
            5 => .{ .five = bytes[0..5].* },
            6 => .{ .six = bytes[0..6].* },
            7 => .{ .seven = bytes[0..7].* },
            8 => .{ .eight = bytes[0..8].* },
            else => error.InvalidRequestId,
        };
    }

    pub fn slice(self: *const RequestId) []const u8 {
        return switch (self.*) {
            inline else => |*bytes| bytes,
        };
    }
};

/// Exact actor-assigned ownership token for one request generation.
pub const RequestHandle = struct {
    node_id: types.NodeId,
    address: types.Address,
    request_id: RequestId,
    generation: u64,
};

pub fn requestIdFromWire(id: message.ReqId) RequestId {
    return RequestId.fromSlice(id.slice()) catch unreachable;
}

pub fn requestIdToWire(id: RequestId) message.ReqId {
    return message.ReqId.fromSlice(id.slice()) catch unreachable;
}

pub fn handleFromInternal(handle: types.RequestHandle) RequestHandle {
    return .{
        .node_id = handle.key.endpoint.node_id,
        .address = handle.key.endpoint.addr,
        .request_id = requestIdFromWire(handle.key.req_id),
        .generation = handle.generation,
    };
}

pub fn handleToInternal(handle: RequestHandle) types.RequestHandle {
    return .{
        .key = .init(.{ .node_id = handle.node_id, .addr = handle.address }, requestIdToWire(handle.request_id)),
        .generation = handle.generation,
    };
}
