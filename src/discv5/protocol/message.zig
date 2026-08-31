//! Discovery v5 message types

const std = @import("std");
const Allocator = std.mem.Allocator;
const rlp = @import("../rlp.zig");
const packet = @import("packet.zig");
const config = @import("../config.zig");

pub const MSG_PING: u8 = 0x01;
pub const MSG_PONG: u8 = 0x02;
pub const MSG_FINDNODE: u8 = 0x03;
pub const MSG_NODES: u8 = 0x04;
pub const MSG_TALKREQ: u8 = 0x05;
pub const MSG_TALKRESP: u8 = 0x06;

pub const MAX_ENCODED_SIZE: usize = 1280;

/// A FINDNODE request is carried in an ordinary packet. The wire specification
/// caps that packet at 1280 bytes, leaving `MAX_ORDINARY_MESSAGE_SIZE` bytes
/// after the masking IV, static header, NodeId authdata, and GCM tag. At the
/// maximum cardinality, zero is the smallest valid RLP integer (one byte), and
/// the message type, empty request ID, and two three-byte long-list prefixes
/// consume eight bytes. The specification does not require unique distances,
/// so packet capacity, rather than the 257-value distance domain, sets the cap.
pub const MAX_FINDNODE_DISTANCES: usize = packet.MAX_ORDINARY_MESSAGE_SIZE - 8;

pub const Error = error{
    InvalidMessage,
    OutOfMemory,
    InvalidEncoding,
    UnexpectedType,
    Overflow,
    BufferTooSmall,
};

// Message payloads are fixed-shape RLP lists. Reject both trailing outer RLP
// bytes and extra fields inside the list so malformed packets have one clear
// interpretation.
fn readMessageList(data: []const u8, expected_type: u8) Error!rlp.Reader {
    if (data.len < 1 or data[0] != expected_type) return Error.InvalidMessage;

    var r = rlp.Reader.init(data[1..]);
    const list = r.readList() catch return Error.InvalidEncoding;
    if (!r.atEnd()) return Error.InvalidEncoding;
    return list;
}

fn expectEnd(r: *const rlp.Reader) Error!void {
    if (!r.atEnd()) return Error.InvalidEncoding;
}

/// Discv5 request IDs are RLP byte arrays of length 0..8, and responses must
/// echo the exact byte sequence from the request. Keep the length alongside the
/// fixed backing storage so values like `01`, `01 00`, and `01 00 00 00` stay
/// distinct without allocating. The unused tail is zeroed so `ReqId` can be
/// used directly as a value key in hash maps.
pub const ReqId = struct {
    bytes: [8]u8,
    len: u8,

    pub fn fromSlice(s: []const u8) Error!ReqId {
        if (s.len > 8) return Error.InvalidMessage;
        var id = ReqId{ .bytes = [_]u8{0} ** 8, .len = @intCast(s.len) };
        @memcpy(id.bytes[0..s.len], s);
        return id;
    }

    pub fn slice(self: *const ReqId) []const u8 {
        return self.bytes[0..self.len];
    }
};

pub const Ping = struct {
    req_id: ReqId,
    enr_seq: u64,

    pub fn encode(self: *const Ping, alloc: Allocator) ![]u8 {
        var buf: [MAX_ENCODED_SIZE]u8 = undefined;
        const encoded = try self.encodeInto(&buf);
        return try alloc.dupe(u8, encoded);
    }

    pub fn encodeInto(self: *const Ping, out: []u8) Error![]u8 {
        if (out.len == 0) return Error.BufferTooSmall;
        var w = rlp.Writer.initBuffer(out[1..]);
        const list_start = try w.beginListBounded();
        try w.writeBytesBounded(self.req_id.slice());
        try w.writeUint64Bounded(self.enr_seq);
        try w.finishList(list_start);
        const rlp_bytes = w.bytes();
        out[0] = MSG_PING;
        return out[0 .. 1 + rlp_bytes.len];
    }

    pub fn decode(data: []const u8) Error!Ping {
        var list = try readMessageList(data, MSG_PING);
        const req_id_bytes = list.readBytes() catch return Error.InvalidEncoding;
        const req_id = try ReqId.fromSlice(req_id_bytes);
        const enr_seq = list.readUint64() catch return Error.InvalidEncoding;
        try expectEnd(&list);
        return Ping{ .req_id = req_id, .enr_seq = enr_seq };
    }
};

pub const Pong = struct {
    pub const RecipientIp = union(enum) {
        ip4: [4]u8,
        ip6: [16]u8,
    };

    req_id: ReqId,
    enr_seq: u64,
    recipient_ip: RecipientIp,
    recipient_port: u16,

    pub fn encode(self: *const Pong, alloc: Allocator) ![]u8 {
        var buf: [MAX_ENCODED_SIZE]u8 = undefined;
        const encoded = try self.encodeInto(&buf);
        return try alloc.dupe(u8, encoded);
    }

    pub fn encodeInto(self: *const Pong, out: []u8) Error![]u8 {
        if (out.len == 0) return Error.BufferTooSmall;
        var w = rlp.Writer.initBuffer(out[1..]);
        const list_start = try w.beginListBounded();
        try w.writeBytesBounded(self.req_id.slice());
        try w.writeUint64Bounded(self.enr_seq);
        switch (self.recipient_ip) {
            .ip4 => |ip| try w.writeBytesBounded(&ip),
            .ip6 => |ip| try w.writeBytesBounded(&ip),
        }
        try w.writeUint64Bounded(self.recipient_port);
        try w.finishList(list_start);
        const rlp_bytes = w.bytes();
        out[0] = MSG_PONG;
        return out[0 .. 1 + rlp_bytes.len];
    }

    pub fn decode(data: []const u8) Error!Pong {
        var list = try readMessageList(data, MSG_PONG);
        const req_id_bytes = list.readBytes() catch return Error.InvalidEncoding;
        const req_id = try ReqId.fromSlice(req_id_bytes);
        const enr_seq = list.readUint64() catch return Error.InvalidEncoding;
        const ip_bytes = list.readBytes() catch return Error.InvalidEncoding;
        const port_value = list.readUint64() catch return Error.InvalidEncoding;
        if (port_value > std.math.maxInt(u16)) return Error.InvalidMessage;
        const port: u16 = @intCast(port_value);
        try expectEnd(&list);
        return Pong{
            .req_id = req_id,
            .enr_seq = enr_seq,
            .recipient_ip = switch (ip_bytes.len) {
                4 => .{ .ip4 = ip_bytes[0..4].* },
                16 => .{ .ip6 = ip_bytes[0..16].* },
                else => return Error.InvalidMessage,
            },
            .recipient_port = port,
        };
    }
};

pub const FindNode = struct {
    req_id: ReqId,
    distances: []const u16,

    pub fn encode(self: *const FindNode, alloc: Allocator) ![]u8 {
        var buf: [MAX_ENCODED_SIZE]u8 = undefined;
        const encoded = try self.encodeInto(&buf);
        return try alloc.dupe(u8, encoded);
    }

    pub fn encodeInto(self: *const FindNode, out: []u8) Error![]u8 {
        if (self.distances.len > MAX_FINDNODE_DISTANCES) return Error.InvalidMessage;
        for (self.distances) |distance| {
            if (distance > 256) return Error.InvalidMessage;
        }
        if (out.len == 0) return Error.BufferTooSmall;
        var w = rlp.Writer.initBuffer(out[1..]);
        const list_start = try w.beginListBounded();
        try w.writeBytesBounded(self.req_id.slice());
        const dist_start = try w.beginListBounded();
        for (self.distances) |d| {
            try w.writeUint64Bounded(d);
        }
        try w.finishList(dist_start);
        try w.finishList(list_start);
        const rlp_bytes = w.bytes();
        if (!packet.ordinaryMessageFits(1 + rlp_bytes.len)) return Error.InvalidMessage;
        out[0] = MSG_FINDNODE;
        return out[0 .. 1 + rlp_bytes.len];
    }

    const Validated = struct {
        req_id: ReqId,
        encoded_distances: rlp.Reader,
        distances_len: usize,
    };

    /// Validate the complete message and retain a reader over the already
    /// validated distance list. Publication can then be infallible and is only
    /// attempted after the caller's output capacity is known to be sufficient.
    fn validate(data: []const u8) Error!Validated {
        if (data.len > packet.MAX_ORDINARY_MESSAGE_SIZE) return Error.InvalidMessage;
        var list = try readMessageList(data, MSG_FINDNODE);
        const req_id_bytes = list.readBytes() catch return Error.InvalidEncoding;
        const req_id = try ReqId.fromSlice(req_id_bytes);

        var dist_list = list.readList() catch return Error.InvalidEncoding;
        const encoded_distances = dist_list;
        var distances_len: usize = 0;
        while (!dist_list.atEnd()) {
            const distance = dist_list.readUint64() catch return Error.InvalidEncoding;
            if (distance > 256) return Error.InvalidMessage;
            if (distances_len == MAX_FINDNODE_DISTANCES) return Error.InvalidMessage;
            distances_len += 1;
        }
        try expectEnd(&list);
        return .{
            .req_id = req_id,
            .encoded_distances = encoded_distances,
            .distances_len = distances_len,
        };
    }

    fn publish(validated: Validated, distances_out: []u16) FindNode {
        std.debug.assert(distances_out.len >= validated.distances_len);
        var dist_list = validated.encoded_distances;
        for (distances_out[0..validated.distances_len]) |*distance| {
            const value = dist_list.readUint64() catch unreachable;
            std.debug.assert(value <= 256);
            distance.* = @intCast(value);
        }
        std.debug.assert(dist_list.atEnd());
        return .{
            .req_id = validated.req_id,
            .distances = distances_out[0..validated.distances_len],
        };
    }

    pub fn decodeInto(data: []const u8, distances_out: []u16) Error!FindNode {
        const validated = try validate(data);
        if (distances_out.len < validated.distances_len) return Error.BufferTooSmall;
        return publish(validated, distances_out);
    }
};

pub const Nodes = struct {
    req_id: ReqId,
    total: u64,
    enrs: []const []const u8,

    pub fn encode(self: *const Nodes, alloc: Allocator) ![]u8 {
        var buf: [MAX_ENCODED_SIZE]u8 = undefined;
        const encoded = try self.encodeInto(&buf);
        return try alloc.dupe(u8, encoded);
    }

    pub fn encodeInto(self: *const Nodes, out: []u8) Error![]u8 {
        if (out.len == 0) return Error.BufferTooSmall;
        var w = rlp.Writer.initBuffer(out[1..]);
        const list_start = try w.beginListBounded();
        try w.writeBytesBounded(self.req_id.slice());
        try w.writeUint64Bounded(self.total);
        const enr_start = try w.beginListBounded();
        for (self.enrs) |enr| {
            try w.writeRawItemBounded(enr);
        }
        try w.finishList(enr_start);
        try w.finishList(list_start);
        const rlp_bytes = w.bytes();
        out[0] = MSG_NODES;
        return out[0 .. 1 + rlp_bytes.len];
    }

    const Validated = struct {
        req_id: ReqId,
        total: u64,
        encoded_enrs: rlp.Reader,
        enrs_len: usize,
    };

    /// Validate the complete enclosing message before exposing any borrowed ENR
    /// views through caller-owned output storage.
    fn validate(data: []const u8) Error!Validated {
        var list = try readMessageList(data, MSG_NODES);
        const req_id_bytes = list.readBytes() catch return Error.InvalidEncoding;
        const req_id = try ReqId.fromSlice(req_id_bytes);
        const total = list.readUint64() catch return Error.InvalidEncoding;

        var enr_list = list.readList() catch return Error.InvalidEncoding;
        const encoded_enrs = enr_list;
        var enrs_len: usize = 0;
        while (!enr_list.atEnd()) {
            _ = enr_list.readRawItem() catch return Error.InvalidEncoding;
            enrs_len += 1;
        }
        try expectEnd(&list);
        return .{
            .req_id = req_id,
            .total = total,
            .encoded_enrs = encoded_enrs,
            .enrs_len = enrs_len,
        };
    }

    pub fn decodeInto(data: []const u8, enrs_out: [][]const u8) Error!Nodes {
        const validated = try validate(data);
        if (enrs_out.len < validated.enrs_len) return Error.BufferTooSmall;

        var enr_list = validated.encoded_enrs;
        for (enrs_out[0..validated.enrs_len]) |*slot| {
            slot.* = enr_list.readRawItem() catch unreachable;
        }
        std.debug.assert(enr_list.atEnd());
        return .{
            .req_id = validated.req_id,
            .total = validated.total,
            .enrs = enrs_out[0..validated.enrs_len],
        };
    }
};

pub const TalkReq = struct {
    req_id: ReqId,
    protocol: []const u8,
    request: []const u8,

    pub fn encode(self: *const TalkReq, alloc: Allocator) ![]u8 {
        var buf: [MAX_ENCODED_SIZE]u8 = undefined;
        const encoded = try self.encodeInto(&buf);
        return try alloc.dupe(u8, encoded);
    }

    pub fn encodeInto(self: *const TalkReq, out: []u8) Error![]u8 {
        if (out.len == 0) return Error.BufferTooSmall;
        var w = rlp.Writer.initBuffer(out[1..]);
        const list_start = try w.beginListBounded();
        try w.writeBytesBounded(self.req_id.slice());
        try w.writeBytesBounded(self.protocol);
        try w.writeBytesBounded(self.request);
        try w.finishList(list_start);
        const rlp_bytes = w.bytes();
        out[0] = MSG_TALKREQ;
        return out[0 .. 1 + rlp_bytes.len];
    }

    pub fn decode(data: []const u8) Error!TalkReq {
        var list = try readMessageList(data, MSG_TALKREQ);
        const req_id_bytes = list.readBytes() catch return Error.InvalidEncoding;
        const req_id = try ReqId.fromSlice(req_id_bytes);
        const protocol = list.readBytes() catch return Error.InvalidEncoding;
        const request = list.readBytes() catch return Error.InvalidEncoding;
        try expectEnd(&list);
        return TalkReq{ .req_id = req_id, .protocol = protocol, .request = request };
    }
};

pub const TalkResp = struct {
    req_id: ReqId,
    response: []const u8,

    pub fn encode(self: *const TalkResp, alloc: Allocator) ![]u8 {
        var buf: [MAX_ENCODED_SIZE]u8 = undefined;
        const encoded = try self.encodeInto(&buf);
        return try alloc.dupe(u8, encoded);
    }

    pub fn encodeInto(self: *const TalkResp, out: []u8) Error![]u8 {
        if (out.len == 0) return Error.BufferTooSmall;
        var w = rlp.Writer.initBuffer(out[1..]);
        const list_start = try w.beginListBounded();
        try w.writeBytesBounded(self.req_id.slice());
        try w.writeBytesBounded(self.response);
        try w.finishList(list_start);
        const rlp_bytes = w.bytes();
        out[0] = MSG_TALKRESP;
        return out[0 .. 1 + rlp_bytes.len];
    }

    pub fn decode(data: []const u8) Error!TalkResp {
        var list = try readMessageList(data, MSG_TALKRESP);
        const req_id_bytes = list.readBytes() catch return Error.InvalidEncoding;
        const req_id = try ReqId.fromSlice(req_id_bytes);
        const response = list.readBytes() catch return Error.InvalidEncoding;
        try expectEnd(&list);
        return TalkResp{ .req_id = req_id, .response = response };
    }
};

pub const DecodedFindNode = struct {
    req_id: ReqId,
    distances: [MAX_FINDNODE_DISTANCES]u16,
    distances_len: usize,

    pub fn distancesSlice(self: *const DecodedFindNode) []const u16 {
        return self.distances[0..self.distances_len];
    }
};

pub const DecodedNodes = struct {
    req_id: ReqId,
    total: u64,
    enrs: [config.MAX_NODES_RESPONSE][]const u8,
    enrs_len: usize,

    pub fn enrsSlice(self: *const DecodedNodes) []const []const u8 {
        return self.enrs[0..self.enrs_len];
    }
};

/// One complete, canonical interpretation of authenticated plaintext. Slice
/// payloads borrow from the plaintext buffer, while bounded repeated fields own
/// their index/value storage so expectation checking and dispatch share this
/// exact value without another RLP pass.
pub const DecodedMessage = union(enum) {
    ping: Ping,
    pong: Pong,
    findnode: DecodedFindNode,
    nodes: DecodedNodes,
    talkreq: TalkReq,
    talkresp: TalkResp,

    pub fn decodeInto(out: *DecodedMessage, data: []const u8) Error!void {
        if (data.len == 0) return Error.InvalidMessage;
        switch (data[0]) {
            MSG_PING => {
                const decoded = try Ping.decode(data);
                out.* = .{ .ping = decoded };
            },
            MSG_PONG => {
                const decoded = try Pong.decode(data);
                out.* = .{ .pong = decoded };
            },
            MSG_FINDNODE => {
                var candidate: DecodedMessage = .{ .findnode = .{
                    .req_id = .{ .bytes = [_]u8{0} ** 8, .len = 0 },
                    .distances = [_]u16{0} ** MAX_FINDNODE_DISTANCES,
                    .distances_len = 0,
                } };
                const decoded = try FindNode.decodeInto(data, &candidate.findnode.distances);
                candidate.findnode.req_id = decoded.req_id;
                candidate.findnode.distances_len = decoded.distances.len;
                out.* = candidate;
            },
            MSG_NODES => {
                var candidate: DecodedMessage = .{ .nodes = .{
                    .req_id = .{ .bytes = [_]u8{0} ** 8, .len = 0 },
                    .total = 0,
                    .enrs = [_][]const u8{&.{}} ** config.MAX_NODES_RESPONSE,
                    .enrs_len = 0,
                } };
                const decoded = try Nodes.decodeInto(data, &candidate.nodes.enrs);
                candidate.nodes.req_id = decoded.req_id;
                candidate.nodes.total = decoded.total;
                candidate.nodes.enrs_len = decoded.enrs.len;
                out.* = candidate;
            },
            MSG_TALKREQ => {
                const decoded = try TalkReq.decode(data);
                out.* = .{ .talkreq = decoded };
            },
            MSG_TALKRESP => {
                const decoded = try TalkResp.decode(data);
                out.* = .{ .talkresp = decoded };
            },
            else => return Error.UnexpectedType,
        }
    }

    pub fn decode(data: []const u8) Error!DecodedMessage {
        var decoded: DecodedMessage = undefined;
        try decodeInto(&decoded, data);
        return decoded;
    }
};

comptime {
    std.debug.assert(@sizeOf(DecodedMessage) <= 3 * 1024);
}

// =========== Tests ===========

fn appendTrailingByte(alloc: Allocator, encoded: []const u8) ![]u8 {
    const with_trailing = try alloc.alloc(u8, encoded.len + 1);
    @memcpy(with_trailing[0..encoded.len], encoded);
    with_trailing[encoded.len] = 0x80;
    return with_trailing;
}

fn appendExtraShortListField(alloc: Allocator, encoded: []const u8) ![]u8 {
    try std.testing.expect(encoded.len >= 2);
    try std.testing.expect(encoded[1] >= 0xc0 and encoded[1] < 0xf8);
    try std.testing.expect(encoded[1] < 0xf7);

    const with_extra = try alloc.alloc(u8, encoded.len + 1);
    @memcpy(with_extra[0..encoded.len], encoded);
    with_extra[1] += 1;
    with_extra[encoded.len] = 0x80;
    return with_extra;
}

fn decodedMessageSentinel() DecodedMessage {
    return .{ .findnode = .{
        .req_id = .{ .bytes = [_]u8{0xa5} ** 8, .len = 8 },
        .distances = [_]u16{0xa5a5} ** MAX_FINDNODE_DISTANCES,
        .distances_len = MAX_FINDNODE_DISTANCES,
    } };
}

fn expectDecodedMessageSentinel(actual: *const DecodedMessage) !void {
    switch (actual.*) {
        .findnode => |findnode| {
            try std.testing.expectEqualSlices(u8, &([_]u8{0xa5} ** 8), &findnode.req_id.bytes);
            try std.testing.expectEqual(@as(u8, 8), findnode.req_id.len);
            try std.testing.expectEqualSlices(
                u16,
                &([_]u16{0xa5a5} ** MAX_FINDNODE_DISTANCES),
                &findnode.distances,
            );
            try std.testing.expectEqual(@as(usize, MAX_FINDNODE_DISTANCES), findnode.distances_len);
        },
        else => return error.TestExpectedEqual,
    }
}

test "DecodedMessage decodeInto preserves sentinel on FINDNODE errors" {
    const alloc = std.testing.allocator;
    var encoded_buf: [MAX_ENCODED_SIZE]u8 = undefined;
    const request = FindNode{
        .req_id = try ReqId.fromSlice(&.{0x01}),
        .distances = &.{ 1, 256 },
    };
    const encoded = try request.encodeInto(&encoded_buf);
    const with_trailing = try appendTrailingByte(alloc, encoded);
    defer alloc.free(with_trailing);

    const malformed_final_boundary = encoded[0 .. encoded.len - 1];
    const semantic_invalid = [_]u8{ MSG_FINDNODE, 0xc5, 0x01, 0xc3, 0x82, 0x01, 0x01 };
    const cases = .{
        .{ malformed_final_boundary, Error.InvalidEncoding },
        .{ with_trailing, Error.InvalidEncoding },
        .{ semantic_invalid[0..], Error.InvalidMessage },
    };
    inline for (cases) |case| {
        var decoded = decodedMessageSentinel();
        try std.testing.expectError(case[1], DecodedMessage.decodeInto(&decoded, case[0]));
        try expectDecodedMessageSentinel(&decoded);
    }
}

test "DecodedMessage decodeInto preserves sentinel on NODES errors" {
    const alloc = std.testing.allocator;
    var encoded_buf: [MAX_ENCODED_SIZE]u8 = undefined;
    const response = Nodes{
        .req_id = try ReqId.fromSlice(&.{0x01}),
        .total = 1,
        .enrs = &.{&.{0x80}},
    };
    const encoded = try response.encodeInto(&encoded_buf);
    const with_trailing = try appendTrailingByte(alloc, encoded);
    defer alloc.free(with_trailing);

    const malformed_final_boundary = encoded[0 .. encoded.len - 1];
    const malformed_enr = [_]u8{ MSG_NODES, 0xc5, 0x01, 0x01, 0xc2, 0x82, 0x01 };
    const malformed_cases = .{
        .{ malformed_final_boundary, Error.InvalidEncoding },
        .{ with_trailing, Error.InvalidEncoding },
        .{ malformed_enr[0..], Error.InvalidEncoding },
    };
    inline for (malformed_cases) |case| {
        var decoded = decodedMessageSentinel();
        try std.testing.expectError(case[1], DecodedMessage.decodeInto(&decoded, case[0]));
        try expectDecodedMessageSentinel(&decoded);
    }

    const too_many_enrs = [_][]const u8{&.{0x80}} ** (config.MAX_NODES_RESPONSE + 1);
    const oversized_response = Nodes{
        .req_id = try ReqId.fromSlice(&.{0x01}),
        .total = 1,
        .enrs = &too_many_enrs,
    };
    const oversized_encoded = try oversized_response.encodeInto(&encoded_buf);
    var decoded = decodedMessageSentinel();
    try std.testing.expectError(Error.BufferTooSmall, DecodedMessage.decodeInto(&decoded, oversized_encoded));
    try expectDecodedMessageSentinel(&decoded);
}

test "discv5 messages: PING encode/decode" {
    const alloc = std.testing.allocator;
    const ping = Ping{
        .req_id = try ReqId.fromSlice(&[_]u8{ 0x00, 0x00, 0x00, 0x01 }),
        .enr_seq = 2,
    };
    const encoded = try ping.encode(alloc);
    defer alloc.free(encoded);

    const decoded = try Ping.decode(encoded);
    try std.testing.expectEqual(@as(u64, 2), decoded.enr_seq);
    try std.testing.expectEqualSlices(u8, ping.req_id.slice(), decoded.req_id.slice());
}

test "discv5 messages accept empty request IDs" {
    const empty_req_id = try ReqId.fromSlice(&.{});
    try std.testing.expectEqual(@as(u8, 0), empty_req_id.len);
    try std.testing.expectEqual(@as(usize, 0), empty_req_id.slice().len);
    try std.testing.expectError(Error.InvalidMessage, ReqId.fromSlice(&([_]u8{0} ** 9)));

    var encoded_buf: [MAX_ENCODED_SIZE]u8 = undefined;

    const ping = Ping{ .req_id = empty_req_id, .enr_seq = 1 };
    const encoded_ping = try ping.encodeInto(&encoded_buf);
    const decoded_ping = try Ping.decode(encoded_ping);
    try std.testing.expectEqual(@as(usize, 0), decoded_ping.req_id.slice().len);

    const pong = Pong{
        .req_id = decoded_ping.req_id,
        .enr_seq = 1,
        .recipient_ip = .{ .ip4 = .{ 127, 0, 0, 1 } },
        .recipient_port = 9000,
    };
    const encoded_pong = try pong.encodeInto(&encoded_buf);
    const decoded_pong = try Pong.decode(encoded_pong);
    try std.testing.expectEqual(@as(usize, 0), decoded_pong.req_id.slice().len);

    const find_node = FindNode{ .req_id = empty_req_id, .distances = &.{1} };
    const encoded_find_node = try find_node.encodeInto(&encoded_buf);
    var distances_buf: [1]u16 = undefined;
    const decoded_find_node = try FindNode.decodeInto(encoded_find_node, &distances_buf);
    try std.testing.expectEqual(@as(usize, 0), decoded_find_node.req_id.slice().len);

    const nodes = Nodes{ .req_id = empty_req_id, .total = 1, .enrs = &.{} };
    const encoded_nodes = try nodes.encodeInto(&encoded_buf);
    var enrs_buf: [1][]const u8 = undefined;
    const decoded_nodes = try Nodes.decodeInto(encoded_nodes, &enrs_buf);
    try std.testing.expectEqual(@as(usize, 0), decoded_nodes.req_id.slice().len);

    const talk_req = TalkReq{ .req_id = empty_req_id, .protocol = "test", .request = "request" };
    const encoded_talk_req = try talk_req.encodeInto(&encoded_buf);
    const decoded_talk_req = try TalkReq.decode(encoded_talk_req);
    try std.testing.expectEqual(@as(usize, 0), decoded_talk_req.req_id.slice().len);

    const talk_resp = TalkResp{ .req_id = empty_req_id, .response = "response" };
    const encoded_talk_resp = try talk_resp.encodeInto(&encoded_buf);
    const decoded_talk_resp = try TalkResp.decode(encoded_talk_resp);
    try std.testing.expectEqual(@as(usize, 0), decoded_talk_resp.req_id.slice().len);
}

test "FINDNODE encoder rejects distances above 256" {
    var encoded: [MAX_ENCODED_SIZE]u8 = undefined;
    const request = FindNode{
        .req_id = try ReqId.fromSlice(&.{0x01}),
        .distances = &.{257},
    };

    try std.testing.expectError(Error.InvalidMessage, request.encodeInto(&encoded));
}

test "discv5 messages reject trailing bytes after outer RLP" {
    const alloc = std.testing.allocator;

    {
        const msg = Ping{
            .req_id = try ReqId.fromSlice(&[_]u8{0x01}),
            .enr_seq = 2,
        };
        const encoded = try msg.encode(alloc);
        defer alloc.free(encoded);
        const with_trailing = try appendTrailingByte(alloc, encoded);
        defer alloc.free(with_trailing);
        try std.testing.expectError(Error.InvalidEncoding, Ping.decode(with_trailing));
    }

    {
        const msg = Pong{
            .req_id = try ReqId.fromSlice(&[_]u8{0x01}),
            .enr_seq = 2,
            .recipient_ip = .{ .ip4 = [4]u8{ 127, 0, 0, 1 } },
            .recipient_port = 9000,
        };
        const encoded = try msg.encode(alloc);
        defer alloc.free(encoded);
        const with_trailing = try appendTrailingByte(alloc, encoded);
        defer alloc.free(with_trailing);
        try std.testing.expectError(Error.InvalidEncoding, Pong.decode(with_trailing));
    }

    {
        const distances = [_]u16{ 256, 255 };
        const msg = FindNode{
            .req_id = try ReqId.fromSlice(&[_]u8{0x01}),
            .distances = &distances,
        };
        const encoded = try msg.encode(alloc);
        defer alloc.free(encoded);
        const with_trailing = try appendTrailingByte(alloc, encoded);
        defer alloc.free(with_trailing);
        var distances_out: [2]u16 = undefined;
        try std.testing.expectError(Error.InvalidEncoding, FindNode.decodeInto(with_trailing, &distances_out));
    }

    {
        var enr_buf: [16]u8 = undefined;
        var w = rlp.Writer.initBuffer(&enr_buf);
        try w.writeBytesBounded("enr");
        const enr = w.bytes();
        const msg = Nodes{
            .req_id = try ReqId.fromSlice(&[_]u8{0x01}),
            .total = 1,
            .enrs = &.{enr},
        };
        const encoded = try msg.encode(alloc);
        defer alloc.free(encoded);
        const with_trailing = try appendTrailingByte(alloc, encoded);
        defer alloc.free(with_trailing);
        var enrs_out: [1][]const u8 = undefined;
        try std.testing.expectError(Error.InvalidEncoding, Nodes.decodeInto(with_trailing, &enrs_out));
    }

    {
        const msg = TalkReq{
            .req_id = try ReqId.fromSlice(&[_]u8{0x01}),
            .protocol = "eth",
            .request = "hello",
        };
        const encoded = try msg.encode(alloc);
        defer alloc.free(encoded);
        const with_trailing = try appendTrailingByte(alloc, encoded);
        defer alloc.free(with_trailing);
        try std.testing.expectError(Error.InvalidEncoding, TalkReq.decode(with_trailing));
    }

    {
        const msg = TalkResp{
            .req_id = try ReqId.fromSlice(&[_]u8{0x01}),
            .response = "hello",
        };
        const encoded = try msg.encode(alloc);
        defer alloc.free(encoded);
        const with_trailing = try appendTrailingByte(alloc, encoded);
        defer alloc.free(with_trailing);
        try std.testing.expectError(Error.InvalidEncoding, TalkResp.decode(with_trailing));
    }
}

test "discv5 messages reject extra fields inside message list" {
    const alloc = std.testing.allocator;

    {
        const msg = Ping{
            .req_id = try ReqId.fromSlice(&[_]u8{0x01}),
            .enr_seq = 2,
        };
        const encoded = try msg.encode(alloc);
        defer alloc.free(encoded);
        const with_extra = try appendExtraShortListField(alloc, encoded);
        defer alloc.free(with_extra);
        try std.testing.expectError(Error.InvalidEncoding, Ping.decode(with_extra));
    }

    {
        const msg = Pong{
            .req_id = try ReqId.fromSlice(&[_]u8{0x01}),
            .enr_seq = 2,
            .recipient_ip = .{ .ip4 = [4]u8{ 127, 0, 0, 1 } },
            .recipient_port = 9000,
        };
        const encoded = try msg.encode(alloc);
        defer alloc.free(encoded);
        const with_extra = try appendExtraShortListField(alloc, encoded);
        defer alloc.free(with_extra);
        try std.testing.expectError(Error.InvalidEncoding, Pong.decode(with_extra));
    }

    {
        const distances = [_]u16{ 256, 255 };
        const msg = FindNode{
            .req_id = try ReqId.fromSlice(&[_]u8{0x01}),
            .distances = &distances,
        };
        const encoded = try msg.encode(alloc);
        defer alloc.free(encoded);
        const with_extra = try appendExtraShortListField(alloc, encoded);
        defer alloc.free(with_extra);
        var distances_out: [2]u16 = undefined;
        try std.testing.expectError(Error.InvalidEncoding, FindNode.decodeInto(with_extra, &distances_out));
    }

    {
        var enr_buf: [16]u8 = undefined;
        var w = rlp.Writer.initBuffer(&enr_buf);
        try w.writeBytesBounded("enr");
        const enr = w.bytes();
        const msg = Nodes{
            .req_id = try ReqId.fromSlice(&[_]u8{0x01}),
            .total = 1,
            .enrs = &.{enr},
        };
        const encoded = try msg.encode(alloc);
        defer alloc.free(encoded);
        const with_extra = try appendExtraShortListField(alloc, encoded);
        defer alloc.free(with_extra);
        var enrs_out: [1][]const u8 = undefined;
        try std.testing.expectError(Error.InvalidEncoding, Nodes.decodeInto(with_extra, &enrs_out));
    }

    {
        const msg = TalkReq{
            .req_id = try ReqId.fromSlice(&[_]u8{0x01}),
            .protocol = "eth",
            .request = "hello",
        };
        const encoded = try msg.encode(alloc);
        defer alloc.free(encoded);
        const with_extra = try appendExtraShortListField(alloc, encoded);
        defer alloc.free(with_extra);
        try std.testing.expectError(Error.InvalidEncoding, TalkReq.decode(with_extra));
    }

    {
        const msg = TalkResp{
            .req_id = try ReqId.fromSlice(&[_]u8{0x01}),
            .response = "hello",
        };
        const encoded = try msg.encode(alloc);
        defer alloc.free(encoded);
        const with_extra = try appendExtraShortListField(alloc, encoded);
        defer alloc.free(with_extra);
        try std.testing.expectError(Error.InvalidEncoding, TalkResp.decode(with_extra));
    }
}
