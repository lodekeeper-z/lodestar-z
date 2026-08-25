const std = @import("std");
const message = @import("message.zig");
const packet = @import("packet.zig");
const rlp = @import("../rlp.zig");

const Error = message.Error;
const FindNode = message.FindNode;
const MSG_PONG = message.MSG_PONG;
const Nodes = message.Nodes;
const Pong = message.Pong;
const ReqId = message.ReqId;
const TalkReq = message.TalkReq;

test "discv5 messages: PONG encode/decode" {
    const alloc = std.testing.allocator;
    const pong = Pong{
        .req_id = try ReqId.fromSlice(&[_]u8{ 0x00, 0x00, 0x00, 0x01 }),
        .enr_seq = 1,
        .recipient_ip = .{ .ip4 = [4]u8{ 127, 0, 0, 1 } },
        .recipient_port = 9000,
    };
    const encoded = try pong.encode(alloc);
    defer alloc.free(encoded);

    const decoded = try Pong.decode(encoded);
    try std.testing.expectEqual(@as(u64, 1), decoded.enr_seq);
    try std.testing.expectEqual(@as(u16, 9000), decoded.recipient_port);
    try std.testing.expectEqualDeep(pong.recipient_ip, decoded.recipient_ip);
}

test "discv5 messages: PONG encode/decode IPv6" {
    const alloc = std.testing.allocator;
    const pong = Pong{
        .req_id = try ReqId.fromSlice(&[_]u8{ 0x00, 0x00, 0x00, 0x02 }),
        .enr_seq = 2,
        .recipient_ip = .{ .ip6 = [16]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } },
        .recipient_port = 9001,
    };
    const encoded = try pong.encode(alloc);
    defer alloc.free(encoded);

    const decoded = try Pong.decode(encoded);
    try std.testing.expectEqual(@as(u64, 2), decoded.enr_seq);
    try std.testing.expectEqual(@as(u16, 9001), decoded.recipient_port);
    try std.testing.expectEqualDeep(pong.recipient_ip, decoded.recipient_ip);
}

test "discv5 messages: PONG rejects a non-canonical port integer" {
    const encoded = [_]u8{
        MSG_PONG,
        0xca,
        0x01,
        0x80,
        0x84,
        127,
        0,
        0,
        1,
        0x82,
        0,
        1,
    };
    try std.testing.expectError(Error.InvalidEncoding, Pong.decode(&encoded));
}

test "discv5 messages: FINDNODE encode/decode" {
    const alloc = std.testing.allocator;
    const distances = [_]u16{ 256, 255, 254 };
    const msg = FindNode{
        .req_id = try ReqId.fromSlice(&[_]u8{0x01}),
        .distances = &distances,
    };
    const encoded = try msg.encode(alloc);
    defer alloc.free(encoded);

    var distances_out: [3]u16 = undefined;
    const decoded = try FindNode.decodeInto(encoded, &distances_out);
    try std.testing.expectEqual(@as(usize, 3), decoded.distances.len);
    try std.testing.expectEqual(@as(u16, 256), decoded.distances[0]);
}

test "discv5 messages: fitting 128-distance FINDNODE round-trips through public codecs" {
    const alloc = std.testing.allocator;
    const distances = [_]u16{1} ** 128;
    const msg = FindNode{
        .req_id = try ReqId.fromSlice(&.{0x01}),
        .distances = &distances,
    };

    const encoded = try msg.encode(alloc);
    defer alloc.free(encoded);

    var distances_out: [128]u16 = undefined;
    const decoded = try FindNode.decodeInto(encoded, &distances_out);
    try std.testing.expectEqualSlices(u16, &distances, decoded.distances);
}

fn encodeFindNodeWireUnchecked(out: []u8, distances: []const u16) ![]const u8 {
    out[0] = message.MSG_FINDNODE;
    var writer = rlp.Writer.initBuffer(out[1..]);
    const message_start = try writer.beginListBounded();
    try writer.writeBytesBounded(&.{});
    const distances_start = try writer.beginListBounded();
    for (distances) |distance| try writer.writeUint64Bounded(distance);
    try writer.finishList(distances_start);
    try writer.finishList(message_start);
    return out[0 .. 1 + writer.bytes().len];
}

test "discv5 messages: FINDNODE rejects distance 257 through public codecs" {
    const alloc = std.testing.allocator;
    const invalid = FindNode{
        .req_id = try ReqId.fromSlice(&.{}),
        .distances = &.{257},
    };
    var encoded_buffer: [message.MAX_ENCODED_SIZE]u8 = undefined;
    try std.testing.expectError(Error.InvalidMessage, invalid.encode(alloc));
    try std.testing.expectError(Error.InvalidMessage, invalid.encodeInto(&encoded_buffer));

    const encoded = try encodeFindNodeWireUnchecked(&encoded_buffer, &.{257});
    var distance_out: [1]u16 = undefined;
    try std.testing.expectError(Error.InvalidMessage, FindNode.decodeInto(encoded, &distance_out));
}

test "discv5 messages: FINDNODE decodeInto validates a later invalid distance before output capacity" {
    var encoded_buffer: [message.MAX_ENCODED_SIZE]u8 = undefined;
    const encoded = try encodeFindNodeWireUnchecked(&encoded_buffer, &.{ 1, 257 });
    var storage = [_]u16{0xa5a5};
    const unchanged = storage;

    try std.testing.expectError(Error.InvalidMessage, FindNode.decodeInto(encoded, storage[0..0]));
    try std.testing.expectEqualSlices(u16, &unchanged, &storage);
    try std.testing.expectError(Error.InvalidMessage, FindNode.decodeInto(encoded, storage[0..1]));
    try std.testing.expectEqualSlices(u16, &unchanged, &storage);
}

test "discv5 messages: FINDNODE decodeInto validates later noncanonical RLP before output capacity" {
    const encoded = [_]u8{
        message.MSG_FINDNODE,
        0xc5, // [request-id, distances]
        0x80, // empty request ID
        0xc3, // two distance items occupy three bytes
        0x01,
        0x81, 0x02, // noncanonical encoding of the single byte 0x02
    };
    var storage = [_]u16{0xa5a5};
    const unchanged = storage;

    try std.testing.expectError(Error.InvalidEncoding, FindNode.decodeInto(&encoded, storage[0..0]));
    try std.testing.expectEqualSlices(u16, &unchanged, &storage);
    try std.testing.expectError(Error.InvalidEncoding, FindNode.decodeInto(&encoded, storage[0..1]));
    try std.testing.expectEqualSlices(u16, &unchanged, &storage);
}

test "discv5 messages: FINDNODE decodeInto valid input is failure-atomic when output is undersized" {
    var encoded_buffer: [message.MAX_ENCODED_SIZE]u8 = undefined;
    const encoded = try encodeFindNodeWireUnchecked(&encoded_buffer, &.{ 1, 2 });
    var storage = [_]u16{0xa5a5};
    const unchanged = storage;

    try std.testing.expectError(Error.BufferTooSmall, FindNode.decodeInto(encoded, &storage));
    try std.testing.expectEqualSlices(u16, &unchanged, &storage);
}

test "discv5 messages: FINDNODE encodeInto reports undersized output buffers" {
    const request = FindNode{
        .req_id = try ReqId.fromSlice(&.{0x01}),
        .distances = &.{ 1, 2 },
    };
    var storage = [_]u8{0xa5} ** 6;

    try std.testing.expectError(Error.BufferTooSmall, request.encodeInto(storage[0..0]));
    try std.testing.expectError(Error.BufferTooSmall, request.encodeInto(&storage));
}

test "discv5 messages: FINDNODE wire cardinality accepts 1185 and rejects 1186" {
    const alloc = std.testing.allocator;
    const maximum = [_]u16{0} ** 1185;
    const accepted = FindNode{
        .req_id = try ReqId.fromSlice(&.{}),
        .distances = &maximum,
    };

    const encoded = try accepted.encode(alloc);
    defer alloc.free(encoded);
    const max_ordinary_plaintext = packet.MAX_PACKET_SIZE - packet.MASKING_IV_SIZE - packet.STATIC_HEADER_SIZE - packet.NODE_ID_SIZE - packet.GCM_TAG_SIZE;
    try std.testing.expectEqual(max_ordinary_plaintext, encoded.len);

    var encoded_into_buffer: [message.MAX_ENCODED_SIZE]u8 = undefined;
    const encoded_into = try accepted.encodeInto(&encoded_into_buffer);
    try std.testing.expectEqualSlices(u8, encoded, encoded_into);

    var maximum_out: [1185]u16 = undefined;
    const decoded = try FindNode.decodeInto(encoded, &maximum_out);
    try std.testing.expectEqualSlices(u16, &maximum, decoded.distances);

    const excessive = [_]u16{0} ** 1186;
    const rejected = FindNode{
        .req_id = try ReqId.fromSlice(&.{}),
        .distances = &excessive,
    };
    try std.testing.expectError(Error.InvalidMessage, rejected.encode(alloc));
    try std.testing.expectError(Error.InvalidMessage, rejected.encodeInto(&encoded_into_buffer));

    var oversized_buffer: [message.MAX_ENCODED_SIZE + 1]u8 = undefined;
    const oversized = try encodeFindNodeWireUnchecked(&oversized_buffer, &excessive);
    var excessive_out: [1186]u16 = undefined;
    try std.testing.expectError(Error.InvalidMessage, FindNode.decodeInto(oversized, &excessive_out));
}

test "discv5 messages: TALKREQ encode/decode" {
    const alloc = std.testing.allocator;
    const req = TalkReq{
        .req_id = try ReqId.fromSlice(&[_]u8{0x01}),
        .protocol = "eth",
        .request = "hello",
    };
    const encoded = try req.encode(alloc);
    defer alloc.free(encoded);

    const decoded = try TalkReq.decode(encoded);
    try std.testing.expectEqualSlices(u8, "eth", decoded.protocol);
    try std.testing.expectEqualSlices(u8, "hello", decoded.request);
}

test "discv5 messages: NODES encode/decode" {
    const alloc = std.testing.allocator;
    const req_id = try ReqId.fromSlice("id");
    var enr_a_buf: [32]u8 = undefined;
    var w_a = rlp.Writer.initBuffer(&enr_a_buf);
    try w_a.writeBytesBounded("enr-a");
    const enr_a = try alloc.dupe(u8, w_a.bytes());
    defer alloc.free(enr_a);

    var enr_b_buf: [32]u8 = undefined;
    var w_b = rlp.Writer.initBuffer(&enr_b_buf);
    const list_start = try w_b.beginListBounded();
    try w_b.writeBytesBounded("enr-b");
    try w_b.finishList(list_start);
    const enr_b = try alloc.dupe(u8, w_b.bytes());
    defer alloc.free(enr_b);
    const msg = Nodes{
        .req_id = req_id,
        .total = 2,
        .enrs = &.{ enr_a, enr_b },
    };

    const encoded = try msg.encode(alloc);
    defer alloc.free(encoded);

    var enrs_out: [2][]const u8 = undefined;
    const decoded = try Nodes.decodeInto(encoded, &enrs_out);
    try std.testing.expectEqual(@as(u64, 2), decoded.total);
    try std.testing.expectEqual(@as(usize, 2), decoded.enrs.len);
    try std.testing.expectEqualSlices(u8, enr_a, decoded.enrs[0]);
    try std.testing.expectEqualSlices(u8, enr_b, decoded.enrs[1]);
}

test "discv5 messages: NODES decode returns encoded ENR bytes" {
    const alloc = std.testing.allocator;
    const enr_mod = @import("../enr.zig");
    const hex_mod = @import("hex");
    const secp = @import("../secp256k1.zig");

    const secret_key = hex_mod.hexToBytesComptime(32, "b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291");
    const key_pair = try secp.keyPairFromSecret(&secret_key);
    var builder = enr_mod.Builder.init(alloc, key_pair, 1);
    builder.ip = [4]u8{ 127, 0, 0, 1 };
    builder.udp = 9000;
    const enr_bytes = try builder.encode();
    defer alloc.free(enr_bytes);

    const req_id = try ReqId.fromSlice("id");
    const msg = Nodes{
        .req_id = req_id,
        .total = 1,
        .enrs = &.{enr_bytes},
    };

    const encoded = try msg.encode(alloc);
    defer alloc.free(encoded);

    var enrs_out: [1][]const u8 = undefined;
    const decoded = try Nodes.decodeInto(encoded, &enrs_out);

    try std.testing.expectEqual(@as(usize, 1), decoded.enrs.len);
    try std.testing.expectEqualSlices(u8, enr_bytes, decoded.enrs[0]);

    const parsed = try enr_mod.decode(decoded.enrs[0]);
    try std.testing.expect((try parsed.nodeId()) != null);
}
