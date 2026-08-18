const std = @import("std");
const message = @import("message.zig");
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

    const result = try FindNode.decode(alloc, encoded);
    defer alloc.free(result.distances);
    try std.testing.expectEqual(@as(usize, 3), result.distances.len);
    try std.testing.expectEqual(@as(u16, 256), result.distances[0]);
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

    const decoded = try Nodes.decode(alloc, encoded);
    defer {
        for (decoded.enrs) |enr| alloc.free(enr);
        alloc.free(decoded.enrs);
    }

    try std.testing.expectEqual(@as(u64, 2), decoded.msg.total);
    try std.testing.expectEqual(@as(usize, 2), decoded.enrs.len);
    try std.testing.expectEqualSlices(u8, enr_a, decoded.enrs[0]);
    try std.testing.expectEqualSlices(u8, enr_b, decoded.enrs[1]);
}

fn nodesDecodeLifecycle(alloc: std.mem.Allocator, encoded: []const u8) !void {
    const decoded = try Nodes.decode(alloc, encoded);
    for (decoded.enrs) |enr| alloc.free(enr);
    alloc.free(decoded.enrs);
}

test "discv5 messages: NODES decode survives every allocation failure without leaking" {
    const alloc = std.testing.allocator;
    const req_id = try ReqId.fromSlice("id");
    var enr_a_buf: [32]u8 = undefined;
    var w_a = rlp.Writer.initBuffer(&enr_a_buf);
    try w_a.writeBytesBounded("enr-alloc-a");
    var enr_b_buf: [32]u8 = undefined;
    var w_b = rlp.Writer.initBuffer(&enr_b_buf);
    const list_start = try w_b.beginListBounded();
    try w_b.writeBytesBounded("enr-alloc-b");
    try w_b.finishList(list_start);
    var enr_c_buf: [32]u8 = undefined;
    var w_c = rlp.Writer.initBuffer(&enr_c_buf);
    try w_c.writeBytesBounded("enr-alloc-c");
    const msg = Nodes{
        .req_id = req_id,
        .total = 1,
        .enrs = &.{ w_a.bytes(), w_b.bytes(), w_c.bytes() },
    };
    const encoded = try msg.encode(alloc);
    defer alloc.free(encoded);

    try std.testing.checkAllAllocationFailures(alloc, nodesDecodeLifecycle, .{encoded});
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

    const decoded = try Nodes.decode(alloc, encoded);
    defer {
        for (decoded.enrs) |enr| alloc.free(enr);
        alloc.free(decoded.enrs);
    }

    try std.testing.expectEqual(@as(usize, 1), decoded.enrs.len);
    try std.testing.expectEqualSlices(u8, enr_bytes, decoded.enrs[0]);

    const parsed = try enr_mod.decode(decoded.enrs[0]);
    try std.testing.expect((try parsed.nodeId()) != null);
}
