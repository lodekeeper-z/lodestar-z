const std = @import("std");
const enr = @import("enr.zig");
const secp = @import("secp256k1.zig");

const Builder = enr.Builder;
const Error = enr.Error;
const countSubnets = enr.countSubnets;
const decode = enr.decode;
const decodeText = enr.decodeText;
const encodeText = enr.encodeText;
const isSubnetSet = enr.isSubnetSet;

test "ENR Builder: key-value pairs sorted alphabetically (EIP-778)" {
    // Regression test: ENR keys must be sorted alphabetically per EIP-778.
    // Correct order: id, ip, secp256k1, udp
    // Previous bug: id, secp256k1, ip, udp — produced an invalid signature.
    //
    // Test vector from https://github.com/ethereum/devp2p/blob/master/enr.md:
    //   private key: b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291
    //   seq: 1, ip: 127.0.0.1, udp: 30303
    //   expected node-id: a448f24c6d18e575453db13171562b71999873db5b286df957af199ec94617f7
    const hex_mod = @import("hex");
    const alloc = std.testing.allocator;

    const secret_key = hex_mod.hexToBytesComptime(32, "b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291");
    const key_pair = try secp.keyPairFromSecret(&secret_key);
    var builder = Builder.init(alloc, key_pair, 1);
    builder.ip = [4]u8{ 127, 0, 0, 1 };
    builder.udp = 30303;
    const enr_bytes = try builder.encode();
    defer alloc.free(enr_bytes);

    // Re-parse and check the node ID is the expected one (proves the pubkey is embedded correctly)
    const parsed = try decode(enr_bytes);

    const expected_node_id = hex_mod.hexToBytesComptime(32, "a448f24c6d18e575453db13171562b71999873db5b286df957af199ec94617f7");
    const node_id = (try parsed.nodeId()) orelse return error.NoNodeId;
    try std.testing.expectEqualSlices(u8, &expected_node_id, &node_id);
}

test "ENR Builder canonicalizes a naturally high-S devp2p signature" {
    const hex_mod = @import("hex");
    const rlp = @import("rlp.zig");
    const alloc = std.testing.allocator;
    const secret_key = hex_mod.hexToBytesComptime(32, "b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291");
    const key_pair = try secp.keyPairFromSecret(&secret_key);
    var builder = Builder.init(alloc, key_pair, 1);
    builder.ip = .{ 127, 0, 0, 1 };
    builder.udp = 30303;
    const encoded = try builder.encode();
    defer alloc.free(encoded);

    var reader = rlp.Reader.init(encoded);
    var list = try reader.readList();
    const signature = try list.readBytes();
    const expected_low = hex_mod.hexToBytesComptime(64, "7098ad865b00a582051940cb9cf36836572411a47278783077011599ed5cd16b76f2635f4e234738f30813a89eb9137e3e3df5266e3a1f11df72ecf1145ccb9c");
    const half_order = hex_mod.hexToBytesComptime(32, "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0");
    try std.testing.expectEqualSlices(u8, &expected_low, signature);
    try std.testing.expect(std.mem.order(u8, signature[32..], &half_order) != .gt);
    _ = try decode(encoded);
}

test "ENR Builder: encode with eth2 and attnets" {
    const hex_mod = @import("hex");
    const alloc = std.testing.allocator;

    const secret_key = hex_mod.hexToBytesComptime(32, "b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291");
    const key_pair = try secp.keyPairFromSecret(&secret_key);
    var builder = Builder.init(alloc, key_pair, 1);
    builder.ip = [4]u8{ 127, 0, 0, 1 };
    builder.udp = 9000;
    builder.tcp = 9000;
    builder.quic = 9001;
    builder.setEth2([4]u8{ 0x6a, 0x95, 0xa1, 0xb0 }, [4]u8{ 0, 0, 0, 0 }, 0xffffffffffffffff);
    builder.attnets = [8]u8{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

    const enr_bytes = try builder.encode();
    defer alloc.free(enr_bytes);

    // Re-parse and verify fields are present
    const parsed = try decode(enr_bytes);

    try std.testing.expect(parsed.ip != null);
    try std.testing.expectEqual([4]u8{ 127, 0, 0, 1 }, parsed.ip.?);
    try std.testing.expectEqual(@as(?u16, 9000), parsed.udp);
    try std.testing.expectEqual(@as(?u16, 9000), parsed.tcp);
    try std.testing.expectEqual(@as(?u16, 9001), parsed.quic);
    try std.testing.expect(parsed.eth2_fork_digest != null);
    try std.testing.expectEqual([4]u8{ 0x6a, 0x95, 0xa1, 0xb0 }, parsed.eth2_fork_digest.?);
    try std.testing.expect(parsed.attnets != null);
    try std.testing.expectEqual([8]u8{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }, parsed.attnets.?);
}

test "ENR Builder: encode with custody group count" {
    const hex_mod = @import("hex");
    const alloc = std.testing.allocator;

    const secret_key = hex_mod.hexToBytesComptime(32, "b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291");
    const key_pair = try secp.keyPairFromSecret(&secret_key);
    var builder = Builder.init(alloc, key_pair, 1);
    builder.ip = [4]u8{ 127, 0, 0, 1 };
    builder.udp = 9000;
    builder.custody_group_count = 12;

    const enr_bytes = try builder.encode();
    defer alloc.free(enr_bytes);

    const parsed = try decode(enr_bytes);

    try std.testing.expectEqual(@as(?u64, 12), parsed.custody_group_count);
}

test "ENR Builder: encodeToString produces valid enr: prefix" {
    const hex_mod = @import("hex");
    const alloc = std.testing.allocator;

    const secret_key = hex_mod.hexToBytesComptime(32, "b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291");
    const key_pair = try secp.keyPairFromSecret(&secret_key);
    var builder = Builder.init(alloc, key_pair, 1);
    builder.ip = [4]u8{ 127, 0, 0, 1 };
    builder.udp = 9000;

    const enr_str = try builder.encodeToString();
    defer alloc.free(enr_str);

    try std.testing.expect(std.mem.startsWith(u8, enr_str, "enr:"));
}

test "ENR text form round-trips raw bytes" {
    const hex_mod = @import("hex");
    const alloc = std.testing.allocator;

    const secret_key = hex_mod.hexToBytesComptime(32, "b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291");
    const key_pair = try secp.keyPairFromSecret(&secret_key);
    var builder = Builder.init(alloc, key_pair, 1);
    builder.ip = [4]u8{ 127, 0, 0, 1 };
    builder.udp = 9000;

    const enr_bytes = try builder.encode();
    defer alloc.free(enr_bytes);
    const enr_text = try encodeText(alloc, enr_bytes);
    defer alloc.free(enr_text);
    const decoded = try decodeText(alloc, enr_text);
    defer alloc.free(decoded);

    try std.testing.expectEqualSlices(u8, enr_bytes, decoded);
}

test "ENR text form rejects wrong prefix" {
    try std.testing.expectError(Error.InvalidEnr, decodeText(std.testing.allocator, "not-enr"));
}

test "ENR decode rejects tampered signature" {
    const hex_mod = @import("hex");
    const alloc = std.testing.allocator;

    const secret_key = hex_mod.hexToBytesComptime(32, "b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291");
    const key_pair = try secp.keyPairFromSecret(&secret_key);
    var builder = Builder.init(alloc, key_pair, 1);
    builder.ip = [4]u8{ 127, 0, 0, 1 };
    builder.udp = 9000;

    const enr_bytes = try builder.encode();
    defer alloc.free(enr_bytes);

    const tampered = try alloc.dupe(u8, enr_bytes);
    defer alloc.free(tampered);
    tampered[tampered.len - 1] ^= 0x01;

    try std.testing.expectError(Error.InvalidSignature, decode(tampered));
}

test "isSubnetSet and countSubnets" {
    // All subnets set
    const all = [8]u8{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    try std.testing.expectEqual(@as(u32, 64), countSubnets(all));
    try std.testing.expect(isSubnetSet(all, 0));
    try std.testing.expect(isSubnetSet(all, 63));

    // Only subnet 0 set
    const one = [8]u8{ 0x01, 0, 0, 0, 0, 0, 0, 0 };
    try std.testing.expectEqual(@as(u32, 1), countSubnets(one));
    try std.testing.expect(isSubnetSet(one, 0));
    try std.testing.expect(!isSubnetSet(one, 1));

    // Subnet 8 set (bit 0 of byte 1)
    const s8 = [8]u8{ 0, 0x01, 0, 0, 0, 0, 0, 0 };
    try std.testing.expect(isSubnetSet(s8, 8));
    try std.testing.expect(!isSubnetSet(s8, 0));
}
