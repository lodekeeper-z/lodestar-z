//! Official discv5 wire test vectors
//!
//! Tests from discv5-wire-test-vectors.md

const std = @import("std");
const hex = @import("hex");
const packet = @import("protocol/packet.zig");
const secp = @import("secp256k1.zig");
const session = @import("protocol/session.zig");
const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;

const node_a_id = hex.hexToBytesComptime(32, "aaaa8419e9f49d0083561b48287df592939a8d19947d8c0ef88f2a4856a69fbb");
const node_b_id = hex.hexToBytesComptime(32, "bbbb9d047f0488c0b5a93c1c3f2d8bafc7c8ff337024a55434a0d0555de64db9");

// =========== Packet decoding test vectors ===========

test "discv5 wire: ping message packet (flag 0)" {
    // 95 bytes (190 hex chars)
    const raw_hex =
        "00000000000000000000000000000000088b3d4342774649325f313964a39e55" ++
        "ea96c005ad52be8c7560413a7008f16c9e6d2f43bbea8814a546b7409ce783d3" ++
        "4c4f53245d08dab84102ed931f66d1492acb308fa1c6715b9d139b81acbdcc";
    var raw: [95]u8 = undefined;
    _ = try std.fmt.hexToBytes(&raw, raw_hex);

    const parsed = try packet.decode(&raw, &node_b_id);

    try std.testing.expectEqual(packet.FLAG_MESSAGE, parsed.static_header.flag);

    const expected_nonce = hex.hexToBytesComptime(12, "ffffffffffffffffffffffff");
    try std.testing.expectEqualSlices(u8, &expected_nonce, &parsed.static_header.nonce);

    // Decrypt: read-key = 0x00000000000000000000000000000000
    const read_key = [_]u8{0} ** 16;
    var pt_buf: [packet.MAX_PACKET_SIZE]u8 = undefined;
    var ad_buf: [packet.MAX_PACKET_SIZE]u8 = undefined;
    const pt = try packet.decryptMessageInto(
        &pt_buf,
        &ad_buf,
        &read_key,
        &parsed.static_header.nonce,
        parsed.message_ciphertext,
        &parsed.masking_iv,
        parsed.header_raw,
    );

    try std.testing.expectEqual(@as(u8, 0x01), pt[0]);

    const msg = @import("protocol/message.zig");
    const ping = try msg.Ping.decode(pt);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x00, 0x00, 0x01 }, ping.req_id.slice());
    try std.testing.expectEqual(@as(u64, 2), ping.enr_seq);
}

test "discv5 wire: WHOAREYOU packet (flag 1)" {
    const raw_hex =
        "00000000000000000000000000000000088b3d434277464933a1ccc59f5967ad" ++
        "1d6035f15e528627dde75cd68292f9e6c27d6b66c8100a873fcbaed4e16b8d";
    var raw: [63]u8 = undefined;
    _ = try std.fmt.hexToBytes(&raw, raw_hex);

    const parsed = try packet.decode(&raw, &node_b_id);

    try std.testing.expectEqual(packet.FLAG_WHOAREYOU, parsed.static_header.flag);
    try std.testing.expectEqual(@as(u16, 24), parsed.static_header.authdata_size);

    const id_nonce = parsed.authdata_raw[0..16];
    const expected_nonce = hex.hexToBytesComptime(16, "0102030405060708090a0b0c0d0e0f10");
    try std.testing.expectEqualSlices(u8, &expected_nonce, id_nonce);

    const enr_seq_bytes = parsed.authdata_raw[16..24];
    const enr_seq = std.mem.readInt(u64, enr_seq_bytes[0..8], .big);
    try std.testing.expectEqual(@as(u64, 0), enr_seq);
}

test "discv5 wire: ping handshake packet (flag 2, no ENR)" {
    const raw_hex =
        "00000000000000000000000000000000088b3d4342774649305f313964a39e55" ++
        "ea96c005ad521d8c7560413a7008f16c9e6d2f43bbea8814a546b7409ce783d3" ++
        "4c4f53245d08da4bb252012b2cba3f4f374a90a75cff91f142fa9be3e0a5f3ef" ++
        "268ccb9065aeecfd67a999e7fdc137e062b2ec4a0eb92947f0d9a74bfbf44dfb" ++
        "a776b21301f8b65efd5796706adff216ab862a9186875f9494150c4ae06fa4d1" ++
        "f0396c93f215fa4ef524f1eadf5f0f4126b79336671cbcf7a885b1f8bd2a5d83" ++
        "9cf8";
    var raw: [194]u8 = undefined;
    _ = try std.fmt.hexToBytes(&raw, raw_hex);

    const parsed = try packet.decode(&raw, &node_b_id);

    try std.testing.expectEqual(packet.FLAG_HANDSHAKE, parsed.static_header.flag);

    const authdata = parsed.authdata_raw;
    const src_id = authdata[0..32];
    try std.testing.expectEqualSlices(u8, &node_a_id, src_id);

    const sig_size = authdata[32];
    const eph_key_size = authdata[33];
    try std.testing.expectEqual(@as(u8, 64), sig_size);
    try std.testing.expectEqual(@as(u8, 33), eph_key_size);

    const eph_pubkey = authdata[34 + sig_size .. 34 + sig_size + eph_key_size];
    const expected_eph_pubkey = hex.hexToBytesComptime(33, "039a003ba6517b473fa0cd74aefe99dadfdb34627f90fec6362df85803908f53a5");
    try std.testing.expectEqualSlices(u8, &expected_eph_pubkey, eph_pubkey);

    // Decrypt: read-key = 0x4f9fac6de7567d1e3b1241dffe90f662
    const read_key = hex.hexToBytesComptime(16, "4f9fac6de7567d1e3b1241dffe90f662");
    const nonce = hex.hexToBytesComptime(12, "ffffffffffffffffffffffff");

    var pt_buf: [packet.MAX_PACKET_SIZE]u8 = undefined;
    var ad_buf: [packet.MAX_PACKET_SIZE]u8 = undefined;
    const pt = try packet.decryptMessageInto(
        &pt_buf,
        &ad_buf,
        &read_key,
        &nonce,
        parsed.message_ciphertext,
        &parsed.masking_iv,
        parsed.header_raw,
    );

    try std.testing.expectEqual(@as(u8, 0x01), pt[0]);
    const msg = @import("protocol/message.zig");
    const ping = try msg.Ping.decode(pt);
    try std.testing.expectEqual(@as(u64, 1), ping.enr_seq);
}

test "discv5 wire: ping handshake with ENR (flag 2)" {
    const raw_hex =
        "00000000000000000000000000000000088b3d4342774649305f313964a39e55" ++
        "ea96c005ad539c8c7560413a7008f16c9e6d2f43bbea8814a546b7409ce783d3" ++
        "4c4f53245d08da4bb23698868350aaad22e3ab8dd034f548a1c43cd246be9856" ++
        "2fafa0a1fa86d8e7a3b95ae78cc2b988ded6a5b59eb83ad58097252188b902b2" ++
        "1481e30e5e285f19735796706adff216ab862a9186875f9494150c4ae06fa4d1" ++
        "f0396c93f215fa4ef524e0ed04c3c21e39b1868e1ca8105e585ec17315e755e6" ++
        "cfc4dd6cb7fd8e1a1f55e49b4b5eb024221482105346f3c82b15fdaae36a3bb1" ++
        "2a494683b4a3c7f2ae41306252fed84785e2bbff3b022812d0882f06978df84a" ++
        "80d443972213342d04b9048fc3b1d5fcb1df0f822152eced6da4d3f6df27e70e" ++
        "4539717307a0208cd208d65093ccab5aa596a34d7511401987662d8cf62b1394" ++
        "71";
    var raw: [321]u8 = undefined;
    _ = try std.fmt.hexToBytes(&raw, raw_hex);

    const parsed = try packet.decode(&raw, &node_b_id);

    try std.testing.expectEqual(packet.FLAG_HANDSHAKE, parsed.static_header.flag);

    const authdata = parsed.authdata_raw;
    const sig_size = authdata[32];
    const eph_key_size = authdata[33];

    const record_start = 34 + sig_size + eph_key_size;
    try std.testing.expect(authdata.len > record_start);

    // Decrypt: read-key = 0x53b1c075f41876423154e157470c2f48
    const read_key = hex.hexToBytesComptime(16, "53b1c075f41876423154e157470c2f48");
    const nonce = hex.hexToBytesComptime(12, "ffffffffffffffffffffffff");

    var pt_buf: [packet.MAX_PACKET_SIZE]u8 = undefined;
    var ad_buf: [packet.MAX_PACKET_SIZE]u8 = undefined;
    const pt = try packet.decryptMessageInto(
        &pt_buf,
        &ad_buf,
        &read_key,
        &nonce,
        parsed.message_ciphertext,
        &parsed.masking_iv,
        parsed.header_raw,
    );

    try std.testing.expectEqual(@as(u8, 0x01), pt[0]);
    const msg = @import("protocol/message.zig");
    const ping = try msg.Ping.decode(pt);
    try std.testing.expectEqual(@as(u64, 1), ping.enr_seq);
}

// =========== Cryptographic primitive test vectors ===========
