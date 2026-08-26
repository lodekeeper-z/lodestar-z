//! Discovery v5 packet encoding/decoding

const std = @import("std");
const handshake = @import("handshake.zig");
const Aes128 = std.crypto.core.aes.Aes128;
const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;

pub const MASKING_IV_SIZE = 16;
pub const MIN_PACKET_SIZE: usize = 63;
pub const MAX_PACKET_SIZE: usize = 1280;
pub const STATIC_HEADER_SIZE = 6 + 2 + 1 + 12 + 2; // = 23
pub const PROTOCOL_ID = "discv5";
pub const VERSION: u16 = 0x0001;

pub const FLAG_MESSAGE: u8 = 0;
pub const FLAG_WHOAREYOU: u8 = 1;
pub const FLAG_HANDSHAKE: u8 = 2;

pub const NONCE_SIZE = 12;
pub const NODE_ID_SIZE = 32;
pub const GCM_TAG_SIZE = 16;
pub const ID_NONCE_SIZE = 16;
pub const WHOAREYOU_AUTHDATA_SIZE = ID_NONCE_SIZE + 8;
pub const WHOAREYOU_CHALLENGE_DATA_SIZE = MASKING_IV_SIZE + STATIC_HEADER_SIZE + WHOAREYOU_AUTHDATA_SIZE;
pub const MAX_ORDINARY_MESSAGE_SIZE = MAX_PACKET_SIZE - MASKING_IV_SIZE - STATIC_HEADER_SIZE - NODE_ID_SIZE - GCM_TAG_SIZE;
const MAX_DECRYPTED_MESSAGE_SIZE = MAX_PACKET_SIZE - GCM_TAG_SIZE;
const MAX_RECOVERY_OVERHEAD = MASKING_IV_SIZE + STATIC_HEADER_SIZE + handshake.MAX_AUTHDATA_SIZE + GCM_TAG_SIZE;
pub const MAX_RECOVERABLE_PLAINTEXT_SIZE = std.math.sub(usize, MAX_PACKET_SIZE, MAX_RECOVERY_OVERHEAD) catch
    @compileError("maximum handshake framing exceeds the discv5 packet size");

comptime {
    std.debug.assert(MAX_RECOVERY_OVERHEAD <= MAX_PACKET_SIZE);
    std.debug.assert(MAX_RECOVERABLE_PLAINTEXT_SIZE == 794);
    std.debug.assert(MAX_RECOVERY_OVERHEAD + MAX_RECOVERABLE_PLAINTEXT_SIZE == MAX_PACKET_SIZE);
}

/// Whether an ordinary packet with fixed NodeId authdata fits the wire limit.
/// Layout: masking IV || static header || NodeId authdata || plaintext || GCM tag.
pub fn ordinaryMessageFits(plaintext_len: usize) bool {
    return plaintext_len <= MAX_ORDINARY_MESSAGE_SIZE;
}

pub const Error = error{
    InvalidPacket,
    InvalidProtocolId,
    UnsupportedVersion,
    DecryptionFailed,
    BufferTooSmall,
    InvalidFlag,
    OutOfMemory,
};

pub const StaticHeader = struct {
    protocol_id: [6]u8,
    version: u16,
    flag: u8,
    nonce: [12]u8,
    authdata_size: u16,
};

/// Views into a decoded discv5 packet.
///
/// `decode` mutates the caller-owned packet buffer in place: bytes
/// `MASKING_IV_SIZE..MASKING_IV_SIZE + header_raw.len` are changed from the
/// masked wire header into the plaintext `static_header || authdata` header.
/// The message ciphertext bytes are not modified.
///
/// All slices in this struct borrow from that caller-owned packet buffer, so a
/// `ParsedPacket` must not outlive the `raw` buffer passed to `decode`.
pub const OrdinaryAuthdata = struct {
    src_id: [NODE_ID_SIZE]u8,
};

pub const WhoareyouAuthdata = struct {
    id_nonce: [ID_NONCE_SIZE]u8,
    enr_seq: u64,
};

pub const PacketForm = union(enum) {
    ordinary: OrdinaryAuthdata,
    whoareyou: WhoareyouAuthdata,
    handshake: handshake.Authdata,
};

pub const DecodedPacket = struct {
    masking_iv: [16]u8,
    /// Plaintext `static_header || authdata`, used as AES-GCM associated data.
    header_raw: []const u8,
    static_header: StaticHeader,
    /// Plaintext authdata slice inside `header_raw`.
    authdata_raw: []const u8,
    /// Encrypted message payload slice inside the original packet buffer.
    message_ciphertext: []const u8,
    /// Typed authdata, validated exactly once while decoding the packet form.
    form: PacketForm,
};

pub const ParsedPacket = DecodedPacket;

comptime {
    std.debug.assert(@sizeOf(DecodedPacket) <= 256);
}

pub const MessagePacketKind = enum {
    ordinary,
    handshake,

    fn flag(self: MessagePacketKind) u8 {
        return switch (self) {
            .ordinary => FLAG_MESSAGE,
            .handshake => FLAG_HANDSHAKE,
        };
    }
};

pub const MessagePacketArgs = struct {
    kind: MessagePacketKind,
    masking_iv: *const [MASKING_IV_SIZE]u8,
    recipient_node_id: *const [NODE_ID_SIZE]u8,
    nonce: *const [NONCE_SIZE]u8,
    authdata: []const u8,
    write_key: *const [16]u8,
    plaintext: []const u8,
};

pub const WhoareyouPacketArgs = struct {
    masking_iv: *const [MASKING_IV_SIZE]u8,
    recipient_node_id: *const [NODE_ID_SIZE]u8,
    request_nonce: *const [NONCE_SIZE]u8,
    id_nonce: *const [ID_NONCE_SIZE]u8,
    enr_seq: u64,
};

/// AES-128-CTR encrypt/decrypt in place
pub fn aesCtr(key: *const [16]u8, iv: *const [16]u8, data: []u8) void {
    const aes = Aes128.initEnc(key.*);
    var counter = iv.*;
    var i: usize = 0;
    while (i < data.len) {
        var keystream: [16]u8 = undefined;
        aes.encrypt(&keystream, &counter);
        // Increment counter (big-endian)
        var j: usize = 15;
        while (true) {
            counter[j] +%= 1;
            if (counter[j] != 0) break;
            if (j == 0) break;
            j -= 1;
        }
        const chunk = @min(16, data.len - i);
        for (0..chunk) |k| {
            data[i + k] ^= keystream[k];
        }
        i += chunk;
    }
}

/// Decode a raw UDP packet in place.
///
/// The caller must pass a mutable packet buffer. On success, the header bytes in
/// `raw` are unmasked in place and the returned `ParsedPacket` borrows slices
/// from `raw`. The message ciphertext is left untouched. On failure before the
/// final in-place unmasking step, `raw` is left unchanged.
pub fn decode(raw: []u8, dest_node_id: *const [32]u8) Error!DecodedPacket {
    try validatePacketSize(raw.len);

    const masking_iv = raw[0..16].*;
    const masking_key = dest_node_id[0..16];

    // Probe a bounded stack copy first so `raw` remains unchanged until the
    // complete packet contract, including per-flag framing, has been validated.
    const masked_static = raw[16 .. 16 + STATIC_HEADER_SIZE];
    var static_buf: [STATIC_HEADER_SIZE]u8 = undefined;
    @memcpy(&static_buf, masked_static);
    aesCtr(masking_key[0..16], &masking_iv, &static_buf);

    if (!std.mem.eql(u8, static_buf[0..6], PROTOCOL_ID)) {
        return Error.InvalidProtocolId;
    }

    const version = std.mem.readInt(u16, static_buf[6..8], .big);
    if (version != VERSION) return Error.UnsupportedVersion;

    const flag = static_buf[8];
    const nonce = static_buf[9..21].*;
    const authdata_size = std.mem.readInt(u16, static_buf[21..23], .big);

    const header_total = std.math.add(usize, STATIC_HEADER_SIZE, authdata_size) catch return Error.InvalidPacket;
    const message_offset = std.math.add(usize, MASKING_IV_SIZE, header_total) catch return Error.InvalidPacket;
    if (header_total > MAX_PACKET_SIZE - MASKING_IV_SIZE or message_offset > raw.len) return Error.InvalidPacket;

    var header_buf: [MAX_PACKET_SIZE - MASKING_IV_SIZE]u8 = undefined;
    @memcpy(header_buf[0..header_total], raw[MASKING_IV_SIZE..message_offset]);
    aesCtr(masking_key[0..16], &masking_iv, header_buf[0..header_total]);
    const authdata = header_buf[STATIC_HEADER_SIZE..header_total];
    const validated_form = try validatePacket(flag, authdata, raw.len - message_offset, raw.len);

    const header_raw = raw[16 .. 16 + header_total];
    @memcpy(header_raw, header_buf[0..header_total]);

    const static_header = StaticHeader{
        .protocol_id = header_raw[0..6].*,
        .version = std.mem.readInt(u16, header_raw[6..8], .big),
        .flag = flag,
        .nonce = nonce,
        .authdata_size = authdata_size,
    };

    const authdata_raw = header_raw[STATIC_HEADER_SIZE..header_total];
    const message_ciphertext = raw[16 + header_total ..];
    const form = rebaseForm(validated_form, authdata_raw);

    return DecodedPacket{
        .masking_iv = masking_iv,
        .header_raw = header_raw,
        .static_header = static_header,
        .authdata_raw = authdata_raw,
        .message_ciphertext = message_ciphertext,
        .form = form,
    };
}

/// Move already validated handshake views from bounded decode scratch onto the
/// caller-owned packet bytes without interpreting authdata a second time.
fn rebaseForm(validated: PacketForm, authdata: []const u8) PacketForm {
    return switch (validated) {
        .ordinary => |value| .{ .ordinary = value },
        .whoareyou => |value| .{ .whoareyou = value },
        .handshake => |value| blk: {
            const sig_end = handshake.AUTHDATA_HEAD_SIZE + @as(usize, handshake.sig_size);
            const eph_end = sig_end + @as(usize, handshake.eph_key_size);
            std.debug.assert(authdata.len >= eph_end);
            break :blk .{ .handshake = .{
                .src_id = value.src_id,
                .id_sig = authdata[handshake.AUTHDATA_HEAD_SIZE..][0..handshake.sig_size],
                .eph_pubkey = authdata[sig_end..][0..handshake.eph_key_size],
                .maybe_enr = if (value.maybe_enr != null) authdata[eph_end..] else null,
            } };
        },
    };
}

/// Decrypt a message packet using AES-128-GCM
/// Decrypt a message packet into caller-owned memory.
///
/// `out` must hold the plaintext (`ciphertext.len - GCM_TAG_SIZE`), and
/// `ad_buf` must hold `masking_iv || header_raw`. `ad_buf` is private scratch
/// and must not overlap `out` or the packet inputs. `out` may overlap
/// `ciphertext`: authentication consumes the complete input before plaintext is
/// published. On every error, `out` remains byte-for-byte unchanged.
pub fn decryptMessageInto(
    out: []u8,
    ad_buf: []u8,
    read_key: *const [16]u8,
    nonce: *const [12]u8,
    ciphertext: []const u8,
    masking_iv: *const [16]u8,
    header_raw: []const u8,
) Error![]u8 {
    if (ciphertext.len < GCM_TAG_SIZE) return Error.DecryptionFailed;

    const ct = ciphertext[0 .. ciphertext.len - GCM_TAG_SIZE];
    if (ct.len > MAX_DECRYPTED_MESSAGE_SIZE) return Error.InvalidPacket;
    if (ct.len > out.len) return Error.BufferTooSmall;
    const ad_len = std.math.add(usize, MASKING_IV_SIZE, header_raw.len) catch return Error.InvalidPacket;
    if (ad_len > MAX_PACKET_SIZE) return Error.InvalidPacket;
    if (ad_len > ad_buf.len) return Error.BufferTooSmall;

    var tag: [GCM_TAG_SIZE]u8 = undefined;
    @memcpy(&tag, ciphertext[ciphertext.len - GCM_TAG_SIZE ..]);

    const ad = ad_buf[0..ad_len];
    @memcpy(ad[0..MASKING_IV_SIZE], masking_iv);
    @memcpy(ad[MASKING_IV_SIZE..], header_raw);

    var plaintext_scratch: [MAX_DECRYPTED_MESSAGE_SIZE]u8 = undefined;
    defer std.crypto.secureZero(u8, &plaintext_scratch);
    const plaintext = plaintext_scratch[0..ct.len];
    Aes128Gcm.decrypt(plaintext, ct, tag, ad, nonce.*, read_key.*) catch {
        return Error.DecryptionFailed;
    };

    @memcpy(out[0..ct.len], plaintext);
    return out[0..ct.len];
}

/// Encode an ordinary or handshake message packet.
///
/// The header is written in plaintext first so it can serve as AES-GCM
/// associated data together with the masking IV. It is masked in place only
/// after the ciphertext and tag have been produced.
/// Encode an ordinary or handshake message packet into caller-owned memory.
pub fn encodeMessagePacketInto(out: []u8, args: MessagePacketArgs) Error![]u8 {
    const header_total = try headerSize(args.authdata);
    const message_offset = std.math.add(usize, MASKING_IV_SIZE, header_total) catch return Error.InvalidPacket;
    const tag_offset = std.math.add(usize, message_offset, args.plaintext.len) catch return Error.InvalidPacket;
    const total = std.math.add(usize, tag_offset, GCM_TAG_SIZE) catch return Error.InvalidPacket;
    const message_size = std.math.add(usize, args.plaintext.len, GCM_TAG_SIZE) catch return Error.InvalidPacket;
    _ = try validatePacket(args.kind.flag(), args.authdata, message_size, total);
    if (total > out.len) return Error.BufferTooSmall;

    const encoded = out[0..total];
    @memcpy(encoded[0..MASKING_IV_SIZE], args.masking_iv);
    const header = encoded[MASKING_IV_SIZE..][0..header_total];
    try writeHeader(header, args.kind.flag(), args.nonce, args.authdata);

    const ad = encoded[0..message_offset];
    const ciphertext = encoded[message_offset..tag_offset];
    var tag: [GCM_TAG_SIZE]u8 = undefined;
    Aes128Gcm.encrypt(ciphertext, &tag, args.plaintext, ad, args.nonce.*, args.write_key.*);
    @memcpy(encoded[tag_offset..], &tag);

    aesCtr(args.recipient_node_id[0..MASKING_IV_SIZE], args.masking_iv, header);
    return encoded;
}

/// Encode a WHOAREYOU challenge packet.
///
/// If `challenge_data_out` is provided, it receives
/// `masking_iv || plaintext_static_header || plaintext_authdata`, the exact
/// challenge data used by the identity proof.
/// Encode a WHOAREYOU challenge packet into caller-owned memory.
pub fn encodeWhoareyouPacketInto(
    out: []u8,
    args: WhoareyouPacketArgs,
    challenge_data_out: ?*[WHOAREYOU_CHALLENGE_DATA_SIZE]u8,
) Error![]u8 {
    var authdata: [WHOAREYOU_AUTHDATA_SIZE]u8 = undefined;
    @memcpy(authdata[0..ID_NONCE_SIZE], args.id_nonce);
    std.mem.writeInt(u64, authdata[ID_NONCE_SIZE..WHOAREYOU_AUTHDATA_SIZE], args.enr_seq, .big);
    _ = try validatePacket(FLAG_WHOAREYOU, &authdata, 0, WHOAREYOU_CHALLENGE_DATA_SIZE);
    if (out.len < WHOAREYOU_CHALLENGE_DATA_SIZE) return Error.BufferTooSmall;

    const encoded = out[0..WHOAREYOU_CHALLENGE_DATA_SIZE];
    @memcpy(encoded[0..MASKING_IV_SIZE], args.masking_iv);
    const header = encoded[MASKING_IV_SIZE..];
    try writeHeader(header, FLAG_WHOAREYOU, args.request_nonce, &authdata);

    if (challenge_data_out) |challenge_out| {
        challenge_out.* = encoded[0..WHOAREYOU_CHALLENGE_DATA_SIZE].*;
    }

    aesCtr(args.recipient_node_id[0..MASKING_IV_SIZE], args.masking_iv, header);
    return encoded;
}

fn headerSize(authdata: []const u8) Error!usize {
    if (authdata.len > std.math.maxInt(u16)) return Error.InvalidPacket;
    return std.math.add(usize, STATIC_HEADER_SIZE, authdata.len) catch Error.InvalidPacket;
}

/// Canonical wire-contract validation shared by decoding and every encoder.
/// Handshake ENR contents are validated later, while fixed framing is checked here.
fn validatePacketSize(packet_size: usize) Error!void {
    if (packet_size < MIN_PACKET_SIZE or packet_size > MAX_PACKET_SIZE) return Error.InvalidPacket;
}

fn validatePacket(flag: u8, authdata: []const u8, message_size: usize, packet_size: usize) Error!PacketForm {
    try validatePacketSize(packet_size);
    return switch (flag) {
        FLAG_MESSAGE => {
            if (authdata.len != NODE_ID_SIZE or message_size < GCM_TAG_SIZE) return Error.InvalidPacket;
            return .{ .ordinary = .{ .src_id = authdata[0..NODE_ID_SIZE].* } };
        },
        FLAG_WHOAREYOU => {
            if (authdata.len != WHOAREYOU_AUTHDATA_SIZE or message_size != 0) return Error.InvalidPacket;
            return .{ .whoareyou = .{
                .id_nonce = authdata[0..ID_NONCE_SIZE].*,
                .enr_seq = std.mem.readInt(u64, authdata[ID_NONCE_SIZE..WHOAREYOU_AUTHDATA_SIZE], .big),
            } };
        },
        FLAG_HANDSHAKE => {
            if (message_size < GCM_TAG_SIZE) return Error.InvalidPacket;
            return .{ .handshake = handshake.parseAuthdata(authdata) catch return Error.InvalidPacket };
        },
        else => return Error.InvalidFlag,
    };
}

fn writeHeader(
    header: []u8,
    flag: u8,
    nonce: *const [NONCE_SIZE]u8,
    authdata: []const u8,
) Error!void {
    const total = try headerSize(authdata);
    if (header.len < total) return Error.BufferTooSmall;
    const out = header[0..total];

    const authdata_size: u16 = @intCast(authdata.len);
    @memcpy(out[0..6], PROTOCOL_ID);
    std.mem.writeInt(u16, out[6..8], VERSION, .big);
    out[8] = flag;
    @memcpy(out[9..21], nonce);
    std.mem.writeInt(u16, out[21..23], authdata_size, .big);
    @memcpy(out[STATIC_HEADER_SIZE..], authdata);
}

fn makeTestWirePacketUnchecked(
    out: []u8,
    dest_node_id: *const [NODE_ID_SIZE]u8,
    flag: u8,
    authdata: []const u8,
    message_len: usize,
) Error![]u8 {
    const header_total = try headerSize(authdata);
    const message_offset = std.math.add(usize, MASKING_IV_SIZE, header_total) catch return Error.InvalidPacket;
    const total = std.math.add(usize, message_offset, message_len) catch return Error.InvalidPacket;
    if (total > out.len) return Error.BufferTooSmall;
    const raw = out[0..total];
    @memset(raw, 0);
    raw[0..MASKING_IV_SIZE].* = [_]u8{0x11} ** MASKING_IV_SIZE;
    const header = raw[MASKING_IV_SIZE..][0..header_total];
    try writeHeader(header, flag, &([_]u8{0x22} ** NONCE_SIZE), authdata);
    aesCtr(dest_node_id[0..MASKING_IV_SIZE], &([_]u8{0x11} ** MASKING_IV_SIZE), header);
    return raw;
}

test "discv5 packet: decode returns typed packet forms" {
    const node_id = [_]u8{0x33} ** NODE_ID_SIZE;
    var buffer: [MAX_PACKET_SIZE]u8 = undefined;

    const ordinary_raw = try makeTestWirePacketUnchecked(&buffer, &node_id, FLAG_MESSAGE, &node_id, GCM_TAG_SIZE);
    const ordinary = try decode(ordinary_raw, &node_id);
    try std.testing.expect(ordinary.form == .ordinary);
    try std.testing.expectEqual(node_id, ordinary.form.ordinary.src_id);

    const who_raw = try makeTestWirePacketUnchecked(&buffer, &node_id, FLAG_WHOAREYOU, &([_]u8{0x55} ** WHOAREYOU_AUTHDATA_SIZE), 0);
    const who = try decode(who_raw, &node_id);
    try std.testing.expect(who.form == .whoareyou);
    try std.testing.expectEqual([_]u8{0x55} ** ID_NONCE_SIZE, who.form.whoareyou.id_nonce);

    var handshake_authdata = [_]u8{0} ** handshake.RECORDLESS_AUTHDATA_SIZE;
    handshake_authdata[32] = handshake.sig_size;
    handshake_authdata[33] = handshake.eph_key_size;
    const handshake_raw = try makeTestWirePacketUnchecked(&buffer, &node_id, FLAG_HANDSHAKE, &handshake_authdata, GCM_TAG_SIZE);
    const decoded_handshake = try decode(handshake_raw, &node_id);
    try std.testing.expect(decoded_handshake.form == .handshake);
    try std.testing.expectEqual([_]u8{0} ** NODE_ID_SIZE, decoded_handshake.form.handshake.src_id);
    handshake_raw[MASKING_IV_SIZE + STATIC_HEADER_SIZE + handshake.AUTHDATA_HEAD_SIZE] = 0x7a;
    try std.testing.expectEqual(@as(u8, 0x7a), decoded_handshake.form.handshake.id_sig[0]);
}

test "discv5 packet: decode rejects datagrams outside the UDP packet bounds" {
    const node_id = [_]u8{0x33} ** NODE_ID_SIZE;

    var undersized_buffer: [MIN_PACKET_SIZE - 1]u8 = [_]u8{0xa5} ** (MIN_PACKET_SIZE - 1);
    for ([_]usize{ 0, 1, 15, 16, 38, MIN_PACKET_SIZE - 1 }) |len| {
        try std.testing.expectError(Error.InvalidPacket, decode(undersized_buffer[0..len], &node_id));
    }

    var oversized_buffer: [MAX_PACKET_SIZE + 1]u8 = undefined;
    const oversized = try makeTestWirePacketUnchecked(
        &oversized_buffer,
        &node_id,
        FLAG_MESSAGE,
        &([_]u8{0x55} ** NODE_ID_SIZE),
        MAX_PACKET_SIZE + 1 - MASKING_IV_SIZE - STATIC_HEADER_SIZE - NODE_ID_SIZE,
    );
    try std.testing.expectError(Error.InvalidPacket, decode(oversized, &node_id));
}

test "discv5 packet: decode rejects unknown flags" {
    const node_id = [_]u8{0x33} ** NODE_ID_SIZE;
    var buffer: [MAX_PACKET_SIZE]u8 = undefined;
    const raw = try makeTestWirePacketUnchecked(
        &buffer,
        &node_id,
        3,
        &([_]u8{0x55} ** NODE_ID_SIZE),
        GCM_TAG_SIZE,
    );
    try std.testing.expectError(Error.InvalidFlag, decode(raw, &node_id));
}

test "discv5 packet: decode rejects invalid ordinary packet shape" {
    const node_id = [_]u8{0x33} ** NODE_ID_SIZE;
    var buffer: [MAX_PACKET_SIZE]u8 = undefined;

    const wrong_authdata = try makeTestWirePacketUnchecked(
        &buffer,
        &node_id,
        FLAG_MESSAGE,
        &([_]u8{0x55} ** (NODE_ID_SIZE - 1)),
        GCM_TAG_SIZE,
    );
    try std.testing.expectError(Error.InvalidPacket, decode(wrong_authdata, &node_id));

    const oversized_authdata = try makeTestWirePacketUnchecked(
        &buffer,
        &node_id,
        FLAG_MESSAGE,
        &([_]u8{0x55} ** (NODE_ID_SIZE + 1)),
        GCM_TAG_SIZE,
    );
    try std.testing.expectError(Error.InvalidPacket, decode(oversized_authdata, &node_id));

    const missing_tag = try makeTestWirePacketUnchecked(
        &buffer,
        &node_id,
        FLAG_MESSAGE,
        &([_]u8{0x55} ** NODE_ID_SIZE),
        GCM_TAG_SIZE - 1,
    );
    try std.testing.expectError(Error.InvalidPacket, decode(missing_tag, &node_id));
}

test "discv5 packet: decode rejects invalid WHOAREYOU packet shape" {
    const node_id = [_]u8{0x33} ** NODE_ID_SIZE;
    var buffer: [MAX_PACKET_SIZE]u8 = undefined;

    const wrong_authdata = try makeTestWirePacketUnchecked(
        &buffer,
        &node_id,
        FLAG_WHOAREYOU,
        &([_]u8{0x55} ** (WHOAREYOU_AUTHDATA_SIZE + 1)),
        0,
    );
    try std.testing.expectError(Error.InvalidPacket, decode(wrong_authdata, &node_id));

    const undersized_authdata = try makeTestWirePacketUnchecked(
        &buffer,
        &node_id,
        FLAG_WHOAREYOU,
        &([_]u8{0x55} ** (WHOAREYOU_AUTHDATA_SIZE - 1)),
        1,
    );
    try std.testing.expectEqual(MIN_PACKET_SIZE, undersized_authdata.len);
    try std.testing.expectError(Error.InvalidPacket, decode(undersized_authdata, &node_id));
    // The minimum wire size requires one trailing byte for this off-by-one
    // fixture. Exercise the authdata-size branch independently as well.
    try std.testing.expectError(
        Error.InvalidPacket,
        validatePacket(FLAG_WHOAREYOU, &([_]u8{0x55} ** (WHOAREYOU_AUTHDATA_SIZE - 1)), 0, MIN_PACKET_SIZE),
    );

    const nonempty_message = try makeTestWirePacketUnchecked(
        &buffer,
        &node_id,
        FLAG_WHOAREYOU,
        &([_]u8{0x55} ** WHOAREYOU_AUTHDATA_SIZE),
        1,
    );
    try std.testing.expectError(Error.InvalidPacket, decode(nonempty_message, &node_id));
}

test "discv5 packet: decode rejects malformed handshake framing" {
    const node_id = [_]u8{0x33} ** NODE_ID_SIZE;
    var buffer: [MAX_PACKET_SIZE]u8 = undefined;

    var short_authdata = [_]u8{0} ** 33;
    const short = try makeTestWirePacketUnchecked(&buffer, &node_id, FLAG_HANDSHAKE, &short_authdata, GCM_TAG_SIZE);
    try std.testing.expectError(Error.InvalidPacket, decode(short, &node_id));

    var framed_authdata = [_]u8{0} ** (34 + handshake.sig_size + handshake.eph_key_size);
    framed_authdata[32] = handshake.sig_size;
    framed_authdata[33] = handshake.eph_key_size;
    const missing_tag = try makeTestWirePacketUnchecked(&buffer, &node_id, FLAG_HANDSHAKE, &framed_authdata, GCM_TAG_SIZE - 1);
    try std.testing.expectError(Error.InvalidPacket, decode(missing_tag, &node_id));

    var wrong_sizes_authdata = [_]u8{0} ** (34 + handshake.sig_size + handshake.eph_key_size);
    wrong_sizes_authdata[32] = handshake.sig_size - 1;
    wrong_sizes_authdata[33] = handshake.eph_key_size;
    const wrong_sizes = try makeTestWirePacketUnchecked(&buffer, &node_id, FLAG_HANDSHAKE, &wrong_sizes_authdata, GCM_TAG_SIZE);
    try std.testing.expectError(Error.InvalidPacket, decode(wrong_sizes, &node_id));

    var wrong_eph_size_authdata = [_]u8{0} ** (34 + handshake.sig_size + handshake.eph_key_size - 1);
    wrong_eph_size_authdata[32] = handshake.sig_size;
    wrong_eph_size_authdata[33] = handshake.eph_key_size - 1;
    // This direct assertion proves the fixture is long enough to pass the
    // truncation check and reaches the declared-size validation branch.
    try std.testing.expectError(handshake.Error.BadAuthdataSizes, handshake.parseAuthdata(&wrong_eph_size_authdata));
    const wrong_eph_size = try makeTestWirePacketUnchecked(&buffer, &node_id, FLAG_HANDSHAKE, &wrong_eph_size_authdata, GCM_TAG_SIZE);
    try std.testing.expectError(Error.InvalidPacket, decode(wrong_eph_size, &node_id));

    var truncated_authdata = [_]u8{0} ** 34;
    truncated_authdata[32] = handshake.sig_size;
    truncated_authdata[33] = handshake.eph_key_size;
    const truncated = try makeTestWirePacketUnchecked(&buffer, &node_id, FLAG_HANDSHAKE, &truncated_authdata, GCM_TAG_SIZE);
    try std.testing.expectError(Error.InvalidPacket, decode(truncated, &node_id));
}

test "discv5 packet: semantic decode failures leave masked wire bytes unchanged" {
    const node_id = [_]u8{0x33} ** NODE_ID_SIZE;
    var buffer: [MAX_PACKET_SIZE]u8 = undefined;

    const invalid_packet = try makeTestWirePacketUnchecked(
        &buffer,
        &node_id,
        FLAG_MESSAGE,
        &([_]u8{0x55} ** (NODE_ID_SIZE + 1)),
        GCM_TAG_SIZE,
    );
    var invalid_packet_before: [MAX_PACKET_SIZE]u8 = undefined;
    @memcpy(invalid_packet_before[0..invalid_packet.len], invalid_packet);
    try std.testing.expectError(Error.InvalidPacket, decode(invalid_packet, &node_id));
    try std.testing.expectEqualSlices(u8, invalid_packet_before[0..invalid_packet.len], invalid_packet);

    const invalid_flag = try makeTestWirePacketUnchecked(
        &buffer,
        &node_id,
        3,
        &([_]u8{0x55} ** NODE_ID_SIZE),
        GCM_TAG_SIZE,
    );
    var invalid_flag_before: [MAX_PACKET_SIZE]u8 = undefined;
    @memcpy(invalid_flag_before[0..invalid_flag.len], invalid_flag);
    try std.testing.expectError(Error.InvalidFlag, decode(invalid_flag, &node_id));
    try std.testing.expectEqualSlices(u8, invalid_flag_before[0..invalid_flag.len], invalid_flag);
}

test "discv5 packet: public encoders reject invalid packet shapes and sizes" {
    const node_id = [_]u8{0x33} ** NODE_ID_SIZE;
    const nonce = [_]u8{0x22} ** NONCE_SIZE;
    const masking_iv = [_]u8{0x11} ** MASKING_IV_SIZE;
    const key = [_]u8{0x66} ** 16;
    var buffer: [MAX_PACKET_SIZE + 1]u8 = undefined;

    try std.testing.expectError(Error.InvalidPacket, encodeMessagePacketInto(&buffer, .{
        .kind = .ordinary,
        .masking_iv = &masking_iv,
        .recipient_node_id = &node_id,
        .nonce = &nonce,
        .authdata = &([_]u8{0} ** (NODE_ID_SIZE - 1)),
        .write_key = &key,
        .plaintext = &.{},
    }));
    try std.testing.expectError(Error.InvalidPacket, encodeMessagePacketInto(&buffer, .{
        .kind = .handshake,
        .masking_iv = &masking_iv,
        .recipient_node_id = &node_id,
        .nonce = &nonce,
        .authdata = &([_]u8{0} ** 34),
        .write_key = &key,
        .plaintext = &.{},
    }));
    try std.testing.expectError(Error.InvalidPacket, encodeMessagePacketInto(&buffer, .{
        .kind = .ordinary,
        .masking_iv = &masking_iv,
        .recipient_node_id = &node_id,
        .nonce = &nonce,
        .authdata = &([_]u8{0} ** NODE_ID_SIZE),
        .write_key = &key,
        .plaintext = &([_]u8{0} ** (MAX_PACKET_SIZE + 1 - MASKING_IV_SIZE - STATIC_HEADER_SIZE - NODE_ID_SIZE - GCM_TAG_SIZE)),
    }));
}

test "discv5 packet: valid WHOAREYOU and maximum ordinary message boundaries round-trip" {
    const node_id = [_]u8{0x33} ** NODE_ID_SIZE;
    const nonce = [_]u8{0x22} ** NONCE_SIZE;
    const masking_iv = [_]u8{0x11} ** MASKING_IV_SIZE;
    const key = [_]u8{0x66} ** 16;
    var buffer: [MAX_PACKET_SIZE]u8 = undefined;

    const whoareyou = try encodeWhoareyouPacketInto(&buffer, .{
        .masking_iv = &masking_iv,
        .recipient_node_id = &node_id,
        .request_nonce = &nonce,
        .id_nonce = &([_]u8{0x77} ** ID_NONCE_SIZE),
        .enr_seq = 1,
    }, null);
    try std.testing.expectEqual(@as(usize, 63), whoareyou.len);
    try std.testing.expectEqual(FLAG_WHOAREYOU, (try decode(whoareyou, &node_id)).static_header.flag);

    const max_plaintext_len = MAX_PACKET_SIZE - MASKING_IV_SIZE - STATIC_HEADER_SIZE - NODE_ID_SIZE - GCM_TAG_SIZE;
    const maximum = try encodeMessagePacketInto(&buffer, .{
        .kind = .ordinary,
        .masking_iv = &masking_iv,
        .recipient_node_id = &node_id,
        .nonce = &nonce,
        .authdata = &node_id,
        .write_key = &key,
        .plaintext = &([_]u8{0x88} ** max_plaintext_len),
    });
    try std.testing.expectEqual(MAX_PACKET_SIZE, maximum.len);
    try std.testing.expectEqual(FLAG_MESSAGE, (try decode(maximum, &node_id)).static_header.flag);
}

test "discv5 packet: ordinary message plaintext fit boundary" {
    const max_plaintext = MAX_PACKET_SIZE - MASKING_IV_SIZE - STATIC_HEADER_SIZE - NODE_ID_SIZE - GCM_TAG_SIZE;
    try std.testing.expect(ordinaryMessageFits(max_plaintext));
    try std.testing.expect(!ordinaryMessageFits(max_plaintext + 1));
    try std.testing.expect(!ordinaryMessageFits(std.math.maxInt(usize)));
}

test "discv5 packet: recoverable plaintext exact maximum handshake boundary" {
    try std.testing.expectEqual(@as(usize, 794), MAX_RECOVERABLE_PLAINTEXT_SIZE);
    try std.testing.expectEqual(
        MAX_PACKET_SIZE,
        MASKING_IV_SIZE + STATIC_HEADER_SIZE + handshake.MAX_AUTHDATA_SIZE + MAX_RECOVERABLE_PLAINTEXT_SIZE + GCM_TAG_SIZE,
    );

    const node_id = [_]u8{0x11} ** NODE_ID_SIZE;
    const nonce = [_]u8{0x22} ** NONCE_SIZE;
    const masking_iv = [_]u8{0x33} ** MASKING_IV_SIZE;
    const key = [_]u8{0x44} ** 16;
    var authdata = [_]u8{0x55} ** handshake.MAX_AUTHDATA_SIZE;
    authdata[32] = handshake.sig_size;
    authdata[33] = handshake.eph_key_size;
    const maximum_plaintext = [_]u8{0x66} ** MAX_RECOVERABLE_PLAINTEXT_SIZE;
    var buffer: [MAX_PACKET_SIZE]u8 = undefined;

    const maximum = try encodeMessagePacketInto(&buffer, .{
        .kind = .handshake,
        .masking_iv = &masking_iv,
        .recipient_node_id = &node_id,
        .nonce = &nonce,
        .authdata = &authdata,
        .write_key = &key,
        .plaintext = &maximum_plaintext,
    });
    try std.testing.expectEqual(MAX_PACKET_SIZE, maximum.len);

    const oversized_plaintext = [_]u8{0x77} ** (MAX_RECOVERABLE_PLAINTEXT_SIZE + 1);
    try std.testing.expectError(error.InvalidPacket, encodeMessagePacketInto(&buffer, .{
        .kind = .handshake,
        .masking_iv = &masking_iv,
        .recipient_node_id = &node_id,
        .nonce = &nonce,
        .authdata = &authdata,
        .write_key = &key,
        .plaintext = &oversized_plaintext,
    }));
}

test "discv5 packet: failed authenticated decryption does not publish plaintext" {
    const key = [_]u8{0} ** 16;
    const nonce = [_]u8{0} ** NONCE_SIZE;
    const masking_iv = [_]u8{0} ** MASKING_IV_SIZE;
    const ciphertext = [_]u8{0} ** (GCM_TAG_SIZE + 3);
    var plaintext = [_]u8{0xa5} ** 3;
    const unchanged = plaintext;
    var ad: [MASKING_IV_SIZE]u8 = undefined;

    try std.testing.expectError(Error.DecryptionFailed, decryptMessageInto(&plaintext, &ad, &key, &nonce, &ciphertext, &masking_iv, &.{}));
    try std.testing.expectEqualSlices(u8, &unchanged, &plaintext);
}

test "discv5 packet: insufficient plaintext capacity does not publish" {
    const key = [_]u8{0} ** 16;
    const nonce = [_]u8{0} ** NONCE_SIZE;
    const masking_iv = [_]u8{0} ** MASKING_IV_SIZE;
    const ciphertext = [_]u8{0} ** (GCM_TAG_SIZE + 3);
    var plaintext = [_]u8{0xa5} ** 2;
    const unchanged = plaintext;
    var ad: [MASKING_IV_SIZE]u8 = undefined;

    try std.testing.expectError(Error.BufferTooSmall, decryptMessageInto(&plaintext, &ad, &key, &nonce, &ciphertext, &masking_iv, &.{}));
    try std.testing.expectEqualSlices(u8, &unchanged, &plaintext);
}

test "discv5 packet: authenticated decryption supports overlapping ciphertext output" {
    const key = [_]u8{0x11} ** 16;
    const nonce = [_]u8{0x22} ** NONCE_SIZE;
    const masking_iv = [_]u8{0x33} ** MASKING_IV_SIZE;
    const header_raw = [_]u8{0x44} ** STATIC_HEADER_SIZE;
    const expected = [_]u8{ 0xaa, 0xbb, 0xcc };
    var encrypted: [expected.len + GCM_TAG_SIZE]u8 = undefined;
    var tag: [GCM_TAG_SIZE]u8 = undefined;
    var ad: [MASKING_IV_SIZE + header_raw.len]u8 = undefined;
    @memcpy(ad[0..MASKING_IV_SIZE], &masking_iv);
    @memcpy(ad[MASKING_IV_SIZE..], &header_raw);
    Aes128Gcm.encrypt(encrypted[0..expected.len], &tag, &expected, &ad, nonce, key);
    @memcpy(encrypted[expected.len..], &tag);

    var ad_scratch: [MASKING_IV_SIZE + header_raw.len]u8 = undefined;
    const plaintext = try decryptMessageInto(encrypted[0..expected.len], &ad_scratch, &key, &nonce, &encrypted, &masking_iv, &header_raw);
    try std.testing.expectEqualSlices(u8, &expected, plaintext);
}

test "discv5 packet: AES-CTR masking round-trip" {
    var data = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05 };
    const key = [_]u8{0xaa} ** 16;
    const iv = [_]u8{0xbb} ** 16;
    aesCtr(&key, &iv, &data);
    aesCtr(&key, &iv, &data);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05 }, &data);
}

test "discv5 packet: AES-GCM encrypt/decrypt" {
    const hex = @import("hex");

    const key = hex.hexToBytesComptime(16, "9f2d77db7004bf8a1a85107ac686990b");
    const nonce = hex.hexToBytesComptime(12, "27b5af763c446acd2749fe8e");
    const pt = hex.hexToBytesComptime(4, "01c20101");
    const ad = hex.hexToBytesComptime(32, "93a7400fa0d6a694ebc24d5cf570f65d04215b6ac00757875e3f3a5f42107903");
    const expected_ct = hex.hexToBytesComptime(20, "a5d12a2d94b8ccb3ba55558229867dc13bfa3648");

    var ct: [4]u8 = undefined;
    var tag: [16]u8 = undefined;
    Aes128Gcm.encrypt(&ct, &tag, &pt, &ad, nonce, key);
    var actual: [20]u8 = undefined;
    @memcpy(actual[0..4], &ct);
    @memcpy(actual[4..], &tag);

    try std.testing.expectEqualSlices(u8, &expected_ct, &actual);

    var pt2: [4]u8 = undefined;
    try Aes128Gcm.decrypt(&pt2, &ct, tag, &ad, nonce, key);
    try std.testing.expectEqualSlices(u8, &pt, &pt2);
}
