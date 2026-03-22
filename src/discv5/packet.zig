const std = @import("std");

const Aes128 = std.crypto.core.aes.Aes128;
const AesEncryptCtx = std.crypto.core.aes.AesEncryptCtx;
const big = std.builtin.Endian.big;

const AesCtr = struct {
    buf: [16]u8,
    pos: u8,
    counter: u128,
    ctx: *AesEncryptCtx(Aes128),

    pub fn init(ctx: *AesEncryptCtx(Aes128), iv: [16]u8) AesCtr {
        const counter = std.mem.readInt(u128, &iv, big);
        return AesCtr{
            .buf = [_]u8{0} ** 16,
            .pos = 0,
            .counter = counter,
            .ctx = ctx,
        };
    }

    fn nextBlock(self: *AesCtr) void {
        var counter_buf: [16]u8 = undefined;
        std.mem.writeInt(u128, &counter_buf, self.counter, big);

        self.ctx.encrypt(&self.buf, &counter_buf);

        self.counter +%= 1;
        self.pos = 0;
    }

    pub fn updateInto(self: *AesCtr, data: []u8) !void {
        var i: usize = 0;

        // use the remaining bytes in buffered block
        if (self.pos != 0) {
            const used = @min(16 - self.pos, data.len);
            for (0..used) |j| {
                data[j] ^= self.buf[self.pos + j];
            }
            i += used;
        }
        while (i < data.len) {
            self.nextBlock();
            const used = @min(16, data.len - i);
            for (0..used) |j| {
                data[i + j] ^= self.buf[self.pos + j];
            }
            i += used;
            self.pos += used;
        }
    }
};

const max_packet_size = 1280;
const min_packet_size = 63;
const masking_iv_size = 16;
const masking_key_size = 16;

const protocol_id = "discv5";
const version_offset = protocol_id.len;
const version = [2]u8{ 0, 1 };
const flag_offset = protocol_id.len + version.len;
const flag_size = 1;
const nonce_offset = flag_offset + flag_size;
const nonce_size = 12;
const authdata_size_offset = nonce_offset + nonce_size;
const authdata_size_size = 2;
const static_header_size = 23;
const authdata_offset = masking_iv_size + static_header_size;

const node_id_size = 32;
const id_nonce_size = 16;

const message_authdata_size = 32;
const whoareyou_authdata_size = 24;

pub const PacketType = enum {
    /// Ordinary message packet
    Message,
    /// Sent when the recipient of an ordinary message packet cannot decrypt/authenticate the packet's message
    WhoAreYou,
    /// Sent following a WhoAreYou.
    /// These packets establish a new session and carry handshake-related data
    /// in addition to the encrypted/authenticated message
    Handshake,
};

pub const MessageAuthdata = struct {
    src_id: *[node_id_size]u8,
};

pub const WhoAreYouAuthdata = struct {
    id_nonce: *[id_nonce_size]u8,
    enr_seq: u64,
};

pub const HandshakeAuthdata = struct {
    src_id: *[node_id_size]u8,
    id_sig: []u8,
    eph_pubkey: []u8,
    record: ?[]u8,
};

pub const MessagePacket = struct {
    masking_iv: *[masking_iv_size]u8,
    nonce: *[nonce_size]u8,
    authdata: MessageAuthdata,
    message: []u8,
};

pub const WhoAreYouPacket = struct {
    masking_iv: *[masking_iv_size]u8,
    nonce: *[nonce_size]u8,
    authdata: WhoAreYouAuthdata,

    pub const size = masking_iv_size + protocol_id.len + version.len + nonce_size + 27;

    pub fn write(data: *[size]u8, nonce: *[nonce_size]u8, enr_seq: u64) void {
        // write masking_iv
        std.crypto.random.bytes(data[0..masking_iv_size]);

        // write static header
        @memcpy(data[masking_iv_size..], protocol_id);
        @memcpy(data[masking_iv_size + protocol_id.len ..], version);
        data[flag_offset] = @intFromEnum(PacketType.WhoAreYou);
        @memcpy(data[nonce_offset .. nonce_offset + nonce_size], nonce);
        std.mem.writeInt(u16, data[authdata_size_offset .. authdata_size_offset + authdata_size_size], 24, big);

        // write authdata
        std.crypto.random.bytes(data[authdata_offset .. authdata_offset + id_nonce_size]);
        std.mem.writeInt(u64, data[authdata_offset + id_nonce_size .. authdata_offset + id_nonce_size + 8], enr_seq, big);
    }

    pub fn mask(data: *[size]u8, ctx: *AesCtr) void {
        ctx.init(data[0..masking_iv_size]);
        ctx.updateInto(data[masking_iv_size..]);
    }
};

pub const HandshakePacket = struct {
    masking_iv: *[masking_iv_size]u8,
    nonce: *[nonce_size]u8,
    authdata: HandshakeAuthdata,
    message: []u8,
};

const Packet = union(PacketType) {
    Message: MessagePacket,
    WhoAreYou: WhoAreYouPacket,
    Handshake: HandshakePacket,

    const Error = error{
        TooBig,
        TooSmall,
        InvalidProtocol,
        InvalidVersion,
        InvalidFlag,
        InvalidMessageAuthdata,
        InvalidWhoAreYouAuthdata,
        InvalidHandshakeAuthdata,
    };

    /// Decodes packet data in-place.
    /// The returned Packet points into the data
    pub fn decode(ctx: *AesEncryptCtx(Aes128), packet_data: []u8) !Packet {
        if (packet_data.len > max_packet_size) {
            return Error.TooBig;
        }
        if (packet_data.len < min_packet_size) {
            return Error.TooSmall;
        }

        const masking_iv = packet_data[0..masking_iv_size];
        var ctr = AesCtr.init(ctx, masking_iv.*);

        var static_header: [static_header_size]u8 = packet_data[masking_iv_size .. masking_iv_size + static_header_size].*;
        try ctr.updateInto(&static_header);

        const packet_protocol_id = static_header[0..protocol_id.len];
        const packet_version = static_header[version_offset .. version_offset + version.len];
        const packet_flag_raw = static_header[flag_offset];
        const packet_nonce = static_header[nonce_offset .. nonce_offset + nonce_size];
        const packet_authdata_size_raw = static_header[authdata_size_offset .. authdata_size_offset + authdata_size_size];

        if (!std.mem.eql(u8, packet_protocol_id, protocol_id)) {
            return Error.InvalidProtocol;
        }

        if (!std.mem.eql(u8, packet_version, &version)) {
            return Error.InvalidVersion;
        }

        if (packet_flag_raw > 2) {
            return Error.InvalidFlag;
        }
        const packet_flag: PacketType = @enumFromInt(packet_flag_raw);

        const packet_authdata_size = std.mem.readInt(u16, packet_authdata_size_raw, big);
        const message_offset = authdata_offset + packet_authdata_size;

        switch (packet_flag) {
            .Message => {
                if (packet_authdata_size != message_authdata_size) {
                    return Error.InvalidMessageAuthdata;
                }
                var packet_authdata = packet_data[authdata_offset .. authdata_offset + packet_authdata_size];
                try ctr.updateInto(packet_authdata);

                const src_id: *[node_id_size]u8 = packet_authdata[0..node_id_size];

                return Packet{ .Message = .{
                    .masking_iv = masking_iv,
                    .nonce = packet_nonce,
                    .authdata = .{ .src_id = src_id },
                    .message = packet_data[message_offset..packet_data.len],
                } };
            },
            .WhoAreYou => {
                if (packet_authdata_size != whoareyou_authdata_size) {
                    return Error.InvalidWhoAreYouAuthdata;
                }
                var packet_authdata = packet_data[authdata_offset .. authdata_offset + packet_authdata_size];
                try ctr.updateInto(packet_authdata);

                const id_nonce: *[id_nonce_size]u8 = packet_authdata[0..id_nonce_size];
                const enr_seq = std.mem.readInt(u64, packet_authdata[id_nonce_size .. id_nonce_size + 8], big);

                return Packet{ .WhoAreYou = .{
                    .masking_iv = masking_iv,
                    .nonce = packet_nonce,
                    .authdata = .{ .id_nonce = id_nonce, .enr_seq = enr_seq },
                } };
            },
            .Handshake => {
                var packet_authdata = packet_data[authdata_offset .. authdata_offset + packet_authdata_size];
                try ctr.updateInto(packet_authdata);

                const src_id: *[node_id_size]u8 = packet_authdata[0..node_id_size];
                const id_sig_size = packet_authdata[node_id_size];
                const eph_pubkey_size = packet_authdata[node_id_size + 1];
                const id_sig_offset = node_id_size + 2;
                const id_sig = packet_authdata[id_sig_offset .. id_sig_offset + id_sig_size];
                const eph_pubkey = packet_authdata[id_sig_offset + id_sig_size .. id_sig_offset + id_sig_size + eph_pubkey_size];
                const record = if (id_sig_offset + id_sig_size + eph_pubkey_size < packet_authdata_size)
                    packet_authdata[id_sig_offset + id_sig_size + eph_pubkey_size ..]
                else
                    null;

                return Packet{ .Handshake = .{
                    .masking_iv = masking_iv,
                    .nonce = packet_nonce,
                    .authdata = .{ .src_id = src_id, .id_sig = id_sig, .eph_pubkey = eph_pubkey, .record = record },
                    .message = packet_data[message_offset..packet_data.len],
                } };
            },
        }
    }
};

const hex = @import("hex.zig").hex;

test "decodePacket - message" {
    // const private_key = try hex("66fb62bfbd66b9177a138c1e5cddbe4f7c30c343e94e68df8769459cb1cde628");
    const src_node_id = try hex("aaaa8419e9f49d0083561b48287df592939a8d19947d8c0ef88f2a4856a69fbb");
    const dst_node_id = try hex("bbbb9d047f0488c0b5a93c1c3f2d8bafc7c8ff337024a55434a0d0555de64db9");
    const nonce = try hex("ffffffffffffffffffffffff");
    var message_packet_data = try hex("00000000000000000000000000000000088b3d4342774649325f313964a39e55ea96c005ad52be8c7560413a7008f16c9e6d2f43bbea8814a546b7409ce783d34c4f53245d08dab84102ed931f66d1492acb308fa1c6715b9d139b81acbdcc");

    var ctx = Aes128.initEnc(dst_node_id[0..16].*);
    const message_packet = try Packet.decode(&ctx, &message_packet_data);
    switch (message_packet) {
        .Message => {},
        else => try std.testing.expect(false),
    }
    try std.testing.expectEqualSlices(u8, &nonce, message_packet.Message.nonce);
    try std.testing.expectEqualSlices(u8, &src_node_id, message_packet.Message.authdata.src_id);
}

test "decodePacket - whoareyou" {
    // const private_key = try hex("66fb62bfbd66b9177a138c1e5cddbe4f7c30c343e94e68df8769459cb1cde628");
    // const src_node_id = try hex("aaaa8419e9f49d0083561b48287df592939a8d19947d8c0ef88f2a4856a69fbb");
    const dst_node_id = try hex("bbbb9d047f0488c0b5a93c1c3f2d8bafc7c8ff337024a55434a0d0555de64db9");
    // const nonce = try hex("ffffffffffffffffffffffff");
    const id_nonce = try hex("0102030405060708090a0b0c0d0e0f10");
    const enr_seq = 0;
    var whoareyou_packet_data = try hex("00000000000000000000000000000000088b3d434277464933a1ccc59f5967ad1d6035f15e528627dde75cd68292f9e6c27d6b66c8100a873fcbaed4e16b8d");

    var ctx = Aes128.initEnc(dst_node_id[0..16].*);
    const whoareyou_packet = try Packet.decode(&ctx, &whoareyou_packet_data);
    switch (whoareyou_packet) {
        .WhoAreYou => {},
        else => try std.testing.expect(false),
    }
    // try std.testing.expectEqualSlices(u8, &nonce, whoareyou_packet.WhoAreYou.nonce);
    try std.testing.expectEqualSlices(u8, &id_nonce, whoareyou_packet.WhoAreYou.authdata.id_nonce);
    try std.testing.expectEqual(enr_seq, whoareyou_packet.WhoAreYou.authdata.enr_seq);
}

test "decodePacket - handshake" {
    // const private_key = try hex("66fb62bfbd66b9177a138c1e5cddbe4f7c30c343e94e68df8769459cb1cde628");
    const src_node_id = try hex("aaaa8419e9f49d0083561b48287df592939a8d19947d8c0ef88f2a4856a69fbb");
    const dst_node_id = try hex("bbbb9d047f0488c0b5a93c1c3f2d8bafc7c8ff337024a55434a0d0555de64db9");
    const nonce = try hex("ffffffffffffffffffffffff");
    var handshake_packet_data = try hex("00000000000000000000000000000000088b3d4342774649305f313964a39e55ea96c005ad521d8c7560413a7008f16c9e6d2f43bbea8814a546b7409ce783d34c4f53245d08da4bb252012b2cba3f4f374a90a75cff91f142fa9be3e0a5f3ef268ccb9065aeecfd67a999e7fdc137e062b2ec4a0eb92947f0d9a74bfbf44dfba776b21301f8b65efd5796706adff216ab862a9186875f9494150c4ae06fa4d1f0396c93f215fa4ef524f1eadf5f0f4126b79336671cbcf7a885b1f8bd2a5d839cf8");
    var ctx = Aes128.initEnc(dst_node_id[0..16].*);
    const handshake_packet = try Packet.decode(&ctx, &handshake_packet_data);
    switch (handshake_packet) {
        .Handshake => {},
        else => try std.testing.expect(false),
    }
    try std.testing.expectEqualSlices(u8, &nonce, handshake_packet.Handshake.nonce);
    try std.testing.expectEqualSlices(u8, &src_node_id, handshake_packet.Handshake.authdata.src_id);
    try std.testing.expectEqual(null, handshake_packet.Handshake.authdata.record);
}
