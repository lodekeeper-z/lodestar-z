const std = @import("std");

const rlp = @import("rlp.zig");
const SmallBufMap = @import("small_buf_map.zig").SmallBufMap;

const RLPReader = rlp.RLPReader;
const RLPWriter = rlp.RLPWriter;

const Keccak = std.crypto.hash.sha3.Keccak256;
const Secp256k1 = @import("secp256k1.zig").Secp256k1;

pub const max_enr_size = 300;
pub const signature_size = 64;
// non-kv bytes
// list_len_len, list_len, sig_len_len, sig_len, sig, seq, id_len, id_byte
pub const max_kvs_size = max_enr_size - signature_size - 7;

// assuming single-byte keys, empty values
pub const max_kvs = max_kvs_size / 3;
pub const KVs = SmallBufMap(max_kvs_size);

pub const IDScheme = enum {
    v4,

    pub fn init(id: []const u8) Error!IDScheme {
        if (std.mem.eql(u8, id, "v4")) {
            return IDScheme.v4;
        } else {
            return Error.BadID;
        }
    }

    pub fn publicKeyKey(id: IDScheme) []const u8 {
        switch (id) {
            .v4 => return "secp256k1",
        }
    }

    pub fn publicKey(id: IDScheme, value: []const u8) Error!PublicKey {
        switch (id) {
            .v4 => {
                return PublicKey{ .v4 = Secp256k1.PublicKey.fromSec1(value) catch return Error.BadPubkey };
            },
        }
    }

    pub fn publicKeyFromKVs(id: IDScheme, kvs: *KVs) Error!PublicKey {
        switch (id) {
            .v4 => {
                return try id.publicKey(kvs.get(id.publicKeyKey()) orelse return Error.BadPubkey);
            },
        }
    }
};

pub const KeyPair = union(IDScheme) {
    v4: Secp256k1.KeyPair,

    pub fn sign(self: KeyPair, data: []const u8) ![signature_size]u8 {
        switch (self) {
            .v4 => |kp| {
                const s = try kp.sign(data, null);
                return s.toBytes();
            },
        }
    }

    pub fn publicKey(self: KeyPair) PublicKey {
        switch (self) {
            .v4 => |kp| {
                return PublicKey{ .v4 = kp.public_key };
            },
        }
    }
};

pub const PublicKey = union(IDScheme) {
    v4: Secp256k1.PublicKey,

    pub fn init(id: IDScheme, data: []const u8) !PublicKey {
        switch (id) {
            .v4 => {
                return try Secp256k1.PublicKey.fromSec1(data);
            },
        }
    }

    pub fn verify(self: PublicKey, data: []const u8, signature: []const u8) Error!void {
        switch (self) {
            .v4 => |pk| {
                const sig = Secp256k1.Signature.fromBytes(signature[0..signature_size].*);
                return sig.verify(data, pk) catch return Error.BadSignature;
            },
        }
    }

    pub fn verifier(self: PublicKey, signature: []const u8) Error!Secp256k1.Verifier {
        switch (self) {
            .v4 => |pk| {
                const sig = Secp256k1.Signature.fromBytes(signature[0..signature_size].*);
                return sig.verifier(pk) catch return Error.BadSignature;
            },
        }
    }

    pub fn nodeId(self: PublicKey) NodeId {
        switch (self) {
            .v4 => |pk| {
                var node_id: NodeId = undefined;
                Keccak.hash(pk.toUncompressedSec1(), &node_id, .{});
                return node_id;
            },
        }
    }
};

pub const node_id_size = 32;
pub const NodeId = [node_id_size]u8;

const Error = rlp.RLPReader.Error || error{
    TooShort,
    TooLong,
    BadPrefix,
    BadKVs,
    BadID,
    BadPubkey,
    BadSignature,
};

pub const ENR = struct {
    kvs: KVs,
    seq: u64,
    signature: [signature_size]u8,

    pub fn get(self: *ENR, key: []const u8) ?[]const u8 {
        return self.kvs.get(key);
    }

    pub fn id(self: *ENR) IDScheme {
        return IDScheme.init(self.kvs.get("id").?) catch unreachable;
    }

    pub fn publicKey(self: *ENR) PublicKey {
        return self.id().publicKeyFromKVs(self.kvs) catch unreachable;
    }

    pub fn nodeId(self: *ENR) NodeId {
        return self.publicKey().nodeId();
    }

    pub fn encodeInto(self: *ENR, out: []u8) !void {
        try encodeIntoFromComponents(out, &self.kvs, self.seq, self.signature);
    }

    pub fn encodedLen(self: *ENR) usize {
        return totalLen(&self.kvs, self.seq);
    }

    pub fn decodeInto(enr: *ENR, data: []const u8) Error!void {
        if (data.len < 8 + signature_size) {
            return Error.TooShort;
        }
        if (data.len > max_enr_size) {
            return Error.TooLong;
        }

        var outer_reader = RLPReader.init(data);
        const list_data = try outer_reader.read(.{.long_list});
        var list_reader = RLPReader.init(list_data);

        const sig = try list_reader.read(.{.long_string});

        const seq_pos = list_reader.pos;
        const seq_bytes = try list_reader.read(.{ .single_byte, .short_string });
        const seq = std.mem.readVarInt(u64, seq_bytes, .big);

        var kvs = KVs.init();
        while (!list_reader.finished()) {
            const key = list_reader.read(.{ .short_string, .long_string }) catch unreachable;
            const value = list_reader.read(.{ .single_byte, .short_string, .long_string }) catch unreachable;

            kvs.put(key, value) catch unreachable;
        }

        const id_scheme = try IDScheme.init(kvs.get("id") orelse return Error.BadID);
        const public_key = id_scheme.publicKeyFromKVs(&kvs) catch return Error.BadPubkey;

        // Verify the signature, streaming the signed data to the verifier
        var sig_verifier = try public_key.verifier(sig);

        // signed_data_list = length_prefix + elements
        {
            const elements = list_reader.data[seq_pos..];
            var length_prefix_buf: [2]u8 = undefined;
            var writer = RLPWriter.init(&length_prefix_buf);
            writer.writeListLength(elements.len) catch unreachable;
            const length_prefix = length_prefix_buf[0..writer.pos];

            // write the length prefix
            sig_verifier.update(length_prefix);
            // write the elements
            sig_verifier.update(elements);

            sig_verifier.verify() catch return Error.BadSignature;
        }

        // the ENR has been proven valid, write
        @memcpy(&enr.signature, sig);
        enr.seq = seq;
        enr.kvs = kvs;
    }

    pub fn decodeTxtInto(enr: *ENR, source: []const u8) !void {
        if (!std.mem.eql(u8, source[0..4], "enr:")) {
            return Error.BadPrefix;
        }

        var buffer: [max_enr_size]u8 = undefined;
        const decoder = std.base64.url_safe_no_pad.Decoder;
        const size = try decoder.calcSizeForSlice(source[4..]);
        try decoder.decode(buffer[0..size], source[4..]);

        try decodeInto(enr, buffer[0..size]);
    }
};

pub const SignableENR = struct {
    kvs: KVs,
    seq: u64,
    kp: KeyPair,

    const Self = @This();

    pub fn create(key_pair: KeyPair) SignableENR {
        var kvs = KVs.init();
        switch (key_pair) {
            .v4 => |kp| {
                kvs.put("id", "v4") catch unreachable;
                kvs.put("secp256k1", &kp.public_key.toCompressedSec1()) catch unreachable;
            },
        }
        return SignableENR{ .kp = key_pair, .kvs = kvs, .seq = 0 };
    }

    pub fn get(self: *Self, key: []const u8) ?[]const u8 {
        return self.kvs.get(key);
    }

    pub fn set(self: *Self, key: []const u8, value: []const u8) !void {
        try self.kvs.put(key, value);
    }

    pub fn id(self: *Self) IDScheme {
        return IDScheme.init(self.kvs.get("id").?) catch unreachable;
    }

    pub fn publicKey(self: *Self) PublicKey {
        return self.id().publicKeyFromKVs(self.kvs) catch unreachable;
    }

    pub fn nodeId(self: *Self) NodeId {
        return self.publicKey().nodeId();
    }

    pub fn sign(self: *Self) ![signature_size]u8 {
        var buffer = [_]u8{0} ** max_enr_size;
        try encodeSignedPayload(&buffer, &self.kvs, self.seq);
        const signed = buffer[0..signedLen(&self.kvs, self.seq)];
        return try self.kp.sign(signed);
    }

    pub fn encodeInto(self: *Self, out: []u8) !void {
        const signature = try self.sign();
        try encodeIntoFromComponents(out, &self.kvs, self.seq, signature);
    }

    pub fn encodedLen(self: *Self) usize {
        return totalLen(&self.kvs, self.seq);
    }
};

fn encodeIntoFromComponents(out: []u8, kvs: *KVs, seq: u64, signature: [signature_size]u8) !void {
    const writer = RLPWriter.init(out);
    try writer.writeListLength(listLen(kvs, seq));
    try writer.writeString(signature);
    try writer.writeInt(u64, seq);

    var kvs_it = kvs.iterator();
    while (kvs_it.next()) |entry| {
        try writer.writeString(entry.key);
        try writer.writeString(entry.value);
    }
}

fn encodeSignedPayload(out: []u8, kvs: *KVs, seq: u64) !void {
    var writer = RLPWriter.init(out);
    try writer.writeListLength(signedListLen(kvs, seq));
    try writer.writeInt(u64, seq);

    var kvs_it = kvs.iterator();
    while (kvs_it.next()) |entry| {
        try writer.writeString(entry[0]);
        try writer.writeString(entry[1]);
    }
}

/// The length of the whole rlp list
fn totalLen(kvs: *KVs, seq: u64) usize {
    const list_len = listLen(kvs, seq);
    return rlp.elemLen(list_len);
}

/// The length of all rlp list elements
fn listLen(kvs: *KVs, seq: u64) usize {
    return signedListLen(kvs, seq) + rlp.elemLen(signature_size); // signature
}

/// The length of the rlp list that is signed over
fn signedLen(kvs: *KVs, seq: u64) usize {
    const list_len = signedListLen(kvs, seq);
    return rlp.elemLen(list_len);
}

/// The length of the rlp list elements that are signed over
fn signedListLen(kvs: *KVs, seq: u64) usize {
    var length: usize = 0;
    length += rlp.intLen(u64, seq); // seq
    length += kvsLen(kvs);

    return length;
}

fn kvsLen(kvs: *KVs) usize {
    var length: usize = 0;
    var it = kvs.iterator();
    while (it.next()) |entry| {
        length += rlp.elemLen(entry[0].len);
        length += rlp.elemLen(entry[1].len);
    }
    return length;
}

pub fn decodeTxtIntoRlp(dest: []u8, source: []const u8) ![]u8 {
    if (!std.mem.eql(u8, source[0..4], "enr:")) {
        return Error.BadPrefix;
    }

    const decoder = std.base64.url_safe_no_pad.Decoder;
    const size = try decoder.calcSizeForSlice(source[4..]);
    try decoder.decode(dest[0..size], source[4..]);

    return dest[0..size];
}

/// Methods assume that data is a valid RLP-encoded ENR
pub const EncodedENR = struct {
    data: []const u8,

    const Self = @This();

    /// Ensures that `data` is a valid ENR
    pub fn init(data: []const u8) Error!Self {
        const self = Self{ .data = data };
        try self.verify();
        return self;
    }

    pub fn signature(self: *const Self) []const u8 {
        var outer_reader = RLPReader.init(self.data);
        const list_data = outer_reader.read(.{.long_list}) catch unreachable;
        var list_reader = RLPReader.init(list_data);

        return list_reader.read(.{.long_string}) catch unreachable;
    }

    pub fn seq(self: *const Self) u64 {
        var outer_reader = RLPReader.init(self.data);
        const list_data = outer_reader.read(.{.long_list}) catch unreachable;
        var list_reader = RLPReader.init(list_data);

        _ = list_reader.read(.{.long_string}) catch unreachable;

        const seq_bytes = list_reader.read(.{ .single_byte, .short_string }) catch unreachable;
        return std.mem.readVarInt(u64, seq_bytes, .big);
    }

    pub fn get(self: *const Self, key: []const u8) ?[]const u8 {
        var outer_reader = RLPReader.init(self.data);
        const list_data = outer_reader.read(.{.long_list}) catch unreachable;
        var list_reader = RLPReader.init(list_data);

        // signature
        _ = list_reader.read(.{.long_string}) catch unreachable;
        // seq
        _ = list_reader.read(.{ .single_byte, .short_string }) catch unreachable;

        while (!list_reader.finished()) {
            const k = list_reader.read(.{ .short_string, .long_string }) catch unreachable;
            if (std.mem.eql(u8, k, key)) {
                return list_reader.read(.{ .single_byte, .short_string, .long_string }) catch unreachable;
            } else {
                _ = list_reader.read(.{ .single_byte, .short_string, .long_string }) catch unreachable;
            }
        }
        return null;
    }

    pub fn id(self: *const Self) IDScheme {
        return IDScheme.init(self.get("id").?) catch unreachable;
    }

    pub fn publicKey(self: *const Self) PublicKey {
        const id_scheme = self.id();
        return id_scheme.publicKey(self.kvs.get(id_scheme.publicKeyKey()).?) catch unreachable;
    }

    pub fn nodeId(self: *const Self) NodeId {
        return self.publicKey().nodeId();
    }

    pub fn verify(self: *const Self) Error!void {
        const data = self.data;
        // Sanity bounds checks
        if (data.len < 3 + signature_size) {
            return Error.TooShort;
        }
        if (data.len > max_enr_size) {
            return Error.TooLong;
        }

        // The outer rlp must be a long list because the required elements are > 55 bytes
        var outer_reader = RLPReader.init(data);
        const list_data = try outer_reader.read(.{.long_list});
        var list_reader = RLPReader.init(list_data);

        const sig = try list_reader.read(.{.long_string});

        const seq_pos = list_reader.pos;
        _ = try list_reader.read(.{ .single_byte, .short_string });

        // Check the kvs
        // - id key must be present
        // - keys must be unique
        // - keys must be sorted
        var kvs = KVs.init();
        while (!list_reader.finished()) {
            const key = try list_reader.read(.{ .short_string, .long_string });
            const value = try list_reader.read(.{ .single_byte, .short_string, .long_string });
            kvs.append(key, value) catch return Error.BadKVs;
        }

        const id_scheme = try IDScheme.init(kvs.get("id") orelse return Error.BadID);
        const public_key = try id_scheme.publicKey(kvs.get(id_scheme.publicKeyKey()).?);

        // Verify the signature, streaming the signed data to the verifier
        var sig_verifier = try public_key.verifier(sig);

        // signed_data_list = length_prefix + elements
        {
            const elements = list_reader.data[seq_pos..];
            var length_prefix_buf: [2]u8 = undefined;
            var writer = RLPWriter.init(&length_prefix_buf);
            writer.writeListLength(elements.len) catch unreachable;
            const length_prefix = length_prefix_buf[0..writer.pos];

            // write the length prefix
            sig_verifier.update(length_prefix);
            // write the elements
            sig_verifier.update(elements);

            sig_verifier.verify() catch return Error.BadSignature;
        }
    }

    pub fn encodedLen(self: *const Self) usize {
        var outer_reader = RLPReader.init(self.data);
        const list_data = try outer_reader.read(.{.long_list});
        return rlp.elemLen(list_data.len);
    }

    pub fn decodeIntoENR(self: *const Self, enr: *ENR) void {
        const list_data = RLPReader.init(self.data).read(.{.long_list}) catch unreachable;
        var list_reader = RLPReader.init(list_data);

        const sig = list_reader.read(.{.long_string}) catch unreachable;
        @memcpy(&enr.signature, sig);

        const seq_bytes = list_reader.read(.{ .single_byte, .short_string });
        enr.seq = std.mem.readVarInt(u64, seq_bytes, .big);

        enr.kvs = KVs.init();
        while (!list_reader.finished()) {
            const key = list_reader.read(.{ .short_string, .long_string }) catch unreachable;
            const value = list_reader.read(.{ .single_byte, .short_string, .long_string }) catch unreachable;

            enr.kvs.put(key, value) catch unreachable;
        }
    }

    pub fn decodeTxtInto(dest: []u8, source: []const u8) !Self {
        if (!std.mem.eql(u8, source[0..4], "enr:")) {
            return Error.BadPrefix;
        }

        const decoder = std.base64.url_safe_no_pad.Decoder;
        const size = try decoder.calcSizeForSlice(source[4..]);
        try decoder.decode(dest[0..size], source[4..]);

        return EncodedENR.init(dest[0..size]);
    }
};

const hex = @import("hex.zig").hex;
test "ENR test vector" {
    const enr_txt = "enr:-IS4QHCYrYZbAKWCBRlAy5zzaDZXJBGkcnh4MHcBFZntXNFrdvJjX04jRzjzCBOonrkTfj499SZuOh8R33Ls8RRcy5wBgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQPKY0yuDUmstAHYpMa2_oxVtw0RW_QAdpzBQA8yWM0xOIN1ZHCCdl8";
    const private_key = try hex("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291");
    const kp = try Secp256k1.KeyPair.fromSecretKey(try Secp256k1.SecretKey.fromBytes(private_key));
    const public_key = kp.public_key.toCompressedSec1();
    const signature = try hex("7098ad865b00a582051940cb9cf36836572411a47278783077011599ed5cd16b76f2635f4e234738f30813a89eb9137e3e3df5266e3a1f11df72ecf1145ccb9c");
    const seq: u64 = 1;
    const id = "v4";
    const ip = "\x7f\x00\x00\x01";
    const udp = "\x76\x5f";

    var decoded_enr: ENR = undefined;
    try ENR.decodeTxtInto(&decoded_enr, enr_txt);

    // std.debug.print("{any}\n", .{decoded_enr});
    // ensure all decoded values match the test vector
    try std.testing.expectEqualSlices(u8, &signature, &decoded_enr.signature);
    try std.testing.expectEqual(seq, decoded_enr.seq);
    try std.testing.expectEqualSlices(u8, &public_key, decoded_enr.kvs.get("secp256k1").?);
    try std.testing.expectEqualSlices(u8, id, decoded_enr.kvs.get("id").?);
    try std.testing.expectEqualSlices(u8, ip, decoded_enr.kvs.get("ip").?);
    try std.testing.expectEqualSlices(u8, udp, decoded_enr.kvs.get("udp").?);

    var signable_enr = SignableENR.create(KeyPair{ .v4 = kp });
    signable_enr.seq = seq;
    try signable_enr.set("ip", ip);
    try signable_enr.set("udp", udp);

    try std.testing.expectEqualSlices(u8, &signable_enr.kvs.buffer, &decoded_enr.kvs.buffer);

    _ = try signable_enr.sign();
    // try std.testing.expectEqualSlices(u8, signature, &x);

    var encoded_buffer: [max_enr_size]u8 = undefined;
    const encoded_enr = try EncodedENR.decodeTxtInto(&encoded_buffer, enr_txt);
    std.debug.print("{any}\n", .{encoded_buffer});
    try std.testing.expectEqualStrings(&decoded_enr.signature, encoded_enr.signature());
    try std.testing.expectEqual(decoded_enr.seq, encoded_enr.seq());
    try std.testing.expectEqual(decoded_enr.id(), encoded_enr.id());
    try std.testing.expectEqualSlices(u8, encoded_enr.get("ip").?, decoded_enr.get("ip").?);
    // try std.testing.expectEqualSlices(u8, decoded_enr.get("ip").?, encoded_enr.get("ip").?);
}
