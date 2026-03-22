const std = @import("std");
const Secp256k1 = @import("secp256k1.zig").Secp256k1;
const enr = @import("enr.zig");
const HandshakePacket = @import("packet.zig").HandshakePacket;
const WhoAreYouPacket = @import("packet.zig").WhoAreYouPacket;

const AesGcm = std.crypto.aead.aes_gcm.Aes128Gcm;
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;

const id_signature_text = "discovery v5 identity proof";
const challenge_data_size = WhoAreYouPacket.size;
pub const ChallengeData = [challenge_data_size]u8;

const kdf_info_head = "discovery v5 key agreement";
const kdf_info_size = 90;

pub const SessionStatus = enum {
    unverified,
    verified,
};

pub const Session = struct {
    enc_key: [16]u8,
    dec_key: [16]u8,

    const Self = @This();

    pub fn initiator(
        self: *Self,
        challenge_data: *ChallengeData,
        keypair: *enr.KeyPair,
        public_key: enr.PublicKey,
        src_node_id: *enr.NodeId,
        dst_node_id: *enr.NodeId,
    ) !void {
        switch (public_key) {
            .v4 => {
                const ephem_keypair = try Secp256k1.KeyPair.create(null);
                const ephem_pk = enr.PublicKey{ .v4 = ephem_keypair.public_key };

                const id_signature = idSign(
                    keypair,
                    challenge_data,
                    ephem_pk,
                    dst_node_id,
                );
                _ = id_signature;

                const keys = try initiatorKeys(
                    public_key,
                    ephem_keypair.secret_key.toBytes(),
                    challenge_data,
                    src_node_id,
                    dst_node_id,
                );

                self.enc_key = keys[0..16];
                self.dec_key = keys[16..32];
            },
        }
    }

    pub fn recipient(
        self: *Self,
        challenge_data: *ChallengeData,
        packet: *HandshakePacket,
        keypair: *enr.KeyPair,
        public_key: *enr.PublicKey,
        src_node_id: *enr.NodeId,
    ) !void {
        idVerify(
            keypair,
            public_key,
            challenge_data,
            packet.authdata.eph_pubkey,
            src_node_id,
            packet.authdata.id_sig,
        );

        const keys = try recipientKeys(
            keypair,
            packet.authdata.eph_pubkey,
            challenge_data,
            src_node_id,
            packet.authdata.src_id,
        );

        self.enc_key = keys[0..16];
        self.dec_key = keys[16..32];
    }
};
pub fn initiatorKeys(
    public_key: *enr.PublicKey,
    ephem_sk: []const u8,
    challenge_data: *ChallengeData,
    src_node_id: *enr.NodeId,
    dst_node_id: *enr.NodeId,
) ![32]u8 {
    switch (public_key) {
        .v4 => |pubkey| {
            // create ephemeral keypair
            // const ephem_keypair = try Secp256k1.KeyPair.create(null);
            // const ephem_sk = ephem_keypair.secret_key.bytes,

            // ecdh
            const shared_secret = try pubkey.p.mul(
                ephem_sk,
                .big,
            ).toUncompressedSec1();

            // hkdf
            var kdf_info: [kdf_info_size]u8 = undefined;
            @memcpy(&kdf_info, kdf_info_head);
            @memcpy(&kdf_info[kdf_info_head.len..], src_node_id);
            @memcpy(&kdf_info[kdf_info_head.len + enr.node_id_size ..], dst_node_id);

            const prk = HkdfSha256.extract(challenge_data, &shared_secret);
            var key_data: [32]u8 = undefined;
            HkdfSha256.expand(&key_data, &kdf_info, prk);

            return key_data;
        },
    }
}

pub fn recipientKeys(
    keypair: *enr.KeyPair,
    ephem_pk: []const u8,
    challenge_data: *ChallengeData,
    src_node_id: *enr.NodeId,
    dst_node_id: *enr.NodeId,
) ![32]u8 {
    switch (keypair) {
        .v4 => |kp| {

            // ecdh
            const pubkey = try enr.PublicKey.init(.v4, ephem_pk);
            const shared_secret = try pubkey.p.mul(
                kp.secret_key.bytes,
                .big,
            ).toUncompressedSec1();

            // hkdf
            var kdf_info: [kdf_info_size]u8 = undefined;
            @memcpy(&kdf_info, kdf_info_head);
            @memcpy(&kdf_info[kdf_info_head.len..], src_node_id);
            @memcpy(&kdf_info[kdf_info_head.len + enr.node_id_size ..], dst_node_id);

            const prk = HkdfSha256.extract(challenge_data, &shared_secret);
            var key_data: [32]u8 = undefined;
            HkdfSha256.expand(&key_data, &kdf_info, prk);

            return key_data;
        },
    }
}

pub fn idSign(
    keypair: *enr.KeyPair,
    challenge_data: *ChallengeData,
    ephem_pk: *enr.PublicKey,
    node_id: *enr.NodeId,
) [64]u8 {
    switch (ephem_pk) {
        .v4 => |pk| {
            var id_signature_buf: [id_signature_text.len + challenge_data_size + enr.node_id_size + 33]u8 = undefined;
            @memcpy(&id_signature_buf, id_signature_text);
            @memcpy(&id_signature_buf[id_signature_text.len..], challenge_data);
            @memcpy(&id_signature_buf[id_signature_text.len + challenge_data_size ..], pk.toCompressedSec1());
            @memcpy(&id_signature_buf[id_signature_text.len + challenge_data_size + ephem_pk.len ..], node_id);

            return try keypair.sign(&id_signature_buf);
        },
    }
}

pub fn idVerify(
    keypair: *enr.KeyPair,
    pubkey: *enr.PublicKey,
    challenge_data: *ChallengeData,
    ephem_pubkey: []const u8,
    node_id: *enr.NodeId,
    signature: *[64]u8,
) !void {
    switch (keypair) {
        .v4 => {
            if (ephem_pubkey.len != 33) {
                return error.X;
            }
            var id_signature_buf: [id_signature_text.len + challenge_data_size + enr.node_id_size + 33]u8 = undefined;
            @memcpy(&id_signature_buf, id_signature_text);
            @memcpy(&id_signature_buf[id_signature_text.len..], challenge_data);
            @memcpy(&id_signature_buf[id_signature_text.len + challenge_data_size ..], ephem_pubkey);
            @memcpy(&id_signature_buf[id_signature_text.len + challenge_data_size + ephem_pubkey.len ..], node_id);

            try pubkey.verify(&id_signature_buf, signature);
        },
    }
}
