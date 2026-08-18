//! secp256k1 wrapper for discv5 — ECDH and signing.
//!
//! This module intentionally uses Zig std.crypto instead of a libsecp256k1 C
//! dependency so the discv5 module remains self-contained and testable from the
//! standalone Lodestar-Z build graph.

const std = @import("std");

const Secp256k1 = std.crypto.ecc.Secp256k1;
const Ecdsa = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const Scalar = Secp256k1.scalar.Scalar;
const scalar_order = Secp256k1.scalar.field_order;
const half_scalar_order = scalar_order / 2;
const MAX_RFC6979_CANDIDATES: usize = 1_024;

pub const Error = error{
    InvalidSecretKey,
    InvalidPublicKey,
    InvalidSignature,
    SigningFailed,
    EcdhFailed,
};

/// Compressed public key (33 bytes)
pub const CompressedPubKey = [33]u8;
/// Uncompressed public key (65 bytes)
pub const UncompressedPubKey = [65]u8;
pub const KeyPair = Ecdsa.KeyPair;
pub const SecretKey = Ecdsa.SecretKey;
pub const PublicKey = Ecdsa.PublicKey;

/// Construct a keypair from fixed secret bytes, mainly for protocol vectors and
/// deterministic fixtures. Runtime code should usually call `KeyPair.generate`.
pub fn keyPairFromSecret(secret: *const [32]u8) Error!KeyPair {
    const secret_key = SecretKey.fromBytes(secret.*) catch return Error.InvalidSecretKey;
    return KeyPair.fromSecretKey(secret_key) catch return Error.InvalidSecretKey;
}

pub fn compressedPubkey(key_pair: *const KeyPair) CompressedPubKey {
    return key_pair.public_key.toCompressedSec1();
}

/// ECDH: pubkey * keypair.secret → compressed shared secret point.
///
/// This matches the previous wrapper contract: return the compressed SEC-1
/// encoding of the scalar-multiplied point, not a KDF output.
pub fn ecdh(pubkey_bytes: *const [33]u8, key_pair: *const KeyPair) Error![33]u8 {
    const peer = Secp256k1.fromSec1(pubkey_bytes) catch return Error.InvalidPublicKey;
    const secret = key_pair.secret_key.toBytes();
    const shared = peer.mul(secret, .big) catch return Error.EcdhFailed;
    return shared.toCompressedSec1();
}

/// Sign a caller-supplied 32-byte digest with RFC6979 deterministic ECDSA.
/// The digest is consumed directly: it is not hashed a second time. Compact
/// signatures are normalized to low S for @noble/secp256k1 interoperability.
pub fn sign(msg_hash: *const [32]u8, key_pair: *const KeyPair) Error![64]u8 {
    var generator = Rfc6979.init(key_pair.secret_key.toBytes(), msg_hash.*);
    const secret = Scalar.fromBytes(key_pair.secret_key.toBytes(), .big) catch return Error.SigningFailed;
    const z = scalarFromDigest(msg_hash.*);

    var attempts: usize = 0;
    while (attempts < MAX_RFC6979_CANDIDATES) : (attempts += 1) {
        const nonce = generator.next() orelse continue;
        const point = Secp256k1.basePoint.mul(nonce.toBytes(.big), .big) catch {
            generator.reject();
            continue;
        };
        const r = scalarFromDigest(point.affineCoordinates().x.toBytes(.big));
        if (r.isZero()) {
            generator.reject();
            continue;
        }
        const s = nonce.invert().mul(z.add(r.mul(secret)));
        if (s.isZero()) {
            generator.reject();
            continue;
        }

        var signature: [64]u8 = undefined;
        signature[0..32].* = r.toBytes(.big);
        signature[32..64].* = canonicalLowS(s.toBytes(.big));
        return signature;
    }
    return Error.SigningFailed;
}

const Rfc6979 = struct {
    key: [32]u8,
    value: [32]u8,

    fn init(secret: [32]u8, msg_hash: [32]u8) Rfc6979 {
        var result = Rfc6979{
            .key = [_]u8{0} ** 32,
            .value = [_]u8{1} ** 32,
        };
        const digest_octets = scalarFromDigest(msg_hash).toBytes(.big);
        var seed: [32 + 1 + 32 + 32]u8 = undefined;
        seed[0..32].* = result.value;
        seed[32] = 0;
        seed[33..65].* = secret;
        seed[65..97].* = digest_octets;
        HmacSha256.create(&result.key, &seed, &result.key);
        HmacSha256.create(&result.value, &result.value, &result.key);
        seed[0..32].* = result.value;
        seed[32] = 1;
        HmacSha256.create(&result.key, &seed, &result.key);
        HmacSha256.create(&result.value, &result.value, &result.key);
        return result;
    }

    fn next(self: *Rfc6979) ?Scalar {
        HmacSha256.create(&self.value, &self.value, &self.key);
        const scalar = Scalar.fromBytes(self.value, .big) catch {
            self.reject();
            return null;
        };
        if (scalar.isZero()) {
            self.reject();
            return null;
        }
        return scalar;
    }

    fn reject(self: *Rfc6979) void {
        var input: [33]u8 = undefined;
        input[0..32].* = self.value;
        input[32] = 0;
        HmacSha256.create(&self.key, &input, &self.key);
        HmacSha256.create(&self.value, &self.value, &self.key);
    }
};

fn scalarFromDigest(bytes: [32]u8) Scalar {
    const value = std.mem.readInt(u256, &bytes, .big) % scalar_order;
    var reduced: [32]u8 = undefined;
    std.mem.writeInt(u256, &reduced, value, .big);
    return Scalar.fromBytes(reduced, .big) catch unreachable;
}

fn canonicalLowS(encoded: [32]u8) [32]u8 {
    const value = std.mem.readInt(u256, &encoded, .big);
    std.debug.assert(value > 0 and value < scalar_order);
    if (value <= half_scalar_order) return encoded;
    var low: [32]u8 = undefined;
    std.mem.writeInt(u256, &low, scalar_order - value, .big);
    return low;
}

/// Verify a compact 64-byte signature against msg_hash and compressed pubkey.
pub fn verify(msg_hash: *const [32]u8, sig_compact: *const [64]u8, pubkey_bytes: *const [33]u8) Error!void {
    const public_key = PublicKey.fromSec1(pubkey_bytes) catch return Error.InvalidPublicKey;
    const sig = Ecdsa.Signature.fromBytes(sig_compact.*);
    sig.verifyPrehashed(msg_hash.*, public_key) catch return Error.InvalidSignature;
}

/// Decompress a 33-byte compressed public key to 65-byte uncompressed form.
/// Returns Error.InvalidPublicKey if the key is invalid.
pub fn uncompressedFromCompressed(compressed: *const [33]u8) Error!UncompressedPubKey {
    const public_key = PublicKey.fromSec1(compressed) catch return Error.InvalidPublicKey;
    return public_key.toUncompressedSec1();
}

test "secp256k1 std.crypto wrapper derives, signs, verifies, and rejects invalid signatures" {
    const io = std.Options.debug_io;
    const key_pair = KeyPair.generate(io);
    const public_key = compressedPubkey(&key_pair);

    var msg_hash = [_]u8{0} ** 32;
    msg_hash[31] = 42;

    const sig = try sign(&msg_hash, &key_pair);
    try verify(&msg_hash, &sig, &public_key);

    // Wire verification remains permissive for existing peers that emit the
    // mathematically equivalent high-S form, even though our signer never does.
    var high_sig = sig;
    const low_s = std.mem.readInt(u256, high_sig[32..64], .big);
    std.mem.writeInt(u256, high_sig[32..64], scalar_order - low_s, .big);
    try verify(&msg_hash, &high_sig, &public_key);

    var bad_sig = sig;
    bad_sig[0] ^= 1;
    try std.testing.expectError(Error.InvalidSignature, verify(&msg_hash, &bad_sig, &public_key));
}

test "secp256k1 std.crypto wrapper computes symmetric raw ECDH point" {
    const io = std.Options.debug_io;
    const a_key_pair = KeyPair.generate(io);
    const b_key_pair = KeyPair.generate(io);
    const a_public = compressedPubkey(&a_key_pair);
    const b_public = compressedPubkey(&b_key_pair);

    const ab = try ecdh(&b_public, &a_key_pair);
    const ba = try ecdh(&a_public, &b_key_pair);
    try std.testing.expectEqualSlices(u8, &ab, &ba);

    const uncompressed = try uncompressedFromCompressed(&a_public);
    try std.testing.expectEqual(@as(u8, 0x04), uncompressed[0]);
}
