const std = @import("std");

pub const Secp256k1 = std.crypto.sign.ecdsa.Ecdsa(std.crypto.ecc.Secp256k1, std.crypto.hash.sha3.Keccak256);

test "secp256k1 - verify" {
    // taken from enr test vector
    var data_buffer: [1000]u8 = undefined;
    var private_key_buffer: [32]u8 = undefined;
    var public_key_buffer: [64]u8 = undefined;
    var signature_buffer: [64]u8 = undefined;
    const data_hex = "f84201826964827634826970847f00000189736563703235366b31a103ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd31388375647082765f";
    const private_key_hex = "b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291";
    const public_key_hex = "03ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd3138";
    const signature_hex = "7098ad865b00a582051940cb9cf36836572411a47278783077011599ed5cd16b76f2635f4e234738f30813a89eb9137e3e3df5266e3a1f11df72ecf1145ccb9c";

    const data = try std.fmt.hexToBytes(&data_buffer, data_hex);
    const private_key = try std.fmt.hexToBytes(&private_key_buffer, private_key_hex);
    const public_key = try std.fmt.hexToBytes(&public_key_buffer, public_key_hex);
    const signature = try std.fmt.hexToBytes(&signature_buffer, signature_hex);

    const sk = try Secp256k1.KeyPair.fromSecretKey(try Secp256k1.SecretKey.fromBytes(private_key[0..32].*));
    const pk = try Secp256k1.PublicKey.fromSec1(public_key);
    const sig = Secp256k1.Signature.fromBytes(signature[0..64].*);

    const sig2 = try sk.sign(data, null);
    const x = sig2;
    _ = x;

    try sig.verify(data, pk);
    try std.testing.expectEqualSlices(u8, &pk.toCompressedSec1(), &sk.public_key.toCompressedSec1());

    // Signatures don't match because zig std and enr test vectors use different algos:
    // - zig std https://www.ietf.org/archive/id/draft-mattsson-cfrg-det-sigs-with-noise-04.html#name-updates-to-rfc-8032-eddsa
    // - enr test vectors https://www.rfc-editor.org/rfc/rfc6979.txt
    // try std.testing.expectEqualSlices(u8, &sig2.toBytes(), &sig.toBytes());
}
