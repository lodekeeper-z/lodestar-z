//! discv5 — Discovery v5 protocol implementation
//!
//! Implements the Ethereum Node Discovery v5 protocol including:
//! - ENR (Ethereum Node Records) encoding/decoding
//! - RLP encoding/decoding
//! - discv5 packet format (message, whoareyou, handshake)
//! - Session key derivation and management

pub const enr = @import("enr.zig");
pub const rlp = @import("rlp.zig");
pub const packet = @import("packet.zig");
pub const session = @import("session.zig");
pub const small_buf_map = @import("small_buf_map.zig");

// Re-export primary types for convenience.
pub const ENR = enr.ENR;
pub const EncodedENR = enr.EncodedENR;
pub const SignableENR = enr.SignableENR;
pub const NodeId = enr.NodeId;
pub const IDScheme = enr.IDScheme;
pub const KeyPair = enr.KeyPair;
pub const PublicKey = enr.PublicKey;

pub const RLPReader = rlp.RLPReader;
pub const RLPWriter = rlp.RLPWriter;

pub const PacketType = packet.PacketType;
pub const Session = session.Session;

test {
    _ = enr;
    _ = rlp;
    _ = packet;
    _ = session;
    _ = small_buf_map;
}
