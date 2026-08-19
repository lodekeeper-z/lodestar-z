//! Standalone Discovery v5 runtime.

pub const enr = @import("enr.zig");
pub const rlp = @import("rlp.zig");
pub const packet = @import("protocol/packet.zig");
pub const session = @import("protocol/session.zig");
pub const message = @import("protocol/message.zig");
pub const rate_limit = @import("rate_limit.zig");
pub const metrics = @import("metrics.zig");
pub const secp256k1 = @import("secp256k1.zig");
pub const hex = @import("hex");

const runtime = @import("runtime.zig");
pub const Runtime = runtime.Runtime;
pub const RuntimeError = runtime.Error;
pub const Config = @import("config.zig").Config;
pub const Options = @import("config.zig").Options;
pub const Limits = @import("config.zig").Limits;
pub const BindAddresses = @import("config.zig").BindAddresses;
pub const Event = @import("events.zig").Event;
pub const EventKind = @import("events.zig").EventKind;
pub const LookupResult = @import("lookup_results.zig").LookupResult;
pub const LookupTerminalReason = @import("lookup_results.zig").LookupTerminalReason;
pub const NodeId = enr.NodeId;
pub const Enr = enr.Enr;
pub const Address = @import("types.zig").Address;
pub const MAX_LOOKUP_RESULTS = @import("service/lookup.zig").MAX_RESULTS;

test {
    _ = @import("wire_test_vectors.zig");
    _ = @import("enr.zig");
    _ = @import("enr_test.zig");
    _ = @import("rlp.zig");
    _ = @import("protocol/packet.zig");
    _ = @import("protocol/session.zig");
    _ = @import("protocol/message.zig");
    _ = @import("protocol/message_test.zig");
    _ = @import("protocol/handshake.zig");
    _ = @import("kbucket.zig");
    _ = @import("kbucket_test.zig");
    _ = @import("lru.zig");
    _ = @import("rate_limit.zig");
    _ = @import("metrics.zig");
    _ = @import("types.zig");
    _ = @import("config.zig");
    _ = @import("transport.zig");
    _ = @import("admission.zig");
    _ = @import("events.zig");
    _ = @import("state/session_book.zig");
    _ = @import("state/request_queue.zig");
    _ = @import("state/request_book_test.zig");
    _ = @import("state/response_book.zig");
    _ = @import("state/peer_book_test.zig");
    _ = @import("contact_book.zig");
    _ = @import("actor_tests/eviction_request_lifecycle.zig");
    _ = @import("actor_tests/session_handshake_recovery.zig");
    _ = @import("actor_tests/event_lookup_allocator_failures.zig");
    _ = @import("actor_tests/interoperability_handshake_policy.zig");
    _ = @import("address_vote_test.zig");
    _ = @import("runtime_test.zig");
    _ = @import("service/addr_votes.zig");
    _ = @import("service/lookup.zig");
}
