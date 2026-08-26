//! Standalone Discovery v5 runtime.

pub const enr = @import("enr.zig");
pub const secp256k1 = @import("secp256k1.zig");
pub const hex = @import("hex");

const runtime = @import("runtime.zig");
const metrics = @import("metrics.zig");
const rate_limit = @import("rate_limit.zig");
const public_api = @import("public_api.zig");
pub const Runtime = runtime.Runtime;
pub const RuntimeError = runtime.Error;
pub const Config = @import("config.zig").Config;
pub const Options = @import("config.zig").Options;
pub const Limits = @import("config.zig").Limits;
pub const BindAddresses = @import("config.zig").BindAddresses;
pub const Event = @import("events.zig").Event;
pub const EventKind = @import("events.zig").EventKind;
pub const event_kind_count = @import("events.zig").event_kind_count;
pub const RequestId = public_api.RequestId;
pub const RequestHandle = public_api.RequestHandle;
pub const RateLimitConfig = rate_limit.Config;
pub const MetricsSnapshot = metrics.MetricsSnapshot;
pub const ContactMetricsSnapshot = @import("contact_book.zig").ContactMetricsSnapshot;
pub const SessionMetricsSnapshot = @import("state/session_book.zig").SessionMetricsSnapshot;
pub const LookupResult = @import("lookup_results.zig").LookupResult;
pub const LookupTerminalReason = @import("lookup_results.zig").LookupTerminalReason;
pub const RequestResult = @import("request_results.zig").RequestResult;
pub const RequestTerminal = @import("request_results.zig").RequestTerminal;
pub const RequestSendFailure = @import("request_results.zig").RequestSendFailure;
pub const RequestKind = @import("types.zig").RequestKind;
pub const NodeId = enr.NodeId;
pub const Enr = enr.Enr;
pub const Address = @import("types.zig").Address;
pub const MAX_LOOKUP_RESULTS = @import("service/lookup.zig").MAX_RESULTS;
pub const MAX_REQUEST_RESULTS = @import("config.zig").MAX_REQUEST_RESULTS;

test {
    const std = @import("std");
    try std.testing.expect(!@hasDecl(@This(), "ReqId"));
    try std.testing.expect(!@hasDecl(@This(), "RequestKey"));
    try std.testing.expect(@FieldType(@FieldType(Event, "talkreq"), "req_id") == RequestId);
    try std.testing.expect(@FieldType(RequestResult, "handle") == RequestHandle);
    const maximum = try RequestId.fromSlice(&([_]u8{0xaa} ** 8));
    try std.testing.expectEqual(@as(usize, 8), maximum.slice().len);
    try std.testing.expectError(error.InvalidRequestId, RequestId.fromSlice(&([_]u8{0xaa} ** 9)));

    var empty_bytes = [_]u8{};
    var event: Event = .{ .talkreq = .{
        .peer_id = [_]u8{0x11} ** 32,
        .peer_addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 9000 } },
        .req_id = maximum,
        .protocol = &empty_bytes,
        .request = &empty_bytes,
    } };
    defer event.deinit(std.testing.allocator);
    try std.testing.expectEqualSlices(u8, maximum.slice(), event.talkreq.req_id.slice());

    const handle = RequestHandle{
        .node_id = [_]u8{0x22} ** 32,
        .address = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 2 }, .port = 9001 } },
        .request_id = maximum,
        .generation = 7,
    };
    const result = RequestResult{ .handle = handle, .kind = .ping, .terminal = .timeout };
    try std.testing.expectEqual(@as(u64, 7), result.handle.generation);
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
    _ = @import("request_results.zig");
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
    _ = @import("actor_tests/outbound_effect_contract.zig");
    _ = @import("actor_tests/validated_nodes_contract_test.zig");
    _ = @import("address_vote_test.zig");
    _ = @import("runtime_test.zig");
    _ = @import("service/addr_votes.zig");
    _ = @import("service/lookup.zig");
}
