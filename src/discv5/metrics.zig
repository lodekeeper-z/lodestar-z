const std = @import("std");
const events = @import("events.zig");
const messages = @import("protocol/message.zig");

/// Standalone in-memory discv5 metrics surface mirroring the ChainSafe TS
/// `IDiscv5Metrics` names. The carve-out intentionally does not depend on a
/// process-wide Prometheus registry; embedders can poll `MetricsSnapshot` and
/// export these values under the documented `discv5_*` metric names.
pub const MessageType = enum(u8) {
    ping = messages.MSG_PING,
    pong = messages.MSG_PONG,
    findnode = messages.MSG_FINDNODE,
    nodes = messages.MSG_NODES,
    talkreq = messages.MSG_TALKREQ,
    talkresp = messages.MSG_TALKRESP,

    pub fn fromByte(byte: u8) ?MessageType {
        // The enum is backed by the wire message-type bytes, so a valid byte
        // maps straight to its tag.
        return std.enums.fromInt(MessageType, byte);
    }

    pub fn label(self: MessageType) []const u8 {
        return switch (self) {
            .ping => "PING",
            .pong => "PONG",
            .findnode => "FINDNODE",
            .nodes => "NODES",
            .talkreq => "TALKREQ",
            .talkresp => "TALKRESP",
        };
    }

    pub fn index(self: MessageType) usize {
        return switch (self) {
            .ping => 0,
            .pong => 1,
            .findnode => 2,
            .nodes => 3,
            .talkreq => 4,
            .talkresp => 5,
        };
    }
};

/// Human-readable wire name for a message-type byte, or "unknown".
pub fn messageLabel(byte: u8) []const u8 {
    return if (MessageType.fromByte(byte)) |t| t.label() else "unknown";
}

pub const message_type_count = @typeInfo(MessageType).@"enum".fields.len;

pub const ProtocolMetrics = struct {
    sent_message_count: [message_type_count]u64 = [_]u64{0} ** message_type_count,
    rcvd_message_count: [message_type_count]u64 = [_]u64{0} ** message_type_count,

    pub fn incSent(self: *ProtocolMetrics, message_type: MessageType) void {
        self.sent_message_count[message_type.index()] +|= 1;
    }

    pub fn incReceived(self: *ProtocolMetrics, message_type: MessageType) void {
        self.rcvd_message_count[message_type.index()] +|= 1;
    }
};

pub const MetricsSnapshot = struct {
    /// TS: discv5_kad_table_size
    kad_table_size: usize = 0,
    /// TS: discv5_active_session_count
    active_session_count: usize = 0,
    /// TS: discv5_connected_peer_count
    connected_peer_count: usize = 0,
    /// TS: discv5_lookup_count
    lookup_count: u64 = 0,
    /// Point-in-time actor work queues for stress and saturation diagnostics.
    active_lookup_count: usize = 0,
    active_request_count: usize = 0,
    queued_request_count: usize = 0,
    /// TS: discv5_rate_limit_hit_ip
    rate_limit_hit_ip: u64 = 0,
    /// TS: discv5_rate_limit_hit_total
    rate_limit_hit_total: u64 = 0,
    /// Encoded datagrams observed before pre-decrypt admission.
    received_packet_count: u64 = 0,
    /// Encoded datagrams rejected by pre-decrypt admission.
    filtered_packet_count: u64 = 0,
    /// Admitted datagrams processed by the Actor.
    processed_packet_count: u64 = 0,
    /// TS: discv5_sent_message_count{type}
    sent_message_count: [message_type_count]u64 = [_]u64{0} ** message_type_count,
    /// TS: discv5_rcvd_message_count{type}
    rcvd_message_count: [message_type_count]u64 = [_]u64{0} ** message_type_count,
    /// Completed events dropped before reaching consumers (allocation pressure).
    dropped_event_count: u64 = 0,
    /// Dropped events classified by their intended public event kind.
    dropped_event_count_by_kind: [events.event_kind_count]u64 = [_]u64{0} ** events.event_kind_count,
    /// Point-in-time bounded contact retention.
    contact_count: usize = 0,
    contact_capacity: usize = 0,
    /// Monotonic contact retention decisions.
    contact_inserted_total: u64 = 0,
    contact_updated_total: u64 = 0,
    contact_replaced_total: u64 = 0,
    contact_capacity_rejected_total: u64 = 0,
    contact_policy_rejected_total: u64 = 0,
    contact_removed_total: u64 = 0,
    /// Stable-session capacity and monotonic churn decisions.
    session_capacity: usize = 0,
    session_inserted_total: u64 = 0,
    session_rekeyed_total: u64 = 0,
    session_capacity_reused_total: u64 = 0,
    session_maintenance_expired_total: u64 = 0,
    session_authenticated_refreshed_total: u64 = 0,
    session_replay_rejected_total: u64 = 0,
    session_nonce_exhaustion_rejected_total: u64 = 0,

    pub fn sentMessageCount(self: *const MetricsSnapshot, message_type: MessageType) u64 {
        return self.sent_message_count[message_type.index()];
    }

    pub fn rcvdMessageCount(self: *const MetricsSnapshot, message_type: MessageType) u64 {
        return self.rcvd_message_count[message_type.index()];
    }

    pub fn droppedEventCount(self: *const MetricsSnapshot, kind: events.EventKind) u64 {
        return self.dropped_event_count_by_kind[kind.index()];
    }
};

test "discv5 metrics message labels mirror ChainSafe TS enum labels" {
    try std.testing.expectEqualStrings("PING", MessageType.ping.label());
    try std.testing.expectEqualStrings("PONG", MessageType.pong.label());
    try std.testing.expectEqualStrings("FINDNODE", MessageType.findnode.label());
    try std.testing.expectEqualStrings("NODES", MessageType.nodes.label());
    try std.testing.expectEqualStrings("TALKREQ", MessageType.talkreq.label());
    try std.testing.expectEqualStrings("TALKRESP", MessageType.talkresp.label());
}

test "metrics instrumentation types are root exported" {
    const root = @import("root.zig");
    try std.testing.expect(root.MetricsSnapshot == MetricsSnapshot);
    try std.testing.expect(root.ContactMetricsSnapshot == @import("state/peer_store.zig").ContactMetricsSnapshot);
    try std.testing.expect(root.SessionMetricsSnapshot == @import("state/session_book.zig").SessionMetricsSnapshot);
}
