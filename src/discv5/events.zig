const std = @import("std");
const config = @import("config.zig");
const enr = @import("enr.zig");
const message = @import("protocol/message.zig");
const types = @import("types.zig");

const Allocator = std.mem.Allocator;
const Io = std.Io;

pub const PongEvent = struct {
    peer_id: types.NodeId,
    peer_addr: types.Address,
    req_id: message.ReqId,
    enr_seq: u64,
    recipient_ip: message.Pong.RecipientIp,
    recipient_port: u16,
};

pub const NodesEvent = struct {
    peer_id: types.NodeId,
    peer_addr: types.Address,
    req_id: message.ReqId,
    enrs: std.ArrayListUnmanaged([]u8),

    pub fn deinit(self: *NodesEvent, alloc: Allocator) void {
        for (self.enrs.items) |bytes| alloc.free(bytes);
        self.enrs.deinit(alloc);
    }
};

pub const TalkReqEvent = struct {
    peer_id: types.NodeId,
    peer_addr: types.Address,
    req_id: message.ReqId,
    protocol: []u8,
    request: []u8,

    pub fn deinit(self: *TalkReqEvent, alloc: Allocator) void {
        alloc.free(self.protocol);
        alloc.free(self.request);
    }
};

pub const TalkRespEvent = struct {
    peer_id: types.NodeId,
    peer_addr: types.Address,
    req_id: message.ReqId,
    response: []u8,

    pub fn deinit(self: *TalkRespEvent, alloc: Allocator) void {
        alloc.free(self.response);
    }
};

pub const RequestTimeoutEvent = struct {
    peer_id: types.NodeId,
    req_id: message.ReqId,
    kind: types.RequestKind,
};

pub const LookupFinishedEvent = struct {
    lookup_id: u32,
    target: types.NodeId,
    enrs: std.ArrayListUnmanaged([]u8),
    timed_out: bool,

    pub fn deinit(self: *LookupFinishedEvent, alloc: Allocator) void {
        for (self.enrs.items) |bytes| alloc.free(bytes);
        self.enrs.deinit(alloc);
    }
};

pub const EnrAddedEvent = struct {
    node_id: types.NodeId,
    addr: types.Address,
    enr: []u8,
    replaced_enr: ?[]u8,

    pub fn deinit(self: *EnrAddedEvent, alloc: Allocator) void {
        alloc.free(self.enr);
        if (self.replaced_enr) |bytes| alloc.free(bytes);
    }
};

/// Stable programmatic classification independent of Zig union tag names.
pub const EventKind = enum {
    discovered,
    enr_added,
    multiaddr_updated,
    talk_req_received,
    talk_resp_received,
    session_established,
    request_failed,
    response_received,
    lookup_finished,
    peer_disconnected,

    pub fn index(self: EventKind) usize {
        return switch (self) {
            .discovered => 0,
            .enr_added => 1,
            .multiaddr_updated => 2,
            .talk_req_received => 3,
            .talk_resp_received => 4,
            .session_established => 5,
            .request_failed => 6,
            .response_received => 7,
            .lookup_finished => 8,
            .peer_disconnected => 9,
        };
    }

    /// ChainSafe TypeScript discv5-aligned event label.
    pub fn label(self: EventKind) []const u8 {
        return switch (self) {
            .discovered => "discovered",
            .enr_added => "enrAdded",
            .multiaddr_updated => "multiaddrUpdated",
            .talk_req_received => "talkReqReceived",
            .talk_resp_received => "talkRespReceived",
            .session_established => "established",
            .request_failed => "requestFailed",
            .response_received => "response",
            .lookup_finished => "lookupFinished",
            .peer_disconnected => "disconnected",
        };
    }
};

pub const event_kind_count = @typeInfo(EventKind).@"enum".fields.len;

pub const Event = union(enum) {
    pong: PongEvent,
    nodes: NodesEvent,
    talkreq: TalkReqEvent,
    talkresp: TalkRespEvent,
    request_timeout: RequestTimeoutEvent,
    discovered_enr: struct { raw: enr.RawEnr, enr: enr.Enr },
    enr_added: EnrAddedEvent,
    lookup_finished: LookupFinishedEvent,
    local_enr_updated: struct { seq: u64, enr: []u8 },
    peer_connected: struct { peer_id: types.NodeId, peer_addr: types.Address },
    peer_disconnected: struct { peer_id: types.NodeId, peer_addr: types.Address },

    pub fn kind(self: *const Event) EventKind {
        return switch (self.*) {
            .discovered_enr => .discovered,
            .enr_added => .enr_added,
            .local_enr_updated => .multiaddr_updated,
            .talkreq => .talk_req_received,
            .talkresp => .talk_resp_received,
            .peer_connected => .session_established,
            .request_timeout => .request_failed,
            .pong, .nodes => .response_received,
            .lookup_finished => .lookup_finished,
            .peer_disconnected => .peer_disconnected,
        };
    }

    /// ChainSafe TypeScript discv5-aligned event labels.
    pub fn tsEventName(self: *const Event) []const u8 {
        return self.kind().label();
    }

    pub fn deinit(self: *Event, alloc: Allocator) void {
        switch (self.*) {
            .pong, .request_timeout, .discovered_enr, .peer_connected, .peer_disconnected => {},
            .nodes => |*value| value.deinit(alloc),
            .talkreq => |*value| value.deinit(alloc),
            .talkresp => |*value| value.deinit(alloc),
            .enr_added => |*value| value.deinit(alloc),
            .lookup_finished => |*value| value.deinit(alloc),
            .local_enr_updated => |value| alloc.free(value.enr),
        }
    }
};

pub const EventOutbox = struct {
    allocator: Allocator,
    io: Io,
    queue: Io.Queue(Event),
    buffer: []Event,
    dropped: std.atomic.Value(u64) = .init(0),
    dropped_by_kind: [event_kind_count]std.atomic.Value(u64) = [_]std.atomic.Value(u64){.init(0)} ** event_kind_count,

    pub fn init(io: Io, allocator: Allocator, capacity: usize) !EventOutbox {
        if (capacity == 0 or capacity > config.MAX_EVENTS) return error.InvalidEventCapacity;
        const buffer = try allocator.alloc(Event, capacity);
        return .{
            .allocator = allocator,
            .io = io,
            .queue = .init(buffer),
            .buffer = buffer,
        };
    }

    pub fn close(self: *EventOutbox) void {
        self.queue.close(self.io);
    }

    pub fn deinit(self: *EventOutbox) void {
        self.close();
        var events: [16]Event = undefined;
        while (true) {
            const count = self.queue.getUncancelable(self.io, &events, 0) catch break;
            if (count == 0) break;
            for (events[0..count]) |*event| event.deinit(self.allocator);
        }
        self.allocator.free(self.buffer);
    }

    pub fn publish(self: *EventOutbox, event: Event) void {
        const kind = event.kind();
        const count = self.queue.putUncancelable(self.io, &.{event}, 0) catch {
            var dropped = event;
            dropped.deinit(self.allocator);
            self.noteDrop(kind);
            return;
        };
        if (count == 0) {
            var dropped = event;
            dropped.deinit(self.allocator);
            self.noteDrop(kind);
        }
    }

    pub fn notePayloadDrop(self: *EventOutbox, kind: EventKind) void {
        self.noteDrop(kind);
    }

    fn noteDrop(self: *EventOutbox, kind: EventKind) void {
        _ = self.dropped.fetchAdd(1, .acq_rel);
        _ = self.dropped_by_kind[kind.index()].fetchAdd(1, .acq_rel);
    }

    pub fn next(self: *EventOutbox) (Io.QueueClosedError || Io.Cancelable)!Event {
        return self.queue.getOne(self.io);
    }

    pub fn pop(self: *EventOutbox) ?Event {
        var result: [1]Event = undefined;
        const count = self.queue.getUncancelable(self.io, &result, 0) catch return null;
        return if (count == 1) result[0] else null;
    }

    pub fn droppedCount(self: *const EventOutbox) u64 {
        return self.dropped.load(.acquire);
    }

    pub fn droppedEventCount(self: *const EventOutbox, kind: EventKind) u64 {
        return self.dropped_by_kind[kind.index()].load(.acquire);
    }

    pub fn droppedEventCounts(self: *const EventOutbox) [event_kind_count]u64 {
        var snapshot = [_]u64{0} ** event_kind_count;
        for (&snapshot, &self.dropped_by_kind) |*count, *stored| count.* = stored.load(.acquire);
        return snapshot;
    }
};

test "event outbox drops and deinitializes owned payloads when full" {
    const io = std.Options.debug_io;
    var outbox = try EventOutbox.init(io, std.testing.allocator, 1);
    defer outbox.deinit();
    outbox.publish(.{ .local_enr_updated = .{
        .seq = 1,
        .enr = try std.testing.allocator.dupe(u8, "first"),
    } });
    outbox.publish(.{ .local_enr_updated = .{
        .seq = 2,
        .enr = try std.testing.allocator.dupe(u8, "second"),
    } });
    try std.testing.expectEqual(@as(u64, 1), outbox.droppedCount());
    try std.testing.expectEqual(@as(u64, 1), outbox.droppedEventCount(.multiaddr_updated));
    try std.testing.expectEqual(@as(u64, 0), outbox.droppedEventCount(.lookup_finished));
    const counts = outbox.droppedEventCounts();
    try std.testing.expectEqual(@as(u64, 1), counts[EventKind.multiaddr_updated.index()]);
}

test "payload drops are classified by intended event kind" {
    const io = std.Options.debug_io;
    var outbox = try EventOutbox.init(io, std.testing.allocator, 1);
    defer outbox.deinit();

    outbox.notePayloadDrop(.talk_req_received);
    outbox.notePayloadDrop(.talk_req_received);
    outbox.notePayloadDrop(.enr_added);

    try std.testing.expectEqual(@as(u64, 3), outbox.droppedCount());
    try std.testing.expectEqual(@as(u64, 2), outbox.droppedEventCount(.talk_req_received));
    try std.testing.expectEqual(@as(u64, 1), outbox.droppedEventCount(.enr_added));
    try std.testing.expectEqual(@as(u64, 0), outbox.droppedEventCount(.response_received));
}

test "every event maps to a stable kind and TS-aligned event name" {
    const peer_id = [_]u8{1} ** 32;
    const addr = types.Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 9000 } };
    const req_id = try message.ReqId.fromSlice(&.{1});
    var empty_bytes = [_]u8{};
    const empty: []u8 = &empty_bytes;
    const Expectation = struct {
        event: Event,
        kind: EventKind,
        name: []const u8,
    };
    const expectations = [_]Expectation{
        .{
            .event = .{ .pong = .{ .peer_id = peer_id, .peer_addr = addr, .req_id = req_id, .enr_seq = 0, .recipient_ip = .{ .ip4 = .{ 127, 0, 0, 1 } }, .recipient_port = 9000 } },
            .kind = .response_received,
            .name = "response",
        },
        .{
            .event = .{ .nodes = .{ .peer_id = peer_id, .peer_addr = addr, .req_id = req_id, .enrs = .empty } },
            .kind = .response_received,
            .name = "response",
        },
        .{
            .event = .{ .talkreq = .{ .peer_id = peer_id, .peer_addr = addr, .req_id = req_id, .protocol = empty, .request = empty } },
            .kind = .talk_req_received,
            .name = "talkReqReceived",
        },
        .{
            .event = .{ .talkresp = .{ .peer_id = peer_id, .peer_addr = addr, .req_id = req_id, .response = empty } },
            .kind = .talk_resp_received,
            .name = "talkRespReceived",
        },
        .{
            .event = .{ .request_timeout = .{ .peer_id = peer_id, .req_id = req_id, .kind = .ping } },
            .kind = .request_failed,
            .name = "requestFailed",
        },
        .{
            .event = .{ .discovered_enr = .{ .raw = .{}, .enr = undefined } },
            .kind = .discovered,
            .name = "discovered",
        },
        .{
            .event = .{ .enr_added = .{ .node_id = peer_id, .addr = addr, .enr = empty, .replaced_enr = null } },
            .kind = .enr_added,
            .name = "enrAdded",
        },
        .{
            .event = .{ .lookup_finished = .{ .lookup_id = 1, .target = peer_id, .enrs = .empty, .timed_out = false } },
            .kind = .lookup_finished,
            .name = "lookupFinished",
        },
        .{
            .event = .{ .local_enr_updated = .{ .seq = 1, .enr = empty } },
            .kind = .multiaddr_updated,
            .name = "multiaddrUpdated",
        },
        .{
            .event = .{ .peer_connected = .{ .peer_id = peer_id, .peer_addr = addr } },
            .kind = .session_established,
            .name = "established",
        },
        .{
            .event = .{ .peer_disconnected = .{ .peer_id = peer_id, .peer_addr = addr } },
            .kind = .peer_disconnected,
            .name = "disconnected",
        },
    };
    comptime std.debug.assert(expectations.len == @typeInfo(Event).@"union".fields.len);
    for (expectations) |expectation| {
        try std.testing.expectEqual(expectation.kind, expectation.event.kind());
        try std.testing.expectEqualStrings(expectation.name, expectation.event.tsEventName());
    }
}

test "EventKind is root exported for stable classification" {
    try std.testing.expect(@import("root.zig").EventKind == EventKind);
    try std.testing.expect(@import("root.zig").Event == Event);
    try std.testing.expectEqual(event_kind_count, @typeInfo(EventKind).@"enum".fields.len);
    try std.testing.expectEqualStrings("talkReqReceived", EventKind.talk_req_received.label());
    try std.testing.expectEqual(@as(usize, 3), EventKind.talk_req_received.index());
}
