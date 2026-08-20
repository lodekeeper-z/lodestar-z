const std = @import("std");
const config = @import("config.zig");
const enr = @import("enr.zig");
const message = @import("protocol/message.zig");
const types = @import("types.zig");

const Allocator = std.mem.Allocator;
const Io = std.Io;

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
    peer_disconnected,

    pub fn index(self: EventKind) usize {
        return switch (self) {
            .discovered => 0,
            .enr_added => 1,
            .multiaddr_updated => 2,
            .talk_req_received => 3,
            .talk_resp_received => 4,
            .session_established => 5,
            .peer_disconnected => 6,
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
            .peer_disconnected => "disconnected",
        };
    }
};

pub const event_kind_count = @typeInfo(EventKind).@"enum".fields.len;

/// Best-effort observations only. Initiated request and lookup terminal outcomes
/// are delivered through the reserved RequestResult and LookupResult outboxes.
pub const Event = union(enum) {
    talkreq: TalkReqEvent,
    talkresp: TalkRespEvent,
    discovered_enr: struct { raw: enr.RawEnr, enr: enr.Enr },
    enr_added: EnrAddedEvent,
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
            .peer_disconnected => .peer_disconnected,
        };
    }

    /// ChainSafe TypeScript discv5-aligned event labels.
    pub fn tsEventName(self: *const Event) []const u8 {
        return self.kind().label();
    }

    pub fn deinit(self: *Event, alloc: Allocator) void {
        switch (self.*) {
            .discovered_enr, .peer_connected, .peer_disconnected => {},
            .talkreq => |*value| value.deinit(alloc),
            .talkresp => |*value| value.deinit(alloc),
            .enr_added => |*value| value.deinit(alloc),
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
