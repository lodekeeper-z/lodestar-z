const std = @import("std");
const config = @import("config.zig");
const enr = @import("enr.zig");
const message = @import("protocol/message.zig");
const public_api = @import("public_api.zig");
const types = @import("types.zig");

const Allocator = std.mem.Allocator;
const Io = std.Io;

pub const PongResult = struct {
    enr_seq: u64,
    recipient_ip: message.Pong.RecipientIp,
    recipient_port: u16,
};

pub const RawEnrList = struct {
    buffer: [config.MAX_NODES_RESPONSE]enr.RawEnr = undefined,
    len: u8 = 0,

    pub fn slice(self: *const RawEnrList) []const enr.RawEnr {
        return self.buffer[0..self.len];
    }

    pub fn append(self: *RawEnrList, raw: enr.RawEnr) void {
        if (self.len >= self.buffer.len) unreachable;
        self.buffer[self.len] = raw;
        self.len += 1;
    }

    pub fn clear(self: *RawEnrList) void {
        self.len = 0;
    }

    pub fn fromValidated(validated_enrs: []const enr.ValidatedEnr) RawEnrList {
        if (validated_enrs.len > config.MAX_NODES_RESPONSE) unreachable;
        var result = RawEnrList{};
        for (validated_enrs) |validated| result.append(validated.raw);
        return result;
    }
};

pub const RequestSendFailure = enum {
    packet_too_large,
};

pub const RequestTerminal = union(enum) {
    pong: PongResult,
    nodes: RawEnrList,
    talk_response: types.PacketBytes,
    send_failure: RequestSendFailure,
    timeout,
    canceled,
    runtime_stopped,
};

pub const RequestResult = struct {
    handle: public_api.RequestHandle,
    kind: types.RequestKind,
    terminal: RequestTerminal,
};

/// Reliable take-once API request terminals. Runtime reserves one slot before
/// accepting a send command, so actor publication cannot allocate or wait.
pub const RequestResultOutbox = struct {
    allocator: Allocator,
    io: Io,
    queue: Io.Queue(RequestResult),
    buffer: []RequestResult,
    capacity: usize,
    outstanding: std.atomic.Value(usize) = .init(0),
    unclaimed: std.atomic.Value(usize) = .init(0),

    pub fn init(io: Io, allocator: Allocator, capacity: usize) !RequestResultOutbox {
        if (capacity == 0 or capacity > config.MAX_REQUEST_RESULTS) return error.InvalidRequestResultCapacity;
        const buffer = try allocator.alloc(RequestResult, capacity);
        return .{
            .allocator = allocator,
            .io = io,
            .queue = .init(buffer),
            .buffer = buffer,
            .capacity = capacity,
        };
    }

    pub fn close(self: *RequestResultOutbox) void {
        self.queue.close(self.io);
    }

    pub fn deinit(self: *RequestResultOutbox) void {
        self.close();
        var results: [1]RequestResult = undefined;
        while (true) {
            const count = self.queue.getUncancelable(self.io, &results, 0) catch break;
            if (count == 0) break;
            for (0..count) |_| self.release();
        }
        std.debug.assert(self.outstanding.load(.acquire) == 0);
        std.debug.assert(self.unclaimed.load(.acquire) == 0);
        self.allocator.free(self.buffer);
    }

    pub fn reserve(self: *RequestResultOutbox) bool {
        var current = self.outstanding.load(.acquire);
        while (current < self.capacity) {
            if (self.outstanding.cmpxchgWeak(current, current + 1, .acq_rel, .acquire)) |actual| {
                current = actual;
                continue;
            }
            _ = self.unclaimed.fetchAdd(1, .acq_rel);
            return true;
        }
        return false;
    }

    /// Transfer one pre-command reservation to actor-owned request work.
    pub fn claim(self: *RequestResultOutbox) bool {
        return decrement(&self.unclaimed);
    }

    /// Roll back a reservation whose command was not accepted.
    pub fn cancelUnclaimed(self: *RequestResultOutbox) void {
        if (!decrement(&self.unclaimed)) unreachable;
        self.release();
    }

    /// Roll back a claimed reservation when actor admission or send fails.
    pub fn release(self: *RequestResultOutbox) void {
        if (!decrement(&self.outstanding)) unreachable;
    }

    pub fn publishAssumeReserved(self: *RequestResultOutbox, result: RequestResult) void {
        std.debug.assert(self.outstanding.load(.acquire) > 0);
        const count = self.queue.putUncancelable(self.io, &.{result}, 0) catch unreachable;
        if (count != 1) unreachable;
    }

    pub fn next(self: *RequestResultOutbox) (Io.QueueClosedError || Io.Cancelable)!RequestResult {
        const result = try self.queue.getOne(self.io);
        self.release();
        return result;
    }

    pub fn pop(self: *RequestResultOutbox) ?RequestResult {
        var result: [1]RequestResult = undefined;
        const count = self.queue.getUncancelable(self.io, &result, 0) catch return null;
        if (count == 0) return null;
        std.debug.assert(count == 1);
        self.release();
        return result[0];
    }
};

fn decrement(value: *std.atomic.Value(usize)) bool {
    var current = value.load(.acquire);
    while (current > 0) {
        if (value.cmpxchgWeak(current, current - 1, .acq_rel, .acquire)) |actual| {
            current = actual;
            continue;
        }
        return true;
    }
    return false;
}
