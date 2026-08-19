const std = @import("std");
const config = @import("config.zig");
const enr = @import("enr.zig");
const lookup = @import("service/lookup.zig");
const types = @import("types.zig");

const Allocator = std.mem.Allocator;
const Io = std.Io;

pub const LookupTerminalReason = enum {
    completed,
    timed_out,
    runtime_stopped,
};

pub const RawEnrList = struct {
    buffer: [lookup.MAX_RESULTS]enr.RawEnr = undefined,
    len: u8 = 0,

    pub fn slice(self: *const RawEnrList) []const enr.RawEnr {
        return self.buffer[0..self.len];
    }

    pub fn append(self: *RawEnrList, raw: enr.RawEnr) void {
        if (self.len >= self.buffer.len) unreachable;
        self.buffer[self.len] = raw;
        self.len += 1;
    }
};

pub const LookupResult = struct {
    lookup_id: u32,
    target: types.NodeId,
    reason: LookupTerminalReason,
    enrs: RawEnrList = .{},
};

/// Reliable take-once lookup completions. One slot is reserved before lookup
/// work is accepted, so publishing a terminal result is allocation-free and
/// cannot wait for a consumer.
pub const LookupResultOutbox = struct {
    allocator: Allocator,
    io: Io,
    queue: Io.Queue(LookupResult),
    buffer: []LookupResult,
    capacity: usize,
    outstanding: std.atomic.Value(usize) = .init(0),
    unclaimed: std.atomic.Value(usize) = .init(0),

    pub fn init(io: Io, allocator: Allocator, capacity: usize) !LookupResultOutbox {
        if (capacity == 0 or capacity > config.MAX_LOOKUPS) return error.InvalidLookupResultCapacity;
        const buffer = try allocator.alloc(LookupResult, capacity);
        return .{
            .allocator = allocator,
            .io = io,
            .queue = .init(buffer),
            .buffer = buffer,
            .capacity = capacity,
        };
    }

    pub fn close(self: *LookupResultOutbox) void {
        self.queue.close(self.io);
    }

    pub fn deinit(self: *LookupResultOutbox) void {
        self.close();
        var results: [16]LookupResult = undefined;
        while (true) {
            const count = self.queue.getUncancelable(self.io, &results, 0) catch break;
            if (count == 0) break;
            for (0..count) |_| self.release();
        }
        std.debug.assert(self.outstanding.load(.acquire) == 0);
        std.debug.assert(self.unclaimed.load(.acquire) == 0);
        self.allocator.free(self.buffer);
    }

    pub fn reserve(self: *LookupResultOutbox) bool {
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

    /// Transfer one pre-command reservation to actor-owned lookup work.
    pub fn claim(self: *LookupResultOutbox) bool {
        return decrement(&self.unclaimed);
    }

    /// Roll back a reservation whose command was never accepted.
    pub fn cancelUnclaimed(self: *LookupResultOutbox) void {
        if (!decrement(&self.unclaimed)) unreachable;
        self.release();
    }

    pub fn release(self: *LookupResultOutbox) void {
        if (!decrement(&self.outstanding)) unreachable;
    }

    pub fn publishAssumeReserved(self: *LookupResultOutbox, result: LookupResult) void {
        std.debug.assert(self.outstanding.load(.acquire) > 0);
        const count = self.queue.putUncancelable(self.io, &.{result}, 0) catch unreachable;
        if (count != 1) unreachable;
    }

    pub fn next(self: *LookupResultOutbox) (Io.QueueClosedError || Io.Cancelable)!LookupResult {
        const result = try self.queue.getOne(self.io);
        self.release();
        return result;
    }

    pub fn pop(self: *LookupResultOutbox) ?LookupResult {
        var result: [1]LookupResult = undefined;
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
