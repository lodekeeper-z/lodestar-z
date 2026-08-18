const std = @import("std");
const config_mod = @import("config.zig");
const rate_limit = @import("rate_limit.zig");
const types = @import("types.zig");

const Allocator = std.mem.Allocator;
pub const IpKey = rate_limit.IpKey;

pub const Stats = struct {
    received_total: u64 = 0,
    filtered_total: u64 = 0,
    processed_total: u64 = 0,
    rate_limit_hit_ip_total: u64 = 0,
    rate_limit_hit_total: u64 = 0,
};

const SlotIndex = u32;

pub const AdmissionPermit = struct {
    slot: SlotIndex,
    generation: u64,
    armed: bool = true,

    pub fn release(self: *AdmissionPermit, admission: *IngressAdmission) void {
        if (!self.armed) return;
        admission.release(self.slot, self.generation);
        self.armed = false;
    }

    pub fn move(self: *AdmissionPermit) AdmissionPermit {
        std.debug.assert(self.armed);
        const result = self.*;
        self.armed = false;
        return result;
    }
};

const ExpectedEntry = struct {
    remaining: u32,
    head: ?SlotIndex,
};

const PermitSlot = struct {
    ip: IpKey = undefined,
    remaining: u16 = 0,
    generation: u64 = 0,
    in_use: bool = false,
    previous: ?SlotIndex = null,
    next: ?SlotIndex = null,
    free_next: ?SlotIndex = null,
};

pub const IngressAdmission = struct {
    alloc: Allocator,
    mutex: std.atomic.Mutex = .unlocked,
    limiter: ?rate_limit.RateLimiter,
    stats: Stats = .{},
    expected_by_ip: std.AutoHashMap(IpKey, ExpectedEntry),
    permit_slots: []PermitSlot,
    free_head: ?SlotIndex,
    live_permits: usize = 0,

    pub fn init(alloc: Allocator, config: ?rate_limit.Config, max_permits: usize) !IngressAdmission {
        if (max_permits == 0 or max_permits > std.math.maxInt(SlotIndex)) return error.InvalidAdmissionCapacity;
        var limiter: ?rate_limit.RateLimiter = if (config) |value| try .init(alloc, value) else null;
        errdefer if (limiter) |*value| value.deinit();
        var expected = std.AutoHashMap(IpKey, ExpectedEntry).init(alloc);
        errdefer expected.deinit();
        try expected.ensureTotalCapacity(@intCast(max_permits));
        const slots = try alloc.alloc(PermitSlot, max_permits);
        errdefer alloc.free(slots);
        for (slots, 0..) |*slot, index| {
            slot.* = .{ .free_next = if (index + 1 < slots.len) @intCast(index + 1) else null };
        }
        return .{
            .alloc = alloc,
            .limiter = limiter,
            .expected_by_ip = expected,
            .permit_slots = slots,
            .free_head = 0,
        };
    }

    pub fn deinit(self: *IngressAdmission) void {
        std.debug.assert(self.live_permits == 0);
        std.debug.assert(self.expected_by_ip.count() == 0);
        if (self.limiter) |*limiter| limiter.deinit();
        self.expected_by_ip.deinit();
        self.alloc.free(self.permit_slots);
    }

    pub fn accept(self: *IngressAdmission, from: types.Address, now_ms: u64) bool {
        self.lock();
        defer self.mutex.unlock();
        self.stats.received_total +|= 1;
        const ip = IpKey.fromAddress(from);
        if (self.consumeExpected(ip)) return true;
        if (self.limiter) |*limiter| {
            if (!limiter.allowEncodedPacket(from, now_ms)) {
                self.stats.filtered_total +|= 1;
                const rate_stats = limiter.statsSnapshot();
                self.stats.rate_limit_hit_ip_total = rate_stats.rate_limit_hit_ip_total;
                self.stats.rate_limit_hit_total = rate_stats.rate_limit_hit_total;
                return false;
            }
        }
        return true;
    }

    /// Capacity is reserved at initialization, so acquiring a permit is
    /// allocation-free and cannot fail after request preparation.
    pub fn acquire(
        self: *IngressAdmission,
        address: types.Address,
        packet_budget: u16,
    ) error{ TooManyAdmissionPermits, InvalidPacketBudget, AdmissionBudgetOverflow, PermitGenerationExhausted }!AdmissionPermit {
        if (packet_budget == 0) return error.InvalidPacketBudget;
        self.lock();
        defer self.mutex.unlock();
        const slot_index = self.free_head orelse return error.TooManyAdmissionPermits;
        const ip = IpKey.fromAddress(address);
        const previous_budget = if (self.expected_by_ip.get(ip)) |entry| entry.remaining else 0;
        const next_budget = std.math.add(u32, previous_budget, packet_budget) catch return error.AdmissionBudgetOverflow;
        const slot = &self.permit_slots[slot_index];
        const generation = std.math.add(u64, slot.generation, 1) catch return error.PermitGenerationExhausted;
        const entry = self.expected_by_ip.getOrPutAssumeCapacity(ip);
        if (!entry.found_existing) entry.value_ptr.* = .{ .remaining = 0, .head = null };
        self.free_head = slot.free_next;
        slot.* = .{
            .ip = ip,
            .remaining = packet_budget,
            .generation = generation,
            .in_use = true,
            .next = entry.value_ptr.head,
        };
        if (slot.next) |next| self.permit_slots[next].previous = slot_index;
        entry.value_ptr.head = slot_index;
        entry.value_ptr.remaining = next_budget;
        self.live_permits += 1;
        return .{ .slot = slot_index, .generation = generation };
    }

    pub fn noteProcessed(self: *IngressAdmission) void {
        self.lock();
        defer self.mutex.unlock();
        self.stats.processed_total +|= 1;
    }

    pub fn noteTruncated(self: *IngressAdmission) void {
        self.lock();
        defer self.mutex.unlock();
        self.stats.received_total +|= 1;
        self.stats.filtered_total +|= 1;
    }

    pub fn snapshot(self: *IngressAdmission) Stats {
        self.lock();
        defer self.mutex.unlock();
        return self.stats;
    }

    pub fn permitCount(self: *IngressAdmission) usize {
        self.lock();
        defer self.mutex.unlock();
        return self.live_permits;
    }

    fn consumeExpected(self: *IngressAdmission, ip: IpKey) bool {
        const entry = self.expected_by_ip.getPtr(ip) orelse return false;
        const slot_index = entry.head orelse unreachable;
        const slot = &self.permit_slots[slot_index];
        std.debug.assert(slot.in_use and slot.remaining > 0);
        std.debug.assert(entry.remaining > 0);
        slot.remaining -= 1;
        entry.remaining -= 1;
        if (slot.remaining == 0) self.unlinkExpected(entry, slot_index);
        if (entry.remaining == 0) std.debug.assert(self.expected_by_ip.remove(ip));
        return true;
    }

    fn release(self: *IngressAdmission, slot_index: SlotIndex, generation: u64) void {
        self.lock();
        defer self.mutex.unlock();
        std.debug.assert(slot_index < self.permit_slots.len);
        const slot = &self.permit_slots[slot_index];
        std.debug.assert(slot.in_use and slot.generation == generation);
        std.debug.assert(self.live_permits > 0);
        if (slot.remaining > 0) {
            const ip = slot.ip;
            const entry = self.expected_by_ip.getPtr(ip) orelse unreachable;
            std.debug.assert(entry.remaining >= slot.remaining);
            entry.remaining -= slot.remaining;
            self.unlinkExpected(entry, slot_index);
            if (entry.remaining == 0) std.debug.assert(self.expected_by_ip.remove(ip));
        }
        const next_generation = slot.generation;
        slot.* = .{ .generation = next_generation, .free_next = self.free_head };
        self.free_head = slot_index;
        self.live_permits -= 1;
    }

    fn unlinkExpected(self: *IngressAdmission, entry: *ExpectedEntry, slot_index: SlotIndex) void {
        const slot = &self.permit_slots[slot_index];
        if (slot.previous) |previous| {
            self.permit_slots[previous].next = slot.next;
        } else {
            std.debug.assert(entry.head == slot_index);
            entry.head = slot.next;
        }
        if (slot.next) |next| self.permit_slots[next].previous = slot.previous;
        slot.previous = null;
        slot.next = null;
    }

    fn lock(self: *IngressAdmission) void {
        while (!self.mutex.tryLock()) std.atomic.spinLoopHint();
    }
};

pub fn permitCapacity(limits: config_mod.Limits) error{AdmissionCapacityOverflow}!usize {
    const requests_and_challenges = std.math.add(usize, limits.max_active_requests, limits.challenge_capacity) catch
        return error.AdmissionCapacityOverflow;
    const owned_capacity = std.math.add(usize, requests_and_challenges, limits.response_recovery_capacity) catch
        return error.AdmissionCapacityOverflow;
    return std.math.add(usize, owned_capacity, ADMISSION_PREPARATION_HEADROOM) catch
        return error.AdmissionCapacityOverflow;
}

pub fn requestPacketBudget(kind: types.RequestKind) u16 {
    return switch (kind) {
        .ping, .talkreq => 2,
        .findnode => 1 + config_mod.MAX_NODES_RESPONSE,
    };
}

pub fn challengePacketBudget(request_retries: u32) u16 {
    std.debug.assert(request_retries <= config_mod.MAX_REQUEST_RETRIES);
    return @intCast(request_retries + 1);
}

pub const RESPONSE_RECOVERY_PACKET_BUDGET: u16 = 1;
pub const ADMISSION_PREPARATION_HEADROOM: usize = 1;

fn initAdmissionFailure(alloc: Allocator) !void {
    var admission = try IngressAdmission.init(alloc, .{
        .global_quota = .{ .replenish_all_every_ms = 1_000, .max_tokens = 4 },
        .by_ip_quota = .{ .replenish_all_every_ms = 1_000, .max_tokens = 2 },
    }, 8);
    admission.deinit();
}

test "admission initialization cleans up every allocation failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, initAdmissionFailure, .{});
}

test "admission permits conserve exact per-IP ownership" {
    var admission = try IngressAdmission.init(std.testing.allocator, null, 3);
    defer admission.deinit();
    const a: types.Address = .{ .ip4 = .{ .bytes = .{ 192, 0, 2, 1 }, .port = 1 } };
    const a_other_port: types.Address = .{ .ip4 = .{ .bytes = .{ 192, 0, 2, 1 }, .port = 2 } };
    const b: types.Address = .{ .ip4 = .{ .bytes = .{ 192, 0, 2, 2 }, .port = 1 } };
    var first = try admission.acquire(a, 1);
    var second = try admission.acquire(a_other_port, 1);
    var third = try admission.acquire(b, 1);
    try std.testing.expectError(error.TooManyAdmissionPermits, admission.acquire(b, 1));
    try std.testing.expectEqual(@as(usize, 3), admission.permitCount());
    second.release(&admission);
    second.release(&admission);
    try std.testing.expectEqual(@as(usize, 2), admission.permitCount());
    first.release(&admission);
    third.release(&admission);
    try std.testing.expectEqual(@as(usize, 0), admission.permitCount());
}

test "same-IP permit release removes only its own unconsumed packet budget" {
    var admission = try IngressAdmission.init(std.testing.allocator, .{
        .global_quota = .{ .replenish_all_every_ms = 1_000, .max_tokens = 8 },
        .by_ip_quota = .{ .replenish_all_every_ms = 1_000, .max_tokens = 1 },
    }, 2);
    defer admission.deinit();
    const address: types.Address = .{ .ip4 = .{ .bytes = .{ 203, 0, 113, 20 }, .port = 9_000 } };
    try std.testing.expect(admission.accept(address, 0));
    try std.testing.expect(!admission.accept(address, 0));
    var first = try admission.acquire(address, 1);
    var second = try admission.acquire(address, 2);
    try std.testing.expect(admission.accept(address, 1));
    first.release(&admission);
    try std.testing.expect(admission.accept(address, 1));
    try std.testing.expect(!admission.accept(address, 1));
    second.release(&admission);
    try std.testing.expectEqual(@as(usize, 0), admission.permitCount());
}

test "request packet budgets match ordinary and canonical multipart exchanges" {
    try std.testing.expectEqual(@as(u16, 2), requestPacketBudget(.ping));
    try std.testing.expectEqual(@as(u16, 2), requestPacketBudget(.talkreq));
    try std.testing.expectEqual(@as(u16, 17), requestPacketBudget(.findnode));
}

test "challenge budget admits every bounded retry probe plus the handshake" {
    var admission = try IngressAdmission.init(std.testing.allocator, .{
        .global_quota = .{ .replenish_all_every_ms = 1_000, .max_tokens = 10 },
        .by_ip_quota = .{ .replenish_all_every_ms = 1_000, .max_tokens = 1 },
    }, 1);
    defer admission.deinit();
    const address: types.Address = .{ .ip4 = .{ .bytes = .{ 198, 51, 100, 21 }, .port = 9_000 } };
    try std.testing.expect(admission.accept(address, 0));
    try std.testing.expect(!admission.accept(address, 0));

    var permit = try admission.acquire(address, challengePacketBudget(1));
    defer permit.release(&admission);
    try std.testing.expect(admission.accept(address, 1)); // exact retry probe
    try std.testing.expect(admission.accept(address, 1)); // resulting HANDSHAKE
    try std.testing.expect(!admission.accept(address, 1));
}

test "admission capacity includes one transactional preparation permit" {
    const limits = config_mod.Limits{
        .max_active_requests = 1,
        .challenge_capacity = 1,
        .response_recovery_capacity = 1,
    };
    const capacity = try permitCapacity(limits);
    try std.testing.expectEqual(@as(usize, 4), capacity);
    var admission = try IngressAdmission.init(std.testing.allocator, null, capacity);
    defer admission.deinit();
    const address: types.Address = .{ .ip4 = .{ .bytes = .{ 192, 0, 2, 40 }, .port = 9_000 } };
    var first = try admission.acquire(address, 1);
    var second = try admission.acquire(address, 1);
    var third = try admission.acquire(address, 1);
    var preparation = try admission.acquire(address, 1);
    try std.testing.expectError(error.TooManyAdmissionPermits, admission.acquire(address, 1));
    first.release(&admission);
    second.release(&admission);
    third.release(&admission);
    preparation.release(&admission);
}

test "admission acquisition remains allocation-free after initialization" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    const alloc = failing.allocator();
    var admission = try IngressAdmission.init(alloc, null, 1);
    defer admission.deinit();
    failing.fail_index = failing.alloc_index;
    var permit = try admission.acquire(.{ .ip4 = .{ .bytes = .{ 203, 0, 113, 1 }, .port = 9000 } }, 1);
    try std.testing.expect(!failing.has_induced_failure);
    permit.release(&admission);
}

test "expected response IP bypasses a pre-existing rate-limit ban" {
    var admission = try IngressAdmission.init(std.testing.allocator, .{
        .global_quota = .{ .replenish_all_every_ms = 1_000, .max_tokens = 10 },
        .by_ip_quota = .{ .replenish_all_every_ms = 1_000, .max_tokens = 1 },
    }, 1);
    defer admission.deinit();
    const address: types.Address = .{ .ip4 = .{ .bytes = .{ 198, 51, 100, 1 }, .port = 9000 } };
    try std.testing.expect(admission.accept(address, 0));
    try std.testing.expect(!admission.accept(address, 0));
    var permit = try admission.acquire(.{ .ip4 = .{ .bytes = .{ 198, 51, 100, 1 }, .port = 9001 } }, 1);
    try std.testing.expect(admission.accept(address, 1));
    permit.release(&admission);
    try std.testing.expect(!admission.accept(address, 1));
}

test "expected admission is packet bounded and preserves unrelated peer progress" {
    var admission = try IngressAdmission.init(std.testing.allocator, .{
        .global_quota = .{ .replenish_all_every_ms = 1_000, .max_tokens = 16 },
        .by_ip_quota = .{ .replenish_all_every_ms = 1_000, .max_tokens = 1 },
    }, 2);
    defer admission.deinit();
    const first: types.Address = .{ .ip4 = .{ .bytes = .{ 198, 51, 100, 10 }, .port = 9000 } };
    const second: types.Address = .{ .ip4 = .{ .bytes = .{ 198, 51, 100, 11 }, .port = 9000 } };

    try std.testing.expect(admission.accept(first, 0));
    try std.testing.expect(!admission.accept(first, 0));
    try std.testing.expect(admission.accept(second, 0));
    try std.testing.expect(!admission.accept(second, 0));

    var first_permit = try admission.acquire(first, 1);
    defer first_permit.release(&admission);
    var second_permit = try admission.acquire(second, 1);
    defer second_permit.release(&admission);

    const expected = admission.accept(first, 1);
    const unrelated_over_budget = admission.accept(first, 1);
    const unrelated_peer_expected = admission.accept(second, 1);
    try std.testing.expect(expected);
    try std.testing.expect(!unrelated_over_budget);
    try std.testing.expect(unrelated_peer_expected);
}
