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

pub const SlotIndex = u32;
pub const MAX_EXPECTED_CREDITS_PER_PERMIT: u16 = 17;

pub const PermitHandle = struct {
    slot: SlotIndex,
    generation: u64,
};

pub const AdmissionPermit = struct {
    slot: SlotIndex,
    generation: u64,
    armed: bool = true,

    pub fn handle(self: *const AdmissionPermit) PermitHandle {
        return .{ .slot = self.slot, .generation = self.generation };
    }

    pub fn release(self: *AdmissionPermit, admission: *IngressAdmission) void {
        if (!self.armed) return;
        admission.release(self.handle());
        self.armed = false;
    }

    pub fn move(self: *AdmissionPermit) AdmissionPermit {
        std.debug.assert(self.armed);
        const result = self.*;
        self.armed = false;
        return result;
    }
};

pub const ExpectedCredit = struct {
    source_slot: SlotIndex,
    source_permit_generation: u64,
    credit_generation: u64,
    armed: bool = true,

    pub fn source(self: *const ExpectedCredit) PermitHandle {
        return .{ .slot = self.source_slot, .generation = self.source_permit_generation };
    }

    pub fn commit(self: *ExpectedCredit, admission: *IngressAdmission, target: PermitHandle) bool {
        if (!self.armed) return false;
        if (!admission.commitExpected(self.source(), self.credit_generation, target)) return false;
        self.armed = false;
        return true;
    }

    pub fn rollback(self: *ExpectedCredit, admission: *IngressAdmission) void {
        if (!self.armed) return;
        admission.rollbackExpected(self.source(), self.credit_generation);
        self.armed = false;
    }

    pub fn move(self: *ExpectedCredit) ExpectedCredit {
        std.debug.assert(self.armed);
        const result = self.*;
        self.armed = false;
        return result;
    }
};

pub const Admission = union(enum) {
    filtered,
    ordinary,
    expected: ExpectedCredit,
};

const ExpectedEntry = struct {
    remaining: u32,
    head: ?SlotIndex,
};

const PermitSlot = struct {
    ip: IpKey = undefined,
    credit_generations: [MAX_EXPECTED_CREDITS_PER_PERMIT]u64 = [_]u64{0} ** MAX_EXPECTED_CREDITS_PER_PERMIT,
    permit_generation: u64 = 0,
    next_credit_generation: u64 = 0,
    remaining: u16 = 0,
    reserved: u16 = 0,
    in_use: bool = false,
    owner_live: bool = false,
    previous: ?SlotIndex = null,
    next: ?SlotIndex = null,
    free_next: ?SlotIndex = null,
};

pub const IngressAdmission = struct {
    alloc: Allocator,
    mutex: std.Io.Mutex = .init,
    limiter: ?rate_limit.RateLimiter,
    stats: Stats = .{},
    expected_by_ip: std.AutoHashMap(IpKey, ExpectedEntry),
    permit_slots: []PermitSlot,
    free_head: ?SlotIndex,
    live_permits: usize = 0,
    reserved_credits: usize = 0,

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
        std.debug.assert(self.reserved_credits == 0);
        std.debug.assert(self.expected_by_ip.count() == 0);
        if (self.limiter) |*limiter| limiter.deinit();
        self.expected_by_ip.deinit();
        self.alloc.free(self.permit_slots);
    }

    pub fn admit(self: *IngressAdmission, from: types.Address, now_ms: u64) Admission {
        self.lock();
        defer self.unlock();
        self.stats.received_total +|= 1;
        const ip = IpKey.fromAddress(from);
        if (self.limiter) |*limiter| {
            if (limiter.allowEncodedPacket(from, now_ms)) return .ordinary;
            const rate_stats = limiter.statsSnapshot();
            self.stats.rate_limit_hit_ip_total = rate_stats.rate_limit_hit_ip_total;
            self.stats.rate_limit_hit_total = rate_stats.rate_limit_hit_total;
            if (self.reserveExpected(ip)) |credit| return .{ .expected = credit };
            self.stats.filtered_total +|= 1;
            return .filtered;
        }
        return .ordinary;
    }

    pub fn acceptForTesting(self: *IngressAdmission, from: types.Address, now_ms: u64) bool {
        std.debug.assert(@import("builtin").is_test);
        var admitted = self.admit(from, now_ms);
        return switch (admitted) {
            .filtered => false,
            .ordinary => true,
            .expected => |*credit| blk: {
                if (!credit.commit(self, credit.source())) unreachable;
                break :blk true;
            },
        };
    }

    /// Capacity is reserved at initialization, so acquiring a permit is
    /// allocation-free and cannot fail after request preparation.
    pub fn acquire(
        self: *IngressAdmission,
        address: types.Address,
        packet_budget: u16,
    ) error{ TooManyAdmissionPermits, InvalidPacketBudget, AdmissionBudgetOverflow, PermitGenerationExhausted }!AdmissionPermit {
        if (packet_budget == 0 or packet_budget > MAX_EXPECTED_CREDITS_PER_PERMIT) return error.InvalidPacketBudget;
        self.lock();
        defer self.unlock();

        var cursor = self.free_head orelse return error.TooManyAdmissionPermits;
        var previous: ?SlotIndex = null;
        var selected: ?SlotIndex = null;
        var selected_previous: ?SlotIndex = null;
        var generation: u64 = undefined;
        var scanned: usize = 0;
        while (scanned < self.permit_slots.len) : (scanned += 1) {
            const slot = &self.permit_slots[cursor];
            if (slot.permit_generation < std.math.maxInt(u64)) {
                selected = cursor;
                selected_previous = previous;
                generation = slot.permit_generation + 1;
                break;
            }
            previous = cursor;
            cursor = slot.free_next orelse break;
        }
        std.debug.assert(scanned < self.permit_slots.len);
        const slot_index = selected orelse return error.PermitGenerationExhausted;
        const slot = &self.permit_slots[slot_index];
        const ip = IpKey.fromAddress(address);
        const previous_budget = if (self.expected_by_ip.get(ip)) |entry| entry.remaining else 0;
        const next_budget = std.math.add(u32, previous_budget, packet_budget) catch return error.AdmissionBudgetOverflow;
        const entry = self.expected_by_ip.getOrPutAssumeCapacity(ip);
        if (!entry.found_existing) entry.value_ptr.* = .{ .remaining = 0, .head = null };

        if (selected_previous) |free_previous| {
            self.permit_slots[free_previous].free_next = slot.free_next;
        } else {
            self.free_head = slot.free_next;
        }
        const next_credit_generation = slot.next_credit_generation;
        slot.* = .{
            .ip = ip,
            .remaining = packet_budget,
            .permit_generation = generation,
            .next_credit_generation = next_credit_generation,
            .in_use = true,
            .owner_live = true,
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
        defer self.unlock();
        self.stats.processed_total +|= 1;
    }

    pub fn noteTruncated(self: *IngressAdmission) void {
        self.lock();
        defer self.unlock();
        self.stats.received_total +|= 1;
        self.stats.filtered_total +|= 1;
    }

    pub fn snapshot(self: *IngressAdmission) Stats {
        self.lock();
        defer self.unlock();
        return self.stats;
    }

    pub fn permitCount(self: *IngressAdmission) usize {
        self.lock();
        defer self.unlock();
        return self.live_permits;
    }

    pub const Testing = if (@import("builtin").is_test) struct {
        pub const Fingerprint = struct {
            active_receipts: u64,
            list_links: u64,
            remaining: u64,
            free_slots: u64,
            live_permits: usize,
            reserved_credits: usize,
            permit_generations: u64,
            credit_generations: u64,
        };

        fn mix(value: u64, input: u64) u64 {
            return std.math.rotl(u64, value ^ input, 17) *% 0x9e3779b97f4a7c15;
        }

        pub fn fingerprint(self: *IngressAdmission) Fingerprint {
            self.lock();
            defer self.unlock();
            var result = Fingerprint{
                .active_receipts = 0,
                .list_links = 0,
                .remaining = 0,
                .free_slots = 0,
                .live_permits = self.live_permits,
                .reserved_credits = self.reserved_credits,
                .permit_generations = 0,
                .credit_generations = 0,
            };
            for (self.permit_slots, 0..) |slot, index| {
                const tag: u64 = @intCast(index + 1);
                result.permit_generations = mix(result.permit_generations, tag ^ slot.permit_generation);
                result.credit_generations = mix(result.credit_generations, tag ^ slot.next_credit_generation);
                result.remaining = mix(result.remaining, tag ^ slot.remaining ^ (@as(u64, slot.reserved) << 16));
                result.list_links = mix(result.list_links, tag ^ (@as(u64, @intFromBool(slot.in_use)) << 63) ^
                    (@as(u64, @intFromBool(slot.owner_live)) << 62) ^
                    (@as(u64, if (slot.previous) |value| value + 1 else 0) << 31) ^
                    @as(u64, if (slot.next) |value| value + 1 else 0));
                result.free_slots = mix(result.free_slots, tag ^ @as(u64, if (slot.free_next) |value| value + 1 else 0));
                for (slot.credit_generations, 0..) |generation, lane| {
                    if (generation != 0) result.active_receipts = mix(
                        result.active_receipts,
                        (tag << 48) ^ (@as(u64, @intCast(lane + 1)) << 40) ^ generation,
                    );
                }
            }
            result.free_slots = mix(result.free_slots, @as(u64, if (self.free_head) |value| value + 1 else 0));
            return result;
        }

        pub fn permitGenerationFingerprint(self: *IngressAdmission) u64 {
            return fingerprint(self).permit_generations;
        }
    } else struct {};

    fn reserveExpected(self: *IngressAdmission, ip: IpKey) ?ExpectedCredit {
        const entry = self.expected_by_ip.getPtr(ip) orelse return null;
        var cursor = entry.head orelse unreachable;
        var selected: ?SlotIndex = null;
        var selected_lane: usize = undefined;
        var credit_generation: u64 = undefined;
        var scanned: usize = 0;
        while (scanned < self.permit_slots.len) : (scanned += 1) {
            const slot = &self.permit_slots[cursor];
            std.debug.assert(slot.in_use and slot.owner_live and slot.remaining > 0);
            if (slot.next_credit_generation < std.math.maxInt(u64)) {
                for (slot.credit_generations, 0..) |active_generation, lane| {
                    if (active_generation == 0) {
                        selected = cursor;
                        selected_lane = lane;
                        credit_generation = slot.next_credit_generation + 1;
                        break;
                    }
                }
                if (selected != null) break;
            }
            cursor = slot.next orelse break;
        }
        std.debug.assert(scanned < self.permit_slots.len);
        const slot_index = selected orelse return null;
        const slot = &self.permit_slots[slot_index];
        std.debug.assert(entry.remaining > 0);
        slot.credit_generations[selected_lane] = credit_generation;
        slot.next_credit_generation = credit_generation;
        slot.remaining -= 1;
        slot.reserved = std.math.add(u16, slot.reserved, 1) catch unreachable;
        self.reserved_credits += 1;
        entry.remaining -= 1;
        if (slot.remaining == 0) self.unlinkExpected(entry, slot_index);
        if (entry.remaining == 0) std.debug.assert(self.expected_by_ip.remove(ip));
        return .{
            .source_slot = slot_index,
            .source_permit_generation = slot.permit_generation,
            .credit_generation = credit_generation,
        };
    }

    fn activeCreditLane(slot: *const PermitSlot, credit_generation: u64) ?usize {
        if (credit_generation == 0) return null;
        for (slot.credit_generations, 0..) |active_generation, lane| {
            if (active_generation == credit_generation) return lane;
        }
        return null;
    }

    fn commitExpected(
        self: *IngressAdmission,
        source: PermitHandle,
        credit_generation: u64,
        target: PermitHandle,
    ) bool {
        self.lock();
        defer self.unlock();
        if (source.slot >= self.permit_slots.len) return false;
        const source_slot = &self.permit_slots[source.slot];
        if (!source_slot.in_use or source_slot.permit_generation != source.generation) return false;
        const credit_lane = activeCreditLane(source_slot, credit_generation) orelse return false;
        if (target.slot >= self.permit_slots.len) return false;
        const target_slot = &self.permit_slots[target.slot];
        if (!target_slot.in_use or !target_slot.owner_live or target_slot.permit_generation != target.generation) return false;
        if (!std.meta.eql(source_slot.ip, target_slot.ip)) return false;

        const same_permit = source.slot == target.slot and source.generation == target.generation;
        if (same_permit) {
            if (!source_slot.owner_live) return false;
        } else {
            if (target_slot.remaining == 0) return false;
            const entry = self.expected_by_ip.getPtr(source_slot.ip) orelse unreachable;
            target_slot.remaining -= 1;
            std.debug.assert(entry.remaining > 0);
            entry.remaining -= 1;
            if (target_slot.remaining == 0) self.unlinkExpected(entry, target.slot);
            if (source_slot.owner_live) {
                const source_was_empty = source_slot.remaining == 0;
                source_slot.remaining = std.math.add(u16, source_slot.remaining, 1) catch unreachable;
                entry.remaining = std.math.add(u32, entry.remaining, 1) catch unreachable;
                if (source_was_empty) self.linkExpected(entry, source.slot);
            }
            if (entry.remaining == 0) std.debug.assert(self.expected_by_ip.remove(source_slot.ip));
        }

        std.debug.assert(source_slot.reserved > 0 and self.reserved_credits > 0);
        source_slot.credit_generations[credit_lane] = 0;
        source_slot.reserved -= 1;
        self.reserved_credits -= 1;
        if (!source_slot.owner_live and source_slot.reserved == 0) self.recycleSlot(source.slot);
        return true;
    }

    fn rollbackExpected(self: *IngressAdmission, source: PermitHandle, credit_generation: u64) void {
        self.lock();
        defer self.unlock();
        if (source.slot >= self.permit_slots.len) return;
        const slot = &self.permit_slots[source.slot];
        if (!slot.in_use or slot.permit_generation != source.generation) return;
        const credit_lane = activeCreditLane(slot, credit_generation) orelse return;
        std.debug.assert(slot.reserved > 0 and self.reserved_credits > 0);
        slot.credit_generations[credit_lane] = 0;
        slot.reserved -= 1;
        self.reserved_credits -= 1;
        if (slot.owner_live) {
            const was_empty = slot.remaining == 0;
            const entry = self.expected_by_ip.getOrPutAssumeCapacity(slot.ip);
            if (!entry.found_existing) entry.value_ptr.* = .{ .remaining = 0, .head = null };
            slot.remaining = std.math.add(u16, slot.remaining, 1) catch unreachable;
            entry.value_ptr.remaining = std.math.add(u32, entry.value_ptr.remaining, 1) catch unreachable;
            if (was_empty) self.linkExpected(entry.value_ptr, source.slot);
        } else if (slot.reserved == 0) {
            self.recycleSlot(source.slot);
        }
    }

    fn release(self: *IngressAdmission, handle: PermitHandle) void {
        self.lock();
        defer self.unlock();
        if (handle.slot >= self.permit_slots.len) return;
        const slot = &self.permit_slots[handle.slot];
        if (!slot.in_use or !slot.owner_live or slot.permit_generation != handle.generation) return;
        std.debug.assert(self.live_permits > 0);
        if (slot.remaining > 0) {
            const ip = slot.ip;
            const entry = self.expected_by_ip.getPtr(ip) orelse unreachable;
            std.debug.assert(entry.remaining >= slot.remaining);
            entry.remaining -= slot.remaining;
            self.unlinkExpected(entry, handle.slot);
            if (entry.remaining == 0) std.debug.assert(self.expected_by_ip.remove(ip));
            slot.remaining = 0;
        }
        slot.owner_live = false;
        self.live_permits -= 1;
        if (slot.reserved == 0) self.recycleSlot(handle.slot);
    }

    fn recycleSlot(self: *IngressAdmission, slot_index: SlotIndex) void {
        const slot = &self.permit_slots[slot_index];
        std.debug.assert(slot.in_use and !slot.owner_live and slot.remaining == 0 and slot.reserved == 0);
        const permit_generation = slot.permit_generation;
        const next_credit_generation = slot.next_credit_generation;
        slot.* = .{
            .permit_generation = permit_generation,
            .next_credit_generation = next_credit_generation,
            .free_next = self.free_head,
        };
        self.free_head = slot_index;
    }

    fn linkExpected(self: *IngressAdmission, entry: *ExpectedEntry, slot_index: SlotIndex) void {
        const slot = &self.permit_slots[slot_index];
        std.debug.assert(slot.in_use and slot.owner_live and slot.remaining > 0);
        std.debug.assert(slot.previous == null and slot.next == null);
        slot.next = entry.head;
        if (slot.next) |next| self.permit_slots[next].previous = slot_index;
        entry.head = slot_index;
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
        std.Io.Threaded.mutexLock(&self.mutex);
    }

    fn unlock(self: *IngressAdmission) void {
        std.Io.Threaded.mutexUnlock(&self.mutex);
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

comptime {
    std.debug.assert(1 + config_mod.MAX_NODES_RESPONSE <= MAX_EXPECTED_CREDITS_PER_PERMIT);
    std.debug.assert(config_mod.MAX_REQUEST_RETRIES + 1 <= MAX_EXPECTED_CREDITS_PER_PERMIT);
    std.debug.assert(RESPONSE_RECOVERY_PACKET_BUDGET <= MAX_EXPECTED_CREDITS_PER_PERMIT);
}

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

test "packet budget above exact credit capacity is rejected without mutation" {
    var admission = try IngressAdmission.init(std.testing.allocator, null, 2);
    defer admission.deinit();
    const address: types.Address = .{ .ip4 = .{ .bytes = .{ 192, 0, 2, 18 }, .port = 9_000 } };
    const free_head_before = admission.free_head;
    const map_count_before = admission.expected_by_ip.count();
    const generation_before = IngressAdmission.Testing.permitGenerationFingerprint(&admission);

    try std.testing.expectError(error.InvalidPacketBudget, admission.acquire(address, 18));
    try std.testing.expectEqual(free_head_before, admission.free_head);
    try std.testing.expectEqual(map_count_before, admission.expected_by_ip.count());
    try std.testing.expectEqual(generation_before, IngressAdmission.Testing.permitGenerationFingerprint(&admission));
    try std.testing.expectEqual(@as(usize, 0), admission.live_permits);
    try std.testing.expectEqual(@as(usize, 0), admission.reserved_credits);
}

test "exact receipt generations resolve independently out of order" {
    var admission = try IngressAdmission.init(std.testing.allocator, .{
        .global_quota = .{ .replenish_all_every_ms = 1_000, .max_tokens = 4 },
        .by_ip_quota = .{ .replenish_all_every_ms = 1_000, .max_tokens = 1 },
    }, 1);
    defer admission.deinit();
    const address: types.Address = .{ .ip4 = .{ .bytes = .{ 192, 0, 2, 19 }, .port = 9_000 } };
    try std.testing.expect(admission.admit(address, 0) == .ordinary);
    var permit = try admission.acquire(address, 2);
    defer permit.release(&admission);
    var first = switch (admission.admit(address, 0)) {
        .expected => |credit| credit,
        else => return error.MissingFirstExpectedCredit,
    };
    var second = switch (admission.admit(address, 0)) {
        .expected => |credit| credit,
        else => return error.MissingSecondExpectedCredit,
    };
    var first_copy = first;
    var second_copy = second;

    try std.testing.expect(first.commit(&admission, permit.handle()));
    try std.testing.expect(!first_copy.commit(&admission, permit.handle()));
    second.rollback(&admission);
    first_copy.rollback(&admission);
    second_copy.rollback(&admission);
    try std.testing.expectEqual(@as(usize, 0), admission.reserved_credits);

    var restored = switch (admission.admit(address, 0)) {
        .expected => |credit| credit,
        else => return error.MissingRestoredSiblingCredit,
    };
    try std.testing.expect(restored.commit(&admission, permit.handle()));
}

test "copied and stale permit releases cannot release a reused slot" {
    var admission = try IngressAdmission.init(std.testing.allocator, null, 1);
    defer admission.deinit();
    const address: types.Address = .{ .ip4 = .{ .bytes = .{ 192, 0, 2, 20 }, .port = 9_000 } };
    var first = try admission.acquire(address, 1);
    var first_copy = first;
    const old_generation = first.generation;
    first.release(&admission);
    first_copy.release(&admission);
    try std.testing.expectEqual(@as(usize, 0), admission.permitCount());

    var replacement = try admission.acquire(address, 1);
    defer replacement.release(&admission);
    try std.testing.expect(replacement.generation > old_generation);
    var stale = AdmissionPermit{ .slot = replacement.slot, .generation = old_generation };
    stale.release(&admission);
    try std.testing.expectEqual(@as(usize, 1), admission.permitCount());
}

test "permit generation exhaustion skips viable free slots and all-exhausted is atomic" {
    var admission = try IngressAdmission.init(std.testing.allocator, null, 2);
    defer admission.deinit();
    const address: types.Address = .{ .ip4 = .{ .bytes = .{ 192, 0, 2, 21 }, .port = 9_000 } };
    admission.permit_slots[0].permit_generation = std.math.maxInt(u64);
    var alternate = try admission.acquire(address, 1);
    try std.testing.expectEqual(@as(SlotIndex, 1), alternate.slot);
    alternate.release(&admission);
    admission.permit_slots[1].permit_generation = std.math.maxInt(u64);
    const free_head_before = admission.free_head;
    const fingerprint_before = IngressAdmission.Testing.permitGenerationFingerprint(&admission);
    try std.testing.expectError(error.PermitGenerationExhausted, admission.acquire(address, 1));
    try std.testing.expectEqual(free_head_before, admission.free_head);
    try std.testing.expectEqual(fingerprint_before, IngressAdmission.Testing.permitGenerationFingerprint(&admission));
    try std.testing.expectEqual(@as(usize, 0), admission.expected_by_ip.count());
}

test "credit generation exhaustion skips same-IP permit and all-exhausted reserve is atomic" {
    var admission = try IngressAdmission.init(std.testing.allocator, null, 2);
    defer admission.deinit();
    const address: types.Address = .{ .ip4 = .{ .bytes = .{ 192, 0, 2, 22 }, .port = 9_000 } };
    var first = try admission.acquire(address, 1);
    defer first.release(&admission);
    var exhausted_head = try admission.acquire(address, 1);
    defer exhausted_head.release(&admission);
    admission.permit_slots[exhausted_head.slot].next_credit_generation = std.math.maxInt(u64);
    const ip = IpKey.fromAddress(address);
    admission.lock();
    var credit = admission.reserveExpected(ip) orelse {
        admission.unlock();
        return error.MissingAlternateExpectedCredit;
    };
    admission.unlock();
    try std.testing.expectEqual(first.handle(), credit.source());
    credit.rollback(&admission);

    admission.permit_slots[first.slot].next_credit_generation = std.math.maxInt(u64);
    const remaining_before = admission.expected_by_ip.get(ip).?.remaining;
    const reserved_before = admission.reserved_credits;
    admission.lock();
    const unavailable = admission.reserveExpected(ip);
    admission.unlock();
    try std.testing.expect(unavailable == null);
    try std.testing.expectEqual(remaining_before, admission.expected_by_ip.get(ip).?.remaining);
    try std.testing.expectEqual(reserved_before, admission.reserved_credits);
}

test "same-IP exact reassignment relinks source and unlinks exhausted target" {
    var admission = try IngressAdmission.init(std.testing.allocator, null, 2);
    defer admission.deinit();
    const address: types.Address = .{ .ip4 = .{ .bytes = .{ 192, 0, 2, 23 }, .port = 9_000 } };
    var target = try admission.acquire(address, 1);
    defer target.release(&admission);
    var source = try admission.acquire(address, 1);
    defer source.release(&admission);
    const ip = IpKey.fromAddress(address);
    admission.lock();
    var credit = admission.reserveExpected(ip).?;
    admission.unlock();
    try std.testing.expectEqual(source.handle(), credit.source());
    try std.testing.expectEqual(@as(u16, 0), admission.permit_slots[source.slot].remaining);
    try std.testing.expectEqual(@as(u16, 1), admission.permit_slots[target.slot].remaining);

    try std.testing.expect(credit.commit(&admission, target.handle()));
    try std.testing.expectEqual(@as(u16, 1), admission.permit_slots[source.slot].remaining);
    try std.testing.expectEqual(@as(u16, 0), admission.permit_slots[target.slot].remaining);
    const entry = admission.expected_by_ip.get(ip).?;
    try std.testing.expectEqual(@as(u32, 1), entry.remaining);
    try std.testing.expectEqual(source.slot, entry.head.?);
    try std.testing.expectEqual(@as(usize, 0), admission.reserved_credits);
}

test "invalid exact commit targets are atomic and rollback restores the source" {
    var admission = try IngressAdmission.init(std.testing.allocator, null, 4);
    defer admission.deinit();
    const same_ip: types.Address = .{ .ip4 = .{ .bytes = .{ 192, 0, 2, 24 }, .port = 9_000 } };
    const other_ip: types.Address = .{ .ip4 = .{ .bytes = .{ 192, 0, 2, 25 }, .port = 9_000 } };
    var target = try admission.acquire(same_ip, 1);
    var source = try admission.acquire(same_ip, 4);
    defer source.release(&admission);
    var foreign = try admission.acquire(other_ip, 1);
    defer foreign.release(&admission);
    admission.lock();
    var credit = admission.reserveExpected(IpKey.fromAddress(same_ip)).?;
    admission.unlock();
    const source_remaining = admission.permit_slots[source.slot].remaining;

    var before = IngressAdmission.Testing.fingerprint(&admission);
    try std.testing.expect(!credit.commit(&admission, foreign.handle()));
    try std.testing.expectEqual(before, IngressAdmission.Testing.fingerprint(&admission));
    try std.testing.expect(credit.armed);

    const stale_target = PermitHandle{ .slot = target.slot, .generation = target.generation + 1 };
    before = IngressAdmission.Testing.fingerprint(&admission);
    try std.testing.expect(!credit.commit(&admission, stale_target));
    try std.testing.expectEqual(before, IngressAdmission.Testing.fingerprint(&admission));

    const released_target = target.handle();
    target.release(&admission);
    before = IngressAdmission.Testing.fingerprint(&admission);
    try std.testing.expect(!credit.commit(&admission, released_target));
    try std.testing.expectEqual(before, IngressAdmission.Testing.fingerprint(&admission));

    var exhausted_target = try admission.acquire(same_ip, 1);
    defer exhausted_target.release(&admission);
    admission.lock();
    var target_receipt = admission.reserveExpected(IpKey.fromAddress(same_ip)).?;
    admission.unlock();
    try std.testing.expectEqual(exhausted_target.handle(), target_receipt.source());
    try std.testing.expectEqual(@as(u16, 0), admission.permit_slots[exhausted_target.slot].remaining);
    before = IngressAdmission.Testing.fingerprint(&admission);
    try std.testing.expect(!credit.commit(&admission, exhausted_target.handle()));
    try std.testing.expectEqual(before, IngressAdmission.Testing.fingerprint(&admission));

    target_receipt.rollback(&admission);
    credit.rollback(&admission);
    try std.testing.expectEqual(source_remaining + 1, admission.permit_slots[source.slot].remaining);
    var late_copy = credit;
    late_copy.rollback(&admission);
    try std.testing.expectEqual(@as(usize, 0), admission.reserved_credits);
}

test "dead receipt sources recycle only after their exact final callback" {
    var admission = try IngressAdmission.init(std.testing.allocator, null, 3);
    defer admission.deinit();
    const address: types.Address = .{ .ip4 = .{ .bytes = .{ 192, 0, 2, 26 }, .port = 9_000 } };

    var rollback_source = try admission.acquire(address, 1);
    admission.lock();
    var rollback_credit = admission.reserveExpected(IpKey.fromAddress(address)).?;
    admission.unlock();
    const rollback_slot = rollback_source.slot;
    rollback_source.release(&admission);
    try std.testing.expect(admission.permit_slots[rollback_slot].in_use);
    rollback_credit.rollback(&admission);
    try std.testing.expect(!admission.permit_slots[rollback_slot].in_use);

    var target = try admission.acquire(address, 2);
    defer target.release(&admission);
    var source = try admission.acquire(address, 2);
    admission.lock();
    var first = admission.reserveExpected(IpKey.fromAddress(address)).?;
    var second = admission.reserveExpected(IpKey.fromAddress(address)).?;
    admission.unlock();
    var first_copy = first;
    var second_copy = second;
    const dead_slot = source.slot;
    source.release(&admission);
    first.rollback(&admission);
    try std.testing.expect(admission.permit_slots[dead_slot].in_use);
    try std.testing.expect(!admission.permit_slots[dead_slot].owner_live);
    try std.testing.expectEqual(@as(u16, 0), admission.permit_slots[dead_slot].remaining);
    const target_before = admission.permit_slots[target.slot].remaining;
    try std.testing.expect(second.commit(&admission, target.handle()));
    try std.testing.expectEqual(target_before - 1, admission.permit_slots[target.slot].remaining);
    try std.testing.expect(!admission.permit_slots[dead_slot].in_use);
    first_copy.rollback(&admission);
    try std.testing.expect(!second_copy.commit(&admission, target.handle()));
    second_copy.rollback(&admission);
    try std.testing.expectEqual(@as(usize, 0), admission.reserved_credits);
}

test "post-init exact admission ledger transitions allocate no memory" {
    var backing: [32 * 1024]u8 = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&backing);
    var admission = try IngressAdmission.init(fixed.allocator(), null, 3);
    defer admission.deinit();
    const used_after_init = fixed.end_index;
    const address: types.Address = .{ .ip4 = .{ .bytes = .{ 192, 0, 2, 27 }, .port = 9_000 } };
    var target = try admission.acquire(address, 2);
    var source = try admission.acquire(address, 2);
    admission.lock();
    var committed = admission.reserveExpected(IpKey.fromAddress(address)).?;
    var rolled_back = admission.reserveExpected(IpKey.fromAddress(address)).?;
    admission.unlock();
    try std.testing.expect(committed.commit(&admission, target.handle()));
    rolled_back.rollback(&admission);
    source.release(&admission);
    target.release(&admission);
    try std.testing.expectEqual(used_after_init, fixed.end_index);
}

test "admission exact ledger registered layouts lock default backing" {
    const default_slots = try permitCapacity(.{});
    try std.testing.expectEqual(@as(usize, 16), @sizeOf(PermitHandle));
    try std.testing.expectEqual(@as(usize, 16), @sizeOf(AdmissionPermit));
    try std.testing.expectEqual(@as(usize, 24), @sizeOf(ExpectedCredit));
    try std.testing.expectEqual(@as(usize, 200), @sizeOf(PermitSlot));
    try std.testing.expectEqual(
        @as(usize, if (@import("builtin").mode == .ReleaseFast) 416 else 440),
        @sizeOf(IngressAdmission),
    );
    try std.testing.expectEqual(@as(usize, 3_073), default_slots);
    try std.testing.expectEqual(@as(usize, 614_600), default_slots * @sizeOf(PermitSlot));
    std.debug.print(
        "ADMISSION_LEDGER_LAYOUT permit_handle={} permit={} credit={} slot={} admission={} default_slots={} backing={}\n",
        .{ @sizeOf(PermitHandle), @sizeOf(AdmissionPermit), @sizeOf(ExpectedCredit), @sizeOf(PermitSlot), @sizeOf(IngressAdmission), default_slots, default_slots * @sizeOf(PermitSlot) },
    );
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
    try std.testing.expect(admission.acceptForTesting(address, 0));
    try std.testing.expect(!admission.acceptForTesting(address, 0));
    var first = try admission.acquire(address, 1);
    var second = try admission.acquire(address, 2);
    try std.testing.expect(admission.acceptForTesting(address, 1));
    first.release(&admission);
    try std.testing.expect(admission.acceptForTesting(address, 1));
    try std.testing.expect(!admission.acceptForTesting(address, 1));
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
    try std.testing.expect(admission.acceptForTesting(address, 0));
    try std.testing.expect(!admission.acceptForTesting(address, 0));

    var permit = try admission.acquire(address, challengePacketBudget(1));
    defer permit.release(&admission);
    try std.testing.expect(admission.acceptForTesting(address, 1)); // exact retry probe
    try std.testing.expect(admission.acceptForTesting(address, 1)); // resulting HANDSHAKE
    try std.testing.expect(!admission.acceptForTesting(address, 1));
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

test "expected response IP bypasses an exhausted per-IP quota" {
    var admission = try IngressAdmission.init(std.testing.allocator, .{
        .global_quota = .{ .replenish_all_every_ms = 1_000, .max_tokens = 10 },
        .by_ip_quota = .{ .replenish_all_every_ms = 1_000, .max_tokens = 1 },
    }, 1);
    defer admission.deinit();
    const address: types.Address = .{ .ip4 = .{ .bytes = .{ 198, 51, 100, 1 }, .port = 9000 } };
    try std.testing.expect(admission.acceptForTesting(address, 0));
    try std.testing.expect(!admission.acceptForTesting(address, 0));
    var permit = try admission.acquire(.{ .ip4 = .{ .bytes = .{ 198, 51, 100, 1 }, .port = 9001 } }, 1);
    try std.testing.expect(admission.acceptForTesting(address, 1));
    permit.release(&admission);
    try std.testing.expect(!admission.acceptForTesting(address, 1));
}

test "expected admission is packet bounded and preserves unrelated peer progress" {
    var admission = try IngressAdmission.init(std.testing.allocator, .{
        .global_quota = .{ .replenish_all_every_ms = 1_000, .max_tokens = 16 },
        .by_ip_quota = .{ .replenish_all_every_ms = 1_000, .max_tokens = 1 },
    }, 2);
    defer admission.deinit();
    const first: types.Address = .{ .ip4 = .{ .bytes = .{ 198, 51, 100, 10 }, .port = 9000 } };
    const second: types.Address = .{ .ip4 = .{ .bytes = .{ 198, 51, 100, 11 }, .port = 9000 } };

    try std.testing.expect(admission.acceptForTesting(first, 0));
    try std.testing.expect(!admission.acceptForTesting(first, 0));
    try std.testing.expect(admission.acceptForTesting(second, 0));
    try std.testing.expect(!admission.acceptForTesting(second, 0));

    var first_permit = try admission.acquire(first, 1);
    defer first_permit.release(&admission);
    var second_permit = try admission.acquire(second, 1);
    defer second_permit.release(&admission);

    const expected = admission.acceptForTesting(first, 1);
    const unrelated_over_budget = admission.acceptForTesting(first, 1);
    const unrelated_peer_expected = admission.acceptForTesting(second, 1);
    try std.testing.expect(expected);
    try std.testing.expect(!unrelated_over_budget);
    try std.testing.expect(unrelated_peer_expected);
}

test "expected credit is reserved only when ordinary admission rejects" {
    var admission = try IngressAdmission.init(std.testing.allocator, .{
        .global_quota = .{ .replenish_all_every_ms = 1_000, .max_tokens = 2 },
        .by_ip_quota = .{ .replenish_all_every_ms = 1_000, .max_tokens = 1 },
    }, 1);
    defer admission.deinit();
    const address: types.Address = .{ .ip4 = .{ .bytes = .{ 198, 51, 100, 30 }, .port = 9000 } };
    var permit = try admission.acquire(address, 1);
    defer permit.release(&admission);

    const first = admission.admit(address, 0);
    switch (first) {
        .ordinary => {},
        .expected => |value| {
            var premature = value;
            premature.rollback(&admission);
            return error.ExpectedCreditConsumedBeforeQuotaExhaustion;
        },
        .filtered => return error.UnexpectedFilter,
    }
    const second = admission.admit(address, 0);
    var credit = switch (second) {
        .expected => |value| value,
        else => return error.ExpectedCreditConsumedBeforeQuotaExhaustion,
    };
    credit.rollback(&admission);
}

test "expected admission reservation is bounded and rollback restores credit" {
    var admission = try IngressAdmission.init(std.testing.allocator, .{
        .global_quota = .{ .replenish_all_every_ms = 1_000, .max_tokens = 10 },
        .by_ip_quota = .{ .replenish_all_every_ms = 1_000, .max_tokens = 1 },
    }, 1);
    defer admission.deinit();
    const address: types.Address = .{ .ip4 = .{ .bytes = .{ 198, 51, 100, 30 }, .port = 9000 } };
    try std.testing.expect(admission.acceptForTesting(address, 0));
    try std.testing.expect(!admission.acceptForTesting(address, 0));
    var permit = try admission.acquire(address, 1);
    defer permit.release(&admission);

    const first = admission.admit(address, 1);
    var credit = switch (first) {
        .expected => |value| value,
        else => return error.MissingExpectedCredit,
    };
    try std.testing.expect(admission.admit(address, 1) == .filtered);
    credit.rollback(&admission);

    const retried = admission.admit(address, 1);
    var committed = switch (retried) {
        .expected => |value| value,
        else => return error.MissingRestoredCredit,
    };
    try std.testing.expect(committed.commit(&admission, permit.handle()));
    try std.testing.expect(admission.admit(address, 1) == .filtered);
}

test "outstanding expected credit pins a released permit slot" {
    var admission = try IngressAdmission.init(std.testing.allocator, .{
        .global_quota = .{ .replenish_all_every_ms = 1_000, .max_tokens = 2 },
        .by_ip_quota = .{ .replenish_all_every_ms = 1_000, .max_tokens = 1 },
    }, 1);
    defer admission.deinit();
    const address: types.Address = .{ .ip4 = .{ .bytes = .{ 198, 51, 100, 31 }, .port = 9000 } };
    try std.testing.expect(admission.admit(address, 0) == .ordinary);
    var permit = try admission.acquire(address, 1);
    const admitted = admission.admit(address, 0);
    var credit = switch (admitted) {
        .expected => |value| value,
        else => return error.MissingExpectedCredit,
    };

    permit.release(&admission);
    if (admission.acquire(address, 1)) |unexpected| {
        var leaked = unexpected;
        leaked.release(&admission);
        credit.rollback(&admission);
        return error.ExpectedPinnedPermitSlot;
    } else |err| try std.testing.expectEqual(error.TooManyAdmissionPermits, err);
    credit.rollback(&admission);

    var replacement = try admission.acquire(address, 1);
    replacement.release(&admission);
}

const CONCURRENCY_WAIT_LIMIT: usize = 10_000_000;

fn waitForAtLeast(value: *const std.atomic.Value(u32), expected: u32) bool {
    for (0..CONCURRENCY_WAIT_LIMIT) |_| {
        if (value.load(.acquire) >= expected) return true;
        std.Thread.yield() catch std.atomic.spinLoopHint();
    }
    return false;
}

fn waitForContended(mutex: *const std.Io.Mutex) bool {
    for (0..CONCURRENCY_WAIT_LIMIT) |_| {
        if (mutex.state.load(.acquire) == .contended) return true;
        std.Thread.yield() catch std.atomic.spinLoopHint();
    }
    return false;
}

const HeldLockWaiter = struct {
    admission: *IngressAdmission,
    completed: std.atomic.Value(u32) = .init(0),

    fn run(self: *HeldLockWaiter) void {
        self.admission.noteProcessed();
        self.completed.store(1, .release);
    }
};

test "admission waiter progresses after explicitly held lock is released" {
    var admission = try IngressAdmission.init(std.testing.allocator, null, 1);
    defer admission.deinit();
    admission.lock();
    var lock_held = true;
    defer if (lock_held) admission.unlock();

    var waiter_state = HeldLockWaiter{ .admission = &admission };
    const waiter = try std.Thread.spawn(.{}, HeldLockWaiter.run, .{&waiter_state});
    var waiter_joined = false;
    defer if (!waiter_joined) {
        if (lock_held) {
            admission.unlock();
            lock_held = false;
        }
        waiter.join();
    };

    try std.testing.expect(waitForContended(&admission.mutex));
    try std.testing.expectEqual(@as(u32, 0), waiter_state.completed.load(.acquire));
    admission.unlock();
    lock_held = false;
    try std.testing.expect(waitForAtLeast(&waiter_state.completed, 1));
    waiter.join();
    waiter_joined = true;
    try std.testing.expectEqual(@as(u64, 1), admission.snapshot().processed_total);
}

const AdmissionStress = struct {
    const worker_count: u32 = 4;
    const iterations: u32 = 128;

    admission: *IngressAdmission,
    start: std.atomic.Value(bool) = .init(false),
    acquired: std.atomic.Value(u32) = .init(0),
    release_epoch: std.atomic.Value(u32) = .init(0),
    completed: std.atomic.Value(u32) = .init(0),
    occupied_slots: std.atomic.Value(u32) = .init(0),
    failed: std.atomic.Value(bool) = .init(false),

    fn address(worker: u8) types.Address {
        return .{ .ip4 = .{ .bytes = .{ 198, 51, 100, worker + 1 }, .port = 9_000 } };
    }

    fn run(self: *AdmissionStress, worker: u8) void {
        while (!self.start.load(.acquire)) std.Thread.yield() catch std.atomic.spinLoopHint();
        for (0..iterations) |iteration| {
            var permit = self.admission.acquire(address(worker), 1) catch {
                self.failed.store(true, .release);
                return;
            };
            const slot_bit = @as(u32, 1) << @intCast(permit.slot);
            if (self.occupied_slots.fetchOr(slot_bit, .acq_rel) & slot_bit != 0) self.failed.store(true, .release);
            _ = self.acquired.fetchAdd(1, .acq_rel);
            while (self.release_epoch.load(.acquire) <= iteration) std.Thread.yield() catch std.atomic.spinLoopHint();

            var credit = switch (self.admission.admit(address(worker), 0)) {
                .expected => |value| value,
                else => {
                    self.failed.store(true, .release);
                    permit.release(self.admission);
                    return;
                },
            };
            if (iteration % 2 == 0) {
                if (!credit.commit(self.admission, permit.handle())) self.failed.store(true, .release);
            } else credit.rollback(self.admission);
            self.admission.noteProcessed();
            if (self.occupied_slots.fetchAnd(~slot_bit, .acq_rel) & slot_bit == 0) self.failed.store(true, .release);
            permit.release(self.admission);
            _ = self.completed.fetchAdd(1, .acq_rel);
        }
    }
};

test "concurrent public admission methods conserve stats permits and expected credits" {
    var admission = try IngressAdmission.init(std.testing.allocator, .{
        .global_quota = .{ .replenish_all_every_ms = 1_000_000, .max_tokens = AdmissionStress.worker_count },
        .by_ip_quota = .{ .replenish_all_every_ms = 1_000_000, .max_tokens = 1 },
    }, AdmissionStress.worker_count);
    defer admission.deinit();
    for (0..AdmissionStress.worker_count) |worker| {
        try std.testing.expect(admission.admit(AdmissionStress.address(@intCast(worker)), 0) == .ordinary);
    }

    var stress = AdmissionStress{ .admission = &admission };
    var threads: [AdmissionStress.worker_count]std.Thread = undefined;
    var spawned: usize = 0;
    defer {
        stress.start.store(true, .release);
        stress.release_epoch.store(AdmissionStress.iterations, .release);
        for (threads[0..spawned]) |thread| thread.join();
    }
    for (&threads, 0..) |*thread, worker| {
        thread.* = try std.Thread.spawn(.{}, AdmissionStress.run, .{ &stress, @as(u8, @intCast(worker)) });
        spawned += 1;
    }
    stress.start.store(true, .release);

    for (0..AdmissionStress.iterations) |iteration| {
        try std.testing.expect(waitForAtLeast(&stress.acquired, AdmissionStress.worker_count));
        try std.testing.expectEqual(@as(usize, AdmissionStress.worker_count), admission.permitCount());
        try std.testing.expectEqual((@as(u32, 1) << @intCast(AdmissionStress.worker_count)) - 1, stress.occupied_slots.load(.acquire));
        stress.acquired.store(0, .release);
        stress.release_epoch.store(@intCast(iteration + 1), .release);
        try std.testing.expect(waitForAtLeast(&stress.completed, @intCast((iteration + 1) * AdmissionStress.worker_count)));
    }
    for (threads[0..spawned]) |thread| thread.join();
    spawned = 0;

    try std.testing.expect(!stress.failed.load(.acquire));
    try std.testing.expectEqual(@as(usize, 0), admission.permitCount());
    try std.testing.expectEqual(@as(u32, 0), stress.occupied_slots.load(.acquire));
    const before_probe = admission.snapshot();
    try std.testing.expectEqual(@as(u64, AdmissionStress.worker_count * (AdmissionStress.iterations + 1)), before_probe.received_total);
    try std.testing.expectEqual(@as(u64, AdmissionStress.worker_count * AdmissionStress.iterations), before_probe.processed_total);
    try std.testing.expectEqual(@as(u64, 0), before_probe.filtered_total);

    for (0..AdmissionStress.worker_count) |worker| {
        const address = AdmissionStress.address(@intCast(worker));
        var permit = try admission.acquire(address, 1);
        var credit = switch (admission.admit(address, 0)) {
            .expected => |value| value,
            else => return error.ExpectedCreditCorrupted,
        };
        try std.testing.expect(credit.commit(&admission, permit.handle()));
        permit.release(&admission);
        try std.testing.expect(admission.admit(address, 0) == .filtered);
    }
    const after_probe = admission.snapshot();
    try std.testing.expectEqual(@as(u64, AdmissionStress.worker_count * (AdmissionStress.iterations + 3)), after_probe.received_total);
    try std.testing.expectEqual(@as(u64, AdmissionStress.worker_count), after_probe.filtered_total);
    try std.testing.expectEqual(@as(usize, 0), admission.permitCount());
}
