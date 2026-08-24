const std = @import("std");
const types = @import("types.zig");

const Allocator = std.mem.Allocator;

pub const Contact = struct {
    pubkey: [33]u8,
    addr: types.Address,
    explicitly_trusted: bool,
};

pub const ContactMetricsSnapshot = struct {
    count: usize,
    capacity: usize,
    inserted_total: u64,
    updated_total: u64,
    replaced_total: u64,
    capacity_rejected_total: u64,
    policy_rejected_total: u64,
    removed_total: u64,
};

/// Bounded fallback directory for peers whose identity and address are known
/// but whose ENR has not earned a routing-table entry.
pub const ContactBook = struct {
    contacts: std.AutoHashMap(types.NodeId, Contact),
    local_node_id: types.NodeId,
    capacity: usize,
    inserted_total: u64 = 0,
    updated_total: u64 = 0,
    replaced_total: u64 = 0,
    capacity_rejected_total: u64 = 0,
    policy_rejected_total: u64 = 0,
    removed_total: u64 = 0,

    pub fn init(alloc: Allocator, local_node_id: types.NodeId, capacity: usize) !ContactBook {
        if (capacity == 0 or capacity > std.math.maxInt(u32)) return error.InvalidContactCapacity;
        var contacts = std.AutoHashMap(types.NodeId, Contact).init(alloc);
        errdefer contacts.deinit();
        try contacts.ensureTotalCapacity(@intCast(capacity));
        return .{ .contacts = contacts, .local_node_id = local_node_id, .capacity = capacity };
    }

    pub fn deinit(self: *ContactBook) void {
        self.contacts.deinit();
    }

    pub fn get(self: *const ContactBook, node_id: types.NodeId) ?Contact {
        return self.contacts.get(node_id);
    }

    pub fn remember(self: *ContactBook, node_id: types.NodeId, pubkey: ?*const [33]u8, addr: types.Address, explicitly_trusted: bool) void {
        if (std.mem.eql(u8, &node_id, &self.local_node_id)) {
            self.policy_rejected_total +|= 1;
            return;
        }
        const key = pubkey orelse {
            self.policy_rejected_total +|= 1;
            return;
        };
        const existing = self.contacts.get(node_id);
        if (existing) |value| {
            if (value.explicitly_trusted and !explicitly_trusted) {
                self.policy_rejected_total +|= 1;
                return;
            }
        }
        if (existing == null and self.contacts.count() >= self.capacity) {
            var iterator = self.contacts.iterator();
            while (iterator.next()) |entry| {
                if (entry.value_ptr.explicitly_trusted) continue;
                std.debug.assert(self.contacts.remove(entry.key_ptr.*));
                self.replaced_total +|= 1;
                break;
            } else {
                self.capacity_rejected_total +|= 1;
                return;
            }
        }
        self.contacts.putAssumeCapacity(node_id, .{
            .pubkey = key.*,
            .addr = addr,
            .explicitly_trusted = explicitly_trusted,
        });
        if (existing == null) {
            self.inserted_total +|= 1;
        } else {
            self.updated_total +|= 1;
        }
    }

    pub fn forget(self: *ContactBook, node_id: types.NodeId) void {
        if (self.contacts.remove(node_id)) self.removed_total +|= 1;
    }

    pub fn count(self: *const ContactBook) usize {
        return self.contacts.count();
    }

    pub fn metricsSnapshot(self: *const ContactBook) ContactMetricsSnapshot {
        return .{
            .count = self.contacts.count(),
            .capacity = self.capacity,
            .inserted_total = self.inserted_total,
            .updated_total = self.updated_total,
            .replaced_total = self.replaced_total,
            .capacity_rejected_total = self.capacity_rejected_total,
            .policy_rejected_total = self.policy_rejected_total,
            .removed_total = self.removed_total,
        };
    }
};

test "contact book bounds distinct peers while allowing updates" {
    var book = try ContactBook.init(std.testing.allocator, [_]u8{0} ** 32, 2);
    defer book.deinit();
    const pubkey = [_]u8{2} ** 33;
    const addr_a: types.Address = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 9000 } };
    const addr_b: types.Address = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 9001 } };
    book.remember([_]u8{1} ** 32, &pubkey, addr_a, false);
    book.remember([_]u8{2} ** 32, &pubkey, addr_a, false);
    book.remember([_]u8{3} ** 32, &pubkey, addr_a, false);
    try std.testing.expectEqual(@as(usize, 2), book.count());
    try std.testing.expect(book.get([_]u8{3} ** 32) != null);
    try std.testing.expect(book.get([_]u8{1} ** 32) == null or book.get([_]u8{2} ** 32) == null);
    book.remember([_]u8{1} ** 32, &pubkey, addr_b, false);
    try std.testing.expect(book.get([_]u8{1} ** 32).?.addr.eql(&addr_b));
}

test "trusted contacts displace only untrusted contacts at capacity" {
    var book = try ContactBook.init(std.testing.allocator, [_]u8{0} ** 32, 2);
    defer book.deinit();
    const pubkey = [_]u8{2} ** 33;
    const address: types.Address = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 9000 } };
    const trusted = [_]u8{1} ** 32;
    const untrusted = [_]u8{2} ** 32;
    const trusted_replacement = [_]u8{3} ** 32;
    const rejected_untrusted = [_]u8{4} ** 32;
    const rejected_trusted = [_]u8{5} ** 32;

    book.remember(trusted, &pubkey, address, true);
    book.remember(untrusted, &pubkey, address, false);
    book.remember(trusted_replacement, &pubkey, address, true);
    try std.testing.expect(book.get(trusted) != null);
    try std.testing.expect(book.get(untrusted) == null);
    try std.testing.expect(book.get(trusted_replacement).?.explicitly_trusted);

    book.remember(rejected_untrusted, &pubkey, address, false);
    book.remember(rejected_trusted, &pubkey, address, true);
    try std.testing.expect(book.get(rejected_untrusted) == null);
    try std.testing.expect(book.get(rejected_trusted) == null);
    try std.testing.expect(book.get(trusted).?.explicitly_trusted);
    try std.testing.expect(book.get(trusted_replacement).?.explicitly_trusted);
    try std.testing.expectEqual(@as(usize, 2), book.count());
    const snapshot = book.metricsSnapshot();
    try std.testing.expectEqual(@as(u64, 1), snapshot.replaced_total);
    try std.testing.expectEqual(@as(u64, 2), snapshot.capacity_rejected_total);
}

test "contact metrics count retention decisions exactly without mutating state" {
    const local_id = [_]u8{0} ** 32;
    var book = try ContactBook.init(std.testing.allocator, local_id, 2);
    defer book.deinit();
    const pubkey = [_]u8{2} ** 33;
    const addr_a: types.Address = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 9000 } };
    const addr_b: types.Address = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 9001 } };
    const first = [_]u8{1} ** 32;
    const protected = [_]u8{2} ** 32;
    const rejected = [_]u8{3} ** 32;

    book.remember(local_id, &pubkey, addr_a, false);
    book.remember(first, null, addr_a, false);
    book.remember(first, &pubkey, addr_a, false);
    book.remember(protected, &pubkey, addr_a, true);
    book.remember(first, &pubkey, addr_b, false);
    book.remember(protected, &pubkey, addr_b, false);
    book.remember(rejected, &pubkey, addr_a, false);
    book.forget(rejected);
    book.forget(first);

    const inspection: *const ContactBook = &book;
    const first_snapshot = inspection.metricsSnapshot();
    const second_snapshot = inspection.metricsSnapshot();
    try std.testing.expectEqual(first_snapshot, second_snapshot);
    try std.testing.expectEqual(@as(usize, 1), first_snapshot.count);
    try std.testing.expectEqual(@as(usize, 2), first_snapshot.capacity);
    try std.testing.expectEqual(@as(u64, 3), first_snapshot.inserted_total);
    try std.testing.expectEqual(@as(u64, 1), first_snapshot.updated_total);
    try std.testing.expectEqual(@as(u64, 1), first_snapshot.replaced_total);
    try std.testing.expectEqual(@as(u64, 0), first_snapshot.capacity_rejected_total);
    try std.testing.expectEqual(@as(u64, 3), first_snapshot.policy_rejected_total);
    try std.testing.expectEqual(@as(u64, 1), first_snapshot.removed_total);
    try std.testing.expect(book.get(protected) != null);
    try std.testing.expect(book.get(protected).?.explicitly_trusted);
    try std.testing.expect(book.get(protected).?.addr.eql(&addr_a));
    try std.testing.expect(book.get(first) == null);
    try std.testing.expect(book.get(rejected) == null);
}
