const std = @import("std");
const types = @import("types.zig");

const Allocator = std.mem.Allocator;

pub const Contact = struct {
    pubkey: [33]u8,
    addr: types.Address,
    explicitly_trusted: bool,
};

/// Bounded fallback directory for peers whose identity and address are known
/// but whose ENR has not earned a routing-table entry.
pub const ContactBook = struct {
    contacts: std.AutoHashMap(types.NodeId, Contact),
    local_node_id: types.NodeId,
    capacity: usize,

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
        if (std.mem.eql(u8, &node_id, &self.local_node_id)) return;
        const key = pubkey orelse return;
        if (self.contacts.get(node_id)) |existing| {
            if (existing.explicitly_trusted and !explicitly_trusted) return;
        }
        if (!self.contacts.contains(node_id) and self.contacts.count() >= self.capacity) return;
        self.contacts.putAssumeCapacity(node_id, .{
            .pubkey = key.*,
            .addr = addr,
            .explicitly_trusted = explicitly_trusted,
        });
    }

    pub fn forget(self: *ContactBook, node_id: types.NodeId) void {
        _ = self.contacts.remove(node_id);
    }

    pub fn count(self: *const ContactBook) usize {
        return self.contacts.count();
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
    try std.testing.expect(book.get([_]u8{3} ** 32) == null);
    book.remember([_]u8{1} ** 32, &pubkey, addr_b, false);
    try std.testing.expect(book.get([_]u8{1} ** 32).?.addr.eql(&addr_b));
}
