const std = @import("std");
const util = @import("util.zig");
const Allocator = std.mem.Allocator;

pub const Error = Allocator.Error || error{
    CapacityTooLarge,
    ZeroCapacity,
};

pub fn LruCacheWithContext(comptime K: type, comptime V: type, comptime Context: type) type {
    return struct {
        map: std.HashMapUnmanaged(K, usize, Context, std.hash_map.default_max_load_percentage) = .empty,
        nodes: []Node,
        free_head: ?usize,
        head: ?usize = null,
        tail: ?usize = null,
        len: usize = 0,

        const Self = @This();

        pub const Entry = struct {
            key: K,
            value: V,
        };

        const Node = struct {
            key: K,
            value: V,
            expires_at_ns: i64,
            prev: ?usize = null,
            next: ?usize = null,
            free_next: ?usize = null,
        };

        pub fn init(alloc: Allocator, capacity_value: usize) Error!Self {
            if (capacity_value == 0) return error.ZeroCapacity;
            if (capacity_value > std.math.maxInt(u32)) return error.CapacityTooLarge;

            var map: std.HashMapUnmanaged(K, usize, Context, std.hash_map.default_max_load_percentage) = .empty;
            errdefer map.deinit(alloc);
            try map.ensureTotalCapacity(alloc, @intCast(capacity_value));

            const nodes = try alloc.alloc(Node, capacity_value);
            errdefer alloc.free(nodes);
            for (nodes, 0..) |*node, i| {
                node.free_next = if (i + 1 < nodes.len) i + 1 else null;
            }

            return .{
                .map = map,
                .nodes = nodes,
                .free_head = 0,
            };
        }

        pub fn deinit(self: *Self, alloc: Allocator) void {
            self.map.deinit(alloc);
            alloc.free(self.nodes);
            self.* = undefined;
        }

        pub fn count(self: *const Self) usize {
            return self.len;
        }

        pub fn capacity(self: *const Self) usize {
            return self.nodes.len;
        }

        pub const Testing = if (@import("builtin").is_test) struct {
            pub fn nodeSize() usize {
                return @sizeOf(Node);
            }

            pub fn nodeBackingBytes(self: *const Self) usize {
                return self.nodes.len * @sizeOf(Node);
            }

            pub fn mapCapacity(self: *const Self) usize {
                return self.map.capacity();
            }
        } else struct {};

        /// Test whether storage contains a key without changing TTL or recency.
        pub fn contains(self: *const Self, key: K) bool {
            return self.map.contains(key);
        }

        pub fn get(self: *Self, key: K, now_ns: i64) ?V {
            const index = self.map.get(key) orelse return null;
            if (self.isExpired(index, now_ns)) {
                self.removeIndex(index);
                return null;
            }
            self.moveToFront(index);
            return self.nodes[index].value;
        }

        /// Return and promote a live value without removing expired state.
        pub fn getPromote(self: *Self, key: K, now_ns: i64) ?V {
            const index = self.map.get(key) orelse return null;
            if (self.isExpired(index, now_ns)) return null;
            self.moveToFront(index);
            return self.nodes[index].value;
        }

        /// Read a live value without changing recency or removing expired state.
        pub fn peek(self: *const Self, key: K, now_ns: i64) ?V {
            const index = self.map.get(key) orelse return null;
            if (self.isExpired(index, now_ns)) return null;
            return self.nodes[index].value;
        }

        pub fn peekPtr(self: *const Self, key: K, now_ns: i64) ?*const V {
            const index = self.map.get(key) orelse return null;
            if (self.isExpired(index, now_ns)) return null;
            return &self.nodes[index].value;
        }

        /// Read a value without applying TTL policy. Exact terminal cleanup uses
        /// this only to compare ownership before removing an already-matched entry.
        pub fn peekPtrRaw(self: *const Self, key: K) ?*const V {
            const index = self.map.get(key) orelse return null;
            return &self.nodes[index].value;
        }

        /// Mutate a value without applying TTL or recency policy. Callers must
        /// preserve the key and ownership invariants encoded by the cache.
        pub fn getPtrRaw(self: *Self, key: K) ?*V {
            const index = self.map.get(key) orelse return null;
            return &self.nodes[index].value;
        }

        /// Promote an existing value without applying TTL policy.
        pub fn promoteRaw(self: *Self, key: K) bool {
            const index = self.map.get(key) orelse return false;
            self.moveToFront(index);
            return true;
        }

        pub fn isKeyExpired(self: *const Self, key: K, now_ns: i64) bool {
            const index = self.map.get(key) orelse return false;
            return self.isExpired(index, now_ns);
        }

        pub fn getRefreshPtr(self: *Self, key: K, ttl_ms: u64, now_ns: i64) ?*V {
            const index = self.map.get(key) orelse return null;
            if (self.isExpired(index, now_ns)) {
                self.removeIndex(index);
                return null;
            }
            self.nodes[index].expires_at_ns = util.deadlineNs(now_ns, ttl_ms);
            self.moveToFront(index);
            return &self.nodes[index].value;
        }

        pub fn put(self: *Self, key: K, value: V, ttl_ms: u64, now_ns: i64) void {
            _ = self.putMove(key, value, ttl_ms, now_ns);
        }

        /// At full capacity, reuse an expired entry before evicting the LRU.
        pub fn putReplacingExpired(self: *Self, key: K, value: V, ttl_ms: u64, now_ns: i64) void {
            _ = self.putMoveWithPolicy(key, value, ttl_ms, now_ns, true);
        }

        /// Moves `value` into the cache and returns ownership of a replaced or
        /// evicted entry. Callers storing owned resources must use this API.
        pub fn putMove(self: *Self, key: K, value: V, ttl_ms: u64, now_ns: i64) ?Entry {
            return self.putMoveWithPolicy(key, value, ttl_ms, now_ns, false);
        }

        fn putMoveWithPolicy(
            self: *Self,
            key: K,
            value: V,
            ttl_ms: u64,
            now_ns: i64,
            replace_expired: bool,
        ) ?Entry {
            if (self.map.get(key)) |index| {
                const node = &self.nodes[index];
                const removed = Entry{ .key = node.key, .value = node.value };
                node.key = key;
                node.value = value;
                node.expires_at_ns = util.deadlineNs(now_ns, ttl_ms);
                self.moveToFront(index);
                return removed;
            }

            var removed: ?Entry = null;
            const index = self.free_head orelse blk: {
                const evicted_index = if (replace_expired)
                    self.findExpired(now_ns) orelse self.tail.?
                else
                    self.tail.?;
                removed = .{ .key = self.nodes[evicted_index].key, .value = self.nodes[evicted_index].value };
                self.evictForReuse(evicted_index);
                break :blk evicted_index;
            };
            self.free_head = self.nodes[index].free_next;
            self.nodes[index] = .{
                .key = key,
                .value = value,
                .expires_at_ns = util.deadlineNs(now_ns, ttl_ms),
            };
            self.linkFront(index);
            self.map.putAssumeCapacityNoClobber(key, index);
            self.len += 1;
            return removed;
        }

        pub fn remove(self: *Self, key: K) bool {
            return self.takeMove(key) != null;
        }

        pub fn takeMove(self: *Self, key: K) ?V {
            const removed = self.map.fetchRemove(key) orelse return null;
            const value = self.nodes[removed.value].value;
            self.unlink(removed.value);
            self.releaseNode(removed.value);
            self.len -= 1;
            return value;
        }

        pub fn takeExpiredMove(self: *Self, key: K, now_ns: i64) ?V {
            const index = self.map.get(key) orelse return null;
            if (!self.isExpired(index, now_ns)) return null;
            return self.takeMove(key).?;
        }

        pub fn popLruMove(self: *Self) ?Entry {
            const index = self.tail orelse return null;
            const entry = Entry{ .key = self.nodes[index].key, .value = self.nodes[index].value };
            self.removeIndex(index);
            return entry;
        }

        pub fn popExpiredLruMove(self: *Self, now_ns: i64) ?Entry {
            const index = self.tail orelse return null;
            if (!self.isExpired(index, now_ns)) return null;
            return self.popLruMove();
        }

        /// Remove the least-recent value accepted by `predicate`. The scan is
        /// bounded by physical cache capacity.
        pub fn popLruWhereMove(self: *Self, predicate: anytype) ?Entry {
            var current = self.tail;
            var scanned: usize = 0;
            while (current != null and scanned < self.nodes.len) : (scanned += 1) {
                const index = current.?;
                if (predicate.accepts(&self.nodes[index].value)) {
                    const entry = Entry{ .key = self.nodes[index].key, .value = self.nodes[index].value };
                    self.removeIndex(index);
                    return entry;
                }
                current = self.nodes[index].prev;
            }
            std.debug.assert(current == null);
            return null;
        }

        /// Remove the least-recent expired value accepted by `predicate`.
        /// The scan is bounded by physical cache capacity.
        pub fn popExpiredLruWhereMove(self: *Self, now_ns: i64, predicate: anytype) ?Entry {
            var current = self.tail;
            var scanned: usize = 0;
            while (current != null and scanned < self.nodes.len) : (scanned += 1) {
                const index = current.?;
                if (self.isExpired(index, now_ns) and predicate.accepts(&self.nodes[index].value)) {
                    const entry = Entry{ .key = self.nodes[index].key, .value = self.nodes[index].value };
                    self.removeIndex(index);
                    return entry;
                }
                current = self.nodes[index].prev;
            }
            std.debug.assert(current == null);
            return null;
        }

        pub fn hasExpiredWhere(self: *const Self, now_ns: i64, predicate: anytype) bool {
            var current = self.tail;
            var scanned: usize = 0;
            while (current != null and scanned < self.nodes.len) : (scanned += 1) {
                const index = current.?;
                if (self.isExpired(index, now_ns) and predicate.accepts(&self.nodes[index].value)) return true;
                current = self.nodes[index].prev;
            }
            std.debug.assert(current == null);
            return false;
        }

        pub fn pruneExpired(self: *Self, now_ns: i64) void {
            var current = self.head;
            while (current) |index| {
                const next = self.nodes[index].next;
                if (self.isExpired(index, now_ns)) self.removeIndex(index);
                current = next;
            }
        }

        fn isExpired(self: *const Self, index: usize, now_ns: i64) bool {
            return now_ns >= self.nodes[index].expires_at_ns;
        }

        fn removeIndex(self: *Self, index: usize) void {
            std.debug.assert(self.map.remove(self.nodes[index].key));
            self.unlink(index);
            self.releaseNode(index);
            self.len -= 1;
        }

        fn evictForReuse(self: *Self, index: usize) void {
            std.debug.assert(self.map.remove(self.nodes[index].key));
            self.unlink(index);
            self.len -= 1;
        }

        fn findExpired(self: *const Self, now_ns: i64) ?usize {
            var current = self.tail;
            var scanned: usize = 0;
            while (current != null and scanned < self.nodes.len) : (scanned += 1) {
                const index = current.?;
                if (self.isExpired(index, now_ns)) return index;
                current = self.nodes[index].prev;
            }
            std.debug.assert(current == null);
            return null;
        }

        fn releaseNode(self: *Self, index: usize) void {
            self.nodes[index].free_next = self.free_head;
            self.nodes[index].prev = null;
            self.nodes[index].next = null;
            self.free_head = index;
        }

        fn moveToFront(self: *Self, index: usize) void {
            if (self.head == index) return;
            self.unlink(index);
            self.linkFront(index);
        }

        fn linkFront(self: *Self, index: usize) void {
            self.nodes[index].prev = null;
            self.nodes[index].next = self.head;
            if (self.head) |old_head| {
                self.nodes[old_head].prev = index;
            } else {
                self.tail = index;
            }
            self.head = index;
        }

        fn unlink(self: *Self, index: usize) void {
            const prev = self.nodes[index].prev;
            const next = self.nodes[index].next;

            if (prev) |prev_index| {
                self.nodes[prev_index].next = next;
            } else {
                self.head = next;
            }

            if (next) |next_index| {
                self.nodes[next_index].prev = prev;
            } else {
                self.tail = prev;
            }

            self.nodes[index].prev = null;
            self.nodes[index].next = null;
        }

        fn assertInvariants(self: *const Self) void {
            std.debug.assert(self.len == self.map.count());
            std.debug.assert((self.len == 0) == (self.head == null));
            std.debug.assert((self.len == 0) == (self.tail == null));
            if (self.head) |head| std.debug.assert(self.nodes[head].prev == null);
            if (self.tail) |tail| std.debug.assert(self.nodes[tail].next == null);

            var live_count: usize = 0;
            var previous: ?usize = null;
            var current = self.head;
            while (current) |index| {
                std.debug.assert(index < self.nodes.len);
                std.debug.assert(self.nodes[index].prev == previous);
                std.debug.assert(self.map.get(self.nodes[index].key).? == index);
                previous = index;
                current = self.nodes[index].next;
                live_count += 1;
                std.debug.assert(live_count <= self.nodes.len);
            }
            std.debug.assert(live_count == self.len);
            std.debug.assert(previous == self.tail);

            var free_count: usize = 0;
            current = self.free_head;
            while (current) |index| {
                std.debug.assert(index < self.nodes.len);
                current = self.nodes[index].free_next;
                free_count += 1;
                std.debug.assert(free_count <= self.nodes.len);
            }
            std.debug.assert(live_count + free_count == self.nodes.len);
        }

        fn expectOrder(self: *const Self, expected: []const K) !void {
            try std.testing.expectEqual(expected.len, self.len);
            var current = self.head;
            for (expected) |key| {
                const index = current orelse return error.MissingLruNode;
                try std.testing.expectEqual(key, self.nodes[index].key);
                current = self.nodes[index].next;
            }
            try std.testing.expect(current == null);
        }
    };
}

pub fn LruCache(comptime K: type, comptime V: type) type {
    return LruCacheWithContext(K, V, std.hash_map.AutoContext(K));
}

test "lru rejects zero capacity" {
    const Cache = LruCache(u8, u8);
    try std.testing.expectError(error.ZeroCapacity, Cache.init(std.testing.allocator, 0));
}

test "lru get promotes and put evicts least recently used" {
    const Cache = LruCache(u8, u64);
    var cache = try Cache.init(std.testing.allocator, 2);
    defer cache.deinit(std.testing.allocator);

    cache.put(1, 10, 100, 0);
    cache.put(2, 20, 100, 0);
    cache.assertInvariants();
    try cache.expectOrder(&.{ 2, 1 });

    try std.testing.expectEqual(@as(?u64, 10), cache.get(1, 1));
    cache.assertInvariants();
    try cache.expectOrder(&.{ 1, 2 });

    cache.put(3, 30, 100, 2);
    cache.assertInvariants();
    try cache.expectOrder(&.{ 3, 1 });
    try std.testing.expectEqual(@as(?u64, null), cache.get(2, 3));
    try std.testing.expectEqual(@as(?u64, 10), cache.get(1, 3));
    try std.testing.expectEqual(@as(?u64, 30), cache.get(3, 3));
}

test "lru getPromote promotes live values without refreshing or removing expired state" {
    const Cache = LruCache(u8, u64);
    var cache = try Cache.init(std.testing.allocator, 2);
    defer cache.deinit(std.testing.allocator);

    cache.put(1, 10, 10, 0);
    cache.put(2, 20, 20, 0);
    try cache.expectOrder(&.{ 2, 1 });

    try std.testing.expectEqual(@as(?u64, 10), cache.getPromote(1, 5 * std.time.ns_per_ms));
    try cache.expectOrder(&.{ 1, 2 });
    try std.testing.expectEqual(@as(?u64, null), cache.getPromote(1, 10 * std.time.ns_per_ms));
    try std.testing.expectEqual(@as(usize, 2), cache.count());
    try cache.expectOrder(&.{ 1, 2 });

    cache.pruneExpired(10 * std.time.ns_per_ms);
    try std.testing.expectEqual(@as(usize, 1), cache.count());
    try cache.expectOrder(&.{2});
}

test "lru replacing a key updates value ttl and recency without growing" {
    const Cache = LruCache(u8, u64);
    var cache = try Cache.init(std.testing.allocator, 2);
    defer cache.deinit(std.testing.allocator);

    cache.put(1, 10, 1, 0);
    cache.put(2, 20, 100, 0);
    cache.put(1, 11, 100, 1);
    cache.assertInvariants();

    try std.testing.expectEqual(@as(usize, 2), cache.count());
    try cache.expectOrder(&.{ 1, 2 });
    try std.testing.expectEqual(@as(?u64, 11), cache.get(1, 2 * std.time.ns_per_ms));
}

test "lru expired entries are removed by get and prune" {
    const Cache = LruCache(u8, u64);
    var cache = try Cache.init(std.testing.allocator, 3);
    defer cache.deinit(std.testing.allocator);

    cache.put(1, 10, 1, 0);
    cache.put(2, 20, 10, 0);
    cache.put(3, 30, 1, 0);
    cache.assertInvariants();

    try std.testing.expectEqual(@as(?u64, null), cache.get(1, std.time.ns_per_ms));
    cache.assertInvariants();
    try cache.expectOrder(&.{ 3, 2 });

    cache.pruneExpired(std.time.ns_per_ms);
    cache.assertInvariants();
    try cache.expectOrder(&.{2});
}

test "lru predicate helpers preserve bounds order and rejected entries" {
    const Value = struct { live: bool, byte: u8 };
    const Live = struct {
        fn accepts(_: @This(), value: *const Value) bool {
            return value.live;
        }
    };
    const Cache = LruCache(u8, Value);
    var cache = try Cache.init(std.testing.allocator, 3);
    defer cache.deinit(std.testing.allocator);

    cache.put(1, .{ .live = true, .byte = 1 }, 1, 0);
    cache.put(2, .{ .live = false, .byte = 2 }, 1, 0);
    cache.put(3, .{ .live = true, .byte = 3 }, 100, 0);
    try cache.expectOrder(&.{ 3, 2, 1 });
    try std.testing.expect(cache.hasExpiredWhere(std.time.ns_per_ms, Live{}));
    const expired = cache.popExpiredLruWhereMove(std.time.ns_per_ms, Live{}) orelse return error.MissingExpiredLive;
    try std.testing.expectEqual(@as(u8, 1), expired.key);
    try cache.expectOrder(&.{ 3, 2 });
    try std.testing.expect(cache.contains(2));
    try std.testing.expect(cache.promoteRaw(2));
    try cache.expectOrder(&.{ 2, 3 });
    const live = cache.popLruWhereMove(Live{}) orelse return error.MissingLive;
    try std.testing.expectEqual(@as(u8, 3), live.key);
    try cache.expectOrder(&.{2});
    cache.assertInvariants();
}

test "lru remove unlinks map and recency list" {
    const Cache = LruCache(u8, u64);
    var cache = try Cache.init(std.testing.allocator, 3);
    defer cache.deinit(std.testing.allocator);

    cache.put(1, 10, 100, 0);
    cache.put(2, 20, 100, 0);
    cache.put(3, 30, 100, 0);

    try std.testing.expect(cache.remove(2));
    try std.testing.expect(!cache.remove(2));
    cache.assertInvariants();
    try cache.expectOrder(&.{ 3, 1 });

    cache.put(4, 40, 100, 0);
    cache.assertInvariants();
    try cache.expectOrder(&.{ 4, 3, 1 });
}
