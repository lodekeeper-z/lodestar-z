//! TS-compatible discv5 packet rate limiter.

const std = @import("std");
const Allocator = std.mem.Allocator;

const lru = @import("lru.zig");
const Address = std.Io.net.IpAddress;
pub const MAX_SOURCE_STATE: usize = 4_096;

pub const RateLimiterQuota = struct {
    /// How often `max_tokens` fully replenish, in milliseconds.
    replenish_all_every_ms: u64,
    /// Instantaneous burst token limit.
    max_tokens: u32,
};

pub const Config = struct {
    global_quota: RateLimiterQuota,
    by_ip_quota: RateLimiterQuota,
    /// State keyed by packet source IP is attacker-controlled, so keep it
    /// bounded even when a peer sprays many spoofed or rotating addresses.
    by_ip_state_capacity: usize = 4096,
};

pub const Stats = struct {
    rate_limit_hit_ip_total: u64 = 0,
    rate_limit_hit_total: u64 = 0,
};

pub const IpKey = struct {
    family: Address.Family,
    bytes: [16]u8,

    pub fn fromAddress(addr: Address) IpKey {
        const normalized = switch (addr) {
            .ip4 => addr,
            .ip6 => |ip6| Address.fromIp6(ip6),
        };
        return switch (normalized) {
            .ip4 => |ip4| blk: {
                var bytes = [_]u8{0} ** 16;
                @memcpy(bytes[0..4], &ip4.bytes);
                break :blk .{ .family = .ip4, .bytes = bytes };
            },
            .ip6 => |ip6| .{ .family = .ip6, .bytes = ip6.bytes },
        };
    }
};

pub fn RateLimiterGcra(comptime Key: type) type {
    return struct {
        const Self = @This();

        const Commit = struct {
            key: Key,
            tat_ms: f64,
            now_ns: i64,
        };

        allocator: Allocator,
        tat_per_key: lru.LruCache(Key, f64),
        tau_ms: f64,
        token_interval_ms: f64,
        ttl_ms: u64,

        pub fn fromQuota(allocator: Allocator, quota: RateLimiterQuota, capacity: usize) !Self {
            if (quota.max_tokens == 0) return error.InvalidRateLimiterQuota;
            if (quota.replenish_all_every_ms == 0) return error.InvalidRateLimiterQuota;
            const tau_ms: f64 = @floatFromInt(quota.replenish_all_every_ms);
            const max_tokens: f64 = @floatFromInt(quota.max_tokens);
            return .{
                .allocator = allocator,
                .tat_per_key = try lru.LruCache(Key, f64).init(allocator, capacity),
                .tau_ms = tau_ms,
                .token_interval_ms = tau_ms / max_tokens,
                .ttl_ms = quota.replenish_all_every_ms,
            };
        }

        pub fn deinit(self: *Self) void {
            self.tat_per_key.deinit(self.allocator);
        }

        /// Compute an admission without changing quota, TTL, or LRU recency.
        /// The caller must serialize preview/commit ownership so another
        /// admission cannot invalidate the preview before it is committed.
        fn preview(self: *const Self, key: Key, tokens: u32, ms_since_start: u64) ?Commit {
            const additional_time = self.token_interval_ms * @as(f64, @floatFromInt(tokens));
            if (additional_time > self.tau_ms) return null;

            const now: f64 = @floatFromInt(ms_since_start);
            const now_ns = timestampMsToNs(ms_since_start);
            const tat = self.tat_per_key.peek(key, now_ns) orelse now;

            const earliest_time = tat + additional_time - self.tau_ms;
            if (now < earliest_time) return null;

            return .{
                .key = key,
                .tat_ms = @max(now, tat) + additional_time,
                .now_ns = now_ns,
            };
        }

        fn commit(self: *Self, admission: Commit) void {
            self.tat_per_key.put(admission.key, admission.tat_ms, self.ttl_ms, admission.now_ns);
        }

        pub fn allows(self: *Self, key: Key, tokens: u32, ms_since_start: u64) bool {
            const additional_time = self.token_interval_ms * @as(f64, @floatFromInt(tokens));
            if (additional_time > self.tau_ms) return false;

            const now: f64 = @floatFromInt(ms_since_start);
            const now_ns = timestampMsToNs(ms_since_start);
            const tat = self.tat_per_key.get(key, now_ns) orelse now;

            const earliest_time = tat + additional_time - self.tau_ms;
            if (now < earliest_time) return false;

            self.tat_per_key.put(key, @max(now, tat) + additional_time, self.ttl_ms, now_ns);
            return true;
        }

        pub fn prune(self: *Self, now_ms: u64) void {
            self.tat_per_key.pruneExpired(timestampMsToNs(now_ms));
        }
    };
}

pub const RateLimiter = struct {
    global: RateLimiterGcra(u8),
    by_ip: RateLimiterGcra(IpKey),
    stats: Stats = .{},

    pub fn init(allocator: Allocator, config: Config) !RateLimiter {
        if (config.by_ip_state_capacity == 0 or config.by_ip_state_capacity > MAX_SOURCE_STATE)
            return error.InvalidRateLimiterCapacity;
        var global = try RateLimiterGcra(u8).fromQuota(allocator, config.global_quota, 1);
        errdefer global.deinit();

        var by_ip = try RateLimiterGcra(IpKey).fromQuota(allocator, config.by_ip_quota, config.by_ip_state_capacity);
        errdefer by_ip.deinit();

        return .{
            .global = global,
            .by_ip = by_ip,
        };
    }

    pub fn deinit(self: *RateLimiter) void {
        self.global.deinit();
        self.by_ip.deinit();
    }

    pub fn allowEncodedPacket(self: *RateLimiter, addr: Address, now_ms: u64) bool {
        const ip = IpKey.fromAddress(addr);
        const by_ip_admission = self.by_ip.preview(ip, 1, now_ms) orelse {
            self.stats.rate_limit_hit_ip_total +|= 1;
            return false;
        };

        const global_admission = self.global.preview(0, 1, now_ms) orelse {
            self.stats.rate_limit_hit_total +|= 1;
            return false;
        };

        // Preserve per-IP-before-global commit order.
        self.by_ip.commit(by_ip_admission);
        self.global.commit(global_admission);
        return true;
    }

    pub fn statsSnapshot(self: *const RateLimiter) Stats {
        return self.stats;
    }
};

fn timestampMsToNs(ms: u64) i64 {
    const ns = @as(i128, ms) * std.time.ns_per_ms;
    return if (ns > std.math.maxInt(i64)) std.math.maxInt(i64) else @intCast(ns);
}

test "GCRA allows burst then replenishes over time" {
    var limiter = try RateLimiterGcra(IpKey).fromQuota(std.testing.allocator, .{
        .replenish_all_every_ms = 1_000,
        .max_tokens = 2,
    }, 16);
    defer limiter.deinit();

    const ip = IpKey.fromAddress(.{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 9000 } });
    try std.testing.expect(limiter.allows(ip, 1, 0));
    try std.testing.expect(limiter.allows(ip, 1, 0));
    try std.testing.expect(!limiter.allows(ip, 1, 0));
    try std.testing.expect(limiter.allows(ip, 1, 500));
}

test "standalone GCRA rejected live lookup promotes recency" {
    var limiter = try RateLimiterGcra(u8).fromQuota(std.testing.allocator, .{
        .replenish_all_every_ms = 1_000,
        .max_tokens = 1,
    }, 2);
    defer limiter.deinit();

    try std.testing.expect(limiter.allows(1, 1, 0));
    try std.testing.expect(limiter.allows(2, 1, 0));
    try std.testing.expect(!limiter.allows(1, 1, 0));
    try std.testing.expect(limiter.allows(3, 1, 0));

    try std.testing.expect(limiter.tat_per_key.contains(1));
    try std.testing.expect(!limiter.tat_per_key.contains(2));
    try std.testing.expect(limiter.tat_per_key.contains(3));
}

test "standalone GCRA expired lookup is replaced and charged once" {
    var limiter = try RateLimiterGcra(u8).fromQuota(std.testing.allocator, .{
        .replenish_all_every_ms = 1_000,
        .max_tokens = 2,
    }, 1);
    defer limiter.deinit();

    try std.testing.expect(limiter.allows(1, 1, 0));
    try std.testing.expect(limiter.allows(1, 1, 1_000));
    try std.testing.expect(limiter.allows(1, 1, 1_000));
    try std.testing.expect(!limiter.allows(1, 1, 1_000));
    try std.testing.expectEqual(@as(usize, 1), limiter.tat_per_key.count());
}

test "per-IP quota hit does not create a punitive ban" {
    var limiter = try RateLimiter.init(std.testing.allocator, .{
        .global_quota = .{ .replenish_all_every_ms = 1_000, .max_tokens = 100 },
        .by_ip_quota = .{ .replenish_all_every_ms = 1_000, .max_tokens = 1 },
    });
    defer limiter.deinit();

    const addr = Address{ .ip4 = .{ .bytes = .{ 192, 0, 2, 1 }, .port = 9000 } };
    try std.testing.expect(limiter.allowEncodedPacket(addr, 0));
    try std.testing.expect(!limiter.allowEncodedPacket(addr, 0));
    try std.testing.expect(!limiter.allowEncodedPacket(addr, 999));
    try std.testing.expect(limiter.allowEncodedPacket(addr, 1_000));

    const stats = limiter.statsSnapshot();
    try std.testing.expectEqual(@as(u64, 2), stats.rate_limit_hit_ip_total);
}

test "rate limiter rejects source-state capacities outside the bound" {
    const base = Config{
        .global_quota = .{ .replenish_all_every_ms = 1_000, .max_tokens = 100 },
        .by_ip_quota = .{ .replenish_all_every_ms = 1_000, .max_tokens = 1 },
    };
    var invalid = base;
    invalid.by_ip_state_capacity = 0;
    try std.testing.expectError(error.InvalidRateLimiterCapacity, RateLimiter.init(std.testing.allocator, invalid));
    invalid.by_ip_state_capacity = MAX_SOURCE_STATE + 1;
    try std.testing.expectError(error.InvalidRateLimiterCapacity, RateLimiter.init(std.testing.allocator, invalid));
}

test "IPv4-mapped IPv6 shares one normalized source-IP key" {
    const v4 = Address{ .ip4 = .{ .bytes = .{ 192, 0, 2, 44 }, .port = 9_000 } };
    const mapped = Address{ .ip6 = .{
        .bytes = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 44 },
        .port = 9_001,
    } };
    try std.testing.expectEqual(IpKey.fromAddress(v4), IpKey.fromAddress(mapped));
}

test "rate limiter bounds source IP state" {
    var limiter = try RateLimiter.init(std.testing.allocator, .{
        .global_quota = .{ .replenish_all_every_ms = 1_000, .max_tokens = 100 },
        .by_ip_quota = .{ .replenish_all_every_ms = 1_000, .max_tokens = 1 },
        .by_ip_state_capacity = 2,
    });
    defer limiter.deinit();

    for (0..8) |i| {
        const addr = Address{ .ip4 = .{
            .bytes = .{ 198, 51, 100, @intCast(i + 1) },
            .port = 9000,
        } };
        try std.testing.expect(limiter.allowEncodedPacket(addr, 0));
        try std.testing.expect(!limiter.allowEncodedPacket(addr, 0));
        try std.testing.expect(limiter.by_ip.tat_per_key.count() <= 2);
    }
}

test "global rejection neither spends nor creates per-IP state" {
    var limiter = try RateLimiter.init(std.testing.allocator, .{
        .global_quota = .{ .replenish_all_every_ms = 1_000, .max_tokens = 1 },
        .by_ip_quota = .{ .replenish_all_every_ms = 1_000, .max_tokens = 1 },
        .by_ip_state_capacity = 2,
    });
    defer limiter.deinit();

    const first = testAddress(1);
    const rejected = testAddress(2);
    try std.testing.expect(limiter.allowEncodedPacket(first, 0));
    try std.testing.expect(!limiter.allowEncodedPacket(rejected, 0));
    try std.testing.expectEqual(@as(usize, 1), limiter.by_ip.tat_per_key.count());
    try std.testing.expect(!limiter.by_ip.tat_per_key.contains(IpKey.fromAddress(rejected)));
    try std.testing.expectEqual(Stats{ .rate_limit_hit_total = 1 }, limiter.statsSnapshot());

    try std.testing.expect(limiter.allowEncodedPacket(rejected, 1_000));
}

test "global rejection does not refresh existing per-IP state" {
    var limiter = try RateLimiter.init(std.testing.allocator, .{
        .global_quota = .{ .replenish_all_every_ms = 1_000, .max_tokens = 1 },
        .by_ip_quota = .{ .replenish_all_every_ms = 1_000, .max_tokens = 2 },
    });
    defer limiter.deinit();

    const addr = testAddress(1);
    const ip = IpKey.fromAddress(addr);
    try std.testing.expect(limiter.allowEncodedPacket(addr, 0));
    try std.testing.expect(!limiter.allowEncodedPacket(addr, 500));
    try std.testing.expectEqual(@as(?f64, null), limiter.by_ip.tat_per_key.peek(ip, timestampMsToNs(1_000)));
}

test "global rejection of current per-IP LRU does not promote it" {
    var limiter = try RateLimiter.init(std.testing.allocator, .{
        .global_quota = .{ .replenish_all_every_ms = 1_000, .max_tokens = 2 },
        .by_ip_quota = .{ .replenish_all_every_ms = 1_000, .max_tokens = 100 },
        .by_ip_state_capacity = 2,
    });
    defer limiter.deinit();

    const lru_addr = testAddress(1);
    const mru_addr = testAddress(2);
    const new_addr = testAddress(3);
    const lru_ip = IpKey.fromAddress(lru_addr);
    const mru_ip = IpKey.fromAddress(mru_addr);
    const new_ip = IpKey.fromAddress(new_addr);
    try std.testing.expect(limiter.allowEncodedPacket(lru_addr, 0));
    try std.testing.expect(limiter.allowEncodedPacket(mru_addr, 0));
    try std.testing.expect(!limiter.allowEncodedPacket(lru_addr, 0));
    try std.testing.expect(limiter.allowEncodedPacket(new_addr, 500));

    try std.testing.expect(!limiter.by_ip.tat_per_key.contains(lru_ip));
    try std.testing.expect(limiter.by_ip.tat_per_key.contains(mru_ip));
    try std.testing.expect(limiter.by_ip.tat_per_key.contains(new_ip));
}

test "global rejection leaves expired per-IP entry wholly unchanged" {
    var limiter = try RateLimiter.init(std.testing.allocator, .{
        .global_quota = .{ .replenish_all_every_ms = 1_000, .max_tokens = 2 },
        .by_ip_quota = .{ .replenish_all_every_ms = 100, .max_tokens = 100 },
        .by_ip_state_capacity = 2,
    });
    defer limiter.deinit();

    const expired_addr = testAddress(1);
    const other_addr = testAddress(2);
    const new_addr = testAddress(3);
    const expired_ip = IpKey.fromAddress(expired_addr);
    const other_ip = IpKey.fromAddress(other_addr);
    const new_ip = IpKey.fromAddress(new_addr);
    try std.testing.expect(limiter.allowEncodedPacket(expired_addr, 0));
    try std.testing.expect(limiter.allowEncodedPacket(other_addr, 0));
    try std.testing.expect(!limiter.allowEncodedPacket(expired_addr, 100));

    try std.testing.expectEqual(@as(usize, 2), limiter.by_ip.tat_per_key.count());
    try std.testing.expect(limiter.by_ip.tat_per_key.contains(expired_ip));
    try std.testing.expect(limiter.by_ip.tat_per_key.contains(other_ip));
    try std.testing.expectEqual(@as(?f64, null), limiter.by_ip.tat_per_key.peek(expired_ip, timestampMsToNs(100)));

    try std.testing.expect(limiter.allowEncodedPacket(new_addr, 500));
    try std.testing.expectEqual(@as(usize, 2), limiter.by_ip.tat_per_key.count());
    try std.testing.expect(!limiter.by_ip.tat_per_key.contains(expired_ip));
    try std.testing.expect(limiter.by_ip.tat_per_key.contains(other_ip));
    try std.testing.expect(limiter.by_ip.tat_per_key.contains(new_ip));
}

test "per-IP rejection does not spend global quota" {
    var limiter = try RateLimiter.init(std.testing.allocator, .{
        .global_quota = .{ .replenish_all_every_ms = 1_000, .max_tokens = 2 },
        .by_ip_quota = .{ .replenish_all_every_ms = 1_000, .max_tokens = 1 },
    });
    defer limiter.deinit();

    const first = testAddress(1);
    try std.testing.expect(limiter.allowEncodedPacket(first, 0));
    try std.testing.expect(!limiter.allowEncodedPacket(first, 0));
    try std.testing.expect(limiter.allowEncodedPacket(testAddress(2), 0));
    try std.testing.expectEqual(Stats{ .rate_limit_hit_ip_total = 1 }, limiter.statsSnapshot());
}

test "accepted hierarchy commits exactly one per-IP unit at the two-unit boundary" {
    var limiter = try RateLimiter.init(std.testing.allocator, .{
        .global_quota = .{ .replenish_all_every_ms = 1_000, .max_tokens = 100 },
        .by_ip_quota = .{ .replenish_all_every_ms = 1_000, .max_tokens = 2 },
    });
    defer limiter.deinit();

    const addr = testAddress(1);
    try std.testing.expect(limiter.allowEncodedPacket(addr, 0));
    try std.testing.expect(limiter.allowEncodedPacket(addr, 0));
    try std.testing.expect(!limiter.allowEncodedPacket(addr, 0));
}

test "accepted hierarchy commits exactly one global unit at the two-unit boundary" {
    var limiter = try RateLimiter.init(std.testing.allocator, .{
        .global_quota = .{ .replenish_all_every_ms = 1_000, .max_tokens = 2 },
        .by_ip_quota = .{ .replenish_all_every_ms = 1_000, .max_tokens = 100 },
    });
    defer limiter.deinit();

    try std.testing.expect(limiter.allowEncodedPacket(testAddress(1), 0));
    try std.testing.expect(limiter.allowEncodedPacket(testAddress(2), 0));
    try std.testing.expect(!limiter.allowEncodedPacket(testAddress(3), 0));
}

test "globally rejected new IPs cannot churn bounded per-IP state" {
    var limiter = try RateLimiter.init(std.testing.allocator, .{
        .global_quota = .{ .replenish_all_every_ms = 1_000, .max_tokens = 2 },
        .by_ip_quota = .{ .replenish_all_every_ms = 1_000, .max_tokens = 1 },
        .by_ip_state_capacity = 2,
    });
    defer limiter.deinit();

    const first = testAddress(1);
    const second = testAddress(2);
    try std.testing.expect(limiter.allowEncodedPacket(first, 0));
    try std.testing.expect(limiter.allowEncodedPacket(second, 0));
    try std.testing.expect(!limiter.allowEncodedPacket(testAddress(3), 0));
    try std.testing.expect(!limiter.allowEncodedPacket(testAddress(4), 499));

    try std.testing.expectEqual(@as(usize, 2), limiter.by_ip.tat_per_key.count());
    try std.testing.expect(limiter.by_ip.tat_per_key.contains(IpKey.fromAddress(first)));
    try std.testing.expect(limiter.by_ip.tat_per_key.contains(IpKey.fromAddress(second)));
    try std.testing.expect(!limiter.by_ip.tat_per_key.contains(IpKey.fromAddress(testAddress(3))));
    try std.testing.expect(!limiter.by_ip.tat_per_key.contains(IpKey.fromAddress(testAddress(4))));
}

test "hierarchical quota refill boundaries remain exact" {
    var limiter = try RateLimiter.init(std.testing.allocator, .{
        .global_quota = .{ .replenish_all_every_ms = 1_000, .max_tokens = 2 },
        .by_ip_quota = .{ .replenish_all_every_ms = 1_000, .max_tokens = 2 },
    });
    defer limiter.deinit();

    const addr = testAddress(1);
    try std.testing.expect(limiter.allowEncodedPacket(addr, 0));
    try std.testing.expect(limiter.allowEncodedPacket(addr, 0));
    try std.testing.expect(!limiter.allowEncodedPacket(addr, 499));
    try std.testing.expect(limiter.allowEncodedPacket(addr, 500));
    try std.testing.expect(!limiter.allowEncodedPacket(addr, 999));
    try std.testing.expect(limiter.allowEncodedPacket(addr, 1_000));
}

fn testAddress(last_octet: u8) Address {
    return .{ .ip4 = .{ .bytes = .{ 198, 51, 100, last_octet }, .port = 9_000 } };
}
