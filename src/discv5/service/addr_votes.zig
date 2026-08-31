const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const Address = Io.net.IpAddress;

pub const MAX_ADDR_VOTES: usize = 200;
pub const VOTE_OBSERVATION_WINDOW_MS: u64 = 5 * 60 * 1_000;
pub const ENR_UPDATE_COOLDOWN_MS: u64 = 5 * 60 * 1_000;

const SourceKey = struct {
    family: Address.Family,
    bytes: [16]u8,

    fn fromAddress(addr: Address) SourceKey {
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
            .ip6 => |ip6| blk: {
                var prefix = ip6.bytes;
                @memset(prefix[8..16], 0);
                break :blk .{ .family = .ip6, .bytes = prefix };
            },
        };
    }
};

const VoteKey = struct {
    family: Address.Family,
    bytes: [16]u8,
    port: u16,

    fn fromAddress(addr: Address) VoteKey {
        return switch (addr) {
            .ip4 => |ip4| blk: {
                var bytes = [_]u8{0} ** 16;
                @memcpy(bytes[0..4], &ip4.bytes);
                break :blk .{ .family = .ip4, .bytes = bytes, .port = ip4.port };
            },
            .ip6 => |ip6| .{ .family = .ip6, .bytes = ip6.bytes, .port = ip6.port },
        };
    }
};

const VoterRecord = struct {
    vote_key: VoteKey,
    observed_at_ns: i64,
};

const VoteOrderEntry = struct {
    source: SourceKey,
    vote_key: VoteKey,
};

pub const WinningVote = struct {
    vote_key: VoteKey,
};

pub const AddVoteResult = union(enum) {
    duplicate,
    recorded,
    winner: WinningVote,

    pub fn isWinner(self: AddVoteResult) bool {
        return self == .winner;
    }
};

pub const AddrVotes = struct {
    allocator: Allocator,
    threshold: usize,
    voters: std.AutoHashMap(SourceKey, VoterRecord),
    tallies: std.AutoHashMap(VoteKey, usize),
    order: std.ArrayListUnmanaged(VoteOrderEntry) = .empty,

    pub fn init(allocator: Allocator, threshold: usize) AddrVotes {
        return .{
            .allocator = allocator,
            .threshold = threshold,
            .voters = std.AutoHashMap(SourceKey, VoterRecord).init(allocator),
            .tallies = std.AutoHashMap(VoteKey, usize).init(allocator),
        };
    }

    pub fn deinit(self: *AddrVotes) void {
        self.voters.deinit();
        self.tallies.deinit();
        self.order.deinit(self.allocator);
    }

    pub fn clear(self: *AddrVotes) void {
        self.voters.clearRetainingCapacity();
        self.tallies.clearRetainingCapacity();
        self.order.clearRetainingCapacity();
    }

    /// Record one external-address vote per source IP. Node IDs are cheap to
    /// generate, so counting them independently would let one remote host meet
    /// the ENR-update threshold with local sybils. A winning result is only a
    /// prepare token: the caller must commit it after the local ENR swap.
    pub fn addVote(self: *AddrVotes, source_addr: Address, observed_addr: Address, now_ns: i64) !AddVoteResult {
        self.pruneExpired(now_ns);
        const source = SourceKey.fromAddress(source_addr);
        const vote_key = VoteKey.fromAddress(observed_addr);
        const previous = self.voters.get(source);

        if (previous) |record| {
            if (std.meta.eql(record.vote_key, vote_key)) {
                self.voters.getPtr(source).?.observed_at_ns = now_ns;
                const tally = self.tallies.get(vote_key) orelse unreachable;
                return if (tally >= self.threshold) .{ .winner = .{ .vote_key = vote_key } } else .duplicate;
            }
        }

        const tally = (self.tallies.get(vote_key) orelse 0) + 1;
        try self.tallies.ensureUnusedCapacity(1);
        try self.voters.ensureUnusedCapacity(1);
        if (previous == null) try self.order.ensureUnusedCapacity(self.allocator, 1);

        if (previous) |record| self.decrementTally(record.vote_key);
        self.tallies.putAssumeCapacity(vote_key, tally);
        self.voters.putAssumeCapacity(source, .{ .vote_key = vote_key, .observed_at_ns = now_ns });

        if (previous == null) {
            self.order.appendAssumeCapacity(.{ .source = source, .vote_key = vote_key });
        } else {
            for (self.order.items) |*entry| {
                if (!std.meta.eql(entry.source, source)) continue;
                entry.vote_key = vote_key;
                break;
            } else unreachable;
        }

        self.evictOverflow();
        const retained_tally = self.tallies.get(vote_key) orelse 0;
        return if (retained_tally >= self.threshold) .{ .winner = .{ .vote_key = vote_key } } else .recorded;
    }

    pub fn commitWinner(self: *AddrVotes, winner: WinningVote) void {
        const tally = self.tallies.get(winner.vote_key) orelse unreachable;
        std.debug.assert(tally >= self.threshold);
        self.clear();
    }

    pub fn currentVoteCount(self: *const AddrVotes) usize {
        return self.voters.count();
    }

    fn pruneExpired(self: *AddrVotes, now_ns: i64) void {
        var expired: [MAX_ADDR_VOTES]SourceKey = undefined;
        var expired_len: usize = 0;
        var iterator = self.voters.iterator();
        while (iterator.next()) |entry| {
            const elapsed_ns = @as(i128, now_ns) - @as(i128, entry.value_ptr.observed_at_ns);
            const window_ns = @as(i128, VOTE_OBSERVATION_WINDOW_MS) * std.time.ns_per_ms;
            if (elapsed_ns < window_ns) continue;
            std.debug.assert(expired_len < expired.len);
            expired[expired_len] = entry.key_ptr.*;
            expired_len += 1;
        }
        for (expired[0..expired_len]) |source| self.removeSource(source);
    }

    fn removeSource(self: *AddrVotes, source: SourceKey) void {
        const removed = self.voters.fetchRemove(source) orelse return;
        self.decrementTally(removed.value.vote_key);
        for (self.order.items, 0..) |entry, index| {
            if (!std.meta.eql(entry.source, source)) continue;
            _ = self.order.orderedRemove(index);
            return;
        }
        unreachable;
    }

    fn decrementTally(self: *AddrVotes, vote_key: VoteKey) void {
        const tally = self.tallies.getPtr(vote_key) orelse return;
        std.debug.assert(tally.* > 0);
        if (tally.* == 1) {
            _ = self.tallies.remove(vote_key);
        } else {
            tally.* -= 1;
        }
    }

    fn evictOverflow(self: *AddrVotes) void {
        while (self.voters.count() > MAX_ADDR_VOTES and self.order.items.len > 0) {
            const evicted = self.order.orderedRemove(0);
            const current = self.voters.get(evicted.source) orelse continue;
            if (!std.meta.eql(current.vote_key, evicted.vote_key)) continue;
            _ = self.voters.remove(evicted.source);
            self.decrementTally(evicted.vote_key);
        }
    }
};

fn testIp4(last: u8, port: u16) Address {
    return .{ .ip4 = .{ .bytes = .{ 127, 0, 0, last }, .port = port } };
}

fn testIp6(host: u64, port: u16) Address {
    var bytes = [_]u8{0} ** 16;
    bytes[0..8].* = .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1 };
    std.mem.writeInt(u64, bytes[8..16], host, .big);
    return .{ .ip6 = .{ .bytes = bytes, .port = port } };
}

test "address votes collapse native IPv6 voters to one source prefix" {
    var votes = AddrVotes.init(std.testing.allocator, 10);
    defer votes.deinit();

    const observed = testIp6(100, 9000);
    for (1..11) |host| {
        try std.testing.expect(!(try votes.addVote(testIp6(host, @intCast(1000 + host)), observed, @intCast(host))).isWinner());
    }
    try std.testing.expectEqual(@as(usize, 1), votes.currentVoteCount());
}

test "address votes normalize IPv4-mapped IPv6 voters to IPv4 identity" {
    var votes = AddrVotes.init(std.testing.allocator, 2);
    defer votes.deinit();

    const ip4 = testIp4(9, 1000);
    const mapped = Address{ .ip6 = std.Io.net.Ip6Address.fromIp4(ip4.ip4) };
    const observed = testIp4(10, 9000);
    try std.testing.expect(!(try votes.addVote(ip4, observed, 0)).isWinner());
    try std.testing.expect(!(try votes.addVote(mapped, observed, 1)).isWinner());
    try std.testing.expectEqual(@as(usize, 1), votes.currentVoteCount());
}

test "address vote observations expire at the fixed window boundary" {
    var votes = AddrVotes.init(std.testing.allocator, 2);
    defer votes.deinit();

    const observed = testIp4(10, 9000);
    const window_ns: i64 = VOTE_OBSERVATION_WINDOW_MS * std.time.ns_per_ms;
    try std.testing.expect(!(try votes.addVote(testIp4(1, 1001), observed, 0)).isWinner());
    try std.testing.expect(!(try votes.addVote(testIp4(2, 1002), observed, window_ns)).isWinner());
    try std.testing.expectEqual(@as(usize, 1), votes.currentVoteCount());
    try std.testing.expect((try votes.addVote(testIp4(1, 1001), observed, window_ns + 1)).isWinner());
}

test "address votes replace a source IP's previous tally" {
    var votes = AddrVotes.init(std.testing.allocator, 3);
    defer votes.deinit();

    const address_a = testIp4(10, 9000);
    const address_b = testIp4(11, 9000);

    try std.testing.expect(!(try votes.addVote(testIp4(1, 1001), address_a, 0)).isWinner());
    try std.testing.expect(!(try votes.addVote(testIp4(2, 1002), address_a, 1)).isWinner());
    try std.testing.expect(!(try votes.addVote(testIp4(1, 2001), address_b, 2)).isWinner());
    try std.testing.expect(!(try votes.addVote(testIp4(3, 1003), address_a, 3)).isWinner());
    try std.testing.expect((try votes.addVote(testIp4(4, 1004), address_a, 4)).isWinner());
}

test "address votes count one vote per source IP despite port changes" {
    var votes = AddrVotes.init(std.testing.allocator, 2);
    defer votes.deinit();

    const observed = testIp4(10, 9000);
    try std.testing.expect(!(try votes.addVote(testIp4(1, 1001), observed, 0)).isWinner());
    try std.testing.expect(!(try votes.addVote(testIp4(1, 2002), observed, 1)).isWinner());
    try std.testing.expectEqual(@as(usize, 1), votes.currentVoteCount());
    try std.testing.expect((try votes.addVote(testIp4(2, 1002), observed, 2)).isWinner());
}

test "address vote replacement keeps ordering storage bounded" {
    var votes = AddrVotes.init(std.testing.allocator, 10);
    defer votes.deinit();

    const source = testIp4(1, 1001);
    for (0..500) |index| {
        const address: Address = .{
            .ip4 = .{
                .bytes = .{ 127, 0, 0, @intCast(index % 255) },
                .port = @intCast(1 + index),
            },
        };
        try std.testing.expect(!(try votes.addVote(source, address, @intCast(index))).isWinner());
    }

    try std.testing.expectEqual(@as(usize, 1), votes.currentVoteCount());
    try std.testing.expectEqual(@as(usize, 1), votes.order.items.len);
}
