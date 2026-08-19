const std = @import("std");
const admission_mod = @import("../admission.zig");
const config_mod = @import("../config.zig");
const enr = @import("../enr.zig");
const lru = @import("../lru.zig");
const packet = @import("../protocol/packet.zig");
const rate_limit = @import("../rate_limit.zig");
const types = @import("../types.zig");

const Allocator = std.mem.Allocator;

pub const SEEN_NONCES_CAP: usize = 32;
pub const MAX_WHOAREYOU_PER_SEC: u32 = 5;

pub const SeenNonces = struct {
    values: [SEEN_NONCES_CAP][packet.NONCE_SIZE]u8 = undefined,
    len: usize = 0,

    pub fn contains(self: *const SeenNonces, nonce: *const [packet.NONCE_SIZE]u8) bool {
        for (self.values[0..self.len]) |value| if (std.mem.eql(u8, &value, nonce)) return true;
        return false;
    }

    pub fn insert(self: *SeenNonces, nonce: *const [packet.NONCE_SIZE]u8) bool {
        if (self.contains(nonce)) return true;
        if (self.len == SEEN_NONCES_CAP) return false;
        self.values[self.len] = nonce.*;
        self.len += 1;
        return true;
    }
};

/// Stable accepted keys only. Pending outbound keys are request-owned.
pub const StableSession = struct {
    initiator_key: [16]u8,
    recipient_key: [16]u8,
    seen_nonces: SeenNonces = .{},
};

pub const AcceptAuthenticatedResult = enum {
    accepted,
    replay,
    exhausted,
    missing,
};

pub const ActiveChallenge = struct {
    challenge_data: [packet.WHOAREYOU_CHALLENGE_DATA_SIZE]u8,
    triggering_nonce: [packet.NONCE_SIZE]u8,
    datagram: types.PacketBytes,
    admission: admission_mod.AdmissionPermit,
    remote_enr: ?enr.RawEnr = null,
};

const RateEntry = struct {
    count: u32,
    window_start_ns: i64,
};

const SessionCache = lru.LruCacheWithContext(types.Endpoint, StableSession, types.EndpointContext);
const ChallengeCache = lru.LruCacheWithContext(types.Endpoint, ActiveChallenge, types.EndpointContext);
const RateCache = lru.LruCache(rate_limit.IpKey, RateEntry);

pub const SessionBook = struct {
    sessions: SessionCache,
    challenges: ChallengeCache,
    whoareyou_rate: RateCache,
    session_timeout_ms: u64,
    challenge_timeout_ms: u64,
    rate_ttl_ms: u64,

    pub fn init(alloc: Allocator, config: config_mod.Config) !SessionBook {
        var sessions = try SessionCache.init(alloc, config.limits.session_capacity);
        errdefer sessions.deinit(alloc);
        var challenges = try ChallengeCache.init(alloc, config.limits.challenge_capacity);
        errdefer challenges.deinit(alloc);
        const rate = try RateCache.init(alloc, config.limits.whoareyou_rate_capacity);
        return .{
            .sessions = sessions,
            .challenges = challenges,
            .whoareyou_rate = rate,
            .session_timeout_ms = config.session_timeout_ms,
            .challenge_timeout_ms = config.challenge_timeout_ms,
            .rate_ttl_ms = config.whoareyou_rate_ttl_ms,
        };
    }

    pub fn deinit(self: *SessionBook, alloc: Allocator, admission: *admission_mod.IngressAdmission) void {
        var removed: usize = 0;
        while (removed < self.challenges.capacity()) : (removed += 1) {
            const entry = self.challenges.popLruMove() orelse break;
            var challenge = entry.value;
            challenge.admission.release(admission);
        }
        self.deinitEmpty(alloc);
    }

    pub fn deinitEmpty(self: *SessionBook, alloc: Allocator) void {
        std.debug.assert(self.challenges.count() == 0);
        self.sessions.deinit(alloc);
        self.challenges.deinit(alloc);
        self.whoareyou_rate.deinit(alloc);
    }

    pub fn get(self: *SessionBook, endpoint: types.Endpoint, now_ns: i64) ?StableSession {
        return self.sessions.getPromote(endpoint, now_ns);
    }

    /// Read a live session without changing LRU/TTL recency. Unauthenticated
    /// ciphertext must use this for tentative decryption so spoofed traffic
    /// cannot bias which honest session gets evicted at capacity.
    pub fn peekPtr(self: *const SessionBook, endpoint: types.Endpoint, now_ns: i64) ?*const StableSession {
        return self.sessions.peekPtr(endpoint, now_ns);
    }

    pub fn acceptAuthenticated(
        self: *SessionBook,
        endpoint: types.Endpoint,
        nonce: *const [packet.NONCE_SIZE]u8,
        now_ns: i64,
    ) AcceptAuthenticatedResult {
        const current = self.sessions.peekPtr(endpoint, now_ns) orelse return .missing;
        if (current.seen_nonces.contains(nonce)) return .replay;
        if (current.seen_nonces.len == SEEN_NONCES_CAP) return .exhausted;

        const accepted = self.sessions.getRefreshPtr(endpoint, self.session_timeout_ms, now_ns) orelse unreachable;
        std.debug.assert(accepted.seen_nonces.insert(nonce));
        return .accepted;
    }

    pub fn put(self: *SessionBook, endpoint: types.Endpoint, value: StableSession, now_ns: i64) void {
        // Capacity-safe replacement lets authenticated/new admission atomically
        // reuse expired storage. This is not observational pruning: reads leave
        // expired sessions in place for proactive maintenance.
        self.sessions.putReplacingExpired(endpoint, value, self.session_timeout_ms, now_ns);
    }

    pub fn remove(self: *SessionBook, endpoint: types.Endpoint) bool {
        return self.sessions.remove(endpoint);
    }

    pub fn pruneSessions(self: *SessionBook, now_ns: i64) void {
        self.sessions.pruneExpired(now_ns);
    }

    pub fn count(self: *const SessionBook) usize {
        return self.sessions.count();
    }

    pub fn peekChallenge(self: *const SessionBook, endpoint: types.Endpoint, now_ns: i64) ?*const ActiveChallenge {
        return self.challenges.peekPtr(endpoint, now_ns);
    }

    pub fn removeExpiredChallenge(
        self: *SessionBook,
        endpoint: types.Endpoint,
        now_ns: i64,
        admission: *admission_mod.IngressAdmission,
    ) bool {
        var challenge = self.challenges.takeExpiredMove(endpoint, now_ns) orelse return false;
        challenge.admission.release(admission);
        return true;
    }

    pub fn putChallenge(
        self: *SessionBook,
        endpoint: types.Endpoint,
        value: ActiveChallenge,
        now_ns: i64,
        admission: *admission_mod.IngressAdmission,
    ) void {
        if (self.challenges.putMove(endpoint, value, self.challenge_timeout_ms, now_ns)) |entry| {
            var removed = entry.value;
            removed.admission.release(admission);
        }
    }

    pub fn removeChallenge(self: *SessionBook, endpoint: types.Endpoint, admission: *admission_mod.IngressAdmission) bool {
        var removed = self.challenges.takeMove(endpoint) orelse return false;
        removed.admission.release(admission);
        return true;
    }

    pub fn pruneChallenges(self: *SessionBook, now_ns: i64, admission: *admission_mod.IngressAdmission) void {
        var pruned: usize = 0;
        while (pruned < self.challenges.capacity()) : (pruned += 1) {
            var removed = (self.challenges.popExpiredLruMove(now_ns) orelse return).value;
            removed.admission.release(admission);
        }
    }

    pub fn challengeCount(self: *const SessionBook) usize {
        return self.challenges.count();
    }

    pub fn allowWhoareyou(self: *SessionBook, address: types.Address, now_ns: i64) bool {
        const ip = rate_limit.IpKey.fromAddress(address);
        var entry = self.whoareyou_rate.get(ip, now_ns) orelse RateEntry{ .count = 0, .window_start_ns = now_ns };
        if (now_ns - entry.window_start_ns >= std.time.ns_per_s) {
            entry = .{ .count = 1, .window_start_ns = now_ns };
        } else {
            if (entry.count >= MAX_WHOAREYOU_PER_SEC) return false;
            entry.count += 1;
        }
        self.whoareyou_rate.put(ip, entry, self.rate_ttl_ms, now_ns);
        return true;
    }
};

test "session book stores stable keys independently from challenges" {
    const secp = @import("../secp256k1.zig");
    const key_pair = secp.KeyPair.generate(std.Options.debug_io);
    const node_id = try enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&key_pair));
    var admission = try admission_mod.IngressAdmission.init(std.testing.allocator, null, 2);
    defer admission.deinit();
    var book = try SessionBook.init(std.testing.allocator, .{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = key_pair,
        .local_node_id = node_id,
    });
    defer book.deinit(std.testing.allocator, &admission);
    const endpoint = types.Endpoint{
        .node_id = [_]u8{2} ** 32,
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 9000 } },
    };
    book.put(endpoint, .{ .initiator_key = [_]u8{3} ** 16, .recipient_key = [_]u8{4} ** 16 }, 0);
    book.putChallenge(endpoint, try testChallenge(&admission, endpoint.addr, 5), 0, &admission);
    try std.testing.expect(book.get(endpoint, 1) != null);
    try std.testing.expect(book.peekChallenge(endpoint, 1) != null);
    try std.testing.expect(book.removeChallenge(endpoint, &admission));
    try std.testing.expect(book.get(endpoint, 1) != null);
}

test "expired stable session reads leave stored state for maintenance" {
    const secp = @import("../secp256k1.zig");
    const key_pair = try secp.keyPairFromSecret(&([_]u8{0x11} ** 32));
    const node_id = try enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&key_pair));
    var admission = try admission_mod.IngressAdmission.init(std.testing.allocator, null, 2);
    defer admission.deinit();
    var book = try SessionBook.init(std.testing.allocator, .{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = key_pair,
        .local_node_id = node_id,
        .session_timeout_ms = 10,
        .limits = .{ .session_capacity = 2, .challenge_capacity = 2, .whoareyou_rate_capacity = 2 },
    });
    defer book.deinit(std.testing.allocator, &admission);

    const endpoint = testEndpoint(21);
    const stable = StableSession{ .initiator_key = [_]u8{1} ** 16, .recipient_key = [_]u8{2} ** 16 };
    const expired_ns = 10 * std.time.ns_per_ms;
    book.put(endpoint, stable, 0);

    try std.testing.expect(book.peekPtr(endpoint, 5 * std.time.ns_per_ms) != null);
    try std.testing.expect(book.get(endpoint, expired_ns) == null);
    const inspection: *const SessionBook = &book;
    try std.testing.expectEqual(@as(usize, 1), inspection.count());
    try std.testing.expect(book.peekPtr(endpoint, expired_ns) == null);
    try std.testing.expectEqual(@as(usize, 1), inspection.count());
    const nonce = [_]u8{3} ** packet.NONCE_SIZE;
    try std.testing.expectEqual(AcceptAuthenticatedResult.missing, book.acceptAuthenticated(endpoint, &nonce, expired_ns));
    try std.testing.expectEqual(@as(usize, 1), inspection.count());

    book.pruneSessions(expired_ns);
    try std.testing.expectEqual(@as(usize, 0), inspection.count());
}

test "put replaces an expired stable session before maintenance" {
    const secp = @import("../secp256k1.zig");
    const key_pair = try secp.keyPairFromSecret(&([_]u8{0x12} ** 32));
    const node_id = try enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&key_pair));
    var admission = try admission_mod.IngressAdmission.init(std.testing.allocator, null, 1);
    defer admission.deinit();
    var book = try SessionBook.init(std.testing.allocator, .{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = key_pair,
        .local_node_id = node_id,
        .session_timeout_ms = 10,
        .limits = .{ .session_capacity = 1, .challenge_capacity = 1, .whoareyou_rate_capacity = 1 },
    });
    defer book.deinit(std.testing.allocator, &admission);

    const endpoint = testEndpoint(22);
    const old = StableSession{ .initiator_key = [_]u8{1} ** 16, .recipient_key = [_]u8{2} ** 16 };
    const replacement = StableSession{ .initiator_key = [_]u8{3} ** 16, .recipient_key = [_]u8{4} ** 16 };
    const expired_ns = 10 * std.time.ns_per_ms;
    book.put(endpoint, old, 0);
    try std.testing.expect(book.get(endpoint, expired_ns) == null);
    try std.testing.expectEqual(@as(usize, 1), book.count());

    book.put(endpoint, replacement, expired_ns);
    try std.testing.expectEqual(@as(usize, 1), book.count());
    const stored = book.get(endpoint, expired_ns) orelse return error.MissingReplacementSession;
    try std.testing.expectEqual(replacement.initiator_key, stored.initiator_key);
    try std.testing.expectEqual(replacement.recipient_key, stored.recipient_key);
    book.pruneSessions(expired_ns);
    try std.testing.expectEqual(@as(usize, 1), book.count());
}

test "put reuses a promoted expired stable session before evicting live LRU" {
    const secp = @import("../secp256k1.zig");
    const key_pair = try secp.keyPairFromSecret(&([_]u8{0x14} ** 32));
    const node_id = try enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&key_pair));
    var admission = try admission_mod.IngressAdmission.init(std.testing.allocator, null, 2);
    defer admission.deinit();
    var book = try SessionBook.init(std.testing.allocator, .{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = key_pair,
        .local_node_id = node_id,
        .session_timeout_ms = 10,
        .limits = .{ .session_capacity = 2, .challenge_capacity = 2, .whoareyou_rate_capacity = 2 },
    });
    defer book.deinit(std.testing.allocator, &admission);

    const a = testEndpoint(26);
    const b = testEndpoint(27);
    const c = testEndpoint(28);
    const stable = StableSession{ .initiator_key = [_]u8{1} ** 16, .recipient_key = [_]u8{2} ** 16 };
    book.put(a, stable, 0);
    book.put(b, stable, std.time.ns_per_ms);

    try std.testing.expect(book.get(a, 2 * std.time.ns_per_ms) != null);
    try std.testing.expect(book.get(a, 10 * std.time.ns_per_ms) == null);
    try std.testing.expect(book.peekPtr(b, 10 * std.time.ns_per_ms) != null);
    try std.testing.expectEqual(@as(usize, 2), book.count());

    book.put(c, stable, 10 * std.time.ns_per_ms);
    try std.testing.expectEqual(@as(usize, 2), book.count());
    try std.testing.expect(book.peekPtr(a, 10 * std.time.ns_per_ms) == null);
    try std.testing.expect(book.peekPtr(b, 10 * std.time.ns_per_ms) != null);
    try std.testing.expect(book.peekPtr(c, 10 * std.time.ns_per_ms) != null);
}

test "session book enforces TTL LRU and non-evicting nonce epochs" {
    const secp = @import("../secp256k1.zig");
    const key_pair = secp.KeyPair.generate(std.Options.debug_io);
    const node_id = try enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&key_pair));
    var admission = try admission_mod.IngressAdmission.init(std.testing.allocator, null, 2);
    defer admission.deinit();
    var book = try SessionBook.init(std.testing.allocator, .{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = key_pair,
        .local_node_id = node_id,
        .session_timeout_ms = 10,
        .limits = .{ .session_capacity = 2, .challenge_capacity = 2, .whoareyou_rate_capacity = 2 },
    });
    defer book.deinit(std.testing.allocator, &admission);
    const first = testEndpoint(1);
    const second = testEndpoint(2);
    const third = testEndpoint(3);
    const stable = StableSession{ .initiator_key = [_]u8{1} ** 16, .recipient_key = [_]u8{2} ** 16 };
    book.put(first, stable, 0);
    book.put(second, stable, 0);
    try std.testing.expect(book.get(first, 1) != null);
    book.put(third, stable, 2);
    try std.testing.expect(book.get(second, 2) == null);
    try std.testing.expect(book.get(first, 2) != null);
    try std.testing.expect(book.get(first, 10 * std.time.ns_per_ms) == null);
    try std.testing.expectEqual(@as(usize, 2), book.count());
    book.pruneSessions(10 * std.time.ns_per_ms);
    try std.testing.expectEqual(@as(usize, 1), book.count());

    var seen = SeenNonces{};
    const replay = [_]u8{7} ** packet.NONCE_SIZE;
    try std.testing.expect(seen.insert(&replay));
    try std.testing.expect(seen.contains(&replay));
    try std.testing.expect(seen.insert(&replay));
    try std.testing.expect(seen.contains(&replay));
    for (0..SEEN_NONCES_CAP - 1) |i| {
        const nonce = [_]u8{@intCast(i + 8)} ** packet.NONCE_SIZE;
        try std.testing.expect(seen.insert(&nonce));
    }
    try std.testing.expect(!seen.insert(&([_]u8{0xff} ** packet.NONCE_SIZE)));
    try std.testing.expect(seen.contains(&replay));
}

test "session book accepts authenticated nonces in place without refreshing rejected state" {
    const secp = @import("../secp256k1.zig");
    const key_pair = secp.KeyPair.generate(std.Options.debug_io);
    const node_id = try enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&key_pair));
    var admission = try admission_mod.IngressAdmission.init(std.testing.allocator, null, 2);
    defer admission.deinit();
    var book = try SessionBook.init(std.testing.allocator, .{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = key_pair,
        .local_node_id = node_id,
        .session_timeout_ms = 10,
        .limits = .{ .session_capacity = 2, .challenge_capacity = 2, .whoareyou_rate_capacity = 2 },
    });
    defer book.deinit(std.testing.allocator, &admission);

    const first = testEndpoint(1);
    const second = testEndpoint(2);
    const third = testEndpoint(3);
    const stable = StableSession{ .initiator_key = [_]u8{1} ** 16, .recipient_key = [_]u8{2} ** 16 };
    book.put(first, stable, 0);
    book.put(second, stable, 0);

    const accepted = [_]u8{3} ** packet.NONCE_SIZE;
    try std.testing.expectEqual(AcceptAuthenticatedResult.accepted, book.acceptAuthenticated(first, &accepted, 5 * std.time.ns_per_ms));
    try std.testing.expect(book.peekPtr(first, 5 * std.time.ns_per_ms).?.seen_nonces.contains(&accepted));
    book.put(third, stable, 6 * std.time.ns_per_ms);
    try std.testing.expect(book.peekPtr(second, 6 * std.time.ns_per_ms) == null);
    try std.testing.expect(book.peekPtr(first, 10 * std.time.ns_per_ms) != null);

    try std.testing.expectEqual(AcceptAuthenticatedResult.replay, book.acceptAuthenticated(first, &accepted, 10 * std.time.ns_per_ms));
    try std.testing.expect(book.peekPtr(first, 15 * std.time.ns_per_ms) == null);
    try std.testing.expectEqual(AcceptAuthenticatedResult.missing, book.acceptAuthenticated(first, &accepted, 15 * std.time.ns_per_ms));
    try std.testing.expectEqual(@as(usize, 2), book.count());
    book.pruneSessions(15 * std.time.ns_per_ms);
    try std.testing.expectEqual(@as(usize, 1), book.count());

    var full = stable;
    for (0..SEEN_NONCES_CAP) |i| {
        const nonce = [_]u8{@intCast(i)} ** packet.NONCE_SIZE;
        try std.testing.expect(full.seen_nonces.insert(&nonce));
    }
    book.put(first, full, 20 * std.time.ns_per_ms);
    const overflow = [_]u8{0xff} ** packet.NONCE_SIZE;
    try std.testing.expectEqual(AcceptAuthenticatedResult.exhausted, book.acceptAuthenticated(first, &overflow, 25 * std.time.ns_per_ms));
    try std.testing.expect(book.peekPtr(first, 30 * std.time.ns_per_ms) == null);
}

test "replay and exhausted authentication do not promote stable sessions" {
    const secp = @import("../secp256k1.zig");
    const key_pair = try secp.keyPairFromSecret(&([_]u8{0x13} ** 32));
    const node_id = try enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&key_pair));
    var admission = try admission_mod.IngressAdmission.init(std.testing.allocator, null, 2);
    defer admission.deinit();
    var book = try SessionBook.init(std.testing.allocator, .{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = key_pair,
        .local_node_id = node_id,
        .session_timeout_ms = 100,
        .limits = .{ .session_capacity = 2, .challenge_capacity = 2, .whoareyou_rate_capacity = 2 },
    });
    defer book.deinit(std.testing.allocator, &admission);

    const rejected = testEndpoint(23);
    const other = testEndpoint(24);
    const replacement = testEndpoint(25);
    const nonce = [_]u8{5} ** packet.NONCE_SIZE;
    var replay = StableSession{ .initiator_key = [_]u8{1} ** 16, .recipient_key = [_]u8{2} ** 16 };
    try std.testing.expect(replay.seen_nonces.insert(&nonce));
    const stable = StableSession{ .initiator_key = [_]u8{3} ** 16, .recipient_key = [_]u8{4} ** 16 };
    book.put(rejected, replay, 0);
    book.put(other, stable, 1);
    try std.testing.expectEqual(AcceptAuthenticatedResult.replay, book.acceptAuthenticated(rejected, &nonce, 2));
    book.put(replacement, stable, 3);
    try std.testing.expect(book.peekPtr(rejected, 4) == null);
    try std.testing.expect(book.peekPtr(other, 4) != null);
    try std.testing.expect(book.peekPtr(replacement, 4) != null);

    try std.testing.expect(book.remove(other));
    try std.testing.expect(book.remove(replacement));
    var full = stable;
    for (0..SEEN_NONCES_CAP) |i| {
        const seen = [_]u8{@intCast(i)} ** packet.NONCE_SIZE;
        try std.testing.expect(full.seen_nonces.insert(&seen));
    }
    book.put(rejected, full, 10);
    book.put(other, stable, 11);
    const overflow = [_]u8{0xff} ** packet.NONCE_SIZE;
    try std.testing.expectEqual(AcceptAuthenticatedResult.exhausted, book.acceptAuthenticated(rejected, &overflow, 12));
    book.put(replacement, stable, 13);
    try std.testing.expect(book.peekPtr(rejected, 14) == null);
    try std.testing.expect(book.peekPtr(other, 14) != null);
    try std.testing.expect(book.peekPtr(replacement, 14) != null);
}

test "session challenge cache moves permit ownership through TTL and LRU cleanup" {
    const secp = @import("../secp256k1.zig");
    const key_pair = secp.KeyPair.generate(std.Options.debug_io);
    const node_id = try enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&key_pair));
    var admission = try admission_mod.IngressAdmission.init(std.testing.allocator, null, 3);
    defer admission.deinit();
    var book = try SessionBook.init(std.testing.allocator, .{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = key_pair,
        .local_node_id = node_id,
        .challenge_timeout_ms = 10,
        .limits = .{ .session_capacity = 2, .challenge_capacity = 2, .whoareyou_rate_capacity = 2 },
    });
    defer book.deinit(std.testing.allocator, &admission);
    const first = testEndpoint(11);
    const second = testEndpoint(12);
    const third = testEndpoint(13);
    book.putChallenge(first, try testChallenge(&admission, first.addr, 1), 0, &admission);
    book.putChallenge(second, try testChallenge(&admission, second.addr, 2), 0, &admission);
    try std.testing.expectEqual(@as(usize, 2), admission.permitCount());
    book.putChallenge(third, try testChallenge(&admission, third.addr, 3), 2, &admission);
    try std.testing.expect(book.peekChallenge(first, 2) == null);
    try std.testing.expect(book.peekChallenge(second, 2) != null);
    try std.testing.expect(book.peekChallenge(third, 2) != null);
    try std.testing.expectEqual(@as(usize, 2), admission.permitCount());
    try std.testing.expect(book.peekChallenge(second, 10 * std.time.ns_per_ms) == null);
    try std.testing.expect(book.removeExpiredChallenge(second, 10 * std.time.ns_per_ms, &admission));
    try std.testing.expectEqual(@as(usize, 1), admission.permitCount());
}

test "WHOAREYOU rate is per source IP and capacity bounded" {
    const secp = @import("../secp256k1.zig");
    const key_pair = secp.KeyPair.generate(std.Options.debug_io);
    const node_id = try enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&key_pair));
    var admission = try admission_mod.IngressAdmission.init(std.testing.allocator, null, 2);
    defer admission.deinit();
    var book = try SessionBook.init(std.testing.allocator, .{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = key_pair,
        .local_node_id = node_id,
        .whoareyou_rate_ttl_ms = 10,
        .limits = .{ .session_capacity = 2, .challenge_capacity = 2, .whoareyou_rate_capacity = 2 },
    });
    defer book.deinit(std.testing.allocator, &admission);
    for (0..MAX_WHOAREYOU_PER_SEC) |port| {
        try std.testing.expect(book.allowWhoareyou(.{ .ip4 = .{ .bytes = .{ 192, 0, 2, 1 }, .port = @intCast(9000 + port) } }, 0));
    }
    try std.testing.expect(!book.allowWhoareyou(.{ .ip4 = .{ .bytes = .{ 192, 0, 2, 1 }, .port = 9999 } }, 0));
    try std.testing.expect(book.allowWhoareyou(.{ .ip4 = .{ .bytes = .{ 192, 0, 2, 1 }, .port = 9999 } }, 10 * std.time.ns_per_ms));
    try std.testing.expect(book.allowWhoareyou(.{ .ip4 = .{ .bytes = .{ 192, 0, 2, 1 }, .port = 9999 } }, std.time.ns_per_s));
    for (2..8) |last| {
        _ = book.allowWhoareyou(.{ .ip4 = .{ .bytes = .{ 192, 0, 2, @intCast(last) }, .port = 9000 } }, 0);
        try std.testing.expect(book.whoareyou_rate.count() <= 2);
    }
}

fn testEndpoint(last: u8) types.Endpoint {
    return .{
        .node_id = [_]u8{last} ** 32,
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, last }, .port = 9000 } },
    };
}

fn testChallenge(admission: *admission_mod.IngressAdmission, address: types.Address, byte: u8) !ActiveChallenge {
    var permit = try admission.acquire(address, admission_mod.challengePacketBudget(0));
    return .{
        .challenge_data = [_]u8{byte} ** packet.WHOAREYOU_CHALLENGE_DATA_SIZE,
        .triggering_nonce = [_]u8{byte} ** packet.NONCE_SIZE,
        .datagram = try .init(&.{byte}),
        .admission = permit.move(),
    };
}
