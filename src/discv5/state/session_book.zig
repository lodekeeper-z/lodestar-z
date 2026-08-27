const std = @import("std");
const builtin = @import("builtin");
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

pub const SessionMetricsSnapshot = struct {
    count: usize,
    capacity: usize,
    inserted_total: u64,
    rekeyed_total: u64,
    capacity_reused_total: u64,
    maintenance_expired_total: u64,
    authenticated_refreshed_total: u64,
    replay_rejected_total: u64,
    nonce_exhaustion_rejected_total: u64,
};

pub const ChallengeHandle = struct {
    endpoint: types.Endpoint,
    generation: u64,
};

pub const ChallengePublication = struct {
    challenge_data: [packet.WHOAREYOU_CHALLENGE_DATA_SIZE]u8,
    triggering_nonce: [packet.NONCE_SIZE]u8,
    datagram: types.PacketBytes,
    remote_enr: ?enr.RawEnr = null,
    prepared_at_ns: i64,
};

pub const ChallengeView = struct {
    handle: ChallengeHandle,
    challenge_data: [packet.WHOAREYOU_CHALLENGE_DATA_SIZE]u8,
    triggering_nonce: [packet.NONCE_SIZE]u8,
    datagram: types.PacketBytes,
    remote_enr: ?enr.RawEnr,
    permit: admission_mod.PermitHandle,
};

const ChallengePhase = enum { sending_whoareyou, live };

const StoredChallenge = struct {
    generation: u64,
    phase: ChallengePhase,
    challenge_data: [packet.WHOAREYOU_CHALLENGE_DATA_SIZE]u8,
    triggering_nonce: [packet.NONCE_SIZE]u8,
    datagram: types.PacketBytes,
    admission: admission_mod.AdmissionPermit,
    remote_enr: ?enr.RawEnr,
};

const RateEntry = struct {
    count: u32,
    window_start_ns: i64,
};

const SessionCache = lru.LruCacheWithContext(types.Endpoint, StableSession, types.EndpointContext);
const ChallengeCache = lru.LruCacheWithContext(types.Endpoint, StoredChallenge, types.EndpointContext);
const RateCache = lru.LruCache(rate_limit.IpKey, RateEntry);

pub const SessionBook = struct {
    sessions: SessionCache,
    challenges: ChallengeCache,
    whoareyou_rate: RateCache,
    session_timeout_ms: u64,
    challenge_timeout_ms: u64,
    rate_ttl_ms: u64,
    inserted_total: u64 = 0,
    rekeyed_total: u64 = 0,
    capacity_reused_total: u64 = 0,
    maintenance_expired_total: u64 = 0,
    authenticated_refreshed_total: u64 = 0,
    replay_rejected_total: u64 = 0,
    nonce_exhaustion_rejected_total: u64 = 0,
    next_challenge_generation: u64 = 1,
    live_challenge_count: usize = 0,

    pub fn init(alloc: Allocator, config: config_mod.Config) !SessionBook {
        if (config.limits.challenge_capacity == 0) return error.InvalidCapacity;
        const challenge_phase_capacity = std.math.add(usize, config.limits.challenge_capacity, 1) catch
            return error.ChallengeCapacityOverflow;
        var sessions = try SessionCache.init(alloc, config.limits.session_capacity);
        errdefer sessions.deinit(alloc);
        var challenges = try ChallengeCache.init(alloc, challenge_phase_capacity);
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
        if (current.seen_nonces.contains(nonce)) {
            self.replay_rejected_total +|= 1;
            return .replay;
        }
        if (current.seen_nonces.len == SEEN_NONCES_CAP) {
            self.nonce_exhaustion_rejected_total +|= 1;
            return .exhausted;
        }

        const accepted = self.sessions.getRefreshPtr(endpoint, self.session_timeout_ms, now_ns) orelse unreachable;
        std.debug.assert(accepted.seen_nonces.insert(nonce));
        self.authenticated_refreshed_total +|= 1;
        return .accepted;
    }

    /// Detect a replay before decryption without changing session recency.
    pub fn rejectsReplay(
        self: *SessionBook,
        endpoint: types.Endpoint,
        nonce: *const [packet.NONCE_SIZE]u8,
        now_ns: i64,
    ) bool {
        const current = self.sessions.peekPtr(endpoint, now_ns) orelse return false;
        if (!current.seen_nonces.contains(nonce)) return false;
        self.replay_rejected_total +|= 1;
        return true;
    }

    pub fn put(self: *SessionBook, endpoint: types.Endpoint, value: StableSession, now_ns: i64) void {
        // Capacity-safe replacement lets authenticated/new admission atomically
        // reuse expired storage. This is not observational pruning: reads leave
        // expired sessions in place for proactive maintenance.
        const replaces_endpoint = self.sessions.contains(endpoint);
        const reuses_capacity = !replaces_endpoint and self.sessions.count() == self.sessions.capacity();
        self.sessions.putReplacingExpired(endpoint, value, self.session_timeout_ms, now_ns);
        if (replaces_endpoint) {
            self.rekeyed_total +|= 1;
        } else if (reuses_capacity) {
            self.capacity_reused_total +|= 1;
        } else {
            self.inserted_total +|= 1;
        }
    }

    pub fn remove(self: *SessionBook, endpoint: types.Endpoint) bool {
        return self.sessions.remove(endpoint);
    }

    pub fn pruneSessions(self: *SessionBook, now_ns: i64) void {
        const count_before = self.sessions.count();
        self.sessions.pruneExpired(now_ns);
        const removed = count_before - self.sessions.count();
        self.maintenance_expired_total +|= @intCast(removed);
    }

    pub fn count(self: *const SessionBook) usize {
        return self.sessions.count();
    }

    pub fn metricsSnapshot(self: *const SessionBook) SessionMetricsSnapshot {
        return .{
            .count = self.sessions.count(),
            .capacity = self.sessions.capacity(),
            .inserted_total = self.inserted_total,
            .rekeyed_total = self.rekeyed_total,
            .capacity_reused_total = self.capacity_reused_total,
            .maintenance_expired_total = self.maintenance_expired_total,
            .authenticated_refreshed_total = self.authenticated_refreshed_total,
            .replay_rejected_total = self.replay_rejected_total,
            .nonce_exhaustion_rejected_total = self.nonce_exhaustion_rejected_total,
        };
    }

    const LivePhase = struct {
        pub fn accepts(_: @This(), challenge: *const StoredChallenge) bool {
            return challenge.phase == .live;
        }
    };

    const AnyPhase = struct {
        pub fn accepts(_: @This(), _: *const StoredChallenge) bool {
            return true;
        }
    };

    pub fn preflightChallenge(
        self: *const SessionBook,
        endpoint: types.Endpoint,
        triggering_nonce: *const [packet.NONCE_SIZE]u8,
        now_ns: i64,
    ) error{ ChallengeInProgress, ChallengeNonceConflict, ChallengeCapacity, GenerationExhausted }!?ChallengeView {
        if (self.challenges.peekPtrRaw(endpoint)) |stored| {
            if (stored.phase == .sending_whoareyou) return error.ChallengeInProgress;
            if (!self.challenges.isKeyExpired(endpoint, now_ns)) {
                if (!std.mem.eql(u8, &stored.triggering_nonce, triggering_nonce)) return error.ChallengeNonceConflict;
                return challengeView(endpoint, stored.*);
            }
        }
        _ = std.math.add(u64, self.next_challenge_generation, 1) catch return error.GenerationExhausted;
        if (self.challenges.count() == self.challenges.capacity() and
            !self.challenges.hasExpiredWhere(now_ns, LivePhase{})) return error.ChallengeCapacity;
        return null;
    }

    pub fn publishChallenge(
        self: *SessionBook,
        endpoint: types.Endpoint,
        publication: ChallengePublication,
        permit: *admission_mod.AdmissionPermit,
        admission: *admission_mod.IngressAdmission,
    ) !ChallengeHandle {
        _ = try self.preflightChallenge(endpoint, &publication.triggering_nonce, publication.prepared_at_ns);
        const successor = std.math.add(u64, self.next_challenge_generation, 1) catch return error.GenerationExhausted;

        if (self.challenges.peekPtrRaw(endpoint) != null) {
            var expired = self.challenges.takeExpiredMove(endpoint, publication.prepared_at_ns) orelse
                return error.ChallengeConflict;
            std.debug.assert(expired.phase == .live);
            self.live_challenge_count -= 1;
            expired.admission.release(admission);
        }
        if (self.challenges.count() == self.challenges.capacity()) {
            var expired = (self.challenges.popExpiredLruWhereMove(publication.prepared_at_ns, LivePhase{}) orelse
                return error.ChallengeCapacity).value;
            self.live_challenge_count -= 1;
            expired.admission.release(admission);
        }

        const generation = self.next_challenge_generation;
        self.next_challenge_generation = successor;
        const replaced = self.challenges.putMove(endpoint, .{
            .generation = generation,
            .phase = .sending_whoareyou,
            .challenge_data = publication.challenge_data,
            .triggering_nonce = publication.triggering_nonce,
            .datagram = publication.datagram,
            .admission = permit.move(),
            .remote_enr = publication.remote_enr,
        }, self.challenge_timeout_ms, publication.prepared_at_ns);
        std.debug.assert(replaced == null);
        return .{ .endpoint = endpoint, .generation = generation };
    }

    pub fn completeChallengeSend(
        self: *SessionBook,
        handle: ChallengeHandle,
        completion: enum { sent, failed, runtime_stopped },
        admission: *admission_mod.IngressAdmission,
    ) bool {
        const stored = self.challenges.peekPtrRaw(handle.endpoint) orelse return false;
        if (stored.generation != handle.generation or
            stored.phase != .sending_whoareyou) return false;
        if (completion != .sent) return self.removeChallenge(handle, admission);

        if (self.live_challenge_count == self.liveChallengeCapacity()) {
            var evicted = (self.challenges.popLruWhereMove(LivePhase{}) orelse unreachable).value;
            self.live_challenge_count -= 1;
            evicted.admission.release(admission);
        }
        const sending = self.challenges.getPtrRaw(handle.endpoint) orelse unreachable;
        std.debug.assert(sending.generation == handle.generation and sending.phase == .sending_whoareyou);
        sending.phase = .live;
        self.live_challenge_count += 1;
        std.debug.assert(self.challenges.promoteRaw(handle.endpoint));
        return true;
    }

    pub fn removeChallenge(self: *SessionBook, handle: ChallengeHandle, admission: *admission_mod.IngressAdmission) bool {
        const stored = self.challenges.peekPtrRaw(handle.endpoint) orelse return false;
        if (stored.generation != handle.generation) return false;
        var removed = self.challenges.takeMove(handle.endpoint) orelse unreachable;
        if (removed.phase == .live) self.live_challenge_count -= 1;
        removed.admission.release(admission);
        return true;
    }

    pub fn peekChallenge(self: *const SessionBook, endpoint: types.Endpoint, now_ns: i64) ?ChallengeView {
        const stored = self.challenges.peekPtr(endpoint, now_ns) orelse return null;
        if (stored.phase != .live) return null;
        return challengeView(endpoint, stored.*);
    }

    pub fn matchesChallenge(self: *const SessionBook, view: ChallengeView) bool {
        const stored = self.challenges.peekPtrRaw(view.handle.endpoint) orelse return false;
        return stored.phase == .live and
            stored.generation == view.handle.generation and
            std.meta.eql(stored.admission.handle(), view.permit);
    }

    pub fn pruneChallenges(self: *SessionBook, now_ns: i64, admission: *admission_mod.IngressAdmission) void {
        var pruned: usize = 0;
        while (pruned < self.challenges.capacity()) : (pruned += 1) {
            var removed = (self.challenges.popExpiredLruWhereMove(now_ns, AnyPhase{}) orelse return).value;
            if (removed.phase == .live) self.live_challenge_count -= 1;
            removed.admission.release(admission);
        }
    }

    pub fn challengeCount(self: *const SessionBook) usize {
        return self.live_challenge_count;
    }

    pub fn challengePhaseCount(self: *const SessionBook) usize {
        return self.challenges.count();
    }

    pub fn liveChallengeCapacity(self: *const SessionBook) usize {
        return self.challenges.capacity() - 1;
    }

    pub const Testing = if (@import("builtin").is_test) struct {
        pub fn setNextChallengeGeneration(self: *SessionBook, generation: u64) void {
            self.next_challenge_generation = generation;
        }

        pub fn challengeGenerationFingerprint(self: *const SessionBook) u64 {
            return self.next_challenge_generation +% @as(u64, @intCast(self.challengePhaseCount())) +%
                (@as(u64, @intCast(self.challengeCount())) << 32);
        }

        pub fn whoareyouRateState(self: *const SessionBook, address: types.Address, now_ns: i64) ?struct { count: u32, window_start_ns: i64 } {
            const entry = self.whoareyou_rate.peek(rate_limit.IpKey.fromAddress(address), now_ns) orelse return null;
            return .{ .count = entry.count, .window_start_ns = entry.window_start_ns };
        }

        pub fn challengeLayout(self: *const SessionBook) struct { stored: usize, node: usize, node_bytes: usize, map_capacity: usize, physical_capacity: usize } {
            return .{
                .stored = @sizeOf(StoredChallenge),
                .node = ChallengeCache.Testing.nodeSize(),
                .node_bytes = ChallengeCache.Testing.nodeBackingBytes(&self.challenges),
                .map_capacity = ChallengeCache.Testing.mapCapacity(&self.challenges),
                .physical_capacity = self.challenges.capacity(),
            };
        }
    } else struct {};

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

fn challengeView(endpoint: types.Endpoint, stored: StoredChallenge) ChallengeView {
    return .{
        .handle = .{ .endpoint = endpoint, .generation = stored.generation },
        .challenge_data = stored.challenge_data,
        .triggering_nonce = stored.triggering_nonce,
        .datagram = stored.datagram,
        .remote_enr = stored.remote_enr,
        .permit = stored.admission.handle(),
    };
}

test "session book stores stable keys independently from challenges" {
    const secp = @import("../secp256k1.zig");
    const key_pair = secp.KeyPair.generate(std.Options.debug_io);
    var admission = try admission_mod.IngressAdmission.init(std.testing.allocator, null, 2);
    defer admission.deinit();
    var book = try SessionBook.init(std.testing.allocator, .{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = key_pair,
    });
    defer book.deinit(std.testing.allocator, &admission);
    const endpoint = types.Endpoint{
        .node_id = [_]u8{2} ** 32,
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 9000 } },
    };
    book.put(endpoint, .{ .initiator_key = [_]u8{3} ** 16, .recipient_key = [_]u8{4} ** 16 }, 0);
    const handle = try publishTestChallenge(&book, &admission, endpoint, 5, 0);
    try std.testing.expect(book.completeChallengeSend(handle, .sent, &admission));
    try std.testing.expect(book.get(endpoint, 1) != null);
    try std.testing.expect(book.peekChallenge(endpoint, 1) != null);
    try std.testing.expect(book.removeChallenge(handle, &admission));
    try std.testing.expect(book.get(endpoint, 1) != null);
}

test "expired stable session reads leave stored state for maintenance" {
    const secp = @import("../secp256k1.zig");
    const key_pair = try secp.keyPairFromSecret(&([_]u8{0x11} ** 32));
    var admission = try admission_mod.IngressAdmission.init(std.testing.allocator, null, 2);
    defer admission.deinit();
    var book = try SessionBook.init(std.testing.allocator, .{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = key_pair,
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
    var admission = try admission_mod.IngressAdmission.init(std.testing.allocator, null, 1);
    defer admission.deinit();
    var book = try SessionBook.init(std.testing.allocator, .{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = key_pair,
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
    var admission = try admission_mod.IngressAdmission.init(std.testing.allocator, null, 2);
    defer admission.deinit();
    var book = try SessionBook.init(std.testing.allocator, .{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = key_pair,
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
    var admission = try admission_mod.IngressAdmission.init(std.testing.allocator, null, 2);
    defer admission.deinit();
    var book = try SessionBook.init(std.testing.allocator, .{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = key_pair,
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
    var admission = try admission_mod.IngressAdmission.init(std.testing.allocator, null, 2);
    defer admission.deinit();
    var book = try SessionBook.init(std.testing.allocator, .{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = key_pair,
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

test "stable session metrics count churn and authentication decisions exactly" {
    const secp = @import("../secp256k1.zig");
    const key_pair = try secp.keyPairFromSecret(&([_]u8{0x18} ** 32));
    var admission = try admission_mod.IngressAdmission.init(std.testing.allocator, null, 2);
    defer admission.deinit();
    var book = try SessionBook.init(std.testing.allocator, .{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = key_pair,
        .session_timeout_ms = 10,
        .limits = .{ .session_capacity = 2, .challenge_capacity = 2, .whoareyou_rate_capacity = 2 },
    });
    defer book.deinit(std.testing.allocator, &admission);

    const first = testEndpoint(31);
    const second = testEndpoint(32);
    const third = testEndpoint(33);
    const stable = StableSession{ .initiator_key = [_]u8{1} ** 16, .recipient_key = [_]u8{2} ** 16 };
    const rekeyed = StableSession{ .initiator_key = [_]u8{3} ** 16, .recipient_key = [_]u8{4} ** 16 };
    book.put(first, stable, 0);
    book.put(second, stable, 1);
    book.put(first, rekeyed, 2);
    book.put(third, stable, 3);

    const accepted_nonce = [_]u8{5} ** packet.NONCE_SIZE;
    try std.testing.expectEqual(AcceptAuthenticatedResult.accepted, book.acceptAuthenticated(first, &accepted_nonce, 4));
    try std.testing.expectEqual(AcceptAuthenticatedResult.replay, book.acceptAuthenticated(first, &accepted_nonce, 5));

    var exhausted = rekeyed;
    for (0..SEEN_NONCES_CAP) |i| {
        const nonce = [_]u8{@intCast(i)} ** packet.NONCE_SIZE;
        try std.testing.expect(exhausted.seen_nonces.insert(&nonce));
    }
    book.put(first, exhausted, 6);
    const overflow = [_]u8{0xff} ** packet.NONCE_SIZE;
    try std.testing.expectEqual(AcceptAuthenticatedResult.exhausted, book.acceptAuthenticated(first, &overflow, 7));
    book.pruneSessions(10 * std.time.ns_per_ms + 3);

    const inspection: *const SessionBook = &book;
    const first_snapshot = inspection.metricsSnapshot();
    const second_snapshot = inspection.metricsSnapshot();
    try std.testing.expectEqual(first_snapshot, second_snapshot);
    try std.testing.expectEqual(@as(usize, 1), first_snapshot.count);
    try std.testing.expectEqual(@as(usize, 2), first_snapshot.capacity);
    try std.testing.expectEqual(@as(u64, 2), first_snapshot.inserted_total);
    try std.testing.expectEqual(@as(u64, 2), first_snapshot.rekeyed_total);
    try std.testing.expectEqual(@as(u64, 1), first_snapshot.capacity_reused_total);
    try std.testing.expectEqual(@as(u64, 1), first_snapshot.maintenance_expired_total);
    try std.testing.expectEqual(@as(u64, 1), first_snapshot.authenticated_refreshed_total);
    try std.testing.expectEqual(@as(u64, 1), first_snapshot.replay_rejected_total);
    try std.testing.expectEqual(@as(u64, 1), first_snapshot.nonce_exhaustion_rejected_total);
    try std.testing.expect(book.peekPtr(first, 10 * std.time.ns_per_ms + 3) != null);
}

test "replay and exhausted authentication do not promote stable sessions" {
    const secp = @import("../secp256k1.zig");
    const key_pair = try secp.keyPairFromSecret(&([_]u8{0x13} ** 32));
    var admission = try admission_mod.IngressAdmission.init(std.testing.allocator, null, 2);
    defer admission.deinit();
    var book = try SessionBook.init(std.testing.allocator, .{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = key_pair,
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
    var admission = try admission_mod.IngressAdmission.init(std.testing.allocator, null, 3);
    defer admission.deinit();
    var book = try SessionBook.init(std.testing.allocator, .{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = key_pair,
        .challenge_timeout_ms = 10,
        .limits = .{ .session_capacity = 2, .challenge_capacity = 2, .whoareyou_rate_capacity = 2 },
    });
    defer book.deinit(std.testing.allocator, &admission);
    const first = testEndpoint(11);
    const second = testEndpoint(12);
    const third = testEndpoint(13);
    const first_handle = try publishTestChallenge(&book, &admission, first, 1, 0);
    try std.testing.expect(book.completeChallengeSend(first_handle, .sent, &admission));
    const second_handle = try publishTestChallenge(&book, &admission, second, 2, 0);
    try std.testing.expect(book.completeChallengeSend(second_handle, .sent, &admission));
    try std.testing.expectEqual(@as(usize, 2), admission.permitCount());
    const third_handle = try publishTestChallenge(&book, &admission, third, 3, 2);
    try std.testing.expect(book.completeChallengeSend(third_handle, .sent, &admission));
    try std.testing.expect(book.peekChallenge(first, 2) == null);
    try std.testing.expect(book.peekChallenge(second, 2) != null);
    try std.testing.expect(book.peekChallenge(third, 2) != null);
    try std.testing.expectEqual(@as(usize, 2), admission.permitCount());
    try std.testing.expect(book.peekChallenge(second, 10 * std.time.ns_per_ms) == null);
    book.pruneChallenges(10 * std.time.ns_per_ms, &admission);
    try std.testing.expectEqual(@as(usize, 1), admission.permitCount());
}

test "copied fresh WHOAREYOU sent completion transitions canonical generation once" {
    const secp = @import("../secp256k1.zig");
    const key_pair = try secp.keyPairFromSecret(&([_]u8{0x41} ** 32));
    var admission = try admission_mod.IngressAdmission.init(std.testing.allocator, null, 1);
    defer admission.deinit();
    var book = try SessionBook.init(std.testing.allocator, .{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = key_pair,
        .limits = .{ .session_capacity = 1, .challenge_capacity = 1, .whoareyou_rate_capacity = 1 },
    });
    defer book.deinit(std.testing.allocator, &admission);

    const endpoint = testEndpoint(41);
    var permit = try admission.acquire(endpoint.addr, admission_mod.challengePacketBudget(0));
    const handle = try book.publishChallenge(endpoint, .{
        .challenge_data = [_]u8{0x41} ** packet.WHOAREYOU_CHALLENGE_DATA_SIZE,
        .triggering_nonce = [_]u8{0x42} ** packet.NONCE_SIZE,
        .datagram = try .init(&.{0x43}),
        .prepared_at_ns = 0,
    }, &permit, &admission);

    try std.testing.expect(book.completeChallengeSend(handle, .sent, &admission));
    try std.testing.expect(!book.completeChallengeSend(handle, .sent, &admission));
    const live = book.peekChallenge(endpoint, 0) orelse return error.MissingChallenge;
    try std.testing.expectEqual(handle, live.handle);
    try std.testing.expectEqual(@as(usize, 1), admission.permitCount());
}

test "failed fresh WHOAREYOU completion makes copied stale success harmless" {
    const secp = @import("../secp256k1.zig");
    var admission = try admission_mod.IngressAdmission.init(std.testing.allocator, null, 1);
    defer admission.deinit();
    var book = try SessionBook.init(std.testing.allocator, testConfig(try secp.keyPairFromSecret(&([_]u8{0x44} ** 32)), 1, 10));
    defer book.deinit(std.testing.allocator, &admission);
    const handle = try publishTestChallenge(&book, &admission, testEndpoint(44), 0x44, 0);

    try std.testing.expect(book.completeChallengeSend(handle, .failed, &admission));
    try std.testing.expect(!book.completeChallengeSend(handle, .sent, &admission));
    try std.testing.expectEqual(@as(usize, 0), book.challengePhaseCount());
    try std.testing.expectEqual(@as(usize, 0), admission.permitCount());
}

test "stale WHOAREYOU completions preserve reused endpoint generation" {
    const secp = @import("../secp256k1.zig");
    var admission = try admission_mod.IngressAdmission.init(std.testing.allocator, null, 2);
    defer admission.deinit();
    var book = try SessionBook.init(std.testing.allocator, testConfig(try secp.keyPairFromSecret(&([_]u8{0x45} ** 32)), 1, 10));
    defer book.deinit(std.testing.allocator, &admission);
    const endpoint = testEndpoint(45);
    const old = try publishTestChallenge(&book, &admission, endpoint, 0x45, 0);
    try std.testing.expect(book.completeChallengeSend(old, .failed, &admission));
    const newer = try publishTestChallenge(&book, &admission, endpoint, 0x46, 1);

    try std.testing.expect(!book.completeChallengeSend(old, .sent, &admission));
    try std.testing.expect(!book.completeChallengeSend(old, .failed, &admission));
    try std.testing.expect(book.completeChallengeSend(newer, .sent, &admission));
    const live = book.peekChallenge(endpoint, 1) orelse return error.MissingNewChallenge;
    try std.testing.expectEqual(newer, live.handle);
    try std.testing.expectEqual([_]u8{0x46} ** packet.NONCE_SIZE, live.triggering_nonce);
    try std.testing.expectEqual(@as(usize, 1), admission.permitCount());
}

test "stale WHOAREYOU handle cannot remove newer reused endpoint generation" {
    const secp = @import("../secp256k1.zig");
    var admission = try admission_mod.IngressAdmission.init(std.testing.allocator, null, 2);
    defer admission.deinit();
    var book = try SessionBook.init(std.testing.allocator, testConfig(try secp.keyPairFromSecret(&([_]u8{0x46} ** 32)), 1, 10));
    defer book.deinit(std.testing.allocator, &admission);
    const endpoint = testEndpoint(46);
    const old = try publishTestChallenge(&book, &admission, endpoint, 0x46, 0);
    try std.testing.expect(book.completeChallengeSend(old, .failed, &admission));
    const newer = try publishTestChallenge(&book, &admission, endpoint, 0x47, 1);
    try std.testing.expect(book.completeChallengeSend(newer, .sent, &admission));

    try std.testing.expect(!book.removeChallenge(old, &admission));
    const retained = book.peekChallenge(endpoint, 1) orelse return error.NewerChallengeRemoved;
    try std.testing.expectEqual(newer, retained.handle);
    try std.testing.expectEqual([_]u8{0x47} ** packet.NONCE_SIZE, retained.triggering_nonce);
    try std.testing.expectEqual(@as(usize, 1), admission.permitCount());
}

test "challenge expiry exact removal makes stale success harmless" {
    const secp = @import("../secp256k1.zig");
    var admission = try admission_mod.IngressAdmission.init(std.testing.allocator, null, 2);
    defer admission.deinit();
    var book = try SessionBook.init(std.testing.allocator, testConfig(try secp.keyPairFromSecret(&([_]u8{0x47} ** 32)), 1, 1));
    defer book.deinit(std.testing.allocator, &admission);
    const sending = try publishTestChallenge(&book, &admission, testEndpoint(47), 0x47, 0);
    book.pruneChallenges(std.time.ns_per_ms, &admission);

    try std.testing.expect(!book.completeChallengeSend(sending, .sent, &admission));
    try std.testing.expectEqual(@as(usize, 0), book.challengePhaseCount());
    try std.testing.expectEqual(@as(usize, 0), admission.permitCount());
}

test "challenge generation exhaustion is side effect free" {
    const secp = @import("../secp256k1.zig");
    var admission = try admission_mod.IngressAdmission.init(std.testing.allocator, null, 1);
    defer admission.deinit();
    var book = try SessionBook.init(std.testing.allocator, testConfig(try secp.keyPairFromSecret(&([_]u8{0x48} ** 32)), 1, 10));
    defer book.deinit(std.testing.allocator, &admission);
    book.next_challenge_generation = std.math.maxInt(u64);
    const endpoint = testEndpoint(48);
    const rate_before = book.whoareyou_rate.count();

    try std.testing.expectError(error.GenerationExhausted, book.preflightChallenge(endpoint, &([_]u8{0x48} ** packet.NONCE_SIZE), 0));
    try std.testing.expectEqual(rate_before, book.whoareyou_rate.count());
    try std.testing.expectEqual(@as(usize, 0), book.challengePhaseCount());
    try std.testing.expectEqual(@as(usize, 0), admission.permitCount());
}

test "challenge C plus one backing preserves live capacity and oldest live replacement" {
    const secp = @import("../secp256k1.zig");
    var admission = try admission_mod.IngressAdmission.init(std.testing.allocator, null, 3);
    defer admission.deinit();
    var book = try SessionBook.init(std.testing.allocator, testConfig(try secp.keyPairFromSecret(&([_]u8{0x49} ** 32)), 2, 10));
    defer book.deinit(std.testing.allocator, &admission);
    const first = try publishTestChallenge(&book, &admission, testEndpoint(49), 0x49, 0);
    try std.testing.expect(book.completeChallengeSend(first, .sent, &admission));
    const second = try publishTestChallenge(&book, &admission, testEndpoint(50), 0x50, 1);
    try std.testing.expect(book.completeChallengeSend(second, .sent, &admission));
    const prepared = try publishTestChallenge(&book, &admission, testEndpoint(51), 0x51, 2);

    try std.testing.expectEqual(@as(usize, 3), book.challenges.capacity());
    try std.testing.expectEqual(@as(usize, 3), book.challengePhaseCount());
    try std.testing.expectEqual(@as(usize, 2), book.challengeCount());
    try std.testing.expect(book.completeChallengeSend(prepared, .sent, &admission));
    try std.testing.expect(book.peekChallenge(first.endpoint, 2) == null);
    try std.testing.expect(book.peekChallenge(second.endpoint, 2) != null);
    try std.testing.expect(book.peekChallenge(prepared.endpoint, 2) != null);
    try std.testing.expectEqual(@as(usize, 2), book.challengeCount());
    try std.testing.expectEqual(@as(usize, 2), admission.permitCount());
}

test "multiple sending WHOAREYOU phases stay bounded and never evict one another" {
    const secp = @import("../secp256k1.zig");
    var admission = try admission_mod.IngressAdmission.init(std.testing.allocator, null, 4);
    defer admission.deinit();
    var book = try SessionBook.init(std.testing.allocator, testConfig(try secp.keyPairFromSecret(&([_]u8{0x52} ** 32)), 2, 10));
    defer book.deinit(std.testing.allocator, &admission);
    const first = try publishTestChallenge(&book, &admission, testEndpoint(52), 0x52, 0);
    const second = try publishTestChallenge(&book, &admission, testEndpoint(53), 0x53, 0);
    const third = try publishTestChallenge(&book, &admission, testEndpoint(54), 0x54, 0);
    var fourth_permit = try admission.acquire(testEndpoint(55).addr, admission_mod.challengePacketBudget(0));
    defer fourth_permit.release(&admission);

    try std.testing.expectError(error.ChallengeCapacity, book.publishChallenge(testEndpoint(55), .{
        .challenge_data = [_]u8{0x55} ** packet.WHOAREYOU_CHALLENGE_DATA_SIZE,
        .triggering_nonce = [_]u8{0x55} ** packet.NONCE_SIZE,
        .datagram = try .init(&.{0x55}),
        .prepared_at_ns = 0,
    }, &fourth_permit, &admission));
    try std.testing.expect(book.completeChallengeSend(first, .sent, &admission));
    try std.testing.expect(book.completeChallengeSend(second, .sent, &admission));
    try std.testing.expect(book.completeChallengeSend(third, .sent, &admission));
    try std.testing.expect(book.peekChallenge(first.endpoint, 0) == null);
    try std.testing.expect(book.peekChallenge(second.endpoint, 0) != null);
    try std.testing.expect(book.peekChallenge(third.endpoint, 0) != null);
}

test "challenge ledger registered layout report locks physical backing" {
    const secp = @import("../secp256k1.zig");
    var admission = try admission_mod.IngressAdmission.init(std.testing.allocator, null, 1);
    defer admission.deinit();
    var book = try SessionBook.init(std.testing.allocator, testConfig(try secp.keyPairFromSecret(&([_]u8{0x58} ** 32)), 3, 10));
    defer book.deinit(std.testing.allocator, &admission);
    const layout = SessionBook.Testing.challengeLayout(&book);
    const actor_mod = @import("../actor.zig");
    std.debug.print("CHALLENGE_LEDGER_LAYOUT handle={} effect={} publication={} view={} book={} stored={} node={} node_bytes={} map_capacity={} live_capacity={} physical_capacity={} actor_effect={} fifo={}\n", .{
        @sizeOf(ChallengeHandle), @sizeOf(actor_mod.WhoareyouSendEffect), @sizeOf(ChallengePublication), @sizeOf(ChallengeView), @sizeOf(SessionBook), layout.stored, layout.node, layout.node_bytes, layout.map_capacity, book.liveChallengeCapacity(), layout.physical_capacity, @sizeOf(actor_mod.ActorEffect), 1_024,
    });
    try std.testing.expectEqual(@as(usize, 72), @sizeOf(ChallengeHandle));
    try std.testing.expectEqual(@as(usize, 1_360), @sizeOf(actor_mod.WhoareyouSendEffect));
    try std.testing.expectEqual(@as(usize, 1_672), @sizeOf(ChallengePublication));
    try std.testing.expectEqual(@as(usize, 1_752), @sizeOf(ChallengeView));
    try std.testing.expectEqual(@as(usize, if (builtin.mode == .ReleaseFast) 360 else 384), @sizeOf(SessionBook));
    try std.testing.expectEqual(@as(usize, 1_688), layout.stored);
    try std.testing.expectEqual(@as(usize, 1_808), layout.node);
    try std.testing.expectEqual(@as(usize, 7_232), layout.node_bytes);
    try std.testing.expectEqual(@as(usize, 8), layout.map_capacity);
    try std.testing.expectEqual(@as(usize, 3), book.liveChallengeCapacity());
    try std.testing.expectEqual(@as(usize, 4), layout.physical_capacity);
    try std.testing.expectEqual(layout.physical_capacity * layout.node, layout.node_bytes);
    try std.testing.expectEqual(@as(usize, 1_400), @sizeOf(@import("../actor.zig").ActorEffect));
    try std.testing.expectEqual(@as(usize, 1_024), 1_024);
}

test "challenge capacity zero is rejected and C plus one overflow is failure atomic" {
    const secp = @import("../secp256k1.zig");
    var zero = testConfig(try secp.keyPairFromSecret(&([_]u8{0x59} ** 32)), 0, 10);
    try std.testing.expectError(error.InvalidCapacity, zero.validate());
    try std.testing.expectError(error.InvalidCapacity, SessionBook.init(std.testing.allocator, zero));
    zero.limits.challenge_capacity = std.math.maxInt(usize);
    try std.testing.expectError(error.ChallengeCapacityOverflow, SessionBook.init(std.testing.allocator, zero));
}

test "same endpoint live nonce conflicts and sending phase reject without mutation" {
    const secp = @import("../secp256k1.zig");
    var admission = try admission_mod.IngressAdmission.init(std.testing.allocator, null, 2);
    defer admission.deinit();
    var book = try SessionBook.init(std.testing.allocator, testConfig(try secp.keyPairFromSecret(&([_]u8{0x56} ** 32)), 1, 10));
    defer book.deinit(std.testing.allocator, &admission);
    const endpoint = testEndpoint(56);
    const sending = try publishTestChallenge(&book, &admission, endpoint, 0x56, 0);
    try std.testing.expectError(error.ChallengeInProgress, book.preflightChallenge(endpoint, &([_]u8{0x56} ** packet.NONCE_SIZE), 0));
    try std.testing.expectEqual(@as(usize, 1), book.challengePhaseCount());
    try std.testing.expect(book.completeChallengeSend(sending, .sent, &admission));
    try std.testing.expectError(error.ChallengeNonceConflict, book.preflightChallenge(endpoint, &([_]u8{0x57} ** packet.NONCE_SIZE), 0));
    try std.testing.expectEqual(@as(usize, 1), book.challengeCount());
    try std.testing.expectEqual(@as(usize, 1), admission.permitCount());
}

test "WHOAREYOU rate is per source IP and capacity bounded" {
    const secp = @import("../secp256k1.zig");
    const key_pair = secp.KeyPair.generate(std.Options.debug_io);
    var admission = try admission_mod.IngressAdmission.init(std.testing.allocator, null, 2);
    defer admission.deinit();
    var book = try SessionBook.init(std.testing.allocator, .{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = key_pair,
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

fn testConfig(key_pair: @import("../secp256k1.zig").KeyPair, challenge_capacity: usize, challenge_timeout_ms: u64) config_mod.Config {
    return .{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = key_pair,
        .challenge_timeout_ms = challenge_timeout_ms,
        .limits = .{
            .session_capacity = 2,
            .challenge_capacity = challenge_capacity,
            .whoareyou_rate_capacity = 2,
        },
    };
}

fn publishTestChallenge(
    book: *SessionBook,
    admission: *admission_mod.IngressAdmission,
    endpoint: types.Endpoint,
    byte: u8,
    now_ns: i64,
) !ChallengeHandle {
    var permit = try admission.acquire(endpoint.addr, admission_mod.challengePacketBudget(0));
    errdefer permit.release(admission);
    return book.publishChallenge(endpoint, .{
        .challenge_data = [_]u8{byte} ** packet.WHOAREYOU_CHALLENGE_DATA_SIZE,
        .triggering_nonce = [_]u8{byte} ** packet.NONCE_SIZE,
        .datagram = try .init(&.{byte}),
        .prepared_at_ns = now_ns,
    }, &permit, admission);
}
