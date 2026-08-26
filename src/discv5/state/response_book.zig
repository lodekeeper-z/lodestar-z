const std = @import("std");
const admission_mod = @import("../admission.zig");
const config_mod = @import("../config.zig");
const lru = @import("../lru.zig");
const packet = @import("../protocol/packet.zig");
const types = @import("../types.zig");

const Allocator = std.mem.Allocator;
const RecoveryCache = lru.LruCache(types.ChallengeKey, StoredRecovery);
const CandidateCache = lru.LruCacheWithContext(types.Endpoint, CandidateKeys, types.EndpointContext);

pub const Recovery = struct {
    endpoint: types.Endpoint,
    nonce: [packet.NONCE_SIZE]u8,
    dest_pubkey: [33]u8,
    plaintext: types.RecoverablePlaintext,
    admission: admission_mod.AdmissionPermit,
};

const StoredRecovery = struct {
    recovery: Recovery,
    generation: u64,
};

pub const ChallengeView = struct {
    endpoint: types.Endpoint,
    nonce: [packet.NONCE_SIZE]u8,
    dest_pubkey: [33]u8,
    plaintext: types.RecoverablePlaintext,
    generation: u64,
};

pub const CandidateKeys = struct {
    initiator_key: [16]u8,
    recipient_key: [16]u8,
};

pub const ResponseBook = struct {
    recoveries: RecoveryCache,
    candidates: CandidateCache,
    timeout_ms: u64,
    next_generation: u64 = 1,

    pub fn init(alloc: Allocator, config: config_mod.Config) !ResponseBook {
        var recoveries = try RecoveryCache.init(alloc, config.limits.response_recovery_capacity);
        errdefer recoveries.deinit(alloc);
        return .{
            .recoveries = recoveries,
            .candidates = try .init(alloc, config.limits.response_recovery_capacity),
            .timeout_ms = config.response_recovery_timeout_ms,
        };
    }

    pub fn deinit(self: *ResponseBook, alloc: Allocator, admission: *admission_mod.IngressAdmission) void {
        var removed: usize = 0;
        while (removed < self.recoveries.capacity()) : (removed += 1) {
            const entry = self.recoveries.popLruMove() orelse break;
            cleanup(entry.value.recovery, admission);
        }
        removed = 0;
        while (removed < self.candidates.capacity()) : (removed += 1) {
            _ = self.candidates.popLruMove() orelse break;
        }
        self.deinitEmpty(alloc);
    }

    pub fn deinitEmpty(self: *ResponseBook, alloc: Allocator) void {
        std.debug.assert(self.recoveries.count() == 0);
        std.debug.assert(self.candidates.count() == 0);
        self.recoveries.deinit(alloc);
        self.candidates.deinit(alloc);
    }

    pub fn put(
        self: *ResponseBook,
        recovery: Recovery,
        now_ns: i64,
        admission: *admission_mod.IngressAdmission,
    ) void {
        const key = types.ChallengeKey.init(recovery.endpoint.addr, &recovery.nonce);
        const generation = self.next_generation;
        self.next_generation = std.math.add(u64, self.next_generation, 1) catch unreachable;
        if (self.recoveries.putMove(key, .{ .recovery = recovery, .generation = generation }, self.timeout_ms, now_ns)) |removed|
            cleanup(removed.value.recovery, admission);
    }

    pub fn hasLive(self: *const ResponseBook, address: types.Address, nonce: *const [packet.NONCE_SIZE]u8, now_ns: i64) bool {
        return self.recoveries.peekPtr(.init(address, nonce), now_ns) != null;
    }

    pub fn removeExpired(
        self: *ResponseBook,
        address: types.Address,
        nonce: *const [packet.NONCE_SIZE]u8,
        now_ns: i64,
        admission: *admission_mod.IngressAdmission,
    ) void {
        const removed = self.recoveries.takeExpiredMove(.init(address, nonce), now_ns) orelse return;
        cleanup(removed.recovery, admission);
    }

    pub fn challenge(
        self: *ResponseBook,
        address: types.Address,
        nonce: *const [packet.NONCE_SIZE]u8,
        now_ns: i64,
        admission: *admission_mod.IngressAdmission,
    ) ?ChallengeView {
        self.removeExpired(address, nonce, now_ns, admission);
        const recovery = self.recoveries.peekPtr(.init(address, nonce), now_ns) orelse return null;
        return .{
            .endpoint = recovery.recovery.endpoint,
            .nonce = recovery.recovery.nonce,
            .dest_pubkey = recovery.recovery.dest_pubkey,
            .plaintext = recovery.recovery.plaintext,
            .generation = recovery.generation,
        };
    }

    pub fn remove(
        self: *ResponseBook,
        address: types.Address,
        nonce: *const [packet.NONCE_SIZE]u8,
        admission: *admission_mod.IngressAdmission,
    ) bool {
        const recovery = self.recoveries.takeMove(.init(address, nonce)) orelse return false;
        cleanup(recovery.recovery, admission);
        return true;
    }

    pub fn failRecovery(self: *ResponseBook, view: ChallengeView, admission: *admission_mod.IngressAdmission) bool {
        const key = types.ChallengeKey.init(view.endpoint.addr, &view.nonce);
        const current = self.recoveries.peekPtrRaw(key) orelse return false;
        if (current.generation != view.generation or
            !types.EndpointContext.eql(.{}, current.recovery.endpoint, view.endpoint)) return false;
        const recovery = self.recoveries.takeMove(key) orelse unreachable;
        cleanup(recovery.recovery, admission);
        return true;
    }

    pub fn commitCandidate(
        self: *ResponseBook,
        view: ChallengeView,
        keys: CandidateKeys,
        now_ns: i64,
        admission: *admission_mod.IngressAdmission,
    ) bool {
        const key = types.ChallengeKey.init(view.endpoint.addr, &view.nonce);
        const current = self.recoveries.peekPtrRaw(key) orelse return false;
        if (current.generation != view.generation or
            !types.EndpointContext.eql(.{}, current.recovery.endpoint, view.endpoint)) return false;
        const recovery = self.recoveries.takeMove(key) orelse unreachable;
        cleanup(recovery.recovery, admission);
        _ = self.candidates.putMove(view.endpoint, keys, self.timeout_ms, now_ns);
        return true;
    }

    pub fn candidate(self: *const ResponseBook, endpoint: types.Endpoint, now_ns: i64) ?CandidateKeys {
        return self.candidates.peek(endpoint, now_ns);
    }

    pub fn removeCandidate(self: *ResponseBook, endpoint: types.Endpoint) bool {
        return self.candidates.remove(endpoint);
    }

    pub fn prune(self: *ResponseBook, now_ns: i64, admission: *admission_mod.IngressAdmission) void {
        var pruned: usize = 0;
        while (pruned < self.recoveries.capacity()) : (pruned += 1) {
            const removed = self.recoveries.popExpiredLruMove(now_ns) orelse break;
            cleanup(removed.value.recovery, admission);
        }
        pruned = 0;
        while (pruned < self.candidates.capacity()) : (pruned += 1) {
            _ = self.candidates.popExpiredLruMove(now_ns) orelse break;
        }
    }

    pub fn count(self: *const ResponseBook) usize {
        return self.recoveries.count() + self.candidates.count();
    }
};

fn cleanup(owned: Recovery, admission: *admission_mod.IngressAdmission) void {
    var recovery = owned;
    recovery.admission.release(admission);
}

test "response recovery LRU expiry explicit removal and shutdown release each permit once" {
    const alloc = std.testing.allocator;
    var admission = try admission_mod.IngressAdmission.init(alloc, null, 4);
    defer admission.deinit();
    const key_pair = @import("../secp256k1.zig").KeyPair.generate(std.Options.debug_io);
    var book = try ResponseBook.init(alloc, .{
        .bind_addresses = .{ .ip4 = testAddress(1) },
        .local_key_pair = key_pair,
        .response_recovery_timeout_ms = 1,
        .limits = .{ .response_recovery_capacity = 2 },
    });
    defer book.deinit(alloc, &admission);

    try putTestRecovery(&book, &admission, 1, 0);
    try putTestRecovery(&book, &admission, 2, 0);
    try std.testing.expectEqual(@as(usize, 2), admission.permitCount());
    try putTestRecovery(&book, &admission, 3, 1);
    try std.testing.expectEqual(@as(usize, 2), admission.permitCount());
    try std.testing.expect(book.remove(testAddress(2), &([_]u8{2} ** packet.NONCE_SIZE), &admission));
    try std.testing.expectEqual(@as(usize, 1), admission.permitCount());
    book.prune(2 * std.time.ns_per_ms, &admission);
    try std.testing.expectEqual(@as(usize, 0), admission.permitCount());
    try putTestRecovery(&book, &admission, 4, 3 * std.time.ns_per_ms);
}

test "response candidates are key-only bounded expiring and shutdown-clean" {
    const alloc = std.testing.allocator;
    var admission = try admission_mod.IngressAdmission.init(alloc, null, 1);
    defer admission.deinit();
    const key_pair = @import("../secp256k1.zig").KeyPair.generate(std.Options.debug_io);
    var book = try ResponseBook.init(alloc, .{
        .bind_addresses = .{ .ip4 = testAddress(1) },
        .local_key_pair = key_pair,
        .response_recovery_timeout_ms = 1,
        .limits = .{ .response_recovery_capacity = 2 },
    });
    defer book.deinit(alloc, &admission);

    try putTestCandidate(&book, &admission, 1, 0);
    try putTestCandidate(&book, &admission, 2, 0);
    try std.testing.expectEqual(@as(usize, 2), book.count());
    try std.testing.expectEqual(@as(usize, 0), admission.permitCount());
    try putTestCandidate(&book, &admission, 3, 0);
    try std.testing.expect(book.candidate(testEndpoint(1), 0) == null);
    try std.testing.expect(book.candidate(testEndpoint(2), 0) != null);
    try std.testing.expect(book.candidate(testEndpoint(3), 0) != null);
    try std.testing.expect(book.candidate(testEndpoint(2), std.time.ns_per_ms) == null);
    book.prune(std.time.ns_per_ms, &admission);
    try std.testing.expectEqual(@as(usize, 0), book.count());
    try putTestCandidate(&book, &admission, 4, 2 * std.time.ns_per_ms);
    try std.testing.expectEqual(@as(usize, 1), book.count());
    try std.testing.expectEqual(@as(usize, 0), admission.permitCount());
}

test "exact failed response recovery releases once and stale replay preserves newer recovery" {
    const alloc = std.testing.allocator;
    var admission = try admission_mod.IngressAdmission.init(alloc, null, 2);
    defer admission.deinit();
    const key_pair = @import("../secp256k1.zig").KeyPair.generate(std.Options.debug_io);
    var book = try ResponseBook.init(alloc, .{
        .bind_addresses = .{ .ip4 = testAddress(1) },
        .local_key_pair = key_pair,
        .limits = .{ .response_recovery_capacity = 2 },
    });
    defer book.deinit(alloc, &admission);

    try putTestRecovery(&book, &admission, 1, 0);
    const nonce_one = [_]u8{1} ** packet.NONCE_SIZE;
    const matched = book.challenge(testAddress(1), &nonce_one, 0, &admission) orelse return error.MissingRecovery;
    try std.testing.expectEqual(@as(usize, 1), admission.permitCount());

    try std.testing.expect(book.failRecovery(matched, &admission));
    try std.testing.expectEqual(@as(usize, 0), admission.permitCount());

    // Reuse the exact address and nonce with a newer recovery generation. The
    // stale matched view must not remove it or release its permit.
    try putTestRecovery(&book, &admission, 1, 0);
    try std.testing.expect(!book.failRecovery(matched, &admission));
    try std.testing.expectEqual(@as(usize, 1), admission.permitCount());
    try std.testing.expect(book.hasLive(testAddress(1), &nonce_one, 0));
}

fn putTestRecovery(book: *ResponseBook, admission: *admission_mod.IngressAdmission, byte: u8, now_ns: i64) !void {
    var permit = try admission.acquire(testAddress(byte), admission_mod.RESPONSE_RECOVERY_PACKET_BUDGET);
    book.put(.{
        .endpoint = .{ .node_id = [_]u8{byte} ** 32, .addr = testAddress(byte) },
        .nonce = [_]u8{byte} ** packet.NONCE_SIZE,
        .dest_pubkey = [_]u8{byte} ** 33,
        .plaintext = try .init(&.{byte}),
        .admission = permit.move(),
    }, now_ns, admission);
}

fn putTestCandidate(book: *ResponseBook, admission: *admission_mod.IngressAdmission, byte: u8, now_ns: i64) !void {
    try putTestRecovery(book, admission, byte, now_ns);
    const nonce = [_]u8{byte} ** packet.NONCE_SIZE;
    const view = book.challenge(testAddress(byte), &nonce, now_ns, admission) orelse return error.MissingRecovery;
    _ = book.commitCandidate(view, .{
        .initiator_key = [_]u8{byte} ** 16,
        .recipient_key = [_]u8{byte + 1} ** 16,
    }, now_ns, admission);
}

fn testEndpoint(byte: u8) types.Endpoint {
    return .{ .node_id = [_]u8{byte} ** 32, .addr = testAddress(byte) };
}

fn testAddress(byte: u8) types.Address {
    return .{ .ip4 = .{ .bytes = .{ 127, 0, 0, byte }, .port = 9_000 + @as(u16, byte) } };
}
