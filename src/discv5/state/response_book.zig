const std = @import("std");
const builtin = @import("builtin");
const admission_mod = @import("../admission.zig");
const config_mod = @import("../config.zig");
const lru = @import("../lru.zig");
const packet = @import("../protocol/packet.zig");
const types = @import("../types.zig");

const Allocator = std.mem.Allocator;
const PhaseCache = lru.LruCache(types.ChallengeKey, StoredResponse);
const CandidateCache = lru.LruCacheWithContext(types.Endpoint, Candidate, types.EndpointContext);

pub const ResponseHandle = struct {
    endpoint: types.Endpoint,
    nonce: [packet.NONCE_SIZE]u8,
    generation: u64,
};

pub const HandshakeHandle = struct {
    response: ResponseHandle,
    send_generation: u64,
};

pub const ResponseIntent = struct {
    endpoint: types.Endpoint,
    nonce: [packet.NONCE_SIZE]u8,
    dest_pubkey: [33]u8,
    plaintext: types.RecoverablePlaintext,
};

const Recovery = struct {
    dest_pubkey: [33]u8,
    plaintext: types.RecoverablePlaintext,
    admission: admission_mod.AdmissionPermit,
};

pub const CandidateKeys = struct {
    initiator_key: [16]u8,
    recipient_key: [16]u8,
};

const SendingHandshake = struct {
    send_generation: u64,
    keys: CandidateKeys,
    prepared_at_ns: i64,
};

pub const Phase = union(enum) {
    sending_response,
    recoverable,
    sending_handshake: SendingHandshake,
};

const StoredResponse = struct {
    handle: ResponseHandle,
    recovery: Recovery,
    phase: Phase,
};

pub const ChallengeView = struct {
    handle: ResponseHandle,
    dest_pubkey: [33]u8,
    plaintext: types.RecoverablePlaintext,
    permit: admission_mod.PermitHandle,
};

const Candidate = struct {
    handle: ResponseHandle,
    keys: CandidateKeys,
};

pub const CandidateView = struct {
    handle: ResponseHandle,
    keys: CandidateKeys,
};

pub const SendOutcome = enum {
    sent,
    failed,
    runtime_stopped,
};

pub const ResponseBook = struct {
    phases: PhaseCache,
    candidates: CandidateCache,
    timeout_ms: u64,
    recovery_capacity: usize,
    recoverable_count: usize = 0,
    next_generation: u64 = 1,
    next_handshake_generation: u64 = 1,

    pub fn init(alloc: Allocator, config: config_mod.Config) !ResponseBook {
        const phase_capacity = std.math.add(usize, config.limits.response_recovery_capacity, 1) catch return error.CapacityTooLarge;
        var phases = try PhaseCache.init(alloc, phase_capacity);
        errdefer phases.deinit(alloc);
        return .{
            .phases = phases,
            .candidates = try .init(alloc, config.limits.response_recovery_capacity),
            .timeout_ms = config.response_recovery_timeout_ms,
            .recovery_capacity = config.limits.response_recovery_capacity,
        };
    }

    pub fn deinit(self: *ResponseBook, alloc: Allocator, admission: *admission_mod.IngressAdmission) void {
        self.clear(admission);
        self.deinitEmpty(alloc);
    }

    pub fn clear(self: *ResponseBook, admission: *admission_mod.IngressAdmission) void {
        var removed: usize = 0;
        while (removed < self.phases.capacity()) : (removed += 1) {
            const entry = self.phases.popLruMove() orelse break;
            cleanup(entry.value, admission);
        }
        self.recoverable_count = 0;
        removed = 0;
        while (removed < self.candidates.capacity()) : (removed += 1) {
            _ = self.candidates.popLruMove() orelse break;
        }
    }

    pub fn deinitEmpty(self: *ResponseBook, alloc: Allocator) void {
        std.debug.assert(self.phases.count() == 0);
        std.debug.assert(self.candidates.count() == 0);
        std.debug.assert(self.recoverable_count == 0);
        self.phases.deinit(alloc);
        self.candidates.deinit(alloc);
    }

    /// Publishes canonical `.sending_response` only after every failure check.
    /// `permit` remains caller-owned on error and is moved only on success.
    pub fn beginResponse(
        self: *ResponseBook,
        intent: ResponseIntent,
        permit: *admission_mod.AdmissionPermit,
        now_ns: i64,
    ) !ResponseHandle {
        const successor = std.math.add(u64, self.next_generation, 1) catch return error.GenerationExhausted;
        const key = types.ChallengeKey.init(intent.endpoint.addr, &intent.nonce);
        if (self.phases.contains(key)) return error.DuplicateChallenge;
        if (self.phases.count() == self.phases.capacity()) return error.TooManyResponseRecoveries;

        const handle = ResponseHandle{
            .endpoint = intent.endpoint,
            .nonce = intent.nonce,
            .generation = self.next_generation,
        };
        const removed = self.phases.putMove(key, .{
            .handle = handle,
            .recovery = .{
                .dest_pubkey = intent.dest_pubkey,
                .plaintext = intent.plaintext,
                .admission = permit.move(),
            },
            .phase = .sending_response,
        }, self.timeout_ms, now_ns);
        std.debug.assert(removed == null);
        self.next_generation = successor;
        return handle;
    }

    pub fn completeResponseSend(
        self: *ResponseBook,
        handle: ResponseHandle,
        outcome: SendOutcome,
        admission: *admission_mod.IngressAdmission,
    ) bool {
        const key = handleKey(handle);
        const current = self.phases.getPtrRaw(key) orelse return false;
        if (!sameHandle(current.handle, handle) or current.phase != .sending_response) return false;
        if (outcome != .sent) {
            const removed = self.phases.takeMove(key) orelse unreachable;
            cleanup(removed, admission);
            return true;
        }

        if (self.recoverable_count == self.recovery_capacity) {
            const Predicate = struct {
                pub fn accepts(_: @This(), value: *const StoredResponse) bool {
                    return value.phase == .recoverable;
                }
            };
            const evicted = self.phases.popLruWhereMove(Predicate{}) orelse unreachable;
            cleanup(evicted.value, admission);
            self.recoverable_count -= 1;
        }
        current.phase = .recoverable;
        self.recoverable_count += 1;
        return true;
    }

    pub fn hasLive(self: *const ResponseBook, address: types.Address, nonce: *const [packet.NONCE_SIZE]u8, now_ns: i64) bool {
        return self.phases.peekPtr(.init(address, nonce), now_ns) != null;
    }

    pub fn removeExpired(
        self: *ResponseBook,
        address: types.Address,
        nonce: *const [packet.NONCE_SIZE]u8,
        now_ns: i64,
        admission: *admission_mod.IngressAdmission,
    ) void {
        const removed = self.phases.takeExpiredMove(.init(address, nonce), now_ns) orelse return;
        if (removed.phase == .recoverable) self.recoverable_count -= 1;
        cleanup(removed, admission);
    }

    pub fn challenge(
        self: *ResponseBook,
        address: types.Address,
        nonce: *const [packet.NONCE_SIZE]u8,
        now_ns: i64,
        admission: *admission_mod.IngressAdmission,
    ) ?ChallengeView {
        self.removeExpired(address, nonce, now_ns, admission);
        const stored = self.phases.peekPtr(.init(address, nonce), now_ns) orelse return null;
        if (stored.phase != .recoverable) return null;
        return .{
            .handle = stored.handle,
            .dest_pubkey = stored.recovery.dest_pubkey,
            .plaintext = stored.recovery.plaintext,
            .permit = stored.recovery.admission.handle(),
        };
    }

    pub fn beginHandshake(
        self: *ResponseBook,
        view: ChallengeView,
        keys: CandidateKeys,
        prepared_at_ns: i64,
    ) !HandshakeHandle {
        const successor = std.math.add(u64, self.next_handshake_generation, 1) catch return error.GenerationExhausted;
        const current = self.phases.getPtrRaw(handleKey(view.handle)) orelse return error.StaleResponse;
        if (!sameHandle(current.handle, view.handle) or current.phase != .recoverable) return error.StaleResponse;
        const handle = HandshakeHandle{
            .response = view.handle,
            .send_generation = self.next_handshake_generation,
        };
        current.phase = .{ .sending_handshake = .{
            .send_generation = handle.send_generation,
            .keys = keys,
            .prepared_at_ns = prepared_at_ns,
        } };
        self.recoverable_count -= 1;
        self.next_handshake_generation = successor;
        return handle;
    }

    pub fn failRecovery(self: *ResponseBook, view: ChallengeView, admission: *admission_mod.IngressAdmission) bool {
        const key = handleKey(view.handle);
        const current = self.phases.peekPtrRaw(key) orelse return false;
        if (!sameHandle(current.handle, view.handle) or current.phase != .recoverable) return false;
        const removed = self.phases.takeMove(key) orelse unreachable;
        self.recoverable_count -= 1;
        cleanup(removed, admission);
        return true;
    }

    pub fn handshakePlaintext(self: *const ResponseBook, handle: HandshakeHandle) ?types.RecoverablePlaintext {
        const current = self.phases.peekPtrRaw(handleKey(handle.response)) orelse return null;
        if (!sameHandle(current.handle, handle.response)) return null;
        const sending = switch (current.phase) {
            .sending_handshake => |value| value,
            else => return null,
        };
        if (sending.send_generation != handle.send_generation) return null;
        return current.recovery.plaintext;
    }

    pub fn completeHandshake(
        self: *ResponseBook,
        handle: HandshakeHandle,
        outcome: SendOutcome,
        admission: *admission_mod.IngressAdmission,
    ) bool {
        const key = handleKey(handle.response);
        const current = self.phases.peekPtrRaw(key) orelse return false;
        if (!sameHandle(current.handle, handle.response)) return false;
        const sending = switch (current.phase) {
            .sending_handshake => |value| value,
            else => return false,
        };
        if (sending.send_generation != handle.send_generation) return false;
        const removed = self.phases.takeMove(key) orelse unreachable;
        cleanup(removed, admission);
        if (outcome == .sent) {
            _ = self.candidates.putMove(handle.response.endpoint, .{
                .handle = handle.response,
                .keys = sending.keys,
            }, self.timeout_ms, sending.prepared_at_ns);
        }
        return true;
    }

    pub fn candidate(self: *const ResponseBook, endpoint: types.Endpoint, now_ns: i64) ?CandidateView {
        const value = self.candidates.peek(endpoint, now_ns) orelse return null;
        return .{ .handle = value.handle, .keys = value.keys };
    }

    pub fn acceptCandidate(self: *ResponseBook, view: CandidateView) bool {
        const current = self.candidates.peekPtrRaw(view.handle.endpoint) orelse return false;
        if (!sameHandle(current.handle, view.handle)) return false;
        _ = self.candidates.takeMove(view.handle.endpoint) orelse unreachable;
        return true;
    }

    pub fn matchesCandidate(self: *const ResponseBook, view: CandidateView) bool {
        const current = self.candidates.peekPtrRaw(view.handle.endpoint) orelse return false;
        return sameHandle(current.handle, view.handle) and std.meta.eql(current.keys, view.keys);
    }

    pub fn remove(
        self: *ResponseBook,
        address: types.Address,
        nonce: *const [packet.NONCE_SIZE]u8,
        admission: *admission_mod.IngressAdmission,
    ) bool {
        const removed = self.phases.takeMove(.init(address, nonce)) orelse return false;
        if (removed.phase == .recoverable) self.recoverable_count -= 1;
        cleanup(removed, admission);
        return true;
    }

    pub fn prune(self: *ResponseBook, now_ns: i64, admission: *admission_mod.IngressAdmission) void {
        var pruned: usize = 0;
        while (pruned < self.phases.capacity()) : (pruned += 1) {
            const removed = self.phases.popExpiredLruMove(now_ns) orelse break;
            if (removed.value.phase == .recoverable) self.recoverable_count -= 1;
            cleanup(removed.value, admission);
        }
        pruned = 0;
        while (pruned < self.candidates.capacity()) : (pruned += 1) {
            _ = self.candidates.popExpiredLruMove(now_ns) orelse break;
        }
    }

    pub fn count(self: *const ResponseBook) usize {
        return self.phases.count() + self.candidates.count();
    }

    pub fn phaseCount(self: *const ResponseBook) usize {
        return self.phases.count();
    }

    pub fn candidateCount(self: *const ResponseBook) usize {
        return self.candidates.count();
    }

    pub const Testing = if (builtin.is_test) struct {
        pub fn setNextGeneration(self: *ResponseBook, generation: u64) void {
            self.next_generation = generation;
        }

        pub fn setNextHandshakeGeneration(self: *ResponseBook, generation: u64) void {
            self.next_handshake_generation = generation;
        }

        pub fn putCandidate(self: *ResponseBook, endpoint: types.Endpoint, keys: CandidateKeys, now_ns: i64) void {
            const successor = std.math.add(u64, self.next_generation, 1) catch unreachable;
            const handle = ResponseHandle{
                .endpoint = endpoint,
                .nonce = [_]u8{0} ** packet.NONCE_SIZE,
                .generation = self.next_generation,
            };
            self.next_generation = successor;
            _ = self.candidates.putMove(endpoint, .{ .handle = handle, .keys = keys }, self.timeout_ms, now_ns);
        }

        /// Replace an exact copied candidate through the canonical generation
        /// counter while preserving the bounded one-entry endpoint owner.
        pub fn replaceCandidate(
            self: *ResponseBook,
            stale: CandidateView,
            keys: CandidateKeys,
            now_ns: i64,
        ) !CandidateView {
            if (!self.matchesCandidate(stale)) return error.StaleResponse;
            const successor = std.math.add(u64, self.next_generation, 1) catch return error.GenerationExhausted;
            const handle = ResponseHandle{
                .endpoint = stale.handle.endpoint,
                .nonce = stale.handle.nonce,
                .generation = self.next_generation,
            };
            self.next_generation = successor;
            const removed = self.candidates.putMove(
                handle.endpoint,
                .{ .handle = handle, .keys = keys },
                self.timeout_ms,
                now_ns,
            ) orelse unreachable;
            std.debug.assert(sameHandle(removed.value.handle, stale.handle));
            return .{ .handle = handle, .keys = keys };
        }

        pub fn hasPhase(self: *const ResponseBook, handle: ResponseHandle) bool {
            const current = self.phases.peekPtrRaw(handleKey(handle)) orelse return false;
            return sameHandle(current.handle, handle);
        }
    } else struct {};
};

fn handleKey(handle: ResponseHandle) types.ChallengeKey {
    return .init(handle.endpoint.addr, &handle.nonce);
}

fn sameHandle(a: ResponseHandle, b: ResponseHandle) bool {
    return a.generation == b.generation and
        std.mem.eql(u8, &a.nonce, &b.nonce) and
        types.EndpointContext.eql(.{}, a.endpoint, b.endpoint);
}

fn cleanup(owned: StoredResponse, admission: *admission_mod.IngressAdmission) void {
    var stored = owned;
    stored.recovery.admission.release(admission);
}

fn testBook(capacity: usize) !ResponseBook {
    return ResponseBook.init(std.testing.allocator, .{
        .bind_addresses = .{ .ip4 = testAddress(1) },
        .local_key_pair = @import("../secp256k1.zig").KeyPair.generate(std.Options.debug_io),
        .response_recovery_timeout_ms = 1,
        .limits = .{ .response_recovery_capacity = capacity },
    });
}

fn beginTestResponse(book: *ResponseBook, admission: *admission_mod.IngressAdmission, byte: u8, now_ns: i64) !ResponseHandle {
    var permit = try admission.acquire(testAddress(byte), admission_mod.RESPONSE_RECOVERY_PACKET_BUDGET);
    errdefer permit.release(admission);
    return book.beginResponse(.{
        .endpoint = testEndpoint(byte),
        .nonce = [_]u8{byte} ** packet.NONCE_SIZE,
        .dest_pubkey = [_]u8{byte} ** 33,
        .plaintext = try .init(&.{byte}),
    }, &permit, now_ns);
}

fn recoverTestResponse(book: *ResponseBook, admission: *admission_mod.IngressAdmission, byte: u8, now_ns: i64) !ResponseHandle {
    const handle = try beginTestResponse(book, admission, byte, now_ns);
    if (!book.completeResponseSend(handle, .sent, admission)) return error.StaleResponse;
    return handle;
}

fn beginTestHandshake(book: *ResponseBook, admission: *admission_mod.IngressAdmission, byte: u8, now_ns: i64) !HandshakeHandle {
    const nonce = [_]u8{byte} ** packet.NONCE_SIZE;
    const view = book.challenge(testAddress(byte), &nonce, now_ns, admission) orelse return error.MissingRecovery;
    return book.beginHandshake(view, .{
        .initiator_key = [_]u8{byte} ** 16,
        .recipient_key = [_]u8{byte + 1} ** 16,
    }, now_ns);
}

test "copied initial response completion commits exactly once" {
    var admission = try admission_mod.IngressAdmission.init(std.testing.allocator, null, 2);
    defer admission.deinit();
    var book = try testBook(1);
    defer book.deinit(std.testing.allocator, &admission);

    const handle = try beginTestResponse(&book, &admission, 1, 0);
    try std.testing.expect(book.completeResponseSend(handle, .sent, &admission));
    try std.testing.expect(!book.completeResponseSend(handle, .sent, &admission));
    try std.testing.expectEqual(@as(usize, 1), admission.permitCount());
}

test "failed initial response then stale success cannot install recovery" {
    var admission = try admission_mod.IngressAdmission.init(std.testing.allocator, null, 2);
    defer admission.deinit();
    var book = try testBook(1);
    defer book.deinit(std.testing.allocator, &admission);

    const handle = try beginTestResponse(&book, &admission, 1, 0);
    try std.testing.expect(book.completeResponseSend(handle, .failed, &admission));
    try std.testing.expect(!book.completeResponseSend(handle, .sent, &admission));
    try std.testing.expectEqual(@as(usize, 0), book.count());
    try std.testing.expectEqual(@as(usize, 0), admission.permitCount());
}

test "stale initial success preserves exact endpoint nonce replacement generation" {
    var admission = try admission_mod.IngressAdmission.init(std.testing.allocator, null, 3);
    defer admission.deinit();
    var book = try testBook(2);
    defer book.deinit(std.testing.allocator, &admission);

    const old = try beginTestResponse(&book, &admission, 1, 0);
    try std.testing.expect(book.completeResponseSend(old, .failed, &admission));
    const replacement = try beginTestResponse(&book, &admission, 1, 0);
    try std.testing.expect(!book.completeResponseSend(old, .sent, &admission));
    try std.testing.expect(book.completeResponseSend(replacement, .sent, &admission));
    try std.testing.expectEqual(@as(usize, 1), admission.permitCount());
}

test "response capacity allows C recoverables plus one sending and fails atomically after" {
    var admission = try admission_mod.IngressAdmission.init(std.testing.allocator, null, 4);
    defer admission.deinit();
    var book = try testBook(2);
    defer book.deinit(std.testing.allocator, &admission);

    _ = try recoverTestResponse(&book, &admission, 1, 0);
    _ = try recoverTestResponse(&book, &admission, 2, 0);
    _ = try beginTestResponse(&book, &admission, 3, 0);
    var permit = try admission.acquire(testAddress(4), admission_mod.RESPONSE_RECOVERY_PACKET_BUDGET);
    defer permit.release(&admission);
    try std.testing.expectError(error.TooManyResponseRecoveries, book.beginResponse(.{
        .endpoint = testEndpoint(4),
        .nonce = [_]u8{4} ** packet.NONCE_SIZE,
        .dest_pubkey = [_]u8{4} ** 33,
        .plaintext = try .init(&.{4}),
    }, &permit, 0));
    try std.testing.expectEqual(@as(usize, 3), book.phaseCount());
    try std.testing.expectEqual(@as(usize, 4), admission.permitCount());
}

test "response generation exhaustion is typed and leaves permit and state with caller" {
    var admission = try admission_mod.IngressAdmission.init(std.testing.allocator, null, 1);
    defer admission.deinit();
    var book = try testBook(1);
    defer book.deinit(std.testing.allocator, &admission);
    ResponseBook.Testing.setNextGeneration(&book, std.math.maxInt(u64));
    var permit = try admission.acquire(testAddress(1), admission_mod.RESPONSE_RECOVERY_PACKET_BUDGET);
    defer permit.release(&admission);

    try std.testing.expectError(error.GenerationExhausted, book.beginResponse(.{
        .endpoint = testEndpoint(1),
        .nonce = [_]u8{1} ** packet.NONCE_SIZE,
        .dest_pubkey = [_]u8{1} ** 33,
        .plaintext = try .init(&.{1}),
    }, &permit, 0));
    try std.testing.expectEqual(@as(usize, 0), book.count());
    try std.testing.expectEqual(@as(usize, 1), admission.permitCount());
}

test "duplicate WHOAREYOU creates one sending handshake" {
    var admission = try admission_mod.IngressAdmission.init(std.testing.allocator, null, 1);
    defer admission.deinit();
    var book = try testBook(1);
    defer book.deinit(std.testing.allocator, &admission);
    _ = try recoverTestResponse(&book, &admission, 1, 0);
    const nonce = [_]u8{1} ** packet.NONCE_SIZE;
    const first = book.challenge(testAddress(1), &nonce, 0, &admission) orelse return error.MissingRecovery;
    _ = try book.beginHandshake(first, .{ .initiator_key = [_]u8{1} ** 16, .recipient_key = [_]u8{2} ** 16 }, 0);
    try std.testing.expect(book.challenge(testAddress(1), &nonce, 0, &admission) == null);
    try std.testing.expectError(error.StaleResponse, book.beginHandshake(first, .{ .initiator_key = [_]u8{1} ** 16, .recipient_key = [_]u8{2} ** 16 }, 0));
}

test "failed response handshake then stale success cannot create candidate" {
    var admission = try admission_mod.IngressAdmission.init(std.testing.allocator, null, 1);
    defer admission.deinit();
    var book = try testBook(1);
    defer book.deinit(std.testing.allocator, &admission);
    _ = try recoverTestResponse(&book, &admission, 1, 0);
    const handle = try beginTestHandshake(&book, &admission, 1, 0);
    try std.testing.expect(book.completeHandshake(handle, .failed, &admission));
    try std.testing.expect(!book.completeHandshake(handle, .sent, &admission));
    try std.testing.expectEqual(@as(usize, 0), book.candidateCount());
    try std.testing.expectEqual(@as(usize, 0), admission.permitCount());
}

test "old response handshake completion preserves replacement candidate" {
    var admission = try admission_mod.IngressAdmission.init(std.testing.allocator, null, 2);
    defer admission.deinit();
    var book = try testBook(1);
    defer book.deinit(std.testing.allocator, &admission);
    _ = try recoverTestResponse(&book, &admission, 1, 0);
    const old = try beginTestHandshake(&book, &admission, 1, 0);
    try std.testing.expect(book.completeHandshake(old, .failed, &admission));
    _ = try recoverTestResponse(&book, &admission, 1, 0);
    const replacement = try beginTestHandshake(&book, &admission, 1, 0);
    try std.testing.expect(book.completeHandshake(replacement, .sent, &admission));
    try std.testing.expect(!book.completeHandshake(old, .sent, &admission));
    const candidate = book.candidate(testEndpoint(1), 0) orelse return error.MissingCandidate;
    try std.testing.expectEqual(replacement.response.generation, candidate.handle.generation);
}

test "duplicate response handshake success transitions and releases once" {
    var admission = try admission_mod.IngressAdmission.init(std.testing.allocator, null, 1);
    defer admission.deinit();
    var book = try testBook(1);
    defer book.deinit(std.testing.allocator, &admission);
    _ = try recoverTestResponse(&book, &admission, 1, 0);
    const handle = try beginTestHandshake(&book, &admission, 1, 0);
    try std.testing.expect(book.completeHandshake(handle, .sent, &admission));
    try std.testing.expect(!book.completeHandshake(handle, .sent, &admission));
    try std.testing.expectEqual(@as(usize, 1), book.candidateCount());
    try std.testing.expectEqual(@as(usize, 0), admission.permitCount());
}

test "candidate acceptance requires exact response generation" {
    var admission = try admission_mod.IngressAdmission.init(std.testing.allocator, null, 2);
    defer admission.deinit();
    var book = try testBook(1);
    defer book.deinit(std.testing.allocator, &admission);
    _ = try recoverTestResponse(&book, &admission, 1, 0);
    const old_handshake = try beginTestHandshake(&book, &admission, 1, 0);
    try std.testing.expect(book.completeHandshake(old_handshake, .sent, &admission));
    const old_candidate = book.candidate(testEndpoint(1), 0) orelse return error.MissingCandidate;
    _ = try recoverTestResponse(&book, &admission, 1, 0);
    const new_handshake = try beginTestHandshake(&book, &admission, 1, 0);
    try std.testing.expect(book.completeHandshake(new_handshake, .sent, &admission));
    try std.testing.expect(!book.acceptCandidate(old_candidate));
    const current = book.candidate(testEndpoint(1), 0) orelse return error.MissingCandidate;
    try std.testing.expectEqual(new_handshake.response.generation, current.handle.generation);
    try std.testing.expect(book.acceptCandidate(current));
}

test "shutdown and expiration release every response phase exactly once" {
    var admission = try admission_mod.IngressAdmission.init(std.testing.allocator, null, 4);
    defer admission.deinit();
    var book = try testBook(3);
    _ = try beginTestResponse(&book, &admission, 1, 0);
    _ = try recoverTestResponse(&book, &admission, 2, 0);
    _ = try recoverTestResponse(&book, &admission, 3, 0);
    _ = try beginTestHandshake(&book, &admission, 3, 0);
    try std.testing.expectEqual(@as(usize, 3), admission.permitCount());
    book.prune(std.time.ns_per_ms, &admission);
    try std.testing.expectEqual(@as(usize, 0), admission.permitCount());
    _ = try recoverTestResponse(&book, &admission, 4, 2 * std.time.ns_per_ms);
    book.deinit(std.testing.allocator, &admission);
    try std.testing.expectEqual(@as(usize, 0), admission.permitCount());
}

test "response book backing is exactly recovery capacity plus one and candidate capacity independent" {
    var admission = try admission_mod.IngressAdmission.init(std.testing.allocator, null, 1);
    defer admission.deinit();
    var book = try testBook(3);
    defer book.deinit(std.testing.allocator, &admission);
    try std.testing.expectEqual(@as(usize, 4), book.phases.capacity());
    try std.testing.expectEqual(@as(usize, 3), book.candidates.capacity());
    try std.testing.expectEqual(book.phases.capacity() * PhaseCache.Testing.nodeSize(), PhaseCache.Testing.nodeBackingBytes(&book.phases));
    try std.testing.expectEqual(book.candidates.capacity() * CandidateCache.Testing.nodeSize(), CandidateCache.Testing.nodeBackingBytes(&book.candidates));
    std.debug.print("RESPONSE_BOOK_LAYOUT book={d} stored_response={d} candidate={d} phase_capacity={d} phase_map_capacity={d} phase_node_size={d} phase_node_bytes={d} candidate_capacity={d} candidate_map_capacity={d} candidate_node_size={d} candidate_node_bytes={d}\n", .{
        @sizeOf(ResponseBook),
        @sizeOf(StoredResponse),
        @sizeOf(Candidate),
        book.phases.capacity(),
        PhaseCache.Testing.mapCapacity(&book.phases),
        PhaseCache.Testing.nodeSize(),
        PhaseCache.Testing.nodeBackingBytes(&book.phases),
        book.candidates.capacity(),
        CandidateCache.Testing.mapCapacity(&book.candidates),
        CandidateCache.Testing.nodeSize(),
        CandidateCache.Testing.nodeBackingBytes(&book.candidates),
    });
}

fn testEndpoint(byte: u8) types.Endpoint {
    return .{ .node_id = [_]u8{byte} ** 32, .addr = testAddress(byte) };
}

fn testAddress(byte: u8) types.Address {
    return .{ .ip4 = .{ .bytes = .{ 127, 0, 0, byte }, .port = 9_000 + @as(u16, byte) } };
}
