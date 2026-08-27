const std = @import("std");
const actor_mod = @import("../actor.zig");
const admission = @import("../admission.zig");
const config = @import("../config.zig");
const enr = @import("../enr.zig");
const events = @import("../events.zig");
const outbound = @import("../flow/outbound.zig");
const packet = @import("../protocol/packet.zig");
const message = @import("../protocol/message.zig");
const metrics = @import("../metrics.zig");
const secp = @import("../secp256k1.zig");
const peer_store = @import("../state/peer_store.zig");
const request_book = @import("../state/request_book.zig");
const response_book = @import("../state/response_book.zig");
const session_book = @import("../state/session_book.zig");
const types = @import("../types.zig");
const ActorHarness = @import("../test_support/actor_harness.zig").ActorHarness;
const RecordingSender = @import("../test_support/recording_sender.zig").RecordingSender;
const deliverEncrypted = @import("../test_support/encrypted_delivery.zig").deliverEncrypted;

test "Actor isolates health request identity" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x41} ** 32));
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x42} ** 32));
    var remote_builder = enr.Builder.init(alloc, remote_key, 1);
    remote_builder.ip = .{ 127, 0, 0, 2 };
    remote_builder.udp = 9000;
    const remote_enr = try remote_builder.encode();
    defer alloc.free(remote_enr);
    const remote_id = (try (try enr.decode(remote_enr)).nodeId()).?;
    const address = types.Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 2 }, .port = 9000 } };
    const endpoint = types.Endpoint{ .node_id = remote_id, .addr = address };
    const cfg = config.Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
        .rate_limiter = null,
        .limits = .{ .max_active_requests = 4, .max_queued_requests = 4, .event_capacity = 8, .command_capacity = 4 },
    };
    var harness = try ActorHarness.init(alloc, io, cfg);
    defer harness.deinit();
    const actor = &harness.actor;
    try std.testing.expect(actor.peers.learnEnr(remote_enr, 0) != null);
    _ = actor.peers.markResponsive(remote_id, address, 0, null);

    const health = types.RequestKey.init(endpoint, try message.ReqId.fromSlice(&.{1}));
    const unrelated = types.RequestKey.init(endpoint, try message.ReqId.fromSlice(&.{2}));
    const newer = types.RequestKey.init(endpoint, try message.ReqId.fromSlice(&.{3}));
    try std.testing.expect(actor.peers.armHealthRequest(health, .connected_only));
    actor.onRequestCompletion(harness.env(), unrelated, .api, true, &.{});
    try expectActorHealthRequest(actor, remote_id, health);
    actor.onRequestCompletion(harness.env(), health, .api, false, &.{});
    try expectActorHealthRequest(actor, remote_id, health);
    actor.onRequestCompletion(harness.env(), health, .{ .maintenance = .enr_refresh }, false, &.{});
    try expectActorHealthRequest(actor, remote_id, health);

    try std.testing.expect(!actor.peers.armHealthRequest(newer, .connected_only));
    actor.onRequestCompletion(harness.env(), unrelated, .{ .maintenance = .health }, false, &.{});
    try expectActorHealthRequest(actor, remote_id, health);
    actor.onRequestCompletion(harness.env(), health, .{ .maintenance = .health }, true, &.{});
    try std.testing.expect(actor.peers.healthRequest(&remote_id) == null);
}

test "stale eviction candidate fails reservation before any send or permit" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x34} ** 32));
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x35} ** 32));
    const remote_pubkey = secp.compressedPubkey(&remote_key);
    const remote_id = try enr.nodeIdFromCompressedPubkey(&remote_pubkey);
    const address_a = types.Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 8 }, .port = 9006 } };
    const address_b = types.Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 9 }, .port = 9007 } };
    const cfg = config.Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
        .rate_limiter = null,
        .limits = .{ .max_active_requests = 2, .max_queued_requests = 2, .event_capacity = 2, .command_capacity = 2 },
    };
    var harness = try ActorHarness.init(alloc, io, cfg);
    defer harness.deinit();
    const actor = &harness.actor;
    try std.testing.expect(actor.addNode(remote_id, &remote_pubkey, address_b, null, outbound.nowNs(io)));
    const remote_ref = actor.peers.lookup(&remote_id).?;

    actor.probeEviction(harness.env(), .{
        .endpoint = .{ .node_id = remote_id, .addr = address_a },
        .pubkey = remote_pubkey,
        .ticket = .{
            .incumbent = remote_ref,
            .candidate = remote_ref,
            .probe = .{ .index = 0, .generation = 0 },
            .generation = 1,
        },
    });
    try std.testing.expectEqual(@as(usize, 0), actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 0), harness.ingress.permitCount());
}

const EvictionHarness = struct {
    allocator: std.mem.Allocator,
    ingress: admission.IngressAdmission,
    outbox: events.EventOutbox,
    actor: actor_mod.Actor,
    recording: RecordingSender,
    effect_storage: []actor_mod.ActorEffect,
    effects: actor_mod.EffectQueue,
    candidate: peer_store.EvictionProbe,
    candidate_key: secp.KeyPair,
    candidate_id: types.NodeId,
    candidate_endpoint: types.Endpoint,
    pending_id: types.NodeId,
    pending_inserted_at_ns: i64,
    bucket_distance: u8,

    fn init(alloc: std.mem.Allocator, io: std.Io) !EvictionHarness {
        const local_key = try secp.keyPairFromSecret(&([_]u8{0x25} ** 32));
        const local_id = try enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&local_key));
        const candidate_key = try secp.keyPairFromSecret(&([_]u8{0x26} ** 32));
        const candidate_pubkey = secp.compressedPubkey(&candidate_key);
        const candidate_id = try enr.nodeIdFromCompressedPubkey(&candidate_pubkey);
        const distance = peer_store.logDistance(&local_id, &candidate_id) orelse return error.SameNodeId;
        // Low-byte variations below preserve the bucket only when the highest
        // differing bit is far above them.
        try std.testing.expect(distance > 64);
        const candidate_addr = types.Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 51 }, .port = 9051 } };
        const cfg = config.Config{
            .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
            .local_key_pair = local_key,
            .request_timeout_ms = 60_000,
            .request_retries = 0,
            .bucket_pending_timeout_ms = 1,
            .ping_interval_ms = 0,
            .rate_limiter = null,
            .limits = .{ .max_active_requests = 4, .max_queued_requests = 4, .event_capacity = 8, .command_capacity = 4 },
        };
        var ingress = try admission.IngressAdmission.init(alloc, null, cfg.limits.max_active_requests);
        errdefer ingress.deinit();
        var outbox = try events.EventOutbox.init(io, alloc, cfg.limits.event_capacity);
        errdefer outbox.deinit();
        var actor = try actor_mod.Actor.init(alloc, cfg);
        errdefer actor.deinit(&ingress);
        const effect_storage = try alloc.alloc(actor_mod.ActorEffect, try admission.permitCapacity(cfg.limits) + 1);
        errdefer alloc.free(effect_storage);

        // Fill the candidate's bucket: the real candidate first (learned via
        // a valid ENR like production peers), then K - 1 fabricated
        // disconnected peers in the same bucket.
        var candidate_builder = enr.Builder.init(alloc, candidate_key, 1);
        candidate_builder.ip = candidate_addr.ip4.bytes;
        candidate_builder.udp = candidate_addr.ip4.port;
        const candidate_enr = try candidate_builder.encode();
        defer alloc.free(candidate_enr);
        try std.testing.expect(actor.peers.learnEnr(candidate_enr, 0) != null);
        try std.testing.expect(!actor.peers.routeIsConnected(&candidate_id).?);
        var sibling = candidate_id;
        for (1..peer_store.K) |i| {
            sibling[31] = candidate_id[31] ^ @as(u8, @intCast(i));
            const sibling_ref = try actor.peers.remember(
                sibling,
                &candidate_pubkey,
                .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 52 }, .port = @intCast(9052 + i) } },
                false,
            );
            try std.testing.expect((try actor.peers.admitRoute(sibling_ref, false, 0)).inserted);
        }

        // A connected newcomer overflows the bucket; the genuine eviction
        // candidate handed back is the disconnected oldest entry.
        var pending_id = candidate_id;
        pending_id[30] = candidate_id[30] ^ 0x55;
        const pending_addr = types.Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 53 }, .port = 9053 } };
        const pending_ref = try actor.peers.remember(pending_id, &candidate_pubkey, pending_addr, false);
        try actor.peers.putEnr(pending_ref, &.{ 0xc1, 0x80 }, 1);
        const pending_inserted_at_ns = outbound.nowNs(io);
        const responsive = actor.peers.markResponsive(pending_id, pending_addr, pending_inserted_at_ns, null);
        const candidate = responsive.eviction_candidate orelse return error.MissingEvictionCandidate;
        try std.testing.expectEqualSlices(u8, &candidate_id, &candidate.endpoint.node_id);
        try std.testing.expect(!actor.peers.routeIsConnected(&candidate_id).?);

        return .{
            .allocator = alloc,
            .ingress = ingress,
            .outbox = outbox,
            .actor = actor,
            .recording = RecordingSender.init(alloc),
            .effect_storage = effect_storage,
            .effects = .init(effect_storage),
            .candidate = candidate,
            .candidate_key = candidate_key,
            .candidate_id = candidate_id,
            .candidate_endpoint = .{ .node_id = candidate_id, .addr = candidate_addr },
            .pending_id = pending_id,
            .pending_inserted_at_ns = pending_inserted_at_ns,
            .bucket_distance = distance,
        };
    }

    fn deinit(self: *EvictionHarness) void {
        self.failEffects();
        self.recording.deinit();
        self.actor.deinit(&self.ingress);
        self.outbox.deinit();
        self.ingress.deinit();
        self.allocator.free(self.effect_storage);
    }

    fn env(self: *EvictionHarness) actor_mod.Env {
        return .{
            .io = std.Options.debug_io,

            .ingress = &self.ingress,
            .outbox = &self.outbox,
            .effects = &self.effects,
        };
    }

    fn drainEffects(self: *EvictionHarness) !void {
        while (self.effects.pop()) |effect| {
            self.recording.sender().send(effect.destination(), effect.packetBytes()) catch |err| {
                self.actor.applyEffectCompletion(self.env(), effect, .failed);
                return err;
            };
            self.actor.applyEffectCompletion(self.env(), effect, .sent);
        }
    }

    fn drainEffectsIgnoringFailures(self: *EvictionHarness) void {
        while (self.effects.pop()) |effect| {
            self.recording.sender().send(effect.destination(), effect.packetBytes()) catch {
                self.actor.applyEffectCompletion(self.env(), effect, .failed);
                continue;
            };
            self.actor.applyEffectCompletion(self.env(), effect, .sent);
        }
    }

    fn failEffects(self: *EvictionHarness) void {
        while (self.effects.pop()) |effect| self.actor.applyEffectCompletion(self.env(), effect, .failed);
    }

    fn hasPending(self: *EvictionHarness) bool {
        const pending_ref = self.actor.peers.lookup(&self.pending_id) orelse return false;
        return self.actor.peers.pendingContains(pending_ref);
    }

    fn armedKey(self: *EvictionHarness) !types.RequestKey {
        return self.actor.peers.healthRequest(&self.candidate_id) orelse error.MissingEvictionReservation;
    }

    fn expectProbeRequest(self: *EvictionHarness) !types.RequestKey {
        const key = try self.armedKey();
        try std.testing.expect(types.EndpointContext.eql(.{}, key.endpoint, self.candidate_endpoint));
        const request = self.actor.requests.get(key) orelse return error.MissingEvictionRequest;
        switch (request.origin) {
            .eviction => |generation| try std.testing.expectEqual(self.candidate.ticket.generation, generation),
            else => return error.WrongEvictionOrigin,
        }
        try std.testing.expectEqual(@as(usize, 1), self.actor.requests.activeCount());
        try std.testing.expectEqual(@as(usize, 1), self.ingress.permitCount());
        try std.testing.expectEqual(@as(usize, 1), self.recording.datagrams.items.len);
        return key;
    }
};

test "real full-bucket eviction probe stays active with a live permit after send" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    var harness = try EvictionHarness.init(alloc, io);
    defer harness.deinit();

    harness.actor.probeEviction(harness.env(), harness.candidate);
    try harness.drainEffects();
    _ = try harness.expectProbeRequest();
    try std.testing.expect(harness.hasPending());
    try std.testing.expect(!harness.actor.peers.routeIsConnected(&harness.candidate_id).?);
}

test "real eviction probe PONG keeps the candidate and clears the pending replacement" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    var harness = try EvictionHarness.init(alloc, io);
    defer harness.deinit();
    const stable = session_book.StableSession{ .initiator_key = [_]u8{0x27} ** 16, .recipient_key = [_]u8{0x28} ** 16 };
    harness.actor.sessions.put(harness.candidate_endpoint, stable, outbound.nowNs(io));

    harness.actor.probeEviction(harness.env(), harness.candidate);
    try harness.drainEffects();
    const key = try harness.expectProbeRequest();
    const pong = message.Pong{ .req_id = key.req_id, .enr_seq = 0, .recipient_ip = .{ .ip4 = .{ 127, 0, 0, 1 } }, .recipient_port = 9000 };
    var pong_buffer: [128]u8 = undefined;
    try deliverEncrypted(&harness.actor, io, harness.recording.sender(), &harness.ingress, &harness.outbox, harness.candidate_endpoint, &stable.recipient_key, try pong.encodeInto(&pong_buffer), 31);

    try std.testing.expectEqual(@as(usize, 0), harness.actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 0), harness.ingress.permitCount());
    try std.testing.expect(harness.actor.peers.activeRoute(&harness.candidate_id) != null);
    try std.testing.expect(harness.actor.peers.routeIsConnected(&harness.candidate_id).?);
    try std.testing.expect(harness.actor.peers.healthRequest(&harness.candidate_id) == null);
    try std.testing.expect(!harness.hasPending());
    try std.testing.expect(harness.actor.peers.activeRoute(&harness.pending_id) == null);
    var connected_event = harness.outbox.pop() orelse return error.MissingConnectedEvent;
    defer connected_event.deinit(alloc);
    try std.testing.expect(connected_event == .peer_connected);
    try std.testing.expectEqualSlices(u8, &harness.candidate_id, &connected_event.peer_connected.peer_id);
}

test "real eviction probe WHOAREYOU recovery preserves reservation and completes" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    var harness = try EvictionHarness.init(alloc, io);
    defer harness.deinit();

    harness.actor.probeEviction(harness.env(), harness.candidate);
    try harness.drainEffects();
    const key = try harness.expectProbeRequest();
    var probe = harness.recording.datagrams.items[0].bytes;
    const request_nonce = (try packet.decode(probe.bytes[0..probe.len], &harness.candidate_id)).static_header.nonce;
    var challenge_buffer: [packet.WHOAREYOU_CHALLENGE_DATA_SIZE]u8 = undefined;
    const challenge = try packet.encodeWhoareyouPacketInto(&challenge_buffer, .{
        .masking_iv = &([_]u8{0x29} ** 16),
        .recipient_node_id = &harness.actor.local_node_id,
        .request_nonce = &request_nonce,
        .id_nonce = &([_]u8{0x2a} ** 16),
        .enr_seq = 0,
    }, null);
    harness.actor.handlePacket(harness.env(), challenge, harness.candidate_endpoint.addr);
    harness.drainEffectsIgnoringFailures();

    // The recovery handshake is on the wire while reservation, request,
    // permit, and pending keys all survive.
    try std.testing.expectEqual(@as(usize, 2), harness.recording.datagrams.items.len);
    try std.testing.expectEqual(@as(usize, 1), harness.actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 1), harness.ingress.permitCount());
    const pending = harness.actor.requests.pendingKeys(harness.candidate_endpoint) orelse return error.MissingPendingKeys;
    try std.testing.expect(types.RequestKeyContext.eql(.{}, pending.handle.key, key));
    try std.testing.expect(types.RequestKeyContext.eql(.{}, try harness.armedKey(), key));

    const pong = message.Pong{ .req_id = key.req_id, .enr_seq = 0, .recipient_ip = .{ .ip4 = .{ 127, 0, 0, 1 } }, .recipient_port = 9000 };
    var pong_buffer: [128]u8 = undefined;
    try deliverEncrypted(&harness.actor, io, harness.recording.sender(), &harness.ingress, &harness.outbox, harness.candidate_endpoint, &pending.keys.recipient_key, try pong.encodeInto(&pong_buffer), 32);
    try std.testing.expectEqual(@as(usize, 0), harness.actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 0), harness.ingress.permitCount());
    try std.testing.expect(harness.actor.peers.routeIsConnected(&harness.candidate_id).?);
    try std.testing.expect(!harness.hasPending());
}

test "real eviction probe timeout removes the exact candidate and promotes pending" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    var harness = try EvictionHarness.init(alloc, io);
    defer harness.deinit();

    harness.actor.probeEviction(harness.env(), harness.candidate);
    try harness.drainEffects();
    const key = try harness.expectProbeRequest();

    const deadline_ns = harness.actor.requests.get(key).?.deadline_ns;
    harness.actor.maintenanceAt(harness.env(), deadline_ns);
    harness.drainEffectsIgnoringFailures();

    try std.testing.expectEqual(@as(usize, 0), harness.actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 0), harness.ingress.permitCount());
    try std.testing.expect(harness.actor.peers.activeRoute(&harness.candidate_id) == null);
    _ = harness.actor.peers.activeRoute(&harness.pending_id) orelse return error.PendingNotPromoted;
    try std.testing.expect(harness.actor.peers.routeIsConnected(&harness.pending_id).?);
    try std.testing.expect(!harness.hasPending());
    var saw_promoted_connected = false;
    while (harness.outbox.pop()) |event_value| {
        var event = event_value;
        defer event.deinit(alloc);
        if (event == .peer_connected and std.mem.eql(u8, &event.peer_connected.peer_id, &harness.pending_id)) saw_promoted_connected = true;
    }
    try std.testing.expect(saw_promoted_connected);
}

test "bucket expiry resolves a live eviction generation before request timeout" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    var harness = try EvictionHarness.init(alloc, io);
    defer harness.deinit();

    harness.actor.probeEviction(harness.env(), harness.candidate);
    try harness.drainEffects();
    const key = try harness.expectProbeRequest();
    const active_deadline = harness.actor.requests.get(key).?.deadline_ns;
    try std.testing.expect(harness.hasPending());
    const pending_deadline = harness.pending_inserted_at_ns + std.time.ns_per_ms;
    try std.testing.expect(pending_deadline < active_deadline);

    harness.actor.maintenanceAt(harness.env(), pending_deadline);
    harness.drainEffectsIgnoringFailures();

    try std.testing.expectEqual(@as(usize, 1), harness.actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 1), harness.ingress.permitCount());
    try std.testing.expect(harness.actor.peers.activeRoute(&harness.candidate_id) == null);
    try std.testing.expect(!harness.hasPending());
    _ = harness.actor.peers.activeRoute(&harness.pending_id) orelse return error.PendingNotPromoted;
    try std.testing.expect(harness.actor.peers.routeIsConnected(&harness.pending_id).?);
    var saw_connected = false;
    while (harness.outbox.pop()) |event_value| {
        var event = event_value;
        defer event.deinit(alloc);
        if (event == .peer_connected and std.mem.eql(u8, &event.peer_connected.peer_id, &harness.pending_id)) saw_connected = true;
    }
    try std.testing.expect(saw_connected);

    // The still-indexed request belongs to the already-consumed generation.
    // A stale completion cannot remove the promoted peer or recreate pending.
    harness.actor.onRequestCompletion(harness.env(), key, .{ .eviction = harness.candidate.ticket.generation }, true, &.{});
    try std.testing.expect(!harness.hasPending());
    try std.testing.expect(harness.actor.peers.activeRoute(&harness.pending_id) != null);
    try std.testing.expectEqual(@as(usize, 1), harness.ingress.permitCount());

    const handle = types.RequestHandle{ .key = key, .generation = harness.actor.requests.get(key).?.generation };
    try std.testing.expect(harness.actor.cancelRequest(harness.env(), handle));
    try std.testing.expect(!harness.actor.cancelRequest(harness.env(), handle));
    try std.testing.expectEqual(@as(usize, 0), harness.actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 0), harness.ingress.permitCount());
    try std.testing.expect(harness.actor.peers.activeRoute(&harness.pending_id) != null);
}

test "real eviction probe cancellation releases only its ticketed reservation" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    var harness = try EvictionHarness.init(alloc, io);
    defer harness.deinit();

    harness.actor.probeEviction(harness.env(), harness.candidate);
    try harness.drainEffects();
    const key = try harness.expectProbeRequest();
    const handle = types.RequestHandle{ .key = key, .generation = harness.actor.requests.get(key).?.generation };
    try std.testing.expect(harness.actor.cancelRequest(harness.env(), handle));
    try std.testing.expectEqual(@as(usize, 0), harness.actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 0), harness.ingress.permitCount());
    try std.testing.expect(harness.actor.peers.healthRequest(&harness.candidate_id) == null);
    try std.testing.expect(harness.hasPending());
}

test "stale P1 eviction success preserves P2 reservation when RequestKey is reused" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    var harness = try EvictionHarness.init(alloc, io);
    defer harness.deinit();

    harness.actor.probeEviction(harness.env(), harness.candidate);
    try harness.drainEffects();
    const reused_key = try harness.expectProbeRequest();
    var p1_request = harness.actor.requests.take(reused_key) orelse return error.MissingP1Request;
    p1_request.admission.release(&harness.ingress);
    harness.actor.onRequestCompletion(
        harness.env(),
        reused_key,
        .{ .eviction = harness.candidate.ticket.generation },
        true,
        &.{},
    );
    try std.testing.expect(!harness.hasPending());

    const candidate_pubkey = secp.compressedPubkey(&harness.candidate_key);
    const incumbent_addr = harness.actor.peers.activeRoute(&harness.candidate_id).?.addr;
    const disconnect_key = types.RequestKey.init(
        .{ .node_id = harness.candidate_id, .addr = incumbent_addr },
        try message.ReqId.fromSlice(&.{0xee}),
    );
    try std.testing.expect(harness.actor.peers.armHealthRequest(disconnect_key, .connected_only));
    try std.testing.expect(harness.actor.peers.markDisconnected(disconnect_key, 2) == .disconnected);
    var sibling = harness.candidate_id;
    for (0..peer_store.K) |index| {
        sibling[31] = harness.candidate_id[31] ^ @as(u8, @intCast(index));
        const sibling_ref = harness.actor.peers.lookup(&sibling) orelse continue;
        _ = harness.actor.peers.removeRoute(sibling_ref);
    }
    const incumbent_ref = harness.actor.peers.lookup(&harness.candidate_id).?;
    try std.testing.expect((try harness.actor.peers.admitRoute(incumbent_ref, false, 2)).inserted);
    for (1..peer_store.K) |index| {
        sibling = harness.candidate_id;
        sibling[31] ^= @intCast(index);
        const sibling_ref = harness.actor.peers.lookup(&sibling) orelse try harness.actor.peers.remember(
            sibling,
            &candidate_pubkey,
            .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 54 }, .port = @intCast(9054 + index) } },
            false,
        );
        try std.testing.expect((try harness.actor.peers.admitRoute(sibling_ref, false, 2)).inserted);
    }
    var p2_id = harness.candidate_id;
    p2_id[30] ^= 0x56;
    const p2_addr = types.Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 55 }, .port = 9055 } };
    const p2_ref = try harness.actor.peers.remember(p2_id, &candidate_pubkey, p2_addr, false);
    try harness.actor.peers.putEnr(p2_ref, &.{ 0xc1, 0x80 }, 1);
    const p2_probe = harness.actor.peers.markResponsive(p2_id, p2_addr, 3, null).eviction_candidate orelse return error.MissingP2;
    try std.testing.expect(p2_probe.ticket.generation != harness.candidate.ticket.generation);
    try std.testing.expect(harness.actor.peers.armHealthRequest(reused_key, .{ .allow_eviction_candidate = p2_probe.ticket }));

    harness.actor.onRequestCancellation(
        harness.env(),
        reused_key,
        .{ .eviction = harness.candidate.ticket.generation },
    );
    _ = harness.actor.peers.activeRoute(&harness.candidate_id) orelse return error.MissingIncumbent;
    try std.testing.expect(harness.actor.peers.healthRequest(&harness.candidate_id) != null);
    try std.testing.expect(harness.actor.peers.pendingContains(p2_ref));

    // Exercise the actor completion boundary: stale authenticated P1 traffic
    // still proves incumbent liveness, but cannot consume P2's reservation.
    harness.actor.onRequestCompletion(
        harness.env(),
        reused_key,
        .{ .eviction = harness.candidate.ticket.generation },
        true,
        &.{},
    );
    _ = harness.actor.peers.activeRoute(&harness.candidate_id) orelse return error.MissingIncumbent;
    try std.testing.expect(harness.actor.peers.routeIsConnected(&harness.candidate_id).?);
    const health_key = harness.actor.peers.healthRequest(&harness.candidate_id) orelse return error.MissingP2Reservation;
    try std.testing.expect(types.RequestKeyContext.eql(.{}, reused_key, health_key));
    try std.testing.expect(harness.actor.peers.pendingContains(p2_ref));
}

test "real eviction probe send failure rolls back reservation and bucket state" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    var harness = try EvictionHarness.init(alloc, io);
    defer harness.deinit();

    harness.recording.fail_next = true;
    harness.actor.probeEviction(harness.env(), harness.candidate);

    try std.testing.expectEqual(@as(usize, 1), harness.effects.count());
    try std.testing.expectEqual(@as(usize, 0), harness.recording.datagrams.items.len);
    try std.testing.expectEqual(@as(usize, 0), harness.actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 1), harness.ingress.permitCount());
    try std.testing.expect(harness.actor.peers.healthRequest(&harness.candidate_id) != null);
    try std.testing.expect(harness.hasPending());

    try std.testing.expectError(error.TransportSendFailed, harness.drainEffects());

    try std.testing.expectEqual(@as(usize, 0), harness.recording.datagrams.items.len);
    try std.testing.expectEqual(@as(usize, 0), harness.actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 0), harness.ingress.permitCount());
    try std.testing.expect(harness.actor.peers.healthRequest(&harness.candidate_id) == null);
    try std.testing.expect(harness.hasPending());
    harness.actor.requests.assertInvariants();
}

test "health probe emits before transport and failed completion releases reservation" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x91} ** 32));
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x92} ** 32));
    const remote_pubkey = secp.compressedPubkey(&remote_key);
    var remote_builder = enr.Builder.init(alloc, remote_key, 1);
    remote_builder.ip = .{ 127, 0, 0, 91 };
    remote_builder.udp = 9091;
    const remote_enr = try remote_builder.encode();
    defer alloc.free(remote_enr);
    const remote_id = (try (try enr.decode(remote_enr)).nodeId()).?;
    const endpoint = types.Endpoint{
        .node_id = remote_id,
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 91 }, .port = 9091 } },
    };
    const cfg = config.Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
        .rate_limiter = null,
        .limits = .{ .max_active_requests = 2, .max_queued_requests = 2, .event_capacity = 2, .command_capacity = 2 },
    };
    var harness = try ActorHarness.init(alloc, io, cfg);
    defer harness.deinit();
    try std.testing.expect(harness.actor.peers.learnEnr(remote_enr, 0) != null);
    _ = harness.actor.peers.markResponsive(remote_id, endpoint.addr, 0, null);

    const req_id = try harness.actor.sendProbe(harness.env(), endpoint, &remote_pubkey, .health, .connected_only);
    const key = types.RequestKey.init(endpoint, req_id);

    try std.testing.expectEqual(@as(usize, 1), harness.effects.count());
    try std.testing.expectEqual(@as(usize, 0), harness.recording.datagrams.items.len);
    try std.testing.expectEqual(@as(usize, 0), harness.actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 1), harness.ingress.permitCount());
    try expectActorHealthRequest(&harness.actor, remote_id, key);

    harness.failEffects();

    try std.testing.expectEqual(@as(usize, 0), harness.ingress.permitCount());
    try std.testing.expect(harness.actor.peers.healthRequest(&remote_id) == null);
}

test "health and eviction probes never queue behind endpoint establishment" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x36} ** 32));
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x37} ** 32));
    const remote_pubkey = secp.compressedPubkey(&remote_key);
    var remote_builder = enr.Builder.init(alloc, remote_key, 1);
    remote_builder.ip = .{ 127, 0, 0, 10 };
    remote_builder.udp = 9010;
    const remote_enr = try remote_builder.encode();
    defer alloc.free(remote_enr);
    const remote_id = (try (try enr.decode(remote_enr)).nodeId()).?;
    const endpoint = types.Endpoint{
        .node_id = remote_id,
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 10 }, .port = 9010 } },
    };
    const cfg = config.Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
        .request_timeout_ms = 1,
        .request_retries = 0,
        .ping_interval_ms = 0,
        .rate_limiter = null,
        .limits = .{ .max_active_requests = 4, .max_queued_requests = 4, .event_capacity = 4, .command_capacity = 4 },
    };
    var harness = try ActorHarness.init(alloc, io, cfg);
    defer harness.deinit();
    const actor = &harness.actor;
    try std.testing.expect(actor.peers.learnEnr(remote_enr, 0) != null);
    _ = actor.peers.markResponsive(remote_id, endpoint.addr, 0, null);

    const req_id = try actor_mod.Testing.sendPingResolvedForTest(&actor, harness.env(), endpoint, &remote_pubkey, .api);
    try harness.drainEffects();
    try std.testing.expectError(error.EndpointBusy, actor_mod.Testing.sendPingResolvedForTest(&actor, harness.env(), endpoint, &remote_pubkey, .{ .maintenance = .health }));
    const remote_ref = actor.peers.lookup(&remote_id).?;
    actor.probeEviction(harness.env(), .{
        .endpoint = endpoint,
        .pubkey = remote_pubkey,
        .ticket = .{
            .incumbent = remote_ref,
            .candidate = remote_ref,
            .probe = .{ .index = 0, .generation = 0 },
            .generation = 1,
        },
    });
    try std.testing.expectEqual(@as(usize, 1), actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 0), actor.requests.queuedCount());
    try std.testing.expectEqual(@as(usize, 1), harness.ingress.permitCount());
    try std.testing.expect(actor.peers.healthRequest(&remote_id) == null);
    try std.testing.expectEqual(@as(usize, 1), harness.recording.datagrams.items.len);

    const deadline_ns = actor.requests.get(req_id.key).?.deadline_ns;
    actor.maintenanceAt(harness.env(), deadline_ns);
    harness.drainEffectsIgnoringFailures();
    try std.testing.expectEqual(@as(usize, 0), actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 0), harness.ingress.permitCount());
    try std.testing.expect(actor.peers.routeIsConnected(&remote_id).?);
}

fn expectActorHealthRequest(actor: *const actor_mod.Actor, node_id: types.NodeId, expected: types.RequestKey) !void {
    const actual = actor.peers.healthRequest(&node_id) orelse return error.MissingHealthRequest;
    try std.testing.expect(types.RequestKeyContext.eql(.{}, actual, expected));
    try std.testing.expect(actor.peers.routeIsConnected(&node_id).?);
}

test "named cancellation conserves permits and queued FIFO across drain failure" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x43} ** 32));
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x44} ** 32));
    const remote_pubkey = secp.compressedPubkey(&remote_key);
    const remote_id = try enr.nodeIdFromCompressedPubkey(&remote_pubkey);
    const endpoint = types.Endpoint{
        .node_id = remote_id,
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 4 }, .port = 9004 } },
    };
    const cfg = config.Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
        .rate_limiter = null,
        .limits = .{ .max_active_requests = 4, .max_queued_requests = 4, .event_capacity = 4, .command_capacity = 4 },
    };
    var harness = try ActorHarness.init(alloc, io, cfg);
    defer harness.deinit();
    const actor = &harness.actor;

    const first = try actor_mod.Testing.sendPingResolvedForTest(&actor, harness.env(), endpoint, &remote_pubkey, .api);
    try harness.drainEffects();
    const second = try actor_mod.Testing.sendPingResolvedForTest(&actor, harness.env(), endpoint, &remote_pubkey, .api);
    const third = try actor_mod.Testing.sendPingResolvedForTest(&actor, harness.env(), endpoint, &remote_pubkey, .api);
    try std.testing.expectEqual(@as(usize, 1), harness.ingress.permitCount());
    try std.testing.expectEqual(@as(usize, 2), actor.requests.queuedCount());

    try std.testing.expect(actor.cancelRequest(harness.env(), second));
    try std.testing.expectEqual(@as(usize, 1), harness.ingress.permitCount());
    try std.testing.expectEqual(@as(usize, 1), actor.requests.queuedCount());

    harness.recording.fail_next = true;
    try std.testing.expect(actor.cancelRequest(harness.env(), first));
    try std.testing.expect(!actor.cancelRequest(harness.env(), first));
    try std.testing.expectError(error.TransportSendFailed, harness.drainEffects());
    try std.testing.expectEqual(@as(usize, 0), harness.ingress.permitCount());
    try std.testing.expectEqual(@as(usize, 0), actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 1), actor.requests.queuedCount());
    try std.testing.expectEqual(@as(usize, 1), harness.recording.datagrams.items.len);

    const stable = session_book.StableSession{
        .initiator_key = [_]u8{0x51} ** 16,
        .recipient_key = [_]u8{0x52} ** 16,
    };
    actor.sessions.put(endpoint, stable, outbound.nowNs(io));
    outbound.drainEndpoint(actor, harness.env(), endpoint);
    try harness.drainEffects();
    try std.testing.expectEqual(@as(usize, 0), actor.requests.queuedCount());
    try std.testing.expectEqual(@as(usize, 1), actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 1), harness.ingress.permitCount());
    try std.testing.expectEqual(@as(usize, 2), harness.recording.datagrams.items.len);
    try std.testing.expectEqualSlices(u8, third.key.req_id.slice(), (try decodeSentPing(&harness.recording.datagrams.items[1].bytes, &remote_id, &stable.initiator_key)).req_id.slice());
}

test "maintenance automatically redrains a queued lane after one transient send failure" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x99} ** 32));
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x9a} ** 32));
    const remote_pubkey = secp.compressedPubkey(&remote_key);
    const remote_id = try enr.nodeIdFromCompressedPubkey(&remote_pubkey);
    const endpoint = types.Endpoint{
        .node_id = remote_id,
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 44 }, .port = 9244 } },
    };
    const cfg = config.Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
        .request_timeout_ms = 60_000,
        .rate_limiter = null,
        .limits = .{
            .max_active_requests = 2,
            .max_queued_requests = 2,
            .max_queued_requests_per_endpoint = 2,
            .event_capacity = 2,
            .command_capacity = 2,
        },
    };
    var harness = try ActorHarness.init(alloc, io, cfg);
    defer harness.deinit();
    const actor = &harness.actor;

    const first = try actor_mod.Testing.sendPingResolvedForTest(&actor, harness.env(), endpoint, &remote_pubkey, .api);
    try harness.drainEffects();
    const second = try actor_mod.Testing.sendPingResolvedForTest(&actor, harness.env(), endpoint, &remote_pubkey, .api);
    try std.testing.expectEqual(@as(usize, 1), actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 1), actor.requests.queuedCount());

    const stable = session_book.StableSession{
        .initiator_key = [_]u8{0xc1} ** 16,
        .recipient_key = [_]u8{0xc2} ** 16,
    };
    actor.sessions.put(endpoint, stable, outbound.nowNs(io));
    harness.recording.fail_next = true;
    try std.testing.expect(actor.cancelRequest(harness.env(), first));
    try std.testing.expectError(error.TransportSendFailed, harness.drainEffects());
    try std.testing.expectEqual(@as(usize, 0), actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 1), actor.requests.queuedCount());
    try std.testing.expectEqual(@as(usize, 0), harness.ingress.permitCount());

    actor.maintenance(harness.env());
    try harness.drainEffects();
    try std.testing.expectEqual(@as(usize, 1), actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 0), actor.requests.queuedCount());
    try std.testing.expectEqual(@as(usize, 1), harness.ingress.permitCount());
    try std.testing.expectEqual(@as(usize, 2), harness.recording.datagrams.items.len);
    try std.testing.expectEqual(@as(u64, 2), actor.metrics.sent_message_count[metrics.MessageType.ping.index()]);
    const retried = try decodeSentPing(&harness.recording.datagrams.items[1].bytes, &remote_id, &stable.initiator_key);
    try std.testing.expectEqualSlices(u8, second.key.req_id.slice(), retried.req_id.slice());
}

fn decodeSentPing(datagram: *const types.PacketBytes, recipient_id: *const types.NodeId, write_key: *const [16]u8) !message.Ping {
    var raw = datagram.*;
    const parsed = try packet.decode(raw.bytes[0..raw.len], recipient_id);
    var plaintext_buffer: [packet.MAX_PACKET_SIZE]u8 = undefined;
    var ad_buffer: [packet.MAX_PACKET_SIZE]u8 = undefined;
    const plaintext = try packet.decryptMessageInto(
        &plaintext_buffer,
        &ad_buffer,
        write_key,
        &parsed.static_header.nonce,
        parsed.message_ciphertext,
        &parsed.masking_iv,
        parsed.header_raw,
    );
    return message.Ping.decode(plaintext);
}

test "queued request expires exactly at its actor maintenance deadline" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0xa1} ** 32));
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0xa2} ** 32));
    const remote_pubkey = secp.compressedPubkey(&remote_key);
    const endpoint = types.Endpoint{
        .node_id = try enr.nodeIdFromCompressedPubkey(&remote_pubkey),
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 62 }, .port = 9062 } },
    };
    const cfg = config.Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
        .request_timeout_ms = 60_000,
        .request_retries = 1,
        .rate_limiter = null,
        .limits = .{
            .max_active_requests = 1,
            .max_queued_requests = 1,
            .max_queued_requests_per_endpoint = 1,
            .event_capacity = 1,
            .command_capacity = 1,
        },
    };
    var harness = try ActorHarness.init(alloc, io, cfg);
    defer harness.deinit();
    const actor = &harness.actor;

    const active_req_id = try actor_mod.Testing.sendPingResolvedForTest(&actor, harness.env(), endpoint, &remote_pubkey, .api);
    try harness.drainEffects();
    const queued_req_id = try actor_mod.Testing.sendPingResolvedForTest(&actor, harness.env(), endpoint, &remote_pubkey, .api);
    const active_key = active_req_id.key;
    const queued_key = queued_req_id.key;
    const active_deadline_ns = actor.requests.get(active_key).?.deadline_ns;
    const queued = (actor.requests.lanes.get(endpoint) orelse return error.MissingQueuedLane).queued.first() orelse return error.MissingQueuedRequest;
    const queued_deadline_ns = queued.deadline_ns;
    try std.testing.expect(types.RequestKeyContext.eql(.{}, queued_key, .init(queued.endpoint, queued.req_id)));
    try std.testing.expect(active_deadline_ns <= queued_deadline_ns);
    try std.testing.expectEqual(@as(usize, 1), actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 1), actor.requests.queuedCount());
    try std.testing.expectEqual(@as(usize, 1), harness.ingress.permitCount());
    try std.testing.expectEqual(@as(usize, 1), harness.recording.datagrams.items.len);
    try std.testing.expect(harness.outbox.pop() == null);

    actor.maintenanceAt(harness.env(), queued_deadline_ns - 1);
    harness.drainEffectsIgnoringFailures();
    const queued_before_deadline = (actor.requests.lanes.get(endpoint) orelse return error.MissingQueuedLane).queued.first() orelse return error.QueuedExpiredEarly;
    try std.testing.expect(types.RequestKeyContext.eql(.{}, queued_key, .init(queued_before_deadline.endpoint, queued_before_deadline.req_id)));
    try std.testing.expect(actor.requests.get(active_key) != null);
    try std.testing.expectEqual(@as(usize, 1), actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 1), actor.requests.queuedCount());
    try std.testing.expectEqual(@as(usize, 1), harness.ingress.permitCount());
    const datagrams_before_boundary: usize = if (active_deadline_ns < queued_deadline_ns) 2 else 1;
    try std.testing.expectEqual(datagrams_before_boundary, harness.recording.datagrams.items.len);
    try std.testing.expect(harness.outbox.pop() == null);

    actor.maintenanceAt(harness.env(), queued_deadline_ns);
    harness.drainEffectsIgnoringFailures();
    try std.testing.expect(actor.requests.get(active_key) != null);
    try std.testing.expectEqual(@as(usize, 0), actor.requests.lanes.get(endpoint).?.queued.len());
    try std.testing.expectEqual(@as(usize, 1), actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 0), actor.requests.queuedCount());
    try std.testing.expectEqual(@as(usize, 1), harness.ingress.permitCount());
    try std.testing.expectEqual(@as(usize, 2), harness.recording.datagrams.items.len);
    try std.testing.expect(harness.outbox.pop() == null);
}

test "copied retained retry completion commits actor metric once" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x47} ** 32));
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x48} ** 32));
    const remote_pubkey = secp.compressedPubkey(&remote_key);
    const endpoint = types.Endpoint{
        .node_id = try enr.nodeIdFromCompressedPubkey(&remote_pubkey),
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 48 }, .port = 9048 } },
    };
    const cfg = config.Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
        .request_timeout_ms = 1,
        .request_retries = 1,
        .rate_limiter = null,
        .limits = .{ .max_active_requests = 2, .max_queued_requests = 2, .event_capacity = 2, .command_capacity = 2 },
    };
    var harness = try ActorHarness.init(alloc, io, cfg);
    defer harness.deinit();
    const actor = &harness.actor;
    const request = try actor_mod.Testing.sendPingResolvedForTest(&actor, harness.env(), endpoint, &remote_pubkey, .api);
    try harness.drainEffects();
    const deadline = actor.requests.get(request.key).?.deadline_ns;
    actor.maintenanceAt(harness.env(), deadline);
    const effect = harness.effects.pop() orelse return error.MissingRetryEffect;
    const copied = effect;

    actor.applyEffectCompletion(harness.env(), effect, .sent);
    actor.applyEffectCompletion(harness.env(), copied, .sent);
    try std.testing.expectEqual(@as(u32, 1), actor.requests.get(request.key).?.attempts);
    try std.testing.expectEqual(@as(u64, 2), actor.metrics.sent_message_count[metrics.MessageType.ping.index()]);
}

test "fresh retry generation exhaustion preflights before actor side effects" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0xb3} ** 32));
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0xb4} ** 32));
    const remote_pubkey = secp.compressedPubkey(&remote_key);
    const endpoint = types.Endpoint{
        .node_id = try enr.nodeIdFromCompressedPubkey(&remote_pubkey),
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 73 }, .port = 9073 } },
    };
    const sentinel_endpoint = types.Endpoint{
        .node_id = [_]u8{0xb5} ** 32,
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 74 }, .port = 9074 } },
    };
    const cfg = config.Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
        .request_timeout_ms = 1,
        .request_retries = 1,
        .rate_limiter = null,
        .limits = .{ .max_active_requests = 2, .max_queued_requests = 2, .event_capacity = 2, .command_capacity = 2 },
    };
    var harness = try ActorHarness.init(alloc, io, cfg);
    defer harness.deinit();
    const actor = &harness.actor;
    actor.sessions.put(endpoint, .{ .initiator_key = [_]u8{7} ** 16, .recipient_key = [_]u8{8} ** 16 }, outbound.nowNs(io));
    const handle = try actor_mod.Testing.sendPingResolvedForTest(&actor, harness.env(), endpoint, &remote_pubkey, .api);
    try harness.drainEffects();
    const deadline = actor.requests.get(handle.key).?.deadline_ns;
    response_book.ResponseBook.Testing.putCandidate(&actor.responses, sentinel_endpoint, .{
        .initiator_key = [_]u8{9} ** 16,
        .recipient_key = [_]u8{10} ** 16,
    }, deadline);
    request_book.Testing.exhaustRetryGeneration(&actor.requests);

    const before = actor.requests.get(handle.key).?.*;
    const response_count = actor.responses.count();
    const permit_count = harness.ingress.permitCount();
    const permit_fingerprint = admission.IngressAdmission.Testing.permitGenerationFingerprint(&harness.ingress);
    const actor_metrics = actor.metrics;
    const effect_count = harness.effects.count();

    actor.maintenanceAt(harness.env(), deadline);

    const after = actor.requests.get(handle.key) orelse return error.MissingActiveRequest;
    try std.testing.expect(std.meta.eql(before, after.*));
    try std.testing.expectEqual(response_count, actor.responses.count());
    try std.testing.expect(response_book.ResponseBook.Testing.hasCandidate(&actor.responses, sentinel_endpoint));
    try std.testing.expectEqual(permit_count, harness.ingress.permitCount());
    try std.testing.expectEqual(permit_fingerprint, admission.IngressAdmission.Testing.permitGenerationFingerprint(&harness.ingress));
    try std.testing.expect(std.meta.eql(actor_metrics, actor.metrics));
    try std.testing.expectEqual(effect_count, harness.effects.count());
}

test "retry FIFO rejection resolves exact generation and preserves retry policy" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x49} ** 32));
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x4a} ** 32));
    const remote_pubkey = secp.compressedPubkey(&remote_key);
    const endpoint = types.Endpoint{
        .node_id = try enr.nodeIdFromCompressedPubkey(&remote_pubkey),
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 49 }, .port = 9049 } },
    };
    const cfg = config.Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
        .request_timeout_ms = 1,
        .request_retries = 1,
        .rate_limiter = null,
        .limits = .{ .max_active_requests = 2, .max_queued_requests = 2, .event_capacity = 2, .command_capacity = 2 },
    };
    var harness = try ActorHarness.init(alloc, io, cfg);
    defer harness.deinit();
    const actor = &harness.actor;
    const request = try actor_mod.Testing.sendPingResolvedForTest(&actor, harness.env(), endpoint, &remote_pubkey, .api);
    const initial = harness.effects.pop() orelse return error.MissingInitialEffect;
    const filler = initial;
    actor.applyEffectCompletion(harness.env(), initial, .sent);
    const first_deadline = actor.requests.get(request.key).?.deadline_ns;

    var full_storage: [1]actor_mod.ActorEffect = undefined;
    var full_effects = actor_mod.EffectQueue.init(&full_storage);
    try full_effects.push(filler);
    var full_env = harness.env();
    full_env.effects = &full_effects;
    actor.maintenanceAt(full_env, first_deadline);

    const active = actor.requests.get(request.key) orelse return error.MissingActiveRequest;
    try std.testing.expectEqual(@as(u32, 1), active.attempts);
    try std.testing.expect(active.deadline_ns > first_deadline);
    try std.testing.expectEqual(@as(usize, 1), harness.ingress.permitCount());
    try std.testing.expectEqual(@as(usize, 1), full_effects.count());
    actor.applyEffectCompletion(full_env, full_effects.pop().?, .failed);
    try std.testing.expectEqual(@as(u32, 1), actor.requests.get(request.key).?.attempts);
}

test "fresh retry FIFO rejection restores prior state and releases prepared permit" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0xb6} ** 32));
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0xb7} ** 32));
    const remote_pubkey = secp.compressedPubkey(&remote_key);
    const endpoint = types.Endpoint{
        .node_id = try enr.nodeIdFromCompressedPubkey(&remote_pubkey),
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 75 }, .port = 9075 } },
    };
    const cfg = config.Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
        .request_timeout_ms = 1,
        .request_retries = 1,
        .rate_limiter = null,
        .limits = .{ .max_active_requests = 1, .max_queued_requests = 1, .event_capacity = 2, .command_capacity = 1 },
    };
    var harness = try ActorHarness.init(alloc, io, cfg);
    defer harness.deinit();
    const actor = &harness.actor;
    actor.sessions.put(endpoint, .{ .initiator_key = [_]u8{11} ** 16, .recipient_key = [_]u8{12} ** 16 }, outbound.nowNs(io));
    const request = try actor_mod.Testing.sendFindNodeResolvedForTest(&actor, harness.env(), endpoint, &remote_pubkey, &.{1}, .api);
    const initial = harness.effects.pop() orelse return error.MissingInitialEffect;
    const filler = initial;
    actor.applyEffectCompletion(harness.env(), initial, .sent);
    const active_before = actor.requests.get(request.key) orelse return error.MissingActiveRequest;
    active_before.response.nodes.total_responses = 7;
    active_before.response.nodes.responses_received = 3;
    const phase_before = active_before.phase;
    const deadline_before = active_before.deadline_ns;
    const sent_before = actor.metrics.sent_message_count[metrics.MessageType.findnode.index()];

    var full_storage: [1]actor_mod.ActorEffect = undefined;
    var full_effects = actor_mod.EffectQueue.init(&full_storage);
    try full_effects.push(filler);
    var full_env = harness.env();
    full_env.effects = &full_effects;
    actor.maintenanceAt(full_env, deadline_before);

    const restored = actor.requests.get(request.key) orelse return error.MissingActiveRequest;
    try std.testing.expect(std.meta.eql(phase_before, restored.phase));
    try std.testing.expectEqual(@as(u64, 7), restored.response.nodes.total_responses.?);
    try std.testing.expectEqual(@as(u64, 3), restored.response.nodes.responses_received);
    try std.testing.expectEqual(@as(u32, 1), restored.attempts);
    try std.testing.expect(restored.deadline_ns > deadline_before);
    try std.testing.expectEqual(@as(usize, 1), harness.ingress.permitCount());
    try std.testing.expectEqual(sent_before, actor.metrics.sent_message_count[metrics.MessageType.findnode.index()]);
    try std.testing.expectEqual(@as(usize, 1), full_effects.count());

    const stale = full_effects.pop() orelse return error.MissingFillerEffect;
    try std.testing.expect(std.meta.eql(filler, stale));
    actor.applyEffectCompletion(full_env, stale, .failed);
    const after_stale = actor.requests.get(request.key) orelse return error.MissingActiveRequest;
    try std.testing.expect(std.meta.eql(phase_before, after_stale.phase));
    try std.testing.expectEqual(@as(u64, 7), after_stale.response.nodes.total_responses.?);
    try std.testing.expectEqual(@as(u64, 3), after_stale.response.nodes.responses_received);
    try std.testing.expectEqual(@as(u32, 1), after_stale.attempts);
    try std.testing.expectEqual(@as(usize, 1), harness.ingress.permitCount());
    try std.testing.expectEqual(sent_before, actor.metrics.sent_message_count[metrics.MessageType.findnode.index()]);
}

test "exact cancellation of prepared fresh retry releases both permits and invalidates copy" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x4b} ** 32));
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x4c} ** 32));
    const remote_pubkey = secp.compressedPubkey(&remote_key);
    const endpoint = types.Endpoint{
        .node_id = try enr.nodeIdFromCompressedPubkey(&remote_pubkey),
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 50 }, .port = 9050 } },
    };
    const cfg = config.Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
        .request_timeout_ms = 1,
        .request_retries = 1,
        .rate_limiter = null,
        .limits = .{ .max_active_requests = 2, .max_queued_requests = 2, .event_capacity = 2, .command_capacity = 2 },
    };
    var harness = try ActorHarness.init(alloc, io, cfg);
    defer harness.deinit();
    const actor = &harness.actor;
    actor.sessions.put(endpoint, .{ .initiator_key = [_]u8{5} ** 16, .recipient_key = [_]u8{6} ** 16 }, outbound.nowNs(io));
    const request = try actor_mod.Testing.sendPingResolvedForTest(&actor, harness.env(), endpoint, &remote_pubkey, .api);
    try harness.drainEffects();
    const nonce = actor.requests.get(request.key).?.phase.awaiting_response.recovery.nonce;
    actor.maintenanceAt(harness.env(), actor.requests.get(request.key).?.deadline_ns);
    const retry = harness.effects.pop() orelse return error.MissingRetryEffect;
    const copied = retry;
    const sent_before = actor.metrics.sent_message_count[metrics.MessageType.ping.index()];
    try std.testing.expect(actor.requests.hasChallenge(&nonce, endpoint.addr));
    try std.testing.expectEqual(@as(usize, 2), harness.ingress.permitCount());

    try std.testing.expect(actor.cancelRequest(harness.env(), request));
    try std.testing.expect(!actor.cancelRequest(harness.env(), request));
    try std.testing.expect(actor.requests.get(request.key) == null);
    try std.testing.expect(!actor.requests.hasChallenge(&nonce, endpoint.addr));
    try std.testing.expect(actor.requests.lanes.get(endpoint) == null);
    try std.testing.expectEqual(@as(usize, 0), harness.ingress.permitCount());
    try std.testing.expect(harness.outbox.pop() == null);

    actor.applyEffectCompletion(harness.env(), copied, .sent);
    try std.testing.expect(actor.requests.get(request.key) == null);
    try std.testing.expectEqual(@as(usize, 0), harness.ingress.permitCount());
    try std.testing.expectEqual(sent_before, actor.metrics.sent_message_count[metrics.MessageType.ping.index()]);
    try std.testing.expect(harness.outbox.pop() == null);
}

test "AdmissionPermit survives retry and releases on final timeout" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x45} ** 32));
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x46} ** 32));
    const remote_pubkey = secp.compressedPubkey(&remote_key);
    const endpoint = types.Endpoint{
        .node_id = try enr.nodeIdFromCompressedPubkey(&remote_pubkey),
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 6 }, .port = 9006 } },
    };
    const cfg = config.Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
        .request_timeout_ms = 1,
        .request_retries = 1,
        .rate_limiter = null,
        .limits = .{ .max_active_requests = 2, .max_queued_requests = 2, .event_capacity = 2, .command_capacity = 2 },
    };
    var harness = try ActorHarness.init(alloc, io, cfg);
    defer harness.deinit();
    const actor = &harness.actor;
    actor.sessions.put(endpoint, .{ .initiator_key = [_]u8{1} ** 16, .recipient_key = [_]u8{2} ** 16 }, outbound.nowNs(io));
    const req_id = try actor_mod.Testing.sendPingResolvedForTest(&actor, harness.env(), endpoint, &remote_pubkey, .api);
    try harness.drainEffects();
    try std.testing.expectEqual(@as(usize, 1), harness.ingress.permitCount());
    try std.testing.expectEqual(@as(u64, 1), actor.metrics.sent_message_count[metrics.MessageType.ping.index()]);

    const first_deadline_ns = actor.requests.get(req_id.key).?.deadline_ns;
    actor.maintenanceAt(harness.env(), first_deadline_ns);
    harness.drainEffectsIgnoringFailures();
    try std.testing.expectEqual(@as(usize, 1), actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 1), harness.ingress.permitCount());
    try std.testing.expectEqual(@as(usize, 2), harness.recording.datagrams.items.len);
    try std.testing.expectEqual(@as(u64, 2), actor.metrics.sent_message_count[metrics.MessageType.ping.index()]);

    const retry_deadline_ns = actor.requests.get(req_id.key).?.deadline_ns;
    actor.maintenanceAt(harness.env(), retry_deadline_ns);
    harness.drainEffectsIgnoringFailures();
    try std.testing.expectEqual(@as(usize, 0), actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 0), harness.ingress.permitCount());
    try std.testing.expect(harness.outbox.pop() == null);
}

test "fresh FINDNODE retry resets multipart generation and swaps one permit" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x18} ** 32));
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x19} ** 32));
    const remote_pubkey = secp.compressedPubkey(&remote_key);
    const remote_id = try enr.nodeIdFromCompressedPubkey(&remote_pubkey);
    const endpoint = types.Endpoint{
        .node_id = remote_id,
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 25 }, .port = 9025 } },
    };
    const discovered_key_a = try secp.keyPairFromSecret(&([_]u8{0x1a} ** 32));
    var builder_a = enr.Builder.init(alloc, discovered_key_a, 1);
    builder_a.ip = .{ 127, 0, 0, 26 };
    builder_a.udp = 9026;
    const raw_a = try builder_a.encode();
    defer alloc.free(raw_a);
    const id_a = (try (try enr.decode(raw_a)).nodeId()).?;
    const discovered_key_b = try secp.keyPairFromSecret(&([_]u8{0x1b} ** 32));
    var builder_b = enr.Builder.init(alloc, discovered_key_b, 1);
    builder_b.ip = .{ 127, 0, 0, 27 };
    builder_b.udp = 9027;
    const raw_b = try builder_b.encode();
    defer alloc.free(raw_b);
    const id_b = (try (try enr.decode(raw_b)).nodeId()).?;
    const distance_a: u16 = if (peer_store.logDistance(&id_a, &remote_id)) |value| @as(u16, value) + 1 else 0;
    const distance_b: u16 = if (peer_store.logDistance(&id_b, &remote_id)) |value| @as(u16, value) + 1 else 0;
    const cfg = config.Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
        .request_timeout_ms = 1,
        .request_retries = 1,
        .rate_limiter = null,
        .limits = .{
            .max_active_requests = 1,
            .max_queued_requests = 1,
            .challenge_capacity = 1,
            .response_recovery_capacity = 1,
            .event_capacity = 4,
            .command_capacity = 1,
        },
    };
    var harness = try ActorHarness.init(alloc, io, cfg);
    defer harness.deinit();
    const actor = &harness.actor;
    const stable = session_book.StableSession{
        .initiator_key = [_]u8{0x1c} ** 16,
        .recipient_key = [_]u8{0x1d} ** 16,
    };
    actor.sessions.put(endpoint, stable, outbound.nowNs(io));
    const req_id = try actor_mod.Testing.sendFindNodeResolvedForTest(
        &actor,
        harness.env(),
        endpoint,
        &remote_pubkey,
        &.{ distance_a, distance_b },
        .api,
    );
    try harness.drainEffects();
    try std.testing.expectEqual(@as(usize, 1), harness.ingress.permitCount());

    var first_buffer: [packet.MAX_PACKET_SIZE]u8 = undefined;
    const first = message.Nodes{ .req_id = req_id.key.req_id, .total = 2, .enrs = &.{raw_a} };
    const first_plaintext = try first.encodeInto(&first_buffer);
    try deliverEncrypted(actor, io, harness.recording.sender(), &harness.ingress, &harness.outbox, endpoint, &stable.recipient_key, first_plaintext, 0x21);
    const partial = &actor.requests.get(req_id.key).?.response.nodes;
    try std.testing.expectEqual(@as(u64, 2), partial.total_responses.?);
    try std.testing.expectEqual(@as(u64, 1), partial.responses_received);
    try std.testing.expectEqual(@as(usize, 1), partial.validated_enrs.slice().len);

    const deadline_ns = actor.requests.get(req_id.key).?.deadline_ns;
    actor.maintenanceAt(harness.env(), deadline_ns);
    harness.drainEffectsIgnoringFailures();
    const fresh = &actor.requests.get(req_id.key).?.response.nodes;
    try std.testing.expect(fresh.total_responses == null);
    try std.testing.expectEqual(@as(u64, 0), fresh.responses_received);
    try std.testing.expectEqual(@as(usize, 0), fresh.validated_enrs.slice().len);
    try std.testing.expectEqual(@as(usize, 1), harness.ingress.permitCount());

    try deliverEncrypted(actor, io, harness.recording.sender(), &harness.ingress, &harness.outbox, endpoint, &stable.recipient_key, first_plaintext, 0x22);
    const repeated = &actor.requests.get(req_id.key).?.response.nodes;
    try std.testing.expectEqual(@as(u64, 1), repeated.responses_received);
    try std.testing.expectEqual(@as(usize, 1), repeated.validated_enrs.slice().len);
    try std.testing.expectEqual(id_a, repeated.validated_enrs.slice()[0].node_id);
    try std.testing.expectEqual(@as(usize, 1), actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 1), harness.ingress.permitCount());

    var final_buffer: [packet.MAX_PACKET_SIZE]u8 = undefined;
    const final = message.Nodes{ .req_id = req_id.key.req_id, .total = 2, .enrs = &.{raw_b} };
    try deliverEncrypted(actor, io, harness.recording.sender(), &harness.ingress, &harness.outbox, endpoint, &stable.recipient_key, try final.encodeInto(&final_buffer), 0x23);
    try std.testing.expectEqual(@as(usize, 0), actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 0), harness.ingress.permitCount());
    var discovered_count: usize = 0;
    var processed: usize = 0;
    while (processed < cfg.limits.event_capacity) : (processed += 1) {
        var event = harness.outbox.pop() orelse break;
        try std.testing.expect(event == .discovered_enr);
        discovered_count += 1;
        event.deinit(alloc);
    }
    try std.testing.expectEqual(@as(usize, 3), discovered_count);
    try std.testing.expect(actor.peers.findEnr(&id_a) != null);
    try std.testing.expect(actor.peers.findEnr(&id_b) != null);
}

test "Actor rejects invalid FINDNODE distance before request or send state" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x79} ** 32));
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x7a} ** 32));
    const remote_pubkey = secp.compressedPubkey(&remote_key);
    const remote_id = try enr.nodeIdFromCompressedPubkey(&remote_pubkey);
    const endpoint = types.Endpoint{
        .node_id = remote_id,
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 79 }, .port = 9_079 } },
    };
    const cfg = config.Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
        .rate_limiter = null,
        .limits = .{ .max_active_requests = 2, .max_queued_requests = 2, .event_capacity = 2, .command_capacity = 2 },
    };
    var harness = try ActorHarness.init(alloc, io, cfg);
    defer harness.deinit();

    try std.testing.expectError(
        error.InvalidDistance,
        actor_mod.Testing.sendFindNodeResolvedForTest(&harness.actor, harness.env(), endpoint, &remote_pubkey, &.{257}, .api),
    );
    try std.testing.expectEqual(@as(usize, 0), harness.actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 0), harness.actor.requests.queuedCount());
    try std.testing.expectEqual(@as(usize, 0), harness.ingress.permitCount());
    try std.testing.expectEqual(@as(usize, 0), harness.recording.datagrams.items.len);
}
