const std = @import("std");
const actor_mod = @import("actor.zig");
const completion = @import("flow/completion.zig");
const admission = @import("admission.zig");
const config = @import("config.zig");
const enr = @import("enr.zig");
const events = @import("events.zig");
const outbound = @import("flow/outbound.zig");
const lookup_mod = @import("service/lookup.zig");
const packet = @import("protocol/packet.zig");
const message = @import("protocol/message.zig");
const metrics = @import("metrics.zig");
const secp = @import("secp256k1.zig");
const request_book = @import("state/request_book.zig");
const session_book = @import("state/session_book.zig");
const transport = @import("transport.zig");
const types = @import("types.zig");

test "request completion has one canonical finish path" {
    try std.testing.expect(@hasDecl(completion, "finish"));
    try std.testing.expect(!@hasDecl(completion, "apply"));
    try std.testing.expect(!@hasDecl(completion, "cancel"));
}

test "Actor isolates health identity and arms exact eviction probes" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x41} ** 32));
    const local_id = enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&local_key));
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x42} ** 32));
    const remote_pubkey = secp.compressedPubkey(&remote_key);
    var remote_builder = enr.Builder.init(alloc, remote_key, 1);
    remote_builder.ip = .{ 127, 0, 0, 2 };
    remote_builder.udp = 9000;
    const remote_enr = try remote_builder.encode();
    defer alloc.free(remote_enr);
    const remote_id = (try enr.decode(remote_enr)).nodeId().?;
    const address = types.Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 2 }, .port = 9000 } };
    const endpoint = types.Endpoint{ .node_id = remote_id, .addr = address };
    const cfg = config.Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
        .local_node_id = local_id,
        .rate_limiter = null,
        .limits = .{ .max_active_requests = 4, .max_queued_requests = 4, .event_capacity = 8, .command_capacity = 4 },
    };
    var ingress = try admission.IngressAdmission.init(alloc, null, cfg.limits.max_active_requests);
    defer ingress.deinit();
    var outbox = try events.EventOutbox.init(io, alloc, cfg.limits.event_capacity);
    defer outbox.deinit();
    var actor = try actor_mod.Actor.init(alloc, cfg);
    defer actor.deinit(&ingress);
    var recording = transport.RecordingSender.init(alloc);
    defer recording.deinit();
    try std.testing.expect(actor.peers.learnEnr(remote_enr, 0) != null);
    _ = actor.peers.markResponsive(remote_id, address, 0, null);

    const health = types.RequestKey.init(endpoint, try message.ReqId.fromSlice(&.{1}));
    const unrelated = types.RequestKey.init(endpoint, try message.ReqId.fromSlice(&.{2}));
    const newer = types.RequestKey.init(endpoint, try message.ReqId.fromSlice(&.{3}));
    try std.testing.expect(actor.peers.armHealthRequest(health, .connected_only));
    actor.onRequestCompletion(.{ .io = io, .sender = recording.sender(), .ingress = &ingress, .outbox = &outbox }, unrelated, .api, true, &.{});
    try expectActorHealthRequest(&actor, remote_id, health);
    actor.onRequestCompletion(.{ .io = io, .sender = recording.sender(), .ingress = &ingress, .outbox = &outbox }, health, .api, false, &.{});
    try expectActorHealthRequest(&actor, remote_id, health);
    actor.onRequestCompletion(.{ .io = io, .sender = recording.sender(), .ingress = &ingress, .outbox = &outbox }, health, .{ .maintenance = .enr_refresh }, false, &.{});
    try expectActorHealthRequest(&actor, remote_id, health);

    try std.testing.expect(!actor.peers.armHealthRequest(newer, .connected_only));
    actor.onRequestCompletion(.{ .io = io, .sender = recording.sender(), .ingress = &ingress, .outbox = &outbox }, unrelated, .{ .maintenance = .health }, false, &.{});
    try expectActorHealthRequest(&actor, remote_id, health);
    actor.onRequestCompletion(.{ .io = io, .sender = recording.sender(), .ingress = &ingress, .outbox = &outbox }, health, .{ .maintenance = .health }, true, &.{});
    try std.testing.expect(actor.peers.routing.getEntry(&remote_id).?.health_request == null);

    try std.testing.expect(actor.peers.armHealthRequest(newer, .connected_only));
    actor.onRequestCompletion(.{ .io = io, .sender = recording.sender(), .ingress = &ingress, .outbox = &outbox }, newer, .{ .maintenance = .eviction }, false, &.{});
    // Exact-candidate eviction timeout on a still-connected entry keeps the
    // incumbent (liveness proven by other authenticated traffic) and only
    // releases the probe reservation.
    try std.testing.expectEqual(@import("kbucket.zig").EntryStatus.connected, actor.peers.routing.getEntry(&remote_id).?.status);
    try std.testing.expect(actor.peers.routing.getEntry(&remote_id).?.health_request == null);
    _ = actor.peers.markResponsive(remote_id, address, 0, null);
    const candidate = actor.peers.routing.getEntry(&remote_id).?.*;
    actor.probeEviction(.{ .io = io, .sender = recording.sender(), .ingress = &ingress, .outbox = &outbox }, candidate);
    const eviction_key = actor.peers.routing.getEntry(&remote_id).?.health_request orelse return error.MissingEvictionHealthRequest;
    try std.testing.expect(types.EndpointContext.eql(.{}, eviction_key.endpoint, endpoint));
    const request = actor.requests.get(eviction_key) orelse return error.MissingEvictionRequest;
    switch (request.origin) {
        .maintenance => |reason| try std.testing.expectEqual(types.MaintenanceReason.eviction, reason),
        else => return error.WrongEvictionRequestOrigin,
    }
    try std.testing.expectEqual(remote_pubkey, actor.peers.known(&remote_id).?.pubkey);
}

test "stale eviction candidate fails reservation before any send or permit" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x34} ** 32));
    const local_id = enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&local_key));
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x35} ** 32));
    const remote_pubkey = secp.compressedPubkey(&remote_key);
    const remote_id = enr.nodeIdFromCompressedPubkey(&remote_pubkey);
    const address_a = types.Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 8 }, .port = 9006 } };
    const address_b = types.Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 9 }, .port = 9007 } };
    const cfg = config.Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
        .local_node_id = local_id,
        .rate_limiter = null,
        .limits = .{ .max_active_requests = 2, .max_queued_requests = 2, .event_capacity = 2, .command_capacity = 2 },
    };
    var ingress = try admission.IngressAdmission.init(alloc, null, cfg.limits.max_active_requests);
    defer ingress.deinit();
    var actor = try actor_mod.Actor.init(alloc, cfg);
    defer actor.deinit(&ingress);
    var outbox = try events.EventOutbox.init(io, alloc, cfg.limits.event_capacity);
    defer outbox.deinit();
    var recording = transport.RecordingSender.init(alloc);
    defer recording.deinit();
    try std.testing.expect(actor.addNode(remote_id, &remote_pubkey, address_b, null, outbound.nowNs(io)));
    const stale = @import("kbucket.zig").Entry{
        .node_id = remote_id,
        .pubkey = remote_pubkey,
        .addr = address_a,
        .last_seen = 0,
        .status = .connected,
    };

    actor.probeEviction(.{ .io = io, .sender = recording.sender(), .ingress = &ingress, .outbox = &outbox }, stale);
    try std.testing.expectEqual(@as(usize, 0), actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 0), ingress.permitCount());
}

const EvictionHarness = struct {
    ingress: admission.IngressAdmission,
    outbox: events.EventOutbox,
    actor: actor_mod.Actor,
    recording: transport.RecordingSender,
    candidate: @import("kbucket.zig").Entry,
    candidate_key: secp.KeyPair,
    candidate_id: types.NodeId,
    candidate_endpoint: types.Endpoint,
    pending_id: types.NodeId,
    bucket_distance: u8,

    const kbucket_mod = @import("kbucket.zig");

    fn init(alloc: std.mem.Allocator, io: std.Io) !EvictionHarness {
        const local_key = try secp.keyPairFromSecret(&([_]u8{0x25} ** 32));
        const local_id = enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&local_key));
        const candidate_key = try secp.keyPairFromSecret(&([_]u8{0x26} ** 32));
        const candidate_pubkey = secp.compressedPubkey(&candidate_key);
        const candidate_id = enr.nodeIdFromCompressedPubkey(&candidate_pubkey);
        const distance = kbucket_mod.logDistance(&local_id, &candidate_id) orelse return error.SameNodeId;
        // Low-byte variations below preserve the bucket only when the highest
        // differing bit is far above them.
        try std.testing.expect(distance > 64);
        const candidate_addr = types.Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 51 }, .port = 9051 } };
        const cfg = config.Config{
            .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
            .local_key_pair = local_key,
            .local_node_id = local_id,
            .request_timeout_ms = 1,
            .request_retries = 0,
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

        // Fill the candidate's bucket: the real candidate first (learned via
        // a valid ENR like production peers), then K - 1 fabricated
        // disconnected peers in the same bucket.
        var candidate_builder = enr.Builder.init(alloc, candidate_key, 1);
        candidate_builder.ip = candidate_addr.ip4.bytes;
        candidate_builder.udp = candidate_addr.ip4.port;
        const candidate_enr = try candidate_builder.encode();
        defer alloc.free(candidate_enr);
        try std.testing.expect(actor.peers.learnEnr(candidate_enr, 0) != null);
        try std.testing.expectEqual(kbucket_mod.EntryStatus.disconnected, actor.peers.routing.getEntry(&candidate_id).?.status);
        var sibling = candidate_id;
        for (1..kbucket_mod.K) |i| {
            sibling[31] = candidate_id[31] ^ @as(u8, @intCast(i));
            try std.testing.expect(actor.peers.routing.insert(.{
                .node_id = sibling,
                .pubkey = candidate_pubkey,
                .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 52 }, .port = @intCast(9052 + i) } },
                .last_seen = 0,
                .status = .disconnected,
            }));
        }

        // A connected newcomer overflows the bucket; the genuine eviction
        // candidate handed back is the disconnected oldest entry.
        var pending_id = candidate_id;
        pending_id[30] = candidate_id[30] ^ 0x55;
        const outcome = actor.peers.routing.insertDetailed(.{
            .node_id = pending_id,
            .pubkey = candidate_pubkey,
            .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 53 }, .port = 9053 } },
            .last_seen = 1,
            .status = .connected,
        });
        try std.testing.expect(!outcome.inserted);
        const candidate = outcome.pending_eviction orelse return error.MissingEvictionCandidate;
        try std.testing.expectEqualSlices(u8, &candidate_id, &candidate.node_id);
        try std.testing.expectEqual(kbucket_mod.EntryStatus.disconnected, candidate.status);

        return .{
            .ingress = ingress,
            .outbox = outbox,
            .actor = actor,
            .recording = transport.RecordingSender.init(alloc),
            .candidate = candidate,
            .candidate_key = candidate_key,
            .candidate_id = candidate_id,
            .candidate_endpoint = .{ .node_id = candidate_id, .addr = candidate_addr },
            .pending_id = pending_id,
            .bucket_distance = distance,
        };
    }

    fn deinit(self: *EvictionHarness) void {
        self.recording.deinit();
        self.actor.deinit(&self.ingress);
        self.outbox.deinit();
        self.ingress.deinit();
    }

    fn bucket(self: *EvictionHarness) *kbucket_mod.KBucket {
        return &self.actor.peers.routing.buckets[self.bucket_distance];
    }

    fn armedKey(self: *EvictionHarness) !types.RequestKey {
        return self.actor.peers.routing.getEntry(&self.candidate_id).?.health_request orelse error.MissingEvictionReservation;
    }

    fn expectProbeRequest(self: *EvictionHarness) !types.RequestKey {
        const key = try self.armedKey();
        try std.testing.expect(types.EndpointContext.eql(.{}, key.endpoint, self.candidate_endpoint));
        const request = self.actor.requests.get(key) orelse return error.MissingEvictionRequest;
        switch (request.origin) {
            .maintenance => |reason| try std.testing.expectEqual(types.MaintenanceReason.eviction, reason),
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

    harness.actor.probeEviction(.{ .io = io, .sender = harness.recording.sender(), .ingress = &harness.ingress, .outbox = &harness.outbox }, harness.candidate);
    _ = try harness.expectProbeRequest();
    try std.testing.expect(harness.bucket().pending != null);
    try std.testing.expectEqual(@import("kbucket.zig").EntryStatus.disconnected, harness.actor.peers.routing.getEntry(&harness.candidate_id).?.status);
}

test "real eviction probe PONG keeps the candidate and clears the pending replacement" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    var harness = try EvictionHarness.init(alloc, io);
    defer harness.deinit();
    const stable = session_book.StableSession{ .initiator_key = [_]u8{0x27} ** 16, .recipient_key = [_]u8{0x28} ** 16 };
    harness.actor.sessions.put(harness.candidate_endpoint, stable, outbound.nowNs(io));

    harness.actor.probeEviction(.{ .io = io, .sender = harness.recording.sender(), .ingress = &harness.ingress, .outbox = &harness.outbox }, harness.candidate);
    const key = try harness.expectProbeRequest();
    const pong = message.Pong{ .req_id = key.req_id, .enr_seq = 0, .recipient_ip = .{ .ip4 = .{ 127, 0, 0, 1 } }, .recipient_port = 9000 };
    var pong_buffer: [128]u8 = undefined;
    try deliverEncrypted(&harness.actor, io, harness.recording.sender(), &harness.ingress, &harness.outbox, harness.candidate_endpoint, &stable.recipient_key, try pong.encodeInto(&pong_buffer), 31);

    try std.testing.expectEqual(@as(usize, 0), harness.actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 0), harness.ingress.permitCount());
    const survivor = harness.actor.peers.routing.getEntry(&harness.candidate_id) orelse return error.CandidateEvicted;
    try std.testing.expectEqual(@import("kbucket.zig").EntryStatus.connected, survivor.status);
    try std.testing.expect(survivor.health_request == null);
    try std.testing.expect(harness.bucket().pending == null);
    try std.testing.expect(harness.actor.peers.routing.getEntry(&harness.pending_id) == null);
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

    harness.actor.probeEviction(.{ .io = io, .sender = harness.recording.sender(), .ingress = &harness.ingress, .outbox = &harness.outbox }, harness.candidate);
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
    harness.actor.handlePacket(.{ .io = io, .sender = harness.recording.sender(), .ingress = &harness.ingress, .outbox = &harness.outbox }, challenge, harness.candidate_endpoint.addr);

    // The recovery handshake is on the wire while reservation, request,
    // permit, and pending keys all survive.
    try std.testing.expectEqual(@as(usize, 2), harness.recording.datagrams.items.len);
    try std.testing.expectEqual(@as(usize, 1), harness.actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 1), harness.ingress.permitCount());
    const pending = harness.actor.requests.pendingKeys(harness.candidate_endpoint) orelse return error.MissingPendingKeys;
    try std.testing.expect(types.RequestKeyContext.eql(.{}, pending.key, key));
    try std.testing.expect(types.RequestKeyContext.eql(.{}, try harness.armedKey(), key));

    const pong = message.Pong{ .req_id = key.req_id, .enr_seq = 0, .recipient_ip = .{ .ip4 = .{ 127, 0, 0, 1 } }, .recipient_port = 9000 };
    var pong_buffer: [128]u8 = undefined;
    try deliverEncrypted(&harness.actor, io, harness.recording.sender(), &harness.ingress, &harness.outbox, harness.candidate_endpoint, &pending.keys.recipient_key, try pong.encodeInto(&pong_buffer), 32);
    try std.testing.expectEqual(@as(usize, 0), harness.actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 0), harness.ingress.permitCount());
    try std.testing.expectEqual(@import("kbucket.zig").EntryStatus.connected, harness.actor.peers.routing.getEntry(&harness.candidate_id).?.status);
    try std.testing.expect(harness.bucket().pending == null);
}

test "real eviction probe timeout removes the exact candidate and promotes pending" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    var harness = try EvictionHarness.init(alloc, io);
    defer harness.deinit();

    harness.actor.probeEviction(.{ .io = io, .sender = harness.recording.sender(), .ingress = &harness.ingress, .outbox = &harness.outbox }, harness.candidate);
    _ = try harness.expectProbeRequest();

    try std.Io.sleep(io, .fromMilliseconds(2), .awake);
    harness.actor.maintenance(.{ .io = io, .sender = harness.recording.sender(), .ingress = &harness.ingress, .outbox = &harness.outbox });

    try std.testing.expectEqual(@as(usize, 0), harness.actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 0), harness.ingress.permitCount());
    try std.testing.expect(harness.actor.peers.routing.getEntry(&harness.candidate_id) == null);
    const promoted = harness.actor.peers.routing.getEntry(&harness.pending_id) orelse return error.PendingNotPromoted;
    try std.testing.expectEqual(@import("kbucket.zig").EntryStatus.connected, promoted.status);
    try std.testing.expect(harness.bucket().pending == null);
    var saw_promoted_connected = false;
    while (harness.outbox.pop()) |event_value| {
        var event = event_value;
        defer event.deinit(alloc);
        if (event == .peer_connected and std.mem.eql(u8, &event.peer_connected.peer_id, &harness.pending_id)) saw_promoted_connected = true;
    }
    try std.testing.expect(saw_promoted_connected);
}

test "real eviction probe send failure rolls back reservation and bucket state" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    var harness = try EvictionHarness.init(alloc, io);
    defer harness.deinit();

    harness.recording.fail_next = true;
    harness.actor.probeEviction(.{ .io = io, .sender = harness.recording.sender(), .ingress = &harness.ingress, .outbox = &harness.outbox }, harness.candidate);

    try std.testing.expectEqual(@as(usize, 0), harness.recording.datagrams.items.len);
    try std.testing.expectEqual(@as(usize, 0), harness.actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 0), harness.ingress.permitCount());
    try std.testing.expect(harness.actor.peers.routing.getEntry(&harness.candidate_id).?.health_request == null);
    try std.testing.expect(harness.bucket().pending != null);
    try std.testing.expectEqualSlices(u8, &harness.pending_id, &harness.bucket().pending.?.node_id);
    harness.actor.requests.assertInvariants();
}

test "health and eviction probes never queue behind endpoint establishment" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x36} ** 32));
    const local_id = enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&local_key));
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x37} ** 32));
    const remote_pubkey = secp.compressedPubkey(&remote_key);
    var remote_builder = enr.Builder.init(alloc, remote_key, 1);
    remote_builder.ip = .{ 127, 0, 0, 10 };
    remote_builder.udp = 9010;
    const remote_enr = try remote_builder.encode();
    defer alloc.free(remote_enr);
    const remote_id = (try enr.decode(remote_enr)).nodeId().?;
    const endpoint = types.Endpoint{
        .node_id = remote_id,
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 10 }, .port = 9010 } },
    };
    const cfg = config.Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
        .local_node_id = local_id,
        .request_timeout_ms = 1,
        .request_retries = 0,
        .ping_interval_ms = 0,
        .rate_limiter = null,
        .limits = .{ .max_active_requests = 4, .max_queued_requests = 4, .event_capacity = 4, .command_capacity = 4 },
    };
    var ingress = try admission.IngressAdmission.init(alloc, null, cfg.limits.max_active_requests);
    defer ingress.deinit();
    var outbox = try events.EventOutbox.init(io, alloc, cfg.limits.event_capacity);
    defer outbox.deinit();
    var actor = try actor_mod.Actor.init(alloc, cfg);
    defer actor.deinit(&ingress);
    var recording = transport.RecordingSender.init(alloc);
    defer recording.deinit();
    try std.testing.expect(actor.peers.learnEnr(remote_enr, 0) != null);
    _ = actor.peers.markResponsive(remote_id, endpoint.addr, 0, null);

    _ = try actor.sendPing(.{ .io = io, .sender = recording.sender(), .ingress = &ingress, .outbox = &outbox }, endpoint, &remote_pubkey, 1, .api);
    try std.testing.expectError(error.EndpointBusy, actor.sendPing(.{ .io = io, .sender = recording.sender(), .ingress = &ingress, .outbox = &outbox }, endpoint, &remote_pubkey, 1, .{ .maintenance = .health }));
    actor.probeEviction(.{ .io = io, .sender = recording.sender(), .ingress = &ingress, .outbox = &outbox }, actor.peers.routing.getEntry(&remote_id).?.*);
    try std.testing.expectEqual(@as(usize, 1), actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 0), actor.requests.queuedCount());
    try std.testing.expectEqual(@as(usize, 1), ingress.permitCount());
    try std.testing.expect(actor.peers.routing.getEntry(&remote_id).?.health_request == null);
    try std.testing.expectEqual(@as(usize, 1), recording.datagrams.items.len);

    try std.Io.sleep(io, .fromMilliseconds(2), .awake);
    actor.maintenance(.{ .io = io, .sender = recording.sender(), .ingress = &ingress, .outbox = &outbox });
    try std.testing.expectEqual(@as(usize, 0), actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 0), ingress.permitCount());
    try std.testing.expectEqual(@import("kbucket.zig").EntryStatus.connected, actor.peers.routing.getEntry(&remote_id).?.status);
}

fn expectActorHealthRequest(actor: *const actor_mod.Actor, node_id: types.NodeId, expected: types.RequestKey) !void {
    const actual = actor.peers.routing.getEntryWithPending(&node_id).?.health_request orelse return error.MissingHealthRequest;
    try std.testing.expect(types.RequestKeyContext.eql(.{}, actual, expected));
    try std.testing.expectEqual(@import("kbucket.zig").EntryStatus.connected, actor.peers.routing.getEntry(&node_id).?.status);
}

test "named cancellation conserves permits and queued FIFO across drain failure" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x43} ** 32));
    const local_id = enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&local_key));
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x44} ** 32));
    const remote_pubkey = secp.compressedPubkey(&remote_key);
    const remote_id = enr.nodeIdFromCompressedPubkey(&remote_pubkey);
    const endpoint = types.Endpoint{
        .node_id = remote_id,
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 4 }, .port = 9004 } },
    };
    const cfg = config.Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
        .local_node_id = local_id,
        .rate_limiter = null,
        .limits = .{ .max_active_requests = 4, .max_queued_requests = 4, .event_capacity = 4, .command_capacity = 4 },
    };
    var ingress = try admission.IngressAdmission.init(alloc, null, cfg.limits.max_active_requests);
    defer ingress.deinit();
    var outbox = try events.EventOutbox.init(io, alloc, cfg.limits.event_capacity);
    defer outbox.deinit();
    var actor = try actor_mod.Actor.init(alloc, cfg);
    defer actor.deinit(&ingress);
    var recording = transport.RecordingSender.init(alloc);
    defer recording.deinit();

    const first = try actor.sendPing(.{ .io = io, .sender = recording.sender(), .ingress = &ingress, .outbox = &outbox }, endpoint, &remote_pubkey, 1, .api);
    const second = try actor.sendPing(.{ .io = io, .sender = recording.sender(), .ingress = &ingress, .outbox = &outbox }, endpoint, &remote_pubkey, 2, .api);
    const third = try actor.sendPing(.{ .io = io, .sender = recording.sender(), .ingress = &ingress, .outbox = &outbox }, endpoint, &remote_pubkey, 3, .api);
    try std.testing.expectEqual(@as(usize, 1), ingress.permitCount());
    try std.testing.expectEqual(@as(usize, 2), actor.requests.queuedCount());

    try std.testing.expect(actor.cancelRequest(.{ .io = io, .sender = recording.sender(), .ingress = &ingress, .outbox = &outbox }, .init(endpoint, second)));
    try std.testing.expectEqual(@as(usize, 1), ingress.permitCount());
    try std.testing.expectEqual(@as(usize, 1), actor.requests.queuedCount());

    recording.fail_next = true;
    try std.testing.expect(actor.cancelRequest(.{ .io = io, .sender = recording.sender(), .ingress = &ingress, .outbox = &outbox }, .init(endpoint, first)));
    try std.testing.expect(!actor.cancelRequest(.{ .io = io, .sender = recording.sender(), .ingress = &ingress, .outbox = &outbox }, .init(endpoint, first)));
    try std.testing.expectEqual(@as(usize, 0), ingress.permitCount());
    try std.testing.expectEqual(@as(usize, 0), actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 1), actor.requests.queuedCount());
    try std.testing.expectEqual(@as(usize, 1), recording.datagrams.items.len);

    const stable = session_book.StableSession{
        .initiator_key = [_]u8{0x51} ** 16,
        .recipient_key = [_]u8{0x52} ** 16,
    };
    actor.sessions.put(endpoint, stable, outbound.nowNs(io));
    outbound.drainEndpoint(&actor, .{ .io = io, .sender = recording.sender(), .ingress = &ingress, .outbox = &outbox }, endpoint);
    try std.testing.expectEqual(@as(usize, 0), actor.requests.queuedCount());
    try std.testing.expectEqual(@as(usize, 1), actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 1), ingress.permitCount());
    try std.testing.expectEqual(@as(usize, 2), recording.datagrams.items.len);
    try std.testing.expectEqualSlices(u8, third.slice(), (try decodeSentPing(&recording.datagrams.items[1].bytes, &remote_id, &stable.initiator_key)).req_id.slice());
}

test "maintenance automatically redrains a queued lane after one transient send failure" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x99} ** 32));
    const local_id = enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&local_key));
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x9a} ** 32));
    const remote_pubkey = secp.compressedPubkey(&remote_key);
    const remote_id = enr.nodeIdFromCompressedPubkey(&remote_pubkey);
    const endpoint = types.Endpoint{
        .node_id = remote_id,
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 44 }, .port = 9244 } },
    };
    const cfg = config.Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
        .local_node_id = local_id,
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
    var ingress = try admission.IngressAdmission.init(alloc, null, try admission.permitCapacity(cfg.limits));
    defer ingress.deinit();
    var outbox = try events.EventOutbox.init(io, alloc, cfg.limits.event_capacity);
    defer outbox.deinit();
    var actor = try actor_mod.Actor.init(alloc, cfg);
    defer actor.deinit(&ingress);
    var recording = transport.RecordingSender.init(alloc);
    defer recording.deinit();

    const first = try actor.sendPing(
        .{ .io = io, .sender = recording.sender(), .ingress = &ingress, .outbox = &outbox },
        endpoint,
        &remote_pubkey,
        0,
        .api,
    );
    const second = try actor.sendPing(
        .{ .io = io, .sender = recording.sender(), .ingress = &ingress, .outbox = &outbox },
        endpoint,
        &remote_pubkey,
        0,
        .api,
    );
    try std.testing.expectEqual(@as(usize, 1), actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 1), actor.requests.queuedCount());

    const stable = session_book.StableSession{
        .initiator_key = [_]u8{0xc1} ** 16,
        .recipient_key = [_]u8{0xc2} ** 16,
    };
    actor.sessions.put(endpoint, stable, outbound.nowNs(io));
    recording.fail_next = true;
    try std.testing.expect(actor.cancelRequest(
        .{ .io = io, .sender = recording.sender(), .ingress = &ingress, .outbox = &outbox },
        .init(endpoint, first),
    ));
    try std.testing.expectEqual(@as(usize, 0), actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 1), actor.requests.queuedCount());
    try std.testing.expectEqual(@as(usize, 0), ingress.permitCount());

    actor.maintenance(.{ .io = io, .sender = recording.sender(), .ingress = &ingress, .outbox = &outbox });
    try std.testing.expectEqual(@as(usize, 1), actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 0), actor.requests.queuedCount());
    try std.testing.expectEqual(@as(usize, 1), ingress.permitCount());
    try std.testing.expectEqual(@as(usize, 2), recording.datagrams.items.len);
    const retried = try decodeSentPing(&recording.datagrams.items[1].bytes, &remote_id, &stable.initiator_key);
    try std.testing.expectEqualSlices(u8, second.slice(), retried.req_id.slice());
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

test "AdmissionPermit survives retry and releases on final timeout" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x45} ** 32));
    const local_id = enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&local_key));
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x46} ** 32));
    const remote_pubkey = secp.compressedPubkey(&remote_key);
    const endpoint = types.Endpoint{
        .node_id = enr.nodeIdFromCompressedPubkey(&remote_pubkey),
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 6 }, .port = 9006 } },
    };
    const cfg = config.Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
        .local_node_id = local_id,
        .request_timeout_ms = 1,
        .request_retries = 1,
        .rate_limiter = null,
        .limits = .{ .max_active_requests = 2, .max_queued_requests = 2, .event_capacity = 2, .command_capacity = 2 },
    };
    var ingress = try admission.IngressAdmission.init(alloc, null, cfg.limits.max_active_requests);
    defer ingress.deinit();
    var outbox = try events.EventOutbox.init(io, alloc, cfg.limits.event_capacity);
    defer outbox.deinit();
    var actor = try actor_mod.Actor.init(alloc, cfg);
    defer actor.deinit(&ingress);
    var recording = transport.RecordingSender.init(alloc);
    defer recording.deinit();
    actor.sessions.put(endpoint, .{ .initiator_key = [_]u8{1} ** 16, .recipient_key = [_]u8{2} ** 16 }, outbound.nowNs(io));
    _ = try actor.sendPing(.{ .io = io, .sender = recording.sender(), .ingress = &ingress, .outbox = &outbox }, endpoint, &remote_pubkey, 0, .api);
    try std.testing.expectEqual(@as(usize, 1), ingress.permitCount());
    try std.testing.expectEqual(@as(u64, 1), actor.metrics.sent_message_count[metrics.MessageType.ping.index()]);

    try std.Io.sleep(io, .fromMilliseconds(2), .awake);
    actor.maintenance(.{ .io = io, .sender = recording.sender(), .ingress = &ingress, .outbox = &outbox });
    try std.testing.expectEqual(@as(usize, 1), actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 1), ingress.permitCount());
    try std.testing.expectEqual(@as(usize, 2), recording.datagrams.items.len);
    try std.testing.expectEqual(@as(u64, 2), actor.metrics.sent_message_count[metrics.MessageType.ping.index()]);

    try std.Io.sleep(io, .fromMilliseconds(2), .awake);
    actor.maintenance(.{ .io = io, .sender = recording.sender(), .ingress = &ingress, .outbox = &outbox });
    try std.testing.expectEqual(@as(usize, 0), actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 0), ingress.permitCount());
    var timeout_event = outbox.pop() orelse return error.MissingTimeoutEvent;
    defer timeout_event.deinit(alloc);
    try std.testing.expect(timeout_event == .request_timeout);
}

test "fresh FINDNODE retry resets multipart generation and swaps one permit" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x18} ** 32));
    const local_id = enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&local_key));
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x19} ** 32));
    const remote_pubkey = secp.compressedPubkey(&remote_key);
    const remote_id = enr.nodeIdFromCompressedPubkey(&remote_pubkey);
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
    const id_a = (try enr.decode(raw_a)).nodeId().?;
    const discovered_key_b = try secp.keyPairFromSecret(&([_]u8{0x1b} ** 32));
    var builder_b = enr.Builder.init(alloc, discovered_key_b, 1);
    builder_b.ip = .{ 127, 0, 0, 27 };
    builder_b.udp = 9027;
    const raw_b = try builder_b.encode();
    defer alloc.free(raw_b);
    const id_b = (try enr.decode(raw_b)).nodeId().?;
    const distance_a: u16 = if (@import("kbucket.zig").logDistance(&id_a, &remote_id)) |value| @as(u16, value) + 1 else 0;
    const distance_b: u16 = if (@import("kbucket.zig").logDistance(&id_b, &remote_id)) |value| @as(u16, value) + 1 else 0;
    const cfg = config.Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
        .local_node_id = local_id,
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
    var ingress = try admission.IngressAdmission.init(alloc, null, try admission.permitCapacity(cfg.limits));
    defer ingress.deinit();
    var outbox = try events.EventOutbox.init(io, alloc, cfg.limits.event_capacity);
    defer outbox.deinit();
    var actor = try actor_mod.Actor.init(alloc, cfg);
    defer actor.deinit(&ingress);
    var recording = transport.RecordingSender.init(alloc);
    defer recording.deinit();
    const stable = session_book.StableSession{
        .initiator_key = [_]u8{0x1c} ** 16,
        .recipient_key = [_]u8{0x1d} ** 16,
    };
    actor.sessions.put(endpoint, stable, outbound.nowNs(io));
    const req_id = try actor.sendFindNode(
        .{ .io = io, .sender = recording.sender(), .ingress = &ingress, .outbox = &outbox },
        endpoint,
        &remote_pubkey,
        &.{ distance_a, distance_b },
        .api,
    );
    try std.testing.expectEqual(@as(usize, 1), ingress.permitCount());

    var first_buffer: [packet.MAX_PACKET_SIZE]u8 = undefined;
    const first = message.Nodes{ .req_id = req_id, .total = 2, .enrs = &.{raw_a} };
    const first_plaintext = try first.encodeInto(&first_buffer);
    try deliverEncrypted(&actor, io, recording.sender(), &ingress, &outbox, endpoint, &stable.recipient_key, first_plaintext, 0x21);
    const partial = &actor.requests.get(.init(endpoint, req_id)).?.response.nodes;
    try std.testing.expectEqual(@as(u64, 2), partial.total_responses.?);
    try std.testing.expectEqual(@as(u64, 1), partial.responses_received);
    try std.testing.expectEqual(@as(usize, 1), partial.enrs.items.len);

    try std.Io.sleep(io, .fromMilliseconds(2), .awake);
    actor.maintenance(.{ .io = io, .sender = recording.sender(), .ingress = &ingress, .outbox = &outbox });
    const fresh = &actor.requests.get(.init(endpoint, req_id)).?.response.nodes;
    try std.testing.expect(fresh.total_responses == null);
    try std.testing.expectEqual(@as(u64, 0), fresh.responses_received);
    try std.testing.expectEqual(@as(usize, 0), fresh.enrs.items.len);
    try std.testing.expectEqual(@as(usize, request_book.MAX_NODES_RESPONSE), fresh.enrs.capacity);
    try std.testing.expectEqual(@as(usize, 1), ingress.permitCount());

    try deliverEncrypted(&actor, io, recording.sender(), &ingress, &outbox, endpoint, &stable.recipient_key, first_plaintext, 0x22);
    const repeated = &actor.requests.get(.init(endpoint, req_id)).?.response.nodes;
    try std.testing.expectEqual(@as(u64, 1), repeated.responses_received);
    try std.testing.expectEqual(@as(usize, 1), repeated.enrs.items.len);
    try std.testing.expectEqual(@as(usize, 1), actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 1), ingress.permitCount());

    var final_buffer: [packet.MAX_PACKET_SIZE]u8 = undefined;
    const final = message.Nodes{ .req_id = req_id, .total = 2, .enrs = &.{raw_b} };
    try deliverEncrypted(&actor, io, recording.sender(), &ingress, &outbox, endpoint, &stable.recipient_key, try final.encodeInto(&final_buffer), 0x23);
    try std.testing.expectEqual(@as(usize, 0), actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 0), ingress.permitCount());
    var saw_nodes = false;
    var processed: usize = 0;
    while (processed < cfg.limits.event_capacity) : (processed += 1) {
        var event = outbox.pop() orelse break;
        if (event == .nodes) {
            try std.testing.expectEqual(@as(usize, 2), event.nodes.enrs.items.len);
            saw_nodes = true;
        }
        event.deinit(alloc);
    }
    try std.testing.expect(saw_nodes);
}

test "paired Actors retry an established PING with a fresh nonce and complete on the second PONG" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const key_a = try secp.keyPairFromSecret(&([_]u8{0x93} ** 32));
    const pubkey_a = secp.compressedPubkey(&key_a);
    const id_a = enr.nodeIdFromCompressedPubkey(&pubkey_a);
    const key_b = try secp.keyPairFromSecret(&([_]u8{0x94} ** 32));
    const pubkey_b = secp.compressedPubkey(&key_b);
    const id_b = enr.nodeIdFromCompressedPubkey(&pubkey_b);
    const address_a = types.Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 31 }, .port = 9231 } };
    const address_b = types.Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 32 }, .port = 9232 } };
    const limits = config.Limits{
        .max_active_requests = 2,
        .max_queued_requests = 2,
        .challenge_capacity = 2,
        .response_recovery_capacity = 2,
        .event_capacity = 4,
        .command_capacity = 2,
    };
    const config_a = config.Config{
        .bind_addresses = .{ .ip4 = address_a },
        .local_key_pair = key_a,
        .local_node_id = id_a,
        .request_timeout_ms = 1,
        .request_retries = 1,
        .rate_limiter = null,
        .limits = limits,
    };
    const config_b = config.Config{
        .bind_addresses = .{ .ip4 = address_b },
        .local_key_pair = key_b,
        .local_node_id = id_b,
        .rate_limiter = null,
        .limits = limits,
    };
    var ingress_a = try admission.IngressAdmission.init(alloc, null, try admission.permitCapacity(limits));
    defer ingress_a.deinit();
    var ingress_b = try admission.IngressAdmission.init(alloc, null, try admission.permitCapacity(limits));
    defer ingress_b.deinit();
    var outbox_a = try events.EventOutbox.init(io, alloc, limits.event_capacity);
    defer outbox_a.deinit();
    var outbox_b = try events.EventOutbox.init(io, alloc, limits.event_capacity);
    defer outbox_b.deinit();
    var actor_a = try actor_mod.Actor.init(alloc, config_a);
    defer actor_a.deinit(&ingress_a);
    var actor_b = try actor_mod.Actor.init(alloc, config_b);
    defer actor_b.deinit(&ingress_b);
    var sender_a = transport.RecordingSender.init(alloc);
    defer sender_a.deinit();
    var sender_b = transport.RecordingSender.init(alloc);
    defer sender_b.deinit();
    const now_ns = outbound.nowNs(io);
    try std.testing.expect(actor_a.addNode(id_b, &pubkey_b, address_b, null, now_ns));
    try std.testing.expect(actor_b.addNode(id_a, &pubkey_a, address_a, null, now_ns));
    const a_to_b = [_]u8{0xa1} ** 16;
    const b_to_a = [_]u8{0xb1} ** 16;
    actor_a.sessions.put(.{ .node_id = id_b, .addr = address_b }, .{
        .initiator_key = a_to_b,
        .recipient_key = b_to_a,
    }, now_ns);
    actor_b.sessions.put(.{ .node_id = id_a, .addr = address_a }, .{
        .initiator_key = b_to_a,
        .recipient_key = a_to_b,
    }, now_ns);

    const req_id = try actor_a.sendPing(
        .{ .io = io, .sender = sender_a.sender(), .ingress = &ingress_a, .outbox = &outbox_a },
        .{ .node_id = id_b, .addr = address_b },
        &pubkey_b,
        0,
        .api,
    );
    deliver(&sender_a, 0, &actor_b, io, sender_b.sender(), &ingress_b, &outbox_b, address_a);
    try std.testing.expectEqual(@as(usize, 1), sender_b.datagrams.items.len);
    var first_packet = sender_a.datagrams.items[0].bytes;
    const first_nonce = (try packet.decode(first_packet.bytes[0..first_packet.len], &id_b)).static_header.nonce;

    try std.Io.sleep(io, .fromMilliseconds(2), .awake);
    actor_a.maintenance(.{ .io = io, .sender = sender_a.sender(), .ingress = &ingress_a, .outbox = &outbox_a });
    try std.testing.expectEqual(@as(usize, 2), sender_a.datagrams.items.len);
    var retry_packet = sender_a.datagrams.items[1].bytes;
    const retry_nonce = (try packet.decode(retry_packet.bytes[0..retry_packet.len], &id_b)).static_header.nonce;
    try std.testing.expect(!std.mem.eql(u8, &first_nonce, &retry_nonce));
    deliver(&sender_a, 1, &actor_b, io, sender_b.sender(), &ingress_b, &outbox_b, address_a);
    try std.testing.expectEqual(@as(usize, 2), sender_b.datagrams.items.len);
    deliver(&sender_b, 1, &actor_a, io, sender_a.sender(), &ingress_a, &outbox_a, address_b);

    try std.testing.expectEqual(@as(usize, 0), actor_a.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 0), ingress_a.permitCount());
    var pong_event = outbox_a.pop() orelse return error.MissingRetriedPong;
    defer pong_event.deinit(alloc);
    try std.testing.expect(pong_event == .pong);
    try std.testing.expectEqualSlices(u8, req_id.slice(), pong_event.pong.req_id.slice());
}

test "paired Actors recover a dropped WHOAREYOU by replaying its exact retained datagram" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const key_a = try secp.keyPairFromSecret(&([_]u8{0x95} ** 32));
    const pubkey_a = secp.compressedPubkey(&key_a);
    const id_a = enr.nodeIdFromCompressedPubkey(&pubkey_a);
    const key_b = try secp.keyPairFromSecret(&([_]u8{0x96} ** 32));
    const pubkey_b = secp.compressedPubkey(&key_b);
    const id_b = enr.nodeIdFromCompressedPubkey(&pubkey_b);
    const address_a = types.Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 33 }, .port = 9233 } };
    const address_b = types.Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 34 }, .port = 9234 } };
    const limits = config.Limits{
        .max_active_requests = 2,
        .max_queued_requests = 2,
        .challenge_capacity = 2,
        .response_recovery_capacity = 2,
        .event_capacity = 4,
        .command_capacity = 2,
    };
    const config_a = config.Config{
        .bind_addresses = .{ .ip4 = address_a },
        .local_key_pair = key_a,
        .local_node_id = id_a,
        .request_timeout_ms = 1,
        .request_retries = 1,
        .rate_limiter = null,
        .limits = limits,
    };
    const config_b = config.Config{
        .bind_addresses = .{ .ip4 = address_b },
        .local_key_pair = key_b,
        .local_node_id = id_b,
        .rate_limiter = null,
        .limits = limits,
    };
    var ingress_a = try admission.IngressAdmission.init(alloc, null, try admission.permitCapacity(limits));
    defer ingress_a.deinit();
    var ingress_b = try admission.IngressAdmission.init(alloc, null, try admission.permitCapacity(limits));
    defer ingress_b.deinit();
    var outbox_a = try events.EventOutbox.init(io, alloc, limits.event_capacity);
    defer outbox_a.deinit();
    var outbox_b = try events.EventOutbox.init(io, alloc, limits.event_capacity);
    defer outbox_b.deinit();
    var actor_a = try actor_mod.Actor.init(alloc, config_a);
    defer actor_a.deinit(&ingress_a);
    var actor_b = try actor_mod.Actor.init(alloc, config_b);
    defer actor_b.deinit(&ingress_b);
    var sender_a = transport.RecordingSender.init(alloc);
    defer sender_a.deinit();
    var sender_b = transport.RecordingSender.init(alloc);
    defer sender_b.deinit();
    const now_ns = outbound.nowNs(io);
    try std.testing.expect(actor_a.addNode(id_b, &pubkey_b, address_b, null, now_ns));
    try std.testing.expect(actor_b.addNode(id_a, &pubkey_a, address_a, null, now_ns));

    const req_id = try actor_a.sendPing(
        .{ .io = io, .sender = sender_a.sender(), .ingress = &ingress_a, .outbox = &outbox_a },
        .{ .node_id = id_b, .addr = address_b },
        &pubkey_b,
        0,
        .api,
    );
    deliver(&sender_a, 0, &actor_b, io, sender_b.sender(), &ingress_b, &outbox_b, address_a);
    try std.testing.expectEqual(@as(usize, 1), sender_b.datagrams.items.len);
    try std.testing.expectEqual(@as(usize, 1), ingress_b.permitCount());

    try std.Io.sleep(io, .fromMilliseconds(2), .awake);
    actor_a.maintenance(.{ .io = io, .sender = sender_a.sender(), .ingress = &ingress_a, .outbox = &outbox_a });
    try std.testing.expectEqualSlices(u8, sender_a.datagrams.items[0].bytes.slice(), sender_a.datagrams.items[1].bytes.slice());
    deliver(&sender_a, 1, &actor_b, io, sender_b.sender(), &ingress_b, &outbox_b, address_a);
    try std.testing.expectEqual(@as(usize, 2), sender_b.datagrams.items.len);
    try std.testing.expectEqualSlices(u8, sender_b.datagrams.items[0].bytes.slice(), sender_b.datagrams.items[1].bytes.slice());
    try std.testing.expectEqual(@as(usize, 1), ingress_b.permitCount());

    deliver(&sender_b, 1, &actor_a, io, sender_a.sender(), &ingress_a, &outbox_a, address_b);
    deliver(&sender_a, 2, &actor_b, io, sender_b.sender(), &ingress_b, &outbox_b, address_a);
    deliver(&sender_b, 2, &actor_a, io, sender_a.sender(), &ingress_a, &outbox_a, address_b);
    try std.testing.expectEqual(@as(usize, 0), actor_a.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 0), ingress_a.permitCount());
    try std.testing.expectEqual(@as(usize, 1), ingress_b.permitCount());
    actor_b.responses.prune(std.math.maxInt(i64), &ingress_b);
    try std.testing.expectEqual(@as(usize, 0), ingress_b.permitCount());
    var pong_event = outbox_a.pop() orelse return error.MissingRecoveredPong;
    defer pong_event.deinit(alloc);
    try std.testing.expect(pong_event == .pong);
    try std.testing.expectEqualSlices(u8, req_id.slice(), pong_event.pong.req_id.slice());
}

test "response recovery keeps stable keys until candidate proof then promotes and cleans" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const key_a = try secp.keyPairFromSecret(&([_]u8{0x97} ** 32));
    const pubkey_a = secp.compressedPubkey(&key_a);
    const id_a = enr.nodeIdFromCompressedPubkey(&pubkey_a);
    const key_b = try secp.keyPairFromSecret(&([_]u8{0x98} ** 32));
    const pubkey_b = secp.compressedPubkey(&key_b);
    const id_b = enr.nodeIdFromCompressedPubkey(&pubkey_b);
    const address_a = types.Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 35 }, .port = 9235 } };
    const address_b = types.Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 36 }, .port = 9236 } };
    const endpoint_a = types.Endpoint{ .node_id = id_a, .addr = address_a };
    const endpoint_b = types.Endpoint{ .node_id = id_b, .addr = address_b };
    const limits = config.Limits{
        .max_active_requests = 2,
        .max_queued_requests = 2,
        .challenge_capacity = 2,
        .response_recovery_capacity = 2,
        .event_capacity = 4,
        .command_capacity = 2,
    };
    const config_a = config.Config{
        .bind_addresses = .{ .ip4 = address_a },
        .local_key_pair = key_a,
        .local_node_id = id_a,
        .rate_limiter = null,
        .limits = limits,
    };
    const config_b = config.Config{
        .bind_addresses = .{ .ip4 = address_b },
        .local_key_pair = key_b,
        .local_node_id = id_b,
        .rate_limiter = null,
        .limits = limits,
    };
    var ingress_a = try admission.IngressAdmission.init(alloc, null, try admission.permitCapacity(limits));
    defer ingress_a.deinit();
    var ingress_b = try admission.IngressAdmission.init(alloc, null, try admission.permitCapacity(limits));
    defer ingress_b.deinit();
    var outbox_a = try events.EventOutbox.init(io, alloc, limits.event_capacity);
    defer outbox_a.deinit();
    var outbox_b = try events.EventOutbox.init(io, alloc, limits.event_capacity);
    defer outbox_b.deinit();
    var actor_a = try actor_mod.Actor.init(alloc, config_a);
    defer actor_a.deinit(&ingress_a);
    var actor_b = try actor_mod.Actor.init(alloc, config_b);
    defer actor_b.deinit(&ingress_b);
    var sender_a = transport.RecordingSender.init(alloc);
    defer sender_a.deinit();
    var sender_b = transport.RecordingSender.init(alloc);
    defer sender_b.deinit();
    const now_ns = outbound.nowNs(io);
    try std.testing.expect(actor_a.addNode(id_b, &pubkey_b, address_b, null, now_ns));
    try std.testing.expect(actor_b.addNode(id_a, &pubkey_a, address_a, null, now_ns));
    const a_to_b = [_]u8{0xa2} ** 16;
    const b_to_a = [_]u8{0xb2} ** 16;
    actor_a.sessions.put(endpoint_b, .{ .initiator_key = a_to_b, .recipient_key = b_to_a }, now_ns);
    actor_b.sessions.put(endpoint_a, .{ .initiator_key = b_to_a, .recipient_key = a_to_b }, now_ns);

    const req_id = try actor_a.sendPing(
        .{ .io = io, .sender = sender_a.sender(), .ingress = &ingress_a, .outbox = &outbox_a },
        endpoint_b,
        &pubkey_b,
        0,
        .api,
    );
    deliver(&sender_a, 0, &actor_b, io, sender_b.sender(), &ingress_b, &outbox_b, address_a);
    try std.testing.expectEqual(@as(usize, 1), sender_b.datagrams.items.len);
    try std.testing.expect(actor_a.sessions.remove(endpoint_b));
    deliver(&sender_b, 0, &actor_a, io, sender_a.sender(), &ingress_a, &outbox_a, address_b);
    try std.testing.expectEqual(@as(usize, 2), sender_a.datagrams.items.len);
    try std.testing.expectEqual(@as(usize, 1), actor_b.responses.count());
    try std.testing.expectEqual(@as(usize, 1), ingress_b.permitCount());
    const wrong_address = types.Address{ .ip4 = .{ .bytes = address_a.ip4.bytes, .port = address_a.ip4.port + 1 } };
    var retained_challenge = sender_a.datagrams.items[1].bytes;
    actor_b.handlePacket(
        .{ .io = io, .sender = sender_b.sender(), .ingress = &ingress_b, .outbox = &outbox_b },
        retained_challenge.bytes[0..retained_challenge.len],
        wrong_address,
    );
    var wrong_nonce_buffer: [packet.WHOAREYOU_CHALLENGE_DATA_SIZE]u8 = undefined;
    const wrong_nonce_challenge = try packet.encodeWhoareyouPacketInto(&wrong_nonce_buffer, .{
        .masking_iv = &([_]u8{0xd1} ** packet.MASKING_IV_SIZE),
        .recipient_node_id = &id_b,
        .request_nonce = &([_]u8{0xd2} ** packet.NONCE_SIZE),
        .id_nonce = &([_]u8{0xd3} ** packet.ID_NONCE_SIZE),
        .enr_seq = 0,
    }, null);
    actor_b.handlePacket(
        .{ .io = io, .sender = sender_b.sender(), .ingress = &ingress_b, .outbox = &outbox_b },
        wrong_nonce_challenge,
        address_a,
    );
    try std.testing.expectEqual(@as(usize, 1), sender_b.datagrams.items.len);
    try std.testing.expectEqual(@as(usize, 1), actor_b.responses.count());
    try std.testing.expectEqual(@as(usize, 1), ingress_b.permitCount());
    deliver(&sender_a, 1, &actor_b, io, sender_b.sender(), &ingress_b, &outbox_b, address_a);
    try std.testing.expectEqual(@as(usize, 2), sender_b.datagrams.items.len);
    try std.testing.expectEqual(@as(usize, 1), actor_b.responses.count());
    try std.testing.expectEqual(@as(usize, 0), ingress_b.permitCount());
    const stable_before_proof = actor_b.sessions.get(endpoint_a, outbound.nowNs(io)) orelse return error.MissingStableSession;
    try std.testing.expectEqual(b_to_a, stable_before_proof.initiator_key);
    try std.testing.expectEqual(a_to_b, stable_before_proof.recipient_key);

    const old_talkresp = message.TalkResp{
        .req_id = try message.ReqId.fromSlice(&.{0xe1}),
        .response = "old key still works",
    };
    var old_plaintext_buffer: [128]u8 = undefined;
    var old_packet = try encodeEncryptedPacket(
        &actor_b,
        id_a,
        &a_to_b,
        try old_talkresp.encodeInto(&old_plaintext_buffer),
        0xe2,
    );
    actor_b.handlePacket(
        .{ .io = io, .sender = sender_b.sender(), .ingress = &ingress_b, .outbox = &outbox_b },
        old_packet.bytes[0..old_packet.len],
        address_a,
    );
    try std.testing.expectEqual(@as(u64, 1), actor_b.metrics.rcvd_message_count[metrics.MessageType.talkresp.index()]);
    const stable_after_old_packet = actor_b.sessions.get(endpoint_a, outbound.nowNs(io)) orelse return error.MissingStableSession;
    try std.testing.expectEqual(b_to_a, stable_after_old_packet.initiator_key);
    try std.testing.expectEqual(a_to_b, stable_after_old_packet.recipient_key);

    deliver(&sender_b, 1, &actor_a, io, sender_a.sender(), &ingress_a, &outbox_a, address_b);

    try std.testing.expectEqual(@as(usize, 0), actor_a.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 0), ingress_a.permitCount());
    try std.testing.expectEqual(@as(usize, 0), ingress_b.permitCount());
    var pong_event = outbox_a.pop() orelse return error.MissingRecoveredResponse;
    defer pong_event.deinit(alloc);
    try std.testing.expect(pong_event == .pong);
    try std.testing.expectEqualSlices(u8, req_id.slice(), pong_event.pong.req_id.slice());

    const candidate_keys = actor_a.sessions.get(endpoint_b, outbound.nowNs(io)) orelse return error.MissingCandidatePeerSession;
    const candidate_talkresp = message.TalkResp{
        .req_id = try message.ReqId.fromSlice(&.{0xe3}),
        .response = "candidate proof",
    };
    var candidate_plaintext_buffer: [128]u8 = undefined;
    var candidate_packet = try encodeEncryptedPacket(
        &actor_b,
        id_a,
        &candidate_keys.initiator_key,
        try candidate_talkresp.encodeInto(&candidate_plaintext_buffer),
        0xe4,
    );
    actor_b.handlePacket(
        .{ .io = io, .sender = sender_b.sender(), .ingress = &ingress_b, .outbox = &outbox_b },
        candidate_packet.bytes[0..candidate_packet.len],
        address_a,
    );
    try std.testing.expectEqual(@as(usize, 0), actor_b.responses.count());
    const promoted = actor_b.sessions.get(endpoint_a, outbound.nowNs(io)) orelse return error.MissingPromotedSession;
    try std.testing.expectEqual(candidate_keys.recipient_key, promoted.initiator_key);
    try std.testing.expectEqual(candidate_keys.initiator_key, promoted.recipient_key);
}

test "failed retry datagram does not increment sent message metrics" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x53} ** 32));
    const local_id = enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&local_key));
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x54} ** 32));
    const remote_pubkey = secp.compressedPubkey(&remote_key);
    const endpoint = types.Endpoint{
        .node_id = enr.nodeIdFromCompressedPubkey(&remote_pubkey),
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 7 }, .port = 9007 } },
    };
    const cfg = config.Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
        .local_node_id = local_id,
        .request_timeout_ms = 1,
        .request_retries = 1,
        .rate_limiter = null,
        .limits = .{ .max_active_requests = 2, .max_queued_requests = 2, .event_capacity = 2, .command_capacity = 2 },
    };
    var ingress = try admission.IngressAdmission.init(alloc, null, cfg.limits.max_active_requests);
    defer ingress.deinit();
    var outbox = try events.EventOutbox.init(io, alloc, cfg.limits.event_capacity);
    defer outbox.deinit();
    var actor = try actor_mod.Actor.init(alloc, cfg);
    defer actor.deinit(&ingress);
    var recording = transport.RecordingSender.init(alloc);
    defer recording.deinit();
    actor.sessions.put(endpoint, .{ .initiator_key = [_]u8{3} ** 16, .recipient_key = [_]u8{4} ** 16 }, outbound.nowNs(io));
    const req_id = try actor.sendPing(.{ .io = io, .sender = recording.sender(), .ingress = &ingress, .outbox = &outbox }, endpoint, &remote_pubkey, 0, .api);
    var initial = recording.datagrams.items[0].bytes;
    const initial_nonce = (try packet.decode(initial.bytes[0..initial.len], &endpoint.node_id)).static_header.nonce;

    recording.fail_next = true;
    try std.Io.sleep(io, .fromMilliseconds(2), .awake);
    actor.maintenance(.{ .io = io, .sender = recording.sender(), .ingress = &ingress, .outbox = &outbox });
    try std.testing.expectEqual(@as(u64, 1), actor.metrics.sent_message_count[metrics.MessageType.ping.index()]);
    try std.testing.expectEqual(@as(usize, 1), recording.datagrams.items.len);
    const active = actor.requests.get(.init(endpoint, req_id)) orelse return error.MissingRequestAfterRetryFailure;
    try std.testing.expect(active.phase == .awaiting_response);
    try std.testing.expectEqual(initial_nonce, active.phase.awaiting_response.recovery.nonce);
    try std.testing.expect(actor.requests.hasChallenge(&initial_nonce, endpoint.addr));
    try std.testing.expectEqual(@as(usize, 1), ingress.permitCount());
}

test "local ENR update pings every connected peer in a live bucket exactly once" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x58} ** 32));
    const local_id = enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&local_key));
    const local_address = types.Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 9058 } };
    var initial_builder = enr.Builder.init(alloc, local_key, 1);
    initial_builder.ip = local_address.ip4.bytes;
    initial_builder.udp = local_address.ip4.port;
    const initial_enr = try initial_builder.encode();
    defer alloc.free(initial_enr);
    var replacement_builder = enr.Builder.init(alloc, local_key, 2);
    replacement_builder.ip = local_address.ip4.bytes;
    replacement_builder.udp = local_address.ip4.port;
    const replacement_enr = try replacement_builder.encode();
    defer alloc.free(replacement_enr);
    const cfg = config.Config{
        .bind_addresses = .{ .ip4 = local_address },
        .local_key_pair = local_key,
        .local_node_id = local_id,
        .local_enr = initial_enr,
        .ping_interval_ms = 0,
        .rate_limiter = null,
        .limits = .{ .max_active_requests = 8, .max_queued_requests = 8, .event_capacity = 8, .command_capacity = 4 },
    };
    var ingress = try admission.IngressAdmission.init(alloc, null, cfg.limits.max_active_requests);
    defer ingress.deinit();
    var outbox = try events.EventOutbox.init(io, alloc, cfg.limits.event_capacity);
    defer outbox.deinit();
    var actor = try actor_mod.Actor.init(alloc, cfg);
    defer actor.deinit(&ingress);
    var recording = transport.RecordingSender.init(alloc);
    defer recording.deinit();

    var peer_ids: [3]types.NodeId = undefined;
    var peer_addresses: [3]types.Address = undefined;
    var peer_count: usize = 0;
    for (1..128) |candidate| {
        var secret = [_]u8{0} ** 32;
        @memset(&secret, @as(u8, @intCast(candidate)));
        const remote_key = try secp.keyPairFromSecret(&secret);
        const remote_pubkey = secp.compressedPubkey(&remote_key);
        const remote_id = enr.nodeIdFromCompressedPubkey(&remote_pubkey);
        if (@import("kbucket.zig").logDistance(&local_id, &remote_id) != 255) continue;
        const address = types.Address{ .ip4 = .{
            .bytes = .{ 127, 0, 0, @as(u8, @intCast(candidate)) },
            .port = @as(u16, @intCast(10_000 + candidate)),
        } };
        try std.testing.expect(actor.peers.routing.insert(.{
            .node_id = remote_id,
            .pubkey = remote_pubkey,
            .addr = address,
            .last_seen = 0,
            .status = .connected,
        }));
        peer_ids[peer_count] = remote_id;
        peer_addresses[peer_count] = address;
        peer_count += 1;
        if (peer_count == peer_ids.len) break;
    }
    try std.testing.expectEqual(peer_ids.len, peer_count);

    try actor.setLocalEnr(.{ .io = io, .sender = recording.sender(), .ingress = &ingress, .outbox = &outbox }, replacement_enr);
    try std.testing.expectEqual(peer_ids.len, recording.datagrams.items.len);
    try std.testing.expectEqual(peer_ids.len, actor.requests.activeCount());
    try std.testing.expectEqual(peer_ids.len, ingress.permitCount());
    for (peer_ids, peer_addresses) |peer_id, address| {
        try std.testing.expect(actor.peers.routing.getEntry(&peer_id).?.health_request != null);
        var address_count: usize = 0;
        for (recording.datagrams.items) |datagram| {
            if (datagram.address.eql(&address)) address_count += 1;
        }
        try std.testing.expectEqual(@as(usize, 1), address_count);
    }
}

test "NODES total is exact bounded consistent and controls final permit release" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x47} ** 32));
    const local_id = enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&local_key));
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x48} ** 32));
    const remote_pubkey = secp.compressedPubkey(&remote_key);
    const remote_id = enr.nodeIdFromCompressedPubkey(&remote_pubkey);
    const endpoint = types.Endpoint{
        .node_id = remote_id,
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 8 }, .port = 9008 } },
    };
    const cfg = config.Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
        .local_node_id = local_id,
        .rate_limiter = null,
        .limits = .{ .max_active_requests = 2, .max_queued_requests = 2, .event_capacity = 2, .command_capacity = 2 },
    };
    var ingress = try admission.IngressAdmission.init(alloc, null, cfg.limits.max_active_requests);
    defer ingress.deinit();
    var outbox = try events.EventOutbox.init(io, alloc, cfg.limits.event_capacity);
    defer outbox.deinit();
    var actor = try actor_mod.Actor.init(alloc, cfg);
    defer actor.deinit(&ingress);
    var recording = transport.RecordingSender.init(alloc);
    defer recording.deinit();
    const stable = session_book.StableSession{ .initiator_key = [_]u8{3} ** 16, .recipient_key = [_]u8{4} ** 16 };
    actor.sessions.put(endpoint, stable, outbound.nowNs(io));
    const req_id = try actor.sendFindNode(.{ .io = io, .sender = recording.sender(), .ingress = &ingress, .outbox = &outbox }, endpoint, &remote_pubkey, &.{0}, .api);
    try std.testing.expectEqual(@as(usize, 1), ingress.permitCount());

    var invalid_buffer: [128]u8 = undefined;
    const invalid = message.Nodes{ .req_id = req_id, .total = 17, .enrs = &.{} };
    try deliverEncrypted(&actor, io, recording.sender(), &ingress, &outbox, endpoint, &stable.recipient_key, try invalid.encodeInto(&invalid_buffer), 1);
    try std.testing.expect(actor.requests.get(.init(endpoint, req_id)).?.response.nodes.total_responses == null);
    try std.testing.expectEqual(@as(u64, 0), actor.requests.get(.init(endpoint, req_id)).?.response.nodes.responses_received);
    try std.testing.expectEqual(@as(usize, 1), actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 1), ingress.permitCount());

    var nodes_buffer: [128]u8 = undefined;
    const nodes = message.Nodes{ .req_id = req_id, .total = 10, .enrs = &.{} };
    const plaintext = try nodes.encodeInto(&nodes_buffer);
    try deliverEncrypted(&actor, io, recording.sender(), &ingress, &outbox, endpoint, &stable.recipient_key, plaintext, 2);
    try std.testing.expectEqual(@as(u64, 10), actor.requests.get(.init(endpoint, req_id)).?.response.nodes.total_responses.?);
    try std.testing.expectEqual(@as(u64, 1), actor.requests.get(.init(endpoint, req_id)).?.response.nodes.responses_received);

    var inconsistent_buffer: [128]u8 = undefined;
    const inconsistent = message.Nodes{ .req_id = req_id, .total = 9, .enrs = &.{} };
    try deliverEncrypted(&actor, io, recording.sender(), &ingress, &outbox, endpoint, &stable.recipient_key, try inconsistent.encodeInto(&inconsistent_buffer), 3);
    try std.testing.expectEqual(@as(u64, 1), actor.requests.get(.init(endpoint, req_id)).?.response.nodes.responses_received);

    for (4..9) |nonce| try deliverEncrypted(
        &actor,
        io,
        recording.sender(),
        &ingress,
        &outbox,
        endpoint,
        &stable.recipient_key,
        plaintext,
        @intCast(nonce),
    );
    try std.testing.expectEqual(@as(u64, 6), actor.requests.get(.init(endpoint, req_id)).?.response.nodes.responses_received);
    try std.testing.expectEqual(@as(usize, 1), actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 1), ingress.permitCount());

    for (9..13) |nonce| try deliverEncrypted(
        &actor,
        io,
        recording.sender(),
        &ingress,
        &outbox,
        endpoint,
        &stable.recipient_key,
        plaintext,
        @intCast(nonce),
    );
    try std.testing.expectEqual(@as(usize, 0), actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 0), ingress.permitCount());
    var nodes_event = outbox.pop() orelse return error.MissingNodesEvent;
    defer nodes_event.deinit(alloc);
    try std.testing.expect(nodes_event == .nodes);
}

fn deliverEncrypted(
    actor: *actor_mod.Actor,
    io: std.Io,
    sender: transport.Sender,
    ingress: *admission.IngressAdmission,
    outbox: *events.EventOutbox,
    endpoint: types.Endpoint,
    read_key: *const [16]u8,
    plaintext: []const u8,
    nonce_byte: u8,
) !void {
    var buffer: [packet.MAX_PACKET_SIZE]u8 = undefined;
    var masking_iv = [_]u8{0x61} ** packet.MASKING_IV_SIZE;
    masking_iv[0] = nonce_byte;
    const nonce = [_]u8{nonce_byte} ** packet.NONCE_SIZE;
    const encoded = try packet.encodeMessagePacketInto(&buffer, .{
        .kind = .ordinary,
        .masking_iv = &masking_iv,
        .recipient_node_id = &actor.local_node_id,
        .nonce = &nonce,
        .authdata = &endpoint.node_id,
        .write_key = read_key,
        .plaintext = plaintext,
    });
    actor.handlePacket(.{ .io = io, .sender = sender, .ingress = ingress, .outbox = outbox }, encoded, endpoint.addr);
}

test "competing WHOAREYOU is rejected before a conflicting handshake is sent" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x11} ** 32));
    const local_id = enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&local_key));
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x22} ** 32));
    const remote_pubkey = secp.compressedPubkey(&remote_key);
    const remote_id = enr.nodeIdFromCompressedPubkey(&remote_pubkey);
    const cfg = config.Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
        .local_node_id = local_id,
        .rate_limiter = null,
        .limits = .{ .max_active_requests = 4, .max_queued_requests = 4, .event_capacity = 8, .command_capacity = 8 },
    };
    var ingress = try admission.IngressAdmission.init(alloc, null, cfg.limits.max_active_requests);
    defer ingress.deinit();
    var outbox = try events.EventOutbox.init(io, alloc, cfg.limits.event_capacity);
    defer outbox.deinit();
    var actor = try actor_mod.Actor.init(alloc, cfg);
    defer actor.deinit(&ingress);
    var recording = transport.RecordingSender.init(alloc);
    defer recording.deinit();
    const address = @import("types.zig").Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 9000 } };
    const endpoint = @import("types.zig").Endpoint{ .node_id = remote_id, .addr = address };
    const stable = session_book.StableSession{
        .initiator_key = [_]u8{0x31} ** 16,
        .recipient_key = [_]u8{0x32} ** 16,
    };
    const now_ns: i64 = @intCast(std.Io.Timestamp.now(io, .real).toNanoseconds());
    actor.sessions.put(endpoint, stable, now_ns);

    const req_a = try actor.sendPing(.{ .io = io, .sender = recording.sender(), .ingress = &ingress, .outbox = &outbox }, endpoint, &remote_pubkey, 1, .api);
    const req_b = try actor.sendPing(.{ .io = io, .sender = recording.sender(), .ingress = &ingress, .outbox = &outbox }, endpoint, &remote_pubkey, 1, .api);
    var sent_a = recording.datagrams.items[0].bytes;
    var sent_b = recording.datagrams.items[1].bytes;
    const nonce_a = (try packet.decode(sent_a.bytes[0..sent_a.len], &remote_id)).static_header.nonce;
    const nonce_b = (try packet.decode(sent_b.bytes[0..sent_b.len], &remote_id)).static_header.nonce;
    var challenge_a: [packet.WHOAREYOU_CHALLENGE_DATA_SIZE]u8 = undefined;
    var challenge_b: [packet.WHOAREYOU_CHALLENGE_DATA_SIZE]u8 = undefined;
    const first = try packet.encodeWhoareyouPacketInto(&challenge_a, .{
        .masking_iv = &([_]u8{0x41} ** 16),
        .recipient_node_id = &local_id,
        .request_nonce = &nonce_a,
        .id_nonce = &([_]u8{0x51} ** 16),
        .enr_seq = 0,
    }, null);
    const second = try packet.encodeWhoareyouPacketInto(&challenge_b, .{
        .masking_iv = &([_]u8{0x42} ** 16),
        .recipient_node_id = &local_id,
        .request_nonce = &nonce_b,
        .id_nonce = &([_]u8{0x52} ** 16),
        .enr_seq = 0,
    }, null);
    actor.handlePacket(.{ .io = io, .sender = recording.sender(), .ingress = &ingress, .outbox = &outbox }, first, address);
    try std.testing.expectEqual(@as(usize, 3), recording.datagrams.items.len);
    actor.handlePacket(.{ .io = io, .sender = recording.sender(), .ingress = &ingress, .outbox = &outbox }, first, address);
    try std.testing.expectEqual(@as(usize, 3), recording.datagrams.items.len);
    actor.handlePacket(.{ .io = io, .sender = recording.sender(), .ingress = &ingress, .outbox = &outbox }, second, address);
    try std.testing.expectEqual(@as(usize, 3), recording.datagrams.items.len);
    const retained = actor.sessions.get(endpoint, now_ns) orelse return error.MissingStableSession;
    try std.testing.expectEqual(stable.initiator_key, retained.initiator_key);
    try std.testing.expectEqual(stable.recipient_key, retained.recipient_key);
    try std.testing.expect(actor.requests.get(.init(endpoint, req_a)) != null);
    try std.testing.expect(actor.requests.get(.init(endpoint, req_b)) != null);
    try std.testing.expect(actor.requests.hasChallenge(&nonce_b, address));
}

test "HANDSHAKE send failure leaves WHOAREYOU request state unchanged" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x53} ** 32));
    const local_id = enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&local_key));
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x54} ** 32));
    const remote_pubkey = secp.compressedPubkey(&remote_key);
    const remote_id = enr.nodeIdFromCompressedPubkey(&remote_pubkey);
    const endpoint = types.Endpoint{
        .node_id = remote_id,
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 14 }, .port = 9014 } },
    };
    const cfg = config.Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
        .local_node_id = local_id,
        .rate_limiter = null,
        .limits = .{ .max_active_requests = 2, .max_queued_requests = 2, .event_capacity = 2, .command_capacity = 2 },
    };
    var ingress = try admission.IngressAdmission.init(alloc, null, cfg.limits.max_active_requests);
    defer ingress.deinit();
    var outbox = try events.EventOutbox.init(io, alloc, cfg.limits.event_capacity);
    defer outbox.deinit();
    var actor = try actor_mod.Actor.init(alloc, cfg);
    defer actor.deinit(&ingress);
    var recording = transport.RecordingSender.init(alloc);
    defer recording.deinit();
    const req_id = try actor.sendPing(.{ .io = io, .sender = recording.sender(), .ingress = &ingress, .outbox = &outbox }, endpoint, &remote_pubkey, 0, .api);
    var probe = recording.datagrams.items[0].bytes;
    const request_nonce = (try packet.decode(probe.bytes[0..probe.len], &remote_id)).static_header.nonce;
    var challenge_buffer: [packet.WHOAREYOU_CHALLENGE_DATA_SIZE]u8 = undefined;
    const challenge = try packet.encodeWhoareyouPacketInto(&challenge_buffer, .{
        .masking_iv = &([_]u8{0x55} ** 16),
        .recipient_node_id = &local_id,
        .request_nonce = &request_nonce,
        .id_nonce = &([_]u8{0x56} ** 16),
        .enr_seq = 0,
    }, null);
    recording.fail_next = true;
    actor.handlePacket(.{ .io = io, .sender = recording.sender(), .ingress = &ingress, .outbox = &outbox }, challenge, endpoint.addr);

    try std.testing.expectEqual(@as(usize, 1), recording.datagrams.items.len);
    try std.testing.expectEqual(@as(usize, 1), ingress.permitCount());
    try std.testing.expect(actor.requests.hasChallenge(&request_nonce, endpoint.addr));
    try std.testing.expect(actor.requests.pendingKeys(endpoint) == null);
    const active = actor.requests.get(.init(endpoint, req_id)) orelse return error.MissingRequestAfterSendFailure;
    try std.testing.expect(active.phase == .awaiting_whoareyou);
}

test "failed ciphertext does not refresh stable session LRU recency" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x21} ** 32));
    const local_id = enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&local_key));
    const cfg = config.Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
        .local_node_id = local_id,
        .rate_limiter = null,
        .limits = .{
            .max_active_requests = 2,
            .max_queued_requests = 2,
            .session_capacity = 2,
            .event_capacity = 2,
            .command_capacity = 2,
        },
    };
    var ingress = try admission.IngressAdmission.init(alloc, null, cfg.limits.max_active_requests);
    defer ingress.deinit();
    var outbox = try events.EventOutbox.init(io, alloc, cfg.limits.event_capacity);
    defer outbox.deinit();
    var actor = try actor_mod.Actor.init(alloc, cfg);
    defer actor.deinit(&ingress);
    var recording = transport.RecordingSender.init(alloc);
    defer recording.deinit();
    const lru_endpoint = types.Endpoint{
        .node_id = [_]u8{0xa1} ** 32,
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 41 }, .port = 9041 } },
    };
    const fresh_endpoint = types.Endpoint{
        .node_id = [_]u8{0xa2} ** 32,
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 42 }, .port = 9042 } },
    };
    const third_endpoint = types.Endpoint{
        .node_id = [_]u8{0xa3} ** 32,
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 43 }, .port = 9043 } },
    };
    const stable = session_book.StableSession{ .initiator_key = [_]u8{0xa4} ** 16, .recipient_key = [_]u8{0xa5} ** 16 };
    actor.sessions.put(lru_endpoint, stable, 0);
    actor.sessions.put(fresh_endpoint, stable, 1);

    // A source-spoofing attacker sends undecryptable ciphertext for the LRU
    // session. Tentative decrypt must peek and leave eviction order unchanged.
    var garbage = try encodeEncryptedPacket(&actor, lru_endpoint.node_id, &([_]u8{0xff} ** 16), &.{message.MSG_PING}, 21);
    actor.handlePacket(.{ .io = io, .sender = recording.sender(), .ingress = &ingress, .outbox = &outbox }, garbage.bytes[0..garbage.len], lru_endpoint.addr);
    try std.testing.expect(actor.sessions.peek(lru_endpoint, 2) != null);

    actor.sessions.put(third_endpoint, stable, 3);
    try std.testing.expect(actor.sessions.peek(lru_endpoint, 4) == null);
    try std.testing.expect(actor.sessions.peek(fresh_endpoint, 4) != null);
    try std.testing.expect(actor.sessions.peek(third_endpoint, 4) != null);
}

test "authenticated packets reject stale nonce and wrong source address" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x57} ** 32));
    const local_id = enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&local_key));
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x58} ** 32));
    const remote_pubkey = secp.compressedPubkey(&remote_key);
    const remote_id = enr.nodeIdFromCompressedPubkey(&remote_pubkey);
    const endpoint = types.Endpoint{
        .node_id = remote_id,
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 18 }, .port = 9018 } },
    };
    const wrong_address = types.Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 19 }, .port = 9019 } };
    const cfg = config.Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
        .local_node_id = local_id,
        .rate_limiter = null,
        .limits = .{ .max_active_requests = 2, .max_queued_requests = 2, .event_capacity = 2, .command_capacity = 2 },
    };
    var ingress = try admission.IngressAdmission.init(alloc, null, cfg.limits.max_active_requests);
    defer ingress.deinit();
    var outbox = try events.EventOutbox.init(io, alloc, cfg.limits.event_capacity);
    defer outbox.deinit();
    var actor = try actor_mod.Actor.init(alloc, cfg);
    defer actor.deinit(&ingress);
    var recording = transport.RecordingSender.init(alloc);
    defer recording.deinit();
    try std.testing.expect(actor.addNode(remote_id, &remote_pubkey, endpoint.addr, null, outbound.nowNs(io)));
    const stable = session_book.StableSession{ .initiator_key = [_]u8{0x61} ** 16, .recipient_key = [_]u8{0x62} ** 16 };
    actor.sessions.put(endpoint, stable, outbound.nowNs(io));
    const ping = message.Ping{ .req_id = try message.ReqId.fromSlice(&.{1}), .enr_seq = 0 };
    var plaintext_buffer: [128]u8 = undefined;
    const plaintext = try ping.encodeInto(&plaintext_buffer);
    const replay = try encodeEncryptedPacket(&actor, endpoint.node_id, &stable.recipient_key, plaintext, 1);
    var first = replay;
    actor.handlePacket(.{ .io = io, .sender = recording.sender(), .ingress = &ingress, .outbox = &outbox }, first.bytes[0..first.len], endpoint.addr);
    try std.testing.expectEqual(@as(usize, 1), recording.datagrams.items.len);
    var duplicate = replay;
    actor.handlePacket(.{ .io = io, .sender = recording.sender(), .ingress = &ingress, .outbox = &outbox }, duplicate.bytes[0..duplicate.len], endpoint.addr);
    try std.testing.expectEqual(@as(usize, 1), recording.datagrams.items.len);

    var wrong_source = try encodeEncryptedPacket(&actor, endpoint.node_id, &stable.recipient_key, plaintext, 2);
    actor.handlePacket(.{ .io = io, .sender = recording.sender(), .ingress = &ingress, .outbox = &outbox }, wrong_source.bytes[0..wrong_source.len], wrong_address);
    try std.testing.expectEqual(@as(usize, 2), recording.datagrams.items.len);
    try std.testing.expect(recording.datagrams.items[1].address.eql(&wrong_address));
    var whoareyou = recording.datagrams.items[1].bytes;
    try std.testing.expectEqual(packet.FLAG_WHOAREYOU, (try packet.decode(whoareyou.bytes[0..whoareyou.len], &remote_id)).static_header.flag);
    try std.testing.expectEqual(@as(u64, 1), actor.metrics.rcvd_message_count[metrics.MessageType.ping.index()]);
}

test "session nonce epoch retires at capacity and never redispatches its first request" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x5d} ** 32));
    const local_id = enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&local_key));
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x5e} ** 32));
    const remote_id = enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&remote_key));
    const endpoint = types.Endpoint{
        .node_id = remote_id,
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 22 }, .port = 9022 } },
    };
    const cfg = config.Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
        .local_node_id = local_id,
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
    var ingress = try admission.IngressAdmission.init(alloc, null, try admission.permitCapacity(cfg.limits));
    defer ingress.deinit();
    var outbox = try events.EventOutbox.init(io, alloc, cfg.limits.event_capacity);
    defer outbox.deinit();
    var actor = try actor_mod.Actor.init(alloc, cfg);
    defer actor.deinit(&ingress);
    var recording = transport.RecordingSender.init(alloc);
    defer recording.deinit();
    const stable = session_book.StableSession{
        .initiator_key = [_]u8{0x5f} ** 16,
        .recipient_key = [_]u8{0x60} ** 16,
    };
    actor.sessions.put(endpoint, stable, outbound.nowNs(io));

    const original_request = message.TalkReq{
        .req_id = try message.ReqId.fromSlice(&.{1}),
        .protocol = "epoch",
        .request = "original",
    };
    var original_plaintext_buffer: [128]u8 = undefined;
    var original_packet = try encodeEncryptedPacket(
        &actor,
        remote_id,
        &stable.recipient_key,
        try original_request.encodeInto(&original_plaintext_buffer),
        1,
    );
    actor.handlePacket(
        .{ .io = io, .sender = recording.sender(), .ingress = &ingress, .outbox = &outbox },
        original_packet.bytes[0..original_packet.len],
        endpoint.addr,
    );

    const filler = message.TalkResp{ .req_id = try message.ReqId.fromSlice(&.{2}), .response = "filler" };
    var filler_plaintext_buffer: [128]u8 = undefined;
    const filler_plaintext = try filler.encodeInto(&filler_plaintext_buffer);
    for (0..session_book.SEEN_NONCES_CAP) |index| {
        var filler_packet = try encodeEncryptedPacket(
            &actor,
            remote_id,
            &stable.recipient_key,
            filler_plaintext,
            @intCast(index + 2),
        );
        actor.handlePacket(
            .{ .io = io, .sender = recording.sender(), .ingress = &ingress, .outbox = &outbox },
            filler_packet.bytes[0..filler_packet.len],
            endpoint.addr,
        );
    }
    try std.testing.expect(actor.sessions.peek(endpoint, outbound.nowNs(io)) == null);
    try std.testing.expectEqual(@as(usize, 1), actor.sessions.challengeCount());
    try std.testing.expectEqual(@as(usize, 1), ingress.permitCount());
    try std.testing.expectEqual(@as(usize, 1), recording.datagrams.items.len);

    actor.handlePacket(
        .{ .io = io, .sender = recording.sender(), .ingress = &ingress, .outbox = &outbox },
        original_packet.bytes[0..original_packet.len],
        endpoint.addr,
    );
    try std.testing.expectEqual(@as(u64, 1), actor.metrics.rcvd_message_count[metrics.MessageType.talkreq.index()]);
    try std.testing.expectEqual(@as(u64, session_book.SEEN_NONCES_CAP - 1), actor.metrics.rcvd_message_count[metrics.MessageType.talkresp.index()]);
    try std.testing.expectEqual(@as(usize, 1), recording.datagrams.items.len);
}

test "successful handshake records initial probe nonce and replay is inert" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const key_a = try secp.keyPairFromSecret(&([_]u8{0x63} ** 32));
    const pubkey_a = secp.compressedPubkey(&key_a);
    const id_a = enr.nodeIdFromCompressedPubkey(&pubkey_a);
    const key_b = try secp.keyPairFromSecret(&([_]u8{0x64} ** 32));
    const pubkey_b = secp.compressedPubkey(&key_b);
    const id_b = enr.nodeIdFromCompressedPubkey(&pubkey_b);
    const address_a = types.Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 23 }, .port = 9023 } };
    const address_b = types.Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 24 }, .port = 9024 } };
    const limits = config.Limits{
        .max_active_requests = 1,
        .max_queued_requests = 1,
        .challenge_capacity = 1,
        .response_recovery_capacity = 1,
        .event_capacity = 4,
        .command_capacity = 1,
    };
    const config_a = config.Config{
        .bind_addresses = .{ .ip4 = address_a },
        .local_key_pair = key_a,
        .local_node_id = id_a,
        .rate_limiter = null,
        .limits = limits,
    };
    const config_b = config.Config{
        .bind_addresses = .{ .ip4 = address_b },
        .local_key_pair = key_b,
        .local_node_id = id_b,
        .rate_limiter = null,
        .limits = limits,
    };
    var ingress_a = try admission.IngressAdmission.init(alloc, null, try admission.permitCapacity(limits));
    defer ingress_a.deinit();
    var ingress_b = try admission.IngressAdmission.init(alloc, null, try admission.permitCapacity(limits));
    defer ingress_b.deinit();
    var outbox_a = try events.EventOutbox.init(io, alloc, limits.event_capacity);
    defer outbox_a.deinit();
    var outbox_b = try events.EventOutbox.init(io, alloc, limits.event_capacity);
    defer outbox_b.deinit();
    var actor_a = try actor_mod.Actor.init(alloc, config_a);
    defer actor_a.deinit(&ingress_a);
    var actor_b = try actor_mod.Actor.init(alloc, config_b);
    defer actor_b.deinit(&ingress_b);
    var sender_a = transport.RecordingSender.init(alloc);
    defer sender_a.deinit();
    var sender_b = transport.RecordingSender.init(alloc);
    defer sender_b.deinit();
    try std.testing.expect(actor_a.addNode(id_b, &pubkey_b, address_b, null, outbound.nowNs(io)));
    try std.testing.expect(actor_b.addNode(id_a, &pubkey_a, address_a, null, outbound.nowNs(io)));

    _ = try actor_a.sendPing(
        .{ .io = io, .sender = sender_a.sender(), .ingress = &ingress_a, .outbox = &outbox_a },
        .{ .node_id = id_b, .addr = address_b },
        &pubkey_b,
        0,
        .api,
    );
    var original_probe = sender_a.datagrams.items[0].bytes;
    const probe_nonce = (try packet.decode(original_probe.bytes[0..original_probe.len], &id_b)).static_header.nonce;
    deliver(&sender_a, 0, &actor_b, io, sender_b.sender(), &ingress_b, &outbox_b, address_a);
    deliver(&sender_b, 0, &actor_a, io, sender_a.sender(), &ingress_a, &outbox_a, address_b);
    deliver(&sender_a, 1, &actor_b, io, sender_b.sender(), &ingress_b, &outbox_b, address_a);
    try std.testing.expectEqual(@as(usize, 0), actor_b.sessions.challengeCount());
    try std.testing.expectEqual(@as(usize, 2), sender_b.datagrams.items.len);
    const established = actor_b.sessions.get(.{ .node_id = id_a, .addr = address_a }, outbound.nowNs(io)) orelse return error.MissingEstablishedSession;
    try std.testing.expect(established.seen_nonces.contains(&probe_nonce));

    actor_b.handlePacket(
        .{ .io = io, .sender = sender_b.sender(), .ingress = &ingress_b, .outbox = &outbox_b },
        original_probe.bytes[0..original_probe.len],
        address_a,
    );
    try std.testing.expectEqual(@as(u64, 1), actor_b.metrics.rcvd_message_count[metrics.MessageType.ping.index()]);
    try std.testing.expectEqual(@as(usize, 0), actor_b.sessions.challengeCount());
    try std.testing.expectEqual(@as(usize, 2), sender_b.datagrams.items.len);
}

fn encodeEncryptedPacket(actor: *const actor_mod.Actor, source_id: types.NodeId, read_key: *const [16]u8, plaintext: []const u8, nonce_byte: u8) !types.PacketBytes {
    var buffer: [packet.MAX_PACKET_SIZE]u8 = undefined;
    const nonce = [_]u8{nonce_byte} ** packet.NONCE_SIZE;
    const encoded = try packet.encodeMessagePacketInto(&buffer, .{
        .kind = .ordinary,
        .masking_iv = &([_]u8{0x63} ** packet.MASKING_IV_SIZE),
        .recipient_node_id = &actor.local_node_id,
        .nonce = &nonce,
        .authdata = &source_id,
        .write_key = read_key,
        .plaintext = plaintext,
    });
    return types.PacketBytes.init(encoded);
}

test "old key remains accepted without promotion until candidate response" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x59} ** 32));
    const local_id = enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&local_key));
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x5a} ** 32));
    const remote_pubkey = secp.compressedPubkey(&remote_key);
    const remote_id = enr.nodeIdFromCompressedPubkey(&remote_pubkey);
    const endpoint = types.Endpoint{
        .node_id = remote_id,
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 20 }, .port = 9020 } },
    };
    const cfg = config.Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
        .local_node_id = local_id,
        .rate_limiter = null,
        .limits = .{ .max_active_requests = 2, .max_queued_requests = 2, .event_capacity = 2, .command_capacity = 2 },
    };
    var ingress = try admission.IngressAdmission.init(alloc, null, cfg.limits.max_active_requests);
    defer ingress.deinit();
    var outbox = try events.EventOutbox.init(io, alloc, cfg.limits.event_capacity);
    defer outbox.deinit();
    var actor = try actor_mod.Actor.init(alloc, cfg);
    defer actor.deinit(&ingress);
    var recording = transport.RecordingSender.init(alloc);
    defer recording.deinit();
    try std.testing.expect(actor.addNode(remote_id, &remote_pubkey, endpoint.addr, null, outbound.nowNs(io)));
    const old = session_book.StableSession{ .initiator_key = [_]u8{0x71} ** 16, .recipient_key = [_]u8{0x72} ** 16 };
    actor.sessions.put(endpoint, old, outbound.nowNs(io));
    const req_id = try actor.sendPing(.{ .io = io, .sender = recording.sender(), .ingress = &ingress, .outbox = &outbox }, endpoint, &remote_pubkey, 0, .api);
    var sent = recording.datagrams.items[0].bytes;
    const request_nonce = (try packet.decode(sent.bytes[0..sent.len], &remote_id)).static_header.nonce;
    var challenge_buffer: [packet.WHOAREYOU_CHALLENGE_DATA_SIZE]u8 = undefined;
    const challenge = try packet.encodeWhoareyouPacketInto(&challenge_buffer, .{
        .masking_iv = &([_]u8{0x73} ** 16),
        .recipient_node_id = &local_id,
        .request_nonce = &request_nonce,
        .id_nonce = &([_]u8{0x74} ** 16),
        .enr_seq = 0,
    }, null);
    actor.handlePacket(.{ .io = io, .sender = recording.sender(), .ingress = &ingress, .outbox = &outbox }, challenge, endpoint.addr);
    const pending = actor.requests.pendingKeys(endpoint) orelse return error.MissingPendingRekey;
    try std.testing.expectEqual(@as(usize, 2), recording.datagrams.items.len);

    const old_ping = message.Ping{ .req_id = try message.ReqId.fromSlice(&.{0xa1}), .enr_seq = 0 };
    var old_ping_buffer: [128]u8 = undefined;
    var old_response = try encodeEncryptedPacket(&actor, remote_id, &old.recipient_key, try old_ping.encodeInto(&old_ping_buffer), 9);
    actor.handlePacket(.{ .io = io, .sender = recording.sender(), .ingress = &ingress, .outbox = &outbox }, old_response.bytes[0..old_response.len], endpoint.addr);
    const still_pending = actor.requests.pendingKeys(endpoint) orelse return error.PendingRekeyWasPromotedByOldKey;
    try std.testing.expect(types.RequestKeyContext.eql(.{}, pending.key, still_pending.key));
    try std.testing.expect(actor.requests.shouldQueue(endpoint));
    try std.testing.expectEqual(@as(usize, 1), actor.requests.activeCount());
    const still_old = actor.sessions.get(endpoint, outbound.nowNs(io)) orelse return error.MissingOldSession;
    try std.testing.expectEqual(old.initiator_key, still_old.initiator_key);
    try std.testing.expectEqual(old.recipient_key, still_old.recipient_key);
    try std.testing.expectEqual(@as(usize, 3), recording.datagrams.items.len);

    const pong = message.Pong{
        .req_id = req_id,
        .enr_seq = 0,
        .recipient_ip = .{ .ip4 = .{ 127, 0, 0, 1 } },
        .recipient_port = 9000,
    };
    var pong_buffer: [128]u8 = undefined;
    var response = try encodeEncryptedPacket(&actor, remote_id, &pending.keys.recipient_key, try pong.encodeInto(&pong_buffer), 10);
    actor.handlePacket(.{ .io = io, .sender = recording.sender(), .ingress = &ingress, .outbox = &outbox }, response.bytes[0..response.len], endpoint.addr);

    try std.testing.expectEqual(@as(usize, 0), actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 1), ingress.permitCount());
    actor.responses.prune(std.math.maxInt(i64), &ingress);
    try std.testing.expectEqual(@as(usize, 0), ingress.permitCount());
    try std.testing.expect(actor.requests.pendingKeys(endpoint) == null);
    const promoted = actor.sessions.get(endpoint, outbound.nowNs(io)) orelse return error.MissingPromotedSession;
    try std.testing.expectEqual(pending.keys.initiator_key, promoted.initiator_key);
    try std.testing.expectEqual(pending.keys.recipient_key, promoted.recipient_key);
    var pong_event = outbox.pop() orelse return error.MissingPongEvent;
    defer pong_event.deinit(alloc);
    try std.testing.expect(pong_event == .pong);
}

test "rekey lane queues stable-key requests and drains FIFO after candidate proof" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x5b} ** 32));
    const local_id = enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&local_key));
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x5c} ** 32));
    const remote_pubkey = secp.compressedPubkey(&remote_key);
    const remote_id = enr.nodeIdFromCompressedPubkey(&remote_pubkey);
    const endpoint = types.Endpoint{
        .node_id = remote_id,
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 21 }, .port = 9021 } },
    };
    const cfg = config.Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
        .local_node_id = local_id,
        .rate_limiter = null,
        .limits = .{
            .max_active_requests = 4,
            .max_queued_requests = 4,
            .max_queued_requests_per_endpoint = 3,
            .event_capacity = 4,
            .command_capacity = 2,
        },
    };
    var ingress = try admission.IngressAdmission.init(alloc, null, cfg.limits.max_active_requests);
    defer ingress.deinit();
    var outbox = try events.EventOutbox.init(io, alloc, cfg.limits.event_capacity);
    defer outbox.deinit();
    var actor = try actor_mod.Actor.init(alloc, cfg);
    defer actor.deinit(&ingress);
    var recording = transport.RecordingSender.init(alloc);
    defer recording.deinit();
    try std.testing.expect(actor.addNode(remote_id, &remote_pubkey, endpoint.addr, null, outbound.nowNs(io)));
    const old = session_book.StableSession{ .initiator_key = [_]u8{0x75} ** 16, .recipient_key = [_]u8{0x76} ** 16 };
    actor.sessions.put(endpoint, old, outbound.nowNs(io));

    _ = try actor.sendPing(.{ .io = io, .sender = recording.sender(), .ingress = &ingress, .outbox = &outbox }, endpoint, &remote_pubkey, 0, .api);
    var sent = recording.datagrams.items[0].bytes;
    const request_nonce = (try packet.decode(sent.bytes[0..sent.len], &remote_id)).static_header.nonce;
    var challenge_buffer: [packet.WHOAREYOU_CHALLENGE_DATA_SIZE]u8 = undefined;
    const challenge = try packet.encodeWhoareyouPacketInto(&challenge_buffer, .{
        .masking_iv = &([_]u8{0x77} ** 16),
        .recipient_node_id = &local_id,
        .request_nonce = &request_nonce,
        .id_nonce = &([_]u8{0x78} ** 16),
        .enr_seq = 0,
    }, null);
    actor.handlePacket(.{ .io = io, .sender = recording.sender(), .ingress = &ingress, .outbox = &outbox }, challenge, endpoint.addr);
    const pending = actor.requests.pendingKeys(endpoint) orelse return error.MissingPendingRekey;
    try std.testing.expectEqual(@as(usize, 2), recording.datagrams.items.len);

    const second_id = try actor.sendPing(.{ .io = io, .sender = recording.sender(), .ingress = &ingress, .outbox = &outbox }, endpoint, &remote_pubkey, 1, .api);
    const third_id = try actor.sendPing(.{ .io = io, .sender = recording.sender(), .ingress = &ingress, .outbox = &outbox }, endpoint, &remote_pubkey, 2, .api);
    try std.testing.expectEqual(@as(usize, 2), recording.datagrams.items.len);
    try std.testing.expectEqual(@as(usize, 2), actor.requests.queuedCount());

    const proof_ping = message.Ping{ .req_id = try message.ReqId.fromSlice(&.{0xa2}), .enr_seq = 0 };
    var proof_buffer: [128]u8 = undefined;
    var proof = try encodeEncryptedPacket(&actor, remote_id, &pending.keys.recipient_key, try proof_ping.encodeInto(&proof_buffer), 11);
    actor.handlePacket(.{ .io = io, .sender = recording.sender(), .ingress = &ingress, .outbox = &outbox }, proof.bytes[0..proof.len], endpoint.addr);

    try std.testing.expect(actor.requests.pendingKeys(endpoint) == null);
    try std.testing.expectEqual(@as(usize, 0), actor.requests.queuedCount());
    try std.testing.expectEqual(@as(usize, 5), recording.datagrams.items.len);
    const second_plaintext = try decryptRecorded(&recording, 3, remote_id, &pending.keys.initiator_key);
    const third_plaintext = try decryptRecorded(&recording, 4, remote_id, &pending.keys.initiator_key);
    const second_ping = try message.Ping.decode(second_plaintext.slice());
    const third_ping = try message.Ping.decode(third_plaintext.slice());
    try std.testing.expectEqualSlices(u8, second_id.slice(), second_ping.req_id.slice());
    try std.testing.expectEqualSlices(u8, third_id.slice(), third_ping.req_id.slice());
}

fn decryptRecorded(recording: *const transport.RecordingSender, index: usize, recipient_id: types.NodeId, read_key: *const [16]u8) !types.PacketBytes {
    var raw = recording.datagrams.items[index].bytes;
    var parsed = try packet.decode(raw.bytes[0..raw.len], &recipient_id);
    var plaintext_buffer: [packet.MAX_PACKET_SIZE]u8 = undefined;
    var ad_buffer: [packet.MAX_PACKET_SIZE]u8 = undefined;
    const plaintext = try packet.decryptMessageInto(
        &plaintext_buffer,
        &ad_buffer,
        read_key,
        &parsed.static_header.nonce,
        parsed.message_ciphertext,
        &parsed.masking_iv,
        parsed.header_raw,
    );
    return types.PacketBytes.init(plaintext);
}

test "initial tracked send failure is caller-visible and fully unwinds" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x61} ** 32));
    const local_id = enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&local_key));
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x62} ** 32));
    const remote_pubkey = secp.compressedPubkey(&remote_key);
    const remote_id = enr.nodeIdFromCompressedPubkey(&remote_pubkey);
    const cfg = config.Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
        .local_node_id = local_id,
        .rate_limiter = null,
        .limits = .{ .max_active_requests = 2, .max_queued_requests = 2, .event_capacity = 2, .command_capacity = 2 },
    };
    var ingress = try admission.IngressAdmission.init(alloc, null, cfg.limits.max_active_requests);
    defer ingress.deinit();
    var outbox = try events.EventOutbox.init(io, alloc, cfg.limits.event_capacity);
    defer outbox.deinit();
    var actor = try actor_mod.Actor.init(alloc, cfg);
    defer actor.deinit(&ingress);
    var recording = transport.RecordingSender.init(alloc);
    defer recording.deinit();
    recording.fail_next = true;
    const endpoint = @import("types.zig").Endpoint{
        .node_id = remote_id,
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 2 }, .port = 9000 } },
    };

    try std.testing.expectError(
        error.RecordingSendFailure,
        actor.sendFindNode(.{ .io = io, .sender = recording.sender(), .ingress = &ingress, .outbox = &outbox }, endpoint, &remote_pubkey, &.{1}, .api),
    );
    try std.testing.expectEqual(@as(usize, 0), recording.datagrams.items.len);
    try std.testing.expectEqual(@as(usize, 0), actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 0), actor.requests.queuedCount());
    try std.testing.expectEqual(@as(usize, 0), ingress.permitCount());
    actor.requests.assertInvariants();
}

test "WHOAREYOU and response send failures release prepared permits and retained state" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x9b} ** 32));
    const local_id = enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&local_key));
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x9c} ** 32));
    const remote_pubkey = secp.compressedPubkey(&remote_key);
    const remote_id = enr.nodeIdFromCompressedPubkey(&remote_pubkey);
    const endpoint = types.Endpoint{
        .node_id = remote_id,
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 45 }, .port = 9245 } },
    };
    const cfg = config.Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
        .local_node_id = local_id,
        .rate_limiter = null,
        .limits = .{
            .max_active_requests = 2,
            .max_queued_requests = 2,
            .challenge_capacity = 2,
            .response_recovery_capacity = 2,
            .event_capacity = 2,
            .command_capacity = 2,
        },
    };
    var ingress = try admission.IngressAdmission.init(alloc, null, try admission.permitCapacity(cfg.limits));
    defer ingress.deinit();
    var outbox = try events.EventOutbox.init(io, alloc, cfg.limits.event_capacity);
    defer outbox.deinit();
    var actor = try actor_mod.Actor.init(alloc, cfg);
    defer actor.deinit(&ingress);
    var recording = transport.RecordingSender.init(alloc);
    defer recording.deinit();
    try std.testing.expect(actor.addNode(remote_id, &remote_pubkey, endpoint.addr, null, outbound.nowNs(io)));
    actor.sessions.put(endpoint, .{
        .initiator_key = [_]u8{0xe1} ** 16,
        .recipient_key = [_]u8{0xe2} ** 16,
    }, outbound.nowNs(io));

    recording.fail_next = true;
    try std.testing.expectError(error.RecordingSendFailure, actor.sendTalkResponse(
        .{ .io = io, .sender = recording.sender(), .ingress = &ingress, .outbox = &outbox },
        endpoint,
        try message.ReqId.fromSlice(&.{1}),
        "failed",
    ));
    try std.testing.expectEqual(@as(usize, 0), actor.responses.count());
    try std.testing.expectEqual(@as(usize, 0), ingress.permitCount());

    try std.testing.expect(actor.sessions.remove(endpoint));
    var undecryptable = try encodeEncryptedPacket(&actor, remote_id, &([_]u8{0xff} ** 16), &.{message.MSG_PING}, 0xe3);
    recording.fail_next = true;
    actor.handlePacket(
        .{ .io = io, .sender = recording.sender(), .ingress = &ingress, .outbox = &outbox },
        undecryptable.bytes[0..undecryptable.len],
        endpoint.addr,
    );
    try std.testing.expectEqual(@as(usize, 0), actor.sessions.challengeCount());
    try std.testing.expectEqual(@as(usize, 0), ingress.permitCount());
    try std.testing.expectEqual(@as(usize, 0), recording.datagrams.items.len);
}

test "transactional capacity-one challenge replacement send failure preserves original" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x2c} ** 32));
    const local_id = enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&local_key));
    const remote_key_a = try secp.keyPairFromSecret(&([_]u8{0x2d} ** 32));
    const remote_id_a = enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&remote_key_a));
    const remote_key_b = try secp.keyPairFromSecret(&([_]u8{0x2e} ** 32));
    const remote_id_b = enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&remote_key_b));
    const endpoint_a = types.Endpoint{
        .node_id = remote_id_a,
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 46 }, .port = 9246 } },
    };
    const endpoint_b = types.Endpoint{
        .node_id = remote_id_b,
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 47 }, .port = 9247 } },
    };
    const cfg = config.Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
        .local_node_id = local_id,
        .rate_limiter = null,
        .limits = .{
            .max_active_requests = 1,
            .max_queued_requests = 1,
            .challenge_capacity = 1,
            .response_recovery_capacity = 1,
            .event_capacity = 1,
            .command_capacity = 1,
        },
    };
    var ingress = try admission.IngressAdmission.init(alloc, null, try admission.permitCapacity(cfg.limits));
    defer ingress.deinit();
    var outbox = try events.EventOutbox.init(io, alloc, cfg.limits.event_capacity);
    defer outbox.deinit();
    var actor = try actor_mod.Actor.init(alloc, cfg);
    defer actor.deinit(&ingress);
    var recording = transport.RecordingSender.init(alloc);
    defer recording.deinit();

    var first = try encodeEncryptedPacket(&actor, remote_id_a, &([_]u8{0xa1} ** 16), &.{message.MSG_PING}, 0xa2);
    actor.handlePacket(
        .{ .io = io, .sender = recording.sender(), .ingress = &ingress, .outbox = &outbox },
        first.bytes[0..first.len],
        endpoint_a.addr,
    );
    try std.testing.expect(actor.sessions.peekChallenge(endpoint_a, outbound.nowNs(io)) != null);
    try std.testing.expectEqual(@as(usize, 1), actor.sessions.challengeCount());
    try std.testing.expectEqual(@as(usize, 1), ingress.permitCount());

    recording.fail_next = true;
    var second = try encodeEncryptedPacket(&actor, remote_id_b, &([_]u8{0xb1} ** 16), &.{message.MSG_PING}, 0xb2);
    actor.handlePacket(
        .{ .io = io, .sender = recording.sender(), .ingress = &ingress, .outbox = &outbox },
        second.bytes[0..second.len],
        endpoint_b.addr,
    );
    try std.testing.expect(actor.sessions.peekChallenge(endpoint_a, outbound.nowNs(io)) != null);
    try std.testing.expect(actor.sessions.peekChallenge(endpoint_b, outbound.nowNs(io)) == null);
    try std.testing.expectEqual(@as(usize, 1), actor.sessions.challengeCount());
    try std.testing.expectEqual(@as(usize, 1), ingress.permitCount());
}

test "transactional capacity-one response replacement send failure preserves original" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x2f} ** 32));
    const local_id = enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&local_key));
    const remote_key_a = try secp.keyPairFromSecret(&([_]u8{0x30} ** 32));
    const remote_pubkey_a = secp.compressedPubkey(&remote_key_a);
    const remote_id_a = enr.nodeIdFromCompressedPubkey(&remote_pubkey_a);
    const remote_key_b = try secp.keyPairFromSecret(&([_]u8{0x31} ** 32));
    const remote_pubkey_b = secp.compressedPubkey(&remote_key_b);
    const remote_id_b = enr.nodeIdFromCompressedPubkey(&remote_pubkey_b);
    const endpoint_a = types.Endpoint{
        .node_id = remote_id_a,
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 48 }, .port = 9248 } },
    };
    const endpoint_b = types.Endpoint{
        .node_id = remote_id_b,
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 49 }, .port = 9249 } },
    };
    const cfg = config.Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
        .local_node_id = local_id,
        .rate_limiter = null,
        .limits = .{
            .max_active_requests = 1,
            .max_queued_requests = 1,
            .challenge_capacity = 1,
            .response_recovery_capacity = 1,
            .event_capacity = 1,
            .command_capacity = 1,
        },
    };
    var ingress = try admission.IngressAdmission.init(alloc, null, try admission.permitCapacity(cfg.limits));
    defer ingress.deinit();
    var outbox = try events.EventOutbox.init(io, alloc, cfg.limits.event_capacity);
    defer outbox.deinit();
    var actor = try actor_mod.Actor.init(alloc, cfg);
    defer actor.deinit(&ingress);
    var recording = transport.RecordingSender.init(alloc);
    defer recording.deinit();
    try std.testing.expect(actor.addNode(remote_id_a, &remote_pubkey_a, endpoint_a.addr, null, outbound.nowNs(io)));
    try std.testing.expect(actor.addNode(remote_id_b, &remote_pubkey_b, endpoint_b.addr, null, outbound.nowNs(io)));
    actor.sessions.put(endpoint_a, .{ .initiator_key = [_]u8{0xc1} ** 16, .recipient_key = [_]u8{0xc2} ** 16 }, outbound.nowNs(io));
    actor.sessions.put(endpoint_b, .{ .initiator_key = [_]u8{0xd1} ** 16, .recipient_key = [_]u8{0xd2} ** 16 }, outbound.nowNs(io));

    try actor.sendTalkResponse(
        .{ .io = io, .sender = recording.sender(), .ingress = &ingress, .outbox = &outbox },
        endpoint_a,
        try message.ReqId.fromSlice(&.{1}),
        "first",
    );
    var sent = recording.datagrams.items[0].bytes;
    const first_nonce = (try packet.decode(sent.bytes[0..sent.len], &remote_id_a)).static_header.nonce;
    try std.testing.expect(actor.responses.hasLive(endpoint_a.addr, &first_nonce, outbound.nowNs(io)));
    try std.testing.expectEqual(@as(usize, 1), actor.responses.count());
    try std.testing.expectEqual(@as(usize, 1), ingress.permitCount());

    recording.fail_next = true;
    try std.testing.expectError(error.RecordingSendFailure, actor.sendTalkResponse(
        .{ .io = io, .sender = recording.sender(), .ingress = &ingress, .outbox = &outbox },
        endpoint_b,
        try message.ReqId.fromSlice(&.{2}),
        "second",
    ));
    try std.testing.expect(actor.responses.hasLive(endpoint_a.addr, &first_nonce, outbound.nowNs(io)));
    try std.testing.expectEqual(@as(usize, 1), actor.responses.count());
    try std.testing.expectEqual(@as(usize, 1), ingress.permitCount());
}

test "addEnr treats an older ENR for a known newer node as usable without an event" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x2b} ** 32));
    const local_id = enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&local_key));
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x2c} ** 32));
    const remote_id = enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&remote_key));
    var older_builder = enr.Builder.init(alloc, remote_key, 1);
    older_builder.ip = .{ 127, 0, 0, 61 };
    older_builder.udp = 9061;
    const older_enr = try older_builder.encode();
    defer alloc.free(older_enr);
    var newer_builder = enr.Builder.init(alloc, remote_key, 2);
    newer_builder.ip = .{ 127, 0, 0, 61 };
    newer_builder.udp = 9061;
    const newer_enr = try newer_builder.encode();
    defer alloc.free(newer_enr);
    const cfg = config.Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
        .local_node_id = local_id,
        .rate_limiter = null,
        .limits = .{ .max_active_requests = 2, .max_queued_requests = 2, .event_capacity = 4, .command_capacity = 2 },
    };
    var ingress = try admission.IngressAdmission.init(alloc, null, cfg.limits.max_active_requests);
    defer ingress.deinit();
    var outbox = try events.EventOutbox.init(io, alloc, cfg.limits.event_capacity);
    defer outbox.deinit();
    var actor = try actor_mod.Actor.init(alloc, cfg);
    defer actor.deinit(&ingress);

    try std.testing.expect(actor.addEnr(&outbox, newer_enr, 1));
    var added_event = outbox.pop() orelse return error.MissingEnrAdded;
    defer added_event.deinit(alloc);
    try std.testing.expect(added_event == .enr_added);

    // The stored ENR is newer: local-trust merge succeeds, the node stays
    // usable, and no duplicate/stale event is emitted.
    try std.testing.expect(actor.addEnr(&outbox, older_enr, 2));
    try std.testing.expect(actor.peers.known(&remote_id).?.runtime_contact_trusted);
    try std.testing.expectEqualSlices(u8, newer_enr, actor.peers.findEnr(&remote_id).?);
    try std.testing.expect(outbox.pop() == null);

    // An exact duplicate of the stored ENR also stays usable without an event.
    try std.testing.expect(actor.addEnr(&outbox, newer_enr, 3));
    try std.testing.expect(outbox.pop() == null);
}

test "event payload allocation failure preserves Actor state and counts one drop" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x73} ** 32));
    const local_id = enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&local_key));
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x74} ** 32));
    var remote_builder = enr.Builder.init(alloc, remote_key, 1);
    remote_builder.ip = .{ 127, 0, 0, 2 };
    remote_builder.udp = 9000;
    const remote_enr = try remote_builder.encode();
    defer alloc.free(remote_enr);
    const cfg = config.Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
        .local_node_id = local_id,
        .rate_limiter = null,
        .limits = .{ .max_active_requests = 2, .max_queued_requests = 2, .event_capacity = 2, .command_capacity = 2 },
    };
    var ingress = try admission.IngressAdmission.init(alloc, null, cfg.limits.max_active_requests);
    defer ingress.deinit();
    var outbox = try events.EventOutbox.init(io, alloc, cfg.limits.event_capacity);
    defer outbox.deinit();
    var actor = try actor_mod.Actor.init(alloc, cfg);
    defer actor.deinit(&ingress);
    var failing = std.testing.FailingAllocator.init(alloc, .{ .fail_index = 0 });
    actor.alloc = failing.allocator();
    const added = actor.addEnr(&outbox, remote_enr, 1);
    actor.alloc = alloc;

    try std.testing.expect(added);
    try std.testing.expect(failing.has_induced_failure);
    try std.testing.expectEqual(@as(u64, 1), outbox.droppedCount());
    const remote_id = enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&remote_key));
    try std.testing.expect(actor.peers.findEnr(&remote_id) != null);
    try std.testing.expect(outbox.pop() == null);
}

test "response payload allocation failure still completes and releases permit" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x60} ** 32));
    const local_id = enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&local_key));
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x63} ** 32));
    const remote_pubkey = secp.compressedPubkey(&remote_key);
    const remote_id = enr.nodeIdFromCompressedPubkey(&remote_pubkey);
    const endpoint = types.Endpoint{
        .node_id = remote_id,
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 23 }, .port = 9023 } },
    };
    const cfg = config.Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
        .local_node_id = local_id,
        .rate_limiter = null,
        .limits = .{ .max_active_requests = 2, .max_queued_requests = 2, .event_capacity = 2, .command_capacity = 2 },
    };
    var ingress = try admission.IngressAdmission.init(alloc, null, cfg.limits.max_active_requests);
    defer ingress.deinit();
    var outbox = try events.EventOutbox.init(io, alloc, cfg.limits.event_capacity);
    defer outbox.deinit();
    var actor = try actor_mod.Actor.init(alloc, cfg);
    defer actor.deinit(&ingress);
    var recording = transport.RecordingSender.init(alloc);
    defer recording.deinit();
    const stable = session_book.StableSession{ .initiator_key = [_]u8{0x64} ** 16, .recipient_key = [_]u8{0x65} ** 16 };
    actor.sessions.put(endpoint, stable, outbound.nowNs(io));
    const req_id = try actor.sendTalkRequest(.{ .io = io, .sender = recording.sender(), .ingress = &ingress, .outbox = &outbox }, endpoint, &remote_pubkey, "test", "request");
    const response = message.TalkResp{ .req_id = req_id, .response = "allocation must fail" };
    var response_buffer: [128]u8 = undefined;
    const plaintext = try response.encodeInto(&response_buffer);
    var failing = std.testing.FailingAllocator.init(alloc, .{ .fail_index = 0 });
    actor.alloc = failing.allocator();
    try deliverEncrypted(&actor, io, recording.sender(), &ingress, &outbox, endpoint, &stable.recipient_key, plaintext, 10);
    actor.alloc = alloc;

    try std.testing.expect(failing.has_induced_failure);
    try std.testing.expectEqual(@as(usize, 0), actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 0), ingress.permitCount());
    try std.testing.expectEqual(@as(u64, 1), outbox.droppedCount());
    try std.testing.expect(outbox.pop() == null);
}

test "full event outbox preserves completion and queued drain with one owned drop" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x64} ** 32));
    const local_id = enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&local_key));
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x65} ** 32));
    const remote_pubkey = secp.compressedPubkey(&remote_key);
    const remote_id = enr.nodeIdFromCompressedPubkey(&remote_pubkey);
    const endpoint = types.Endpoint{
        .node_id = remote_id,
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 25 }, .port = 9025 } },
    };
    const cfg = config.Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
        .local_node_id = local_id,
        .rate_limiter = null,
        .limits = .{ .max_active_requests = 3, .max_queued_requests = 3, .event_capacity = 1, .command_capacity = 2 },
    };
    var ingress = try admission.IngressAdmission.init(alloc, null, cfg.limits.max_active_requests);
    defer ingress.deinit();
    var outbox = try events.EventOutbox.init(io, alloc, cfg.limits.event_capacity);
    defer outbox.deinit();
    var actor = try actor_mod.Actor.init(alloc, cfg);
    defer actor.deinit(&ingress);
    var recording = transport.RecordingSender.init(alloc);
    defer recording.deinit();
    const stable = session_book.StableSession{ .initiator_key = [_]u8{0x66} ** 16, .recipient_key = [_]u8{0x67} ** 16 };
    actor.sessions.put(endpoint, stable, outbound.nowNs(io));
    const talk_id = try actor.sendTalkRequest(.{ .io = io, .sender = recording.sender(), .ingress = &ingress, .outbox = &outbox }, endpoint, &remote_pubkey, "test", "request");
    const queued_id = try message.ReqId.fromSlice(&.{9});
    const queued_ping = message.Ping{ .req_id = queued_id, .enr_seq = 0 };
    var queued_buffer: [128]u8 = undefined;
    try actor.requests.queue(try .init(.api, endpoint, &remote_pubkey, queued_id, .ping, &.{}, try queued_ping.encodeInto(&queued_buffer), std.math.maxInt(i64)));
    outbox.publish(.{ .local_enr_updated = .{ .seq = 1, .enr = try alloc.dupe(u8, "blocker") } });

    const response = message.TalkResp{ .req_id = talk_id, .response = "owned response" };
    var response_buffer: [128]u8 = undefined;
    try deliverEncrypted(&actor, io, recording.sender(), &ingress, &outbox, endpoint, &stable.recipient_key, try response.encodeInto(&response_buffer), 11);
    try std.testing.expectEqual(@as(u64, 1), outbox.droppedCount());
    try std.testing.expect(actor.requests.get(.init(endpoint, talk_id)) == null);
    try std.testing.expectEqual(@as(usize, 0), actor.requests.queuedCount());
    try std.testing.expect(actor.requests.get(.init(endpoint, queued_id)) != null);
    try std.testing.expectEqual(@as(usize, 1), ingress.permitCount());
    try std.testing.expectEqual(@as(usize, 2), recording.datagrams.items.len);
}

test "full event outbox preserves lookup finalization with one owned drop" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x68} ** 32));
    const local_id = enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&local_key));
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x69} ** 32));
    var remote_builder = enr.Builder.init(alloc, remote_key, 1);
    remote_builder.ip = .{ 127, 0, 0, 29 };
    remote_builder.udp = 9029;
    const remote_enr = try remote_builder.encode();
    defer alloc.free(remote_enr);
    const remote_id = (try enr.decode(remote_enr)).nodeId().?;
    const cfg = config.Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
        .local_node_id = local_id,
        .rate_limiter = null,
        .limits = .{ .max_active_requests = 2, .max_queued_requests = 2, .event_capacity = 1, .command_capacity = 2 },
    };
    var ingress = try admission.IngressAdmission.init(alloc, null, cfg.limits.max_active_requests);
    defer ingress.deinit();
    var outbox = try events.EventOutbox.init(io, alloc, cfg.limits.event_capacity);
    defer outbox.deinit();
    var actor = try actor_mod.Actor.init(alloc, cfg);
    defer actor.deinit(&ingress);
    try std.testing.expect(actor.peers.learnEnr(remote_enr, 0) != null);
    var lookup = try lookup_mod.Lookup.init(alloc, [_]u8{0} ** 32, &.{remote_id}, 0, actor.lookup_config);
    const contacted = lookup.nextPeer(actor.lookup_config).?;
    lookup.onSuccess(&contacted, &.{}, actor.lookup_config);
    actor.lookups.putAssumeCapacityNoClobber(1, lookup);
    outbox.publish(.{ .local_enr_updated = .{ .seq = 1, .enr = try alloc.dupe(u8, "blocker") } });

    actor.finishLookup(&outbox, 1, false);
    try std.testing.expectEqual(@as(usize, 0), actor.lookups.count());
    try std.testing.expectEqual(@as(u64, 1), outbox.droppedCount());
}

test "full event outbox preserves matching health completion with one drop" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x6a} ** 32));
    const local_id = enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&local_key));
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x6b} ** 32));
    const remote_pubkey = secp.compressedPubkey(&remote_key);
    var remote_builder = enr.Builder.init(alloc, remote_key, 1);
    remote_builder.ip = .{ 127, 0, 0, 31 };
    remote_builder.udp = 9031;
    const remote_enr = try remote_builder.encode();
    defer alloc.free(remote_enr);
    const remote_id = (try enr.decode(remote_enr)).nodeId().?;
    const endpoint = types.Endpoint{
        .node_id = remote_id,
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 31 }, .port = 9031 } },
    };
    const cfg = config.Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
        .local_node_id = local_id,
        .rate_limiter = null,
        .limits = .{ .max_active_requests = 2, .max_queued_requests = 2, .event_capacity = 1, .command_capacity = 2 },
    };
    var ingress = try admission.IngressAdmission.init(alloc, null, cfg.limits.max_active_requests);
    defer ingress.deinit();
    var outbox = try events.EventOutbox.init(io, alloc, cfg.limits.event_capacity);
    defer outbox.deinit();
    var actor = try actor_mod.Actor.init(alloc, cfg);
    defer actor.deinit(&ingress);
    var recording = transport.RecordingSender.init(alloc);
    defer recording.deinit();
    try std.testing.expect(actor.peers.learnEnr(remote_enr, 0) != null);
    _ = actor.peers.markResponsive(remote_id, endpoint.addr, 0, null);
    const stable = session_book.StableSession{ .initiator_key = [_]u8{0x6c} ** 16, .recipient_key = [_]u8{0x6d} ** 16 };
    actor.sessions.put(endpoint, stable, outbound.nowNs(io));
    const req_id = try actor.sendPing(.{ .io = io, .sender = recording.sender(), .ingress = &ingress, .outbox = &outbox }, endpoint, &remote_pubkey, 1, .{ .maintenance = .health });
    const key = types.RequestKey.init(endpoint, req_id);
    try std.testing.expect(actor.peers.armHealthRequest(key, .connected_only));
    outbox.publish(.{ .local_enr_updated = .{ .seq = 1, .enr = try alloc.dupe(u8, "blocker") } });
    const pong = message.Pong{ .req_id = req_id, .enr_seq = 1, .recipient_ip = .{ .ip4 = .{ 127, 0, 0, 1 } }, .recipient_port = 9000 };
    var pong_buffer: [128]u8 = undefined;
    try deliverEncrypted(&actor, io, recording.sender(), &ingress, &outbox, endpoint, &stable.recipient_key, try pong.encodeInto(&pong_buffer), 12);

    try std.testing.expectEqual(@as(u64, 1), outbox.droppedCount());
    try std.testing.expect(actor.peers.routing.getEntry(&remote_id).?.health_request == null);
    try std.testing.expectEqual(@as(usize, 0), actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 0), ingress.permitCount());
}

test "LocalRecord replacement is atomic across allocator failure" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x75} ** 32));
    const local_id = enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&local_key));
    var local_builder = enr.Builder.init(alloc, local_key, 1);
    local_builder.ip = .{ 127, 0, 0, 1 };
    local_builder.udp = 9000;
    const local_enr = try local_builder.encode();
    defer alloc.free(local_enr);
    const cfg = config.Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
        .local_node_id = local_id,
        .local_enr = local_enr,
        .addr_votes_to_update_enr = 1,
        .rate_limiter = null,
        .limits = .{ .max_active_requests = 2, .max_queued_requests = 2, .event_capacity = 2, .command_capacity = 2 },
    };
    var ingress = try admission.IngressAdmission.init(alloc, null, cfg.limits.max_active_requests);
    defer ingress.deinit();
    var outbox = try events.EventOutbox.init(io, alloc, cfg.limits.event_capacity);
    defer outbox.deinit();
    var actor = try actor_mod.Actor.init(alloc, cfg);
    defer actor.deinit(&ingress);
    var recording = transport.RecordingSender.init(alloc);
    defer recording.deinit();
    const before = actor.local.raw.?;
    var failing = std.testing.FailingAllocator.init(alloc, .{ .fail_index = 0 });
    actor.alloc = failing.allocator();
    actor.observeAddressVote(
        .{ .io = io, .sender = recording.sender(), .ingress = &ingress, .outbox = &outbox },
        .{ .ip4 = .{ .bytes = .{ 192, 0, 2, 1 }, .port = 1 } },
        .{ .ip4 = .{ .bytes = .{ 198, 51, 100, 2 }, .port = 9100 } },
    );
    actor.alloc = alloc;

    try std.testing.expect(failing.has_induced_failure);
    try std.testing.expectEqual(@as(u64, 1), actor.local.seq);
    try std.testing.expectEqualSlices(u8, before.slice(), actor.local.raw.?.slice());
    try std.testing.expectEqual(@as(usize, 1), actor.votes_ip4.currentVoteCount());
    try std.testing.expect(outbox.pop() == null);

    actor.observeAddressVote(
        .{ .io = io, .sender = recording.sender(), .ingress = &ingress, .outbox = &outbox },
        .{ .ip4 = .{ .bytes = .{ 192, 0, 2, 1 }, .port = 2 } },
        .{ .ip4 = .{ .bytes = .{ 198, 51, 100, 2 }, .port = 9100 } },
    );
    try std.testing.expectEqual(@as(u64, 2), actor.local.seq);
    try std.testing.expect(!std.mem.eql(u8, before.slice(), actor.local.raw.?.slice()));
    try std.testing.expectEqual(@as(usize, 0), actor.votes_ip4.currentVoteCount());
    var updated = outbox.pop() orelse return error.MissingLocalEnrUpdated;
    defer updated.deinit(alloc);
    try std.testing.expect(updated == .local_enr_updated);
}

test "lookup finish allocation failure still removes and detaches lookup" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    const alloc = failing.allocator();
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x76} ** 32));
    const local_id = enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&local_key));
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x79} ** 32));
    const remote_pubkey = secp.compressedPubkey(&remote_key);
    const remote_id = enr.nodeIdFromCompressedPubkey(&remote_pubkey);
    const endpoint = types.Endpoint{
        .node_id = remote_id,
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 34 }, .port = 9034 } },
    };
    const cfg = config.Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
        .local_node_id = local_id,
        .rate_limiter = null,
        .limits = .{ .max_active_requests = 2, .max_queued_requests = 2, .event_capacity = 2, .command_capacity = 2 },
    };
    var ingress = try admission.IngressAdmission.init(alloc, null, cfg.limits.max_active_requests);
    defer ingress.deinit();
    var outbox = try events.EventOutbox.init(io, alloc, cfg.limits.event_capacity);
    defer outbox.deinit();
    var actor = try actor_mod.Actor.init(alloc, cfg);
    defer actor.deinit(&ingress);
    var recording = transport.RecordingSender.init(alloc);
    defer recording.deinit();
    actor.sessions.put(endpoint, .{
        .initiator_key = [_]u8{0x7a} ** 16,
        .recipient_key = [_]u8{0x7b} ** 16,
    }, outbound.nowNs(io));
    const lookup = try lookup_mod.Lookup.init(alloc, [_]u8{1} ** 32, &.{}, 0, actor.lookup_config);
    actor.lookups.putAssumeCapacityNoClobber(1, lookup);
    const req_id = try actor.sendFindNode(.{ .io = io, .sender = recording.sender(), .ingress = &ingress, .outbox = &outbox }, endpoint, &remote_pubkey, &.{1}, .{ .lookup = 1 });
    try std.testing.expectEqual(@as(usize, 1), ingress.permitCount());
    failing.fail_index = failing.alloc_index;

    actor.finishLookup(&outbox, 1, true);
    try std.testing.expect(failing.has_induced_failure);
    try std.testing.expectEqual(@as(usize, 0), actor.lookups.count());
    try std.testing.expectEqual(@as(u64, 1), outbox.droppedCount());
    try std.testing.expectEqual(types.RequestOrigin.detached_lookup, actor.requests.get(.init(endpoint, req_id)).?.origin);
    try std.testing.expectEqual(@as(usize, 1), ingress.permitCount());
}

test "detached late multipart NODES still learns emits and releases final permit" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x6e} ** 32));
    const local_id = enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&local_key));
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x6f} ** 32));
    const remote_pubkey = secp.compressedPubkey(&remote_key);
    const remote_id = enr.nodeIdFromCompressedPubkey(&remote_pubkey);
    const endpoint = types.Endpoint{
        .node_id = remote_id,
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 32 }, .port = 9032 } },
    };
    const discovered_key = try secp.keyPairFromSecret(&([_]u8{0x70} ** 32));
    var discovered_builder = enr.Builder.init(alloc, discovered_key, 1);
    discovered_builder.ip = .{ 127, 0, 0, 33 };
    discovered_builder.udp = 9033;
    const discovered_enr = try discovered_builder.encode();
    defer alloc.free(discovered_enr);
    const discovered_id = (try enr.decode(discovered_enr)).nodeId().?;
    const distance: u16 = if (@import("kbucket.zig").logDistance(&discovered_id, &remote_id)) |value| @as(u16, value) + 1 else 0;
    const cfg = config.Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
        .local_node_id = local_id,
        .rate_limiter = null,
        .limits = .{ .max_active_requests = 2, .max_queued_requests = 2, .event_capacity = 4, .command_capacity = 2 },
    };
    var ingress = try admission.IngressAdmission.init(alloc, null, cfg.limits.max_active_requests);
    defer ingress.deinit();
    var outbox = try events.EventOutbox.init(io, alloc, cfg.limits.event_capacity);
    defer outbox.deinit();
    var actor = try actor_mod.Actor.init(alloc, cfg);
    defer actor.deinit(&ingress);
    var recording = transport.RecordingSender.init(alloc);
    defer recording.deinit();
    const stable = session_book.StableSession{ .initiator_key = [_]u8{0x75} ** 16, .recipient_key = [_]u8{0x76} ** 16 };
    actor.sessions.put(endpoint, stable, outbound.nowNs(io));
    const lookup_id: u32 = 42;
    const lookup = try lookup_mod.Lookup.init(alloc, [_]u8{0} ** 32, &.{}, 0, actor.lookup_config);
    actor.lookups.putAssumeCapacityNoClobber(lookup_id, lookup);
    const req_id = try actor.sendFindNode(.{ .io = io, .sender = recording.sender(), .ingress = &ingress, .outbox = &outbox }, endpoint, &remote_pubkey, &.{distance}, .{ .lookup = lookup_id });
    actor.finishLookup(&outbox, lookup_id, false);
    var lookup_event = outbox.pop() orelse return error.MissingLookupFinished;
    defer lookup_event.deinit(alloc);
    try std.testing.expect(lookup_event == .lookup_finished);
    try std.testing.expectEqual(types.RequestOrigin.detached_lookup, actor.requests.get(.init(endpoint, req_id)).?.origin);
    try std.testing.expectEqual(@as(usize, 1), ingress.permitCount());

    var first_buffer: [packet.MAX_PACKET_SIZE]u8 = undefined;
    const first = message.Nodes{ .req_id = req_id, .total = 2, .enrs = &.{discovered_enr} };
    try deliverEncrypted(&actor, io, recording.sender(), &ingress, &outbox, endpoint, &stable.recipient_key, try first.encodeInto(&first_buffer), 13);
    try std.testing.expectEqual(@as(usize, 1), actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 1), ingress.permitCount());
    try std.testing.expect(actor.peers.findEnr(&discovered_id) != null);
    var discovered_event = outbox.pop() orelse return error.MissingDiscoveredEvent;
    defer discovered_event.deinit(alloc);
    try std.testing.expect(discovered_event == .discovered_enr);

    var final_buffer: [128]u8 = undefined;
    const final = message.Nodes{ .req_id = req_id, .total = 2, .enrs = &.{} };
    try deliverEncrypted(&actor, io, recording.sender(), &ingress, &outbox, endpoint, &stable.recipient_key, try final.encodeInto(&final_buffer), 14);
    try std.testing.expectEqual(@as(usize, 0), actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 0), ingress.permitCount());
    var nodes_event = outbox.pop() orelse return error.MissingNodesEvent;
    defer nodes_event.deinit(alloc);
    try std.testing.expect(nodes_event == .nodes);
    try std.testing.expectEqual(@as(usize, 1), nodes_event.nodes.enrs.items.len);
    try std.testing.expectEqualSlices(u8, discovered_enr, nodes_event.nodes.enrs.items[0]);
}

test "Actor RPC NODES allocation failures preserve first and final ownership transitions" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x82} ** 32));
    const local_id = enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&local_key));
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x83} ** 32));
    const remote_pubkey = secp.compressedPubkey(&remote_key);
    const remote_id = enr.nodeIdFromCompressedPubkey(&remote_pubkey);
    const endpoint = types.Endpoint{
        .node_id = remote_id,
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 35 }, .port = 9035 } },
    };
    const discovered_key_a = try secp.keyPairFromSecret(&([_]u8{0x84} ** 32));
    var builder_a = enr.Builder.init(alloc, discovered_key_a, 1);
    builder_a.ip = .{ 127, 0, 0, 36 };
    builder_a.udp = 9036;
    const raw_a = try builder_a.encode();
    defer alloc.free(raw_a);
    const id_a = (try enr.decode(raw_a)).nodeId().?;
    const discovered_key_b = try secp.keyPairFromSecret(&([_]u8{0x85} ** 32));
    var builder_b = enr.Builder.init(alloc, discovered_key_b, 1);
    builder_b.ip = .{ 127, 0, 0, 37 };
    builder_b.udp = 9037;
    const raw_b = try builder_b.encode();
    defer alloc.free(raw_b);
    const id_b = (try enr.decode(raw_b)).nodeId().?;
    const distance_a: u16 = if (@import("kbucket.zig").logDistance(&id_a, &remote_id)) |value| @as(u16, value) + 1 else 0;
    const distance_b: u16 = if (@import("kbucket.zig").logDistance(&id_b, &remote_id)) |value| @as(u16, value) + 1 else 0;
    const cfg = config.Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
        .local_node_id = local_id,
        .rate_limiter = null,
        .limits = .{ .max_active_requests = 2, .max_queued_requests = 2, .event_capacity = 8, .command_capacity = 2 },
    };
    var ingress = try admission.IngressAdmission.init(alloc, null, cfg.limits.max_active_requests);
    defer ingress.deinit();
    var outbox = try events.EventOutbox.init(io, alloc, cfg.limits.event_capacity);
    defer outbox.deinit();
    var actor = try actor_mod.Actor.init(alloc, cfg);
    defer actor.deinit(&ingress);
    var recording = transport.RecordingSender.init(alloc);
    defer recording.deinit();
    const stable = session_book.StableSession{ .initiator_key = [_]u8{0x86} ** 16, .recipient_key = [_]u8{0x87} ** 16 };
    actor.sessions.put(endpoint, stable, outbound.nowNs(io));

    const first_req = try actor.sendFindNode(.{ .io = io, .sender = recording.sender(), .ingress = &ingress, .outbox = &outbox }, endpoint, &remote_pubkey, &.{ distance_a, distance_b }, .api);
    var first_chunk_buffer: [packet.MAX_PACKET_SIZE]u8 = undefined;
    const first_chunk = message.Nodes{ .req_id = first_req, .total = 2, .enrs = &.{raw_a} };
    var fail_first = std.testing.FailingAllocator.init(alloc, .{ .fail_index = 0 });
    actor.alloc = fail_first.allocator();
    try deliverEncrypted(&actor, io, recording.sender(), &ingress, &outbox, endpoint, &stable.recipient_key, try first_chunk.encodeInto(&first_chunk_buffer), 15);
    actor.alloc = alloc;
    try std.testing.expect(fail_first.has_induced_failure);
    try std.testing.expectEqual(@as(usize, 1), actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 1), ingress.permitCount());
    var first_discovered = outbox.pop() orelse return error.MissingFirstDiscovered;
    defer first_discovered.deinit(alloc);
    try std.testing.expect(first_discovered == .discovered_enr);
    var first_final_buffer: [128]u8 = undefined;
    const first_final = message.Nodes{ .req_id = first_req, .total = 2, .enrs = &.{} };
    try deliverEncrypted(&actor, io, recording.sender(), &ingress, &outbox, endpoint, &stable.recipient_key, try first_final.encodeInto(&first_final_buffer), 16);
    try std.testing.expectEqual(@as(usize, 0), actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 0), ingress.permitCount());
    var empty_nodes = outbox.pop() orelse return error.MissingEmptyNodes;
    defer empty_nodes.deinit(alloc);
    try std.testing.expect(empty_nodes == .nodes);
    try std.testing.expectEqual(@as(usize, 0), empty_nodes.nodes.enrs.items.len);

    const final_req = try actor.sendFindNode(.{ .io = io, .sender = recording.sender(), .ingress = &ingress, .outbox = &outbox }, endpoint, &remote_pubkey, &.{ distance_a, distance_b }, .api);
    var successful_first_buffer: [packet.MAX_PACKET_SIZE]u8 = undefined;
    const successful_first = message.Nodes{ .req_id = final_req, .total = 2, .enrs = &.{raw_a} };
    try deliverEncrypted(&actor, io, recording.sender(), &ingress, &outbox, endpoint, &stable.recipient_key, try successful_first.encodeInto(&successful_first_buffer), 17);
    var repeated_discovered = outbox.pop() orelse return error.MissingRepeatedDiscovered;
    defer repeated_discovered.deinit(alloc);
    try std.testing.expect(repeated_discovered == .discovered_enr);
    var final_chunk_buffer: [packet.MAX_PACKET_SIZE]u8 = undefined;
    const final_chunk = message.Nodes{ .req_id = final_req, .total = 2, .enrs = &.{raw_b} };
    var fail_final = std.testing.FailingAllocator.init(alloc, .{ .fail_index = 0 });
    actor.alloc = fail_final.allocator();
    try deliverEncrypted(&actor, io, recording.sender(), &ingress, &outbox, endpoint, &stable.recipient_key, try final_chunk.encodeInto(&final_chunk_buffer), 18);
    actor.alloc = alloc;
    try std.testing.expect(fail_final.has_induced_failure);
    try std.testing.expectEqual(@as(usize, 0), actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 0), ingress.permitCount());
    var final_discovered = outbox.pop() orelse return error.MissingFinalDiscovered;
    defer final_discovered.deinit(alloc);
    try std.testing.expect(final_discovered == .discovered_enr);
    var moved_nodes = outbox.pop() orelse return error.MissingMovedNodes;
    defer moved_nodes.deinit(alloc);
    try std.testing.expect(moved_nodes == .nodes);
    try std.testing.expectEqual(@as(usize, 1), moved_nodes.nodes.enrs.items.len);
    try std.testing.expectEqualSlices(u8, raw_a, moved_nodes.nodes.enrs.items[0]);
}

fn actorInitializationLifecycle(alloc: std.mem.Allocator) !void {
    const key_pair = try secp.keyPairFromSecret(&([_]u8{0x77} ** 32));
    const node_id = enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&key_pair));
    const cfg = config.Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = key_pair,
        .local_node_id = node_id,
        .rate_limiter = null,
        .limits = .{ .max_active_requests = 2, .max_queued_requests = 2, .event_capacity = 2, .command_capacity = 2 },
    };
    var ingress = try admission.IngressAdmission.init(alloc, null, cfg.limits.max_active_requests);
    defer ingress.deinit();
    var actor = try actor_mod.Actor.init(alloc, cfg);
    actor.deinit(&ingress);
}

test "Actor partial initialization cleans up every allocator failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, actorInitializationLifecycle, .{});
}

test "WHOAREYOU permit admits a valid HANDSHAKE through an existing source IP ban" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const key_a = try secp.keyPairFromSecret(&([_]u8{0x91} ** 32));
    const pubkey_a = secp.compressedPubkey(&key_a);
    const id_a = enr.nodeIdFromCompressedPubkey(&pubkey_a);
    const key_b = try secp.keyPairFromSecret(&([_]u8{0x92} ** 32));
    const pubkey_b = secp.compressedPubkey(&key_b);
    const id_b = enr.nodeIdFromCompressedPubkey(&pubkey_b);
    const address_a = types.Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 21 }, .port = 9221 } };
    const address_b = types.Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 22 }, .port = 9222 } };
    const limits = config.Limits{
        .max_active_requests = 2,
        .max_queued_requests = 2,
        .challenge_capacity = 2,
        .response_recovery_capacity = 2,
        .event_capacity = 4,
        .command_capacity = 2,
    };
    const config_a = config.Config{
        .bind_addresses = .{ .ip4 = address_a },
        .local_key_pair = key_a,
        .local_node_id = id_a,
        .rate_limiter = null,
        .limits = limits,
    };
    const config_b = config.Config{
        .bind_addresses = .{ .ip4 = address_b },
        .local_key_pair = key_b,
        .local_node_id = id_b,
        .rate_limiter = .{
            .global_quota = .{ .replenish_all_every_ms = 1_000, .max_tokens = 8 },
            .by_ip_quota = .{ .replenish_all_every_ms = 1_000, .max_tokens = 1 },
        },
        .limits = limits,
    };
    var ingress_a = try admission.IngressAdmission.init(alloc, null, try admission.permitCapacity(limits));
    defer ingress_a.deinit();
    var ingress_b = try admission.IngressAdmission.init(alloc, config_b.rate_limiter, try admission.permitCapacity(limits));
    defer ingress_b.deinit();
    var outbox_a = try events.EventOutbox.init(io, alloc, limits.event_capacity);
    defer outbox_a.deinit();
    var outbox_b = try events.EventOutbox.init(io, alloc, limits.event_capacity);
    defer outbox_b.deinit();
    var actor_a = try actor_mod.Actor.init(alloc, config_a);
    defer actor_a.deinit(&ingress_a);
    var actor_b = try actor_mod.Actor.init(alloc, config_b);
    defer actor_b.deinit(&ingress_b);
    var sender_a = transport.RecordingSender.init(alloc);
    defer sender_a.deinit();
    var sender_b = transport.RecordingSender.init(alloc);
    defer sender_b.deinit();
    const now_ns = outbound.nowNs(io);
    try std.testing.expect(actor_a.addNode(id_b, &pubkey_b, address_b, null, now_ns));
    try std.testing.expect(actor_b.addNode(id_a, &pubkey_a, address_a, null, now_ns));

    try std.testing.expect(ingress_b.accept(address_a, 0));
    const same_ip_other_port = types.Address{ .ip4 = .{ .bytes = address_a.ip4.bytes, .port = address_a.ip4.port + 1 } };
    try std.testing.expect(!ingress_b.accept(same_ip_other_port, 0));

    _ = try actor_a.sendTalkRequest(
        .{ .io = io, .sender = sender_a.sender(), .ingress = &ingress_a, .outbox = &outbox_a },
        .{ .node_id = id_b, .addr = address_b },
        &pubkey_b,
        "permit",
        "handshake",
    );
    deliver(&sender_a, 0, &actor_b, io, sender_b.sender(), &ingress_b, &outbox_b, address_a);
    try std.testing.expectEqual(@as(usize, 1), ingress_b.permitCount());
    try std.testing.expect(ingress_a.accept(address_b, 1));
    deliver(&sender_b, 0, &actor_a, io, sender_a.sender(), &ingress_a, &outbox_a, address_b);
    try std.testing.expect(ingress_b.accept(address_a, 1));
    deliver(&sender_a, 1, &actor_b, io, sender_b.sender(), &ingress_b, &outbox_b, address_a);

    try std.testing.expect(actor_b.sessions.get(.{ .node_id = id_a, .addr = address_a }, outbound.nowNs(io)) != null);
    try std.testing.expectEqual(@as(usize, 0), ingress_b.permitCount());
}

test "paired Actors complete handshake PING and TALK request response flows" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const key_a = try secp.keyPairFromSecret(&([_]u8{0x78} ** 32));
    const pubkey_a = secp.compressedPubkey(&key_a);
    const id_a = enr.nodeIdFromCompressedPubkey(&pubkey_a);
    const key_b = try secp.keyPairFromSecret(&([_]u8{0x79} ** 32));
    const pubkey_b = secp.compressedPubkey(&key_b);
    const id_b = enr.nodeIdFromCompressedPubkey(&pubkey_b);
    const address_a = @import("types.zig").Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 9201 } };
    const address_b = @import("types.zig").Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 9202 } };
    const limits = config.Limits{ .max_active_requests = 4, .max_queued_requests = 4, .event_capacity = 8, .command_capacity = 4 };
    const config_a = config.Config{
        .bind_addresses = .{ .ip4 = address_a },
        .local_key_pair = key_a,
        .local_node_id = id_a,
        .rate_limiter = null,
        .limits = limits,
    };
    const config_b = config.Config{
        .bind_addresses = .{ .ip4 = address_b },
        .local_key_pair = key_b,
        .local_node_id = id_b,
        .rate_limiter = null,
        .limits = limits,
    };
    var ingress_a = try admission.IngressAdmission.init(alloc, null, limits.max_active_requests);
    defer ingress_a.deinit();
    var ingress_b = try admission.IngressAdmission.init(alloc, null, limits.max_active_requests);
    defer ingress_b.deinit();
    var outbox_a = try events.EventOutbox.init(io, alloc, limits.event_capacity);
    defer outbox_a.deinit();
    var outbox_b = try events.EventOutbox.init(io, alloc, limits.event_capacity);
    defer outbox_b.deinit();
    var actor_a = try actor_mod.Actor.init(alloc, config_a);
    defer actor_a.deinit(&ingress_a);
    var actor_b = try actor_mod.Actor.init(alloc, config_b);
    defer actor_b.deinit(&ingress_b);
    var sender_a = transport.RecordingSender.init(alloc);
    defer sender_a.deinit();
    var sender_b = transport.RecordingSender.init(alloc);
    defer sender_b.deinit();
    const now_ns: i64 = @intCast(std.Io.Timestamp.now(io, .real).toNanoseconds());
    try std.testing.expect(actor_a.addNode(id_b, &pubkey_b, address_b, null, now_ns));
    try std.testing.expect(actor_b.addNode(id_a, &pubkey_a, address_a, null, now_ns));

    const ping_id = try actor_a.sendPing(.{ .io = io, .sender = sender_a.sender(), .ingress = &ingress_a, .outbox = &outbox_a }, .{ .node_id = id_b, .addr = address_b }, &pubkey_b, 0, .api);
    deliver(&sender_a, 0, &actor_b, io, sender_b.sender(), &ingress_b, &outbox_b, address_a);
    deliver(&sender_b, 0, &actor_a, io, sender_a.sender(), &ingress_a, &outbox_a, address_b);
    deliver(&sender_a, 1, &actor_b, io, sender_b.sender(), &ingress_b, &outbox_b, address_a);
    deliver(&sender_b, 1, &actor_a, io, sender_a.sender(), &ingress_a, &outbox_a, address_b);

    var pong_event = outbox_a.pop() orelse return error.MissingPongEvent;
    defer pong_event.deinit(alloc);
    try std.testing.expect(pong_event == .pong);
    try std.testing.expectEqualSlices(u8, ping_id.slice(), pong_event.pong.req_id.slice());
    try std.testing.expectEqual(@as(usize, 0), actor_a.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 0), ingress_a.permitCount());
    try std.testing.expect(actor_a.sessions.get(.{ .node_id = id_b, .addr = address_b }, now_ns) != null);
    try std.testing.expect(actor_b.sessions.get(.{ .node_id = id_a, .addr = address_a }, now_ns) != null);

    const talk_id = try actor_a.sendTalkRequest(.{ .io = io, .sender = sender_a.sender(), .ingress = &ingress_a, .outbox = &outbox_a }, .{ .node_id = id_b, .addr = address_b }, &pubkey_b, "test", "request");
    deliver(&sender_a, 2, &actor_b, io, sender_b.sender(), &ingress_b, &outbox_b, address_a);
    var request_event = outbox_b.pop() orelse return error.MissingTalkRequest;
    defer request_event.deinit(alloc);
    try std.testing.expect(request_event == .talkreq);
    try std.testing.expectEqualStrings("test", request_event.talkreq.protocol);
    try std.testing.expectEqualStrings("request", request_event.talkreq.request);
    try std.testing.expectEqualSlices(u8, talk_id.slice(), request_event.talkreq.req_id.slice());
    try actor_b.sendTalkResponse(.{ .io = io, .sender = sender_b.sender(), .ingress = &ingress_b, .outbox = &outbox_b }, .{ .node_id = id_a, .addr = address_a }, request_event.talkreq.req_id, "response");
    deliver(&sender_b, 2, &actor_a, io, sender_a.sender(), &ingress_a, &outbox_a, address_b);
    var response_event = outbox_a.pop() orelse return error.MissingTalkResponse;
    defer response_event.deinit(alloc);
    try std.testing.expect(response_event == .talkresp);
    try std.testing.expectEqualStrings("response", response_event.talkresp.response);
    try std.testing.expectEqual(@as(usize, 0), actor_a.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 0), ingress_a.permitCount());

    const key_c = try secp.keyPairFromSecret(&([_]u8{0x7a} ** 32));
    var builder_c = enr.Builder.init(alloc, key_c, 1);
    builder_c.ip = .{ 127, 0, 0, 3 };
    builder_c.udp = 9203;
    const enr_c = try builder_c.encode();
    defer alloc.free(enr_c);
    const id_c = (try enr.decode(enr_c)).nodeId().?;
    const key_d = try secp.keyPairFromSecret(&([_]u8{0x7b} ** 32));
    var builder_d = enr.Builder.init(alloc, key_d, 1);
    builder_d.ip = .{ 127, 0, 0, 4 };
    builder_d.udp = 9204;
    const enr_d = try builder_d.encode();
    defer alloc.free(enr_d);
    const id_d = (try enr.decode(enr_d)).nodeId().?;
    try std.testing.expect(actor_b.learnDiscovered(enr_c, now_ns) != null);
    try std.testing.expect(actor_b.addEnr(&outbox_b, enr_d, now_ns));
    var added_event = outbox_b.pop() orelse return error.MissingEnrAdded;
    defer added_event.deinit(alloc);
    try std.testing.expect(added_event == .enr_added);
    const distance_c: u16 = @as(u16, @import("kbucket.zig").logDistance(&id_b, &id_c).?) + 1;
    const distance_d: u16 = @as(u16, @import("kbucket.zig").logDistance(&id_b, &id_d).?) + 1;
    _ = try actor_a.sendFindNode(
        .{ .io = io, .sender = sender_a.sender(), .ingress = &ingress_a, .outbox = &outbox_a },
        .{ .node_id = id_b, .addr = address_b },
        &pubkey_b,
        &.{ distance_c, distance_d },
        .api,
    );
    deliver(&sender_a, 3, &actor_b, io, sender_b.sender(), &ingress_b, &outbox_b, address_a);
    deliver(&sender_b, 3, &actor_a, io, sender_a.sender(), &ingress_a, &outbox_a, address_b);
    var discovered_event = outbox_a.pop() orelse return error.MissingDiscoveredEnr;
    defer discovered_event.deinit(alloc);
    try std.testing.expect(discovered_event == .discovered_enr);
    try std.testing.expectEqualSlices(u8, enr_d, discovered_event.discovered_enr.raw.slice());
    var nodes_event = outbox_a.pop() orelse return error.MissingNodesEvent;
    defer nodes_event.deinit(alloc);
    try std.testing.expect(nodes_event == .nodes);
    try std.testing.expectEqual(@as(usize, 1), nodes_event.nodes.enrs.items.len);
    try std.testing.expectEqualSlices(u8, enr_d, nodes_event.nodes.enrs.items[0]);
    try std.testing.expectEqual(@as(usize, 0), actor_a.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 0), ingress_a.permitCount());
}

test "strict handshake rejects untrusted contact without endpoint proof" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const key_a = try secp.keyPairFromSecret(&([_]u8{0x7c} ** 32));
    const pubkey_a = secp.compressedPubkey(&key_a);
    const id_a = enr.nodeIdFromCompressedPubkey(&pubkey_a);
    const key_b = try secp.keyPairFromSecret(&([_]u8{0x7d} ** 32));
    const pubkey_b = secp.compressedPubkey(&key_b);
    const id_b = enr.nodeIdFromCompressedPubkey(&pubkey_b);
    const address_a = types.Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 9301 } };
    const address_b = types.Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 9302 } };
    const limits = config.Limits{ .max_active_requests = 2, .max_queued_requests = 2, .event_capacity = 4, .command_capacity = 2 };
    const config_a = config.Config{
        .bind_addresses = .{ .ip4 = address_a },
        .local_key_pair = key_a,
        .local_node_id = id_a,
        .rate_limiter = null,
        .limits = limits,
    };
    const config_b = config.Config{
        .bind_addresses = .{ .ip4 = address_b },
        .local_key_pair = key_b,
        .local_node_id = id_b,
        .rate_limiter = null,
        .limits = limits,
        .allow_unverified_sessions = false,
    };
    var ingress_a = try admission.IngressAdmission.init(alloc, null, limits.max_active_requests);
    defer ingress_a.deinit();
    var ingress_b = try admission.IngressAdmission.init(alloc, null, limits.max_active_requests);
    defer ingress_b.deinit();
    var outbox_a = try events.EventOutbox.init(io, alloc, limits.event_capacity);
    defer outbox_a.deinit();
    var outbox_b = try events.EventOutbox.init(io, alloc, limits.event_capacity);
    defer outbox_b.deinit();
    var actor_a = try actor_mod.Actor.init(alloc, config_a);
    defer actor_a.deinit(&ingress_a);
    var actor_b = try actor_mod.Actor.init(alloc, config_b);
    defer actor_b.deinit(&ingress_b);
    var sender_a = transport.RecordingSender.init(alloc);
    defer sender_a.deinit();
    var sender_b = transport.RecordingSender.init(alloc);
    defer sender_b.deinit();

    actor_b.peers.rememberContact(id_a, &pubkey_a, address_a, false);
    _ = try actor_a.sendPing(.{ .io = io, .sender = sender_a.sender(), .ingress = &ingress_a, .outbox = &outbox_a }, .{ .node_id = id_b, .addr = address_b }, &pubkey_b, 0, .api);
    deliver(&sender_a, 0, &actor_b, io, sender_b.sender(), &ingress_b, &outbox_b, address_a);
    deliver(&sender_b, 0, &actor_a, io, sender_a.sender(), &ingress_a, &outbox_a, address_b);
    deliver(&sender_a, 1, &actor_b, io, sender_b.sender(), &ingress_b, &outbox_b, address_a);

    try std.testing.expect(actor_b.sessions.get(.{ .node_id = id_a, .addr = address_a }, outbound.nowNs(io)) == null);
    try std.testing.expectEqual(@as(usize, 1), sender_b.datagrams.items.len);
}

test "permissive handshake accepts untrusted contact without endpoint proof" {
    try std.testing.expect(try contactHandshakeAccepted(true, false));
}

test "strict handshake accepts explicitly trusted raw contact" {
    try std.testing.expect(try contactHandshakeAccepted(false, true));
}

test "default handshake rejects a signed ENR advertising a different endpoint" {
    const result = try mismatchedSignedEnrHandshake(null);
    try std.testing.expect(!result.session_installed);
    try std.testing.expect(!result.established_event);
}

test "explicit unverified-session opt-in accepts a signed ENR endpoint mismatch" {
    const result = try mismatchedSignedEnrHandshake(true);
    try std.testing.expect(result.session_installed);
    try std.testing.expect(result.established_event);
}

fn mismatchedSignedEnrHandshake(allow_unverified: ?bool) !struct { session_installed: bool, established_event: bool } {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const key_a = try secp.keyPairFromSecret(&([_]u8{0x86} ** 32));
    const pubkey_a = secp.compressedPubkey(&key_a);
    const id_a = enr.nodeIdFromCompressedPubkey(&pubkey_a);
    const key_b = try secp.keyPairFromSecret(&([_]u8{0x87} ** 32));
    const pubkey_b = secp.compressedPubkey(&key_b);
    const id_b = enr.nodeIdFromCompressedPubkey(&pubkey_b);
    const observed_a = types.Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 9386 } };
    const address_b = types.Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 9387 } };
    var advertised = enr.Builder.init(alloc, key_a, 1);
    advertised.ip = .{ 127, 0, 0, 1 };
    advertised.udp = 9486;
    const advertised_enr = try advertised.encode();
    defer alloc.free(advertised_enr);
    const limits = config.Limits{ .max_active_requests = 2, .max_queued_requests = 2, .event_capacity = 4, .command_capacity = 2 };
    const config_a = config.Config{
        .bind_addresses = .{ .ip4 = observed_a },
        .local_key_pair = key_a,
        .local_node_id = id_a,
        .local_enr = advertised_enr,
        .rate_limiter = null,
        .limits = limits,
    };
    var config_b = config.Config{
        .bind_addresses = .{ .ip4 = address_b },
        .local_key_pair = key_b,
        .local_node_id = id_b,
        .rate_limiter = null,
        .limits = limits,
    };
    if (allow_unverified) |value| config_b.allow_unverified_sessions = value;
    var ingress_a = try admission.IngressAdmission.init(alloc, null, limits.max_active_requests);
    defer ingress_a.deinit();
    var ingress_b = try admission.IngressAdmission.init(alloc, null, limits.max_active_requests);
    defer ingress_b.deinit();
    var outbox_a = try events.EventOutbox.init(io, alloc, limits.event_capacity);
    defer outbox_a.deinit();
    var outbox_b = try events.EventOutbox.init(io, alloc, limits.event_capacity);
    defer outbox_b.deinit();
    var actor_a = try actor_mod.Actor.init(alloc, config_a);
    defer actor_a.deinit(&ingress_a);
    var actor_b = try actor_mod.Actor.init(alloc, config_b);
    defer actor_b.deinit(&ingress_b);
    var sender_a = transport.RecordingSender.init(alloc);
    defer sender_a.deinit();
    var sender_b = transport.RecordingSender.init(alloc);
    defer sender_b.deinit();

    _ = try actor_a.sendPing(.{ .io = io, .sender = sender_a.sender(), .ingress = &ingress_a, .outbox = &outbox_a }, .{ .node_id = id_b, .addr = address_b }, &pubkey_b, 0, .api);
    deliver(&sender_a, 0, &actor_b, io, sender_b.sender(), &ingress_b, &outbox_b, observed_a);
    deliver(&sender_b, 0, &actor_a, io, sender_a.sender(), &ingress_a, &outbox_a, address_b);
    deliver(&sender_a, 1, &actor_b, io, sender_b.sender(), &ingress_b, &outbox_b, observed_a);

    var established_event = false;
    while (outbox_b.pop()) |value| {
        var event = value;
        defer event.deinit(alloc);
        if (event == .peer_connected) established_event = true;
    }
    return .{
        .session_installed = actor_b.sessions.get(.{ .node_id = id_a, .addr = observed_a }, outbound.nowNs(io)) != null,
        .established_event = established_event,
    };
}

fn contactHandshakeAccepted(allow_unverified: bool, runtime_contact_trusted: bool) !bool {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const key_a = try secp.keyPairFromSecret(&([_]u8{0x7e} ** 32));
    const pubkey_a = secp.compressedPubkey(&key_a);
    const id_a = enr.nodeIdFromCompressedPubkey(&pubkey_a);
    const key_b = try secp.keyPairFromSecret(&([_]u8{0x7f} ** 32));
    const pubkey_b = secp.compressedPubkey(&key_b);
    const id_b = enr.nodeIdFromCompressedPubkey(&pubkey_b);
    const address_a = types.Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 9311 } };
    const address_b = types.Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 9312 } };
    const limits = config.Limits{ .max_active_requests = 2, .max_queued_requests = 2, .event_capacity = 4, .command_capacity = 2 };
    const config_a = config.Config{
        .bind_addresses = .{ .ip4 = address_a },
        .local_key_pair = key_a,
        .local_node_id = id_a,
        .rate_limiter = null,
        .limits = limits,
    };
    const config_b = config.Config{
        .bind_addresses = .{ .ip4 = address_b },
        .local_key_pair = key_b,
        .local_node_id = id_b,
        .rate_limiter = null,
        .limits = limits,
        .allow_unverified_sessions = allow_unverified,
    };
    var ingress_a = try admission.IngressAdmission.init(alloc, null, limits.max_active_requests);
    defer ingress_a.deinit();
    var ingress_b = try admission.IngressAdmission.init(alloc, null, limits.max_active_requests);
    defer ingress_b.deinit();
    var outbox_a = try events.EventOutbox.init(io, alloc, limits.event_capacity);
    defer outbox_a.deinit();
    var outbox_b = try events.EventOutbox.init(io, alloc, limits.event_capacity);
    defer outbox_b.deinit();
    var actor_a = try actor_mod.Actor.init(alloc, config_a);
    defer actor_a.deinit(&ingress_a);
    var actor_b = try actor_mod.Actor.init(alloc, config_b);
    defer actor_b.deinit(&ingress_b);
    var sender_a = transport.RecordingSender.init(alloc);
    defer sender_a.deinit();
    var sender_b = transport.RecordingSender.init(alloc);
    defer sender_b.deinit();

    if (runtime_contact_trusted) {
        try std.testing.expect(actor_b.addNode(id_a, &pubkey_a, address_a, null, outbound.nowNs(io)));
    } else {
        actor_b.peers.rememberContact(id_a, &pubkey_a, address_a, false);
    }
    try std.testing.expectEqual(runtime_contact_trusted, actor_b.peers.known(&id_a).?.runtime_contact_trusted);
    _ = try actor_a.sendPing(.{ .io = io, .sender = sender_a.sender(), .ingress = &ingress_a, .outbox = &outbox_a }, .{ .node_id = id_b, .addr = address_b }, &pubkey_b, 0, .api);
    deliver(&sender_a, 0, &actor_b, io, sender_b.sender(), &ingress_b, &outbox_b, address_a);
    deliver(&sender_b, 0, &actor_a, io, sender_a.sender(), &ingress_a, &outbox_a, address_b);
    deliver(&sender_a, 1, &actor_b, io, sender_b.sender(), &ingress_b, &outbox_b, address_a);
    try std.testing.expectEqual(runtime_contact_trusted, actor_b.peers.known(&id_a).?.runtime_contact_trusted);
    return actor_b.sessions.get(.{ .node_id = id_a, .addr = address_a }, outbound.nowNs(io)) != null;
}

fn deliver(
    source: *const transport.RecordingSender,
    index: usize,
    destination: *actor_mod.Actor,
    io: std.Io,
    sender: transport.Sender,
    ingress: *admission.IngressAdmission,
    outbox: *events.EventOutbox,
    source_address: @import("types.zig").Address,
) void {
    var datagram = source.datagrams.items[index].bytes;
    destination.handlePacket(.{ .io = io, .sender = sender, .ingress = ingress, .outbox = outbox }, datagram.bytes[0..datagram.len], source_address);
}
