const std = @import("std");
const actor_mod = @import("../actor.zig");
const admission = @import("../admission.zig");
const config = @import("../config.zig");
const enr = @import("../enr.zig");
const events = @import("../events.zig");
const lookup_results = @import("../lookup_results.zig");
const outbound = @import("../flow/outbound.zig");
const lookup_mod = @import("../service/lookup.zig");
const packet = @import("../protocol/packet.zig");
const message = @import("../protocol/message.zig");
const secp = @import("../secp256k1.zig");
const session_book = @import("../state/session_book.zig");
const types = @import("../types.zig");
const ActorHarness = @import("../test_support/actor_harness.zig").ActorHarness;
const RecordingSender = @import("../test_support/recording_sender.zig").RecordingSender;
const deliverEncrypted = @import("../test_support/encrypted_delivery.zig").deliverEncrypted;

test "addEnr treats an older ENR for a known newer node as usable without an event" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x2b} ** 32));
    const local_id = try enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&local_key));
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x2c} ** 32));
    const remote_id = try enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&remote_key));
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
    var harness = try ActorHarness.init(alloc, io, cfg);
    defer harness.deinit();
    const actor = &harness.actor;

    try std.testing.expect(actor.addEnr(&harness.outbox, newer_enr, 1));
    var added_event = harness.outbox.pop() orelse return error.MissingEnrAdded;
    defer added_event.deinit(alloc);
    try std.testing.expect(added_event == .enr_added);

    // The stored ENR is newer: local-trust merge succeeds, the node stays
    // usable, and no duplicate/stale event is emitted.
    try std.testing.expect(actor.addEnr(&harness.outbox, older_enr, 2));
    try std.testing.expect(actor.peers.known(&remote_id).?.runtime_contact_trusted);
    try std.testing.expectEqualSlices(u8, newer_enr, actor.peers.findEnr(&remote_id).?);
    try std.testing.expect(harness.outbox.pop() == null);

    // An exact duplicate of the stored ENR also stays usable without an event.
    try std.testing.expect(actor.addEnr(&harness.outbox, newer_enr, 3));
    try std.testing.expect(harness.outbox.pop() == null);
}

test "event payload allocation failure preserves Actor state and counts one drop" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x73} ** 32));
    const local_id = try enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&local_key));
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
    try std.testing.expectEqual(@as(u64, 1), outbox.droppedEventCount(.enr_added));
    const remote_id = try enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&remote_key));
    try std.testing.expect(actor.peers.findEnr(&remote_id) != null);
    try std.testing.expect(outbox.pop() == null);
}

test "full event outbox preserves non-reliable completion and queued drain without an event" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x64} ** 32));
    const local_id = try enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&local_key));
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x65} ** 32));
    const remote_pubkey = secp.compressedPubkey(&remote_key);
    const remote_id = try enr.nodeIdFromCompressedPubkey(&remote_pubkey);
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
    var harness = try ActorHarness.init(alloc, io, cfg);
    defer harness.deinit();
    const actor = &harness.actor;
    const stable = session_book.StableSession{ .initiator_key = [_]u8{0x66} ** 16, .recipient_key = [_]u8{0x67} ** 16 };
    actor.sessions.put(endpoint, stable, outbound.nowNs(io));
    const talk_id = try actor.sendTalkRequest(harness.env(), endpoint, &remote_pubkey, "test", "request");
    const queued_id = try message.ReqId.fromSlice(&.{9});
    const queued_ping = message.Ping{ .req_id = queued_id, .enr_seq = 0 };
    var queued_buffer: [128]u8 = undefined;
    try actor.requests.queue(try .init(.api, endpoint, &remote_pubkey, queued_id, .ping, &.{}, try queued_ping.encodeInto(&queued_buffer), std.math.maxInt(i64)));
    harness.outbox.publish(.{ .local_enr_updated = .{ .seq = 1, .enr = try alloc.dupe(u8, "blocker") } });

    const response = message.TalkResp{ .req_id = talk_id, .response = "owned response" };
    var response_buffer: [128]u8 = undefined;
    var failing = std.testing.FailingAllocator.init(alloc, .{ .fail_index = 0 });
    actor.alloc = failing.allocator();
    defer actor.alloc = alloc;
    try deliverEncrypted(actor, io, harness.recording.sender(), &harness.ingress, &harness.outbox, endpoint, &stable.recipient_key, try response.encodeInto(&response_buffer), 11);
    actor.alloc = alloc;
    try std.testing.expect(!failing.has_induced_failure);
    try std.testing.expectEqual(@as(u64, 0), harness.outbox.droppedCount());
    try std.testing.expect(actor.requests.get(.init(endpoint, talk_id)) == null);
    try std.testing.expectEqual(@as(usize, 0), actor.requests.queuedCount());
    try std.testing.expect(actor.requests.get(.init(endpoint, queued_id)) != null);
    try std.testing.expectEqual(@as(usize, 1), harness.ingress.permitCount());
    try std.testing.expectEqual(@as(usize, 2), harness.recording.datagrams.items.len);
    var blocker = harness.outbox.pop() orelse return error.MissingEventOutboxBlocker;
    defer blocker.deinit(alloc);
    try std.testing.expect(blocker == .local_enr_updated);
    try std.testing.expect(harness.outbox.pop() == null);
}

test "maintenance removes every expired lookup and retains live lookups" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x7c} ** 32));
    const local_id = try enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&local_key));
    const cfg = config.Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
        .local_node_id = local_id,
        .rate_limiter = null,
        .lookup_timeout_ms = 10,
        .ping_interval_ms = 0,
        .limits = .{ .max_active_requests = 2, .max_queued_requests = 2, .event_capacity = 16, .command_capacity = 2 },
    };
    var harness = try ActorHarness.init(alloc, io, cfg);
    defer harness.deinit();
    const actor = &harness.actor;
    const now_ns: i64 = 20 * std.time.ns_per_ms;

    for (1..10) |lookup_id| {
        var target = [_]u8{0} ** 32;
        target[0] = @intCast(lookup_id);
        const started_at_ns = if (lookup_id <= 6) 0 else now_ns;
        const lookup = try lookup_mod.Lookup.init(alloc, target, &.{}, started_at_ns, actor.lookup_config);
        actor.lookups.putAssumeCapacityNoClobber(@intCast(lookup_id), lookup);
    }

    actor.maintenanceAt(harness.env(), now_ns);

    for (1..7) |lookup_id| {
        try std.testing.expect(!actor.lookups.contains(@intCast(lookup_id)));
    }
    for (7..10) |lookup_id| try std.testing.expect(actor.lookups.contains(@intCast(lookup_id)));
    try std.testing.expect(harness.outbox.pop() == null);
}

test "health PONG completion is independent of a full best-effort event outbox" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x6a} ** 32));
    const local_id = try enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&local_key));
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x6b} ** 32));
    const remote_pubkey = secp.compressedPubkey(&remote_key);
    var remote_builder = enr.Builder.init(alloc, remote_key, 1);
    remote_builder.ip = .{ 127, 0, 0, 31 };
    remote_builder.udp = 9031;
    const remote_enr = try remote_builder.encode();
    defer alloc.free(remote_enr);
    const remote_id = (try (try enr.decode(remote_enr)).nodeId()).?;
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
    var harness = try ActorHarness.init(alloc, io, cfg);
    defer harness.deinit();
    const actor = &harness.actor;
    try std.testing.expect(actor.peers.learnEnr(remote_enr, 0) != null);
    _ = actor.peers.markResponsive(remote_id, endpoint.addr, 0, null);
    const stable = session_book.StableSession{ .initiator_key = [_]u8{0x6c} ** 16, .recipient_key = [_]u8{0x6d} ** 16 };
    actor.sessions.put(endpoint, stable, outbound.nowNs(io));
    const req_id = try actor.sendPing(harness.env(), endpoint, &remote_pubkey, 1, .{ .maintenance = .health });
    const key = types.RequestKey.init(endpoint, req_id);
    try std.testing.expect(actor.peers.armHealthRequest(key, .connected_only));
    harness.outbox.publish(.{ .local_enr_updated = .{ .seq = 1, .enr = try alloc.dupe(u8, "blocker") } });
    const pong = message.Pong{ .req_id = req_id, .enr_seq = 1, .recipient_ip = .{ .ip4 = .{ 127, 0, 0, 1 } }, .recipient_port = 9000 };
    var pong_buffer: [128]u8 = undefined;
    try deliverEncrypted(actor, io, harness.recording.sender(), &harness.ingress, &harness.outbox, endpoint, &stable.recipient_key, try pong.encodeInto(&pong_buffer), 12);

    try std.testing.expectEqual(@as(u64, 0), harness.outbox.droppedCount());
    try std.testing.expect(actor.peers.routing.getEntry(&remote_id).?.health_request == null);
    try std.testing.expectEqual(@as(usize, 0), actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 0), harness.ingress.permitCount());
}

test "LocalRecord replacement is atomic across allocator failure" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x75} ** 32));
    const local_id = try enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&local_key));
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
    var harness = try ActorHarness.init(alloc, io, cfg);
    defer harness.deinit();
    const actor = &harness.actor;
    const before = actor.local.raw.?;
    var failing = std.testing.FailingAllocator.init(alloc, .{ .fail_index = 0 });
    actor.alloc = failing.allocator();
    actor.observeAddressVote(
        harness.env(),
        .{ .ip4 = .{ .bytes = .{ 192, 0, 2, 1 }, .port = 1 } },
        .{ .ip4 = .{ .bytes = .{ 198, 51, 100, 2 }, .port = 9100 } },
    );
    actor.alloc = alloc;

    try std.testing.expect(failing.has_induced_failure);
    try std.testing.expectEqual(@as(u64, 1), actor.local.seq);
    try std.testing.expectEqualSlices(u8, before.slice(), actor.local.raw.?.slice());
    try std.testing.expectEqual(@as(usize, 1), actor.votes_ip4.currentVoteCount());
    try std.testing.expect(harness.outbox.pop() == null);

    actor.observeAddressVote(
        harness.env(),
        .{ .ip4 = .{ .bytes = .{ 192, 0, 2, 1 }, .port = 2 } },
        .{ .ip4 = .{ .bytes = .{ 198, 51, 100, 2 }, .port = 9100 } },
    );
    try std.testing.expectEqual(@as(u64, 2), actor.local.seq);
    try std.testing.expect(!std.mem.eql(u8, before.slice(), actor.local.raw.?.slice()));
    try std.testing.expectEqual(@as(usize, 0), actor.votes_ip4.currentVoteCount());
    var updated = harness.outbox.pop() orelse return error.MissingLocalEnrUpdated;
    defer updated.deinit(alloc);
    try std.testing.expect(updated == .local_enr_updated);
}

test "reliable lookup terminal payload needs no compatibility event allocation" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    const alloc = failing.allocator();
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x8e} ** 32));
    const local_id = try enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&local_key));
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x8f} ** 32));
    var remote_builder = enr.Builder.init(alloc, remote_key, 1);
    remote_builder.ip = .{ 127, 0, 0, 143 };
    remote_builder.udp = 9143;
    const remote_enr = try remote_builder.encode();
    defer alloc.free(remote_enr);
    const remote_id = (try (try enr.decode(remote_enr)).nodeId()).?;
    const cfg = config.Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
        .local_node_id = local_id,
        .rate_limiter = null,
        .limits = .{
            .max_active_requests = 2,
            .max_queued_requests = 2,
            .event_capacity = 2,
            .command_capacity = 2,
            .lookup_result_capacity = 1,
        },
    };
    var harness = try ActorHarness.init(alloc, io, cfg);
    defer harness.deinit();
    var result_outbox = try lookup_results.LookupResultOutbox.init(io, alloc, 1);
    defer result_outbox.deinit();
    try std.testing.expect(result_outbox.reserve());
    try std.testing.expect(result_outbox.claim());
    try std.testing.expect(harness.actor.peers.learnEnr(remote_enr, 0) != null);

    var lookup = try lookup_mod.Lookup.init(alloc, [_]u8{0x90} ** 32, &.{remote_id}, 0, harness.actor.lookup_config);
    const contacted = lookup.nextPeer(harness.actor.lookup_config).?;
    lookup.onSuccess(&contacted, &.{}, harness.actor.lookup_config);
    lookup.reliable_result = true;
    harness.actor.lookups.putAssumeCapacityNoClobber(1, lookup);
    var env = harness.env();
    env.lookup_results = &result_outbox;
    failing.fail_index = failing.alloc_index;

    harness.actor.finishLookup(env, 1, .completed);

    try std.testing.expect(!failing.has_induced_failure);
    try std.testing.expectEqual(@as(u64, 0), harness.outbox.droppedCount());
    try std.testing.expect(harness.outbox.pop() == null);
    const result = result_outbox.pop() orelse return error.MissingLookupResult;
    try std.testing.expectEqual(@as(u32, 1), result.lookup_id);
    try std.testing.expectEqual(lookup_results.LookupTerminalReason.completed, result.reason);
    try std.testing.expectEqual(@as(usize, 1), result.enrs.slice().len);
    try std.testing.expectEqualSlices(u8, remote_enr, result.enrs.slice()[0].slice());
}

test "detached late multipart NODES still learns emits and releases final permit" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x6e} ** 32));
    const local_id = try enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&local_key));
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x6f} ** 32));
    const remote_pubkey = secp.compressedPubkey(&remote_key);
    const remote_id = try enr.nodeIdFromCompressedPubkey(&remote_pubkey);
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
    const discovered_id = (try (try enr.decode(discovered_enr)).nodeId()).?;
    const distance: u16 = if (@import("../kbucket.zig").logDistance(&discovered_id, &remote_id)) |value| @as(u16, value) + 1 else 0;
    const cfg = config.Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
        .local_node_id = local_id,
        .rate_limiter = null,
        .limits = .{ .max_active_requests = 2, .max_queued_requests = 2, .event_capacity = 4, .command_capacity = 2 },
    };
    var harness = try ActorHarness.init(alloc, io, cfg);
    defer harness.deinit();
    const actor = &harness.actor;
    const stable = session_book.StableSession{ .initiator_key = [_]u8{0x75} ** 16, .recipient_key = [_]u8{0x76} ** 16 };
    actor.sessions.put(endpoint, stable, outbound.nowNs(io));
    const lookup_id: u32 = 42;
    const lookup = try lookup_mod.Lookup.init(alloc, [_]u8{0} ** 32, &.{}, 0, actor.lookup_config);
    actor.lookups.putAssumeCapacityNoClobber(lookup_id, lookup);
    const req_id = try actor.sendFindNode(harness.env(), endpoint, &remote_pubkey, &.{distance}, .{ .lookup = lookup_id });
    actor.finishLookup(harness.env(), lookup_id, .completed);
    try std.testing.expect(harness.outbox.pop() == null);
    try std.testing.expectEqual(types.RequestOrigin.detached_lookup, actor.requests.get(.init(endpoint, req_id)).?.origin);
    try std.testing.expectEqual(@as(usize, 1), harness.ingress.permitCount());

    var first_buffer: [packet.MAX_PACKET_SIZE]u8 = undefined;
    const first = message.Nodes{ .req_id = req_id, .total = 2, .enrs = &.{discovered_enr} };
    try deliverEncrypted(actor, io, harness.recording.sender(), &harness.ingress, &harness.outbox, endpoint, &stable.recipient_key, try first.encodeInto(&first_buffer), 13);
    try std.testing.expectEqual(@as(usize, 1), actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 1), harness.ingress.permitCount());
    try std.testing.expect(actor.peers.findEnr(&discovered_id) != null);
    var discovered_event = harness.outbox.pop() orelse return error.MissingDiscoveredEvent;
    defer discovered_event.deinit(alloc);
    try std.testing.expect(discovered_event == .discovered_enr);

    var final_buffer: [128]u8 = undefined;
    const final = message.Nodes{ .req_id = req_id, .total = 2, .enrs = &.{} };
    try deliverEncrypted(actor, io, harness.recording.sender(), &harness.ingress, &harness.outbox, endpoint, &stable.recipient_key, try final.encodeInto(&final_buffer), 14);
    try std.testing.expectEqual(@as(usize, 0), actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 0), harness.ingress.permitCount());
    try std.testing.expect(harness.outbox.pop() == null);
}

test "Actor RPC NODES accumulation avoids compatibility payload allocations" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x82} ** 32));
    const local_id = try enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&local_key));
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x83} ** 32));
    const remote_pubkey = secp.compressedPubkey(&remote_key);
    const remote_id = try enr.nodeIdFromCompressedPubkey(&remote_pubkey);
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
    const id_a = (try (try enr.decode(raw_a)).nodeId()).?;
    const discovered_key_b = try secp.keyPairFromSecret(&([_]u8{0x85} ** 32));
    var builder_b = enr.Builder.init(alloc, discovered_key_b, 1);
    builder_b.ip = .{ 127, 0, 0, 37 };
    builder_b.udp = 9037;
    const raw_b = try builder_b.encode();
    defer alloc.free(raw_b);
    const id_b = (try (try enr.decode(raw_b)).nodeId()).?;
    const distance_a: u16 = if (@import("../kbucket.zig").logDistance(&id_a, &remote_id)) |value| @as(u16, value) + 1 else 0;
    const distance_b: u16 = if (@import("../kbucket.zig").logDistance(&id_b, &remote_id)) |value| @as(u16, value) + 1 else 0;
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
    var recording = RecordingSender.init(alloc);
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
    try std.testing.expect(!fail_first.has_induced_failure);
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
    try std.testing.expect(outbox.pop() == null);

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
    try std.testing.expect(!fail_final.has_induced_failure);
    try std.testing.expectEqual(@as(usize, 0), actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 0), ingress.permitCount());
    var final_discovered = outbox.pop() orelse return error.MissingFinalDiscovered;
    defer final_discovered.deinit(alloc);
    try std.testing.expect(final_discovered == .discovered_enr);
    try std.testing.expect(outbox.pop() == null);
}

fn actorInitializationLifecycle(alloc: std.mem.Allocator) !void {
    const key_pair = try secp.keyPairFromSecret(&([_]u8{0x77} ** 32));
    const node_id = try enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&key_pair));
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
