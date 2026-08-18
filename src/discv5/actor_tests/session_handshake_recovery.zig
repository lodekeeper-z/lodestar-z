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
const session_book = @import("../state/session_book.zig");
const types = @import("../types.zig");
const ActorHarness = @import("../test_support/actor_harness.zig").ActorHarness;
const PacketLink = @import("../test_support/packet_link.zig").PacketLink;
const RecordingSender = @import("../test_support/recording_sender.zig").RecordingSender;
const deliverEncrypted = @import("../test_support/encrypted_delivery.zig").deliverEncrypted;

test "paired Actors retry an established PING with a fresh nonce and complete on the second PONG" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const key_a = try secp.keyPairFromSecret(&([_]u8{0x93} ** 32));
    const pubkey_a = secp.compressedPubkey(&key_a);
    const id_a = try enr.nodeIdFromCompressedPubkey(&pubkey_a);
    const key_b = try secp.keyPairFromSecret(&([_]u8{0x94} ** 32));
    const pubkey_b = secp.compressedPubkey(&key_b);
    const id_b = try enr.nodeIdFromCompressedPubkey(&pubkey_b);
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
    var sender_a = RecordingSender.init(alloc);
    defer sender_a.deinit();
    var sender_b = RecordingSender.init(alloc);
    defer sender_b.deinit();
    var link_a_to_b = PacketLink.init(&sender_a, address_b, address_a, &actor_b, .{ .io = io, .sender = sender_b.sender(), .ingress = &ingress_b, .outbox = &outbox_b });
    var link_b_to_a = PacketLink.init(&sender_b, address_a, address_b, &actor_a, .{ .io = io, .sender = sender_a.sender(), .ingress = &ingress_a, .outbox = &outbox_a });
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
    try link_a_to_b.deliverNext();
    try std.testing.expectEqual(@as(usize, 1), sender_b.datagrams.items.len);
    try link_b_to_a.dropNext();
    var first_packet = sender_a.datagrams.items[0].bytes;
    const first_nonce = (try packet.decode(first_packet.bytes[0..first_packet.len], &id_b)).static_header.nonce;

    try std.Io.sleep(io, .fromMilliseconds(2), .awake);
    actor_a.maintenance(.{ .io = io, .sender = sender_a.sender(), .ingress = &ingress_a, .outbox = &outbox_a });
    try std.testing.expectEqual(@as(usize, 2), sender_a.datagrams.items.len);
    var retry_packet = sender_a.datagrams.items[1].bytes;
    const retry_nonce = (try packet.decode(retry_packet.bytes[0..retry_packet.len], &id_b)).static_header.nonce;
    try std.testing.expect(!std.mem.eql(u8, &first_nonce, &retry_nonce));
    try link_a_to_b.deliverNext();
    try std.testing.expectEqual(@as(usize, 2), sender_b.datagrams.items.len);
    try link_b_to_a.deliverNext();

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
    const id_a = try enr.nodeIdFromCompressedPubkey(&pubkey_a);
    const key_b = try secp.keyPairFromSecret(&([_]u8{0x96} ** 32));
    const pubkey_b = secp.compressedPubkey(&key_b);
    const id_b = try enr.nodeIdFromCompressedPubkey(&pubkey_b);
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
    var sender_a = RecordingSender.init(alloc);
    defer sender_a.deinit();
    var sender_b = RecordingSender.init(alloc);
    defer sender_b.deinit();
    var link_a_to_b = PacketLink.init(&sender_a, address_b, address_a, &actor_b, .{ .io = io, .sender = sender_b.sender(), .ingress = &ingress_b, .outbox = &outbox_b });
    var link_b_to_a = PacketLink.init(&sender_b, address_a, address_b, &actor_a, .{ .io = io, .sender = sender_a.sender(), .ingress = &ingress_a, .outbox = &outbox_a });
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
    try link_a_to_b.deliverNext();
    try std.testing.expectEqual(@as(usize, 1), sender_b.datagrams.items.len);
    try std.testing.expectEqual(@as(usize, 1), ingress_b.permitCount());
    try link_b_to_a.dropNext();

    try std.Io.sleep(io, .fromMilliseconds(2), .awake);
    actor_a.maintenance(.{ .io = io, .sender = sender_a.sender(), .ingress = &ingress_a, .outbox = &outbox_a });
    try std.testing.expectEqualSlices(u8, sender_a.datagrams.items[0].bytes.slice(), sender_a.datagrams.items[1].bytes.slice());
    try link_a_to_b.deliverNext();
    try std.testing.expectEqual(@as(usize, 2), sender_b.datagrams.items.len);
    try std.testing.expectEqualSlices(u8, sender_b.datagrams.items[0].bytes.slice(), sender_b.datagrams.items[1].bytes.slice());
    try std.testing.expectEqual(@as(usize, 1), ingress_b.permitCount());

    try link_b_to_a.deliverNext();
    try link_a_to_b.deliverNext();
    try link_b_to_a.deliverNext();
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
    const id_a = try enr.nodeIdFromCompressedPubkey(&pubkey_a);
    const key_b = try secp.keyPairFromSecret(&([_]u8{0x98} ** 32));
    const pubkey_b = secp.compressedPubkey(&key_b);
    const id_b = try enr.nodeIdFromCompressedPubkey(&pubkey_b);
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
    var sender_a = RecordingSender.init(alloc);
    defer sender_a.deinit();
    var sender_b = RecordingSender.init(alloc);
    defer sender_b.deinit();
    var link_a_to_b = PacketLink.init(&sender_a, address_b, address_a, &actor_b, .{ .io = io, .sender = sender_b.sender(), .ingress = &ingress_b, .outbox = &outbox_b });
    var link_b_to_a = PacketLink.init(&sender_b, address_a, address_b, &actor_a, .{ .io = io, .sender = sender_a.sender(), .ingress = &ingress_a, .outbox = &outbox_a });
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
    try link_a_to_b.deliverNext();
    try std.testing.expectEqual(@as(usize, 1), sender_b.datagrams.items.len);
    try std.testing.expect(actor_a.sessions.remove(endpoint_b));
    try link_b_to_a.deliverNext();
    try std.testing.expectEqual(@as(usize, 2), sender_a.datagrams.items.len);
    try std.testing.expectEqual(@as(usize, 1), actor_b.responses.count());
    try std.testing.expectEqual(@as(usize, 1), ingress_b.permitCount());
    const wrong_address = types.Address{ .ip4 = .{ .bytes = address_a.ip4.bytes, .port = address_a.ip4.port + 1 } };
    const retained_challenge = try link_a_to_b.snapshotNext();
    try link_a_to_b.replayFrom(retained_challenge, wrong_address);
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
    try link_a_to_b.deliverNext();
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

    try link_b_to_a.deliverNext();

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
    const local_id = try enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&local_key));
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x54} ** 32));
    const remote_pubkey = secp.compressedPubkey(&remote_key);
    const endpoint = types.Endpoint{
        .node_id = try enr.nodeIdFromCompressedPubkey(&remote_pubkey),
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
    var harness = try ActorHarness.init(alloc, io, cfg);
    defer harness.deinit();
    const actor = &harness.actor;
    actor.sessions.put(endpoint, .{ .initiator_key = [_]u8{3} ** 16, .recipient_key = [_]u8{4} ** 16 }, outbound.nowNs(io));
    const req_id = try actor.sendPing(harness.env(), endpoint, &remote_pubkey, 0, .api);
    var initial = harness.recording.datagrams.items[0].bytes;
    const initial_nonce = (try packet.decode(initial.bytes[0..initial.len], &endpoint.node_id)).static_header.nonce;

    harness.recording.fail_next = true;
    try std.Io.sleep(io, .fromMilliseconds(2), .awake);
    actor.maintenance(harness.env());
    try std.testing.expectEqual(@as(u64, 1), actor.metrics.sent_message_count[metrics.MessageType.ping.index()]);
    try std.testing.expectEqual(@as(usize, 1), harness.recording.datagrams.items.len);
    const active = actor.requests.get(.init(endpoint, req_id)) orelse return error.MissingRequestAfterRetryFailure;
    try std.testing.expect(active.phase == .awaiting_response);
    try std.testing.expectEqual(initial_nonce, active.phase.awaiting_response.recovery.nonce);
    try std.testing.expect(actor.requests.hasChallenge(&initial_nonce, endpoint.addr));
    try std.testing.expectEqual(@as(usize, 1), harness.ingress.permitCount());
}

test "local ENR update pings every connected peer in a live bucket exactly once" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x58} ** 32));
    const local_id = try enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&local_key));
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
    var harness = try ActorHarness.init(alloc, io, cfg);
    defer harness.deinit();
    const actor = &harness.actor;

    var peer_ids: [3]types.NodeId = undefined;
    var peer_addresses: [3]types.Address = undefined;
    var peer_count: usize = 0;
    for (1..128) |candidate| {
        var secret = [_]u8{0} ** 32;
        @memset(&secret, @as(u8, @intCast(candidate)));
        const remote_key = try secp.keyPairFromSecret(&secret);
        const remote_pubkey = secp.compressedPubkey(&remote_key);
        const remote_id = try enr.nodeIdFromCompressedPubkey(&remote_pubkey);
        if (@import("../kbucket.zig").logDistance(&local_id, &remote_id) != 255) continue;
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

    try actor.setLocalEnr(harness.env(), replacement_enr);
    try std.testing.expectEqual(peer_ids.len, harness.recording.datagrams.items.len);
    try std.testing.expectEqual(peer_ids.len, actor.requests.activeCount());
    try std.testing.expectEqual(peer_ids.len, harness.ingress.permitCount());
    for (peer_ids, peer_addresses) |peer_id, address| {
        try std.testing.expect(actor.peers.routing.getEntry(&peer_id).?.health_request != null);
        var address_count: usize = 0;
        for (harness.recording.datagrams.items) |datagram| {
            if (datagram.address.eql(&address)) address_count += 1;
        }
        try std.testing.expectEqual(@as(usize, 1), address_count);
    }
}

test "NODES total is exact bounded consistent and controls final permit release" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x47} ** 32));
    const local_id = try enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&local_key));
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x48} ** 32));
    const remote_pubkey = secp.compressedPubkey(&remote_key);
    const remote_id = try enr.nodeIdFromCompressedPubkey(&remote_pubkey);
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
    var harness = try ActorHarness.init(alloc, io, cfg);
    defer harness.deinit();
    const actor = &harness.actor;
    const stable = session_book.StableSession{ .initiator_key = [_]u8{3} ** 16, .recipient_key = [_]u8{4} ** 16 };
    actor.sessions.put(endpoint, stable, outbound.nowNs(io));
    const req_id = try actor.sendFindNode(harness.env(), endpoint, &remote_pubkey, &.{0}, .api);
    try std.testing.expectEqual(@as(usize, 1), harness.ingress.permitCount());

    var invalid_buffer: [128]u8 = undefined;
    const invalid = message.Nodes{ .req_id = req_id, .total = 17, .enrs = &.{} };
    try deliverEncrypted(actor, io, harness.recording.sender(), &harness.ingress, &harness.outbox, endpoint, &stable.recipient_key, try invalid.encodeInto(&invalid_buffer), 1);
    try std.testing.expect(actor.requests.get(.init(endpoint, req_id)).?.response.nodes.total_responses == null);
    try std.testing.expectEqual(@as(u64, 0), actor.requests.get(.init(endpoint, req_id)).?.response.nodes.responses_received);
    try std.testing.expectEqual(@as(usize, 1), actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 1), harness.ingress.permitCount());

    var nodes_buffer: [128]u8 = undefined;
    const nodes = message.Nodes{ .req_id = req_id, .total = 10, .enrs = &.{} };
    const plaintext = try nodes.encodeInto(&nodes_buffer);
    try deliverEncrypted(actor, io, harness.recording.sender(), &harness.ingress, &harness.outbox, endpoint, &stable.recipient_key, plaintext, 2);
    try std.testing.expectEqual(@as(u64, 10), actor.requests.get(.init(endpoint, req_id)).?.response.nodes.total_responses.?);
    try std.testing.expectEqual(@as(u64, 1), actor.requests.get(.init(endpoint, req_id)).?.response.nodes.responses_received);

    var inconsistent_buffer: [128]u8 = undefined;
    const inconsistent = message.Nodes{ .req_id = req_id, .total = 9, .enrs = &.{} };
    try deliverEncrypted(actor, io, harness.recording.sender(), &harness.ingress, &harness.outbox, endpoint, &stable.recipient_key, try inconsistent.encodeInto(&inconsistent_buffer), 3);
    try std.testing.expectEqual(@as(u64, 1), actor.requests.get(.init(endpoint, req_id)).?.response.nodes.responses_received);

    for (4..9) |nonce| try deliverEncrypted(
        actor,
        io,
        harness.recording.sender(),
        &harness.ingress,
        &harness.outbox,
        endpoint,
        &stable.recipient_key,
        plaintext,
        @intCast(nonce),
    );
    try std.testing.expectEqual(@as(u64, 6), actor.requests.get(.init(endpoint, req_id)).?.response.nodes.responses_received);
    try std.testing.expectEqual(@as(usize, 1), actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 1), harness.ingress.permitCount());

    for (9..13) |nonce| try deliverEncrypted(
        actor,
        io,
        harness.recording.sender(),
        &harness.ingress,
        &harness.outbox,
        endpoint,
        &stable.recipient_key,
        plaintext,
        @intCast(nonce),
    );
    try std.testing.expectEqual(@as(usize, 0), actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 0), harness.ingress.permitCount());
    var nodes_event = harness.outbox.pop() orelse return error.MissingNodesEvent;
    defer nodes_event.deinit(alloc);
    try std.testing.expect(nodes_event == .nodes);
}

test "competing WHOAREYOU is rejected before a conflicting handshake is sent" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x11} ** 32));
    const local_id = try enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&local_key));
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x22} ** 32));
    const remote_pubkey = secp.compressedPubkey(&remote_key);
    const remote_id = try enr.nodeIdFromCompressedPubkey(&remote_pubkey);
    const cfg = config.Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
        .local_node_id = local_id,
        .rate_limiter = null,
        .limits = .{ .max_active_requests = 4, .max_queued_requests = 4, .event_capacity = 8, .command_capacity = 8 },
    };
    var harness = try ActorHarness.init(alloc, io, cfg);
    defer harness.deinit();
    const actor = &harness.actor;
    const address = @import("../types.zig").Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 9000 } };
    const endpoint = @import("../types.zig").Endpoint{ .node_id = remote_id, .addr = address };
    const stable = session_book.StableSession{
        .initiator_key = [_]u8{0x31} ** 16,
        .recipient_key = [_]u8{0x32} ** 16,
    };
    const now_ns: i64 = @intCast(std.Io.Timestamp.now(io, .real).toNanoseconds());
    actor.sessions.put(endpoint, stable, now_ns);

    const req_a = try actor.sendPing(harness.env(), endpoint, &remote_pubkey, 1, .api);
    const req_b = try actor.sendPing(harness.env(), endpoint, &remote_pubkey, 1, .api);
    var sent_a = harness.recording.datagrams.items[0].bytes;
    var sent_b = harness.recording.datagrams.items[1].bytes;
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
    actor.handlePacket(harness.env(), first, address);
    try std.testing.expectEqual(@as(usize, 3), harness.recording.datagrams.items.len);
    actor.handlePacket(harness.env(), first, address);
    try std.testing.expectEqual(@as(usize, 3), harness.recording.datagrams.items.len);
    actor.handlePacket(harness.env(), second, address);
    try std.testing.expectEqual(@as(usize, 3), harness.recording.datagrams.items.len);
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
    const local_id = try enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&local_key));
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x54} ** 32));
    const remote_pubkey = secp.compressedPubkey(&remote_key);
    const remote_id = try enr.nodeIdFromCompressedPubkey(&remote_pubkey);
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
    var harness = try ActorHarness.init(alloc, io, cfg);
    defer harness.deinit();
    const actor = &harness.actor;
    const req_id = try actor.sendPing(harness.env(), endpoint, &remote_pubkey, 0, .api);
    var probe = harness.recording.datagrams.items[0].bytes;
    const request_nonce = (try packet.decode(probe.bytes[0..probe.len], &remote_id)).static_header.nonce;
    var challenge_buffer: [packet.WHOAREYOU_CHALLENGE_DATA_SIZE]u8 = undefined;
    const challenge = try packet.encodeWhoareyouPacketInto(&challenge_buffer, .{
        .masking_iv = &([_]u8{0x55} ** 16),
        .recipient_node_id = &local_id,
        .request_nonce = &request_nonce,
        .id_nonce = &([_]u8{0x56} ** 16),
        .enr_seq = 0,
    }, null);
    harness.recording.fail_next = true;
    actor.handlePacket(harness.env(), challenge, endpoint.addr);

    try std.testing.expectEqual(@as(usize, 1), harness.recording.datagrams.items.len);
    try std.testing.expectEqual(@as(usize, 1), harness.ingress.permitCount());
    try std.testing.expect(actor.requests.hasChallenge(&request_nonce, endpoint.addr));
    try std.testing.expect(actor.requests.pendingKeys(endpoint) == null);
    const active = actor.requests.get(.init(endpoint, req_id)) orelse return error.MissingRequestAfterSendFailure;
    try std.testing.expect(active.phase == .awaiting_whoareyou);
}

test "failed ciphertext does not refresh stable session LRU recency" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x21} ** 32));
    const local_id = try enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&local_key));
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
    var harness = try ActorHarness.init(alloc, io, cfg);
    defer harness.deinit();
    const actor = &harness.actor;
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
    var garbage = try encodeEncryptedPacket(actor, lru_endpoint.node_id, &([_]u8{0xff} ** 16), &.{message.MSG_PING}, 21);
    actor.handlePacket(harness.env(), garbage.bytes[0..garbage.len], lru_endpoint.addr);
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
    const local_id = try enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&local_key));
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x58} ** 32));
    const remote_pubkey = secp.compressedPubkey(&remote_key);
    const remote_id = try enr.nodeIdFromCompressedPubkey(&remote_pubkey);
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
    var harness = try ActorHarness.init(alloc, io, cfg);
    defer harness.deinit();
    const actor = &harness.actor;
    try std.testing.expect(actor.addNode(remote_id, &remote_pubkey, endpoint.addr, null, outbound.nowNs(io)));
    const stable = session_book.StableSession{ .initiator_key = [_]u8{0x61} ** 16, .recipient_key = [_]u8{0x62} ** 16 };
    actor.sessions.put(endpoint, stable, outbound.nowNs(io));
    const ping = message.Ping{ .req_id = try message.ReqId.fromSlice(&.{1}), .enr_seq = 0 };
    var plaintext_buffer: [128]u8 = undefined;
    const plaintext = try ping.encodeInto(&plaintext_buffer);
    const replay = try encodeEncryptedPacket(actor, endpoint.node_id, &stable.recipient_key, plaintext, 1);
    var first = replay;
    actor.handlePacket(harness.env(), first.bytes[0..first.len], endpoint.addr);
    try std.testing.expectEqual(@as(usize, 1), harness.recording.datagrams.items.len);
    var duplicate = replay;
    actor.handlePacket(harness.env(), duplicate.bytes[0..duplicate.len], endpoint.addr);
    try std.testing.expectEqual(@as(usize, 1), harness.recording.datagrams.items.len);

    var wrong_source = try encodeEncryptedPacket(actor, endpoint.node_id, &stable.recipient_key, plaintext, 2);
    actor.handlePacket(harness.env(), wrong_source.bytes[0..wrong_source.len], wrong_address);
    try std.testing.expectEqual(@as(usize, 2), harness.recording.datagrams.items.len);
    try std.testing.expect(harness.recording.datagrams.items[1].address.eql(&wrong_address));
    var whoareyou = harness.recording.datagrams.items[1].bytes;
    try std.testing.expectEqual(packet.FLAG_WHOAREYOU, (try packet.decode(whoareyou.bytes[0..whoareyou.len], &remote_id)).static_header.flag);
    try std.testing.expectEqual(@as(u64, 1), actor.metrics.rcvd_message_count[metrics.MessageType.ping.index()]);
}

test "session nonce epoch retires at capacity and never redispatches its first request" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x5d} ** 32));
    const local_id = try enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&local_key));
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x5e} ** 32));
    const remote_id = try enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&remote_key));
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
    var harness = try ActorHarness.init(alloc, io, cfg);
    defer harness.deinit();
    const actor = &harness.actor;
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
        actor,
        remote_id,
        &stable.recipient_key,
        try original_request.encodeInto(&original_plaintext_buffer),
        1,
    );
    actor.handlePacket(
        harness.env(),
        original_packet.bytes[0..original_packet.len],
        endpoint.addr,
    );

    const filler = message.TalkResp{ .req_id = try message.ReqId.fromSlice(&.{2}), .response = "filler" };
    var filler_plaintext_buffer: [128]u8 = undefined;
    const filler_plaintext = try filler.encodeInto(&filler_plaintext_buffer);
    for (0..session_book.SEEN_NONCES_CAP) |index| {
        var filler_packet = try encodeEncryptedPacket(
            actor,
            remote_id,
            &stable.recipient_key,
            filler_plaintext,
            @intCast(index + 2),
        );
        actor.handlePacket(
            harness.env(),
            filler_packet.bytes[0..filler_packet.len],
            endpoint.addr,
        );
    }
    try std.testing.expect(actor.sessions.peek(endpoint, outbound.nowNs(io)) == null);
    try std.testing.expectEqual(@as(usize, 1), actor.sessions.challengeCount());
    try std.testing.expectEqual(@as(usize, 1), harness.ingress.permitCount());
    try std.testing.expectEqual(@as(usize, 1), harness.recording.datagrams.items.len);

    actor.handlePacket(
        harness.env(),
        original_packet.bytes[0..original_packet.len],
        endpoint.addr,
    );
    try std.testing.expectEqual(@as(u64, 1), actor.metrics.rcvd_message_count[metrics.MessageType.talkreq.index()]);
    try std.testing.expectEqual(@as(u64, session_book.SEEN_NONCES_CAP - 1), actor.metrics.rcvd_message_count[metrics.MessageType.talkresp.index()]);
    try std.testing.expectEqual(@as(usize, 1), harness.recording.datagrams.items.len);
}

test "successful handshake records initial probe nonce and replay is inert" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const key_a = try secp.keyPairFromSecret(&([_]u8{0x63} ** 32));
    const pubkey_a = secp.compressedPubkey(&key_a);
    const id_a = try enr.nodeIdFromCompressedPubkey(&pubkey_a);
    const key_b = try secp.keyPairFromSecret(&([_]u8{0x64} ** 32));
    const pubkey_b = secp.compressedPubkey(&key_b);
    const id_b = try enr.nodeIdFromCompressedPubkey(&pubkey_b);
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
    var sender_a = RecordingSender.init(alloc);
    defer sender_a.deinit();
    var sender_b = RecordingSender.init(alloc);
    defer sender_b.deinit();
    var link_a_to_b = PacketLink.init(&sender_a, address_b, address_a, &actor_b, .{ .io = io, .sender = sender_b.sender(), .ingress = &ingress_b, .outbox = &outbox_b });
    var link_b_to_a = PacketLink.init(&sender_b, address_a, address_b, &actor_a, .{ .io = io, .sender = sender_a.sender(), .ingress = &ingress_a, .outbox = &outbox_a });
    try std.testing.expect(actor_a.addNode(id_b, &pubkey_b, address_b, null, outbound.nowNs(io)));
    try std.testing.expect(actor_b.addNode(id_a, &pubkey_a, address_a, null, outbound.nowNs(io)));

    _ = try actor_a.sendPing(
        .{ .io = io, .sender = sender_a.sender(), .ingress = &ingress_a, .outbox = &outbox_a },
        .{ .node_id = id_b, .addr = address_b },
        &pubkey_b,
        0,
        .api,
    );
    const original_probe_index = try link_a_to_b.snapshotNext();
    var original_probe = sender_a.datagrams.items[original_probe_index].bytes;
    const probe_nonce = (try packet.decode(original_probe.bytes[0..original_probe.len], &id_b)).static_header.nonce;
    try link_a_to_b.deliverNext();
    try link_b_to_a.deliverNext();
    try link_a_to_b.deliverNext();
    try std.testing.expectEqual(@as(usize, 0), actor_b.sessions.challengeCount());
    try std.testing.expectEqual(@as(usize, 2), sender_b.datagrams.items.len);
    const established = actor_b.sessions.get(.{ .node_id = id_a, .addr = address_a }, outbound.nowNs(io)) orelse return error.MissingEstablishedSession;
    try std.testing.expect(established.seen_nonces.contains(&probe_nonce));

    try link_a_to_b.replay(original_probe_index);
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
    const local_id = try enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&local_key));
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x5a} ** 32));
    const remote_pubkey = secp.compressedPubkey(&remote_key);
    const remote_id = try enr.nodeIdFromCompressedPubkey(&remote_pubkey);
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
    var harness = try ActorHarness.init(alloc, io, cfg);
    defer harness.deinit();
    const actor = &harness.actor;
    try std.testing.expect(actor.addNode(remote_id, &remote_pubkey, endpoint.addr, null, outbound.nowNs(io)));
    const old = session_book.StableSession{ .initiator_key = [_]u8{0x71} ** 16, .recipient_key = [_]u8{0x72} ** 16 };
    actor.sessions.put(endpoint, old, outbound.nowNs(io));
    const req_id = try actor.sendPing(harness.env(), endpoint, &remote_pubkey, 0, .api);
    var sent = harness.recording.datagrams.items[0].bytes;
    const request_nonce = (try packet.decode(sent.bytes[0..sent.len], &remote_id)).static_header.nonce;
    var challenge_buffer: [packet.WHOAREYOU_CHALLENGE_DATA_SIZE]u8 = undefined;
    const challenge = try packet.encodeWhoareyouPacketInto(&challenge_buffer, .{
        .masking_iv = &([_]u8{0x73} ** 16),
        .recipient_node_id = &local_id,
        .request_nonce = &request_nonce,
        .id_nonce = &([_]u8{0x74} ** 16),
        .enr_seq = 0,
    }, null);
    actor.handlePacket(harness.env(), challenge, endpoint.addr);
    const pending = actor.requests.pendingKeys(endpoint) orelse return error.MissingPendingRekey;
    try std.testing.expectEqual(@as(usize, 2), harness.recording.datagrams.items.len);

    const old_ping = message.Ping{ .req_id = try message.ReqId.fromSlice(&.{0xa1}), .enr_seq = 0 };
    var old_ping_buffer: [128]u8 = undefined;
    var old_response = try encodeEncryptedPacket(actor, remote_id, &old.recipient_key, try old_ping.encodeInto(&old_ping_buffer), 9);
    actor.handlePacket(harness.env(), old_response.bytes[0..old_response.len], endpoint.addr);
    const still_pending = actor.requests.pendingKeys(endpoint) orelse return error.PendingRekeyWasPromotedByOldKey;
    try std.testing.expect(types.RequestKeyContext.eql(.{}, pending.key, still_pending.key));
    try std.testing.expect(actor.requests.shouldQueue(endpoint));
    try std.testing.expectEqual(@as(usize, 1), actor.requests.activeCount());
    const still_old = actor.sessions.get(endpoint, outbound.nowNs(io)) orelse return error.MissingOldSession;
    try std.testing.expectEqual(old.initiator_key, still_old.initiator_key);
    try std.testing.expectEqual(old.recipient_key, still_old.recipient_key);
    try std.testing.expectEqual(@as(usize, 3), harness.recording.datagrams.items.len);

    const pong = message.Pong{
        .req_id = req_id,
        .enr_seq = 0,
        .recipient_ip = .{ .ip4 = .{ 127, 0, 0, 1 } },
        .recipient_port = 9000,
    };
    var pong_buffer: [128]u8 = undefined;
    var response = try encodeEncryptedPacket(actor, remote_id, &pending.keys.recipient_key, try pong.encodeInto(&pong_buffer), 10);
    actor.handlePacket(harness.env(), response.bytes[0..response.len], endpoint.addr);

    try std.testing.expectEqual(@as(usize, 0), actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 1), harness.ingress.permitCount());
    actor.responses.prune(std.math.maxInt(i64), &harness.ingress);
    try std.testing.expectEqual(@as(usize, 0), harness.ingress.permitCount());
    try std.testing.expect(actor.requests.pendingKeys(endpoint) == null);
    const promoted = actor.sessions.get(endpoint, outbound.nowNs(io)) orelse return error.MissingPromotedSession;
    try std.testing.expectEqual(pending.keys.initiator_key, promoted.initiator_key);
    try std.testing.expectEqual(pending.keys.recipient_key, promoted.recipient_key);
    var pong_event = harness.outbox.pop() orelse return error.MissingPongEvent;
    defer pong_event.deinit(alloc);
    try std.testing.expect(pong_event == .pong);
}

test "rekey lane queues stable-key requests and drains FIFO after candidate proof" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x5b} ** 32));
    const local_id = try enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&local_key));
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x5c} ** 32));
    const remote_pubkey = secp.compressedPubkey(&remote_key);
    const remote_id = try enr.nodeIdFromCompressedPubkey(&remote_pubkey);
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
    var harness = try ActorHarness.init(alloc, io, cfg);
    defer harness.deinit();
    const actor = &harness.actor;
    try std.testing.expect(actor.addNode(remote_id, &remote_pubkey, endpoint.addr, null, outbound.nowNs(io)));
    const old = session_book.StableSession{ .initiator_key = [_]u8{0x75} ** 16, .recipient_key = [_]u8{0x76} ** 16 };
    actor.sessions.put(endpoint, old, outbound.nowNs(io));

    _ = try actor.sendPing(harness.env(), endpoint, &remote_pubkey, 0, .api);
    var sent = harness.recording.datagrams.items[0].bytes;
    const request_nonce = (try packet.decode(sent.bytes[0..sent.len], &remote_id)).static_header.nonce;
    var challenge_buffer: [packet.WHOAREYOU_CHALLENGE_DATA_SIZE]u8 = undefined;
    const challenge = try packet.encodeWhoareyouPacketInto(&challenge_buffer, .{
        .masking_iv = &([_]u8{0x77} ** 16),
        .recipient_node_id = &local_id,
        .request_nonce = &request_nonce,
        .id_nonce = &([_]u8{0x78} ** 16),
        .enr_seq = 0,
    }, null);
    actor.handlePacket(harness.env(), challenge, endpoint.addr);
    const pending = actor.requests.pendingKeys(endpoint) orelse return error.MissingPendingRekey;
    try std.testing.expectEqual(@as(usize, 2), harness.recording.datagrams.items.len);

    const second_id = try actor.sendPing(harness.env(), endpoint, &remote_pubkey, 1, .api);
    const third_id = try actor.sendPing(harness.env(), endpoint, &remote_pubkey, 2, .api);
    try std.testing.expectEqual(@as(usize, 2), harness.recording.datagrams.items.len);
    try std.testing.expectEqual(@as(usize, 2), actor.requests.queuedCount());

    const proof_ping = message.Ping{ .req_id = try message.ReqId.fromSlice(&.{0xa2}), .enr_seq = 0 };
    var proof_buffer: [128]u8 = undefined;
    var proof = try encodeEncryptedPacket(actor, remote_id, &pending.keys.recipient_key, try proof_ping.encodeInto(&proof_buffer), 11);
    actor.handlePacket(harness.env(), proof.bytes[0..proof.len], endpoint.addr);

    try std.testing.expect(actor.requests.pendingKeys(endpoint) == null);
    try std.testing.expectEqual(@as(usize, 0), actor.requests.queuedCount());
    try std.testing.expectEqual(@as(usize, 5), harness.recording.datagrams.items.len);
    const second_plaintext = try decryptRecorded(&harness.recording, 3, remote_id, &pending.keys.initiator_key);
    const third_plaintext = try decryptRecorded(&harness.recording, 4, remote_id, &pending.keys.initiator_key);
    const second_ping = try message.Ping.decode(second_plaintext.slice());
    const third_ping = try message.Ping.decode(third_plaintext.slice());
    try std.testing.expectEqualSlices(u8, second_id.slice(), second_ping.req_id.slice());
    try std.testing.expectEqualSlices(u8, third_id.slice(), third_ping.req_id.slice());
}

fn decryptRecorded(recording: *const RecordingSender, index: usize, recipient_id: types.NodeId, read_key: *const [16]u8) !types.PacketBytes {
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
    const local_id = try enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&local_key));
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x62} ** 32));
    const remote_pubkey = secp.compressedPubkey(&remote_key);
    const remote_id = try enr.nodeIdFromCompressedPubkey(&remote_pubkey);
    const cfg = config.Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
        .local_node_id = local_id,
        .rate_limiter = null,
        .limits = .{ .max_active_requests = 2, .max_queued_requests = 2, .event_capacity = 2, .command_capacity = 2 },
    };
    var harness = try ActorHarness.init(alloc, io, cfg);
    defer harness.deinit();
    const actor = &harness.actor;
    harness.recording.fail_next = true;
    const endpoint = @import("../types.zig").Endpoint{
        .node_id = remote_id,
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 2 }, .port = 9000 } },
    };

    try std.testing.expectError(
        error.TransportSendFailed,
        actor.sendFindNode(harness.env(), endpoint, &remote_pubkey, &.{1}, .api),
    );
    try std.testing.expectEqual(@as(usize, 0), harness.recording.datagrams.items.len);
    try std.testing.expectEqual(@as(usize, 0), actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 0), actor.requests.queuedCount());
    try std.testing.expectEqual(@as(usize, 0), harness.ingress.permitCount());
    actor.requests.assertInvariants();
}

test "WHOAREYOU and response send failures release prepared permits and retained state" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x9b} ** 32));
    const local_id = try enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&local_key));
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x9c} ** 32));
    const remote_pubkey = secp.compressedPubkey(&remote_key);
    const remote_id = try enr.nodeIdFromCompressedPubkey(&remote_pubkey);
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
    var harness = try ActorHarness.init(alloc, io, cfg);
    defer harness.deinit();
    const actor = &harness.actor;
    try std.testing.expect(actor.addNode(remote_id, &remote_pubkey, endpoint.addr, null, outbound.nowNs(io)));
    actor.sessions.put(endpoint, .{
        .initiator_key = [_]u8{0xe1} ** 16,
        .recipient_key = [_]u8{0xe2} ** 16,
    }, outbound.nowNs(io));

    harness.recording.fail_next = true;
    try std.testing.expectError(error.TransportSendFailed, actor.sendTalkResponse(
        harness.env(),
        endpoint,
        try message.ReqId.fromSlice(&.{1}),
        "failed",
    ));
    try std.testing.expectEqual(@as(usize, 0), actor.responses.count());
    try std.testing.expectEqual(@as(usize, 0), harness.ingress.permitCount());

    try std.testing.expect(actor.sessions.remove(endpoint));
    var undecryptable = try encodeEncryptedPacket(actor, remote_id, &([_]u8{0xff} ** 16), &.{message.MSG_PING}, 0xe3);
    harness.recording.fail_next = true;
    actor.handlePacket(
        harness.env(),
        undecryptable.bytes[0..undecryptable.len],
        endpoint.addr,
    );
    try std.testing.expectEqual(@as(usize, 0), actor.sessions.challengeCount());
    try std.testing.expectEqual(@as(usize, 0), harness.ingress.permitCount());
    try std.testing.expectEqual(@as(usize, 0), harness.recording.datagrams.items.len);
}

test "transactional capacity-one challenge replacement send failure preserves original" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x2c} ** 32));
    const local_id = try enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&local_key));
    const remote_key_a = try secp.keyPairFromSecret(&([_]u8{0x2d} ** 32));
    const remote_id_a = try enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&remote_key_a));
    const remote_key_b = try secp.keyPairFromSecret(&([_]u8{0x2e} ** 32));
    const remote_id_b = try enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&remote_key_b));
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
    var harness = try ActorHarness.init(alloc, io, cfg);
    defer harness.deinit();
    const actor = &harness.actor;

    var first = try encodeEncryptedPacket(actor, remote_id_a, &([_]u8{0xa1} ** 16), &.{message.MSG_PING}, 0xa2);
    actor.handlePacket(
        harness.env(),
        first.bytes[0..first.len],
        endpoint_a.addr,
    );
    try std.testing.expect(actor.sessions.peekChallenge(endpoint_a, outbound.nowNs(io)) != null);
    try std.testing.expectEqual(@as(usize, 1), actor.sessions.challengeCount());
    try std.testing.expectEqual(@as(usize, 1), harness.ingress.permitCount());

    harness.recording.fail_next = true;
    var second = try encodeEncryptedPacket(actor, remote_id_b, &([_]u8{0xb1} ** 16), &.{message.MSG_PING}, 0xb2);
    actor.handlePacket(
        harness.env(),
        second.bytes[0..second.len],
        endpoint_b.addr,
    );
    try std.testing.expect(actor.sessions.peekChallenge(endpoint_a, outbound.nowNs(io)) != null);
    try std.testing.expect(actor.sessions.peekChallenge(endpoint_b, outbound.nowNs(io)) == null);
    try std.testing.expectEqual(@as(usize, 1), actor.sessions.challengeCount());
    try std.testing.expectEqual(@as(usize, 1), harness.ingress.permitCount());
}

test "transactional capacity-one response replacement send failure preserves original" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x2f} ** 32));
    const local_id = try enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&local_key));
    const remote_key_a = try secp.keyPairFromSecret(&([_]u8{0x30} ** 32));
    const remote_pubkey_a = secp.compressedPubkey(&remote_key_a);
    const remote_id_a = try enr.nodeIdFromCompressedPubkey(&remote_pubkey_a);
    const remote_key_b = try secp.keyPairFromSecret(&([_]u8{0x31} ** 32));
    const remote_pubkey_b = secp.compressedPubkey(&remote_key_b);
    const remote_id_b = try enr.nodeIdFromCompressedPubkey(&remote_pubkey_b);
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
    var harness = try ActorHarness.init(alloc, io, cfg);
    defer harness.deinit();
    const actor = &harness.actor;
    try std.testing.expect(actor.addNode(remote_id_a, &remote_pubkey_a, endpoint_a.addr, null, outbound.nowNs(io)));
    try std.testing.expect(actor.addNode(remote_id_b, &remote_pubkey_b, endpoint_b.addr, null, outbound.nowNs(io)));
    actor.sessions.put(endpoint_a, .{ .initiator_key = [_]u8{0xc1} ** 16, .recipient_key = [_]u8{0xc2} ** 16 }, outbound.nowNs(io));
    actor.sessions.put(endpoint_b, .{ .initiator_key = [_]u8{0xd1} ** 16, .recipient_key = [_]u8{0xd2} ** 16 }, outbound.nowNs(io));

    try actor.sendTalkResponse(
        harness.env(),
        endpoint_a,
        try message.ReqId.fromSlice(&.{1}),
        "first",
    );
    var sent = harness.recording.datagrams.items[0].bytes;
    const first_nonce = (try packet.decode(sent.bytes[0..sent.len], &remote_id_a)).static_header.nonce;
    try std.testing.expect(actor.responses.hasLive(endpoint_a.addr, &first_nonce, outbound.nowNs(io)));
    try std.testing.expectEqual(@as(usize, 1), actor.responses.count());
    try std.testing.expectEqual(@as(usize, 1), harness.ingress.permitCount());

    harness.recording.fail_next = true;
    try std.testing.expectError(error.TransportSendFailed, actor.sendTalkResponse(
        harness.env(),
        endpoint_b,
        try message.ReqId.fromSlice(&.{2}),
        "second",
    ));
    try std.testing.expect(actor.responses.hasLive(endpoint_a.addr, &first_nonce, outbound.nowNs(io)));
    try std.testing.expectEqual(@as(usize, 1), actor.responses.count());
    try std.testing.expectEqual(@as(usize, 1), harness.ingress.permitCount());
}
