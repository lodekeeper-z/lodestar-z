const std = @import("std");
const actor_mod = @import("../actor.zig");
const admission = @import("../admission.zig");
const config = @import("../config.zig");
const enr = @import("../enr.zig");
const events = @import("../events.zig");
const handshake = @import("../protocol/handshake.zig");
const outbound = @import("../flow/outbound.zig");
const packet = @import("../protocol/packet.zig");
const message = @import("../protocol/message.zig");
const request_results = @import("../request_results.zig");
const metrics = @import("../metrics.zig");
const secp = @import("../secp256k1.zig");
const peer_store = @import("../state/peer_store.zig");
const session_book = @import("../state/session_book.zig");
const types = @import("../types.zig");
const ActorHarness = @import("../test_support/actor_harness.zig").ActorHarness;
const PacketLink = @import("../test_support/packet_link.zig").PacketLink;
const RecordingSender = @import("../test_support/recording_sender.zig").RecordingSender;
const deliverEncrypted = @import("../test_support/encrypted_delivery.zig").deliverEncrypted;

fn drainEffects(
    actor: *actor_mod.Actor,
    env: actor_mod.Env,
    effects: *actor_mod.EffectQueue,
    sender: *RecordingSender,
) !void {
    while (effects.pop()) |effect| {
        sender.sender().send(effect.destination(), effect.packetBytes()) catch |err| {
            actor.applyEffectCompletion(env, effect, .failed);
            return err;
        };
        actor.applyEffectCompletion(env, effect, .sent);
    }
}

const HandshakeChallengeReplacement = struct {
    publication: session_book.ChallengePublication,
    called: bool = false,
    old_removed: bool = false,
    newer_handle: ?session_book.ChallengeHandle = null,
    challenge_fingerprint: u64 = 0,
    permit_fingerprint: u64 = 0,
    failure: ?anyerror = null,

    fn run(
        context: *anyopaque,
        actor: *actor_mod.Actor,
        ingress: *admission.IngressAdmission,
        old: session_book.ChallengeView,
    ) void {
        const self: *@This() = @ptrCast(@alignCast(context));
        self.replace(actor, ingress, old) catch |err| {
            self.failure = err;
        };
    }

    fn replace(
        self: *@This(),
        actor: *actor_mod.Actor,
        ingress: *admission.IngressAdmission,
        old: session_book.ChallengeView,
    ) !void {
        if (self.called) return error.ReplacementHookCalledTwice;
        self.called = true;
        self.old_removed = actor.sessions.removeChallenge(old.handle, ingress);
        if (!self.old_removed) return error.OldChallengeNotRemoved;

        var permit = try ingress.acquire(old.handle.endpoint.addr, admission.challengePacketBudget(actor.request_retries));
        var permit_transferred = false;
        defer if (!permit_transferred) permit.release(ingress);
        const newer = try actor.sessions.publishChallenge(old.handle.endpoint, self.publication, &permit, ingress);
        permit_transferred = true;
        errdefer _ = actor.sessions.removeChallenge(newer, ingress);
        if (!actor.sessions.completeChallengeSend(newer, .sent, ingress)) return error.NewChallengeNotLive;
        self.newer_handle = newer;
        self.challenge_fingerprint = session_book.SessionBook.Testing.challengeGenerationFingerprint(&actor.sessions);
        self.permit_fingerprint = admission.IngressAdmission.Testing.permitGenerationFingerprint(ingress);
    }
};

test "oversized sessionless TALKREQ handshake fails once without waiting for timeout" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0xa7} ** 32));
    const local_id = try enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&local_key));
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0xa8} ** 32));
    const remote_pubkey = secp.compressedPubkey(&remote_key);
    const remote_id = try enr.nodeIdFromCompressedPubkey(&remote_pubkey);
    const endpoint = types.Endpoint{
        .node_id = remote_id,
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 50 }, .port = 9250 } },
    };
    const cfg = config.Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
        .request_timeout_ms = 1,
        .request_retries = 0,
        .rate_limiter = null,
        .limits = .{
            .max_active_requests = 1,
            .max_queued_requests = 1,
            .challenge_capacity = 1,
            .response_recovery_capacity = 1,
            .event_capacity = 1,
            .command_capacity = 1,
            .request_result_capacity = 1,
        },
    };
    var harness = try ActorHarness.init(alloc, io, cfg);
    defer harness.deinit();
    var results = try request_results.RequestResultOutbox.init(io, alloc, 1);
    defer results.deinit();
    try std.testing.expect(results.reserve());
    try std.testing.expect(results.claim());
    var env = harness.env();
    env.request_results = &results;

    const request = [_]u8{0x5a} ** 1_100;
    const req_id = try actor_mod.Testing.sendTalkRequestResolvedWithOriginForTest(&harness.actor, env, endpoint, &remote_pubkey, "utp", &request, .reliable_api);
    try harness.drainEffects();
    try std.testing.expectEqual(@as(usize, 1), harness.recording.datagrams.items.len);
    try std.testing.expect(harness.recording.datagrams.items[0].bytes.len <= packet.MAX_PACKET_SIZE);
    const key = req_id.key;
    const plaintext_len = harness.actor.requests.get(key).?.phase.awaiting_whoareyou.recovery.plaintext.len;
    const recordless_handshake_overhead = packet.MASKING_IV_SIZE + packet.STATIC_HEADER_SIZE + 34 + handshake.sig_size + handshake.eph_key_size + packet.GCM_TAG_SIZE;
    try std.testing.expect(recordless_handshake_overhead + plaintext_len > packet.MAX_PACKET_SIZE);

    var initial = harness.recording.datagrams.items[0].bytes;
    const request_nonce = (try packet.decode(initial.bytes[0..initial.len], &remote_id)).static_header.nonce;
    var challenge_buffer: [packet.WHOAREYOU_CHALLENGE_DATA_SIZE]u8 = undefined;
    const challenge = try packet.encodeWhoareyouPacketInto(&challenge_buffer, .{
        .masking_iv = &([_]u8{0xa9} ** 16),
        .recipient_node_id = &local_id,
        .request_nonce = &request_nonce,
        .id_nonce = &([_]u8{0xaa} ** 16),
        .enr_seq = 0,
    }, null);
    const duplicate_challenge = challenge_buffer;
    harness.actor.handlePacket(env, challenge, endpoint.addr);

    try std.testing.expectEqual(@as(usize, 1), harness.recording.datagrams.items.len);
    try std.testing.expectEqual(@as(usize, 0), harness.actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 0), harness.actor.requests.queuedCount());
    try std.testing.expectEqual(@as(usize, 0), harness.ingress.permitCount());
    try std.testing.expect(harness.actor.requests.challenge(&request_nonce, endpoint.addr) == error.InvalidChallenge);
    const result = results.pop() orelse return error.MissingSendFailure;
    try std.testing.expectEqual(types.RequestKind.talkreq, result.kind);
    try std.testing.expectEqualSlices(u8, req_id.key.req_id.slice(), result.handle.request_id.slice());
    try std.testing.expectEqual(request_results.RequestSendFailure.packet_too_large, result.terminal.send_failure);
    try std.testing.expect(results.pop() == null);

    harness.actor.maintenanceAt(env, std.math.maxInt(i64));
    try std.testing.expect(!harness.actor.cancelRequest(env, req_id));
    var duplicate = duplicate_challenge;
    harness.actor.handlePacket(env, &duplicate, endpoint.addr);
    try std.testing.expect(results.pop() == null);
    harness.actor.requests.assertInvariants();
}

test "smaller sessionless TALKREQ still recovers with one handshake packet" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0xab} ** 32));
    const local_id = try enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&local_key));
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0xac} ** 32));
    const remote_pubkey = secp.compressedPubkey(&remote_key);
    const remote_id = try enr.nodeIdFromCompressedPubkey(&remote_pubkey);
    const endpoint = types.Endpoint{
        .node_id = remote_id,
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 51 }, .port = 9251 } },
    };
    const cfg = config.Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
        .rate_limiter = null,
        .limits = .{ .max_active_requests = 1, .max_queued_requests = 1, .event_capacity = 1, .command_capacity = 1 },
    };
    var harness = try ActorHarness.init(alloc, io, cfg);
    defer harness.deinit();
    const req_id = try actor_mod.Testing.sendTalkRequestResolvedForTest(&harness.actor, harness.env(), endpoint, &remote_pubkey, "utp", "small request");
    try harness.drainEffects();
    var initial = harness.recording.datagrams.items[0].bytes;
    const request_nonce = (try packet.decode(initial.bytes[0..initial.len], &remote_id)).static_header.nonce;
    var challenge_buffer: [packet.WHOAREYOU_CHALLENGE_DATA_SIZE]u8 = undefined;
    const challenge = try packet.encodeWhoareyouPacketInto(&challenge_buffer, .{
        .masking_iv = &([_]u8{0xad} ** 16),
        .recipient_node_id = &local_id,
        .request_nonce = &request_nonce,
        .id_nonce = &([_]u8{0xae} ** 16),
        .enr_seq = 0,
    }, null);

    harness.actor.handlePacket(harness.env(), challenge, endpoint.addr);
    harness.drainEffectsIgnoringFailures();

    try std.testing.expectEqual(@as(usize, 2), harness.recording.datagrams.items.len);
    var recovered = harness.recording.datagrams.items[1].bytes;
    try std.testing.expectEqual(packet.FLAG_HANDSHAKE, (try packet.decode(recovered.bytes[0..recovered.len], &remote_id)).static_header.flag);
    try std.testing.expectEqual(@as(usize, 1), harness.actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 1), harness.ingress.permitCount());
    try std.testing.expect(harness.actor.cancelRequest(harness.env(), req_id));
    try std.testing.expectEqual(@as(usize, 0), harness.ingress.permitCount());
    harness.actor.requests.assertInvariants();
}

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
        .request_timeout_ms = 1,
        .request_retries = 1,
        .rate_limiter = null,
        .limits = limits,
    };
    const config_b = config.Config{
        .bind_addresses = .{ .ip4 = address_b },
        .local_key_pair = key_b,
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
    var effect_storage_a: [2]actor_mod.ActorEffect = undefined;
    var effects_a = actor_mod.EffectQueue.init(&effect_storage_a);
    const env_a = actor_mod.Env{ .io = io, .ingress = &ingress_a, .outbox = &outbox_a, .effects = &effects_a };
    var link_a_to_b = PacketLink.init(&sender_a, address_b, address_a, &actor_b, .{ .io = io, .ingress = &ingress_b, .outbox = &outbox_b }, &sender_b);
    var link_b_to_a = PacketLink.init(&sender_b, address_a, address_b, &actor_a, env_a, &sender_a);
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

    const req_id = try actor_mod.Testing.sendPingResolvedForTest(
        &actor_a,
        env_a,
        .{ .node_id = id_b, .addr = address_b },
        &pubkey_b,
        .api,
    );
    try drainEffects(&actor_a, env_a, &effects_a, &sender_a);
    try link_a_to_b.deliverNext();
    try std.testing.expectEqual(@as(usize, 1), sender_b.datagrams.items.len);
    try link_b_to_a.dropNext();
    var first_packet = sender_a.datagrams.items[0].bytes;
    const first_nonce = (try packet.decode(first_packet.bytes[0..first_packet.len], &id_b)).static_header.nonce;

    const request_key = req_id.key;
    const deadline_ns = actor_a.requests.get(request_key).?.deadline_ns;
    actor_a.maintenanceAt(env_a, deadline_ns - 1);
    try drainEffects(&actor_a, env_a, &effects_a, &sender_a);
    try std.testing.expectEqual(@as(usize, 1), actor_a.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 1), ingress_a.permitCount());
    try std.testing.expectEqual(@as(usize, 1), sender_a.datagrams.items.len);
    try std.testing.expect(outbox_a.pop() == null);
    actor_a.maintenanceAt(env_a, deadline_ns);
    try drainEffects(&actor_a, env_a, &effects_a, &sender_a);
    try std.testing.expectEqual(@as(usize, 2), sender_a.datagrams.items.len);
    var retry_packet = sender_a.datagrams.items[1].bytes;
    const retry_nonce = (try packet.decode(retry_packet.bytes[0..retry_packet.len], &id_b)).static_header.nonce;
    try std.testing.expect(!std.mem.eql(u8, &first_nonce, &retry_nonce));
    try link_a_to_b.deliverNext();
    try std.testing.expectEqual(@as(usize, 2), sender_b.datagrams.items.len);
    try link_b_to_a.deliverNext();

    try std.testing.expectEqual(@as(usize, 0), actor_a.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 0), ingress_a.permitCount());
    try std.testing.expect(outbox_a.pop() == null);
}

test "fresh WHOAREYOU effect queue rejection exact-aborts its challenge and permit" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x90} ** 32));
    const local_id = try enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&local_key));
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x91} ** 32));
    const remote_id = try enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&remote_key));
    const remote_address = types.Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 90 }, .port = 9290 } };
    const cfg = config.Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
        .rate_limiter = null,
        .limits = .{ .max_active_requests = 1, .max_queued_requests = 1, .challenge_capacity = 1, .response_recovery_capacity = 1, .event_capacity = 1, .command_capacity = 1 },
    };
    var ingress = try admission.IngressAdmission.init(alloc, null, try admission.permitCapacity(cfg.limits));
    defer ingress.deinit();
    var outbox = try events.EventOutbox.init(io, alloc, 1);
    defer outbox.deinit();
    var actor = try actor_mod.Actor.init(alloc, cfg);
    defer actor.deinit(&ingress);
    var effect_storage: [1]actor_mod.ActorEffect = undefined;
    var effects = actor_mod.EffectQueue.init(&effect_storage);
    const env = actor_mod.Env{ .io = io, .ingress = &ingress, .outbox = &outbox, .effects = &effects };

    const stale_handle = session_book.ChallengeHandle{
        .endpoint = .{ .node_id = [_]u8{0xee} ** 32, .addr = remote_address },
        .generation = std.math.maxInt(u64),
    };
    const filler = actor_mod.ActorEffect{ .whoareyou = .{ .handle = stale_handle, .packet = try .init(&.{0xee}) } };
    try effects.push(filler);

    var datagram_buffer: [packet.MAX_PACKET_SIZE]u8 = undefined;
    const datagram = try packet.encodeMessagePacketInto(&datagram_buffer, .{
        .kind = .ordinary,
        .masking_iv = &([_]u8{0x92} ** packet.MASKING_IV_SIZE),
        .recipient_node_id = &local_id,
        .nonce = &([_]u8{0x93} ** packet.NONCE_SIZE),
        .authdata = &remote_id,
        .write_key = &([_]u8{0x94} ** 16),
        .plaintext = &.{0x95},
    });
    actor.handlePacket(env, datagram_buffer[0..datagram.len], remote_address);

    try std.testing.expectEqual(@as(usize, 0), actor.sessions.challengePhaseCount());
    try std.testing.expectEqual(@as(usize, 0), actor.sessions.challengeCount());
    try std.testing.expectEqual(@as(usize, 0), ingress.permitCount());
    const retained_filler = effects.pop() orelse return error.MissingFiller;
    try std.testing.expectEqual(stale_handle, retained_filler.whoareyou.handle);
    actor.applyEffectCompletion(env, retained_filler, .sent);
    actor.applyEffectCompletion(env, filler, .failed);
    try std.testing.expectEqual(@as(usize, 0), actor.sessions.challengePhaseCount());
    try std.testing.expectEqual(@as(usize, 0), ingress.permitCount());
}

test "actor challenge generation exhaustion preflight preserves every downstream sentinel" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x98} ** 32));
    const local_id = try enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&local_key));
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x99} ** 32));
    const remote_pubkey = secp.compressedPubkey(&remote_key);
    const remote_id = try enr.nodeIdFromCompressedPubkey(&remote_pubkey);
    const remote_address = types.Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 99 }, .port = 9299 } };
    const cfg = config.Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
        .rate_limiter = null,
        .limits = .{ .max_active_requests = 2, .max_queued_requests = 2, .challenge_capacity = 2, .response_recovery_capacity = 1, .event_capacity = 2, .command_capacity = 1, .whoareyou_rate_capacity = 2 },
    };
    var harness = try ActorHarness.init(alloc, io, cfg);
    defer harness.deinit();
    const now_ns = outbound.nowNs(io);
    harness.actor.peers.rememberContact(remote_id, &remote_pubkey, remote_address, false);
    const stable_endpoint = types.Endpoint{ .node_id = [_]u8{0x97} ** 32, .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 97 }, .port = 9297 } } };
    const stable = session_book.StableSession{ .initiator_key = [_]u8{0xa1} ** 16, .recipient_key = [_]u8{0xa2} ** 16 };
    harness.actor.sessions.put(stable_endpoint, stable, now_ns);
    const live_endpoint = types.Endpoint{ .node_id = [_]u8{0x96} ** 32, .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 96 }, .port = 9296 } } };
    var live_permit = try harness.ingress.acquire(live_endpoint.addr, admission.challengePacketBudget(0));
    const live_handle = try harness.actor.sessions.publishChallenge(live_endpoint, .{
        .challenge_data = [_]u8{0xb1} ** packet.WHOAREYOU_CHALLENGE_DATA_SIZE,
        .triggering_nonce = [_]u8{0xb2} ** packet.NONCE_SIZE,
        .datagram = try .init(&.{0xb3}),
        .prepared_at_ns = now_ns,
    }, &live_permit, &harness.ingress);
    try std.testing.expect(harness.actor.sessions.completeChallengeSend(live_handle, .sent, &harness.ingress));
    try std.testing.expect(harness.actor.sessions.allowWhoareyou(remote_address, now_ns));
    session_book.SessionBook.Testing.setNextChallengeGeneration(&harness.actor.sessions, std.math.maxInt(u64));

    const rate_before = session_book.SessionBook.Testing.whoareyouRateState(&harness.actor.sessions, remote_address, now_ns) orelse return error.MissingRateSentinel;
    const challenge_before = session_book.SessionBook.Testing.challengeGenerationFingerprint(&harness.actor.sessions);
    const permit_before = admission.IngressAdmission.Testing.permitGenerationFingerprint(&harness.ingress);
    const metrics_before = harness.actor.metrics;
    const peer_before = harness.actor.peers.known(&remote_id) orelse return error.MissingPeerSentinel;
    var datagram_buffer: [packet.MAX_PACKET_SIZE]u8 = undefined;
    const datagram = try packet.encodeMessagePacketInto(&datagram_buffer, .{
        .kind = .ordinary,
        .masking_iv = &([_]u8{0xc1} ** packet.MASKING_IV_SIZE),
        .recipient_node_id = &local_id,
        .nonce = &([_]u8{0xc2} ** packet.NONCE_SIZE),
        .authdata = &remote_id,
        .write_key = &([_]u8{0xc3} ** 16),
        .plaintext = &.{0xc4},
    });
    harness.actor.handlePacket(harness.env(), datagram_buffer[0..datagram.len], remote_address);

    try std.testing.expectEqual(rate_before, session_book.SessionBook.Testing.whoareyouRateState(&harness.actor.sessions, remote_address, now_ns).?);
    try std.testing.expectEqual(challenge_before, session_book.SessionBook.Testing.challengeGenerationFingerprint(&harness.actor.sessions));
    try std.testing.expectEqual(live_handle, (harness.actor.sessions.peekChallenge(live_endpoint, now_ns) orelse return error.LiveSentinelRemoved).handle);
    try std.testing.expectEqual(permit_before, admission.IngressAdmission.Testing.permitGenerationFingerprint(&harness.ingress));
    try std.testing.expectEqual(@as(usize, 1), harness.ingress.permitCount());
    try std.testing.expectEqual(@as(usize, 0), harness.effects.count());
    try std.testing.expect(std.meta.eql(metrics_before, harness.actor.metrics));
    try std.testing.expectEqual(peer_before, harness.actor.peers.known(&remote_id).?);
    try std.testing.expectEqual(stable, harness.actor.sessions.get(stable_endpoint, now_ns).?);
}

test "paired Actors authenticate a captured WHOAREYOU without removing its same-endpoint replacement" {
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
        .request_timeout_ms = 1,
        .request_retries = 1,
        .rate_limiter = null,
        .limits = limits,
    };
    const config_b = config.Config{
        .bind_addresses = .{ .ip4 = address_b },
        .local_key_pair = key_b,
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
    const replacement_packet = try types.PacketBytes.init(&.{ 0xd7, 0xd8, 0xd9 });
    var replacement = HandshakeChallengeReplacement{ .publication = .{
        .challenge_data = [_]u8{0xd4} ** packet.WHOAREYOU_CHALLENGE_DATA_SIZE,
        .triggering_nonce = [_]u8{0xd5} ** packet.NONCE_SIZE,
        .datagram = replacement_packet,
        .prepared_at_ns = outbound.nowNs(io),
    } };
    var effect_storage_a: [2]actor_mod.ActorEffect = undefined;
    var effects_a = actor_mod.EffectQueue.init(&effect_storage_a);
    const env_a = actor_mod.Env{ .io = io, .ingress = &ingress_a, .outbox = &outbox_a, .effects = &effects_a };
    const env_b = actor_mod.Env{
        .io = io,
        .ingress = &ingress_b,
        .outbox = &outbox_b,
        .handshake_challenge_hook = .{ .context = &replacement, .run = HandshakeChallengeReplacement.run },
    };
    var link_a_to_b = PacketLink.init(&sender_a, address_b, address_a, &actor_b, env_b, &sender_b);
    var link_b_to_a = PacketLink.init(&sender_b, address_a, address_b, &actor_a, env_a, &sender_a);
    const now_ns = outbound.nowNs(io);
    try std.testing.expect(actor_a.addNode(id_b, &pubkey_b, address_b, null, now_ns));
    try std.testing.expect(actor_b.addNode(id_a, &pubkey_a, address_a, null, now_ns));

    const req_id = try actor_mod.Testing.sendPingResolvedForTest(
        &actor_a,
        env_a,
        .{ .node_id = id_b, .addr = address_b },
        &pubkey_b,
        .api,
    );
    try drainEffects(&actor_a, env_a, &effects_a, &sender_a);
    try link_a_to_b.deliverNext();
    try std.testing.expectEqual(@as(usize, 1), sender_b.datagrams.items.len);
    try std.testing.expectEqual(@as(usize, 1), ingress_b.permitCount());
    const endpoint_a = types.Endpoint{ .node_id = id_a, .addr = address_a };
    const live_before_replay = actor_b.sessions.peekChallenge(endpoint_a, outbound.nowNs(io)) orelse return error.MissingLiveChallenge;
    const permit_fingerprint = admission.IngressAdmission.Testing.permitGenerationFingerprint(&ingress_b);
    const copied_replay = actor_mod.ActorEffect{ .whoareyou = .{
        .handle = live_before_replay.handle,
        .packet = live_before_replay.datagram,
    } };
    try link_b_to_a.dropNext();

    const deadline_ns = actor_a.requests.get(req_id.key).?.deadline_ns;
    actor_a.maintenanceAt(env_a, deadline_ns);
    try drainEffects(&actor_a, env_a, &effects_a, &sender_a);
    try std.testing.expectEqualSlices(u8, sender_a.datagrams.items[0].bytes.slice(), sender_a.datagrams.items[1].bytes.slice());
    try link_a_to_b.deliverNext();
    try std.testing.expectEqual(@as(usize, 2), sender_b.datagrams.items.len);
    try std.testing.expectEqualSlices(u8, sender_b.datagrams.items[0].bytes.slice(), sender_b.datagrams.items[1].bytes.slice());
    const live_after_replay = actor_b.sessions.peekChallenge(endpoint_a, outbound.nowNs(io)) orelse return error.ReplayRemovedChallenge;
    try std.testing.expectEqual(live_before_replay.handle, live_after_replay.handle);
    try std.testing.expectEqual(live_before_replay.triggering_nonce, live_after_replay.triggering_nonce);
    try std.testing.expectEqualSlices(u8, live_before_replay.datagram.slice(), live_after_replay.datagram.slice());
    try std.testing.expectEqual(@as(usize, 1), actor_b.sessions.challengeCount());
    try std.testing.expectEqual(permit_fingerprint, admission.IngressAdmission.Testing.permitGenerationFingerprint(&ingress_b));
    actor_b.applyEffectCompletion(.{ .io = io, .ingress = &ingress_b, .outbox = &outbox_b }, copied_replay, .sent);
    actor_b.applyEffectCompletion(.{ .io = io, .ingress = &ingress_b, .outbox = &outbox_b }, copied_replay, .failed);
    try std.testing.expectEqual(live_before_replay.handle, (actor_b.sessions.peekChallenge(endpoint_a, outbound.nowNs(io)) orelse return error.CopiedReplayMutatedChallenge).handle);
    try std.testing.expectEqual(permit_fingerprint, admission.IngressAdmission.Testing.permitGenerationFingerprint(&ingress_b));
    try std.testing.expectEqual(@as(usize, 1), ingress_b.permitCount());

    try link_b_to_a.deliverNext();
    try link_a_to_b.deliverNext();
    try std.testing.expect(replacement.called);
    try std.testing.expect(replacement.failure == null);
    try std.testing.expect(replacement.old_removed);
    const newer_handle = replacement.newer_handle orelse return error.MissingReplacementChallenge;
    try std.testing.expect(newer_handle.generation != live_before_replay.handle.generation);
    try std.testing.expect(!std.mem.eql(u8, &replacement.publication.challenge_data, &live_before_replay.challenge_data));
    try std.testing.expect(!std.mem.eql(u8, &replacement.publication.triggering_nonce, &live_before_replay.triggering_nonce));
    try std.testing.expect(!std.mem.eql(u8, replacement_packet.slice(), live_before_replay.datagram.slice()));
    try std.testing.expect(replacement.permit_fingerprint != permit_fingerprint);
    const newer = actor_b.sessions.peekChallenge(endpoint_a, outbound.nowNs(io)) orelse return error.ReplacementChallengeRemoved;
    try std.testing.expectEqual(newer_handle, newer.handle);
    try std.testing.expectEqual(replacement.publication.challenge_data, newer.challenge_data);
    try std.testing.expectEqual(replacement.publication.triggering_nonce, newer.triggering_nonce);
    try std.testing.expectEqualSlices(u8, replacement_packet.slice(), newer.datagram.slice());
    try std.testing.expectEqual(replacement.challenge_fingerprint, session_book.SessionBook.Testing.challengeGenerationFingerprint(&actor_b.sessions));
    const authenticated_session = actor_b.sessions.get(endpoint_a, outbound.nowNs(io)) orelse return error.HandshakeNotAuthenticated;
    try std.testing.expect(authenticated_session.seen_nonces.contains(&live_before_replay.triggering_nonce));
    try std.testing.expectEqual(@as(u64, 1), actor_b.metrics.rcvd_message_count[metrics.MessageType.ping.index()]);
    try std.testing.expectEqual(@as(usize, 2), ingress_b.permitCount());
    const authenticated_permit_fingerprint = admission.IngressAdmission.Testing.permitGenerationFingerprint(&ingress_b);
    try std.testing.expect(authenticated_permit_fingerprint != replacement.permit_fingerprint);
    try std.testing.expect(!actor_b.sessions.removeChallenge(live_before_replay.handle, &ingress_b));
    actor_b.applyEffectCompletion(.{ .io = io, .ingress = &ingress_b, .outbox = &outbox_b }, copied_replay, .sent);
    actor_b.applyEffectCompletion(.{ .io = io, .ingress = &ingress_b, .outbox = &outbox_b }, copied_replay, .failed);
    try std.testing.expectEqual(newer_handle, (actor_b.sessions.peekChallenge(endpoint_a, outbound.nowNs(io)) orelse return error.CopiedReplayRemovedReplacement).handle);
    try link_b_to_a.deliverNext();
    try std.testing.expectEqual(@as(usize, 0), actor_a.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 0), ingress_a.permitCount());
    try std.testing.expectEqual(@as(usize, 2), ingress_b.permitCount());
    actor_b.responses.prune(std.math.maxInt(i64), &ingress_b);
    try std.testing.expectEqual(@as(usize, 1), ingress_b.permitCount());
    try std.testing.expectEqual(authenticated_permit_fingerprint, admission.IngressAdmission.Testing.permitGenerationFingerprint(&ingress_b));
    try std.testing.expectEqual(newer_handle, (actor_b.sessions.peekChallenge(endpoint_a, outbound.nowNs(io)) orelse return error.ReplacementNotOwned).handle);
    try std.testing.expect(actor_b.sessions.removeChallenge(newer_handle, &ingress_b));
    try std.testing.expectEqual(@as(usize, 0), ingress_b.permitCount());
    try std.testing.expectEqual(authenticated_permit_fingerprint, admission.IngressAdmission.Testing.permitGenerationFingerprint(&ingress_b));
    try std.testing.expectEqual(@as(usize, 0), actor_b.sessions.challengePhaseCount());
    try std.testing.expect(outbox_a.pop() == null);
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
        .rate_limiter = null,
        .limits = limits,
    };
    const config_b = config.Config{
        .bind_addresses = .{ .ip4 = address_b },
        .local_key_pair = key_b,
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
    var effect_storage_a: [2]actor_mod.ActorEffect = undefined;
    var effects_a = actor_mod.EffectQueue.init(&effect_storage_a);
    const env_a = actor_mod.Env{ .io = io, .ingress = &ingress_a, .outbox = &outbox_a, .effects = &effects_a };
    var link_a_to_b = PacketLink.init(&sender_a, address_b, address_a, &actor_b, .{ .io = io, .ingress = &ingress_b, .outbox = &outbox_b }, &sender_b);
    var link_b_to_a = PacketLink.init(&sender_b, address_a, address_b, &actor_a, env_a, &sender_a);
    const now_ns = outbound.nowNs(io);
    try std.testing.expect(actor_a.addNode(id_b, &pubkey_b, address_b, null, now_ns));
    try std.testing.expect(actor_b.addNode(id_a, &pubkey_a, address_a, null, now_ns));
    const a_to_b = [_]u8{0xa2} ** 16;
    const b_to_a = [_]u8{0xb2} ** 16;
    actor_a.sessions.put(endpoint_b, .{ .initiator_key = a_to_b, .recipient_key = b_to_a }, now_ns);
    actor_b.sessions.put(endpoint_a, .{ .initiator_key = b_to_a, .recipient_key = a_to_b }, now_ns);

    _ = try actor_mod.Testing.sendPingResolvedForTest(
        &actor_a,
        env_a,
        endpoint_b,
        &pubkey_b,
        .api,
    );
    try drainEffects(&actor_a, env_a, &effects_a, &sender_a);
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
        .{ .io = io, .ingress = &ingress_b, .outbox = &outbox_b },
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
        .{ .io = io, .ingress = &ingress_b, .outbox = &outbox_b },
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
    try std.testing.expect(outbox_a.pop() == null);

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
        .{ .io = io, .ingress = &ingress_b, .outbox = &outbox_b },
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
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x54} ** 32));
    const remote_pubkey = secp.compressedPubkey(&remote_key);
    const endpoint = types.Endpoint{
        .node_id = try enr.nodeIdFromCompressedPubkey(&remote_pubkey),
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 7 }, .port = 9007 } },
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
    actor.sessions.put(endpoint, .{ .initiator_key = [_]u8{3} ** 16, .recipient_key = [_]u8{4} ** 16 }, outbound.nowNs(io));
    const req_id = try actor_mod.Testing.sendPingResolvedForTest(&actor, harness.env(), endpoint, &remote_pubkey, .api);
    try harness.drainEffects();
    var initial = harness.recording.datagrams.items[0].bytes;
    const initial_nonce = (try packet.decode(initial.bytes[0..initial.len], &endpoint.node_id)).static_header.nonce;

    harness.recording.fail_next = true;
    const deadline_ns = actor.requests.get(req_id.key).?.deadline_ns;
    actor.maintenanceAt(harness.env(), deadline_ns);
    harness.drainEffectsIgnoringFailures();
    try std.testing.expectEqual(@as(u64, 1), actor.metrics.sent_message_count[metrics.MessageType.ping.index()]);
    try std.testing.expectEqual(@as(usize, 1), harness.recording.datagrams.items.len);
    const active = actor.requests.get(req_id.key) orelse return error.MissingRequestAfterRetryFailure;
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
        if (peer_store.logDistance(&local_id, &remote_id) != 255) continue;
        const address = types.Address{ .ip4 = .{
            .bytes = .{ 127, 0, 0, @as(u8, @intCast(candidate)) },
            .port = @as(u16, @intCast(10_000 + candidate)),
        } };
        const peer_ref = try actor.peers.remember(remote_id, &remote_pubkey, address, false);
        try std.testing.expect((try actor.peers.admitRoute(peer_ref, true, 0)).inserted);
        peer_ids[peer_count] = remote_id;
        peer_addresses[peer_count] = address;
        peer_count += 1;
        if (peer_count == peer_ids.len) break;
    }
    try std.testing.expectEqual(peer_ids.len, peer_count);

    try actor.setLocalEnr(harness.env(), replacement_enr);
    try harness.drainEffects();
    try std.testing.expectEqual(peer_ids.len, harness.recording.datagrams.items.len);
    try std.testing.expectEqual(peer_ids.len, actor.requests.activeCount());
    try std.testing.expectEqual(peer_ids.len, harness.ingress.permitCount());
    for (peer_ids, peer_addresses) |peer_id, address| {
        try std.testing.expect(actor.peers.healthRequest(&peer_id) != null);
        var address_count: usize = 0;
        for (harness.recording.datagrams.items) |datagram| {
            if (datagram.address.eql(&address)) address_count += 1;
        }
        try std.testing.expectEqual(@as(usize, 1), address_count);
    }
}

test "maintenance schedules the next health probe only after a successful send" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x59} ** 32));
    const local_address = types.Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 9059 } };
    const cfg = config.Config{
        .bind_addresses = .{ .ip4 = local_address },
        .local_key_pair = local_key,
        .ping_interval_ms = 60_000,
        .rate_limiter = null,
        .limits = .{ .max_active_requests = 2, .max_queued_requests = 2, .event_capacity = 4, .command_capacity = 2 },
    };
    var harness = try ActorHarness.init(alloc, io, cfg);
    defer harness.deinit();
    const actor = &harness.actor;

    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x5a} ** 32));
    const remote_pubkey = secp.compressedPubkey(&remote_key);
    const remote_id = try enr.nodeIdFromCompressedPubkey(&remote_pubkey);
    const remote_address = types.Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 90 }, .port = 10_059 } };
    const remote_ref = try actor.peers.remember(remote_id, &remote_pubkey, remote_address, false);
    try std.testing.expect((try actor.peers.admitRoute(remote_ref, true, outbound.nowNs(io))).inserted);

    harness.recording.fail_next = true;
    actor.maintenance(harness.env());
    try std.testing.expectError(error.TransportSendFailed, harness.drainEffects());
    try std.testing.expectEqual(@as(usize, 0), harness.recording.datagrams.items.len);
    try std.testing.expectEqual(@as(usize, 0), actor.requests.activeCount());
    try std.testing.expect(actor.peers.healthRequest(&remote_id) == null);

    actor.maintenance(harness.env());
    try harness.drainEffects();
    try std.testing.expectEqual(@as(usize, 1), harness.recording.datagrams.items.len);
    const health_request = actor.peers.healthRequest(&remote_id) orelse
        return error.MissingHealthRequest;
    const health_handle = actor.requests.handleFor(health_request) orelse return error.MissingHealthRequestHandle;
    try std.testing.expect(actor.cancelRequest(harness.env(), health_handle));

    actor.maintenance(harness.env());
    try harness.drainEffects();
    try std.testing.expectEqual(@as(usize, 1), harness.recording.datagrams.items.len);
    try std.testing.expectEqual(@as(usize, 0), actor.requests.activeCount());
    try std.testing.expect(actor.peers.healthRequest(&remote_id) == null);
}

test "NODES total is exact bounded consistent and controls final permit release" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x47} ** 32));
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
        .rate_limiter = null,
        .limits = .{ .max_active_requests = 2, .max_queued_requests = 2, .event_capacity = 2, .command_capacity = 2 },
    };
    var harness = try ActorHarness.init(alloc, io, cfg);
    defer harness.deinit();
    const actor = &harness.actor;
    const stable = session_book.StableSession{ .initiator_key = [_]u8{3} ** 16, .recipient_key = [_]u8{4} ** 16 };
    actor.sessions.put(endpoint, stable, outbound.nowNs(io));
    const req_id = try actor_mod.Testing.sendFindNodeResolvedForTest(&actor, harness.env(), endpoint, &remote_pubkey, &.{0}, .api);
    try harness.drainEffects();
    try std.testing.expectEqual(@as(usize, 1), harness.ingress.permitCount());

    var invalid_buffer: [128]u8 = undefined;
    const invalid = message.Nodes{ .req_id = req_id.key.req_id, .total = 17, .enrs = &.{} };
    try deliverEncrypted(actor, io, harness.recording.sender(), &harness.ingress, &harness.outbox, endpoint, &stable.recipient_key, try invalid.encodeInto(&invalid_buffer), 1);
    try std.testing.expect(actor.requests.get(req_id.key).?.response.nodes.total_responses == null);
    try std.testing.expectEqual(@as(u64, 0), actor.requests.get(req_id.key).?.response.nodes.responses_received);
    try std.testing.expectEqual(@as(usize, 1), actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 1), harness.ingress.permitCount());

    var nodes_buffer: [128]u8 = undefined;
    const nodes = message.Nodes{ .req_id = req_id.key.req_id, .total = 10, .enrs = &.{} };
    const plaintext = try nodes.encodeInto(&nodes_buffer);
    try deliverEncrypted(actor, io, harness.recording.sender(), &harness.ingress, &harness.outbox, endpoint, &stable.recipient_key, plaintext, 2);
    try std.testing.expectEqual(@as(u64, 10), actor.requests.get(req_id.key).?.response.nodes.total_responses.?);
    try std.testing.expectEqual(@as(u64, 1), actor.requests.get(req_id.key).?.response.nodes.responses_received);

    var inconsistent_buffer: [128]u8 = undefined;
    const inconsistent = message.Nodes{ .req_id = req_id.key.req_id, .total = 9, .enrs = &.{} };
    try deliverEncrypted(actor, io, harness.recording.sender(), &harness.ingress, &harness.outbox, endpoint, &stable.recipient_key, try inconsistent.encodeInto(&inconsistent_buffer), 3);
    try std.testing.expectEqual(@as(u64, 1), actor.requests.get(req_id.key).?.response.nodes.responses_received);

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
    try std.testing.expectEqual(@as(u64, 6), actor.requests.get(req_id.key).?.response.nodes.responses_received);
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
    try std.testing.expect(harness.outbox.pop() == null);
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
    const now_ns = outbound.nowNs(io);
    actor.sessions.put(endpoint, stable, now_ns);

    const req_a = try actor_mod.Testing.sendPingResolvedForTest(&actor, harness.env(), endpoint, &remote_pubkey, .api);
    try harness.drainEffects();
    const req_b = try actor_mod.Testing.sendPingResolvedForTest(&actor, harness.env(), endpoint, &remote_pubkey, .api);
    try harness.drainEffects();
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
    harness.drainEffectsIgnoringFailures();
    try std.testing.expectEqual(@as(usize, 3), harness.recording.datagrams.items.len);
    actor.handlePacket(harness.env(), first, address);
    harness.drainEffectsIgnoringFailures();
    try std.testing.expectEqual(@as(usize, 3), harness.recording.datagrams.items.len);
    actor.handlePacket(harness.env(), second, address);
    harness.drainEffectsIgnoringFailures();
    try std.testing.expectEqual(@as(usize, 3), harness.recording.datagrams.items.len);
    const retained = actor.sessions.get(endpoint, now_ns) orelse return error.MissingStableSession;
    try std.testing.expectEqual(stable.initiator_key, retained.initiator_key);
    try std.testing.expectEqual(stable.recipient_key, retained.recipient_key);
    try std.testing.expect(actor.requests.get(req_a.key) != null);
    try std.testing.expect(actor.requests.get(req_b.key) != null);
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
        .rate_limiter = null,
        .limits = .{ .max_active_requests = 2, .max_queued_requests = 2, .event_capacity = 2, .command_capacity = 2 },
    };
    var harness = try ActorHarness.init(alloc, io, cfg);
    defer harness.deinit();
    const actor = &harness.actor;
    const req_id = try actor_mod.Testing.sendPingResolvedForTest(&actor, harness.env(), endpoint, &remote_pubkey, .api);
    try harness.drainEffects();
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
    harness.drainEffectsIgnoringFailures();

    try std.testing.expectEqual(@as(usize, 1), harness.recording.datagrams.items.len);
    try std.testing.expectEqual(@as(usize, 1), harness.ingress.permitCount());
    try std.testing.expect(actor.requests.hasChallenge(&request_nonce, endpoint.addr));
    try std.testing.expect(actor.requests.pendingKeys(endpoint) == null);
    const active = actor.requests.get(req_id.key) orelse return error.MissingRequestAfterSendFailure;
    try std.testing.expect(active.phase == .awaiting_whoareyou);
}

test "failed ciphertext does not refresh stable session LRU recency" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x21} ** 32));
    const cfg = config.Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
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
    harness.drainEffectsIgnoringFailures();
    try std.testing.expect(actor.sessions.peekPtr(lru_endpoint, 2) != null);

    actor.sessions.put(third_endpoint, stable, 3);
    try std.testing.expect(actor.sessions.peekPtr(lru_endpoint, 4) == null);
    try std.testing.expect(actor.sessions.peekPtr(fresh_endpoint, 4) != null);
    try std.testing.expect(actor.sessions.peekPtr(third_endpoint, 4) != null);
}

test "expired stable outbound paths recover without access-time removal" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x22} ** 32));
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x23} ** 32));
    const remote_pubkey = secp.compressedPubkey(&remote_key);
    const remote_id = try enr.nodeIdFromCompressedPubkey(&remote_pubkey);
    const endpoint = types.Endpoint{
        .node_id = remote_id,
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 44 }, .port = 9044 } },
    };
    const cfg = config.Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
        .request_timeout_ms = 1,
        .request_retries = 1,
        .session_timeout_ms = 1,
        .ping_interval_ms = 0,
        .rate_limiter = null,
        .limits = .{
            .max_active_requests = 2,
            .max_queued_requests = 2,
            .session_capacity = 1,
            .event_capacity = 2,
            .command_capacity = 2,
        },
    };
    var harness = try ActorHarness.init(alloc, io, cfg);
    defer harness.deinit();
    const actor = &harness.actor;
    const now_ns = outbound.nowNs(io);
    try std.testing.expect(actor.addNode(remote_id, &remote_pubkey, endpoint.addr, null, now_ns));
    actor.sessions.put(endpoint, .{
        .initiator_key = [_]u8{0x24} ** 16,
        .recipient_key = [_]u8{0x25} ** 16,
    }, now_ns - 2 * std.time.ns_per_ms);

    try std.testing.expectError(error.NoSession, actor.sendTalkResponse(
        harness.env(),
        endpoint,
        try message.ReqId.fromSlice(&.{1}),
        "expired",
    ));
    try std.testing.expectEqual(@as(usize, 1), actor.sessions.count());

    const req_id = try actor_mod.Testing.sendPingResolvedForTest(&actor, harness.env(), endpoint, &remote_pubkey, .api);
    try harness.drainEffects();
    try std.testing.expectEqual(@as(usize, 1), actor.sessions.count());
    const active = actor.requests.get(req_id.key) orelse return error.MissingExpiredSessionRequest;
    try std.testing.expect(active.phase == .awaiting_whoareyou);
    const deadline_ns = active.deadline_ns;
    try std.testing.expectEqual(@as(usize, 1), harness.recording.datagrams.items.len);
    const initial_probe = harness.recording.datagrams.items[0].bytes;

    actor.maintenanceAt(harness.env(), deadline_ns);
    harness.drainEffectsIgnoringFailures();
    try std.testing.expectEqual(@as(usize, 0), actor.sessions.count());
    try std.testing.expectEqual(@as(usize, 2), harness.recording.datagrams.items.len);
    try std.testing.expectEqualSlices(u8, initial_probe.slice(), harness.recording.datagrams.items[1].bytes.slice());
}

test "metrics snapshots preserve session count and recency until maintenance" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x26} ** 32));
    const cfg = config.Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
        .session_timeout_ms = 10,
        .ping_interval_ms = 0,
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
    const first = types.Endpoint{
        .node_id = [_]u8{0x27} ** 32,
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 45 }, .port = 9045 } },
    };
    const second = types.Endpoint{
        .node_id = [_]u8{0x28} ** 32,
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 46 }, .port = 9046 } },
    };
    const third = types.Endpoint{
        .node_id = [_]u8{0x29} ** 32,
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 47 }, .port = 9047 } },
    };
    const stable = session_book.StableSession{
        .initiator_key = [_]u8{0x2a} ** 16,
        .recipient_key = [_]u8{0x2b} ** 16,
    };
    actor.sessions.put(first, stable, 0);
    actor.sessions.put(second, stable, std.time.ns_per_ms);

    const inspection: *const actor_mod.Actor = actor;
    var snapshot = inspection.metricsSnapshot();
    try std.testing.expectEqual(@as(usize, 2), snapshot.active_session_count);
    try std.testing.expectEqual(@as(usize, 2), snapshot.session_capacity);
    try std.testing.expectEqual(@as(u64, 2), snapshot.session_inserted_total);
    try std.testing.expectEqual(@as(u64, 0), snapshot.session_capacity_reused_total);
    actor.sessions.put(third, stable, 2 * std.time.ns_per_ms);
    try std.testing.expect(actor.sessions.peekPtr(first, 2 * std.time.ns_per_ms) == null);
    try std.testing.expect(actor.sessions.peekPtr(second, 2 * std.time.ns_per_ms) != null);
    try std.testing.expect(actor.sessions.peekPtr(third, 2 * std.time.ns_per_ms) != null);

    snapshot = inspection.metricsSnapshot();
    try std.testing.expectEqual(@as(usize, 2), snapshot.active_session_count);
    try std.testing.expectEqual(@as(u64, 1), snapshot.session_capacity_reused_total);
    actor.maintenanceAt(harness.env(), 11 * std.time.ns_per_ms);
    harness.drainEffectsIgnoringFailures();
    snapshot = inspection.metricsSnapshot();
    try std.testing.expectEqual(@as(usize, 1), snapshot.active_session_count);
    try std.testing.expectEqual(@as(u64, 1), snapshot.session_maintenance_expired_total);
    try std.testing.expect(actor.sessions.peekPtr(second, 11 * std.time.ns_per_ms) == null);
    try std.testing.expect(actor.sessions.peekPtr(third, 11 * std.time.ns_per_ms) != null);
}

test "authenticated packets reject stale nonce and wrong source address" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x57} ** 32));
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
    harness.drainEffectsIgnoringFailures();
    try std.testing.expectEqual(@as(usize, 1), harness.recording.datagrams.items.len);
    var duplicate = replay;
    actor.handlePacket(harness.env(), duplicate.bytes[0..duplicate.len], endpoint.addr);
    harness.drainEffectsIgnoringFailures();
    try std.testing.expectEqual(@as(usize, 1), harness.recording.datagrams.items.len);

    var wrong_source = try encodeEncryptedPacket(actor, endpoint.node_id, &stable.recipient_key, plaintext, 2);
    actor.handlePacket(harness.env(), wrong_source.bytes[0..wrong_source.len], wrong_address);
    harness.drainEffectsIgnoringFailures();
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
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x5e} ** 32));
    const remote_id = try enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&remote_key));
    const endpoint = types.Endpoint{
        .node_id = remote_id,
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 22 }, .port = 9022 } },
    };
    const cfg = config.Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
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
    harness.drainEffectsIgnoringFailures();

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
        harness.drainEffectsIgnoringFailures();
    }
    try std.testing.expect(actor.sessions.peekPtr(endpoint, outbound.nowNs(io)) == null);
    try std.testing.expectEqual(@as(usize, 1), actor.sessions.challengeCount());
    try std.testing.expectEqual(@as(usize, 1), harness.ingress.permitCount());
    try std.testing.expectEqual(@as(usize, 1), harness.recording.datagrams.items.len);

    actor.handlePacket(
        harness.env(),
        original_packet.bytes[0..original_packet.len],
        endpoint.addr,
    );
    harness.drainEffectsIgnoringFailures();
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
        .rate_limiter = null,
        .limits = limits,
    };
    const config_b = config.Config{
        .bind_addresses = .{ .ip4 = address_b },
        .local_key_pair = key_b,
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
    var effect_storage_a: [2]actor_mod.ActorEffect = undefined;
    var effects_a = actor_mod.EffectQueue.init(&effect_storage_a);
    const env_a = actor_mod.Env{ .io = io, .ingress = &ingress_a, .outbox = &outbox_a, .effects = &effects_a };
    var link_a_to_b = PacketLink.init(&sender_a, address_b, address_a, &actor_b, .{ .io = io, .ingress = &ingress_b, .outbox = &outbox_b }, &sender_b);
    var link_b_to_a = PacketLink.init(&sender_b, address_a, address_b, &actor_a, env_a, &sender_a);
    try std.testing.expect(actor_a.addNode(id_b, &pubkey_b, address_b, null, outbound.nowNs(io)));
    try std.testing.expect(actor_b.addNode(id_a, &pubkey_a, address_a, null, outbound.nowNs(io)));

    _ = try actor_mod.Testing.sendPingResolvedForTest(
        &actor_a,
        env_a,
        .{ .node_id = id_b, .addr = address_b },
        &pubkey_b,
        .api,
    );
    try drainEffects(&actor_a, env_a, &effects_a, &sender_a);
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

test "stable session wins a same-read-key candidate collision" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x55} ** 32));
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x56} ** 32));
    const remote_pubkey = secp.compressedPubkey(&remote_key);
    const remote_id = try enr.nodeIdFromCompressedPubkey(&remote_pubkey);
    const endpoint = types.Endpoint{
        .node_id = remote_id,
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 19 }, .port = 9019 } },
    };
    const cfg = config.Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
        .rate_limiter = null,
        .limits = .{ .response_recovery_capacity = 2, .event_capacity = 2, .command_capacity = 2 },
    };
    var harness = try ActorHarness.init(alloc, io, cfg);
    defer harness.deinit();
    const actor = &harness.actor;
    const now_ns = outbound.nowNs(io);
    try std.testing.expect(actor.addNode(remote_id, &remote_pubkey, endpoint.addr, null, now_ns));

    const shared_read_key = [_]u8{0x82} ** 16;
    const stable = session_book.StableSession{
        .initiator_key = [_]u8{0x81} ** 16,
        .recipient_key = shared_read_key,
    };
    const candidate = @import("../state/response_book.zig").CandidateKeys{
        .initiator_key = [_]u8{0x83} ** 16,
        .recipient_key = shared_read_key,
    };
    actor.sessions.put(endpoint, stable, now_ns);
    @import("../state/response_book.zig").ResponseBook.Testing.putCandidate(&actor.responses, endpoint, candidate, now_ns);

    const talk_response = message.TalkResp{
        .req_id = try message.ReqId.fromSlice(&.{0x84}),
        .response = "stable collision proof",
    };
    var plaintext_buffer: [128]u8 = undefined;
    var encrypted = try encodeEncryptedPacket(
        actor,
        remote_id,
        &shared_read_key,
        try talk_response.encodeInto(&plaintext_buffer),
        0x85,
    );
    actor.handlePacket(harness.env(), encrypted.bytes[0..encrypted.len], endpoint.addr);
    harness.drainEffectsIgnoringFailures();

    const retained_candidate = actor.responses.candidate(endpoint, outbound.nowNs(io)) orelse return error.CandidateWasPromoted;
    try std.testing.expectEqual(candidate.initiator_key, retained_candidate.keys.initiator_key);
    const retained_stable = actor.sessions.get(endpoint, outbound.nowNs(io)) orelse return error.MissingStableSession;
    try std.testing.expectEqual(stable.initiator_key, retained_stable.initiator_key);
    try std.testing.expect(retained_stable.seen_nonces.contains(&([_]u8{0x85} ** packet.NONCE_SIZE)));
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
        .rate_limiter = null,
        .limits = .{ .max_active_requests = 2, .max_queued_requests = 2, .event_capacity = 2, .command_capacity = 2 },
    };
    var harness = try ActorHarness.init(alloc, io, cfg);
    defer harness.deinit();
    const actor = &harness.actor;
    try std.testing.expect(actor.addNode(remote_id, &remote_pubkey, endpoint.addr, null, outbound.nowNs(io)));
    const old = session_book.StableSession{ .initiator_key = [_]u8{0x71} ** 16, .recipient_key = [_]u8{0x72} ** 16 };
    actor.sessions.put(endpoint, old, outbound.nowNs(io));
    const req_id = try actor_mod.Testing.sendPingResolvedForTest(&actor, harness.env(), endpoint, &remote_pubkey, .api);
    try harness.drainEffects();
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
    harness.drainEffectsIgnoringFailures();
    const pending = actor.requests.pendingKeys(endpoint) orelse return error.MissingPendingRekey;
    try std.testing.expectEqual(@as(usize, 2), harness.recording.datagrams.items.len);

    const old_ping = message.Ping{ .req_id = try message.ReqId.fromSlice(&.{0xa1}), .enr_seq = 0 };
    var old_ping_buffer: [128]u8 = undefined;
    var old_response = try encodeEncryptedPacket(actor, remote_id, &old.recipient_key, try old_ping.encodeInto(&old_ping_buffer), 9);
    actor.handlePacket(harness.env(), old_response.bytes[0..old_response.len], endpoint.addr);
    harness.drainEffectsIgnoringFailures();
    const still_pending = actor.requests.pendingKeys(endpoint) orelse return error.PendingRekeyWasPromotedByOldKey;
    try std.testing.expect(types.RequestKeyContext.eql(.{}, pending.handle.key, still_pending.handle.key));
    try std.testing.expect(actor.requests.shouldQueue(endpoint));
    try std.testing.expectEqual(@as(usize, 1), actor.requests.activeCount());
    const still_old = actor.sessions.get(endpoint, outbound.nowNs(io)) orelse return error.MissingOldSession;
    try std.testing.expectEqual(old.initiator_key, still_old.initiator_key);
    try std.testing.expectEqual(old.recipient_key, still_old.recipient_key);
    try std.testing.expectEqual(@as(usize, 3), harness.recording.datagrams.items.len);

    const pong = message.Pong{
        .req_id = req_id.key.req_id,
        .enr_seq = 0,
        .recipient_ip = .{ .ip4 = .{ 127, 0, 0, 1 } },
        .recipient_port = 9000,
    };
    var pong_buffer: [128]u8 = undefined;
    var response = try encodeEncryptedPacket(actor, remote_id, &pending.keys.recipient_key, try pong.encodeInto(&pong_buffer), 10);
    actor.handlePacket(harness.env(), response.bytes[0..response.len], endpoint.addr);
    harness.drainEffectsIgnoringFailures();

    try std.testing.expectEqual(@as(usize, 0), actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 1), harness.ingress.permitCount());
    actor.responses.prune(std.math.maxInt(i64), &harness.ingress);
    try std.testing.expectEqual(@as(usize, 0), harness.ingress.permitCount());
    try std.testing.expect(actor.requests.pendingKeys(endpoint) == null);
    const promoted = actor.sessions.get(endpoint, outbound.nowNs(io)) orelse return error.MissingPromotedSession;
    try std.testing.expectEqual(pending.keys.initiator_key, promoted.initiator_key);
    try std.testing.expectEqual(pending.keys.recipient_key, promoted.recipient_key);
    try std.testing.expect(harness.outbox.pop() == null);
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

    _ = try actor_mod.Testing.sendPingResolvedForTest(&actor, harness.env(), endpoint, &remote_pubkey, .api);
    try harness.drainEffects();
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
    harness.drainEffectsIgnoringFailures();
    const pending = actor.requests.pendingKeys(endpoint) orelse return error.MissingPendingRekey;
    try std.testing.expectEqual(@as(usize, 2), harness.recording.datagrams.items.len);

    const second_id = try actor_mod.Testing.sendPingResolvedForTest(&actor, harness.env(), endpoint, &remote_pubkey, .api);
    const third_id = try actor_mod.Testing.sendPingResolvedForTest(&actor, harness.env(), endpoint, &remote_pubkey, .api);
    try std.testing.expectEqual(@as(usize, 2), harness.recording.datagrams.items.len);
    try std.testing.expectEqual(@as(usize, 2), actor.requests.queuedCount());

    const proof_ping = message.Ping{ .req_id = try message.ReqId.fromSlice(&.{0xa2}), .enr_seq = 0 };
    var proof_buffer: [128]u8 = undefined;
    var proof = try encodeEncryptedPacket(actor, remote_id, &pending.keys.recipient_key, try proof_ping.encodeInto(&proof_buffer), 11);
    actor.handlePacket(harness.env(), proof.bytes[0..proof.len], endpoint.addr);
    try harness.drainEffects();

    try std.testing.expect(actor.requests.pendingKeys(endpoint) == null);
    try std.testing.expectEqual(@as(usize, 0), actor.requests.queuedCount());
    try std.testing.expectEqual(@as(usize, 5), harness.recording.datagrams.items.len);
    const second_plaintext = try decryptRecorded(&harness.recording, 3, remote_id, &pending.keys.initiator_key);
    const third_plaintext = try decryptRecorded(&harness.recording, 4, remote_id, &pending.keys.initiator_key);
    const second_ping = try message.Ping.decode(second_plaintext.slice());
    const third_ping = try message.Ping.decode(third_plaintext.slice());
    try std.testing.expectEqualSlices(u8, second_id.key.req_id.slice(), second_ping.req_id.slice());
    try std.testing.expectEqualSlices(u8, third_id.key.req_id.slice(), third_ping.req_id.slice());
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
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x62} ** 32));
    const remote_pubkey = secp.compressedPubkey(&remote_key);
    const remote_id = try enr.nodeIdFromCompressedPubkey(&remote_pubkey);
    const cfg = config.Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
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

    _ = try actor_mod.Testing.sendFindNodeResolvedForTest(&actor, harness.env(), endpoint, &remote_pubkey, &.{1}, .api);
    try std.testing.expectError(error.TransportSendFailed, harness.drainEffects());
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
    try actor.sendTalkResponse(
        harness.env(),
        endpoint,
        try message.ReqId.fromSlice(&.{1}),
        "failed",
    );
    try std.testing.expectError(error.TransportSendFailed, harness.drainEffects());
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
    harness.drainEffectsIgnoringFailures();
    try std.testing.expectEqual(@as(usize, 0), actor.sessions.challengeCount());
    try std.testing.expectEqual(@as(usize, 0), harness.ingress.permitCount());
    try std.testing.expectEqual(@as(usize, 0), harness.recording.datagrams.items.len);
}

test "established session rejects 1100 byte TALK response before recovery ownership" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x6a} ** 32));
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x6b} ** 32));
    const remote_pubkey = secp.compressedPubkey(&remote_key);
    const remote_id = try enr.nodeIdFromCompressedPubkey(&remote_pubkey);
    const endpoint = types.Endpoint{
        .node_id = remote_id,
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 52 }, .port = 9252 } },
    };
    const cfg = config.Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
        .rate_limiter = null,
        .limits = .{ .response_recovery_capacity = 1, .event_capacity = 1, .command_capacity = 1 },
    };
    var harness = try ActorHarness.init(alloc, io, cfg);
    defer harness.deinit();
    const actor = &harness.actor;
    try std.testing.expect(actor.addNode(remote_id, &remote_pubkey, endpoint.addr, null, outbound.nowNs(io)));
    const stable = session_book.StableSession{
        .initiator_key = [_]u8{0xc1} ** 16,
        .recipient_key = [_]u8{0xc2} ** 16,
    };
    actor.sessions.put(endpoint, stable, outbound.nowNs(io));
    const response = [_]u8{0x5a} ** 1_100;

    try std.testing.expectError(error.MessageTooLarge, actor.sendTalkResponse(
        harness.env(),
        endpoint,
        try message.ReqId.fromSlice(&.{1}),
        &response,
    ));
    try std.testing.expectEqual(@as(usize, 0), harness.effects.count());
    try std.testing.expectEqual(@as(usize, 0), harness.recording.datagrams.items.len);
    try std.testing.expectEqual(@as(usize, 0), actor.responses.count());
    try std.testing.expectEqual(@as(usize, 0), harness.ingress.permitCount());
    const unchanged = actor.sessions.get(endpoint, outbound.nowNs(io)) orelse return error.MissingStableSession;
    try std.testing.expectEqual(stable.initiator_key, unchanged.initiator_key);
    try std.testing.expectEqual(stable.recipient_key, unchanged.recipient_key);
}

test "matched WHOAREYOU enqueue failure removes exact response recovery once" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x6c} ** 32));
    const local_id = try enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&local_key));
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x6d} ** 32));
    const remote_pubkey = secp.compressedPubkey(&remote_key);
    const remote_id = try enr.nodeIdFromCompressedPubkey(&remote_pubkey);
    const endpoint = types.Endpoint{
        .node_id = remote_id,
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 53 }, .port = 9253 } },
    };
    const cfg = config.Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
        .rate_limiter = null,
        .limits = .{ .response_recovery_capacity = 2, .event_capacity = 1, .command_capacity = 1 },
    };
    var harness = try ActorHarness.init(alloc, io, cfg);
    defer harness.deinit();
    const actor = &harness.actor;
    try std.testing.expect(actor.addNode(remote_id, &remote_pubkey, endpoint.addr, null, outbound.nowNs(io)));
    actor.sessions.put(endpoint, .{
        .initiator_key = [_]u8{0xd1} ** 16,
        .recipient_key = [_]u8{0xd2} ** 16,
    }, outbound.nowNs(io));

    try actor.sendTalkResponse(harness.env(), endpoint, try message.ReqId.fromSlice(&.{1}), "retained");
    try harness.drainEffects();
    var first_datagram = harness.recording.datagrams.items[0].bytes;
    const retained_nonce = (try packet.decode(first_datagram.bytes[0..first_datagram.len], &remote_id)).static_header.nonce;
    try std.testing.expectEqual(@as(usize, 1), actor.responses.count());
    try std.testing.expectEqual(@as(usize, 1), harness.ingress.permitCount());

    // Keep a second prepared response in a separate capacity-one effect queue so
    // the matching response handshake cannot be enqueued.
    try actor.sendTalkResponse(harness.env(), endpoint, try message.ReqId.fromSlice(&.{2}), "queue filler");
    const filler = harness.effects.pop() orelse return error.MissingFillerEffect;
    var full_storage: [1]actor_mod.ActorEffect = undefined;
    var full_effects = actor_mod.EffectQueue.init(&full_storage);
    try full_effects.push(filler);
    var full_env = harness.env();
    full_env.effects = &full_effects;
    try std.testing.expectEqual(@as(usize, 1), full_effects.count());
    try std.testing.expectEqual(@as(usize, 2), harness.ingress.permitCount());

    var challenge_buffer: [packet.WHOAREYOU_CHALLENGE_DATA_SIZE]u8 = undefined;
    _ = try packet.encodeWhoareyouPacketInto(&challenge_buffer, .{
        .masking_iv = &([_]u8{0xde} ** packet.MASKING_IV_SIZE),
        .recipient_node_id = &local_id,
        .request_nonce = &retained_nonce,
        .id_nonce = &([_]u8{0xdf} ** packet.ID_NONCE_SIZE),
        .enr_seq = 0,
    }, null);
    const replay = challenge_buffer;
    actor.handlePacket(full_env, &challenge_buffer, endpoint.addr);
    // The rejected handshake terminalized its exact recovery. The queue filler
    // remains canonical in `.sending_response` until its own completion.
    try std.testing.expectEqual(@as(usize, 1), actor.responses.count());
    try std.testing.expectEqual(@as(usize, 1), harness.ingress.permitCount());
    try std.testing.expectEqual(@as(usize, 1), full_effects.count());
    try std.testing.expect(full_effects.storage[full_effects.head] == .response);

    var duplicate = replay;
    actor.handlePacket(full_env, &duplicate, endpoint.addr);
    try std.testing.expectEqual(@as(usize, 1), actor.responses.count());
    try std.testing.expectEqual(@as(usize, 1), harness.ingress.permitCount());
    try std.testing.expectEqual(@as(usize, 1), full_effects.count());

    const retained_filler = full_effects.pop() orelse return error.MissingFillerEffect;
    actor.applyEffectCompletion(full_env, retained_filler, .failed);
    try std.testing.expectEqual(@as(usize, 0), actor.responses.count());
    try std.testing.expectEqual(@as(usize, 0), harness.ingress.permitCount());
}

test "copied initial response completion commits metrics and ownership once" {
    const io = std.Options.debug_io;
    const endpoint = responseCompletionEndpoint(0x61);
    var harness = try ActorHarness.init(std.testing.allocator, io, responseCompletionConfig(try secp.keyPairFromSecret(&([_]u8{0x60} ** 32))));
    defer harness.deinit();
    const effect = try retainInitialResponse(&harness, endpoint, 0x62);

    harness.actor.applyEffectCompletion(harness.env(), effect, .sent);
    try expectInitialResponseState(&harness, effect.response.handle, 1, 1);

    harness.actor.applyEffectCompletion(harness.env(), effect, .sent);
    try expectInitialResponseState(&harness, effect.response.handle, 1, 1);
}

test "failed initial response makes copied stale success harmless" {
    const io = std.Options.debug_io;
    const endpoint = responseCompletionEndpoint(0x64);
    var harness = try ActorHarness.init(std.testing.allocator, io, responseCompletionConfig(try secp.keyPairFromSecret(&([_]u8{0x63} ** 32))));
    defer harness.deinit();
    const stable = session_book.StableSession{
        .initiator_key = [_]u8{0xd1} ** 16,
        .recipient_key = [_]u8{0xd2} ** 16,
    };
    harness.actor.sessions.put(endpoint, stable, 0);
    const effect = try retainInitialResponse(&harness, endpoint, 0x65);

    harness.actor.applyEffectCompletion(harness.env(), effect, .failed);
    harness.actor.applyEffectCompletion(harness.env(), effect, .sent);
    try std.testing.expectEqual(@as(usize, 0), harness.actor.responses.count());
    try std.testing.expectEqual(@as(usize, 0), harness.ingress.permitCount());
    try std.testing.expectEqual(@as(u64, 0), harness.actor.metrics.sent_message_count[metrics.MessageType.talkresp.index()]);
    const unchanged = harness.actor.sessions.get(endpoint, 0) orelse return error.MissingStableSession;
    try std.testing.expectEqual(stable.initiator_key, unchanged.initiator_key);
    try std.testing.expectEqual(stable.recipient_key, unchanged.recipient_key);
}

test "reused endpoint nonce rejects old initial success at Actor completion boundary" {
    const io = std.Options.debug_io;
    const endpoint = responseCompletionEndpoint(0x67);
    var harness = try ActorHarness.init(std.testing.allocator, io, responseCompletionConfig(try secp.keyPairFromSecret(&([_]u8{0x66} ** 32))));
    defer harness.deinit();
    const stale = try retainInitialResponse(&harness, endpoint, 0x68);
    harness.actor.applyEffectCompletion(harness.env(), stale, .failed);
    const current = try retainInitialResponse(&harness, endpoint, 0x68);
    try std.testing.expect(stale.response.handle.generation != current.response.handle.generation);

    harness.actor.applyEffectCompletion(harness.env(), stale, .sent);
    try std.testing.expectEqual(@as(usize, 1), harness.actor.responses.phaseCount());
    try std.testing.expectEqual(@as(usize, 1), harness.ingress.permitCount());
    try std.testing.expectEqual(@as(u64, 0), harness.actor.metrics.sent_message_count[metrics.MessageType.talkresp.index()]);

    harness.actor.applyEffectCompletion(harness.env(), current, .sent);
    try expectInitialResponseState(&harness, current.response.handle, 1, 1);
}

test "duplicate successful response handshake completion is a stale no-op" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const endpoint = responseCompletionEndpoint(0x71);
    var harness = try ActorHarness.init(alloc, io, responseCompletionConfig(try secp.keyPairFromSecret(&([_]u8{0x70} ** 32))));
    defer harness.deinit();
    const stable = session_book.StableSession{
        .initiator_key = [_]u8{0xa1} ** 16,
        .recipient_key = [_]u8{0xa2} ** 16,
    };
    harness.actor.sessions.put(endpoint, stable, 0);
    const effect = try retainResponseHandshake(&harness, endpoint, 0x73, 0xb1);

    harness.actor.applyEffectCompletion(harness.env(), effect, .sent);
    try expectResponseCompletionState(&harness, endpoint, 0xb1, stable, 0, 1);

    harness.actor.applyEffectCompletion(harness.env(), effect, .sent);
    try expectResponseCompletionState(&harness, endpoint, 0xb1, stable, 0, 1);
}

test "failed response handshake cleanup makes stale success a no-op" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const endpoint = responseCompletionEndpoint(0x75);
    var harness = try ActorHarness.init(alloc, io, responseCompletionConfig(try secp.keyPairFromSecret(&([_]u8{0x74} ** 32))));
    defer harness.deinit();
    const stable = session_book.StableSession{
        .initiator_key = [_]u8{0xa3} ** 16,
        .recipient_key = [_]u8{0xa4} ** 16,
    };
    harness.actor.sessions.put(endpoint, stable, 0);
    const effect = try retainResponseHandshake(&harness, endpoint, 0x76, 0xb2);

    harness.actor.applyEffectCompletion(harness.env(), effect, .failed);
    try std.testing.expectEqual(@as(usize, 0), harness.ingress.permitCount());
    try std.testing.expect(harness.actor.responses.candidate(endpoint, 0) == null);

    harness.actor.applyEffectCompletion(harness.env(), effect, .sent);
    try std.testing.expectEqual(@as(usize, 0), harness.ingress.permitCount());
    try std.testing.expect(harness.actor.responses.candidate(endpoint, 0) == null);
    try std.testing.expectEqual(@as(u64, 0), harness.actor.metrics.sent_message_count[metrics.MessageType.talkresp.index()]);
    const unchanged = harness.actor.sessions.get(endpoint, 0) orelse return error.MissingStableSession;
    try std.testing.expectEqual(stable.initiator_key, unchanged.initiator_key);
    try std.testing.expectEqual(stable.recipient_key, unchanged.recipient_key);
}

test "stale response handshake success preserves reused nonce generation" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const endpoint = responseCompletionEndpoint(0x78);
    var harness = try ActorHarness.init(alloc, io, responseCompletionConfig(try secp.keyPairFromSecret(&([_]u8{0x77} ** 32))));
    defer harness.deinit();
    const stable = session_book.StableSession{
        .initiator_key = [_]u8{0xa5} ** 16,
        .recipient_key = [_]u8{0xa6} ** 16,
    };
    harness.actor.sessions.put(endpoint, stable, 0);
    const stale = try retainResponseHandshake(&harness, endpoint, 0x79, 0xb3);
    harness.actor.applyEffectCompletion(harness.env(), stale, .failed);
    const current = try retainResponseHandshake(&harness, endpoint, 0x79, 0xb4);
    try std.testing.expectEqual(@as(usize, 1), harness.ingress.permitCount());

    harness.actor.applyEffectCompletion(harness.env(), stale, .sent);
    try std.testing.expectEqual(@as(usize, 1), harness.ingress.permitCount());
    try std.testing.expect(harness.actor.responses.candidate(endpoint, 0) == null);
    try std.testing.expect(harness.actor.responses.hasLive(endpoint.addr, &([_]u8{0x79} ** packet.NONCE_SIZE), 0));
    try std.testing.expectEqual(@as(u64, 0), harness.actor.metrics.sent_message_count[metrics.MessageType.talkresp.index()]);
    const unchanged = harness.actor.sessions.get(endpoint, 0) orelse return error.MissingStableSession;
    try std.testing.expectEqual(stable.initiator_key, unchanged.initiator_key);
    try std.testing.expectEqual(stable.recipient_key, unchanged.recipient_key);

    harness.actor.applyEffectCompletion(harness.env(), current, .sent);
    try expectResponseCompletionState(&harness, endpoint, 0xb4, stable, 0, 1);
}

fn responseCompletionConfig(local_key: secp.KeyPair) config.Config {
    return .{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
        .rate_limiter = null,
        .limits = .{ .response_recovery_capacity = 2, .event_capacity = 1, .command_capacity = 1 },
    };
}

fn responseCompletionEndpoint(byte: u8) types.Endpoint {
    return .{
        .node_id = [_]u8{byte} ** 32,
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, byte }, .port = 9_300 + @as(u16, byte) } },
    };
}

fn retainInitialResponse(harness: *ActorHarness, endpoint: types.Endpoint, nonce_byte: u8) !actor_mod.ActorEffect {
    var permit = try harness.ingress.acquire(endpoint.addr, admission.RESPONSE_RECOVERY_PACKET_BUDGET);
    errdefer permit.release(&harness.ingress);
    const now_ns = outbound.nowNs(harness.io);
    const handle = try harness.actor.responses.beginResponse(.{
        .endpoint = endpoint,
        .nonce = [_]u8{nonce_byte} ** packet.NONCE_SIZE,
        .dest_pubkey = [_]u8{nonce_byte} ** 33,
        .plaintext = try .init(&.{message.MSG_TALKRESP}),
    }, &permit, now_ns);
    return .{ .response = .{ .handle = handle, .packet = try .init(&.{}) } };
}

fn expectInitialResponseState(
    harness: *ActorHarness,
    handle: @import("../state/response_book.zig").ResponseHandle,
    expected_permits: usize,
    expected_sent: u64,
) !void {
    const nonce = handle.nonce;
    const view = harness.actor.responses.challenge(handle.endpoint.addr, &nonce, outbound.nowNs(harness.io), &harness.ingress) orelse return error.MissingRecovery;
    try std.testing.expectEqual(handle.generation, view.handle.generation);
    try std.testing.expectEqual(expected_permits, harness.ingress.permitCount());
    try std.testing.expectEqual(expected_sent, harness.actor.metrics.sent_message_count[metrics.MessageType.talkresp.index()]);
}

fn retainResponseHandshake(harness: *ActorHarness, endpoint: types.Endpoint, nonce_byte: u8, key_byte: u8) !actor_mod.ActorEffect {
    var permit = try harness.ingress.acquire(endpoint.addr, admission.RESPONSE_RECOVERY_PACKET_BUDGET);
    errdefer permit.release(&harness.ingress);
    const nonce = [_]u8{nonce_byte} ** packet.NONCE_SIZE;
    const response = try harness.actor.responses.beginResponse(.{
        .endpoint = endpoint,
        .nonce = nonce,
        .dest_pubkey = [_]u8{nonce_byte} ** 33,
        .plaintext = try .init(&.{message.MSG_TALKRESP}),
    }, &permit, 0);
    if (!harness.actor.responses.completeResponseSend(response, .sent, &harness.ingress)) return error.StaleResponse;
    const view = harness.actor.responses.challenge(endpoint.addr, &nonce, 0, &harness.ingress) orelse return error.MissingRecovery;
    const handle = try harness.actor.responses.beginHandshake(view, .{
        .initiator_key = [_]u8{key_byte} ** 16,
        .recipient_key = [_]u8{key_byte + 1} ** 16,
    }, 0);
    return .{ .handshake = .{ .response = .{
        .handle = handle,
        .packet = try .init(&.{}),
    } } };
}

fn expectResponseCompletionState(
    harness: *ActorHarness,
    endpoint: types.Endpoint,
    key_byte: u8,
    stable: session_book.StableSession,
    expected_permits: usize,
    expected_sent: u64,
) !void {
    try std.testing.expectEqual(expected_permits, harness.ingress.permitCount());
    const candidate = harness.actor.responses.candidate(endpoint, 0) orelse return error.MissingCandidate;
    try std.testing.expectEqual([_]u8{key_byte} ** 16, candidate.keys.initiator_key);
    try std.testing.expectEqual([_]u8{key_byte + 1} ** 16, candidate.keys.recipient_key);
    try std.testing.expectEqual(expected_sent, harness.actor.metrics.sent_message_count[metrics.MessageType.talkresp.index()]);
    const unchanged = harness.actor.sessions.get(endpoint, 0) orelse return error.MissingStableSession;
    try std.testing.expectEqual(stable.initiator_key, unchanged.initiator_key);
    try std.testing.expectEqual(stable.recipient_key, unchanged.recipient_key);
}

test "transactional capacity-one challenge replacement send failure preserves original" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x2c} ** 32));
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
    harness.drainEffectsIgnoringFailures();
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
    harness.drainEffectsIgnoringFailures();
    try std.testing.expect(actor.sessions.peekChallenge(endpoint_a, outbound.nowNs(io)) != null);
    try std.testing.expect(actor.sessions.peekChallenge(endpoint_b, outbound.nowNs(io)) == null);
    try std.testing.expectEqual(@as(usize, 1), actor.sessions.challengeCount());
    try std.testing.expectEqual(@as(usize, 1), harness.ingress.permitCount());
}

test "transactional capacity-one response replacement send failure preserves original" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x2f} ** 32));
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
    try harness.drainEffects();
    var sent = harness.recording.datagrams.items[0].bytes;
    const first_nonce = (try packet.decode(sent.bytes[0..sent.len], &remote_id_a)).static_header.nonce;
    try std.testing.expect(actor.responses.hasLive(endpoint_a.addr, &first_nonce, outbound.nowNs(io)));
    try std.testing.expectEqual(@as(usize, 1), actor.responses.count());
    try std.testing.expectEqual(@as(usize, 1), harness.ingress.permitCount());

    harness.recording.fail_next = true;
    try actor.sendTalkResponse(
        harness.env(),
        endpoint_b,
        try message.ReqId.fromSlice(&.{2}),
        "second",
    );
    try std.testing.expectError(error.TransportSendFailed, harness.drainEffects());
    try std.testing.expect(actor.responses.hasLive(endpoint_a.addr, &first_nonce, outbound.nowNs(io)));
    try std.testing.expectEqual(@as(usize, 1), actor.responses.count());
    try std.testing.expectEqual(@as(usize, 1), harness.ingress.permitCount());
}
