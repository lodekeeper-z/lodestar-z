const std = @import("std");
const actor_mod = @import("../actor.zig");
const admission = @import("../admission.zig");
const config = @import("../config.zig");
const enr = @import("../enr.zig");
const events = @import("../events.zig");
const outbound = @import("../flow/outbound.zig");
const handshake = @import("../protocol/handshake.zig");
const message = @import("../protocol/message.zig");
const packet = @import("../protocol/packet.zig");
const request_results = @import("../request_results.zig");
const session_crypto = @import("../protocol/session.zig");
const secp = @import("../secp256k1.zig");
const types = @import("../types.zig");
const PacketLink = @import("../test_support/packet_link.zig").PacketLink;
const RecordingSender = @import("../test_support/recording_sender.zig").RecordingSender;

fn expectNoEvent(outbox: *events.EventOutbox, alloc: std.mem.Allocator) !void {
    var event = outbox.pop() orelse return;
    defer event.deinit(alloc);
    return error.UnexpectedEvent;
}

fn drainRequestEffects(
    actor: *actor_mod.Actor,
    env: actor_mod.Env,
    effects: *actor_mod.RequestEffectQueue,
    sender: *RecordingSender,
) !void {
    while (effects.pop()) |effect| {
        sender.sender().send(effect.destination(), effect.packetBytes()) catch |err| {
            actor.applySendCompletion(env, effect, .failed);
            return err;
        };
        actor.applySendCompletion(env, effect, .sent);
    }
}

const ReliableRequestCleanup = struct {
    actor: *actor_mod.Actor,
    env: actor_mod.Env,
    results: *request_results.RequestResultOutbox,
    key: ?types.RequestKey = null,
    state: enum { unclaimed, claimed, consumed } = .unclaimed,

    fn claim(self: *ReliableRequestCleanup, key: types.RequestKey) void {
        if (!self.results.claim()) unreachable;
        self.key = key;
        self.state = .claimed;
    }

    fn consume(self: *ReliableRequestCleanup) void {
        std.debug.assert(self.state == .claimed);
        self.state = .consumed;
    }

    fn deinit(self: *ReliableRequestCleanup) void {
        switch (self.state) {
            .unclaimed => self.results.cancelUnclaimed(),
            .consumed => {},
            .claimed => {
                const key = self.key.?;
                if (self.actor.requests.get(key) != null) {
                    if (!self.actor.cancelRequest(self.env, key)) unreachable;
                }
                if (self.results.pop() != null) return;
                std.debug.assert(self.actor.requests.get(key) == null);
                self.results.release();
            },
        }
    }
};

test "WHOAREYOU permit admits a valid HANDSHAKE through an exhausted source quota" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const key_a = try secp.keyPairFromSecret(&([_]u8{0x91} ** 32));
    const pubkey_a = secp.compressedPubkey(&key_a);
    const id_a = try enr.nodeIdFromCompressedPubkey(&pubkey_a);
    const key_b = try secp.keyPairFromSecret(&([_]u8{0x92} ** 32));
    const pubkey_b = secp.compressedPubkey(&key_b);
    const id_b = try enr.nodeIdFromCompressedPubkey(&pubkey_b);
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
        .rate_limiter = null,
        .limits = limits,
    };
    const config_b = config.Config{
        .bind_addresses = .{ .ip4 = address_b },
        .local_key_pair = key_b,
        .rate_limiter = .{
            .global_quota = .{ .replenish_all_every_ms = 1_000, .max_tokens = 8 },
            .by_ip_quota = .{ .replenish_all_every_ms = 1_000, .max_tokens = 1 },
        },
        .limits = limits,
    };
    var ingress_a = try admission.IngressAdmission.init(alloc, config_b.rate_limiter, try admission.permitCapacity(limits));
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
    var sender_a = RecordingSender.init(alloc);
    defer sender_a.deinit();
    var sender_b = RecordingSender.init(alloc);
    defer sender_b.deinit();
    var link_a_to_b = PacketLink.init(&sender_a, address_b, address_a, &actor_b, .{ .io = io, .sender = sender_b.sender(), .ingress = &ingress_b, .outbox = &outbox_b });
    var link_b_to_a = PacketLink.init(&sender_b, address_a, address_b, &actor_a, .{ .io = io, .sender = sender_a.sender(), .ingress = &ingress_a, .outbox = &outbox_a });
    const now_ns = outbound.nowNs(io);
    try std.testing.expect(actor_a.addNode(id_b, &pubkey_b, address_b, null, now_ns));
    try std.testing.expect(actor_b.addNode(id_a, &pubkey_a, address_a, null, now_ns));

    try std.testing.expect(ingress_a.acceptForTesting(address_b, 0));
    try std.testing.expect(ingress_b.acceptForTesting(address_a, 0));
    const same_ip_other_port = types.Address{ .ip4 = .{ .bytes = address_a.ip4.bytes, .port = address_a.ip4.port + 1 } };
    try std.testing.expect(!ingress_b.acceptForTesting(same_ip_other_port, 0));

    _ = try actor_a.sendTalkRequest(
        .{ .io = io, .sender = sender_a.sender(), .ingress = &ingress_a, .outbox = &outbox_a },
        .{ .node_id = id_b, .addr = address_b },
        &pubkey_b,
        "permit",
        "handshake",
    );
    try link_a_to_b.deliverNext();
    try std.testing.expectEqual(@as(usize, 1), ingress_b.permitCount());
    const challenge_admission = ingress_a.admit(address_b, 1);
    var challenge_credit = switch (challenge_admission) {
        .expected => |value| value,
        else => return error.MissingChallengeCredit,
    };
    defer challenge_credit.rollback(&ingress_a);
    try link_b_to_a.deliverNextExpected(&challenge_credit);
    try std.testing.expect(!challenge_credit.armed);
    const handshake_admission = ingress_b.admit(address_a, 1);
    var handshake_credit = switch (handshake_admission) {
        .expected => |value| value,
        else => return error.MissingHandshakeCredit,
    };
    defer handshake_credit.rollback(&ingress_b);
    try link_a_to_b.deliverNextExpected(&handshake_credit);
    try std.testing.expect(!handshake_credit.armed);

    try std.testing.expect(actor_b.sessions.get(.{ .node_id = id_a, .addr = address_a }, outbound.nowNs(io)) != null);
    try std.testing.expectEqual(@as(usize, 0), ingress_b.permitCount());
}

test "paired Actors complete handshake PING and TALK request response flows" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const key_a = try secp.keyPairFromSecret(&([_]u8{0x78} ** 32));
    const pubkey_a = secp.compressedPubkey(&key_a);
    const id_a = try enr.nodeIdFromCompressedPubkey(&pubkey_a);
    const key_b = try secp.keyPairFromSecret(&([_]u8{0x79} ** 32));
    const pubkey_b = secp.compressedPubkey(&key_b);
    const id_b = try enr.nodeIdFromCompressedPubkey(&pubkey_b);
    const address_a = @import("../types.zig").Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 9201 } };
    const address_b = @import("../types.zig").Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 9202 } };
    const limits = config.Limits{ .max_active_requests = 4, .max_queued_requests = 4, .event_capacity = 8, .command_capacity = 4 };
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
    const expected_bypass_limiter = @import("../rate_limit.zig").Config{
        .global_quota = .{ .replenish_all_every_ms = 1_000, .max_tokens = 2 },
        .by_ip_quota = .{ .replenish_all_every_ms = 1_000, .max_tokens = 1 },
    };
    var ingress_a = try admission.IngressAdmission.init(alloc, expected_bypass_limiter, limits.max_active_requests);
    defer ingress_a.deinit();
    var ingress_b = try admission.IngressAdmission.init(alloc, null, limits.max_active_requests);
    defer ingress_b.deinit();
    var outbox_a = try events.EventOutbox.init(io, alloc, limits.event_capacity);
    defer outbox_a.deinit();
    var outbox_b = try events.EventOutbox.init(io, alloc, limits.event_capacity);
    defer outbox_b.deinit();
    var results_a = try request_results.RequestResultOutbox.init(io, alloc, 1);
    defer results_a.deinit();
    var actor_a = try actor_mod.Actor.init(alloc, config_a);
    defer actor_a.deinit(&ingress_a);
    var actor_b = try actor_mod.Actor.init(alloc, config_b);
    defer actor_b.deinit(&ingress_b);
    var sender_a = RecordingSender.init(alloc);
    defer sender_a.deinit();
    var sender_b = RecordingSender.init(alloc);
    defer sender_b.deinit();
    var effect_storage_a: [4]actor_mod.SendDatagramEffect = undefined;
    var effects_a = actor_mod.RequestEffectQueue.init(&effect_storage_a);
    const env_a = actor_mod.Env{ .io = io, .sender = sender_a.sender(), .ingress = &ingress_a, .outbox = &outbox_a, .request_effects = &effects_a, .request_results = &results_a };
    const env_b = actor_mod.Env{ .io = io, .sender = sender_b.sender(), .ingress = &ingress_b, .outbox = &outbox_b };
    var link_a_to_b = PacketLink.init(&sender_a, address_b, address_a, &actor_b, env_b);
    var link_b_to_a = PacketLink.init(&sender_b, address_a, address_b, &actor_a, env_a);
    const now_ns = outbound.nowNs(io);
    try std.testing.expect(actor_a.addNode(id_b, &pubkey_b, address_b, null, now_ns));
    try std.testing.expect(actor_b.addNode(id_a, &pubkey_a, address_a, null, now_ns));

    const ping_id = try actor_a.sendPing(.{ .io = io, .sender = sender_a.sender(), .ingress = &ingress_a, .outbox = &outbox_a }, .{ .node_id = id_b, .addr = address_b }, &pubkey_b, 0, .api);
    try link_a_to_b.deliverNext();
    try link_b_to_a.deliverNext();
    try link_a_to_b.deliverNext();
    try link_b_to_a.deliverNext();

    try expectNoEvent(&outbox_a, alloc);
    try std.testing.expect(actor_a.requests.get(.init(.{ .node_id = id_b, .addr = address_b }, ping_id)) == null);
    try std.testing.expectEqual(@as(usize, 0), actor_a.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 0), ingress_a.permitCount());
    try std.testing.expect(actor_a.sessions.get(.{ .node_id = id_b, .addr = address_b }, now_ns) != null);
    try std.testing.expect(actor_b.sessions.get(.{ .node_id = id_a, .addr = address_a }, now_ns) != null);

    try std.testing.expect(ingress_a.admit(address_b, 0) == .ordinary);
    try std.testing.expect(results_a.reserve());
    var result_cleanup = ReliableRequestCleanup{ .actor = &actor_a, .env = env_a, .results = &results_a };
    defer result_cleanup.deinit();
    const talk_id = try actor_a.sendTalkRequestWithOrigin(env_a, .{ .node_id = id_b, .addr = address_b }, &pubkey_b, "test", "request", .reliable_api);
    result_cleanup.claim(.init(.{ .node_id = id_b, .addr = address_b }, talk_id));

    const unrelated_ping_id = try actor_b.sendPing(
        .{ .io = io, .sender = sender_b.sender(), .ingress = &ingress_b, .outbox = &outbox_b },
        .{ .node_id = id_a, .addr = address_a },
        &pubkey_a,
        0,
        .api,
    );
    const unrelated_admission = ingress_a.admit(address_b, 1);
    var unrelated_credit = switch (unrelated_admission) {
        .expected => |value| value,
        else => return error.MissingUnrelatedPacketCredit,
    };
    defer unrelated_credit.rollback(&ingress_a);
    const sends_before_unrelated = sender_a.datagrams.items.len;
    try link_b_to_a.deliverNextExpected(&unrelated_credit);
    try std.testing.expect(unrelated_credit.armed);
    try std.testing.expectEqual(sends_before_unrelated, sender_a.datagrams.items.len);
    unrelated_credit.rollback(&ingress_a);
    try std.testing.expect(actor_b.cancelRequest(
        .{ .io = io, .sender = sender_b.sender(), .ingress = &ingress_b, .outbox = &outbox_b },
        .init(.{ .node_id = id_a, .addr = address_a }, unrelated_ping_id),
    ));

    try link_a_to_b.deliverNext();
    var request_event = outbox_b.pop() orelse return error.MissingTalkRequest;
    defer request_event.deinit(alloc);
    try std.testing.expect(request_event == .talkreq);
    try std.testing.expectEqualStrings("test", request_event.talkreq.protocol);
    try std.testing.expectEqualStrings("request", request_event.talkreq.request);
    try std.testing.expectEqualSlices(u8, talk_id.slice(), request_event.talkreq.req_id.slice());
    try actor_b.sendTalkResponse(.{ .io = io, .sender = sender_b.sender(), .ingress = &ingress_b, .outbox = &outbox_b }, .{ .node_id = id_a, .addr = address_a }, request_event.talkreq.req_id, "response");
    const response_admission = ingress_a.admit(address_b, 1);
    var response_credit = switch (response_admission) {
        .expected => |value| value,
        else => return error.MissingResponseCredit,
    };
    defer response_credit.rollback(&ingress_a);
    try link_b_to_a.deliverNextExpected(&response_credit);
    try std.testing.expect(!response_credit.armed);
    const response_result = results_a.pop() orelse return error.MissingTalkResponse;
    result_cleanup.consume();
    try std.testing.expectEqual(types.RequestKind.talkreq, response_result.kind);
    try std.testing.expect(response_result.key.endpoint.addr.eql(&address_b));
    try std.testing.expectEqual(id_b, response_result.key.endpoint.node_id);
    try std.testing.expectEqualSlices(u8, talk_id.slice(), response_result.key.req_id.slice());
    try std.testing.expect(response_result.terminal == .talk_response);
    try std.testing.expectEqualStrings("response", response_result.terminal.talk_response.slice());
    try std.testing.expect(results_a.pop() == null);
    try expectNoEvent(&outbox_a, alloc);
    try std.testing.expectEqual(@as(usize, 0), actor_a.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 0), ingress_a.permitCount());

    const key_c = try secp.keyPairFromSecret(&([_]u8{0x7a} ** 32));
    var builder_c = enr.Builder.init(alloc, key_c, 1);
    builder_c.ip = .{ 127, 0, 0, 3 };
    builder_c.udp = 9203;
    const enr_c = try builder_c.encode();
    defer alloc.free(enr_c);
    const id_c = (try (try enr.decode(enr_c)).nodeId()).?;
    const key_d = try secp.keyPairFromSecret(&([_]u8{0x7b} ** 32));
    var builder_d = enr.Builder.init(alloc, key_d, 1);
    builder_d.ip = .{ 127, 0, 0, 4 };
    builder_d.udp = 9204;
    const enr_d = try builder_d.encode();
    defer alloc.free(enr_d);
    const id_d = (try (try enr.decode(enr_d)).nodeId()).?;
    try std.testing.expect(actor_b.learnDiscovered(enr_c, now_ns) != null);
    try std.testing.expect(actor_b.addEnr(&outbox_b, enr_d, now_ns));
    var added_event = outbox_b.pop() orelse return error.MissingEnrAdded;
    defer added_event.deinit(alloc);
    try std.testing.expect(added_event == .enr_added);
    const distance_c: u16 = @as(u16, @import("../kbucket.zig").logDistance(&id_b, &id_c).?) + 1;
    const distance_d: u16 = @as(u16, @import("../kbucket.zig").logDistance(&id_b, &id_d).?) + 1;
    _ = try actor_a.sendFindNode(
        env_a,
        .{ .node_id = id_b, .addr = address_b },
        &pubkey_b,
        &.{ distance_c, distance_d },
        .api,
    );
    try drainRequestEffects(&actor_a, env_a, &effects_a, &sender_a);
    try link_a_to_b.deliverNext();
    try link_b_to_a.deliverNext();
    var discovered_event = outbox_a.pop() orelse return error.MissingDiscoveredEnr;
    defer discovered_event.deinit(alloc);
    try std.testing.expect(discovered_event == .discovered_enr);
    try std.testing.expectEqualSlices(u8, enr_d, discovered_event.discovered_enr.raw.slice());
    try expectNoEvent(&outbox_a, alloc);
    try std.testing.expectEqual(@as(usize, 0), actor_a.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 0), ingress_a.permitCount());
}

test "identity handshake accepts a known contact without endpoint proof" {
    try std.testing.expect((try contactHandshake(false)).accepted);
}

test "identity handshake accepts an explicitly trusted raw contact" {
    try std.testing.expect((try contactHandshake(true)).accepted);
}

test "known contact rejects a matching claimed ENR whose key differs from the stored key" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const stored_key_a = try secp.keyPairFromSecret(&([_]u8{0x81} ** 32));
    const stored_pubkey_a = secp.compressedPubkey(&stored_key_a);
    const key_b = try secp.keyPairFromSecret(&([_]u8{0x82} ** 32));
    const pubkey_b = secp.compressedPubkey(&key_b);
    const id_b = try enr.nodeIdFromCompressedPubkey(&pubkey_b);
    const key_c = try secp.keyPairFromSecret(&([_]u8{0x83} ** 32));
    const pubkey_c = secp.compressedPubkey(&key_c);
    const id_c = try enr.nodeIdFromCompressedPubkey(&pubkey_c);
    var builder_c = enr.Builder.init(alloc, key_c, 1);
    builder_c.ip = .{ 127, 0, 0, 31 };
    builder_c.udp = 9_331;
    const enr_c = try builder_c.encode();
    defer alloc.free(enr_c);
    try std.testing.expectEqualSlices(u8, &id_c, &(try (try enr.decode(enr_c)).nodeId()).?);

    const address_b = types.Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 30 }, .port = 9_330 } };
    const address_c = types.Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 31 }, .port = 9_331 } };
    const limits = config.Limits{
        .max_active_requests = 2,
        .max_queued_requests = 2,
        .challenge_capacity = 2,
        .event_capacity = 4,
        .command_capacity = 2,
    };
    const limiter = @import("../rate_limit.zig").Config{
        .global_quota = .{ .replenish_all_every_ms = 1_000, .max_tokens = 2 },
        .by_ip_quota = .{ .replenish_all_every_ms = 1_000, .max_tokens = 1 },
    };
    const config_b = config.Config{
        .bind_addresses = .{ .ip4 = address_b },
        .local_key_pair = key_b,
        .rate_limiter = limiter,
        .limits = limits,
    };
    var ingress_b = try admission.IngressAdmission.init(alloc, limiter, try admission.permitCapacity(limits));
    defer ingress_b.deinit();
    var outbox_b = try events.EventOutbox.init(io, alloc, limits.event_capacity);
    defer outbox_b.deinit();
    var actor_b = try actor_mod.Actor.init(alloc, config_b);
    defer actor_b.deinit(&ingress_b);
    var sender_b = RecordingSender.init(alloc);
    defer sender_b.deinit();
    const env_b = actor_mod.Env{ .io = io, .sender = sender_b.sender(), .ingress = &ingress_b, .outbox = &outbox_b };

    // Deliberately model a corrupted known-contact mapping: node ID C is
    // associated with stored key A even though key C derives ID C.
    actor_b.peers.rememberContact(id_c, &stored_pubkey_a, address_c, false);
    const peer_before = actor_b.peers.known(&id_c) orelse return error.MissingKnownPeer;
    try std.testing.expectEqual(@as(usize, 1), actor_b.peers.contacts.count());

    const triggering_nonce = [_]u8{0x41} ** packet.NONCE_SIZE;
    const message_masking_iv = [_]u8{0x42} ** packet.MASKING_IV_SIZE;
    var initial_datagram_buffer: [packet.MAX_PACKET_SIZE]u8 = undefined;
    const initial_datagram = try packet.encodeMessagePacketInto(&initial_datagram_buffer, .{
        .kind = .ordinary,
        .masking_iv = &message_masking_iv,
        .recipient_node_id = &id_b,
        .nonce = &triggering_nonce,
        .authdata = &id_c,
        .write_key = &([_]u8{0x43} ** 16),
        .plaintext = &.{0x44},
    });
    actor_b.handlePacket(env_b, initial_datagram_buffer[0..initial_datagram.len], address_c);

    const endpoint = types.Endpoint{ .node_id = id_c, .addr = address_c };
    const challenge = actor_b.sessions.peekChallenge(endpoint, outbound.nowNs(io)) orelse return error.MissingChallenge;
    try std.testing.expectEqual(@as(usize, 1), actor_b.sessions.challengeCount());
    try std.testing.expect(outbox_b.pop() == null);

    const ephemeral = try secp.keyPairFromSecret(&([_]u8{0x84} ** 32));
    const ephemeral_pubkey = secp.compressedPubkey(&ephemeral);
    const keys = try session_crypto.deriveKeys(&ephemeral, &pubkey_b, &id_c, &id_b, &challenge.challenge_data);
    const signature = try session_crypto.signIdNonce(&stored_key_a, &challenge.challenge_data, &ephemeral_pubkey, &id_b);
    var authdata_buffer: [packet.MAX_PACKET_SIZE]u8 = undefined;
    const authdata = try handshake.buildAuthdata(&authdata_buffer, id_c, &signature, &ephemeral_pubkey, enr_c);
    const ping = message.Ping{ .req_id = try .fromSlice(&.{0x45}), .enr_seq = 1 };
    var plaintext_buffer: [128]u8 = undefined;
    const plaintext = try ping.encodeInto(&plaintext_buffer);
    const handshake_nonce = [_]u8{0x46} ** packet.NONCE_SIZE;
    const handshake_masking_iv = [_]u8{0x47} ** packet.MASKING_IV_SIZE;
    var handshake_datagram_buffer: [packet.MAX_PACKET_SIZE]u8 = undefined;
    const handshake_datagram = try packet.encodeMessagePacketInto(&handshake_datagram_buffer, .{
        .kind = .handshake,
        .masking_iv = &handshake_masking_iv,
        .recipient_node_id = &id_b,
        .nonce = &handshake_nonce,
        .authdata = authdata,
        .write_key = &keys.initiator_key,
        .plaintext = plaintext,
    });

    try std.testing.expect(ingress_b.acceptForTesting(address_c, 0));
    var credit = switch (ingress_b.admit(address_c, 0)) {
        .expected => |value| value,
        else => return error.MissingExpectedCredit,
    };
    defer credit.rollback(&ingress_b);
    const expected_env = actor_mod.Env{
        .io = io,
        .sender = sender_b.sender(),
        .ingress = &ingress_b,
        .outbox = &outbox_b,
        .expected_credit = &credit,
    };
    actor_b.handlePacket(expected_env, handshake_datagram_buffer[0..handshake_datagram.len], address_c);

    try std.testing.expectEqual(true, credit.armed);
    try std.testing.expect(actor_b.sessions.get(endpoint, outbound.nowNs(io)) == null);
    try std.testing.expectEqual(@as(usize, 1), actor_b.sessions.challengeCount());
    try std.testing.expect(outbox_b.pop() == null);
    try std.testing.expect(actor_b.peers.routing.getEntryWithPending(&id_c) == null);
    try std.testing.expectEqual(@as(usize, 1), actor_b.peers.contacts.count());
    const peer_after = actor_b.peers.known(&id_c) orelse return error.KnownPeerRemoved;
    try std.testing.expectEqual(peer_before.pubkey, peer_after.pubkey);
    try std.testing.expect(peer_before.addr.eql(&peer_after.addr));
    try std.testing.expectEqual(peer_before.runtime_contact_trusted, peer_after.runtime_contact_trusted);

    credit.rollback(&ingress_b);
    var restored = switch (ingress_b.admit(address_c, 0)) {
        .expected => |value| value,
        else => return error.ExpectedCreditNotRestored,
    };
    restored.rollback(&ingress_b);
}

test "known peer cannot authenticate with a foreign ENR or commit expected credit" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const key_a = try secp.keyPairFromSecret(&([_]u8{0x88} ** 32));
    const pubkey_a = secp.compressedPubkey(&key_a);
    const id_a = try enr.nodeIdFromCompressedPubkey(&pubkey_a);
    const key_b = try secp.keyPairFromSecret(&([_]u8{0x89} ** 32));
    const pubkey_b = secp.compressedPubkey(&key_b);
    const id_b = try enr.nodeIdFromCompressedPubkey(&pubkey_b);
    const key_c = try secp.keyPairFromSecret(&([_]u8{0x8a} ** 32));
    var foreign_builder = enr.Builder.init(alloc, key_c, 1);
    foreign_builder.ip = .{ 127, 0, 0, 30 };
    foreign_builder.udp = 9_330;
    const foreign_enr = try foreign_builder.encode();
    defer alloc.free(foreign_enr);
    const foreign_id = try enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&key_c));
    const address_a = types.Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 28 }, .port = 9_328 } };
    const address_b = types.Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 29 }, .port = 9_329 } };
    const limits = config.Limits{ .max_active_requests = 2, .max_queued_requests = 2, .event_capacity = 4, .command_capacity = 2 };
    const config_a = config.Config{
        .bind_addresses = .{ .ip4 = address_a },
        .local_key_pair = key_a,
        .rate_limiter = null,
        .limits = limits,
    };
    const limiter = @import("../rate_limit.zig").Config{
        .global_quota = .{ .replenish_all_every_ms = 1_000, .max_tokens = 2 },
        .by_ip_quota = .{ .replenish_all_every_ms = 1_000, .max_tokens = 1 },
    };
    const config_b = config.Config{
        .bind_addresses = .{ .ip4 = address_b },
        .local_key_pair = key_b,
        .rate_limiter = limiter,
        .limits = limits,
    };
    var ingress_a = try admission.IngressAdmission.init(alloc, null, limits.max_active_requests);
    defer ingress_a.deinit();
    var ingress_b = try admission.IngressAdmission.init(alloc, limiter, try admission.permitCapacity(limits));
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

    actor_b.peers.rememberContact(id_a, &pubkey_a, address_a, false);
    const peer_before = actor_b.peers.known(&id_a) orelse return error.MissingKnownPeer;
    try std.testing.expectEqual(@as(usize, 1), actor_b.peers.contacts.count());
    _ = try actor_a.sendPing(.{ .io = io, .sender = sender_a.sender(), .ingress = &ingress_a, .outbox = &outbox_a }, .{ .node_id = id_b, .addr = address_b }, &pubkey_b, 0, .api);
    try link_a_to_b.deliverNext();
    const endpoint = types.Endpoint{ .node_id = id_a, .addr = address_a };
    const challenge = actor_b.sessions.peekChallenge(endpoint, outbound.nowNs(io)) orelse return error.MissingChallenge;
    try std.testing.expect(outbox_b.pop() == null);

    const ephemeral = try secp.keyPairFromSecret(&([_]u8{0x8b} ** 32));
    const ephemeral_pubkey = secp.compressedPubkey(&ephemeral);
    const keys = try session_crypto.deriveKeys(&ephemeral, &pubkey_b, &id_a, &id_b, &challenge.challenge_data);
    const signature = try session_crypto.signIdNonce(&key_a, &challenge.challenge_data, &ephemeral_pubkey, &id_b);
    var authdata_buffer: [packet.MAX_PACKET_SIZE]u8 = undefined;
    const authdata = try handshake.buildAuthdata(&authdata_buffer, id_a, &signature, &ephemeral_pubkey, foreign_enr);
    const ping = message.Ping{ .req_id = try .fromSlice(&.{0x44}), .enr_seq = 0 };
    var plaintext_buffer: [128]u8 = undefined;
    const plaintext = try ping.encodeInto(&plaintext_buffer);
    const nonce = [_]u8{0x55} ** packet.NONCE_SIZE;
    const masking_iv = [_]u8{0x66} ** packet.MASKING_IV_SIZE;
    var datagram_buffer: [packet.MAX_PACKET_SIZE]u8 = undefined;
    const datagram = try packet.encodeMessagePacketInto(&datagram_buffer, .{
        .kind = .handshake,
        .masking_iv = &masking_iv,
        .recipient_node_id = &id_b,
        .nonce = &nonce,
        .authdata = authdata,
        .write_key = &keys.initiator_key,
        .plaintext = plaintext,
    });

    try std.testing.expect(ingress_b.acceptForTesting(address_a, 0));
    const admitted = ingress_b.admit(address_a, 0);
    var credit = switch (admitted) {
        .expected => |value| value,
        else => return error.MissingExpectedCredit,
    };
    defer credit.rollback(&ingress_b);
    const env_b = actor_mod.Env{ .io = io, .sender = sender_b.sender(), .ingress = &ingress_b, .outbox = &outbox_b, .expected_credit = &credit };
    actor_b.handlePacket(env_b, datagram_buffer[0..datagram.len], address_a);

    try std.testing.expect(credit.armed);
    try std.testing.expect(actor_b.sessions.get(endpoint, outbound.nowNs(io)) == null);
    try std.testing.expectEqual(@as(usize, 1), actor_b.sessions.challengeCount());
    try std.testing.expect(outbox_b.pop() == null);
    try std.testing.expect(actor_b.peers.routing.getEntryWithPending(&id_a) == null);
    try std.testing.expect(actor_b.peers.known(&foreign_id) == null);
    try std.testing.expectEqual(@as(usize, 1), actor_b.peers.contacts.count());
    const peer_after = actor_b.peers.known(&id_a) orelse return error.KnownPeerRemoved;
    try std.testing.expectEqual(peer_before.pubkey, peer_after.pubkey);
    try std.testing.expect(peer_before.addr.eql(&peer_after.addr));
    try std.testing.expectEqual(peer_before.runtime_contact_trusted, peer_after.runtime_contact_trusted);

    credit.rollback(&ingress_b);
    const retried = ingress_b.admit(address_a, 0);
    var restored = switch (retried) {
        .expected => |value| value,
        else => return error.ExpectedCreditNotRestored,
    };
    restored.rollback(&ingress_b);

    var bad_signature = signature;
    bad_signature[0] ^= 1;
    const bad_signature_authdata = try handshake.buildAuthdata(&authdata_buffer, id_a, &bad_signature, &ephemeral_pubkey, &.{});
    const bad_signature_datagram = try packet.encodeMessagePacketInto(&datagram_buffer, .{
        .kind = .handshake,
        .masking_iv = &masking_iv,
        .recipient_node_id = &id_b,
        .nonce = &nonce,
        .authdata = bad_signature_authdata,
        .write_key = &keys.initiator_key,
        .plaintext = plaintext,
    });
    var signature_credit = switch (ingress_b.admit(address_a, 0)) {
        .expected => |value| value,
        else => return error.MissingSignatureValidationCredit,
    };
    defer signature_credit.rollback(&ingress_b);
    const signature_env = actor_mod.Env{ .io = io, .sender = sender_b.sender(), .ingress = &ingress_b, .outbox = &outbox_b, .expected_credit = &signature_credit };
    actor_b.handlePacket(signature_env, datagram_buffer[0..bad_signature_datagram.len], address_a);
    try std.testing.expect(signature_credit.armed);
    signature_credit.rollback(&ingress_b);

    const valid_authdata = try handshake.buildAuthdata(&authdata_buffer, id_a, &signature, &ephemeral_pubkey, &.{});
    const wrong_write_key = [_]u8{0xff} ** 16;
    const undecryptable_datagram = try packet.encodeMessagePacketInto(&datagram_buffer, .{
        .kind = .handshake,
        .masking_iv = &masking_iv,
        .recipient_node_id = &id_b,
        .nonce = &nonce,
        .authdata = valid_authdata,
        .write_key = &wrong_write_key,
        .plaintext = plaintext,
    });
    var decryption_credit = switch (ingress_b.admit(address_a, 0)) {
        .expected => |value| value,
        else => return error.MissingDecryptionValidationCredit,
    };
    defer decryption_credit.rollback(&ingress_b);
    const decryption_env = actor_mod.Env{ .io = io, .sender = sender_b.sender(), .ingress = &ingress_b, .outbox = &outbox_b, .expected_credit = &decryption_credit };
    actor_b.handlePacket(decryption_env, datagram_buffer[0..undecryptable_datagram.len], address_a);
    try std.testing.expect(decryption_credit.armed);
    try std.testing.expect(actor_b.sessions.get(endpoint, outbound.nowNs(io)) == null);
    try std.testing.expectEqual(@as(usize, 1), actor_b.sessions.challengeCount());
    try std.testing.expect(outbox_b.pop() == null);
}

test "signed handshake with a mismatched advertised endpoint authenticates only the observed source" {
    const result = try signedEnrHandshake(.mismatched, .none);
    try std.testing.expect(result.session_installed);
    try std.testing.expect(result.established_event);
    try std.testing.expect(result.observed_source_retained);
    try std.testing.expect(!result.relay_eligible);
}

test "signed handshake with an endpoint-less ENR authenticates only the observed source" {
    const result = try signedEnrHandshake(.endpointless, .none);
    try std.testing.expect(result.session_installed);
    try std.testing.expect(result.established_event);
    try std.testing.expect(result.observed_source_retained);
    try std.testing.expect(!result.relay_eligible);
}

test "trusted observed source does not transfer trust to a mismatched advertised endpoint" {
    const result = try signedEnrHandshake(.trusted_mismatched, .none);
    try std.testing.expect(result.session_installed);
    try std.testing.expect(result.runtime_contact_trusted);
    try std.testing.expect(!result.advertised_endpoint_trusted);
    try std.testing.expect(!result.relay_eligible);
}

test "trusted observed source does not make an endpoint-less ENR relayable" {
    const result = try signedEnrHandshake(.trusted_endpointless, .none);
    try std.testing.expect(result.session_installed);
    try std.testing.expect(result.runtime_contact_trusted);
    try std.testing.expect(!result.advertised_endpoint_trusted);
    try std.testing.expect(!result.relay_eligible);
}

test "later traffic from the advertised endpoint makes the mismatched ENR relayable" {
    const result = try signedEnrHandshake(.mismatched, .prove_advertised_endpoint);
    try std.testing.expect(!result.relay_eligible);
    try std.testing.expect(result.later_relay_eligible);
}

test "later explicit trust in the advertised endpoint makes the mismatched ENR relayable" {
    const result = try signedEnrHandshake(.mismatched, .trust_advertised_endpoint);
    try std.testing.expect(!result.relay_eligible);
    try std.testing.expect(result.later_relay_eligible);
}

test "new mismatched ENR does not inherit relay proof from a previously proven endpoint" {
    const result = try signedEnrHandshake(.mismatched_after_proven_enr, .none);
    try std.testing.expect(result.session_installed);
    try std.testing.expect(!result.relay_eligible);
}

const SignedEnrKind = enum { mismatched, endpointless, trusted_mismatched, trusted_endpointless, mismatched_after_proven_enr };
const LaterEndpointEvidence = enum { none, prove_advertised_endpoint, trust_advertised_endpoint };

fn signedEnrHandshake(kind: SignedEnrKind, later_evidence: LaterEndpointEvidence) !struct {
    session_installed: bool,
    established_event: bool,
    observed_source_retained: bool,
    runtime_contact_trusted: bool,
    advertised_endpoint_trusted: bool,
    relay_eligible: bool,
    later_relay_eligible: bool,
} {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const key_a = try secp.keyPairFromSecret(&([_]u8{0x86} ** 32));
    const pubkey_a = secp.compressedPubkey(&key_a);
    const id_a = try enr.nodeIdFromCompressedPubkey(&pubkey_a);
    const key_b = try secp.keyPairFromSecret(&([_]u8{0x87} ** 32));
    const pubkey_b = secp.compressedPubkey(&key_b);
    const id_b = try enr.nodeIdFromCompressedPubkey(&pubkey_b);
    const observed_a = types.Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 9386 } };
    const address_b = types.Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 9387 } };
    var advertised = enr.Builder.init(alloc, key_a, if (kind == .mismatched_after_proven_enr) 2 else 1);
    if (kind != .endpointless and kind != .trusted_endpointless) {
        advertised.ip = .{ 127, 0, 0, 1 };
        advertised.udp = 9486;
    }
    const advertised_enr = try advertised.encode();
    defer alloc.free(advertised_enr);
    const limits = config.Limits{ .max_active_requests = 2, .max_queued_requests = 2, .event_capacity = 4, .command_capacity = 2 };
    const config_a = config.Config{
        .bind_addresses = .{ .ip4 = observed_a },
        .local_key_pair = key_a,
        .local_enr = advertised_enr,
        .rate_limiter = null,
        .limits = limits,
    };
    const config_b = config.Config{
        .bind_addresses = .{ .ip4 = address_b },
        .local_key_pair = key_b,
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
    var sender_a = RecordingSender.init(alloc);
    defer sender_a.deinit();
    var sender_b = RecordingSender.init(alloc);
    defer sender_b.deinit();
    var link_a_to_b = PacketLink.init(&sender_a, address_b, observed_a, &actor_b, .{ .io = io, .sender = sender_b.sender(), .ingress = &ingress_b, .outbox = &outbox_b });
    var link_b_to_a = PacketLink.init(&sender_b, observed_a, address_b, &actor_a, .{ .io = io, .sender = sender_a.sender(), .ingress = &ingress_a, .outbox = &outbox_a });

    if (kind == .trusted_mismatched or kind == .trusted_endpointless) {
        try std.testing.expect(actor_b.addNode(id_a, &pubkey_a, observed_a, null, outbound.nowNs(io)));
    }

    if (kind == .mismatched_after_proven_enr) {
        var prior = enr.Builder.init(alloc, key_a, 1);
        prior.ip = observed_a.ip4.bytes;
        prior.udp = observed_a.ip4.port;
        const prior_enr = try prior.encode();
        defer alloc.free(prior_enr);
        try std.testing.expect(actor_b.learnDiscovered(prior_enr, outbound.nowNs(io)) != null);
        _ = actor_b.peers.markResponsive(id_a, observed_a, outbound.nowNs(io), null);
        try std.testing.expect(actor_b.peers.routing.getEntry(&id_a).?.raw_enr_relay_eligible);
    }

    _ = try actor_a.sendPing(.{ .io = io, .sender = sender_a.sender(), .ingress = &ingress_a, .outbox = &outbox_a }, .{ .node_id = id_b, .addr = address_b }, &pubkey_b, 0, .api);
    try link_a_to_b.deliverNext();
    try link_b_to_a.deliverNext();
    try link_a_to_b.deliverNext();

    var established_event = false;
    while (outbox_b.pop()) |value| {
        var event = value;
        defer event.deinit(alloc);
        if (event == .peer_connected) established_event = true;
    }
    const retained = actor_b.peers.routing.getEntry(&id_a);
    const observed_source_retained = if (retained) |entry| entry.addr.eql(&observed_a) else false;
    const relay_eligible = if (retained) |entry| entry.relayableEnr() != null else false;
    const advertised_address = types.Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 9486 } };
    switch (later_evidence) {
        .none => {},
        .prove_advertised_endpoint => _ = actor_b.peers.markResponsive(id_a, advertised_address, outbound.nowNs(io), null),
        .trust_advertised_endpoint => try std.testing.expect(actor_b.addNode(id_a, &pubkey_a, advertised_address, advertised_enr, outbound.nowNs(io))),
    }
    const after_evidence = actor_b.peers.routing.getEntry(&id_a);
    return .{
        .session_installed = actor_b.sessions.get(.{ .node_id = id_a, .addr = observed_a }, outbound.nowNs(io)) != null,
        .established_event = established_event,
        .observed_source_retained = observed_source_retained,
        .runtime_contact_trusted = if (retained) |entry| entry.runtime_contact_trusted else false,
        .advertised_endpoint_trusted = if (retained) |entry| entry.advertised_endpoint_trusted else false,
        .relay_eligible = relay_eligible,
        .later_relay_eligible = if (after_evidence) |entry| entry.relayableEnr() != null else false,
    };
}

const ContactHandshakeResult = struct {
    accepted: bool,
    responder_datagram_count: usize,
};

fn contactHandshake(runtime_contact_trusted: bool) !ContactHandshakeResult {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const key_a = try secp.keyPairFromSecret(&([_]u8{0x7e} ** 32));
    const pubkey_a = secp.compressedPubkey(&key_a);
    const id_a = try enr.nodeIdFromCompressedPubkey(&pubkey_a);
    const key_b = try secp.keyPairFromSecret(&([_]u8{0x7f} ** 32));
    const pubkey_b = secp.compressedPubkey(&key_b);
    const id_b = try enr.nodeIdFromCompressedPubkey(&pubkey_b);
    const address_a = types.Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 9311 } };
    const address_b = types.Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 9312 } };
    const limits = config.Limits{ .max_active_requests = 2, .max_queued_requests = 2, .event_capacity = 4, .command_capacity = 2 };
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
    var sender_a = RecordingSender.init(alloc);
    defer sender_a.deinit();
    var sender_b = RecordingSender.init(alloc);
    defer sender_b.deinit();
    var link_a_to_b = PacketLink.init(&sender_a, address_b, address_a, &actor_b, .{ .io = io, .sender = sender_b.sender(), .ingress = &ingress_b, .outbox = &outbox_b });
    var link_b_to_a = PacketLink.init(&sender_b, address_a, address_b, &actor_a, .{ .io = io, .sender = sender_a.sender(), .ingress = &ingress_a, .outbox = &outbox_a });

    if (runtime_contact_trusted) {
        try std.testing.expect(actor_b.addNode(id_a, &pubkey_a, address_a, null, outbound.nowNs(io)));
    } else {
        actor_b.peers.rememberContact(id_a, &pubkey_a, address_a, false);
    }
    try std.testing.expectEqual(runtime_contact_trusted, actor_b.peers.known(&id_a).?.runtime_contact_trusted);
    _ = try actor_a.sendPing(.{ .io = io, .sender = sender_a.sender(), .ingress = &ingress_a, .outbox = &outbox_a }, .{ .node_id = id_b, .addr = address_b }, &pubkey_b, 0, .api);
    try link_a_to_b.deliverNext();
    try link_b_to_a.deliverNext();
    try link_a_to_b.deliverNext();
    try std.testing.expectEqual(runtime_contact_trusted, actor_b.peers.known(&id_a).?.runtime_contact_trusted);
    return .{
        .accepted = actor_b.sessions.get(.{ .node_id = id_a, .addr = address_a }, outbound.nowNs(io)) != null,
        .responder_datagram_count = sender_b.datagrams.items.len,
    };
}
