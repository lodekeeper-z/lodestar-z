const std = @import("std");
const actor_mod = @import("../actor.zig");
const admission = @import("../admission.zig");
const config = @import("../config.zig");
const enr = @import("../enr.zig");
const events = @import("../events.zig");
const outbound = @import("../flow/outbound.zig");
const secp = @import("../secp256k1.zig");
const types = @import("../types.zig");
const PacketLink = @import("../test_support/packet_link.zig").PacketLink;
const RecordingSender = @import("../test_support/recording_sender.zig").RecordingSender;

test "WHOAREYOU permit admits a valid HANDSHAKE through an existing source IP ban" {
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
    var sender_a = RecordingSender.init(alloc);
    defer sender_a.deinit();
    var sender_b = RecordingSender.init(alloc);
    defer sender_b.deinit();
    var link_a_to_b = PacketLink.init(&sender_a, address_b, address_a, &actor_b, .{ .io = io, .sender = sender_b.sender(), .ingress = &ingress_b, .outbox = &outbox_b });
    var link_b_to_a = PacketLink.init(&sender_b, address_a, address_b, &actor_a, .{ .io = io, .sender = sender_a.sender(), .ingress = &ingress_a, .outbox = &outbox_a });
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
    try link_a_to_b.deliverNext();
    try std.testing.expectEqual(@as(usize, 1), ingress_b.permitCount());
    try std.testing.expect(ingress_a.accept(address_b, 1));
    try link_b_to_a.deliverNext();
    try std.testing.expect(ingress_b.accept(address_a, 1));
    try link_a_to_b.deliverNext();

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
    var sender_a = RecordingSender.init(alloc);
    defer sender_a.deinit();
    var sender_b = RecordingSender.init(alloc);
    defer sender_b.deinit();
    var link_a_to_b = PacketLink.init(&sender_a, address_b, address_a, &actor_b, .{ .io = io, .sender = sender_b.sender(), .ingress = &ingress_b, .outbox = &outbox_b });
    var link_b_to_a = PacketLink.init(&sender_b, address_a, address_b, &actor_a, .{ .io = io, .sender = sender_a.sender(), .ingress = &ingress_a, .outbox = &outbox_a });
    const now_ns = outbound.nowNs(io);
    try std.testing.expect(actor_a.addNode(id_b, &pubkey_b, address_b, null, now_ns));
    try std.testing.expect(actor_b.addNode(id_a, &pubkey_a, address_a, null, now_ns));

    const ping_id = try actor_a.sendPing(.{ .io = io, .sender = sender_a.sender(), .ingress = &ingress_a, .outbox = &outbox_a }, .{ .node_id = id_b, .addr = address_b }, &pubkey_b, 0, .api);
    try link_a_to_b.deliverNext();
    try link_b_to_a.deliverNext();
    try link_a_to_b.deliverNext();
    try link_b_to_a.deliverNext();

    try std.testing.expect(outbox_a.pop() == null);
    try std.testing.expect(actor_a.requests.get(.init(.{ .node_id = id_b, .addr = address_b }, ping_id)) == null);
    try std.testing.expectEqual(@as(usize, 0), actor_a.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 0), ingress_a.permitCount());
    try std.testing.expect(actor_a.sessions.get(.{ .node_id = id_b, .addr = address_b }, now_ns) != null);
    try std.testing.expect(actor_b.sessions.get(.{ .node_id = id_a, .addr = address_a }, now_ns) != null);

    const talk_id = try actor_a.sendTalkRequest(.{ .io = io, .sender = sender_a.sender(), .ingress = &ingress_a, .outbox = &outbox_a }, .{ .node_id = id_b, .addr = address_b }, &pubkey_b, "test", "request");
    try link_a_to_b.deliverNext();
    var request_event = outbox_b.pop() orelse return error.MissingTalkRequest;
    defer request_event.deinit(alloc);
    try std.testing.expect(request_event == .talkreq);
    try std.testing.expectEqualStrings("test", request_event.talkreq.protocol);
    try std.testing.expectEqualStrings("request", request_event.talkreq.request);
    try std.testing.expectEqualSlices(u8, talk_id.slice(), request_event.talkreq.req_id.slice());
    try actor_b.sendTalkResponse(.{ .io = io, .sender = sender_b.sender(), .ingress = &ingress_b, .outbox = &outbox_b }, .{ .node_id = id_a, .addr = address_a }, request_event.talkreq.req_id, "response");
    try link_b_to_a.deliverNext();
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
        .{ .io = io, .sender = sender_a.sender(), .ingress = &ingress_a, .outbox = &outbox_a },
        .{ .node_id = id_b, .addr = address_b },
        &pubkey_b,
        &.{ distance_c, distance_d },
        .api,
    );
    try link_a_to_b.deliverNext();
    try link_b_to_a.deliverNext();
    var discovered_event = outbox_a.pop() orelse return error.MissingDiscoveredEnr;
    defer discovered_event.deinit(alloc);
    try std.testing.expect(discovered_event == .discovered_enr);
    try std.testing.expectEqualSlices(u8, enr_d, discovered_event.discovered_enr.raw.slice());
    try std.testing.expect(outbox_a.pop() == null);
    try std.testing.expectEqual(@as(usize, 0), actor_a.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 0), ingress_a.permitCount());
}

test "strict handshake rejects untrusted contact without endpoint proof" {
    const result = try contactHandshake(false, false);
    try std.testing.expect(!result.accepted);
    try std.testing.expectEqual(@as(usize, 1), result.responder_datagram_count);
}

test "permissive handshake accepts untrusted contact without endpoint proof" {
    try std.testing.expect((try contactHandshake(true, false)).accepted);
}

test "strict handshake accepts explicitly trusted raw contact" {
    try std.testing.expect((try contactHandshake(false, true)).accepted);
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
    const id_a = try enr.nodeIdFromCompressedPubkey(&pubkey_a);
    const key_b = try secp.keyPairFromSecret(&([_]u8{0x87} ** 32));
    const pubkey_b = secp.compressedPubkey(&key_b);
    const id_b = try enr.nodeIdFromCompressedPubkey(&pubkey_b);
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
    var sender_a = RecordingSender.init(alloc);
    defer sender_a.deinit();
    var sender_b = RecordingSender.init(alloc);
    defer sender_b.deinit();
    var link_a_to_b = PacketLink.init(&sender_a, address_b, observed_a, &actor_b, .{ .io = io, .sender = sender_b.sender(), .ingress = &ingress_b, .outbox = &outbox_b });
    var link_b_to_a = PacketLink.init(&sender_b, observed_a, address_b, &actor_a, .{ .io = io, .sender = sender_a.sender(), .ingress = &ingress_a, .outbox = &outbox_a });

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
    return .{
        .session_installed = actor_b.sessions.get(.{ .node_id = id_a, .addr = observed_a }, outbound.nowNs(io)) != null,
        .established_event = established_event,
    };
}

const ContactHandshakeResult = struct {
    accepted: bool,
    responder_datagram_count: usize,
};

fn contactHandshake(allow_unverified: bool, runtime_contact_trusted: bool) !ContactHandshakeResult {
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
