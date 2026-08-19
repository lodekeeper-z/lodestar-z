const std = @import("std");
const actor_mod = @import("../actor.zig");
const config = @import("../config.zig");
const enr = @import("../enr.zig");
const kbucket = @import("../kbucket.zig");
const lookup_mod = @import("../service/lookup.zig");
const message = @import("../protocol/message.zig");
const outbound = @import("../flow/outbound.zig");
const packet = @import("../protocol/packet.zig");
const peer_book = @import("../state/peer_book.zig");
const lookup_results = @import("../lookup_results.zig");
const request_results = @import("../request_results.zig");
const secp = @import("../secp256k1.zig");
const session_book = @import("../state/session_book.zig");
const types = @import("../types.zig");
const ActorHarness = @import("../test_support/actor_harness.zig").ActorHarness;

test "validated NODES ENR preserves fields and enabled address selection" {
    const alloc = std.testing.allocator;
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x91} ** 32));
    const remote_pubkey = secp.compressedPubkey(&remote_key);
    const remote_id = try enr.nodeIdFromCompressedPubkey(&remote_pubkey);
    var builder = enr.Builder.init(alloc, remote_key, 7);
    builder.ip = .{ 192, 0, 2, 91 };
    builder.udp = 9091;
    builder.ip6 = .{ 0x20, 0x01, 0x0d, 0xb8 } ++ ([_]u8{0} ** 11) ++ .{0x91};
    builder.udp6 = 9191;
    const raw = try builder.encode();
    defer alloc.free(raw);

    const validated = try enr.ValidatedEnr.init(raw);
    try std.testing.expectEqualSlices(u8, raw, validated.raw.slice());
    try std.testing.expectEqual(@as(u64, 7), validated.parsed.seq);
    try std.testing.expectEqual(remote_pubkey, validated.parsed.pubkey.?);
    try std.testing.expectEqual(remote_id, validated.node_id);

    const address4 = types.Address{ .ip4 = .{ .bytes = builder.ip.?, .port = builder.udp.? } };
    const address6 = types.Address{ .ip6 = .{ .bytes = builder.ip6.?, .port = builder.udp6.? } };
    var ip4_only = try peer_book.PeerBook.init(alloc, [_]u8{0} ** 32, 4, true, false);
    defer ip4_only.deinit();
    try std.testing.expectEqual(remote_id, ip4_only.learnValidatedEnr(&validated, 1).?);
    try std.testing.expect(ip4_only.routing.getEntry(&remote_id).?.addr.eql(&address4));

    var ip6_only = try peer_book.PeerBook.init(alloc, [_]u8{0} ** 32, 4, false, true);
    defer ip6_only.deinit();
    try std.testing.expectEqual(remote_id, ip6_only.learnValidatedEnr(&validated, 2).?);
    try std.testing.expect(ip6_only.routing.getEntry(&remote_id).?.addr.eql(&address6));

    var dual = try peer_book.PeerBook.init(alloc, [_]u8{0} ** 32, 4, true, true);
    defer dual.deinit();
    try std.testing.expectEqual(remote_id, dual.learnValidatedEnr(&validated, 3).?);
    try std.testing.expect(dual.routing.getEntry(&remote_id).?.addr.eql(&address4));

    const tampered = try alloc.dupe(u8, raw);
    defer alloc.free(tampered);
    tampered[tampered.len - 1] ^= 0x01;
    try std.testing.expectError(enr.Error.InvalidSignature, enr.ValidatedEnr.init(tampered));
}

test "validated NODES boundary rejects invalid signatures and preserves reliable multipart results" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x92} ** 32));
    const local_id = try enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&local_key));
    const responder_key = try secp.keyPairFromSecret(&([_]u8{0x93} ** 32));
    const responder_pubkey = secp.compressedPubkey(&responder_key);
    const responder_id = try enr.nodeIdFromCompressedPubkey(&responder_pubkey);
    const endpoint = types.Endpoint{
        .node_id = responder_id,
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 93 }, .port = 9093 } },
    };
    const returned_a = try makeEnr(alloc, 0x94, 4, .{ 127, 0, 0, 94 }, 9094);
    defer alloc.free(returned_a.raw);
    const returned_b = try makeEnr(alloc, 0x95, 5, .{ 127, 0, 0, 95 }, 9095);
    defer alloc.free(returned_b.raw);
    const invalid = try alloc.dupe(u8, returned_a.raw);
    defer alloc.free(invalid);
    invalid[invalid.len - 1] ^= 0x01;
    const distance_a = wireDistance(&returned_a.node_id, &responder_id);
    const distance_b = wireDistance(&returned_b.node_id, &responder_id);
    const cfg = testConfig(local_key, local_id, 8);
    var harness = try ActorHarness.init(alloc, io, cfg);
    defer harness.deinit();
    const actor = &harness.actor;
    const stable = session_book.StableSession{
        .initiator_key = [_]u8{0x96} ** 16,
        .recipient_key = [_]u8{0x97} ** 16,
    };
    actor.sessions.put(endpoint, stable, outbound.nowNs(io));
    var results = try request_results.RequestResultOutbox.init(io, alloc, 1);
    defer results.deinit();
    try std.testing.expect(results.reserve());
    try std.testing.expect(results.claim());
    var env = harness.env();
    env.request_results = &results;
    const req_id = try actor.sendFindNode(env, endpoint, &responder_pubkey, &.{ distance_a, distance_b }, .reliable_api);

    var invalid_buffer: [packet.MAX_PACKET_SIZE]u8 = undefined;
    const invalid_nodes = message.Nodes{ .req_id = req_id, .total = 3, .enrs = &.{invalid} };
    try deliverEncrypted(actor, env, endpoint, &stable.recipient_key, try invalid_nodes.encodeInto(&invalid_buffer), 0x31);
    const after_invalid = &actor.requests.get(.init(endpoint, req_id)).?.response.nodes;
    try std.testing.expectEqual(@as(usize, 0), after_invalid.validated_enrs.slice().len);
    try std.testing.expect(actor.peers.findEnr(&returned_a.node_id) == null);
    try std.testing.expect(harness.outbox.pop() == null);
    try std.testing.expect(results.pop() == null);

    var first_buffer: [packet.MAX_PACKET_SIZE]u8 = undefined;
    const first = message.Nodes{ .req_id = req_id, .total = 3, .enrs = &.{returned_a.raw} };
    try deliverEncrypted(actor, env, endpoint, &stable.recipient_key, try first.encodeInto(&first_buffer), 0x32);
    const partial = &actor.requests.get(.init(endpoint, req_id)).?.response.nodes;
    try std.testing.expectEqual(@as(usize, 1), partial.validated_enrs.slice().len);
    try std.testing.expectEqual(returned_a.node_id, partial.validated_enrs.slice()[0].node_id);
    const learned_a = actor.peers.routing.getEntry(&returned_a.node_id) orelse return error.MissingLearnedPeer;
    try std.testing.expectEqualSlices(u8, returned_a.raw, learned_a.enrBytes());
    try std.testing.expectEqual(@as(u64, 4), learned_a.enr_seq);
    try std.testing.expect(learned_a.addr.eql(&returned_a.address));
    var discovered_a = harness.outbox.pop() orelse return error.MissingDiscoveredEvent;
    defer discovered_a.deinit(alloc);
    try expectDiscovered(&discovered_a, returned_a);

    var final_buffer: [packet.MAX_PACKET_SIZE]u8 = undefined;
    const final = message.Nodes{ .req_id = req_id, .total = 3, .enrs = &.{returned_b.raw} };
    try deliverEncrypted(actor, env, endpoint, &stable.recipient_key, try final.encodeInto(&final_buffer), 0x33);
    try std.testing.expect(actor.requests.get(.init(endpoint, req_id)) == null);
    const result = results.pop() orelse return error.MissingRequestResult;
    try std.testing.expect(result.terminal == .nodes);
    try std.testing.expectEqual(@as(usize, 2), result.terminal.nodes.slice().len);
    try std.testing.expectEqualSlices(u8, returned_a.raw, result.terminal.nodes.slice()[0].slice());
    try std.testing.expectEqualSlices(u8, returned_b.raw, result.terminal.nodes.slice()[1].slice());

    var discovered_b = harness.outbox.pop() orelse return error.MissingDiscoveredEvent;
    defer discovered_b.deinit(alloc);
    try expectDiscovered(&discovered_b, returned_b);
    var nodes_event = harness.outbox.pop() orelse return error.MissingNodesEvent;
    defer nodes_event.deinit(alloc);
    try std.testing.expect(nodes_event == .nodes);
    try std.testing.expectEqual(@as(usize, 2), nodes_event.nodes.enrs.items.len);
    try std.testing.expectEqualSlices(u8, returned_a.raw, nodes_event.nodes.enrs.items[0]);
    try std.testing.expectEqualSlices(u8, returned_b.raw, nodes_event.nodes.enrs.items[1]);
    try std.testing.expect(harness.outbox.pop() == null);
}

test "validated NODES multipart values survive as lookup closer IDs" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x98} ** 32));
    const local_id = try enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&local_key));
    const responder_key = try secp.keyPairFromSecret(&([_]u8{0x99} ** 32));
    const responder_pubkey = secp.compressedPubkey(&responder_key);
    const responder_id = try enr.nodeIdFromCompressedPubkey(&responder_pubkey);
    const endpoint = types.Endpoint{
        .node_id = responder_id,
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 99 }, .port = 9099 } },
    };
    const returned_a = try makeEnr(alloc, 0x9a, 1, .{ 127, 0, 0, 100 }, 9100);
    defer alloc.free(returned_a.raw);
    const returned_b = try makeEnr(alloc, 0x9b, 2, .{ 127, 0, 0, 101 }, 9101);
    defer alloc.free(returned_b.raw);
    const cfg = testConfig(local_key, local_id, 8);
    var harness = try ActorHarness.init(alloc, io, cfg);
    defer harness.deinit();
    const actor = &harness.actor;
    const stable = session_book.StableSession{
        .initiator_key = [_]u8{0x9c} ** 16,
        .recipient_key = [_]u8{0x9d} ** 16,
    };
    actor.sessions.put(endpoint, stable, outbound.nowNs(io));
    const lookup_id: u32 = 91;
    var lookup = try lookup_mod.Lookup.init(alloc, [_]u8{0} ** 32, &.{responder_id}, 0, actor.lookup_config);
    try std.testing.expectEqual(responder_id, lookup.nextPeer(actor.lookup_config).?);
    actor.lookups.putAssumeCapacityNoClobber(lookup_id, lookup);
    const distance_a = wireDistance(&returned_a.node_id, &responder_id);
    const distance_b = wireDistance(&returned_b.node_id, &responder_id);
    const req_id = try actor.sendFindNode(
        harness.env(),
        endpoint,
        &responder_pubkey,
        &.{ distance_a, distance_b },
        .{ .lookup = lookup_id },
    );

    var first_buffer: [packet.MAX_PACKET_SIZE]u8 = undefined;
    const first = message.Nodes{ .req_id = req_id, .total = 2, .enrs = &.{returned_a.raw} };
    try deliverEncrypted(actor, harness.env(), endpoint, &stable.recipient_key, try first.encodeInto(&first_buffer), 0x34);
    var final_buffer: [packet.MAX_PACKET_SIZE]u8 = undefined;
    const final = message.Nodes{ .req_id = req_id, .total = 2, .enrs = &.{returned_b.raw} };
    try deliverEncrypted(actor, harness.env(), endpoint, &stable.recipient_key, try final.encodeInto(&final_buffer), 0x35);

    const completed_lookup = actor.lookups.getPtr(lookup_id) orelse return error.MissingLookup;
    try std.testing.expect(completed_lookup.findPeerIndex(&returned_a.node_id) != null);
    try std.testing.expect(completed_lookup.findPeerIndex(&returned_b.node_id) != null);
    const responder_index = completed_lookup.findPeerIndex(&responder_id) orelse return error.MissingResponder;
    try std.testing.expectEqual(@as(usize, 2), completed_lookup.peers.items[responder_index].peers_returned);
}

test "discv5 lookup-local contact dispatch survives full global retention" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0xa1} ** 32));
    const local_id = try enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&local_key));
    const responder_key = try secp.keyPairFromSecret(&([_]u8{0xa2} ** 32));
    const responder_pubkey = secp.compressedPubkey(&responder_key);
    const responder_id = try enr.nodeIdFromCompressedPubkey(&responder_pubkey);
    const endpoint = types.Endpoint{
        .node_id = responder_id,
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 162 }, .port = 9162 } },
    };
    const returned = try makeEnr(alloc, 0xa3, 3, .{ 127, 0, 0, 163 }, 9163);
    defer alloc.free(returned.raw);
    const validated = try enr.ValidatedEnr.init(returned.raw);
    var cfg = testConfig(local_key, local_id, 8);
    cfg.lookup_num_results = 1;
    cfg.lookup_parallelism = 1;
    cfg.limits.contact_capacity = 1;
    var harness = try ActorHarness.init(alloc, io, cfg);
    defer harness.deinit();
    const actor = &harness.actor;

    const contact_id = [_]u8{0xa4} ** 32;
    actor.peers.rememberContact(contact_id, &responder_pubkey, endpoint.addr, false);
    try std.testing.expectEqual(@as(usize, 1), actor.peers.contacts.count());
    const candidate_bucket = kbucket.logDistance(&local_id, &returned.node_id) orelse return error.InvalidTestIdentity;
    try std.testing.expect(candidate_bucket >= 8);
    for (1..kbucket.K + 1) |value| {
        var filler_id = returned.node_id;
        filler_id[31] ^= @intCast(value);
        try std.testing.expect(actor.peers.routing.insert(.{
            .node_id = filler_id,
            .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 1, @intCast(value) }, .port = @intCast(9200 + value) } },
            .last_seen = 0,
            .status = .disconnected,
        }));
    }
    try std.testing.expectEqual(kbucket.K, actor.peers.routing.getBucket(candidate_bucket).len);

    const stable = session_book.StableSession{
        .initiator_key = [_]u8{0xa5} ** 16,
        .recipient_key = [_]u8{0xa6} ** 16,
    };
    actor.sessions.put(endpoint, stable, outbound.nowNs(io));
    const lookup_id: u32 = 101;
    var lookup = try lookup_mod.Lookup.init(alloc, returned.node_id, &.{responder_id}, 0, actor.lookup_config);
    try std.testing.expectEqual(responder_id, lookup.nextPeer(actor.lookup_config).?);
    actor.lookups.putAssumeCapacityNoClobber(lookup_id, lookup);
    const req_id = try actor.sendFindNode(
        harness.env(),
        endpoint,
        &responder_pubkey,
        &.{wireDistance(&returned.node_id, &responder_id)},
        .{ .lookup = lookup_id },
    );

    var nodes_buffer: [packet.MAX_PACKET_SIZE]u8 = undefined;
    const nodes = message.Nodes{ .req_id = req_id, .total = 1, .enrs = &.{returned.raw} };
    try deliverEncrypted(actor, harness.env(), endpoint, &stable.recipient_key, try nodes.encodeInto(&nodes_buffer), 0xa7);

    try std.testing.expect(actor.peers.known(&returned.node_id) == null);
    try std.testing.expect(actor.peers.findEnr(&returned.node_id) == null);
    const active_lookup = actor.lookups.getPtr(lookup_id) orelse return error.LookupFinishedBeforeLocalDispatch;
    const returned_index = active_lookup.findPeerIndex(&returned.node_id) orelse return error.MissingReturnedCandidate;
    try std.testing.expectEqual(lookup_mod.PeerState.waiting, active_lookup.peers.items[returned_index].state);
    try std.testing.expectEqual(@as(usize, 1), active_lookup.num_waiting);
    const retained = active_lookup.localCandidate(&returned.node_id) orelse return error.MissingLookupLocalContact;
    try std.testing.expectEqual(returned.node_id, retained.node_id);
    try std.testing.expectEqual(validated.parsed.pubkey.?, retained.pubkey);
    try std.testing.expect(retained.addr.eql(&returned.address));
    try std.testing.expectEqualSlices(u8, returned.raw, retained.raw.slice());
    try std.testing.expectEqual(@as(usize, 2), harness.recording.datagrams.items.len);
    try std.testing.expect(harness.recording.datagrams.items[1].address.eql(&returned.address));
}

test "discv5 lookup-local successful result retains raw ENR without PeerBook" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0xa8} ** 32));
    const local_id = try enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&local_key));
    const returned = try makeEnr(alloc, 0xa9, 9, .{ 127, 0, 0, 169 }, 9169);
    defer alloc.free(returned.raw);
    const validated = try enr.ValidatedEnr.init(returned.raw);
    const candidate = lookup_mod.Candidate.fromValidated(&validated, returned.address);
    var cfg = testConfig(local_key, local_id, 8);
    cfg.lookup_num_results = 1;
    cfg.lookup_parallelism = 1;
    cfg.limits.lookup_result_capacity = 1;
    var harness = try ActorHarness.init(alloc, io, cfg);
    defer harness.deinit();
    var results = try lookup_results.LookupResultOutbox.init(io, alloc, 1);
    defer results.deinit();
    try std.testing.expect(results.reserve());
    try std.testing.expect(results.claim());

    var lookup = try lookup_mod.Lookup.init(alloc, returned.node_id, &.{returned.node_id}, 0, harness.actor.lookup_config);
    const contacted = lookup.nextPeer(harness.actor.lookup_config).?;
    lookup.onSuccess(&contacted, &.{candidate}, harness.actor.lookup_config);
    const returned_index = lookup.findPeerIndex(&returned.node_id) orelse return error.MissingReturnedCandidate;
    try std.testing.expectEqual(lookup_mod.PeerState.succeeded, lookup.peers.items[returned_index].state);
    lookup.reliable_result = true;
    harness.actor.lookups.putAssumeCapacityNoClobber(102, lookup);
    try std.testing.expect(harness.actor.peers.findEnr(&returned.node_id) == null);
    var env = harness.env();
    env.lookup_results = &results;

    harness.actor.finishLookup(env, 102, .completed);

    const result = results.pop() orelse return error.MissingLookupResult;
    try std.testing.expectEqual(@as(usize, 1), result.enrs.slice().len);
    try std.testing.expectEqualSlices(u8, returned.raw, result.enrs.slice()[0].slice());
    var event = harness.outbox.pop() orelse return error.MissingLookupEvent;
    defer event.deinit(alloc);
    try std.testing.expect(event == .lookup_finished);
    try std.testing.expectEqual(@as(usize, 1), event.lookup_finished.enrs.items.len);
    try std.testing.expectEqualSlices(u8, returned.raw, event.lookup_finished.enrs.items[0]);
}

test "discv5 lookup-local duplicate enrichment preserves candidate state" {
    const alloc = std.testing.allocator;
    const returned = try makeEnr(alloc, 0xaa, 10, .{ 127, 0, 0, 170 }, 9170);
    defer alloc.free(returned.raw);
    const validated = try enr.ValidatedEnr.init(returned.raw);
    const candidate = lookup_mod.Candidate.fromValidated(&validated, returned.address);
    var responder_id = [_]u8{0xbb} ** 32;
    if (std.mem.eql(u8, &responder_id, &returned.node_id)) responder_id[31] ^= 1;
    const lookup_config = lookup_mod.Config{
        .num_results = 2,
        .parallelism = 2,
        .request_limit = 3,
        .timeout_ms = 60_000,
    };
    var lookup = try lookup_mod.Lookup.init(alloc, [_]u8{0} ** 32, &.{ returned.node_id, responder_id }, 0, lookup_config);
    defer lookup.deinit(alloc);
    _ = lookup.nextPeer(lookup_config) orelse return error.MissingFirstCandidate;
    _ = lookup.nextPeer(lookup_config) orelse return error.MissingSecondCandidate;

    lookup.onSuccess(&responder_id, &.{candidate}, lookup_config);

    try std.testing.expectEqual(@as(usize, 2), lookup.peers.items.len);
    const returned_index = lookup.findPeerIndex(&returned.node_id) orelse return error.MissingReturnedCandidate;
    try std.testing.expectEqual(lookup_mod.PeerState.waiting, lookup.peers.items[returned_index].state);
    try std.testing.expectEqual(@as(usize, 1), lookup.num_waiting);
    const retained = lookup.localCandidate(&returned.node_id) orelse return error.MissingLookupLocalContact;
    try std.testing.expectEqualSlices(u8, returned.raw, retained.raw.slice());

    lookup.onFailure(&returned.node_id, lookup_config);
    try std.testing.expectEqual(lookup_mod.PeerState.failed, lookup.peers.items[returned_index].state);
    lookup.onSuccess(&responder_id, &.{candidate}, lookup_config);
    try std.testing.expectEqual(@as(usize, 2), lookup.peers.items.len);
    try std.testing.expectEqual(lookup_mod.PeerState.failed, lookup.peers.items[returned_index].state);
    try std.testing.expectEqual(@as(usize, 0), lookup.num_waiting);
}

test "discv5 lookup-local protocol bounds remain unchanged" {
    try std.testing.expectEqual(@as(usize, 32), lookup_mod.MAX_CANDIDATES);
    try std.testing.expectEqual(@as(usize, 16), lookup_mod.MAX_RESULTS);
    try std.testing.expectEqual(@as(usize, 16), lookup_mod.MAX_PARALLELISM);
    try std.testing.expectEqual(@as(u16, 16), config.MAX_NODES_RESPONSE);
}

const ReturnedEnr = struct {
    raw: []u8,
    node_id: types.NodeId,
    address: types.Address,
    seq: u64,
};

fn makeEnr(alloc: std.mem.Allocator, secret_byte: u8, seq: u64, ip: [4]u8, port: u16) !ReturnedEnr {
    const key = try secp.keyPairFromSecret(&([_]u8{secret_byte} ** 32));
    const node_id = try enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&key));
    var builder = enr.Builder.init(alloc, key, seq);
    builder.ip = ip;
    builder.udp = port;
    return .{
        .raw = try builder.encode(),
        .node_id = node_id,
        .address = .{ .ip4 = .{ .bytes = ip, .port = port } },
        .seq = seq,
    };
}

fn testConfig(local_key: secp.KeyPair, local_id: types.NodeId, event_capacity: usize) config.Config {
    return .{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
        .local_node_id = local_id,
        .rate_limiter = null,
        .limits = .{
            .max_active_requests = 8,
            .max_queued_requests = 8,
            .event_capacity = event_capacity,
            .command_capacity = 2,
        },
    };
}

fn wireDistance(node_id: *const types.NodeId, responder_id: *const types.NodeId) u16 {
    return if (kbucket.logDistance(node_id, responder_id)) |value| @as(u16, value) + 1 else 0;
}

fn deliverEncrypted(
    actor: *actor_mod.Actor,
    env: actor_mod.Env,
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
    actor.handlePacket(env, encoded, endpoint.addr);
}

fn expectDiscovered(event: *const @import("../events.zig").Event, expected: ReturnedEnr) !void {
    try std.testing.expect(event.* == .discovered_enr);
    try std.testing.expectEqualSlices(u8, expected.raw, event.discovered_enr.raw.slice());
    try std.testing.expectEqual(expected.seq, event.discovered_enr.enr.seq);
    try std.testing.expectEqual(expected.node_id, (try event.discovered_enr.enr.nodeId()).?);
    try std.testing.expect(event.discovered_enr.enr.udpAddress().?.eql(&expected.address));
}
