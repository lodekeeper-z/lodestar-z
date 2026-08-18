const std = @import("std");
const enr = @import("../enr.zig");
const kbucket = @import("../kbucket.zig");
const message = @import("../protocol/message.zig");
const peer_book = @import("peer_book.zig");
const secp = @import("../secp256k1.zig");
const types = @import("../types.zig");

test "PeerBook health request is an exact foreign key" {
    const alloc = std.testing.allocator;
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x31} ** 32));
    var builder = enr.Builder.init(alloc, remote_key, 1);
    builder.ip = .{ 127, 0, 0, 2 };
    builder.udp = 9000;
    const raw = try builder.encode();
    defer alloc.free(raw);
    const remote_id = (try enr.decode(raw)).nodeId().?;
    const address = types.Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 2 }, .port = 9000 } };
    const endpoint = types.Endpoint{ .node_id = remote_id, .addr = address };
    var peers = try peer_book.PeerBook.init(alloc, [_]u8{0} ** 32, 4, true, false);
    defer peers.deinit();
    try std.testing.expect(peers.learnEnr(raw, 0) != null);
    _ = peers.markResponsive(remote_id, address, 0, null);

    const first = types.RequestKey.init(endpoint, try message.ReqId.fromSlice(&.{1}));
    const unrelated = types.RequestKey.init(endpoint, try message.ReqId.fromSlice(&.{2}));
    const newer = types.RequestKey.init(endpoint, try message.ReqId.fromSlice(&.{3}));
    try std.testing.expect(peers.armHealthRequest(first, .connected_only));
    _ = peers.markResponsive(remote_id, address, 1, unrelated);
    try expectHealthRequest(&peers, remote_id, first);

    try std.testing.expect(!peers.armHealthRequest(newer, .connected_only));
    try std.testing.expect(peers.markDisconnected(newer, 2) == .none);
    try expectHealthRequest(&peers, remote_id, first);
    try std.testing.expectEqual(@import("../kbucket.zig").EntryStatus.connected, peers.routing.getEntry(&remote_id).?.status);
    _ = peers.markResponsive(remote_id, address, 3, first);
    try std.testing.expect(peers.routing.getEntry(&remote_id).?.health_request == null);

    try std.testing.expect(peers.armHealthRequest(newer, .connected_only));
    try std.testing.expect(peers.markDisconnected(unrelated, 5) == .none);
    try expectHealthRequest(&peers, remote_id, newer);
    try std.testing.expect(peers.markDisconnected(newer, 6) == .disconnected);
    try std.testing.expect(peers.routing.getEntry(&remote_id).?.health_request == null);
}

test "authenticated endpoint migration disarms stale health timeout" {
    const alloc = std.testing.allocator;
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x33} ** 32));
    const address_a = types.Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 6 }, .port = 9004 } };
    const address_b = types.Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 7 }, .port = 9005 } };
    const raw = try encodeEnr(alloc, remote_key, 1, address_a);
    defer alloc.free(raw);
    const remote_id = (try enr.decode(raw)).nodeId().?;
    var peers = try peer_book.PeerBook.init(alloc, [_]u8{0} ** 32, 4, true, false);
    defer peers.deinit();
    try std.testing.expect(peers.learnEnr(raw, 0) != null);
    _ = peers.markResponsive(remote_id, address_a, 1, null);
    const stale = types.RequestKey.init(.{ .node_id = remote_id, .addr = address_a }, try message.ReqId.fromSlice(&.{9}));
    try std.testing.expect(peers.armHealthRequest(stale, .connected_only));

    _ = peers.markResponsive(remote_id, address_b, 2, null);
    try std.testing.expect(peers.routing.getEntry(&remote_id).?.health_request == null);
    try std.testing.expect(peers.markDisconnected(stale, 3) == .none);
    try std.testing.expectEqual(@import("../kbucket.zig").EntryStatus.connected, peers.routing.getEntry(&remote_id).?.status);
    try std.testing.expect(peers.routing.getEntry(&remote_id).?.addr.eql(&address_b));
}

test "ENR replacement preserves health only for the final effective endpoint" {
    const alloc = std.testing.allocator;
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x34} ** 32));
    const remote_pubkey = secp.compressedPubkey(&remote_key);
    const address_a = types.Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 8 }, .port = 9006 } };
    const address_b = types.Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 9 }, .port = 9007 } };
    const raw_a = try encodeEnr(alloc, remote_key, 1, address_a);
    defer alloc.free(raw_a);
    const learned_b = try encodeEnr(alloc, remote_key, 2, address_b);
    defer alloc.free(learned_b);
    const authenticated_b = try encodeEnr(alloc, remote_key, 3, address_b);
    defer alloc.free(authenticated_b);
    const remote_id = (try enr.decode(raw_a)).nodeId().?;
    var peers = try peer_book.PeerBook.init(alloc, [_]u8{0} ** 32, 4, true, false);
    defer peers.deinit();
    try std.testing.expect(peers.learnEnr(raw_a, 0) != null);
    _ = peers.markResponsive(remote_id, address_a, 1, null);
    const stale = types.RequestKey.init(.{ .node_id = remote_id, .addr = address_a }, try message.ReqId.fromSlice(&.{10}));
    try std.testing.expect(peers.armHealthRequest(stale, .connected_only));

    try std.testing.expect(peers.learnEnr(learned_b, 2) != null);
    try std.testing.expect(peers.routing.getEntry(&remote_id).?.addr.eql(&address_a));
    try expectHealthRequest(&peers, remote_id, stale);

    _ = peers.acceptHandshake(remote_id, &remote_pubkey, address_b, authenticated_b, 3);
    try std.testing.expect(peers.routing.getEntry(&remote_id).?.addr.eql(&address_b));
    try std.testing.expect(peers.routing.getEntry(&remote_id).?.health_request == null);
    try std.testing.expect(peers.markDisconnected(stale, 4) == .none);
}

fn expectHealthRequest(peers: *const peer_book.PeerBook, node_id: types.NodeId, expected: types.RequestKey) !void {
    const actual = peers.routing.getEntryWithPending(&node_id).?.health_request orelse return error.MissingHealthRequest;
    try std.testing.expect(types.RequestKeyContext.eql(.{}, actual, expected));
}

test "new raw ENR needs proof or explicit trust for its exact endpoint" {
    const alloc = std.testing.allocator;
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x41} ** 32));
    const remote_pubkey = secp.compressedPubkey(&remote_key);
    const remote_id = enr.nodeIdFromCompressedPubkey(&remote_pubkey);
    const address_a = types.Address{ .ip4 = .{ .bytes = .{ 192, 0, 2, 30 }, .port = 9030 } };
    const address_b = types.Address{ .ip4 = .{ .bytes = .{ 192, 0, 2, 31 }, .port = 9031 } };
    const raw_a = try encodeEnr(alloc, remote_key, 1, address_a);
    defer alloc.free(raw_a);
    const raw_b = try encodeEnr(alloc, remote_key, 2, address_b);
    defer alloc.free(raw_b);
    var peers = try peer_book.PeerBook.init(alloc, [_]u8{0} ** 32, 4, true, false);
    defer peers.deinit();

    try std.testing.expect(peers.addTrusted(remote_id, &remote_pubkey, address_a, raw_a, 0));
    _ = peers.markResponsive(remote_id, address_a, 1, null);
    try std.testing.expect(peers.learnEnr(raw_b, 2) != null);
    _ = peers.markResponsive(remote_id, address_a, 3, null);

    const retained_a = peers.routing.getEntry(&remote_id) orelse return error.MissingRuntimeContact;
    try std.testing.expect(retained_a.addr.eql(&address_a));
    try std.testing.expectEqualSlices(u8, raw_b, retained_a.enrBytes());
    try std.testing.expect(retained_a.runtime_contact_trusted);
    try std.testing.expect(!retained_a.advertised_endpoint_trusted);
    try std.testing.expect(!retained_a.raw_enr_relay_eligible);
    try std.testing.expect(retained_a.relayableEnr() == null);
    const trusted_a = peers.contacts.get(remote_id) orelse return error.MissingTrustedRuntimeContact;
    try std.testing.expect(trusted_a.explicitly_trusted);
    try std.testing.expect(trusted_a.addr.eql(&address_a));

    _ = peers.markResponsive(remote_id, address_b, 4, null);
    const proven_b = peers.routing.getEntry(&remote_id) orelse return error.MissingProvenEndpoint;
    try std.testing.expect(proven_b.addr.eql(&address_b));
    try std.testing.expect(!proven_b.runtime_contact_trusted);
    try std.testing.expect(!proven_b.advertised_endpoint_trusted);
    try std.testing.expect(proven_b.raw_enr_relay_eligible);
    try std.testing.expectEqualSlices(u8, raw_b, proven_b.relayableEnr().?);

    var explicitly_trusted = try peer_book.PeerBook.init(alloc, [_]u8{0} ** 32, 4, true, false);
    defer explicitly_trusted.deinit();
    try std.testing.expect(explicitly_trusted.addTrusted(remote_id, &remote_pubkey, address_a, raw_a, 5));
    _ = explicitly_trusted.markResponsive(remote_id, address_a, 6, null);
    try std.testing.expect(explicitly_trusted.learnEnr(raw_b, 7) != null);
    _ = explicitly_trusted.markResponsive(remote_id, address_a, 8, null);
    try std.testing.expect(!explicitly_trusted.routing.getEntry(&remote_id).?.raw_enr_relay_eligible);

    try std.testing.expect(explicitly_trusted.addTrusted(remote_id, &remote_pubkey, address_b, raw_b, 9));
    const configured_b = explicitly_trusted.routing.getEntry(&remote_id) orelse return error.MissingConfiguredEndpoint;
    try std.testing.expect(configured_b.addr.eql(&address_a));
    try std.testing.expect(configured_b.runtime_contact_trusted);
    try std.testing.expect(configured_b.advertised_endpoint_trusted);
    try std.testing.expect(configured_b.raw_enr_relay_eligible);
    try std.testing.expectEqualSlices(u8, raw_b, configured_b.relayableEnr().?);
}

test "explicit raw ENR trust rejects an address that differs from its advertised endpoint" {
    const alloc = std.testing.allocator;
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x42} ** 32));
    const remote_pubkey = secp.compressedPubkey(&remote_key);
    const remote_id = enr.nodeIdFromCompressedPubkey(&remote_pubkey);
    const advertised = types.Address{ .ip4 = .{ .bytes = .{ 192, 0, 2, 40 }, .port = 9040 } };
    const configured = types.Address{ .ip4 = .{ .bytes = .{ 192, 0, 2, 41 }, .port = 9041 } };
    const raw = try encodeEnr(alloc, remote_key, 1, advertised);
    defer alloc.free(raw);
    var peers = try peer_book.PeerBook.init(alloc, [_]u8{0} ** 32, 4, true, false);
    defer peers.deinit();

    try std.testing.expect(!peers.addTrusted(remote_id, &remote_pubkey, configured, raw, 0));
    try std.testing.expect(peers.known(&remote_id) == null);
}

test "PeerBook keeps explicit trust endpoint-specific across newer ENR replacements" {
    const alloc = std.testing.allocator;
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x32} ** 32));
    const remote_pubkey = secp.compressedPubkey(&remote_key);
    const remote_id = enr.nodeIdFromCompressedPubkey(&remote_pubkey);
    const address_a = types.Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 3 }, .port = 9001 } };
    const address_b = types.Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 4 }, .port = 9002 } };
    const address_c = types.Address{ .ip4 = .{ .bytes = .{ 127, 0, 0, 5 }, .port = 9003 } };
    const raw_1 = try encodeEnr(alloc, remote_key, 1, address_a);
    defer alloc.free(raw_1);
    const raw_2 = try encodeEnr(alloc, remote_key, 2, address_a);
    defer alloc.free(raw_2);
    const raw_3 = try encodeEnr(alloc, remote_key, 3, address_b);
    defer alloc.free(raw_3);
    const raw_4 = try encodeEnr(alloc, remote_key, 4, address_b);
    defer alloc.free(raw_4);
    const raw_5 = try encodeEnr(alloc, remote_key, 5, address_c);
    defer alloc.free(raw_5);
    var peers = try peer_book.PeerBook.init(alloc, [_]u8{0} ** 32, 4, true, false);
    defer peers.deinit();

    try std.testing.expect(peers.learnEnr(raw_1, 0) != null);
    _ = peers.markResponsive(remote_id, address_a, 1, null);
    try std.testing.expect(peers.routing.getEntry(&remote_id).?.raw_enr_relay_eligible);
    try std.testing.expect(peers.learnEnr(raw_2, 2) != null);
    try std.testing.expect(peers.routing.getEntry(&remote_id).?.raw_enr_relay_eligible);
    try std.testing.expect(peers.learnEnr(raw_3, 3) != null);
    try std.testing.expect(!peers.routing.getEntry(&remote_id).?.raw_enr_relay_eligible);

    try std.testing.expect(peers.addTrusted(remote_id, &remote_pubkey, address_b, raw_4, 4));
    try std.testing.expect(peers.routing.getEntry(&remote_id).?.runtime_contact_trusted);
    try std.testing.expect(peers.routing.getEntry(&remote_id).?.raw_enr_relay_eligible);
    try std.testing.expect(peers.learnEnr(raw_5, 5) != null);
    try std.testing.expect(!peers.routing.getEntry(&remote_id).?.runtime_contact_trusted);
    try std.testing.expect(!peers.routing.getEntry(&remote_id).?.raw_enr_relay_eligible);
    const preserved = peers.contacts.get(remote_id) orelse return error.MissingTrustedContact;
    try std.testing.expect(preserved.explicitly_trusted);
    try std.testing.expect(preserved.addr.eql(&address_b));
}

test "PeerBook rejects opposite-family ENRs and dual mode accepts either" {
    const alloc = std.testing.allocator;
    const key_v4 = try secp.keyPairFromSecret(&([_]u8{0x36} ** 32));
    const key_v6 = try secp.keyPairFromSecret(&([_]u8{0x37} ** 32));
    const address_v4 = types.Address{ .ip4 = .{ .bytes = .{ 192, 0, 2, 1 }, .port = 9010 } };
    const address_v6 = types.Address{ .ip6 = .{ .bytes = .{ 0x20, 0x01, 0x0d, 0xb8 } ++ ([_]u8{0} ** 11) ++ .{1}, .port = 9011 } };
    const raw_v4 = try encodeEnr(alloc, key_v4, 1, address_v4);
    defer alloc.free(raw_v4);
    const raw_v6 = try encodeEnr(alloc, key_v6, 1, address_v6);
    defer alloc.free(raw_v6);

    var ip4_only = try peer_book.PeerBook.init(alloc, [_]u8{0} ** 32, 4, true, false);
    defer ip4_only.deinit();
    try std.testing.expect(ip4_only.learnEnr(raw_v6, 0) == null);

    var ip6_only = try peer_book.PeerBook.init(alloc, [_]u8{0} ** 32, 4, false, true);
    defer ip6_only.deinit();
    try std.testing.expect(ip6_only.learnEnr(raw_v4, 0) == null);

    var dual = try peer_book.PeerBook.init(alloc, [_]u8{0} ** 32, 4, true, true);
    defer dual.deinit();
    try std.testing.expect(dual.learnEnr(raw_v4, 0) != null);
    try std.testing.expect(dual.learnEnr(raw_v6, 0) != null);
}

test "contact eviction preserves only matching explicit trust and malformed ENR fails" {
    const alloc = std.testing.allocator;
    const trusted_key = try secp.keyPairFromSecret(&([_]u8{0x38} ** 32));
    const trusted_pubkey = secp.compressedPubkey(&trusted_key);
    const trusted_id = enr.nodeIdFromCompressedPubkey(&trusted_pubkey);
    const trusted_address = types.Address{ .ip4 = .{ .bytes = .{ 192, 0, 2, 8 }, .port = 9012 } };
    const trusted_enr = try encodeEnr(alloc, trusted_key, 1, trusted_address);
    defer alloc.free(trusted_enr);
    var peers = try peer_book.PeerBook.init(alloc, [_]u8{0} ** 32, 4, true, false);
    defer peers.deinit();

    try std.testing.expect(!peers.addTrusted(trusted_id, &trusted_pubkey, trusted_address, &.{0xff}, 0));
    try std.testing.expect(peers.known(&trusted_id) == null);
    try std.testing.expect(peers.addTrusted(trusted_id, &trusted_pubkey, trusted_address, null, 1));
    try std.testing.expect(peers.known(&trusted_id).?.runtime_contact_trusted);
    try std.testing.expect(peers.learnEnr(trusted_enr, 2) != null);
    try std.testing.expect(peers.contacts.get(trusted_id) == null);
    try std.testing.expect(peers.known(&trusted_id).?.runtime_contact_trusted);

    const untrusted_key = try secp.keyPairFromSecret(&([_]u8{0x39} ** 32));
    const untrusted_pubkey = secp.compressedPubkey(&untrusted_key);
    const untrusted_id = enr.nodeIdFromCompressedPubkey(&untrusted_pubkey);
    const untrusted_address = types.Address{ .ip4 = .{ .bytes = .{ 192, 0, 2, 9 }, .port = 9013 } };
    peers.rememberContact(untrusted_id, &untrusted_pubkey, untrusted_address, false);
    _ = peers.acceptHandshake(untrusted_id, &untrusted_pubkey, untrusted_address, null, 3);
    try std.testing.expect(!peers.known(&untrusted_id).?.runtime_contact_trusted);
}

test "full bucket preserves a matching locally trusted contact after learning its signed ENR" {
    const alloc = std.testing.allocator;
    const local_id = [_]u8{0} ** 32;
    const trusted_key = try secp.keyPairFromSecret(&([_]u8{0x3a} ** 32));
    const trusted_pubkey = secp.compressedPubkey(&trusted_key);
    const trusted_id = enr.nodeIdFromCompressedPubkey(&trusted_pubkey);
    const trusted_address = types.Address{ .ip4 = .{ .bytes = .{ 192, 0, 2, 10 }, .port = 9014 } };
    const trusted_enr = try encodeEnr(alloc, trusted_key, 1, trusted_address);
    defer alloc.free(trusted_enr);
    var peers = try peer_book.PeerBook.init(alloc, local_id, 4, true, false);
    defer peers.deinit();

    try std.testing.expect(peers.addTrusted(trusted_id, &trusted_pubkey, trusted_address, null, 0));
    try fillBucketFor(&peers, trusted_id);
    try std.testing.expect(peers.routing.getEntryWithPending(&trusted_id) == null);

    try std.testing.expect(peers.learnEnr(trusted_enr, 1) != null);
    try std.testing.expect(peers.routing.getEntryWithPending(&trusted_id) == null);
    const known = peers.known(&trusted_id) orelse return error.TrustedContactLost;
    try std.testing.expect(known.runtime_contact_trusted);
    try std.testing.expectEqual(trusted_pubkey, known.pubkey);
    try std.testing.expect(known.addr.eql(&trusted_address));
}

test "addTrusted reports failure when neither routing nor contact storage retains the ENR" {
    const alloc = std.testing.allocator;
    const local_id = [_]u8{0} ** 32;
    const trusted_key = try secp.keyPairFromSecret(&([_]u8{0x3b} ** 32));
    const trusted_pubkey = secp.compressedPubkey(&trusted_key);
    const trusted_id = enr.nodeIdFromCompressedPubkey(&trusted_pubkey);
    const trusted_address = types.Address{ .ip4 = .{ .bytes = .{ 192, 0, 2, 11 }, .port = 9015 } };
    const trusted_enr = try encodeEnr(alloc, trusted_key, 1, trusted_address);
    defer alloc.free(trusted_enr);
    var peers = try peer_book.PeerBook.init(alloc, local_id, 1, true, false);
    defer peers.deinit();

    const occupying_pubkey = [_]u8{2} ** 33;
    const occupying_id = [_]u8{0x7f} ** 32;
    const occupying_address = types.Address{ .ip4 = .{ .bytes = .{ 192, 0, 2, 12 }, .port = 9016 } };
    try std.testing.expect(peers.addTrusted(occupying_id, &occupying_pubkey, occupying_address, null, 0));
    try fillBucketFor(&peers, trusted_id);

    try std.testing.expect(!peers.addTrusted(trusted_id, &trusted_pubkey, trusted_address, trusted_enr, 1));
    try std.testing.expect(peers.routing.getEntryWithPending(&trusted_id) == null);
    try std.testing.expect(peers.contacts.get(trusted_id) == null);
}

test "locally trusted contact remains durable while a pending ENR can still be rejected" {
    const alloc = std.testing.allocator;
    const local_id = [_]u8{0} ** 32;
    const trusted_key = try secp.keyPairFromSecret(&([_]u8{0x3c} ** 32));
    const trusted_pubkey = secp.compressedPubkey(&trusted_key);
    const trusted_id = enr.nodeIdFromCompressedPubkey(&trusted_pubkey);
    const trusted_address = types.Address{ .ip4 = .{ .bytes = .{ 192, 0, 2, 13 }, .port = 9017 } };
    const trusted_enr = try encodeEnr(alloc, trusted_key, 1, trusted_address);
    defer alloc.free(trusted_enr);
    var peers = try peer_book.PeerBook.init(alloc, local_id, 2, true, false);
    defer peers.deinit();

    try std.testing.expect(peers.addTrusted(trusted_id, &trusted_pubkey, trusted_address, null, 0));
    try fillBucketFor(&peers, trusted_id);
    const accepted = peers.acceptHandshake(trusted_id, &trusted_pubkey, trusted_address, trusted_enr, 1);
    const incumbent = accepted.eviction_candidate orelse return error.MissingEvictionCandidate;
    try std.testing.expect(peers.routing.getEntry(&trusted_id) == null);
    try std.testing.expect(peers.routing.getEntryWithPending(&trusted_id) != null);
    try std.testing.expect(peers.contacts.get(trusted_id).?.explicitly_trusted);

    var responsive_incumbent = incumbent;
    responsive_incumbent.status = .connected;
    _ = peers.routing.insertDetailed(responsive_incumbent);
    peers.resolveEvictionSuccess(&incumbent.node_id);
    try std.testing.expect(peers.routing.getEntryWithPending(&trusted_id) == null);
    try std.testing.expect(peers.contacts.get(trusted_id).?.explicitly_trusted);
    try std.testing.expect(peers.known(&trusted_id).?.addr.eql(&trusted_address));
}

test "network-learned endpoint changes preserve endpoint-specific local trust" {
    const alloc = std.testing.allocator;
    const key_pair = try secp.keyPairFromSecret(&([_]u8{0x3f} ** 32));
    const pubkey = secp.compressedPubkey(&key_pair);
    const node_id = enr.nodeIdFromCompressedPubkey(&pubkey);
    const address_a = types.Address{ .ip4 = .{ .bytes = .{ 192, 0, 2, 20 }, .port = 9020 } };
    const address_b = types.Address{ .ip4 = .{ .bytes = .{ 192, 0, 2, 21 }, .port = 9021 } };
    const raw_a = try encodeEnr(alloc, key_pair, 1, address_a);
    defer alloc.free(raw_a);
    const raw_b = try encodeEnr(alloc, key_pair, 2, address_b);
    defer alloc.free(raw_b);
    var peers = try peer_book.PeerBook.init(alloc, [_]u8{0} ** 32, 2, true, false);
    defer peers.deinit();

    try std.testing.expect(peers.addTrusted(node_id, &pubkey, address_a, raw_a, 0));
    try std.testing.expect(peers.learnEnr(raw_b, 1) != null);

    const routed = peers.routing.getEntry(&node_id) orelse return error.MissingRoutedPeer;
    try std.testing.expect(routed.addr.eql(&address_b));
    try std.testing.expect(!routed.runtime_contact_trusted);
    try std.testing.expect(!routed.raw_enr_relay_eligible);
    const contact = peers.contacts.get(node_id) orelse return error.MissingTrustedContact;
    try std.testing.expect(contact.explicitly_trusted);
    try std.testing.expect(contact.addr.eql(&address_a));
}

test "authenticated endpoint move does not migrate local trust" {
    const alloc = std.testing.allocator;
    const key_pair = try secp.keyPairFromSecret(&([_]u8{0x40} ** 32));
    const pubkey = secp.compressedPubkey(&key_pair);
    const node_id = enr.nodeIdFromCompressedPubkey(&pubkey);
    const address_a = types.Address{ .ip4 = .{ .bytes = .{ 192, 0, 2, 22 }, .port = 9022 } };
    const address_b = types.Address{ .ip4 = .{ .bytes = .{ 192, 0, 2, 23 }, .port = 9023 } };
    const raw_a = try encodeEnr(alloc, key_pair, 1, address_a);
    defer alloc.free(raw_a);
    const raw_b = try encodeEnr(alloc, key_pair, 2, address_b);
    defer alloc.free(raw_b);
    var peers = try peer_book.PeerBook.init(alloc, [_]u8{0} ** 32, 2, true, false);
    defer peers.deinit();

    try std.testing.expect(peers.addTrusted(node_id, &pubkey, address_a, raw_a, 0));
    _ = peers.markResponsive(node_id, address_a, 1, null);
    try std.testing.expect(peers.learnEnr(raw_b, 2) != null);
    _ = peers.markResponsive(node_id, address_b, 3, null);

    const routed = peers.routing.getEntry(&node_id) orelse return error.MissingRoutedPeer;
    try std.testing.expect(routed.addr.eql(&address_b));
    try std.testing.expect(!routed.runtime_contact_trusted);
    try std.testing.expect(routed.raw_enr_relay_eligible);
    const contact = peers.contacts.get(node_id) orelse return error.MissingTrustedContact;
    try std.testing.expect(contact.explicitly_trusted);
    try std.testing.expect(contact.addr.eql(&address_a));
}

test "PeerBook knownEnrSeq reads routed and pending canonical metadata" {
    const alloc = std.testing.allocator;
    const local_id = [_]u8{0} ** 32;

    const routed_key = try secp.keyPairFromSecret(&([_]u8{0x3d} ** 32));
    const routed_pubkey = secp.compressedPubkey(&routed_key);
    const routed_id = enr.nodeIdFromCompressedPubkey(&routed_pubkey);
    const routed_address = types.Address{ .ip4 = .{ .bytes = .{ 192, 0, 2, 14 }, .port = 9018 } };
    const routed_enr = try encodeEnr(alloc, routed_key, 4, routed_address);
    defer alloc.free(routed_enr);
    var routed = try peer_book.PeerBook.init(alloc, local_id, 2, true, false);
    defer routed.deinit();
    try std.testing.expect(routed.learnEnr(routed_enr, 0) != null);
    try std.testing.expectEqual(@as(?u64, 4), routed.knownEnrSeq(&routed_id));

    const pending_key = try secp.keyPairFromSecret(&([_]u8{0x3e} ** 32));
    const pending_pubkey = secp.compressedPubkey(&pending_key);
    const pending_id = enr.nodeIdFromCompressedPubkey(&pending_pubkey);
    const pending_address = types.Address{ .ip4 = .{ .bytes = .{ 192, 0, 2, 15 }, .port = 9019 } };
    const pending_enr = try encodeEnr(alloc, pending_key, 7, pending_address);
    defer alloc.free(pending_enr);
    var pending = try peer_book.PeerBook.init(alloc, local_id, 2, true, false);
    defer pending.deinit();
    try fillBucketFor(&pending, pending_id);
    _ = pending.acceptHandshake(pending_id, &pending_pubkey, pending_address, pending_enr, 1);
    try std.testing.expect(pending.routing.getEntry(&pending_id) == null);
    try std.testing.expect(pending.routing.getEntryWithPending(&pending_id) != null);
    try std.testing.expectEqual(@as(?u64, 7), pending.knownEnrSeq(&pending_id));
}

fn fillBucketFor(peers: *peer_book.PeerBook, target_id: types.NodeId) !void {
    const distance = kbucket.logDistance(&peers.local_node_id, &target_id) orelse return error.SameNodeId;
    try std.testing.expect(distance > 7);
    for (1..kbucket.K + 1) |index| {
        var sibling = target_id;
        sibling[31] ^= @intCast(index);
        try std.testing.expect(peers.routing.insert(.{
            .node_id = sibling,
            .pubkey = [_]u8{@intCast(index)} ** 33,
            .addr = .{ .ip4 = .{ .bytes = .{ 198, 51, 100, @intCast(index) }, .port = @intCast(10_000 + index) } },
            .last_seen = @intCast(index),
            .status = .disconnected,
        }));
    }
}

fn encodeEnr(alloc: std.mem.Allocator, key_pair: secp.KeyPair, seq: u64, address: types.Address) ![]u8 {
    var builder = enr.Builder.init(alloc, key_pair, seq);
    switch (address) {
        .ip4 => |value| {
            builder.ip = value.bytes;
            builder.udp = value.port;
        },
        .ip6 => |value| {
            builder.ip6 = value.bytes;
            builder.udp6 = value.port;
        },
    }
    return builder.encode();
}
