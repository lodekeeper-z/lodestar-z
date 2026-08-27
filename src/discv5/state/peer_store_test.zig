const std = @import("std");
const enr = @import("../enr.zig");
const message = @import("../protocol/message.zig");
const peer_store = @import("peer_store.zig");
const secp = @import("../secp256k1.zig");
const types = @import("../types.zig");

fn address(port: u16) types.Address {
    return .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = port } };
}

fn request(node_id: types.NodeId, addr: types.Address, id: u8) !types.RequestKey {
    return types.RequestKey.init(.{ .node_id = node_id, .addr = addr }, try message.ReqId.fromSlice(&.{id}));
}

test "PeerStore distance and bucket index boundaries" {
    const zero = [_]u8{0} ** 32;
    var other = zero;
    try std.testing.expect(peer_store.logDistance(&zero, &other) == null);
    try std.testing.expectEqual(zero, peer_store.xorDistance(&zero, &other));
    other[31] = 1;
    try std.testing.expectEqual(@as(?u8, 0), peer_store.logDistance(&zero, &other));
    try std.testing.expectEqual(other, peer_store.xorDistance(&zero, &other));
    other[31] = 0x80;
    try std.testing.expectEqual(@as(?u8, 7), peer_store.logDistance(&zero, &other));
    other = zero;
    other[0] = 0x80;
    try std.testing.expectEqual(@as(?u8, 255), peer_store.logDistance(&zero, &other));
}

test "PeerStore stale PeerRef cannot resolve or mutate a reused slot" {
    var store = try peer_store.PeerStore.init(std.testing.allocator, [_]u8{0} ** 32, true, false);
    defer store.deinit();
    const first_id = [_]u8{1} ** 32;
    const second_id = [_]u8{2} ** 32;
    const key = [_]u8{3} ** 33;
    const stale = try store.remember(first_id, &key, address(9000), false);
    try std.testing.expect(store.remove(stale));
    const current = try store.remember(second_id, &key, address(9001), false);
    try std.testing.expectEqual(stale.index, current.index);
    try std.testing.expect(stale.generation != current.generation);
    try std.testing.expect(store.resolve(stale) == null);
    try std.testing.expect(!store.updateAddress(stale, address(9002)));
    try std.testing.expect(!store.remove(stale));
    try std.testing.expect(store.resolve(current).?.address().eql(&address(9001)));
}

test "PeerStore v4 evidence update preserves v6 evidence" {
    var store = try peer_store.PeerStore.init(std.testing.allocator, [_]u8{0} ** 32, true, true);
    defer store.deinit();
    const ref = try store.remember([_]u8{4} ** 32, &([_]u8{5} ** 33), address(9000), false);
    const v6: types.Address = .{ .ip6 = .{ .bytes = [_]u8{0xaa} ** 16, .port = 9006 } };
    try std.testing.expect(store.setAdvertisedEvidence(ref, v6, true));
    const before = store.advertisedEvidence(ref).?;
    try std.testing.expect(store.setAdvertisedEvidence(ref, address(9004), true));
    const after = store.advertisedEvidence(ref).?;
    try std.testing.expect(before.ip6.address().eql(&after.ip6.address()));
    try std.testing.expect(after.ip4.address().eql(&address(9004)));
}

test "PeerStore active and pending routing refs pin slots" {
    var store = try peer_store.PeerStore.init(std.testing.allocator, [_]u8{0} ** 32, true, false);
    defer store.deinit();
    const active = try store.remember([_]u8{6} ** 32, &([_]u8{7} ** 33), address(9000), false);
    const pending = try store.remember([_]u8{8} ** 32, &([_]u8{9} ** 33), address(9001), false);
    try std.testing.expect(store.pinActive(active));
    try std.testing.expect(store.pinPending(pending));
    try std.testing.expect(!store.remove(active));
    try std.testing.expect(!store.remove(pending));
    try std.testing.expect(store.unpinActive(active));
    try std.testing.expect(store.remove(active));
    try std.testing.expect(store.unpinPending(pending));
    try std.testing.expect(store.remove(pending));
}

test "PeerStore exact 300 byte ENR preserves unknown extension bytes" {
    var store = try peer_store.PeerStore.init(std.testing.allocator, [_]u8{0} ** 32, true, false);
    defer store.deinit();
    const ref = try store.remember([_]u8{10} ** 32, &([_]u8{11} ** 33), address(9000), false);
    var raw: [300]u8 = undefined;
    for (&raw, 0..) |*byte, index| byte.* = @truncate(index * 37 + 11);
    try store.putEnr(ref, &raw, 7);
    try std.testing.expectEqualSlices(u8, &raw, store.enrBytes(ref).?);
    try std.testing.expectEqualSlices(u8, raw[173..199], store.enrBytes(ref).?[173..199]);
}

test "PeerStore peer capacity exhaustion is typed and failure atomic" {
    var store = try peer_store.PeerStore.init(std.testing.allocator, [_]u8{0} ** 32, true, false);
    defer store.deinit();
    const key = [_]u8{12} ** 33;
    for (0..peer_store.PEER_CAPACITY) |index| {
        var node_id = [_]u8{0} ** 32;
        std.mem.writeInt(u64, node_id[24..32], index + 1, .big);
        _ = try store.remember(node_id, &key, address(@intCast(10_000 + index)), false);
    }
    const before = store.count();
    try std.testing.expectError(
        error.PeerCapacityExceeded,
        store.remember([_]u8{0xff} ** 32, &key, address(9999), false),
    );
    try std.testing.expectEqual(before, store.count());
    try std.testing.expect(store.lookup(&([_]u8{0xff} ** 32)) == null);
}

test "PeerStore production layouts and exact backing pass hard gates" {
    const accounting = peer_store.PeerStore.memoryAccounting();
    // Raw ENR retention is promised only for 4096 active routes plus one
    // pending candidate per bucket. The 2000 fallback-only peers retain
    // canonical contact facts but do not consume or promise an ENR slab slot.
    try std.testing.expectEqual(peer_store.ROUTE_BUCKETS * (peer_store.K + 1), peer_store.ENR_CAPACITY);
    try std.testing.expectEqual(peer_store.ENR_CAPACITY, peer_store.PROBE_CAPACITY);
    try std.testing.expect(@sizeOf(peer_store.PeerRecord) <= 128);
    try std.testing.expect(@sizeOf(peer_store.RouteEntry) <= 104);
    try std.testing.expect((peer_store.K - 1) * @sizeOf(peer_store.RouteEntry) <= 1600);
    try std.testing.expect(accounting.total <= 3_298_126);
    const sum = accounting.map + accounting.records + accounting.schedules + accounting.evidence +
        accounting.slot_generations + accounting.slot_freelist + accounting.enr_slots +
        accounting.enr_freelist + accounting.probes + accounting.probe_generations +
        accounting.probe_freelist + accounting.routing + accounting.control;
    try std.testing.expectEqual(accounting.total, sum);
    std.debug.print("PEERSTORE_MEMORY map={} records={} schedules={} evidence={} slot_generations={} slot_freelist={} enr_slots={} enr_freelist={} probes={} probe_generations={} probe_freelist={} routing={} control={} total={} PeerRecord={} RouteEntry={} shift={}\n", .{
        accounting.map,
        accounting.records,
        accounting.schedules,
        accounting.evidence,
        accounting.slot_generations,
        accounting.slot_freelist,
        accounting.enr_slots,
        accounting.enr_freelist,
        accounting.probes,
        accounting.probe_generations,
        accounting.probe_freelist,
        accounting.routing,
        accounting.control,
        accounting.total,
        @sizeOf(peer_store.PeerRecord),
        @sizeOf(peer_store.RouteEntry),
        (peer_store.K - 1) * @sizeOf(peer_store.RouteEntry),
    });
}

test "PeerStore canonical contact lookup returns a copied effective contact" {
    var store = try peer_store.PeerStore.init(std.testing.allocator, [_]u8{0} ** 32, true, false);
    defer store.deinit();
    const node_id = [_]u8{13} ** 32;
    const pubkey = [_]u8{14} ** 33;
    store.rememberContact(node_id, &pubkey, address(9013), true);

    var known = store.known(&node_id) orelse return error.MissingKnownContact;
    try std.testing.expectEqual(node_id, known.node_id);
    try std.testing.expectEqual(pubkey, known.pubkey);
    try std.testing.expect(known.addr.eql(&address(9013)));
    try std.testing.expect(known.runtime_contact_trusted);
    known.addr = address(9999);
    try std.testing.expect(store.known(&node_id).?.addr.eql(&address(9013)));
}

fn bucketNode(index: usize) types.NodeId {
    var node_id = [_]u8{0} ** 32;
    node_id[0] = 0x80;
    std.mem.writeInt(u64, node_id[24..32], index + 1, .big);
    return node_id;
}

test "compact routing duplicate refresh pins an active peer exactly once" {
    var store = try peer_store.PeerStore.init(std.testing.allocator, [_]u8{0} ** 32, true, false);
    defer store.deinit();
    const peer = try store.remember(bucketNode(0), &([_]u8{1} ** 33), address(9000), false);

    const first = try store.admitRoute(peer, false, 10);
    try std.testing.expect(first.inserted);
    try std.testing.expect(first.eviction == null);
    try std.testing.expect(store.routeContains(peer));
    try std.testing.expectEqual(@as(u8, 1), store.resolve(peer).?.activePins());

    const refreshed = try store.admitRoute(peer, true, 20);
    try std.testing.expect(refreshed.inserted);
    try std.testing.expect(refreshed.eviction == null);
    try std.testing.expectEqual(@as(u8, 1), store.resolve(peer).?.activePins());
    try std.testing.expectEqual(@as(usize, 1), store.routeCount());
}

test "full compact bucket owns one pending candidate and rollback conserves pins" {
    var store = try peer_store.PeerStore.init(std.testing.allocator, [_]u8{0} ** 32, true, false);
    defer store.deinit();
    var active: [peer_store.K]peer_store.PeerRef = undefined;
    for (&active, 0..) |*slot, index| {
        slot.* = try store.remember(bucketNode(index), &([_]u8{2} ** 33), address(@intCast(9100 + index)), false);
        try std.testing.expect((try store.admitRoute(slot.*, false, @intCast(index))).inserted);
    }
    const candidate = try store.remember(bucketNode(peer_store.K), &([_]u8{3} ** 33), address(9200), false);
    const admission = try store.admitRoute(candidate, true, 100);
    const ticket = admission.eviction orelse return error.MissingEvictionTicket;

    try std.testing.expect(!admission.inserted);
    try std.testing.expectEqual(active[0], ticket.incumbent);
    try std.testing.expect(store.pendingContains(candidate));
    try std.testing.expect(!store.routeContains(candidate));
    try std.testing.expectEqual(@as(u8, 1), store.resolve(candidate).?.pendingPins());
    try std.testing.expectEqual(@as(u8, 1), store.resolve(active[0]).?.activePins());

    const duplicate = try store.admitRoute(candidate, true, 101);
    try std.testing.expect(duplicate.eviction == null);
    try std.testing.expectEqual(@as(u8, 1), store.resolve(candidate).?.pendingPins());
    try std.testing.expect(store.updateAddress(active[0], address(9999)));
    try std.testing.expect(store.completeEvictionTimeout(ticket) == null);
    try std.testing.expect(store.rollbackEviction(ticket));
    try std.testing.expect(!store.pendingContains(candidate));
    try std.testing.expectEqual(@as(u8, 0), store.resolve(candidate).?.pendingPins());
    try std.testing.expect(!store.rollbackEviction(ticket));
    try std.testing.expect(store.routeContains(active[0]));
}

test "eviction timeout promotes exact pending generation and stale completion is rejected" {
    var store = try peer_store.PeerStore.init(std.testing.allocator, [_]u8{0} ** 32, true, false);
    defer store.deinit();
    var active: [peer_store.K]peer_store.PeerRef = undefined;
    for (&active, 0..) |*slot, index| {
        slot.* = try store.remember(bucketNode(index), &([_]u8{4} ** 33), address(@intCast(9300 + index)), false);
        _ = try store.admitRoute(slot.*, false, @intCast(index));
    }
    const candidate = try store.remember(bucketNode(peer_store.K), &([_]u8{5} ** 33), address(9400), false);
    const ticket = (try store.admitRoute(candidate, true, 100)).eviction.?;

    const promoted = store.completeEvictionTimeout(ticket) orelse return error.NotPromoted;
    try std.testing.expectEqual(candidate, promoted);
    try std.testing.expect(!store.routeContains(active[0]));
    try std.testing.expect(store.routeContains(candidate));
    try std.testing.expectEqual(@as(u8, 0), store.resolve(active[0]).?.activePins());
    try std.testing.expectEqual(@as(u8, 0), store.resolve(candidate).?.pendingPins());
    try std.testing.expectEqual(@as(u8, 1), store.resolve(candidate).?.activePins());
    try std.testing.expect(store.completeEvictionTimeout(ticket) == null);

    try std.testing.expect(store.remove(active[0]));
    const reused = try store.remember(bucketNode(peer_store.K + 1), &([_]u8{6} ** 33), address(9401), false);
    try std.testing.expectEqual(active[0].index, reused.index);
    try std.testing.expect(active[0].generation != reused.generation);
    const newer_ticket = (try store.admitRoute(reused, true, 200)).eviction.?;
    try std.testing.expectEqual(ticket.probe.index, newer_ticket.probe.index);
    try std.testing.expect(ticket.probe.generation != newer_ticket.probe.generation);
    try std.testing.expect(store.completeEvictionTimeout(ticket) == null);
    try std.testing.expect(store.rollbackEviction(newer_ticket));
}

test "compact closest excludes pending and has deterministic XOR order" {
    var store = try peer_store.PeerStore.init(std.testing.allocator, [_]u8{0} ** 32, true, false);
    defer store.deinit();
    const order = [_]usize{ 9, 3, 14, 1, 7, 12, 0, 15, 5, 10, 2, 13, 6, 8, 4, 11 };
    for (order) |index| {
        const peer = try store.remember(bucketNode(index), &([_]u8{7} ** 33), address(@intCast(9500 + index)), false);
        _ = try store.admitRoute(peer, false, @intCast(index));
    }
    const pending = try store.remember(bucketNode(peer_store.K), &([_]u8{8} ** 33), address(9600), false);
    try std.testing.expect((try store.admitRoute(pending, true, 100)).eviction != null);

    var closest: [peer_store.K]types.NodeId = undefined;
    const count = store.findClosestNodeIds(&([_]u8{0} ** 32), &closest);
    try std.testing.expectEqual(peer_store.K, count);
    for (closest[1..], closest[0 .. peer_store.K - 1]) |node_id, previous| {
        try std.testing.expect(std.mem.order(u8, &previous, &node_id) == .lt);
    }
    for (closest) |node_id| try std.testing.expect(!std.mem.eql(u8, &node_id, &bucketNode(peer_store.K)));
}

test "removing an active route promotes and repins the sole pending candidate" {
    var store = try peer_store.PeerStore.init(std.testing.allocator, [_]u8{0} ** 32, true, false);
    defer store.deinit();
    var active: [peer_store.K]peer_store.PeerRef = undefined;
    for (&active, 0..) |*slot, index| {
        slot.* = try store.remember(bucketNode(index), &([_]u8{9} ** 33), address(@intCast(9700 + index)), false);
        _ = try store.admitRoute(slot.*, false, @intCast(index));
    }
    const candidate = try store.remember(bucketNode(peer_store.K), &([_]u8{10} ** 33), address(9800), false);
    _ = (try store.admitRoute(candidate, true, 100)).eviction.?;

    try std.testing.expect(store.removeRoute(active[5]));
    try std.testing.expect(!store.routeContains(active[5]));
    try std.testing.expect(store.routeContains(candidate));
    try std.testing.expectEqual(@as(u8, 0), store.resolve(candidate).?.pendingPins());
    try std.testing.expectEqual(@as(u8, 1), store.resolve(candidate).?.activePins());
    try std.testing.expect(store.remove(active[5]));
}

test "responsive exact incumbent rolls back pending generation without pin drift" {
    var store = try peer_store.PeerStore.init(std.testing.allocator, [_]u8{0} ** 32, true, false);
    defer store.deinit();
    var active: [peer_store.K]peer_store.PeerRef = undefined;
    for (&active, 0..) |*slot, index| {
        slot.* = try store.remember(bucketNode(index), &([_]u8{11} ** 33), address(@intCast(9900 + index)), false);
        _ = try store.admitRoute(slot.*, false, @intCast(index));
    }
    const candidate = try store.remember(bucketNode(peer_store.K), &([_]u8{12} ** 33), address(10_000), false);
    const ticket = (try store.admitRoute(candidate, true, 100)).eviction.?;

    try std.testing.expect(store.resolveEvictionSuccess(ticket));
    try std.testing.expect(store.routeContains(active[0]));
    try std.testing.expect(!store.pendingContains(candidate));
    try std.testing.expectEqual(@as(u8, 1), store.resolve(active[0]).?.activePins());
    try std.testing.expectEqual(@as(u8, 0), store.resolve(candidate).?.pendingPins());
    try std.testing.expect(!store.resolveEvictionSuccess(ticket));
}

test "PeerStore fallback replacement policy capacity and metrics match fallback storage" {
    const local_id = [_]u8{0} ** 32;
    var store = try peer_store.PeerStore.initWithFallbackCapacity(std.testing.allocator, local_id, true, false, 2);
    defer store.deinit();
    const key = [_]u8{2} ** 33;
    const trusted = [_]u8{1} ** 32;
    const untrusted = [_]u8{2} ** 32;
    const trusted_replacement = [_]u8{3} ** 32;
    const rejected_untrusted = [_]u8{4} ** 32;
    const rejected_trusted = [_]u8{5} ** 32;

    store.rememberContact(local_id, &key, address(9000), false);
    store.rememberContact(trusted, &key, address(9001), true);
    store.rememberContact(untrusted, &key, address(9002), false);
    store.rememberContact(trusted_replacement, &key, address(9003), true);
    try std.testing.expect(store.known(&trusted) != null);
    try std.testing.expect(store.known(&untrusted) == null);
    try std.testing.expect(store.known(&trusted_replacement).?.runtime_contact_trusted);

    store.rememberContact(rejected_untrusted, &key, address(9004), false);
    store.rememberContact(rejected_trusted, &key, address(9005), true);
    store.rememberContact(trusted, &key, address(9999), false);
    const first = store.contactMetricsSnapshot();
    const second = store.contactMetricsSnapshot();
    try std.testing.expectEqual(first, second);
    try std.testing.expectEqual(@as(usize, 2), first.count);
    try std.testing.expectEqual(@as(usize, 2), first.capacity);
    try std.testing.expectEqual(@as(u64, 3), first.inserted_total);
    try std.testing.expectEqual(@as(u64, 1), first.replaced_total);
    try std.testing.expectEqual(@as(u64, 2), first.capacity_rejected_total);
    try std.testing.expectEqual(@as(u64, 2), first.policy_rejected_total);
    try std.testing.expect(store.known(&trusted).?.addr.eql(&address(9001)));
}

test "PeerStore health ownership is exact and endpoint migration makes stale completion a no-op" {
    var store = try peer_store.PeerStore.init(std.testing.allocator, [_]u8{0} ** 32, true, false);
    defer store.deinit();
    const node_id = bucketNode(100);
    const key = [_]u8{13} ** 33;
    const addr_a = address(10_100);
    const addr_b = address(10_101);
    const ref = try store.remember(node_id, &key, addr_a, false);
    try store.putEnr(ref, &.{ 0xc1, 0x80 }, 1);
    try std.testing.expect((try store.admitRoute(ref, true, 0)).inserted);
    _ = store.markResponsive(node_id, addr_a, 1, null);

    const first = try request(node_id, addr_a, 1);
    const unrelated = try request(node_id, addr_a, 2);
    const newer = try request(node_id, addr_a, 3);
    try std.testing.expect(store.armHealthRequest(first, .connected_only));
    _ = store.markResponsive(node_id, addr_a, 2, unrelated);
    try std.testing.expect(types.RequestKeyContext.eql(.{}, first, store.healthRequest(&node_id).?));
    try std.testing.expect(!store.armHealthRequest(newer, .connected_only));
    try std.testing.expect(store.markDisconnected(unrelated, 3) == .none);
    try std.testing.expect(store.routeIsConnected(&node_id).?);

    _ = store.markResponsive(node_id, addr_b, 4, null);
    try std.testing.expect(store.healthRequest(&node_id) == null);
    try std.testing.expect(store.markDisconnected(first, 5) == .none);
    try std.testing.expect(store.routeIsConnected(&node_id).?);
    try std.testing.expect(store.activeRoute(&node_id).?.addr.eql(&addr_b));

    const current = try request(node_id, addr_b, 4);
    try std.testing.expect(store.armHealthRequest(current, .connected_only));
    try std.testing.expect(store.markDisconnected(current, 6) == .disconnected);
    try std.testing.expect(!store.routeIsConnected(&node_id).?);
    try std.testing.expect(store.healthRequest(&node_id) == null);
}

test "PeerStore full connected bucket rejects a disconnected newcomer without pending state" {
    var store = try peer_store.PeerStore.init(std.testing.allocator, [_]u8{0} ** 32, true, false);
    defer store.deinit();
    for (0..peer_store.K) |index| {
        const ref = try store.remember(bucketNode(index), &([_]u8{14} ** 33), address(@intCast(11_000 + index)), false);
        try std.testing.expect((try store.admitRoute(ref, true, @intCast(index))).inserted);
    }
    const newcomer = try store.remember(bucketNode(peer_store.K), &([_]u8{15} ** 33), address(11_100), false);
    const rejected = try store.admitRoute(newcomer, false, 100);
    try std.testing.expect(!rejected.inserted);
    try std.testing.expect(rejected.eviction == null);
    try std.testing.expect(!store.routeContains(newcomer));
    try std.testing.expect(!store.pendingContains(newcomer));
    try std.testing.expectEqual(peer_store.K, store.routeCount());
}

test "PeerStore maintenance keeps the original pending deadline and promotes exactly at expiry" {
    var store = try peer_store.PeerStore.init(std.testing.allocator, [_]u8{0} ** 32, true, false);
    defer store.deinit();
    for (0..peer_store.K) |index| {
        const ref = try store.remember(bucketNode(index), &([_]u8{16} ** 33), address(@intCast(11_200 + index)), false);
        _ = try store.admitRoute(ref, false, @intCast(index));
    }
    const candidate_id = bucketNode(peer_store.K);
    const candidate_addr = address(11_300);
    const candidate = try store.remember(candidate_id, &([_]u8{17} ** 33), candidate_addr, false);
    const inserted_at: i64 = 1_000;
    const ticket = (try store.admitRoute(candidate, true, inserted_at)).eviction orelse return error.MissingEvictionTicket;

    _ = store.markResponsive(candidate_id, candidate_addr, inserted_at + 500_000, null);
    try std.testing.expect(store.currentEvictionTicket(&store.resolve(ticket.incumbent).?.node_id, ticket.generation) != null);
    var transitions: [1]peer_store.ConnectionEvent = undefined;
    try std.testing.expectEqual(@as(usize, 0), store.prune(inserted_at + std.time.ns_per_ms - 1, 1, &transitions));
    try std.testing.expect(store.pendingContains(candidate));
    try std.testing.expectEqual(@as(usize, 1), store.prune(inserted_at + std.time.ns_per_ms, 1, &transitions));
    try std.testing.expect(store.routeContains(candidate));
    try std.testing.expect(!store.pendingContains(candidate));
    try std.testing.expectEqual(candidate_id, transitions[0].node_id);
    try std.testing.expect(transitions[0].transition == .connected);
}

test "PeerStore newer ENR resets relay proof and equal-sequence trust promotes the advertised endpoint" {
    const alloc = std.testing.allocator;
    const key_pair = try secp.keyPairFromSecret(&([_]u8{0x51} ** 32));
    const pubkey = secp.compressedPubkey(&key_pair);
    const node_id = try enr.nodeIdFromCompressedPubkey(&pubkey);
    const addr_a = address(11_400);
    const addr_b = address(11_401);
    const raw_a = try encodeEnr(alloc, key_pair, 1, addr_a);
    defer alloc.free(raw_a);
    const raw_b = try encodeEnr(alloc, key_pair, 2, addr_b);
    defer alloc.free(raw_b);
    var store = try peer_store.PeerStore.init(alloc, [_]u8{0} ** 32, true, false);
    defer store.deinit();

    try std.testing.expect(store.learnEnr(raw_a, 0) != null);
    _ = store.markResponsive(node_id, addr_a, 1, null);
    try std.testing.expect(store.routeIsRelayable(&node_id));
    try std.testing.expectEqual(@as(?u64, 1), store.knownEnrSeq(&node_id));

    try std.testing.expect(store.learnEnr(raw_b, 2) != null);
    try std.testing.expectEqual(@as(?u64, 2), store.knownEnrSeq(&node_id));
    try std.testing.expect(!store.routeIsRelayable(&node_id));
    try std.testing.expectEqualSlices(u8, raw_b, store.findEnr(&node_id).?);
    try std.testing.expect(store.learnEnr(raw_a, 3) != null);
    try std.testing.expectEqual(@as(?u64, 2), store.knownEnrSeq(&node_id));
    try std.testing.expectEqualSlices(u8, raw_b, store.findEnr(&node_id).?);

    try std.testing.expect(store.addTrusted(node_id, &pubkey, addr_b, raw_b, 4));
    try std.testing.expect(store.routeIsRelayable(&node_id));
    try std.testing.expect(store.activeRoute(&node_id).?.advertised_endpoint_trusted);
}

test "PeerStore fallback-only learned ENR retains contact facts without raw ENR ownership" {
    const alloc = std.testing.allocator;
    const key_pair = try secp.keyPairFromSecret(&([_]u8{0x52} ** 32));
    const pubkey = secp.compressedPubkey(&key_pair);
    const node_id = try enr.nodeIdFromCompressedPubkey(&pubkey);
    const candidate_addr = address(11_500);
    const raw = try encodeEnr(alloc, key_pair, 7, candidate_addr);
    defer alloc.free(raw);
    var store = try peer_store.PeerStore.init(alloc, [_]u8{0} ** 32, true, false);
    defer store.deinit();

    for (1..peer_store.K + 1) |index| {
        var sibling = node_id;
        sibling[31] ^= @intCast(index);
        const ref = try store.remember(sibling, &([_]u8{18} ** 33), address(@intCast(11_500 + index)), false);
        try std.testing.expect((try store.admitRoute(ref, false, @intCast(index))).inserted);
    }
    try std.testing.expect(store.learnEnr(raw, 100) != null);
    const candidate = store.lookup(&node_id) orelse return error.MissingFallbackContact;
    try std.testing.expect(!store.routeContains(candidate));
    try std.testing.expect(!store.pendingContains(candidate));
    try std.testing.expect(store.known(&node_id) != null);
    try std.testing.expect(store.findEnr(&node_id) == null);
    try std.testing.expect(store.knownEnrSeq(&node_id) == null);
}

fn encodeEnr(alloc: std.mem.Allocator, key_pair: secp.KeyPair, seq: u64, addr: types.Address) ![]u8 {
    var builder = enr.Builder.init(alloc, key_pair, seq);
    switch (addr) {
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
