const std = @import("std");
const actor_mod = @import("actor.zig");
const admission = @import("admission.zig");
const addr_votes = @import("service/addr_votes.zig");
const config = @import("config.zig");
const enr = @import("enr.zig");
const events = @import("events.zig");
const secp = @import("secp256k1.zig");
const RecordingSender = @import("test_support/recording_sender.zig").RecordingSender;
const types = @import("types.zig");

fn ip6(prefix: [8]u8, host: u64, port: u16) types.Address {
    var bytes = [_]u8{0} ** 16;
    @memcpy(bytes[0..8], &prefix);
    std.mem.writeInt(u64, bytes[8..16], host, .big);
    return .{ .ip6 = .{ .bytes = bytes, .port = port } };
}

fn ip4(bytes: [4]u8, port: u16) types.Address {
    return .{ .ip4 = .{ .bytes = bytes, .port = port } };
}

fn drainEffects(
    actor: *actor_mod.Actor,
    env: actor_mod.Env,
    effects: *actor_mod.EffectQueue,
    recording: *RecordingSender,
) !void {
    while (effects.pop()) |effect| {
        recording.sender().send(effect.destination(), effect.packetBytes()) catch |err| {
            actor.applyEffectCompletion(env, effect, .failed);
            return err;
        };
        actor.applyEffectCompletion(env, effect, .sent);
    }
}

test "Actor address votes count one voter per native IPv6 source prefix" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x91} ** 32));
    const local_address = ip6(.{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1 }, 1, 9000);
    var local_builder = enr.Builder.init(alloc, local_key, 1);
    local_builder.ip6 = local_address.ip6.bytes;
    local_builder.udp6 = local_address.ip6.port;
    const local_enr = try local_builder.encode();
    defer alloc.free(local_enr);
    const cfg = config.Config{
        .bind_addresses = .{ .ip6 = local_address },
        .local_key_pair = local_key,
        .local_enr = local_enr,
        .addr_votes_to_update_enr = 10,
        .rate_limiter = null,
        .limits = .{ .max_active_requests = 2, .max_queued_requests = 2, .event_capacity = 2, .command_capacity = 2 },
    };
    var ingress = try admission.IngressAdmission.init(alloc, null, cfg.limits.max_active_requests);
    defer ingress.deinit();
    var outbox = try events.EventOutbox.init(io, alloc, cfg.limits.event_capacity);
    defer outbox.deinit();
    var actor = try actor_mod.Actor.init(alloc, cfg);
    defer actor.deinit(&ingress);
    var recording = RecordingSender.init(alloc);
    defer recording.deinit();
    const env = actor_mod.Env{ .io = io, .ingress = &ingress, .outbox = &outbox };

    const voter_prefix = [8]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 2 };
    const observed = ip6(.{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 3 }, 1, 9100);
    for (1..11) |host| actor.observeAddressVoteAt(env, ip6(voter_prefix, host, @intCast(10_000 + host)), observed, @intCast(host));

    try std.testing.expectEqual(@as(u64, 1), actor.localEnrSeq());
    try std.testing.expectEqual(@as(usize, 1), actor.votes_ip6.currentVoteCount());
    try std.testing.expectEqual(@as(usize, 0), recording.datagrams.items.len);
    try std.testing.expect(outbox.pop() == null);
}

test "Actor address vote window expires old observations deterministically" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x95} ** 32));
    var local_builder = enr.Builder.init(alloc, local_key, 1);
    local_builder.ip = .{ 127, 0, 0, 1 };
    local_builder.udp = 9000;
    const local_enr = try local_builder.encode();
    defer alloc.free(local_enr);
    const cfg = config.Config{
        .bind_addresses = .{ .ip4 = ip4(.{ 127, 0, 0, 1 }, 9000) },
        .local_key_pair = local_key,
        .local_enr = local_enr,
        .addr_votes_to_update_enr = 2,
        .rate_limiter = null,
        .limits = .{ .max_active_requests = 2, .max_queued_requests = 2, .event_capacity = 2, .command_capacity = 2 },
    };
    var ingress = try admission.IngressAdmission.init(alloc, null, cfg.limits.max_active_requests);
    defer ingress.deinit();
    var outbox = try events.EventOutbox.init(io, alloc, cfg.limits.event_capacity);
    defer outbox.deinit();
    var actor = try actor_mod.Actor.init(alloc, cfg);
    defer actor.deinit(&ingress);
    var recording = RecordingSender.init(alloc);
    defer recording.deinit();
    const env = actor_mod.Env{ .io = io, .ingress = &ingress, .outbox = &outbox };
    const observed = ip4(.{ 198, 51, 100, 20 }, 9100);
    const window_ns: i64 = addr_votes.VOTE_OBSERVATION_WINDOW_MS * std.time.ns_per_ms;

    actor.observeAddressVoteAt(env, ip4(.{ 192, 0, 2, 1 }, 9201), observed, 0);
    actor.observeAddressVoteAt(env, ip4(.{ 192, 0, 2, 2 }, 9202), observed, window_ns);
    try std.testing.expectEqual(@as(u64, 1), actor.localEnrSeq());
    try std.testing.expectEqual(@as(usize, 1), actor.votes_ip4.currentVoteCount());

    actor.observeAddressVoteAt(env, ip4(.{ 192, 0, 2, 1 }, 9201), observed, window_ns + 1);
    try std.testing.expectEqual(@as(u64, 2), actor.localEnrSeq());
    try std.testing.expectEqual(@as(usize, 0), actor.votes_ip4.currentVoteCount());
}

test "Actor rejects invalid observed endpoints but accepts private unicast" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x92} ** 32));
    var local_builder = enr.Builder.init(alloc, local_key, 1);
    local_builder.ip = .{ 127, 0, 0, 1 };
    local_builder.udp = 9000;
    const local_enr = try local_builder.encode();
    defer alloc.free(local_enr);
    const cfg = config.Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 9000 } } },
        .local_key_pair = local_key,
        .local_enr = local_enr,
        .addr_votes_to_update_enr = 1,
        .rate_limiter = null,
        .limits = .{ .max_active_requests = 2, .max_queued_requests = 2, .event_capacity = 4, .command_capacity = 2 },
    };
    var ingress = try admission.IngressAdmission.init(alloc, null, cfg.limits.max_active_requests);
    defer ingress.deinit();
    var outbox = try events.EventOutbox.init(io, alloc, cfg.limits.event_capacity);
    defer outbox.deinit();
    var actor = try actor_mod.Actor.init(alloc, cfg);
    defer actor.deinit(&ingress);
    var recording = RecordingSender.init(alloc);
    defer recording.deinit();
    const env = actor_mod.Env{ .io = io, .ingress = &ingress, .outbox = &outbox };
    const voter = types.Address{ .ip4 = .{ .bytes = .{ 192, 0, 2, 1 }, .port = 10_000 } };
    const invalid = [_]types.Address{
        .{ .ip4 = .{ .bytes = .{ 198, 51, 100, 1 }, .port = 0 } },
        .{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = 9100 } },
        .{ .ip4 = .{ .bytes = .{ 224, 0, 0, 1 }, .port = 9100 } },
        .{ .ip4 = .{ .bytes = .{ 255, 255, 255, 255 }, .port = 9100 } },
        ip6(.{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 4 }, 1, 9100),
    };
    for (invalid, 0..) |observed, index| actor.observeAddressVoteAt(env, voter, observed, @intCast(index));

    try std.testing.expectEqual(@as(u64, 1), actor.localEnrSeq());
    try std.testing.expectEqual(@as(usize, 0), actor.votes_ip4.currentVoteCount());
    try std.testing.expectEqual(@as(usize, 0), actor.votes_ip6.currentVoteCount());
    try std.testing.expect(outbox.pop() == null);

    const private_unicast = types.Address{ .ip4 = .{ .bytes = .{ 10, 0, 0, 9 }, .port = 9100 } };
    actor.observeAddressVoteAt(env, voter, private_unicast, invalid.len);
    try std.testing.expectEqual(@as(u64, 2), actor.localEnrSeq());
    const parsed = try enr.decode(actor.localEnr().?.slice());
    try std.testing.expect(parsed.udpAddress4().?.eql(&private_unicast));
}

test "Actor coalesces alternating address updates through a deterministic cooldown" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x93} ** 32));
    var local_builder = enr.Builder.init(alloc, local_key, 1);
    local_builder.ip = .{ 127, 0, 0, 1 };
    local_builder.udp = 9000;
    const local_enr = try local_builder.encode();
    defer alloc.free(local_enr);
    const cfg = config.Config{
        .bind_addresses = .{ .ip4 = ip4(.{ 127, 0, 0, 1 }, 9000) },
        .local_key_pair = local_key,
        .local_enr = local_enr,
        .addr_votes_to_update_enr = 1,
        .rate_limiter = null,
        .limits = .{ .max_active_requests = 4, .max_queued_requests = 4, .event_capacity = 8, .command_capacity = 2 },
    };
    var ingress = try admission.IngressAdmission.init(alloc, null, cfg.limits.max_active_requests);
    defer ingress.deinit();
    var outbox = try events.EventOutbox.init(io, alloc, cfg.limits.event_capacity);
    defer outbox.deinit();
    var actor = try actor_mod.Actor.init(alloc, cfg);
    defer actor.deinit(&ingress);
    var recording = RecordingSender.init(alloc);
    defer recording.deinit();
    var effect_storage: [4]actor_mod.ActorEffect = undefined;
    var effects = actor_mod.EffectQueue.init(&effect_storage);
    const env = actor_mod.Env{
        .io = io,

        .ingress = &ingress,
        .outbox = &outbox,
        .effects = &effects,
    };

    const remote_key = try secp.keyPairFromSecret(&([_]u8{0x94} ** 32));
    const remote_id = try enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&remote_key));
    const remote_address = ip4(.{ 192, 0, 2, 10 }, 9200);
    var remote_builder = enr.Builder.init(alloc, remote_key, 1);
    remote_builder.ip = remote_address.ip4.bytes;
    remote_builder.udp = remote_address.ip4.port;
    const remote_enr = try remote_builder.encode();
    defer alloc.free(remote_enr);
    try std.testing.expect(actor.peers.learnEnr(remote_enr, 0) != null);
    _ = actor.peers.markResponsive(remote_id, remote_address, 0, null);

    const observed_a = ip4(.{ 198, 51, 100, 10 }, 9100);
    const observed_b = ip4(.{ 198, 51, 100, 11 }, 9101);
    actor.observeAddressVoteAt(env, remote_address, observed_a, 100);
    try drainEffects(&actor, env, &effects, &recording);
    try std.testing.expectEqual(@as(u64, 2), actor.localEnrSeq());
    try std.testing.expectEqual(@as(usize, 1), recording.datagrams.items.len);
    const propagation = actor.peers.healthRequest(&remote_id) orelse return error.MissingPropagationPing;
    const propagation_handle = actor.requests.handleFor(propagation) orelse return error.MissingPropagationHandle;
    try std.testing.expect(actor.cancelRequest(env, propagation_handle));

    actor.observeAddressVoteAt(env, remote_address, observed_b, 101);
    actor.observeAddressVoteAt(env, remote_address, observed_a, 102);
    actor.observeAddressVoteAt(env, remote_address, observed_b, 103);
    try std.testing.expectEqual(@as(u64, 2), actor.localEnrSeq());
    try std.testing.expectEqual(@as(usize, 1), recording.datagrams.items.len);
    try std.testing.expectEqual(@as(usize, 0), actor.votes_ip4.currentVoteCount());

    const cooldown_ns: i64 = addr_votes.ENR_UPDATE_COOLDOWN_MS * std.time.ns_per_ms;
    actor.observeAddressVoteAt(env, remote_address, observed_b, 100 + cooldown_ns);
    try drainEffects(&actor, env, &effects, &recording);
    try std.testing.expectEqual(@as(u64, 3), actor.localEnrSeq());
    try std.testing.expectEqual(@as(usize, 2), recording.datagrams.items.len);
}
