const std = @import("std");
const actor_mod = @import("../actor.zig");
const config = @import("../config.zig");
const enr = @import("../enr.zig");
const outbound = @import("../flow/outbound.zig");
const message = @import("../protocol/message.zig");
const packet = @import("../protocol/packet.zig");
const secp = @import("../secp256k1.zig");
const request_book = @import("../state/request_book.zig");
const types = @import("../types.zig");
const ActorHarness = @import("../test_support/actor_harness.zig").ActorHarness;

const TestContext = struct {
    harness: ActorHarness,
    endpoint: types.Endpoint,
    remote_pubkey: [33]u8,

    fn init(alloc: std.mem.Allocator, io: std.Io, local_byte: u8, remote_byte: u8, remote_ip: u8, remote_port: u16) !TestContext {
        return initWithMaxActive(alloc, io, local_byte, remote_byte, remote_ip, remote_port, 1);
    }

    fn initWithMaxActive(alloc: std.mem.Allocator, io: std.Io, local_byte: u8, remote_byte: u8, remote_ip: u8, remote_port: u16, max_active_requests: usize) !TestContext {
        const local_key = try secp.keyPairFromSecret(&([_]u8{local_byte} ** 32));
        const remote_key = try secp.keyPairFromSecret(&([_]u8{remote_byte} ** 32));
        const remote_pubkey = secp.compressedPubkey(&remote_key);
        return .{
            .harness = try ActorHarness.init(alloc, io, config.Config{
                .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
                .local_key_pair = local_key,
                .rate_limiter = null,
                .limits = .{
                    .max_active_requests = max_active_requests,
                    .max_queued_requests = 1,
                    .event_capacity = 1,
                    .command_capacity = 1,
                },
            }),
            .endpoint = .{
                .node_id = try enr.nodeIdFromCompressedPubkey(&remote_pubkey),
                .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, remote_ip }, .port = remote_port } },
            },
            .remote_pubkey = remote_pubkey,
        };
    }

    fn deinit(self: *TestContext) void {
        self.harness.deinit();
    }

    fn preparePing(self: *TestContext) !actor_mod.SendDatagramEffect {
        const action = try self.harness.actor.preparePing(
            .{ .io = self.harness.io, .ingress = &self.harness.ingress },
            self.endpoint,
            &self.remote_pubkey,
            0,
            .reliable_api,
        );
        return switch (action) {
            .send => |effect| effect,
            .queued => error.UnexpectedQueuedRequest,
        };
    }
};

test "request effect is compact handle plus packet bytes" {
    const fields = @typeInfo(actor_mod.SendDatagramEffect).@"struct".fields;
    try std.testing.expectEqual(@as(usize, 2), fields.len);
    try std.testing.expectEqualStrings("handle", fields[0].name);
    try std.testing.expectEqual(request_book.RequestHandle, fields[0].type);
    try std.testing.expectEqualStrings("packet", fields[1].name);
    try std.testing.expectEqual(types.PacketBytes, fields[1].type);
    comptime {
        std.debug.assert(@sizeOf(actor_mod.ActorEffect) <= (13 * packet.MAX_PACKET_SIZE) / 4);
    }
}

test "sending outbound ping owns request until successful send completion" {
    var context = try TestContext.init(std.testing.allocator, std.Options.debug_io, 0xb1, 0xb2, 81, 9281);
    defer context.deinit();

    var effect = try context.preparePing();
    const key = types.RequestKey.init(context.endpoint, effect.requestId());

    try std.testing.expectEqual(@as(usize, 0), context.harness.actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 1), context.harness.actor.requests.sendingCount());
    try std.testing.expect(context.harness.actor.requests.get(key) == null);
    try std.testing.expect(context.harness.actor.requests.shouldQueue(context.endpoint));
    try std.testing.expectEqual(@as(usize, 1), context.harness.ingress.permitCount());
    try std.testing.expect(effect.packetBytes().len > 0);
    try std.testing.expect(effect.destination().eql(&context.endpoint.addr));

    context.harness.actor.applySendCompletion(context.harness.env(), effect, .sent);

    try std.testing.expectEqual(@as(usize, 1), context.harness.actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 0), context.harness.actor.requests.sendingCount());
    try std.testing.expect(context.harness.actor.requests.get(key) != null);
    try std.testing.expect(context.harness.actor.requests.shouldQueue(context.endpoint));
    try std.testing.expectEqual(@as(usize, 1), context.harness.ingress.permitCount());
}

test "failed outbound ping completion releases the effect-owned request" {
    var context = try TestContext.init(std.testing.allocator, std.Options.debug_io, 0xb3, 0xb4, 82, 9282);
    defer context.deinit();

    var effect = try context.preparePing();
    const key = types.RequestKey.init(context.endpoint, effect.requestId());
    try std.testing.expectEqual(@as(usize, 1), context.harness.ingress.permitCount());

    context.harness.actor.applyEffectCompletion(context.harness.env(), effect, .failed);

    try std.testing.expectEqual(@as(usize, 0), context.harness.actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 0), context.harness.actor.requests.sendingCount());
    try std.testing.expect(context.harness.actor.requests.get(key) == null);
    try std.testing.expect(!context.harness.actor.requests.shouldQueue(context.endpoint));
    try std.testing.expectEqual(@as(usize, 0), context.harness.ingress.permitCount());
}

test "copied request effect completion is accepted exactly once" {
    var context = try TestContext.init(std.testing.allocator, std.Options.debug_io, 0xd1, 0xd2, 92, 9292);
    defer context.deinit();
    const effect = try context.preparePing();
    const duplicate = effect;

    context.harness.actor.applySendCompletion(context.harness.env(), effect, .sent);
    context.harness.actor.applySendCompletion(context.harness.env(), duplicate, .sent);

    try std.testing.expectEqual(@as(usize, 1), context.harness.actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 1), context.harness.ingress.permitCount());
}

test "sent FINDNODE effect activates the nodes response state" {
    var context = try TestContext.init(std.testing.allocator, std.Options.debug_io, 0xb5, 0xb6, 83, 9283);
    defer context.deinit();

    const action = try context.harness.actor.prepareFindNode(
        .{ .io = context.harness.io, .ingress = &context.harness.ingress },
        context.endpoint,
        &context.remote_pubkey,
        &.{ 0, 256 },
        .reliable_api,
    );
    var effect = switch (action) {
        .send => |value| value,
        .queued => return error.UnexpectedQueuedRequest,
    };
    const key = types.RequestKey.init(context.endpoint, effect.requestId());

    context.harness.actor.applySendCompletion(context.harness.env(), effect, .sent);

    const request = context.harness.actor.requests.get(key) orelse return error.MissingActiveRequest;
    try std.testing.expect(request.response == .nodes);
}

test "bounded request effect output owns sending state without executing transport" {
    var context = try TestContext.init(std.testing.allocator, std.Options.debug_io, 0xb9, 0xba, 85, 9285);
    defer context.deinit();
    var storage: [1]actor_mod.ActorEffect = undefined;
    var effects = actor_mod.EffectQueue.init(&storage);
    const action = try context.harness.actor.preparePing(
        .{ .io = context.harness.io, .ingress = &context.harness.ingress },
        context.endpoint,
        &context.remote_pubkey,
        0,
        .reliable_api,
    );

    var env = context.harness.env();
    env.effects = &effects;
    try outbound.emitPrepared(&context.harness.actor, env, action);

    try std.testing.expectEqual(@as(usize, 1), effects.count());
    try std.testing.expectEqual(@as(usize, 0), context.harness.recording.datagrams.items.len);
    try std.testing.expectEqual(@as(usize, 1), context.harness.ingress.permitCount());
    const effect = effects.pop() orelse return error.MissingEffect;
    context.harness.actor.applyEffectCompletion(context.harness.env(), effect, .failed);
}

test "full request effect output aborts the unaccepted sending state" {
    var context = try TestContext.initWithMaxActive(std.testing.allocator, std.Options.debug_io, 0xbb, 0xbc, 86, 9286, 2);
    defer context.deinit();
    var storage: [1]actor_mod.ActorEffect = undefined;
    var effects = actor_mod.EffectQueue.init(&storage);

    const first = try context.harness.actor.preparePing(
        .{ .io = context.harness.io, .ingress = &context.harness.ingress },
        context.endpoint,
        &context.remote_pubkey,
        0,
        .reliable_api,
    );
    var env = context.harness.env();
    env.effects = &effects;
    try outbound.emitPrepared(&context.harness.actor, env, first);
    var second_endpoint = context.endpoint;
    second_endpoint.addr.ip4.port += 1;
    const second = try context.harness.actor.preparePing(
        .{ .io = context.harness.io, .ingress = &context.harness.ingress },
        second_endpoint,
        &context.remote_pubkey,
        0,
        .reliable_api,
    );
    const second_key = types.RequestKey.init(second_endpoint, second.requestId());

    try std.testing.expectError(
        error.TooManyActiveRequests,
        outbound.emitPrepared(&context.harness.actor, env, second),
    );

    try std.testing.expectEqual(@as(usize, 1), effects.count());
    try std.testing.expectEqual(@as(usize, 1), context.harness.actor.requests.sendingCount());
    try std.testing.expect(!context.harness.actor.requests.containsRequest(second_key));
    try std.testing.expectEqual(@as(usize, 1), context.harness.ingress.permitCount());
    const effect = effects.pop() orelse return error.MissingEffect;
    context.harness.actor.applyEffectCompletion(context.harness.env(), effect, .failed);
    try std.testing.expectEqual(@as(usize, 0), context.harness.ingress.permitCount());
}

test "queued effect enqueue abort preserves intent and releases canonical sending state" {
    var context = try TestContext.initWithMaxActive(std.testing.allocator, std.Options.debug_io, 0xd3, 0xd4, 93, 9293, 2);
    defer context.deinit();
    var storage: [1]actor_mod.ActorEffect = undefined;
    var effects = actor_mod.EffectQueue.init(&storage);
    var env = context.harness.env();
    env.effects = &effects;
    const blocker = try context.harness.actor.preparePing(
        .{ .io = context.harness.io, .ingress = &context.harness.ingress },
        context.endpoint,
        &context.remote_pubkey,
        0,
        .api,
    );
    try outbound.emitPrepared(&context.harness.actor, env, blocker);
    var queued_endpoint = context.endpoint;
    queued_endpoint.addr.ip4.port += 1;
    const queued_id = try message.ReqId.fromSlice(&.{0x44});
    var plaintext: [128]u8 = undefined;
    try context.harness.actor.requests.queue(try .init(
        .api,
        queued_endpoint,
        &context.remote_pubkey,
        queued_id,
        .ping,
        &.{},
        try (message.Ping{ .req_id = queued_id, .enr_seq = 0 }).encodeInto(&plaintext),
        std.math.maxInt(i64),
    ));

    outbound.drainEndpoint(&context.harness.actor, env, queued_endpoint);

    try std.testing.expectEqual(@as(usize, 1), context.harness.actor.requests.queuedCount());
    try std.testing.expectEqual(@as(usize, 1), context.harness.actor.requests.sendingCount());
    try std.testing.expectEqual(@as(usize, 1), context.harness.ingress.permitCount());
    try std.testing.expectEqual(queued_id, context.harness.actor.requests.firstQueued(queued_endpoint).?.req_id);
    const blocker_effect = effects.pop() orelse return error.MissingEffect;
    context.harness.actor.applyEffectCompletion(context.harness.env(), blocker_effect, .failed);

    outbound.drainEndpoint(&context.harness.actor, env, queued_endpoint);
    try std.testing.expectEqual(@as(usize, 1), effects.count());
    try std.testing.expectEqual(@as(usize, 1), context.harness.actor.requests.queuedCount());
    try std.testing.expectEqual(@as(usize, 1), context.harness.actor.requests.sendingCount());
    const queued_effect = effects.pop() orelse return error.MissingQueuedEffect;
    context.harness.actor.applyEffectCompletion(context.harness.env(), queued_effect, .failed);
    try std.testing.expectEqual(@as(usize, 1), context.harness.actor.requests.queuedCount());
    try std.testing.expectEqual(@as(usize, 0), context.harness.actor.requests.sendingCount());
    try std.testing.expectEqual(@as(usize, 0), context.harness.ingress.permitCount());
    _ = context.harness.actor.requests.takeQueued(.init(queued_endpoint, queued_id)) orelse return error.MissingQueuedIntent;
}

test "sending endpoint establishment queues a second request before send completion" {
    var context = try TestContext.initWithMaxActive(std.testing.allocator, std.Options.debug_io, 0xcb, 0xcc, 91, 9291, 2);
    defer context.deinit();

    const env = context.harness.env();
    const first = try context.harness.actor.preparePing(
        .{ .io = context.harness.io, .ingress = &context.harness.ingress },
        context.endpoint,
        &context.remote_pubkey,
        0,
        .api,
    );
    try outbound.emitPrepared(&context.harness.actor, env, first);

    const second = try context.harness.actor.preparePing(
        .{ .io = context.harness.io, .ingress = &context.harness.ingress },
        context.endpoint,
        &context.remote_pubkey,
        0,
        .api,
    );
    switch (second) {
        .queued => {},
        .send => |effect| {
            _ = context.harness.actor.requests.abortSending(effect.handle, &context.harness.ingress);
            return error.UnexpectedDuplicateEndpointEstablishment;
        },
    }

    try std.testing.expectEqual(@as(usize, 1), context.harness.effects.count());
    try std.testing.expectEqual(@as(usize, 1), context.harness.actor.requests.queuedCount());
    try std.testing.expectEqual(@as(usize, 1), context.harness.ingress.permitCount());
}

test "queued drain emits one FIFO effect per sent completion" {
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0xbb} ** 32));
    const remote_key = try secp.keyPairFromSecret(&([_]u8{0xbc} ** 32));
    const remote_pubkey = secp.compressedPubkey(&remote_key);
    const endpoint = types.Endpoint{
        .node_id = try enr.nodeIdFromCompressedPubkey(&remote_pubkey),
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 86 }, .port = 9286 } },
    };
    var harness = try ActorHarness.init(alloc, io, config.Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
        .rate_limiter = null,
        .limits = .{
            .max_active_requests = 3,
            .max_queued_requests = 3,
            .max_queued_requests_per_endpoint = 3,
            .event_capacity = 2,
            .command_capacity = 2,
        },
    });
    defer harness.deinit();
    harness.actor.sessions.put(endpoint, .{
        .initiator_key = [_]u8{0xbd} ** 16,
        .recipient_key = [_]u8{0xbe} ** 16,
    }, outbound.nowNs(io));

    const blocker_action = try harness.actor.preparePing(
        .{ .io = io, .ingress = &harness.ingress },
        endpoint,
        &remote_pubkey,
        0,
        .api,
    );
    var blocker_effect = switch (blocker_action) {
        .send => |effect| effect,
        .queued => return error.UnexpectedQueuedRequest,
    };
    const blocker_key = types.RequestKey.init(endpoint, blocker_effect.requestId());
    harness.actor.applySendCompletion(harness.env(), blocker_effect, .sent);

    const first_id = try message.ReqId.fromSlice(&.{0x31});
    const second_id = try message.ReqId.fromSlice(&.{0x32});
    var first_buffer: [128]u8 = undefined;
    var second_buffer: [128]u8 = undefined;
    try harness.actor.requests.queue(try .init(
        .api,
        endpoint,
        &remote_pubkey,
        first_id,
        .ping,
        &.{},
        try (message.Ping{ .req_id = first_id, .enr_seq = 0 }).encodeInto(&first_buffer),
        std.math.maxInt(i64),
    ));
    try harness.actor.requests.queue(try .init(
        .api,
        endpoint,
        &remote_pubkey,
        second_id,
        .ping,
        &.{},
        try (message.Ping{ .req_id = second_id, .enr_seq = 0 }).encodeInto(&second_buffer),
        std.math.maxInt(i64),
    ));

    try std.testing.expect(harness.actor.cancelRequest(harness.env(), blocker_key));
    try std.testing.expectEqual(@as(usize, 2), harness.actor.requests.queuedCount());
    try std.testing.expectEqual(@as(usize, 1), harness.effects.count());
    try std.testing.expectEqual(@as(usize, 0), harness.recording.datagrams.items.len);

    var first_effect = harness.effects.pop() orelse return error.MissingFirstDrainEffect;
    try std.testing.expectEqual(first_id, first_effect.requestId());
    harness.actor.applyEffectCompletion(harness.env(), first_effect, .sent);
    try std.testing.expectEqual(@as(usize, 1), harness.actor.requests.queuedCount());
    try std.testing.expectEqual(@as(usize, 1), harness.effects.count());

    var second_effect = harness.effects.pop() orelse return error.MissingSecondDrainEffect;
    try std.testing.expectEqual(second_id, second_effect.requestId());
    harness.actor.applyEffectCompletion(harness.env(), second_effect, .sent);
    try std.testing.expectEqual(@as(usize, 0), harness.actor.requests.queuedCount());
    try std.testing.expectEqual(@as(usize, 0), harness.effects.count());
    try std.testing.expectEqual(@as(usize, 2), harness.actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 2), harness.ingress.permitCount());
}

test "Actor tracked send helpers emit without executing transport" {
    var context = try TestContext.init(std.testing.allocator, std.Options.debug_io, 0xbf, 0xc0, 87, 9287);
    defer context.deinit();

    _ = try context.harness.actor.sendPing(
        context.harness.env(),
        context.endpoint,
        &context.remote_pubkey,
        0,
        .api,
    );
    try std.testing.expectEqual(@as(usize, 1), context.harness.effects.count());
    try std.testing.expectEqual(@as(usize, 0), context.harness.recording.datagrams.items.len);
    context.harness.failEffects();

    _ = try context.harness.actor.sendTalkRequest(
        context.harness.env(),
        context.endpoint,
        &context.remote_pubkey,
        "contract",
        "payload",
    );
    try std.testing.expectEqual(@as(usize, 1), context.harness.effects.count());
    try std.testing.expectEqual(@as(usize, 0), context.harness.recording.datagrams.items.len);
    context.harness.failEffects();
    try std.testing.expectEqual(@as(usize, 0), context.harness.ingress.permitCount());
}

test "sent TALKREQ effect activates the talk response state" {
    var context = try TestContext.init(std.testing.allocator, std.Options.debug_io, 0xb7, 0xb8, 84, 9284);
    defer context.deinit();

    const action = try context.harness.actor.prepareTalkRequest(
        .{ .io = context.harness.io, .ingress = &context.harness.ingress },
        context.endpoint,
        &context.remote_pubkey,
        "utp",
        "bounded request",
        .reliable_api,
    );
    var effect = switch (action) {
        .send => |value| value,
        .queued => return error.UnexpectedQueuedRequest,
    };
    const key = types.RequestKey.init(context.endpoint, effect.requestId());

    context.harness.actor.applySendCompletion(context.harness.env(), effect, .sent);

    const request = context.harness.actor.requests.get(key) orelse return error.MissingActiveRequest;
    try std.testing.expectEqual(request_book.Response.talkresp, request.response);
}
