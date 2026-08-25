const std = @import("std");
const actor_mod = @import("../actor.zig");
const config = @import("../config.zig");
const enr = @import("../enr.zig");
const outbound = @import("../flow/outbound.zig");
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
        const local_key = try secp.keyPairFromSecret(&([_]u8{local_byte} ** 32));
        const remote_key = try secp.keyPairFromSecret(&([_]u8{remote_byte} ** 32));
        const remote_pubkey = secp.compressedPubkey(&remote_key);
        return .{
            .harness = try ActorHarness.init(alloc, io, config.Config{
                .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
                .local_key_pair = local_key,
                .rate_limiter = null,
                .limits = .{
                    .max_active_requests = 1,
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

test "outbound request effect fits within four packet budgets" {
    try std.testing.expect(@sizeOf(actor_mod.SendDatagramEffect) <= 4 * packet.MAX_PACKET_SIZE);
}

test "prepared outbound ping owns request until successful send completion" {
    var context = try TestContext.init(std.testing.allocator, std.Options.debug_io, 0xb1, 0xb2, 81, 9281);
    defer context.deinit();

    var effect = try context.preparePing();
    const key = types.RequestKey.init(context.endpoint, effect.requestId());

    try std.testing.expectEqual(@as(usize, 0), context.harness.actor.requests.activeCount());
    try std.testing.expect(context.harness.actor.requests.get(key) == null);
    try std.testing.expect(!context.harness.actor.requests.shouldQueue(context.endpoint));
    try std.testing.expectEqual(@as(usize, 1), context.harness.ingress.permitCount());
    try std.testing.expect(effect.packetBytes().len > 0);
    try std.testing.expect(effect.destination().eql(&context.endpoint.addr));

    context.harness.actor.applySendCompletion(&context.harness.ingress, effect, .sent);

    try std.testing.expectEqual(@as(usize, 1), context.harness.actor.requests.activeCount());
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

    context.harness.actor.applySendCompletion(&context.harness.ingress, effect, .failed);

    try std.testing.expectEqual(@as(usize, 0), context.harness.actor.requests.activeCount());
    try std.testing.expect(context.harness.actor.requests.get(key) == null);
    try std.testing.expect(!context.harness.actor.requests.shouldQueue(context.endpoint));
    try std.testing.expectEqual(@as(usize, 0), context.harness.ingress.permitCount());
}

test "prepared FINDNODE effect commits the nodes response state" {
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

    context.harness.actor.applySendCompletion(&context.harness.ingress, effect, .sent);

    const request = context.harness.actor.requests.get(key) orelse return error.MissingActiveRequest;
    try std.testing.expect(request.response == .nodes);
}

test "bounded request effect output owns preparation without executing transport" {
    var context = try TestContext.init(std.testing.allocator, std.Options.debug_io, 0xb9, 0xba, 85, 9285);
    defer context.deinit();
    var storage: [1]actor_mod.SendDatagramEffect = undefined;
    var effects = actor_mod.RequestEffectQueue.init(&storage);
    const action = try context.harness.actor.preparePing(
        .{ .io = context.harness.io, .ingress = &context.harness.ingress },
        context.endpoint,
        &context.remote_pubkey,
        0,
        .reliable_api,
    );

    try outbound.emitPrepared(&context.harness.actor, &context.harness.ingress, &effects, action);

    try std.testing.expectEqual(@as(usize, 1), effects.count());
    try std.testing.expectEqual(@as(usize, 0), context.harness.recording.datagrams.items.len);
    try std.testing.expectEqual(@as(usize, 1), context.harness.ingress.permitCount());
    const effect = effects.pop() orelse return error.MissingEffect;
    context.harness.actor.applySendCompletion(&context.harness.ingress, effect, .failed);
}

test "full request effect output aborts the unaccepted preparation" {
    var context = try TestContext.init(std.testing.allocator, std.Options.debug_io, 0xbb, 0xbc, 86, 9286);
    defer context.deinit();
    var storage: [1]actor_mod.SendDatagramEffect = undefined;
    var effects = actor_mod.RequestEffectQueue.init(&storage);

    const first = try context.harness.actor.preparePing(
        .{ .io = context.harness.io, .ingress = &context.harness.ingress },
        context.endpoint,
        &context.remote_pubkey,
        0,
        .reliable_api,
    );
    try outbound.emitPrepared(&context.harness.actor, &context.harness.ingress, &effects, first);
    const second = try context.harness.actor.preparePing(
        .{ .io = context.harness.io, .ingress = &context.harness.ingress },
        context.endpoint,
        &context.remote_pubkey,
        0,
        .reliable_api,
    );

    try std.testing.expectError(
        error.TooManyActiveRequests,
        outbound.emitPrepared(&context.harness.actor, &context.harness.ingress, &effects, second),
    );

    try std.testing.expectEqual(@as(usize, 1), effects.count());
    try std.testing.expectEqual(@as(usize, 1), context.harness.ingress.permitCount());
    const effect = effects.pop() orelse return error.MissingEffect;
    context.harness.actor.applySendCompletion(&context.harness.ingress, effect, .failed);
    try std.testing.expectEqual(@as(usize, 0), context.harness.ingress.permitCount());
}

test "prepared TALKREQ effect commits the talk response state" {
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

    context.harness.actor.applySendCompletion(&context.harness.ingress, effect, .sent);

    const request = context.harness.actor.requests.get(key) orelse return error.MissingActiveRequest;
    try std.testing.expectEqual(request_book.Response.talkresp, request.response);
}
