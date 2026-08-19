const std = @import("std");
const actor_mod = @import("../actor.zig");
const enr = @import("../enr.zig");
const kbucket = @import("../kbucket.zig");
const message = @import("../protocol/message.zig");
const metrics = @import("../metrics.zig");
const outbound = @import("outbound.zig");
const completion = @import("completion.zig");
const request_results = @import("../request_results.zig");
const request_book = @import("../state/request_book.zig");
const types = @import("../types.zig");

const Actor = actor_mod.Actor;
const Env = actor_mod.Env;

const MAX_NODES_RESPONSE = request_book.MAX_NODES_RESPONSE;
const MAX_ENRS_PER_PACKET: usize = @max((@import("../protocol/packet.zig").MAX_PACKET_SIZE - 92) / enr.MAX_ENR_SIZE, 1);
const MAX_RESPONSE_CHUNKS: usize = std.math.divCeil(usize, MAX_NODES_RESPONSE, MAX_ENRS_PER_PACKET) catch unreachable;

pub fn dispatch(actor: *Actor, env: Env, plaintext: []const u8, endpoint: types.Endpoint) void {
    if (plaintext.len == 0) return;
    switch (plaintext[0]) {
        message.MSG_PING => handlePing(actor, env, plaintext, endpoint),
        message.MSG_PONG => handlePong(actor, env, plaintext, endpoint),
        message.MSG_FINDNODE => handleFindNode(actor, env, plaintext, endpoint),
        message.MSG_NODES => handleNodes(actor, env, plaintext, endpoint),
        message.MSG_TALKREQ => handleTalkReq(actor, env, plaintext, endpoint),
        message.MSG_TALKRESP => handleTalkResp(actor, env, plaintext, endpoint),
        else => {},
    }
}

fn handlePing(actor: *Actor, env: Env, plaintext: []const u8, endpoint: types.Endpoint) void {
    const ping = message.Ping.decode(plaintext) catch return;
    noteReceived(actor, plaintext);
    actor.maybeRequestEnrUpdate(env, endpoint, ping.enr_seq);
    const pong = message.Pong{
        .req_id = ping.req_id,
        .enr_seq = actor.local.seq,
        .recipient_ip = switch (endpoint.addr) {
            .ip4 => |ip4| .{ .ip4 = ip4.bytes },
            .ip6 => |ip6| .{ .ip6 = ip6.bytes },
        },
        .recipient_port = endpoint.addr.getPort(),
    };
    var buffer: [128]u8 = undefined;
    const encoded = pong.encodeInto(&buffer) catch return;
    outbound.sendResponse(actor, env, endpoint, encoded) catch {};
}

fn handlePong(actor: *Actor, env: Env, plaintext: []const u8, endpoint: types.Endpoint) void {
    const pong = message.Pong.decode(plaintext) catch return;
    noteReceived(actor, plaintext);
    const key = types.RequestKey.init(endpoint, pong.req_id);
    const request = actor.requests.get(key) orelse return;
    if (request.response != .pong) return;
    var finished = completion.finish(actor, env, key, .{ .success = &.{} }, .{ .pong = .{
        .enr_seq = pong.enr_seq,
        .recipient_ip = pong.recipient_ip,
        .recipient_port = pong.recipient_port,
    } }) orelse return;
    defer finished.deinit(actor.alloc);
    actor.observeAddressVote(env, endpoint.addr, recipientAddress(pong.recipient_ip, pong.recipient_port));
    actor.maybeRequestEnrUpdate(env, endpoint, pong.enr_seq);
    env.outbox.publish(.{ .pong = .{
        .peer_id = endpoint.node_id,
        .peer_addr = endpoint.addr,
        .req_id = pong.req_id,
        .enr_seq = pong.enr_seq,
        .recipient_ip = pong.recipient_ip,
        .recipient_port = pong.recipient_port,
    } });
}

fn handleFindNode(actor: *Actor, env: Env, plaintext: []const u8, endpoint: types.Endpoint) void {
    var distance_buffer: [127]u16 = undefined;
    const findnode = message.FindNode.decodeInto(plaintext, &distance_buffer) catch return;
    noteReceived(actor, plaintext);
    var seen = [_]bool{false} ** 257;
    var references_buffer: [MAX_NODES_RESPONSE][]const u8 = undefined;
    var references = std.ArrayListUnmanaged([]const u8).initBuffer(&references_buffer);
    for (findnode.distances) |distance| {
        if (distance > 256 or seen[distance]) continue;
        seen[distance] = true;
        if (distance == 0) {
            if (references.items.len < references.capacity) if (actor.local.raw) |*raw| references.appendAssumeCapacity(raw.slice());
            continue;
        }
        for (actor.peers.routing.getBucket(@intCast(distance - 1))) |*entry| {
            const raw = entry.relayableEnr() orelse continue;
            if (references.items.len == references.capacity) break;
            references.appendAssumeCapacity(raw);
        }
        if (references.items.len == references.capacity) break;
    }
    const total: u64 = @max(@as(u64, @intCast(std.math.divCeil(usize, references.items.len, MAX_ENRS_PER_PACKET) catch 1)), 1);
    var index: usize = 0;
    while (index < total and index < MAX_RESPONSE_CHUNKS) : (index += 1) {
        const start = index * MAX_ENRS_PER_PACKET;
        const end = @min(start + MAX_ENRS_PER_PACKET, references.items.len);
        const nodes = message.Nodes{ .req_id = findnode.req_id, .total = total, .enrs = references.items[start..end] };
        var buffer: [@import("../protocol/packet.zig").MAX_PACKET_SIZE]u8 = undefined;
        const encoded = nodes.encodeInto(&buffer) catch return;
        outbound.sendResponse(actor, env, endpoint, encoded) catch return;
    }
}

fn handleNodes(actor: *Actor, env: Env, plaintext: []const u8, endpoint: types.Endpoint) void {
    var enr_buffer: [MAX_NODES_RESPONSE][]const u8 = undefined;
    const nodes = message.Nodes.decodeInto(plaintext, &enr_buffer) catch return;
    if (nodes.total == 0 or nodes.total > MAX_NODES_RESPONSE) return;
    noteReceived(actor, plaintext);
    const key = types.RequestKey.init(endpoint, nodes.req_id);
    const active = actor.requests.get(key) orelse return;
    if (active.response != .nodes) return;
    const accumulator = &active.response.nodes;
    const total = nodes.total;
    if (accumulator.total_responses) |expected| {
        if (expected != total) return;
    } else {
        accumulator.total_responses = total;
    }
    var discovered: [MAX_NODES_RESPONSE]enr.ValidatedEnr = undefined;
    const discovered_len = retainNodes(actor, env, active, nodes.enrs, &endpoint.node_id, &discovered);
    accumulator.responses_received += 1;
    if (accumulator.responses_received < accumulator.total_responses.?) {
        for (discovered[0..discovered_len]) |*validated| actor.publishValidatedDiscovered(env.outbox, validated);
        return;
    }

    var closer: [MAX_NODES_RESPONSE]types.NodeId = undefined;
    const closer_len = closerNodeIds(actor, accumulator.validated_enrs.slice(), &closer);
    const terminal_nodes = request_results.RawEnrList.fromValidated(accumulator.validated_enrs.slice());
    var finished = completion.finish(
        actor,
        env,
        key,
        .{ .success = closer[0..closer_len] },
        .{ .nodes = terminal_nodes },
    ) orelse return;
    defer finished.deinit(actor.alloc);
    var event_enrs = finished.takeNodes() orelse unreachable;
    if (finished.reliable) {
        std.debug.assert(event_enrs.items.len == 0);
        const raw_nodes = finished.raw_nodes orelse unreachable;
        event_enrs.ensureTotalCapacityPrecise(actor.alloc, raw_nodes.slice().len) catch {
            env.outbox.notePayloadDrop();
            return;
        };
        for (raw_nodes.slice()) |*raw| {
            const copy = actor.alloc.dupe(u8, raw.slice()) catch {
                env.outbox.notePayloadDrop();
                continue;
            };
            event_enrs.appendAssumeCapacity(copy);
        }
    }
    for (discovered[0..discovered_len]) |*validated| actor.publishValidatedDiscovered(env.outbox, validated);
    env.outbox.publish(.{ .nodes = .{
        .peer_id = endpoint.node_id,
        .peer_addr = endpoint.addr,
        .req_id = nodes.req_id,
        .enrs = event_enrs,
    } });
}

fn retainNodes(
    actor: *Actor,
    env: Env,
    active: *request_book.ActiveRequest,
    returned_enrs: []const []const u8,
    responder: *const types.NodeId,
    discovered: *[MAX_NODES_RESPONSE]enr.ValidatedEnr,
) usize {
    std.debug.assert(active.response == .nodes);
    std.debug.assert(returned_enrs.len <= MAX_NODES_RESPONSE);
    const accumulator = &active.response.nodes;
    var discovered_len: usize = 0;
    for (returned_enrs) |raw| {
        if (accumulator.validated_enrs.slice().len >= MAX_NODES_RESPONSE) break;
        const validated = enr.ValidatedEnr.init(raw) catch continue;
        if (!matchesDistances(&validated.node_id, responder, accumulator)) continue;
        if (actor.learnValidatedDiscovered(&validated, outbound.nowNs(env.io)) != null and discovered_len < discovered.len) {
            discovered[discovered_len] = validated;
            discovered_len += 1;
        }
        accumulator.validated_enrs.append(validated);
        if (active.origin == .reliable_api) continue;
        const copy = actor.alloc.dupe(u8, validated.raw.slice()) catch {
            env.outbox.notePayloadDrop();
            continue;
        };
        accumulator.enrs.appendAssumeCapacity(copy);
    }
    return discovered_len;
}

fn closerNodeIds(actor: *const Actor, validated_enrs: []const enr.ValidatedEnr, closer: *[MAX_NODES_RESPONSE]types.NodeId) usize {
    std.debug.assert(validated_enrs.len <= MAX_NODES_RESPONSE);
    var closer_len: usize = 0;
    for (validated_enrs) |*validated| {
        const node_id = actor.validatedDiscoveredNodeId(validated) orelse continue;
        closer[closer_len] = node_id;
        closer_len += 1;
    }
    return closer_len;
}

fn handleTalkReq(actor: *Actor, env: Env, plaintext: []const u8, endpoint: types.Endpoint) void {
    const request = message.TalkReq.decode(plaintext) catch return;
    noteReceived(actor, plaintext);
    const protocol_copy = actor.alloc.dupe(u8, request.protocol) catch {
        env.outbox.notePayloadDrop();
        return;
    };
    const request_copy = actor.alloc.dupe(u8, request.request) catch {
        actor.alloc.free(protocol_copy);
        env.outbox.notePayloadDrop();
        return;
    };
    env.outbox.publish(.{ .talkreq = .{
        .peer_id = endpoint.node_id,
        .peer_addr = endpoint.addr,
        .req_id = request.req_id,
        .protocol = protocol_copy,
        .request = request_copy,
    } });
}

fn handleTalkResp(actor: *Actor, env: Env, plaintext: []const u8, endpoint: types.Endpoint) void {
    const response = message.TalkResp.decode(plaintext) catch return;
    noteReceived(actor, plaintext);
    const key = types.RequestKey.init(endpoint, response.req_id);
    const request = actor.requests.get(key) orelse return;
    if (request.response != .talkresp) return;
    var finished = completion.finish(
        actor,
        env,
        key,
        .{ .success = &.{} },
        .{ .talk_response = types.PacketBytes.init(response.response) catch unreachable },
    ) orelse return;
    defer finished.deinit(actor.alloc);
    const copy = actor.alloc.dupe(u8, response.response) catch {
        env.outbox.notePayloadDrop();
        return;
    };
    env.outbox.publish(.{ .talkresp = .{
        .peer_id = endpoint.node_id,
        .peer_addr = endpoint.addr,
        .req_id = response.req_id,
        .response = copy,
    } });
}

fn matchesDistances(node_id: *const types.NodeId, responder: *const types.NodeId, accumulator: *const request_book.NodesAccumulator) bool {
    const distance: u16 = if (kbucket.logDistance(node_id, responder)) |value| @as(u16, value) + 1 else 0;
    return accumulator.requested_distances.contains(distance);
}

fn recipientAddress(ip: message.Pong.RecipientIp, port: u16) types.Address {
    return switch (ip) {
        .ip4 => |bytes| .{ .ip4 = .{ .bytes = bytes, .port = port } },
        .ip6 => |bytes| .{ .ip6 = .{ .bytes = bytes, .port = port } },
    };
}

fn noteReceived(actor: *Actor, plaintext: []const u8) void {
    if (metrics.MessageType.fromByte(plaintext[0])) |kind| actor.metrics.incReceived(kind);
}
