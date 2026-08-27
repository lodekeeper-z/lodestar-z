const std = @import("std");
const actor_mod = @import("../actor.zig");
const config = @import("../config.zig");
const enr = @import("../enr.zig");
const peer_store = @import("../state/peer_store.zig");
const message = @import("../protocol/message.zig");
const metrics = @import("../metrics.zig");
const outbound = @import("outbound.zig");
const completion = @import("completion.zig");
const lookup = @import("../service/lookup.zig");
const request_results = @import("../request_results.zig");
const request_book = @import("../state/request_book.zig");
const public_api = @import("../public_api.zig");
const types = @import("../types.zig");

const Actor = actor_mod.Actor;
const Env = actor_mod.Env;

const MAX_NODES_RESPONSE = request_book.MAX_NODES_RESPONSE;
const MAX_ENRS_PER_PACKET = config.MAX_ENRS_PER_NODES_PACKET;
const MAX_RESPONSE_CHUNKS = config.MAX_NODES_RESPONSE_CHUNKS;

pub fn dispatch(actor: *Actor, env: Env, decoded: *const message.DecodedMessage, endpoint: types.Endpoint) void {
    switch (decoded.*) {
        .ping => |*ping| handlePing(actor, env, ping, endpoint),
        .pong => |*pong| handlePong(actor, env, pong, endpoint),
        .findnode => |*findnode| handleFindNode(actor, env, findnode, endpoint),
        .nodes => |*nodes| handleNodes(actor, env, nodes, endpoint),
        .talkreq => |*request| handleTalkReq(actor, env, request, endpoint),
        .talkresp => |*response| handleTalkResp(actor, env, response, endpoint),
    }
}

pub fn isExpectedResponse(actor: *Actor, decoded: *const message.DecodedMessage, endpoint: types.Endpoint) bool {
    switch (decoded.*) {
        .pong => |pong| {
            const active = actor.requests.get(.init(endpoint, pong.req_id)) orelse return false;
            return active.response == .pong;
        },
        .nodes => |nodes| {
            if (nodes.total == 0 or nodes.total > MAX_NODES_RESPONSE) return false;
            const active = actor.requests.get(.init(endpoint, nodes.req_id)) orelse return false;
            if (active.response != .nodes) return false;
            if (active.response.nodes.total_responses) |expected| return expected == nodes.total;
            return true;
        },
        .talkresp => |response| {
            const active = actor.requests.get(.init(endpoint, response.req_id)) orelse return false;
            return active.response == .talkresp;
        },
        else => return false,
    }
}

fn handlePing(actor: *Actor, env: Env, ping: *const message.Ping, endpoint: types.Endpoint) void {
    noteReceived(actor, message.MSG_PING);
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

fn handlePong(actor: *Actor, env: Env, pong: *const message.Pong, endpoint: types.Endpoint) void {
    noteReceived(actor, message.MSG_PONG);
    const key = types.RequestKey.init(endpoint, pong.req_id);
    const request = actor.requests.get(key) orelse return;
    if (request.response != .pong) return;
    if (!completion.finish(actor, env, key, .{ .success = &.{} }, .{ .pong = .{
        .enr_seq = pong.enr_seq,
        .recipient_ip = pong.recipient_ip,
        .recipient_port = pong.recipient_port,
    } })) return;
    actor.observeAddressVote(env, endpoint.addr, recipientAddress(pong.recipient_ip, pong.recipient_port));
    actor.maybeRequestEnrUpdate(env, endpoint, pong.enr_seq);
}

fn handleFindNode(actor: *Actor, env: Env, findnode: *const message.DecodedFindNode, endpoint: types.Endpoint) void {
    noteReceived(actor, message.MSG_FINDNODE);
    var seen = [_]bool{false} ** 257;
    var references_buffer: [MAX_NODES_RESPONSE][]const u8 = undefined;
    var references = std.ArrayListUnmanaged([]const u8).initBuffer(&references_buffer);
    var retained_enrs: [MAX_NODES_RESPONSE]enr.RawEnr = undefined;
    for (findnode.distancesSlice()) |distance| {
        if (distance > 256 or seen[distance]) continue;
        seen[distance] = true;
        if (distance == 0) {
            if (references.items.len < references.capacity) if (actor.local.raw) |*raw| references.appendAssumeCapacity(raw.slice());
            continue;
        }
        const retained = actor.peers.collectBucketRelayable(
            @intCast(distance - 1),
            retained_enrs[references.items.len..],
        );
        for (retained_enrs[references.items.len .. references.items.len + retained]) |*raw| {
            references.appendAssumeCapacity(raw.slice());
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

fn handleNodes(actor: *Actor, env: Env, nodes: *const message.DecodedNodes, endpoint: types.Endpoint) void {
    if (nodes.total == 0 or nodes.total > MAX_NODES_RESPONSE) return;
    noteReceived(actor, message.MSG_NODES);
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
    const discovered_len = retainNodes(actor, env, active, nodes.enrsSlice(), &endpoint.node_id, &discovered);
    accumulator.responses_received += 1;
    if (accumulator.responses_received < accumulator.total_responses.?) {
        for (discovered[0..discovered_len]) |*validated| actor.publishValidatedDiscovered(env.outbox, validated);
        return;
    }

    var closer: [MAX_NODES_RESPONSE]lookup.Candidate = undefined;
    const closer_len = closerCandidates(actor, accumulator.validated_enrs.slice(), &closer);
    const terminal_nodes = request_results.RawEnrList.fromValidated(accumulator.validated_enrs.slice());
    if (!completion.finish(
        actor,
        env,
        key,
        .{ .success = closer[0..closer_len] },
        .{ .nodes = terminal_nodes },
    )) return;
    for (discovered[0..discovered_len]) |*validated| actor.publishValidatedDiscovered(env.outbox, validated);
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
    }
    return discovered_len;
}

fn closerCandidates(actor: *const Actor, validated_enrs: []const enr.ValidatedEnr, closer: *[MAX_NODES_RESPONSE]lookup.Candidate) usize {
    std.debug.assert(validated_enrs.len <= MAX_NODES_RESPONSE);
    var closer_len: usize = 0;
    for (validated_enrs) |*validated| {
        if (std.mem.eql(u8, &validated.node_id, &actor.local_node_id)) continue;
        if (actor.peers.routeWithPending(&validated.node_id)) |route| {
            if (route.enr_seq >= validated.parsed.seq) {
                if (route.enr) |raw| {
                    closer[closer_len] = .{
                        .node_id = route.node_id,
                        .pubkey = route.pubkey,
                        .addr = route.addr,
                        .raw = raw,
                        .seq = route.enr_seq,
                    };
                    closer_len += 1;
                    continue;
                }
            }
        }
        const address = actor.peers.addressForEnr(&validated.parsed) orelse continue;
        closer[closer_len] = .fromValidated(validated, address);
        closer_len += 1;
    }
    return closer_len;
}

fn handleTalkReq(actor: *Actor, env: Env, request: *const message.TalkReq, endpoint: types.Endpoint) void {
    noteReceived(actor, message.MSG_TALKREQ);
    const protocol_copy = actor.alloc.dupe(u8, request.protocol) catch {
        env.outbox.notePayloadDrop(.talk_req_received);
        return;
    };
    const request_copy = actor.alloc.dupe(u8, request.request) catch {
        actor.alloc.free(protocol_copy);
        env.outbox.notePayloadDrop(.talk_req_received);
        return;
    };
    env.outbox.publish(.{ .talkreq = .{
        .peer_id = endpoint.node_id,
        .peer_addr = endpoint.addr,
        .req_id = public_api.requestIdFromWire(request.req_id),
        .protocol = protocol_copy,
        .request = request_copy,
    } });
}

fn handleTalkResp(actor: *Actor, env: Env, response: *const message.TalkResp, endpoint: types.Endpoint) void {
    noteReceived(actor, message.MSG_TALKRESP);
    const key = types.RequestKey.init(endpoint, response.req_id);
    const request = actor.requests.get(key) orelse return;
    if (request.response != .talkresp) return;
    if (!completion.finish(
        actor,
        env,
        key,
        .{ .success = &.{} },
        .{ .talk_response = types.PacketBytes.init(response.response) catch unreachable },
    )) return;
}

fn matchesDistances(node_id: *const types.NodeId, responder: *const types.NodeId, accumulator: *const request_book.NodesAccumulator) bool {
    const distance: u16 = if (peer_store.logDistance(node_id, responder)) |value| @as(u16, value) + 1 else 0;
    return accumulator.requested_distances.contains(distance);
}

fn recipientAddress(ip: message.Pong.RecipientIp, port: u16) types.Address {
    return switch (ip) {
        .ip4 => |bytes| .{ .ip4 = .{ .bytes = bytes, .port = port } },
        .ip6 => |bytes| .{ .ip6 = .{ .bytes = bytes, .port = port } },
    };
}

fn noteReceived(actor: *Actor, message_type: u8) void {
    if (metrics.MessageType.fromByte(message_type)) |kind| actor.metrics.incReceived(kind);
}
