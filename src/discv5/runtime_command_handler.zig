const std = @import("std");
const actor_mod = @import("actor.zig");
const runtime_mod = @import("runtime.zig");
const types = @import("types.zig");

const RuntimeImpl = runtime_mod.RuntimeImpl;
const Command = RuntimeImpl.Command;

pub fn handle(runtime: *RuntimeImpl, command: Command) std.Io.Cancelable!void {
    const env = runtime.env();
    switch (command) {
        .inbound => |value| {
            var bytes = value.bytes;
            runtime.actor.handlePacket(env, bytes.bytes[0..bytes.len], value.from);
            runtime.admission.noteProcessed();
        },
        .maintenance => {
            if (runtime.maintenance_due.swap(false, .acq_rel)) runtime.actor.maintenance(env);
        },
        .add_node => |value| {
            defer if (value.enr) |bytes| runtime.allocator.free(bytes);
            var pubkey = value.pubkey;
            const result = runtime.actor.addNode(value.node_id, if (pubkey) |*key| key else null, value.address, value.enr, nowNs(runtime.io));
            value.reply.putOneUncancelable(runtime.io, result) catch {};
        },
        .add_enr => |value| {
            defer runtime.allocator.free(value.enr);
            value.reply.putOneUncancelable(runtime.io, runtime.actor.addEnr(&runtime.outbox, value.enr, nowNs(runtime.io))) catch {};
        },
        .set_local_enr => |value| {
            defer runtime.allocator.free(value.enr);
            try replyResult(runtime.io, value.reply, runtime.actor.setLocalEnr(env, value.enr));
        },
        .send_ping => |value| try replyResult(runtime.io, value.reply, runtime.actor.sendPing(env, value.endpoint, &value.pubkey, value.enr_seq, .api)),
        .send_findnode => |value| try replyResult(runtime.io, value.reply, runtime.actor.sendFindNode(env, value.endpoint, &value.pubkey, value.distances[0..value.distances_len], .api)),
        .send_talk_request => |value| {
            defer runtime.allocator.free(value.protocol_name);
            defer runtime.allocator.free(value.request);
            try replyResult(runtime.io, value.reply, runtime.actor.sendTalkRequest(env, value.endpoint, &value.pubkey, value.protocol_name, value.request));
        },
        .send_talk_response => |value| {
            defer runtime.allocator.free(value.response);
            try replyResult(runtime.io, value.reply, runtime.actor.sendTalkResponse(env, value.endpoint, value.req_id, value.response));
        },
        .cancel_request => |value| value.reply.putOneUncancelable(
            runtime.io,
            runtime.actor.cancelRequest(env, value.key),
        ) catch {},
        .start_lookup => |value| try replyResult(runtime.io, value.reply, runtime.actor.startLookup(env, value.target)),
        .start_random_lookup => |reply| {
            var target: types.NodeId = undefined;
            runtime.io.random(&target);
            try replyResult(runtime.io, reply, runtime.actor.startLookup(env, target));
        },
        .metrics_snapshot => |reply| {
            var snapshot = runtime.actor.metricsSnapshot(nowNs(runtime.io));
            const admission = runtime.admission.snapshot();
            snapshot.rate_limit_hit_ip = admission.rate_limit_hit_ip_total;
            snapshot.rate_limit_hit_total = admission.rate_limit_hit_total;
            snapshot.received_packet_count = admission.received_total;
            snapshot.filtered_packet_count = admission.filtered_total;
            snapshot.processed_packet_count = admission.processed_total;
            snapshot.dropped_event_count = runtime.outbox.droppedCount();
            reply.putOneUncancelable(runtime.io, snapshot) catch {};
        },
        .local_enr => |reply| reply.putOneUncancelable(runtime.io, runtime.actor.localEnr()) catch {},
        .peer_enr => |value| value.reply.putOneUncancelable(runtime.io, runtime.actor.peerEnr(&value.node_id)) catch {},
        .local_enr_seq => |reply| reply.putOneUncancelable(runtime.io, runtime.actor.localEnrSeq()) catch {},
    }
}

fn replyResult(io: std.Io, reply: anytype, result: anytype) std.Io.Cancelable!void {
    reply.putOneUncancelable(io, result) catch {};
    if (result) |_| {} else |err| if (err == error.Canceled) return error.Canceled;
}

fn nowNs(io: std.Io) i64 {
    return @intCast(std.Io.Timestamp.now(io, .real).toNanoseconds());
}
