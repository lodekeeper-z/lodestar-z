const std = @import("std");
const actor_mod = @import("../actor.zig");
const events = @import("../events.zig");
const outbound = @import("outbound.zig");
const completion = @import("completion.zig");
const kbucket = @import("../kbucket.zig");
const peer_book = @import("../state/peer_book.zig");
const request_book = @import("../state/request_book.zig");
const packet = @import("../protocol/packet.zig");
const types = @import("../types.zig");

const Actor = actor_mod.Actor;
const Env = actor_mod.Env;
const MAX_REDRAIN_LANES_PER_MAINTENANCE: usize = 16;

const RetryState = struct {
    attempts: u32,
    kind: types.RequestKind,
    phase: request_book.Phase,
};

pub fn run(actor: *Actor, env: Env, now_ns: i64) void {
    actor.sessions.pruneChallenges(now_ns, env.ingress);
    actor.responses.prune(now_ns, env.ingress);
    pruneActive(actor, env, now_ns);
    pruneQueued(actor, env, now_ns);
    redrainQueued(actor, env);
    pruneLookups(actor, env.outbox, now_ns);
    var transitions: [kbucket.NUM_BUCKETS]peer_book.ConnectionEvent = undefined;
    const transition_count = actor.peers.prune(now_ns, actor.bucket_pending_timeout_ms, &transitions);
    for (transitions[0..transition_count]) |event| actor.publishConnection(env.outbox, event.node_id, event.transition);
    pingDue(actor, env, now_ns);
    actor.requests.assertInvariants();
}

fn redrainQueued(actor: *Actor, env: Env) void {
    var endpoints: [MAX_REDRAIN_LANES_PER_MAINTENANCE]types.Endpoint = undefined;
    const count = actor.requests.collectDrainable(&endpoints);
    for (endpoints[0..count]) |endpoint| outbound.drainEndpoint(actor, env, endpoint);
}

fn pruneActive(actor: *Actor, env: Env, now_ns: i64) void {
    var scan = request_book.RequestBook.ActiveScan{};
    var keys: [16]types.RequestKey = undefined;
    while (!scan.done) {
        const count = actor.requests.collectTimedOutBatch(&keys, now_ns, &scan);
        for (keys[0..count]) |key| {
            const retry: RetryState = blk: {
                const active = actor.requests.get(key) orelse continue;
                break :blk .{
                    .attempts = active.attempts,
                    .kind = active.response.kind(),
                    .phase = active.phase,
                };
            };
            if (retry.attempts < actor.request_retries) {
                retryTimedOut(actor, env, key, retry, now_ns);
                continue;
            }
            timeout(actor, env, key);
        }
    }
}

fn retryTimedOut(actor: *Actor, env: Env, key: types.RequestKey, retry: RetryState, now_ns: i64) void {
    const deadline_ns = outbound.deadlineNs(now_ns, actor.request_timeout_ms);
    switch (retry.phase) {
        .awaiting_whoareyou => |probe| {
            env.sender.send(key.endpoint.addr, probe.retry_packet.slice()) catch {
                actor.requests.commitRetry(key, deadline_ns);
                return;
            };
            outbound.noteSentRequest(actor, retry.kind);
            actor.requests.commitRetry(key, deadline_ns);
        },
        .awaiting_response => |response| {
            var buffer: [packet.MAX_PACKET_SIZE]u8 = undefined;
            const pending_write_key = if (response.wait.pendingKeys()) |keys| keys.initiator_key else null;
            const stable = if (pending_write_key == null) actor.sessions.get(key.endpoint, now_ns) else null;
            const awaiting_whoareyou = pending_write_key == null and stable == null;
            const encoded = if (pending_write_key) |write_key|
                outbound.encodeMessage(actor, env.io, &buffer, key.endpoint.node_id, &write_key, response.recovery.plaintext.slice()) catch {
                    actor.requests.commitRetry(key, deadline_ns);
                    return;
                }
            else if (stable) |session|
                outbound.encodeMessage(actor, env.io, &buffer, key.endpoint.node_id, &session.initiator_key, response.recovery.plaintext.slice()) catch {
                    actor.requests.commitRetry(key, deadline_ns);
                    return;
                }
            else
                outbound.encodeProbe(actor, env.io, &buffer, key.endpoint.node_id, response.recovery.plaintext.slice()) catch {
                    actor.requests.commitRetry(key, deadline_ns);
                    return;
                };
            actor.responses.removeExpired(key.endpoint.addr, &encoded.nonce, now_ns, env.ingress);
            if (!actor.requests.canReplaceChallenge(key, &encoded.nonce) or
                (awaiting_whoareyou and !actor.requests.canEstablish(key)) or
                actor.responses.hasLive(key.endpoint.addr, &encoded.nonce, now_ns))
            {
                actor.requests.commitRetry(key, deadline_ns);
                return;
            }
            const transition: request_book.FreshRetryTransition = if (awaiting_whoareyou)
                .{ .probe = .{
                    .retry_packet = types.PacketBytes.init(encoded.bytes) catch {
                        actor.requests.commitRetry(key, deadline_ns);
                        return;
                    },
                    .nonce = encoded.nonce,
                } }
            else
                .{ .response = encoded.nonce };
            var next_admission = env.ingress.acquire(
                key.endpoint.addr,
                @import("../admission.zig").requestPacketBudget(retry.kind),
            ) catch {
                actor.requests.commitRetry(key, deadline_ns);
                return;
            };
            env.sender.send(key.endpoint.addr, encoded.bytes) catch {
                next_admission.release(env.ingress);
                actor.requests.commitRetry(key, deadline_ns);
                return;
            };
            actor.requests.commitFreshRetry(
                key,
                transition,
                deadline_ns,
                next_admission.move(),
                env.ingress,
            );
            outbound.noteSentRequest(actor, retry.kind);
        },
    }
}

fn timeout(actor: *Actor, env: Env, key: types.RequestKey) void {
    var finished = completion.finish(actor, env, key, .failure) orelse return;
    defer finished.deinit(actor.alloc);
    env.outbox.publish(.{ .request_timeout = .{ .peer_id = key.endpoint.node_id, .req_id = key.req_id, .kind = finished.kind } });
}

fn pruneQueued(actor: *Actor, env: Env, now_ns: i64) void {
    var processed: usize = 0;
    while (processed < actor.limits.max_queued_requests) : (processed += 1) {
        const queued = actor.requests.takeOneExpiredQueued(now_ns) orelse break;
        const key = types.RequestKey.init(queued.endpoint, queued.req_id);
        actor.onRequestCompletion(env, key, queued.origin, false, &.{});
        env.outbox.publish(.{ .request_timeout = .{ .peer_id = queued.endpoint.node_id, .req_id = queued.req_id, .kind = queued.kind } });
    }
}

fn pruneLookups(actor: *Actor, outbox: *events.EventOutbox, now_ns: i64) void {
    var processed: usize = 0;
    while (processed < 1_024) : (processed += 1) {
        var timed_out: ?u32 = null;
        var iterator = actor.lookups.iterator();
        while (iterator.next()) |entry| {
            if (entry.value_ptr.isTimedOut(now_ns, actor.lookup_config)) {
                timed_out = entry.key_ptr.*;
                break;
            }
        }
        actor.finishLookup(outbox, timed_out orelse break, true);
    }
}

fn pingDue(actor: *Actor, env: Env, now_ns: i64) void {
    if (actor.ping_interval_ms == 0) return;
    for (actor.peers.routing.buckets) |*bucket| {
        var snapshots: [kbucket.K]actor_mod.ProbeSnapshot = undefined;
        var count: usize = 0;
        for (bucket.entries[0..bucket.count]) |entry| {
            if (entry.status != .connected or entry.health_request != null or entry.next_ping_at_ns > now_ns) continue;
            const known = actor.peers.known(&entry.node_id) orelse continue;
            std.debug.assert(count < snapshots.len);
            snapshots[count] = .{
                .endpoint = .{ .node_id = entry.node_id, .addr = entry.addr },
                .pubkey = known.pubkey,
            };
            count += 1;
        }
        for (snapshots[0..count]) |*snapshot| {
            _ = actor.sendProbe(
                env,
                snapshot.endpoint,
                &snapshot.pubkey,
                .health,
                .connected_only,
            ) catch continue;
            if (actor.peers.routing.getEntryMutWithPending(&snapshot.endpoint.node_id)) |current| {
                current.next_ping_at_ns = outbound.deadlineNs(now_ns, actor.ping_interval_ms);
            }
        }
    }
}
