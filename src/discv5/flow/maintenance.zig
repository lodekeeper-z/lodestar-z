const std = @import("std");
const actor_mod = @import("../actor.zig");
const config = @import("../config.zig");
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
    // Stable-session expiry is maintenance-owned. Metrics report the stored
    // session state left by the most recent completed maintenance pass.
    actor.sessions.pruneSessions(now_ns);
    actor.sessions.pruneChallenges(now_ns, env.ingress);
    actor.responses.prune(now_ns, env.ingress);
    pruneActive(actor, env, now_ns);
    pruneQueued(actor, env, now_ns);
    redrainQueued(actor, env);
    pruneLookups(actor, env, now_ns);
    actor.repumpLookups(env);
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
    _ = completion.finish(actor, env, key, .failure, .timeout);
}

fn pruneQueued(actor: *Actor, env: Env, now_ns: i64) void {
    var scan = request_book.RequestBook.QueuedScan{};
    var keys: [config.MAX_QUEUED_PER_ENDPOINT]types.RequestKey = undefined;
    while (!scan.done) {
        const count = actor.requests.collectExpiredQueuedBatch(&keys, now_ns, &scan);
        for (keys[0..count]) |key| {
            const queued = actor.requests.takeQueued(key) orelse unreachable;
            actor.publishRequestTerminal(env, key, queued.kind, queued.origin, .timeout);
            actor.onRequestCompletion(env, key, queued.origin, false, &.{});
        }
    }
}

fn pruneLookups(actor: *Actor, env: Env, now_ns: i64) void {
    var timed_out: [actor_mod.MAX_LOOKUPS]u32 = undefined;
    const count = blk: {
        var count: usize = 0;
        var iterator = actor.lookups.iterator();
        while (iterator.next()) |entry| {
            if (!entry.value_ptr.isTimedOut(now_ns, actor.lookup_config)) continue;
            std.debug.assert(count < timed_out.len);
            timed_out[count] = entry.key_ptr.*;
            count += 1;
        }
        break :blk count;
    };
    for (timed_out[0..count]) |lookup_id| actor.finishLookup(env, lookup_id, .timed_out);
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
        }
    }
}
