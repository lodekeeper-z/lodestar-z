const std = @import("std");
const actor_mod = @import("../actor.zig");
const outbound = @import("outbound.zig");
const request_results = @import("../request_results.zig");
const types = @import("../types.zig");

const Actor = actor_mod.Actor;
const Env = actor_mod.Env;

pub const Outcome = union(enum) {
    success: []const types.NodeId,
    failure,
    canceled,
};

pub const Finished = struct {
    kind: types.RequestKind,
    nodes: ?std.ArrayListUnmanaged([]u8) = null,
    raw_nodes: ?request_results.RawEnrList = null,
    reliable: bool = false,

    pub fn takeNodes(self: *Finished) ?std.ArrayListUnmanaged([]u8) {
        const value = self.nodes;
        self.nodes = null;
        return value;
    }

    pub fn deinit(self: *Finished, alloc: std.mem.Allocator) void {
        if (self.nodes) |*nodes| {
            for (nodes.items) |bytes| alloc.free(bytes);
            nodes.deinit(alloc);
        }
        self.nodes = null;
    }
};

/// The sole active-request terminal transition. It takes indexed state first,
/// moves any owned completion payload, releases admission exactly once, applies
/// peer/lookup/health state, and only then drains the endpoint lane.
pub fn finish(actor: *Actor, env: Env, key: types.RequestKey, outcome: Outcome, terminal: request_results.RequestTerminal) ?Finished {
    var active = actor.requests.take(key) orelse return null;
    var result = Finished{
        .kind = active.response.kind(),
        .reliable = active.origin == .reliable_api,
    };
    if (active.response == .nodes) {
        result.nodes = active.response.nodes.enrs;
        result.raw_nodes = active.response.nodes.terminal_enrs;
        active.response.nodes.enrs = .empty;
    }
    actor.publishRequestTerminal(env, key, result.kind, active.origin, terminal);
    active.admission.release(env.ingress);
    switch (outcome) {
        .success => |closer| actor.onRequestCompletion(env, key, active.origin, true, closer),
        .failure => actor.onRequestCompletion(env, key, active.origin, false, &.{}),
        .canceled => actor.onRequestCancellation(env, key, active.origin),
    }
    outbound.drainEndpoint(actor, env, key.endpoint);
    active.deinit(actor.alloc);
    return result;
}
