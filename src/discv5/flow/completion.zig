const actor_mod = @import("../actor.zig");
const lookup = @import("../service/lookup.zig");
const outbound = @import("outbound.zig");
const request_results = @import("../request_results.zig");
const types = @import("../types.zig");

const Actor = actor_mod.Actor;
const Env = actor_mod.Env;

pub const Outcome = union(enum) {
    success: []const lookup.Candidate,
    failure,
    canceled,
};

/// The sole active-request terminal transition. It takes indexed state first,
/// publishes the reliable terminal result, releases admission exactly once,
/// applies peer/lookup/health state, and only then drains the endpoint lane.
pub fn finish(actor: *Actor, env: Env, key: types.RequestKey, outcome: Outcome, terminal: request_results.RequestTerminal) bool {
    var active = actor.requests.take(key) orelse return false;
    actor.publishRequestTerminal(env, key, active.response.kind(), active.origin, terminal);
    active.admission.release(env.ingress);
    switch (outcome) {
        .success => |closer| actor.onRequestCompletion(env, key, active.origin, true, closer),
        .failure => actor.onRequestCompletion(env, key, active.origin, false, &.{}),
        .canceled => actor.onRequestCancellation(env, key, active.origin),
    }
    outbound.drainEndpoint(actor, env, key.endpoint);
    return true;
}
