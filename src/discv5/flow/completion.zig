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
    shutdown,
};

/// The sole canonical-request terminal transition. It takes indexed state first,
/// publishes the reliable terminal result, and releases admission exactly once.
/// Ordinary completion then applies owner state and drains the endpoint lane;
/// shutdown consumes ownership without starting more work.
pub fn finish(actor: *Actor, env: Env, key: types.RequestKey, outcome: Outcome, terminal: request_results.RequestTerminal) bool {
    var request = actor.requests.takeTerminal(key) orelse return false;
    const origin = request.origin();
    actor.publishRequestTerminal(env, key, request.kind(), origin, terminal);
    request.release(env.ingress);
    switch (outcome) {
        .success => |closer| actor.onRequestCompletion(env, key, origin, true, closer),
        .failure => actor.onRequestCompletion(env, key, origin, false, &.{}),
        .canceled => actor.onRequestCancellation(env, key, origin),
        .shutdown => return true,
    }
    outbound.drainEndpoint(actor, env, key.endpoint);
    return true;
}
