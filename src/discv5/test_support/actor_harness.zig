const std = @import("std");
const actor_mod = @import("../actor.zig");
const admission = @import("../admission.zig");
const config = @import("../config.zig");
const events = @import("../events.zig");
const RecordingSender = @import("recording_sender.zig").RecordingSender;

pub const ActorHarness = struct {
    io: std.Io,
    ingress: admission.IngressAdmission,
    outbox: events.EventOutbox,
    actor: actor_mod.Actor,
    recording: RecordingSender,

    pub fn init(allocator: std.mem.Allocator, io: std.Io, cfg: config.Config) !ActorHarness {
        try cfg.validate();
        var ingress = try admission.IngressAdmission.init(allocator, cfg.rate_limiter, try admission.permitCapacity(cfg.limits));
        errdefer ingress.deinit();
        var outbox = try events.EventOutbox.init(io, allocator, cfg.limits.event_capacity);
        errdefer outbox.deinit();
        var actor = try actor_mod.Actor.init(allocator, cfg);
        errdefer actor.deinit(&ingress);
        return .{
            .io = io,
            .ingress = ingress,
            .outbox = outbox,
            .actor = actor,
            .recording = .init(allocator),
        };
    }

    pub fn deinit(self: *ActorHarness) void {
        self.recording.deinit();
        self.actor.deinit(&self.ingress);
        self.outbox.deinit();
        self.ingress.deinit();
    }

    pub fn env(self: *ActorHarness) actor_mod.Env {
        return .{
            .io = self.io,
            .sender = self.recording.sender(),
            .ingress = &self.ingress,
            .outbox = &self.outbox,
        };
    }
};
