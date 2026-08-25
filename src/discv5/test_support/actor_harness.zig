const std = @import("std");
const actor_mod = @import("../actor.zig");
const admission = @import("../admission.zig");
const config = @import("../config.zig");
const events = @import("../events.zig");
const RecordingSender = @import("recording_sender.zig").RecordingSender;

pub const ActorHarness = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    ingress: admission.IngressAdmission,
    outbox: events.EventOutbox,
    actor: actor_mod.Actor,
    recording: RecordingSender,
    request_effect_storage: []actor_mod.SendDatagramEffect,
    request_effects: actor_mod.RequestEffectQueue,

    pub fn init(allocator: std.mem.Allocator, io: std.Io, cfg: config.Config) !ActorHarness {
        try cfg.validate();
        var ingress = try admission.IngressAdmission.init(allocator, cfg.rate_limiter, try admission.permitCapacity(cfg.limits));
        errdefer ingress.deinit();
        var outbox = try events.EventOutbox.init(io, allocator, cfg.limits.event_capacity);
        errdefer outbox.deinit();
        var actor = try actor_mod.Actor.init(allocator, cfg);
        errdefer actor.deinit(&ingress);
        const request_effect_storage = try allocator.alloc(actor_mod.SendDatagramEffect, cfg.limits.max_active_requests);
        return .{
            .allocator = allocator,
            .io = io,
            .ingress = ingress,
            .outbox = outbox,
            .actor = actor,
            .recording = .init(allocator),
            .request_effect_storage = request_effect_storage,
            .request_effects = .init(request_effect_storage),
        };
    }

    pub fn deinit(self: *ActorHarness) void {
        while (self.request_effects.pop()) |effect| effect.abortPreparation(&self.ingress);
        self.recording.deinit();
        self.actor.deinit(&self.ingress);
        self.outbox.deinit();
        self.ingress.deinit();
        self.allocator.free(self.request_effect_storage);
    }

    pub fn env(self: *ActorHarness) actor_mod.Env {
        return .{
            .io = self.io,
            .sender = self.recording.sender(),
            .ingress = &self.ingress,
            .outbox = &self.outbox,
            .request_effects = &self.request_effects,
        };
    }

    pub fn drainRequestEffects(self: *ActorHarness) !void {
        while (self.request_effects.pop()) |effect| {
            self.recording.sender().send(effect.destination(), effect.packetBytes()) catch |err| {
                self.actor.applySendCompletion(self.env(), effect, .failed);
                return err;
            };
            self.actor.applySendCompletion(self.env(), effect, .sent);
        }
    }

    pub fn failRequestEffects(self: *ActorHarness) void {
        while (self.request_effects.pop()) |effect| {
            self.actor.applySendCompletion(self.env(), effect, .failed);
        }
    }
};
