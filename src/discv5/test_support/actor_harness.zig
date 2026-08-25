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
    effect_storage: []actor_mod.ActorEffect,
    effects: actor_mod.EffectQueue,

    pub fn init(allocator: std.mem.Allocator, io: std.Io, cfg: config.Config) !ActorHarness {
        try cfg.validate();
        var ingress = try admission.IngressAdmission.init(allocator, cfg.rate_limiter, try admission.permitCapacity(cfg.limits));
        errdefer ingress.deinit();
        var outbox = try events.EventOutbox.init(io, allocator, cfg.limits.event_capacity);
        errdefer outbox.deinit();
        var actor = try actor_mod.Actor.init(allocator, cfg);
        errdefer actor.deinit(&ingress);
        const effect_storage = try allocator.alloc(actor_mod.ActorEffect, try admission.permitCapacity(cfg.limits) + 1);
        return .{
            .allocator = allocator,
            .io = io,
            .ingress = ingress,
            .outbox = outbox,
            .actor = actor,
            .recording = .init(allocator),
            .effect_storage = effect_storage,
            .effects = .init(effect_storage),
        };
    }

    pub fn deinit(self: *ActorHarness) void {
        while (self.effects.pop()) |effect| effect.abortPreparation(&self.ingress);
        self.recording.deinit();
        self.actor.deinit(&self.ingress);
        self.outbox.deinit();
        self.ingress.deinit();
        self.allocator.free(self.effect_storage);
    }

    pub fn env(self: *ActorHarness) actor_mod.Env {
        return .{
            .io = self.io,
            .ingress = &self.ingress,
            .outbox = &self.outbox,
            .effects = &self.effects,
        };
    }

    pub fn drainEffects(self: *ActorHarness) !void {
        while (self.effects.pop()) |effect| {
            self.recording.sender().send(effect.destination(), effect.packetBytes()) catch |err| {
                self.actor.applyEffectCompletion(self.env(), effect, .failed);
                return err;
            };
            self.actor.applyEffectCompletion(self.env(), effect, .sent);
        }
    }

    pub fn drainEffectsIgnoringFailures(self: *ActorHarness) void {
        while (self.effects.pop()) |effect| {
            self.recording.sender().send(effect.destination(), effect.packetBytes()) catch {
                self.actor.applyEffectCompletion(self.env(), effect, .failed);
                continue;
            };
            self.actor.applyEffectCompletion(self.env(), effect, .sent);
        }
    }

    pub fn failEffects(self: *ActorHarness) void {
        while (self.effects.pop()) |effect| {
            self.actor.applyEffectCompletion(self.env(), effect, .failed);
        }
    }
};
