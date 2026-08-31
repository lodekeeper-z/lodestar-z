const actor_mod = @import("../actor.zig");
const admission = @import("../admission.zig");
const types = @import("../types.zig");
const RecordingSender = @import("recording_sender.zig").RecordingSender;

pub const PacketLink = struct {
    source: *const RecordingSender,
    expected_destination: types.Address,
    source_address: types.Address,
    destination: *actor_mod.Actor,
    destination_env: actor_mod.Env,
    executor: *RecordingSender,
    next_index: usize = 0,

    pub fn init(
        source: *const RecordingSender,
        expected_destination: types.Address,
        source_address: types.Address,
        destination: *actor_mod.Actor,
        destination_env: actor_mod.Env,
        executor: *RecordingSender,
    ) PacketLink {
        return .{
            .source = source,
            .expected_destination = expected_destination,
            .source_address = source_address,
            .destination = destination,
            .destination_env = destination_env,
            .executor = executor,
        };
    }

    pub fn deliverNext(self: *PacketLink) !void {
        try self.deliverNextFrom(self.source_address);
    }

    pub fn deliverNextExpected(self: *PacketLink, credit: *admission.ExpectedCredit) !void {
        const index = try self.snapshotNext();
        var env = self.destination_env;
        env.expected_credit = credit;
        var fallback_storage: [32]actor_mod.ActorEffect = undefined;
        var fallback_effects = actor_mod.EffectQueue.init(&fallback_storage);
        if (env.effects == null) env.effects = &fallback_effects;
        var bytes = (try self.packetBytes(index)).*;
        self.destination.handlePacket(env, bytes.bytes[0..bytes.len], self.source_address);
        try self.drainEffects(env);
        self.next_index += 1;
    }

    pub fn deliverNextFrom(self: *PacketLink, source_address: types.Address) !void {
        const index = try self.snapshotNext();
        try self.replayFrom(index, source_address);
        self.next_index += 1;
    }

    pub fn dropNext(self: *PacketLink) !void {
        _ = try self.snapshotNext();
        self.next_index += 1;
    }

    pub fn snapshotNext(self: *const PacketLink) !usize {
        _ = try self.packetBytes(self.next_index);
        return self.next_index;
    }

    pub fn replay(self: *const PacketLink, index: usize) !void {
        try self.replayFrom(index, self.source_address);
    }

    pub fn replayFrom(self: *const PacketLink, index: usize, source_address: types.Address) !void {
        var bytes = (try self.packetBytes(index)).*;
        var env = self.destination_env;
        var fallback_storage: [32]actor_mod.ActorEffect = undefined;
        var fallback_effects = actor_mod.EffectQueue.init(&fallback_storage);
        if (env.effects == null) env.effects = &fallback_effects;
        self.destination.handlePacket(
            env,
            bytes.bytes[0..bytes.len],
            source_address,
        );
        try self.drainEffects(env);
    }

    fn drainEffects(self: *const PacketLink, env: actor_mod.Env) !void {
        const effects = env.effects orelse return;
        while (effects.pop()) |effect| {
            self.executor.sender().send(effect.destination(), effect.packetBytes()) catch |err| {
                self.destination.applyEffectCompletion(env, effect, .failed);
                return err;
            };
            self.destination.applyEffectCompletion(env, effect, .sent);
        }
    }

    fn packetBytes(self: *const PacketLink, index: usize) !*const types.PacketBytes {
        if (index >= self.source.datagrams.items.len) return error.NoPacketToDeliver;
        const datagram = &self.source.datagrams.items[index];
        if (!datagram.address.eql(&self.expected_destination)) return error.UnexpectedPacketDestination;
        return &datagram.bytes;
    }
};
