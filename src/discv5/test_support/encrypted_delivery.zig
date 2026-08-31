const std = @import("std");
const actor_mod = @import("../actor.zig");
const admission = @import("../admission.zig");
const events = @import("../events.zig");
const packet = @import("../protocol/packet.zig");
const transport = @import("../transport.zig");
const types = @import("../types.zig");

pub fn deliverEncrypted(
    actor: *actor_mod.Actor,
    io: std.Io,
    sender: transport.Sender,
    ingress: *admission.IngressAdmission,
    outbox: *events.EventOutbox,
    endpoint: types.Endpoint,
    read_key: *const [16]u8,
    plaintext: []const u8,
    nonce_byte: u8,
) !void {
    var storage: [32]actor_mod.ActorEffect = undefined;
    var effects = actor_mod.EffectQueue.init(&storage);
    const env = actor_mod.Env{ .io = io, .ingress = ingress, .outbox = outbox, .effects = &effects };
    try deliverEncryptedWithEnv(
        actor,
        env,
        endpoint,
        read_key,
        plaintext,
        nonce_byte,
    );
    while (effects.pop()) |effect| {
        sender.send(effect.destination(), effect.packetBytes()) catch |err| {
            actor.applyEffectCompletion(env, effect, .failed);
            return err;
        };
        actor.applyEffectCompletion(env, effect, .sent);
    }
}

pub fn deliverEncryptedWithEnv(
    actor: *actor_mod.Actor,
    env: actor_mod.Env,
    endpoint: types.Endpoint,
    read_key: *const [16]u8,
    plaintext: []const u8,
    nonce_byte: u8,
) !void {
    var buffer: [packet.MAX_PACKET_SIZE]u8 = undefined;
    var masking_iv = [_]u8{0x61} ** packet.MASKING_IV_SIZE;
    masking_iv[0] = nonce_byte;
    const nonce = [_]u8{nonce_byte} ** packet.NONCE_SIZE;
    const encoded = try packet.encodeMessagePacketInto(&buffer, .{
        .kind = .ordinary,
        .masking_iv = &masking_iv,
        .recipient_node_id = &actor.local_node_id,
        .nonce = &nonce,
        .authdata = &endpoint.node_id,
        .write_key = read_key,
        .plaintext = plaintext,
    });
    actor.handlePacket(env, encoded, endpoint.addr);
}
