const std = @import("std");
const admission = @import("admission.zig");
const actor_mod = @import("actor.zig");
const message = @import("protocol/message.zig");
const public_api = @import("public_api.zig");
const response_book = @import("state/response_book.zig");
const session_book = @import("state/session_book.zig");
const runtime_error = @import("runtime_error.zig");
const transport = @import("transport.zig");
const types = @import("types.zig");

pub fn Hooks(comptime Runtime: type, comptime RuntimeImpl: type, comptime shutdown: anytype, comptime receive_backoff: anytype) type {
    return if (@import("builtin").is_test) struct {
        pub const CommandGate = struct {
            entered: std.atomic.Value(bool) = .init(false),
            proceed: std.atomic.Value(bool) = .init(false),
        };
        pub const CancellationGate = struct {
            queue: std.Io.Queue(u8),
            buffer: [1]u8 = undefined,
            entered: std.atomic.Value(bool) = .init(false),
            cancellation_observed: std.atomic.Value(bool) = .init(false),

            pub fn init(self: *CancellationGate) void {
                self.* = .{ .queue = undefined };
                self.queue = .init(&self.buffer);
            }

            pub fn release(self: *CancellationGate, io: std.Io) void {
                if (self.cancellation_observed.load(.acquire)) return;
                self.queue.putOneUncancelable(io, 0) catch unreachable;
            }
        };
        pub const EnrAdmissionResult = runtime_error.EnrAdmissionError!bool;
        pub const EnrAdmissionReply = std.Io.Queue(EnrAdmissionResult);
        pub const PingResult = runtime_error.RequestError!public_api.RequestHandle;
        pub const PingReply = std.Io.Queue(PingResult);

        pub fn actorLoop(runtime: *Runtime) std.Io.Cancelable!void {
            const storage = impl(runtime);
            defer shutdown(storage);
            return storage.actorLoop();
        }

        pub fn enqueueAddEnr(runtime: *Runtime, bytes: []u8, reply: *EnrAdmissionReply) !void {
            const storage = impl(runtime);
            errdefer storage.allocator.free(bytes);
            try storage.enqueueCommand(.{ .add_enr = .{ .enr = bytes, .reply = reply } });
        }

        pub fn enqueueSendPing(runtime: *Runtime, endpoint: types.Endpoint, pubkey: [33]u8, reply: *PingReply) !void {
            const storage = impl(runtime);
            if (!storage.actor.addNode(endpoint.node_id, &pubkey, endpoint.addr, null, 0)) return error.InvalidPeer;
            if (!storage.request_result_outbox.reserve()) return error.RequestResultCapacityExceeded;
            var reservation_transferred = false;
            errdefer if (!reservation_transferred) storage.request_result_outbox.cancelUnclaimed();
            try storage.enqueueCommand(.{ .send_ping = .{
                .node_id = endpoint.node_id,
                .origin = .reliable_api,
                .reply = reply,
            } });
            reservation_transferred = true;
        }

        pub fn putMaintenance(runtime: *Runtime) !void {
            try impl(runtime).requestMaintenanceWake();
        }

        pub fn enqueueStaleMaintenance(runtime: *Runtime) !void {
            try impl(runtime).enqueueCommand(.maintenance);
        }

        pub fn setCommandGate(runtime: *Runtime, gate: ?*CommandGate) void {
            impl(runtime).test_command_gate = gate;
        }

        pub fn setCancellationGate(runtime: *Runtime, gate: ?*CancellationGate) void {
            impl(runtime).test_cancellation_gate = gate;
        }

        pub fn setSendGate(runtime: *Runtime, gate: ?*transport.Testing.SendGate) void {
            transport.Testing.setSendGate(&impl(runtime).transport, gate);
        }

        pub fn effectCapacity(runtime: *Runtime) usize {
            return impl(runtime).effect_storage.len;
        }

        pub fn enqueuePingEffect(
            runtime: *Runtime,
            endpoint: types.Endpoint,
            pubkey: [33]u8,
        ) !public_api.RequestHandle {
            const storage = impl(runtime);
            var action = try actor_mod.Testing.preparePingResolvedForTest(
                &storage.actor,
                .{ .io = storage.io, .ingress = &storage.admission },
                endpoint,
                &pubkey,
                .api,
            );
            const handle = public_api.handleFromInternal(action.handle());
            switch (action) {
                .send => |effect| try storage.effects.push(.{ .request = effect }),
                .queued => unreachable,
            }
            return handle;
        }

        pub fn addConnectedNode(
            runtime: *Runtime,
            node_id: types.NodeId,
            pubkey: [33]u8,
            address: types.Address,
            raw_enr: []const u8,
        ) bool {
            const storage = impl(runtime);
            if (!storage.actor.addNode(node_id, &pubkey, address, raw_enr, 0)) return false;
            _ = storage.actor.peers.markResponsive(node_id, address, 0, null);
            return true;
        }

        pub fn knowsNode(runtime: *Runtime, node_id: types.NodeId) bool {
            return impl(runtime).actor.peers.known(&node_id) != null;
        }

        pub fn activeAndPermitCount(runtime: *Runtime) struct { active: usize, permits: usize } {
            const counts = activeQueuedAndPermitCount(runtime);
            return .{ .active = counts.active, .permits = counts.permits };
        }

        pub fn activeQueuedAndPermitCount(runtime: *Runtime) struct { active: usize, queued: usize, permits: usize } {
            const storage = impl(runtime);
            return .{
                .active = storage.actor.requests.activeCount(),
                .queued = storage.actor.requests.queuedCount(),
                .permits = storage.admission.permitCount(),
            };
        }

        pub fn resetAdmissionAfterDetectedLeak(runtime: *Runtime) void {
            const state = &impl(runtime).admission;
            state.expected_by_ip.clearRetainingCapacity();
            state.live_permits = 0;
            state.reserved_credits = 0;
            for (state.permit_slots, 0..) |*slot, index| {
                slot.* = .{ .free_next = if (index + 1 < state.permit_slots.len) @intCast(index + 1) else null };
            }
            state.free_head = 0;
        }

        pub fn requestResultReservationCount(runtime: *Runtime) struct { outstanding: usize, unclaimed: usize } {
            const outbox = &impl(runtime).request_result_outbox;
            return .{
                .outstanding = outbox.outstanding.load(.acquire),
                .unclaimed = outbox.unclaimed.load(.acquire),
            };
        }

        pub fn effectCount(runtime: *Runtime) usize {
            return impl(runtime).effects.count();
        }

        pub const ResponseShutdownFixture = struct {
            copied_effect: actor_mod.ActorEffect,
            stable_endpoint: types.Endpoint,
            stable: session_book.StableSession,
        };

        pub fn seedResponseShutdownFixture(runtime: *Runtime) !ResponseShutdownFixture {
            const storage = impl(runtime);
            const stable_endpoint = testEndpoint(0xe0);
            const stable = session_book.StableSession{
                .initiator_key = [_]u8{0xa1} ** 16,
                .recipient_key = [_]u8{0xa2} ** 16,
            };
            storage.actor.sessions.put(stable_endpoint, stable, 0);

            const sending = try beginResponse(storage, 0xe1);
            const copied_effect = actor_mod.ActorEffect{ .response = .{
                .handle = sending,
                .packet = try .init(&.{}),
            } };
            try storage.effects.push(copied_effect);

            const recoverable = try beginResponse(storage, 0xe2);
            std.debug.assert(storage.actor.responses.completeResponseSend(recoverable, .sent, &storage.admission));

            const handshaking = try beginResponse(storage, 0xe3);
            std.debug.assert(storage.actor.responses.completeResponseSend(handshaking, .sent, &storage.admission));
            const handshake_nonce = handshaking.nonce;
            const challenge = storage.actor.responses.challenge(handshaking.endpoint.addr, &handshake_nonce, 0, &storage.admission) orelse unreachable;
            _ = try storage.actor.responses.beginHandshake(challenge, .{
                .initiator_key = [_]u8{0xb1} ** 16,
                .recipient_key = [_]u8{0xb2} ** 16,
            }, 0);

            response_book.ResponseBook.Testing.putCandidate(&storage.actor.responses, testEndpoint(0xe4), .{
                .initiator_key = [_]u8{0xc1} ** 16,
                .recipient_key = [_]u8{0xc2} ** 16,
            }, 0);
            return .{ .copied_effect = copied_effect, .stable_endpoint = stable_endpoint, .stable = stable };
        }

        pub fn responseShutdownState(runtime: *Runtime, fixture: *const ResponseShutdownFixture) struct {
            responses: usize,
            permits: usize,
            effects: usize,
            stable_unchanged: bool,
        } {
            const storage = impl(runtime);
            const stable = storage.actor.sessions.get(fixture.stable_endpoint, 0);
            return .{
                .responses = storage.actor.responses.count(),
                .permits = storage.admission.permitCount(),
                .effects = storage.effects.count(),
                .stable_unchanged = if (stable) |value|
                    std.meta.eql(value.initiator_key, fixture.stable.initiator_key) and
                        std.meta.eql(value.recipient_key, fixture.stable.recipient_key)
                else
                    false,
            };
        }

        pub fn applyCopiedResponseCompletion(runtime: *Runtime, fixture: *const ResponseShutdownFixture) void {
            const storage = impl(runtime);
            storage.actor.applyEffectCompletion(.{
                .io = storage.io,
                .ingress = &storage.admission,
                .outbox = &storage.outbox,
                .effects = &storage.effects,
                .lookup_results = &storage.lookup_result_outbox,
                .request_results = &storage.request_result_outbox,
            }, fixture.copied_effect, .sent);
        }

        pub const ActiveRequestEvidence = struct {
            endpoint: types.Endpoint,
            dest_pubkey: [33]u8,
            plaintext: types.PacketBytes,
        };

        pub fn activeRequestEvidence(runtime: *Runtime, handle: public_api.RequestHandle) ?ActiveRequestEvidence {
            const storage = impl(runtime);
            const internal = public_api.handleToInternal(handle);
            if (!storage.actor.requests.matchesHandle(internal)) return null;
            const active = storage.actor.requests.get(internal.key) orelse return null;
            const recovery = switch (active.phase) {
                .awaiting_whoareyou => |value| value.recovery,
                .awaiting_response => |value| value.recovery,
            };
            return .{
                .endpoint = internal.key.endpoint,
                .dest_pubkey = recovery.dest_pubkey,
                .plaintext = recovery.plaintext,
            };
        }

        pub fn requestHandleMatches(runtime: *Runtime, handle: public_api.RequestHandle) bool {
            const storage = impl(runtime);
            const internal = public_api.handleToInternal(handle);
            if (storage.actor.requests.matchesHandle(internal)) return true;
            const queued = storage.actor.requests.queuedHandleFor(internal.key) orelse return false;
            return queued.generation == internal.generation and
                types.RequestKeyContext.eql(.{}, queued.key, internal.key);
        }

        /// Reconcile a claimed reservation after a test has used cancelRequest
        /// as an actor-loop barrier and still observed no public terminal.
        pub fn reconcileClaimedRequest(runtime: *Runtime, key: types.RequestKey) void {
            const storage = impl(runtime);
            std.debug.assert(storage.actor.requests.get(key) == null);
            if (storage.request_result_outbox.pop()) |result| {
                const internal = public_api.handleToInternal(result.handle);
                std.debug.assert(types.RequestKeyContext.eql(.{}, internal.key, key));
                return;
            }
            std.debug.assert(storage.actor.requests.get(key) == null);
            storage.request_result_outbox.release();
        }

        pub fn acquireAdmission(runtime: *Runtime, address: types.Address, budget: u16) !admission.AdmissionPermit {
            return impl(runtime).admission.acquire(address, budget);
        }

        pub fn admissionState(runtime: *Runtime) *admission.IngressAdmission {
            return &impl(runtime).admission;
        }

        pub fn admit(runtime: *Runtime, address: types.Address, now_ms: u64) admission.Admission {
            return impl(runtime).admission.admit(address, now_ms);
        }

        pub fn enqueueInbound(
            runtime: *Runtime,
            address: types.Address,
            raw: []const u8,
            credit: ?admission.ExpectedCredit,
        ) !void {
            return impl(runtime).enqueueInboundForTesting(address, raw, credit);
        }

        pub fn handleInbound(
            runtime: *Runtime,
            address: types.Address,
            raw: []const u8,
            credit: ?admission.ExpectedCredit,
        ) !void {
            return impl(runtime).handleInboundForTesting(address, raw, credit);
        }

        pub fn closeCommandsAndDrain(runtime: *Runtime) void {
            impl(runtime).closeCommandsAndDrainForTesting();
        }

        pub fn receiveBackoff(consecutive_errors: u8) u64 {
            return receive_backoff(consecutive_errors);
        }

        fn beginResponse(storage: *RuntimeImpl, byte: u8) !response_book.ResponseHandle {
            const endpoint = testEndpoint(byte);
            var permit = try storage.admission.acquire(endpoint.addr, admission.RESPONSE_RECOVERY_PACKET_BUDGET);
            errdefer permit.release(&storage.admission);
            return storage.actor.responses.beginResponse(.{
                .endpoint = endpoint,
                .nonce = [_]u8{byte} ** 12,
                .dest_pubkey = [_]u8{byte} ** 33,
                .plaintext = try .init(&.{message.MSG_TALKRESP}),
            }, &permit, 0);
        }

        fn testEndpoint(byte: u8) types.Endpoint {
            return .{
                .node_id = [_]u8{byte} ** 32,
                .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 1, byte }, .port = 9_000 + @as(u16, byte) } },
            };
        }

        fn impl(runtime: *Runtime) *RuntimeImpl {
            return @ptrCast(@alignCast(runtime));
        }
    } else struct {};
}
