const std = @import("std");
const admission = @import("admission.zig");
const message = @import("protocol/message.zig");
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
        pub const PingResult = runtime_error.RequestError!message.ReqId;
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
            if (!storage.request_result_outbox.reserve()) return error.RequestResultCapacityExceeded;
            var reservation_transferred = false;
            errdefer if (!reservation_transferred) storage.request_result_outbox.cancelUnclaimed();
            try storage.enqueueCommand(.{ .send_ping = .{
                .endpoint = endpoint,
                .pubkey = pubkey,
                .enr_seq = 0,
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

        pub fn enqueuePingEffect(
            runtime: *Runtime,
            endpoint: types.Endpoint,
            pubkey: [33]u8,
        ) !message.ReqId {
            const storage = impl(runtime);
            var action = try storage.actor.preparePing(
                .{ .io = storage.io, .ingress = &storage.admission },
                endpoint,
                &pubkey,
                0,
                .api,
            );
            const req_id = action.requestId();
            switch (action) {
                .send => |effect| try storage.effects.push(.{ .request = effect }),
                .queued => unreachable,
            }
            return req_id;
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

        /// Reconcile a claimed reservation after a test has used cancelRequest
        /// as an actor-loop barrier and still observed no public terminal.
        pub fn reconcileClaimedRequest(runtime: *Runtime, key: types.RequestKey) void {
            const storage = impl(runtime);
            std.debug.assert(storage.actor.requests.get(key) == null);
            if (storage.request_result_outbox.pop()) |result| {
                std.debug.assert(types.RequestKeyContext.eql(.{}, result.key, key));
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

        fn impl(runtime: *Runtime) *RuntimeImpl {
            return @ptrCast(@alignCast(runtime));
        }
    } else struct {};
}
