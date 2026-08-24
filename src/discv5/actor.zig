const std = @import("std");
const admission = @import("admission.zig");
const addr_votes = @import("service/addr_votes.zig");
const config_mod = @import("config.zig");
const enr = @import("enr.zig");
const events = @import("events.zig");
const completion = @import("flow/completion.zig");
const kbucket = @import("kbucket.zig");
const lookup_mod = @import("service/lookup.zig");
const lookup_results = @import("lookup_results.zig");
const message = @import("protocol/message.zig");
const packet = @import("protocol/packet.zig");
const metrics_mod = @import("metrics.zig");
const outbound = @import("flow/outbound.zig");
const maintenance_flow = @import("flow/maintenance.zig");
const session_flow = @import("flow/session.zig");
const peer_book = @import("state/peer_book.zig");
const request_book = @import("state/request_book.zig");
const response_book = @import("state/response_book.zig");
const request_results = @import("request_results.zig");
const session_book = @import("state/session_book.zig");
const transport = @import("transport.zig");
const types = @import("types.zig");

const Allocator = std.mem.Allocator;
pub const MAX_LOOKUPS: usize = config_mod.MAX_LOOKUPS;

const LookupAttempt = struct {
    peer_id: types.NodeId,
    target: types.NodeId,
};

pub const LocalRecord = struct {
    raw: ?enr.RawEnr,
    seq: u64,
};
/// Ephemeral runtime capabilities; Actor never stores this context.
pub const Env = struct {
    io: std.Io,
    sender: transport.Sender,
    ingress: *admission.IngressAdmission,
    outbox: *events.EventOutbox,
    lookup_results: ?*lookup_results.LookupResultOutbox = null,
    request_results: ?*request_results.RequestResultOutbox = null,
    expected_credit: ?*admission.ExpectedCredit = null,

    pub fn commitExpected(self: Env) void {
        if (self.expected_credit) |credit| credit.commit(self.ingress);
    }
};

pub const ProbeSnapshot = struct {
    endpoint: types.Endpoint,
    pubkey: [33]u8,
};

pub const Actor = struct {
    alloc: Allocator,
    local_key_pair: @import("secp256k1.zig").KeyPair,
    local_node_id: types.NodeId,
    local: LocalRecord,
    sessions: session_book.SessionBook,
    requests: request_book.RequestBook,
    responses: response_book.ResponseBook,
    peers: peer_book.PeerBook,
    lookups: std.AutoHashMap(u32, lookup_mod.Lookup),
    votes_ip4: addr_votes.AddrVotes,
    votes_ip6: addr_votes.AddrVotes,
    metrics: metrics_mod.ProtocolMetrics = .{},
    limits: config_mod.Limits,
    next_lookup_id: u32 = 1,
    lookup_count: u64 = 0,
    request_timeout_ms: u64,
    request_retries: u32,
    allow_unverified_sessions: bool,
    bucket_pending_timeout_ms: u64,
    lookup_config: lookup_mod.Config,
    ping_interval_ms: u64,
    enr_update: bool,
    addr_vote_cooldown_until_ns: i64 = std.math.minInt(i64),

    pub fn init(alloc: Allocator, config: config_mod.Config) !Actor {
        try config.validate();
        const local = if (config.local_enr) |raw| blk: {
            const parsed = try enr.decode(raw);
            break :blk LocalRecord{ .raw = try .init(raw), .seq = parsed.seq };
        } else LocalRecord{ .raw = null, .seq = 0 };
        var sessions = try session_book.SessionBook.init(alloc, config);
        errdefer sessions.deinitEmpty(alloc);
        var requests = try request_book.RequestBook.init(alloc, config.limits);
        errdefer requests.deinitEmpty();
        var responses = try response_book.ResponseBook.init(alloc, config);
        errdefer responses.deinitEmpty(alloc);
        var peers = try peer_book.PeerBook.init(
            alloc,
            config.local_node_id,
            config.limits.contact_capacity,
            config.bind_addresses.ip4 != null,
            config.bind_addresses.ip6 != null,
        );
        errdefer peers.deinit();
        var lookups = std.AutoHashMap(u32, lookup_mod.Lookup).init(alloc);
        errdefer lookups.deinit();
        try lookups.ensureTotalCapacity(MAX_LOOKUPS);
        return .{
            .alloc = alloc,
            .local_key_pair = config.local_key_pair,
            .local_node_id = config.local_node_id,
            .local = local,
            .sessions = sessions,
            .requests = requests,
            .responses = responses,
            .peers = peers,
            .lookups = lookups,
            .votes_ip4 = .init(alloc, config.addr_votes_to_update_enr),
            .votes_ip6 = .init(alloc, config.addr_votes_to_update_enr),
            .limits = config.limits,
            .request_timeout_ms = config.request_timeout_ms,
            .request_retries = config.request_retries,
            .allow_unverified_sessions = config.allow_unverified_sessions,
            .bucket_pending_timeout_ms = config.bucket_pending_timeout_ms,
            .lookup_config = .{
                .num_results = config.lookup_num_results,
                .parallelism = config.lookup_parallelism,
                .request_limit = config.lookup_request_limit,
                .timeout_ms = config.lookup_timeout_ms,
            },
            .ping_interval_ms = config.ping_interval_ms,
            .enr_update = config.enr_update,
        };
    }

    pub fn deinit(self: *Actor, ingress: *admission.IngressAdmission) void {
        var iterator = self.lookups.iterator();
        while (iterator.next()) |entry| entry.value_ptr.deinit(self.alloc);
        self.lookups.deinit();
        self.votes_ip4.deinit();
        self.votes_ip6.deinit();
        self.peers.deinit();
        self.responses.deinit(self.alloc, ingress);
        self.requests.deinit(ingress);
        self.sessions.deinit(self.alloc, ingress);
    }

    pub fn handlePacket(self: *Actor, env: Env, raw: []u8, from: types.Address) void {
        session_flow.handlePacket(self, env, raw, from);
    }

    pub fn sendPing(
        self: *Actor,
        env: Env,
        endpoint: types.Endpoint,
        pubkey: *const [33]u8,
        enr_seq: u64,
        origin: types.RequestOrigin,
    ) !message.ReqId {
        const req_id = randomReqId(env.io);
        const ping = message.Ping{ .req_id = req_id, .enr_seq = enr_seq };
        var buffer: [128]u8 = undefined;
        try outbound.sendTracked(self, env, endpoint, pubkey, req_id, .ping, &.{}, try ping.encodeInto(&buffer), origin);
        return req_id;
    }

    pub fn sendFindNode(
        self: *Actor,
        env: Env,
        endpoint: types.Endpoint,
        pubkey: *const [33]u8,
        distances: []const u16,
        origin: types.RequestOrigin,
    ) !message.ReqId {
        if (distances.len > 127) return error.TooManyDistances;
        for (distances) |distance| {
            if (distance > 256) return error.InvalidDistance;
        }
        const req_id = randomReqId(env.io);
        const findnode = message.FindNode{ .req_id = req_id, .distances = distances };
        var buffer: [512]u8 = undefined;
        try outbound.sendTracked(self, env, endpoint, pubkey, req_id, .findnode, distances, try findnode.encodeInto(&buffer), origin);
        return req_id;
    }

    pub fn sendTalkRequest(
        self: *Actor,
        env: Env,
        endpoint: types.Endpoint,
        pubkey: *const [33]u8,
        protocol_name: []const u8,
        request: []const u8,
    ) !message.ReqId {
        return self.sendTalkRequestWithOrigin(env, endpoint, pubkey, protocol_name, request, .api);
    }

    pub fn sendTalkRequestWithOrigin(
        self: *Actor,
        env: Env,
        endpoint: types.Endpoint,
        pubkey: *const [33]u8,
        protocol_name: []const u8,
        request: []const u8,
        origin: types.RequestOrigin,
    ) !message.ReqId {
        const req_id = randomReqId(env.io);
        const talk = message.TalkReq{ .req_id = req_id, .protocol = protocol_name, .request = request };
        var buffer: [packet.MAX_PACKET_SIZE]u8 = undefined;
        const plaintext = try talk.encodeInto(&buffer);
        if (!packet.ordinaryMessageFits(plaintext.len)) return error.MessageTooLarge;
        try outbound.sendTracked(self, env, endpoint, pubkey, req_id, .talkreq, &.{}, plaintext, origin);
        return req_id;
    }

    pub fn sendTalkResponse(self: *Actor, env: Env, endpoint: types.Endpoint, req_id: message.ReqId, response: []const u8) !void {
        const talk = message.TalkResp{ .req_id = req_id, .response = response };
        var buffer: [packet.MAX_PACKET_SIZE]u8 = undefined;
        const plaintext = try talk.encodeInto(&buffer);
        if (!packet.ordinaryMessageFits(plaintext.len)) return error.MessageTooLarge;
        try outbound.sendResponse(self, env, endpoint, plaintext);
    }

    pub fn addNode(self: *Actor, node_id: types.NodeId, pubkey: ?*const [33]u8, address: types.Address, raw: ?[]const u8, now_ns: i64) bool {
        return self.peers.addTrusted(node_id, pubkey, address, raw, now_ns);
    }

    pub fn addEnr(self: *Actor, outbox: *events.EventOutbox, raw: []const u8, now_ns: i64) bool {
        const validated = enr.ValidatedEnr.init(raw) catch return false;
        const node_id = validated.node_id;
        const pubkey = validated.parsed.pubkey orelse return false;
        const address = self.peers.addressForEnr(&validated.parsed) orelse return false;
        const previous = if (self.peers.findEnr(&node_id)) |bytes| enr.RawEnr.init(bytes) catch null else null;
        if (!self.peers.addValidatedTrustedEnr(node_id, &pubkey, address, &validated, now_ns)) return false;
        const stored = self.peers.findEnr(&node_id) orelse return false;
        if (!std.mem.eql(u8, stored, raw)) {
            // The routing table already held a same/newer-seq ENR and the
            // local-trust merge succeeded: the node is usable, but nothing
            // was added, so no event is emitted.
            return true;
        }
        if (previous) |value| if (std.mem.eql(u8, value.slice(), raw)) return true;
        const event_raw = self.alloc.dupe(u8, raw) catch {
            outbox.notePayloadDrop(.enr_added);
            return true;
        };
        const previous_raw = if (previous) |value| self.alloc.dupe(u8, value.slice()) catch {
            self.alloc.free(event_raw);
            outbox.notePayloadDrop(.enr_added);
            return true;
        } else null;
        outbox.publish(.{ .enr_added = .{ .node_id = node_id, .addr = address, .enr = event_raw, .replaced_enr = previous_raw } });
        return true;
    }

    pub fn setLocalEnr(self: *Actor, env: Env, raw: []const u8) !void {
        const parsed = try enr.decode(raw);
        const node_id = (parsed.nodeId() catch return error.InvalidEnr) orelse return error.InvalidEnr;
        if (!std.mem.eql(u8, &node_id, &self.local_node_id)) return error.WrongNodeId;
        if (self.local.raw) |*current| if (std.mem.eql(u8, current.slice(), raw)) return;
        if (parsed.seq <= self.local.seq) return error.StaleEnrSeq;
        self.local = .{ .raw = try .init(raw), .seq = parsed.seq };
        self.votes_ip4.clear();
        self.votes_ip6.clear();
        self.addr_vote_cooldown_until_ns = outbound.deadlineNs(addressVoteNowNs(env.io), addr_votes.ENR_UPDATE_COOLDOWN_MS);
        self.publishLocalEnr(env.outbox);
        self.pingAll(env);
    }

    pub fn learnDiscovered(self: *Actor, raw: []const u8, now_ns: i64) ?types.NodeId {
        const validated = enr.ValidatedEnr.init(raw) catch return null;
        return self.learnValidatedDiscovered(&validated, now_ns);
    }

    pub fn learnValidatedDiscovered(self: *Actor, validated: *const enr.ValidatedEnr, now_ns: i64) ?types.NodeId {
        const node_id = self.validatedDiscoveredNodeId(validated) orelse return null;
        if (self.peers.learnValidatedEnr(validated, now_ns) == null) return null;
        return node_id;
    }

    pub fn discoveredNodeId(self: *const Actor, raw: []const u8) ?types.NodeId {
        const validated = enr.ValidatedEnr.init(raw) catch return null;
        return self.validatedDiscoveredNodeId(&validated);
    }

    pub fn validatedDiscoveredNodeId(self: *const Actor, validated: *const enr.ValidatedEnr) ?types.NodeId {
        if (std.mem.eql(u8, &validated.node_id, &self.local_node_id)) return null;
        if (self.peers.addressForEnr(&validated.parsed) == null) return null;
        return validated.node_id;
    }

    pub fn publishDiscovered(self: *Actor, outbox: *events.EventOutbox, raw: enr.RawEnr) void {
        const validated = enr.ValidatedEnr.init(raw.slice()) catch return;
        self.publishValidatedDiscovered(outbox, &validated);
    }

    pub fn publishValidatedDiscovered(self: *Actor, outbox: *events.EventOutbox, validated: *const enr.ValidatedEnr) void {
        _ = self;
        outbox.publish(.{ .discovered_enr = .{ .raw = validated.raw, .enr = validated.parsed } });
    }

    pub fn startLookup(self: *Actor, env: Env, target: types.NodeId) !u32 {
        const result_outbox = env.lookup_results orelse return error.LookupResultPlaneUnavailable;
        if (!result_outbox.claim()) return error.LookupResultReservationMissing;
        if (self.lookups.count() >= MAX_LOOKUPS) return error.TooManyLookups;
        var seeds: [lookup_mod.MAX_RESULTS]types.NodeId = undefined;
        const found = self.peers.routing.findClosestNodeIds(&target, lookup_mod.MAX_RESULTS, &seeds);
        const id = self.allocateLookupId() orelse return error.TooManyLookups;
        var lookup = try lookup_mod.Lookup.init(self.alloc, target, seeds[0..found], outbound.nowNs(env.io), self.lookup_config);
        errdefer lookup.deinit(self.alloc);
        lookup.reliable_result = true;
        self.lookups.putAssumeCapacityNoClobber(id, lookup);
        self.lookup_count +|= 1;
        self.pumpLookup(env, id);
        return id;
    }

    pub fn maintenance(self: *Actor, env: Env) void {
        self.maintenanceAt(env, outbound.nowNs(env.io));
    }

    pub fn maintenanceAt(self: *Actor, env: Env, now_real_ns: i64) void {
        maintenance_flow.run(self, env, now_real_ns);
    }

    pub fn cancelRequest(self: *Actor, env: Env, key: types.RequestKey) bool {
        if (self.requests.get(key) != null) {
            return completion.finish(self, env, key, .canceled, .canceled);
        }
        const queued = self.requests.takeQueued(key) orelse return false;
        self.publishRequestTerminal(env, key, queued.kind, queued.origin, .canceled);
        self.onRequestCancellation(env, key, queued.origin);
        outbound.drainEndpoint(self, env, key.endpoint);
        return true;
    }

    pub fn onRequestCancellation(self: *Actor, env: Env, key: types.RequestKey, origin: types.RequestOrigin) void {
        switch (origin) {
            .lookup => self.onRequestCompletion(env, key, origin, false, &.{}),
            .maintenance => |reason| switch (reason) {
                .health, .eviction => _ = self.peers.cancelHealthRequest(key),
                .enr_refresh => {},
            },
            .api, .reliable_api, .detached_lookup => {},
        }
    }

    pub fn onRequestCompletion(
        self: *Actor,
        env: Env,
        key: types.RequestKey,
        origin: types.RequestOrigin,
        success: bool,
        closer: []const lookup_mod.Candidate,
    ) void {
        if (success) {
            const responsive = self.peers.markResponsive(key.endpoint.node_id, key.endpoint.addr, outbound.nowNs(env.io), key);
            self.publishConnection(env.outbox, key.endpoint.node_id, responsive.transition);
        }
        switch (origin) {
            .lookup => |id| {
                if (self.lookups.getPtr(id)) |lookup| {
                    if (success) lookup.onSuccess(&key.endpoint.node_id, closer, self.lookup_config) else lookup.onFailure(&key.endpoint.node_id, self.lookup_config);
                } else return;
                self.pumpLookup(env, id);
            },
            .maintenance => |reason| switch (reason) {
                .health => if (!success) self.publishConnection(env.outbox, key.endpoint.node_id, self.peers.markDisconnected(key, outbound.nowNs(env.io))),
                .eviction => if (success) {
                    // Exact-candidate result: the probed incumbent answered,
                    // so the bucket keeps it and drops the pending newcomer.
                    self.peers.resolveEvictionSuccess(&key.endpoint.node_id);
                } else {
                    // Exact-candidate result: the probe timed out, so the
                    // unresponsive candidate is removed and the pending
                    // replacement resolves immediately.
                    if (self.peers.completeEvictionTimeout(key)) |event|
                        self.publishConnection(env.outbox, event.node_id, event.transition);
                },
                .enr_refresh => {},
            },
            .api, .reliable_api => {},
            .detached_lookup => {},
        }
    }

    pub fn publishRequestTerminal(
        self: *Actor,
        env: Env,
        key: types.RequestKey,
        kind: types.RequestKind,
        origin: types.RequestOrigin,
        terminal: request_results.RequestTerminal,
    ) void {
        _ = self;
        if (origin != .reliable_api) return;
        switch (terminal) {
            .pong => std.debug.assert(kind == .ping),
            .nodes => std.debug.assert(kind == .findnode),
            .talk_response => std.debug.assert(kind == .talkreq),
            .timeout, .canceled, .runtime_stopped => {},
        }
        const result_outbox = env.request_results orelse unreachable;
        result_outbox.publishAssumeReserved(.{ .key = key, .kind = kind, .terminal = terminal });
    }

    pub fn finishAllReliableRequests(self: *Actor, env: Env) void {
        var active_finished: usize = 0;
        while (active_finished < self.limits.max_active_requests) : (active_finished += 1) {
            const snapshot = self.requests.firstReliableActive() orelse break;
            var active = self.requests.take(snapshot.key) orelse unreachable;
            self.publishRequestTerminal(env, snapshot.key, snapshot.kind, active.origin, .runtime_stopped);
            active.admission.release(env.ingress);
        }
        std.debug.assert(self.requests.firstReliableActive() == null);

        var queued_finished: usize = 0;
        while (queued_finished < self.limits.max_queued_requests) : (queued_finished += 1) {
            const snapshot = self.requests.firstReliableQueued() orelse break;
            const queued = self.requests.takeQueued(snapshot.key) orelse unreachable;
            self.publishRequestTerminal(env, snapshot.key, snapshot.kind, queued.origin, .runtime_stopped);
        }
        std.debug.assert(self.requests.firstReliableQueued() == null);
    }

    pub fn publishConnection(self: *Actor, outbox: *events.EventOutbox, node_id: types.NodeId, transition: peer_book.ConnectionTransition) void {
        _ = self;
        switch (transition) {
            .none => {},
            .connected => |address| outbox.publish(.{ .peer_connected = .{ .peer_id = node_id, .peer_addr = address } }),
            .disconnected => |address| outbox.publish(.{ .peer_disconnected = .{ .peer_id = node_id, .peer_addr = address } }),
        }
    }

    pub fn metricsSnapshot(self: *const Actor) metrics_mod.MetricsSnapshot {
        const contacts = self.peers.contactMetricsSnapshot();
        const sessions = self.sessions.metricsSnapshot();
        return .{
            .kad_table_size = self.peers.routing.nodeCount(),
            .active_session_count = sessions.count,
            .connected_peer_count = self.peers.connectedCount(),
            .lookup_count = self.lookup_count,
            .active_lookup_count = self.lookups.count(),
            .active_request_count = self.requests.activeCount(),
            .queued_request_count = self.requests.queuedCount(),
            .sent_message_count = self.metrics.sent_message_count,
            .rcvd_message_count = self.metrics.rcvd_message_count,
            .contact_count = contacts.count,
            .contact_capacity = contacts.capacity,
            .contact_inserted_total = contacts.inserted_total,
            .contact_updated_total = contacts.updated_total,
            .contact_replaced_total = contacts.replaced_total,
            .contact_capacity_rejected_total = contacts.capacity_rejected_total,
            .contact_policy_rejected_total = contacts.policy_rejected_total,
            .contact_removed_total = contacts.removed_total,
            .session_capacity = sessions.capacity,
            .session_inserted_total = sessions.inserted_total,
            .session_rekeyed_total = sessions.rekeyed_total,
            .session_capacity_reused_total = sessions.capacity_reused_total,
            .session_maintenance_expired_total = sessions.maintenance_expired_total,
            .session_authenticated_refreshed_total = sessions.authenticated_refreshed_total,
            .session_replay_rejected_total = sessions.replay_rejected_total,
            .session_nonce_exhaustion_rejected_total = sessions.nonce_exhaustion_rejected_total,
        };
    }

    pub fn localEnr(self: *const Actor) ?enr.RawEnr {
        return self.local.raw;
    }

    pub fn peerEnr(self: *const Actor, node_id: *const types.NodeId) ?enr.RawEnr {
        const raw = self.peers.findEnr(node_id) orelse return null;
        return enr.RawEnr.init(raw) catch unreachable;
    }

    pub fn localEnrSeq(self: *const Actor) u64 {
        return self.local.seq;
    }

    pub fn maybeRequestEnrUpdate(self: *Actor, env: Env, endpoint: types.Endpoint, advertised_seq: u64) void {
        const known_seq = self.peers.knownEnrSeq(&endpoint.node_id) orelse return;
        if (known_seq >= advertised_seq or self.requests.hasActiveFindNode(&endpoint.node_id)) return;
        const known = self.peers.known(&endpoint.node_id) orelse return;
        _ = self.sendFindNode(env, endpoint, &known.pubkey, &.{0}, .{ .maintenance = .enr_refresh }) catch {};
    }

    pub fn observeAddressVote(self: *Actor, env: Env, voter: types.Address, observed: types.Address) void {
        self.observeAddressVoteAt(env, voter, observed, addressVoteNowNs(env.io));
    }

    pub fn observeAddressVoteAt(self: *Actor, env: Env, voter: types.Address, observed: types.Address, now_ns: i64) void {
        if (!self.enr_update or self.local.raw == null) return;
        const normalized = normalize(observed);
        if (!validObservedAddress(self, normalized)) return;
        if (now_ns < self.addr_vote_cooldown_until_ns) {
            self.votes_ip4.clear();
            self.votes_ip6.clear();
            return;
        }
        const votes = switch (normalized) {
            .ip4 => &self.votes_ip4,
            .ip6 => &self.votes_ip6,
        };
        const vote_result = votes.addVote(normalize(voter), normalized, now_ns) catch return;
        const winner = switch (vote_result) {
            .duplicate, .recorded => return,
            .winner => |value| value,
        };
        const current = enr.decode(self.local.raw.?.slice()) catch return;
        const current_address = switch (normalized) {
            .ip4 => current.udpAddress4(),
            .ip6 => current.udpAddress6(),
        };
        if (current_address) |value| if (value.eql(&normalized)) {
            votes.commitWinner(winner);
            return;
        };
        if (!self.updateLocalAddress(normalized)) return;
        votes.commitWinner(winner);
        self.votes_ip4.clear();
        self.votes_ip6.clear();
        self.addr_vote_cooldown_until_ns = outbound.deadlineNs(now_ns, addr_votes.ENR_UPDATE_COOLDOWN_MS);
        self.publishLocalEnr(env.outbox);
        self.pingAll(env);
    }

    pub fn probeEviction(self: *Actor, env: Env, candidate: kbucket.Entry) void {
        if (candidate.health_request != null) return;
        const known = self.peers.known(&candidate.node_id) orelse return;
        const endpoint = types.Endpoint{ .node_id = known.node_id, .addr = candidate.addr };
        // The genuine full-bucket candidate is normally disconnected, so the
        // reservation policy must admit it; the send failure path rolls the
        // reservation back inside sendProbe.
        _ = self.sendProbe(env, endpoint, &known.pubkey, .eviction, .allow_eviction_candidate) catch return;
    }

    /// Pre-send reservation transaction for health/eviction liveness probes:
    /// reserve exact probe ownership before the packet can become visible,
    /// send, and roll the reservation back only when the send path fails
    /// before the tracked request commits.
    pub fn sendProbe(
        self: *Actor,
        env: Env,
        endpoint: types.Endpoint,
        pubkey: *const [33]u8,
        reason: types.MaintenanceReason,
        policy: peer_book.PeerBook.HealthReservationPolicy,
    ) !message.ReqId {
        std.debug.assert(reason == .health or reason == .eviction);
        const req_id = randomReqId(env.io);
        const key = types.RequestKey.init(endpoint, req_id);
        if (!self.peers.armHealthRequest(key, policy)) return error.ProbeUnavailable;
        errdefer _ = self.peers.cancelHealthRequest(key);
        const ping = message.Ping{ .req_id = req_id, .enr_seq = self.local.seq };
        var buffer: [128]u8 = undefined;
        try outbound.sendTracked(self, env, endpoint, pubkey, req_id, .ping, &.{}, try ping.encodeInto(&buffer), .{ .maintenance = reason });
        return req_id;
    }

    fn pumpLookup(self: *Actor, env: Env, id: u32) void {
        // A candidate can fail synchronously before any request is active. Walk
        // the complete bounded frontier so such failures cannot leave a lookup
        // with no request that could wake it again.
        var attempts: usize = 0;
        while (attempts < lookup_mod.MAX_CANDIDATES) : (attempts += 1) {
            const attempt: LookupAttempt = blk: {
                const lookup = self.lookups.getPtr(id) orelse return;
                lookup.deferred = false;
                const peer_id = lookup.nextPeer(self.lookup_config) orelse break;
                break :blk .{ .peer_id = peer_id, .target = lookup.target };
            };
            const peer_id = attempt.peer_id;
            var distances: [127]u16 = undefined;
            const count = lookup_mod.findNodeLogDistances(&attempt.target, &peer_id, @min(self.lookup_config.request_limit, distances.len), &distances);
            const send_result = blk: {
                const lookup = self.lookups.getPtr(id) orelse return;
                if (lookup.localCandidate(&peer_id)) |candidate| {
                    break :blk self.sendFindNode(
                        env,
                        .{ .node_id = peer_id, .addr = candidate.addr },
                        &candidate.pubkey,
                        distances[0..count],
                        .{ .lookup = id },
                    );
                }
                const known = self.peers.known(&peer_id) orelse {
                    lookup.onFailure(&peer_id, self.lookup_config);
                    continue;
                };
                break :blk self.sendFindNode(
                    env,
                    .{ .node_id = peer_id, .addr = known.addr },
                    &known.pubkey,
                    distances[0..count],
                    .{ .lookup = id },
                );
            };
            _ = send_result catch |err| {
                if (isLookupBackpressure(err)) {
                    if (self.lookups.getPtr(id)) |lookup| lookup.onDeferred(&peer_id);
                    break;
                }
                if (self.lookups.getPtr(id)) |lookup| lookup.onFailure(&peer_id, self.lookup_config);
                continue;
            };
        }
        const finished = if (self.lookups.get(id)) |lookup| lookup.state == .finished else false;
        if (finished) self.finishLookup(env, id, .completed);
    }

    pub fn repumpLookups(self: *Actor, env: Env) void {
        var lookup_ids: [MAX_LOOKUPS]u32 = undefined;
        const count = blk: {
            var count: usize = 0;
            var iterator = self.lookups.iterator();
            while (iterator.next()) |entry| {
                if (!entry.value_ptr.deferred) continue;
                std.debug.assert(count < lookup_ids.len);
                lookup_ids[count] = entry.key_ptr.*;
                count += 1;
            }
            break :blk count;
        };
        for (lookup_ids[0..count]) |lookup_id| self.pumpLookup(env, lookup_id);
    }

    fn allocateLookupId(self: *Actor) ?u32 {
        var attempts: usize = 0;
        while (attempts <= MAX_LOOKUPS) : (attempts += 1) {
            const candidate = self.next_lookup_id;
            self.next_lookup_id +%= 1;
            if (self.next_lookup_id == 0) self.next_lookup_id = 1;
            if (!self.lookups.contains(candidate)) return candidate;
        }
        return null;
    }

    pub fn finishLookup(self: *Actor, env: Env, id: u32, reason: lookup_results.LookupTerminalReason) void {
        const lookup = self.lookups.getPtr(id) orelse return;
        var terminal = lookup_results.LookupResult{
            .lookup_id = id,
            .target = lookup.target,
            .reason = reason,
        };
        for (lookup.peers.items) |*peer| {
            if (peer.state != .succeeded or terminal.enrs.slice().len >= self.lookup_config.num_results) continue;
            if (peer.local_candidate) |*candidate| {
                terminal.enrs.append(candidate.raw);
                continue;
            }
            const raw = self.peers.findEnr(&peer.node_id) orelse continue;
            terminal.enrs.append(enr.RawEnr.init(raw) catch unreachable);
        }
        const reliable_result = lookup.reliable_result;
        var removed = self.lookups.fetchRemove(id).?.value;
        self.requests.detachLookup(id);
        removed.deinit(self.alloc);

        if (reliable_result) {
            const result_outbox = env.lookup_results orelse unreachable;
            result_outbox.publishAssumeReserved(terminal);
        }
    }

    pub fn finishAllLookups(self: *Actor, env: Env, reason: lookup_results.LookupTerminalReason) void {
        var lookup_ids: [MAX_LOOKUPS]u32 = undefined;
        const count = blk: {
            var count: usize = 0;
            var iterator = self.lookups.iterator();
            while (iterator.next()) |entry| {
                std.debug.assert(count < lookup_ids.len);
                lookup_ids[count] = entry.key_ptr.*;
                count += 1;
            }
            break :blk count;
        };
        for (lookup_ids[0..count]) |lookup_id| self.finishLookup(env, lookup_id, reason);
    }

    fn updateLocalAddress(self: *Actor, address: types.Address) bool {
        const current = self.local.raw orelse return false;
        const parsed = enr.decode(current.slice()) catch return false;
        const next_seq = std.math.add(u64, @max(parsed.seq, self.local.seq), 1) catch return false;
        var builder = enr.Builder.init(self.alloc, self.local_key_pair, next_seq);
        builder.ip = parsed.ip;
        builder.udp = parsed.udp;
        builder.tcp = parsed.tcp;
        builder.quic = parsed.quic;
        builder.ip6 = parsed.ip6;
        builder.udp6 = parsed.udp6;
        builder.tcp6 = parsed.tcp6;
        builder.quic6 = parsed.quic6;
        builder.eth2 = parsed.eth2_raw;
        builder.attnets = parsed.attnets;
        builder.syncnets = parsed.syncnets;
        builder.custody_group_count = parsed.custody_group_count;
        switch (address) {
            .ip4 => |value| {
                builder.ip = value.bytes;
                builder.udp = value.port;
            },
            .ip6 => |value| {
                builder.ip6 = value.bytes;
                builder.udp6 = value.port;
            },
        }
        const encoded = builder.encode() catch return false;
        defer self.alloc.free(encoded);
        const replacement = enr.RawEnr.init(encoded) catch return false;
        self.local = .{ .raw = replacement, .seq = builder.seq };
        return true;
    }

    fn publishLocalEnr(self: *Actor, outbox: *events.EventOutbox) void {
        const raw = self.local.raw orelse return;
        const copy = self.alloc.dupe(u8, raw.slice()) catch {
            outbox.notePayloadDrop(.multiaddr_updated);
            return;
        };
        outbox.publish(.{ .local_enr_updated = .{ .seq = self.local.seq, .enr = copy } });
    }

    fn pingAll(self: *Actor, env: Env) void {
        for (self.peers.routing.buckets) |*bucket| {
            var snapshots: [kbucket.K]ProbeSnapshot = undefined;
            var count: usize = 0;
            for (bucket.entries[0..bucket.count]) |entry| {
                if (entry.status != .connected or entry.health_request != null) continue;
                const known = self.peers.known(&entry.node_id) orelse continue;
                std.debug.assert(count < snapshots.len);
                snapshots[count] = .{
                    .endpoint = .{ .node_id = entry.node_id, .addr = entry.addr },
                    .pubkey = known.pubkey,
                };
                count += 1;
            }
            for (snapshots[0..count]) |*snapshot| {
                _ = self.sendProbe(env, snapshot.endpoint, &snapshot.pubkey, .health, .connected_only) catch continue;
            }
        }
    }
};

fn randomReqId(io: std.Io) message.ReqId {
    var id = message.ReqId{ .bytes = [_]u8{0} ** 8, .len = 4 };
    io.random(id.bytes[0..4]);
    return id;
}

fn normalize(address: types.Address) types.Address {
    return switch (address) {
        .ip4 => address,
        .ip6 => |ip6| .fromIp6(ip6),
    };
}

fn addressVoteNowNs(io: std.Io) i64 {
    return @intCast(std.Io.Timestamp.now(io, .awake).toNanoseconds());
}

/// Address votes accept private, documentation, loopback, and other unicast
/// ranges so local/test deployments keep working. Only representations that
/// cannot identify a UDP endpoint are rejected here: zero ports, unspecified
/// addresses, multicast, the IPv4 limited broadcast, and disabled families.
fn validObservedAddress(actor: *const Actor, address: types.Address) bool {
    if (address.getPort() == 0) return false;
    return switch (address) {
        .ip4 => |ip4| actor.peers.allow_ip4 and
            !std.mem.allEqual(u8, &ip4.bytes, 0) and
            !std.mem.allEqual(u8, &ip4.bytes, 0xff) and
            (ip4.bytes[0] & 0xf0) != 0xe0,
        .ip6 => |ip6| actor.peers.allow_ip6 and
            !std.mem.allEqual(u8, &ip6.bytes, 0) and
            ip6.bytes[0] != 0xff,
    };
}

fn isLookupBackpressure(err: anyerror) bool {
    return switch (err) {
        error.TooManyActiveRequests,
        error.TooManyQueuedRequests,
        error.TooManyQueuedRequestsForEndpoint,
        error.TooManyAdmissionPermits,
        => true,
        else => false,
    };
}

test "discv5 actor: lookup pump exhausts bounded synchronous candidate failures" {
    const test_secp = @import("secp256k1.zig");
    const RecordingSender = @import("test_support/recording_sender.zig").RecordingSender;
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try test_secp.keyPairFromSecret(&([_]u8{0x91} ** 32));
    const local_id = try enr.nodeIdFromCompressedPubkey(&test_secp.compressedPubkey(&local_key));
    const cfg = config_mod.Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
        .local_node_id = local_id,
        .rate_limiter = null,
        .limits = .{ .event_capacity = 4, .command_capacity = 4 },
    };
    var ingress = try admission.IngressAdmission.init(alloc, null, try admission.permitCapacity(cfg.limits));
    defer ingress.deinit();
    var outbox = try events.EventOutbox.init(io, alloc, cfg.limits.event_capacity);
    defer outbox.deinit();
    var actor = try Actor.init(alloc, cfg);
    defer actor.deinit(&ingress);
    var recording = RecordingSender.init(alloc);
    defer recording.deinit();
    const env = Env{ .io = io, .sender = recording.sender(), .ingress = &ingress, .outbox = &outbox };

    const target = [_]u8{0} ** 32;
    var seeds: [lookup_mod.MAX_RESULTS]types.NodeId = undefined;
    for (&seeds, 1..) |*seed, value| {
        seed.* = [_]u8{0} ** 32;
        seed.*[31] = @intCast(value);
    }
    var lookup = try lookup_mod.Lookup.init(alloc, target, &seeds, 0, actor.lookup_config);
    for (lookup_mod.MAX_RESULTS + 1..lookup_mod.MAX_CANDIDATES + 1) |value| {
        var node_id = [_]u8{0} ** 32;
        node_id[31] = @intCast(value);
        lookup.peers.appendAssumeCapacity(.{ .node_id = node_id });
    }
    actor.lookups.putAssumeCapacityNoClobber(1, lookup);

    actor.pumpLookup(env, 1);

    try std.testing.expect(!actor.lookups.contains(1));
    try std.testing.expect(outbox.pop() == null);
}

test "discv5 actor: lookup local backpressure defers until bounded maintenance repump" {
    const test_secp = @import("secp256k1.zig");
    const RecordingSender = @import("test_support/recording_sender.zig").RecordingSender;
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try test_secp.keyPairFromSecret(&([_]u8{0x92} ** 32));
    const local_id = try enr.nodeIdFromCompressedPubkey(&test_secp.compressedPubkey(&local_key));
    const blocker_key = try test_secp.keyPairFromSecret(&([_]u8{0x93} ** 32));
    const blocker_pubkey = test_secp.compressedPubkey(&blocker_key);
    const blocker_id = try enr.nodeIdFromCompressedPubkey(&blocker_pubkey);
    const lookup_key = try test_secp.keyPairFromSecret(&([_]u8{0x94} ** 32));
    const lookup_pubkey = test_secp.compressedPubkey(&lookup_key);
    const lookup_peer_id = try enr.nodeIdFromCompressedPubkey(&lookup_pubkey);
    const blocker_endpoint = types.Endpoint{
        .node_id = blocker_id,
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 92 }, .port = 9092 } },
    };
    const lookup_address: types.Address = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 94 }, .port = 9094 } };
    const cfg = config_mod.Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
        .local_node_id = local_id,
        .request_retries = 0,
        .lookup_num_results = 1,
        .lookup_parallelism = 1,
        .rate_limiter = null,
        .limits = .{
            .max_active_requests = 1,
            .max_queued_requests = 1,
            .event_capacity = 4,
            .command_capacity = 4,
        },
    };
    var ingress = try admission.IngressAdmission.init(alloc, null, try admission.permitCapacity(cfg.limits));
    defer ingress.deinit();
    var outbox = try events.EventOutbox.init(io, alloc, cfg.limits.event_capacity);
    defer outbox.deinit();
    var actor = try Actor.init(alloc, cfg);
    defer actor.deinit(&ingress);
    var recording = RecordingSender.init(alloc);
    defer recording.deinit();
    const env = Env{ .io = io, .sender = recording.sender(), .ingress = &ingress, .outbox = &outbox };
    try std.testing.expect(actor.addNode(lookup_peer_id, &lookup_pubkey, lookup_address, null, 0));

    const blocker_req_id = try actor.sendPing(env, blocker_endpoint, &blocker_pubkey, 0, .api);
    try std.testing.expectEqual(@as(usize, 1), actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 1), ingress.permitCount());
    try std.testing.expectEqual(@as(usize, 1), recording.datagrams.items.len);

    const lookup_id: u32 = 1;
    const target = [_]u8{0x95} ** 32;
    const lookup = try lookup_mod.Lookup.init(alloc, target, &.{lookup_peer_id}, outbound.nowNs(io), actor.lookup_config);
    actor.lookups.putAssumeCapacityNoClobber(lookup_id, lookup);
    actor.pumpLookup(env, lookup_id);

    const deferred = actor.lookups.getPtr(lookup_id) orelse return error.LookupFinishedUnderBackpressure;
    try std.testing.expectEqual(lookup_mod.State.iterating, deferred.state);
    try std.testing.expectEqual(@as(usize, 0), deferred.num_waiting);
    try std.testing.expect(deferred.deferred);
    try std.testing.expectEqual(lookup_mod.PeerState.not_contacted, deferred.peers.items[0].state);
    try std.testing.expectEqual(@as(usize, 1), actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 1), ingress.permitCount());
    try std.testing.expectEqual(@as(usize, 1), recording.datagrams.items.len);
    try std.testing.expect(outbox.pop() == null);

    try std.testing.expect(actor.cancelRequest(env, .init(blocker_endpoint, blocker_req_id)));
    try std.testing.expectEqual(@as(usize, 0), actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 0), ingress.permitCount());

    actor.maintenance(env);
    const dispatched = actor.lookups.getPtr(lookup_id) orelse return error.LookupFinishedBeforeDispatch;
    try std.testing.expectEqual(@as(usize, 1), dispatched.num_waiting);
    try std.testing.expect(!dispatched.deferred);
    try std.testing.expectEqual(lookup_mod.PeerState.waiting, dispatched.peers.items[0].state);
    try std.testing.expectEqual(@as(usize, 1), actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 1), ingress.permitCount());
    try std.testing.expectEqual(@as(usize, 2), recording.datagrams.items.len);

    actor.maintenance(env);
    try std.testing.expectEqual(@as(usize, 1), actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 1), ingress.permitCount());
    try std.testing.expectEqual(@as(usize, 2), recording.datagrams.items.len);

    actor.maintenanceAt(env, std.math.maxInt(i64));
    try std.testing.expectEqual(@as(usize, 0), actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 0), ingress.permitCount());
}

test "discv5 actor: lookup transport send failure remains terminal" {
    const test_secp = @import("secp256k1.zig");
    const RecordingSender = @import("test_support/recording_sender.zig").RecordingSender;
    const alloc = std.testing.allocator;
    const io = std.Options.debug_io;
    const local_key = try test_secp.keyPairFromSecret(&([_]u8{0x96} ** 32));
    const local_id = try enr.nodeIdFromCompressedPubkey(&test_secp.compressedPubkey(&local_key));
    const remote_key = try test_secp.keyPairFromSecret(&([_]u8{0x97} ** 32));
    const remote_pubkey = test_secp.compressedPubkey(&remote_key);
    const remote_id = try enr.nodeIdFromCompressedPubkey(&remote_pubkey);
    const remote_address: types.Address = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 97 }, .port = 9097 } };
    const cfg = config_mod.Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
        .local_node_id = local_id,
        .lookup_num_results = 1,
        .lookup_parallelism = 1,
        .rate_limiter = null,
        .limits = .{ .max_active_requests = 1, .max_queued_requests = 1, .event_capacity = 2, .command_capacity = 2 },
    };
    var ingress = try admission.IngressAdmission.init(alloc, null, try admission.permitCapacity(cfg.limits));
    defer ingress.deinit();
    var outbox = try events.EventOutbox.init(io, alloc, cfg.limits.event_capacity);
    defer outbox.deinit();
    var actor = try Actor.init(alloc, cfg);
    defer actor.deinit(&ingress);
    var recording = RecordingSender.init(alloc);
    defer recording.deinit();
    const env = Env{ .io = io, .sender = recording.sender(), .ingress = &ingress, .outbox = &outbox };
    try std.testing.expect(actor.addNode(remote_id, &remote_pubkey, remote_address, null, 0));
    const lookup = try lookup_mod.Lookup.init(alloc, [_]u8{0x98} ** 32, &.{remote_id}, outbound.nowNs(io), actor.lookup_config);
    actor.lookups.putAssumeCapacityNoClobber(1, lookup);
    recording.fail_next = true;

    actor.pumpLookup(env, 1);

    try std.testing.expect(!actor.lookups.contains(1));
    try std.testing.expectEqual(@as(usize, 0), actor.requests.activeCount());
    try std.testing.expectEqual(@as(usize, 0), ingress.permitCount());
    try std.testing.expectEqual(@as(usize, 0), recording.datagrams.items.len);
    try std.testing.expect(outbox.pop() == null);
}
