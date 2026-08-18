const std = @import("std");
const admission = @import("admission.zig");
const addr_votes = @import("service/addr_votes.zig");
const config_mod = @import("config.zig");
const enr = @import("enr.zig");
const events = @import("events.zig");
const completion = @import("flow/completion.zig");
const kbucket = @import("kbucket.zig");
const lookup_mod = @import("service/lookup.zig");
const message = @import("protocol/message.zig");
const metrics_mod = @import("metrics.zig");
const outbound = @import("flow/outbound.zig");
const maintenance_flow = @import("flow/maintenance.zig");
const session_flow = @import("flow/session.zig");
const peer_book = @import("state/peer_book.zig");
const request_book = @import("state/request_book.zig");
const response_book = @import("state/response_book.zig");
const session_book = @import("state/session_book.zig");
const transport = @import("transport.zig");
const types = @import("types.zig");

const Allocator = std.mem.Allocator;
const MAX_LOOKUPS: usize = 1_024;

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
        const req_id = randomReqId(env.io);
        const talk = message.TalkReq{ .req_id = req_id, .protocol = protocol_name, .request = request };
        var buffer: [@import("protocol/packet.zig").MAX_PACKET_SIZE]u8 = undefined;
        try outbound.sendTracked(self, env, endpoint, pubkey, req_id, .talkreq, &.{}, try talk.encodeInto(&buffer), .api);
        return req_id;
    }

    pub fn sendTalkResponse(self: *Actor, env: Env, endpoint: types.Endpoint, req_id: message.ReqId, response: []const u8) !void {
        const talk = message.TalkResp{ .req_id = req_id, .response = response };
        var buffer: [@import("protocol/packet.zig").MAX_PACKET_SIZE]u8 = undefined;
        try outbound.sendResponse(self, env, endpoint, try talk.encodeInto(&buffer));
    }

    pub fn addNode(self: *Actor, node_id: types.NodeId, pubkey: ?*const [33]u8, address: types.Address, raw: ?[]const u8, now_ns: i64) bool {
        return self.peers.addTrusted(node_id, pubkey, address, raw, now_ns);
    }

    pub fn addEnr(self: *Actor, outbox: *events.EventOutbox, raw: []const u8, now_ns: i64) bool {
        const parsed = enr.decode(raw) catch return false;
        const node_id = parsed.nodeId() orelse return false;
        const pubkey = parsed.pubkey orelse return false;
        const address = self.peers.addressForEnr(&parsed) orelse return false;
        const previous = if (self.peers.findEnr(&node_id)) |bytes| enr.RawEnr.init(bytes) catch null else null;
        if (!self.peers.addTrusted(node_id, &pubkey, address, raw, now_ns)) return false;
        const stored = self.peers.findEnr(&node_id) orelse return false;
        if (!std.mem.eql(u8, stored, raw)) {
            // The routing table already held a same/newer-seq ENR and the
            // local-trust merge succeeded: the node is usable, but nothing
            // was added, so no event is emitted.
            return true;
        }
        if (previous) |value| if (std.mem.eql(u8, value.slice(), raw)) return true;
        const event_raw = self.alloc.dupe(u8, raw) catch {
            outbox.notePayloadDrop();
            return true;
        };
        const previous_raw = if (previous) |value| self.alloc.dupe(u8, value.slice()) catch {
            self.alloc.free(event_raw);
            outbox.notePayloadDrop();
            return true;
        } else null;
        outbox.publish(.{ .enr_added = .{ .node_id = node_id, .addr = address, .enr = event_raw, .replaced_enr = previous_raw } });
        return true;
    }

    pub fn setLocalEnr(self: *Actor, env: Env, raw: []const u8) !void {
        const parsed = try enr.decode(raw);
        const node_id = parsed.nodeId() orelse return error.InvalidEnr;
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
        const node_id = self.discoveredNodeId(raw) orelse return null;
        if (self.peers.learnEnr(raw, now_ns) == null) return null;
        return node_id;
    }

    pub fn discoveredNodeId(self: *const Actor, raw: []const u8) ?types.NodeId {
        const parsed = enr.decode(raw) catch return null;
        const node_id = parsed.nodeId() orelse return null;
        if (std.mem.eql(u8, &node_id, &self.local_node_id)) return null;
        if (self.peers.addressForEnr(&parsed) == null) return null;
        return node_id;
    }

    pub fn publishDiscovered(self: *Actor, outbox: *events.EventOutbox, raw: enr.RawEnr) void {
        _ = self;
        const parsed = enr.decode(raw.slice()) catch return;
        outbox.publish(.{ .discovered_enr = .{ .raw = raw, .enr = parsed } });
    }

    pub fn startLookup(self: *Actor, env: Env, target: types.NodeId) !u32 {
        if (self.lookups.count() >= MAX_LOOKUPS) return error.TooManyLookups;
        var closest: [lookup_mod.MAX_RESULTS]kbucket.Entry = undefined;
        const found = self.peers.routing.findClosest(&target, lookup_mod.MAX_RESULTS, &closest);
        var seeds: [lookup_mod.MAX_RESULTS]types.NodeId = undefined;
        for (closest[0..found], 0..) |entry, index| seeds[index] = entry.node_id;
        const id = self.allocateLookupId() orelse return error.TooManyLookups;
        var lookup = try lookup_mod.Lookup.init(self.alloc, target, seeds[0..found], outbound.nowNs(env.io), self.lookup_config);
        errdefer lookup.deinit(self.alloc);
        self.lookups.putAssumeCapacityNoClobber(id, lookup);
        self.lookup_count +|= 1;
        self.pumpLookup(env, id);
        return id;
    }

    pub fn maintenance(self: *Actor, env: Env) void {
        maintenance_flow.run(self, env);
    }

    pub fn cancelRequest(self: *Actor, env: Env, key: types.RequestKey) bool {
        if (self.requests.get(key) != null) {
            var finished = completion.finish(self, env, key, .canceled) orelse return false;
            defer finished.deinit(self.alloc);
            return true;
        }
        const queued = self.requests.takeQueued(key) orelse return false;
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
            .api, .detached_lookup => {},
        }
    }

    pub fn onRequestCompletion(
        self: *Actor,
        env: Env,
        key: types.RequestKey,
        origin: types.RequestOrigin,
        success: bool,
        closer: []const types.NodeId,
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
            .api => {},
            .detached_lookup => {},
        }
    }

    pub fn publishConnection(self: *Actor, outbox: *events.EventOutbox, node_id: types.NodeId, transition: peer_book.ConnectionTransition) void {
        _ = self;
        switch (transition) {
            .none => {},
            .connected => |address| outbox.publish(.{ .peer_connected = .{ .peer_id = node_id, .peer_addr = address } }),
            .disconnected => |address| outbox.publish(.{ .peer_disconnected = .{ .peer_id = node_id, .peer_addr = address } }),
        }
    }

    pub fn metricsSnapshot(self: *Actor, now_ns: i64) metrics_mod.MetricsSnapshot {
        return .{
            .kad_table_size = self.peers.routing.nodeCount(),
            .active_session_count = self.sessions.count(now_ns),
            .connected_peer_count = self.peers.connectedCount(),
            .lookup_count = self.lookup_count,
            .sent_message_count = self.metrics.sent_message_count,
            .rcvd_message_count = self.metrics.rcvd_message_count,
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
        var attempts: usize = 0;
        while (attempts < lookup_mod.MAX_PARALLELISM) : (attempts += 1) {
            const attempt: LookupAttempt = blk: {
                const lookup = self.lookups.getPtr(id) orelse return;
                const peer_id = lookup.nextPeer(self.lookup_config) orelse break;
                break :blk .{ .peer_id = peer_id, .target = lookup.target };
            };
            const peer_id = attempt.peer_id;
            const known = self.peers.known(&peer_id) orelse {
                if (self.lookups.getPtr(id)) |lookup| lookup.onFailure(&peer_id, self.lookup_config);
                continue;
            };
            var distances: [127]u16 = undefined;
            const count = lookup_mod.findNodeLogDistances(&attempt.target, &peer_id, @min(self.lookup_config.request_limit, distances.len), &distances);
            _ = self.sendFindNode(env, .{ .node_id = peer_id, .addr = known.addr }, &known.pubkey, distances[0..count], .{ .lookup = id }) catch {
                if (self.lookups.getPtr(id)) |lookup| lookup.onFailure(&peer_id, self.lookup_config);
                continue;
            };
        }
        const finished = if (self.lookups.get(id)) |lookup| lookup.state == .finished else false;
        if (finished) self.finishLookup(env.outbox, id, false);
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

    pub fn finishLookup(self: *Actor, outbox: *events.EventOutbox, id: u32, timed_out: bool) void {
        const lookup = self.lookups.getPtr(id) orelse return;
        const target = lookup.target;
        var result: std.ArrayListUnmanaged([]u8) = .empty;
        result.ensureTotalCapacityPrecise(self.alloc, self.lookup_config.num_results) catch {
            var removed = self.lookups.fetchRemove(id).?.value;
            self.requests.detachLookup(id);
            removed.deinit(self.alloc);
            outbox.notePayloadDrop();
            return;
        };
        for (lookup.peers.items) |peer| {
            if (peer.state != .succeeded or result.items.len >= self.lookup_config.num_results) continue;
            const raw = self.peers.findEnr(&peer.node_id) orelse continue;
            const copy = self.alloc.dupe(u8, raw) catch {
                outbox.notePayloadDrop();
                continue;
            };
            result.appendAssumeCapacity(copy);
        }
        var removed = self.lookups.fetchRemove(id).?.value;
        self.requests.detachLookup(id);
        removed.deinit(self.alloc);
        outbox.publish(.{ .lookup_finished = .{ .lookup_id = id, .target = target, .enrs = result, .timed_out = timed_out } });
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
            outbox.notePayloadDrop();
            return;
        };
        outbox.publish(.{ .local_enr_updated = .{ .seq = self.local.seq, .enr = copy } });
    }

    fn pingAll(self: *Actor, env: Env) void {
        for (self.peers.routing.buckets) |*bucket| {
            var snapshot: [kbucket.K]kbucket.Entry = undefined;
            const count = bucket.count;
            std.debug.assert(count <= snapshot.len);
            @memcpy(snapshot[0..count], bucket.entries[0..count]);
            for (snapshot[0..count]) |entry| {
                if (entry.status != .connected or entry.health_request != null) continue;
                const known = self.peers.known(&entry.node_id) orelse continue;
                const endpoint = types.Endpoint{ .node_id = entry.node_id, .addr = entry.addr };
                _ = self.sendProbe(env, endpoint, &known.pubkey, .health, .connected_only) catch continue;
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
