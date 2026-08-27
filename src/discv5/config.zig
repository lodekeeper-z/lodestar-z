const std = @import("std");
const addr_votes = @import("service/addr_votes.zig");
const peer_store = @import("state/peer_store.zig");
const lookup = @import("service/lookup.zig");
const enr = @import("enr.zig");
const packet = @import("protocol/packet.zig");
const rate_limit = @import("rate_limit.zig");
const secp = @import("secp256k1.zig");
const types = @import("types.zig");

pub const MAX_SESSIONS: u32 = 2_000;
pub const MAX_ACTIVE_REQUESTS: usize = 1_024;
pub const MAX_NODES_RESPONSE: u16 = 16;
pub const MAX_ENRS_PER_NODES_PACKET: usize = @max((packet.MAX_PACKET_SIZE - 92) / enr.MAX_ENR_SIZE, 1);
pub const MAX_NODES_RESPONSE_CHUNKS: usize = std.math.divCeil(usize, MAX_NODES_RESPONSE, MAX_ENRS_PER_NODES_PACKET) catch unreachable;
pub const MAX_RESPONSE_RECOVERIES: usize = MAX_ACTIVE_REQUESTS;
pub const MAX_REQUEST_RETRIES: u32 = 16;
pub const MAX_QUEUED_REQUESTS: usize = 1_024;
pub const MAX_QUEUED_PER_ENDPOINT: usize = 16;
pub const MAX_CHALLENGES: usize = 1_024;
pub const MAX_WHOAREYOU_SOURCES: usize = 4_096;
pub const MAX_CONTACTS: usize = MAX_SESSIONS;
pub const MAX_EVENTS: usize = 1_024;
pub const MAX_COMMANDS: usize = 1_024;
pub const MAX_LOOKUPS: usize = 1_024;
pub const MAX_REQUEST_RESULTS: usize = MAX_ACTIVE_REQUESTS;

pub const BindAddresses = struct {
    ip4: ?types.Address = null,
    ip6: ?types.Address = null,

    pub fn count(self: BindAddresses) usize {
        return @as(usize, @intFromBool(self.ip4 != null)) + @as(usize, @intFromBool(self.ip6 != null));
    }
};

pub const Limits = struct {
    max_active_requests: usize = MAX_ACTIVE_REQUESTS,
    response_recovery_capacity: usize = MAX_RESPONSE_RECOVERIES,
    max_queued_requests: usize = MAX_QUEUED_REQUESTS,
    max_queued_requests_per_endpoint: usize = MAX_QUEUED_PER_ENDPOINT,
    session_capacity: u32 = MAX_SESSIONS,
    challenge_capacity: usize = MAX_CHALLENGES,
    whoareyou_rate_capacity: usize = MAX_WHOAREYOU_SOURCES,
    contact_capacity: usize = MAX_CONTACTS,
    event_capacity: usize = MAX_EVENTS,
    command_capacity: usize = MAX_COMMANDS,
    lookup_result_capacity: usize = MAX_LOOKUPS,
    request_result_capacity: usize = MAX_REQUEST_RESULTS,
};

pub const Config = struct {
    bind_addresses: BindAddresses,
    local_key_pair: secp.KeyPair,
    local_enr: ?[]const u8 = null,
    request_timeout_ms: u64 = 1_000,
    request_retries: u32 = 1,
    session_timeout_ms: u64 = 86_400_000,
    challenge_timeout_ms: u64 = 2_000,
    response_recovery_timeout_ms: u64 = 2_000,
    whoareyou_rate_ttl_ms: u64 = 60_000,
    bucket_pending_timeout_ms: u64 = peer_store.BUCKET_PENDING_TIMEOUT_MS,
    lookup_num_results: usize = lookup.MAX_RESULTS,
    lookup_parallelism: usize = 3,
    lookup_request_limit: usize = 3,
    lookup_timeout_ms: u64 = 60_000,
    ping_interval_ms: u64 = 30_000,
    enr_update: bool = true,
    addr_votes_to_update_enr: usize = 10,
    rate_limiter: ?rate_limit.Config = .{
        .global_quota = .{ .replenish_all_every_ms = 1_000, .max_tokens = 256 },
        .by_ip_quota = .{ .replenish_all_every_ms = 1_000, .max_tokens = 64 },
    },
    limits: Limits = .{},

    pub fn localNodeId(self: *const Config) types.NodeId {
        return enr.nodeIdFromCompressedPubkey(&secp.compressedPubkey(&self.local_key_pair)) catch unreachable;
    }

    pub fn validate(self: Config) !void {
        if (self.bind_addresses.count() == 0) return error.NoBindAddresses;
        if (self.request_retries > MAX_REQUEST_RETRIES) return error.InvalidRequestRetries;
        if (self.bind_addresses.ip4) |address| if (address != .ip4) return error.InvalidBindAddressFamily;
        if (self.bind_addresses.ip6) |address| if (address != .ip6) return error.InvalidBindAddressFamily;
        if (self.limits.max_active_requests == 0 or self.limits.max_active_requests > MAX_ACTIVE_REQUESTS or
            self.limits.response_recovery_capacity == 0 or self.limits.response_recovery_capacity > MAX_RESPONSE_RECOVERIES or
            self.limits.max_queued_requests == 0 or self.limits.max_queued_requests > MAX_QUEUED_REQUESTS or
            self.limits.max_queued_requests_per_endpoint == 0 or self.limits.max_queued_requests_per_endpoint > MAX_QUEUED_PER_ENDPOINT or
            self.limits.challenge_capacity == 0 or self.limits.challenge_capacity > MAX_CHALLENGES or
            self.limits.whoareyou_rate_capacity == 0 or self.limits.whoareyou_rate_capacity > MAX_WHOAREYOU_SOURCES or
            self.limits.contact_capacity == 0 or self.limits.contact_capacity > MAX_CONTACTS or
            self.limits.command_capacity == 0 or self.limits.command_capacity > MAX_COMMANDS or
            self.limits.lookup_result_capacity == 0 or self.limits.lookup_result_capacity > MAX_LOOKUPS or
            self.limits.request_result_capacity == 0 or self.limits.request_result_capacity > MAX_REQUEST_RESULTS or
            self.limits.event_capacity == 0 or self.limits.event_capacity > MAX_EVENTS) return error.InvalidCapacity;
        if (self.limits.session_capacity == 0 or self.limits.session_capacity > MAX_SESSIONS)
            return error.InvalidSessionCapacity;
        if (self.lookup_num_results == 0 or self.lookup_num_results > lookup.MAX_RESULTS)
            return error.InvalidLookupNumResults;
        if (self.lookup_parallelism == 0 or self.lookup_parallelism > lookup.MAX_PARALLELISM)
            return error.InvalidLookupParallelism;
        if (self.lookup_request_limit == 0 or self.lookup_request_limit > 127)
            return error.InvalidLookupRequestLimit;
        if (self.addr_votes_to_update_enr == 0 or
            self.addr_votes_to_update_enr > addr_votes.MAX_ADDR_VOTES) return error.InvalidVoteThreshold;
        const local_node_id = self.localNodeId();
        if (self.rate_limiter) |limiter| {
            if (limiter.by_ip_state_capacity == 0 or limiter.by_ip_state_capacity > MAX_WHOAREYOU_SOURCES)
                return error.InvalidRateLimiterCapacity;
        }
        if (self.local_enr) |bytes| {
            if (bytes.len > enr.MAX_ENR_SIZE) return error.InvalidEnr;
            const parsed = enr.decode(bytes) catch return error.InvalidEnr;
            const node_id = (parsed.nodeId() catch return error.InvalidEnr) orelse return error.InvalidEnr;
            if (!std.mem.eql(u8, &node_id, &local_node_id)) return error.InvalidLocalIdentity;
        }
    }
};

pub const Options = struct {
    maintenance_interval_ms: u64 = 100,

    pub fn validate(self: Options) !void {
        if (self.maintenance_interval_ms > std.math.maxInt(i64)) return error.InvalidMaintenanceInterval;
    }
};

test "config keeps protocol capacities bounded" {
    const key_pair = secp.KeyPair.generate(std.Options.debug_io);
    var config = Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = key_pair,
    };
    try config.validate();
    config.limits.session_capacity = MAX_SESSIONS + 1;
    try std.testing.expectError(error.InvalidSessionCapacity, config.validate());
    config.limits.session_capacity = (Limits{}).session_capacity;
    config.request_retries = MAX_REQUEST_RETRIES + 1;
    try std.testing.expectError(error.InvalidRequestRetries, config.validate());
    config.request_retries = 1;
    config.limits.lookup_result_capacity = 0;
    try std.testing.expectError(error.InvalidCapacity, config.validate());
    config.limits.lookup_result_capacity = MAX_LOOKUPS + 1;
    try std.testing.expectError(error.InvalidCapacity, config.validate());
    config.limits.lookup_result_capacity = (Limits{}).lookup_result_capacity;
    config.limits.request_result_capacity = 0;
    try std.testing.expectError(error.InvalidCapacity, config.validate());
    config.limits.request_result_capacity = MAX_REQUEST_RESULTS + 1;
    try std.testing.expectError(error.InvalidCapacity, config.validate());
    try std.testing.expectEqual(MAX_ACTIVE_REQUESTS, MAX_REQUEST_RESULTS);
}

test "config rejects address vote thresholds above the bounded voter capacity" {
    const key_pair = secp.KeyPair.generate(std.Options.debug_io);
    const config = Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = key_pair,
        .addr_votes_to_update_enr = 201,
    };
    try std.testing.expectError(error.InvalidVoteThreshold, config.validate());
}

test "config rejects rate limiter source-state capacities outside the bound" {
    const key_pair = secp.KeyPair.generate(std.Options.debug_io);
    var config = Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = key_pair,
    };

    config.rate_limiter.?.by_ip_state_capacity = 0;
    try std.testing.expectError(error.InvalidRateLimiterCapacity, config.validate());
    config.rate_limiter.?.by_ip_state_capacity = MAX_WHOAREYOU_SOURCES + 1;
    try std.testing.expectError(error.InvalidRateLimiterCapacity, config.validate());
}

test "config derives its local node ID from the key pair" {
    const key_pair = try secp.keyPairFromSecret(&([_]u8{0x31} ** 32));
    const config = Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = key_pair,
    };

    try config.validate();
    try std.testing.expectEqualSlices(
        u8,
        &(try @import("enr.zig").nodeIdFromCompressedPubkey(&secp.compressedPubkey(&key_pair))),
        &config.localNodeId(),
    );
}

test "config rejects a local ENR signed by another key" {
    const alloc = std.testing.allocator;
    const local_key = try secp.keyPairFromSecret(&([_]u8{0x32} ** 32));
    const other_key = try secp.keyPairFromSecret(&([_]u8{0x33} ** 32));
    var builder = @import("enr.zig").Builder.init(alloc, other_key, 1);
    const other_enr = try builder.encode();
    defer alloc.free(other_enr);
    const config = Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = local_key,
        .local_enr = other_enr,
    };

    try std.testing.expectError(error.InvalidLocalIdentity, config.validate());
}
