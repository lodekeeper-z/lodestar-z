const std = @import("std");
const addr_votes = @import("service/addr_votes.zig");
const kbucket = @import("kbucket.zig");
const lookup = @import("service/lookup.zig");
const rate_limit = @import("rate_limit.zig");
const secp = @import("secp256k1.zig");
const types = @import("types.zig");

pub const MAX_SESSIONS: u32 = 2_000;
pub const MAX_ACTIVE_REQUESTS: usize = 1_024;
pub const MAX_NODES_RESPONSE: u16 = 16;
pub const MAX_RESPONSE_RECOVERIES: usize = MAX_ACTIVE_REQUESTS;
pub const MAX_REQUEST_RETRIES: u32 = 16;
pub const MAX_QUEUED_REQUESTS: usize = 1_024;
pub const MAX_QUEUED_PER_ENDPOINT: usize = 16;
pub const MAX_CHALLENGES: usize = 1_024;
pub const MAX_WHOAREYOU_SOURCES: usize = 4_096;
pub const MAX_CONTACTS: usize = MAX_SESSIONS;
pub const MAX_EVENTS: usize = 1_024;
pub const MAX_COMMANDS: usize = 1_024;

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
};

pub const Config = struct {
    bind_addresses: BindAddresses,
    local_key_pair: secp.KeyPair,
    local_node_id: types.NodeId,
    local_enr: ?[]const u8 = null,
    request_timeout_ms: u64 = 1_000,
    request_retries: u32 = 1,
    session_timeout_ms: u64 = 86_400_000,
    challenge_timeout_ms: u64 = 2_000,
    response_recovery_timeout_ms: u64 = 2_000,
    whoareyou_rate_ttl_ms: u64 = 60_000,
    allow_unverified_sessions: bool = false,
    bucket_pending_timeout_ms: u64 = kbucket.BUCKET_PENDING_TIMEOUT_MS,
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
        const local_pubkey = secp.compressedPubkey(&self.local_key_pair);
        const derived_node_id = @import("enr.zig").nodeIdFromCompressedPubkey(&local_pubkey) catch
            return error.InvalidLocalIdentity;
        if (!std.mem.eql(u8, &derived_node_id, &self.local_node_id)) return error.InvalidLocalIdentity;
        if (self.rate_limiter) |limiter| {
            if (limiter.by_ip_state_capacity == 0 or limiter.by_ip_state_capacity > MAX_WHOAREYOU_SOURCES or
                limiter.banned_ip_capacity == 0 or limiter.banned_ip_capacity > MAX_WHOAREYOU_SOURCES) return error.InvalidRateLimiterCapacity;
        }
        if (self.local_enr) |bytes| {
            if (bytes.len > @import("enr.zig").MAX_ENR_SIZE) return error.InvalidEnr;
            const parsed = @import("enr.zig").decode(bytes) catch return error.InvalidEnr;
            const node_id = (parsed.nodeId() catch return error.InvalidEnr) orelse return error.InvalidEnr;
            if (!std.mem.eql(u8, &node_id, &self.local_node_id)) return error.InvalidLocalIdentity;
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
    const node_id = try @import("enr.zig").nodeIdFromCompressedPubkey(&secp.compressedPubkey(&key_pair));
    var config = Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = key_pair,
        .local_node_id = node_id,
    };
    try config.validate();
    config.limits.session_capacity = MAX_SESSIONS + 1;
    try std.testing.expectError(error.InvalidSessionCapacity, config.validate());
    config.limits.session_capacity = (Limits{}).session_capacity;
    config.request_retries = MAX_REQUEST_RETRIES + 1;
    try std.testing.expectError(error.InvalidRequestRetries, config.validate());
}

test "config rejects address vote thresholds above the bounded voter capacity" {
    const key_pair = secp.KeyPair.generate(std.Options.debug_io);
    const node_id = try @import("enr.zig").nodeIdFromCompressedPubkey(&secp.compressedPubkey(&key_pair));
    const config = Config{
        .bind_addresses = .{ .ip4 = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } } },
        .local_key_pair = key_pair,
        .local_node_id = node_id,
        .addr_votes_to_update_enr = 201,
    };
    try std.testing.expectError(error.InvalidVoteThreshold, config.validate());
}
