const std = @import("std");
const enr = @import("enr.zig");
const message = @import("protocol/message.zig");
const packet = @import("protocol/packet.zig");

pub const Address = std.Io.net.IpAddress;
pub const NodeId = enr.NodeId;

pub const RequestKind = enum {
    ping,
    findnode,
    talkreq,
};

pub const MaintenanceReason = enum {
    health,
    enr_refresh,
    eviction,
};

pub const RequestOrigin = union(enum) {
    api,
    reliable_api,
    lookup: u32,
    detached_lookup,
    maintenance: MaintenanceReason,
};

pub const Endpoint = struct {
    node_id: NodeId,
    addr: Address,
};

pub const RequestKey = struct {
    endpoint: Endpoint,
    req_id: message.ReqId,

    pub fn init(endpoint: Endpoint, req_id: message.ReqId) RequestKey {
        return .{ .endpoint = endpoint, .req_id = req_id };
    }
};

pub const EndpointContext = struct {
    pub fn hash(_: EndpointContext, endpoint: Endpoint) u64 {
        var hasher = std.hash.Wyhash.init(0);
        hasher.update(&endpoint.node_id);
        hashAddress(&hasher, endpoint.addr);
        return hasher.final();
    }

    pub fn eql(_: EndpointContext, a: Endpoint, b: Endpoint) bool {
        return std.mem.eql(u8, &a.node_id, &b.node_id) and Address.eql(&a.addr, &b.addr);
    }
};

pub const RequestKeyContext = struct {
    pub fn hash(_: RequestKeyContext, key: RequestKey) u64 {
        var hasher = std.hash.Wyhash.init(0);
        hasher.update(&key.endpoint.node_id);
        hashAddress(&hasher, key.endpoint.addr);
        hasher.update(key.req_id.slice());
        std.hash.autoHash(&hasher, key.req_id.len);
        return hasher.final();
    }

    pub fn eql(_: RequestKeyContext, a: RequestKey, b: RequestKey) bool {
        return EndpointContext.eql(.{}, a.endpoint, b.endpoint) and
            a.req_id.len == b.req_id.len and
            std.mem.eql(u8, a.req_id.slice(), b.req_id.slice());
    }
};

pub const AddressPortKey = struct {
    family: Address.Family,
    bytes: [16]u8,
    port: u16,

    pub fn fromAddress(addr: Address) AddressPortKey {
        return switch (addr) {
            .ip4 => |ip4| blk: {
                var bytes = [_]u8{0} ** 16;
                @memcpy(bytes[0..4], &ip4.bytes);
                break :blk .{ .family = .ip4, .bytes = bytes, .port = ip4.port };
            },
            .ip6 => |ip6| .{ .family = .ip6, .bytes = ip6.bytes, .port = ip6.port },
        };
    }
};

pub const ChallengeKey = struct {
    addr: AddressPortKey,
    nonce: [packet.NONCE_SIZE]u8,

    pub fn init(addr: Address, nonce: *const [packet.NONCE_SIZE]u8) ChallengeKey {
        return .{ .addr = .fromAddress(addr), .nonce = nonce.* };
    }
};

pub const PacketBytes = struct {
    bytes: [packet.MAX_PACKET_SIZE]u8 = undefined,
    len: u16 = 0,

    pub fn init(data: []const u8) error{PacketTooLarge}!PacketBytes {
        if (data.len > packet.MAX_PACKET_SIZE) return error.PacketTooLarge;
        var result = PacketBytes{ .len = @intCast(data.len) };
        @memcpy(result.bytes[0..data.len], data);
        return result;
    }

    pub fn slice(self: *const PacketBytes) []const u8 {
        return self.bytes[0..self.len];
    }
};

fn hashAddress(hasher: *std.hash.Wyhash, addr: Address) void {
    switch (addr) {
        .ip4 => |ip4| {
            hasher.update(&.{4});
            hasher.update(&ip4.bytes);
            std.hash.autoHash(hasher, ip4.port);
        },
        .ip6 => |ip6| {
            hasher.update(&.{6});
            hasher.update(&ip6.bytes);
            std.hash.autoHash(hasher, ip6.port);
        },
    }
}

test "request keys distinguish empty request ids" {
    const endpoint = Endpoint{
        .node_id = [_]u8{1} ** 32,
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 9000 } },
    };
    const empty = try message.ReqId.fromSlice(&.{});
    const zero = try message.ReqId.fromSlice(&.{0});
    try std.testing.expect(!RequestKeyContext.eql(.{}, .init(endpoint, empty), .init(endpoint, zero)));
}

test "endpoint identity includes node family address and port semantics" {
    const base = Endpoint{
        .node_id = [_]u8{1} ** 32,
        .addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 9000 } },
    };
    const same = base;
    var different_node = base;
    different_node.node_id[0] = 2;
    var different_port = base;
    different_port.addr.ip4.port = 9001;
    const different_family = Endpoint{
        .node_id = base.node_id,
        .addr = .{ .ip6 = .{ .bytes = [_]u8{0} ** 15 ++ .{1}, .port = 9000 } },
    };
    try std.testing.expect(EndpointContext.eql(.{}, base, same));
    try std.testing.expectEqual(EndpointContext.hash(.{}, base), EndpointContext.hash(.{}, same));
    try std.testing.expect(!EndpointContext.eql(.{}, base, different_node));
    try std.testing.expect(!EndpointContext.eql(.{}, base, different_port));
    try std.testing.expect(!EndpointContext.eql(.{}, base, different_family));
}
