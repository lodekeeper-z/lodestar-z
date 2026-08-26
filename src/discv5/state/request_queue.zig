const std = @import("std");
const message = @import("../protocol/message.zig");
const types = @import("../types.zig");

const Allocator = std.mem.Allocator;

pub const RequestDistances = struct {
    bits: std.StaticBitSet(257) = .initEmpty(),

    pub fn fromSlice(distances: []const u16) RequestDistances {
        var result = RequestDistances{};
        for (distances) |distance| {
            if (distance <= 256) result.bits.set(distance);
        }
        return result;
    }

    pub fn contains(self: *const RequestDistances, distance: u16) bool {
        return distance <= 256 and self.bits.isSet(distance);
    }
};

pub const QueuedRequest = struct {
    origin: types.RequestOrigin,
    endpoint: types.Endpoint,
    dest_pubkey: [33]u8,
    req_id: message.ReqId,
    kind: types.RequestKind,
    requested_distances: RequestDistances,
    plaintext: types.PacketBytes,
    deadline_ns: i64,

    pub fn init(
        origin: types.RequestOrigin,
        endpoint: types.Endpoint,
        dest_pubkey: *const [33]u8,
        req_id: message.ReqId,
        kind: types.RequestKind,
        distances: []const u16,
        plaintext: []const u8,
        deadline_ns: i64,
    ) !QueuedRequest {
        if (distances.len > types.MAX_OUTBOUND_FINDNODE_DISTANCES) return error.TooManyDistances;
        return .{
            .origin = origin,
            .endpoint = endpoint,
            .dest_pubkey = dest_pubkey.*,
            .req_id = req_id,
            .kind = kind,
            .requested_distances = .fromSlice(distances),
            .plaintext = try .init(plaintext),
            .deadline_ns = deadline_ns,
        };
    }
};

pub const RequestFifo = struct {
    items: std.ArrayListUnmanaged(QueuedRequest) = .empty,
    head: usize = 0,

    pub fn deinit(self: *RequestFifo, alloc: Allocator) void {
        self.items.deinit(alloc);
    }

    pub fn len(self: RequestFifo) usize {
        return self.items.items.len - self.head;
    }

    pub fn first(self: *const RequestFifo) ?*const QueuedRequest {
        return if (self.len() == 0) null else &self.items.items[self.head];
    }

    pub fn append(self: *RequestFifo, alloc: Allocator, request: QueuedRequest) !void {
        if (self.head > 0 and self.head >= self.len()) self.compact();
        try self.items.append(alloc, request);
    }

    pub fn discardFirst(self: *RequestFifo) void {
        std.debug.assert(self.len() > 0);
        self.head += 1;
        if (self.len() == 0) self.compact();
    }

    pub fn compact(self: *RequestFifo) void {
        const live = self.len();
        if (live > 0) std.mem.copyForwards(QueuedRequest, self.items.items[0..live], self.items.items[self.head..]);
        self.items.shrinkRetainingCapacity(live);
        self.head = 0;
    }
};

pub const EndpointLane = struct {
    establishing: ?types.RequestHandle = null,
    queued: RequestFifo = .{},

    pub fn deinit(self: *EndpointLane, alloc: Allocator) void {
        self.queued.deinit(alloc);
    }
};
