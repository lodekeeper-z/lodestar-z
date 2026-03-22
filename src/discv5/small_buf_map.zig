const std = @import("std");
const print = std.debug.print;

/// Small fixed-size BufMap
///
/// Backed by a single array, suitable for "small" maps where `kv_data_len + num_kvs * 2 < buffer_size`.
///
/// In practice, `max_kvs = (buffer_size - 1) / (avg_kv_data_len + 2)`
pub fn SmallBufMap(comptime buffer_size: u8) type {
    comptime if (buffer_size < 5) {
        @compileError("buffer_size must be greater than 4");
    };
    return struct {
        /// offsets are stored at the end of the array, treated as a reversed sentinal-terminated slice:
        /// - `key_start(i) = if (i == 0) 0 else self.buffer[buffer_size - (2 * i)]`
        /// - `key_end(i) = self.buffer[buffer_size - (2 * i) - 1]`
        /// - `value_start(i) = self.buffer[buffer_size - (2 * i) - 1]`
        /// - `value_end(i) = self.buffer[buffer_size - (2 * i) - 2]`
        buffer: [buffer_size]u8 = [_]u8{0} ** buffer_size,

        const Self = @This();

        /// Assumes the existence of a key at i
        inline fn getKey(self: Self, i: u8) []const u8 {
            const start = if (i == 0) 0 else self.buffer[buffer_size - (2 * i)];
            const end = self.buffer[buffer_size - (2 * i) - 1];
            return self.buffer[start..end];
        }
        /// Assumes the existence of a value at i
        inline fn getValue(self: Self, i: u8) []const u8 {
            const start = self.buffer[buffer_size - (2 * i) - 1];
            const end = self.buffer[buffer_size - (2 * i) - 2];
            return self.buffer[start..end];
        }
        /// Assumes the existence of key+value at i
        pub fn getKeyValue(self: Self, i: u8) [2][]const u8 {
            return [2][]const u8{ self.getKey(i), self.getValue(i) };
        }

        /// Assumes that key and value don't come from the interal buffer memory
        fn putKeyValue(self: *Self, i: u8, key: []const u8, value: []const u8) void {
            const key_start = if (i == 0) 0 else self.buffer[buffer_size - (2 * i)];
            const key_end = @as(u8, @intCast(key_start + key.len));
            const value_end = @as(u8, @intCast(key_end + value.len));

            self.buffer[buffer_size - (2 * i) - 1] = key_end;
            self.buffer[buffer_size - (2 * i) - 2] = value_end;

            @memcpy(self.buffer[key_start..key_end], key);
            @memcpy(self.buffer[key_end..value_end], value);
        }

        fn hasEntry(self: Self, i: u8) bool {
            const offset = self.buffer[buffer_size - (2 * i) - 1];
            return offset != 0;
        }

        pub fn count(self: Self) u8 {
            var i: u8 = 0;
            while (i < 256) : (i += 1) {
                if (!self.hasEntry(i)) {
                    return i;
                }
            }
            return 255;
        }

        pub fn dataCount(self: Self) u8 {
            const c = self.count();
            return if (c == 0) 0 else self.buffer[buffer_size - (2 * c)];
        }

        inline fn getKeyIndex(self: Self, key: []const u8) ?u8 {
            var i: u8 = 0;
            while (i < 256) : (i += 1) {
                if (!self.hasEntry(i)) {
                    break;
                }
                const key_i = self.getKey(i);
                if (std.mem.eql(u8, key, key_i)) {
                    return i;
                }
            }
            return null;
        }

        pub fn get(self: Self, key: []const u8) ?[]const u8 {
            const i = self.getKeyIndex(key) orelse return null;
            return self.getValue(i);
        }

        const PutOpType = enum { replace, insert, append };
        const PutOp = struct { op: PutOpType, i: u8 };
        fn getPutOp(self: Self, key: []const u8) PutOp {
            var i: u8 = 0;
            while (i < 256) : (i += 1) {
                if (!self.hasEntry(i)) {
                    break;
                }
                switch (std.mem.order(u8, key, self.getKey(i))) {
                    .lt => return .{ .op = .insert, .i = i },
                    .eq => return .{ .op = .replace, .i = i },
                    .gt => {},
                }
            }
            return .{ .op = .append, .i = i };
        }

        const Error = error{NotEnoughSpace};

        fn appendAt(self: *Self, i: u8, key: []const u8, value: []const u8) Error!void {
            const data_c = self.dataCount();
            const c = self.count();
            const offset_c = if (c == 0) 0 else 2 * c;

            if (data_c + offset_c + 2 + key.len + value.len >= buffer_size) {
                return Error.NotEnoughSpace;
            }

            self.putKeyValue(i, key, value);
        }

        const Direction = enum { left, right };

        fn shiftData(self: *Self, direction: Direction, shift_bytes: u8, start_i: u8, end_i: u8) void {
            const start = if (start_i == 0) 0 else self.buffer[buffer_size - (2 * start_i)];
            const end = self.buffer[buffer_size - (2 * end_i) - 2];

            const shifted_start = start + shift_bytes;
            const shifted_end = end + shift_bytes;
            if (direction == .right) {
                std.mem.copyBackwards(u8, self.buffer[shifted_start..shifted_end], self.buffer[start..end]);
            } else {
                std.mem.copyForwards(u8, self.buffer[start..end], self.buffer[shifted_start..shifted_end]);
                // zero out the "shifted" data
                @memset(self.buffer[end..shifted_end], 0);
            }
        }

        fn shiftOffsets(self: *Self, direction: Direction, shift_i: u8, delta: u8, start_i: u8, cnt: u8) void {
            if (direction == .right) {
                // adding shift_i gaps
                var j: u8 = 0;
                while (j < cnt) : (j += 1) {
                    const i = cnt + start_i - 1 - j;
                    const new_i = i + shift_i;
                    self.buffer[buffer_size - (2 * new_i) - 1] = self.buffer[buffer_size - (2 * i) - 1] + delta;
                    self.buffer[buffer_size - (2 * new_i) - 2] = self.buffer[buffer_size - (2 * i) - 2] + delta;
                }
            } else {
                // removing shift_i offsets
                var i: u8 = start_i;
                while (i < start_i + cnt) : (i += 1) {
                    if (shift_i > i) {
                        continue;
                    }
                    const new_i = i - shift_i;
                    if (i != 0) self.buffer[buffer_size - (2 * new_i) - 1] = self.buffer[buffer_size - (2 * i) - 1] - delta;
                    self.buffer[buffer_size - (2 * new_i) - 2] = self.buffer[buffer_size - (2 * i) - 2] - delta;
                }
                // zero out the "shifted" offsets
                const shifted = if (shift_i > (start_i + cnt)) 0 else start_i + cnt - shift_i;
                i = start_i + shifted;
                while (i < start_i + cnt) : (i += 1) {
                    self.buffer[buffer_size - (2 * i) - 1] = 0;
                    self.buffer[buffer_size - (2 * i) - 2] = 0;
                }
            }
        }

        fn insertAt(self: *Self, i: u8, key: []const u8, value: []const u8) Error!void {
            const data_c = self.dataCount();
            const c = self.count();
            const offset_c = if (c == 0) 0 else 2 * c;
            const kv_len = @as(u8, @intCast(key.len + value.len));

            const size = @addWithOverflow(data_c + offset_c, kv_len);
            if (size[1] == 1 or size[0] >= buffer_size - 2) {
                return Error.NotEnoughSpace;
            }

            self.shiftData(.right, kv_len, i, c - 1);
            self.shiftOffsets(.right, 1, kv_len, i, c - i);
            self.putKeyValue(i, key, value);
        }

        fn replaceAt(self: *Self, i: u8, key: []const u8, value: []const u8) Error!void {
            const data_c = self.dataCount();
            const c = self.count();
            const offset_c = if (c == 0) 0 else 2 * c;
            const kv_len = key.len + value.len;
            const old_kv_len = self.getKey(i).len + self.getValue(i).len;

            const size = @addWithOverflow(data_c + offset_c - old_kv_len, kv_len);
            if (size[1] == 1 or size[0] >= buffer_size - 2) {
                return Error.NotEnoughSpace;
            }

            const kv_len_delta = @as(u8, @intCast(if (old_kv_len < kv_len) kv_len - old_kv_len else old_kv_len - kv_len));
            const direction: Direction = if (old_kv_len < kv_len) .right else .left;

            self.shiftData(direction, kv_len_delta, i, c - 1);
            self.shiftOffsets(direction, 0, kv_len_delta, i, c - i);
            self.putKeyValue(i, key, value);
        }

        pub fn put(self: *Self, key: []const u8, value: []const u8) Error!void {
            const put_op = self.getPutOp(key);
            switch (put_op.op) {
                .append => try self.appendAt(put_op.i, key, value),
                .insert => try self.insertAt(put_op.i, key, value),
                .replace => try self.replaceAt(put_op.i, key, value),
            }
        }

        const OpError = Error || error{WrongOp};

        pub fn append(self: *Self, key: []const u8, value: []const u8) OpError!void {
            const put_op = self.getPutOp(key);
            switch (put_op.op) {
                .append => try self.appendAt(put_op.i, key, value),
                else => return OpError.WrongOp,
            }
        }

        pub fn replace(self: *Self, key: []const u8, value: []const u8) OpError!void {
            const put_op = self.getPutOp(key);
            switch (put_op.op) {
                .replace => try self.replace(put_op.i, key, value),
                else => return OpError.WrongOp,
            }
        }

        pub fn insert(self: *Self, key: []const u8, value: []const u8) OpError!void {
            const put_op = self.getPutOp(key);
            switch (put_op.op) {
                .insert => try self.insertAt(put_op.i, key, value),
                else => return OpError.WrongOp,
            }
        }

        fn removeAt(self: *Self, i: u8) void {
            const c = self.count();
            const kv_len = self.getKey(i) + self.getValue(i);

            if (i == c - 1) {
                const data_c = self.dataCount();
                @memset(self.buffer[data_c - kv_len .. data_c], 0);
                self.buffer[buffer_size - (2 * i) - 1] = 0;
                self.buffer[buffer_size - (2 * i) - 2] = 0;
            } else {
                const next_i = i + 1;
                self.shiftData(.left, kv_len, next_i, c - 1);
                self.shiftOffsets(.left, 1, kv_len, next_i, c - next_i);
            }
        }

        pub fn remove(self: *Self, key: []const u8) void {
            const i = self.getKeyIndex(key) orelse return;
            self.removeAt(i);
        }

        pub fn init() Self {
            return Self{ .buffer = [_]u8{0} ** buffer_size };
        }

        pub fn clear(self: *Self) void {
            @memset(&self.buffer, 0);
        }

        const Iterator = struct {
            bm: *Self,
            pos: u8,
            len: u8,

            pub fn init(buf_map: *Self) Iterator {
                return Iterator{
                    .bm = buf_map,
                    .pos = 0,
                    .len = buf_map.count(),
                };
            }

            pub fn next(self: *Iterator) ?[2][]const u8 {
                if (self.pos < self.len) {
                    const i = self.pos;
                    self.pos += 1;
                    return self.bm.getKeyValue(i);
                }
                return null;
            }
        };

        pub fn iterator(self: *Self) Iterator {
            return Iterator.init(self);
        }
    };
}

test "sanity" {
    const Buf = SmallBufMap(25);
    var b = Buf.init();
    const k = "k";
    const v = "v";
    try b.put(k, v);
    try std.testing.expectEqualSlices(u8, v, b.get("k").?);
}

test "append" {
    const buffer_size = 16;
    const max_kvs = (buffer_size - 1) / 4;
    const Buf = SmallBufMap(buffer_size);
    var b = Buf.init();
    var i: u8 = 0;
    while (i < max_kvs) : (i += 1) {
        try b.put(&[_]u8{'a' +% i}, &[_]u8{'A' +% i});
    }

    i = 0;
    const c = b.count();
    try std.testing.expectEqual(max_kvs, c);

    while (i < c) : (i += 1) {
        try std.testing.expectEqualSlices(
            u8,
            &[_]u8{'A' + i},
            b.get(&[_]u8{'a' + i}).?,
        );
    }

    var it = b.iterator();
    var k: []const u8 = &[_]u8{0};
    while (it.next()) |kv| {
        try std.testing.expectEqual(.lt, std.mem.order(u8, k, kv[0]));
        k = kv[0];
    }
}

test "insert" {
    const buffer_size = 16;
    const max_kvs = (buffer_size - 1) / 4;
    const Buf = SmallBufMap(buffer_size);
    var b = Buf.init();
    var j: u8 = 0;
    while (j < max_kvs) : (j += 1) {
        const i = max_kvs - 1 - j;
        try b.put(&[_]u8{'a' +% i}, &[_]u8{'A' +% i});
    }

    j = 0;
    const c = b.count();
    try std.testing.expectEqual(max_kvs, c);

    while (j < c) : (j += 1) {
        const i = j;
        try std.testing.expectEqualSlices(
            u8,
            &[_]u8{'A' + i},
            b.get(&[_]u8{'a' + i}).?,
        );
    }
}

test "replace" {
    const buffer_size = 64;
    const max_kvs = (buffer_size - 1) / 4;
    const Buf = SmallBufMap(buffer_size);
    var b = Buf.init();

    var i: u8 = 0;
    while (i < max_kvs / 2) : (i += 1) {
        try b.put(&[_]u8{'a' +% i}, &[_]u8{'A' +% i});
    }
    var c = b.count();
    try std.testing.expectEqual(max_kvs / 2, c);

    // replace i=2 with longer
    try b.put(&[_]u8{'a' +% 2}, &[_]u8{'A' +% 2} ** 4);

    i = 0;
    c = b.count();
    try std.testing.expectEqual(max_kvs / 2, c);

    while (i < c) : (i += 1) {
        const expected = if (i == 2) &[_]u8{'A' + i} ** 4 else &[_]u8{'A' + i};
        try std.testing.expectEqualSlices(
            u8,
            expected,
            b.get(&[_]u8{'a' + i}).?,
        );
    }

    // replace i=2 with shorter
    try b.put(&[_]u8{'a' +% 2}, &[_]u8{'A' +% 2});

    i = 0;
    c = b.count();
    try std.testing.expectEqual(max_kvs / 2, c);

    while (i < c) : (i += 1) {
        try std.testing.expectEqualSlices(
            u8,
            &[_]u8{'A' + i},
            b.get(&[_]u8{'a' + i}).?,
        );
    }
    // replace i=0 with longer
    try b.put(&[_]u8{'a'}, &[_]u8{'A'} ** 4);

    i = 0;
    c = b.count();
    try std.testing.expectEqual(max_kvs / 2, c);

    while (i < c) : (i += 1) {
        const expected = if (i == 0) &[_]u8{'A'} ** 4 else &[_]u8{'A' + i};
        try std.testing.expectEqualSlices(
            u8,
            expected,
            b.get(&[_]u8{'a' + i}).?,
        );
    }

    // replace i=0 with shorter
    try b.put(&[_]u8{'a'}, &[_]u8{'A'});

    i = 0;
    c = b.count();
    try std.testing.expectEqual(max_kvs / 2, c);

    while (i < c) : (i += 1) {
        try std.testing.expectEqualSlices(
            u8,
            &[_]u8{'A' + i},
            b.get(&[_]u8{'a' + i}).?,
        );
    }
}

test "check bounds" {
    const buffer_sizes = [_]u8{ 5, 6, 7, 8, 254, 255 };
    inline for (buffer_sizes) |buffer_size| {
        const max_kvs = (buffer_size - 1) / 4;

        const Buf = SmallBufMap(buffer_size);
        var b = Buf.init();

        var i: u8 = 0;
        while (i < max_kvs) : (i += 1) {
            try b.put(&[_]u8{'a' +% i}, &[_]u8{'A' +% i});
        }

        i = 0;
        const c = b.count();
        while (i < c) : (i += 1) {
            try std.testing.expectEqualSlices(
                u8,
                &[_]u8{'A' + i},
                b.get(&[_]u8{'a' + i}).?,
            );
        }

        // assert correct bounds check in append
        try std.testing.expectError(
            Buf.Error.NotEnoughSpace,
            b.put(&[_]u8{'a' +% max_kvs}, &[_]u8{'A' +% max_kvs}),
        );

        // assert correct bounds check in replacement
        try std.testing.expectError(
            Buf.Error.NotEnoughSpace,
            b.put(&[_]u8{'a'}, &[_]u8{'A'} ** 4),
        );

        // assert correct bounds check in insert
        try std.testing.expectError(
            Buf.Error.NotEnoughSpace,
            b.put(&[_]u8{'a' - 1}, &[_]u8{'A'}),
        );
    }
}
