const hexToBytes = @import("std").fmt.hexToBytes;

pub fn hex(hex_string: anytype) ![hex_string.len / 2]u8 {
    var buffer: [hex_string.len / 2]u8 = undefined;
    _ = try hexToBytes(&buffer, hex_string);
    return buffer;
}

const std = @import("std");
test "hex" {
    const foo = try hex("000102030405060708090a0b0c0d0e0f");
    std.debug.print("{any}\n", .{foo});
}
