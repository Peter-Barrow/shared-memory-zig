# Shared Memory Zig

**Overview**

This library implements a unified interface to shared memory on Linux, macOS and Windows

## Features

- Cross-platform support (Linux, FreeBSD, Windows)
- Multiple implementation strategies (memfd, POSIX shm, Windows file mapping)
- Type-safe shared memory segments
- Automatic memory layout management with headers
- Built-in existence checking

## Installation
Add the following to you `build.zig.zon`, replacing the url with the latest archive, for example `https://github.com/Peter-Barrow/shared-memory-zig/archive/699c748fbb143733183760cc7e83ded098eac6d1.zip` and then replacing the hash with the latest commit hash.
``` zig
.{
    .name = "my-project",
    .version = "0.0.0",
    .dependencies = .{
        .shared_memory = .{
            .url = "",
            .hash = "",
        },
    },
}
```
Or alternatively run:
``` shell
zig fetch --save git+https://github.com/Peter-Barrow/shared-memory-zig.git
```

Add the following to your `build.zig`
``` zig
const shared_memory = b.dependency("shared_memory", .{}).module("shared_memory");
const exe = b.addExecutable(...);
// This adds the shared-memory-zig module to the executable which can then be imported with `@import("shared-memory-zig")`
exe.root_module.addImport("shared-memory-zig", shared_memory);
```

## Dependencies
For compatibility with Windows this requires [zigwin32](https://github.com/marlersoft/zigwin32)
This codebase also uses the [known-folders](https://github.com/ziglibs/known-folders/tree/master) library to get the runtime directory on Linux and FreeBSD when using the `memfd` backend.

## Example
### Create a shared struct
``` zig
const shmem = @import("shared_memory");

const TestStruct = struct {
    id: i32,
    float: f64,
    string: [20]u8,
};

const shm_name = "/test_struct_with_string";

var shm: SharedStruct = try SharedStruct.create(shm_name, alloca);
defer shm.close();

shm.data.* = .{ .x = 42, .y = 3.14 };

// Open the shared memory in another "process"
var shm2 = try SharedStruct.open(shm_name, alloca);
defer shm2.close();

try std.testing.expectEqual(@as(i32, 42), shm2.data.x);
try std.testing.expectApproxEqAbs(@as(f64, 3.14), shm2.data.y, 0.001);
```

### Create a shared array of comptime known length
``` zig
const shmem = @import("shared_memory");

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
defer _ = gpa.deinit();
const alloca = switch (tag) {
    .linux, .freebsd => gpa.allocator(),
    else => null,
};

const array_size = 20;
var expected = [_]i32{0} ** array_size;
for (0..array_size) |i| {
    expected[i] = @intCast(i * 2);
}

const shm_name = "/test_array";

const SharedI32 = SharedMemory([array_size]i32);

var shm: SharedI32 = try SharedI32.create(shm_name, alloca);
defer shm.close();

for (shm.data, 0..) |*item, i| {
    item.* = @intCast(i * 2);
}

// Open the shared memory in another "process"
var shm2 = try SharedI32.open(shm_name, alloca);
defer shm2.close();

for (shm2.data, 0..) |item, i| {
    try std.testing.expectEqual(@as(i32, @intCast(i * 2)), item);
}
try std.testing.expectEqualSlices(i32, &expected, shm2.data);
}
```
### Create an array with runtime known length
``` zig
const shmem = @import("shared_memory");

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
defer _ = gpa.deinit();
const alloca = switch (tag) {
    .linux, .freebsd => gpa.allocator(),
    else => null,
};

const array_size = 20;
var expected = [_]i32{0} ** array_size;
for (0..array_size) |i| {
    expected[i] = @intCast(i * 2);
}

const shm_name = "/test_array";

const SharedI32 = SharedMemory([]i32);

var shm: SharedI32 = try SharedI32.createWithLength(shm_name, array_size, alloca);
defer shm.close();

for (shm.data, 0..) |*item, i| {
    item.* = @intCast(i * 2);
}

// Open the shared memory in another "process"
var shm2 = try SharedI32.open(shm_name, alloca);
defer shm2.close();

for (shm2.data, 0..) |item, i| {
    try std.testing.expectEqual(@as(i32, @intCast(i * 2)), item);
}
try std.testing.expectEqualSlices(i32, &expected, shm2.data);
```
