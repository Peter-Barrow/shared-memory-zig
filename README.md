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
const shared_memory = b.dependency("shared-memory-zig", .{}).module("shared-memory-zig");
const exe = b.addExecutable(...);
// This adds the shared-memory-zig module to the executable which can then be imported with `@import("shared-memory-zig")`
exe.root_module.addImport("shared-memory-zig", shared_memory);
```

## Dependencies
For compatibility with Windows this requires [zigwin32](https://github.com/marlersoft/zigwin32)
This codebase also uses the [known-folders](https://github.com/ziglibs/known-folders/tree/master) library to get the runtime directory on Linux and FreeBSD when using the `memfd` backend.

## Example
``` zig
const shmem = @import("shared_memory");

const TestStruct = struct {
    id: i32,
    float: f64,
    string: [20]u8,
};

const shm_name = "/test_struct_with_string";

const count = 1;

var shm = try shmem.SharedMemory(TestStruct).create(shm_name, count);
defer shm.close();

shm.data[0].id = 42;
shm.data[0].float = 3.14;
_ = std.fmt.bufPrint(&shm.data[0].string, "Hello, SHM!", .{}) catch unreachable;

// Open the shared memory in another "process"
var shm2 = try shmem.SharedMemory(TestStruct).open(shm_name);
defer shm2.close();

try std.testing.expectEqual(@as(i32, 42), shm2.data[0].id);
try std.testing.expectApproxEqAbs(@as(f64, 3.14), shm2.data[0].float, 0.001);
try std.testing.expectEqualStrings("Hello, SHM!", std.mem.sliceTo(&shm2.data[0].string, 0));

```
