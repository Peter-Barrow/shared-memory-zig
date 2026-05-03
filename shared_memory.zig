const std = @import("std");

const tag = @import("builtin").target.os.tag;

const windows = if (tag == .windows) std.os.windows;
const winZig = if (tag == .windows) @import("zigwin32").zig;
const winFoundation = if (tag == .windows) @import("zigwin32").foundation;

const winSysInfo = if (tag == .windows) @import("zigwin32").system.system_information;
const winMem = if (tag == .windows) @import("zigwin32").system.memory;
const winSec = if (tag == .windows) @import("zigwin32").security;

const knownFolders = @import("known-folders");

const pid_t = switch (tag) {
    .windows => u32,
    else => i32,
};

const assert = std.debug.assert;

const config = @import("config");
const use_shm_funcs = switch (tag) {
    .linux, .freebsd => if (@hasDecl(config, "use_shm_funcs")) config.use_shm_funcs else false,
    .windows => false,
    else => true, // all other platforms that support shm_open and shm_unlink
};

const ShmHeader = struct {
    size_bytes: usize,
    total_elements: usize,
};

// pub const Shared = struct {
//     // data: []align(4096) u8,
//     data: []u8,
//     size: usize,
//     fd: std.fs.File.Handle,
//     pid: ?pid_t = null,
// };

fn fileNameStartsWithSlash(name: []const u8) bool {
    return std.mem.count(u8, name, "/") == 0;
}

/// Returns the XDG runtime path for a memfd metadata file with the given name
/// Caller owns returned memory
fn xgdRunTimePath(allocator: std.mem.Allocator, name: []const u8) ![]const u8 {
    const runtime_dir = blk: {
        const dir = try knownFolders.getPath(allocator, .runtime);
        if (dir) |d| {
            break :blk d;
        }
        return error.NoRuntimePathAvailable;
    };
    defer allocator.free(runtime_dir);

    return std.fmt.allocPrint(allocator, "{s}/.memfd_{s}.meta", .{ runtime_dir, name });
}

/// Metadata about a memfd file that is stored on disk
pub const XdgMemfdMeta = struct {
    pid: pid_t,
    fd: std.fs.File.Handle,
    size: usize,
    timestamp: i64,

    pub fn init(size: usize, fd: std.fs.File.Handle) XdgMemfdMeta {
        return .{
            .pid = switch (tag) {
                .linux => std.os.linux.getpid(),
                else => std.c.getpid(),
            },
            .fd = fd,
            .size = size,
            .timestamp = std.time.timestamp(),
        };
    }

    pub fn initFromAbsolutePath(absolute_path: []const u8) !XdgMemfdMeta {
        const file = try std.fs.openFileAbsolute(
            absolute_path,
            .{},
        );
        defer file.close();

        var meta: XdgMemfdMeta = undefined;
        const bytes_read = try file.readAll(std.mem.asBytes(&meta));
        if (bytes_read != @sizeOf(XdgMemfdMeta)) return error.IncorrectSize;

        // If process no longer exists, clean up file
        std.posix.kill(meta.pid, 0) catch {
            // we know the process no longer exists so delete the meta file
            try std.fs.deleteFileAbsolute(absolute_path);
        };

        return meta;
    }

    pub fn write(
        self: *XdgMemfdMeta,
        absolute_path: []const u8,
    ) void {
        const file = try std.fs.createFileAbsolute(
            absolute_path,
            .{
                .read = true,
                .truncate = true,
            },
        );
        defer file.close();

        try file.writeAll(std.mem.asBytes(self));
    }

    /// Deletes the metadata file for a memfd if it exists
    /// Does nothing if the file doesn't exist or can't be deleted
    pub fn deinit(self: *XdgMemfdMeta, absolute_path: []const u8) void {
        _ = self;
        std.fs.deleteFileAbsolute(absolute_path) catch return;
    }
};

/// Creates a shared memory segment using memfd on Linux and FreeBSD.
///
/// This function creates an anonymous file using memfd_create and maps it into memory.
/// The resulting shared memory can be accessed by child processes or other processes
/// that know the file descriptor.
///
/// Args:
///     name: The name of the shared memory segment. This is used for debugging purposes
///           and may appear in /proc/self/fd/.
///     size: The size of the shared memory segment in bytes.
///
/// Returns:
///     A Shared struct representing the created shared memory, containing:
///     - data: A slice of the mapped memory
///     - size: The size of the shared memory
///     - fd: The file descriptor of the memfd
///     - pid: The process ID that created the memfd (optional)
///
/// Error: Returns an error if any step of the shared memory creation fails, including:
///     - memfd_create failure
///     - ftruncate failure
///     - mmap failure
pub fn memfdBasedCreate(meta_data_path: []const u8, name: []const u8, size: usize) !Shared {
    const n = if (fileNameStartsWithSlash(name)) name else name[1..name.len];
    // std.debug.print("name (n):\t{s}\n", .{n});
    const fd = try std.posix.memfd_create(n, 0);

    try std.posix.ftruncate(fd, size);

    const ptr = try std.posix.mmap(
        null,
        size,
        @intCast(std.posix.PROT.READ | std.posix.PROT.WRITE),
        .{ .TYPE = .SHARED },
        fd,
        0,
    );

    const pid: pid_t = switch (tag) {
        .linux => std.os.linux.getpid(),
        else => std.c.getpid(),
    };

    // var buffer = [_]u8{0} ** std.fs.MAX_NAME_BYTES;
    // const path = std.fmt.bufPrintZ(&buffer, "/proc/{d}/fd/{d}", .{ pid, fd }) catch unreachable;
    // assert(memfdBasedExists(allocator, path) == true);

    // try writeMemfdMeta(
    //     allocator,
    //     n,
    //     .{
    //         .pid = pid,
    //         .fd = fd,
    //         .size = size,
    //         .timestamp = std.time.timestamp(),
    //     },
    // );

    const meta = XdgMemfdMeta.init(size, fd);
    meta.write(absolute_path);

    return .{
        .data = ptr,
        .size = size,
        .fd = fd,
        .pid = pid,
    };
}

/// Opens an existing memfd-based shared memory segment.
///
/// This function opens a previously created memfd-based shared memory segment
/// using its file path. It's typically used to open a shared memory segment
/// created by another process.
///
/// Args:
///     name: The name (file path) of the shared memory segment to open.
///           This should be the full path to the memfd file, typically
///           in the format "/proc/<pid>/fd/<fd>".
///
/// Returns:
///     A Shared struct representing the opened shared memory, containing:
///     - data: A slice of the mapped memory
///     - size: The size of the shared memory
///     - fd: The file descriptor of the opened memfd
///
/// Error: Returns an error if the shared memory cannot be opened, including:
///     - File open failure
///     - fstat failure
///     - mmap failure
pub fn memfdBasedOpen(allocator: std.mem.Allocator, name: []const u8) !Shared {

    // const meta = try readMemfdMeta(allocator, name) catch return error.SharedMemoryNotFound;
    const n = if (fileNameStartsWithSlash(name)) name else name[1..name.len];
    const meta = try readMemfdMeta(allocator, n);
    var buffer = [_]u8{0} ** std.fs.max_path_bytes;
    const path = try std.fmt.bufPrint(&buffer, "/proc/{d}/fd/{d}", .{ meta.pid, meta.fd });
    // assert(memfdBasedExists(allocator, path) == true);
    // std.debug.print("name to test existence:\t{s}\n", .{path});

    const handle = try std.fs.openFileAbsolute(path, .{});
    const fd = handle.handle;
    const stat = try std.posix.fstat(fd);
    const flags_protection: u32 = std.posix.PROT.READ;

    const ptr = try std.posix.mmap(
        null,
        @intCast(stat.size),
        flags_protection,
        .{ .TYPE = .SHARED },
        fd,
        0,
    );

    return .{
        .data = ptr,
        .size = @intCast(stat.size),
        .fd = fd,
    };
}

/// Checks if a memfd-based shared memory segment exists.
///
/// This function attempts to open the file at the given path to determine
/// if the memfd-based shared memory segment exists and is accessible.
///
/// Args:
///     name: The name (file path) of the shared memory segment to check.
///           This should be the full path to the memfd file, typically
///           in the format "/proc/<pid>/fd/<fd>".
///
/// Returns:
///     true if the shared memory segment exists and is accessible, false otherwise.
///
/// Note: This function does not throw errors. A false return could mean either that the
/// segment doesn't exist or that there was an error checking for its existence.
pub fn memfdBasedExists(allocator: std.mem.Allocator, name: []const u8) bool {
    // std.debug.print("name to test existence:\t{s}\n", .{name});
    const n = if (fileNameStartsWithSlash(name)) name[1..] else name;
    const handle = std.fs.openFileAbsolute(n, .{}) catch return false;
    handle.close();
    _ = readMemfdMeta(allocator, name) catch return false;
    return true;
}

/// Closes and cleans up a memfd-based shared memory segment.
///
/// This function performs the necessary cleanup operations for a memfd-based shared memory:
/// - Unmaps the shared memory from the process's address space (if a pointer is provided)
/// - Closes the file descriptor associated with the memfd
///
/// Args:
///     ptr: Optional pointer to the mapped memory. If provided, this memory will be unmapped.
///     fd: File descriptor of the shared memory (memfd).
///     name: Name of the shared memory segment. This is currently unused but kept for consistency.
///
/// Note: This function does not remove the memfd from the system. The memfd will be automatically
/// cleaned up when all references to it are closed.
pub fn memfdBasedClose(
    allocator: std.mem.Allocator,
    ptr: ?[]u8,
    fd: std.fs.File.Handle,
    name: []const u8,
) void {
    // assert(existsMemfdBased(name) == true);
    if (ptr) |p| std.posix.munmap(@alignCast(p));
    std.posix.close(fd);
    const n = if (fileNameStartsWithSlash(name)) name[1..] else name;
    deleteMemfdMeta(allocator, n);

    // assert(memfdBasedExists(name) == false);
}

/// Forcibly closes a POSIX shared memory segment.
///
/// Args:
///     name: The name of the shared memory segment to close.
pub fn posixForceClose(name: []const u8) void {
    var buffer = [_]u8{0} ** std.fs.max_name_bytes;
    const name_z = std.fmt.bufPrintZ(&buffer, "{s}", .{name}) catch unreachable;
    const rc = std.c.shm_unlink(name_z);
    _ = rc;
}

/// Generates a path string for a memory-mapped file descriptor.
///
/// This function creates a path string that represents the location of a memory-mapped
/// file descriptor in the /proc filesystem. It's primarily used for Linux and similar
/// systems that expose file descriptors through the /proc filesystem.
///
/// Args:
///     buffer: A slice of u8 to store the generated path string.
///     file_handle: The file handle of the memory-mapped file.
///     pid: An optional process ID. If not provided, the current process ID is used.
///
/// Returns:
///     A slice of u8 containing the generated path string.
///
/// Error: Returns an error if the path string cannot be formatted into the buffer.
pub fn pathFromMemFdFile(buffer: []const u8, file_handle: std.fs.File, pid: ?u32) ![]const u8 {
    const process_id = if (pid) |p| p else switch (tag) {
        .linux => std.os.linux.getpid(),
        .windows => 0,
        else => std.c.getpid(),
    };

    const path = try std.fmt.bufPrint(&buffer, "/proc/{d}/fd/{d}", .{
        process_id,
        file_handle.handle,
    });
    return path;
}

test "SharedMemory - Single Struct" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloca = switch (tag) {
        .linux, .freebsd => gpa.allocator(),
        else => null,
    };

    const TestStruct = struct {
        x: i32,
        y: f64,
    };
    const SharedStruct = SharedMemory(TestStruct);

    const shm_name = "/test_single_struct";

    if (tag != .windows) {
        if (use_shm_funcs) posixForceClose(shm_name);
    }

    var shm: SharedStruct = try SharedStruct.create(shm_name, alloca);
    defer shm.close();

    shm.data.* = .{ .x = 42, .y = 3.14 };

    // Open the shared memory in another "process"
    var shm2 = try SharedStruct.open(shm_name, alloca);
    defer shm2.close();

    try std.testing.expectEqual(@as(i32, 42), shm2.data.x);
    try std.testing.expectApproxEqAbs(@as(f64, 3.14), shm2.data.y, 0.001);
}

test "SharedMemory - Array Fixed Length" {
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

    const shm_name = "/test_array_fixed_length";

    if (tag != .windows) {
        if (use_shm_funcs) posixForceClose(shm_name);
    }

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
        // std.debug.print("data @ idx:{d} -> {d}\n", .{ i, item });
    }
    try std.testing.expectEqualSlices(i32, &expected, shm2.data);
}

test "SharedMemory - Array Runtime Length" {
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

    const shm_name = "/test_array_runtime_length";

    if (tag != .windows) {
        if (use_shm_funcs) posixForceClose(shm_name);
    }

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
        // std.debug.print("data @ idx:{d} -> {d}\n", .{ i, item });
    }
    try std.testing.expectEqualSlices(i32, &expected, shm2.data);
}

test "SharedMemory - Structure with String" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloca = switch (tag) {
        .linux, .freebsd => gpa.allocator(),
        else => null,
    };

    const TestStruct = struct {
        id: i32,
        float: f64,
        string: [20]u8,
    };

    const SharedTestStruct = SharedMemory(TestStruct);

    const shm_name = "/test_struct_with_string";

    if (tag != .windows) {
        if (use_shm_funcs) posixForceClose(shm_name);
    }

    var shm = try SharedTestStruct.create(shm_name, alloca);
    defer shm.close();

    shm.data.id = 42;
    shm.data.float = 3.14;
    _ = std.fmt.bufPrint(&shm.data.string, "Hello, SHM!", .{}) catch unreachable;

    // Open the shared memory in another "process"
    var shm2 = try SharedTestStruct.open(shm_name, alloca);
    defer shm2.close();

    try std.testing.expectEqual(@as(i32, 42), shm2.data.id);
    try std.testing.expectApproxEqAbs(@as(f64, 3.14), shm2.data.float, 0.001);
    try std.testing.expectEqualStrings("Hello, SHM!", std.mem.sliceTo(&shm2.data.string, 0));
}

pub const RawMapping = struct {
    data: []u8,
    size: usize,
    fd: std.fs.File.Handle,
    pid: ?pid_t = null,
};

pub const VTable = struct {
    createRaw: *const fn (ptr: *anyopaque, name: []const u8, size: usize) anyerror!RawMapping,
    openRaw: *const fn (ptr: *anyopaque, name: []const u8) anyerror!RawMapping,
    closeRaw: *const fn (ptr: *anyopaque, mapping: RawMapping, name: []const u8) void,
    exists: *const fn (ptr: *anyopaque, name: []const u8, size: usize) bool,
};

pub const SHMBackend = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub fn createRaw(self: SHMBackend, name: []const u8, size: usize) !RawMapping {
        return try self.vtable.createRaw(self.ptr, name, size);
    }

    pub fn openRaw(self: SHMBackend, name: []const u8) !RawMapping {
        return try self.vtable.openRaw(self.ptr, name);
    }

    pub fn closeRaw(self: SHMBackend, mapping: RawMapping, name: []const u8) void {
        try self.vtable.closeRaw(self.ptr, mapping, name);
    }

    pub fn exists(self: SHMBackend, name: []const u8, size: usize) bool {
        return self.vtable.exists(self.ptr, name, size);
    }
};

pub const PosixBackend = struct {
    const Self = @This();

    pub fn backend(self: *Self) SHMBackend {
        return .{
            .ptr = self,
            .vtable = .{
                .createRaw = create,
                .openRaw = open,
                .closeRaw = close,
                .exists = exists,
            },
        };
    }

    /// Creates a POSIX shared memory segment.
    ///
    /// This function creates a new POSIX shared memory segment that can be accessed by multiple processes.
    /// It uses shm_open to create the shared memory object and mmap to map it into the process's address space.
    ///
    /// Args:
    ///     context: An opaque pointer to be case to "Self"
    ///     name: The name of the shared memory segment. This should be unique across the system.
    ///     size: The size of the shared memory segment in bytes.
    ///
    /// Returns:
    ///     A RawMapping struct representing the created shared memory, containing:
    ///     - data: A slice of the mapped memory
    ///     - size: The size of the shared memory
    ///     - fd: The file descriptor of the shared memory object
    ///
    /// Error: Returns an error if the shared memory creation fails, including:
    ///     - shm_open failure
    ///     - ftruncate failure
    ///     - mmap failure
    fn create(context: *anyopaque, name: []const u8, size: usize) !RawMapping {
        _ = context;
        assert(exists(name) == true);

        const permissions: std.posix.mode_t = 0o666;
        const flags: std.posix.O = .{
            .ACCMODE = .RDWR,
            .CREAT = true,
            .EXCL = true,
        };

        var buffer = [_]u8{0} ** std.fs.max_name_bytes;
        const name_z = try std.fmt.bufPrintZ(&buffer, "{s}", .{name});
        const fd = std.c.shm_open(name_z, @bitCast(flags), permissions);

        if (fd == -1) {
            const err_no: u32 = @bitCast(std.c._errno().*);
            const err: std.posix.E = @enumFromInt(err_no);
            switch (err) {
                .SUCCESS => @panic("Success"),
                .ACCES => return error.AccessDenied,
                .EXIST => return error.PathAlreadyExists,
                .INVAL => unreachable,
                .MFILE => return error.ProcessFdQuotaExceeded,
                .NAMETOOLONG => return error.NameTooLong,
                .NFILE => return error.SystemFdQuotaExceeded,
                .NOENT => return error.FileNotFound,
                else => return std.posix.unexpectedErrno(err),
            }
        }

        try std.posix.ftruncate(fd, @intCast(size));

        const flags_protection: u32 = std.posix.PROT.READ | std.posix.PROT.WRITE;

        const ptr = try std.posix.mmap(
            null,
            @intCast(size),
            flags_protection,
            .{ .TYPE = .SHARED },
            fd,
            0,
        );

        assert(exists(name) == true);

        return .{
            .data = ptr,
            .size = size,
            .fd = fd,
        };
    }

    /// Opens an existing POSIX shared memory segment.
    ///
    /// This function opens a previously created POSIX shared memory segment using its name.
    /// It uses shm_open to open the shared memory object and mmap to map it into the process's address space.
    ///
    /// Args:
    ///     context: An opaque pointer to be case to "Self"
    ///     name: The name of the shared memory segment to open. This should match the name used in posixCreate().
    ///
    /// Returns:
    ///     A RawMapping struct representing the opened shared memory, containing:
    ///     - data: A slice of the mapped memory
    ///     - size: The size of the shared memory
    ///     - fd: The file descriptor of the shared memory object
    ///
    /// Error: Returns an error if the shared memory cannot be opened, including:
    ///     - shm_open failure
    ///     - fstat failure
    ///     - mmap failure
    fn open(context: *anyopaque, name: []const u8) !RawMapping {
        _ = context;
        assert(exists(name) == true);

        const permissions: std.posix.mode_t = 0o666;
        const flags: std.posix.O = .{
            .ACCMODE = .RDWR,
        };

        var buffer = [_]u8{0} ** std.fs.max_name_bytes;
        const name_z = try std.fmt.bufPrintZ(&buffer, "{s}", .{name});
        const fd = std.c.shm_open(name_z, @bitCast(flags), permissions);
        if (fd == -1) {
            const err_no: u32 = @bitCast(std.c._errno().*);
            const err: std.posix.E = @enumFromInt(err_no);
            switch (err) {
                .SUCCESS => @panic("Success"),
                .ACCES => return error.AccessDenied,
                .EXIST => return error.PathAlreadyExists,
                .INVAL => unreachable,
                .MFILE => return error.ProcessFdQuotaExceeded,
                .NAMETOOLONG => return error.NameTooLong,
                .NFILE => return error.SystemFdQuotaExceeded,
                .NOENT => return error.FileNotFound,
                else => return std.posix.unexpectedErrno(err),
            }
        }

        const stat = try std.posix.fstat(fd);

        const flags_protection: u32 = std.posix.PROT.READ | std.posix.PROT.WRITE;

        const ptr = try std.posix.mmap(
            null,
            @intCast(stat.size),
            flags_protection,
            .{ .TYPE = .SHARED },
            fd,
            0,
        );

        return .{
            .data = ptr,
            .size = @intCast(stat.size),
            .fd = fd,
        };
    }

    /// Closes and cleans up a POSIX shared memory segment.
    ///
    /// This function performs necessary cleanup operations for the POSIX shared memory segment:
    /// - Unmaps the shared memory from the process's address space (if a pointer is provided)
    /// - Closes the file descriptor associated with the shared memory
    /// - Removes the shared memory object from the system
    ///
    /// Args:
    ///     context: An opaque pointer to be case to "Self"
    ///     mapping: RawMapping of a shared memory segment
    ///     name: Name of the shared memory segment.
    ///
    /// Note: After calling this function, the shared memory segment will be removed from the system
    /// and will no longer be accessible by any process.
    fn close(context: *anyopaque, mapping: RawMapping, name: []const u8) void {
        _ = context;
        std.posix.munmap(mapping.data.ptr);

        std.posix.close(mapping.fd);

        var buffer = [_]u8{0} ** std.fs.max_name_bytes;
        const name_z = std.fmt.bufPrintZ(&buffer, "{s}", .{name}) catch unreachable;
        const rc = std.c.shm_unlink(name_z);
        _ = rc;
        // if (rc == -1) {
        //     const err_no = std.c._errno().*;
        //     const err: std.posix.E = @enumFromInt(err_no);
        //     switch (err) {
        //         .SUCCESS => return,
        //         .ACCES => return error.AccessDenied,
        //         .PERM => return error.AccessDenied,
        //         .INVAL => unreachable,
        //         .NAMETOOLONG => return error.NameTooLong,
        //         .NOENT => return, //return error.FileNotFound,
        //         else => return std.posix.unexpectedErrno(err),
        //     }
        // }
        assert(exists(name) == false);
    }

    /// Checks if a POSIX shared memory segment exists.
    ///
    /// This function attempts to open the shared memory object with read-only access
    /// to determine if it exists and is accessible.
    ///
    /// Args:
    ///     context: An opaque pointer to be case to "Self"
    ///     name: The name of the shared memory segment to check.
    ///
    /// Returns:
    ///     true if the shared memory segment exists and is accessible, false otherwise.
    ///
    /// Note: This function does not throw errors. A false return could mean either that the
    /// segment doesn't exist or that there was an error checking for its existence.
    fn exists(context: *anyopaque, name: []const u8) bool {
        _ = context;
        const flags: std.posix.O = .{
            .ACCMODE = .RDONLY,
        };

        var buffer = [_]u8{0} ** std.fs.max_path_bytes;
        const name_z = std.fmt.bufPrintZ(&buffer, "{s}", .{name}) catch unreachable;

        const rc = std.c.shm_open(name_z, @bitCast(flags), 0o444);

        if (rc >= 0) {
            return true;
        }

        return false;
    }
};

pub const WindowsBackend = struct {
    const Self = @This();

    pub fn backend(self: *Self) SHMBackend {
        return .{
            .ptr = self,
            .vtable = .{
                .createRaw = create,
                .openRaw = open,
                .closeRaw = close,
                .exists = exists,
            },
        };
    }

    /// Creates a Windows shared memory segment.
    ///
    /// This function creates a new Windows shared memory segment that can be accessed by multiple processes.
    /// It uses CreateFileMappingA to create the shared memory object and MapViewOfFile to map it into the process's address space.
    ///
    /// Args:
    ///     context: An opaque pointer to be case to "Self"
    ///     name: The name of the shared memory segment. This should be unique across the system.
    ///     size: The size of the shared memory segment in bytes.
    ///
    /// Returns:
    ///     A RawMapping struct representing the created shared memory, containing:
    ///     - data: A slice of the mapped memory
    ///     - size: The size of the shared memory
    ///     - fd: The handle of the file mapping object
    ///
    /// Error: Returns an error if the shared memory creation fails, including:
    ///     - CreateFileMappingA failure
    ///     - MapViewOfFile failure
    fn create(context: *anyopaque, name: []const u8, size: usize) !RawMapping {
        _ = context;
        assert(exists(name) == false);

        var buffer = [_]u8{0} ** std.fs.max_name_bytes;
        const name_z = std.fmt.bufPrintZ(&buffer, "{s}", .{name}) catch unreachable;

        const handle_maybe: ?std.os.windows.HANDLE = winMem.CreateFileMappingA(
            windows.INVALID_HANDLE_VALUE,
            null,
            .{
                .PAGE_EXECUTE_READWRITE = 1,
            },
            0,
            @intCast(size),
            name_z,
        );

        var handle: std.os.windows.HANDLE = std.os.windows.INVALID_HANDLE_VALUE;
        if (handle_maybe) |h| {
            handle = h;
        } else {
            switch (std.os.windows.kernel32.GetLastError()) {
                else => |err| return std.os.windows.unexpectedError(err),
            }
        }

        const ptr_maybe = winMem.MapViewOfFile(
            handle,
            .{
                .READ = 1,
                .WRITE = 1,
            },
            0,
            0,
            size,
        );

        var ptr: []align(4096) u8 = undefined;

        if (ptr_maybe) |p| {
            ptr.ptr = @ptrCast(@alignCast(p));
            // ptr.len = size;
        } else {
            switch (std.os.windows.kernel32.GetLastError()) {
                else => |err| return std.os.windows.unexpectedError(err),
            }
        }

        assert(exists(name) == true);

        return .{
            .data = ptr[0..@as(usize, @intCast(size))],
            .size = size,
            .fd = handle,
        };
    }

    /// Opens an existing Windows shared memory segment.
    ///
    /// This function opens a previously created Windows shared memory segment using its name.
    /// It uses OpenFileMappingA to open the shared memory object and MapViewOfFile to map it into the process's address space.
    ///
    /// Args:
    ///     context: An opaque pointer to be case to "Self"
    ///     name: The name of the shared memory segment to open. This should match the name used in windowsCreate().
    ///
    /// Returns:
    ///     A RawMapping struct representing the opened shared memory, containing:
    ///     - data: A slice of the mapped memory
    ///     - size: The size of the shared memory
    ///     - fd: The handle of the file mapping object
    ///
    /// Error: Returns an error if the shared memory cannot be opened, including:
    ///     - OpenFileMappingA failure
    ///     - MapViewOfFile failure
    fn open(context: *anyopaque, name: []const u8) !RawMapping {
        _ = context;
        assert(exists(name) == true);

        var buffer = [_]u8{0} ** std.fs.max_name_bytes;
        const name_z = std.fmt.bufPrintZ(&buffer, "{s}", .{name}) catch unreachable;

        const handle_flags: winMem.FILE_MAP = .{
            .READ = 1,
            .WRITE = 1,
        };

        const handle_maybe = winMem.OpenFileMappingA(
            @bitCast(handle_flags),
            winZig.FALSE,
            name_z,
        );

        var handle: std.os.windows.HANDLE = std.os.windows.INVALID_HANDLE_VALUE;
        if (handle_maybe) |h| {
            handle = h;
        } else {
            switch (std.os.windows.kernel32.GetLastError()) {
                else => |err| return std.os.windows.unexpectedError(err),
            }
        }

        const ptr_maybe = winMem.MapViewOfFile(
            handle,
            .{
                .READ = 1,
                .WRITE = 1,
            },
            0,
            0,
            0,
        );

        var size: usize = 0;
        var ptr: []u8 = undefined;

        if (ptr_maybe) |p| {
            ptr.ptr = @ptrCast(@alignCast(p));
            const header: ShmHeader = @as(
                *ShmHeader,
                @ptrCast(@alignCast(ptr.ptr[0..@sizeOf(ShmHeader)])),
            ).*;
            size = header.size_bytes;
            ptr.len = @intCast(size);
        } else {
            switch (std.os.windows.kernel32.GetLastError()) {
                else => |err| return std.os.windows.unexpectedError(err),
            }
        }

        return .{
            .data = ptr[0..@as(usize, @intCast(size))],
            .size = @intCast(size - 1),
            .fd = handle,
        };
    }

    /// Closes and cleans up a Windows shared memory segment.
    ///
    /// This function performs necessary cleanup operations for the Windows shared memory segment:
    /// - Unmaps the view of the file from the process's address space (if a pointer is provided)
    /// - Closes the handle associated with the file mapping object
    ///
    /// Args:
    ///     context: An opaque pointer to be case to "Self"
    ///     mapping: RawMapping of a shared memory segment
    ///     name: Name of the shared memory segment.
    ///
    /// Note: After calling this function, the shared memory segment will no longer be accessible
    /// by this process, but it may still exist in the system if other processes are using it.
    fn close(context: *anyopaque, mapping: RawMapping, name: []const u8) void {
        _ = context;
        assert(exists(name) == true);
        //if (ptr) |p| _ = winMem.UnmapViewOfFile;
        // if (ptr) |p| {
        //     _ = winMem.UnmapViewOfFile(@ptrCast(p.ptr)) == winZig.FALSE;
        //     // if (winMem.UnmapViewOfFile(@ptrCast(p.ptr)) == winZig.FALSE) {
        //     //     switch (std.os.windows.kernel32.GetLastError()) {
        //     //         else => |err| return std.os.windows.unexpectedError(err),
        //     //     }
        //     // }
        // }
        _ = winMem.UnmapViewOfFile(@ptrCast(mapping.data.ptr)) == winZig.FALSE;
        windows.CloseHandle(mapping.fd);
        assert(exists(name) == false);
    }

    /// Checks if a Windows shared memory segment exists.
    ///
    /// This function attempts to open the shared memory object with read-write access
    /// to determine if it exists and is accessible.
    ///
    /// Args:
    ///     context: An opaque pointer to be case to "Self"
    ///     name: The name of the shared memory segment to check.
    ///
    /// Returns:
    ///     true if the shared memory segment exists and is accessible, false otherwise.
    ///
    /// Note: This function does not throw errors. A false return could mean either that the
    /// segment doesn't exist or that there was an error checking for its existence.
    fn exists(context: *anyopaque, name: []const u8) bool {
        _ = context;
        var buffer = [_]u8{0} ** std.fs.max_name_bytes;
        const name_z = std.fmt.bufPrintZ(&buffer, "{s}", .{name}) catch unreachable;

        const handle_flags: winMem.FILE_MAP = .{
            .READ = 1,
            .WRITE = 1,
        };

        const handle = winMem.OpenFileMappingA(
            @bitCast(handle_flags),
            winZig.FALSE,
            name_z,
        );

        if (handle) |h| {
            const file: std.fs.File = .{
                .handle = h,
            };
            file.close();
            return true;
        }

        return false;
    }
};

pub const DefaultBackend = switch (tag) {
    .windows => WindowsBackend,
    // .linux, .freebsd => if (use_shm_funcs) PosixBackend else MemfdBackend,
    else => PosixBackend,
};

pub const SharedRegion = struct {
    name: []const u8 = [_]u8{0} ** std.fs.max_name_bytes,
    mapping: RawMapping,
    meta_dir: std.fs.Dir,
    backend: SHMBackend,

    pub fn create(
        name: []const u8,
        size: usize,
        meta_dir: std.fs.Dir,
        backend: SHMBackend,
    ) !SharedRegion {
        const mapping = try backend.createRaw(name, size);
        const result: SharedRegion = .{
            .mapping = mapping,
            .meta_dir = meta_dir,
            .backend = backend,
        };

        @memcpy(result.name, name);

        return result;
    }

    pub fn open(name: []const u8, meta_dir: std.fs.Dir, backend: SHMBackend) !SharedRegion {
        const mapping = try backend.openRaw(name);
        const result: SharedRegion = .{
            .mapping = mapping,
            .meta_dir = meta_dir,
            .backend = backend,
        };

        @memcpy(result.name, name);

        return result;
    }

    pub fn close(self: *SharedRegion) void {
        self.backend.closeRaw(self.mapping, self.name);
    }

    pub fn exists(self: *SharedRegion) bool {
        return self.backend.exists(self.name, self.mapping.size);
    }

    pub fn bytes(self: *SharedRegion) []u8 {
        return self.mapping.data;
    }
};

pub fn SharedMemory(comptime S: type) type {
    return struct {
        const Self = @This();
        const T = switch (@typeInfo(S)) {
            .pointer => |ptr| switch (ptr.size) {
                .slice => S,
                else => []S,
            },
            .array => *S,
            else => *S,
        };

        region: SharedRegion,
        data: T,

        pub fn create(name: []const u8, meta_dir: std.fs.Dir, backend: SHMBackend) !Self {
            const shared_region = try SharedRegion.create(
                name,
                @sizeOf(S),
                meta_dir,
                backend,
            );

            const data: T = @ptrCast(@alignCast(shared_region.bytes()));

            return .{
                .region = shared_region,
                .data = data,
            };
        }

        pub fn createCapacity(name: []const u8, count: usize, meta_dir: std.fs.Dir, backend: SHMBackend) !Self {
            const size = @sizeOf(S) * count;
            const shared_region = try SharedRegion.create(
                name,
                size,
                meta_dir,
                backend,
            );

            const data: T = @ptrCast(@alignCast(shared_region.bytes()));

            return .{
                .region = shared_region,
                .data = data,
            };
        }

        pub fn open(name: []const u8, meta_dir: std.fs.Dir, backend: SHMBackend) !Self {
            const shared_region = try SharedRegion.open(
                name,
                meta_dir,
                backend,
            );

            const data: T = @ptrCast(@alignCast(shared_region.bytes()));

            return .{
                .region = shared_region,
                .data = data,
            };
        }

        pub fn close(self: *Self) void {
            self.region.close();
            self.data = undefined;
        }
    };
}
