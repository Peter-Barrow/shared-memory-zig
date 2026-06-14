const std = @import("std");

const tag = @import("builtin").target.os.tag;

const windows = if (tag == .windows) std.os.windows;
const winZig = if (tag == .windows) @import("win32").zig;
const winFoundation = if (tag == .windows) @import("win32").foundation;

const winSysInfo = if (tag == .windows) @import("win32").system.system_information;
const winMem = if (tag == .windows) @import("win32").system.memory;
const winSec = if (tag == .windows) @import("win32").security;

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

pub const RawMapping = struct {
    data: []u8,
    size: usize,
    fd: std.Io.File.Handle,
    pid: ?pid_t = null,
    is_owner: bool = false,
};

pub const VTable = struct {
    createRaw: *const fn (ptr: *anyopaque, name: []const u8, size: usize) anyerror!RawMapping,
    openRaw: *const fn (ptr: *anyopaque, name: []const u8) anyerror!RawMapping,
    closeRaw: *const fn (ptr: *anyopaque, mapping: RawMapping, name: []const u8) void,
    exists: *const fn (ptr: *anyopaque, name: []const u8) bool,
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
        self.vtable.closeRaw(self.ptr, mapping, name);
    }

    pub fn exists(self: SHMBackend, name: []const u8) bool {
        return self.vtable.exists(self.ptr, name);
    }
};

pub const PosixBackend = struct {
    const Self = @This();
    const vtable: VTable = .{
        .createRaw = create,
        .openRaw = open,
        .closeRaw = close,
        .exists = exists,
    };

    pub fn backend(self: *Self) SHMBackend {
        return .{
            .ptr = self,
            .vtable = &vtable,
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
        assert(exists(context, name) == false);

        const permissions: std.c.mode_t = 0o666;
        const flags: std.c.O = .{
            .ACCMODE = .RDWR,
            .CREAT = true,
            .EXCL = true,
        };

        var buffer = [_]u8{0} ** std.fs.max_name_bytes;
        const name_z = try std.fmt.bufPrintZ(&buffer, "{s}", .{name});
        const fd = std.c.shm_open(name_z, @bitCast(flags), permissions);
        switch (std.c.errno(fd)) {
            .SUCCESS => {},
            else => return error.Unexpected,
        }

        const ftrunctate_rc = std.c.ftruncate(fd, @intCast(size));
        switch (std.c.errno(ftrunctate_rc)) {
            .SUCCESS => {},
            else => return error.Unexpected,
        }
        const flags_protection: std.posix.PROT = .{
            .READ = true,
            .WRITE = true,
        };

        const ptr: [*]u8 = @ptrCast(std.c.mmap(
            null,
            @intCast(size),
            flags_protection,
            .{ .TYPE = .SHARED },
            fd,
            0,
        ));

        return .{
            .data = ptr[0..size],
            .size = size,
            .fd = fd,
            .is_owner = true,
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
        assert(exists(context, name) == true);

        const permissions: std.c.mode_t = 0o666;
        const flags: std.c.O = .{
            .ACCMODE = .RDWR,
        };

        var buffer = [_]u8{0} ** std.fs.max_name_bytes;
        const name_z = try std.fmt.bufPrintZ(&buffer, "{s}", .{name});
        const fd = std.c.shm_open(name_z, @bitCast(flags), permissions);

        switch (std.c.errno(fd)) {
            .SUCCESS => {},
            else => return error.Unexpected,
        }

        var stat: std.c.Stat = undefined;
        const stat_rc = std.c.fstat(fd, &stat);
        switch (std.c.errno(stat_rc)) {
            .SUCCESS => {},
            else => return error.Unexpected,
        }

        // const flags_protection: u32 = std.posix.PROT.READ | std.posix.PROT.WRITE;
        const flags_protection: std.posix.PROT = .{
            .READ = true,
            .WRITE = true,
        };

        const ptr: [*]u8 = @ptrCast(std.c.mmap(
            null,
            @intCast(stat.size),
            flags_protection,
            .{ .TYPE = .SHARED },
            fd,
            0,
        ));

        return .{
            .data = ptr[0..@as(usize, @intCast(stat.size))],
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
        // std.c.munmap(@alignCast(&mapping.data.ptr[0]), @intCast(mapping.size));
        _ = std.c.munmap(@ptrCast(@alignCast(mapping.data.ptr)), @intCast(mapping.size));
        _ = std.c.close(@intCast(mapping.fd));
        if (mapping.is_owner) {
            var buffer = [_]u8{0} ** std.fs.max_name_bytes;
            const name_z = std.fmt.bufPrintZ(&buffer, "{s}", .{name}) catch unreachable;
            _ = std.c.shm_unlink(name_z);
        }
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
        const flags: std.c.O = .{
            .ACCMODE = .RDONLY,
        };

        var buffer = [_]u8{0} ** std.fs.max_path_bytes;
        const name_z = std.fmt.bufPrintZ(&buffer, "{s}", .{name}) catch unreachable;

        const rc = std.c.shm_open(name_z, @bitCast(flags));

        if (rc >= 0) {
            _ = std.c.close(rc);
            return true;
        }

        return false;
    }
};

pub const WindowsBackend = struct {
    const Self = @This();
    const vtable: VTable = .{
        .createRaw = create,
        .openRaw = open,
        .closeRaw = close,
        .exists = exists,
    };

    pub fn backend(self: *Self) SHMBackend {
        return .{
            .ptr = self,
            .vtable = &vtable,
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
        assert(exists(context, name) == false);

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

        assert(exists(context, name) == true);

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
        assert(exists(context, name) == true);

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
        assert(exists(context, name) == true);
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
        assert(exists(context, name) == false);
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
            const file: std.Io.File = .{
                .handle = h,
            };
            file.close();
            return true;
        }

        return false;
    }
};

pub const MemfdBackend = struct {
    const Self = @This();
    meta_dir: std.Io.Dir,
    allocator: std.mem.Allocator,

    const vtable: VTable = .{
        .createRaw = create,
        .openRaw = open,
        .closeRaw = close,
        .exists = exists,
    };

    pub fn backend(self: *Self) SHMBackend {
        return .{
            .ptr = self,
            .vtable = &vtable,
        };
    }

    /// Creates a shared memory segment using memfd on Linux and FreeBSD.
    ///
    /// This function creates an anonymous file using memfd_create and maps it into memory.
    /// The resulting shared memory can be accessed by child processes or other processes
    /// that know the file descriptor.
    ///
    /// Args:
    ///     context: An opaque pointer to be case to "Self"
    ///     name: The name of the shared memory segment. This is used for debugging purposes
    ///           and may appear in /proc/self/fd/.
    ///     size: The size of the shared memory segment in bytes.
    ///
    /// Returns:
    ///     A RawMapping struct representing the created shared memory, containing:
    ///     - data: A slice of the mapped memory
    ///     - size: The size of the shared memory
    ///     - fd: The file descriptor of the memfd
    ///     - pid: The process ID that created the memfd (optional)
    ///
    /// Error: Returns an error if any step of the shared memory creation fails, including:
    ///     - memfd_create failure
    ///     - ftruncate failure
    ///     - mmap failure
    fn create(context: *anyopaque, name: []const u8, size: usize) !RawMapping {
        _ = context;

        const fd = try std.posix.memfd_create(name, 0);

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
    ///     context: An opaque pointer to be case to "Self"
    ///     name: The name (file path) of the shared memory segment to open.
    ///           This should be the full path to the memfd file, typically
    ///           in the format "/proc/<pid>/fd/<fd>".
    ///
    /// Returns:
    ///     A RawMapping struct representing the opened shared memory, containing:
    ///     - data: A slice of the mapped memory
    ///     - size: The size of the shared memory
    ///     - fd: The file descriptor of the opened memfd
    ///
    /// Error: Returns an error if the shared memory cannot be opened, including:
    ///     - File open failure
    ///     - fstat failure
    ///     - mmap failure
    fn open(context: *anyopaque, name: []const u8) !RawMapping {
        const self: *@This() = @ptrCast(context);

        const meta_data = try SharedMappingMeta.initFromFile(
            self.meta_dir,
            name,
            self.allocator,
        );

        const memfd_path_buf: []const u8 = .{0} ** std.fs.max_path_bytes;
        const memfd_path = try std.fmt.bufPrint(
            &memfd_path_buf,
            "/proc/{d}/fd/{d}",
            .{ meta_data.pid, meta_data.fd },
        );
        const handle = try std.Io.openFileAbsolute(memfd_path, .{});
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
            .pid = meta_data.pid,
        };
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
    fn close(context: *anyopaque, mapping: RawMapping, name: []const u8) void {
        const self: *@This() = @ptrCast(context);

        if (!self.exists(name)) {
            return;
        }

        std.posix.munmap(@alignCast(mapping.data));
        std.posix.close(mapping.fd);
        // const meta_path = try xgdRunTimePath(self.allocator, name);
        // defer self.allocator.free(meta_path);
        // std.fs.deleteFileAbsolute(meta_path) catch return;
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
    fn exists(context: *anyopaque, name: []const u8) bool {
        const self: *@This() = @ptrCast(context);
        // const meta_path = try xgdRunTimePath(self.allocator, name);
        // try XdgMemfdMeta.initFromAbsolutePath(meta_path) catch |err| switch (err) {
        //     .MetaDoesNotExist => return false,
        //     else => return true,
        // };

        try SharedMappingMeta.initFromFile(
            self.meta_dir,
            name,
            self.allocator,
        ) catch return false;

        return true;
    }
};

pub const DefaultBackend = switch (tag) {
    .windows => WindowsBackend,
    .linux, .freebsd => if (use_shm_funcs) PosixBackend else MemfdBackend,
    else => PosixBackend,
};

fn fieldsOf(comptime T: type) []const std.builtin.Type.StructField {
    return switch (@typeInfo(T)) {
        .@"struct" => |s| s.fields,
        .pointer, .array => &.{.{
            .name = "data",
            .type = T,
            .default_value_ptr = null,
            .is_comptime = false,
            .alignment = @alignOf(T),
        }},
        else => &.{.{
            .name = @typeName(T),
            .type = T,
            .default_value_ptr = null,
            .is_comptime = false,
            .alignment = @alignOf(T),
        }},
    };
}

// test "fieldsOf" {
//     const S = struct { x: i32, y: f64 };
//
//     inline for (fieldsOf(S)) |f| {
//         std.debug.print(
//             "struct  | name: {s:<10} type: {s}\n",
//             .{
//                 f.name,
//                 @typeName(f.type),
//             },
//         );
//     }
//     inline for (fieldsOf(i32)) |f| {
//         std.debug.print(
//             "scalar  | name: {s:<10} type: {s}\n",
//             .{
//                 f.name,
//                 @typeName(f.type),
//             },
//         );
//     }
//     inline for (fieldsOf([]u8)) |f| {
//         std.debug.print(
//             "pointer | name: {s:<10} type: {s}\n",
//             .{
//                 f.name,
//                 @typeName(f.type),
//             },
//         );
//     }
//     inline for (fieldsOf([4]u8)) |f| {
//         std.debug.print(
//             "array   | name: {s:<10} type: {s}\n",
//             .{
//                 f.name,
//                 @typeName(f.type),
//             },
//         );
//     }
// }

pub const SharedMappingMeta = struct {
    const Field = struct {
        name: []const u8 = "data",
        type: []const u8 = "u8",
        size: u32 = 0,
        offset: u64 = 0,
    };

    version: u16 = 1,
    size_bytes: u64,
    // timestamp: i64,
    pid: u32,
    fd: u32,
    fields: []const Field,

    pub fn init(
        size_bytes: u64,
        pid: pid_t,
        fd: std.Io.File.Handle,
        allocator: std.mem.Allocator,
    ) !@This() {
        const fields = try allocator.dupe(
            Field,
            &.{
                .{
                    .name = "data",
                    .type = "u8",
                    .size = 1,
                    .offset = 0,
                },
            },
        );
        return .{
            .size_bytes = size_bytes,
            // .timestamp = std.time.timestamp(),
            // .timestamp = std.Io.Timestamp.now(io: Io, clock: Clock);
            .pid = @intCast(pid),
            .fd = @intCast(fd),
            .fields = fields,
        };
    }

    pub fn initWithFields(
        comptime T: type,
        size_bytes: u64,
        pid: pid_t,
        fd: std.Io.File.Handle,
        allocator: std.mem.Allocator,
    ) !@This() {
        const comptime_fields: []const Field = comptime blk: {
            const fields_of_t = fieldsOf(T);
            var _fields: [fields_of_t.len]Field = undefined;
            for (&_fields, fields_of_t) |*_f, f| {
                _f.name = f.name;
                _f.type = @typeName(f.type);
                _f.size = @sizeOf(f.type);
            }
            const final = _fields;
            break :blk &final;
        };

        const fields = try allocator.dupe(Field, comptime_fields);

        const num_elements = @divFloor(size_bytes, @sizeOf(T));
        var offset: u64 = 0;
        for (fields) |*f| {
            f.offset = offset;
            offset += f.size * num_elements;
        }

        var new = try SharedMappingMeta.init(
            size_bytes,
            pid,
            fd,
            allocator,
        );
        allocator.free(new.fields);
        new.fields = fields;
        return new;
    }

    pub fn initFromFile(
        meta_dir: std.Io.Dir,
        name: []const u8,
        allocator: std.mem.Allocator,
    ) !@This() {
        const buf: []const u8 = .{0} ** std.fs.max_path_bytes;
        const file_name = try std.fmt.bufPrint(buf, "{s}-meta.json", .{name});

        const contents = meta_dir.readFileAlloc(allocator, file_name, 4096);
        defer allocator.free(contents);

        const parsed = try std.json.parseFromSlice(
            @This(),
            allocator,
            contents,
            .{},
        );
        defer parsed.deinit();

        const new: @This() = parsed.value;
        return new;
    }

    pub fn write(
        self: *const @This(),
        meta_dir: std.Io.Dir,
        name: []const u8,
        io: std.Io,
        allocator: std.mem.Allocator,
    ) !void {
        var buf: std.Io.Writer.Allocating = .init(allocator);
        defer buf.deinit();
        try buf.writer.print("{f}", .{std.json.fmt(
            self,
            .{
                .whitespace = .indent_4,
            },
        )});

        var name_buf = [_]u8{0} ** std.fs.max_name_bytes;
        const name_ext = try std.fmt.bufPrint(
            &name_buf,
            "{s}-meta.json",
            .{name},
        );
        const file = try meta_dir.createFile(io, name_ext, .{});
        defer file.close(io);

        try file.writePositionalAll(io, buf.written(), 0);
    }

    pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
        allocator.free(self.fields);
        self.fields = undefined;
    }
};

pub const SharedRegion = struct {
    name: [std.fs.max_name_bytes]u8 = [_]u8{0} ** std.fs.max_name_bytes,
    name_len: usize = 0,
    mapping: RawMapping,
    meta_dir: std.Io.Dir,
    backend: SHMBackend,

    pub fn create(
        name: []const u8,
        size: usize,
        meta_dir: std.Io.Dir,
        backend: SHMBackend,
    ) !SharedRegion {
        const mapping = try backend.createRaw(name, size);
        var result: SharedRegion = .{
            .name_len = name.len,
            .mapping = mapping,
            .meta_dir = meta_dir,
            .backend = backend,
        };

        @memcpy(@constCast(result.name[0..name.len]), name);

        return result;
    }

    pub fn nameSlice(self: *const SharedRegion) []const u8 {
        return self.name[0..self.name_len];
    }

    pub fn open(name: []const u8, meta_dir: std.Io.Dir, backend: SHMBackend) !SharedRegion {
        const mapping = try backend.openRaw(name);
        var result: SharedRegion = .{
            .name_len = name.len,
            .mapping = mapping,
            .meta_dir = meta_dir,
            .backend = backend,
        };

        @memcpy(result.name[0..name.len], name);

        return result;
    }

    pub fn close(self: *SharedRegion) void {
        self.backend.closeRaw(self.mapping, self.nameSlice());
    }

    pub fn exists(self: *SharedRegion) bool {
        return self.backend.exists(self.nameSlice());
    }

    pub fn bytes(self: *const SharedRegion) []u8 {
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

        pub fn create(
            name: []const u8,
            meta_dir: std.Io.Dir,
            backend: SHMBackend,
            io: std.Io,
            allocator: std.mem.Allocator,
        ) !Self {
            const shared_region = try SharedRegion.create(
                name,
                @sizeOf(S),
                meta_dir,
                backend,
            );

            var meta_data = try SharedMappingMeta.initWithFields(
                T,
                @sizeOf(T),
                if (shared_region.mapping.pid) |p| p else 0,
                shared_region.mapping.fd,
                allocator,
            );
            defer meta_data.deinit(allocator);

            try meta_data.write(meta_dir, name, io, allocator);

            const data: T = @ptrCast(@alignCast(shared_region.bytes()));

            return .{
                .region = shared_region,
                .data = data,
            };
        }

        pub fn createCapacity(
            name: []const u8,
            meta_dir: std.Io.Dir,
            count: usize,
            backend: SHMBackend,
            io: std.Io,
            allocator: std.mem.Allocator,
        ) !Self {
            const size = @sizeOf(S) * count;
            const shared_region = try SharedRegion.create(
                name,
                size,
                meta_dir,
                backend,
            );

            var meta_data = try SharedMappingMeta.initWithFields(
                T,
                @sizeOf(T) * count,
                if (shared_region.mapping.pid) |p| p else 0,
                shared_region.mapping.fd,
                allocator,
            );
            defer meta_data.deinit(allocator);

            try meta_data.write(
                meta_dir,
                name,
                io,
                allocator,
            );

            const data: T = @ptrCast(@alignCast(shared_region.bytes()));

            return .{
                .region = shared_region,
                .data = data,
            };
        }

        pub fn open(name: []const u8, meta_dir: std.Io.Dir, backend: SHMBackend) !Self {
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

test "SharedMemory - Single Struct" {
    const TestStruct = struct {
        x: i32,
        y: f64,
    };
    const SharedStruct = SharedMemory(TestStruct);

    const shm_name = "test_single_struct";
    if (use_shm_funcs) posixForceClose(shm_name);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const alloca = std.testing.allocator;
    const io = std.testing.io;

    var b: DefaultBackend = .{};
    const backend = b.backend();

    var shm: SharedStruct = try SharedStruct.create(
        shm_name,
        tmp.dir,
        backend,
        io,
        alloca,
    );
    defer shm.close();

    shm.data.* = .{ .x = 42, .y = 3.14 };

    // Open the shared memory in another "process"
    var shm2 = try SharedStruct.open(
        shm_name,
        tmp.dir,
        backend,
    );
    defer shm2.close();

    try std.testing.expectEqual(@as(i32, 42), shm2.data.x);
    try std.testing.expectApproxEqAbs(@as(f64, 3.14), shm2.data.y, 0.001);
}

test "SharedMemory - Array Fixed Length" {
    const array_size = 20;
    var expected = [_]i32{0} ** array_size;
    for (0..array_size) |i| {
        expected[i] = @intCast(i * 2);
    }

    const alloca = std.testing.allocator;
    var io_threaded: std.Io.Threaded = .init(alloca, .{});
    const io = io_threaded.io();

    const shm_name = "test_array_fixed_length";

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    if (use_shm_funcs) posixForceClose(shm_name);

    var b: DefaultBackend = .{};
    const backend = b.backend();

    const SharedI32 = SharedMemory([array_size]i32);

    var shm: SharedI32 = try SharedI32.create(
        shm_name,
        tmp.dir,
        backend,
        io,
        alloca,
    );
    defer shm.close();

    for (shm.data, 0..) |*item, i| {
        item.* = @intCast(i * 2);
    }

    // Open the shared memory in another "process"
    var shm2 = try SharedI32.open(shm_name, tmp.dir, backend);
    defer shm2.close();

    for (shm2.data, 0..) |item, i| {
        try std.testing.expectEqual(@as(i32, @intCast(i * 2)), item);
    }
    try std.testing.expectEqualSlices(i32, &expected, shm2.data);
}

test "SharedMemory - Array Runtime Length" {
    const array_size = 20;
    var expected = [_]i32{0} ** array_size;
    for (0..array_size) |i| {
        expected[i] = @intCast(i * 2);
    }

    const alloca = std.testing.allocator;
    var io_threaded: std.Io.Threaded = .init(alloca, .{});
    const io = io_threaded.io();

    const shm_name = "test_array_runtime_length";

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    if (use_shm_funcs) posixForceClose(shm_name);

    var b: DefaultBackend = .{};
    const backend = b.backend();

    const SharedI32 = SharedMemory([]i32);

    var shm: SharedI32 = try SharedI32.createCapacity(
        shm_name,
        tmp.dir,
        array_size,
        backend,
        io,
        alloca,
    );
    defer shm.close();

    for (shm.data, 0..) |*item, i| {
        item.* = @intCast(i * 2);
    }

    // Open the shared memory in another "process"
    var shm2 = try SharedI32.open(shm_name, tmp.dir, backend);
    defer shm2.close();

    //for (shm2.data, 0..) |item, i| {
    for (0..array_size) |i| {
        try std.testing.expectEqual(@as(i32, @intCast(i * 2)), shm2.data[i]);
    }
    //FIX: the mapped in data should have the correct length
    // This can come from the metadata file
    try std.testing.expectEqualSlices(i32, &expected, shm2.data[0..array_size]);
}

test "SharedMemory - Structure with String" {
    const TestStruct = struct {
        id: i32,
        float: f64,
        string: [20]u8,
    };

    const SharedTestStruct = SharedMemory(TestStruct);

    const shm_name = "test_struct_with_string";

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    if (use_shm_funcs) posixForceClose(shm_name);

    const alloca = std.testing.allocator;
    var io_threaded: std.Io.Threaded = .init(alloca, .{});
    const io = io_threaded.io();

    var b: DefaultBackend = .{};
    const backend = b.backend();

    var shm = try SharedTestStruct.create(
        shm_name,
        tmp.dir,
        backend,
        io,
        alloca,
    );
    defer shm.close();

    shm.data.id = 42;
    shm.data.float = 3.14;
    _ = std.fmt.bufPrint(&shm.data.string, "Hello, SHM!", .{}) catch unreachable;

    // Open the shared memory in another "process"
    var shm2 = try SharedTestStruct.open(shm_name, tmp.dir, backend);
    defer shm2.close();

    try std.testing.expectEqual(@as(i32, 42), shm2.data.id);
    try std.testing.expectApproxEqAbs(@as(f64, 3.14), shm2.data.float, 0.001);
    try std.testing.expectEqualStrings("Hello, SHM!", std.mem.sliceTo(&shm2.data.string, 0));
}
