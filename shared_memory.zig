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

pub fn SharedMemory(comptime S: type) type {
    return struct {
        const Self = @This();
        // const T = if (@typeInfo(S) == .pointer) []S else *S;
        const T = switch (@typeInfo(S)) {
            .pointer => |ptr| switch (ptr.size) {
                .slice => S,
                else => []S,
            },
            .array => *S,
            else => *S,
        };

        handle: std.fs.File.Handle,
        name: []const u8,
        size: usize,
        ptr: ?[]u8,
        data: T,
        allocator: ?std.mem.Allocator,

        pub fn extractHeader(shared: Shared) *ShmHeader {
            const header_size = @sizeOf(ShmHeader);
            return @ptrCast(@alignCast(shared.data.ptr[0..header_size]));
        }

        pub fn makeSharedMemory(name: []const u8, size: usize, allocator: ?std.mem.Allocator) !Shared {
            return switch (tag) {
                .linux, .freebsd => blk: {
                    if (use_shm_funcs) {
                        break :blk try posixCreate(name, size);
                    }
                    assert(allocator != null);
                    if (allocator) |alloca| {
                        break :blk try memfdBasedCreate(alloca, name, size);
                    }
                    return error.NoAllocatorForMemfdMeta;
                },
                .windows => try windowsCreate(name, size),
                else => try posixCreate(name, size),
            };
        }

        /// Creates a new shared memory segment with the given name and fixed size.
        ///
        /// This function creates a new shared memory segment that can be accessed by multiple processes.
        /// It allocates space for a header (ShmHeader) and the requested number of type T.
        ///
        /// Args:
        ///     name: The name of the shared memory segment. This should be unique across the system.
        ///     allocator: Optional allocator, this is a requirement for using memfd
        ///
        /// Returns:
        ///     A new Self instance representing the created shared memory. This includes:
        ///     - handle: The file handle for the shared memory.
        ///     - name: The name of the shared memory segment.
        ///     - size: The number of elements allocated.
        ///     - ptr: A pointer to the entire shared memory block.
        ///     - data: A slice of the shared memory containing only the data elements (excluding the header).
        ///
        /// Error: Returns an error if the shared memory creation fails. This can happen due to:
        ///     - Insufficient permissions
        ///     - Out of memory
        ///     - Name conflicts
        ///     - System-specific limitations
        pub fn create(name: []const u8, allocator: ?std.mem.Allocator) !Self {
            const size = @sizeOf(ShmHeader) + @sizeOf(S);
            const result = try makeSharedMemory(name, size, allocator);

            var header: *ShmHeader = extractHeader(result);

            header.size_bytes = size;
            header.total_elements = 1;

            const header_size = @sizeOf(ShmHeader);

            // @compileLog(T);
            // @compileLog(S);
            const data: T = @as(
                *S,
                @ptrCast(@alignCast(&result.data.ptr[header_size])),
            );

            return .{
                .handle = result.fd,
                .name = name,
                .size = 1,
                .ptr = result.data,
                .data = data,
                .allocator = allocator,
            };
        }

        /// Creates a new shared memory segment with the given name and size.
        ///
        /// This function creates a new shared memory segment that can be accessed by multiple processes.
        /// It allocates space for a header (ShmHeader) and the requested number of elements of type T.
        ///
        /// Args:
        ///     name: The name of the shared memory segment. This should be unique across the system.
        ///     count: The number of elements of type T to allocate in the shared memory.
        ///     allocator: Optional allocator, this is a requirement for using memfd
        ///
        /// Returns:
        ///     A new Self instance representing the created shared memory. This includes:
        ///     - handle: The file handle for the shared memory.
        ///     - name: The name of the shared memory segment.
        ///     - size: The number of elements allocated.
        ///     - ptr: A pointer to the entire shared memory block.
        ///     - data: A slice of the shared memory containing only the data elements (excluding the header).
        ///
        /// Error: Returns an error if the shared memory creation fails. This can happen due to:
        ///     - Insufficient permissions
        ///     - Out of memory
        ///     - Name conflicts
        ///     - System-specific limitations
        pub fn createWithLength(name: []const u8, count: usize, allocator: ?std.mem.Allocator) !Self {
            //const size = count * @sizeOf(T);
            const size = @sizeOf(ShmHeader) + (count * @sizeOf(S));
            const result = try makeSharedMemory(name, size, allocator);

            var header: *ShmHeader = extractHeader(result);

            header.size_bytes = size;
            header.total_elements = count;

            const header_size = @sizeOf(ShmHeader);

            const data: T = switch (@typeInfo(S)) {
                .pointer => |ptr| switch (ptr.size) {
                    .slice => @as(
                        [*]@typeInfo(S).pointer.child,
                        @ptrCast(@alignCast(&result.data.ptr[header_size])),
                    )[0..count],
                    else => @as([*]S, @ptrCast(@alignCast(&result.data.ptr[header_size])))[0..count],
                },
                else => unreachable,
            };

            return .{
                .handle = result.fd,
                .name = name,
                .size = count,
                .ptr = result.data,
                .data = data,
                .allocator = allocator,
            };
        }

        /// Opens an existing shared memory segment with the given name.
        ///
        /// This function attempts to open a previously created shared memory segment.
        /// It reads the header information to determine the size and layout of the shared memory.
        ///
        /// Args:
        ///     name: The name of the shared memory segment to open. This should match the name used in create().
        ///     allocator: Optional allocator, this is a requirement for using memfd
        ///
        /// Returns:
        ///     A Self instance representing the opened shared memory. This includes:
        ///     - handle: The file handle for the shared memory.
        ///     - name: The name of the shared memory segment.
        ///     - size: The number of elements in the shared memory.
        ///     - ptr: A pointer to the entire shared memory block.
        ///     - data: A slice of the shared memory containing only the data elements (excluding the header).
        ///
        /// Error: Returns an error if the shared memory cannot be opened. This can happen due to:
        ///     - The shared memory segment does not exist
        ///     - Insufficient permissions
        ///     - System-specific errors in opening or mapping the shared memory
        pub fn open(name: []const u8, allocator: ?std.mem.Allocator) !Self {
            const result = switch (tag) {
                .linux, .freebsd => blk: {
                    if (use_shm_funcs) {
                        break :blk try posixOpen(name);
                    }
                    assert(allocator != null);
                    // break :blk if (allocator) |alloca| try memfdBasedOpen(alloca, name);
                    if (allocator) |alloca| {
                        break :blk try memfdBasedOpen(alloca, name);
                    }
                    return error.NoAllocatorForMemfdMeta;
                },
                .windows => try windowsOpen(name),
                else => try posixOpen(name),
            };

            const header_size = @sizeOf(ShmHeader);
            const header: *ShmHeader = @ptrCast(@alignCast(result.data.ptr[0..header_size]));

            const count = header.total_elements;

            const data: T = switch (@typeInfo(S)) {
                .pointer => |ptr| switch (ptr.size) {
                    .slice => @as(
                        [*]@typeInfo(S).pointer.child,
                        @ptrCast(@alignCast(&result.data.ptr[header_size])),
                    )[0..count],
                    else => @compileError("here"),
                },
                .array => @as(
                    T,
                    @ptrCast(@alignCast(&result.data.ptr[header_size])),
                ),
                else => @as(
                    *S,
                    @ptrCast(@alignCast(&result.data.ptr[header_size])),
                ),
            };

            return .{
                .handle = result.fd,
                .name = name,
                .size = count,
                .ptr = result.data,
                .data = data,
                .allocator = allocator,
            };
        }

        /// Checks if a shared memory segment with the given name exists.
        ///
        /// This function attempts to detect whether a shared memory segment with the specified name
        /// is currently present in the system.
        ///
        /// Args:
        ///     path: The name or path of the shared memory segment to check. The exact format
        ///           may depend on the operating system and the method used to create the segment.
        ///
        ///     allocator: Optional allocator, this is a requirement for using memfd
        /// Returns:
        ///     true if the shared memory segment exists and is accessible, false otherwise.
        ///
        /// Note: This function does not throw errors. A false return could mean either that the
        /// segment doesn't exist or that there was an error checking for its existence.
        pub fn exists(path: []const u8, allocator: ?std.mem.Allocator) bool {
            return switch (tag) {
                .linux, .freebsd => {
                    assert(allocator != null);
                    return if (allocator) |alloca| memfdBasedExists(alloca, path) else false;
                },
                .windows => windowsMapExists(path),
                else => posixMapExists(path),
            };
        }

        /// Closes and cleans up the shared memory segment.
        ///
        /// This function performs necessary cleanup operations for the shared memory segment:
        /// - Unmaps the shared memory from the process's address space
        /// - Closes the file descriptor or handle associated with the shared memory
        /// - On some systems, it may also remove the shared memory object
        ///
        /// Args:
        ///     self: Pointer to the Self instance to close.
        ///
        /// Note: After calling this function, the Self instance should no longer be used.
        /// The shared memory segment may still exist in the system if other processes are using it.
        pub fn close(self: *Self) void {
            switch (tag) {
                .linux, .freebsd => {
                    assert(self.allocator != null);
                    // if (self.allocator) |alloca| memfdBasedClose(alloca, self.ptr, self.handle, self.name);
                    if (self.allocator) |alloca| {
                        memfdBasedClose(alloca, self.ptr, self.handle, self.name);
                    }
                },
                .windows => windowsClose(self.ptr, self.handle, self.name),
                else => posixClose(self.ptr, self.handle, self.name),
            }
        }
    };
}

pub const Shared = struct {
    // data: []align(4096) u8,
    data: []u8,
    size: usize,
    fd: std.fs.File.Handle,
    pid: ?pid_t = null,
};

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
};

/// Writes metadata about a memfd file to disk
/// The metadata is stored in the XDG runtime directory
pub fn writeMemfdMeta(allocator: std.mem.Allocator, name: []const u8, meta: XdgMemfdMeta) !void {
    const meta_path = try xgdRunTimePath(allocator, name);
    defer allocator.free(meta_path);

    const file = try std.fs.createFileAbsolute(meta_path, .{
        .read = true,
        .truncate = true,
    });
    defer file.close();

    try file.writeAll(std.mem.asBytes(&meta));
}

/// Reads metadata about a memfd file from disk
/// If the process that created the memfd no longer exists, the metadata file is deleted
/// Returns error.IncorrectSize if the metadata file is corrupted
pub fn readMemfdMeta(allocator: std.mem.Allocator, name: []const u8) !XdgMemfdMeta {
    const meta_path = try xgdRunTimePath(allocator, name);
    defer allocator.free(meta_path);

    const file = try std.fs.openFileAbsolute(meta_path, .{});
    defer file.close();

    var meta: XdgMemfdMeta = undefined;
    const bytes_read = try file.readAll(std.mem.asBytes(&meta));
    if (bytes_read != @sizeOf(XdgMemfdMeta)) return error.IncorrectSize;

    // If process no longer exists, clean up file
    std.posix.kill(meta.pid, 0) catch {
        // we know the process no longer exists so delete the meta file
        try std.fs.deleteFileAbsolute(meta_path);
    };

    return meta;
}

/// Deletes the metadata file for a memfd if it exists
/// Does nothing if the file doesn't exist or can't be deleted
pub fn deleteMemfdMeta(allocator: std.mem.Allocator, name: []const u8) void {
    const meta_path = xgdRunTimePath(allocator, name) catch return;
    defer allocator.free(meta_path);
    std.fs.deleteFileAbsolute(meta_path) catch return;
}

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
pub fn memfdBasedCreate(allocator: std.mem.Allocator, name: []const u8, size: usize) !Shared {
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

    try writeMemfdMeta(
        allocator,
        n,
        .{
            .pid = pid,
            .fd = fd,
            .size = size,
            .timestamp = std.time.timestamp(),
        },
    );

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

/// Creates a POSIX shared memory segment.
///
/// This function creates a new POSIX shared memory segment that can be accessed by multiple processes.
/// It uses shm_open to create the shared memory object and mmap to map it into the process's address space.
///
/// Args:
///     name: The name of the shared memory segment. This should be unique across the system.
///     size: The size of the shared memory segment in bytes.
///
/// Returns:
///     A Shared struct representing the created shared memory, containing:
///     - data: A slice of the mapped memory
///     - size: The size of the shared memory
///     - fd: The file descriptor of the shared memory object
///
/// Error: Returns an error if the shared memory creation fails, including:
///     - shm_open failure
///     - ftruncate failure
///     - mmap failure
pub fn posixCreate(name: []const u8, size: usize) !Shared {
    assert(posixMapExists(name) == false);

    const permissions: std.posix.mode_t = 0o666;
    const flags: std.posix.O = .{
        .ACCMODE = .RDWR,
        .CREAT = true,
        .EXCL = true,
    };

    var buffer = [_]u8{0} ** std.fs.MAX_NAME_BYTES;
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

    assert(posixMapExists(name) == true);

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
///     name: The name of the shared memory segment to open. This should match the name used in posixCreate().
///
/// Returns:
///     A Shared struct representing the opened shared memory, containing:
///     - data: A slice of the mapped memory
///     - size: The size of the shared memory
///     - fd: The file descriptor of the shared memory object
///
/// Error: Returns an error if the shared memory cannot be opened, including:
///     - shm_open failure
///     - fstat failure
///     - mmap failure
pub fn posixOpen(name: []const u8) !Shared {
    assert(posixMapExists(name) == true);

    const permissions: std.posix.mode_t = 0o666;
    const flags: std.posix.O = .{
        .ACCMODE = .RDWR,
    };

    var buffer = [_]u8{0} ** std.fs.MAX_NAME_BYTES;
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

/// Checks if a POSIX shared memory segment exists.
///
/// This function attempts to open the shared memory object with read-only access
/// to determine if it exists and is accessible.
///
/// Args:
///     name: The name of the shared memory segment to check.
///
/// Returns:
///     true if the shared memory segment exists and is accessible, false otherwise.
///
/// Note: This function does not throw errors. A false return could mean either that the
/// segment doesn't exist or that there was an error checking for its existence.
pub fn posixMapExists(name: []const u8) bool {
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

/// Forcibly closes a POSIX shared memory segment.
///
/// Args:
///     name: The name of the shared memory segment to close.
pub fn posixForceClose(name: []const u8) void {
    var buffer = [_]u8{0} ** std.fs.MAX_NAME_BYTES;
    const name_z = std.fmt.bufPrintZ(&buffer, "{s}", .{name}) catch unreachable;
    const rc = std.c.shm_unlink(name_z);
    _ = rc;
}

/// Closes and cleans up a POSIX shared memory segment.
///
/// This function performs necessary cleanup operations for the POSIX shared memory segment:
/// - Unmaps the shared memory from the process's address space (if a pointer is provided)
/// - Closes the file descriptor associated with the shared memory
/// - Removes the shared memory object from the system
///
/// Args:
///     ptr: Optional pointer to the mapped memory. If provided, this memory will be unmapped.
///     fd: File descriptor of the shared memory.
///     name: Name of the shared memory segment.
///
/// Note: After calling this function, the shared memory segment will be removed from the system
/// and will no longer be accessible by any process.
pub fn posixClose(ptr: ?[]u8, fd: std.fs.File.Handle, name: []const u8) void {
    if (ptr) |p| std.posix.munmap(@alignCast(p));

    std.posix.close(fd);

    var buffer = [_]u8{0} ** std.fs.MAX_NAME_BYTES;
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
    assert(posixMapExists(name) == false);
}

/// Creates a Windows shared memory segment.
///
/// This function creates a new Windows shared memory segment that can be accessed by multiple processes.
/// It uses CreateFileMappingA to create the shared memory object and MapViewOfFile to map it into the process's address space.
///
/// Args:
///     name: The name of the shared memory segment. This should be unique across the system.
///     size: The size of the shared memory segment in bytes.
///
/// Returns:
///     A Shared struct representing the created shared memory, containing:
///     - data: A slice of the mapped memory
///     - size: The size of the shared memory
///     - fd: The handle of the file mapping object
///
/// Error: Returns an error if the shared memory creation fails, including:
///     - CreateFileMappingA failure
///     - MapViewOfFile failure
pub fn windowsCreate(name: []const u8, size: usize) !Shared {
    assert(windowsMapExists(name) == false);

    var buffer = [_]u8{0} ** std.fs.MAX_NAME_BYTES;
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
        ptr.ptr = @alignCast(@ptrCast(p));
        // ptr.len = size;
    } else {
        switch (std.os.windows.kernel32.GetLastError()) {
            else => |err| return std.os.windows.unexpectedError(err),
        }
    }

    assert(windowsMapExists(name) == true);

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
///     name: The name of the shared memory segment to open. This should match the name used in windowsCreate().
///
/// Returns:
///     A Shared struct representing the opened shared memory, containing:
///     - data: A slice of the mapped memory
///     - size: The size of the shared memory
///     - fd: The handle of the file mapping object
///
/// Error: Returns an error if the shared memory cannot be opened, including:
///     - OpenFileMappingA failure
///     - MapViewOfFile failure
pub fn windowsOpen(name: []const u8) !Shared {
    assert(windowsMapExists(name) == true);

    var buffer = [_]u8{0} ** std.fs.MAX_NAME_BYTES;
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
        ptr.ptr = @alignCast(@ptrCast(p));
        const header: ShmHeader = @as(*ShmHeader, @ptrCast(@alignCast(ptr.ptr[0..@sizeOf(ShmHeader)]))).*;
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

/// Checks if a Windows shared memory segment exists.
///
/// This function attempts to open the shared memory object with read-write access
/// to determine if it exists and is accessible.
///
/// Args:
///     name: The name of the shared memory segment to check.
///
/// Returns:
///     true if the shared memory segment exists and is accessible, false otherwise.
///
/// Note: This function does not throw errors. A false return could mean either that the
/// segment doesn't exist or that there was an error checking for its existence.
pub fn windowsMapExists(name: []const u8) bool {
    var buffer = [_]u8{0} ** std.fs.MAX_NAME_BYTES;
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

/// Closes and cleans up a Windows shared memory segment.
///
/// This function performs necessary cleanup operations for the Windows shared memory segment:
/// - Unmaps the view of the file from the process's address space (if a pointer is provided)
/// - Closes the handle associated with the file mapping object
///
/// Args:
///     ptr: Optional pointer to the mapped memory. If provided, this memory will be unmapped.
///     handle: Handle of the file mapping object.
///     name: Name of the shared memory segment.
///
/// Note: After calling this function, the shared memory segment will no longer be accessible
/// by this process, but it may still exist in the system if other processes are using it.
pub fn windowsClose(ptr: ?[]u8, handle: std.os.windows.HANDLE, name: []const u8) void {
    assert(windowsMapExists(name) == true);
    //if (ptr) |p| _ = winMem.UnmapViewOfFile;
    if (ptr) |p| {
        _ = winMem.UnmapViewOfFile(@ptrCast(p.ptr)) == winZig.FALSE;
        // if (winMem.UnmapViewOfFile(@ptrCast(p.ptr)) == winZig.FALSE) {
        //     switch (std.os.windows.kernel32.GetLastError()) {
        //         else => |err| return std.os.windows.unexpectedError(err),
        //     }
        // }
    }
    // assert(windowsMapExists(name) == false);
    windows.CloseHandle(handle);
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

    //posixForceClose(shm_name);

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

    const shm_name = "/test_array";

    // posixForceClose(shm_name);

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

    const shm_name = "/test_array";

    // posixForceClose(shm_name);

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

    //posixForceClose(shm_name);

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
