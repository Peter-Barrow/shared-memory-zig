const std = @import("std");

// Although this function looks imperative, note that its job is to
// declaratively construct a build graph that will be executed by an external
// runner.
pub fn build(b: *std.Build) void {
    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});

    // Standard optimization options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall. Here we do not
    // set a preferred release mode, allowing the user to decide how to optimize.
    const optimize = b.standardOptimizeOption(.{});

    const zigwin32 = b.dependency("zigwin32", .{}).module("win32");
    const known_folders = b.dependency("known_folders", .{}).module("known-folders");

    const mod = b.addModule("shared_memory", .{
        .root_source_file = b.path("shared_memory.zig"),
    });
    mod.addImport("known_folders", known_folders);

    const use_shm_funcs = b.option(
        bool,
        "use_shm_funcs",
        "Use shm_open and shm_unlink instead of memfd_create",
    ) orelse false;

    const test_module = b.createModule(.{
        .optimize = optimize,
        .target = target,
        .root_source_file = b.path("shared_memory.zig"),
        .link_libc = use_shm_funcs,
    });

    const lib_unit_tests = b.addTest(.{
        .name = "test",
        .root_module = test_module,
        // .link_libc = use_shm_funcs,
    });

    const options = b.addOptions();
    options.addOption(bool, "use_shm_funcs", use_shm_funcs);
    lib_unit_tests.root_module.addOptions("config", options);
    lib_unit_tests.root_module.addImport("zigwin32", zigwin32);
    lib_unit_tests.root_module.addImport("known-folders", known_folders);

    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);

    // Similar to creating the run step earlier, this exposes a `test` step to
    // the `zig build --help` menu, providing a way for the user to request
    // running the unit tests.
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_lib_unit_tests.step);

    const unit_test_check = b.addTest(.{
        // .root_source_file = b.path("shared_memory.zig"),
        .name = "test",
        .root_module = test_module,
    });

    unit_test_check.root_module.addOptions("config", options);
    unit_test_check.root_module.addImport("zigwin32", zigwin32);
    lib_unit_tests.root_module.addImport("known-folders", known_folders);

    const check = b.step("check", "Check if tests compiles");
    check.dependOn(&unit_test_check.step);
}
