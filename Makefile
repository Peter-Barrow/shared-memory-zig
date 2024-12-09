.PHONY: test_linux
test_linux:
	zig build test -Dtarget=x86_64-linux-gnu

.PHONY: test_linux_libc
test_linux_libc:
	zig build test -Dtarget=x86_64-linux-gnu -Duse_shm_funcs=true

.PHONY: test_windows
test_windows:
	zig build test -Dtarget=x86_64-windows-msvc

.PHONY: test_all
test_all: test_linux test_windows
