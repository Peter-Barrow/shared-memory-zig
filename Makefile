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
test_all: test_linux test_linux_libc test_windows

.PHONY: test_mac
test_mac:
	zig test shared_memory.zig -lc -target aarch64-macos.17.0 --test-no-exec && \
	BINARY=$$(ls -t .zig-cache/o/*/test | head -1) && \
	codesign --sign - "$$BINARY" 2>/dev/null || true && \
	"$$BINARY"
