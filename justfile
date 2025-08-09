default:
    @just --list

test-linux:
	zig build test -Dtarget=x86_64-linux-gnu

test-linux-libc:
	zig build test -Dtarget=x86_64-linux-gnu -Duse_shm_funcs=true

test-windows:
	zig build test -Dtarget=x86_64-windows-msvc

test: test-linux test-linux-libc test-windows

clean:
    rm -r zig-out
    rm -r .zig-cache
