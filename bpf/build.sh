#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# 编译 rrp 服务端 TC eBPF 程序 (bpf/rrp_tc.c -> bpf/rrp_tc.o)
#
# 产物是与内核版本无关的 BPF 字节码（不依赖 CO-RE / vmlinux.h），编译后提交到仓库，
# Rust 侧通过 include_bytes! 内嵌，运行时由 aya 加载。
#
# 需要带 BPF 后端的 clang (Linux: apt install clang llvm；macOS: brew install llvm)。
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="${SCRIPT_DIR}/rrp_tc.c"
OUT="${SCRIPT_DIR}/rrp_tc.o"

find_clang() {
    for candidate in "${CLANG:-}" clang-20 clang-19 clang-18 clang-17 clang \
        /opt/homebrew/opt/llvm/bin/clang /usr/local/opt/llvm/bin/clang; do
        [[ -n "$candidate" ]] || continue
        if command -v "$candidate" >/dev/null 2>&1 \
            && echo 'int x;' | "$candidate" -target bpf -x c -c - -o /dev/null >/dev/null 2>&1; then
            echo "$candidate"
            return 0
        fi
    done
    return 1
}

CC="$(find_clang)" || {
    echo "error: no clang with BPF backend found (set CLANG=/path/to/clang)" >&2
    exit 1
}

# bpfel: BPF 字节码按小端编译，服务端目标 (x86_64 / aarch64 Linux) 均为小端。
#
# -ffreestanding -nostdlibinc: BPF 程序没有 libc，只用 clang 自带的 <stdint.h> /
# <stddef.h> / <stdbool.h>，不再回落到宿主机的 glibc 头文件。否则在 Debian/Ubuntu 上
# clang -target bpf 找不到多架构目录 (/usr/include/<arch>-linux-gnu) 里的
# bits/libc-header-start.h，GitHub Actions 的 ubuntu runner 会编译失败。
"$CC" -O2 -g -Wall -Wextra -Werror \
    -target bpfel \
    -ffreestanding -nostdlibinc \
    -I "${SCRIPT_DIR}/include" \
    -c "$SRC" -o "$OUT"

echo "built ${OUT} with ${CC}"
if command -v llvm-objdump >/dev/null 2>&1; then
    llvm-objdump -h "$OUT" | grep -E 'classifier|maps|BTF' || true
fi
