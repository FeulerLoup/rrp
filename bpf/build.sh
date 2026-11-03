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
"$CC" -O2 -g -Wall -Wextra -Werror \
    -target bpfel \
    -I "${SCRIPT_DIR}/include" \
    -c "$SRC" -o "$OUT"

echo "built ${OUT} with ${CC}"
if command -v llvm-objdump >/dev/null 2>&1; then
    llvm-objdump -h "$OUT" | grep -E 'classifier|maps|BTF' || true
fi
