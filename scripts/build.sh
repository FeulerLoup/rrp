#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# rrp 本地静态构建脚本
# 自动识别当前系统架构，静态编译 (Linux 使用 musl) 二进制文件并输出到 dist 目录
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "$ROOT_DIR"

PROFILE="debug"
OUT_DIR="dist"
BIN_NAME="rrp"
CUSTOM_TARGET=""

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info()  { printf "${BLUE}[INFO]${NC} %s\n" "$*"; }
ok()    { printf "${GREEN}[OK]${NC} %s\n" "$*"; }
warn()  { printf "${YELLOW}[WARN]${NC} %s\n" "$*"; }
err()   { printf "${RED}[ERROR]${NC} %s\n" "$*" >&2; exit 1; }

usage() {
    cat <<EOF
用法: ./scripts/build.sh [选项]

默认静态编译当前系统架构对应的 debug 二进制文件，并输出到 dist/rrp。

选项:
  -r, --release         编译 release 版本 (默认: debug)
  -t, --target <triple> 手动指定 Rust 编译目标三元组
  -o, --out-dir <dir>   指定输出目录 (默认: dist)
  -h, --help            显示此帮助信息

示例:
  ./scripts/build.sh            # 静态编译当前架构 debug 版本 -> dist/rrp
  ./scripts/build.sh --release  # 静态编译当前架构 release 版本 -> dist/rrp
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -r|--release)
            PROFILE="release"
            shift
            ;;
        -t|--target)
            [[ $# -ge 2 ]] || err "选项 $1 需要参数"
            CUSTOM_TARGET="$2"
            shift 2
            ;;
        -o|--out-dir)
            [[ $# -ge 2 ]] || err "选项 $1 需要参数"
            OUT_DIR="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            err "未知选项: $1 (使用 --help 查看帮助)"
            ;;
    esac
done

[[ -f "Cargo.toml" ]] || err "未找到 Cargo.toml，请在项目根目录运行此脚本"

detect_target() {
    if [[ -n "$CUSTOM_TARGET" ]]; then
        TARGET="$CUSTOM_TARGET"
        return
    fi

    local os_raw arch_raw
    os_raw="$(uname -s 2>/dev/null || echo unknown)"
    arch_raw="$(uname -m 2>/dev/null || echo unknown)"

    case "$os_raw" in
        Linux|linux)
            case "$arch_raw" in
                x86_64|amd64|x64)
                    TARGET="x86_64-unknown-linux-musl"
                    ;;
                aarch64|arm64|armv8*)
                    TARGET="aarch64-unknown-linux-musl"
                    ;;
                *)
                    err "不支持的 Linux CPU 架构: ${arch_raw}"
                    ;;
            esac
            ;;
        Darwin|darwin)
            case "$arch_raw" in
                aarch64|arm64)
                    TARGET="aarch64-apple-darwin"
                    ;;
                x86_64|amd64|x64)
                    TARGET="x86_64-apple-darwin"
                    ;;
                *)
                    err "不支持的 macOS CPU 架构: ${arch_raw}"
                    ;;
            esac
            ;;
        *)
            err "不支持的操作系统: ${os_raw}"
            ;;
    esac
}

detect_target

if command -v rustup >/dev/null 2>&1; then
    if ! rustup target list --installed | grep -qx "$TARGET"; then
        info "正在安装 Rust 目标工具链: ${TARGET} ..."
        rustup target add "$TARGET"
    fi
fi

export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER="${CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER:-rust-lld}"
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER="${CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER:-rust-lld}"

CARGO_ARGS=(build --target "$TARGET")
if [[ "$PROFILE" == "release" ]]; then
    CARGO_ARGS+=(--release)
fi

info "开始编译: profile=${PROFILE}, target=${TARGET} ..."
cargo "${CARGO_ARGS[@]}"

SRC_BIN="target/${TARGET}/${PROFILE}/${BIN_NAME}"
[[ -f "$SRC_BIN" ]] || err "未找到编译产物: ${SRC_BIN}"

mkdir -p "$OUT_DIR"
DEST_BIN="${OUT_DIR}/${BIN_NAME}"
cp -f "$SRC_BIN" "$DEST_BIN"
chmod +x "$DEST_BIN"

ok "编译完成: ${DEST_BIN}"
if command -v file >/dev/null 2>&1; then
    info "文件信息: $(file -b "$DEST_BIN")"
fi
