#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# rrp 自动安装脚本
# 自动识别操作系统 (Linux / macOS) 与架构 (x64 / arm64)，从 GitHub Releases 下载并安装
# 仓库地址: https://github.com/FeulerLoup/rrp
# ==============================================================================

REPO="${RRP_REPO:-FeulerLoup/rrp}"
INSTALL_DIR="${RRP_INSTALL_DIR:-/usr/local/bin}"
VERSION="${RRP_VERSION:-latest}"
MIRROR="${RRP_MIRROR:-}"
GITHUB_BASE="${GITHUB_BASE:-https://github.com}"
BIN_NAME="rrp"

set_mirror() {
    local m="${1%/}"
    m="${m#https://}"
    m="${m#http://}"
    m="${m%/https://github.com}"
    m="${m%/http://github.com}"
    m="${m%/github.com}"
    m="${m%/}"
    if [[ -z "$m" || "$m" == "github.com" ]]; then
        GITHUB_BASE="https://github.com"
    else
        GITHUB_BASE="https://${m}/https://github.com"
    fi
}

if [[ -n "$MIRROR" ]]; then
    set_mirror "$MIRROR"
fi

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
用法: ./scripts/install.sh [选项]

选项:
  -v, --version <tag>     指定安装版本 (例如: v0.1.0，默认: latest)
  -d, --dir <path>        指定安装目录 (默认: /usr/local/bin)
  -m, --mirror <domain>   指定 GitHub 镜像加速域名 (例如: ghfast.top)
  -h, --help              显示此帮助信息

环境变量:
  RRP_VERSION             同 --version
  RRP_INSTALL_DIR         同 --dir
  RRP_MIRROR              同 --mirror

示例:
  curl -fsSL https://raw.githubusercontent.com/FeulerLoup/rrp/main/scripts/install.sh | bash
  curl -fsSL https://ghfast.top/https://raw.githubusercontent.com/FeulerLoup/rrp/main/scripts/install.sh | bash -s -- --mirror ghfast.top
  ./scripts/install.sh --version v0.1.0 --dir /usr/local/bin
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -v|--version)
            [[ $# -ge 2 ]] || err "选项 $1 需要参数"
            VERSION="$2"
            shift 2
            ;;
        -d|--dir)
            [[ $# -ge 2 ]] || err "选项 $1 需要参数"
            INSTALL_DIR="$2"
            shift 2
            ;;
        -m|--mirror)
            [[ $# -ge 2 ]] || err "选项 $1 需要参数"
            set_mirror "$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            err "未知参数: $1 (使用 --help 查看帮助)"
            ;;
    esac
done

# 1. 检测操作系统与 CPU 架构
detect_platform() {
    local os_raw arch_raw
    os_raw="$(uname -s 2>/dev/null || echo unknown)"
    arch_raw="$(uname -m 2>/dev/null || echo unknown)"

    case "$os_raw" in
        Linux|linux)
            OS="linux"
            ;;
        Darwin|darwin)
            OS="macos"
            ;;
        *)
            err "不支持的操作系统: ${os_raw} (目前仅支持 Linux 和 macOS)"
            ;;
    esac

    case "$arch_raw" in
        x86_64|amd64|x64)
            ARCH="x64"
            ;;
        aarch64|arm64|armv8*)
            ARCH="arm64"
            ;;
        *)
            err "不支持的 CPU 架构: ${arch_raw} (目前仅支持 x64 / arm64)"
            ;;
    esac

    PLATFORM="${OS}-${ARCH}"
    case "$PLATFORM" in
        linux-x64|linux-arm64|macos-arm64)
            ;;
        *)
            err "当前平台组合 ${PLATFORM} 暂无预编译二进制 (支持目标: linux-x64, linux-arm64, macos-arm64)"
            ;;
    esac
}

# 2. 下载工具封装 (支持 curl 和 wget)
download_file() {
    local url="$1"
    local dest="$2"

    if command -v curl >/dev/null 2>&1; then
        curl -fL --retry 3 --connect-timeout 15 -o "$dest" "$url"
    elif command -v wget >/dev/null 2>&1; then
        wget -q --tries=3 --timeout=15 -O "$dest" "$url"
    else
        err "未检测到 curl 或 wget，请先安装其中之一"
    fi
}

# 3. 校验 SHA256 (若校验文件和工具可用)
verify_sha256() {
    local file_path="$1"
    local sha_file="$2"

    [[ -s "$sha_file" ]] || return 0

    local expected actual
    expected="$(awk '{print $1}' "$sha_file" | head -n1)"
    [[ -n "$expected" ]] || return 0

    if command -v sha256sum >/dev/null 2>&1; then
        actual="$(sha256sum "$file_path" | awk '{print $1}')"
    elif command -v shasum >/dev/null 2>&1; then
        actual="$(shasum -a 256 "$file_path" | awk '{print $1}')"
    else
        warn "未检测到 sha256sum / shasum，跳过哈希校验"
        return 0
    fi

    if [[ "$expected" != "$actual" ]]; then
        err "SHA256 校验失败! 期望: ${expected}, 实际: ${actual}"
    fi
    ok "SHA256 校验通过 (${actual})"
}

detect_platform
ASSET_BASE="rrp-${PLATFORM}"

# 4. 构造下载链接
if [[ "$VERSION" == "latest" ]]; then
    BASE_DOWNLOAD_URL="${GITHUB_BASE}/${REPO}/releases/latest/download"
    DISPLAY_VERSION="latest"
else
    # 确保版本号带有 v 前缀
    TAG="v${VERSION#v}"
    BASE_DOWNLOAD_URL="${GITHUB_BASE}/${REPO}/releases/download/${TAG}"
    DISPLAY_VERSION="$TAG"
fi

info "检测到系统环境: ${OS} (${ARCH}) -> 目标产物: ${ASSET_BASE}"
info "准备从 ${REPO} (${DISPLAY_VERSION}) 下载并安装到 ${INSTALL_DIR}/${BIN_NAME}..."

TMP_DIR="$(mktemp -d 2>/dev/null || mktemp -d -t 'rrp-install')"
cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

BIN_TMP="${TMP_DIR}/${BIN_NAME}"

# 优先下载 .tar.gz 压缩包，若系统无 tar 则直接下载裸二进制
if command -v tar >/dev/null 2>&1; then
    ARCHIVE_NAME="${ASSET_BASE}.tar.gz"
    ARCHIVE_URL="${BASE_DOWNLOAD_URL}/${ARCHIVE_NAME}"
    SHA_URL="${ARCHIVE_URL}.sha256"
    ARCHIVE_PATH="${TMP_DIR}/${ARCHIVE_NAME}"
    SHA_PATH="${TMP_DIR}/${ARCHIVE_NAME}.sha256"

    info "正在下载 ${ARCHIVE_URL} ..."
    if download_file "$ARCHIVE_URL" "$ARCHIVE_PATH"; then
        if download_file "$SHA_URL" "$SHA_PATH" 2>/dev/null; then
            verify_sha256 "$ARCHIVE_PATH" "$SHA_PATH"
        fi
        tar -xzf "$ARCHIVE_PATH" -C "$TMP_DIR"
    else
        warn "下载压缩包失败，尝试直接下载二进制文件 ${ASSET_BASE}..."
        RAW_URL="${BASE_DOWNLOAD_URL}/${ASSET_BASE}"
        download_file "$RAW_URL" "$BIN_TMP" || err "下载失败，请检查网络连接或确认 Release (${DISPLAY_VERSION}) 已发布"
    fi
else
    RAW_URL="${BASE_DOWNLOAD_URL}/${ASSET_BASE}"
    SHA_URL="${RAW_URL}.sha256"
    SHA_PATH="${TMP_DIR}/${ASSET_BASE}.sha256"

    info "正在下载 ${RAW_URL} ..."
    download_file "$RAW_URL" "$BIN_TMP" || err "下载失败，请检查网络连接或确认 Release (${DISPLAY_VERSION}) 已发布"
    if download_file "$SHA_URL" "$SHA_PATH" 2>/dev/null; then
        verify_sha256 "$BIN_TMP" "$SHA_PATH"
    fi
fi

[[ -f "$BIN_TMP" ]] || err "解压后未找到二进制文件 '${BIN_NAME}'"
chmod +x "$BIN_TMP"

# 5. 安装到目标目录 (必要时使用 sudo)
run_privileged() {
    if [[ "$(id -u)" -eq 0 ]]; then
        "$@"
    elif command -v sudo >/dev/null 2>&1; then
        sudo "$@"
    else
        err "安装到 ${INSTALL_DIR} 需要管理员权限，请使用 root 运行或安装 sudo"
    fi
}

if [[ ! -d "$INSTALL_DIR" ]]; then
    if mkdir -p "$INSTALL_DIR" 2>/dev/null; then
        :
    else
        info "需要管理员权限以创建目录 ${INSTALL_DIR}..."
        run_privileged mkdir -p "$INSTALL_DIR"
    fi
fi

TARGET_BIN="${INSTALL_DIR}/${BIN_NAME}"
if [[ -w "$INSTALL_DIR" ]]; then
    mv -f "$BIN_TMP" "$TARGET_BIN"
else
    info "需要管理员权限以写入 ${TARGET_BIN}..."
    run_privileged mv -f "$BIN_TMP" "$TARGET_BIN"
    run_privileged chmod +x "$TARGET_BIN"
fi

ok "成功安装 rrp 到: ${TARGET_BIN}"

if "$TARGET_BIN" --version >/dev/null 2>&1; then
    INSTALLED_VER="$("$TARGET_BIN" --version)"
    ok "当前已安装版本: ${INSTALLED_VER}"
fi

cat <<EOF

快速开始 (默认配置目录: /usr/local/etc/rrp/):
  1. 客户端初始化密钥:  sudo rrp install --mode client
  2. 服务端授权公钥:    sudo rrp approve <CLIENT_PUBLIC_KEY>
  3. 启动服务端/客户端: rrp server  |  rrp client
EOF
