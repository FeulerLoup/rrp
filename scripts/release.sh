#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# rrp 一键发布脚本 (修改版本 + 提交 + 打 Tag + 推送触发 GitHub Actions Release)
# 仓库地址: https://github.com/FeulerLoup/rrp.git
# ==============================================================================

DEFAULT_REPO_URL="https://github.com/FeulerLoup/rrp.git"
REMOTE="origin"
DRY_RUN=false
FORCE_TAG=false
AUTO_YES=false
CUSTOM_MSG=""
TARGET_ARG=""

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
用法: ./scripts/release.sh [版本号 | patch | minor | major] [选项]

位置参数:
  <version>             指定目标版本号，例如: 0.2.0 或 v0.2.0
  patch                 自动递增修订号 (例如: 0.1.0 -> 0.1.1)
  minor                 自动递增次版本号 (例如: 0.1.0 -> 0.2.0)
  major                 自动递增主版本号 (例如: 0.1.0 -> 1.0.0)
  (留空)                若当前版本尚未打 Tag 则发布当前版本，否则默认递增 patch

选项:
  -m, --message <msg>   自定义提交与 Tag 备注信息
  -r, --remote <name>   指定推送的 Git 远程名称 (默认: origin)
  -f, --force           若同名 Tag 已存在则强制覆盖并推送
  -y, --yes             跳过交互确认
  -n, --dry-run         仅演练并输出将执行的操作，不实际修改或推送
  -h, --help            显示此帮助信息

示例:
  ./scripts/release.sh 0.1.0
  ./scripts/release.sh patch
  ./scripts/release.sh minor -m "feat: 新增多服务端负载均衡支持"
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -m|--message)
            [[ $# -ge 2 ]] || err "选项 $1 需要参数"
            CUSTOM_MSG="$2"
            shift 2
            ;;
        -r|--remote)
            [[ $# -ge 2 ]] || err "选项 $1 需要参数"
            REMOTE="$2"
            shift 2
            ;;
        -f|--force)
            FORCE_TAG=true
            shift
            ;;
        -y|--yes)
            AUTO_YES=true
            shift
            ;;
        -n|--dry-run)
            DRY_RUN=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        -*)
            err "未知选项: $1 (使用 --help 查看帮助)"
            ;;
        *)
            if [[ -z "$TARGET_ARG" ]]; then
                TARGET_ARG="$1"
                shift
            else
                err "多余的参数: $1 (使用 --help 查看帮助)"
            fi
            ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "$ROOT_DIR"

[[ -f "Cargo.toml" ]] || err "未找到 Cargo.toml，请在项目根目录运行此脚本"

# 读取 Cargo.toml 中 [package] 下的当前版本号
get_current_version() {
    awk '
        /^\[package\]/ { in_pkg = 1; next }
        /^\[/          { in_pkg = 0 }
        in_pkg && /^[[:space:]]*version[[:space:]]*=/ {
            gsub(/.*=[[:space:]]*"/, "")
            gsub(/".*/, "")
            print
            exit
        }
    ' Cargo.toml
}

# 计算递增后的版本号
bump_version() {
    local cur="$1"
    local mode="$2"
    local base="${cur%%-*}"
    local major minor patch
    IFS='.' read -r major minor patch <<< "$base"
    major="${major:-0}"
    minor="${minor:-0}"
    patch="${patch:-0}"

    case "$mode" in
        major) echo "$((major + 1)).0.0" ;;
        minor) echo "${major}.$((minor + 1)).0" ;;
        patch) echo "${major}.${minor}.$((patch + 1))" ;;
        *) err "未知的版本递增类型: $mode" ;;
    esac
}

CURRENT_VERSION="$(get_current_version)"
[[ -n "$CURRENT_VERSION" ]] || err "无法从 Cargo.toml 解析当前版本号"

# 确保 Git 仓库已初始化并配置好远程地址
if [[ ! -d ".git" ]]; then
    info "当前目录尚未初始化 Git 仓库，正在初始化..."
    if [[ "$DRY_RUN" == false ]]; then
        git init -b main >/dev/null 2>&1 || { git init >/dev/null && git checkout -B main >/dev/null; }
    fi
fi

if [[ -d ".git" ]] && ! git remote get-url "$REMOTE" >/dev/null 2>&1; then
    info "未检测到远程仓库 '$REMOTE'，自动配置为: $DEFAULT_REPO_URL"
    if [[ "$DRY_RUN" == false ]]; then
        git remote add "$REMOTE" "$DEFAULT_REPO_URL"
    fi
fi

# 解析目标版本号
if [[ -z "$TARGET_ARG" ]]; then
    if [[ -d ".git" ]] && git rev-parse "v${CURRENT_VERSION}" >/dev/null 2>&1; then
        DEFAULT_NEXT="$(bump_version "$CURRENT_VERSION" patch)"
    else
        DEFAULT_NEXT="$CURRENT_VERSION"
    fi

    if [[ "$AUTO_YES" == true ]] || [[ ! -t 0 ]]; then
        NEW_VERSION="$DEFAULT_NEXT"
    else
        printf "${BLUE}[INFO]${NC} 当前版本为 ${YELLOW}%s${NC}，请输入要发布的版本号 [默认: %s]: " "$CURRENT_VERSION" "$DEFAULT_NEXT"
        read -r input_ver
        NEW_VERSION="${input_ver:-$DEFAULT_NEXT}"
    fi
elif [[ "$TARGET_ARG" == "patch" || "$TARGET_ARG" == "minor" || "$TARGET_ARG" == "major" ]]; then
    NEW_VERSION="$(bump_version "$CURRENT_VERSION" "$TARGET_ARG")"
else
    NEW_VERSION="$TARGET_ARG"
fi

# 去除可能携带的前缀 v
NEW_VERSION="${NEW_VERSION#v}"

# 校验语义化版本号格式 (支持 x.y.z 及预发布后缀如 x.y.z-rc.1)
if [[ ! "$NEW_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$ ]]; then
    err "非法的语义化版本号格式: '$NEW_VERSION' (示例: 0.1.0, 0.2.1, 1.0.0-beta.1)"
fi

TAG_NAME="v${NEW_VERSION}"
COMMIT_MSG="${CUSTOM_MSG:-chore(release): ${TAG_NAME}}"
TAG_MSG="${CUSTOM_MSG:-Release ${TAG_NAME}}"

info "当前版本: v${CURRENT_VERSION} -> 目标发布版本: ${TAG_NAME}"

# 检查本地 Tag 是否已存在
if [[ -d ".git" ]] && git rev-parse "$TAG_NAME" >/dev/null 2>&1; then
    if [[ "$FORCE_TAG" == false ]]; then
        err "本地已存在 Tag '${TAG_NAME}'。如需覆盖请添加 --force 参数，或指定新版本号（如 ./scripts/release.sh patch）"
    else
        warn "本地已存在 Tag '${TAG_NAME}'，将使用 --force 覆盖"
    fi
fi

# 更新 Cargo.toml 中的 [package] version
update_cargo_toml() {
    local target_ver="$1"
    awk -v ver="$target_ver" '
        /^\[package\]/ { in_pkg = 1 }
        /^\[/ && !/^\[package\]/ { in_pkg = 0 }
        in_pkg && !updated && /^[[:space:]]*version[[:space:]]*=/ {
            sub(/=[[:space:]]*"[^"]*"/, "= \"" ver "\"")
            updated = 1
        }
        { print }
    ' Cargo.toml > Cargo.toml.tmp && mv Cargo.toml.tmp Cargo.toml
}

# 更新 Cargo.lock 中 rrp 包的 version
update_cargo_lock() {
    local target_ver="$1"
    [[ -f "Cargo.lock" ]] || return 0
    awk -v ver="$target_ver" '
        /^\[\[package\]\]/ { in_rrp = 0 }
        /^name = "rrp"$/   { in_rrp = 1 }
        in_rrp && /^version = "/ {
            sub(/^version = "[^"]*"/, "version = \"" ver "\"")
            in_rrp = 0
        }
        { print }
    ' Cargo.lock > Cargo.lock.tmp && mv Cargo.lock.tmp Cargo.lock
}

if [[ "$DRY_RUN" == true ]]; then
    info "[DRY-RUN] 将更新 Cargo.toml 和 Cargo.lock 版本为 ${NEW_VERSION}"
    info "[DRY-RUN] 将执行 git add -A && git commit -m \"${COMMIT_MSG}\""
    info "[DRY-RUN] 将创建 Git Tag: ${TAG_NAME}"
    info "[DRY-RUN] 将推送分支与 Tag 到远程仓库 '${REMOTE}' (${DEFAULT_REPO_URL})"
    exit 0
fi

if [[ "$NEW_VERSION" != "$CURRENT_VERSION" ]]; then
    info "正在更新 Cargo.toml 与 Cargo.lock 版本号为 ${NEW_VERSION}..."
    update_cargo_toml "$NEW_VERSION"
    update_cargo_lock "$NEW_VERSION"
    ok "版本号已更新为 ${NEW_VERSION}"
else
    info "Cargo.toml 版本号已是 ${NEW_VERSION}，保持不变"
fi

# 暂存并提交变更
git add -A

if ! git rev-parse --verify HEAD >/dev/null 2>&1; then
    info "创建初始版本提交: ${COMMIT_MSG}"
    git commit -m "$COMMIT_MSG"
elif ! git diff --cached --quiet; then
    info "提交版本变更: ${COMMIT_MSG}"
    git commit -m "$COMMIT_MSG"
else
    info "工作区无新增文件变更，直接基于当前 HEAD 打 Tag"
fi

# 创建 Tag
if [[ "$FORCE_TAG" == true ]]; then
    git tag -a -f "$TAG_NAME" -m "$TAG_MSG"
else
    git tag -a "$TAG_NAME" -m "$TAG_MSG"
fi
ok "已创建 Git Tag: ${TAG_NAME}"

# 获取当前分支名
BRANCH="$(git symbolic-ref --short HEAD 2>/dev/null || echo "main")"

# 推送分支与 Tag
info "正在推送分支 '${BRANCH}' 到远程 '${REMOTE}'..."
git push -u "$REMOTE" "$BRANCH"

info "正在推送 Tag '${TAG_NAME}' 到远程 '${REMOTE}'..."
if [[ "$FORCE_TAG" == true ]]; then
    git push "$REMOTE" "$TAG_NAME" --force
else
    git push "$REMOTE" "$TAG_NAME"
fi

ok "发布完成! GitHub Actions 将自动执行测试、构建 (linux-x64 / linux-arm64 / macos-arm64) 并发布 Release: ${TAG_NAME}"
ok "查看构建进度: https://github.com/FeulerLoup/rrp/actions"
