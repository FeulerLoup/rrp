# rrp (Rust Reverse Proxy)

## 0. 一键安装与版本发布

```bash
# 自动识别系统 (Linux x64/arm64, macOS arm64) 下载安装最新 Release 二进制
curl -fsSL https://raw.githubusercontent.com/FeulerLoup/rrp/main/scripts/install.sh | bash

# 使用 GitHub 代理镜像加速一键安装（如国内网络环境）
curl -fsSL https://ghfast.top/https://raw.githubusercontent.com/FeulerLoup/rrp/main/scripts/install.sh | bash -s -- --mirror ghfast.top

# 或指定版本与安装目录
./scripts/install.sh --version v0.1.0 --dir /usr/local/bin

# 本地静态编译当前架构二进制到 dist/rrp
./scripts/build.sh

# 开发者一键改版本号 + 打 Tag + 推送触发 GitHub Actions 自动构建测试与发布
./scripts/release.sh 0.1.0    # 或 ./scripts/release.sh patch / minor / major
```

## 1. 客户端生成密钥与设置开机自启

```bash
# 生成 mlkem768x25519 密钥对，默认写入 /usr/local/etc/rrp/rrpc.toml，终端输出公钥
sudo rrp install --mode client

# 同时设置系统级开机自启（Linux systemd / macOS launchd），也可通过 -c 指定自定义路径
sudo rrp install --mode client -c /usr/local/etc/rrp/rrpc.toml --autostart
```

## 2. 服务端授权公钥与设置开机自启

```bash
# 将客户端生成的公钥写入服务端配置（默认 /usr/local/etc/rrp/rrps.toml）
sudo rrp approve <CLIENT_PUBLIC_KEY>

# 可选：设置服务端系统级开机自启
sudo rrp install --mode server -c /usr/local/etc/rrp/rrps.toml --autostart
```

## 3. 配置文件示例

服务端 `rrps.toml`（默认监听端口为 `3700`）：

```toml
bind_addr = "[::]:3700"
proxy_bind_ip = "::"
enable_ebpf = true
authorized_keys = [
    "<CLIENT_PUBLIC_KEY>"
]
```

客户端 `rrpc.toml`（支持单服务端或多服务端同时注册、`tcp`/`udp`/`all` 及 IPv4/IPv6 互转）：

```toml
# 方式一：单服务端使用 server_addr = "203.0.113.10:3700"
# 方式二：多服务端同时注册使用 server_addrs（全局 [[proxies]] 默认注册到所有服务端）
server_addrs = ["203.0.113.10:3700", "[2001:db8::1]:3700"]
private_key = "<GENERATED_BY_RRP_INSTALL>"
enable_ebpf = true

# 全局代理（自动同时注册到上述所有服务端）
[[proxies]]
name = "web_tcp"
type = "tcp"
local_addr = "127.0.0.1:8080"
remote_port = 18080

# 仅注册到指定服务端（可通过 server / servers 指定服务端地址或名称）
[[proxies]]
name = "dns_udp"
type = "udp"
server = "203.0.113.10:3700"
local_addr = "[::1]:5353"
remote_port = 15353

[[proxies]]
name = "game_all"
type = "all"
local_addr = "127.0.0.1:9000"
remote_port = 19000

# 方式三：通过 [[servers]] 单独配置服务端（支持独立密钥、心跳间隔及专属代理）
[[servers]]
name = "backup_node"
server_addr = "198.51.100.20:3700"
# private_key = "<OPTIONAL_DEDICATED_PRIVATE_KEY>"

[[servers.proxies]]
name = "ssh_backup"
type = "tcp"
local_addr = "127.0.0.1:22"
remote_port = 20022
```

## 4. 启动运行

```bash
# 启动服务端（默认读取 /usr/local/etc/rrp/rrps.toml，可通过 -c 指定其他路径）
rrp server

# 启动客户端（默认读取 /usr/local/etc/rrp/rrpc.toml，可通过 -c 指定其他路径）
rrp client

# 启动客户端并通过命令行指定/覆盖多个服务端地址
rrp client -c /usr/local/etc/rrp/rrpc.toml -s 203.0.113.10:3700,198.51.100.20:3700
```

## 5. 查看运行状态

```bash
# 自动显示当前运行的客户端和/或服务端
rrp status

# 只查看一种模式
rrp status --mode client
rrp status --mode server

# 输出适合脚本处理的 JSON
rrp status --json
```

状态包含进程运行时长、各服务端/客户端连接时长、实时业务流量、最后心跳及客户端心跳 RTT。
流量统计仅包含代理业务载荷，不包含加密和协议开销。

运行时快照默认写入 Linux 的 `/run/rrp/`（无权限时回退到当前用户临时目录）或
macOS 的 `/var/run/rrp/`。可为运行进程和查询命令同时设置 `RRP_STATUS_DIR`，
也可通过 `rrp status --file <PATH>` 读取指定快照。

## 6. 卸载自启与彻底清理

```bash
# 卸载所有系统级开机自启服务（保留配置文件与 rrp 二进制）
sudo rrp uninstall

# 仅卸载指定模式的开机自启服务
sudo rrp uninstall --mode client
sudo rrp uninstall --mode server

# 卸载开机自启服务，并彻底删除配置文件与 rrp 自身二进制
sudo rrp uninstall --purge
sudo rrp uninstall --mode client -c /usr/local/etc/rrp/rrpc.toml --purge
```

`rrp uninstall` 会自动停止并移除系统级自启服务（Linux 下停止/禁用并删除 `/etc/systemd/system/rrp-{client,server}.service`，macOS 下卸载并删除 `/Library/LaunchDaemons/com.rrp.{client,server}.plist`，可通过 `--service-dir` 指定自定义目录）。

- 默认不带 `--mode` 时会同时检查并卸载 `client` 与 `server` 自启服务；默认保留配置文件与 `rrp` 二进制。
- 附加 `--purge` 时，除移除自启服务外，还会一并删除配置文件（自动识别服务文件中记录的 `-c` 路径、命令行 `-c` 指定路径或默认的 `/usr/local/etc/rrp/rrpc.toml`、`rrps.toml`，并在配置目录为空时自动清理目录）以及当前 `rrp` 二进制文件本身。

