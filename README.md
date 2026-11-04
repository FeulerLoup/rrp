# rrp (Rust Reverse Proxy)

## 0. 一键安装与版本发布

```bash
# 自动识别系统 (Linux x64/arm64, macOS arm64) 下载安装最新 Release 二进制
curl -fsSL https://raw.githubusercontent.com/FeulerLoup/rrp/master/scripts/install.sh | bash

# 使用 GitHub 代理镜像加速一键安装（如国内网络环境）
curl -fsSL https://ghfast.top/https://raw.githubusercontent.com/FeulerLoup/rrp/master/scripts/install.sh | bash -s -- --mirror ghfast.top

# 或指定版本与安装目录
./scripts/install.sh --version v0.1.0 --dir /usr/local/bin

# 本地静态编译当前架构二进制到 dist/rrp
./scripts/build.sh

# 开发者一键改版本号 + 打 Tag + 推送触发 GitHub Actions 自动构建测试与发布
./scripts/release.sh 0.1.0    # 或 ./scripts/release.sh patch / minor / major
```

## 1. 客户端生成密钥与设置开机自启

```bash
# 生成 mlkem768x25519 密钥对，默认写入 /usr/local/etc/rrp/rrpc.toml（文件权限 0600），终端输出公钥
sudo rrp install --mode client

# 同时设置系统级开机自启（Linux systemd / macOS launchd），也可通过 -c 指定自定义路径
sudo rrp install --mode client -c /usr/local/etc/rrp/rrpc.toml --autostart

# 重复执行 install 会保留已有私钥并再次打印公钥；如需轮换密钥（需在服务端重新 approve）：
sudo rrp install --mode client --regenerate-key
```

`rrp install` / `rrp approve` 遇到已存在但无法解析的配置文件时会直接报错退出，不会用默认配置覆盖。

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

## 4.1 内核隧道数据面（Linux 服务端 eBPF + WireGuard）

服务端在 Linux 上以 root 运行且 `enable_ebpf = true`（默认）时，rrp 会尝试启用内核隧道数据面：

- 服务端创建一个 WireGuard 接口（默认 `rrp-wg0`，UDP 端口 `3701`，由内核持有，无用户态进程监听），
  并在公网网卡与该接口上挂载 TC eBPF 程序（源码 `bpf/rrp_tc.c`，预编译对象 `bpf/rrp_tc.o`）。
- 访客流量到达 `公网IP:remote_port` 时，eBPF 程序按静态表改写目的地址为客户端隧道地址后直接送入
  WireGuard 加密发往客户端；被代理的端口**不会出现任何用户态监听 socket**，服务端内存中也不会出现明文载荷。
- 客户端（Linux，root）收到 `RegisterAck` 中的隧道参数后创建 `rrpc-wg<N>` 接口，在隧道地址上用普通 socket
  监听并明文中继到本地服务，回包经策略路由回到隧道。访客真实 IP 在客户端可见。
- WireGuard 的 PSK 由 mlkem768x25519plus 控制握手派生（后量子混合），每次控制会话轮换；X25519 节点密钥
  复用 `rrp install` 生成的密钥，无需额外密钥管理。
- 每个访客连接不再需要单独的 ML-KEM 握手和到服务端的新 TCP 连接。

任一条件不满足（非 Linux、无 `CAP_NET_ADMIN`/`CAP_BPF`、缺少 `wireguard` 内核模块、内核低于 5.10、
客户端或服务端任一方未启用）时自动回退到原有的用户态加密中继，`rrp status` 的 `eBPF:` 一行会说明原因。

服务端 `rrps.toml` 可选配置（均有默认值）：

```toml
enable_ebpf = true

[tunnel]
interface = "rrp-wg0"          # WireGuard 接口名
listen_port = 3701             # WireGuard UDP 端口（需在防火墙放行）
# public_interface = "eth0"    # 默认取默认路由所在网卡
# public_ipv4 = "203.0.113.10" # 默认取该网卡第一个非回环 IPv4
# public_ipv6 = "2001:db8::1"  # 默认取该网卡第一个全局 IPv6
ipv4_cidr = "10.199.0.0/16"    # 隧道地址池，首个地址为服务端
ipv6_cidr = "fd00:7272::/64"
mtu = 1420                     # eBPF 会据此钳制访客 SYN 的 MSS
```

客户端 `rrpc.toml`：

```toml
tunnel_mode = "auto"   # auto: 能用则用，失败回退中继；relay: 始终中继；tunnel: 必须隧道
```

限制：隧道模式下 `remote_bind_ip` 只用于选择地址族（填 IPv4 字面量则仅 IPv4，填 IPv6 则仅 IPv6），
不再绑定到具体地址；服务端每个地址族只使用一个公网 IP 作为回包源地址；访客侧 IPv4/IPv6 互转由客户端
中继完成，服务端 eBPF 只做同族转发。

在 Linux 上核对隧道是否生效：

```bash
rrp status --mode server          # eBPF: active (TC redirect eth0 <-> rrp-wg0, ...)
wg show rrp-wg0                   # 应看到客户端 peer 与最近握手时间
tc filter show dev eth0 ingress   # 应看到 rrp_public_ingress
ss -lntp | grep <remote_port>     # 应为空：端口没有用户态监听
```

单机端到端验证脚本（需要 root，使用三个网络命名空间模拟访客/服务端/客户端，覆盖 IPv4/IPv6 的
TCP/UDP 转发、MSS 钳制、严格 rp_filter、eBPF 计数回填、中继模式共存以及两端退出后的资源清理）：

```bash
sudo ./scripts/linux-tunnel-smoke.sh ./dist/rrp
```

该脚本已在 Ubuntu 26.04（内核 7.0，aarch64，Lima 虚拟机）上通过；macOS 开发机可用 `brew install lima` 后
`limactl start template://ubuntu-lts` 得到同样的环境。

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
流量统计仅包含代理业务载荷，不包含加密和协议开销；隧道模式下服务端的流量来自 eBPF 计数（含 IP/TCP 头）。

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


## 7. 时间同步（时钟偏差导致握手被拒）

握手时客户端会在 ClientHello 中携带当前 Unix 时间戳，服务端校验其与本机时间的偏差，超过 **300 秒**即拒绝连接（用于防重放），并在服务端日志中输出：

```text
WARN rrp::crypto: rejected ClientHello for key_id 08da8632eced9ee1: clock skew of 695s exceeds the 300s window (check NTP on both hosts)
```

出现该日志说明客户端与服务端两台主机的系统时间相差超过 5 分钟，需在**两端**都校准时间。先在两端各执行一次 `date -u` 对比 UTC 时间（与时区无关，只比较 UTC），再按系统类型处理。

### Linux

```bash
# 查看同步状态（System clock synchronized: yes 表示已同步，NTP service: active 表示 NTP 已启用）
timedatectl

# 使用 systemd-timesyncd（大多数发行版默认自带）：启用 NTP 并立即生效
sudo timedatectl set-ntp true

# 若偏差较大，重启服务可触发立即校时
sudo systemctl restart systemd-timesyncd
timedatectl timesync-status
```

若系统使用 `chrony`（RHEL/CentOS/Rocky 默认，Debian/Ubuntu 可 `apt install chrony`）：

```bash
sudo systemctl enable --now chronyd    # Debian/Ubuntu 服务名为 chrony
sudo chronyc makestep                   # 立即跳步校正，而非缓慢调整
chronyc tracking                        # 查看当前偏差（System time 行）
```

若无法安装 NTP 服务（容器、精简系统等），可用 `ntpdate` / `sntp` 做一次性校时，并通过 cron 定期执行：

```bash
sudo apt install ntpsec-ntpdate   # 或 ntpdate / sntp
sudo ntpdate -u pool.ntp.org
```

国内网络可将 NTP 服务器换为 `ntp.aliyun.com`、`ntp.tencent.com` 或 `cn.pool.ntp.org`，例如在 `/etc/systemd/timesyncd.conf` 中设置 `NTP=ntp.aliyun.com`，或在 `/etc/chrony.conf` 中添加 `server ntp.aliyun.com iburst`。

### macOS

```bash
# 查看当前 NTP 服务器与是否启用
sudo systemsetup -getnetworktimeserver
sudo systemsetup -getusingnetworktime

# 启用自动校时（等同于「系统设置 → 通用 → 日期与时间 → 自动设置时间与日期」）
sudo systemsetup -setusingnetworktime on

# 可选：更换 NTP 服务器（国内可用 ntp.aliyun.com）
sudo systemsetup -setnetworktimeserver time.apple.com

# 立即进行一次校时（仅查询不修改可加 -d）
sudo sntp -sS time.apple.com
```

> 注意：macOS 上的 `sntp -sS` 会立即跳步修改系统时间；若仅想查看偏差，使用 `sntp -d time.apple.com`。

### 校准后

两端时间校准完成后无需重启服务端，客户端会在下一次重连时重新握手。若客户端已在退避重连中，可直接重启客户端进程（`sudo systemctl restart rrp-client` 或 `sudo launchctl kickstart -k system/com.rrp.client`）以立即重试。

常见原因：虚拟机/容器挂起后恢复导致时钟停滞、主机未启用 NTP、新装系统默认时间错误、硬件时钟（RTC）电池失效。若校时后仍反复出现偏差，请检查 NTP 服务是否持续运行，而非仅做了一次性校时。
