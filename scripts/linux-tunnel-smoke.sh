#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# 内核隧道数据面端到端验证（单台 Linux 主机，需 root）
#
# 用三个网络命名空间模拟：
#   rrp-visitor (10.10.0.2) --veth-- pub0 (10.10.0.1) [rrp-server] int0 (10.20.0.1) --veth-- cli0 (10.20.0.2) [rrp-client]
#
# 访客连接服务端“公网”地址 10.10.0.1:18080 / :15353，流量应经 TC eBPF 改写进入 WireGuard，
# 到达客户端命名空间后由 rrp 客户端明文中继到本地 echo 服务。服务端上不应有被代理端口的监听 socket。
#
# 用法: sudo ./scripts/linux-tunnel-smoke.sh /path/to/rrp [--keep]
# ==============================================================================

RRP="${1:?用法: $0 /path/to/rrp [--keep]}"
KEEP="${2:-}"
[[ "$(id -u)" -eq 0 ]] || { echo "需要 root" >&2; exit 1; }
[[ -x "$RRP" ]] || { echo "找不到可执行文件: $RRP" >&2; exit 1; }

WORK="$(mktemp -d /tmp/rrp-smoke.XXXXXX)"
TCP_PORT=18080
UDP_PORT=15353
PASS=0

log()  { printf '\033[0;34m[smoke]\033[0m %s\n' "$*"; }
ok()   { printf '\033[0;32m[ OK ]\033[0m %s\n' "$*"; }
fail() { printf '\033[0;31m[FAIL]\033[0m %s\n' "$*" >&2; }

cleanup() {
    set +e
    pkill -f "$RRP server -c $WORK" 2>/dev/null
    pkill -f "$RRP client -c $WORK" 2>/dev/null
    pkill -f "$WORK/echo.py" 2>/dev/null
    pkill -f "$WORK/rrpc-relay.toml" 2>/dev/null
    sleep 0.5
    if [[ "$KEEP" != "--keep" ]]; then
        for ns in rrp-visitor rrp-server rrp-client; do ip netns del "$ns" 2>/dev/null; done
        rm -rf "$WORK"
    else
        log "保留命名空间与工作目录 $WORK"
    fi
}
trap cleanup EXIT

dump_state() {
    echo "----- server.log"; cat "$WORK/server.log" 2>/dev/null | tail -60
    echo "----- client.log"; cat "$WORK/client.log" 2>/dev/null | tail -60
    echo "----- server: tc / wg / ss"
    ip netns exec rrp-server tc filter show dev pub0 ingress 2>/dev/null
    ip netns exec rrp-server tc filter show dev rrp-wg0 ingress 2>/dev/null
    ip netns exec rrp-server wg show 2>/dev/null
    ip netns exec rrp-server ss -lntup 2>/dev/null
    echo "----- client: wg / rule / route"
    ip netns exec rrp-client wg show 2>/dev/null
    ip netns exec rrp-client ip rule 2>/dev/null
    ip netns exec rrp-client ip route show table 7200 2>/dev/null
    ip netns exec rrp-client ss -lntup 2>/dev/null
    echo "----- dmesg (bpf)"; dmesg 2>/dev/null | grep -i -E 'bpf|wireguard' | tail -20
}

log "内核 $(uname -r)"
modprobe wireguard 2>/dev/null || true
command -v wg >/dev/null 2>&1 || log "未安装 wireguard-tools（仅影响诊断输出，不影响测试）"

# ---- 命名空间与链路 ------------------------------------------------------------
for ns in rrp-visitor rrp-server rrp-client; do ip netns del "$ns" 2>/dev/null || true; done
ip netns add rrp-visitor
ip netns add rrp-server
ip netns add rrp-client

ip link add vis0 type veth peer name pub0
ip link set vis0 netns rrp-visitor
ip link set pub0 netns rrp-server
ip -n rrp-visitor addr add 10.10.0.2/24 dev vis0
ip -n rrp-visitor link set lo up
ip -n rrp-visitor link set vis0 up
ip -n rrp-server addr add 10.10.0.1/24 dev pub0
ip -n rrp-server link set lo up
ip -n rrp-server link set pub0 up
# IPv6 on the public link too, so the v6 rewrite path (16-byte csum_diff) is exercised.
ip -n rrp-visitor addr add fd10::2/64 dev vis0 nodad
ip -n rrp-server addr add fd10::1/64 dev pub0 nodad

ip link add int0 type veth peer name cli0
ip link set int0 netns rrp-server
ip link set cli0 netns rrp-client
ip -n rrp-server addr add 10.20.0.1/24 dev int0
ip -n rrp-server link set int0 up
ip -n rrp-client addr add 10.20.0.2/24 dev cli0
ip -n rrp-client link set lo up
ip -n rrp-client link set cli0 up

# 客户端启用严格反向路径过滤，验证策略路由足以让访客包通过。
ip netns exec rrp-client sysctl -qw net.ipv4.conf.all.rp_filter=1 net.ipv4.conf.default.rp_filter=1

# ---- 本地 echo 服务（客户端命名空间）-----------------------------------------
cat > "$WORK/echo.py" <<'EOF'
import socket, threading
def tcp():
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 8080)); s.listen(16)
    while True:
        c, _ = s.accept()
        def h(c):
            try:
                while True:
                    d = c.recv(65536)
                    if not d: break
                    c.sendall(d)
            finally:
                c.close()
        threading.Thread(target=h, args=(c,), daemon=True).start()
def udp():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("127.0.0.1", 5353))
    while True:
        d, a = s.recvfrom(65536); s.sendto(b"udp-echo:" + d, a)
threading.Thread(target=udp, daemon=True).start()
tcp()
EOF
ip netns exec rrp-client python3 "$WORK/echo.py" >/dev/null 2>&1 &
sleep 0.3

# ---- 配置 ------------------------------------------------------------------------
"$RRP" install --mode client -c "$WORK/keygen.toml" >"$WORK/install.out"
PUBKEY="$(tail -1 "$WORK/install.out")"
PRIVKEY="$(grep '^private_key' "$WORK/keygen.toml" | sed 's/.*= *"\(.*\)"/\1/')"

cat > "$WORK/rrps.toml" <<EOF
bind_addr = "10.20.0.1:3700"
proxy_bind_ip = "0.0.0.0"
authorized_keys = ["$PUBKEY"]
enable_ebpf = true
heartbeat_timeout_secs = 30

[tunnel]
interface = "rrp-wg0"
listen_port = 3701
public_interface = "pub0"
mtu = 1420
EOF

cat > "$WORK/rrpc.toml" <<EOF
server_addr = "10.20.0.1:3700"
private_key = "$PRIVKEY"
enable_ebpf = true
heartbeat_interval_secs = 5
tunnel_mode = "tunnel"

[[proxies]]
name = "tcp_echo"
type = "tcp"
local_addr = "127.0.0.1:8080"
remote_port = $TCP_PORT

[[proxies]]
name = "udp_echo"
type = "udp"
local_addr = "127.0.0.1:5353"
remote_port = $UDP_PORT
EOF

# ---- 启动 ------------------------------------------------------------------------
log "启动服务端"
ip netns exec rrp-server env RUST_LOG=debug RRP_STATUS_DIR="$WORK/status-s" \
    "$RRP" server -c "$WORK/rrps.toml" >"$WORK/server.log" 2>&1 &
sleep 2
if ! grep -q 'tunnel data plane active' "$WORK/server.log"; then
    fail "服务端隧道数据面未启动"; dump_state; exit 1
fi
ok "服务端隧道数据面已启动: $(grep -o 'active (TC redirect[^)]*)' "$WORK/server.log" | head -1)"
grep -q 'v6 fd10::1' "$WORK/server.log" || { fail "服务端未自动识别公网 IPv6"; dump_state; exit 1; }

log "启动客户端"
ip netns exec rrp-client env RUST_LOG=debug RRP_STATUS_DIR="$WORK/status-c" \
    "$RRP" client -c "$WORK/rrpc.toml" >"$WORK/client.log" 2>&1 &
for _ in $(seq 1 40); do
    grep -q 'through the tunnel' "$WORK/client.log" && break
    sleep 0.25
done
if ! grep -q 'through the tunnel' "$WORK/client.log"; then
    fail "客户端未通过隧道完成注册"; dump_state; exit 1
fi
ok "客户端已通过隧道注册"

# ---- 断言：服务端没有用户态监听 -------------------------------------------------------
if ip netns exec rrp-server ss -lntu | grep -qE ":($TCP_PORT|$UDP_PORT) "; then
    fail "服务端出现了被代理端口的监听 socket"; dump_state; exit 1
fi
ok "服务端没有被代理端口的用户态监听"

# ---- 等待 WireGuard 握手（客户端保活会触发）------------------------------------------
sleep 1

# ---- 访客测试 ----------------------------------------------------------------------
cat > "$WORK/visitor.py" <<EOF
import socket, sys, time
tcp_port, udp_port = $TCP_PORT, $UDP_PORT
# 1. TCP：大载荷，检验 MSS 钳制与双向改写
payload = bytes((i * 7) % 251 for i in range(300_000))
c = socket.create_connection(("10.10.0.1", tcp_port), timeout=10)
c.sendall(payload)
got = b""
c.settimeout(10)
while len(got) < len(payload):
    d = c.recv(65536)
    if not d: break
    got += d
c.close()
assert got == payload, f"tcp echo mismatch: got {len(got)} bytes"
print("tcp 300000 bytes echoed")
# 2. 多条并发短连接
for i in range(20):
    c = socket.create_connection(("10.10.0.1", tcp_port), timeout=5)
    c.sendall(b"ping-%d" % i); assert c.recv(64) == b"ping-%d" % i; c.close()
print("tcp 20 short connections ok")
# 3. UDP
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.settimeout(5)
u.sendto(b"hello-udp", ("10.10.0.1", udp_port))
d, a = u.recvfrom(1024)
assert d == b"udp-echo:hello-udp", d
assert a[1] == udp_port, a
print("udp echo ok from", a)
# 4. IPv6 访客 -> 服务端 [fd10::1] -> 隧道 v6 -> 客户端 -> 本地 IPv4 服务
c = socket.create_connection(("fd10::1", tcp_port), timeout=10)
c.sendall(payload)
got = b""
c.settimeout(10)
while len(got) < len(payload):
    d = c.recv(65536)
    if not d: break
    got += d
c.close()
assert got == payload, f"tcp6 echo mismatch: got {len(got)} bytes"
print("tcp6 300000 bytes echoed")
u6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM); u6.settimeout(5)
u6.sendto(b"hello-udp6", ("fd10::1", udp_port))
d, a = u6.recvfrom(1024)
assert d == b"udp-echo:hello-udp6", d
assert a[1] == udp_port, a
print("udp6 echo ok from", a[:2])
EOF
if ip netns exec rrp-visitor python3 "$WORK/visitor.py"; then
    ok "访客 TCP/UDP 经隧道转发成功"
else
    fail "访客转发失败"; dump_state; exit 1
fi

# ---- 状态与计数 ------------------------------------------------------------------------
# eBPF 计数每秒回填一次，状态文件每秒写一次，等足两个周期再读。
sleep 3
echo "----- bpftool map dump rrp_stats (server)"
ip netns exec rrp-server bpftool map dump name rrp_stats 2>/dev/null | head -40 || true
echo "----- rrp status (server)"
"$RRP" status --file "$WORK/status-s/server.json" || true
echo "----- rrp status (client)"
"$RRP" status --file "$WORK/status-c/client.json" || true
SERVER_TOTAL="$("$RRP" status --file "$WORK/status-s/server.json" --json | python3 -c 'import json,sys; print(json.load(sys.stdin)["traffic"]["total_bytes"])')"
if [[ "${SERVER_TOTAL:-0}" -lt 300000 ]]; then
    fail "服务端 eBPF 流量计数异常: total_bytes=$SERVER_TOTAL"; dump_state; exit 1
fi
ok "服务端 eBPF 流量计数已回填 (total_bytes=$SERVER_TOTAL)"
CLIENT_PLANE="$("$RRP" status --file "$WORK/status-c/client.json" --json | python3 -c 'import json,sys; print(json.load(sys.stdin)["ebpf_status"])')"
if [[ "$CLIENT_PLANE" != active* ]]; then
    fail "客户端状态未显示隧道生效: $CLIENT_PLANE"; dump_state; exit 1
fi
ok "客户端状态: $CLIENT_PLANE"

# ---- 断开/重连：杀掉客户端，服务端应清理 peer 与端口表 ----------------------------------
if command -v wg >/dev/null 2>&1; then
    PEERS_BEFORE="$(ip netns exec rrp-server wg show rrp-wg0 peers | wc -l)"
    [[ "$PEERS_BEFORE" -eq 1 ]] || { fail "预期服务端有 1 个 peer，实际 $PEERS_BEFORE"; dump_state; exit 1; }
    echo "----- wg show (server)"; ip netns exec rrp-server wg show rrp-wg0
fi
pkill -f "$RRP client -c $WORK" || true
sleep 2
if command -v wg >/dev/null 2>&1; then
    if ip netns exec rrp-server wg show rrp-wg0 peers | grep -q .; then
        fail "客户端断开后服务端仍保留 WireGuard peer"; dump_state; exit 1
    fi
    ok "客户端断开后服务端已清理 peer"
    if ip netns exec rrp-client ip link show rrpc-wg0 >/dev/null 2>&1; then
        fail "客户端退出后 rrpc-wg0 仍存在"; dump_state; exit 1
    fi
    ok "客户端退出后隧道接口已删除"
else
    log "未安装 wg，跳过 peer 清理断言"
fi
if ip netns exec rrp-server bpftool map dump name rrp_portmap 2>/dev/null | grep -q '"port"'; then
    fail "客户端断开后服务端端口表未清空"; dump_state; exit 1
fi
ok "客户端断开后服务端端口表已清空"

# ---- 中继模式客户端仍可与隧道服务端共存 ------------------------------------------------------
sed 's/^tunnel_mode = "tunnel"/tunnel_mode = "relay"/' "$WORK/rrpc.toml" > "$WORK/rrpc-relay.toml"
ip netns exec rrp-client env RRP_STATUS_DIR="$WORK/status-c2" \
    "$RRP" client -c "$WORK/rrpc-relay.toml" >"$WORK/client-relay.log" 2>&1 &
for _ in $(seq 1 40); do
    grep -q 'connected to server .* successfully' "$WORK/client-relay.log" && break
    sleep 0.25
done
grep -q 'connected to server .* successfully' "$WORK/client-relay.log" \
    || { fail "中继模式客户端未能注册"; tail -20 "$WORK/client-relay.log"; dump_state; exit 1; }
ip netns exec rrp-server ss -lnt | grep -q ":$TCP_PORT " \
    || { fail "中继模式下服务端应有用户态监听"; dump_state; exit 1; }
cat > "$WORK/visitor-relay.py" <<EOF
import socket
c = socket.create_connection(("10.10.0.1", $TCP_PORT), timeout=5)
c.sendall(b"relay-mode"); assert c.recv(64) == b"relay-mode"; c.close()
EOF
if ip netns exec rrp-visitor python3 "$WORK/visitor-relay.py"; then
    ok "中继模式客户端经用户态中继转发成功"
else
    fail "中继模式转发失败"; dump_state; exit 1
fi
pkill -f "$RRP client -c $WORK/rrpc-relay.toml" || true
sleep 1

# ---- 服务端退出：接口与 TC 程序应随之消失 ---------------------------------------------------
pkill -f "$RRP server -c $WORK" || true
sleep 2
if ip netns exec rrp-server ip link show rrp-wg0 >/dev/null 2>&1; then
    fail "服务端退出后 rrp-wg0 仍存在"; dump_state; exit 1
fi
ok "服务端退出后 WireGuard 接口已删除"
if ip netns exec rrp-server tc filter show dev pub0 ingress 2>/dev/null | grep -q rrp_public_ingress; then
    fail "服务端退出后 TC 程序仍挂在 pub0 上"; dump_state; exit 1
fi
ok "服务端退出后 TC 程序已卸载"

PASS=1
ok "全部通过"
