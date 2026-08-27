#!/bin/sh
set -u

PROGRAM=${0##*/}
INTERFACE=""
CIDR=""
PRIMARY=""
GATEWAY=""
TEST_ADDRESS=""
TIMEOUT=7
TARGETS_SUPPLIED=0
WORK_DIR=""
CAPTURE_PID=""
ADDRESS_ADDED=0
COLOR_RESET=""
COLOR_BOLD=""
COLOR_CYAN=""
COLOR_GREEN=""
COLOR_RED=""
COLOR_YELLOW=""
COLOR_MUTED=""

if [ -t 1 ] && [ "${TERM:-dumb}" != dumb ] && [ "${NO_COLOR+x}" != x ]; then
  COLOR_RESET=$(printf '\033[0m')
  COLOR_BOLD=$(printf '\033[1m')
  COLOR_CYAN=$(printf '\033[36m')
  COLOR_GREEN=$(printf '\033[32m')
  COLOR_RED=$(printf '\033[31m')
  COLOR_YELLOW=$(printf '\033[33m')
  COLOR_MUTED=$(printf '\033[2m')
fi

usage() {
  cat <<EOF
用法: $PROGRAM [选项]

诊断 on-link Prefix 中的原生 IPv6 地址能否正常发送和接收流量。
脚本只添加一个临时 /128，不修改路由、sysctl、Proxy NDP 或防火墙规则。

选项:
  --interface NAME       IPv6 网卡（默认从 IPv6 默认路由自动检测）
  --cidr PREFIX          connected 公网 Prefix（默认自动检测）
  --primary ADDRESS      已配置的主源 IPv6（默认自动检测）
  --gateway ADDRESS      IPv6 默认网关（默认自动检测）
  --test-address ADDRESS Prefix 内的临时测试地址（默认随机生成）
  --target TARGET        字面量 [IPv6]:端口，可重复指定
  --timeout SECONDS      单次连接超时秒数（默认 7）
  -h, --help             显示帮助

未指定 --target 时使用以下默认目标:
  [2607:9d00:2000:1cf::75d5:d75b]:443
  [2606:4700:4700::1111]:443
EOF
}

die() {
  printf '%s%s错误%s: %s\n' "$COLOR_RED" "$COLOR_BOLD" "$COLOR_RESET" "$*" >&2
  exit 2
}

cleanup() {
  if [ -n "$CAPTURE_PID" ] && kill -0 "$CAPTURE_PID" 2>/dev/null; then
    kill -INT "$CAPTURE_PID" 2>/dev/null || true
    wait "$CAPTURE_PID" 2>/dev/null || true
  fi
  CAPTURE_PID=""
  if [ "$ADDRESS_ADDED" -eq 1 ]; then
    ip -6 addr del "$TEST_ADDRESS/128" dev "$INTERFACE" 2>/dev/null || true
    ADDRESS_ADDED=0
    printf '%s[清理]%s 已删除临时地址 %s/128\n' "$COLOR_GREEN" "$COLOR_RESET" "$TEST_ADDRESS"
  fi
  if [ -n "$WORK_DIR" ] && [ -d "$WORK_DIR" ]; then
    rm -rf "$WORK_DIR"
  fi
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP

if [ "$#" -eq 1 ]; then
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
  esac
fi

for required in ip python3 mktemp awk sed grep sort sysctl tcpdump ping; do
  command -v "$required" >/dev/null 2>&1 || die "缺少必需命令: $required"
done

WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/v6socks-source-debug.XXXXXX") || exit 2
TARGET_FILE="$WORK_DIR/targets"
CAPTURE_FILE="$WORK_DIR/capture.log"
PROBE_FILE="$WORK_DIR/probes.tsv"
ADDR_FILE="$WORK_DIR/interface-addrs"
ROUTE_FILE="$WORK_DIR/interface-routes"
LOCAL_ROUTE_FILE="$WORK_DIR/local-routes"
: >"$TARGET_FILE"
: >"$CAPTURE_FILE"
: >"$PROBE_FILE"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --interface)
      [ "$#" -ge 2 ] || die "--interface 需要参数值"
      INTERFACE=$2
      shift 2
      ;;
    --cidr)
      [ "$#" -ge 2 ] || die "--cidr 需要参数值"
      CIDR=$2
      shift 2
      ;;
    --primary)
      [ "$#" -ge 2 ] || die "--primary 需要参数值"
      PRIMARY=$2
      shift 2
      ;;
    --gateway)
      [ "$#" -ge 2 ] || die "--gateway 需要参数值"
      GATEWAY=$2
      shift 2
      ;;
    --test-address)
      [ "$#" -ge 2 ] || die "--test-address 需要参数值"
      TEST_ADDRESS=$2
      shift 2
      ;;
    --target)
      [ "$#" -ge 2 ] || die "--target 需要参数值"
      printf '%s\n' "$2" >>"$TARGET_FILE"
      TARGETS_SUPPLIED=1
      shift 2
      ;;
    --timeout)
      [ "$#" -ge 2 ] || die "--timeout 需要参数值"
      TIMEOUT=$2
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *) die "未知参数: $1" ;;
  esac
done

case "$TIMEOUT" in ''|*[!0-9]*) die "--timeout 必须是正整数" ;; esac
[ "$TIMEOUT" -gt 0 ] || die "--timeout 必须大于零"

if [ "$TARGETS_SUPPLIED" -eq 0 ]; then
  printf '%s\n' \
    '[2607:9d00:2000:1cf::75d5:d75b]:443' \
    '[2606:4700:4700::1111]:443' >"$TARGET_FILE"
fi

python3 - "$TARGET_FILE" <<'PY' || die "--target 参数无效"
import ipaddress
import sys

path = sys.argv[1]
targets = []
for raw in open(path, encoding="utf-8"):
    value = raw.strip()
    if not value.startswith("[") or "]:" not in value:
        raise SystemExit(f"目标必须使用 [IPv6]:端口 格式: {value}")
    host, port_text = value[1:].rsplit("]:" , 1)
    try:
        host = str(ipaddress.IPv6Address(host))
        port = int(port_text)
    except ValueError as exc:
        raise SystemExit(f"目标无效 {value}: {exc}")
    if not 1 <= port <= 65535:
        raise SystemExit(f"目标端口无效: {value}")
    normalized = f"[{host}]:{port}"
    if normalized not in targets:
        targets.append(normalized)
open(path, "w", encoding="utf-8").write("".join(x + "\n" for x in targets))
PY

FIRST_TARGET=$(sed -n '1p' "$TARGET_FILE")
FIRST_HOST=${FIRST_TARGET#\[}
FIRST_HOST=${FIRST_HOST%%\]:*}

if [ -z "$INTERFACE" ]; then
  interfaces=$(ip -6 route show default 2>/dev/null | awk '{for (i=1; i<=NF; i++) if ($i == "dev" && (i+1) <= NF) print $(i+1)}' | sort -u)
  interface_count=$(printf '%s\n' "$interfaces" | awk 'NF {n++} END {print n+0}')
  [ "$interface_count" -eq 1 ] || die "无法选出唯一 IPv6 默认网卡，请使用 --interface 指定"
  INTERFACE=$interfaces
fi
case "$INTERFACE" in ''|*[!A-Za-z0-9_.:-]*) die "网卡名称无效: $INTERFACE" ;; esac
ip link show dev "$INTERFACE" >/dev/null 2>&1 || die "网卡不存在: $INTERFACE"

if [ -z "$PRIMARY" ]; then
  PRIMARY=$(ip -6 route get "$FIRST_HOST" 2>/dev/null | awk -v dev="$INTERFACE" '
    $0 ~ (" dev " dev "( |$)") {
      for (i=1; i<=NF; i++) if ($i == "src" && (i+1) <= NF) {print $(i+1); exit}
    }')
fi

ip -o -6 addr show dev "$INTERFACE" scope global 2>/dev/null | awk '{print $4}' >"$ADDR_FILE"
ip -6 route show dev "$INTERFACE" 2>/dev/null >"$ROUTE_FILE"
ip -6 route show table local type local 2>/dev/null >"$LOCAL_ROUTE_FILE"

topology=$(python3 - "$PRIMARY" "$CIDR" "$ADDR_FILE" "$ROUTE_FILE" <<'PY'
import ipaddress
import sys

primary_raw, cidr_raw, addr_path, route_path = sys.argv[1:]
addresses = []
for raw in open(addr_path, encoding="utf-8"):
    try:
        addresses.append(ipaddress.IPv6Interface(raw.strip()))
    except ValueError:
        pass
if not addresses:
    raise SystemExit("所选网卡没有全局 IPv6 地址")

if primary_raw:
    primary = ipaddress.IPv6Address(primary_raw)
    matches = [item for item in addresses if item.ip == primary]
    if not matches:
        raise SystemExit("主地址未配置在所选网卡上")
else:
    if len(addresses) != 1:
        raise SystemExit("无法选出唯一主 IPv6 地址，请使用 --primary 指定")
    primary = addresses[0].ip
    matches = addresses

if cidr_raw:
    network = ipaddress.IPv6Network(cidr_raw, strict=False)
else:
    networks = []
    for item in matches:
        if 48 <= item.network.prefixlen <= 64 and item.ip.is_global and item.network not in networks:
            networks.append(item.network)
    if len(networks) != 1:
        raise SystemExit("无法选出唯一 connected 公网 Prefix，请使用 --cidr 指定")
    network = networks[0]

if not 48 <= network.prefixlen <= 64 or not network.network_address.is_global:
    raise SystemExit("Prefix 必须是前缀长度为 /48 到 /64 的公网 IPv6")
if primary not in network:
    raise SystemExit("主地址不在所选 Prefix 内")

connected = False
for raw in open(route_path, encoding="utf-8"):
    fields = raw.split()
    if not fields or fields[0] in ("default", "local", "unreachable") or "via" in fields:
        continue
    try:
        connected |= ipaddress.IPv6Network(fields[0], strict=False) == network
    except ValueError:
        pass
if not connected:
    raise SystemExit("所选 Prefix 与网卡上的 connected 路由不完全匹配")

print(primary)
print(network)
PY
) || die "无法验证 on-link 网络拓扑"
PRIMARY=$(printf '%s\n' "$topology" | sed -n '1p')
CIDR=$(printf '%s\n' "$topology" | sed -n '2p')

if [ -z "$GATEWAY" ]; then
  gateways=$(ip -6 route show default 2>/dev/null | awk -v dev="$INTERFACE" '
    $0 ~ (" dev " dev "( |$)") {
      for (i=1; i<=NF; i++) if ($i == "via" && (i+1) <= NF) print $(i+1)
    }' | sort -u)
  gateway_count=$(printf '%s\n' "$gateways" | awk 'NF {n++} END {print n+0}')
  [ "$gateway_count" -eq 1 ] || die "无法选出唯一 IPv6 默认网关，请使用 --gateway 指定"
  GATEWAY=$gateways
fi

selection=$(python3 - "$CIDR" "$PRIMARY" "$GATEWAY" "$TEST_ADDRESS" "$ADDR_FILE" "$LOCAL_ROUTE_FILE" <<'PY'
import ipaddress
import secrets
import sys

network = ipaddress.IPv6Network(sys.argv[1])
primary = ipaddress.IPv6Address(sys.argv[2])
gateway = ipaddress.IPv6Address(sys.argv[3])
requested = sys.argv[4]
used = {primary, gateway, network.network_address}
for raw in open(sys.argv[5], encoding="utf-8"):
    try:
        used.add(ipaddress.IPv6Interface(raw.strip()).ip)
    except ValueError:
        pass
for raw in open(sys.argv[6], encoding="utf-8"):
    fields = raw.split()
    if len(fields) < 2 or fields[0] != "local":
        continue
    value = fields[1] if "/" in fields[1] else fields[1] + "/128"
    try:
        route = ipaddress.IPv6Network(value, strict=False)
    except ValueError:
        continue
    if route.prefixlen == 128:
        used.add(route.network_address)

if requested:
    selected = ipaddress.IPv6Address(requested)
    if selected not in network:
        raise SystemExit("测试地址不在所选 Prefix 内")
    if selected in used:
        raise SystemExit("测试地址与已知本机地址或网关地址冲突")
else:
    selected = None
    for _ in range(128):
        candidate = ipaddress.IPv6Address(
            int(network.network_address) + secrets.randbelow(network.num_addresses)
        )
        if candidate not in used:
            selected = candidate
            break
    if selected is None:
        raise SystemExit("无法选择未占用的测试地址")
print(gateway)
print(selected)
PY
) || die "无法验证或选择测试地址"
GATEWAY=$(printf '%s\n' "$selection" | sed -n '1p')
TEST_ADDRESS=$(printf '%s\n' "$selection" | sed -n '2p')

if [ "$(id -u)" -ne 0 ]; then
  die "添加临时地址和抓包需要 root 权限"
fi

section() {
  printf '\n%s╭─ %s%s%s\n' "$COLOR_CYAN" "$COLOR_BOLD" "$1" "$COLOR_RESET"
  printf '%s╰────────────────────────────────────────────────────────────%s\n' "$COLOR_MUTED" "$COLOR_RESET"
}

subsection() {
  printf '\n%s▸ %s%s\n' "$COLOR_CYAN" "$1" "$COLOR_RESET"
}

key_value() {
  label=$1
  value=$2
  printf '  %s%s%s  %s\n' "$COLOR_BOLD" "$label" "$COLOR_RESET" "$value"
}

raw_block_start() {
  printf '%s┌─ %s%s\n' "$COLOR_MUTED" "$1" "$COLOR_RESET"
}

raw_block_end() {
  printf '%s└────────────────────────────────────────────────────────────%s\n' "$COLOR_MUTED" "$COLOR_RESET"
}

info() {
  printf '%s[说明]%s %s\n' "$COLOR_CYAN" "$COLOR_RESET" "$1"
}

muted() {
  printf '%s%s%s\n' "$COLOR_MUTED" "$1" "$COLOR_RESET"
}

confirm_detail_output() {
  prompt=$1
  answer=""
  if [ -t 0 ] && [ -t 1 ]; then
    printf '%s[确认]%s %s %s[y/N]%s: ' "$COLOR_YELLOW" "$COLOR_RESET" "$prompt" "$COLOR_BOLD" "$COLOR_RESET"
    IFS= read -r answer || answer=""
  fi
  case "$answer" in
    y|Y|yes|YES|Yes|是) return 0 ;;
    *) return 1 ;;
  esac
}

section "已选参数"
key_value "网卡      " "$INTERFACE"
key_value "Prefix    " "$CIDR"
key_value "主地址    " "$PRIMARY"
key_value "网关      " "$GATEWAY"
key_value "测试地址  " "$TEST_ADDRESS"
printf '  %s探测目标%s\n' "$COLOR_BOLD" "$COLOR_RESET"
sed 's/^/    /' "$TARGET_FILE"

section "基础网络配置"
subsection "系统与接口"
raw_block_start "date / uname / ip address"
date -Is
uname -a
ip -br link show dev "$INTERFACE"
ip -o -6 addr show dev "$INTERFACE"
raw_block_end
subsection "IPv6 路由与规则"
raw_block_start "ip -6 route / rule"
ip -6 route show dev "$INTERFACE"
ip -6 route show default
ip -6 route show table local type local
ip -6 rule show
raw_block_end

section "IPv6 内核参数"
raw_block_start "sysctl"
for key in \
  net.ipv6.conf.all.disable_ipv6 \
  net.ipv6.conf.all.forwarding \
  "net.ipv6.conf.$INTERFACE.disable_ipv6" \
  "net.ipv6.conf.$INTERFACE.forwarding" \
  "net.ipv6.conf.$INTERFACE.proxy_ndp" \
  "net.ipv6.conf.$INTERFACE.accept_ra" \
  net.ipv6.ip_nonlocal_bind
do
  sysctl "$key" 2>&1 || true
done
raw_block_end

capture_filter=$(python3 - "$TARGET_FILE" <<'PY'
import sys

clauses = []
for raw in open(sys.argv[1], encoding="utf-8"):
    host, port = raw.strip()[1:].rsplit("]:" , 1)
    clauses.append(f"(host {host} and port {port})")
print("icmp6 or (tcp and (" + " or ".join(clauses) + "))")
PY
)

section "启动抓包"
key_value "抓包过滤器" "$capture_filter"
tcpdump -l -n -i "$INTERFACE" -vv "$capture_filter" >"$CAPTURE_FILE" 2>&1 &
CAPTURE_PID=$!
sleep 1
if ! kill -0 "$CAPTURE_PID" 2>/dev/null; then
  cat "$CAPTURE_FILE"
  die "tcpdump 启动失败"
fi

section "添加原生测试地址"
if ip -6 addr show to "$TEST_ADDRESS" 2>/dev/null | grep -q .; then
  die "测试地址已存在: $TEST_ADDRESS"
fi
ip -6 addr add "$TEST_ADDRESS/128" dev "$INTERFACE" || die "无法添加临时地址"
ADDRESS_ADDED=1

dad_ready=0
dad_wait=0
while [ "$dad_wait" -lt 10 ]; do
  address_state=$(ip -o -6 addr show dev "$INTERFACE" to "$TEST_ADDRESS" 2>/dev/null || true)
  echo "$address_state" | grep -q 'dadfailed' && die "IPv6 DAD 检测到测试地址重复"
  if [ -n "$address_state" ] && ! echo "$address_state" | grep -q ' tentative'; then
    dad_ready=1
    break
  fi
  dad_wait=$((dad_wait + 1))
  sleep 1
done
[ "$dad_ready" -eq 1 ] || die "临时地址在 10 秒后仍处于 tentative 状态"
printf '%s[成功]%s 临时地址已通过 DAD\n' "$COLOR_GREEN" "$COLOR_RESET"
raw_block_start "ip -6 addr"
echo "$address_state"
raw_block_end

section "源地址路由查询"
while IFS= read -r target; do
  host=${target#\[}
  host=${host%%\]:*}
  subsection "目标 $target"
  raw_block_start "主地址与随机地址的路由选择"
  ip -6 route get "$host" from "$PRIMARY" || true
  ip -6 route get "$host" from "$TEST_ADDRESS" || true
  raw_block_end
done <"$TARGET_FILE"

section "网关连通性测试"
subsection "主地址到网关"
raw_block_start "ping -6"
ping -6 -n -I "$PRIMARY" -c 2 -W 2 "$GATEWAY" || true
raw_block_end
subsection "临时地址到网关"
raw_block_start "ping -6"
ping -6 -n -I "$TEST_ADDRESS" -c 2 -W 2 "$GATEWAY" || true
raw_block_end

section "TCP 连通性测试"
V6_COLOR_GREEN=$COLOR_GREEN V6_COLOR_RED=$COLOR_RED V6_COLOR_RESET=$COLOR_RESET \
python3 - "$PRIMARY" "$TEST_ADDRESS" "$TIMEOUT" "$TARGET_FILE" "$PROBE_FILE" <<'PY'
import ipaddress
import os
import socket
import sys
import time

primary, test_address, timeout_text, target_path, result_path = sys.argv[1:]
timeout = float(timeout_text)
green = os.environ.get("V6_COLOR_GREEN", "")
red = os.environ.get("V6_COLOR_RED", "")
reset = os.environ.get("V6_COLOR_RESET", "")
targets = []
for raw in open(target_path, encoding="utf-8"):
    host, port = raw.strip()[1:].rsplit("]:" , 1)
    targets.append((host, int(port)))

with open(result_path, "w", encoding="utf-8") as results:
    for label, source in (("primary", primary), ("native_random", test_address)):
        for host, port in targets:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            started = time.monotonic()
            ok = False
            try:
                sock.bind((source, 0, 0, 0))
                sock.connect((host, port, 0, 0))
                actual = str(ipaddress.IPv6Address(sock.getsockname()[0]))
                if actual != source:
                    raise OSError(f"源地址不一致: 请求 {source}，实际 {actual}")
                ok = True
                detail = f"本地端点={actual}:{sock.getsockname()[1]}"
            except OSError as exc:
                if isinstance(exc, socket.timeout):
                    detail = "连接超时"
                else:
                    detail = f"errno={exc.errno or 0} 错误={exc}"
            finally:
                sock.close()
            latency = int((time.monotonic() - started) * 1000)
            status = f"{green}[成功]{reset}" if ok else f"{red}[失败]{reset}"
            source_name = "主地址      " if label == "primary" else "随机原生地址"
            target = f"[{host}]:{port}"
            print(f"  {status} {source_name} 源={source} 目标={target} 延迟={latency}ms {detail}", flush=True)
            clean_detail = detail.replace("\t", " ").replace("\n", " ")
            results.write(f"{label}\t{target}\t{int(ok)}\t{latency}\t{clean_detail}\n")
PY

sleep 3
if kill -0 "$CAPTURE_PID" 2>/dev/null; then
  kill -INT "$CAPTURE_PID" 2>/dev/null || true
  wait "$CAPTURE_PID" 2>/dev/null || true
fi
CAPTURE_PID=""

if confirm_detail_output "是否输出完整 tcpdump 抓包原文？"; then
  section "抓包原始输出"
  raw_block_start "tcpdump"
  cat "$CAPTURE_FILE"
  raw_block_end
else
  muted "[跳过] 完整 tcpdump 抓包原文；下方仍会输出抓包摘要。"
fi

section "测试地址抓包摘要"
info "内部保存的原始抓包是最终判断依据；以下计数仅用于快速查看。"
capture_lines=$(grep -F -c "$TEST_ADDRESS" "$CAPTURE_FILE" || true)
neighbor_solicitations=$(grep -F "$TEST_ADDRESS" "$CAPTURE_FILE" | grep -i -c 'neighbor solicitation' || true)
neighbor_advertisements=$(grep -F "$TEST_ADDRESS" "$CAPTURE_FILE" | grep -i -c 'neighbor advertisement' || true)
tcp_syn_lines=$(grep -F "$TEST_ADDRESS" "$CAPTURE_FILE" | grep -c 'Flags \[S' || true)
key_value "相关报文  " "$capture_lines"
key_value "邻居请求  " "$neighbor_solicitations"
key_value "邻居通告  " "$neighbor_advertisements"
key_value "TCP SYN   " "$tcp_syn_lines"

section "IPv6 邻居状态"
raw_block_start "ip -6 neigh"
ip -6 neigh show proxy dev "$INTERFACE" 2>&1 || true
ip -6 neigh show dev "$INTERFACE" 2>&1 || true
raw_block_end

if ! confirm_detail_output "是否输出完整 nftables 规则集？"; then
  muted "[跳过] 完整 nftables 规则集。"
elif command -v nft >/dev/null 2>&1; then
  section "nftables 规则集"
  raw_block_start "nft -a list ruleset"
  nft -a list ruleset 2>&1 || true
  raw_block_end
else
  muted "[跳过] 未安装 nft 命令。"
fi

if ! confirm_detail_output "是否输出完整传统 ip6tables 规则？"; then
  muted "[跳过] 完整传统 ip6tables 规则。"
elif command -v ip6tables-save >/dev/null 2>&1; then
  section "传统 ip6tables 规则"
  raw_block_start "ip6tables-save"
  ip6tables-save 2>&1 || true
  raw_block_end
else
  muted "[跳过] 未安装 ip6tables-save 命令。"
fi

target_count=$(awk 'END {print NR+0}' "$TARGET_FILE")
primary_pass=$(awk -F '\t' '$1 == "primary" && $3 == 1 {n++} END {print n+0}' "$PROBE_FILE")
random_pass=$(awk -F '\t' '$1 == "native_random" && $3 == 1 {n++} END {print n+0}' "$PROBE_FILE")

section "诊断结果"
if [ "$primary_pass" -eq 0 ]; then
  printf '%s[失败]%s baseline_failed（主地址基线失败）\n' "$COLOR_RED" "$COLOR_RESET"
  info "主 IPv6 地址无法连接任何目标，应先修复目标地址或基础 IPv6 连通性。"
  RESULT_CODE=1
elif [ "$random_pass" -eq "$target_count" ]; then
  printf '%s[成功]%s native_random_reachable（随机原生地址可达）\n' "$COLOR_GREEN" "$COLOR_RESET"
  info "临时原生 /128 可以连接全部目标，应继续检查 Proxy NDP 应用路径。"
  RESULT_CODE=0
elif [ "$random_pass" -gt 0 ]; then
  printf '%s[警告]%s native_random_partially_reachable（随机原生地址部分可达）\n' "$COLOR_YELLOW" "$COLOR_RESET"
  info "临时原生 /128 仅能连接部分目标，请对比各目标的路由和抓包。"
  RESULT_CODE=1
else
  printf '%s[失败]%s native_random_unreachable（随机原生地址不可达）\n' "$COLOR_RED" "$COLOR_RESET"
  info "主 IPv6 可用，但临时原生 /128 无法连接任何目标。"
  info "请结合抓包区分本机 ICMPv6 过滤、上游源地址过滤或回程缺失。"
  RESULT_CODE=1
fi
printf '\n'
key_value "主地址通过  " "$primary_pass/$target_count"
key_value "随机地址通过" "$random_pass/$target_count"
key_value "清理状态    " "等待退出时删除临时地址"

exit "$RESULT_CODE"
