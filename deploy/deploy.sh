#!/bin/bash
# ============================================================================
# deploy/deploy.sh —— 扫描节点一条命令部署（TASK-011）
#
# 把 docs/RUNBOOK-scan-node.md 的 Stage A/B（基础环境、nftables 基线、靶场、
# B1-B5 验收）固化为一个幂等脚本：每步重复执行不报错，第二次运行 2 分钟内完成。
# 首次运行约 15 分钟（大头是 secops-scanner 镜像构建与 Juice Shop 镜像拉取）。
#
# 用法：
#   SECOPS_REPO_URL="https://<FINE-GRAINED-TOKEN>@github.com/yydskunbaagent/my-repo.git" \
#     ./deploy/deploy.sh [--ssh-port 22] [--juice-ip 10.10.0.100] [--juice-port 3000]
#                        [--skip-target] [--skip-rebuild] [--rebuild]
#
# 参数：
#   --ssh-port N     运维 SSH 端口（注入 scan-node.nft 的 define SSH_PORT；
#                    云主机映射端口场景如 53142。与实际不一致 = 自锁，见下）
#   --juice-ip IP    Juice Shop 在 scannet 内的固定 IP，须在 10.10.0.0/24 内，
#                    不得占用网络/网关/受控解析器预留位（.0/.1/.53/.255）
#   --juice-port N   靶场服务端口（nft 授权与 B2 扫描都用它；即容器内监听端口）
#   --skip-target    跳过靶场拉起与授权喂入（靶场由外部管理；B2 记 SKIP）
#   --skip-rebuild   跳过镜像构建（镜像缺失则报错退出，不静默继续）
#   --rebuild        强制重建 secops-scanner 镜像（忽略已存在）
#
# 环境变量：
#   SECOPS_REPO_URL  带只读 token 的仓库地址（首次部署必需；已有仓库时缺省
#                    用 git pull，token 从 origin URL 继承）
#
# 事故教训（2026-11-14 实测，RUNBOOK §3）：
#   ① 加载 nft 前必须放行 SSH（define SSH_PORT 注入实际端口），否则新 SSH 会话
#      全部被丢 = 自锁。本脚本 sed 注入后 grep 复核，不一致即拒绝加载（fail closed）。
#   ② Docker Hub 国内不可达：mirror 阶段写 /etc/docker/daemon.json registry-mirrors。
#   ③ 构建镜像用 --network host。
#
# 红线：只在一次性云机上运行（RUNBOOK §7 用完销毁）；本机不存任何模型凭据（B5 把关）。
# ============================================================================

set -Eeuo pipefail
cd /

# ---- 常量 ----
REPO_DIR=/opt/secops/my-repo
NFT_DST=/etc/nftables/scan-node.nft
DAEMON_JSON=/etc/docker/daemon.json

# B3 的 DNS 探针：容器内 python3 标准库直发 UDP 查询到 8.8.8.8（镜像内无
# nslookup，语义等价 RUNBOOK 的 `nslookup baidu.com 8.8.8.8`）。
# 预期：53 出站只放行受控解析器 10.10.0.53，到 8.8.8.8 的包被丢弃 → 超时。
B3_PY='import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(5)
q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
try:
    s.sendto(q, ("8.8.8.8", 53))
    s.recv(512)
    print("DNS-REPLY")
except socket.timeout:
    print("DNS-BLOCKED")'

# ---- 阶段追踪与失败报告 ----
STAGE="init"
die() { echo "FAIL: 阶段 [$STAGE] $*" >&2; exit 1; }
stage() { STAGE="$1"; echo; echo "== Stage: $1 =="; }
trap 'rc=$?; echo "FAIL: 阶段 [$STAGE] 执行失败（deploy.sh:$LINENO，退出码 $rc）" >&2' ERR

# ---- 参数 ----
SSH_PORT=22
JUICE_IP=10.10.0.100
JUICE_PORT=3000
SKIP_TARGET=0
SKIP_REBUILD=0
REBUILD=0

usage() {
    cat <<'USAGE'
用法: deploy/deploy.sh [--ssh-port 22] [--juice-ip 10.10.0.100] [--juice-port 3000]
                        [--skip-target] [--skip-rebuild] [--rebuild]

环境变量:
  SECOPS_REPO_URL   带只读 token 的仓库地址（首次部署必需）
USAGE
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --ssh-port)
            if [ "$#" -lt 2 ]; then echo "错误: --ssh-port 需要一个值" >&2; usage; exit 2; fi
            SSH_PORT="$2"; shift 2 ;;
        --juice-ip)
            if [ "$#" -lt 2 ]; then echo "错误: --juice-ip 需要一个值" >&2; usage; exit 2; fi
            JUICE_IP="$2"; shift 2 ;;
        --juice-port)
            if [ "$#" -lt 2 ]; then echo "错误: --juice-port 需要一个值" >&2; usage; exit 2; fi
            JUICE_PORT="$2"; shift 2 ;;
        --skip-target)  SKIP_TARGET=1;  shift ;;
        --skip-rebuild) SKIP_REBUILD=1; shift ;;
        --rebuild)      REBUILD=1;      shift ;;
        -h|--help)      usage; exit 0 ;;
        *) echo "错误: 未知参数 $1" >&2; usage; exit 2 ;;
    esac
done

is_port() {
    case "$1" in ''|*[!0-9]*) return 1 ;; esac
    [ "$1" -ge 1 ] && [ "$1" -le 65535 ]
}
if ! is_port "$SSH_PORT"; then echo "错误: --ssh-port 必须是 1-65535 的整数" >&2; usage; exit 2; fi
if ! is_port "$JUICE_PORT"; then echo "错误: --juice-port 必须是 1-65535 的整数" >&2; usage; exit 2; fi
SSH_PORT=$((10#$SSH_PORT))    # 去前导零，避免 nft 对 "022" 的解析歧义
JUICE_PORT=$((10#$JUICE_PORT))
# 正则同时排除前导零（docker/Go 的 IP 解析拒绝 "007" 形态，提前拦下）
if ! printf '%s' "$JUICE_IP" | grep -qE '^10\.10\.0\.(0|[1-9][0-9]{0,2})$'; then
    echo "错误: --juice-ip 必须在 scannet 网段 10.10.0.0/24 内（如 10.10.0.100）" >&2; usage; exit 2
fi
case "$JUICE_IP" in
    10.10.0.0|10.10.0.1|10.10.0.53|10.10.0.255)
        echo "错误: --juice-ip 不得占用网络/网关/受控解析器预留位（.0/.1/.53/.255）" >&2; usage; exit 2 ;;
esac
# 10# 强制十进制：裸 [ -gt 255] 会把前导零当八进制（"010" 被当成 8）
if [ "$((10#${JUICE_IP##*.}))" -gt 255 ]; then
    echo "错误: --juice-ip 最后一段越界" >&2; usage; exit 2
fi
[ "$(id -u)" -eq 0 ] || { echo "错误: 请以 root 运行（apt/nft/写入 /etc 均需 root）" >&2; exit 2; }

echo "=== 扫描节点部署（TASK-011）=== $(date '+%F %T')"
echo "参数: ssh-port=$SSH_PORT juice-ip=$JUICE_IP juice-port=$JUICE_PORT skip-target=$SKIP_TARGET skip-rebuild=$SKIP_REBUILD rebuild=$REBUILD"

# ============================================================================
stage preflight
# 基础环境（RUNBOOK §1）：apt/docker/nft 可用性，缺什么装什么；br_netfilter 开启
if ! command -v apt-get >/dev/null 2>&1; then
    die "preflight: 未找到 apt-get，本脚本只支持 Debian/Ubuntu（RUNBOOK §1）"
fi
missing_pkgs=0
for bin in docker nft git curl python3; do
    command -v "$bin" >/dev/null 2>&1 || missing_pkgs=1
done
if [ "$missing_pkgs" -eq 1 ]; then
    echo "缺基础包，apt 安装 docker.io nftables git curl python3 ..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y docker.io nftables git curl python3 ca-certificates
fi
systemctl enable --now docker >/dev/null 2>&1 || die "preflight: docker 服务启用失败"
if ! systemctl is-active --quiet docker; then
    systemctl start docker
fi
systemctl is-active --quiet docker || die "preflight: docker 未运行"
# br_netfilter 是 forward 链管住桥内流量的前提（RUNBOOK §1）
modprobe br_netfilter || die "preflight: modprobe br_netfilter 失败（内核不支持，forward 链管不住桥内流量）"
sysctl -w net.bridge.bridge-nf-call-iptables=1 >/dev/null
nf_call="$(sysctl -n net.bridge.bridge-nf-call-iptables 2>/dev/null || true)"
[ "$nf_call" = "1" ] || die "preflight: net.bridge.bridge-nf-call-iptables != 1，forward 链管不住桥内流量"
mkdir -p /etc/modules-load.d
printf 'br_netfilter\n' > /etc/modules-load.d/hermes.conf
printf 'net.bridge.bridge-nf-call-iptables=1\n' > /etc/sysctl.d/90-hermes.conf
echo "preflight 完成：docker/nftables 就绪，br_netfilter 已开启并持久化"

# ============================================================================
stage mirror
# Docker Hub 国内不可达（教训②）：daemon.json 无 registry-mirrors 则写入四个镜像源
if [ -f "$DAEMON_JSON" ] && grep -q 'registry-mirrors' "$DAEMON_JSON"; then
    echo "daemon.json 已含 registry-mirrors，跳过"
else
    if [ -f "$DAEMON_JSON" ]; then
        cp -a "$DAEMON_JSON" "${DAEMON_JSON}.bak.$(date +%Y%m%d%H%M%S)"
    fi
    mkdir -p /etc/docker
    python3 - "$DAEMON_JSON" <<'PY'
import json, sys

path = sys.argv[1]
try:
    with open(path) as f:
        cfg = json.load(f)
except FileNotFoundError:
    cfg = {}
except ValueError:
    sys.exit("FAIL: " + path + " 不是合法 JSON，请人工修复后重跑（fail closed，不覆盖）")
cfg["registry-mirrors"] = [
    "https://docker.1ms.run",
    "https://docker.m.daocloud.io",
    "https://dockerproxy.net",
    "https://docker.xuanyuan.me",
]
with open(path, "w") as f:
    json.dump(cfg, f, indent=2, ensure_ascii=False)
    f.write("\n")
PY
    systemctl restart docker
    echo "已写入 4 个 registry mirror 并重启 docker"
fi

# ============================================================================
stage repo
# 拉代码（RUNBOOK §2）：SECOPS_REPO_URL 克隆 / 既有仓 git pull；>120s 降级 tarball
mkdir -p /opt/secops
REPO_URL="${SECOPS_REPO_URL:-}"
if [ -z "$REPO_URL" ] && [ -d "$REPO_DIR/.git" ]; then
    REPO_URL="$(git -C "$REPO_DIR" remote get-url origin 2>/dev/null || true)"
fi
# 解析 owner/repo 与 token，供 tarball 降级（codeload.github.com）使用
GIT_TOKEN=""
OWNER_REPO=""
if [ -n "$REPO_URL" ]; then
    maybe_token="${REPO_URL%%@github.com*}"
    if [ "$maybe_token" != "$REPO_URL" ]; then
        GIT_TOKEN="${maybe_token#*://}"
    fi
    OWNER_REPO="${REPO_URL#*github.com/}"
    OWNER_REPO="${OWNER_REPO%.git}"
fi

tarball_fetch() {
    # 走 codeload.github.com 拉 tar.gz（git 超时/失败的降级路径）；$1 = 目标目录
    local dest="$1" branch tmp top
    for branch in main master; do
        tmp="$(mktemp -d /tmp/secops-repo.XXXXXX)"
        local -a curl_args=(-fsSL --max-time 120 -o "$tmp/repo.tar.gz"
                            "https://codeload.github.com/${OWNER_REPO}/tar.gz/refs/heads/${branch}")
        if [ -n "$GIT_TOKEN" ]; then
            curl_args=(-H "Authorization: Bearer $GIT_TOKEN" "${curl_args[@]}")
        fi
        if curl "${curl_args[@]}" && tar -xzf "$tmp/repo.tar.gz" -C "$tmp"; then
            top="$(find "$tmp" -mindepth 1 -maxdepth 1 -type d -print -quit)"
            if [ -n "$top" ]; then
                # dest 就是本脚本所在的仓库目录；bash 对已打开脚本持有 fd，
                # unlink 不影响继续执行（新目录由 tarball 原位顶上）
                rm -rf "$dest"
                mkdir -p "$(dirname "$dest")"
                mv "$top" "$dest"
                rm -rf "$tmp"
                echo "tarball 降级成功（branch=$branch）"
                return 0
            fi
        fi
        rm -rf "$tmp"
    done
    return 1
}

if [ -d "$REPO_DIR/.git" ]; then
    echo "更新既有仓库（git pull --ff-only，120s 超时）"
    if timeout 120 git -C "$REPO_DIR" pull --ff-only; then
        echo "git pull 完成"
    elif [ -n "$OWNER_REPO" ]; then
        echo "git pull 失败或超时（>120s），降级 tarball（codeload.github.com）"
        tarball_fetch "$REPO_DIR" || die "repo: tarball 降级也失败，检查 SECOPS_REPO_URL 与网络"
    else
        die "repo: git pull 失败且无法降级（无 SECOPS_REPO_URL）"
    fi
elif [ -d "$REPO_DIR" ]; then
    echo "目录存在但非 git 仓（历史 tarball 降级产物），继续走 tarball 更新"
    if [ -z "$OWNER_REPO" ]; then die "repo: 需要 SECOPS_REPO_URL 才能更新"; fi
    tarball_fetch "$REPO_DIR" || die "repo: tarball 更新失败"
elif [ -n "$REPO_URL" ]; then
    echo "首次克隆（--depth 1，120s 超时）"
    if timeout 120 git clone --depth 1 "$REPO_URL" "$REPO_DIR"; then
        echo "git clone 完成"
    elif [ -n "$OWNER_REPO" ]; then
        echo "git clone 失败或超时，降级 tarball"
        tarball_fetch "$REPO_DIR" || die "repo: tarball 降级也失败"
    else
        die "repo: clone 失败且无法降级（URL 非 github 形态）"
    fi
else
    die "repo: 首次部署必须提供 SECOPS_REPO_URL（带 token 的只读地址，见 RUNBOOK §2）"
fi
[ -f "$REPO_DIR/deploy/nftables/scan-node.nft" ] || die "repo: 缺 deploy/nftables/scan-node.nft"
[ -f "$REPO_DIR/Dockerfile.scanner" ] || die "repo: 缺 Dockerfile.scanner"
echo "代码就绪: $REPO_DIR"

# ============================================================================
stage nft
# nftables 基线（RUNBOOK §3 + 教训①）：注入 SSH 端口 → grep 复核 → 语法预检 → 加载
NFT_SRC="$REPO_DIR/deploy/nftables/scan-node.nft"
install -m 0644 "$NFT_SRC" "$NFT_DST"
sed -i "s/^define SSH_PORT = 22$/define SSH_PORT = ${SSH_PORT}/" "$NFT_DST"
# fail-closed 复核：替换不成功 = 拒绝加载（自锁只能靠云控制台/VNC 抢救）
ssh_pattern='^define SSH_PORT = '"${SSH_PORT}"'$'
if ! grep -Eq "$ssh_pattern" "$NFT_DST"; then
    die "nft: SSH_PORT 注入复核失败（模板行 'define SSH_PORT = 22' 未被替换）——拒绝加载，避免自锁"
fi
nft -c -f "$NFT_DST"          # 语法预检（不生效）
nft -f "$NFT_DST"
nft list table inet hermes_scan >/dev/null 2>&1 || die "nft: 加载后未找到 hermes_scan 表"
echo "hermes_scan 已加载（SSH 放行端口: ${SSH_PORT}）"
# flush ruleset 连带清掉 Docker 注入的规则（scan-node.nft 头注）——docker 在跑就重启重建，
# 否则桥内流量会被 iptables FORWARD 默认策略拦死（B2 直接受害）
if systemctl is-active --quiet docker; then
    echo "重启 docker 以重建被 flush 清掉的容器网络规则"
    systemctl restart docker
    systemctl is-active --quiet docker || die "nft: docker 重启后未运行"
fi

# ============================================================================
stage net
if docker network inspect scannet >/dev/null 2>&1; then
    echo "scannet 已存在，跳过"
else
    docker network create scannet --subnet 10.10.0.0/24 --gateway 10.10.0.1
fi

# ============================================================================
stage image
BUILD_CMD=(docker build --network host -t secops-scanner -f "$REPO_DIR/Dockerfile.scanner" "$REPO_DIR")
if [ "$REBUILD" -eq 1 ]; then
    echo "强制重建 secops-scanner（--network host，教训③）"
    "${BUILD_CMD[@]}"
elif docker image inspect secops-scanner >/dev/null 2>&1; then
    echo "镜像 secops-scanner 已存在，跳过（--rebuild 可强制重建）"
elif [ "$SKIP_REBUILD" -eq 1 ]; then
    die "image: --skip-rebuild 但镜像不存在，verify 无法进行"
else
    echo "构建 secops-scanner（--network host，首次约 10 分钟）"
    "${BUILD_CMD[@]}"
fi

# ============================================================================
stage target
# 靶场（RUNBOOK §4，按 TASK-011 改为固定 scannet IP）：不 -p 映射，不对公网暴露
juice_recreate() {
    docker rm -f juice-shop >/dev/null 2>&1 || true
    if ! docker image inspect bkimminich/juice-shop >/dev/null 2>&1; then
        docker pull bkimminich/juice-shop
    fi
    docker run -d --name juice-shop --restart unless-stopped \
        --network scannet --ip "$JUICE_IP" bkimminich/juice-shop
}
if [ "$SKIP_TARGET" -eq 1 ]; then
    echo "--skip-target：跳过靶场拉起与授权喂入（B2 将记 SKIP）"
else
    state="$(docker inspect -f '{{.State.Running}}' juice-shop 2>/dev/null || true)"
    cur_ip="$(docker inspect -f '{{.NetworkSettings.Networks.scannet.IPAMConfig.IPv4Address}}' juice-shop 2>/dev/null || true)"
    if [ "$state" = "true" ] && [ "$cur_ip" = "$JUICE_IP" ]; then
        echo "juice-shop 运行中（${JUICE_IP}:${JUICE_PORT}），跳过"
    elif [ "$state" = "true" ] || [ "$state" = "false" ]; then
        echo "juice-shop 已存在但状态/IP 与参数不符（running=$state ip=$cur_ip），重建"
        juice_recreate
    else
        echo "拉起 Juice Shop（镜像经 mirror 拉取，首次约几分钟）"
        juice_recreate
    fi
    # 就绪探活（容器内部端口；未就绪不中止——B2 会给出真实结论）
    ready=0
    for _ in $(seq 1 45); do
        if docker exec juice-shop wget -q -T 2 -O /dev/null "http://127.0.0.1:${JUICE_PORT}/" >/dev/null 2>&1; then
            ready=1
            break
        fi
        sleep 2
    done
    if [ "$ready" -eq 1 ]; then
        echo "juice-shop 已就绪"
    else
        echo "警告: juice-shop 90s 内未就绪（B2 可能 FAIL，可 docker logs juice-shop 排查）"
    fi
    # nft 授权喂入（幂等）：先 add，失败时用 get element 复核是"条目已存在"还是真错误
    if ! nft add element inet hermes_scan allow_ranges4 "{ ${JUICE_IP} }" 2>/dev/null; then
        nft get element inet hermes_scan allow_ranges4 "{ ${JUICE_IP} }" >/dev/null 2>&1 \
            || die "target: allow_ranges4 写入失败: ${JUICE_IP}"
    fi
    if ! nft add element inet hermes_scan allow_ports "{ ${JUICE_PORT} }" 2>/dev/null; then
        nft get element inet hermes_scan allow_ports "{ ${JUICE_PORT} }" >/dev/null 2>&1 \
            || die "target: allow_ports 写入失败: ${JUICE_PORT}"
    fi
    echo "nft 授权已喂入: allow_ranges4 += ${JUICE_IP}，allow_ports += ${JUICE_PORT}"
fi

# ============================================================================
stage verify
# B1-B5 冒烟（RUNBOOK §5）：每条打印 PASS/FAIL，存在 FAIL 即退出码非 0
PASS_N=0
FAIL_N=0
SKIP_N=0
b_report() {
    case "$2" in
        pass) echo "PASS  $1  $3"; PASS_N=$((PASS_N + 1)) ;;
        fail) echo "FAIL  $1  $3"; FAIL_N=$((FAIL_N + 1)) ;;
        skip) echo "SKIP  $1  $3"; SKIP_N=$((SKIP_N + 1)) ;;
        *)    die "b_report 用法错误" ;;
    esac
}

# alpine 预拉取（B1 的载体；拉取失败在此显式暴露，不污染 B1 结论）
if ! docker image inspect alpine >/dev/null 2>&1; then
    docker pull alpine
fi

# B1：无网络容器的 curl 必须失败（RUNBOOK B1）
b1_rc=0
if docker run --rm --network none alpine curl -sm3 https://example.com >/dev/null 2>&1; then
    :
else
    b1_rc=$?
fi
if [ "$b1_rc" -eq 0 ]; then
    b_report "B1" "fail" "无网络容器 curl 意外成功（隔离失效！检查安全组/Docker）"
else
    b_report "B1" "pass" "无网络容器 curl 失败（rc=$b1_rc，预期）"
fi

# B2：扫描容器对靶场 SYN 扫描必须 open（经 forward 链授权放行）
# -Pn 是刻意的：ICMP 被 hermes_scan 默认拒绝策略丢弃，默认 ping 预扫会误判 host down
if [ "$SKIP_TARGET" -eq 1 ]; then
    b_report "B2" "skip" "--skip-target（未喂授权，无法验证）"
else
    b2_out="$(docker run --rm --network scannet --cap-add NET_RAW secops-scanner \
                nmap -sS -Pn -p "${JUICE_PORT}" "${JUICE_IP}" 2>/dev/null || true)"
    if printf '%s' "$b2_out" | grep -Eq "${JUICE_PORT}/tcp[[:space:]]+open"; then
        b_report "B2" "pass" "SYN 扫描 ${JUICE_IP}:${JUICE_PORT} open（allow_ranges4 × allow_ports 放行）"
    else
        b_report "B2" "fail" "未看到 open（nmap: $(printf '%s' "$b2_out" | grep -E 'Host|/tcp' | head -3 | tr '\n' ' ')）"
    fi
fi

# B3：容器直连 8.8.8.8:53 必须超时（53 只许到受控解析器）
b3_out="$(docker run --rm --network scannet secops-scanner python3 -c "$B3_PY" 2>&1 || true)"
if printf '%s' "$b3_out" | grep -q 'DNS-BLOCKED'; then
    b_report "B3" "pass" "直连 8.8.8.8:53 超时（UDP 53 仅放行 10.10.0.53）"
else
    b_report "B3" "fail" "直连 8.8.8.8:53 未按预期丢弃: $(printf '%s' "$b3_out" | head -2 | tr '\n' ' ')"
fi

# B4：越界 IP 必须内核层丢包（curl 超时 rc=28，http_code=000；拒绝而非丢弃会 rc=7）
b4_rc=0
if b4_out="$(docker run --rm --network scannet secops-scanner \
                curl -sm8 -o /dev/null -w '%{http_code}' http://1.1.1.1/ 2>/dev/null)"; then
    :
else
    b4_rc=$?
fi
if [ "$b4_out" = "000" ] && [ "$b4_rc" -eq 28 ]; then
    b_report "B4" "pass" "越界 IP 1.1.1.1 超时（forward 链默认拒绝，http_code=000 rc=28）"
else
    b_report "B4" "fail" "越界 IP 行为异常（http_code=$b4_out rc=$b4_rc，预期 000/28）"
fi

# B5：容器 env 与 /opt/secops 无模型凭据（RUNBOOK B5）
# 高置信度模式：sk-/ghp_ 前缀后 >=20 位（真实 key 48/36 位；仓库 fixture 仅 16 位不误伤）
b5_bad=0
env_pat='api[_-]?key|secret|token|password|sk-[A-Za-z0-9_-]{20,}'
scan_env="$(docker run --rm --network scannet secops-scanner env 2>/dev/null || true)"
juice_env=""
if [ "$SKIP_TARGET" -ne 1 ] \
    && [ "$(docker inspect -f '{{.State.Running}}' juice-shop 2>/dev/null || true)" = "true" ]; then
    juice_env="$(docker exec juice-shop env 2>/dev/null || true)"
fi
if [ -z "$scan_env" ]; then
    b_report "B5" "fail" "scanner 容器 env 读取失败"
    b5_bad=1
elif printf '%s\n%s' "$scan_env" "$juice_env" | grep -iqE "$env_pat"; then
    b_report "B5" "fail" "容器 env 命中凭据模式: $(printf '%s\n%s' "$scan_env" "$juice_env" \
        | grep -iE "$env_pat" | head -3 | tr '\n' ' ')"
    b5_bad=1
fi
host_hits="$(grep -rElI 'sk-[A-Za-z0-9_-]{20,}|ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16,}|[0-9a-f]{32}\.[A-Za-z0-9]{16}' \
    /opt/secops 2>/dev/null || true)"
if [ -n "$host_hits" ]; then
    b_report "B5" "fail" "/opt/secops 命中凭据模式: $(printf '%s' "$host_hits" | head -3 | tr '\n' ' ')"
    b5_bad=1
fi
if [ "$b5_bad" -eq 0 ] && [ -n "$scan_env" ]; then
    b_report "B5" "pass" "容器 env 与 /opt/secops 无凭据模式命中"
fi

# ---- 汇总 ----
echo
echo "== verify 结果: PASS=${PASS_N} FAIL=${FAIL_N} SKIP=${SKIP_N} =="
if [ "$FAIL_N" -gt 0 ]; then
    die "存在 FAIL 项，部署未达验收（逐条见上）"
fi
echo
echo "部署完成（幂等，可重复执行）。后续:"
echo "  - 端到端首扫与报告: docs/RUNBOOK-scan-node.md §6"
echo "  - 收尾（不可跳过）: docker rm -f juice-shop; nft flush ruleset; 云控制台销毁实例（§7）"
