# RUNBOOK：扫描节点部署（P0-B）

> 目标：在一台一次性 Linux 云主机上完成 deploy/ 套件部署 + B1–B5 验收 + 首次端到端扫描。
> 预计耗时：25–40 分钟。机器规格：2C4G，Ubuntu 22.04/24.04 或 Debian 12，按量付费，**用完销毁**。
> 红线：绝不复用 47.74.33.82 及任何承载业务的机器；本机不存任何模型凭据。

## 0. 开机准备（云控制台）

- 安全组入方向：只留你的 SSH 端口（来源限你的 IP）
- 出方向：**先全开**（B 阶段要验证 nftables 的默认拒绝，安全组别抢戏）
- 记录：公网 IP、SSH 私钥路径

## 1. 基础环境（约 5 分钟）

```bash
apt update && apt install -y nftables docker.io python3-yaml git curl
systemctl enable --now docker nftables
# br_netfilter 是 forward 链管住容器流量的前提
modprobe br_netfilter
sysctl -w net.bridge.bridge-nf-call-iptables=1
echo -e "br_netfilter\nnet.bridge.bridge-nf-call-iptables=1" >> /etc/modules-load.d/hermes.conf
echo "net.bridge.bridge-nf-call-iptables=1" > /etc/sysctl.d/90-hermes.conf
```

## 2. 拉代码（私有仓，只读）

```bash
mkdir -p /opt/secops && cd /opt/secops
git clone --depth 1 https://<FINE-GRAINED-TOKEN>@github.com/yydskunbaagent/my-repo.git
```

## 3. nftables 基线（B4 的关键）

```bash
nft -f /opt/secops/my-repo/deploy/nftables/scan-node.nft
nft list ruleset | head -40   # 确认 hermes_scan 表已加载
```

注意：该文件首行 `flush ruleset` 会清掉 Docker 注入的表——**先加载 nft 再起 Docker**；
若顺序反了，`systemctl restart docker` 让 Docker 重建自身规则。

## 4. 靶场（Juice Shop，故意带漏洞的官方练习靶场）

```bash
docker run -d --name juice-shop --restart unless-stopped -p 127.0.0.1:3000:3000 \
  bkimminich/juice-shop
# 只绑 127.0.0.1：靶场不对公网暴露，扫描流量从扫描容器内部发起
```

同时把宿主机 IP（内网 IP）与 3000 端口记入一份**新的 scope.yaml**（engagement 靶场版：
target=该内网 IP:3000，authorized_by=你自己，动作限 recon/vuln_scan，禁 exploit 除 PoC 验证）。

## 5. B1–B5 验收（逐条执行，任何一条不过就停）

| # | 命令 | 预期 |
|---|---|---|
| B1 | `docker run --rm --network none alpine curl -sm3 https://example.com` | 失败（无网络） |
| B2 | 扫描容器对靶场 IP 发 `nmap -sS -p3000 <IP>` | 通（SYN 扫描正常） |
| B3 | 容器内 `nslookup baidu.com 8.8.8.8` | 被丢（53 只许到受控解析器） |
| B4 | 容器内 curl 任一未授权 IP | 内核层丢包（超时，非应用报错） |
| B5 | `grep -r sk- /opt/secops --include=* -l` 与容器内 `env` | 零模型凭据 |

## 6. 端到端首扫（跑通即 MVP）

1. Windows 推理端（现有 Hermes 环境）：`scope.yaml` 换成靶场版 engagement
2. 派扫描任务（终端工具走 SSH 后端或任务 JSON 投递到扫描机）
3. 扫描机执行 nmap/nuclei，原始输出落 `/opt/secops/findings/`
4. 汇总成 findings JSON → `python -m secops_report findings.json --meta meta.json --out-prefix reports/ENG-xxx`
5. 检查报告：confirmed/observed 分档、Rejected 附录、**脱敏生效**

## 7. 收尾（不可跳过）

```bash
docker rm -f juice-shop; nft flush ruleset
# 云控制台：销毁实例；快照/备份一律不留
# 私钥如曾放机器上：视为泄露，立即换 Fine-grained token
```

## 故障速查

- 扫描容器不通目标：先 `nft list ruleset` 确认表在，再查 `br_netfilter` 是否生效
  （`sysctl net.bridge.bridge-nf-call-iptables` 必须 =1），最后看安全组
- unbound 起不来：检查 10.10.0.53 是否为本机/桥内地址（compose 的 ipam 网段对齐）
- B1 误通过：安全组可能只做了出方向限制——B1 必须以"容器视角"验证，不是宿主机
