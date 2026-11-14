# TASK-011：部署脚本化（deploy/deploy.sh 一条命令拉起扫描节点）

## 上下文预置（先读这些）

- `deploy/nftables/scan-node.nft`：规则集（含 `define SSH_PORT`，部署要注入实际端口）
- `deploy/docker-compose.scan.yml`：拓扑声明（P0-B 用的是手工 docker 命令版，本脚本对应它）
- `Dockerfile.scanner`（仓库根）：扫描镜像定义
- `docs/RUNBOOK-scan-node.md`：今天手工执行的完整流程（Stage A/B + B1-B5）
- 实测事故教训：① 加载 nft 前必须放行 SSH（define SSH_PORT），否则自锁；
  ② Docker Hub 国内不可达，要配 daemon.json mirror；③ 构建镜像用 --network host

## 任务：新建 `deploy/deploy.sh`

Bash 脚本（Windows 上无法执行，我在云机验证），用 `#!/bin/bash` + `set -euo pipefail`。
它把 RUNBOOK 的 Stage A/B 变成一条命令：

```bash
./deploy.sh [--ssh-port 22] [--juice-ip 10.10.0.100] [--juice-port 3000] [--skip-target]
```

行为分解（每步幂等——重复执行不报错）：

1. `preflight`：检查 apt/docker/nft 可用性，缺什么装什么（`apt-get install -y docker.io nftables`）；校验内核能加载 br_netfilter（`modprobe br_netfilter`）
2. `mirror`：若 `/etc/docker/daemon.json` 无 registry-mirrors → 写入四个 mirror（docker.1ms.run / docker.m.daocloud.io / dockerproxy.net / docker.xuanyuan.me）并 `systemctl restart docker`；已有则跳过
3. `repo`：从环境变量 `SECOPS_REPO_URL`（带 token）或 `git pull` 更新 `/opt/secops/my-repo`；git fetch 超过 120s 自动降级为 tarball（codeload.github.com）
4. `nft`：把 scan-node.nft 复制到 /etc/nftables/，**sed 把 `define SSH_PORT = 22` 替换为 `--ssh-port` 参数值**，然后 `nft -f` 加载；加载前必须确认 SSH_PORT 已被正确替换（grep 验证），不一致则拒绝执行（fail-closed：不自锁）
5. `net`：`docker network create scannet --subnet 10.10.0.0/24 --gateway 10.10.0.1`（已存在则跳过）
6. `image`：`docker build --network host -t secops-scanner -f Dockerfile.scanner .`（镜像已存在且 --skip-rebuild 时跳过；`--rebuild` 强制重建）
7. `target`（默认开，--skip-target 跳过）：拉起 Juice Shop 固定 `--juice-ip`，并用 nft 喂授权：
   `nft add element inet hermes_scan allow_ranges4 { $JUICE_IP }`
   `nft add element inet hermes_scan allow_ports { $JUICE_PORT }`
8. `verify`：B1-B5 冒烟（每条打印 PASS/FAIL，全部 PASS 才退出码 0）：
   - B1：`docker run --rm --network none` 的 curl 必须失败
   - B2：扫描容器 nmap SYN 扫描靶场必须 open
   - B3：容器 DNS 到 8.8.8.8 必须超时
   - B4：越界 IP curl 必须超时（000）
   - B5：容器 env 无 key/token/secret
9. 每个阶段用 `== Stage: xxx ==` 打印分隔，失败处明确打印是哪个阶段挂了

文件顶部注释写清：此脚本把全手动流程固化；首次运行约 15 分钟（镜像构建）。
不要求 shellcheck 零警告，但关键命令要有错误处理。

## 约束

- 不碰 plugins/、secops_report/、tests/、docs/RUNBOOK-scan-node.md 的内容（可以加一行引用 deploy.sh）
- 这是运维脚本不是产品代码，shellcheck 级别的严格度即可
- LF 行尾

## 验收（调用方执行）

在云机上 `./deploy/deploy.sh` 全程跑通、B1-B5 全部 PASS、重复执行幂等（第二次跑 2 分钟内完成）。
