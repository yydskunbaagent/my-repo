# TASK-006：外部评审修复（compose 网络语义 / 动态端口 / 报告脱敏）

## 背景

外部评审确认 3 个成立问题。前两个是 deploy 拓扑的部署级 bug（不修部署跑不通），
第三个是报告二次泄露风险。**只改 deploy/ 与 secops_report/，不碰 plugins/。**

## 任务 1：compose 网络语义修复（deploy/docker-compose.scan.yml + deploy/nftables/scan-node.nft）

问题：`reasoning` 用 `network_mode: none` 连模型 API 都出不去；`scannet` 用
`internal: true` 会让 Docker 在自身隔离链上丢弃出站流量，nftables forward 链
收不到包，扫描根本发不出去。

修复要求：

- `scannet` 改为 `internal: false`（普通 bridge + 固定 10.10.0.0/24 ipam），
  **宿主机 nftables forward 链成为唯一出网门禁**（default-deny 语义不变）。
  在注释中写明依赖：`br_netfilter`（bridge-nf-call-iptables=1）必须开启，
  否则容器间/出网流量不经过 forward 链
- `reasoning` 不再用 `network_mode: none`：改为接入专用受限网络
  `reasoning-egress`（internal: true），并通过一个轻量 `egress-proxy` 服务
  （如 tinyproxy/squid 占位 + 注释说明）只转发到模型 API 端点
  （示例域名 `open.bigmodel.cn:443`，写注释：部署时按实际 provider 填）。
  reasoning 的出网全部走该代理（`HTTPS_PROXY` 环境变量示例）
- 三服务拓扑注释同步更新：reasoning 只能到模型 API（经代理）、scanner 只能到
  授权目标 + 受控解析器（经 nftables）、proxy 只能到模型 API
- `deploy/nftables/scan-node.nft` 的头部注释与部署决策点段落同步改写
  （internal:true 的旧描述作废；补一条：egress-proxy 到模型 API 的放行
  由宿主机 output 链或另一张表管理，本文件仍只管 forward 面）

## 任务 2：授权端口动态集合（deploy/nftables/scan-node.nft + deploy/dns/scope_feed.py）

问题：扫描端口写死 `{ 80, 443 }`，scope 里授权的 8080/8443 会被静默拦。

修复要求：

- nft 文件新增命名 set `allow_ports`（`type inet_service`，无 interval）
- forward 链四条放行规则改为：`ip daddr @allow_domains4 tcp dport @allow_ports accept`
  （domains6/ranges4/ranges6 同理）
- `scope_feed.py` 新增 `--feed-ports`：从 scope.yaml 收集所有目标的 `ports`
  并集，生成 `nft add element inet hermes_scan allow_ports { 80, 443 }`；
  `--dry-run` 下照常只打印。未带该参数时不喂端口（保持向后兼容）
- 更新 TASK-002 交付时写的相关注释

## 任务 3：报告凭证脱敏（secops_report/）

问题：Evidence 的响应片段可能含 Authorization/Cookie/Token，渲染进报告 =
二次泄露。

修复要求：

- 新增 `secops_report/masking.py`：`mask_text(text: str) -> str`，纯标准库
  正则，对以下模式做掩码（保留前 4 后 2 字符，中间 `***`，长度≤8 全掩码）：
  - Header 形态：`Authorization: Bearer xxx` / `Cookie: xxx` /
    `Set-Cookie: xxx` / `X-Api-Key: xxx`（name 不分大小写）
  - Token 形态：`sk-[A-Za-z0-9_-]{8,}`、`ghp_[A-Za-z0-9]{8,}`、
    `em-sk-[A-Za-z0-9_-]{8,}`、`Bearer\s+[A-Za-z0-9._-]{8,}`、
    `eyJ` 开头的 JWT（三段式 `eyJ...\.eyJ...\...`）
  - URL 查询串：`[?&](token|key|secret|password|api_key)=...`
- `render.py` 的 `render_markdown` 与 `render_sarif` 在输出前对每个 evidence
  的 summary 与 artifact 内联文本统一过 `mask_text`；SARIF 里同样处理
- 新增 `tests/test_masking.py`：
  1. `Authorization: Bearer sk-abcdef1234567890` → token 被掩码
  2. `Cookie: session=abcdefghijklmnop` → 掩码
  3. JWT（`eyJhbGciOi....eyJ...`）→ 掩码
  4. `https://x.com/a?token=secretvalue123` → 查询串掩码
  5. 普通 HTML/文本不含上述模式 → 原样通过（不误伤）
  6. render_markdown 集成：evidence 含敏感 header → 输出无原文

## 约束

- 不碰 plugins/、tests/test_engine.py、test_target.py、test_cli.py 现有用例
- scope_feed.py 只加 `--feed-ports`，不改既有参数语义；`make test` 全绿
- 全部 LF；注释风格对齐现有文件

## 验收（调用方执行）

```bash
python -m pytest tests/ -q     # 95 + 新增全过
python deploy/dns/scope_feed.py --scope engagement-demo/scope.yaml --feed-ports --dry-run
                               # 输出含 allow_ports 集合命令
```
外加我对 compose/nft 语义与 masking 正则的人工审查。
