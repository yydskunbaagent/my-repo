# TASK-009：子域发现喂入管道（并行批次 B，只动 deploy/dns/scope_feed.py 与 docs/）

## 上下文预置（先读这些，别的不用看）

- `deploy/dns/scope_feed.py`：现有喂集脚本。关键函数与参数：
  - `--feed-ports`：scope 全目标 ports 并集 → `allow_ports`
  - `--feed-pairs`：domain 目标解析 → `allow_pairs4/6` 元组 `{ ip . port timeout ttl }`
  - `--resolver 10.10.0.53`（受控解析器），`--dry-run` 只打印
  - 私网/保留段跳过：复用 `plugins/scope_gate/engine.py` 的 `is_blocked_network`（sys.path 引入，不复制代码）
- `deploy/nftables/scan-node.nft`：现有集合 allow_pairs4/6（`ipv4_addr . inet_service`，flags timeout）、allow_ranges4/6、allow_ports
- 背景：scope 授权 `include_subdomains: true` 时，应用层（scope_gate）放行子域，
  但网络层只喂了精确域名——子域 IP 不在 allow_pairs 里，扫描流量被 nft 丢掉。
  已知限制，本任务补上发现→校验→喂入管道

## 任务：scope_feed.py 新增 `--feed-subdomains`

流程（每个 `include_subdomains: true` 的 domain 目标）：

1. **发现**：对子域做枚举探测。纯标准库方案：对一组常见前缀
   （www, api, app, admin, cdn, static, assets, mail, vpn, dev, test, staging,
   m, mobile, portal, git, jenkins, docs, status —— 常量列表写清楚，可扩展），
   逐个向受控解析器查询 `<prefix>.<domain>`
2. **校验归属**（关键，防投毒/防误授权）：解析出的 IP 必须与父域当前解析 IP
   **共享同一 C 段或同一 AS 判定**——纯标准库做不了 AS 查询，降级为：
   解析出的 IP 通过 `is_blocked_network` 检查（拒私网/保留段）+ 与父域 IP 至少
   一个 octet 匹配（IPv4 前两段、IPv6 前 64 位前缀），不匹配的 IP 打 WARNING
   并跳过，注释写明"严格归属校验需 crt.sh/CT 日志或被动 DNS，当前是保守启发式"
3. **喂入**：通过的 (ip, port) 生成 `allow_pairs4/6` 元组命令（端口沿用父域
   目标的 ports，缺省 80,443）
4. `--dry-run` 打印将执行的命令 + 发现的子域清单；正式模式执行 nft
5. 输出摘要：发现 N 个子域、M 个通过校验、K 个因归属校验跳过（列出）

## 参数设计

- `--feed-subdomains`（开关）
- `--subdomain-prefixes <逗号分隔>`（覆盖默认列表）
- `--loose-affinity`（放宽校验：不做 octet 匹配，只要求非私网——默认关闭）

## 测试（新增 `tests/test_scope_feed_sub.py`，或并入现有测试文件的新增段）

不真实联网：把 DNS 查询函数抽成可注入（现有 resolve 逻辑如果不可注入就重构最小化，
但**不改既有参数行为**），用假解析表测：

1. www/api 子域解析成功且 C 段匹配 → 生成对应 pair 命令
2. 子域解析到私网 IP（10.x）→ 跳过并 WARNING
3. 子域 IP 与父域完全不匹配（无 --loose-affinity）→ 跳过
4. --loose-affinity 时仅私网校验 → 放行
5. --dry-run 不执行 nft（只打印）

## 约束

- 纯标准库；不改既有参数（--feed-ports/--feed-pairs/--dry-run）行为
- **不许碰** plugins/、secops_report/、deploy/nftables/、tests/ 现有用例
- `make test` 全绿

## 验收

```bash
python -m pytest tests/ -q
python deploy/dns/scope_feed.py --scope engagement-demo/scope.yaml --feed-pairs --feed-subdomains --dry-run
```
外加我对归属校验语义的人工审查。
