# TASK-007：边缘边界补强（内联代码拦截 / 端口二元组集合 / masking 补全）

## 背景

第二轮外部评审（基于 748a52b）确认三处边缘问题。改动范围：plugins/scope_gate/
（仅 gate.py 与 extract.py 的判定语义）、deploy/（nft + scope_feed）、secops_report/masking.py。
现有 103 条测试不许回归。

## 任务 1：解释器内联执行类别性拦截（plugins/scope_gate）

问题：`python3 -c "..."` / `bash -c "..."` 这类内联执行目前不被拦截——只有脚本
**文件**形态（`script_path`）触发 block。当内联代码含一个可见合法目标 + 一个
不可提取的隐藏 sink（如 `'http://' + 'x' + '.com'` 拼接）时，门禁只看到合法目标
就放行，隐藏 sink 逃过应用层（只能靠网络层兜底）。

修复要求：

- `gate.py` 的 terminal 判定：`analysis` 命中解释器（首词属于
  `extract.py` 的 `_SCRIPT_INTERPRETERS`）**且**命令含内联执行形态
  （`-c` / `-e` / `--eval` / `-m` 任一参数，或除解释器外无其他参数即交互模式）
  → 一律 block，code=`inline_code_execution`，message 说明"扫描节点不允许
  内联代码执行，请使用预授权的原子工具"
  - 需要在 `extract.py` 的 `Analysis` 增加字段（如 `inline_eval: bool`），
    在 analyze_terminal 里判定；不改既有字段语义
  - 纯文件形态（`bash scan.sh`）保持既有 `script_execution` block 不变
- 注意与 delegate 语义的关系：delegate_task 不走 terminal 路径，不受影响
- 新增测试（tests/test_engine.py 或新增）：
  1. `python3 -c "...urlopen(https://yyds520.online)..."`（目标全合法）→ block
     `inline_code_execution`
  2. `bash -c 'curl http://10.20.30.4'` → block
  3. `python3 /opt/scan.py`（文件形态）→ block `script_execution`（既有行为不回归）
  4. `curl https://yyds520.online/` → 放行（不误伤正常工具命令）

## 任务 2：端口二元组集合（deploy/nftables/scan-node.nft + deploy/dns/scope_feed.py）

问题：`allow_domains4` 与 `allow_ports` 是两个独立集合，交叉放行——授权
`a.com:80` + `b.com:8080` 时网络层实际放行 `a.com:8080`。

修复要求：

- nft 新增命名 set `allow_pairs4` / `allow_pairs6`：
  `type ipv4_addr . inet_service` / `type ipv6_addr . inet_service`，`flags timeout`
- forward 链为 domain 目标新增四条规则：
  `ip daddr . tcp dport @allow_pairs4 accept`（v6 同理），
  **置于** 现有 `@allow_domains + @allow_ports` 宽放行规则**之前**；
  宽放行规则保留（服务 netrange 目标：IP/CIDR 无域名语义，继续用
  ranges+ports 组合），注释写清两条路径的分工：
  域名目标走精确二元组，netrange 目标走 ranges×ports
- `scope_feed.py` 新增 `--feed-pairs`：对每个 `kind: domain` 目标，解析其 IP，
  与该目标的 `ports` 逐一生成
  `nft add element inet hermes_scan allow_pairs4 { <ip> . <port> timeout <ttl>s }`
  （ports 缺省的目标按 80,443 处理并打日志说明假设）；
  `--dry-run` 照常只打印。`--feed-ports` 保留（服务 netrange 目标）
- 更新 nft 文件头部注释的喂集说明

## 任务 3：masking 三处补全（secops_report/masking.py）

实测确认的缺口：

1. `_BEARER_RE` 加 `(?i)`：`\b(?i:bearer\s+)(...)`（注意保留组结构，
   lowercase `bearer mysecrettoken123` 必须命中）
2. `_PREFIXED_RE` 补 `github_pat_` 前缀（GitHub Fine-grained PAT）
3. `_HEADER_RE` 补 `x-auth-token`、`private-token` 两个头名

新增测试（tests/test_masking.py 追加，不改现有用例）：

- `bearer mysecrettoken123`（小写、裸 token）→ 掩码
- `github_pat_11ABCdefGHIjklMNOpqrSTUvwx1234567890` → 掩码
- `X-Auth-Token: abcdef1234567890` → 掩码
- `Private-Token: abcdef1234567890` → 掩码
- 既有用例不回归

## 约束

- 不改 GateConfig / AuditLog / scope.py 公开接口
- 不碰 tests/ 现有用例（只新增）
- `make test` 全绿

## 验收（调用方执行）

```bash
python -m pytest tests/ -q   # 103 + 新增全过
python deploy/dns/scope_feed.py --scope engagement-demo/scope.yaml --feed-pairs --dry-run
                             # 输出含 allow_pairs4 元组命令
```
