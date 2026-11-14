# TASK-012：终端本地命令白名单 + execute_code 拦截 + 协议校验修正（plugins/scope_gate/ 与 deploy/protocol/run_scan.py）

## 任务 0（优先）：协议校验修正（deploy/protocol/run_scan.py）

实测（SCAN-002）发现两个问题：

1. nuclei 校验错误：run_scan.py 强制要求 nuclei 动作带 `-json`，但 nuclei v3.3.9
   的 JSONL 输出参数是 **`-jsonl`**（`-json` 在 v3 已移除）。修正：校验接受
   `-json` 或 `-jsonl` 其一；内部按 JSONL 逐行解析的逻辑不变（两种 flag 输出格式
   相同，都是逐行 JSON）
2. curl_probe 健壮性：任一 path 返回 curl exit 18（CURLE_PARTIAL_FILE，大响应体
   截断）时整条动作汇总为 exit 1。修正：exit 18 视为"成功但部分截断"——状态码
   与响应头已拿到即算探测成功，raw 日志标注 partial；仅完全失败（exit 0 以外的
   连接错误/超时）才算失败

补测试：`tests/test_protocol.py` 追加——
- nuclei 动作带 `-jsonl` 通过校验；带 `-json` 也过（向后兼容）；两者都缺才拒
- curl_probe 模拟 exit 18 → 动作整体 success 且标注 partial

## 任务 1：终端本地命令白名单（extract.py）

## 上下文预置（先读这些）

- `plugins/scope_gate/extract.py`：`_SCRIPT_INTERPRETERS`、`analyze_terminal`
  （TASK-005/007 已在此处理 delegate 与 inline_eval）、`LOCAL_TOOLS`（TASK-010）
- `plugins/scope_gate/gate.py`：`is_local_tool` 消费点、路径保护、rate_checker
- 实测证据（2026-11-14 A6 复测后半段）：
  - `ls 目标目录`（terminal 工具，纯本地）被 no_target 拦
  - 终端命令里的 `os.path.join`、`python-3.14*`（glob）被解析成域名/IP
  - `execute_code` 工具（Hermes 原生任意 Python 执行）的 args 被全文提取，
    `json.load`/`d.keys` 当域名拒；同时 execute_code 本身是任意代码执行，
    目标不可可靠提取——属于"应用层门禁接不住"的类别

## 修复设计

### 1. 终端本地命令白名单（extract.py）

```python
_LOCAL_SHELL_COMMANDS = frozenset({
    "ls", "dir", "pwd", "cd", "cat", "type", "head", "tail", "wc", "echo",
    "grep", "find", "stat", "file", "md5sum", "sha256sum", "touch", "mkdir",
    "cp", "mv", "rm", "rmdir", "git", "diff", "sort", "uniq", "which", "where",
    "ps", "env", "date", "whoami", "uname", "hostname", "df", "du", "free",
})
```

- `analyze_terminal`：首词命中该集合 → `Analysis(action=RECON_PASSIVE,
  targets=(), is_local_shell=True)`（加 `is_local_shell: bool` 字段）
- `gate.py`：`is_local_shell` 为真 → **跳过目标提取、no_target、限速记账**，
  但 forbidden 关键词检查（rm -rf / / 类毁灭性命令）与路径保护照常生效
- 注意：`rm -rf` 之类仍由 `_DESTRUCTIVE` 检查拦（现有逻辑），不要因为
  is_local_shell 就跳过 forbidden 判定

### 2. execute_code 类别性拦截（gate.py）

- 新增常量 `_CODE_EXECUTION_TOOLS = frozenset({"execute_code", "code_exec",
  "python_exec"})`（小写比较）
- `gate.py` 的 pre_tool_call：命中 → 一律 block，code=`code_execution_tool`，
  message："execute_code 是任意代码执行，目标无法可靠提取，扫描节点禁用。
  请使用任务协议（deploy/protocol/run_scan.py）的原子动作白名单"
- 这与 TASK-007 的 inline 拦截构成同一防线：terminal 内联拦 `-c/-e/-m`，
  execute_code 是工具级同类问题

### 3. 测试（新增，不改现有用例）

1. `ls /opt/secops` → ALLOW，且不计入任何限速桶（用 FakeClock 验证计数器没变）
2. `cat robots.txt` → ALLOW（不再误解析域名）
3. `grep pattern file.log` → ALLOW
4. `rm -rf /` → 仍被 forbidden 拦（路径保护/毁灭性命令不受本地白名单影响）
5. `execute_code` 任何 args → block `code_execution_tool`
6. `python3 -c "..."` → 仍被 inline_code_execution 拦（TASK-007 不回归）
7. `curl https://yyds520.online/` → 目标校验照旧（不误伤）

## 约束

- 只改 plugins/scope_gate/ 的 extract.py / gate.py（engine.py 如需可动，但不要动
  decide 的判定顺序）、deploy/protocol/run_scan.py（仅任务 0 两处校验修正）+ tests 新增
- GateConfig / AuditLog / LOCAL_TOOLS 公开接口不许再变
- `make test` 全绿（225 + 新增）

## 验收

```bash
python -m pytest tests/ -q
```
外加我在真实 Hermes 会话重跑一次 hermes-security 扫描，确认 ls/execute_code/
点号 token 不再误拦。
