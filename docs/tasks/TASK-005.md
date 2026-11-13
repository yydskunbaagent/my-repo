# TASK-005：门禁实测缺陷修复（委派工具解析 + 文件名误判）

## 背景

A5 运行时实测（2026-11-14，见审计 engagement-demo/audit/decisions.jsonl）暴露两个缺陷。
本任务只改 `plugins/scope_gate/`，对应补负向+正向测试。改动后 `make test` 必须全绿
（现有 74 条不许回归）。

## 缺陷 1：delegate_task 被当"未知工具"整体拒绝

现象：父 Agent 用 delegate_task 派子任务，即使子任务文本里的目标（yyds520.online）
完全在 scope 内，调用也被拒，理由"无法从未知工具解析目标"。

要求（改 `engine.py` / `extract.py`）：

- 新增委派类工具的参数感知：工具名匹配 `delegate_task`（不区分大小写）时，对
  args 里的**字符串值字段**（task/prompt/description/goal 等任意字符串字段，递归
  展开 dict/list）跑现有的文本目标提取（extract_targets 已支持自由文本，直接复用）
- 判定语义改为：
  - 提取出的目标集合为空 → 放行（委派文本不含可识别目标，交给子 Agent 的门禁把关）
  - 全部目标都在 scope 内 → 放行
  - 任一目标越界 → block，message 列出越界目标
- 即：**从"不认识就拒"改为"提得出就按目标判，提不出才交给子层"**。
  与 `on_unparsed_target: block` 的关系：该策略只作用于"工具执行目标是必判项"的
  工具（terminal/curl 类）；委派类工具按上述新语义走

## 缺陷 2：文件名字符串误判为域名

现象：`cat robots.txt`、`ls evidence/` 等命令里的 `robots.txt` 被 extract_targets
当成两段式域名提取为出网目标，导致误拦。

要求（改 `target.py` 的域名分支 / `extract.py` 的过滤）：

- 形如 `<label>.<file-ext>` 且扩展名属于常见文件后缀（txt/html/htm/js/css/json/
  xml/md/log/csv/yaml/yml/py/sh/conf/ini/pdf/zip/png/jpg）的裸 token，
  **不得**提取为 DOMAIN 目标
- 例外（仍要提取为目标的情形，全部必须保真）：
  - 带scheme（`http://x/y.txt`）→ 域名来自 URL host 部分，不受影响
  - 带端口（`example.com:8080`）→ 正常提取
  - 扩展名前有真实多级域名结构（`cdn.example.com/file.txt` 出现在 URL/host
    上下文里）→ 提取 host 部分
- 判定只针对"裸 token 无上下文"的情形：既不在 URL 里、也不带端口、
  token 本身就是 `xxx.txt` 这种两段文件名
- 新增正向用例：`cat robots.txt` 不产生任何目标；`curl https://app.example.com/a.txt`
  提取出 `app.example.com`；`nmap -p443 10.20.30.4` 行为不变

## 测试要求

`tests/test_target.py` / `tests/test_engine.py` 新增（不改已有用例）：

- 委派类：args 含范围内目标 → allow；含越界目标 → block 且 message 带目标；
  args 无目标（如"分析刚才的输出"）→ allow
- 文件名误判：`cat robots.txt` / `ls -la notes.md` / `grep x data.csv` → 0 目标
- URL 内文件路径不受影响：`curl https://a.example.com/s/robots.txt` → 目标
  `a.example.com`
- 回归：`make test` 全绿

## 约束

- 只改 plugins/scope_gate/ 下必要模块 + tests/ 新增用例，不动 deploy/、secops_report/
- 纯标准库，风格对齐现有代码
- 不改 GateConfig / AuditLog 公开接口
