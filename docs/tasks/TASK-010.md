# TASK-010：门禁工具感知分类（并行批次 C，只动 plugins/scope_gate/）

## 上下文预置（先读这些）

- `plugins/scope_gate/gate.py`：`decide()` 调用链、`rate_checker` 闭包、`_protected()` 路径保护
- `plugins/scope_gate/engine.py`：`decide()` 主判定链——关键行为：delegate 工具已特殊化
  （`is_delegate_tool` → 提得出目标按目标判/提不出 ALLOW）；**其他所有工具**无目标 →
  `no_target` block（约 208 行附近），有目标 → 逐个校验
- `plugins/scope_gate/extract.py`：`analyze_tool(tool_name, args)` 对所有工具的 args
  跑全文目标提取；`_parse_legacy_ipv4` 的 inet_aton 语义（三段式 `a.b.c` → IP，
  这就是把 `python-3.14.9` 解析成 `3.14.0.9` 的来源）
- 实测证据（2026-11-14 A6 复测）：`tool_describe` / `tool_search` / `security_scan_*`
  （hermes-security 插件的 9 个本地分析工具）因参数无 IP 被 `no_target` 拦截 ~10 次，
  导致官方插件并发审计几乎被废

## 问题定义

1. **本地工具被误杀**：不出网的工具（文件读写、工具描述、security_scan 系列）
   也被要求"必须有网络目标"，无目标即 block
2. **对本地工具的 args 跑网络目标提取产生误报**：版本号 `python-3.14.9` → IP
   `3.14.0.9`；`os.path.join` → 域名

## 修复设计

### 1. 工具分类（`extract.py` 新增常量 + gate/engine 消费）

```python
# 出网类工具：需要目标校验（terminal/url/browser/delegate 等已有处理）
# 本地类工具：跳过目标提取与 no_target 检查
LOCAL_TOOLS = frozenset({
    "read_file", "write_file", "edit_file", "list_dir", "list_directory",
    "search_files", "tool_describe", "tool_search", "tool_search_describe",
    "memory_write", "memory_read", "todo_write", "session_status",
    # hermes-security 插件的 9 个本地分析工具
    "security_scan_start", "security_scan_get", "security_scan_checkpoint",
    "security_scan_submit_worker_result", "security_scan_record_validations",
    "security_scan_record_chains", "security_scan_finalize",
    "security_scan_cancel", "security_scan_export",
})
def is_local_tool(name: str) -> bool: ...
```

- `gate.py` / `engine.py`：`is_local_tool(tool_name)` 为真 → **跳过目标提取与
  no_target 判定**，直接放行到后续检查
- **路径保护不受影响**：`_protected()` 的作业元数据写保护必须照常生效
  （local 工具写 scope.yaml/audit 仍然要拦）——先确认现有调用顺序，保护检查
  在目标判定之前的话就不用动；若依赖目标提取，需要把保护检查提前
- 可配置：`GateConfig` 增加 `extra_local_tools: tuple[str, ...]`（config.yaml 的
  `extra_local_tools:` 列表），运行时合并进 LOCAL_TOOLS——部署方不用改代码就能
  声明自己的本地工具。**这是唯一允许的 GateConfig 变更**（加一个带默认值的字段，
  不破坏现有构造调用）

### 2. 出网工具的提取保持不变

terminal / url 抓取 / browser / delegate 的目标提取、畸形写法解析、内联拦截
（TASK-007 的 inline_eval）**全部原样保留**——版本号误解析在这些工具里是
可接受的代价（绕过检测优先），注释里写明这个取舍

### 3. 测试（新增，不改现有用例）

1. `tool_describe` 无目标参数 → ALLOW（不再 no_target）
2. `security_scan_start` 参数含仓库路径 → ALLOW
3. local 工具写 `scope.yaml`（write_file path=scope.yaml）→ 仍然 BLOCK（路径保护生效）
4. `extra_local_tools` 配置注入的自定义工具名 → 同样放行
5. terminal 的既有行为不回归：`python3 -c` 拦、`bash scan.sh` 拦、curl 目标校验照旧

## 约束

- 只改 plugins/scope_gate/ 的 extract.py / engine.py / gate.py + models/config 相应
  字段 + tests 新增；**不许碰** deploy/、secops_report/、docs/
- GateConfig 只允许新增 `extra_local_tools` 字段
- `make test` 全绿（127 + 新增）

## 验收

```bash
python -m pytest tests/ -q
```
外加：我在真实 Hermes 会话里重跑 hermes-security 并发扫描，确认 security_scan_*
不再被拦（validator 全程可派子 Agent）。
