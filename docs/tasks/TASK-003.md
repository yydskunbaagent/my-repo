# TASK-003：黑盒发现报告生成器（secops_report）

## 背景

方案 §6：黑盒报告自研，结论三档（`confirmed`/`observed`/`rejected`），借鉴官方
validation-policy 的正负对照原则。**新模块独立于 scope_gate，不碰它的公开接口。**

## 任务

### 1. 新建 `secops_report/` 包（仓库根目录，独立于 plugins/）

模块结构：

- `secops_report/models.py`：数据类
  - `Finding`：`id`(F-001 格式自动编号)、`title`、`target`、`severity`(critical/high/medium/low/info)、
    `status`(confirmed/observed/rejected)、`description`、`evidence: list[Evidence]`、
    `poc: Poc | None`、`discovered_at: datetime`
  - `Evidence`：`kind`(command/screenshot/http_pair/log)、`summary`、`artifact`(文件路径或内联文本引用)
  - `Poc`：`positive: Evidence`、`negative: Evidence | None`、`cleanup_done: bool`
- `secops_report/classify.py`：结论降级规则
  - 输入 Finding，返回最终 status。规则：
    - `poc` 为 None 且声称 `confirmed` → 降为 `observed`
    - `poc.negative` 为 None 且声称 `confirmed` → 降为 `observed`（只有正对照没有负对照，不够格）
    - `poc.negative` 存在但 `cleanup_done` 为 False → 降为 `observed`（清理未完成不得 confirmed）
    - `status == "rejected"` 不降级，保留（Rejected Candidates 附录用）
  - 降级必须在结果里带一句 reason
- `secops_report/render.py`：两个渲染器
  - `render_markdown(findings, engagement_meta) -> str`：执行摘要（按严重度统计）、
    confirmed 在前 observed 在后 rejected 进附录 `Rejected Candidates`、
    每条含证据列表和 PoC 正负对照、末尾 Coverage Gaps 章节（输入参数里的未覆盖项）
  - `render_sarif(findings) -> str`：SARIF 2.1.0 合法 JSON（tool 名 "secops-report"，
    severity 映射：critical/high→error，medium→warning，low/info→note；
    rejected 的 finding **不进** SARIF；`target` 写进 region/uri 字段）
- `secops_report/__init__.py`：只导出 `Finding/Evidence/Poc/classify/render_markdown/render_sarif`

### 2. 新建 `tests/test_report.py`

不碰 conftest.py 现有内容，直接新建用例（自包含，可加自己的 fixture）：

1. claimed confirmed + 无 poc → observed，带 reason
2. claimed confirmed + 只有 positive → observed
3. confirmed + 正负对照 + cleanup_done → 保持 confirmed
4. negative 存在但 cleanup_done False → observed
5. rejected 原样保留
6. markdown 渲染：confirmed 排在 observed 前、rejected 只出现在附录
7. sarif 渲染：json.loads 能解析、$schema/version 字段正确、rejected 不在 results 里、
   severity 映射正确
8. 空 findings 列表 → markdown 有 Coverage Gaps 章节且不崩

## 约束

- 纯标准库（datetime/json/dataclasses/textwrap 可用），无第三方依赖
- LF 行尾，类型注解 + docstring，风格对齐 plugins/scope_gate
- **不要动** plugins/、tests/test_engine.py、tests/test_target.py、tests/conftest.py、deploy/
- SARIF 只要求 2.1.0 最小合法结构（runs[].tool.driver + runs[].results[]），不需要/artifacts 等

## 验收（调用方执行）

```bash
python -m pytest tests/ -v      # 原 66 条 + 新增全部通过
```
