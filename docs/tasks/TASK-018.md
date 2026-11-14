# TASK-018：白盒 + 黑盒统一报告（secops_report 合并模式）

## 背景

官方 hermes-security 产出的白盒 SARIF 与自研 secops_report 的黑盒报告目前是
两份文件，真实交付要人工拼。本任务在 secops_report 加合并模式：一份脱敏后的
Markdown + SARIF 2.1.0，区分"白盒代码推演"与"黑盒实测证据"，同接口命中的
项自动做关联标注。

## 硬约束

- TASK-003 契约不动：渲染器永远接收原始 Finding 列表，classify 由渲染器内部
  执行；render_markdown/render_sarif 对外行为（输出字节）零变化
- 退出码契约不变：0 成功；2 输入错误（含白盒 SARIF 结构非法，fail closed）；
  3 --strict 无 confirmed；1 意外异常
- 白盒 SARIF 的 message/uri 在渲染前一律过 mask_text（白盒证据片段同样可能
  带凭据）；合并输出整体沿用既有脱敏管线
- 不引入第三方依赖；风格与 secops_report 现有模块一致

## 任务

### 1. `secops_report/render.py` 三个公共函数（纯抽取重构，零行为变化）

- `render_blackbox_body(findings, engagement_meta)`：执行摘要 + 分档正文 +
  Rejected 附录 + Coverage Gaps（即现 render_markdown 去掉标题与作业信息块）
- `render_engagement_meta(engagement_meta)`：作业信息块
- `sarif_results(findings)`：SARIF results 数组的构建（现 render_sarif 内循环）
- render_markdown / render_sarif 改为调用三者拼装，现有测试必须原样通过

### 2. `secops_report/merge.py`

- `load_whitebox_sarif(path)`：结构校验（根 object、runs 数组、result 必带
  message.text、level ∈ {error, warning, note, none}（缺省 note）、取首个
  location 的 artifactLocation.uri），违规抛 InputError（fail closed）
- `correlate(findings, wb_results)`：同接口命中启发式——黑盒 target 经
  urlparse 取 host 与 path（path 长度 >1 才参与），任一键是白盒
  uri+message 的子串即关联，编号 X-001…；每条黑盒/白盒最多参与一条关联，
  按 blackbox→whitebox 顺序首个命中；启发式性质写进 docstring
- `render_merged_markdown(findings, wb, engagement_meta)`：标题（综合报告）
  → 作业信息 → 关联发现章节 → 白盒代码推演章节（ruleId/level/位置/message
  表格）→ `render_blackbox_body`（黑盒实测）
- `render_merged_sarif(findings, wb)`：两个 runs——run[0] 黑盒（driver
  secops-report，sarif_results + properties.source=blackbox），run[1] 白盒
  （driver 取输入 SARIF 的 tool.driver.name）；关联项双方 result 加
  properties.correlationId；message/uri 过 mask_text

### 3. `secops_report/__main__.py` 接线

新增可选参数 `--whitebox-sarif PATH`：提供时走合并渲染（--format 语义不变，
--strict/--meta/--out-prefix 不变）；不提供时行为与现状逐字节一致。

### 4. `tests/test_merge.py`

自包含。必须覆盖：

- 合并 md 含三大章节；关联命中（如黑盒 `http://10.10.0.100:3000/ftp` ↔
  白盒 `src/routes/ftp.js`）标 X-001；无命中时显示（无同接口命中）
- 合并 SARIF：两 runs、driver 名正确、关联项双方带 correlationId、
  source 标注正确
- 白盒 message 带凭据形态 → 输出已掩码
- SARIF 结构非法（无 runs / result 缺 message.text / 非法 level）→ 退出码 2
- `--whitebox-sarif` 缺省时 CLI 输出与现状一致（回归保护）
- rejected 黑盒 finding 不进合并 SARIF、只进附录

## 验收标准

- `make test` 全绿（现有 314 条不回归，其中 test_report/test_cli 必须原样通过）
- 白盒输入任何结构违规都不会产出半份报告（先校验后渲染，fail closed）
- 换行 LF；类型注解 + docstring + f-string
