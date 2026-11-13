# TASK-004：报告命令行入口（python -m secops_report）

## 背景

TASK-003 已交付 `secops_report/` 包（models/classify/render，74 测试全绿）。
本任务给它加命令行入口，形成"findings JSON → 报告文件"的一条命令流水线。
**只新增文件，不修改 secops_report/ 现有任何模块。**

## 任务

### 1. 新建 `secops_report/__main__.py`

`python -m secops_report` 入口，argparse 接口：

```
python -m secops_report <findings.json> [--meta meta.json] [--format md|sarif|both]
                        [--out-prefix reports/ENG-DEMO-001] [--strict]
```

行为规格：

- `findings.json`：JSON 数组，每项是一个 Finding 的字典形式
  （字段名与 TASK-003 的 Finding dataclass 一致：title/target/severity/status/
  description/evidence/poc/discovered_at；evidence/poc 同理嵌套 dict）
- 加载逻辑放本文件：写 `_finding_from_dict(d)` 把 dict 递归转成 dataclass；
  缺必填字段 → 报错并指明是第几条缺什么字段，退出码 2；未知多余字段 → 忽略
- `--meta` 可选 JSON（engagement_id/authorized_by/period 等，原样传给
  render_markdown 的第二个参数）；缺省时 markdown 的作业信息章节显示"未提供"
- `--format` 默认 both：
  - md → `<out-prefix>.md`
  - sarif → `<out-prefix>.sarif`
  - 输出目录不存在则自动创建
- `--strict`：classify 后若**没有任何 confirmed**（全是 observed/rejected），退出码 3
  并在 stderr 打印一行警告（用于 CI 里卡"没有可确认发现"的作业）；不加则正常出报告
- 标准输出打印一行摘要：`N findings (confirmed=X observed=Y rejected=Z) → <文件列表>`
- 退出码约定：0 成功；2 输入错误；3 strict 无 confirmed；其他异常 1
- **注意**：`render_markdown/render_sarif` 接收**原始 Finding 列表**（它们内部调
  classify），不要把 classify 的返回值传进去——这是 TASK-003 的既定契约

### 2. 新建 `tests/test_cli.py`

用 pytest + tmp_path + `subprocess`（`sys.executable -m secops_report ...`）或直接
调用 main 函数（推荐后者，快），覆盖：

1. 正常 both：两个文件都生成，stdout 摘要含 `confirmed=1`
2. 坏 JSON（语法错误）→ 退出码 2，stderr 有提示
3. 缺必填字段（如第 2 条缺 target）→ 退出码 2，提示含 "第 2 条"（或等效定位）
4. `--strict` 且全 observed → 退出码 3
5. `--format md` 只生成 .md 不生成 .sarif
6. 空 findings 数组 → 正常退出 0，生成空报告（覆盖 TASK-003 的 case8 语义）
7. poc.negative 存在但 cleanup_done=false 的 confirmed → 降为 observed 且 markdown
   该条出现在 Observed 章节

测试用的 findings 数据直接在文件里定义常量，不依赖外部文件。

## 约束

- 纯标准库（argparse/json/sys/pathlib/dataclasses 可用）
- LF 行尾、类型注解、风格对齐 secops_report 现有代码
- 不碰 secops_report/ 现有模块、plugins/、deploy/、其他测试文件

## 验收（调用方执行）

```bash
python -m pytest tests/ -q          # 74 + 新增全过，无回归
python -m secops_report --help     # 正常输出
```
外加我用一份真实 findings JSON 跑一遍 both 出两个文件。
