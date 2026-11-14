# TASK-014：CI（GitHub Actions 强制执行测试契约）

## 任务

### 1. `.github/workflows/test.yml`

- 触发：`push`（main）与 `pull_request`
- 环境：ubuntu-latest，Python 3.12（矩阵不需要，单版本即可）
- 步骤：
  1. checkout
  2. setup-python（3.12，pip 缓存 key 按 pyproject/requirements 存在性降级：本仓纯标准库，不装依赖）
  3. `pip install pytest`
  4. `python -m pytest tests/ -q`
- 命名：workflow 名 `test`，job 名 `pytest`
- badge：无（README 后续单独做）

### 2. `docs/CI.md`（短文档，<40 行）
- CI 跑什么（291 条负向用例为主的行为契约）、为什么不能跳（门禁负向用例=行为契约）
- 本地等价命令 `make test` / `python -m pytest tests/ -q`

## 约束

- 仓库纯标准库，workflow **不许** `pip install -e .` 或装项目依赖——只装 pytest
- workflow 文件 LF 行尾
- 不碰其他任何文件

## 验收

1. workflow YAML 语法正确（我用 python yaml 解析验证）
2. `python -m pytest tests/ -q` 在 CI 环境下可运行（本地已 291 passed）
