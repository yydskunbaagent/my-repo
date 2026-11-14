# CI（GitHub Actions）

## CI 跑什么

workflow 在 `.github/workflows/test.yml`：`push`（main）与 `pull_request` 触发，
ubuntu-latest + Python 3.12，核心只有一条命令（与本地逐字一致）：

```
python -m pytest tests/ -q
```

## 为什么不能跳

用例主体是负向路径（291 条，2026-11-14 实测）：非法 scope 拒判、畸形命令拦截、
fail closed、限流边界……它们就是门禁的**行为契约**。任何一条变红 = 门禁行为被
改动，CI 必须挡下；跳过/降级用例（`--deselect`、`xfail` 化解）等同于改契约，不允许。

## 本地等价命令

```
make setup                    # 装测试依赖：pyyaml + pytest
make test                     # python -m pytest tests/ -v
python -m pytest tests/ -q    # 与 CI 完全相同
```

## 备注

- 依赖仅测试用的 pytest + pyyaml（同 `make setup`）；不装项目本体（禁止 `pip install -e .`）。
  测试与插件解析 scope.yaml 需要 pyyaml，只装 pytest 会大面积报错（已实测）。
- 根目录无 pyproject/requirements，setup-python 的 pip 缓存 key 无所依凭，降级为不启用。
- workflow 文件一律 LF 行尾。
