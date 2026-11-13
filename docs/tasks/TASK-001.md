# TASK-001：engine 私网/保留段阻断 + 负向测试

## 背景

`scope_gate` 是 Hermes Agent 的授权门禁插件（`pre_tool_call` hook）。
已有模块：`models.py`（数据结构）、`target.py`（目标归一化）、`scope.py`（scope 文件解析）、
`engine.py`（判定引擎）、`gate.py`（hook 注册）、`ratelimit.py`、`audit.py`、`extract.py`。

## 任务

### 1. 在 `engine.py` 实现 DNS 解析私网阻断

当前缺陷：scope 里的域名目标会做 DNS 解析（`engine.py` 中已有解析逻辑），但解析结果只检查
"是否命中排除项"。必须加一层：**解析到的 IP 落在私网/保留段时，默认阻断**，除非该 IP 被
scope 以显式 IP/CIDR 目标授权。

具体规则：

- 新增函数 `is_blocked_network(ip: IPv4Address | IPv6Address) -> bool`，覆盖以下段（IPv4）：
  `0.0.0.0/8`、`10.0.0.0/8`、`100.64.0.0/10`（CGN）、`127.0.0.0/8`、`169.254.0.0/16`、
  `172.16.0.0/12`、`192.0.0.0/24`、`192.0.2.0/24`、`192.88.99.0/24`、`192.168.0.0/16`、
  `198.18.0.0/15`、`198.51.100.0/24`、`203.0.113.0/24`、`224.0.0.0/4`、`240.0.0.0/4`。
  IPv6：`::1/128`、`::/128`、`fc00::/7`、`fe80::/10`、`ff00::/8`、IPv4-mapped `::ffff:0:0/96`
  （映射的 IPv4 按上述 IPv4 规则判断）。
- 域名解析到上述段 → 返回 block，reason 为 `private_network_resolution`，
  message 说明"域名解析到未授权的私网/保留地址"。
- **例外**：若该解析 IP 命中 scope 的显式 `ip_targets` 或 `cidr_targets`（即用户明确授权了这个
  内网 IP），放行。排除项（excludes）仍然优先生效。
- 只用标准库 `ipaddress`。不引入新依赖。
- 解析失败的 fail-closed 行为保持不变，不要动。

### 2. 新增 `tests/test_engine.py`（负向测试，全部必须通过）

用 `tests/conftest.py` 里现成的 fixture（先读它，了解 engagement 构造方式）。
不真实联网：monkeypatch 掉 DNS 解析函数（看 `engine.py` 里解析入口叫什么，patch 那个）。

必须覆盖的用例：

| # | 场景 | 预期 |
|---|---|---|
| 1 | scope 域名 `example.test` 解析到 `10.1.2.3`，scope 无内网授权 | block，reason=`private_network_resolution` |
| 2 | scope 域名解析到 `169.254.169.254`（云元数据） | block |
| 3 | scope 域名解析到 `192.168.1.10`，且 scope 显式授权 `192.168.1.10` | 放行 |
| 4 | scope 域名解析到 `192.168.1.10`，scope 授权的是另一个段 `10.0.0.0/8` | block |
| 5 | scope 域名解析到 `8.8.8.8`（公网） | 放行（不误伤） |
| 6 | IPv4-mapped：域名解析到 `::ffff:10.1.2.3` | block |
| 7 | 解析到 `100.64.1.1`（CGN 段） | block |

### 3. 约束

- Python 3.11，纯标准库（现有模块只用 `ipaddress`/`sqlite3`/`hashlib` 等）。
- 不修改 `gate.py`、`audit.py`、`ratelimit.py`、`models.py` 的公开接口。
- 代码风格与现有文件一致（类型注解、docstring、f-string）。
- 不创建本任务之外的新文件，不动 `refs/`、`plan/`、`.workbuddy/` 目录。

## 验收（由调用方执行，你不用跑）

```bash
python -m pytest build/tests/ -v
```

全绿 + 上述 7 条用例全部在列 + 公网域名用例不误伤，即通过。
