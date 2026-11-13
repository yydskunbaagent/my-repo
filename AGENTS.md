# AGENTS.md

> 所有客户端（WorkBuddy / ZCode / Claude Code / Cursor / Gemini CLI）共读的项目约定。
> 与任何客户端自身的默认习惯冲突时，以本文件为准。

## 环境

- Python >= 3.11，插件代码**纯标准库**（已用：ipaddress/sqlite3/hashlib/yaml）
- 依赖只有测试用的 `pyyaml`、`pytest`：`make setup`
- 跑测试只有一条命令：`make test`（本地与 CI 必须同一条）
- 服务端目标环境是 Linux；本机是 Windows。换行一律 LF（.gitattributes 已锁）
- 生成文件用 Python/Write 工具，**不要用 shell heredoc**（printf 转义差异会写坏文件）

## 目录

- `plugins/scope_gate/` 门禁插件本体；`tests/` 负向测试优先
- `plan/` 方案文档，**保留历史版本不覆盖**
- `docs/tasks/` 派给外部智能体的任务书（含验收标准）
- `refs/` 第三方克隆，不入库（信息见 refs/README.md）
- `deploy/` 部署模板（compose/nftables/dns）
- 作业数据（grants/evidence/audit）永不入库，见 .gitignore

## 代码规则（scope_gate）

- 类型注解 + docstring + f-string，风格与现有文件一致
- 测试不碰真实 DNS / 真实时钟 / 真网络：用 conftest 里的 FakeResolver / FakeClock
- fail closed 是铁律：任何"配置坏了就放行"的口子都不许有
- 公开接口不许改（gate.py/audit.py/ratelimit.py/models.py），改接口需先改 DECISIONS.md

## ZCode 无头调用（Windows）

```
$env:ELECTRON_RUN_AS_NODE='1'
D:\zcode\ZCode.exe D:\zcode\resources\glm\zcode.cjs -p "<任务书路径+要求>" --mode yolo --disallowed-tools Bash --json --cwd <项目根>
```

- 必须 `--mode yolo`（build 模式无头无权限应答者，全拒）+ `--disallowed-tools Bash`（执行权留在调用方）
- 任务书放 `docs/tasks/`，禁止裸传任务描述
- 配额：优先走 Z.AI 套餐（5 小时窗口，超额 429 自动回退 BigModel API Key 通道）
- 供应商配置：`~/.zcode/v2/provider_config.json`（改模型/加通道在那儿）

## 安全红线

- 无书面授权只能打自己的靶场（DVWA/Juice Shop/HTB/自建）
- 阿里云 47.74.33.82 不当攻击跳板（有账号池业务，IP 被标即全线受影响）
- GitHub token 一旦出现在对话即视为泄露，立即吊销；推远端用 Fine-grained token 只授权单仓
