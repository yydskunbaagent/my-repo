# 扫描任务协议（deploy/protocol/）

推理端与扫描节点之间**唯一的任务通道**：结构化 `task.json` 下发、结构化
`result.json` 回传。替代 TASK-008 之前"ssh 进扫描节点手敲 nmap → 人肉汇总
findings.json"的流程。

| 文件 | 说明 |
| --- | --- |
| `task-schema.json` | 任务文件 schema（draft-07），与 `run_scan.py` 的手写校验**双重生效** |
| `run_scan.py` | 扫描节点上的**唯一执行入口**（纯标准库，Python 3.11+） |
| 仓库根 `Dockerfile.scanner` | 扫描镜像（debian + nmap + curl + python3；nuclei 按部署环境二选一放入，版本走 `ARG NUCLEI_VERSION`） |

## 一次完整作业的时序

```text
推理端（reasoning 容器）            扫描节点（宿主机）                     scanner 容器（scannet 网络）
──────────────────────           ─────────────────────                ────────────────────────────
1. 按 task-schema.json 产出
   task.json（含 expires_at，
   须落在 scope 授权窗口内；
   targets ⊆ 授权 scope）
2. scp -P <SSH_PORT> \
     task.json scan-node:/jobs/SCAN-001/
                                 3. docker run --rm --network scannet \
                                      -v /jobs/SCAN-001/task.json:/tmp/task.json:ro \
                                      -v /jobs/SCAN-001/out:/tmp/out \
                                      secops-scanner \
                                      python3 /opt/protocol/run_scan.py \
                                        --task /tmp/task.json \
                                        --out /tmp/out/result.json
                                                                        4. 手写校验 task.json
                                                                           （白名单 / 禁止字符 /
                                                                           过期时间 / rate_limit）
                                                                           不过 → 只写 error，
                                                                           退出码 2，零执行
                                                                        5. 逐条动作以参数列表
                                                                           执行（nmap / nuclei /
                                                                           curl_probe，禁止 shell）；
                                                                           nuclei -json 命中行
                                                                           → findings 自动提取
                                                                        6. 聚合写 result.json，
                                                                           原始输出落 raw/
                                 7. scp -P <SSH_PORT> -r 回传
                                      scan-node:/jobs/SCAN-001/out/
8. 核验 result.json：
   - error 字段为空、各 action exit_code == 0
   - findings（status=observed）逐条对照 raw/ 原始输出研判，
     确认后入库 confirmed / 复核否决 rejected（见 secops_report）
```

## 信任边界

- **`run_scan.py` 是扫描节点上唯一的任务执行入口。** 推理端与扫描节点不共享
  shell，任务与结果只走 JSON 文件（compose 红线：scanner 容器不挂载任何含
  模型凭据的路径）。
- **白名单 + 参数列表执行 = 推理端被注入也跑不出三个工具之外。** task.json
  被篡改时：工具白名单（nmap/nuclei/curl_probe）卡住入口，args/paths 逐元素
  校验禁分号、反引号、`$(` 命令替换，subprocess 走 argv 不经 shell——拿不到
  命令拼接，拿不到反弹 shell。
- **目标越界不由本协议层兜底。** task.json 的 targets 须是授权 scope 的子集
  （推理端保证），网络层由扫描节点 nftables（deploy/nftables/scan-node.nft，
  default deny + IP.端口二元组放行）与受控解析器（deploy/dns/unbound.conf）
  强制——协议层校验只是第一道，不是唯一一道。
- **rate_limit 是声明性字段。** 推理端须把它折进工具参数（如 nmap
  `--max-rate`）；run_scan.py 只校验存在与取值，不代为执行限速。
- **findings 只信 nuclei 的确定指纹（有意设计）。** 模板命中 → 自动 finding
  （status 固定 `observed`）；nmap 指纹与 curl_probe 状态码**不**自动成
  finding，只进 raw/ 由推理端研判——端口开放 / HTTP 200 不等于漏洞。
- **任务时效。** `expires_at` 过期后 run_scan.py 拒绝执行（fail closed），
  过期任务文件重放无效。

## task.json 校验规则（schema 与脚本双重）

- 顶层必填：`task_id` / `engagement_id` / `targets` / `actions` /
  `rate_limit` / `created_at` / `expires_at`；不允许任何额外字段。
- `targets[]`：`host`（主机名/IP，无 scheme 无空白）、`ports`（1-65535 整数）、
  `kind`（目前只支持 `http`/`https`，curl_probe 的 URL scheme 来源）。
- `actions[]`：`tool` 白名单枚举，白名单外一律拒绝；nmap/nuclei 用 `args`、
  curl_probe 用 `paths`（以 `/` 开头），二者互斥；args/paths 逐元素禁
  `;` `` ` `` `$(`；nuclei 动作必须带 `-json`（findings 提取依赖 JSONL）。
- `created_at`/`expires_at`：ISO8601（建议带时区，缺省按 UTC）；`expires_at`
  不得早于 `created_at`，且不得早于执行时刻。
- `--timeout`（默认 600s）为整任务预算：动作之间检查剩余预算，单条命令最多
  拿到剩余预算，超时杀进程后记 `exit_code: null`。

## result.json 结构

```json
{
  "task_id": "SCAN-001",
  "started_at": "…ISO8601…",
  "finished_at": "…ISO8601…",
  "actions": [
    {
      "tool": "nuclei",
      "args": ["-u", "http://10.10.0.100:3000", "-json", "-silent"],
      "exit_code": 0,
      "duration_s": 1.2,
      "raw_output_ref": "raw/01-nuclei.log"
    },
    {
      "tool": "curl_probe",
      "paths": ["/", "/robots.txt"],
      "exit_code": 0,
      "duration_s": 0.2,
      "raw_output_ref": "raw/02-curl_probe.log",
      "requests": [
        {"url": "http://10.10.0.100:3000/", "exit_code": 0,
         "status_code": 200, "headers": ["Server: nginx"], "duration_s": 0.05}
      ]
    }
  ],
  "findings": [
    {
      "title": "cve-2021-44228",
      "target": "http://10.10.0.100:3000/",
      "severity": "critical",
      "status": "observed",
      "description": "jndi-rce",
      "evidence": [{"kind": "log", "summary": "原始 JSON 行前 200 字", "artifact": ""}],
      "discovered_at": "…ISO8601…"
    }
  ]
}
```

- `actions` 与 task.json 的动作一一对应；`raw_output_ref` 指向 out 目录下
  `raw/<序号>-<工具>.log`（含完整命令行、退出状态、stdout/stderr 分节）。
- `curl_probe` 额外带 `requests[]`：每个 (目标端口 × path) 一条，记录状态码
  （`-D -` 解析）与响应头原始行；响应体丢弃（`-o /dev/null`），证据定性是
  "现象"，不是内容转储。任一请求失败则该动作聚合 `exit_code=1`。
- 校验失败时 result 只写 `error` 字段（`actions`/`findings` 为空数组），
  推理端据此排查后重新下发。

### nuclei 字段映射

| finding 字段 | 来源 |
| --- | --- |
| `title` | `template-id`（旧版 `templateID` 兜底，缺省 `unknown-template`） |
| `target` | `matched-at`（`url` / `matched[0]` 兜底） |
| `severity` | `info.severity` 小写；未知/缺失值归 `info` |
| `status` | 固定 `observed`（确认与否由推理端研判） |
| `description` | `matcher-name` |
| `evidence[0]` | `{kind: "log", summary: 原始 JSON 行前 200 字, artifact: ""}` |

## 约束与扩展

- `run_scan.py` 纯标准库 Python 3.11+；LF；类型注解；单测见
  `tests/test_protocol.py`（fake runner 注入，不触网不跑真实工具）。
- 扩充工具白名单 / `kind` 枚举 / 禁止字符：**须同步改** `task-schema.json`
  与 `run_scan.py`（两边校验一一对应），再重建镜像发版；单边改动视为校验
  漏洞。
- nuclei 版本升级：改 `Dockerfile.scanner` 的 `ARG NUCLEI_VERSION`，从
  github.com/projectdiscovery/nuclei/releases 取对应产物（构建机可出网用
  方式 A 直下，否则方式 B 预放 context）。
