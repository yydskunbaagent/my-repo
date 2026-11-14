# TASK-008：扫描任务协议 + nuclei 集成（并行批次 A，只动 deploy/ 与 docs/）

## 上下文预置（先读这些，别的不用看）

- `deploy/docker-compose.scan.yml`：现有拓扑（reasoning/scanner/egress-proxy）
- 扫描镜像构建方式：仓库根 `Dockerfile.scanner`（debian + nmap + curl），`docker build --network host`
- 端到端首扫现状（你要标准化的手工流程）：推理端 `ssh -p 53142 root@47.108.111.56 "docker run --rm --network scannet secops-scanner nmap -sV -p3000 10.10.0.100"` → 人肉汇总 → findings.json
- findings JSON schema 见 `secops_report/models.py` 的 Finding（title/target/severity/status/description/evidence[{kind,summary,artifact}]/poc/discovered_at）

## 任务 1：扫描任务协议（纯文档 + 两个脚本）

### `deploy/protocol/task-schema.json`
任务 JSON 的 JSON Schema（draft-07）：
```json
{
  "task_id": "SCAN-001",
  "engagement_id": "ENG-DEMO-001",
  "targets": [{"host": "10.10.0.100", "ports": [3000], "kind": "http"}],
  "actions": [
    {"tool": "nmap", "args": ["-sV", "-p3000", "10.10.0.100"]},
    {"tool": "nuclei", "args": ["-u", "http://10.10.0.100:3000", "-jsonl", "-silent"  # nuclei v3 用 -jsonl（-json 已移除）]},
    {"tool": "curl_probe", "paths": ["/", "/robots.txt"]}
  ],
  "rate_limit": {"rps_per_host": 2, "max_requests_per_host": 50},
  "created_at": "ISO8601",
  "expires_at": "ISO8601"
}
```
- `actions[].tool` 白名单枚举：nmap / nuclei / curl_probe（其他一律拒绝）
- args 不允许包含分号、反引号、`$(`（schema 的 pattern 校验 + 脚本双重校验）

### `deploy/protocol/run_scan.py`（在扫描节点上运行）
- `python3 run_scan.py --task task.json --out result.json`
- 逐条校验 schema（标准库 json + 手写校验，**不引第三方**）；校验失败 → 拒绝执行并写 result.json 的 error 字段
- 每条 action 用 subprocess 执行（**参数列表形式，禁止 shell=True**）：
  - nmap → `nmap <args>`
  - nuclei → `nuclei <args>`（输出按行解析 JSON）
  - curl_probe → 对每个 path 发 GET（curl，参数列表），记录状态码+响应头
- 所有输出（stdout/stderr/退出码/耗时）聚合进 result.json：
  `{task_id, started_at, finished_at, actions: [{tool, args, exit_code, duration_s, raw_output_ref}], findings: [...]}`
- 自动从 nuclei 的 `-json` 输出提取 findings：每条模板命中转成
  `{title: template-id, target: matched-at, severity: nuclei severity 小写, status: "observed", description: matcher 名, evidence: [{kind:"log", summary: 原始 JSON 行前 200 字, artifact: ""}], discovered_at}`
  severity 映射：critical/high/medium/low/info 原样；未知值归 info
- nmap/curl_probe 的结果**不自动生成 findings**（进 raw_output，由推理端研判）——注释写明这是有意的：自动 findings 只信 nuclei 的确定指纹
- 超时：整任务 `--timeout` 默认 600s

### `Dockerfile.scanner` 更新
- 增加 nuclei：Go 单二进制，`ARG NUCLEI_VERSION=3.3.9`（写注释：部署时从
  github.com/projectdiscovery/nuclei/releases 取对应版本号），下载 URL 用注释说明
  （构建机需要代理或提前放入 context，二选一都写出来）
- 不在 Dockerfile 里写死会过时的下载 URL 逻辑，给出两种方式的注释模板

## 任务 2：协议文档 `deploy/protocol/README.md`
- 一次完整作业的时序图（文本版）：推理端产 task.json → scp 到扫描节点 → run_scan.py → result.json 回传 → 推理端核验 findings
- 信任边界说明：run_scan.py 是扫描节点上唯一执行入口；白名单 + 参数列表执行 = 即使推理端被注入，也只能跑三个预定义工具

## 约束
- run_scan.py 纯标准库，Python 3.11+，LF，类型注解
- **不许碰** plugins/、secops_report/、tests/、engagement-demo/
- 新增 `tests/test_protocol.py`：schema 校验（合法任务通过/含分号的 args 被拒/未知 tool 被拒）、nuclei JSON 行解析成 findings、curl_probe 结果聚合。纯标准库可测（subprocess 用 monkeypatch 或只测解析函数）

## 验收
```bash
python -m pytest tests/ -q          # 127 + 新增全过
python deploy/protocol/run_scan.py --help
```
外加：我拿真实 task.json 在扫描节点实跑一次 nuclei
