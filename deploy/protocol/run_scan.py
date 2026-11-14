#!/usr/bin/env python3
"""扫描任务协议执行器（TASK-008）：在扫描节点上按 task.json 逐条执行扫描动作。

信任边界（deploy/protocol/README.md）：本脚本是扫描节点上唯一的任务执行入口。
安全模型 = 工具白名单（nmap/nuclei/curl_probe，白名单外一律拒绝）+ 参数列表
执行（subprocess 走 argv，禁止 shell=True）+ 参数字符校验（禁分号、反引号、
$( 命令替换）。即使推理端被注入、task.json 被篡改，攻击面也被收敛到三个
预定义工具的参数列表，拿不到 shell；目标越界由扫描节点网络层
（scan-node.nft + 受控解析器）兜底，本脚本只是第一道而非唯一一道防线。

校验为标准库手写实现（不引第三方 schema 库），规则与同目录 task-schema.json
（draft-07）一一对应、双重校验。校验失败 -> 不执行任何动作，result.json 只写
error 字段（退出码 2）；任务过期（expires_at 早于当前时间）同样拒绝——过期
任务文件重放无效（fail closed）。

findings 语义（有意为之的设计）：自动 findings 只信 nuclei 的确定指纹——
模板命中即结构化证据（status 固定 observed，确认与否由推理端研判后入库）。
nmap 指纹与 curl_probe 状态码只进 raw_output 不自动成 finding：端口开放 /
HTTP 200 不等于漏洞，避免误报混进报告。

用法：
    python3 run_scan.py --task task.json --out result.json [--timeout 600]

退出码：0 全部动作成功；1 有动作失败或超时；2 校验失败/输入错误（未执行任何动作）。
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import shlex
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Sequence

logger = logging.getLogger("run_scan")

# ---- 协议常量：与 task-schema.json 一一对应，两边改动须同步 ------------------

ALLOWED_TOOLS: tuple[str, ...] = ("nmap", "nuclei", "curl_probe")
FORBIDDEN_ARG_SUBSTRINGS: tuple[str, ...] = (";", "`", "$(")
NUCLEI_SEVERITIES: frozenset[str] = frozenset(
    {"critical", "high", "medium", "low", "info"})
HTTP_KINDS: frozenset[str] = frozenset({"http", "https"})

REQUIRED_KEYS: tuple[str, ...] = (
    "task_id", "engagement_id", "targets", "actions", "rate_limit",
    "created_at", "expires_at")
ACTION_KEYS: frozenset[str] = frozenset({"tool", "args", "paths"})

ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
HOST_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")

DEFAULT_TIMEOUT_SECONDS = 600
CURL_REQUEST_TIMEOUT_SECONDS = 15
# curl exit 18（CURLE_PARTIAL_FILE，TASK-012）：大响应体截断，但状态码与
# 响应头已到手——视为"成功但部分截断"，不算动作失败
CURL_PARTIAL_EXIT_CODE = 18
NUCLEI_EVIDENCE_SUMMARY_CHARS = 200
RAW_DIR_NAME = "raw"

# 注入点：subprocess 执行函数（测试用 fake runner 替代，签名同 _run_command）
RunFn = Callable[[list[str], float], dict[str, Any]]


# ---------------------------------------------------------------------------
# 校验：与 task-schema.json 一一对应的手写实现（fail closed）
# ---------------------------------------------------------------------------

def _arg_problem(value: str) -> str | None:
    """单个参数/路径的字符校验，返回问题描述或 None（通过）。

    与 task-schema.json 的 pattern 双重校验：禁分号、反引号、$( 命令替换。
    """
    for fragment in FORBIDDEN_ARG_SUBSTRINGS:
        if fragment in value:
            return f"含禁止字符 {fragment!r}"
    return None


def _parse_iso8601(value: Any, where: str, errors: list[str]) -> datetime | None:
    """解析 ISO8601 时间；naive 按 UTC 处理（与 scope_feed 口径一致）。失败记错误并返回 None。"""
    if not isinstance(value, str):
        errors.append(f"{where} 必须是 ISO8601 字符串，收到 {value!r}")
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        errors.append(f"{where} 不是合法 ISO8601 时间: {value!r}")
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _validate_targets(targets: Any, errors: list[str]) -> None:
    """targets 数组校验（与 schema 的 targets/items 对应）。"""
    if targets is None:
        return  # 缺失已在顶层报过
    if not isinstance(targets, list) or not targets:
        errors.append("targets 必须是非空数组")
        return
    for i, target in enumerate(targets):
        where = f"targets[{i}]"
        if not isinstance(target, dict):
            errors.append(f"{where} 必须是 object")
            continue
        for key in ("host", "ports", "kind"):
            if key not in target:
                errors.append(f"{where} 缺少必填字段 {key!r}")
        extra = sorted(set(target) - {"host", "ports", "kind"})
        if extra:
            errors.append(f"{where} 含未知字段: {extra!r}")
        host = target.get("host")
        if host is not None and (not isinstance(host, str)
                                 or not HOST_PATTERN.fullmatch(host)):
            errors.append(f"{where}.host 非法（不允许 scheme/路径/空白）: {host!r}")
        ports = target.get("ports")
        if ports is not None:
            if not isinstance(ports, list) or not ports:
                errors.append(f"{where}.ports 必须是非空数组")
            else:
                for port in ports:
                    if isinstance(port, bool) or not isinstance(port, int) \
                            or not 1 <= port <= 65535:
                        errors.append(
                            f"{where}.ports 含非法端口 {port!r}（需 1-65535 的整数）")
        kind = target.get("kind")
        if kind is not None and (not isinstance(kind, str) or kind not in HTTP_KINDS):
            errors.append(f"{where}.kind 只支持 http/https，收到 {kind!r}")


def _validate_paths(paths: Any, where: str, errors: list[str]) -> None:
    """curl_probe 的 paths 校验：非空、以 / 开头、过禁止字符检查。"""
    if paths is None:
        errors.append(f"{where} 缺少必填字段 'paths'")
        return
    if not isinstance(paths, list) or not paths:
        errors.append(f"{where}.paths 必须是非空数组")
        return
    for j, path in enumerate(paths):
        if not isinstance(path, str):
            errors.append(f"{where}.paths[{j}] 必须是字符串，收到 {path!r}")
            continue
        if not path.startswith("/"):
            errors.append(f"{where}.paths[{j}] 必须以 / 开头: {path!r}")
        problem = _arg_problem(path)
        if problem:
            errors.append(f"{where}.paths[{j}] {problem}: {path!r}")


def _validate_actions(actions: Any, errors: list[str]) -> None:
    """actions 数组校验：白名单、工具-字段配对、禁止字符、nuclei 必带 -json/-jsonl。"""
    if actions is None:
        return
    if not isinstance(actions, list) or not actions:
        errors.append("actions 必须是非空数组")
        return
    for i, action in enumerate(actions):
        where = f"actions[{i}]"
        if not isinstance(action, dict):
            errors.append(f"{where} 必须是 object")
            continue
        extra = sorted(set(action) - ACTION_KEYS)
        if extra:
            errors.append(f"{where} 含未知字段: {extra!r}")
        tool = action.get("tool")
        if tool is None:
            errors.append(f"{where} 缺少必填字段 'tool'")
            continue
        if not isinstance(tool, str) or tool not in ALLOWED_TOOLS:
            errors.append(f"{where}.tool 不在白名单 {'/'.join(ALLOWED_TOOLS)} 内，"
                          f"收到 {tool!r}")
            continue
        args = action.get("args")
        paths = action.get("paths")
        if tool == "curl_probe":
            if args is not None:
                errors.append(f"{where}: curl_probe 不接受 args，只接受 paths")
            _validate_paths(paths, where, errors)
            continue
        # nmap / nuclei：args 必填，paths 不允许
        if paths is not None:
            errors.append(f"{where}: {tool} 不接受 paths，只接受 args")
        if args is None:
            errors.append(f"{where} 缺少必填字段 'args'")
        elif not isinstance(args, list) or not args:
            errors.append(f"{where}.args 必须是非空数组")
        else:
            for j, arg in enumerate(args):
                if not isinstance(arg, str):
                    errors.append(f"{where}.args[{j}] 必须是字符串，收到 {arg!r}")
                    continue
                problem = _arg_problem(arg)
                if problem:
                    errors.append(f"{where}.args[{j}] {problem}: {arg!r}")
            # nuclei v3 起 JSONL 输出参数是 -jsonl（-json 在 v3 已移除，TASK-012）；
            # 两种 flag 输出格式相同（逐行 JSON），向后兼容 -json（v2 写法）
            if tool == "nuclei" and not ({"-json", "-jsonl"} & set(args)):
                errors.append(f"{where}: nuclei 动作必须带 -json 或 -jsonl"
                              "（findings 自动提取依赖逐行 JSONL 输出）")


def validate_task(task: Any, now: datetime | None = None) -> list[str]:
    """逐条校验任务 JSON（与 task-schema.json 一一对应），返回错误列表（空 = 通过）。

    now 由调用方注入以便测试（缺省用当前 UTC 时间）。任何错误都会让 main
    拒绝执行全部动作并只写 result.json 的 error 字段（fail closed）。
    """
    errors: list[str] = []
    if now is None:
        now = datetime.now(timezone.utc)
    if not isinstance(task, dict):
        return ["任务根节点必须是 JSON object"]
    for key in REQUIRED_KEYS:
        if key not in task:
            errors.append(f"缺少必填字段 {key!r}")
    for key in sorted(set(task) - set(REQUIRED_KEYS)):
        errors.append(f"未知字段 {key!r}（协议不允许额外字段）")

    for key in ("task_id", "engagement_id"):
        value = task.get(key)
        if value is None:
            continue  # 缺失已在顶层报过
        if not isinstance(value, str) or not ID_PATTERN.fullmatch(value):
            errors.append(f"{key} 须匹配 ^[A-Za-z0-9][A-Za-z0-9._-]{{0,63}}$，"
                          f"收到 {value!r}")

    _validate_targets(task.get("targets"), errors)
    _validate_actions(task.get("actions"), errors)

    rate_limit = task.get("rate_limit")
    if isinstance(rate_limit, dict):
        for key in ("rps_per_host", "max_requests_per_host"):
            value = rate_limit.get(key)
            if value is None:
                errors.append(f"rate_limit 缺少 {key!r}")
            elif isinstance(value, bool) or not isinstance(value, int) or value < 1:
                errors.append(f"rate_limit.{key} 须为 >=1 的整数，收到 {value!r}")
        extra = sorted(set(rate_limit) - {"rps_per_host", "max_requests_per_host"})
        if extra:
            errors.append(f"rate_limit 含未知字段: {extra!r}")
    elif rate_limit is not None:
        errors.append("rate_limit 必须是 object")

    created = _parse_iso8601(task.get("created_at"), "created_at", errors)
    expires = _parse_iso8601(task.get("expires_at"), "expires_at", errors)
    if created is not None and expires is not None:
        if expires <= created:
            errors.append(f"expires_at ({expires.isoformat()}) "
                          f"不晚于 created_at ({created.isoformat()})")
        if expires <= now:
            errors.append(f"任务已过期（expires_at={expires.isoformat()}），"
                          "拒绝执行（fail closed）")
    return errors


# ---------------------------------------------------------------------------
# nuclei findings 提取与 curl_probe 辅助（纯函数，供测试直测）
# ---------------------------------------------------------------------------

def parse_nuclei_findings(stdout: str, discovered_at: str) -> list[dict[str, Any]]:
    """从 nuclei -json/-jsonl（JSONL）输出逐行提取 findings。

    映射（对齐 secops_report 的 Finding 字段）：title=template-id（旧版
    templateID 兜底）、target=matched-at（url / matched 兜底）、severity=nuclei
    severity 小写（未知/缺失值归 info）、status 固定 observed、description=
    matcher 名、evidence=[{kind: log, summary: 原始 JSON 行前 200 字,
    artifact: ""}]。非 JSON 行（nuclei 告警等）跳过——原始行保留在 raw_output，
    不丢证据。
    """
    findings: list[dict[str, Any]] = []
    for raw_line in stdout.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if not isinstance(record, dict):
            continue
        info = record.get("info")
        info = info if isinstance(info, dict) else {}
        severity = str(info.get("severity", "")).strip().lower()
        if severity not in NUCLEI_SEVERITIES:
            severity = "info"  # 未知/缺失 severity 归 info，不抬高也不丢弃
        title = record.get("template-id") or record.get("templateID") \
            or "unknown-template"
        target = record.get("matched-at") or record.get("url") or ""
        if not target:
            matched = record.get("matched")
            if isinstance(matched, list) and matched:
                target = str(matched[0])
        findings.append({
            "title": str(title),
            "target": str(target),
            "severity": severity,
            "status": "observed",
            "description": str(record.get("matcher-name") or ""),
            "evidence": [{
                "kind": "log",
                "summary": line[:NUCLEI_EVIDENCE_SUMMARY_CHARS],
                "artifact": "",
            }],
            "discovered_at": discovered_at,
        })
    return findings


def build_curl_urls(targets: list[dict[str, Any]], paths: list[str]) -> list[str]:
    """对每个 http/https 目标的每个声明端口 × 每个 path 构造 GET URL（保序去重）。

    kind 已由校验限定为 http/https，直接作为 URL scheme。
    """
    urls: list[str] = []
    for target in targets:
        scheme = target["kind"]
        for port in target["ports"]:
            for path in paths:
                urls.append(f"{scheme}://{target['host']}:{port}{path}")
    return list(dict.fromkeys(urls))


def parse_curl_headers(header_block: str) -> tuple[int | None, list[str]]:
    """从 curl -D - 的响应头块解析（状态码, 原始头行列表）。

    状态行取最后一个 HTTP/ 前缀行（1xx 中间响应在前、最终响应在后）；
    解析不出数字时状态码为 None。头行原样保留（含顺序），供推理端研判。
    """
    status: int | None = None
    headers: list[str] = []
    for line in header_block.splitlines():
        text = line.strip()
        if not text:
            continue
        if text.upper().startswith("HTTP/"):
            try:
                status = int(text.split()[1])
            except (IndexError, ValueError):
                status = None
            continue
        headers.append(text)
    return status, headers


# ---------------------------------------------------------------------------
# 执行：参数列表 subprocess + 原始输出落盘 + 动作聚合
# ---------------------------------------------------------------------------

def _run_command(cmd: list[str], timeout_s: float) -> dict[str, Any]:
    """以参数列表执行单条命令（禁止 shell=True），超时预算用满即杀。

    返回 {exit_code, stdout, stderr, duration_s, timed_out}；exit_code 为
    None 表示进程被超时杀掉（不是正常退出码）。
    """
    if timeout_s <= 0:
        return {"exit_code": None, "stdout": "", "stderr": "",
                "duration_s": 0.0, "timed_out": True}
    started = time.monotonic()
    timed_out = False
    exit_code: int | None = None
    stdout = ""
    stderr = ""
    try:
        completed = subprocess.run(
            cmd, capture_output=True, check=False, timeout=timeout_s,
            encoding="utf-8", errors="replace")
        exit_code = completed.returncode
        stdout = completed.stdout or ""
        stderr = completed.stderr or ""
    except subprocess.TimeoutExpired as exc:
        # run() 已杀掉子进程；部分平台 partial output 可能是 bytes，统一归一
        timed_out = True
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode("utf-8", "replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", "replace")
    duration = time.monotonic() - started
    return {"exit_code": exit_code, "stdout": stdout, "stderr": stderr,
            "duration_s": duration, "timed_out": timed_out}


def _raw_dump(cmd: list[str], result: dict[str, Any]) -> str:
    """一条命令的原始输出落盘内容：命令行 + 退出状态 + stdout/stderr 分节。"""
    header = (f"$ {shlex.join(cmd)}\n"
              f"exit_code={result['exit_code']} timed_out={result['timed_out']} "
              f"duration_s={result['duration_s']:.3f}")
    return (f"{header}\n--- stdout ---\n{result['stdout']}"
            f"\n--- stderr ---\n{result['stderr']}")


def _write_raw(raw_dir: Path, name: str, content: str) -> str:
    """原始输出落盘，返回相对 out 目录的引用（raw/<name>，统一正斜杠）。"""
    raw_dir.mkdir(parents=True, exist_ok=True)
    (raw_dir / name).write_text(content, encoding="utf-8", newline="\n")
    return f"{RAW_DIR_NAME}/{name}"


def _run_action(
    index: int,
    action: dict[str, Any],
    targets: list[dict[str, Any]],
    deadline: float,
    run_fn: RunFn,
    raw_dir: Path,
    discovered_at: str,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """执行单个动作，返回 (动作结果条目, 提取的 findings)。

    run_fn 可注入（测试用 fake runner 替代真实 subprocess）；deadline 为
    time.monotonic() 时刻，整任务预算在"动作之间检查 + 单条命令超时"双重
    强制——单条命令最多拿到剩余预算，不会超出 --timeout 总量。
    """
    tool = action["tool"]
    entry: dict[str, Any] = {
        "tool": tool,
        "args": action.get("args", []),
        "exit_code": None,
        "duration_s": 0.0,
        "raw_output_ref": None,
    }
    if tool == "curl_probe":
        entry["paths"] = action["paths"]

    remaining = deadline - time.monotonic()
    if remaining <= 0:
        entry["error"] = "任务总超时已到，本动作未执行"
        return entry, []

    if tool in ("nmap", "nuclei"):
        cmd = [tool, *action["args"]]
        result = run_fn(cmd, remaining)
        entry["exit_code"] = result["exit_code"]
        entry["duration_s"] = result["duration_s"]
        entry["raw_output_ref"] = _write_raw(
            raw_dir, f"{index:02d}-{tool}.log", _raw_dump(cmd, result))
        findings: list[dict[str, Any]] = []
        if tool == "nuclei":
            # 自动 findings 只信 nuclei 的确定指纹；nmap 输出留给推理端研判
            findings = parse_nuclei_findings(result["stdout"], discovered_at)
        return entry, findings

    # curl_probe：对每个 (目标端口 × path) 发 GET，记录状态码 + 响应头。
    # 响应体丢弃（-o /dev/null），只留头与状态码——证据定性是"现象"，不是内容转储。
    # exit 18（CURLE_PARTIAL_FILE，TASK-012）：响应体截断但状态码/响应头已
    # 到手，算探测成功，请求条目与 raw 日志标注 partial；仅连接错误/超时算失败。
    urls = build_curl_urls(targets, action["paths"])
    if not urls:
        # 正常经 validate_task 的任务到不了这里（targets 非空且 kind 只有
        # http/https）；防御直调 _run_action 的误用，fail closed。
        entry["error"] = "targets 中没有可探测的 http/https 目标，curl_probe 无从执行"
        return entry, []
    requests: list[dict[str, Any]] = []
    chunks: list[str] = []
    started = time.monotonic()
    for url in urls:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            requests.append({
                "url": url, "exit_code": None, "status_code": None,
                "headers": [], "duration_s": 0.0,
                "error": "任务总超时已到，本请求未执行",
            })
            continue
        cmd = ["curl", "-sS", "-D", "-", "-o", "/dev/null", "--max-time",
               f"{min(remaining, float(CURL_REQUEST_TIMEOUT_SECONDS)):.3f}", url]
        result = run_fn(cmd, remaining)
        status_code, headers = parse_curl_headers(result["stdout"])
        partial = result["exit_code"] == CURL_PARTIAL_EXIT_CODE
        request: dict[str, Any] = {
            "url": url,
            "exit_code": result["exit_code"],
            "status_code": status_code,
            "headers": headers,
            "duration_s": result["duration_s"],
        }
        if partial:
            request["partial"] = True
            request["note"] = ("exit 18（CURLE_PARTIAL_FILE）：响应体截断，"
                               "状态码与响应头已获取")
        if result["timed_out"]:
            request["error"] = "请求超时（--max-time / 任务预算耗尽）"
        requests.append(request)
        chunk = _raw_dump(cmd, result)
        if partial:
            chunk += "\npartial=1（exit_code=18 CURLE_PARTIAL_FILE：响应体截断，响应头已完整获取）\n"
        chunks.append(chunk)
    entry["duration_s"] = time.monotonic() - started
    entry["requests"] = requests
    entry["raw_output_ref"] = _write_raw(
        raw_dir, f"{index:02d}-{tool}.log", "\n\n====\n\n".join(chunks))
    # 聚合（TASK-012）：exit 0 = 成功；exit 18 且状态码已到手 = 成功但截断
    # （partial）；其余（连接错误/超时/预算耗尽）= 失败，动作整体 exit 1。
    entry["exit_code"] = 0 if all(
        "error" not in r
        and (r["exit_code"] == 0
             or (r.get("partial") and r["status_code"] is not None))
        for r in requests) else 1
    if any(r.get("partial") for r in requests):
        entry["partial"] = True
    return entry, []


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------

def _write_result(out_path: Path, result: dict[str, Any]) -> None:
    """result.json 落盘（UTF-8、LF、ensure_ascii=False 便于人工核对）。"""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8", newline="\n")


def _now_iso() -> str:
    """当前 UTC 时间的 ISO8601 字符串（result 时间戳 / findings.discovered_at）。"""
    return datetime.now(timezone.utc).isoformat()


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="run_scan",
        description="扫描任务协议执行器：校验并逐条执行 task.json 的动作"
                    "（nmap/nuclei/curl_probe 白名单 + 参数列表执行），"
                    "聚合写 result.json 与 raw/ 原始输出。",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "示例：\n"
            "  python3 run_scan.py --task task.json --out result.json\n"
            "  python3 run_scan.py --task task.json --out result.json --timeout 300\n"
            "\n"
            "校验失败或任务过期 -> 不执行任何动作，result.json 只写 error（退出码 2）。\n"
            "自动 findings 只来自 nuclei -json/-jsonl 的模板命中（status=observed）；\n"
            "nmap/curl_probe 输出只进 raw/ 目录，由推理端研判。协议细节见\n"
            "deploy/protocol/README.md 与同目录 task-schema.json。\n"
            "退出码：0 全部成功；1 有动作失败/超时；2 校验失败/输入错误。\n"
        ),
    )
    parser.add_argument("--task", required=True, metavar="PATH",
                        help="task.json 路径（须符合同目录 task-schema.json）")
    parser.add_argument("--out", required=True, metavar="PATH",
                        help="result.json 输出路径（原始输出写在同目录 raw/ 下）")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_SECONDS,
                        metavar="SECONDS",
                        help="整任务预算秒数（默认 %(default)s）；"
                             "单条命令最多拿到剩余预算")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s",
                        stream=sys.stderr)
    args = _build_parser().parse_args(argv)
    if args.timeout <= 0:
        logger.error("--timeout 必须为正整数，收到 %d", args.timeout)
        return 2

    out_path = Path(args.out)
    started_at = _now_iso()
    deadline = time.monotonic() + args.timeout

    task: Any = None
    load_error: str | None = None
    try:
        task = json.loads(Path(args.task).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        load_error = f"task 文件读取/解析失败: {e}"

    errors = [load_error] if load_error else validate_task(task)
    if errors:
        # fail closed：一条动作都不执行，result 只带 error 供推理端排查
        result: dict[str, Any] = {
            "task_id": task.get("task_id") if isinstance(task, dict) else None,
            "started_at": started_at,
            "finished_at": _now_iso(),
            "error": "；".join(errors),
            "actions": [],
            "findings": [],
        }
        _write_result(out_path, result)
        logger.error("校验失败，未执行任何动作（fail closed）：%s", result["error"])
        return 2

    raw_dir = out_path.parent / RAW_DIR_NAME
    action_results: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    failed = False
    for index, action in enumerate(task["actions"]):
        entry, extracted = _run_action(
            index, action, task["targets"], deadline, _run_command,
            raw_dir, _now_iso())
        action_results.append(entry)
        findings.extend(extracted)
        if entry.get("exit_code") != 0:
            failed = True
            logger.warning("动作 %d（%s）未成功：exit_code=%s error=%s",
                           index, action["tool"], entry.get("exit_code"),
                           entry.get("error", "-"))

    result = {
        "task_id": task["task_id"],
        "started_at": started_at,
        "finished_at": _now_iso(),
        "actions": action_results,
        "findings": findings,
    }
    _write_result(out_path, result)
    logger.info("task=%s 完成：%d 个动作，%d 条 nuclei findings，结果见 %s",
                task["task_id"], len(action_results), len(findings), out_path)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
