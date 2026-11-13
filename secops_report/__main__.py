"""命令行入口（TASK-004）：python -m secops_report。

findings JSON -> 报告文件的一条命令流水线。dict -> Finding 的加载转换
放在本文件，不改动 TASK-003 的任何既有模块；渲染一律把原始 Finding
列表交给 render_markdown/render_sarif（由它们内部调 classify 定档），
绝不把 classify 的返回值传进去——TASK-003 的既定契约。

退出码契约：0 成功；2 输入错误（坏 JSON/缺必填字段/文件不可读等）；
3 --strict 下没有任何 confirmed；其他意外异常兜底 1。
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path
from typing import Any

from .classify import classify
from .models import Evidence, Finding, FindingStatus, Poc
from .render import render_markdown, render_sarif


class InputError(Exception):
    """输入不合法（坏 JSON/缺字段/文件不可读），对应退出码 2。"""


# Finding 无默认值的必填字段；evidence/poc 内部的必填在各自转换函数里查
_REQUIRED_FIELDS: tuple[str, ...] = ("title", "target", "severity", "status", "discovered_at")


def _evidence_from_dict(d: Any, where: str) -> Evidence:
    """dict -> Evidence：kind/summary 必填，artifact 可缺省，未知键忽略。"""
    if not isinstance(d, dict):
        raise ValueError(f"{where} 必须是 JSON 对象")
    missing = [k for k in ("kind", "summary") if k not in d]
    if missing:
        raise ValueError(f"{where} 缺少必填字段: {', '.join(missing)}")
    return Evidence(kind=d["kind"], summary=d["summary"], artifact=d.get("artifact", ""))


def _poc_from_dict(d: Any) -> Poc:
    """dict -> Poc：positive 必填，negative/cleanup_done 可缺省，未知键忽略。"""
    if not isinstance(d, dict):
        raise ValueError("poc 必须是 JSON 对象")
    if "positive" not in d:
        raise ValueError("poc 缺少必填字段: positive")
    cleanup_done = d.get("cleanup_done", False)
    if not isinstance(cleanup_done, bool):
        raise ValueError("poc.cleanup_done 必须是布尔值")
    negative = d.get("negative")
    return Poc(
        positive=_evidence_from_dict(d["positive"], "poc.positive"),
        negative=_evidence_from_dict(negative, "poc.negative")
        if negative is not None else None,
        cleanup_done=cleanup_done,
    )


def _finding_from_dict(d: Any) -> Finding:
    """单个 dict -> Finding 的递归转换，未知多余字段一律忽略。

    缺必填字段/字段类型不对/枚举值非法/时间格式非法都抛 ValueError，
    由加载循环补上"第几条"的位置信息后作为输入错误（退出码 2）上抛。
    """
    if not isinstance(d, dict):
        raise ValueError("必须是 JSON 对象")
    missing = [k for k in _REQUIRED_FIELDS if k not in d]
    if missing:
        raise ValueError(f"缺少必填字段: {', '.join(missing)}")
    for key in ("title", "target", "description", "id"):
        if key in d and not isinstance(d[key], str):
            raise ValueError(f"{key} 必须是字符串")
    try:
        discovered_at = datetime.fromisoformat(str(d["discovered_at"]))
    except ValueError as e:
        raise ValueError(
            f"discovered_at 不是合法的 ISO 8601 时间: {d['discovered_at']!r}") from e

    evidence_raw = d.get("evidence", [])
    if not isinstance(evidence_raw, list):
        raise ValueError("evidence 必须是 JSON 数组")
    extras: dict[str, Any] = {"description": d.get("description", "")}
    if "id" in d:
        extras["id"] = d["id"]
    poc_raw = d.get("poc")
    return Finding(
        title=d["title"],
        target=d["target"],
        severity=d["severity"],
        status=d["status"],
        discovered_at=discovered_at,
        evidence=[_evidence_from_dict(ev, f"evidence[{i}]")
                  for i, ev in enumerate(evidence_raw)],
        poc=_poc_from_dict(poc_raw) if poc_raw is not None else None,
        **extras,
    )


def _read_json(path: Path, label: str) -> Any:
    """读并解析 JSON 文件；不可读/语法错误统一转成 InputError。

    用 utf-8-sig 读取以兼容带 BOM 的文件（Windows 工具链常见）。
    """
    try:
        text = path.read_text(encoding="utf-8-sig")
    except OSError as e:
        raise InputError(f"无法读取 {label} 文件: {path}（{e}）") from e
    try:
        return json.loads(text)
    except json.JSONDecodeError as e:
        raise InputError(
            f"{label} 文件不是合法 JSON: {path}（第 {e.lineno} 行，{e.msg}）") from e


def _load_findings(path: Path) -> list[Finding]:
    """加载 findings 文件：顶层数组，逐条转换并标注"第几条"。"""
    raw = _read_json(path, "findings")
    if not isinstance(raw, list):
        raise InputError("findings 顶层必须是 JSON 数组")
    findings: list[Finding] = []
    for i, item in enumerate(raw, start=1):
        try:
            findings.append(_finding_from_dict(item))
        except ValueError as e:
            raise InputError(f"第 {i} 条 finding {e}") from e
    return findings


def _load_meta(path: Path | None) -> dict[str, Any]:
    """加载作业信息 JSON；未提供时返回空 dict（报告相应字段显示"未提供"）。"""
    if path is None:
        return {}
    raw = _read_json(path, "meta")
    if not isinstance(raw, dict):
        raise InputError("meta 顶层必须是 JSON 对象")
    return raw


def _build_parser() -> argparse.ArgumentParser:
    """构建 argparse 接口；用法见 TASK-004 任务书。"""
    parser = argparse.ArgumentParser(
        prog="python -m secops_report",
        description="黑盒发现报告生成器：findings JSON -> Markdown/SARIF 报告文件",
    )
    parser.add_argument(
        "findings",
        help="findings JSON 文件（顶层数组，每项一个 Finding 的字典形式）")
    parser.add_argument(
        "--meta",
        help="作业信息 JSON（engagement_id/authorized_by/period 等，缺省时相应字段显示为 未提供）")
    parser.add_argument(
        "--format", choices=("md", "sarif", "both"), default="both",
        help="输出格式：md/sarif/both，默认 both")
    parser.add_argument(
        "--out-prefix", default="report",
        help="输出文件路径前缀（可含目录，目录不存在自动创建），默认 report")
    parser.add_argument(
        "--strict", action="store_true",
        help="classify 后没有任何 confirmed 时退出码 3 且不生成报告（CI 卡无确认作业）")
    return parser


def _write_reports(findings: list[Finding], meta: dict[str, Any],
                   out_prefix: str, fmt: str) -> list[str]:
    """按 --format 落盘；输出目录不存在自动创建；返回生成的文件路径列表。

    契约：渲染器接收原始 Finding 列表，classify 由渲染器内部执行。
    """
    prefix = Path(out_prefix)
    prefix.parent.mkdir(parents=True, exist_ok=True)
    written: list[str] = []
    if fmt in ("md", "both"):
        md_path = Path(f"{prefix}.md")
        md_path.write_text(render_markdown(findings, meta), encoding="utf-8")
        written.append(str(md_path))
    if fmt in ("sarif", "both"):
        sarif_path = Path(f"{prefix}.sarif")
        sarif_path.write_text(render_sarif(findings), encoding="utf-8")
        written.append(str(sarif_path))
    return written


def _run(args: argparse.Namespace) -> int:
    """主流程：加载 -> classify 统计 ->（strict 卡口）-> 渲染落盘 -> 摘要。"""
    findings = _load_findings(Path(args.findings))
    meta = _load_meta(Path(args.meta) if args.meta else None)

    counts = Counter(classify(f).status for f in findings)
    confirmed = counts[FindingStatus.CONFIRMED]
    observed = counts[FindingStatus.OBSERVED]
    rejected = counts[FindingStatus.REJECTED]

    if args.strict and confirmed == 0:
        print("警告：classify 后没有任何 confirmed 发现"
              "（全部为 observed/rejected），--strict 下不生成报告", file=sys.stderr)
        return 3

    written = _write_reports(findings, meta, args.out_prefix, args.format)
    files = ", ".join(written)
    print(f"{len(findings)} findings "
          f"(confirmed={confirmed} observed={observed} rejected={rejected}) → {files}")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """命令行入口：解析参数并执行，返回进程退出码（契约见模块 docstring）。"""
    args = _build_parser().parse_args(argv)
    try:
        return _run(args)
    except InputError as e:
        print(f"错误：{e}", file=sys.stderr)
        return 2
    except Exception as e:
        # 退出码契约：意外异常兜底为 1，调用方只看退出码就能区分失败类别
        print(f"错误：意外失败（{type(e).__name__}: {e}）", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
