"""白盒 + 黑盒统一报告（TASK-018）：SARIF 代码推演与实测证据合并成一份交付物。

真实作业里白盒（hermes-security 的 SARIF）与黑盒（secops_report 的
findings.json）各出一份文件，交付要人工拼。本模块把两者合成统一报告：
Markdown 区分"白盒代码推演"与"黑盒实测"两章，SARIF 2.1.0 用两个 runs
分载两个来源，同接口命中的项在两侧做关联标注（correlationId）。

关联是启发式提示不是判定：黑盒 target 经 urlparse 取 host 与 path（path
长度 > 1 才参与，排除根路径的普遍命中），任一键是白盒 uri+message 文本的
子串即视为同接口命中（如黑盒 /ftp ↔ 白盒 src/routes/ftp.js）。每条黑盒/
白盒最多参与一条关联，按黑盒顺序、白盒顺序取首个命中；rejected 的黑盒
发现不参与关联、不进 SARIF results（与 render_sarif 口径一致）。

加载复用 __main__ 的 InputError / _load_findings（不复制代码）；白盒 SARIF
结构校验 fail closed——任何违规抛 InputError（CLI 退出码 2），不产出半份
报告。白盒 message/uri 属于证据文本，渲染前一律过 mask_text（与黑盒同规）。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlparse

from .__main__ import InputError, _load_findings
from .classify import classify
from .masking import mask_text
from .models import Finding, FindingStatus
from .render import _SARIF_SCHEMA, _SARIF_VERSION  # SARIF 常量复用（不重复声明）
from .render import render_blackbox_body, render_engagement_meta, sarif_results

_BLACKBOX_SOURCE = "blackbox"
_WHITEBOX_SOURCE = "whitebox"
# SARIF 2.1.0 的合法 level（缺省 note）；白名单外的值 fail closed
_SARIF_RESULT_LEVELS = frozenset({"error", "warning", "note", "none"})


# ---------------------------------------------------------------------------
# 白盒 SARIF 加载与归一（fail closed）
# ---------------------------------------------------------------------------

def load_whitebox_sarif(path: Path) -> dict[str, Any]:
    """读取白盒 SARIF 并归一成 {"tool": str, "results": [...]}。

    每个 result 归一为 {"rule_id", "level", "uri", "start_line", "message"}；
    message/uri 保留原文，渲染前由调用方统一过 mask_text。结构违规抛
    InputError（CLI 退出码 2）——宁可拒绝合并，也不带脏结构渲染。
    """
    try:
        text = path.read_text(encoding="utf-8-sig")
    except OSError as e:
        raise InputError(f"无法读取白盒 SARIF 文件: {path}（{e}）") from e
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as e:
        raise InputError(
            f"白盒 SARIF 不是合法 JSON: {path}（第 {e.lineno} 行，{e.msg}）") from e

    if not isinstance(doc, dict):
        raise InputError("白盒 SARIF 根节点必须是 JSON object")
    runs = doc.get("runs")
    if not isinstance(runs, list):
        raise InputError("白盒 SARIF 缺少 runs 数组（不是 SARIF 2.1.0 结构）")

    tool = "unknown-tool"
    results: list[dict[str, Any]] = []
    for i, run in enumerate(runs):
        if not isinstance(run, dict):
            raise InputError(f"runs[{i}] 必须是 object")
        tool_field = run.get("tool")
        driver = tool_field.get("driver") if isinstance(tool_field, dict) else None
        if isinstance(driver, dict) and isinstance(driver.get("name"), str) \
                and driver["name"]:
            tool = driver["name"]

        run_results = run.get("results") or []
        if not isinstance(run_results, list):
            raise InputError(f"runs[{i}].results 必须是数组")
        for j, res in enumerate(run_results):
            where = f"runs[{i}].results[{j}]"
            if not isinstance(res, dict):
                raise InputError(f"{where} 必须是 object")
            message = res.get("message")
            msg_text = message.get("text") if isinstance(message, dict) else None
            if not isinstance(msg_text, str):
                raise InputError(f"{where} 缺少 message.text（SARIF 必填）")
            level = res.get("level", "note")  # SARIF 2.1.0：level 缺省 note
            if level not in _SARIF_RESULT_LEVELS:
                raise InputError(
                    f"{where}.level 非法 {level!r}（合法: "
                    "error/warning/note/none）")
            rule_id = res.get("ruleId")
            if rule_id is not None and not isinstance(rule_id, str):
                raise InputError(f"{where}.ruleId 必须是字符串")

            uri, start_line = "", 1
            locations = res.get("locations")
            if locations is not None:
                if not isinstance(locations, list):
                    raise InputError(f"{where}.locations 必须是数组")
                if locations and isinstance(locations[0], dict):
                    phys = locations[0].get("physicalLocation")
                    if not isinstance(phys, dict):
                        continue
                    artifact = phys.get("artifactLocation")
                    if isinstance(artifact, dict) \
                            and isinstance(artifact.get("uri"), str):
                        uri = artifact["uri"]
                    # SARIF 2.1.0：region 与 artifactLocation 同级（都在
                    # physicalLocation 下）
                    region = phys.get("region")
                    if isinstance(region, dict) \
                            and isinstance(region.get("startLine"), int):
                        start_line = region["startLine"]

            results.append({
                "rule_id": rule_id if rule_id else "unknown-rule",
                "level": level,
                "uri": uri,
                "start_line": start_line,
                "message": msg_text,
            })
    return {"tool": tool, "results": results}


# ---------------------------------------------------------------------------
# 同接口命中关联（启发式）
# ---------------------------------------------------------------------------

def _correlation_keys(target: str) -> tuple[str, ...]:
    """黑盒 target 参与关联的键：urlparse 的 host 与 path（path 长度 > 1）。"""
    try:
        parsed = urlparse(target)
    except ValueError:
        return ()
    keys: list[str] = []
    if parsed.netloc:
        keys.append(parsed.netloc)
    if len(parsed.path) > 1:
        keys.append(parsed.path)
    return tuple(keys)


def correlate(findings: list[Finding],
              wb_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """同接口命中关联，返回 [{"id": "X-001", "finding": Finding, "wb_index": int}]。

    纯子串匹配的启发式（见模块 docstring 的威胁声明）：host/path 任一键是
    白盒 uri+message 的子串即命中。每条黑盒/白盒最多参与一条关联——多目标
    同名接口不会重复挂到同一条白盒上。
    """
    used_wb: set[int] = set()
    correlations: list[dict[str, Any]] = []
    for finding in findings:
        keys = _correlation_keys(finding.target)
        if not keys:
            continue
        hit = None
        for idx, wb in enumerate(wb_results):
            if idx in used_wb:
                continue
            haystack = f"{wb['uri']} {wb['message']}"
            if any(key in haystack for key in keys):
                hit = idx
                break
        if hit is None:
            continue
        used_wb.add(hit)
        correlations.append({
            "id": f"X-{len(correlations) + 1:03d}",
            "finding": finding,
            "wb_index": hit,
        })
    return correlations


# ---------------------------------------------------------------------------
# 合并渲染：Markdown（双章节 + 关联表）与 SARIF（双 runs + correlationId）
# ---------------------------------------------------------------------------

def render_merged_markdown(findings: list[Finding], whitebox: dict[str, Any],
                           engagement_meta: Mapping[str, Any]) -> str:
    """渲染统一 Markdown 报告：关联发现 -> 白盒代码推演 -> 黑盒实测。"""
    classified = [(f, classify(f)) for f in findings]
    active = [f for f, c in classified if c.status is not FindingStatus.REJECTED]
    correlations = correlate(active, whitebox["results"])

    engagement_id = engagement_meta.get("engagement_id") or "未提供"
    lines = [f"# 渗透测试综合报告（白盒+黑盒）（{engagement_id}）", ""]
    lines.append(render_engagement_meta(engagement_meta))

    lines.extend(["## 关联发现（同接口命中）", ""])
    if correlations:
        for c in correlations:
            wb = whitebox["results"][c["wb_index"]]
            location = wb["uri"] or "无位置信息"
            lines.append(
                f"- **{c['id']}** 黑盒 `{c['finding'].id}`"
                f"（`{c['finding'].target}`）↔ 白盒 `#{c['wb_index'] + 1}`"
                f" `{wb['rule_id']}`（`{mask_text(location)}`）")
    else:
        lines.append("（无同接口命中）")
    lines.append("")

    lines.extend([f"## 白盒代码推演（{whitebox['tool']}）", ""])
    if whitebox["results"]:
        lines.extend([
            "| # | ruleId | level | 位置 | message |",
            "| ---: | --- | --- | --- | --- |",
        ])
        for idx, wb in enumerate(whitebox["results"], start=1):
            location = wb["uri"] or "无位置信息"
            if wb["uri"]:
                location = f"{wb['uri']}:{wb['start_line']}"
            lines.append(
                f"| {idx} | `{wb['rule_id']}` | {wb['level']} "
                f"| `{mask_text(location)}` | {mask_text(wb['message'])} |")
    else:
        lines.append("（白盒 SARIF 无结果）")
    lines.append("")

    lines.extend(["## 黑盒实测", ""])
    lines.append(render_blackbox_body(findings, engagement_meta))
    return "\n".join(lines).rstrip() + "\n"


def render_merged_sarif(findings: list[Finding],
                        whitebox: dict[str, Any]) -> str:
    """渲染合并 SARIF 2.1.0：run[0] 黑盒（secops-report），run[1] 白盒。

    关联项在双方 result 的 properties.correlationId 上标注；两侧都带
    properties.source 来源标。rejected 的黑盒发现不进 results（与
    render_sarif 口径一致），白盒侧不做结论裁剪（代码推演没有三档语义）。
    """
    active = [f for f in findings
              if classify(f).status is not FindingStatus.REJECTED]
    correlations = correlate(active, whitebox["results"])
    corr_by_finding = {id(c["finding"]): c["id"] for c in correlations}
    corr_by_wb_index = {c["wb_index"]: c["id"] for c in correlations}

    blackbox_results = sarif_results(findings)
    for result, finding in zip(blackbox_results, active):
        properties: dict[str, str] = {"source": _BLACKBOX_SOURCE}
        correlation_id = corr_by_finding.get(id(finding))
        if correlation_id:
            properties["correlationId"] = correlation_id
        result["properties"] = properties

    whitebox_results: list[dict[str, Any]] = []
    for idx, wb in enumerate(whitebox["results"]):
        entry: dict[str, Any] = {
            "ruleId": wb["rule_id"],
            "level": wb["level"],
            "message": {"text": mask_text(wb["message"])},
            "properties": {"source": _WHITEBOX_SOURCE},
        }
        correlation_id = corr_by_wb_index.get(idx)
        if correlation_id:
            entry["properties"]["correlationId"] = correlation_id
        if wb["uri"]:
            entry["locations"] = [{
                "physicalLocation": {
                    "artifactLocation": {"uri": mask_text(wb["uri"])},
                    "region": {"startLine": wb["start_line"]},
                },
            }]
        whitebox_results.append(entry)

    doc = {
        "$schema": _SARIF_SCHEMA,
        "version": _SARIF_VERSION,
        "runs": [
            {"tool": {"driver": {"name": "secops-report"}},
             "results": blackbox_results},
            {"tool": {"driver": {"name": whitebox["tool"]}},
             "results": whitebox_results},
        ],
    }
    return json.dumps(doc, ensure_ascii=False, indent=2) + "\n"
