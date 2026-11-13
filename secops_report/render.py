"""Markdown 与 SARIF 2.1.0 渲染器（TASK-003 §1）。

两个渲染器都只消费 Finding：先过 classify 定档，confirmed 正文在前、
observed 在后、rejected 只进附录且不进 SARIF——渲染器不自己定结论，
一律以 classify 的结果为准。
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from .classify import Classification, classify
from .models import Evidence, Finding, FindingStatus, Severity

_TOOL_NAME = "secops-report"
_SARIF_SCHEMA = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json"
)
_SARIF_VERSION = "2.1.0"

# severity -> SARIF level：critical/high→error，medium→warning，low/info→note
_SARIF_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

# 降级三档分组的展示顺序
_BODY_SECTIONS: tuple[tuple[str, FindingStatus], ...] = (
    ("Confirmed", FindingStatus.CONFIRMED),
    ("Observed", FindingStatus.OBSERVED),
)


def _meta(meta: Mapping[str, Any], key: str, default: str = "未提供") -> str:
    """读 engagement_meta 的字符串键，缺省给占位符，保证渲染不崩。"""
    value = meta.get(key)
    return str(value) if value else default


def _evidence_text(ev: Evidence) -> str:
    artifact = ev.artifact or "无佐证材料"
    return f"[{ev.kind.value}] {ev.summary}（佐证：{artifact}）"


def _summary_table(classified: list[tuple[Finding, Classification]]) -> list[str]:
    """执行摘要：按严重度 x 结论档位统计。"""
    counts: dict[Severity, dict[FindingStatus, int]] = {
        sev: {st: 0 for st in FindingStatus} for sev in Severity
    }
    for f, c in classified:
        counts[f.severity][c.status] += 1
    statuses = (FindingStatus.CONFIRMED, FindingStatus.OBSERVED, FindingStatus.REJECTED)

    lines = [
        "## 执行摘要",
        "",
        "| 严重度 | confirmed | observed | rejected | 小计 |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    totals = {st: 0 for st in statuses}
    for sev in Severity:
        row_total = 0
        cells = []
        for st in statuses:
            n = counts[sev][st]
            totals[st] += n
            row_total += n
            cells.append(str(n))
        lines.append(f"| {sev.value} | {' | '.join(cells)} | {row_total} |")
    grand = sum(totals.values())
    cells = " | ".join(str(totals[st]) for st in statuses)
    lines.append(f"| **合计** | {cells} | {grand} |")
    return lines


def _render_finding(f: Finding, c: Classification) -> list[str]:
    """正文里的一条发现：元信息 + 描述 + 证据列表 + PoC 正负对照。"""
    lines = [f"### {f.id} {f.title}", ""]
    lines.append(f"- 目标：`{f.target}`")
    lines.append(f"- 严重度：{f.severity.value}")
    lines.append(f"- 最终结论：{c.status.value}")
    lines.append(f"- 结论说明：{c.reason}")
    lines.append(f"- 发现时间：{f.discovered_at.isoformat()}")
    lines.append("")
    if f.description:
        lines.extend([f.description, ""])

    lines.extend(["**证据**", ""])
    if f.evidence:
        lines.extend(f"- {_evidence_text(ev)}" for ev in f.evidence)
    else:
        lines.append("- （未附证据）")
    lines.append("")

    lines.extend(["**PoC 正负对照**", ""])
    if f.poc is None:
        lines.append("- 未附 PoC")
    else:
        lines.append(f"- 正对照：{_evidence_text(f.poc.positive)}")
        negative = _evidence_text(f.poc.negative) if f.poc.negative else "未提供"
        lines.append(f"- 负对照：{negative}")
        lines.append(f"- 清理：{'已完成' if f.poc.cleanup_done else '未完成'}")
    lines.append("")
    return lines


def _render_rejected(f: Finding) -> list[str]:
    """附录里的一条否决记录：一笔带过，不展开证据。"""
    lines = [f"- **{f.id}** {f.title}（{f.severity.value}）— `{f.target}`"]
    if f.description:
        lines.append(f"  - 描述：{f.description}")
    lines.append("  - 处理：已否决，不进正文、不进 SARIF")
    return lines


def render_markdown(findings: list[Finding], engagement_meta: Mapping[str, Any]) -> str:
    """渲染整份 Markdown 报告。

    engagement_meta 约定的键（全部可缺省）：
    - engagement_id: 作业编号，进报告标题
    - authorized_by: 授权方
    - period: 作业周期
    - coverage_gaps: 未覆盖项列表，渲染成末尾 Coverage Gaps 章节
    """
    classified = [(f, classify(f)) for f in findings]

    lines = [f"# 黑盒渗透测试报告（{_meta(engagement_meta, 'engagement_id')}）", ""]
    lines.extend([
        "## 作业信息",
        "",
        f"- 授权方：{_meta(engagement_meta, 'authorized_by')}",
        f"- 作业周期：{_meta(engagement_meta, 'period')}",
        "",
    ])
    lines.extend(_summary_table(classified))
    lines.append("")

    grouped = {
        st: [(f, c) for f, c in classified if c.status is st]
        for st in (FindingStatus.CONFIRMED, FindingStatus.OBSERVED)
    }
    for heading, st in _BODY_SECTIONS:
        lines.extend([f"## {heading}", ""])
        items = grouped[st]
        if items:
            for f, c in items:
                lines.extend(_render_finding(f, c))
        else:
            lines.extend(["（无）", ""])

    lines.extend(["## 附录：Rejected Candidates", ""])
    rejected = [(f, c) for f, c in classified if c.status is FindingStatus.REJECTED]
    if rejected:
        for f, _ in rejected:
            lines.extend(_render_rejected(f))
    else:
        lines.extend(["（无）", ""])

    gaps = engagement_meta.get("coverage_gaps") or []
    lines.extend(["## Coverage Gaps", ""])
    if gaps:
        lines.extend(f"- {gap}" for gap in gaps)
    else:
        lines.extend(["- （无未覆盖项记录）", ""])

    return "\n".join(lines).rstrip() + "\n"


def render_sarif(findings: list[Finding]) -> str:
    """渲染 SARIF 2.1.0 最小合法结构（runs[].tool.driver + runs[].results[]）。

    rejected 的 finding 不进 results。黑盒发现的“位置”是主机/URL 而非
    源码行号，所以 target 写进 artifactLocation.uri，region 只给最小占位
    （startLine=1 + snippet 重复 target，满足 spec 对 region 的形状要求）。
    """
    results = []
    for f in findings:
        c = classify(f)
        if c.status is FindingStatus.REJECTED:
            continue
        results.append({
            "ruleId": f.id,
            "level": _SARIF_LEVEL[f.severity],
            "message": {"text": f.title},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.target},
                    "region": {"startLine": 1, "snippet": {"text": f.target}},
                },
            }],
        })
    doc = {
        "$schema": _SARIF_SCHEMA,
        "version": _SARIF_VERSION,
        "runs": [{
            "tool": {"driver": {"name": _TOOL_NAME}},
            "results": results,
        }],
    }
    return json.dumps(doc, ensure_ascii=False, indent=2) + "\n"
