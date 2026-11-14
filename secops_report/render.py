"""Markdown 与 SARIF 2.1.0 渲染器（TASK-003 §1）。

两个渲染器都只消费 Finding：先过 classify 定档，confirmed 正文在前、
observed 在后、rejected 只进附录且不进 SARIF——渲染器不自己定结论，
一律以 classify 的结果为准。

输出前统一过 masking.mask_text（TASK-006 任务 3）：evidence 的 summary 与
artifact 内联文本、SARIF 的 title/target——证据片段里的凭证形态渲染进报告
就是二次泄露。
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from .classify import Classification, classify
from .masking import mask_text
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
    """一条证据的展示文本：summary 与 artifact 过 mask_text 后拼接。

    artifact 是落盘文件路径时不含凭据形态，过掩码是恒等变换；"inline:..."
    内联文本可能带响应头/token，必须脱敏（TASK-006 任务 3）。
    """
    artifact = ev.artifact or "无佐证材料"
    return f"[{ev.kind.value}] {mask_text(ev.summary)}（佐证：{mask_text(artifact)}）"


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


def render_engagement_meta(engagement_meta: Mapping[str, Any]) -> str:
    """作业信息块（TASK-018 抽取为公共函数）：授权方与作业周期两行。

    返回文本以空行结尾（"\n\n"），供合并报告（merge.py）与 render_markdown
    拼接后续章节。
    """
    lines = [
        "## 作业信息",
        "",
        f"- 授权方：{_meta(engagement_meta, 'authorized_by')}",
        f"- 作业周期：{_meta(engagement_meta, 'period')}",
        "",
    ]
    return "\n".join(lines) + "\n"


def render_blackbox_body(findings: list[Finding],
                         engagement_meta: Mapping[str, Any]) -> str:
    """黑盒报告正文（TASK-018 抽取为公共函数）：标题与作业信息块之外的全部。

    = 执行摘要 + Confirmed/Observed 分档正文 + Rejected 附录 + Coverage Gaps。
    render_markdown 与 merge.py 的统一报告共用本函数，保证两条出口的分档
    渲染永远一致。
    """
    classified = [(f, classify(f)) for f in findings]

    lines = []
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


def render_markdown(findings: list[Finding], engagement_meta: Mapping[str, Any]) -> str:
    """渲染整份 Markdown 报告。

    engagement_meta 约定的键（全部可缺省）：
    - engagement_id: 作业编号，进报告标题
    - authorized_by: 授权方
    - period: 作业周期
    - coverage_gaps: 未覆盖项列表，渲染成末尾 Coverage Gaps 章节
    """
    header = (
        f"# 黑盒渗透测试报告（{_meta(engagement_meta, 'engagement_id')}）\n"
        "\n"
        + render_engagement_meta(engagement_meta)
    )
    return header + render_blackbox_body(findings, engagement_meta)


def sarif_results(findings: list[Finding]) -> list[dict[str, Any]]:
    """SARIF results 数组的构建（TASK-018 抽取为公共函数）。

    rejected 的 finding 不进 results；level 按 _SARIF_LEVEL 映射；title/target
    过 mask_text。render_sarif 与 merge.py 的合并 SARIF 共用本函数。
    """
    results = []
    for f in findings:
        c = classify(f)
        if c.status is FindingStatus.REJECTED:
            continue
        results.append({
            "ruleId": f.id,
            "level": _SARIF_LEVEL[f.severity],
            "message": {"text": mask_text(f.title)},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": mask_text(f.target)},
                    "region": {"startLine": 1,
                               "snippet": {"text": mask_text(f.target)}},
                },
            }],
        })
    return results


def render_sarif(findings: list[Finding]) -> str:
    """渲染 SARIF 2.1.0 最小合法结构（runs[].tool.driver + runs[].results[]）。

    黑盒发现的“位置”是主机/URL 而非源码行号，所以 target 写进
    artifactLocation.uri，region 只给最小占位（startLine=1 + snippet 重复
    target，满足 spec 对 region 的形状要求）。SARIF 不携带 evidence 文本，
    其自由文本只有 title/target 两处，输出前同样过 mask_text（TASK-006 任务 3）。
    """
    doc = {
        "$schema": _SARIF_SCHEMA,
        "version": _SARIF_VERSION,
        "runs": [{
            "tool": {"driver": {"name": _TOOL_NAME}},
            "results": sarif_results(findings),
        }],
    }
    return json.dumps(doc, ensure_ascii=False, indent=2) + "\n"
