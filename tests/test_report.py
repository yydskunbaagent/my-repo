"""secops_report 的测试（TASK-003）：结论降级规则 + 两个渲染器。

自包含，不依赖 conftest 的任何夹具；纯内存构造 Finding，
不碰网络/时钟/文件系统。
"""

from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from secops_report import Evidence, Finding, Poc, classify, render_markdown, render_sarif  # noqa: E402


# ---- 构造辅助：默认给全套正负对照 + 清理完成，缺格的用例按需裁掉 ----------

DISCOVERED_AT = datetime(2026, 11, 14, 10, 30, 0)


def _ev(kind: str = "command", summary: str = "读取 /etc/passwd 成功",
        artifact: str = "evidence/F-001-01.txt") -> Evidence:
    return Evidence(kind=kind, summary=summary, artifact=artifact)


def _poc(negative: bool = True, cleanup: bool = True) -> Poc:
    return Poc(
        positive=_ev(),
        negative=_ev(kind="log", summary="对照组请求返回 404，无异常")
        if negative else None,
        cleanup_done=cleanup,
    )


def _finding(status: str = "confirmed", poc: Poc | None = None,
             severity: str = "high", fid: str = "F-001",
             title: str = "前台任意文件读取") -> Finding:
    return Finding(
        title=title,
        target="https://app.example.com/download",
        severity=severity,
        status=status,
        discovered_at=DISCOVERED_AT,
        description="下载接口未校验路径，可读取任意文件。",
        evidence=[_ev()],
        poc=poc,
        id=fid,
    )


# ---- 1-4：confirmed 的降级规则 ---------------------------------------------


def test_case1_confirmed_without_poc_downgrades():
    """用例 1：声称 confirmed + 无 PoC -> observed，带 reason。"""
    c = classify(_finding(status="confirmed", poc=None))
    assert c.status == "observed"
    assert c.reason, "降级必须带一句 reason"
    assert "observed" in c.reason


def test_case2_confirmed_positive_only_downgrades():
    """用例 2：声称 confirmed + 只有正对照 -> observed。"""
    c = classify(_finding(status="confirmed", poc=_poc(negative=False)))
    assert c.status == "observed"
    assert c.reason, "降级必须带一句 reason"


def test_case3_confirmed_full_poc_stays():
    """用例 3：正负对照齐全 + cleanup_done -> 保持 confirmed。"""
    c = classify(_finding(status="confirmed", poc=_poc(negative=True, cleanup=True)))
    assert c.status == "confirmed"


def test_case4_confirmed_without_cleanup_downgrades():
    """用例 4：负对照存在但清理未完成 -> observed。"""
    c = classify(_finding(status="confirmed", poc=_poc(negative=True, cleanup=False)))
    assert c.status == "observed"
    assert c.reason, "降级必须带一句 reason"


def test_case5_rejected_kept_as_is():
    """用例 5：rejected 原样保留，即便连 PoC 都没有。"""
    c = classify(_finding(status="rejected", poc=None))
    assert c.status == "rejected"


# ---- 6：markdown 渲染的分节与排序 ------------------------------------------


def test_case6_markdown_orders_sections_and_rejects_to_appendix():
    """用例 6：confirmed 在 observed 前，rejected 只出现在附录。"""
    confirmed = _finding(status="confirmed", poc=_poc(), fid="F-101")
    observed = _finding(status="observed", poc=None, fid="F-102")
    downgraded = _finding(status="confirmed", poc=None, fid="F-103")  # 会被降级
    rejected = _finding(status="rejected", poc=None, fid="F-104",
                        severity="medium", title="疑似 SQL 注入")
    md = render_markdown(
        [rejected, observed, downgraded, confirmed],  # 故意乱序输入
        {"engagement_id": "ENG-2026-001", "authorized_by": "security@example.com",
         "period": "2026-11-01 ~ 2026-11-14",
         "coverage_gaps": ["未覆盖 10.20.30.0/28 的 8080 端口"]},
    )

    h_confirmed = md.index("## Confirmed")
    h_observed = md.index("## Observed")
    h_appendix = md.index("## 附录：Rejected Candidates")
    # 分节顺序：Confirmed -> Observed -> 附录
    assert h_confirmed < h_observed < h_appendix
    # confirmed 排在 observed 前
    assert h_confirmed < md.index("F-101") < h_observed
    assert h_observed < md.index("F-102") < h_appendix
    # 声称 confirmed 但被降级的，落在 Observed 节
    assert h_observed < md.index("F-103") < h_appendix
    # rejected 全文只出现一次，且在附录头之后
    assert md.count("F-104") == 1
    assert md.index("F-104") > h_appendix
    # Coverage Gaps 在末尾且内容来自 engagement_meta
    h_gaps = md.index("## Coverage Gaps")
    assert h_appendix < h_gaps
    assert "未覆盖 10.20.30.0/28 的 8080 端口" in md[h_gaps:]


# ---- 7：SARIF 渲染 ----------------------------------------------------------


def test_case7_sarif_structure_and_severity_mapping():
    """用例 7：合法 JSON、$schema/version 正确、rejected 不进 results、映射正确。"""
    severities = [("critical", "F-201"), ("high", "F-202"), ("medium", "F-203"),
                  ("low", "F-204"), ("info", "F-205")]
    findings = [_finding(status="observed", severity=sev, fid=fid)
                for sev, fid in severities]
    findings.append(_finding(status="rejected", severity="high", fid="F-206"))
    data = json.loads(render_sarif(findings))

    assert data["version"] == "2.1.0"
    assert data["$schema"].endswith("sarif-schema-2.1.0.json")
    run = data["runs"][0]
    assert run["tool"]["driver"]["name"] == "secops-report"

    levels = {r["ruleId"]: r["level"] for r in run["results"]}
    assert "F-206" not in levels, "rejected 的 finding 不得进 SARIF"
    assert levels == {
        "F-201": "error", "F-202": "error",
        "F-203": "warning",
        "F-204": "note", "F-205": "note",
    }
    # target 写进 uri 与 region
    first = run["results"][0]["locations"][0]["physicalLocation"]
    assert first["artifactLocation"]["uri"] == "https://app.example.com/download"
    assert first["region"]["snippet"]["text"] == "https://app.example.com/download"


# ---- 8：空列表的健壮性 -------------------------------------------------------


def test_case8_empty_findings_render_with_coverage_gaps():
    """用例 8：空 findings 列表 -> 有 Coverage Gaps 章节，且不崩。"""
    md = render_markdown([], {"engagement_id": "ENG-EMPTY"})
    assert "## Coverage Gaps" in md
    assert "## 执行摘要" in md
    # coverage_gaps 键缺失时也不崩，给占位文案
    assert "（无未覆盖项记录）" in md
