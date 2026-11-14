"""白盒 + 黑盒统一报告的测试（TASK-018）：merge 模块 + CLI 合并模式。

自包含，不依赖 conftest 夹具；白盒 SARIF 与 findings 以常量内嵌，
不碰网络/时钟，文件全部落在 pytest 的 tmp_path 里。
"""

from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from secops_report.__main__ import InputError, main  # noqa: E402
from secops_report.merge import (  # noqa: E402
    correlate,
    load_whitebox_sarif,
    render_merged_markdown,
    render_merged_sarif,
)
from secops_report.models import Evidence, Finding, Poc  # noqa: E402

DISCOVERED_AT = datetime(2026, 11, 14, 10, 30, 0)

# ---- 白盒 SARIF 常量：hermes-security 风格的最小合法结构 ----------------------

WB_SARIF: dict[str, Any] = {
    "version": "2.1.0",
    "runs": [{
        "tool": {"driver": {"name": "hermes-security"}},
        "results": [
            {"ruleId": "py/insecure-deserialization", "level": "error",
             "message": {"text": "反序列化不可信数据（上下文含 "
                                 "Bearer sk-abcdef1234567890）"},
             "locations": [{"physicalLocation": {
                 "artifactLocation": {"uri": "src/routes/ftp.js"},
                 "region": {"startLine": 42}}}]},
            {"ruleId": "py/cors-wildcard", "level": "warning",
             "message": {"text": "CORS 允许任意来源"},
             "locations": [{"physicalLocation": {
                 "artifactLocation": {"uri": "src/app.js"},
                 "region": {"startLine": 10}}}]},
        ],
    }],
}

WB_RESULTS = WB_SARIF["runs"][0]["results"]


def _ev(summary: str = "读取 /etc/passwd 成功") -> Evidence:
    return Evidence(kind="command", summary=summary)


def _poc() -> Poc:
    """正负对照齐全 + 清理完成：够格 confirmed。"""
    return Poc(positive=_ev(),
               negative=Evidence(kind="log", summary="对照组请求返回 404"),
               cleanup_done=True)


def _finding(fid: str, target: str, status: str,
             poc: Poc | None = None) -> Finding:
    return Finding(title=f"发现 {fid}", target=target, severity="medium",
                   status=status, discovered_at=DISCOVERED_AT,
                   description="", evidence=[_ev()], poc=poc, id=fid)


def _findings() -> list[Finding]:
    """F-001 confirmed（/ftp 路径，命中白盒 ftp.js）；F-002 observed（根路径，
    无 path 键不命中）；F-003 rejected（不参与关联、不进 SARIF）。"""
    return [
        _finding("F-001", "http://10.10.0.100:3000/ftp", "confirmed", _poc()),
        _finding("F-002", "http://10.10.0.100:3000/", "observed"),
        _finding("F-003", "http://10.10.0.100:3000/ftp", "rejected"),
    ]


def _meta() -> dict[str, Any]:
    return {"engagement_id": "ENG-DEMO-001", "authorized_by": "ops@example.com",
            "period": "2026-11-14"}


# ---- correlate：同接口命中启发式 ---------------------------------------------

def test_correlate_path_hit(tmp_path):
    wb_results = _load_whitebox_sarif_dict(WB_SARIF, tmp_path)["results"]
    correlations = correlate(_findings()[:2], wb_results)
    assert len(correlations) == 1
    assert correlations[0]["id"] == "X-001"
    assert correlations[0]["finding"].id == "F-001"
    assert correlations[0]["wb_index"] == 0


def test_correlate_root_path_does_not_hit(tmp_path):
    # 根路径 "/" 不参与关联（排除普遍命中）；host 键在白盒 uri/message 里
    # 也不存在 -> F-002 无关联
    wb_results = _load_whitebox_sarif_dict(WB_SARIF, tmp_path)["results"]
    correlations = correlate([_findings()[1]], wb_results)
    assert correlations == []


def test_correlate_max_one_per_finding(tmp_path):
    # correlate 本身不做 rejected 过滤（口径由调用方统一），这里验证每个
    # 黑盒/白盒最多参与一条关联：两条同 target 的 confirmed 只中第一条
    wb_results = _load_whitebox_sarif_dict(WB_SARIF, tmp_path)["results"]
    f_a = _finding("F-001", "http://h.test/ftp", "confirmed", _poc())
    f_b = _finding("F-002", "http://h.test/ftp", "confirmed", _poc())
    correlations = correlate([f_a, f_b], wb_results)
    assert [c["finding"].id for c in correlations] == ["F-001"]
    assert [c["wb_index"] for c in correlations] == [0]


# ---- 合并 Markdown -----------------------------------------------------------

def test_merged_markdown_sections(tmp_path):
    findings = _findings()
    md = render_merged_markdown(findings,
                                _load_whitebox_sarif_dict(WB_SARIF, tmp_path),
                                _meta())
    assert "# 渗透测试综合报告（白盒+黑盒）（ENG-DEMO-001）" in md
    assert "## 关联发现（同接口命中）" in md
    assert "- **X-001** 黑盒 `F-001`" in md
    assert "src/routes/ftp.js" in md
    assert "## 白盒代码推演（hermes-security）" in md
    assert "| 1 | `py/insecure-deserialization` | error |" in md
    assert "## 黑盒实测" in md
    assert "## 执行摘要" in md
    assert "## 附录：Rejected Candidates" in md
    assert "**F-003**" in md  # rejected 只进附录


def test_merged_markdown_masks_credentials(tmp_path):
    md = render_merged_markdown(_findings(),
                                _load_whitebox_sarif_dict(WB_SARIF, tmp_path),
                                _meta())
    assert "sk-abcdef1234567890" not in md
    assert "sk-a***90" in md  # 白盒 message 里的凭据已掩码


def _load_whitebox_sarif_dict(doc: dict[str, Any], tmp_path: Path):
    """测试辅助：常量 SARIF dict -> 经 load_whitebox_sarif 的归一结构。"""
    path = tmp_path / "wb.sarif"
    path.write_text(json.dumps(doc), encoding="utf-8")
    return load_whitebox_sarif(path)


# ---- 合并 SARIF ---------------------------------------------------------------

def test_merged_sarif_two_runs_with_correlation(tmp_path):
    whitebox = _load_whitebox_sarif_dict(WB_SARIF, tmp_path)
    sarif = json.loads(render_merged_sarif(_findings(), whitebox))
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 2
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "secops-report"
    assert sarif["runs"][1]["tool"]["driver"]["name"] == "hermes-security"

    blackbox_results = sarif["runs"][0]["results"]
    # rejected（F-003）不进 results：只剩 F-001/F-002
    assert [r["ruleId"] for r in blackbox_results] == ["F-001", "F-002"]
    assert blackbox_results[0]["properties"] == {
        "source": "blackbox", "correlationId": "X-001"}
    assert blackbox_results[1]["properties"] == {"source": "blackbox"}

    whitebox_results = sarif["runs"][1]["results"]
    assert len(whitebox_results) == 2
    assert whitebox_results[0]["properties"] == {
        "source": "whitebox", "correlationId": "X-001"}
    assert whitebox_results[1]["properties"] == {"source": "whitebox"}
    assert whitebox_results[0]["ruleId"] == "py/insecure-deserialization"
    assert whitebox_results[0]["locations"][0]["physicalLocation"][
        "artifactLocation"]["uri"] == "src/routes/ftp.js"
    assert whitebox_results[0]["locations"][0]["physicalLocation"][
        "region"]["startLine"] == 42
    # 凭据不进 SARIF
    assert "sk-abcdef1234567890" not in json.dumps(sarif)


def test_merged_sarif_no_correlation(tmp_path):
    whitebox = _load_whitebox_sarif_dict(WB_SARIF, tmp_path)
    sarif = json.loads(render_merged_sarif([_findings()[1]], whitebox))
    assert sarif["runs"][0]["results"][0]["properties"] == {"source": "blackbox"}
    assert all("correlationId" not in r["properties"]
               for r in sarif["runs"][1]["results"])


# ---- load_whitebox_sarif：fail closed ----------------------------------------

def _write_wb(tmp_path: Path, doc: Any) -> Path:
    path = tmp_path / "wb.sarif"
    path.write_text(doc if isinstance(doc, str) else json.dumps(doc),
                    encoding="utf-8")
    return path


@pytest.mark.parametrize("doc,fragment", [
    ("{not-json", "不是合法 JSON"),
    ([1, 2], "根节点必须是 JSON object"),
    ({"version": "2.1.0"}, "缺少 runs 数组"),
    ({"runs": [{"tool": {"driver": {"name": "t"}}, "results": [{}]}]},
     "缺少 message.text"),
    ({"runs": [{"results": [{"message": {"text": "x"}, "level": "fatal"}]}]},
     "level 非法"),
    ({"runs": [{"results": [{"message": {"text": "x"}, "ruleId": 1}]}]},
     "ruleId 必须是字符串"),
])
def test_load_whitebox_sarif_fail_closed(tmp_path, doc, fragment):
    with pytest.raises(InputError) as excinfo:
        load_whitebox_sarif(_write_wb(tmp_path, doc))
    assert fragment in str(excinfo.value)


def test_load_whitebox_sarif_defaults(tmp_path):
    # level 缺省 note、无 locations 允许、ruleId 缺省 unknown-rule
    doc = {"runs": [{"results": [{"message": {"text": "无位置的结果"}}]}]}
    whitebox = load_whitebox_sarif(_write_wb(tmp_path, doc))
    assert whitebox["tool"] == "unknown-tool"
    assert whitebox["results"][0]["level"] == "note"
    assert whitebox["results"][0]["rule_id"] == "unknown-rule"
    assert whitebox["results"][0]["uri"] == ""
    assert whitebox["results"][0]["start_line"] == 1


# ---- CLI 接线：--whitebox-sarif ----------------------------------------------

FINDINGS_JSON: list[dict[str, Any]] = [
    {"title": "前台任意文件读取", "target": "http://10.10.0.100:3000/ftp",
     "severity": "medium", "status": "confirmed",
     "discovered_at": "2026-11-14T10:30:00",
     "evidence": [{"kind": "command", "summary": "读取 /etc/passwd 成功",
                   "artifact": "evidence/F-001-01.txt"}],
     "poc": {"positive": {"kind": "command", "summary": "正对照"},
             "negative": {"kind": "log", "summary": "负对照"},
             "cleanup_done": True}},
    {"title": "CORS 全开", "target": "http://10.10.0.100:3000/",
     "severity": "low", "status": "observed",
     "discovered_at": "2026-11-14T10:31:00",
     "evidence": [{"kind": "log", "summary": "ACAO: *", "artifact": ""}]},
]


def test_cli_merge_mode(tmp_path, capsys):
    findings_path = tmp_path / "findings.json"
    findings_path.write_text(json.dumps(FINDINGS_JSON), encoding="utf-8")
    wb_path = _write_wb(tmp_path, WB_SARIF)
    prefix = tmp_path / "reports" / "ENG"

    exit_code = main([str(findings_path), "--whitebox-sarif", str(wb_path),
                      "--out-prefix", str(prefix)])
    assert exit_code == 0
    assert "merged; " in capsys.readouterr().out

    md = (tmp_path / "reports" / "ENG.md").read_text(encoding="utf-8")
    assert "# 渗透测试综合报告（白盒+黑盒）" in md
    assert "## 白盒代码推演（hermes-security）" in md
    assert "## 黑盒实测" in md

    sarif = json.loads(
        (tmp_path / "reports" / "ENG.sarif").read_text(encoding="utf-8"))
    assert len(sarif["runs"]) == 2


def test_cli_default_mode_unchanged(tmp_path, capsys):
    findings_path = tmp_path / "findings.json"
    findings_path.write_text(json.dumps(FINDINGS_JSON), encoding="utf-8")
    prefix = tmp_path / "reports" / "ENG"

    exit_code = main([str(findings_path), "--out-prefix", str(prefix)])
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "merged" not in out  # 缺省摘要行与 TASK-004 交付逐字一致

    md = (tmp_path / "reports" / "ENG.md").read_text(encoding="utf-8")
    assert md.startswith("# 黑盒渗透测试报告")
    assert "白盒代码推演" not in md

    sarif = json.loads(
        (tmp_path / "reports" / "ENG.sarif").read_text(encoding="utf-8"))
    assert len(sarif["runs"]) == 1


def test_cli_bad_whitebox_sarif_exit_2(tmp_path, capsys):
    findings_path = tmp_path / "findings.json"
    findings_path.write_text(json.dumps(FINDINGS_JSON), encoding="utf-8")
    wb_path = _write_wb(tmp_path, {"version": "2.1.0"})  # 缺 runs

    exit_code = main([str(findings_path), "--whitebox-sarif", str(wb_path),
                      "--out-prefix", str(tmp_path / "reports" / "ENG")])
    assert exit_code == 2
    assert "缺少 runs 数组" in capsys.readouterr().err
    assert not (tmp_path / "reports" / "ENG.md").exists()  # 不产半份报告
