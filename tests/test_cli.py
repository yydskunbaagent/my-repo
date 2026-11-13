"""命令行入口的测试（TASK-004）：python -m secops_report 的行为规格。

自包含，不依赖 conftest 的任何夹具；findings 数据以常量内嵌在本文件，
直接调用 main()（比 subprocess 快），不碰网络/时钟，所有输入输出
文件都落在 pytest 的 tmp_path 里。
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from secops_report.__main__ import main  # noqa: E402


# ---- findings 数据常量：字段名与 TASK-003 的 Finding dataclass 一一对应 ------

DISCOVERED_AT = "2026-11-14T10:30:00"


def _ev(kind: str = "command", summary: str = "读取 /etc/passwd 成功",
        artifact: str = "evidence/F-001-01.txt") -> dict[str, str]:
    """Evidence 的字典形式。"""
    return {"kind": kind, "summary": summary, "artifact": artifact}


def _full_poc() -> dict[str, Any]:
    """正负对照齐全 + 清理完成：够格 confirmed 的 PoC 字典形式。"""
    return {
        "positive": _ev(),
        "negative": _ev(kind="log", summary="对照组请求返回 404，无异常"),
        "cleanup_done": True,
    }


CONFIRMED: dict[str, Any] = {
    "title": "前台任意文件读取",
    "target": "https://app.example.com/download",
    "severity": "high",
    "status": "confirmed",
    "discovered_at": DISCOVERED_AT,
    "description": "下载接口未校验路径，可读取任意文件。",
    "evidence": [_ev()],
    "poc": _full_poc(),
    "id": "F-001",
}

OBSERVED: dict[str, Any] = {
    "title": "疑似目录列表泄露",
    "target": "https://app.example.com/backup/",
    "severity": "medium",
    "status": "observed",
    "discovered_at": DISCOVERED_AT,
    "evidence": [_ev(kind="http_pair", summary="返回目录索引页面")],
    "id": "F-002",
}


def _write_json(tmp_path: Path, name: str, data: Any) -> Path:
    """把数据写成 JSON 文件（测试输入，落在 tmp_path）。"""
    path = tmp_path / name
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    return path


# ---- 1：正常 both：两个文件都生成，stdout 摘要含 confirmed=1 -----------------


def test_case1_both_writes_two_files_and_summary(tmp_path, capsys):
    """用例 1：默认 both 出 .md + .sarif，目录自动创建，摘要行带档位统计。"""
    findings_file = _write_json(tmp_path, "findings.json", [CONFIRMED, OBSERVED])
    prefix = tmp_path / "reports" / "ENG-001"
    rc = main([str(findings_file), "--out-prefix", str(prefix)])

    assert rc == 0
    md_path = tmp_path / "reports" / "ENG-001.md"
    sarif_path = tmp_path / "reports" / "ENG-001.sarif"
    assert md_path.exists() and sarif_path.exists()
    out = capsys.readouterr().out
    assert "2 findings" in out
    assert "confirmed=1" in out
    assert "observed=1" in out


# ---- 2：坏 JSON -> 退出码 2 + stderr 提示 ------------------------------------


def test_case2_broken_json_is_input_error(tmp_path, capsys):
    """用例 2：语法错误的 findings 文件 -> 退出码 2，stderr 有提示。"""
    bad = tmp_path / "bad.json"
    bad.write_text('{"findings": [', encoding="utf-8")
    rc = main([str(bad), "--out-prefix", str(tmp_path / "out" / "x")])

    assert rc == 2
    assert capsys.readouterr().err.strip(), "stderr 必须有提示"


# ---- 3：缺必填字段 -> 退出码 2 且定位到"第几条" -------------------------------


def test_case3_missing_required_field_reports_position(tmp_path, capsys):
    """用例 3：第 2 条缺 target -> 退出码 2，提示含"第 2 条"与字段名。"""
    broken = {**OBSERVED}
    del broken["target"]
    findings_file = _write_json(tmp_path, "findings.json", [CONFIRMED, broken])
    rc = main([str(findings_file), "--out-prefix", str(tmp_path / "out" / "x")])

    assert rc == 2
    err = capsys.readouterr().err
    assert "第 2 条" in err
    assert "target" in err


# ---- 4：--strict 全 observed -> 退出码 3 -------------------------------------


def test_case4_strict_no_confirmed_exit_3(tmp_path, capsys):
    """用例 4：--strict 且没有任何 confirmed -> 退出码 3 + stderr 警告，不出文件。"""
    findings_file = _write_json(tmp_path, "findings.json", [OBSERVED])
    prefix = tmp_path / "reports" / "ENG-002"
    rc = main([str(findings_file), "--out-prefix", str(prefix), "--strict"])

    assert rc == 3
    err = capsys.readouterr().err
    assert "confirmed" in err, "stderr 必须有一行警告"
    assert not (tmp_path / "reports" / "ENG-002.md").exists()
    assert not (tmp_path / "reports" / "ENG-002.sarif").exists()


# ---- 5：--format md 只出 .md -------------------------------------------------


def test_case5_format_md_only(tmp_path):
    """用例 5：--format md 只生成 .md，不生成 .sarif。"""
    findings_file = _write_json(tmp_path, "findings.json", [CONFIRMED])
    prefix = tmp_path / "out" / "ENG-003"
    rc = main([str(findings_file), "--out-prefix", str(prefix), "--format", "md"])

    assert rc == 0
    assert (tmp_path / "out" / "ENG-003.md").exists()
    assert not (tmp_path / "out" / "ENG-003.sarif").exists()


# ---- 6：空 findings 数组 -> 正常退出，生成空报告 ------------------------------


def test_case6_empty_findings_still_renders(tmp_path, capsys):
    """用例 6：空数组 -> 退出码 0，空报告仍覆盖执行摘要/Coverage Gaps 语义。"""
    findings_file = _write_json(tmp_path, "findings.json", [])
    prefix = tmp_path / "out" / "ENG-EMPTY"
    rc = main([str(findings_file), "--out-prefix", str(prefix)])

    assert rc == 0
    md = (tmp_path / "out" / "ENG-EMPTY.md").read_text(encoding="utf-8")
    assert "## 执行摘要" in md
    assert "## Coverage Gaps" in md
    sarif = json.loads(
        (tmp_path / "out" / "ENG-EMPTY.sarif").read_text(encoding="utf-8"))
    assert sarif["runs"][0]["results"] == []
    assert "0 findings" in capsys.readouterr().out


# ---- 7：cleanup_done=False 的 confirmed 降级进 Observed 章节 -----------------


def test_case7_uncleaned_poc_downgrades_to_observed_section(tmp_path, capsys):
    """用例 7：负对照在但清理未完成 -> 降为 observed，条目出现在 Observed 章节。"""
    finding = {
        **CONFIRMED,
        "poc": {
            "positive": _ev(),
            "negative": _ev(kind="log", summary="对照组请求返回 404，无异常"),
            "cleanup_done": False,
        },
        "id": "F-009",
    }
    findings_file = _write_json(tmp_path, "findings.json", [finding])
    prefix = tmp_path / "out" / "ENG-004"
    rc = main([str(findings_file), "--out-prefix", str(prefix)])

    assert rc == 0
    md = (tmp_path / "out" / "ENG-004.md").read_text(encoding="utf-8")
    h_confirmed = md.index("## Confirmed")
    h_observed = md.index("## Observed")
    assert h_confirmed < h_observed
    assert md.index("F-009") > h_observed, "降级条目必须出现在 Observed 章节"
    assert "cleanup" in md[h_observed:], "结论说明应点出清理未完成"
    assert "confirmed=0" in capsys.readouterr().out


# ---- 补充：--meta 透传与缺省占位 ----------------------------------------------


def test_extra_meta_passthrough_and_default_placeholder(tmp_path):
    """--meta 原样进报告；缺省时作业信息章节显示"未提供"。"""
    findings_file = _write_json(tmp_path, "findings.json", [CONFIRMED])
    meta_file = _write_json(tmp_path, "meta.json", {
        "engagement_id": "ENG-META",
        "authorized_by": "security@example.com",
        "period": "2026-11-01 ~ 2026-11-14",
    })

    prefix_a = tmp_path / "out" / "with-meta"
    assert main([str(findings_file), "--meta", str(meta_file),
                 "--out-prefix", str(prefix_a)]) == 0
    md = (tmp_path / "out" / "with-meta.md").read_text(encoding="utf-8")
    assert "ENG-META" in md
    assert "security@example.com" in md

    prefix_b = tmp_path / "out" / "no-meta"
    assert main([str(findings_file), "--out-prefix", str(prefix_b)]) == 0
    md = (tmp_path / "out" / "no-meta.md").read_text(encoding="utf-8")
    assert "未提供" in md


# ---- 补充：未知多余字段忽略 ----------------------------------------------------


def test_extra_unknown_fields_ignored(tmp_path):
    """findings 条目里混入未知字段 -> 忽略，不影响转换与渲染。"""
    noisy = {**CONFIRMED, "unknown_field": "随便什么", "another": 42}
    findings_file = _write_json(tmp_path, "findings.json", [noisy])
    prefix = tmp_path / "out" / "ENG-NOISY"
    rc = main([str(findings_file), "--out-prefix", str(prefix)])

    assert rc == 0
    assert (tmp_path / "out" / "ENG-NOISY.md").exists()
