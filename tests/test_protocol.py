"""run_scan 任务协议的单元测试（TASK-008）。

自包含，不依赖 conftest 夹具；不触网、不碰真实时钟、不跑真实 nmap/nuclei/curl：
- 校验与解析函数为纯函数，直接测；
- subprocess 经 run_fn 注入 fake runner；
- 时钟经 validate_task(now=...) / discovered_at 参数注入。
schema 一致性测试直接读同目录 task-schema.json（纯标准库 json）。
"""

from __future__ import annotations

import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL_DIR = ROOT / "deploy" / "protocol"
for _p in (str(ROOT), str(PROTOCOL_DIR)):
    if str(_p) not in sys.path:
        sys.path.insert(0, _p)

import run_scan  # noqa: E402

NOW = datetime(2026, 11, 14, 12, 0, 0, tzinfo=timezone.utc)

NUCLEI_JSONL = (
    '{"template-id":"cve-2021-44228","info":{"name":"Log4j RCE","severity":"critical"},'
    '"matcher-name":"jndi-rce","matched-at":"http://10.10.0.100:3000/"}\n'
    '{"template-id":"tech-detect","info":{"name":"Tech","severity":"weird"},'
    '"matcher-name":"tech","matched-at":"http://10.10.0.100:3000/robots.txt"}\n'
    " [WRN] 这行不是 JSON，应被跳过\n"
)

CURL_HEADERS_OK = "HTTP/1.1 200 OK\r\nServer: nginx\r\nX-Powered-By: PHP/7.4\r\n\r\n"


def _task(**overrides) -> dict:
    """任务书示例任务（补齐 created_at/expires_at），供各测试覆盖局部字段。"""
    task = {
        "task_id": "SCAN-001",
        "engagement_id": "ENG-DEMO-001",
        "targets": [{"host": "10.10.0.100", "ports": [3000], "kind": "http"}],
        "actions": [
            {"tool": "nmap", "args": ["-sV", "-p3000", "10.10.0.100"]},
        ],
        "rate_limit": {"rps_per_host": 2, "max_requests_per_host": 50},
        "created_at": "2026-11-14T00:00:00+00:00",
        "expires_at": "2026-11-15T00:00:00+00:00",
    }
    task.update(overrides)
    return task


def _fake_run(stdout: str = "", stderr: str = "", exit_code: int = 0,
              duration: float = 0.1):
    """构造可注入 run_fn 的 fake runner，并记录收到的全部命令。"""
    calls: list[dict] = []

    def run_fn(cmd: list[str], timeout_s: float) -> dict:
        calls.append({"cmd": list(cmd), "timeout_s": timeout_s})
        return {"exit_code": exit_code, "stdout": stdout, "stderr": stderr,
                "duration_s": duration, "timed_out": False}

    return run_fn, calls


def _deadline(seconds: float = 600.0) -> float:
    return time.monotonic() + seconds


def _validate_errors(task, now=NOW) -> str:
    """validate_task 的错误串（空 = 通过），断言用。"""
    return "；".join(run_scan.validate_task(task, now=now))


# ---- schema 一致性：task-schema.json 与 run_scan.py 的规则必须同源 ------------


def _load_schema() -> dict:
    return json.loads((PROTOCOL_DIR / "task-schema.json").read_text(encoding="utf-8"))


def test_schema_whitelist_matches_script():
    """schema 的工具白名单枚举与脚本 ALLOWED_TOOLS 一致。"""
    schema = _load_schema()
    assert schema["$schema"].endswith("draft-07/schema#")
    tool_enum = schema["properties"]["actions"]["items"]["properties"]["tool"]["enum"]
    assert tool_enum == list(run_scan.ALLOWED_TOOLS)


def test_schema_required_keys_match_script():
    """顶层必填键与脚本 REQUIRED_KEYS 一致，且禁止额外字段。"""
    schema = _load_schema()
    assert set(schema["required"]) == set(run_scan.REQUIRED_KEYS)
    assert schema["additionalProperties"] is False


def test_schema_encodes_forbidden_char_patterns():
    """schema 的 args/paths 编码了禁止字符 pattern（分号/反引号/$()。"""
    schema = _load_schema()
    action_items = schema["properties"]["actions"]["items"]["properties"]
    for key in ("args", "paths"):
        subschemas = action_items[key]["items"]["allOf"]
        direct = [s["pattern"] for s in subschemas if "pattern" in s]
        nested = [s["not"]["pattern"] for s in subschemas if "not" in s]
        assert "^[^;`]*$" in direct      # 禁分号与反引号（顶层 pattern）
        assert "\\$\\(" in nested        # 禁 $( 命令替换（not + pattern）
    assert action_items["paths"]["items"]["pattern"] == "^/"  # 路径须以 / 开头


# ---- validate_task：合法任务与各类拒绝 ----------------------------------------


def test_validate_accepts_canonical_task():
    """任务书示例任务（补齐时间字段）校验通过，零错误。"""
    task = _task(actions=[
        {"tool": "nmap", "args": ["-sV", "-p3000", "10.10.0.100"]},
        {"tool": "nuclei", "args": ["-u", "http://10.10.0.100:3000", "-json", "-silent"]},
        {"tool": "curl_probe", "paths": ["/", "/robots.txt"]},
    ])
    assert run_scan.validate_task(task, now=NOW) == []


def test_validate_rejects_root_not_object():
    assert "JSON object" in _validate_errors(["not", "a", "dict"])


@pytest.mark.parametrize("fragment", [";", "`", "$("])
def test_validate_rejects_forbidden_chars_in_args(fragment):
    task = _task(actions=[{"tool": "nmap", "args": [f"-p3000{fragment}echo pwned"]}])
    assert "禁止字符" in _validate_errors(task)


@pytest.mark.parametrize("fragment", [";", "`", "$("])
def test_validate_rejects_forbidden_chars_in_paths(fragment):
    task = _task(actions=[{"tool": "curl_probe", "paths": [f"/x{fragment}y"]}])
    assert "禁止字符" in _validate_errors(task)


@pytest.mark.parametrize("tool", ["sqlmap", "curl", "nmap2", 42])
def test_validate_rejects_unknown_tool(tool):
    task = _task(actions=[{"tool": tool, "args": ["-sV"]}])
    assert "白名单" in _validate_errors(task)


def test_validate_rejects_missing_required_field():
    task = _task()
    del task["engagement_id"]
    assert "缺少必填字段" in _validate_errors(task)


def test_validate_rejects_unknown_top_level_field():
    task = _task(extra="越权字段")
    assert "未知字段" in _validate_errors(task)


def test_validate_rejects_tool_field_mismatch():
    """nuclei 不接受 paths；curl_probe 不接受 args。"""
    bad_nuclei = _task(actions=[{"tool": "nuclei", "paths": ["/"]}])
    assert "只接受 args" in _validate_errors(bad_nuclei)
    bad_curl = _task(actions=[{"tool": "curl_probe", "args": ["-s"]},
                             {"tool": "nmap", "args": ["-sV"]}])
    assert "不接受 args" in _validate_errors(bad_curl)


def test_validate_rejects_nuclei_without_json_flag():
    task = _task(actions=[{"tool": "nuclei", "args": ["-u", "http://10.10.0.100:3000"]}])
    assert "-json" in _validate_errors(task)


def test_validate_rejects_path_without_leading_slash():
    task = _task(actions=[{"tool": "curl_probe", "paths": ["robots.txt"]}])
    assert "/ 开头" in _validate_errors(task)


def test_validate_rejects_expired_task():
    task = _task(expires_at="2026-11-13T00:00:00+00:00")
    assert "已过期" in _validate_errors(task)


def test_validate_rejects_expires_not_after_created():
    task = _task(created_at="2026-11-15T00:00:00+00:00",
                 expires_at="2026-11-15T00:00:00+00:00")
    assert "不晚于" in _validate_errors(task)


@pytest.mark.parametrize("port", [0, 70000, "3000", True])
def test_validate_rejects_bad_port(port):
    task = _task(targets=[{"host": "10.10.0.100", "ports": [port], "kind": "http"}])
    assert "非法端口" in _validate_errors(task)


def test_validate_rejects_bad_kind():
    task = _task(targets=[{"host": "10.10.0.100", "ports": [3000], "kind": "ftp"}])
    assert "kind" in _validate_errors(task)


def test_validate_rejects_host_with_scheme():
    task = _task(targets=[{"host": "http://10.10.0.100", "ports": [3000],
                           "kind": "http"}])
    assert "host" in _validate_errors(task)


# ---- parse_nuclei_findings：JSONL -> findings ---------------------------------


def test_parse_nuclei_maps_template_hit():
    """模板命中逐字段映射：title/target/severity/status/description/evidence。"""
    findings = run_scan.parse_nuclei_findings(
        NUCLEI_JSONL, discovered_at="2026-11-14T12:00:00+00:00")
    assert len(findings) == 2
    first = findings[0]
    assert set(first) == {"title", "target", "severity", "status",
                          "description", "evidence", "discovered_at"}
    assert first["title"] == "cve-2021-44228"
    assert first["target"] == "http://10.10.0.100:3000/"
    assert first["severity"] == "critical"
    assert first["status"] == "observed"
    assert first["description"] == "jndi-rce"
    assert first["discovered_at"] == "2026-11-14T12:00:00+00:00"
    assert first["evidence"] == [{
        "kind": "log",
        "summary": NUCLEI_JSONL.splitlines()[0].strip(),
        "artifact": "",
    }]


def test_parse_nuclei_unknown_or_missing_severity_becomes_info():
    """未知 severity（weird）与缺失 severity 都归 info，不抬高也不丢弃。"""
    lines = (
        '{"template-id":"a","info":{"severity":"weird"},"matcher-name":"m",'
        '"matched-at":"http://x/"}\n'
        '{"template-id":"b","matcher-name":"m","matched-at":"http://x/"}\n'
    )
    findings = run_scan.parse_nuclei_findings(lines, "2026-01-01T00:00:00+00:00")
    assert [f["severity"] for f in findings] == ["info", "info"]


def test_parse_nuclei_skips_non_json_lines():
    """空行与非 JSON 行跳过（原始行保留在 raw_output，不丢证据）。"""
    assert len(run_scan.parse_nuclei_findings(NUCLEI_JSONL, "t")) == 2
    assert run_scan.parse_nuclei_findings("not json\n\n", "t") == []


def test_parse_nuclei_evidence_summary_truncated_to_200():
    """evidence.summary 取原始 JSON 行前 200 字。"""
    long_line = '{"template-id":"' + "a" * 500 + '","matched-at":"http://x/"}'
    findings = run_scan.parse_nuclei_findings(long_line + "\n", "t")
    assert len(findings[0]["evidence"][0]["summary"]) == 200


def test_parse_nuclei_legacy_templateid_fallback():
    """旧版 nuclei（v2）用 templateID 字段，兜底取到。"""
    line = '{"templateID":"old-cve","matcher-name":"m","matched-at":"http://x/"}\n'
    findings = run_scan.parse_nuclei_findings(line, "t")
    assert findings[0]["title"] == "old-cve"


# ---- curl_probe 辅助：URL 构造与响应头解析 -------------------------------------


def test_build_curl_urls_multi_target_port_path():
    """目标 × 端口 × path 逐组展开，保序去重。"""
    targets = [
        {"host": "10.10.0.100", "ports": [3000, 8080], "kind": "http"},
        {"host": "app.example.com", "ports": [443], "kind": "https"},
    ]
    urls = run_scan.build_curl_urls(targets, ["/", "/robots.txt"])
    assert urls[:2] == ["http://10.10.0.100:3000/", "http://10.10.0.100:3000/robots.txt"]
    assert "http://10.10.0.100:8080/" in urls
    assert "https://app.example.com:443/robots.txt" in urls
    assert len(urls) == len(set(urls))


def test_parse_curl_headers_status_and_headers():
    """curl -D - 的头块解析出状态码与原始头行。"""
    status, headers = run_scan.parse_curl_headers(CURL_HEADERS_OK)
    assert status == 200
    assert headers == ["Server: nginx", "X-Powered-By: PHP/7.4"]


def test_parse_curl_headers_no_status_line():
    status, headers = run_scan.parse_curl_headers("garbage output\r\n\r\n")
    assert status is None
    assert headers == ["garbage output"]


# ---- _run_action：fake runner 注入，测命令构造 / 聚合 / 落盘 --------------------


def test_run_action_nmap_aggregates_and_writes_raw(tmp_path):
    run_fn, calls = _fake_run(stdout="3000/tcp open", stderr="")
    entry, findings = run_scan._run_action(
        0, {"tool": "nmap", "args": ["-sV", "-p3000", "10.10.0.100"]},
        _task()["targets"], _deadline(), run_fn, tmp_path / "raw", "t")
    assert calls[0]["cmd"] == ["nmap", "-sV", "-p3000", "10.10.0.100"]
    assert calls[0]["timeout_s"] > 0
    assert entry["exit_code"] == 0
    assert entry["raw_output_ref"] == "raw/00-nmap.log"
    assert findings == []  # nmap 不自动生成 findings（有意为之）
    raw = (tmp_path / "raw" / "00-nmap.log").read_text(encoding="utf-8")
    assert "$ nmap -sV -p3000 10.10.0.100" in raw
    assert "--- stdout ---" in raw and "3000/tcp open" in raw


def test_run_action_nuclei_extracts_findings(tmp_path):
    run_fn, calls = _fake_run(stdout=NUCLEI_JSONL, stderr=" [INF] done")
    entry, findings = run_scan._run_action(
        1, {"tool": "nuclei", "args": ["-u", "http://10.10.0.100:3000", "-json"]},
        _task()["targets"], _deadline(), run_fn, tmp_path / "raw", "t0")
    assert calls[0]["cmd"][0] == "nuclei"
    assert entry["exit_code"] == 0
    assert entry["raw_output_ref"] == "raw/01-nuclei.log"
    assert len(findings) == 2
    assert findings[0]["severity"] == "critical"
    raw = (tmp_path / "raw" / "01-nuclei.log").read_text(encoding="utf-8")
    assert " [INF] done" in raw  # stderr 也进 raw_output，证据不丢


def test_run_action_curl_probe_aggregates_requests(tmp_path):
    run_fn, calls = _fake_run(stdout=CURL_HEADERS_OK)
    action = {"tool": "curl_probe", "paths": ["/", "/robots.txt"]}
    entry, findings = run_scan._run_action(
        2, action, _task()["targets"], _deadline(), run_fn, tmp_path / "raw", "t")
    assert [c["cmd"][-1] for c in calls] == [
        "http://10.10.0.100:3000/", "http://10.10.0.100:3000/robots.txt"]
    assert calls[0]["cmd"][:6] == ["curl", "-sS", "-D", "-", "-o", "/dev/null"]
    assert entry["exit_code"] == 0
    assert entry["raw_output_ref"] == "raw/02-curl_probe.log"
    assert entry["args"] == []  # curl_probe 无 args，paths 单独回填
    assert entry["paths"] == ["/", "/robots.txt"]
    assert [r["status_code"] for r in entry["requests"]] == [200, 200]
    assert entry["requests"][0]["headers"] == ["Server: nginx", "X-Powered-By: PHP/7.4"]
    assert findings == []
    raw = (tmp_path / "raw" / "02-curl_probe.log").read_text(encoding="utf-8")
    assert raw.count("HTTP/1.1 200 OK") == 2  # 每个请求的原始头都落盘


def test_run_action_curl_probe_aggregates_failures(tmp_path):
    """任一请求失败（curl 退出码非 0）-> 动作聚合 exit_code=1，逐请求明细保留。"""
    run_fn, _calls = _fake_run(stdout="", exit_code=28)
    action = {"tool": "curl_probe", "paths": ["/"]}
    entry, _findings = run_scan._run_action(
        0, action, _task()["targets"], _deadline(), run_fn, tmp_path / "raw", "t")
    assert entry["exit_code"] == 1
    assert entry["requests"][0]["exit_code"] == 28
    assert entry["requests"][0]["status_code"] is None


def test_run_action_curl_probe_without_http_targets(tmp_path):
    """无 http/https 目标时 fail closed：不执行 curl，动作条目带 error。"""
    run_fn, calls = _fake_run()
    entry, _findings = run_scan._run_action(
        0, {"tool": "curl_probe", "paths": ["/"]}, [], _deadline(),
        run_fn, tmp_path / "raw", "t")
    assert calls == []
    assert entry["exit_code"] is None
    assert "无从执行" in entry["error"]


def test_run_action_skipped_after_deadline(tmp_path):
    """预算耗尽 -> 动作不执行，条目带 error（exit_code=None 触发 main 退出码 1）。"""
    run_fn, calls = _fake_run()
    entry, findings = run_scan._run_action(
        0, {"tool": "nmap", "args": ["-sV"]}, _task()["targets"],
        time.monotonic() - 1, run_fn, tmp_path / "raw", "t")
    assert calls == []
    assert entry["exit_code"] is None
    assert "超时" in entry["error"]
    assert findings == []


def test_run_command_zero_budget_does_not_spawn():
    """剩余预算 <=0 时不启动子进程（防御 subprocess timeout=0 的 ValueError）。"""
    result = run_scan._run_command(["whatever-cmd"], 0)
    assert result["timed_out"] is True
    assert result["exit_code"] is None


# ---- main 端到端：monkeypatch _run_command，不跑真实工具 -----------------------


def _canned_run(cmd: list[str], timeout_s: float) -> dict:
    if cmd[0] == "nmap":
        return {"exit_code": 0, "stdout": "3000/tcp open  http", "stderr": "",
                "duration_s": 0.5, "timed_out": False}
    if cmd[0] == "nuclei":
        return {"exit_code": 0, "stdout": NUCLEI_JSONL, "stderr": "",
                "duration_s": 1.2, "timed_out": False}
    if cmd[0] == "curl":
        return {"exit_code": 0, "stdout": CURL_HEADERS_OK, "stderr": "",
                "duration_s": 0.05, "timed_out": False}
    raise AssertionError(f"意外命令: {cmd}")


def test_main_runs_task_and_writes_result(tmp_path, monkeypatch):
    """三动作任务端到端：result.json 聚合 + nuclei findings 提取 + raw 落盘。"""
    monkeypatch.setattr(run_scan, "_run_command", _canned_run)
    task_path = tmp_path / "task.json"
    out_path = tmp_path / "out" / "result.json"
    task_path.write_text(json.dumps(_task(actions=[
        {"tool": "nmap", "args": ["-sV", "-p3000", "10.10.0.100"]},
        {"tool": "nuclei", "args": ["-u", "http://10.10.0.100:3000", "-json", "-silent"]},
        {"tool": "curl_probe", "paths": ["/", "/robots.txt"]},
    ]), ensure_ascii=False), encoding="utf-8")

    assert run_scan.main(["--task", str(task_path), "--out", str(out_path)]) == 0

    result = json.loads(out_path.read_text(encoding="utf-8"))
    assert result["task_id"] == "SCAN-001"
    assert "error" not in result
    assert [a["tool"] for a in result["actions"]] == ["nmap", "nuclei", "curl_probe"]
    assert all(a["exit_code"] == 0 for a in result["actions"])
    assert len(result["findings"]) == 2
    assert result["findings"][0]["title"] == "cve-2021-44228"
    assert result["findings"][1]["severity"] == "info"  # 未知 severity 归 info
    for ref in (result["actions"][0]["raw_output_ref"],
                result["actions"][1]["raw_output_ref"],
                result["actions"][2]["raw_output_ref"]):
        assert (tmp_path / "out" / ref).is_file()
    curl_entry = result["actions"][2]
    assert [r["status_code"] for r in curl_entry["requests"]] == [200, 200]


def test_main_returns_1_when_action_fails(tmp_path, monkeypatch):
    """动作失败 -> result 照常落盘，退出码 1。"""

    def failing_run(cmd: list[str], timeout_s: float) -> dict:
        return {"exit_code": 1, "stdout": "", "stderr": "boom",
                "duration_s": 0.1, "timed_out": False}

    monkeypatch.setattr(run_scan, "_run_command", failing_run)
    task_path = tmp_path / "task.json"
    out_path = tmp_path / "result.json"
    task_path.write_text(json.dumps(_task()), encoding="utf-8")
    assert run_scan.main(["--task", str(task_path), "--out", str(out_path)]) == 1
    result = json.loads(out_path.read_text(encoding="utf-8"))
    assert result["actions"][0]["exit_code"] == 1


def test_main_validation_failure_writes_error_only(tmp_path, monkeypatch):
    """校验失败（args 含分号）-> 退出码 2、不执行任何动作、result 只带 error。"""
    run_fn, calls = _fake_run()
    monkeypatch.setattr(run_scan, "_run_command", run_fn)
    task_path = tmp_path / "task.json"
    out_path = tmp_path / "result.json"
    task_path.write_text(json.dumps(
        _task(actions=[{"tool": "nmap", "args": ["-sV; rm -rf /"]}])),
        encoding="utf-8")
    assert run_scan.main(["--task", str(task_path), "--out", str(out_path)]) == 2
    assert calls == []  # 一条命令都没执行
    result = json.loads(out_path.read_text(encoding="utf-8"))
    assert "禁止字符" in result["error"]
    assert result["actions"] == [] and result["findings"] == []


def test_main_rejects_expired_task(tmp_path):
    """过期任务 -> 退出码 2，error 注明已过期（重放无效）。"""
    task_path = tmp_path / "task.json"
    out_path = tmp_path / "result.json"
    task_path.write_text(json.dumps(
        _task(expires_at="2026-01-01T00:00:00+00:00")), encoding="utf-8")
    assert run_scan.main(["--task", str(task_path), "--out", str(out_path)]) == 2
    result = json.loads(out_path.read_text(encoding="utf-8"))
    assert "已过期" in result["error"]


def test_main_help_exits_zero(capsys):
    """--help 打印用法并退出 0（验收命令 python run_scan.py --help 的等价断言）。"""
    with pytest.raises(SystemExit) as exc:
        run_scan.main(["--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "--task" in out and "--timeout" in out
