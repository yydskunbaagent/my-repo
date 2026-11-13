"""TASK-010：门禁工具感知分类——本地工具跳过目标提取与 no_target 判定。

背景（2026-11-14 A6 复测）：tool_describe / tool_search / security_scan_*
（hermes-security 的 9 个本地分析工具）因参数无 IP 被 no_target 拦 ~10 次，
官方插件并发审计几乎被废。本文件按任务书验收表逐条设防：

1. tool_describe 无目标参数 -> ALLOW（不再 no_target）
2. security_scan_start 参数含仓库路径 -> ALLOW
3. local 工具写 scope.yaml -> 仍然 BLOCK（路径保护不豁免）
4. extra_local_tools 配置注入的自定义工具名 -> 同样放行
5. terminal 既有行为不回归：内联拦 / 脚本文件拦 / curl 目标校验照旧

不真实联网：resolver 一律注入 FakeResolver，另加保险丝打断真实 DNS。
"""

from __future__ import annotations

import socket

import pytest

from conftest import FakeResolver
from scope_gate.engine import decide
from scope_gate.extract import LOCAL_TOOLS, is_local_tool
from scope_gate.gate import GateConfig, ScopeGate
from scope_gate.models import Action, DecisionKind


@pytest.fixture(autouse=True)
def _forbid_real_dns(monkeypatch):
    """保险丝：测试进程内任何真实 DNS 查询都直接失败。"""

    def _refuse(*args, **kwargs):
        raise OSError("测试禁止真实 DNS 解析")

    monkeypatch.setattr(socket, "getaddrinfo", _refuse)


# ---- 分类单元：is_local_tool / LOCAL_TOOLS ----------------------------------


@pytest.mark.parametrize("name", sorted(LOCAL_TOOLS))
def test_local_tools_classified(name):
    """本地清单里的每个名字（含 hermes-security 9 个）都判为本地工具。"""
    assert is_local_tool(name)


def test_local_tool_case_insensitive():
    """匹配不区分大小写、容忍首尾空白，与 is_delegate_tool 同一规则。"""
    assert is_local_tool("Tool_Describe")
    assert is_local_tool("  SECURITY_SCAN_START  ")


def test_network_tools_not_local():
    """出网类与未知工具不得进入本地清单：默认按出网处理的策略不变。"""
    for name in ("terminal", "web_search", "browser_navigate", "delegate_task",
                 "weird_unknown_tool", ""):
        assert not is_local_tool(name)


# ---- 验收 1/2：本地工具无目标不再被 no_target 误杀 ---------------------------


def test_tool_describe_without_target_allowed(make_gate):
    """验收 1：tool_describe 无目标参数 -> ALLOW（不再 no_target）。"""
    d = make_gate().evaluate("tool_describe", {"tool": "nmap"})
    assert d.kind is DecisionKind.ALLOW
    assert d.code == "local_tool"


def test_security_scan_start_with_repo_path_allowed(make_gate):
    """验收 2：security_scan_start 参数含仓库路径 -> ALLOW。"""
    d = make_gate().evaluate("security_scan_start", {
        "repo_path": "C:/work/repo",
        "mode": "concurrency",
    })
    assert d.kind is DecisionKind.ALLOW


def test_security_scan_tools_without_targets_allowed(make_gate):
    """hermes-security 其余 8 个本地分析工具参数无 IP 也放行（A6 复测场景）。"""
    gate = make_gate()
    for name in ("security_scan_get", "security_scan_checkpoint",
                 "security_scan_submit_worker_result",
                 "security_scan_record_validations", "security_scan_record_chains",
                 "security_scan_finalize", "security_scan_cancel",
                 "security_scan_export"):
        d = gate.evaluate(name, {"scan_id": "S-1"})
        assert d.kind is DecisionKind.ALLOW, name


def test_unknown_tool_still_requires_target(make_gate):
    """边界不松：清单外的未知工具仍按出网处理，无目标照样拦（unparsed_target）。"""
    d = make_gate().evaluate("weird_exfil_tool", {"blob": "没有任何目标"})
    assert d.is_block
    assert d.code == "unparsed_target"


# ---- 验收 3：路径保护不豁免 --------------------------------------------------


def test_write_file_to_scope_yaml_still_blocked(make_gate, scope_file):
    """验收 3：write_file path=scope.yaml -> 仍然 BLOCK（作业元数据保护生效）。"""
    d = make_gate().evaluate("write_file", {"path": str(scope_file), "content": "hacked"})
    assert d.is_block
    assert d.code == "protected_path"


def test_edit_file_to_scope_yaml_still_blocked(make_gate, scope_file):
    """新增进本地清单的写类工具同样不豁免：edit_file 改写 scope.yaml -> BLOCK。"""
    d = make_gate().evaluate("edit_file",
                             {"file_path": str(scope_file), "old": "a", "new": "b"})
    assert d.is_block
    assert d.code == "protected_path"


def test_local_tool_write_to_audit_dir_blocked(make_gate, tmp_path):
    """审计目录同受保护：本地工具带 path 落到 audit/ 下 -> BLOCK。"""
    d = make_gate().evaluate("memory_write",
                             {"path": str(tmp_path / "audit" / "x.txt"), "content": "x"})
    assert d.is_block
    assert d.code == "protected_path"


# ---- 验收 4：extra_local_tools 配置注入 -------------------------------------


def _gate_with_extras(tmp_path, scope_file, extras):
    cfg = GateConfig(
        scope_path=scope_file,
        audit_path=tmp_path / "audit" / "decisions.jsonl",
        rate_limit_db=tmp_path / "audit" / "rl.sqlite3",
        protected_paths=(scope_file, tmp_path / "audit"),
        extra_local_tools=extras,
    )
    return ScopeGate(cfg, resolver=FakeResolver())


def test_extra_local_tools_injected_allowed(tmp_path, scope_file):
    """验收 4：extra_local_tools 注入的自定义工具名 -> 同样放行。"""
    gate = _gate_with_extras(tmp_path, scope_file, ("my_local_helper", " Another_Local "))
    for name in ("my_local_helper", "another_local", "My_Local_Helper"):
        d = gate.evaluate(name, {"anything": 1})
        assert d.kind is DecisionKind.ALLOW, name


def test_extra_local_tools_keeps_unlisted_blocked(tmp_path, scope_file):
    """注入只放行声明的名字：清单外工具仍被拦（fail closed 不变）。"""
    gate = _gate_with_extras(tmp_path, scope_file, ("my_local_helper",))
    d = gate.evaluate("other_unknown_tool", {"x": 1})
    assert d.is_block
    assert d.code == "unparsed_target"


def test_from_mapping_parses_extra_local_tools(tmp_path):
    """config.yaml 的 extra_local_tools 列表：去空白、丢空项；缺省为空元组。"""
    cfg = GateConfig.from_mapping(
        {"scope_path": str(tmp_path / "scope.yaml"),
         "extra_local_tools": ["tool_a", "  tool_b  ", ""]},
        tmp_path,
    )
    assert cfg.extra_local_tools == ("tool_a", "tool_b")
    assert GateConfig.from_mapping({}, tmp_path).extra_local_tools == ()


# ---- 验收 5：terminal 既有行为不回归 ----------------------------------------


def test_terminal_python_dash_c_still_blocked(make_gate):
    """验收 5a：python3 -c 内联执行照旧类别性拦截（TASK-007 不回归）。"""
    d = make_gate().evaluate("terminal", {
        "command": "python3 -c \"import urllib.request; "
                   "urllib.request.urlopen('https://app.example.com')\"",
    })
    assert d.is_block
    assert d.code == "inline_code_execution"


def test_terminal_bash_script_still_blocked(make_gate):
    """验收 5b：bash scan.sh 脚本文件执行照旧拒绝（目标藏在脚本里）。"""
    d = make_gate().evaluate("terminal", {"command": "bash scan.sh"})
    assert d.is_block
    assert d.code == "script_execution"


def test_terminal_curl_out_of_scope_still_blocked(make_gate):
    """验收 5c：curl 越界目标照旧 out_of_scope（目标校验不因分类变更松动）。"""
    d = make_gate().evaluate("terminal", {"command": "curl https://yyds520.online/"})
    assert d.is_block
    assert d.code == "out_of_scope"


def test_terminal_curl_in_scope_still_allowed(make_gate):
    """验收 5d：curl scope 内目标照旧放行，正常原子命令不误伤。"""
    d = make_gate().evaluate("terminal", {"command": "curl https://app.example.com/"})
    assert d.kind is DecisionKind.ALLOW
    assert d.code == "ok"


# ---- engine 消费 is_local_tool：直接单测 decide（gate 早退外的第二道保障）----


def test_engine_decide_local_tool_no_target_allowed(engagement):
    """engine.decide 对本地工具空目标直接放行，code=local_tool。"""
    d = decide(
        engagement,
        tool_name="tool_describe",
        action=Action.RECON_PASSIVE,
        targets=(),
        resolved={},
        unresolvable=(),
    )
    assert d.kind is DecisionKind.ALLOW
    assert d.code == "local_tool"


def test_engine_decide_unknown_tool_no_target_still_blocked(engagement):
    """engine.decide 对未知工具空目标维持 no_target（不认识就拒不变）。"""
    d = decide(
        engagement,
        tool_name="weird_exfil_tool",
        action=Action.RECON_ACTIVE,
        targets=(),
        resolved={},
        unresolvable=(),
    )
    assert d.is_block
    assert d.code == "no_target"
