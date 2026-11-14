"""TASK-013：终端命令逃逸三漏洞修复 + masking Base64 补全。

按任务书验收清单逐条设防（docs/tasks/TASK-013.md，用例标注逃逸字母编号）：

A   换行多行绕过：ls -la\\ncurl https://evil.com 借首词逃过本地白名单 ->
    \\r?\\n 切分后逐段判定，is_local_shell=False 且 curl 段目标被提取
A'  CRLF 同语义
A'' 纯本地多行（pwd\\nls -la）不误伤
B   多段脚本：curl ... && bash /tmp/evil.sh 借整体首词逃过 script 判定 ->
    逐段遍历后 script_path 指向段 2
B'  脚本在中段：echo x; python3 /tmp/run.py && curl ...
C   无后缀脚本：bash /tmp/no_ext_script（扩展名过滤取消）
回归：bash /tmp/a.sh 仍拦、python3 -c 仍 inline_eval、git status / grep
白名单不变
masking：bearer 后随含 = 的 Base64 -> 掩码

不真实联网：gate 级用例走 conftest 的 FakeResolver，另设保险丝打断真实 DNS。
"""

from __future__ import annotations

import socket
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scope_gate.extract import analyze_terminal  # noqa: E402
from scope_gate.models import DecisionKind  # noqa: E402
from secops_report.masking import mask_text  # noqa: E402


@pytest.fixture(autouse=True)
def _forbid_real_dns(monkeypatch):
    """保险丝：测试进程内任何真实 DNS 查询都直接失败。"""

    def _refuse(*args, **kwargs):
        raise OSError("测试禁止真实 DNS 解析")

    monkeypatch.setattr(socket, "getaddrinfo", _refuse)


# ---- A：换行多行绕过 ----------------------------------------------------------


def test_escape_A_newline_splits_segments():
    """A：ls -la\\ncurl https://evil.com -> is_local_shell=False 且目标被提取。"""
    a = analyze_terminal("ls -la\ncurl https://evil.com")
    assert a.is_local_shell is False
    assert any(t.normalized == "evil.com" for t in a.targets)


def test_escape_A_blocked_by_gate(make_gate):
    """A 端到端：此前门禁放行，现在 curl 段目标照常校验（evil.com 越界 -> 拒）。"""
    d = make_gate().evaluate("terminal", {"command": "ls -la\ncurl https://evil.com"})
    assert d.is_block
    assert d.code == "out_of_scope"


def test_escape_A_crlf_same_semantics():
    """A'：CRLF（\\r\\n）换行同样逐段判定，目标提取不漏。"""
    a = analyze_terminal("echo ok\r\ncurl http://10.20.30.40")
    assert a.is_local_shell is False
    assert any(t.normalized == "10.20.30.40" for t in a.targets)


def test_escape_A_pure_local_multiline_not_flagged():
    """A''：全本地多行命令不误伤，is_local_shell 仍为真、不提取目标。"""
    a = analyze_terminal("pwd\nls -la")
    assert a.is_local_shell is True
    assert a.targets == ()


def test_escape_A_pure_local_multiline_allowed_by_gate(make_gate):
    """A'' 端到端：纯本地多行照旧走 local_shell 放行。"""
    d = make_gate().evaluate("terminal", {"command": "pwd\nls -la"})
    assert d.kind is DecisionKind.ALLOW
    assert d.code == "local_shell"


# ---- B：多段脚本执行 ----------------------------------------------------------


def test_escape_B_script_in_second_segment():
    """B：curl ... && bash /tmp/evil.sh -> script_path 非空且指向段 2。"""
    a = analyze_terminal("curl https://yyds520.online && bash /tmp/evil.sh")
    assert a.script_path
    assert "seg#2" in a.script_path
    assert a.script_path.endswith("/tmp/evil.sh")
    assert a.inline_eval is False


def test_escape_B_blocked_by_gate(make_gate):
    """B 端到端：script_execution 拒绝（此前 script_path 为空被放行）。"""
    d = make_gate().evaluate(
        "terminal", {"command": "curl https://yyds520.online && bash /tmp/evil.sh"})
    assert d.is_block
    assert d.code == "script_execution"


def test_escape_B_script_in_middle_segment():
    """B'：echo x; python3 /tmp/run.py && curl ... -> 中段脚本同样命中。"""
    a = analyze_terminal("echo x; python3 /tmp/run.py && curl https://yyds520.online")
    assert a.script_path
    assert "seg#2" in a.script_path
    assert a.script_path.endswith("/tmp/run.py")


# ---- C：无后缀脚本 ------------------------------------------------------------


def test_escape_C_extensionless_script():
    """C：bash /tmp/no_ext_script ... -> 取消扩展名过滤后 script_path 非空。"""
    a = analyze_terminal("bash /tmp/no_ext_script https://yyds520.online")
    assert a.script_path
    assert "/tmp/no_ext_script" in a.script_path
    assert a.inline_eval is False


def test_escape_C_blocked_by_gate(make_gate):
    """C 端到端：无后缀脚本照旧 script_execution 拒绝。"""
    d = make_gate().evaluate(
        "terminal", {"command": "bash /tmp/no_ext_script https://yyds520.online"})
    assert d.is_block
    assert d.code == "script_execution"


# ---- 回归：既有行为不变 --------------------------------------------------------


def test_regression_script_file_still_detected():
    """回归：bash /tmp/a.sh（带后缀）仍记 script_path（单段保持裸路径形态）。"""
    a = analyze_terminal("bash /tmp/a.sh")
    assert a.script_path == "/tmp/a.sh"
    assert a.inline_eval is False


def test_regression_script_file_blocked_by_gate(make_gate):
    """回归：bash /tmp/a.sh 端到端仍 script_execution 拒绝（既有行为）。"""
    d = make_gate().evaluate("terminal", {"command": "bash /tmp/a.sh"})
    assert d.is_block
    assert d.code == "script_execution"


def test_regression_inline_eval_unchanged():
    """回归：python3 -c 仍 inline_eval 且不记 script_path（TASK-007 不回归）。"""
    a = analyze_terminal('python3 -c "print(1)"')
    assert a.inline_eval is True
    assert a.script_path == ""


def test_regression_inline_eval_blocked_by_gate(make_gate):
    """回归：python3 -c 端到端仍 inline_code_execution 拒绝。"""
    d = make_gate().evaluate("terminal", {"command": 'python3 -c "print(1)"'})
    assert d.is_block
    assert d.code == "inline_code_execution"


def test_regression_interpreter_flags_not_script():
    """解释器纯选项调用不误记脚本：python3 --version 无非选项参数 -> 不置位。"""
    a = analyze_terminal("python3 --version")
    assert a.script_path == ""
    assert a.inline_eval is False


@pytest.mark.parametrize("cmd", [
    "git status",                              # 任务书用例 9
    "grep x f.log",                            # 任务书用例 9
    "pwd\necho done && git status",            # 多行全本地：逐段皆命中
    "git status && grep x f.log",              # 单行组合（TASK-012 既有形态）
])
def test_regression_local_whitelist_unchanged(cmd):
    """回归：白名单行为不变（analysis 层逐段全命中 -> is_local_shell=True）。"""
    a = analyze_terminal(cmd)
    assert a.is_local_shell is True, cmd


@pytest.mark.parametrize("cmd", [
    "git status",
    "grep x f.log",
])
def test_regression_local_whitelist_allowed_by_gate(make_gate, cmd):
    """回归：白名单端到端照旧 local_shell 放行。"""
    d = make_gate().evaluate("terminal", {"command": cmd})
    assert d.kind is DecisionKind.ALLOW, cmd
    assert d.code == "local_shell", cmd


# ---- masking：Bearer Base64 补全 ----------------------------------------------


def test_masking_bearer_base64_with_padding_masked():
    """任务书用例 8：bearer 后随含 = 的 Base64 -> 掩码（保留前 4 后 2）。"""
    out = mask_text("bearer YWJjZGVmZ2hpamtsMTIzNDU=")
    assert "YWJjZGVmZ2hpamtsMTIzNDU=" not in out, "token 原文不得出现在输出里"
    assert out == "bearer YWJj***U="


def test_masking_bearer_base64_plus_slash_masked():
    """Base64 的 + / / 形态同样命中（+//= 均已入字符类）。"""
    out = mask_text("bearer abcd+/efghijklmnop==")
    assert "abcd+/efghijklmnop==" not in out
    assert out == "bearer abcd***=="


def test_masking_bearer_base64_header_form_unchanged():
    """Header 形态的 Base64 Bearer 照旧经 scheme 分支掩码（不回归）。"""
    out = mask_text("Authorization: Bearer YWJjZGVmZ2hpamtsMTIzNDU=")
    assert "YWJjZGVmZ2hpamtsMTIzNDU=" not in out
    assert out == "Authorization: Bearer YWJj***U="


def test_masking_bearer_base64_idempotent():
    """掩码产物（含 *）再过一遍结果不变。"""
    once = mask_text("bearer YWJjZGVmZ2hpamtsMTIzNDU=")
    assert mask_text(once) == once
