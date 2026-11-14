"""TASK-012：终端本地命令白名单 + execute_code 类别性拦截。

按任务书验收表逐条设防（docs/tasks/TASK-012.md 任务 1/2）：

1. ls /opt/secops -> ALLOW，且不计入任何限速桶（FakeClock + snapshot 验证）
2. cat robots.txt -> ALLOW（不再误解析域名）
3. grep pattern file.log -> ALLOW
4. rm -rf / -> 仍被 forbidden 拦（本地白名单不豁免毁灭性命令）
5. execute_code/code_exec/python_exec 任何 args -> block code_execution_tool
6. python3 -c -> 仍 inline_code_execution 拦（TASK-007 不回归）
7. curl https://yyds520.online/ -> 目标校验照旧（白名单不吞出网命令）

另补白名单的逃逸面（fail closed）：组合命令借首词逃逸、命令替换/反引号、
/dev/tcp 网络伪设备、find -exec 任意执行、git 网络子命令、env 带命令形态——
一律退回普通校验路径；本地命令读写删作业元数据（保护路径）仍拦。

不真实联网：resolver 注入 FakeResolver，保险丝打断真实 DNS。
"""

from __future__ import annotations

import socket

import pytest

from conftest import FakeClock, FakeResolver
from scope_gate.extract import analyze_terminal
from scope_gate.gate import GateConfig, ScopeGate
from scope_gate.models import DecisionKind


@pytest.fixture(autouse=True)
def _forbid_real_dns(monkeypatch):
    """保险丝：测试进程内任何真实 DNS 查询都直接失败。"""

    def _refuse(*args, **kwargs):
        raise OSError("测试禁止真实 DNS 解析")

    monkeypatch.setattr(socket, "getaddrinfo", _refuse)


def _gate_with_clock(tmp_path, scope_file, clock):
    """带可注入时钟的 gate（限速记账断言需要 FakeClock + snapshot）。"""
    cfg = GateConfig(
        scope_path=scope_file,
        audit_path=tmp_path / "audit" / "decisions.jsonl",
        rate_limit_db=tmp_path / "audit" / "rl.sqlite3",
        protected_paths=(scope_file, tmp_path / "audit"),
    )
    return ScopeGate(cfg, resolver=FakeResolver(), clock=clock)


# ---- 验收 1：ls 本地目录放行，且不计入限速桶 ---------------------------------


def test_ls_target_dir_allowed_and_not_rate_accounted(tmp_path, scope_file):
    """验收 1：ls /opt/secops -> ALLOW，限速桶零记账（对照组证明记账机制在线）。"""
    clock = FakeClock()
    gate = _gate_with_clock(tmp_path, scope_file, clock)
    d = gate.evaluate("terminal", {"command": "ls /opt/secops"})
    assert d.kind is DecisionKind.ALLOW
    assert d.code == "local_shell"

    eng_id = gate.store.state.engagement.id
    snap = gate.limiter.snapshot(eng_id, "app.example.com")
    assert snap == {"tokens": None, "host_total": 0, "global_total": 0}

    # 对照组：scope 内 curl 正常记账 -> 上面桶没变是白名单豁免，不是断言失效
    d2 = gate.evaluate("terminal", {"command": "curl https://app.example.com/"})
    assert d2.kind is DecisionKind.ALLOW
    snap2 = gate.limiter.snapshot(eng_id, "app.example.com")
    assert snap2["global_total"] == 1
    assert snap2["tokens"] is not None


# ---- 验收 2/3 + A6 复测证据：不再误解析域名/IP -------------------------------


@pytest.mark.parametrize("cmd", [
    "cat robots.txt",                # 验收 2
    "grep pattern file.log",         # 验收 3
    "ls python-3.14*",               # A6 证据：版本号 glob 被当 IP 的旧误拦
    "grep os.path.join *.log",       # A6 证据：标识符被当域名的旧误拦
    "head -n 20 evidence/scan.log",  # 带路径参数的常见只读命令
    "mkdir -p evidence/scan && cp raw/*.log evidence/scan/",
])
def test_local_shell_commands_allowed(make_gate, cmd):
    """验收 2/3 + A6 证据回放：纯本地命令放行，code=local_shell。"""
    d = make_gate().evaluate("terminal", {"command": cmd})
    assert d.kind is DecisionKind.ALLOW, cmd
    assert d.code == "local_shell", cmd


@pytest.mark.parametrize("cmd", [
    "git status && ls /opt",
    "env | grep SCOPE",
    "cd /opt/secops && ls",
    "cat robots.txt | grep disallow | wc -l",
    "sort results.txt | uniq -c",
])
def test_composed_local_commands_allowed(make_gate, cmd):
    """白名单正用例：本地命令的常见组合（管道/&&）照常放行。"""
    d = make_gate().evaluate("terminal", {"command": cmd})
    assert d.kind is DecisionKind.ALLOW, cmd
    assert d.code == "local_shell", cmd


def test_analyze_terminal_local_shell_flag():
    """Analysis 字段语义：白名单命令置 is_local_shell 且不提取目标。"""
    a = analyze_terminal("ls /opt/secops")
    assert a.is_local_shell is True
    assert a.targets == ()
    assert a.action.value == "recon_passive"
    assert a.forbidden == ""
    assert a.parse_error == ""

    b = analyze_terminal("rm -rf /")
    assert b.is_local_shell is True   # rm 在白名单里，但 forbidden 先行命中
    assert b.forbidden == "dos"

    c = analyze_terminal("curl https://yyds520.online/")
    assert c.is_local_shell is False  # 出网命令不进白名单


# ---- 验收 4：毁灭性命令不豁免 ------------------------------------------------


def test_rm_rf_root_still_blocked(make_gate):
    """验收 4：rm -rf / 仍被 forbidden 拦——本地白名单不豁免 forbidden 判定。"""
    d = make_gate().evaluate("terminal", {"command": "rm -rf /"})
    assert d.is_block
    assert d.code == "forbidden_dos"


# ---- 验收 5：execute_code 类工具类别性拦截 ------------------------------------


@pytest.mark.parametrize("tool", [
    "execute_code", "code_exec", "python_exec",
    "Execute_Code", "  EXECUTE_CODE  ",
])
def test_code_execution_tools_always_blocked(make_gate, tool):
    """验收 5：execute_code 类工具任何 args -> block code_execution_tool。"""
    gate = make_gate()
    for args in (
        {},
        {"code": "print(1)"},
        {"language": "python", "code": "import os; os.system('id')"},
        {"files": {"main.py": "import requests; requests.get('http://x')"}},
    ):
        d = gate.evaluate(tool, args)
        assert d.is_block, (tool, args)
        assert d.code == "code_execution_tool", (tool, args)
        assert "run_scan" in d.message  # 指路任务协议的原子动作白名单


def test_execute_code_hook_payload(make_gate):
    """钩子层同样拒绝：pre_tool_call 返回结构化 block，模型可读原因。"""
    res = make_gate().pre_tool_call("execute_code", {"code": "1 / 0"})
    assert isinstance(res, dict)
    assert res["action"] == "block"
    assert "任意代码执行" in res["message"]


# ---- 验收 6/7：TASK-007 不回归 + 出网目标校验照旧 -----------------------------


def test_python_dash_c_still_blocked_inline(make_gate):
    """验收 6：python3 -c 内联执行仍被类别性拦截（TASK-007 不回归）。"""
    d = make_gate().evaluate("terminal", {
        "command": "python3 -c \"import urllib.request; "
                   "urllib.request.urlopen('https://yyds520.online')\"",
    })
    assert d.is_block
    assert d.code == "inline_code_execution"


def test_curl_out_of_scope_still_blocked(make_gate):
    """验收 7：curl 目标校验照旧——白名单不吞出网命令。"""
    d = make_gate().evaluate("terminal", {"command": "curl https://yyds520.online/"})
    assert d.is_block
    assert d.code == "out_of_scope"


def test_curl_in_scope_still_allowed(make_gate):
    """验收 7（不误伤面）：scope 内 curl 照旧放行，code=ok。"""
    d = make_gate().evaluate("terminal", {"command": "curl https://app.example.com/"})
    assert d.kind is DecisionKind.ALLOW
    assert d.code == "ok"


# ---- 逃逸面：白名单只豁免"纯本地"，能引出网络操作的形态一律退回 ---------------


@pytest.mark.parametrize("cmd", [
    "ls /tmp && curl https://yyds520.online/",                     # 组合借首词逃逸
    "cat $(curl https://yyds520.online/x)",                        # 命令替换
    "cat `curl https://yyds520.online/x`",                         # 反引号替换
    "echo x > /dev/tcp/yyds520.online/443",                        # bash 网络伪设备
    "find . -name '*.log' -exec curl https://yyds520.online/ \\;",  # -exec 任意执行
    "git clone https://yyds520.online/x",                          # git 网络子命令
    "env curl https://yyds520.online/",                            # env 带命令形态
    "git push origin main",                                        # 网络子命令（无显式 URL）
])
def test_local_shell_escape_forms_fall_back_to_normal_check(make_gate, cmd):
    """逃逸面：命中逃逸特征的形态退回普通校验路径，不因首词在白名单而放行。"""
    d = make_gate().evaluate("terminal", {"command": cmd})
    assert d.is_block, cmd


def test_analyze_terminal_composed_command_not_local():
    """逐段判定单元验证：任一段不在白名单 -> 整条按普通出网处理。"""
    a = analyze_terminal("ls /tmp && curl https://yyds520.online/")
    assert a.is_local_shell is False
    assert any(t.normalized == "yyds520.online" for t in a.targets)


# ---- 路径保护照常生效：本地命令碰作业元数据仍拦 -------------------------------


def test_local_shell_touching_scope_yaml_still_blocked(make_gate, scope_file):
    """rm/mv scope.yaml -> protected_path（白名单不豁免路径保护）。"""
    d = make_gate().evaluate("terminal", {"command": f"rm {scope_file}"})
    assert d.is_block
    assert d.code == "protected_path"

    d2 = make_gate().evaluate(
        "terminal", {"command": f"mv {scope_file} /tmp/scope.yaml.bak"})
    assert d2.is_block
    assert d2.code == "protected_path"
