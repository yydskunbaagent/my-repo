"""engine 判定引擎的负向测试：域名解析到私网/保留段时必须阻断（TASK-001）。

不真实联网：
- 域名解析一律注入 conftest 的 FakeResolver（gate 的 resolver 可插拔）；
- 另加一道保险丝，直接打断 socket.getaddrinfo——就算哪个用例漏配了映射，
  也只能解析失败（fail closed），绝不允许测试触网。
"""

from __future__ import annotations

import ipaddress
import socket

import pytest

from conftest import FakeResolver
from scope_gate.engine import is_blocked_network
from scope_gate.extract import analyze_terminal
from scope_gate.gate import GateConfig, ScopeGate
from scope_gate.models import DecisionKind


@pytest.fixture(autouse=True)
def _forbid_real_dns(monkeypatch):
    """保险丝：测试进程内任何真实 DNS 查询都直接失败。"""

    def _refuse(*args, **kwargs):
        raise OSError("测试禁止真实 DNS 解析")

    monkeypatch.setattr(socket, "getaddrinfo", _refuse)


# ---- 夹具辅助：与 conftest.make_gate 同构，但 scope 内容按用例定制 ----------


def _scope_dict(targets, exclusions=()):
    return {
        "engagement": {
            "id": "ENG-TEST-ENGINE",
            "authorized_by": "security@example.com",
            "authorization_doc": "authorization.md",
            "window": {"start": "2026-01-01T00:00:00+00:00", "end": "2027-01-01T00:00:00+00:00"},
            "targets": list(targets),
            "exclusions": list(exclusions),
            "allowed_actions": ["recon_passive", "recon_active", "vuln_scan"],
            "forbidden_actions": ["dos", "exfil", "persistence", "cloud_metadata"],
            "rate_limit": {"rps_per_host": 1000, "max_requests_per_host": 1000, "max_total": 5000},
            "on_unparsed_target": "block",
        }
    }


def _domain_scope(extra_targets=()):
    return _scope_dict([{"kind": "domain", "value": "example.test"}, *extra_targets])


def _decide(tmp_path, scope_dict, mapping, command):
    """定制 scope + FakeResolver 跑一次完整判定，返回 Decision。"""
    import yaml

    scope_path = tmp_path / "scope.yaml"
    scope_path.write_text(yaml.safe_dump(scope_dict, allow_unicode=True), encoding="utf-8")
    cfg = GateConfig(
        scope_path=scope_path,
        audit_path=tmp_path / "audit" / "decisions.jsonl",
        rate_limit_db=tmp_path / "audit" / "rl.sqlite3",
        protected_paths=(scope_path, tmp_path / "audit"),
    )
    gate = ScopeGate(cfg, resolver=FakeResolver(mapping))
    return gate.evaluate("terminal", {"command": command})


# ---- TASK-001 验收表的 7 条用例 --------------------------------------------


def test_case1_domain_resolves_to_private_blocked(tmp_path):
    """用例 1：scope 域名解析到 10.1.2.3，无内网授权 -> block。"""
    d = _decide(tmp_path, _domain_scope(), {"example.test": ("10.1.2.3",)},
                "curl http://example.test/")
    assert d.is_block
    assert d.code == "private_network_resolution"
    assert "私网/保留地址" in d.message


def test_case2_domain_resolves_to_cloud_metadata_blocked(tmp_path):
    """用例 2：解析到 169.254.169.254（云元数据）-> block。"""
    d = _decide(tmp_path, _domain_scope(), {"example.test": ("169.254.169.254",)},
                "curl http://example.test/")
    assert d.is_block
    assert d.code == "private_network_resolution"


def test_case3_explicit_ip_authorization_allows_private(tmp_path):
    """用例 3：解析到 192.168.1.10，且 scope 显式授权该 IP -> 放行。"""
    d = _decide(tmp_path, _domain_scope([{"kind": "ip", "value": "192.168.1.10"}]),
                {"example.test": ("192.168.1.10",)}, "curl http://example.test/")
    assert d.kind is DecisionKind.ALLOW
    assert d.code == "ok"


def test_case4_unrelated_cidr_authorization_still_blocked(tmp_path):
    """用例 4：scope 只授权了 10.0.0.0/8，解析到 192.168.1.10 -> block。"""
    d = _decide(tmp_path, _domain_scope([{"kind": "cidr", "value": "10.0.0.0/8"}]),
                {"example.test": ("192.168.1.10",)}, "curl http://example.test/")
    assert d.is_block
    assert d.code == "private_network_resolution"


def test_case5_public_ip_not_blocked(tmp_path):
    """用例 5：解析到公网 8.8.8.8 -> 放行（不误伤）。"""
    d = _decide(tmp_path, _domain_scope(), {"example.test": ("8.8.8.8",)},
                "curl http://example.test/")
    assert d.kind is DecisionKind.ALLOW
    assert d.code == "ok"


def test_case6_ipv4_mapped_private_blocked(tmp_path):
    """用例 6：解析到 IPv4-mapped ::ffff:10.1.2.3 -> block。"""
    d = _decide(tmp_path, _domain_scope(), {"example.test": ("::ffff:10.1.2.3",)},
                "curl http://example.test/")
    assert d.is_block
    assert d.code == "private_network_resolution"


def test_case7_cgn_range_blocked(tmp_path):
    """用例 7：解析到 100.64.1.1（CGN 段）-> block。"""
    d = _decide(tmp_path, _domain_scope(), {"example.test": ("100.64.1.1",)},
                "curl http://example.test/")
    assert d.is_block
    assert d.code == "private_network_resolution"


# ---- 行为边界：排除项优先级 / 显式网段授权不受影响 --------------------------


def test_exclusion_priority_over_private_block(tmp_path):
    """排除项优先：解析到既被排除又在私网段的 IP，报排除而非私网阻断。"""
    scope = _scope_dict(
        [{"kind": "domain", "value": "example.test"}],
        exclusions=[{"kind": "ip", "value": "10.1.2.3", "reason": "生产库"}],
    )
    d = _decide(tmp_path, scope, {"example.test": ("10.1.2.3",)}, "curl http://example.test/")
    assert d.is_block
    assert d.code == "excluded_target"


def test_authorized_cidr_scan_still_allowed(tmp_path):
    """显式授权的内网网段扫描不受影响：私网阻断只针对域名解析结果。"""
    scope = _scope_dict([
        {"kind": "domain", "value": "example.test"},
        {"kind": "cidr", "value": "10.20.30.0/28", "ports": [80, 443]},
    ])
    d = _decide(tmp_path, scope, {}, "nmap -sS -p80 10.20.30.4")
    assert d.kind is DecisionKind.ALLOW


# ---- is_blocked_network 直接单测：逐段穷举 ----------------------------------


@pytest.mark.parametrize(
    "ip",
    [
        "0.0.0.1",          # "this network"
        "10.1.2.3",         # RFC1918
        "100.64.1.1",       # CGN
        "127.0.0.1",        # loopback
        "169.254.1.1",      # link-local
        "172.16.5.5",       # RFC1918
        "192.0.0.1",        # IETF 协议分配
        "192.0.2.1",        # TEST-NET-1
        "192.88.99.1",      # 6to4 relay
        "192.168.1.10",     # RFC1918
        "198.18.0.1",       # 基准测试
        "198.51.100.1",     # TEST-NET-2
        "203.0.113.1",      # TEST-NET-3
        "224.0.0.1",        # 组播
        "240.0.0.1",        # 保留
    ],
)
def test_blocked_ipv4_ranges(ip):
    assert is_blocked_network(ipaddress.ip_address(ip))


@pytest.mark.parametrize(
    "ip",
    ["::", "::1", "fc00::1", "fd00::1", "fe80::1", "ff02::1",
     "::ffff:10.1.2.3", "::ffff:127.0.0.1"],
)
def test_blocked_ipv6_ranges(ip):
    assert is_blocked_network(ipaddress.ip_address(ip))


@pytest.mark.parametrize(
    "ip",
    ["8.8.8.8", "1.1.1.1", "93.184.216.34", "203.0.114.1", "198.51.101.1",
     "::ffff:8.8.8.8", "2001:4860:4860::8888"],
)
def test_public_ips_not_blocked(ip):
    assert not is_blocked_network(ipaddress.ip_address(ip))


# ---- TASK-005 缺陷 1：委派类工具按目标判定 ----------------------------------


def _decide_tool(tmp_path, scope_dict, mapping, tool_name, args):
    """定制 scope + FakeResolver，对任意工具调用跑一次完整判定，返回 Decision。"""
    import yaml

    scope_path = tmp_path / "scope.yaml"
    scope_path.write_text(yaml.safe_dump(scope_dict, allow_unicode=True), encoding="utf-8")
    cfg = GateConfig(
        scope_path=scope_path,
        audit_path=tmp_path / "audit" / "decisions.jsonl",
        rate_limit_db=tmp_path / "audit" / "rl.sqlite3",
        protected_paths=(scope_path, tmp_path / "audit"),
    )
    gate = ScopeGate(cfg, resolver=FakeResolver(mapping))
    return gate.evaluate(tool_name, args)


def test_delegate_in_scope_target_allowed(tmp_path):
    """委派文本里的目标在 scope 内 -> 放行。"""
    d = _decide_tool(tmp_path, _domain_scope(), {}, "delegate_task",
                     {"task": "对 example.test 做端口指纹识别，结果写 evidence/"})
    assert d.kind is DecisionKind.ALLOW


def test_delegate_out_of_scope_target_blocked(tmp_path):
    """委派文本含越界目标 -> block，message 带该目标。"""
    d = _decide_tool(tmp_path, _domain_scope(), {}, "delegate_task",
                     {"task": "先 curl http://yyds520.online/ 抓首页再分析"})
    assert d.is_block
    assert d.code == "out_of_scope"
    assert "yyds520.online" in d.message


def test_delegate_no_target_allowed(tmp_path):
    """委派文本不含可识别目标 -> 放行（交给子 Agent 的门禁把关）。"""
    d = _decide_tool(tmp_path, _domain_scope(), {}, "delegate_task",
                     {"task": "分析刚才的输出，整理成报告"})
    assert d.kind is DecisionKind.ALLOW
    assert d.code == "delegate_no_target"


def test_delegate_nested_args_recursed(tmp_path):
    """args 里的 dict/list 嵌套字符串字段也要递归展开提取目标。"""
    d = _decide_tool(tmp_path, _domain_scope(), {}, "delegate_task",
                     {"subtasks": [
                         {"prompt": "收集 example.test 的站点指纹"},
                         {"prompt": "扫描 198.51.100.77 的 443 端口"},
                     ]})
    assert d.is_block
    assert d.code == "out_of_scope"
    assert "198.51.100.77" in d.message


def test_delegate_tool_name_case_insensitive(tmp_path):
    """工具名不区分大小写：Delegate_Task 同样按委派语义判定。"""
    d = _decide_tool(tmp_path, _domain_scope(), {}, "Delegate_Task",
                     {"task": "分析刚才的输出"})
    assert d.kind is DecisionKind.ALLOW
    assert d.code == "delegate_no_target"


# ---- TASK-007 任务 1：解释器内联执行的类别性拦截 ------------------------------
#
# 内联代码（python3 -c / bash -c / 交互模式）里"可见合法目标 + 隐藏 sink"无法
# 静态提取，不能靠目标校验兜底，只能按形态类别性拦截。scope 用例里目标全合法，
# 才能证明拦截依据是"内联形态"本身而不是目标越界。


def _inline_scope():
    """目标全合法的最小 scope：yyds520.online 带端口授权。"""
    return _scope_dict([
        {"kind": "domain", "value": "yyds520.online", "ports": [80, 443]},
    ])


def test_task007_python_dash_c_blocked_inline(tmp_path):
    """验收 1：python3 -c 里目标全合法 -> 仍 block inline_code_execution。"""
    d = _decide(tmp_path, _inline_scope(), {"yyds520.online": ("8.8.8.8",)},
                "python3 -c \"import urllib.request; "
                "urllib.request.urlopen('https://yyds520.online')\"")
    assert d.is_block
    assert d.code == "inline_code_execution"
    assert "内联代码执行" in d.message
    assert "预授权的原子工具" in d.message


def test_task007_bash_dash_c_blocked_inline(tmp_path):
    """验收 2：bash -c 'curl http://10.20.30.4' -> block inline_code_execution
    （内联拦截先于目标判定，隐藏 sink 轮不到私网判定兜底）。"""
    d = _decide(tmp_path, _inline_scope(), {}, "bash -c 'curl http://10.20.30.4'")
    assert d.is_block
    assert d.code == "inline_code_execution"


def test_task007_file_form_keeps_script_execution(tmp_path):
    """验收 3：纯文件形态 python3 /opt/scan.py -> 既有 script_execution 不回归。"""
    d = _decide(tmp_path, _inline_scope(), {}, "python3 /opt/scan.py")
    assert d.is_block
    assert d.code == "script_execution"


def test_task007_plain_tool_command_allowed(tmp_path):
    """验收 4：curl 直连 scope 内目标 -> 放行，不误伤正常原子工具命令。"""
    d = _decide(tmp_path, _inline_scope(), {"yyds520.online": ("8.8.8.8",)},
                "curl https://yyds520.online/")
    assert d.kind is DecisionKind.ALLOW
    assert d.code == "ok"


def test_task007_interpreter_interactive_mode_blocked(tmp_path):
    """除解释器外无任何参数 = 交互模式，同样是代码注入通道 -> block。"""
    d = _decide(tmp_path, _inline_scope(), {}, "python3")
    assert d.is_block
    assert d.code == "inline_code_execution"


def test_task007_node_dash_e_blocked(tmp_path):
    """node -e 内联形态同样命中（-e 在内联形态清单里）。"""
    d = _decide(tmp_path, _inline_scope(), {"yyds520.online": ("8.8.8.8",)},
                "node -e \"require('http').get('https://yyds520.online')\"")
    assert d.is_block
    assert d.code == "inline_code_execution"


def test_task007_inline_in_later_segment_blocked(tmp_path):
    """组合命令后段藏内联逃逸也要拦：curl 合法 && python3 -c。"""
    d = _decide(tmp_path, _inline_scope(), {"yyds520.online": ("8.8.8.8",)},
                "curl https://yyds520.online/ && python3 -c \"urlopen('https://yyds520.online')\"")
    assert d.is_block
    assert d.code == "inline_code_execution"


def test_task007_curl_dash_c_not_inline(tmp_path):
    """不误伤：curl 的 -c（cookie jar）不是内联执行，正常走目标校验。"""
    d = _decide(tmp_path, _inline_scope(), {"yyds520.online": ("8.8.8.8",)},
                "curl -c cookies.txt https://yyds520.online/")
    assert d.kind is DecisionKind.ALLOW


def test_task007_delegate_path_not_affected(tmp_path):
    """delegate_task 不走 terminal 路径：子任务文本提到 -c 不触发内联拦截。"""
    d = _decide_tool(tmp_path, _inline_scope(), {}, "delegate_task",
                     {"task": "用 python3 -c '...' 对 yyds520.online 做站点指纹识别"})
    assert d.kind is DecisionKind.ALLOW


def test_task007_analysis_inline_eval_flag():
    """Analysis 字段语义：内联形态置位；文件形态只置 script_path。"""
    a = analyze_terminal("python3 -c 'print(1)'")
    assert a.inline_eval is True
    assert a.script_path == ""
    b = analyze_terminal("bash scan.sh")
    assert b.inline_eval is False
    assert b.script_path == "scan.sh"
    c = analyze_terminal("curl https://yyds520.online/")
    assert c.inline_eval is False
    assert c.script_path == ""
