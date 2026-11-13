"""目标归一化与抽取：这是绕过防御的主战场，用例必须覆盖各种畸形写法。"""

from __future__ import annotations

import pytest

from scope_gate.models import TargetKind
from scope_gate.target import (
    TargetError,
    extract_targets,
    is_cloud_metadata,
    make_target,
    normalize_host,
)


@pytest.mark.parametrize(
    "raw,expected_host,expected_port",
    [
        ("http://2130706433/", "127.0.0.1", 0),          # 整数 IP
        ("http://0x7f000001/", "127.0.0.1", 0),          # 十六进制
        ("http://0x7f.1/", "127.0.0.1", 0),              # 十六进制 + 短写
        ("http://0177.0.0.1/", "127.0.0.1", 0),          # 八进制分量
        ("http://127.1/", "127.0.0.1", 0),               # 缺位短写
        ("http://Example.COM.:8080/x", "example.com", 8080),   # 大写 + 尾点 + 端口
        ("http://user:pass@example.com/", "example.com", 0),   # userinfo
        ("https://[::1]:8443/path", "::1", 8443),        # IPv6 + 端口
        ("example.com:443", "example.com", 443),
        ("  APP.example.com  ", "app.example.com", 0),
    ],
)
def test_normalize_host(raw, expected_host, expected_port):
    kind, host, port = normalize_host(raw)
    assert host == expected_host
    assert port == expected_port
    assert kind in (TargetKind.DOMAIN, TargetKind.IP)


def test_normalize_cidr():
    kind, host, _ = normalize_host("10.20.30.9/28")
    assert kind is TargetKind.CIDR
    assert host == "10.20.30.0/28"       # strict=False 归约到网络地址


def test_normalize_idn():
    _, host, _ = normalize_host("例子.中国")
    assert host.startswith("xn--")       # punycode


@pytest.mark.parametrize("bad", ["", "   ", "http://", "999.999.999.999", "::gg"])
def test_normalize_rejects(bad):
    with pytest.raises(TargetError):
        normalize_host(bad)


def test_extract_simple_command():
    targets = extract_targets("nmap -sS -p80,443 10.20.30.4")
    assert any(t.normalized == "10.20.30.4" for t in targets)


def test_extract_multiple_segments():
    cmd = "curl http://evil.example.net/a; wget http://app.example.com/b"
    hosts = {t.normalized for t in extract_targets(cmd)}
    assert "evil.example.net" in hosts
    assert "app.example.com" in hosts


def test_extract_from_url_with_bypass_forms():
    hosts = {t.normalized for t in extract_targets("curl http://2130706433:8080/admin")}
    assert "127.0.0.1" in hosts


def test_extract_dedupes():
    targets = extract_targets("ping example.com && curl http://example.com/")
    assert sum(1 for t in targets if t.normalized == "example.com") == 1


def test_extract_ignores_invalid_ip():
    targets = extract_targets("echo 999.999.999.999")
    assert all(t.normalized != "999.999.999.999" for t in targets)


@pytest.mark.parametrize(
    "value",
    ["169.254.169.254", "100.100.100.200", "fd00:ec2::254", "metadata.google.internal"],
)
def test_cloud_metadata_detected(value):
    t = make_target(value)
    assert is_cloud_metadata(t.kind, t.normalized)


def test_port_preserved_on_target():
    t = make_target("app.example.com:8443")
    assert t.ports == (8443,)


# ---- TASK-005 缺陷 2：裸文件名不是出网目标 ----------------------------------


@pytest.mark.parametrize(
    "cmd",
    [
        "cat robots.txt",
        "ls -la notes.md",
        "grep x data.csv",
    ],
)
def test_bare_filename_not_a_target(cmd):
    """两段式裸文件名（<label>.<常见后缀>）不得提取为域名目标。"""
    assert extract_targets(cmd) == []


def test_url_file_path_still_extracts_host():
    """URL 里的文件路径不受影响：域名来自 URL host 部分。"""
    targets = extract_targets("curl https://a.example.com/s/robots.txt")
    assert {t.normalized for t in targets} == {"a.example.com"}


def test_multilevel_host_with_file_path_still_extracts():
    """多级域名 + 文件路径（无 scheme）仍提取 host 部分。"""
    targets = extract_targets("curl cdn.example.com/file.txt")
    assert {t.normalized for t in targets} == {"cdn.example.com"}


def test_host_with_port_still_extracts():
    """带端口的 host 不受文件名过滤影响。"""
    targets = extract_targets("curl example.com:8080")
    assert len(targets) == 1
    assert targets[0].normalized == "example.com"
    assert targets[0].ports == (8080,)


def test_nmap_ip_command_unchanged():
    """IP 扫描命令行为不变（回归锚点）。"""
    targets = extract_targets("nmap -p443 10.20.30.4")
    assert {t.normalized for t in targets} == {"10.20.30.4"}
