"""scope_feed 二元组喂入的单元测试（TASK-007 任务 2）。

自包含，不依赖 conftest 夹具；只测 nft 命令构造与 dry-run 打印，
不触网（DNS 编解码/解析路径由 TASK-007 验收命令 --dry-run 实测覆盖）。
"""

from __future__ import annotations

import argparse
import ipaddress
import sys
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
DEPLOY_DNS = ROOT / "deploy" / "dns"
for _p in (str(ROOT), str(DEPLOY_DNS)):
    if str(_p) not in sys.path:
        sys.path.insert(0, _p)

import scope_feed  # noqa: E402


def _args(**overrides) -> argparse.Namespace:
    """_feed_target_pairs / _target_ports 所需的最小参数集。"""
    defaults = {
        "table": "hermes_scan",
        "pairs4": "allow_pairs4",
        "pairs6": "allow_pairs6",
        "ttl": 300,
        "dry_run": True,
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


# ---- nft 命令形状：与 scan-node.nft 的 allow_pairs4/6 集合定义严格对应 ---------


def test_pair_command_shape():
    """二元组命令 = `nft add element inet <表> <集合> { <ip> . <port> timeout <ttl>s }`。"""
    cmd = scope_feed._nft_add_pair("hermes_scan", "allow_pairs4", "47.74.33.82", 80, 300)
    assert cmd == ["nft", "add", "element", "inet", "hermes_scan", "allow_pairs4",
                   "{ 47.74.33.82 . 80 timeout 300s }"]


def test_default_set_names_are_pairs():
    """默认集合名指向 scan-node.nft 的二元组集合（allow_domains 已随任务废弃）。"""
    assert scope_feed.DEFAULT_SET_PAIRS4 == "allow_pairs4"
    assert scope_feed.DEFAULT_SET_PAIRS6 == "allow_pairs6"


# ---- 目标端口：缺省按 80,443 的假设必须显式暴露 --------------------------------


def test_target_ports_explicit_sorted_dedup():
    """声明了 ports 的目标用声明值（去重升序），不算缺省假设。"""
    t = SimpleNamespace(ports=(443, 80, 80))
    ports, defaulted = scope_feed._target_ports(t)
    assert ports == [80, 443]
    assert defaulted is False


def test_target_ports_default_80_443():
    """ports 缺省 -> 按 80,443 处理，且 defaulted=True（调用方打日志说明假设）。"""
    t = SimpleNamespace(ports=())
    ports, defaulted = scope_feed._target_ports(t)
    assert ports == [80, 443]
    assert defaulted is True


# ---- dry-run 打印：验收命令要求输出含 allow_pairs4 元组命令 ---------------------


def test_feed_target_pairs_dry_run_prints_pair_commands(capsys):
    """v4 地址 × 每个授权端口逐条打印 allow_pairs4 元组命令。"""
    v4 = [ipaddress.ip_address("47.74.33.82")]
    failed = scope_feed._feed_target_pairs(
        _args(), "yyds520.online", "测试源", v4, [], [80, 443], set())
    out = capsys.readouterr().out
    assert failed == 0
    assert "allow_pairs4" in out
    assert "{ 47.74.33.82 . 80 timeout 300s }" in out
    assert "{ 47.74.33.82 . 443 timeout 300s }" in out


def test_feed_target_pairs_v6_uses_pairs6(capsys):
    """AAAA 地址走 allow_pairs6。"""
    v6 = [ipaddress.ip_address("2001:db8::1")]
    failed = scope_feed._feed_target_pairs(
        _args(), "yyds520.online", "测试源", [], v6, [80], set())
    out = capsys.readouterr().out
    assert failed == 0
    assert "allow_pairs6" in out
    assert "{ 2001:db8::1 . 80 timeout 300s }" in out


def test_feed_target_pairs_skips_private_addresses(capsys):
    """私网/保留地址与门禁引擎口径一致：跳过、不产生任何条目。"""
    v4 = [ipaddress.ip_address("10.1.2.3")]
    failed = scope_feed._feed_target_pairs(
        _args(), "intranet.example", "测试源", v4, [], [80], set())
    assert failed == 0
    assert capsys.readouterr().out == ""


def test_feed_target_pairs_dedupes_across_targets(capsys):
    """多域名解析到同一 IP:端口 -> 只喂一次（seen 跨目标去重）。"""
    seen: set = set()
    v4 = [ipaddress.ip_address("47.74.33.82")]
    failed = scope_feed._feed_target_pairs(
        _args(), "a.example", "测试源", v4, [], [80], seen)
    failed += scope_feed._feed_target_pairs(
        _args(), "b.example", "测试源", v4, [], [80], seen)
    out = capsys.readouterr().out
    assert failed == 0
    assert out.count("{ 47.74.33.82 . 80 timeout 300s }") == 1
