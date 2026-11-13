"""scope_feed 子域发现喂入的单元测试（TASK-009）。

自包含，不依赖 conftest 夹具：DNS 查询通过 _feed_subdomains 的 resolve 参数
注入假解析表（未登记域名按 NXDOMAIN 跳过），不真实联网；nft 只在 dry-run
打印——main 级测试把 subprocess.run 换成炸弹，断言 dry-run 绝不执行。
"""

from __future__ import annotations

import argparse
import ipaddress
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEPLOY_DNS = ROOT / "deploy" / "dns"
for _p in (str(ROOT), str(DEPLOY_DNS)):
    if str(_p) not in sys.path:
        sys.path.insert(0, _p)

import scope_feed  # noqa: E402
from plugins.scope_gate.models import (  # noqa: E402
    Engagement, RateLimit, Target, TargetKind, TimeWindow,
)


def _args(**overrides) -> argparse.Namespace:
    """_feed_subdomains 所需的最小参数集（不含 --feed-pairs 路径的参数）。"""
    defaults = {
        "table": "hermes_scan",
        "pairs4": "allow_pairs4",
        "pairs6": "allow_pairs6",
        "ttl": 300,
        "dry_run": True,
        "resolver": "10.10.0.53",
        "loose_affinity": False,
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


def _domain_target(normalized: str = "parent.example", ports=(80,),
                   include_subdomains: bool = True) -> Target:
    return Target(kind=TargetKind.DOMAIN, normalized=normalized,
                  ports=tuple(ports), include_subdomains=include_subdomains)


def _engagement(*targets) -> Engagement:
    return Engagement(
        id="ENG-SUB-TEST", authorized_by="tester", authorization_doc="auth.md",
        window=TimeWindow(datetime(2026, 1, 1, tzinfo=timezone.utc),
                          datetime(2027, 1, 1, tzinfo=timezone.utc)),
        targets=tuple(targets), exclusions=(),
        allowed_actions=frozenset(), forbidden_actions=frozenset(),
        rate_limit=RateLimit(),
    )


class FakeResolve:
    """假解析表（注入 resolve）：name -> (IPv4 文本列表, IPv6 文本列表)。

    未登记的域名按 NXDOMAIN 处理（抛 ResolutionFailed，枚举探测的常态）；
    names 记录全部被查询过的名字，供断言前缀覆盖/未越界。
    """

    def __init__(self, table: dict | None = None):
        self.table = table or {}
        self.names: list[str] = []

    def __call__(self, name: str, resolver: str):
        self.names.append(name)
        if name not in self.table:
            raise scope_feed.ResolutionFailed(f"NXDOMAIN：{name}")
        v4_raw, v6_raw = self.table[name]
        return ([ipaddress.ip_address(a) for a in v4_raw],
                [ipaddress.ip_address(a) for a in v6_raw])


# ---- 默认前缀清单：任务书点名的常见前缀必须在内 --------------------------------


def test_default_prefixes_cover_task_list():
    """DEFAULT_SUBDOMAIN_PREFIXES 覆盖任务书清单（可 --subdomain-prefixes 覆盖）。"""
    required = {"www", "api", "app", "admin", "cdn", "static", "assets", "mail",
                "vpn", "dev", "test", "staging", "m", "mobile", "portal", "git",
                "jenkins", "docs", "status"}
    assert required <= set(scope_feed.DEFAULT_SUBDOMAIN_PREFIXES)


# ---- 发现→校验→喂入：同段子域生成 pair 命令 -------------------------------------


def test_subdomain_same_segment_generates_pair_commands(capsys):
    """www/api 解析成功且与父域同段 → 生成对应 allow_pairs4 元组命令 + dry-run 清单。"""
    fake = FakeResolve({
        "parent.example": (["47.74.33.82"], []),
        "www.parent.example": (["47.74.33.83"], []),   # 同 C 段（/24）
        "api.parent.example": (["47.74.99.9"], []),    # 同前两段（/16，不同 C 段）
    })
    failed = scope_feed._feed_subdomains(
        _engagement(_domain_target()), _args(),
        scope_feed.DEFAULT_SUBDOMAIN_PREFIXES, resolve=fake)
    out = capsys.readouterr().out
    assert failed == 0
    assert out.count("allow_pairs4") == 2
    assert "{ 47.74.33.83 . 80 timeout 300s }" in out
    assert "{ 47.74.99.9 . 80 timeout 300s }" in out
    # dry-run 打印发现的子域清单与摘要
    assert "# www.parent.example A" in out
    assert "发现 2 个（www.parent.example, api.parent.example）" in out
    assert "通过校验 2 个" in out


def test_subdomain_private_ip_skipped_with_warning(capsys, caplog):
    """子域解析到私网 IP（10.x）→ 跳过并 WARNING，不产生任何 pair 命令。"""
    fake = FakeResolve({
        "parent.example": (["47.74.33.82"], []),
        "www.parent.example": (["10.1.2.3"], []),
    })
    with caplog.at_level(logging.WARNING, logger="scope_feed"):
        failed = scope_feed._feed_subdomains(
            _engagement(_domain_target()), _args(), ("www",), resolve=fake)
    out = capsys.readouterr().out
    assert failed == 0
    assert "allow_pairs4" not in out  # 没有命令，只有摘要注释
    assert "10.1.2.3" in caplog.text and "私网" in caplog.text
    assert "归属校验跳过 1 个" in out  # 计入归属校验跳过并在摘要列出


def test_subdomain_ip_without_affinity_skipped(capsys, caplog):
    """子域 IP 与父域完全不同段（无 --loose-affinity）→ 跳过并 WARNING。"""
    fake = FakeResolve({
        "parent.example": (["47.74.33.82"], []),
        "www.parent.example": (["8.8.4.4"], []),
    })
    with caplog.at_level(logging.WARNING, logger="scope_feed"):
        failed = scope_feed._feed_subdomains(
            _engagement(_domain_target()), _args(), ("www",), resolve=fake)
    out = capsys.readouterr().out
    assert failed == 0
    assert "allow_pairs4" not in out
    assert "无归属亲和" in caplog.text
    # 警告必须写明这是保守启发式（严格归属校验需 crt.sh/CT 日志或被动 DNS）
    assert "保守启发式" in caplog.text and "crt.sh" in caplog.text


def test_loose_affinity_only_private_check(capsys):
    """--loose-affinity：不做亲和匹配、不解析父域，仅拒私网 → 异段公网 IP 放行。"""
    fake = FakeResolve({
        "www.parent.example": (["8.8.4.4"], []),  # 父域不在表里：loose 模式不该查它
    })
    failed = scope_feed._feed_subdomains(
        _engagement(_domain_target()), _args(loose_affinity=True), ("www",),
        resolve=fake)
    out = capsys.readouterr().out
    assert failed == 0
    assert "{ 8.8.4.4 . 80 timeout 300s }" in out
    assert fake.names == ["www.parent.example"]  # 只查了子域，父域查询一次都没发生


def test_v6_affinity_same_slash64_prefix(capsys):
    """IPv6 子域：同 /64 前缀放行并走 allow_pairs6，不同 /64 跳过。"""
    fake = FakeResolve({
        "parent.example": ([], ["2001:db8::1"]),
        "www.parent.example": ([], ["2001:db8::9"]),      # 同 /64
        "api.parent.example": ([], ["2001:db8:1::9"]),    # 不同 /64
    })
    failed = scope_feed._feed_subdomains(
        _engagement(_domain_target()), _args(),
        scope_feed.DEFAULT_SUBDOMAIN_PREFIXES, resolve=fake)
    out = capsys.readouterr().out
    assert failed == 0
    assert "{ 2001:db8::9 . 80 timeout 300s }" in out
    assert "{ 2001:db8:1::9" not in out
    assert "allow_pairs6" in out


# ---- fail closed：父域无公网锚点时严格模式整体跳过 --------------------------------


def test_strict_mode_without_public_anchor_skips_discovery(capsys, caplog):
    """父域解析失败或全落私网 → 无锚点整体跳过子域发现，子域查询一次都不发生。"""
    fake = FakeResolve({
        "allprivate.example": (["10.0.0.1"], []),
        "www.allprivate.example": (["47.74.33.83"], []),  # 不该被查到
    })
    with caplog.at_level(logging.WARNING, logger="scope_feed"):
        failed = scope_feed._feed_subdomains(
            _engagement(_domain_target(normalized="allprivate.example"),
                        _domain_target(normalized="dead.example")),
            _args(), ("www",), resolve=fake)
    out = capsys.readouterr().out
    assert failed == 0
    assert out == ""
    assert fake.names == ["allprivate.example", "dead.example"]  # 只查了父域
    assert caplog.text.count("跳过子域发现") == 2  # 全私网 / 解析失败各一条


# ---- main 级：dry-run 只打印、前缀覆盖与非法清单 fail closed ---------------------


def test_main_dry_run_prints_without_executing_nft(monkeypatch, capsys):
    """--dry-run 端到端：打印命令与清单、rc=0，subprocess.run 被换成炸弹也绝不触发。"""
    eng = _engagement(_domain_target(normalized="parent.example", ports=(80,)))
    monkeypatch.setattr(scope_feed, "_load_engagement", lambda path: eng)
    monkeypatch.setattr(scope_feed, "_check_window", lambda e: True)
    monkeypatch.setattr(scope_feed, "_resolve_domain", FakeResolve({
        "parent.example": (["47.74.33.82"], []),
        "www.parent.example": (["47.74.33.83"], []),
        "api.parent.example": (["47.74.33.84"], []),
    }))
    monkeypatch.setattr(
        scope_feed.subprocess, "run",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError(f"dry-run 不应执行 nft: {a}")))

    rc = scope_feed.main(["--scope", "ignored.yaml", "--feed-subdomains", "--dry-run"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "{ 47.74.33.83 . 80 timeout 300s }" in out
    assert "{ 47.74.33.84 . 80 timeout 300s }" in out
    assert "子域发现摘要" in out and "www.parent.example" in out


def test_subdomain_prefixes_override_via_main(monkeypatch, capsys):
    """--subdomain-prefixes 覆盖默认清单：只查询给定前缀，空白/重复项被清洗。"""
    eng = _engagement(_domain_target(normalized="parent.example"))
    fake = FakeResolve({
        "parent.example": (["47.74.33.82"], []),
        "api.parent.example": (["47.74.33.83"], []),
    })
    monkeypatch.setattr(scope_feed, "_load_engagement", lambda path: eng)
    monkeypatch.setattr(scope_feed, "_check_window", lambda e: True)
    monkeypatch.setattr(scope_feed, "_resolve_domain", fake)

    rc = scope_feed.main(["--scope", "ignored.yaml", "--feed-subdomains", "--dry-run",
                          "--subdomain-prefixes", "api, admin ,,api"])
    assert rc == 0
    assert sorted(fake.names) == ["admin.parent.example", "api.parent.example",
                                  "parent.example"]
    assert fake.names.count("api.parent.example") == 1  # 重复前缀去重
    assert "{ 47.74.33.83 . 80 timeout 300s }" in capsys.readouterr().out


def test_subdomain_prefixes_invalid_label_fails_closed(monkeypatch, caplog):
    """前缀含点/清空清单 → rc=2，在任何 scope 加载与 DNS 查询之前 fail closed。"""
    monkeypatch.setattr(scope_feed, "_load_engagement",
                        lambda path: (_ for _ in ()).throw(
                            AssertionError("非法前缀必须在 scope 加载前拒绝")))
    with caplog.at_level(logging.ERROR, logger="scope_feed"):
        assert scope_feed.main(["--scope", "ignored.yaml", "--feed-subdomains",
                                "--subdomain-prefixes", "www,a.b"]) == 2
        assert scope_feed.main(["--scope", "ignored.yaml", "--feed-subdomains",
                                "--subdomain-prefixes", " , ,"]) == 2
    assert "非法前缀" in caplog.text and "没有给出任何前缀" in caplog.text
