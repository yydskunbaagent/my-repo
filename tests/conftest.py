"""
测试夹具：不碰真实 DNS、不碰真实时钟。

真实网络在单测里是污染源（不可复现、偶发超时）。所有测试都用 FakeResolver
和可注入的 clock，保证判定结果完全确定。
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

PLUGINS_DIR = Path(__file__).resolve().parents[1] / "plugins"
if str(PLUGINS_DIR) not in sys.path:
    sys.path.insert(0, str(PLUGINS_DIR))

from scope_gate.gate import GateConfig, ScopeGate  # noqa: E402
from scope_gate.scope import parse_scope  # noqa: E402


class FakeResolver:
    def __init__(self, mapping: dict[str, tuple[str, ...]] | None = None,
                 fail: set[str] | None = None):
        self.mapping = mapping or {}
        self.fail = fail or set()
        self.calls: list[str] = []

    def resolve(self, host: str):
        self.calls.append(host)
        if host in self.fail:
            return None
        if host in self.mapping:
            return self.mapping[host]
        return ("93.184.216.34",)

    def close(self) -> None:
        pass


SCOPE_DICT = {
    "engagement": {
        "id": "ENG-TEST-001",
        "authorized_by": "security@example.com",
        "authorization_doc": "authorization.md",
        "window": {"start": "2026-01-01T00:00:00+00:00", "end": "2027-01-01T00:00:00+00:00"},
        "targets": [
            {"kind": "domain", "value": "app.example.com"},
            {"kind": "domain", "value": "example.org", "include_subdomains": True},
            {"kind": "cidr", "value": "10.20.30.0/28", "ports": [80, 443, 8080]},
            {"kind": "ip", "value": "203.0.113.10"},
        ],
        "exclusions": [
            {"kind": "ip", "value": "10.20.30.5", "reason": "生产库"},
        ],
        "allowed_actions": ["recon_passive", "recon_active", "vuln_scan", "exploit_proof"],
        "forbidden_actions": ["dos", "exfil", "persistence", "cloud_metadata"],
        "rate_limit": {"rps_per_host": 1000, "max_requests_per_host": 1000, "max_total": 5000},
        "on_unparsed_target": "block",
    }
}


@pytest.fixture
def engagement():
    return parse_scope(SCOPE_DICT)


@pytest.fixture
def scope_file(tmp_path) -> Path:
    import yaml

    p = tmp_path / "scope.yaml"
    p.write_text(yaml.safe_dump(SCOPE_DICT, allow_unicode=True), encoding="utf-8")
    return p


@pytest.fixture
def make_gate(tmp_path, scope_file):
    def _make(resolver=None, **overrides):
        cfg = GateConfig(
            scope_path=scope_file,
            audit_path=tmp_path / "audit" / "decisions.jsonl",
            rate_limit_db=tmp_path / "audit" / "rl.sqlite3",
            protected_paths=(scope_file, tmp_path / "audit"),
            **overrides,
        )
        return ScopeGate(cfg, resolver=resolver or FakeResolver())

    return _make


class FakeClock:
    def __init__(self, start: float = 1000.0):
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds
