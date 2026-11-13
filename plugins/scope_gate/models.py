"""授权范围门禁（scope gate）的领域模型。

全部为 frozen dataclass：判定过程不允许就地修改，避免并发下状态漂移。
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime
from typing import FrozenSet, Mapping, Optional, Tuple


class TargetKind(str, enum.Enum):
    DOMAIN = "domain"
    IP = "ip"
    CIDR = "cidr"


class Action(str, enum.Enum):
    """engagement 允许/禁止的动作分级。

    分级原则：越靠后破坏性越强，需要的确认越重。
    """

    RECON_PASSIVE = "recon_passive"   # 只读公网信息，不触碰目标
    RECON_ACTIVE = "recon_active"     # 主动探测端口/指纹，有流量
    VULN_SCAN = "vuln_scan"           # 漏洞扫描，可能有破坏性 payload
    EXPLOIT_PROOF = "exploit_proof"   # 利用验证，必须人工确认

    @classmethod
    def parse(cls, raw: str) -> "Action":
        try:
            return cls(raw)
        except ValueError as e:
            valid = ", ".join(a.value for a in cls)
            raise ValueError(f"未知动作 {raw!r}，合法值: {valid}") from e


class Forbidden(str, enum.Enum):
    DOS = "dos"
    EXFIL = "exfil"
    PERSISTENCE = "persistence"
    CLOUD_METADATA = "cloud_metadata"
    LATERAL = "lateral"

    @classmethod
    def parse(cls, raw: str) -> "Forbidden":
        try:
            return cls(raw)
        except ValueError as e:
            valid = ", ".join(f.value for f in cls)
            raise ValueError(f"未知禁止项 {raw!r}，合法值: {valid}") from e


class DecisionKind(str, enum.Enum):
    ALLOW = "allow"
    APPROVE = "approve"   # 升级人工确认
    BLOCK = "block"


@dataclass(frozen=True)
class Target:
    """规范化之后的单个目标。

    normalized: 域名为小写 punycode 且无尾点；IP 为标准文本形式；CIDR 为 network 字符串。
    """

    kind: TargetKind
    normalized: str
    ports: Tuple[int, ...] = ()
    include_subdomains: bool = False
    raw: str = ""

    def __str__(self) -> str:
        return f"{self.kind.value}:{self.normalized}"


@dataclass(frozen=True)
class Exclusion:
    kind: TargetKind
    normalized: str
    reason: str = ""

    def __str__(self) -> str:
        return f"{self.kind.value}:{self.normalized}"


@dataclass(frozen=True)
class TimeWindow:
    start: datetime
    end: datetime

    def contains(self, now: datetime) -> bool:
        return self.start <= now <= self.end


@dataclass(frozen=True)
class RateLimit:
    rps_per_host: float = 5.0
    max_requests_per_host: int = 2000
    max_total: int = 20000
    burst: int = 10


@dataclass(frozen=True)
class Engagement:
    """一次授权作业的完整约束。构造后不可变。"""

    id: str
    authorized_by: str
    authorization_doc: str
    window: TimeWindow
    targets: Tuple[Target, ...]
    exclusions: Tuple[Exclusion, ...]
    allowed_actions: FrozenSet[Action]
    forbidden_actions: FrozenSet[Forbidden]
    rate_limit: RateLimit
    source_path: str = ""
    source_sha256: str = ""
    loaded_at: Optional[datetime] = None

    @property
    def domain_targets(self) -> Tuple[Target, ...]:
        return tuple(t for t in self.targets if t.kind is TargetKind.DOMAIN)

    @property
    def cidr_targets(self) -> Tuple[Target, ...]:
        return tuple(t for t in self.targets if t.kind is TargetKind.CIDR)

    @property
    def ip_targets(self) -> Tuple[Target, ...]:
        return tuple(t for t in self.targets if t.kind is TargetKind.IP)

    def summary(self) -> str:
        """给模型看的范围摘要，不含排除项细节（避免泄漏客户内网结构）。"""
        parts = [str(t) for t in self.targets[:6]]
        more = "" if len(self.targets) <= 6 else f" 等 {len(self.targets)} 项"
        acts = ",".join(sorted(a.value for a in self.allowed_actions))
        return f"engagement={self.id} 范围: {' '.join(parts)}{more} 允许动作: {acts}"


@dataclass(frozen=True)
class Request:
    """一次待判定的工具调用。"""

    tool_name: str
    action: Action
    targets: Tuple[str, ...]          # 归一化前的原始目标文本
    resolved_ips: Mapping[str, Tuple[str, ...]] = field(default_factory=dict)
    unresolvable: Tuple[str, ...] = ()
    command: str = ""
    script_path: str = ""
    paths: Tuple[str, ...] = ()
    session_id: str = ""
    conversation_id: str = ""
    tool_call_id: str = ""
    turn_id: str = ""


@dataclass(frozen=True)
class Decision:
    kind: DecisionKind
    code: str
    message: str
    target: str = ""

    @property
    def is_block(self) -> bool:
        return self.kind is DecisionKind.BLOCK

    @property
    def is_approve(self) -> bool:
        return self.kind is DecisionKind.APPROVE

    def as_hook_result(self) -> Optional[dict]:
        """转成 Hermes `pre_tool_call` 约定的返回值。allow 返回 None 表示不干预。"""
        if self.kind is DecisionKind.ALLOW:
            return None
        payload = {"action": self.kind.value, "message": self.message}
        if self.kind is DecisionKind.APPROVE:
            payload["rule_key"] = f"scope:{self.code}"
        return payload
