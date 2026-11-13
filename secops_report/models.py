"""黑盒发现报告生成器（secops_report）的领域模型。

与 plugins/scope_gate 的 models 同风格：frozen dataclass + str 枚举。
构造时把字符串入参归一成枚举成员，非法取值当场抛 ValueError——
报告宁可构造失败，也不带脏数据渲染（fail closed 的报告版）。
"""

from __future__ import annotations

import enum
import itertools
from dataclasses import dataclass, field
from datetime import datetime


class Severity(str, enum.Enum):
    """发现的严重度，执行摘要按此统计。"""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @classmethod
    def parse(cls, raw: str) -> "Severity":
        try:
            return cls(raw)
        except ValueError as e:
            valid = ", ".join(s.value for s in cls)
            raise ValueError(f"未知严重度 {raw!r}，合法值: {valid}") from e


class FindingStatus(str, enum.Enum):
    """结论三档：借鉴 validation-policy 的正负对照原则（方案 §6）。"""

    CONFIRMED = "confirmed"   # 正负对照齐全且清理完成
    OBSERVED = "observed"     # 有现象但证据不足以确认
    REJECTED = "rejected"     # 复核否决，只进附录

    @classmethod
    def parse(cls, raw: str) -> "FindingStatus":
        try:
            return cls(raw)
        except ValueError as e:
            valid = ", ".join(s.value for s in cls)
            raise ValueError(f"未知结论 {raw!r}，合法值: {valid}") from e


class EvidenceKind(str, enum.Enum):
    """证据的定性：命令输出 / 截图 / 请求响应对 / 日志。"""

    COMMAND = "command"
    SCREENSHOT = "screenshot"
    HTTP_PAIR = "http_pair"
    LOG = "log"

    @classmethod
    def parse(cls, raw: str) -> "EvidenceKind":
        try:
            return cls(raw)
        except ValueError as e:
            valid = ", ".join(k.value for k in cls)
            raise ValueError(f"未知证据类型 {raw!r}，合法值: {valid}") from e


def _coerce(value: str | enum.Enum, enum_cls: type[enum.Enum]) -> enum.Enum:
    """字符串/枚举成员二选一进来，统一归一成枚举成员；非法值抛 ValueError。"""
    if isinstance(value, enum_cls):
        return value
    return enum_cls.parse(value)


@dataclass(frozen=True)
class Evidence:
    """一条佐证材料。

    artifact 指向落盘文件路径，或 "inline:..." 形式的内联文本引用；
    缺省表示只有口头描述、没有可复核材料。
    """

    kind: EvidenceKind
    summary: str
    artifact: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", _coerce(self.kind, EvidenceKind))


@dataclass(frozen=True)
class Poc:
    """概念验证：正对照必备；负对照与清理状态决定能否够格 confirmed。"""

    positive: Evidence
    negative: Evidence | None = None
    cleanup_done: bool = False


_finding_seq = itertools.count(1)


def _next_finding_id() -> str:
    """F-001 格式自动编号；显式传入 id 时不消耗计数。"""
    return f"F-{next(_finding_seq):03d}"


@dataclass(frozen=True)
class Finding:
    """一条黑盒发现。

    id 缺省时按 F-001 格式自动编号；severity/status 允许直接传字符串，
    构造时归一成枚举。dataclass 要求无默认值字段在前，故 discovered_at
    排在 status 之后。
    """

    title: str
    target: str
    severity: Severity
    status: FindingStatus
    discovered_at: datetime
    description: str = ""
    evidence: list[Evidence] = field(default_factory=list)
    poc: Poc | None = None
    id: str = field(default_factory=_next_finding_id)

    def __post_init__(self) -> None:
        object.__setattr__(self, "severity", _coerce(self.severity, Severity))
        object.__setattr__(self, "status", _coerce(self.status, FindingStatus))
