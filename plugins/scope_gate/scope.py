"""scope.yaml 的加载与严格校验。

设计原则：
1. **未知字段直接报错**。允许未知字段等于允许"写错了但没人发现"，而这里写错的代价是越界。
2. **不允许把 `on_unparsed_target` 配成 allow**。语义上不提供"解析不出就放行"的开关。
3. 文件按 mtime 热加载；重新加载失败时**保留旧配置并标记 degraded**，而不是退回无约束。
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple

from .models import (
    Action,
    Engagement,
    Exclusion,
    Forbidden,
    RateLimit,
    Target,
    TargetKind,
    TimeWindow,
)
from .target import TargetError, make_target

logger = logging.getLogger(__name__)

try:  # Hermes 自带的 YAML 兼容层优先，避免与宿主环境的 PyYAML 版本冲突
    import hermes_yaml as _yaml  # type: ignore
except Exception:  # pragma: no cover
    try:
        import yaml as _yaml  # type: ignore
    except Exception:  # pragma: no cover
        _yaml = None


class ScopeConfigError(ValueError):
    """scope 配置非法。调用方必须据此拒绝所有出网动作。"""


_TOP_KEYS = {"engagement"}
_ENG_KEYS = {
    "id", "authorized_by", "authorization_doc", "window", "targets",
    "exclusions", "allowed_actions", "forbidden_actions",
    "rate_limit", "on_unparsed_target", "notes",
}
_TARGET_KEYS = {"kind", "value", "ports", "include_subdomains", "reason", "note"}


def _require(mapping: Mapping[str, Any], key: str, where: str) -> Any:
    if key not in mapping:
        raise ScopeConfigError(f"{where} 缺少必填字段 {key!r}")
    return mapping[key]


def _check_keys(mapping: Mapping[str, Any], allowed: set[str], where: str) -> None:
    unknown = set(mapping) - allowed
    if unknown:
        raise ScopeConfigError(
            f"{where} 含未知字段 {sorted(unknown)}；为避免拼写错误被静默忽略，此处直接拒绝"
        )


def _parse_dt(raw: Any, where: str) -> datetime:
    if isinstance(raw, datetime):
        return raw
    if not isinstance(raw, str):
        raise ScopeConfigError(f"{where} 必须是 ISO8601 字符串")
    text = raw.strip().replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(text)
    except ValueError as e:
        raise ScopeConfigError(f"{where} 不是合法 ISO8601: {raw!r}") from e


def _parse_target(item: Any, where: str) -> Target:
    if not isinstance(item, Mapping):
        raise ScopeConfigError(f"{where} 必须是映射")
    _check_keys(item, _TARGET_KEYS, where)
    kind_raw = str(_require(item, "kind", where))
    value = str(_require(item, "value", where))
    if kind_raw not in {k.value for k in TargetKind}:
        raise ScopeConfigError(
            f"{where}.kind={kind_raw!r} 非法，合法值: {[k.value for k in TargetKind]}"
        )
    try:
        target = make_target(
            value,
            include_subdomains=bool(item.get("include_subdomains", False)),
        )
    except TargetError as e:
        raise ScopeConfigError(f"{where}.value 非法: {e}") from e

    if target.kind is not TargetKind(kind_raw):
        raise ScopeConfigError(
            f"{where}.kind={kind_raw} 与 value={value!r} 推导出的类型 {target.kind.value} 不一致"
        )

    ports_raw = item.get("ports") or []
    if not isinstance(ports_raw, (list, tuple)):
        raise ScopeConfigError(f"{where}.ports 必须是列表")
    ports: List[int] = []
    for p in ports_raw:
        if not isinstance(p, int) or not 1 <= p <= 65535:
            raise ScopeConfigError(f"{where}.ports 含非法端口 {p!r}")
        ports.append(p)

    return Target(
        kind=target.kind,
        normalized=target.normalized,
        ports=tuple(ports) or target.ports,
        include_subdomains=target.include_subdomains,
        raw=value,
    )


def _parse_exclusion(item: Any, where: str) -> Exclusion:
    if not isinstance(item, Mapping):
        raise ScopeConfigError(f"{where} 必须是映射")
    _check_keys(item, _TARGET_KEYS, where)
    kind_raw = str(_require(item, "kind", where))
    value = str(_require(item, "value", where))
    if kind_raw not in {k.value for k in TargetKind}:
        raise ScopeConfigError(f"{where}.kind={kind_raw!r} 非法")
    try:
        t = make_target(value)
    except TargetError as e:
        raise ScopeConfigError(f"{where}.value 非法: {e}") from e
    return Exclusion(kind=t.kind, normalized=t.normalized, reason=str(item.get("reason", "")))


def _parse_actions(raw: Any) -> frozenset[Action]:
    if raw is None:
        return frozenset({Action.RECON_PASSIVE})
    if not isinstance(raw, (list, tuple)):
        raise ScopeConfigError("allowed_actions 必须是列表")
    try:
        return frozenset(Action.parse(str(a)) for a in raw)
    except ValueError as e:
        raise ScopeConfigError(str(e)) from e


def _parse_forbidden(raw: Any) -> frozenset[Forbidden]:
    default = {Forbidden.DOS, Forbidden.EXFIL, Forbidden.PERSISTENCE, Forbidden.CLOUD_METADATA}
    if raw is None:
        return frozenset(default)
    if not isinstance(raw, (list, tuple)):
        raise ScopeConfigError("forbidden_actions 必须是列表")
    try:
        return frozenset(Forbidden.parse(str(f)) for f in raw)
    except ValueError as e:
        raise ScopeConfigError(str(e)) from e


def _parse_rate(raw: Any) -> RateLimit:
    if raw is None:
        return RateLimit()
    if not isinstance(raw, Mapping):
        raise ScopeConfigError("rate_limit 必须是映射")
    _check_keys(raw, {"rps_per_host", "max_requests_per_host", "max_total", "burst"}, "rate_limit")
    rps = float(raw.get("rps_per_host", 5.0))
    if not 0 < rps <= 1000:
        raise ScopeConfigError("rate_limit.rps_per_host 必须在 (0, 1000]")
    per_host = int(raw.get("max_requests_per_host", 2000))
    total = int(raw.get("max_total", 20000))
    burst = int(raw.get("burst", max(1, int(rps * 2))))
    if per_host <= 0 or total <= 0 or burst <= 0:
        raise ScopeConfigError("rate_limit 的计数上限必须为正整数")
    if per_host > total:
        raise ScopeConfigError("rate_limit.max_requests_per_host 不能大于 max_total")
    return RateLimit(rps_per_host=rps, max_requests_per_host=per_host, max_total=total, burst=burst)


def parse_scope(data: Mapping[str, Any], *, source_path: str = "",
                source_sha256: str = "") -> Engagement:
    """校验并构造 Engagement。任何可疑之处一律抛 ScopeConfigError。"""
    if not isinstance(data, Mapping):
        raise ScopeConfigError("scope 文件顶层必须是映射")
    _check_keys(data, _TOP_KEYS, "顶层")
    eng = _require(data, "engagement", "顶层")
    if not isinstance(eng, Mapping):
        raise ScopeConfigError("engagement 必须是映射")
    _check_keys(eng, _ENG_KEYS, "engagement")

    on_unparsed = str(eng.get("on_unparsed_target", "block")).lower()
    if on_unparsed != "block":
        raise ScopeConfigError(
            "on_unparsed_target 只允许 'block'：本门禁不提供'解析不出就放行'的开关"
        )

    window_raw = _require(eng, "window", "engagement")
    if not isinstance(window_raw, Mapping):
        raise ScopeConfigError("engagement.window 必须是映射")
    _check_keys(window_raw, {"start", "end"}, "engagement.window")
    start = _parse_dt(_require(window_raw, "start", "engagement.window"), "window.start")
    end = _parse_dt(_require(window_raw, "end", "engagement.window"), "window.end")
    if start >= end:
        raise ScopeConfigError("window.start 必须早于 window.end")

    targets_raw = _require(eng, "targets", "engagement")
    if not isinstance(targets_raw, (list, tuple)) or not targets_raw:
        raise ScopeConfigError("engagement.targets 必须是非空列表")
    targets = tuple(
        _parse_target(t, f"targets[{i}]") for i, t in enumerate(targets_raw)
    )

    exclusions_raw = eng.get("exclusions") or []
    if not isinstance(exclusions_raw, (list, tuple)):
        raise ScopeConfigError("engagement.exclusions 必须是列表")
    exclusions = tuple(
        _parse_exclusion(e, f"exclusions[{i}]") for i, e in enumerate(exclusions_raw)
    )

    if not str(eng.get("authorized_by", "")).strip():
        raise ScopeConfigError("engagement.authorized_by 不能为空——没有授权人就不该有作业")

    return Engagement(
        id=str(_require(eng, "id", "engagement")),
        authorized_by=str(eng["authorized_by"]),
        authorization_doc=str(eng.get("authorization_doc", "")),
        window=TimeWindow(start=start, end=end),
        targets=targets,
        exclusions=exclusions,
        allowed_actions=_parse_actions(eng.get("allowed_actions")),
        forbidden_actions=_parse_forbidden(eng.get("forbidden_actions")),
        rate_limit=_parse_rate(eng.get("rate_limit")),
        source_path=source_path,
        source_sha256=source_sha256,
        loaded_at=datetime.now().astimezone(),
    )


@dataclass
class LoadState:
    engagement: Optional[Engagement] = None
    error: str = ""
    degraded: bool = False

    @property
    def usable(self) -> bool:
        return self.engagement is not None


class ScopeStore:
    """scope.yaml 的持有者。线程安全，按 mtime 热加载。

    加载失败时：
      - 之前有成功配置 -> 保留旧的，标记 degraded（不退回无约束）
      - 从未成功过     -> 保持 unusable，门禁对一切出网动作 fail closed
    """

    def __init__(self, path: str | os.PathLike[str]):
        self.path = Path(path)
        self._lock = __import__("threading").RLock()
        self._mtime: float = -1.0
        self._state = LoadState(error="尚未加载")

    @property
    def state(self) -> LoadState:
        self.reload_if_changed()
        with self._lock:
            return self._state

    def reload_if_changed(self) -> LoadState:
        with self._lock:
            try:
                stat = self.path.stat()
            except OSError as e:
                self._state = LoadState(error=f"scope 文件不可读: {e}", degraded=self._state.usable)
                return self._state
            if stat.st_mtime == self._mtime and self._state.usable:
                return self._state
            self._mtime = stat.st_mtime
            return self._load(stat.st_mtime)

    def _load(self, mtime: float) -> LoadState:
        try:
            raw_bytes = self.path.read_bytes()
        except OSError as e:
            self._state = LoadState(error=f"scope 文件读取失败: {e}", degraded=self._state.usable)
            return self._state

        digest = hashlib.sha256(raw_bytes).hexdigest()
        if _yaml is None:
            self._state = LoadState(error="缺少 YAML 解析器（hermes_yaml / PyYAML）",
                                    degraded=self._state.usable)
            return self._state
        try:
            data = _yaml.safe_load(raw_bytes.decode("utf-8"))
        except Exception as e:
            self._state = LoadState(error=f"scope YAML 解析失败: {e}", degraded=self._state.usable)
            return self._state

        try:
            engagement = parse_scope(data, source_path=str(self.path), source_sha256=digest)
        except ScopeConfigError as e:
            logger.error("scope 校验失败: %s", e)
            self._state = LoadState(error=str(e), degraded=self._state.usable)
            return self._state

        self._state = LoadState(engagement=engagement)
        logger.info("scope 已加载: %s (sha256=%s)", engagement.id, digest[:12])
        return self._state

    def dump_for_audit(self) -> Dict[str, Any]:
        st = self.state
        if not st.engagement:
            return {"loaded": False, "error": st.error}
        eng = st.engagement
        return {
            "loaded": True,
            "engagement_id": eng.id,
            "sha256": eng.source_sha256,
            "window": [eng.window.start.isoformat(), eng.window.end.isoformat()],
            "targets": [str(t) for t in eng.targets],
            "exclusions": [str(e) for e in eng.exclusions],
            "allowed_actions": sorted(a.value for a in eng.allowed_actions),
            "forbidden_actions": sorted(f.value for f in eng.forbidden_actions),
            "degraded": st.degraded,
        }
