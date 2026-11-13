"""钩子入口：把引擎、解析器、限速、审计装配起来。

对外只暴露两个函数，签名严格遵循 Hermes `pre_tool_call` / `post_tool_call` 契约：

    pre_tool_call(tool_name, args, **kwargs)  -> Optional[dict]
    post_tool_call(tool_name, args, result, **kwargs) -> None

`pre_tool_call` 永不抛异常：任何内部错误都转成 block。因为 Hermes 对抛异常的处理是
fail closed 但不给模型可读原因，模型会反复重试同一个调用；我们给结构化原因，让它能纠正。
"""

from __future__ import annotations

import concurrent.futures
import ipaddress
import logging
import os
import socket
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Tuple

from .audit import AuditLog
from .engine import decide
from .extract import LOCAL_READ_TOOLS, LOCAL_WRITE_TOOLS, analyze_tool, paths_from_args
from .models import Action, Decision, DecisionKind, TargetKind
from .ratelimit import RateLimiter
from .scope import ScopeStore

logger = logging.getLogger("scope_gate")

DNS_TTL_SECONDS = 300
DNS_TIMEOUT_SECONDS = 4.0
MAX_CACHE_ENTRIES = 2048


@dataclass
class GateConfig:
    scope_path: Path
    audit_path: Path
    rate_limit_db: Path
    protected_paths: Tuple[Path, ...] = ()
    dns_ttl: int = DNS_TTL_SECONDS
    dns_timeout: float = DNS_TIMEOUT_SECONDS
    allow_local_write: bool = True

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any], base_dir: Path) -> "GateConfig":
        def _resolve(raw: Any, default: str) -> Path:
            p = Path(str(raw if raw not in (None, "") else default)).expanduser()
            return p if p.is_absolute() else (base_dir / p)

        protected = tuple(
            _resolve(item, "") for item in (data.get("protected_paths") or []) if str(item).strip()
        )
        scope_path = _resolve(data.get("scope_path"), "scope.yaml")
        audit_path = _resolve(data.get("audit_path"), "audit/decisions.jsonl")

        # scope 文件与审计目录默认受保护：它们属于"作业元数据"，Agent 不得改写
        mandated = [scope_path, audit_path.parent]
        for extra in protected:
            if extra not in mandated:
                mandated.append(extra)

        return cls(
            scope_path=scope_path,
            audit_path=audit_path,
            rate_limit_db=_resolve(data.get("rate_limit_db"), "audit/ratelimit.sqlite3"),
            protected_paths=tuple(mandated),
            dns_ttl=int(data.get("dns_ttl", DNS_TTL_SECONDS)),
            dns_timeout=float(data.get("dns_timeout", DNS_TIMEOUT_SECONDS)),
            allow_local_write=bool(data.get("allow_local_write", True)),
        )


class Resolver:
    """带 TTL 缓存的 DNS 解析器，超时即判失败（fail closed）。

    getaddrinfo 没有原生超时，这里放到线程池里等；超时后结果丢弃，
    并记入 unresolvable，由引擎拒绝该目标。
    """

    def __init__(self, ttl: int = DNS_TTL_SECONDS, timeout: float = DNS_TIMEOUT_SECONDS):
        self.ttl = ttl
        self.timeout = timeout
        self._cache: Dict[str, Tuple[Tuple[str, ...], float]] = {}
        self._lock = threading.Lock()
        self._pool = concurrent.futures.ThreadPoolExecutor(max_workers=4,
                                                           thread_name_prefix="scope-dns")

    def resolve(self, host: str) -> Optional[Tuple[str, ...]]:
        """返回 IP 元组；None 表示解析失败/超时。"""
        try:
            ipaddress.ip_address(host)
            return (host,)          # 本来就是 IP，无需解析
        except ValueError:
            pass

        now = time.monotonic()
        with self._lock:
            hit = self._cache.get(host)
            if hit and hit[1] > now:
                return hit[0]

        try:
            future = self._pool.submit(
                socket.getaddrinfo, host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            infos = future.result(timeout=self.timeout)
        except Exception as e:
            logger.warning("DNS 解析失败 %s: %s", host, e)
            return None

        ips = []
        for info in infos:
            addr = info[4][0]
            try:
                ips.append(str(ipaddress.ip_address(addr)))
            except ValueError:
                continue
        if not ips:
            return None
        result = tuple(sorted(set(ips)))
        with self._lock:
            if len(self._cache) > MAX_CACHE_ENTRIES:
                self._cache.clear()
            self._cache[host] = (result, now + self.ttl)
        return result

    def close(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)


class ScopeGate:
    def __init__(self, config: GateConfig, *, resolver: Optional[Resolver] = None,
                 clock=None):
        self.config = config
        self.store = ScopeStore(config.scope_path)
        self.audit = AuditLog(config.audit_path)
        self.limiter = RateLimiter(config.rate_limit_db, clock=clock or time.monotonic)
        self.resolver = resolver or Resolver(config.dns_ttl, config.dns_timeout)

    # -- 路径保护 -----------------------------------------------------------

    def _protected(self, paths: Tuple[str, ...]) -> Optional[str]:
        """返回命中的受保护路径。

        保护对象是"作业元数据"：scope.yaml、审计目录、授权书等。命中即拒绝，
        因为这些文件一旦被 Agent 改写，整个门禁的前提就被抽掉了。
        """
        resolved_protected = []
        for root in self.config.protected_paths:
            try:
                resolved_protected.append(Path(root).expanduser().resolve())
            except (OSError, RuntimeError):
                continue
        if not resolved_protected:
            return None

        for raw in paths:
            if not str(raw).strip():
                continue
            try:
                candidate = Path(raw).expanduser().resolve()
            except (OSError, RuntimeError):
                return str(raw)
            for prot in resolved_protected:
                if candidate == prot:
                    return str(candidate)
                if prot.is_dir() and prot in candidate.parents:
                    return str(candidate)
        return None

    # -- 主流程 -------------------------------------------------------------

    def evaluate(self, tool_name: str, args: Any) -> Decision:
        args = args if isinstance(args, dict) else {}

        # 本地只读：直接放行（但仍记账）
        if tool_name in LOCAL_READ_TOOLS:
            return Decision(DecisionKind.ALLOW, "local_read", "")

        # 写本地文件：只做路径保护
        if tool_name in LOCAL_WRITE_TOOLS:
            hit = self._protected(paths_from_args(tool_name, args))
            if hit:
                return Decision(
                    DecisionKind.BLOCK, "protected_path",
                    f"[scope-gate] 被拒绝：{hit} 属于作业元数据（scope / 授权书 / 审计），"
                    f"Agent 不得写入。请把产出写到 evidence/ 或 reports/ 下。",
                )
            return Decision(DecisionKind.ALLOW, "local_write", "")

        state = self.store.state
        if not state.usable:
            return Decision(
                DecisionKind.BLOCK, "no_engagement",
                f"[scope-gate] 被拒绝：scope 不可用（{state.error}）。"
                f"在修复之前，所有出网动作一律阻止。",
            )

        analysis = analyze_tool(tool_name, args)

        # 脚本执行一律拒绝：目标藏在脚本里，命令行无法校验
        if analysis.script_path:
            return Decision(
                DecisionKind.BLOCK, "script_execution",
                f"[scope-gate] 被拒绝：不允许通过脚本文件执行（{analysis.script_path}）。"
                f"命令行里看不到真实目标，无法做范围校验。请直接调用扫描工具，"
                f"或使用预先登记并上报目标的 wrapper。",
            )

        resolved: Dict[str, Tuple[str, ...]] = {}
        unresolvable = []
        for t in analysis.targets:
            if t.kind is TargetKind.DOMAIN:
                ips = self.resolver.resolve(t.normalized)
                if ips is None:
                    unresolvable.append(t.normalized)
                else:
                    resolved[t.normalized] = ips

        eng = state.engagement
        rate_checker = None
        if eng is not None:
            def rate_checker(host: str):  # noqa: ANN001
                v = self.limiter.check(
                    engagement_id=eng.id,
                    host=host,
                    rps=eng.rate_limit.rps_per_host,
                    burst=eng.rate_limit.burst,
                    max_per_host=eng.rate_limit.max_requests_per_host,
                    max_total=eng.rate_limit.max_total,
                )
                return (v.allowed, v.code, v.detail)

        return decide(
            eng,
            tool_name=tool_name,
            action=analysis.action,
            targets=analysis.targets,
            resolved=resolved,
            unresolvable=tuple(unresolvable),
            forbidden_hit=analysis.forbidden,
            parse_error=analysis.parse_error,
            rate_checker=rate_checker,
        )

    # -- 钩子 ---------------------------------------------------------------

    def pre_tool_call(self, tool_name: str = "", args: Any = None, **kwargs: Any) -> Optional[dict]:
        started = time.monotonic()
        try:
            decision = self.evaluate(tool_name, args)
        except Exception as e:  # 任何内部异常都必须转成拒绝
            logger.exception("scope-gate 内部错误")
            decision = Decision(
                DecisionKind.BLOCK, "gate_error",
                f"[scope-gate] 被拒绝：门禁内部错误（{type(e).__name__}: {e}）。"
                f"在运维修复前，出网动作不会放行。",
            )
        try:
            self._record(tool_name, args, decision, kwargs, (time.monotonic() - started) * 1000)
        except Exception:
            logger.exception("审计写入失败")
            # 审计写不进去等于不可复现：此时仍拒绝出网动作
            if not decision.is_block:
                return {"action": "block",
                        "message": "[scope-gate] 被拒绝：审计日志写入失败，无法保证可追溯。"}
        return decision.as_hook_result()

    def post_tool_call(self, tool_name: str = "", args: Any = None, result: Any = None,
                       status: str = "", error_type: str = "", error_message: str = "",
                       duration_ms: Any = None, **kwargs: Any) -> None:
        """只记录元信息，不落工具输出原文（避免凭据进审计库）。"""
        try:
            text = result if isinstance(result, str) else str(result or "")
            self.audit.append("tool_result", {
                "tool": tool_name,
                "status": status,
                "error_type": error_type,
                "error_message": (error_message or "")[:200],
                "duration_ms": duration_ms,
                "result_chars": len(text),
                "session_id": str(kwargs.get("session_id", "")),
                "tool_call_id": str(kwargs.get("tool_call_id", "")),
            })
        except Exception:
            logger.exception("post_tool_call 审计失败")

    # -- 内部 ---------------------------------------------------------------

    def _record(self, tool_name: str, args: Any, decision: Decision,
                kwargs: Mapping[str, Any], elapsed_ms: float) -> None:
        self.audit.append("decision", {
            "tool": tool_name,
            "decision": decision.kind.value,
            "code": decision.code,
            "target": decision.target,
            "scope": self.store.dump_for_audit(),
            "session_id": str(kwargs.get("session_id", "")),
            "conversation_id": str(kwargs.get("conversation_id", "")),
            "tool_call_id": str(kwargs.get("tool_call_id", "")),
            "turn_id": str(kwargs.get("turn_id", "")),
            "task_id": str(kwargs.get("task_id", "")),
            "elapsed_ms": round(elapsed_ms, 2),
        })


# ---------------------------------------------------------------------------
# 进程级单例：Hermes 的 hook 注册表是全局的，状态也应当是全局一份
# ---------------------------------------------------------------------------

_gate: Optional[ScopeGate] = None
_gate_lock = threading.Lock()


def load_config(path: Path) -> GateConfig:
    try:
        import hermes_yaml as yaml  # type: ignore
    except Exception:  # pragma: no cover
        import yaml  # type: ignore
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return GateConfig.from_mapping(raw, path.parent)


def get_gate(config_path: Optional[Path] = None) -> ScopeGate:
    global _gate
    with _gate_lock:
        if _gate is None:
            if config_path is None:
                env = os.environ.get("SCOPE_GATE_CONFIG")
                config_path = Path(env) if env else Path(__file__).with_name("config.yaml")
            _gate = ScopeGate(load_config(Path(config_path)))
            logger.info("scope-gate 已初始化: %s", config_path)
        return _gate


def reset_gate() -> None:
    """测试用：清掉单例。"""
    global _gate
    with _gate_lock:
        if _gate is not None:
            try:
                _gate.resolver.close()
                _gate.limiter.close()
            except Exception:
                pass
        _gate = None
