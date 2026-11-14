"""钩子入口：把引擎、解析器、限速、审计装配起来。

对外暴露三个函数，签名严格遵循 Hermes hook 契约：

    pre_tool_call(tool_name, args, **kwargs)  -> Optional[dict]
    post_tool_call(tool_name, args, result, **kwargs) -> None   （记录型，返回值不被消费）
    transform_tool_result(tool_name, args, result, **kwargs) -> Optional[str]

`pre_tool_call` 永不抛异常：任何内部错误都转成 block。因为 Hermes 对抛异常的处理是
fail closed 但不给模型可读原因，模型会反复重试同一个调用；我们给结构化原因，让它能纠正。
`transform_tool_result` 是 TASK-015（T001/T002）的接入点，取舍见 DECISIONS.md 010。
"""

from __future__ import annotations

import concurrent.futures
import ipaddress
import logging
import os
import shlex
import socket
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Tuple

from .audit import AuditLog
from .engine import decide
from .extract import (
    LOCAL_READ_TOOLS,
    LOCAL_WRITE_TOOLS,
    analyze_tool,
    is_local_tool,
    paths_from_args,
    register_local_tools,
)
from .models import Action, Decision, DecisionKind, TargetKind
from .ratelimit import RateLimiter
from .scope import ScopeStore
from .untrusted import (
    UNTRUSTED_MAX_LEN,
    UNTRUSTED_NOTICE,
    detect_injection,
    mask_text,
    wrap_untrusted,
)

logger = logging.getLogger("scope_gate")

DNS_TTL_SECONDS = 300
DNS_TIMEOUT_SECONDS = 4.0
MAX_CACHE_ENTRIES = 2048

# execute_code 类工具（TASK-012）：任意代码执行，目标无法可靠提取，一律拒绝。
# 与 TASK-007 的 terminal 内联拦截（-c/-e/--eval/-m）构成同一防线：那是命令行
# 形态，这是工具级同类问题。比较统一小写（strip 后）。
_CODE_EXECUTION_TOOLS = frozenset({"execute_code", "code_exec", "python_exec"})
# shell 操作符 token：本地 shell 命令的保护路径检查里跳过它们（不是路径）
_SHELL_OPERATOR_TOKENS = frozenset({">", ">>", "<", "<<", "|", "||", "&", "&&", ";"})


@dataclass
class GateConfig:
    scope_path: Path
    audit_path: Path
    rate_limit_db: Path
    protected_paths: Tuple[Path, ...] = ()
    dns_ttl: int = DNS_TTL_SECONDS
    dns_timeout: float = DNS_TIMEOUT_SECONDS
    allow_local_write: bool = True
    # 部署方声明的本地工具（TASK-010）：运行时合并进 extract 的本地清单，
    # 不改代码即可扩展（config.yaml 的 extra_local_tools: 列表）
    extra_local_tools: Tuple[str, ...] = ()

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
            extra_local_tools=tuple(
                str(item).strip() for item in (data.get("extra_local_tools") or [])
                if str(item).strip()
            ),
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


def _shell_arg_paths(command: str) -> Tuple[str, ...]:
    """本地 shell 命令的路径参数候选（TASK-012 保护路径检查用）。

    切词后取非选项、非 shell 操作符的 token，宁滥勿缺：_protected 靠
    resolve 后精确比对，多余 token 无副作用，漏掉的才是风险。
    """
    try:
        parts = shlex.split(command, posix=not os.name == "nt")
    except ValueError:
        parts = command.split()
    return tuple(
        p for p in parts
        if p and not p.startswith("-") and p not in _SHELL_OPERATOR_TOKENS
    )


class ScopeGate:
    def __init__(self, config: GateConfig, *, resolver: Optional[Resolver] = None,
                 clock=None):
        self.config = config
        # 部署方声明的本地工具合并进本地清单（TASK-010）：不改代码即可扩展
        register_local_tools(config.extra_local_tools)
        self.store = ScopeStore(config.scope_path)
        self.audit = AuditLog(config.audit_path)
        self.limiter = RateLimiter(config.rate_limit_db, clock=clock or time.monotonic)
        self.resolver = resolver or Resolver(config.dns_ttl, config.dns_timeout)
        # T001 一次性条款开关（TASK-015）：首个包域结果携带 UNTRUSTED_NOTICE，
        # 进程内一次。钩子在多个工具 worker 线程里并发跑，置位要加锁。
        self._untrusted_notice_sent = False
        self._untrusted_notice_lock = threading.Lock()

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

        # execute_code 类工具（TASK-012）：任意代码执行、目标无法可靠提取，
        # 类别性一律拒绝（与 TASK-007 内联拦截同一防线，工具级同类问题）。
        # 放在一切判定之前：任何 args、任何 scope 状态下都 block。
        if (tool_name or "").strip().lower() in _CODE_EXECUTION_TOOLS:
            return Decision(
                DecisionKind.BLOCK, "code_execution_tool",
                "[scope-gate] 被拒绝：execute_code 是任意代码执行，目标无法可靠提取，"
                "扫描节点禁用。请使用任务协议（deploy/protocol/run_scan.py）的"
                "原子动作白名单。",
            )

        # 本地只读：直接放行（但仍记账）
        if tool_name in LOCAL_READ_TOOLS:
            return Decision(DecisionKind.ALLOW, "local_read", "")

        # 写本地文件 / 本地类工具（TASK-010）：不要求网络目标，只做路径保护。
        # 路径保护照常生效——本地工具改写作业元数据（scope.yaml / 审计目录）仍要拦。
        if tool_name in LOCAL_WRITE_TOOLS or is_local_tool(tool_name):
            hit = self._protected(paths_from_args(tool_name, args))
            if hit:
                return Decision(
                    DecisionKind.BLOCK, "protected_path",
                    f"[scope-gate] 被拒绝：{hit} 属于作业元数据（scope / 授权书 / 审计），"
                    f"Agent 不得写入。请把产出写到 evidence/ 或 reports/ 下。",
                )
            code = "local_write" if tool_name in LOCAL_WRITE_TOOLS else "local_tool"
            return Decision(DecisionKind.ALLOW, code, "")

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

        # 内联代码执行一律拒绝（TASK-007）：python -c / bash -c / 交互模式把代码
        # 藏在参数里，"可见合法目标 + 隐藏 sink"（如拼接出的 URL）无法静态校验，
        # 门禁只看到合法目标就放行会让隐藏 sink 逃过应用层。
        if analysis.inline_eval:
            return Decision(
                DecisionKind.BLOCK, "inline_code_execution",
                "[scope-gate] 被拒绝：扫描节点不允许内联代码执行，请使用预授权的原子工具。"
                "内联形态（-c/-e/--eval/-m 或交互模式）里的真实目标无法在命令行静态校验。",
            )

        # 终端本地命令白名单（TASK-012）：逐段皆为本地命令 -> 纯本地操作，
        # 跳过目标提取 / no_target / 限速记账（analyze_terminal 已不提取目标）。
        # forbidden（rm -rf / 类毁灭性命令）不豁免：仅 forbidden 为空才走此
        # 早退，命中 forbidden 落到下方正常判定路径由 decide 优先拒绝；
        # 保护路径检查照常生效——本地命令读写删作业元数据（scope/审计）仍拦。
        if analysis.is_local_shell and not analysis.forbidden:
            hit = self._protected(_shell_arg_paths(analysis.command))
            if hit:
                return Decision(
                    DecisionKind.BLOCK, "protected_path",
                    f"[scope-gate] 被拒绝：本地命令涉及作业元数据 {hit}"
                    f"（scope / 授权书 / 审计），不得读写或删除。"
                    f"请把产出写到 evidence/ 或 reports/ 下。",
                )
            return Decision(DecisionKind.ALLOW, "local_shell", "")

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
        """只记录元信息，不落工具输出原文（避免凭据进审计库）。

        T001/T002（TASK-015）限制说明：本 hook 是记录型钩子——Hermes 不消费
        post_tool_call 的返回值（hermes 源码核实：tool_executor 先 emit_post、
        结果另行提交，替换发生在其后的 transform_tool_result），因此无法在此
        把脱敏/包域后的文本回传给模型，即任务书所说"T001 需在工具结果回传
        模型前的钩子点接入"。任务书备选路径二（pre_tool_call 给 system/context
        注入一次性条款）经源码核实同样不可行：Python 插件回调只认
        block/approve/modify（modify 是浅合并进工具 args，会污染工具输入），
        没有 system/context 注入通道。实际接入点为 transform_tool_result（见
        下方同名方法与 DECISIONS.md 010）。
        """
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

    def transform_tool_result(
        self, tool_name: str = "", args: Any = None, result: Any = None,
        status: str = "", error_type: str = "", error_message: str = "",
        duration_ms: Any = None, **kwargs: Any,
    ) -> Optional[str]:
        """T001/T002（TASK-015）实际接入点：工具结果回传模型前的替换钩子。

        Hermes 的 transform_tool_result 契约（hermes 源码 model_tools.py 核实）：
        在 post_tool_call 之后、结果进入上下文之前触发；"plugins may replace the
        final result string"，first string return wins；对异常 fail-open（保留
        原结果）。任务书备选路径（post hook 替换 / pre hook 注入条款）均经源码
        核实不可行，取舍记录见 DECISIONS.md 010。

        处理规则（任务书 TASK-015）：
          - 出网工具（terminal/url 抓取/browser 及一切非本地工具，与 extract 的
            "默认按出网"哲学一致）：先 mask_text（T002 凭据）再 wrap_untrusted
            （T001 包域）；首个包域结果额外携带一次性的 UNTRUSTED_NOTICE 条款。
          - 本地工具（is_local_tool，含 read_file）：只 mask_text 不包域——本地
            文件本来就在自己控制面里，包域反而污染；注入关键词命中仍记审计。
        返回 None 表示不替换（本地结果未变 / 非 str 结果 / 内部错误）。
        """
        try:
            # 非 str 结果（多模态 dict 等）不动：改写其结构语义的风险大于脱敏收益
            if not isinstance(result, str) or not result:
                return None
            name = (tool_name or "").strip()
            low = name.lower()
            is_local = (
                low in LOCAL_READ_TOOLS or low in LOCAL_WRITE_TOOLS
                or is_local_tool(low)
            )

            masked = mask_text(result)
            hits = detect_injection(masked)
            if is_local:
                out = masked
                truncated = False
                wrapped = False
            else:
                truncated = len(masked) > UNTRUSTED_MAX_LEN
                out = wrap_untrusted(masked, source_tool=name or "unknown")
                wrapped = True
                with self._untrusted_notice_lock:
                    first = not self._untrusted_notice_sent
                    self._untrusted_notice_sent = True
                if first:
                    out = f"{UNTRUSTED_NOTICE}\n{out}"

            if out != result or wrapped or hits:
                # 纯透传（本地结果无凭据无命中）不记审计，避免噪音
                self._record_transform(name, masked=masked != result, wrapped=wrapped,
                                       truncated=truncated, injection=hits,
                                       result_chars=len(out) if out != result else len(result))
            return out if out != result else None
        except Exception:
            # Hermes 对本钩子 fail-open：异常时返回 None = 保留原结果。
            # 凭据脱敏/包域缺失只损失纵深，不产生放行口子（出网动作仍由
            # pre_tool_call 硬判）；审计链里留 transform 记录缺失可定位。
            logger.exception("transform_tool_result 处理失败，保留原结果")
            return None

    def _record_transform(self, tool: str, *, masked: bool, wrapped: bool,
                          truncated: bool, injection: list, result_chars: int) -> None:
        """transform 结果的审计元数据（只记元信息，不落输出原文）。"""
        try:
            self.audit.append("result_transform", {
                "tool": tool,
                "masked": masked,
                "wrapped": wrapped,
                "truncated": truncated,
                "injection": injection,
                "result_chars": result_chars,
            })
        except Exception:
            logger.exception("result_transform 审计失败")

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
