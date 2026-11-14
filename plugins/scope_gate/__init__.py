"""scope-gate：基于 Hermes Agent 的授权范围门禁插件。

对外只有一个入口：`register(ctx)`。真正的逻辑在同目录的 `gate.py`，
本文件保持极薄，避免导入期副作用（Hermes 会导入每个已启用插件的 `__init__`）。
"""

from __future__ import annotations

import logging

__version__ = "1.0.0"

logger = logging.getLogger("scope_gate")


def pre_tool_call(tool_name: str = "", args=None, **kwargs):
    """钩子包装：延迟初始化，保证导入阶段不读磁盘、不解析 scope。"""
    from .gate import get_gate

    return get_gate().pre_tool_call(tool_name, args, **kwargs)


def post_tool_call(tool_name: str = "", args=None, result=None, **kwargs):
    from .gate import get_gate

    return get_gate().post_tool_call(tool_name, args, result, **kwargs)


def transform_tool_result(tool_name: str = "", args=None, result=None, **kwargs):
    """T001/T002（TASK-015）：工具结果回传模型前的脱敏 + 不可信域包 wrapper。"""
    from .gate import get_gate

    return get_gate().transform_tool_result(tool_name, args, result, **kwargs)


def register(ctx) -> None:
    ctx.register_hook("pre_tool_call", pre_tool_call)
    ctx.register_hook("post_tool_call", post_tool_call)
    ctx.register_hook("transform_tool_result", transform_tool_result)
    logger.info(
        "scope-gate %s 已注册（pre_tool_call / post_tool_call / transform_tool_result）",
        __version__,
    )


def self_check() -> dict:
    """供 `hermes` 侧或运维脚本调用，确认门禁状态。"""
    from .gate import get_gate

    gate = get_gate()
    state = gate.store.state
    result = {
        "scope_usable": state.usable,
        "scope_error": state.error,
        "scope_degraded": state.degraded,
        "scope": gate.store.dump_for_audit(),
        "audit_chain": gate.audit.verify_chain().__dict__,
    }
    if state.engagement:
        result["ratelimit"] = [
            gate.limiter.snapshot(state.engagement.id, t.normalized)
            for t in state.engagement.targets
        ]
    return result
