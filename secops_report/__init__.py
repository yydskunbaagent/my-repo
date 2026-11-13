"""secops-report：黑盒发现报告生成器（TASK-003）。

独立于 plugins/scope_gate：只消费已完成的发现（Finding），
不导入、不调用门禁的任何公开接口。对外只导出六样东西：
构造数据的三件套 + 定档的 classify + 两个渲染器。
"""

from __future__ import annotations

from .classify import classify
from .models import Evidence, Finding, Poc
from .render import render_markdown, render_sarif

__version__ = "1.0.0"

__all__ = [
    "Finding",
    "Evidence",
    "Poc",
    "classify",
    "render_markdown",
    "render_sarif",
]
