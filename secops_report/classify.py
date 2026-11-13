"""结论三档降级规则（TASK-003 §1）。

正负对照原则：只有同时具备正对照、负对照且完成清理的 PoC，才够格
confirmed；缺任何一项一律降为 observed。rejected 不降级，原样保留
（渲染时进 Rejected Candidates 附录）。
"""

from __future__ import annotations

from dataclasses import dataclass

from .models import Finding, FindingStatus


@dataclass(frozen=True)
class Classification:
    """classify() 的结果：最终档位 + 一句话理由。

    reason 只在降级时是必须的，其余档位也给出说明便于报告直接引用。
    """

    status: FindingStatus
    reason: str = ""


def classify(finding: Finding) -> Classification:
    """按降级规则给出最终结论，不修改原 Finding。"""
    claimed = finding.status

    if claimed is FindingStatus.REJECTED:
        # 否决结论不参与降级，保留进附录
        return Classification(status=FindingStatus.REJECTED,
                              reason="结论为 rejected，不参与降级，仅进附录")

    if claimed is FindingStatus.CONFIRMED:
        if finding.poc is None:
            return Classification(
                status=FindingStatus.OBSERVED,
                reason="声称 confirmed 但未附 PoC，降级为 observed")
        if finding.poc.negative is None:
            return Classification(
                status=FindingStatus.OBSERVED,
                reason="PoC 只有正对照、缺少负对照，不足以 confirmed，降级为 observed")
        if not finding.poc.cleanup_done:
            return Classification(
                status=FindingStatus.OBSERVED,
                reason="PoC 清理未完成（cleanup_done=False），不得 confirmed，降级为 observed")
        return Classification(
            status=FindingStatus.CONFIRMED,
            reason="PoC 正负对照齐全且清理完成，维持 confirmed")

    # 初始就是 observed：保守档位，无降级动作
    return Classification(status=FindingStatus.OBSERVED,
                          reason="初始即 observed，无降级")
