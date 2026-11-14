#!/usr/bin/env python3
"""Hermes 会话轨迹 JSONL 批量脱敏（T002，TASK-015）。

会话轨迹（terminal/browser 结果等）落盘归档前把凭据掩掉——轨迹会流转到
授权交付名单之外（评审、复盘、模板复用），里面常带 Authorization/Cookie/
sk-/ghp_ 形态的凭据，掩码复用 secops_report.masking.mask_text（sys.path
引入，不复制代码）。

用法：

    python tools/trajectory_mask.py <输入.jsonl> [--in-place] [--out <输出路径>]

行为规格（任务书 TASK-015 任务 2）：
  - 逐行 JSON 解析；坏行（非 JSON/空行）原样保留并向 stderr 打 warning、计数
  - 对每个字符串字段值跑 mask_text；dict/list 结构递归处理，不解析字段结构
  - --in-place：原子替换（同目录临时文件 + os.replace）；默认写到
    <输入名>.masked.jsonl（同目录）
  - 标准输出一行摘要：N lines processed, M masked fields, K bad lines
  - 掩码幂等：已掩码文本重复处理不再变更（mask_text 产物含 *，不命中模式）

换行一律 LF（AGENTS.md 约定）；退出码 0 成功 / 2 用法或输入错误。
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any, List, Tuple

# secops_report 经 sys.path 引入（不复制代码）：tools/ 的上一级即仓根
_REPO_ROOT = str(Path(__file__).resolve().parents[1])
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from secops_report.masking import mask_text  # noqa: E402


def mask_value(value: Any) -> Tuple[Any, int]:
    """递归掩掉字符串字段值，返回 (新值, 发生掩码变更的字段数)。

    dict/list 结构原样保留（不解析字段结构、不改键名），数字/布尔/None 原样返回。
    """
    if isinstance(value, str):
        masked = mask_text(value)
        return masked, (1 if masked != value else 0)
    if isinstance(value, dict):
        out: dict = {}
        changed = 0
        for key, item in value.items():
            new_item, n = mask_value(item)
            out[key] = new_item
            changed += n
        return out, changed
    if isinstance(value, list):
        out_list: List[Any] = []
        changed = 0
        for item in value:
            new_item, n = mask_value(item)
            out_list.append(new_item)
            changed += n
        return out_list, changed
    return value, 0


def process_file(src: Path, dst: Path) -> Tuple[int, int, int]:
    """逐行脱敏 src 写入 dst，返回 (总行数, 掩码字段数, 坏行数)。

    坏行（非 JSON/空行）原样保留，warning（带行号）打到 stderr。
    """
    total = masked_fields = bad = 0
    with src.open("r", encoding="utf-8", errors="replace") as fin, \
            dst.open("w", encoding="utf-8", newline="\n") as fout:
        for lineno, line in enumerate(fin, start=1):
            total += 1
            stripped = line.rstrip("\r\n")
            try:
                obj = json.loads(stripped)
            except (json.JSONDecodeError, ValueError):
                bad += 1
                print(f"[trajectory_mask] warning: 第 {lineno} 行非 JSON，原样保留",
                      file=sys.stderr)
                fout.write(line if line.endswith("\n") else line + "\n")
                continue
            new_obj, changed = mask_value(obj)
            masked_fields += changed
            fout.write(json.dumps(new_obj, ensure_ascii=False) + "\n")
    return total, masked_fields, bad


def main(argv: List[str] | None = None) -> int:
    """CLI 入口；返回退出码（测试直接调用本函数，不经 subprocess）。"""
    parser = argparse.ArgumentParser(
        prog="trajectory_mask",
        description="Hermes 会话轨迹 JSONL 批量脱敏（T002）：对每个字符串字段值"
                    "跑 mask_text，坏行原样保留，摘要行打到 stdout。",
    )
    parser.add_argument("input", help="输入 JSONL 路径")
    parser.add_argument("--in-place", action="store_true",
                        help="原子替换原文件（同目录临时文件 + os.replace）")
    parser.add_argument("--out", default=None,
                        help="输出路径（默认 <输入名>.masked.jsonl；与 --in-place 互斥）")
    ns = parser.parse_args(argv)

    src = Path(ns.input)
    if not src.is_file():
        print(f"[trajectory_mask] 输入文件不存在: {src}", file=sys.stderr)
        return 2
    if ns.in_place and ns.out:
        print("[trajectory_mask] --in-place 与 --out 互斥", file=sys.stderr)
        return 2

    if ns.in_place:
        # 原子替换：同目录临时文件（保证同分区 os.replace 原子性），失败即清理
        fd, tmp_name = tempfile.mkstemp(dir=str(src.parent), prefix=src.name + ".",
                                        suffix=".tmp")
        dst = Path(tmp_name)
        os.close(fd)
        try:
            total, masked, bad = process_file(src, dst)
            os.replace(dst, src)
        except Exception:
            dst.unlink(missing_ok=True)
            raise
    else:
        dst = Path(ns.out) if ns.out else src.with_name(src.stem + ".masked.jsonl")
        total, masked, bad = process_file(src, dst)

    print(f"{total} lines processed, {masked} masked fields, {bad} bad lines")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
