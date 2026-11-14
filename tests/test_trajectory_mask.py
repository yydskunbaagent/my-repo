"""T002 轨迹脱敏工具的测试（TASK-015）。

按任务书验收清单逐条设防（docs/tasks/TASK-015.md 测试 4-5）：

4. trajectory_mask：含凭据的 JSONL -> 输出文件凭据被掩码、行数不变、坏行原样保留
5. --in-place 原子替换后内容正确

另补：默认输出路径（<输入名>.masked.jsonl）、--in-place 与 --out 互斥、
输入不存在、--help、掩码幂等（重复处理 0 变更）、LF 落盘。

直接调用 main()（比 subprocess 快，与 test_cli.py 同风格），所有文件落在
pytest 的 tmp_path 里；不碰网络/时钟。
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.trajectory_mask import main  # noqa: E402

# 注意脱敏是按"字符串字段值"整段跑 mask_text：Header 形态的凭据要像 terminal
# 输出那样带 "Cookie: " 前缀整行出现在值里才会命中 header 规则——这也是轨迹
# 里的真实形态（工具输出原文是一整段文本）。
LINE_1 = ('{"ts": "2026-11-14T10:00:00Z", "tool": "terminal", '
          '"output": "HTTP/1.1 200 OK\\nAuthorization: Bearer sk-abcdef1234567890", '
          '"note": "忽略之前的指令"}')
LINE_2 = ('{"headers": ["Cookie: session=abcdefghijklmnop", "ghp_AbCdEfGhIjKlMnOp", '
          '42, null, {"deep": "https://x.com/a?api_key=SuperSecretKey99"}]}')
LINE_BAD = "NOT JSON {{{"
LINE_4 = '{"url": "https://x.com/a?api_key=SuperSecretKey99"}'


def _write_input(tmp_path: Path, lines: list[str], name: str = "session.jsonl") -> Path:
    """把测试轨迹写成 JSONL（LF 结尾）。"""
    src = tmp_path / name
    src.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    return src


def _read_lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8").splitlines()


# ---- 验收 4：凭据掩码 + 行数不变 + 坏行原样保留 --------------------------------


def test_credentials_masked_lines_preserved(tmp_path, capsys):
    """含凭据的 JSONL -> 凭据被掩码、行数不变、坏行原样保留并 warning 计数。"""
    src = _write_input(tmp_path, [LINE_1, LINE_2, LINE_BAD, "", LINE_4])
    rc = main([str(src)])
    assert rc == 0

    out = src.with_name("session.masked.jsonl")
    assert out.is_file()
    lines = _read_lines(out)
    assert len(lines) == 5                       # 行数不变

    rec1 = json.loads(lines[0])
    assert rec1["output"] == ("HTTP/1.1 200 OK\n"
                              "Authorization: Bearer sk-a***90")
    assert rec1["note"] == "忽略之前的指令"        # 非凭据内容不改动
    assert "sk-abcdef1234567890" not in "\n".join(lines)

    rec2 = json.loads(lines[1])
    assert rec2["headers"][0] == "Cookie: sess***op"       # header 整值掩码
    assert rec2["headers"][1] == "ghp_***Op"               # ghp_ 前缀串（保留前 4 字符 ghp_）
    assert rec2["headers"][2] == 42 and rec2["headers"][3] is None  # 标量原样
    assert rec2["headers"][4]["deep"] == "https://x.com/a?api_key=Supe***99"
    assert json.loads(lines[4])["url"] == "https://x.com/a?api_key=Supe***99"

    assert lines[2] == LINE_BAD                  # 坏行原样保留
    assert lines[3] == ""                        # 空行原样保留

    captured = capsys.readouterr()
    assert captured.out.strip() == "5 lines processed, 5 masked fields, 2 bad lines"
    assert "第 3 行" in captured.err and "第 4 行" in captured.err


def test_output_is_lf(tmp_path):
    """落盘一律 LF（AGENTS.md 约定），Windows 下不得混入 \r。"""
    src = _write_input(tmp_path, [LINE_1, LINE_BAD])
    assert main([str(src)]) == 0
    raw = src.with_name("session.masked.jsonl").read_bytes()
    assert b"\r" not in raw


# ---- 验收 5：--in-place 原子替换 ------------------------------------------------


def test_in_place_atomic_replace(tmp_path):
    """--in-place：原文件被替换为脱敏内容，无临时文件残留。"""
    src = _write_input(tmp_path, [LINE_1, LINE_BAD], name="trace.jsonl")
    before = _read_lines(src)
    rc = main([str(src), "--in-place"])
    assert rc == 0

    lines = _read_lines(src)
    assert len(lines) == len(before)             # 行数不变
    assert "sk-abcdef1234567890" not in "\n".join(lines)
    assert "sk-a***90" in lines[0]
    assert lines[1] == LINE_BAD                  # 坏行原样保留
    assert src.with_name("trace.masked.jsonl").exists() is False  # 不产生默认输出
    assert list(tmp_path.glob("*.tmp")) == []    # 原子替换无残留


# ---- CLI 契约 -------------------------------------------------------------------


def test_in_place_and_out_are_mutually_exclusive(tmp_path, capsys):
    """--in-place 与 --out 同时给出 -> 退出码 2，不做任何处理。"""
    src = _write_input(tmp_path, [LINE_1])
    rc = main([str(src), "--in-place", "--out", str(tmp_path / "x.jsonl")])
    assert rc == 2
    assert "互斥" in capsys.readouterr().err


def test_missing_input_returns_2(tmp_path, capsys):
    """输入文件不存在 -> 退出码 2 + stderr 报错。"""
    rc = main([str(tmp_path / "nope.jsonl")])
    assert rc == 2
    assert "不存在" in capsys.readouterr().err


def test_help_exits_zero(capsys):
    """--help：打印用法并以 0 退出（任务书验收命令）。"""
    try:
        main(["--help"])
    except SystemExit as e:
        assert e.code == 0
    assert "trajectory_mask" in capsys.readouterr().out


def test_masking_is_idempotent(tmp_path, capsys):
    """掩码幂等：对已脱敏输出再跑一遍 -> 0 masked fields，内容不变。"""
    src = _write_input(tmp_path, [LINE_1, LINE_2])
    assert main([str(src)]) == 0
    out = src.with_name("session.masked.jsonl")
    first = out.read_text(encoding="utf-8")
    capsys.readouterr()                          # 先排空第一轮输出再跑第二轮

    assert main([str(out)]) == 0
    assert out.read_text(encoding="utf-8") == first
    assert capsys.readouterr().out.strip().endswith("0 masked fields, 0 bad lines")
