#!/usr/bin/env python3
"""扫描任务投递/回收桥接（TASK-017）：推理端一条命令走完投递闭环。

信任边界（deploy/protocol/README.md）：本脚本跑在推理端，是 run_scan.py 的
配套运输层。安全模型 = 密钥认证（ssh 必带 BatchMode=yes，无密钥当场失败，
密码不出现在任何命令/参数/日志里）+ 固定远端命令模板（只有 mkdir 和一条
docker run，远端路径由已校验常量拼装，用户数据不进远端 shell 拼接）+
argv 列表 subprocess（禁止 shell=True）。即使 task.json 被注入篡改，本脚本
也只负责"运输"——执行前先在本地跑 run_scan.validate_task，校验不过一个
ssh 都不发（fail closed）；远端执行面的收敛由 run_scan.py 与扫描节点网络层
负责，本脚本不重复也不削弱那两道防线。

回程处理（不可信数据层，TASK-015 语义在文件传输上的延伸）：扫描节点的
result.json / raw/ 是目标系统输出，一律视为不可信数据——先 T002 递归脱敏
（复用 tools/trajectory_mask.mask_value，不复制代码），再 T001 包域标注
（复用 scope_gate.untrusted.wrap_untrusted），产物归档后才交给研判。

用法：

    python deploy/protocol/dispatch.py --task task.json \
        --host root@47.108.111.56 --port 53142 \
        [--identity ~/.ssh/id_ed25519] \
        [--remote-dir /jobs] [--image secops-scanner] [--network scannet] \
        [--timeout 600] [--ssh-timeout 120] \
        --out-dir <本地归档目录>

归档布局（全部落盘后才算成功，途中失败不留半套残缺归档）：

    <out-dir>/<task_id>/result.json          # T002 脱敏后的扫描结果
    <out-dir>/<task_id>/raw/*.log            # T002 脱敏后的原始输出
    <out-dir>/<task_id>/result.untrusted.txt # T001 包域全文（供模型消费）
    <out-dir>/<task_id>/dispatch.json        # 投递元数据（不含凭据）

退出码：0 全链路成功且远端 RC=0（RC=2 视为远端校验失败、投递环节本身成功，
错误由 result.json 的 error 字段承载）；1 远端 run_scan 有动作失败（RC=1，
结果已拉回）；2 本地输入/校验错误（fail closed，未投递任何东西）；3 投递/
传输/拉回环节失败（意外异常一并归入 3——除输入错误外的失败调用方统一按
"查 stderr 重试"处理）。
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import shutil
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Sequence

logger = logging.getLogger("dispatch")

# ---- sys.path：run_scan（同目录）+ 仓根 + plugins + tools（复用，不复制代码）--
_PROTOCOL_DIR = str(Path(__file__).resolve().parent)
_REPO_ROOT = str(Path(__file__).resolve().parents[2])
for _p in (_PROTOCOL_DIR, _REPO_ROOT,
           str(Path(_REPO_ROOT) / "plugins"), str(Path(_REPO_ROOT) / "tools")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

# 同目录协议执行器：校验复用、subprocess 执行器复用（argv 列表、超时即杀，
# 不复制代码）
from run_scan import RunFn, _run_command, validate_task  # noqa: E402
from secops_report.masking import mask_text  # noqa: E402  T002 掩码原语
from scope_gate.untrusted import detect_injection, wrap_untrusted  # noqa: E402  T001 包域
from trajectory_mask import mask_value  # noqa: E402  T002 JSON 递归掩码

# ---- 协议常量：与 Dockerfile.scanner 头注的运行命令一一对应 ------------------

DEFAULT_REMOTE_DIR = "/jobs"
DEFAULT_IMAGE = "secops-scanner"
DEFAULT_NETWORK = "scannet"
DEFAULT_TIMEOUT_SECONDS = 600
DEFAULT_SSH_TIMEOUT = 120
RUN_OVERHEAD_SECONDS = 60  # 容器启动/停止开销，加在任务预算之外

CONTAINER_TASK_PATH = "/tmp/task.json"
CONTAINER_OUT_DIR = "/tmp/out"
CONTAINER_SCRIPT = "/opt/protocol/run_scan.py"
RESULT_NAME = "result.json"
RAW_DIR_NAME = "raw"
UNTRUSTED_NAME = "result.untrusted.txt"
META_NAME = "dispatch.json"

# ssh/scp 公共选项：BatchMode=yes 是密钥认证的硬约束（无密钥当场失败，
# 不可能挂等密码输入）；accept-new 自动信任首次指纹，指纹变更仍然拒绝
SSH_OPTS: tuple[str, ...] = (
    "-o", "BatchMode=yes",
    "-o", "ConnectTimeout=10",
    "-o", "StrictHostKeyChecking=accept-new",
)

# 远端命令里允许出现的常量形态（fail closed：不合法一律退出码 2，不发包）
HOST_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*(@[A-Za-z0-9][A-Za-z0-9._-]*)?$")
REMOTE_DIR_PATTERN = re.compile(r"^/[A-Za-z0-9/._-]+$")
IMAGE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*(:[A-Za-z0-9._-]+)?$")
NETWORK_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
RC_LINE = re.compile(r"^RC=(\d+)\s*$")

EXIT_OK = 0
EXIT_REMOTE_ACTION_FAILED = 1
EXIT_INPUT = 2
EXIT_TRANSPORT = 3


# ---------------------------------------------------------------------------
# argv 构造：ssh / scp 的固定模板（密钥认证 + 选项 + 已校验常量）
# ---------------------------------------------------------------------------

def _ssh_argv(identity: str | None, port: int, host: str,
              remote_cmd: str) -> list[str]:
    """ssh 命令 argv：选项 + -p 端口 + 主机 + 单条远端命令（模板拼装）。"""
    argv = ["ssh", *SSH_OPTS]
    if identity:
        argv.extend(["-i", identity])
    argv.extend(["-p", str(port), host, remote_cmd])
    return argv


def _scp_argv(identity: str | None, port: int, src: str, dst: str,
              *, recursive: bool = False) -> list[str]:
    """scp 命令 argv：选项 + -P 端口 + 源/目标（scp 的端口选项是大写 P）。"""
    argv = ["scp", *SSH_OPTS]
    if recursive:
        argv.append("-r")
    if identity:
        argv.extend(["-i", identity])
    argv.extend(["-P", str(port), src, dst])
    return argv


def _build_remote_run_cmd(remote_job: str, image: str, network: str,
                          task_timeout: int) -> str:
    """远端 docker run 固定模板；尾部 echo RC=$? 回传 run_scan 的退出码。

    模板与 Dockerfile.scanner 头注的运行命令一致（任务/输出经 -v 挂载，
    容器内路径是常量）。RC=$? 由远端 shell 展开——docker/容器本身启动失败
    （125/126/127）同样会回传，不会伪装成成功。
    """
    return (
        f"docker run --rm --network {network} "
        f"-v {remote_job}/task.json:{CONTAINER_TASK_PATH}:ro "
        f"-v {remote_job}/out:{CONTAINER_OUT_DIR} "
        f"{image} python3 {CONTAINER_SCRIPT} "
        f"--task {CONTAINER_TASK_PATH} --out {CONTAINER_OUT_DIR}/{RESULT_NAME} "
        f"--timeout {task_timeout}; echo RC=$?"
    )


# ---------------------------------------------------------------------------
# 回程处理：T002 脱敏 + T001 包域（全部产物先落临时目录，成功才进归档）
# ---------------------------------------------------------------------------

def _mask_raw_logs(raw_src: Path, raw_dst: Path) -> list[str]:
    """raw/ 目录逐文件 T002 掩码后拷贝，返回归档的相对路径列表。"""
    archived: list[str] = []
    raw_dst.mkdir(parents=True, exist_ok=True)
    for log in sorted(raw_src.iterdir()):
        if not log.is_file():
            continue
        text = log.read_text(encoding="utf-8", errors="replace")
        (raw_dst / log.name).write_text(mask_text(text), encoding="utf-8",
                                        newline="\n")
        archived.append(f"{RAW_DIR_NAME}/{log.name}")
    return archived


def _build_untrusted_text(masked_result: dict[str, Any]) -> tuple[str, list[str]]:
    """T001 包域全文与注入命中清单（脱敏之后再包域，与 gate 侧顺序一致）。"""
    body = json.dumps(masked_result, ensure_ascii=False, indent=2)
    hits = detect_injection(body)
    task_id = masked_result.get("task_id") or "unknown"
    return wrap_untrusted(body, source_tool=f"scan-node:{task_id}"), hits


def _write_dispatch_meta(path: Path, **fields: Any) -> None:
    """dispatch.json 落盘（UTF-8、LF、ensure_ascii=False 便于人工核对）。"""
    path.write_text(json.dumps(fields, ensure_ascii=False, indent=2) + "\n",
                    encoding="utf-8", newline="\n")


# ---------------------------------------------------------------------------
# 主流程：预检（fail closed）→ 投递 → 回收 → 脱敏归档
# ---------------------------------------------------------------------------

def run_dispatch(
    task_path: Path,
    host: str,
    port: int,
    identity: str | None,
    remote_dir: str,
    image: str,
    network: str,
    task_timeout: int,
    ssh_timeout: int,
    out_dir: Path,
    run_fn: RunFn,
    now: datetime | None = None,
) -> tuple[int, str]:
    """投递闭环主流程，返回 (退出码, 一行摘要)。

    run_fn 可注入（测试用 fake runner 替代真实 ssh/scp，签名同
    run_scan._run_command）；now 注入 validate_task 供测试固定时钟。
    """
    # ---- 本地预检：任何一项不过都退出码 2，且零网络副作用（fail closed）----
    if not 1 <= port <= 65535:
        return EXIT_INPUT, f"--port 必须在 1-65535，收到 {port}"
    if not HOST_PATTERN.fullmatch(host):
        return EXIT_INPUT, f"--host 非法（只允许 [user@]host 形态）: {host!r}"
    if identity and not Path(identity).is_file():
        return EXIT_INPUT, f"--identity 文件不存在: {identity}"
    if not REMOTE_DIR_PATTERN.fullmatch(remote_dir):
        return EXIT_INPUT, f"--remote-dir 须为安全字符的绝对路径: {remote_dir!r}"
    if not IMAGE_PATTERN.fullmatch(image):
        return EXIT_INPUT, f"--image 非法: {image!r}"
    if not NETWORK_PATTERN.fullmatch(network):
        return EXIT_INPUT, f"--network 非法: {network!r}"
    if task_timeout <= 0 or ssh_timeout <= 0:
        return EXIT_INPUT, "--timeout / --ssh-timeout 必须为正整数"

    try:
        task = json.loads(task_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        return EXIT_INPUT, f"task 文件读取/解析失败: {e}"

    errors = validate_task(task, now=now)
    if errors:
        for err in errors:
            logger.error("预检失败：%s", err)
        return EXIT_INPUT, f"validate_task 未通过（{len(errors)} 条），未投递任何东西"

    task_id = task["task_id"]
    remote_job = f"{remote_dir.rstrip('/')}/{task_id}"
    remote_out = f"{remote_job}/out"

    # ---- 投递与回收：固定模板，任一步失败即 3 并清空临时目录 ----
    tmp_root = Path(tempfile.mkdtemp(prefix=f"dispatch-{task_id}-"))
    steps: list[dict[str, Any]] = []

    def _step(name: str, argv: list[str], timeout: float) -> dict[str, Any]:
        """执行一个投递/回收步骤；非零退出码 -> 清理并抛 RuntimeError（→ 3）。"""
        result = run_fn(argv, timeout)
        steps.append({"step": name, "argv": argv, "exit_code": result["exit_code"],
                      "duration_s": round(result["duration_s"], 3)})
        if result["exit_code"] != 0:
            raise RuntimeError(
                f"步骤 {name} 失败（exit_code={result['exit_code']}）："
                f"{result['stderr'][:300] or result['stdout'][:300]}")
        return result

    try:
        _step("mkdir", _ssh_argv(identity, port, host, f"mkdir -p {remote_out}"),
              ssh_timeout)
        _step("push-task",
              _scp_argv(identity, port, str(task_path), f"{host}:{remote_job}/task.json"),
              ssh_timeout)
        run_result = _step(
            "remote-run",
            _ssh_argv(identity, port, host,
                      _build_remote_run_cmd(remote_job, image, network, task_timeout)),
            max(ssh_timeout, task_timeout + RUN_OVERHEAD_SECONDS))
        _step("pull-result",
              _scp_argv(identity, port, f"{host}:{remote_out}/{RESULT_NAME}",
                        str(tmp_root / RESULT_NAME)),
              ssh_timeout)

        # result.json 必须可解析（run_scan 连校验失败也会写结果文件）
        try:
            result_raw = (tmp_root / RESULT_NAME).read_text(encoding="utf-8")
            result = json.loads(result_raw)
        except (OSError, ValueError) as e:
            raise RuntimeError(f"拉回的 {RESULT_NAME} 读取/解析失败: {e}") from e
        if not isinstance(result, dict):
            raise RuntimeError(f"拉回的 {RESULT_NAME} 顶层不是 JSON object")

        # raw/ 的存在性以 result.json 的 raw_output_ref 为准：有引用而没拉到
        # = 证据残缺（fail closed）；无引用则跳过（远端校验失败场景没有 raw/）
        needs_raw = any(
            isinstance(action, dict) and action.get("raw_output_ref")
            for action in result.get("actions", []))
        if needs_raw:
            _step("pull-raw",
                  _scp_argv(identity, port, f"{host}:{remote_out}/{RAW_DIR_NAME}",
                            str(tmp_root / RAW_DIR_NAME), recursive=True),
                  ssh_timeout)
    except RuntimeError as e:
        shutil.rmtree(tmp_root, ignore_errors=True)
        logger.error("%s", e)
        return EXIT_TRANSPORT, f"投递/回收失败：{e}"

    # ---- 回程处理：T002 脱敏 → T001 包域 → dispatch.json（先临时目录）----
    masked_result, masked_fields = mask_value(result)
    (tmp_root / RESULT_NAME).write_text(
        json.dumps(masked_result, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8", newline="\n")

    archived_raw: list[str] = []
    raw_src = tmp_root / RAW_DIR_NAME
    if needs_raw and raw_src.is_dir():
        archived_raw = _mask_raw_logs(raw_src, raw_src)  # 就地掩码（同目录覆盖）

    untrusted_text, injection_hits = _build_untrusted_text(masked_result)
    (tmp_root / UNTRUSTED_NAME).write_text(untrusted_text, encoding="utf-8",
                                           newline="\n")

    remote_rc_match = None
    for line in run_result["stdout"].splitlines():
        matched = RC_LINE.match(line.strip())
        if matched:
            remote_rc_match = matched
    if remote_rc_match is None:
        shutil.rmtree(tmp_root, ignore_errors=True)
        return EXIT_TRANSPORT, "远端未回传 RC= 退出码行，无法确认执行状态"

    remote_rc = int(remote_rc_match.group(1))
    _write_dispatch_meta(
        tmp_root / META_NAME,
        task_id=task_id, host=host, port=port, remote_job=remote_job,
        image=image, network=network, remote_rc=remote_rc,
        task_timeout=task_timeout, steps=steps,
        masked_fields=masked_fields, injection_hits=injection_hits,
        archived_files=[RESULT_NAME, *archived_raw, UNTRUSTED_NAME, META_NAME],
    )

    # ---- 全部成功才进归档（途中任何失败都不会留下半套归档）----
    final_dir = out_dir / task_id
    final_dir.mkdir(parents=True, exist_ok=True)
    for item in (RESULT_NAME, UNTRUSTED_NAME, META_NAME):
        shutil.copy2(tmp_root / item, final_dir / item)
    if needs_raw and (tmp_root / RAW_DIR_NAME).is_dir():
        if (final_dir / RAW_DIR_NAME).exists():
            shutil.rmtree(final_dir / RAW_DIR_NAME)
        shutil.copytree(tmp_root / RAW_DIR_NAME, final_dir / RAW_DIR_NAME)
    shutil.rmtree(tmp_root, ignore_errors=True)

    files = ", ".join([RESULT_NAME, *archived_raw, UNTRUSTED_NAME, META_NAME])
    exit_code = EXIT_REMOTE_ACTION_FAILED if remote_rc == 1 else EXIT_OK
    note = "" if remote_rc == 0 else f"（远端 RC={remote_rc}，见 result.json）"
    summary = (f"{task_id}: 投递+回收完成{note}；掩码字段 {masked_fields}；"
               f"注入命中 {len(injection_hits)}；归档 {final_dir}（{files}）")
    return exit_code, summary


# ---------------------------------------------------------------------------
# CLI 入口
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dispatch",
        description="扫描任务投递/回收桥接：本地预检 -> scp 投递 -> 远端 docker run "
                    "执行 run_scan.py -> 拉回结果 -> T002 脱敏 + T001 包域 -> 归档。",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "安全约束：只允许密钥认证（BatchMode=yes，无密钥当场失败）；\n"
            "远端只执行固定模板命令（mkdir / docker run），密码不出现在任何\n"
            "命令行。前置条件：ssh-copy-id <扫描节点>。\n"
            "退出码：0 全链路成功；1 远端有动作失败（结果已拉回）；\n"
            "2 本地输入/校验错误（fail closed，未投递）；3 投递/传输失败。\n"
        ),
    )
    parser.add_argument("--task", required=True, metavar="PATH",
                        help="task.json 路径（须符合 task-schema.json，先本地预检）")
    parser.add_argument("--host", required=True, metavar="[USER@]HOST",
                        help="扫描节点 SSH 目标（如 root@47.108.111.56）")
    parser.add_argument("--port", type=int, default=22, metavar="PORT",
                        help="SSH 端口（默认 %(default)s）")
    parser.add_argument("--identity", default=None, metavar="KEY",
                        help="SSH 私钥路径（缺省用 ssh 默认密钥）")
    parser.add_argument("--remote-dir", default=DEFAULT_REMOTE_DIR, metavar="DIR",
                        help="远端作业根目录（默认 %(default)s）")
    parser.add_argument("--image", default=DEFAULT_IMAGE, metavar="IMAGE",
                        help="扫描镜像（默认 %(default)s）")
    parser.add_argument("--network", default=DEFAULT_NETWORK, metavar="NET",
                        help="扫描容器网络（默认 %(default)s）")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_SECONDS,
                        metavar="SECONDS",
                        help="远端任务预算秒数（透传给 run_scan --timeout，"
                             "默认 %(default)s）")
    parser.add_argument("--ssh-timeout", type=int, default=DEFAULT_SSH_TIMEOUT,
                        metavar="SECONDS",
                        help="单条 ssh/scp 的本地超时秒数（默认 %(default)s）")
    parser.add_argument("--out-dir", required=True, metavar="DIR",
                        help="本地归档目录（结果写 <out-dir>/<task_id>/）")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s",
                        stream=sys.stderr)
    args = _build_parser().parse_args(argv)
    try:
        exit_code, summary = run_dispatch(
            task_path=Path(args.task), host=args.host, port=args.port,
            identity=args.identity, remote_dir=args.remote_dir,
            image=args.image, network=args.network, task_timeout=args.timeout,
            ssh_timeout=args.ssh_timeout, out_dir=Path(args.out_dir),
            run_fn=_run_command)
    except Exception as e:  # 意外异常归入 3（除输入错误外的失败统一处理）
        logger.error("意外失败（%s: %s）", type(e).__name__, e)
        return EXIT_TRANSPORT
    print(summary)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
