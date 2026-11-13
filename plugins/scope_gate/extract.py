"""把工具调用翻译成"要打谁 + 做什么动作"。

分类策略：**默认按出网处理**。只有明确列入本地只读清单的工具才放行，
其余一概走 scope 校验。理由——新装一个插件工具就自动变成绕过通道，是最常见的失守方式。

TASK-010 补充：明确列入 LOCAL_TOOLS 的本地类工具（不出网）跳过目标提取与
no_target 判定（is_local_tool）；清单外的未知工具仍默认按出网处理，策略不变。
"""

from __future__ import annotations

import os
import re
import shlex
from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Tuple

from .models import Action
from .target import Target, TargetError, extract_targets

# 不产生网络流量、不改变系统状态的工具
LOCAL_READ_TOOLS = frozenset({
    "read_file", "search_files", "skills_list", "skill_view", "todo",
    "memory", "vision_analyze", "process_manage", "session_search",
})
# 会写本地文件，需要做路径保护，但不需要 scope
LOCAL_WRITE_TOOLS = frozenset({"write_file", "patch"})
# 明确出网
NETWORK_TOOLS = frozenset({
    "web_search", "web_extract", "terminal", "browser_navigate", "browser_snapshot",
    "browser_click", "browser_type", "browser_eval", "browser_screenshot",
    "browser_back", "browser_forward", "browser_reload", "browser_close",
    "browser_tab_new", "browser_tab_switch", "browser_wait",
})
# 网络工具 -> 动作
_PASSIVE = frozenset({"web_search"})

# 命令里的工具名 -> 动作
_VULN_SCAN_CMDS = frozenset({
    "nmap", "masscan", "nuclei", "ffuf", "gobuster", "feroxbuster", "dirsearch",
    "nikto", "wapiti", "whatweb", "httpx", "katana", "subfinder", "amass",
    "naabu", "dnsx", "wpscan", "joomscan", "testssl.sh",
})
_EXPLOIT_CMDS = frozenset({"sqlmap", "hydra", "medusa", "metasploit", "msfconsole",
                           "msfvenom", "crackmapexec", "impacket-scripts", "responder"})
_RECON_CMDS = frozenset({
    "curl", "wget", "http", "httpie", "dig", "nslookup", "host", "whois",
    "traceroute", "tracert", "ping", "openssl", "nc", "ncat", "telnet", "ssh",
})

# 破坏性/持久化/外泄特征（命中即归 forbidden，不看 scope）
_DESTRUCTIVE = re.compile(
    r"(\bmkfs\b|\bshutdown\b|\breboot\b|\bhalt\b|\bpoweroff\b|"
    r"\brm\s+-[a-z]*r[a-z]*f?\s+/(?!\w)|\bdd\s+if=|"
    r"\bcrontab\b|\bsystemctl\s+enable\b|\buseradd\b|\bchpasswd\b|"
    r"\biptables\s+-F\b|\bnft\s+flush\s+ruleset\b)",
    re.IGNORECASE,
)
_EXFIL = re.compile(r"(\bmysqldump\b|\bpg_dump\b|\bscp\b.+\b@|\brclone\b|\baws\s+s3\s+(cp|sync)\b)",
                    re.IGNORECASE)
_DOS = re.compile(r"(?:\b--flood\b|\bslowloris\b|\bhping3\b|\bgoldeneye\b|\b--rate\s+[5-9]\d{2,})",
                  re.IGNORECASE)

_SCRIPT_INTERPRETERS = frozenset({"bash", "sh", "zsh", "dash", "python", "python3",
                                  "pwsh", "powershell", "node", "perl", "ruby"})
# 内联执行形态（TASK-007）：代码以参数形式传给解释器，或解释器交互模式。
# 内联代码里"可见合法目标 + 隐藏 sink"（如 'http://'+'x'+'.com' 拼接）无法
# 静态提取，只能类别性拦截，不能靠目标校验兜底。
_INLINE_EXEC_FLAGS = frozenset({"-c", "-e", "--eval", "-m"})

# 委派类工具：父 Agent 把子任务文本转交子 Agent。文本里提得出目标就按目标判，
# 提不出目标不算解析失败——子任务的出网动作由子 Agent 的门禁把关（TASK-005 缺陷 1）。
DELEGATE_TOOL = "delegate_task"


def is_delegate_tool(name: str) -> bool:
    """是否委派类工具（不区分大小写）。"""
    return (name or "").strip().lower() == DELEGATE_TOOL


# 本地类工具（TASK-010）：不产生网络流量，跳过目标提取与 no_target 判定。
# 与 LOCAL_READ_TOOLS / LOCAL_WRITE_TOOLS 有意重叠——那两个是 gate 里的更早
# 快速通道，这里是统一兜底：清单外的本地工具（tool_describe / tool_search /
# security_scan_* 等）此前被当未知出网工具误杀（2026-11-14 A6 复测：参数无 IP
# 即 no_target，hermes-security 官方插件并发审计被拦 ~10 次）。
LOCAL_TOOLS = frozenset({
    "read_file", "write_file", "edit_file", "list_dir", "list_directory",
    "search_files", "tool_describe", "tool_search", "tool_search_describe",
    "memory_write", "memory_read", "todo_write", "session_status",
    # hermes-security 插件的 9 个本地分析工具
    "security_scan_start", "security_scan_get", "security_scan_checkpoint",
    "security_scan_submit_worker_result", "security_scan_record_validations",
    "security_scan_record_chains", "security_scan_finalize",
    "security_scan_cancel", "security_scan_export",
})
# 部署方经 GateConfig.extra_local_tools 注入的名字（运行时合并进本地清单）。
# gate 是进程级单例（见 gate.py），注册一次全局生效。
_EXTRA_LOCAL_TOOLS: set[str] = set()


def register_local_tools(names: Iterable[str] | None) -> None:
    """把部署方声明的本地工具合并进本地清单（config.yaml 的 extra_local_tools）。

    运行时合并而非改代码：部署方不改 scope_gate 源码即可声明自己的本地工具。
    重复注册幂等，名字统一小写归一（与 is_local_tool 的匹配规则一致）。
    """
    for n in names or ():
        if isinstance(n, str) and n.strip():
            _EXTRA_LOCAL_TOOLS.add(n.strip().lower())


def is_local_tool(name: str) -> bool:
    """是否本地类工具（不区分大小写，含部署方注入的 extra 清单）。"""
    n = (name or "").strip().lower()
    return n in LOCAL_TOOLS or n in _EXTRA_LOCAL_TOOLS


def _collect_strings(value: object, out: List[str]) -> None:
    """递归展开 args 里的字符串值字段（dict/list 嵌套一律展开）。"""
    if isinstance(value, str):
        if value.strip():
            out.append(value)
    elif isinstance(value, dict):
        for v in value.values():
            _collect_strings(v, out)
    elif isinstance(value, (list, tuple)):
        for v in value:
            _collect_strings(v, out)


@dataclass
class Analysis:
    """一次工具调用的静态分析结果。"""

    action: Action
    targets: Tuple[Target, ...] = ()
    command: str = ""
    script_path: str = ""
    inline_eval: bool = False    # 解释器内联执行/交互模式（TASK-007：类别性拦截）
    forbidden: str = ""          # 非空表示命中违规类别（dos/exfil/persistence/lateral）
    parse_error: str = ""
    notes: List[str] = field(default_factory=list)


def _first_token(cmd: str) -> str:
    try:
        parts = shlex.split(cmd, posix=not os.name == "nt")
    except ValueError:
        parts = cmd.split()
    if not parts:
        return ""
    return os.path.basename(parts[0]).lower()


def _segments(cmd: str) -> List[str]:
    """按 shell 元字符切段，避免 `curl a.com; curl evil.com` 只看到第一个。"""
    return [s.strip() for s in re.split(r"\s*(?:&&|\|\||;|\||&)\s*", cmd) if s.strip()]


def _action_for_command(cmd: str) -> Action:
    action = Action.RECON_PASSIVE
    for seg in _segments(cmd):
        tok = _first_token(seg)
        if tok in _EXPLOIT_CMDS:
            return Action.EXPLOIT_PROOF
        if tok in _VULN_SCAN_CMDS:
            action = max(action, Action.VULN_SCAN, key=lambda a: _ORDER[a])
        elif tok in _RECON_CMDS:
            action = max(action, Action.RECON_ACTIVE, key=lambda a: _ORDER[a])
        else:
            # 未识别的命令：只要出现 http(s) 或 IP，按主动探测算
            if re.search(r"https?://|(?:\d{1,3}\.){3}\d{1,3}", seg):
                action = max(action, Action.RECON_ACTIVE, key=lambda a: _ORDER[a])
    return action


_ORDER = {
    Action.RECON_PASSIVE: 0,
    Action.RECON_ACTIVE: 1,
    Action.VULN_SCAN: 2,
    Action.EXPLOIT_PROOF: 3,
}


def analyze_terminal(command: str) -> Analysis:
    """分析一条 shell 命令。"""
    cmd = (command or "").strip()
    if not cmd:
        return Analysis(Action.RECON_ACTIVE, parse_error="命令为空")

    forbidden = ""
    if _DESTRUCTIVE.search(cmd):
        forbidden = "persistence" if re.search(r"crontab|systemctl enable|useradd", cmd, re.I) else "dos"
    elif _EXFIL.search(cmd):
        forbidden = "exfil"
    elif _DOS.search(cmd):
        forbidden = "dos"

    # 脚本执行：命令行只看得到 `bash scan.sh`，目标藏在脚本里 —— 这是最典型的逃逸路径
    script_path = ""
    tok = _first_token(cmd)
    if tok in _SCRIPT_INTERPRETERS:
        try:
            parts = shlex.split(cmd, posix=not os.name == "nt")
        except ValueError:
            parts = cmd.split()
        for arg in parts[1:]:
            if arg in ("-c", "-e", "--eval", "-m"):
                break
            if arg.startswith("-"):
                continue
            if arg.lower().endswith((".sh", ".py", ".ps1", ".pl", ".rb", ".js")):
                script_path = arg
                break

    # 内联执行判定（TASK-007）：解释器 + -c/-e/--eval/-m 任一参数，或除解释器外
    # 无任何参数（交互模式）。逐段判定——`curl a.com && python3 -c '...'` 的整体
    # 首词是 curl，只看整条命令首词会漏掉后段的内联逃逸。
    inline_eval = False
    for seg in _segments(cmd):
        if _first_token(seg) not in _SCRIPT_INTERPRETERS:
            continue
        try:
            parts = shlex.split(seg, posix=not os.name == "nt")
        except ValueError:
            parts = seg.split()
        rest = parts[1:]
        if not rest or any(arg in _INLINE_EXEC_FLAGS for arg in rest):
            inline_eval = True
            break

    targets: List[Target] = []
    seen: set[Tuple[str, str]] = set()
    for seg in _segments(cmd):
        for t in extract_targets(seg):
            key = (t.kind.value, t.normalized)
            if key not in seen:
                seen.add(key)
                targets.append(t)

    return Analysis(
        action=_action_for_command(cmd),
        targets=tuple(targets),
        command=cmd,
        script_path=script_path,
        inline_eval=inline_eval,
        forbidden=forbidden,
    )


def analyze_tool(tool_name: str, args: dict) -> Analysis:
    """把任意工具调用翻译成 Analysis。未知工具按出网处理。"""
    name = (tool_name or "").strip()

    if name in LOCAL_READ_TOOLS:
        return Analysis(Action.RECON_PASSIVE, notes=["local_read"])

    if name == "terminal":
        cmd = ""
        if isinstance(args, dict):
            for key in ("command", "cmd", "script", "input"):
                v = args.get(key)
                if isinstance(v, str) and v.strip():
                    cmd = v
                    break
        if not cmd:
            return Analysis(Action.RECON_ACTIVE, parse_error="terminal 缺少 command 参数")
        return analyze_terminal(cmd)

    if name in ("write_file", "patch"):
        return Analysis(Action.RECON_PASSIVE, notes=["local_write"])

    if name in _PASSIVE:
        return Analysis(Action.RECON_PASSIVE, notes=["passive"])

    # 委派类工具：对子任务文本里的字符串字段跑目标提取。提不出目标不置
    # parse_error——"不认识就拒"只适用于执行目标必判的工具（terminal/curl 类）。
    if is_delegate_tool(name):
        texts: List[str] = []
        if isinstance(args, dict):
            for v in args.values():
                _collect_strings(v, texts)
        blob = "\n".join(texts)
        found = extract_targets(blob)
        return Analysis(
            Action.RECON_ACTIVE,
            targets=tuple(found),
            command=blob,
            notes=["delegate"],
        )

    if name.startswith("browser_") or name in NETWORK_TOOLS:
        target_text = ""
        if isinstance(args, dict):
            for key in ("url", "href", "target", "address"):
                v = args.get(key)
                if isinstance(v, str) and v.strip():
                    target_text = v
                    break
            if not target_text:
                target_text = " ".join(str(v) for v in args.values() if isinstance(v, str))
        found = extract_targets(target_text)
        return Analysis(Action.RECON_ACTIVE, targets=tuple(found),
                        command=target_text,
                        parse_error="" if found else "浏览器动作未解析出目标")

    # 未知工具：按"可能出网"处理，要求能从参数里解析出目标。已知出网工具
    # （terminal/browser/delegate）的全文提取原样保留——版本号（python-3.14.9
    # -> 3.14.0.9，见 target._parse_legacy_ipv4 的 inet_aton 语义）与标识符
    # （os.path.join -> 域名）会被误解析成目标，在这类工具里是可接受的误报
    # 代价：绕过检测优先于提取精度（TASK-010 取舍，仅本地工具豁免提取）。
    blob = ""
    if isinstance(args, dict):
        blob = " ".join(str(v) for v in args.values() if isinstance(v, str))
    found = extract_targets(blob)
    return Analysis(
        Action.RECON_ACTIVE,
        targets=tuple(found),
        command=blob,
        parse_error="" if found else f"未知工具 {name} 未能解析出目标",
        notes=["unknown_tool"],
    )


def paths_from_args(tool_name: str, args: dict) -> Tuple[str, ...]:
    if not isinstance(args, dict):
        return ()
    out: List[str] = []
    for key in ("path", "file_path", "target_file", "filename"):
        v = args.get(key)
        if isinstance(v, str) and v.strip():
            out.append(v)
    return tuple(out)
