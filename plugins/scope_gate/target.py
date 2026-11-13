"""目标归一化：把模型/命令行里的各种写法还原成规范形式再比对。

这一步是整个门禁的命门。绕过手法几乎全部发生在这里：

    http://2130706433/          整数 IP   -> 127.0.0.1
    http://0177.0.0.1/          八进制分量 -> 127.0.0.1
    http://0x7f.1/              十六进制 + 短写 -> 127.0.0.1
    http://user:pass@host/      带 userinfo
    http://EXAMPLE.com.:8080/   大写 + 尾点 + 端口
    http://[::1]:80/            IPv6
    http://例子.中国/            IDN

本模块只做纯函数，不做 IO。DNS 解析在 resolver 里。
"""

from __future__ import annotations

import ipaddress
import re
from typing import Iterable, List, Optional, Tuple

from .models import Target, TargetKind

MAX_INT_IP = 0xFFFFFFFF

# 云元数据地址：无论 scope 怎么写都默认禁止（SSRF 最常见的目标）
CLOUD_METADATA_IPS = frozenset(
    {
        "169.254.169.254",   # AWS / GCP / Azure / OpenStack
        "100.100.100.200",   # 阿里云
        "fd00:ec2::254",     # AWS IPv6
        "fe80::a9fe:a9fe",   # 通用 link-local
    }
)
CLOUD_METADATA_NAMES = frozenset(
    {"metadata.google.internal", "metadata", "instance-data", "metadata.azure.com"}
)

_URL_RE = re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s\"'`<>|;,\)\]]+")
_CIDR_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}(?![\w.])")
_IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){1,3}\d{1,3}(?![\w.])")
_IPV6_RE = re.compile(r"\[([0-9a-fA-F:]{2,45})\](?::\d{1,5})?")
_HOSTPORT_RE = re.compile(
    r"(?<![\w.@/\-])((?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z\u4e00-\u9fff]{2,})(?::(\d{1,5}))?(?![\w.\-])"
)

# 常见文件后缀（TASK-005 缺陷 2）：`cat robots.txt` 这类命令里的裸文件名
# 会被两段式 host 正则当成域名，这里显式排除。
_FILE_EXTS = frozenset({
    "txt", "html", "htm", "js", "css", "json", "xml", "md", "log", "csv",
    "yaml", "yml", "py", "sh", "conf", "ini", "pdf", "zip", "png", "jpg",
})


def _bare_filename(host: str) -> bool:
    """host 是否为 `<label>.<文件后缀>` 的裸文件名（恰好两段、无上下文）。

    只在 host[:port] 分支且未带端口时调用：URL host 由 scheme 分支处理，
    带端口与多级域名（cdn.example.com）都不满足"恰好两段"，均不受影响。
    """
    parts = host.split(".")
    return len(parts) == 2 and bool(parts[0]) and parts[1].lower() in _FILE_EXTS


class TargetError(ValueError):
    """目标无法规范化。调用方应据此 fail closed。"""


def _parse_legacy_ipv4(token: str) -> Optional[str]:
    """解析 inet_aton 风格的历史写法：整数、十六进制、八进制、缺位短写。

    返回标准点分十进制，失败返回 None。python 的 socket.inet_aton 在 Windows 上
    行为不一致，这里自己实现，保证跨平台可预测。
    """
    token = token.strip()
    if not token or token.count("/") > 0:
        return None
    parts = token.split(".")
    if len(parts) > 4:
        return None

    values: List[int] = []
    for part in parts:
        if not part:
            return None
        try:
            if part.lower().startswith("0x"):
                values.append(int(part, 16))
            elif len(part) > 1 and part.startswith("0"):
                values.append(int(part, 8))
            elif part.isdigit():
                values.append(int(part, 10))
            else:
                return None
        except ValueError:
            return None

    # inet_aton 语义：最后一段吃掉剩余字节
    if any(v < 0 for v in values):
        return None
    if len(values) == 1:
        total = values[0]
        if total > MAX_INT_IP:
            return None
        return str(ipaddress.IPv4Address(total))
    if len(values) >= 2:
        head = values[:-1]
        tail = values[-1]
        if len(head) > 3:
            return None
        for v in head:
            if v > 255:
                return None
        remaining_bytes = 4 - len(head)
        if tail >= (256 ** remaining_bytes):
            return None
        octets: List[int] = list(head)
        for shift in range(remaining_bytes - 1, -1, -1):
            octets.append((tail >> (8 * shift)) & 0xFF)
        if len(octets) != 4:
            return None
        return ".".join(str(o) for o in octets)
    return None


def normalize_host(raw: str) -> Tuple[TargetKind, str, int]:
    """把一个主机写法归一化，返回 (kind, normalized, port)。

    port 为 0 表示未显式指定。无法解析时抛 TargetError。
    """
    if raw is None:
        raise TargetError("空目标")
    text = str(raw).strip()
    if not text:
        raise TargetError("空目标")

    # 去 scheme
    if "://" in text:
        text = text.split("://", 1)[1]
    # 去 userinfo（URL 规范里 @ 之前是凭据）
    if "@" in text:
        text = text.rsplit("@", 1)[1]

    # CIDR 判定必须在去路径之前：路径剥离会把 10.20.30.9/28 剥成 10.20.30.9。
    # 仅当恰好一个 "/"、后缀是纯数字前缀、且前半部分能解析为 IP 网络时才认 CIDR；
    # 否则照常当作路径处理（example.com/x 之类）。
    if text.count("/") == 1:
        head, _, prefix = text.partition("/")
        if prefix.isdigit():
            try:
                net = ipaddress.ip_network(f"{head}/{prefix}", strict=False)
            except ValueError:
                net = None
            if net is not None:
                return TargetKind.CIDR, str(net), 0

    # 去路径 / 查询 / 片段
    for sep in ("/", "?", "#"):
        text = text.split(sep, 1)[0]

    port = 0
    # IPv6 带方括号
    if text.startswith("["):
        end = text.find("]")
        if end < 0:
            raise TargetError(f"IPv6 方括号未闭合: {raw!r}")
        host = text[1:end]
        rest = text[end + 1:]
        if rest.startswith(":"):
            port = _parse_port(rest[1:])
        try:
            addr = ipaddress.IPv6Address(host)
        except ValueError as e:
            raise TargetError(f"非法 IPv6: {raw!r}") from e
        return TargetKind.IP, str(addr), port

    # 显式端口
    if text.count(":") == 1:
        host_part, port_part = text.split(":", 1)
        if port_part.isdigit():
            port = _parse_port(port_part)
            text = host_part

    # IPv6 裸写（多个冒号）
    if text.count(":") >= 2:
        try:
            addr = ipaddress.IPv6Address(text)
            return TargetKind.IP, str(addr), port
        except ValueError as e:
            raise TargetError(f"非法主机: {raw!r}") from e

    # CIDR
    if "/" in text:
        try:
            net = ipaddress.ip_network(text, strict=False)
        except ValueError as e:
            raise TargetError(f"非法 CIDR: {raw!r}") from e
        return TargetKind.CIDR, str(net), port

    # IPv4 / 历史写法
    if re.fullmatch(r"[0-9a-fA-FxX.]+", text) and any(c.isdigit() for c in text):
        dotted = _parse_legacy_ipv4(text)
        if dotted:
            return TargetKind.IP, dotted, port

    # 域名
    host = text.rstrip(".").lower()
    if not host:
        raise TargetError(f"空主机: {raw!r}")
    # 全数字/点串说明它"想"是 IPv4 但解析失败（如 999.999.999.999），
    # 绝不能落到域名分支放行。
    if re.fullmatch(r"[\d.]+", host):
        raise TargetError(f"非法 IPv4 写法: {raw!r}")
    if host in CLOUD_METADATA_NAMES:
        return TargetKind.DOMAIN, host, port
    try:
        host.encode("idna")
        ascii_host = host.encode("idna").decode("ascii")
    except (UnicodeError, ValueError) as e:
        raise TargetError(f"非法域名: {raw!r}") from e
    if len(ascii_host) > 253 or not re.fullmatch(r"[a-z0-9.\-_]+", ascii_host):
        raise TargetError(f"非法域名: {raw!r}")
    return TargetKind.DOMAIN, ascii_host, port


def _parse_port(raw: str) -> int:
    if not raw or not raw.isdigit():
        raise TargetError(f"非法端口: {raw!r}")
    port = int(raw)
    if not 1 <= port <= 65535:
        raise TargetError(f"端口越界: {port}")
    return port


def make_target(raw: str, *, include_subdomains: bool = False) -> Target:
    kind, normalized, port = normalize_host(raw)
    ports: Tuple[int, ...] = (port,) if port else ()
    return Target(kind=kind, normalized=normalized, ports=ports,
                  include_subdomains=include_subdomains, raw=str(raw))


def extract_targets(text: str) -> List[Target]:
    """从任意文本（命令行、URL、自由文本）里抽出所有目标，去重保序。"""
    if not text:
        return []
    found: List[Target] = []
    seen: set[Tuple[str, str]] = set()

    def add(t: Target) -> None:
        key = (t.kind.value, t.normalized)
        if key not in seen:
            seen.add(key)
            found.append(t)

    # 1) URL（最可靠，允许整数 IP 写在 host 位置）
    for m in _URL_RE.finditer(text):
        try:
            add(make_target(m.group(0)))
        except TargetError:
            continue

    # 2) CIDR
    for m in _CIDR_RE.finditer(text):
        try:
            add(make_target(m.group(0)))
        except TargetError:
            continue

    # 3) IPv6 字面量
    for m in _IPV6_RE.finditer(text):
        try:
            add(make_target(m.group(0)))
        except TargetError:
            continue

    # 4) 裸 IPv4 / 短写 / 八进制
    for m in _IPV4_RE.finditer(text):
        token = m.group(0)
        dotted = _parse_legacy_ipv4(token)
        if dotted:
            add(Target(kind=TargetKind.IP, normalized=dotted, raw=token))

    # 5) host[:port]（裸文件名如 robots.txt 不是出网目标，跳过）
    for m in _HOSTPORT_RE.finditer(text):
        host, port = m.group(1), m.group(2)
        if not port and _bare_filename(host):
            continue
        try:
            if port:
                add(make_target(f"{host}:{port}"))
            else:
                add(make_target(host))
        except TargetError:
            continue

    return found


def is_cloud_metadata(kind: TargetKind, normalized: str) -> bool:
    if kind is TargetKind.DOMAIN:
        return normalized in CLOUD_METADATA_NAMES
    if kind is TargetKind.IP:
        return normalized in CLOUD_METADATA_IPS
    return False


def ip_in_any(ip: str, networks: Iterable[str]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for net in networks:
        try:
            if addr in ipaddress.ip_network(net, strict=False):
                return True
        except ValueError:
            continue
    return False
