#!/usr/bin/env python3
"""把 scope.yaml 授权域名的解析结果喂进 nftables 动态集合。

扫描节点（deploy/nftables/scan-node.nft，inet hermes_scan 表）默认拒绝一切出站，
仅放行到受控解析器的 DNS 和到 allow_domains4/6（动态集合）、allow_ranges4/6
（静态网段集合）的 TCP 80/443。本脚本把 scope 中 kind: domain 的目标经受控
解析器（--resolver）解析出的公网地址喂进动态集合；条目带 timeout，到期自动
失效，需按 --ttl 的量级周期性重跑（systemd timer 等）。

fail-closed 语义：
  - scope 加载/校验失败、授权窗口未开始或已结束 -> 报错退出（rc=2），一条不喂
  - 域名解析失败 -> 打印警告并跳过（解析不出的域名自然没有放行条目）
  - 解析结果落在私网/保留段 -> 跳过并警告（复用
    plugins/scope_gate/engine.is_blocked_network，与门禁引擎的
    private_network_resolution 判定口径一致）
  - 单域名解析地址数超过 engine.MAX_IPS_PER_DOMAIN -> 疑似泛解析，整体跳过

仅处理 kind: domain 目标；ip/cidr 目标属于静态集合 allow_ranges，按授权流程
人工维护，脚本不碰。include_subdomains 的子域不在喂入范围：子域解析结果不会
进集合，nft 层自然拒绝（DNS 层由 unbound 的 transparent 子树放行，网络层兜底）。

DNS 查询只用标准库 socket：直接向受控解析器发 UDP 报文（RFC1035 编解码在本文件
内实现），不依赖 dnspython。--dry-run 时若受控解析器不可达，回退用系统解析器
仅作预览（getaddrinfo），并在输出中显著标注；正式运行不做任何回退，只会警告并
跳过——解析器不可达时零放行条目。

用法：
    python3 scope_feed.py --scope /etc/hermes/scope.yaml               # 实际喂入（root + nft）
    python3 scope_feed.py --scope engagement-demo/scope.yaml --dry-run # 只打印将执行的命令

退出码：0 成功（解析失败跳过属设计内行为，只警告）；1 有条目 nft 执行失败；
2 fail-closed（scope 无效 / 授权窗口外 / 参数非法 / nft 缺失）。
"""

from __future__ import annotations

import argparse
import ipaddress
import logging
import os
import shlex
import shutil
import socket
import struct
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Sequence, Tuple

# 复用 plugins/scope_gate：仓库根加进 sys.path（deploy/dns/ 向上两级即仓库根）。
# scope 校验走 ScopeStore（内部即 plugins/scope_gate/scope.parse_scope 的校验路径），
# 私网/保留段判定走 engine.is_blocked_network——本脚本不复制任何校验逻辑。
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from plugins.scope_gate.engine import MAX_IPS_PER_DOMAIN, is_blocked_network
from plugins.scope_gate.models import Engagement
from plugins.scope_gate.scope import ScopeStore

logger = logging.getLogger("scope_feed")

DEFAULT_TABLE = "hermes_scan"
DEFAULT_SET4 = "allow_domains4"
DEFAULT_SET6 = "allow_domains6"
DEFAULT_TTL_SECONDS = 300
DEFAULT_RESOLVER = "10.10.0.53"

DNS_PORT = 53
QUERY_TIMEOUT_SECONDS = 3.0  # 单次 UDP 查询超时；解析器不可达时尽快失败
QTYPE_A = 1
QTYPE_AAAA = 28
RECV_ATTEMPTS = 3  # 丢弃 ID 不匹配的杂散报文，最多等这几轮


class ResolverUnreachable(Exception):
    """网络层连不上受控解析器（超时/不可达/应答不匹配）。"""


class ResolutionFailed(Exception):
    """解析器有应答但解析不出（NXDOMAIN/SERVFAIL/截断/报文异常）。"""


# ---------------------------------------------------------------------------
# 最小 DNS 编解码（RFC1035）：只用标准库，直接与受控解析器对话
# ---------------------------------------------------------------------------

def _encode_query(name: str, qtype: int) -> bytes:
    """构造标准 DNS 查询报文（RD=1，单问题段）。"""
    labels = name.rstrip(".").split(".")
    for label in labels:
        if not label or len(label) > 63:
            raise ValueError(f"非法域名标签: {label!r}")
    try:
        wire_labels = b"".join(
            bytes([len(label)]) + label.encode("ascii") for label in labels
        )
    except UnicodeEncodeError as e:
        raise ValueError(f"域名含非 ASCII 字符: {name!r}") from e
    header = struct.pack("!HHHHHH", _query_id(), 0x0100, 1, 0, 0, 0)
    return header + wire_labels + b"\x00" + struct.pack("!HH", qtype, 1)


def _query_id() -> int:
    return int.from_bytes(os.urandom(2), "big")


def _decode_name(msg: bytes, offset: int) -> Tuple[str, int]:
    """解析（可能压缩的）域名，返回 (域名文本, 名字之后的 offset)。

    压缩指针限制跳数，防止构造报文造成解析死循环。
    """
    labels: List[str] = []
    pos = offset
    after_name = -1
    jumps = 0
    while True:
        if pos >= len(msg):
            raise ResolutionFailed("域名段被截断")
        length = msg[pos]
        if length & 0xC0 == 0xC0:  # 压缩指针
            if pos + 1 >= len(msg):
                raise ResolutionFailed("压缩指针被截断")
            if after_name < 0:
                after_name = pos + 2
            pos = ((length & 0x3F) << 8) | msg[pos + 1]
            jumps += 1
            if jumps > 16:
                raise ResolutionFailed("压缩指针跳数异常")
            continue
        if length & 0xC0:
            raise ResolutionFailed("非法标签类型")
        pos += 1
        if length == 0:
            if after_name < 0:
                after_name = pos
            break
        if pos + length > len(msg):
            raise ResolutionFailed("标签被截断")
        labels.append(msg[pos:pos + length].decode("ascii", "replace"))
        pos += length
    return (".".join(labels) if labels else ""), after_name


def _parse_answers(msg: bytes) -> list:
    """解析 DNS 应答中的 A/AAAA 记录（CNAME 等其他类型跳过）。

    递归解析器会把 CNAME 链的最终地址一起放进应答段，因此不校验记录属主，
    收全部地址记录即可。
    """
    if len(msg) < 12:
        raise ResolutionFailed("应答过短")
    _qid, flags, qdcount, ancount, _ns, _ar = struct.unpack("!HHHHHH", msg[:12])
    if not flags & 0x8000:
        raise ResolutionFailed("不是应答报文（QR=0）")
    rcode = flags & 0x000F
    if rcode == 3:
        raise ResolutionFailed("NXDOMAIN：域名不存在")
    if rcode != 0:
        raise ResolutionFailed(f"RCODE={rcode}")
    if flags & 0x0200:
        raise ResolutionFailed("应答被截断（TC=1），记录可能不全")

    offset = 12
    for _ in range(qdcount):  # 跳过问题段
        _owner, offset = _decode_name(msg, offset)
        offset += 4  # QTYPE + QCLASS

    answers: list = []
    for _ in range(ancount):
        _owner, offset = _decode_name(msg, offset)
        if offset + 10 > len(msg):
            raise ResolutionFailed("资源记录头被截断")
        rtype, _rclass, _ttl, rdlen = struct.unpack("!HHIH", msg[offset:offset + 10])
        offset += 10
        rdata = msg[offset:offset + rdlen]
        if len(rdata) != rdlen:
            raise ResolutionFailed("资源记录数据被截断")
        offset += rdlen
        try:
            if rtype == QTYPE_A and rdlen == 4:
                answers.append(ipaddress.IPv4Address(rdata))
            elif rtype == QTYPE_AAAA and rdlen == 16:
                answers.append(ipaddress.IPv6Address(rdata))
        except ipaddress.AddressValueError as e:
            raise ResolutionFailed(f"地址记录数据非法: {e}") from e
    return answers


def _dns_query(resolver: str, name: str, qtype: int) -> list:
    """向受控解析器发送一次 UDP 查询，返回应答中的地址记录列表。

    网络层失败抛 ResolverUnreachable；应答异常抛 ResolutionFailed。
    """
    query = _encode_query(name, qtype)
    family = socket.AF_INET6 if ipaddress.ip_address(resolver).version == 6 else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.settimeout(QUERY_TIMEOUT_SECONDS)
            sock.sendto(query, (resolver, DNS_PORT))
            data = b""
            for _ in range(RECV_ATTEMPTS):
                data, _peer = sock.recvfrom(4096)
                if len(data) >= 12 and data[:2] == query[:2]:
                    break  # 事务 ID 匹配才算有效应答
                data = b""
            if not data:
                raise ResolverUnreachable("应答事务 ID 不匹配")
    except OSError as e:  # 含 socket.timeout / 不可达 / 连接被拒
        raise ResolverUnreachable(f"{type(e).__name__}: {e}") from e
    return _parse_answers(data)


def _resolve_domain(name: str, resolver: str) -> Tuple[list, list]:
    """解析单个域名的 A/AAAA 记录，返回 (IPv4 列表, IPv6 列表)，各自去重保序。"""
    v4 = _dns_query(resolver, name, QTYPE_A)
    v6 = _dns_query(resolver, name, QTYPE_AAAA)
    return _dedupe(v4), _dedupe(v6)


def _resolve_via_system(name: str) -> Tuple[list, list]:
    """系统解析器回退（仅 --dry-run 预览用），返回 (IPv4 列表, IPv6 列表)。"""
    try:
        infos = socket.getaddrinfo(name, None)
    except socket.gaierror as e:
        raise ResolutionFailed(f"系统解析失败: {e}") from e
    v4: list = []
    v6: list = []
    for info in infos:
        try:
            addr = ipaddress.ip_address(info[4][0])
        except ValueError:
            continue  # 带 scope id 之类的写法，直接忽略
        if addr.version == 4:
            v4.append(addr)
        elif addr.version == 6:
            v6.append(addr)
    return _dedupe(v4), _dedupe(v6)


def _dedupe(addrs: list) -> list:
    return list(dict.fromkeys(addrs))


# ---------------------------------------------------------------------------
# 喂入 nftables
# ---------------------------------------------------------------------------

def _nft_add_element(table: str, set_name: str, ip: str, ttl: int) -> List[str]:
    """单条 nft 命令，参数列表形式（不经 shell 拼接）。"""
    return ["nft", "add", "element", "inet", table, set_name,
            f"{{ {ip} timeout {ttl}s }}"]


def _feed_addresses(args: argparse.Namespace, name: str, source: str,
                    v4: list, v6: list) -> int:
    """喂入（或打印）一个域名的全部地址，返回 nft 执行失败的条目数。"""
    failed = 0
    for rtype, addrs, set_name in (("A", v4, args.set4), ("AAAA", v6, args.set6)):
        for addr in addrs:
            if is_blocked_network(addr):
                logger.warning("%s：解析到私网/保留地址 %s，跳过（与门禁引擎口径一致）",
                               name, addr)
                continue
            cmd = _nft_add_element(args.table, set_name, str(addr), args.ttl)
            if args.dry_run:
                print(f"# {name} {rtype} {addr}  [{source}]")
                print(" ".join(shlex.quote(part) for part in cmd))
            else:
                result = subprocess.run(cmd, capture_output=True, text=True, check=False)
                if result.returncode != 0:
                    detail = (result.stderr or result.stdout or "").strip()
                    logger.error("%s：nft 添加 %s 失败（rc=%d）: %s",
                                 name, addr, result.returncode, detail)
                    failed += 1
                else:
                    logger.info("%s：已添加 %s（timeout %ds）", name, addr, args.ttl)
    return failed


def _feed(engagement: Engagement, args: argparse.Namespace) -> int:
    """对每个授权域名解析并喂入/打印 nft 命令。返回 nft 执行失败的条目数。"""
    domains = engagement.domain_targets
    if not domains:
        logger.info("scope 中没有 kind: domain 目标，无需喂入动态集合")
        return 0

    resolver_down = False
    failed = 0

    for target in domains:
        name = target.normalized
        try:
            if resolver_down:
                raise ResolverUnreachable("受控解析器此前已判定不可达")
            v4, v6 = _resolve_domain(name, args.resolver)
            source = "受控解析器"
        except ResolverUnreachable as e:
            resolver_down = True
            if not args.dry_run:
                # 正式运行不回退：解析器不可达 -> 该域名零放行条目（fail closed）
                logger.warning("%s：无法连接受控解析器 %s（%s），跳过——正式运行不回退",
                               name, args.resolver, e)
                continue
            logger.warning("%s：受控解析器 %s 不可达（%s）；--dry-run 仅作预览，"
                           "回退用系统解析器生成命令；正式运行不做回退，只会警告并跳过",
                           name, args.resolver, e)
            try:
                v4, v6 = _resolve_via_system(name)
                source = "系统解析器（dry-run 预览）"
            except ResolutionFailed as e2:
                logger.warning("%s：解析失败（%s），无放行条目", name, e2)
                continue
        except ResolutionFailed as e:
            logger.warning("%s：解析失败（%s），无放行条目", name, e)
            continue

        if len(v4) + len(v6) > MAX_IPS_PER_DOMAIN:
            logger.warning("%s：解析出 %d 个地址，超过单域名上限 %d，疑似泛解析，整体跳过",
                           name, len(v4) + len(v6), MAX_IPS_PER_DOMAIN)
            continue
        if not v4 and not v6:
            logger.warning("%s：无 A/AAAA 记录，无放行条目", name)
            continue

        logger.info("%s：[%s] 解析到 %d 个 IPv4 / %d 个 IPv6", name, source, len(v4), len(v6))
        failed += _feed_addresses(args, name, source, v4, v6)

    return failed


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------

def _load_engagement(scope_path: str) -> Engagement | None:
    """加载并校验 scope（经 ScopeStore，即 parse_scope 的校验路径）。失败返回 None。"""
    store = ScopeStore(scope_path)
    state = store.state
    if not state.usable or state.engagement is None:
        logger.error("scope 加载/校验失败，拒绝喂入（fail closed）: %s", state.error)
        return None
    return state.engagement


def _check_window(engagement: Engagement) -> bool:
    """授权窗口检查：窗口外一律拒绝喂入（fail closed）。"""
    now = datetime.now(timezone.utc)
    start = engagement.window.start
    end = engagement.window.end
    if start.tzinfo is None:
        logger.warning("scope 的 window.start 不带时区，按 UTC 处理: %s", start)
        start = start.replace(tzinfo=timezone.utc)
    if end.tzinfo is None:
        logger.warning("scope 的 window.end 不带时区，按 UTC 处理: %s", end)
        end = end.replace(tzinfo=timezone.utc)
    if now < start:
        logger.error("授权窗口未开始（%s 起），拒绝喂入（fail closed）", start.isoformat())
        return False
    if now > end:
        logger.error("授权窗口已结束（%s 截止），拒绝喂入（fail closed）", end.isoformat())
        return False
    return True


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scope_feed",
        description="把 scope.yaml 授权域名的解析结果喂进 nftables 动态集合"
                    "（deploy/nftables/scan-node.nft 的 allow_domains4/allow_domains6）。",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "示例：\n"
            "  scope_feed.py --scope /etc/hermes/scope.yaml\n"
            "  scope_feed.py --scope engagement-demo/scope.yaml --dry-run\n"
            "\n"
            "fail-closed：scope 无效或授权窗口外直接退出；域名解析失败仅警告并跳过，\n"
            "解析不出的域名不会产生任何放行条目。条目带 --ttl 自动过期，需周期重跑。\n"
            "仅处理 kind: domain 目标；ip/cidr 目标属于静态集合 allow_ranges，人工维护。\n"
            "退出码：0 成功；1 有条目 nft 执行失败；2 fail-closed（scope 无效/窗口外）。\n"
        ),
    )
    parser.add_argument("--scope", required=True, metavar="PATH",
                        help="scope.yaml 路径")
    parser.add_argument("--table", default=DEFAULT_TABLE,
                        help="nft 表名（默认 %(default)s）")
    parser.add_argument("--set4", default=DEFAULT_SET4,
                        help="IPv4 动态集合名（默认 %(default)s）")
    parser.add_argument("--set6", default=DEFAULT_SET6,
                        help="IPv6 动态集合名（默认 %(default)s）")
    parser.add_argument("--ttl", type=int, default=DEFAULT_TTL_SECONDS, metavar="SECONDS",
                        help="集合条目存活秒数（默认 %(default)s）")
    parser.add_argument("--resolver", default=DEFAULT_RESOLVER, metavar="IP",
                        help="受控解析器地址（默认 %(default)s）")
    parser.add_argument("--dry-run", action="store_true",
                        help="只打印将执行的 nft 命令（stdout），不执行、不改集合")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s",
                        stream=sys.stderr)
    args = _build_parser().parse_args(argv)

    if args.ttl <= 0:
        logger.error("--ttl 必须为正整数，收到 %d", args.ttl)
        return 2
    try:
        ipaddress.ip_address(args.resolver)
    except ValueError as e:
        logger.error("--resolver 不是合法 IP: %r（%s）", args.resolver, e)
        return 2

    engagement = _load_engagement(args.scope)
    if engagement is None:
        return 2
    if not _check_window(engagement):
        return 2

    logger.info("engagement=%s authorized_by=%s 窗口 %s ~ %s，domain 目标 %d 个",
                engagement.id, engagement.authorized_by,
                engagement.window.start.isoformat(), engagement.window.end.isoformat(),
                len(engagement.domain_targets))

    if not args.dry_run and shutil.which("nft") is None:
        logger.error("找不到 nft 可执行文件；实际喂入需在扫描节点以 root 运行（预览请加 --dry-run）")
        return 2

    failed = _feed(engagement, args)
    if failed:
        logger.error("有 %d 个条目 nft 执行失败，请检查表/集合是否存在", failed)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
