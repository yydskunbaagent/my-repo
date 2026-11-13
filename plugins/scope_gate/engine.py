"""判定引擎：纯函数，不做 IO，方便穷举测试。

判定顺序（顺序本身就是安全性的一部分，改动需评审）：

    1. engagement 是否可用          -> 不可用即拒（fail closed）
    2. 动作是否被禁止               -> forbidden 优先于 allowed
    3. 是否在时间窗内
    4. 动作是否在允许集内
    5. 目标是否为空                 -> 空=解析失败=拒（委派类空=交子层把关；
                                       本地类不出网，放行——TASK-010）
    6. 逐个目标：云元数据 / 排除项 / 范围 / 端口 / 解析结果（私网/保留段默认阻断）
    7. 速率与总量
    8. 高危动作升级人工确认
"""

from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from ipaddress import IPv4Address, IPv6Address
from typing import Iterable, List, Optional, Tuple

from .extract import is_delegate_tool, is_local_tool
from .models import (
    Action,
    Decision,
    DecisionKind,
    Engagement,
    Exclusion,
    Target,
    TargetKind,
)
from .target import is_cloud_metadata

MAX_IPS_PER_DOMAIN = 64

# 私网/保留段：域名解析落入这些段默认阻断——公网域名解析到内网地址是 SSRF 的
# 标准前置步骤。例外：该 IP 被 scope 以显式 IP/CIDR 目标授权时放行。
_BLOCKED_IPV4_NETWORKS = tuple(
    ipaddress.ip_network(n) for n in (
        "0.0.0.0/8",        # "this network"
        "10.0.0.0/8",       # RFC1918 私网
        "100.64.0.0/10",    # CGN（运营商级 NAT）
        "127.0.0.0/8",      # loopback
        "169.254.0.0/16",   # link-local（云元数据 169.254.169.254 在此段）
        "172.16.0.0/12",    # RFC1918 私网
        "192.0.0.0/24",     # IETF 协议分配
        "192.0.2.0/24",     # TEST-NET-1
        "192.88.99.0/24",   # 6to4 relay anycast（已废弃）
        "192.168.0.0/16",   # RFC1918 私网
        "198.18.0.0/15",    # 网络基准测试
        "198.51.100.0/24",  # TEST-NET-2
        "203.0.113.0/24",   # TEST-NET-3
        "224.0.0.0/4",      # 组播
        "240.0.0.0/4",      # 保留（含受限广播）
    )
)
_BLOCKED_IPV6_NETWORKS = tuple(
    ipaddress.ip_network(n) for n in (
        "::/128",       # 未指定地址
        "::1/128",      # loopback
        "fc00::/7",     # unique local
        "fe80::/10",    # link-local
        "ff00::/8",     # 组播
    )
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _block(code: str, message: str, target: str = "") -> Decision:
    return Decision(DecisionKind.BLOCK, code, message, target)


def _target_matches_domain(target: Target, host: str) -> bool:
    if target.kind is not TargetKind.DOMAIN:
        return False
    if host == target.normalized:
        return True
    if target.include_subdomains and host.endswith("." + target.normalized):
        return True
    return False


def _target_covers_ip(target: Target, ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if target.kind is TargetKind.IP:
        return str(addr) == target.normalized
    if target.kind is TargetKind.CIDR:
        try:
            return addr in ipaddress.ip_network(target.normalized, strict=False)
        except ValueError:
            return False
    return False


def _excluded(ip: str, host: str, exclusions: Iterable[Exclusion]) -> Optional[Exclusion]:
    for ex in exclusions:
        if ex.kind is TargetKind.IP and ex.normalized == ip:
            return ex
        if ex.kind is TargetKind.CIDR:
            try:
                if ipaddress.ip_address(ip) in ipaddress.ip_network(ex.normalized, strict=False):
                    return ex
            except ValueError:
                continue
        if ex.kind is TargetKind.DOMAIN and (host == ex.normalized or host.endswith("." + ex.normalized)):
            return ex
    return None


def _port_allowed(target: Target, port: int) -> bool:
    if not target.ports or port <= 0:
        return True
    return port in target.ports


def is_blocked_network(ip: IPv4Address | IPv6Address) -> bool:
    """IP 是否落在私网/保留段。

    IPv4-mapped IPv6（::ffff:0:0/96）先还原成 IPv4 再按 IPv4 规则判断，
    防止用映射写法绕过私网阻断。
    """
    if isinstance(ip, IPv4Address):
        return any(ip in net for net in _BLOCKED_IPV4_NETWORKS)
    if isinstance(ip, IPv6Address):
        mapped = ip.ipv4_mapped
        if mapped is not None:
            return is_blocked_network(mapped)
        return any(ip in net for net in _BLOCKED_IPV6_NETWORKS)
    return False


def _unauthorized_private_ip(engagement: Engagement, ip: str) -> bool:
    """解析出的 IP 是否属于"私网/保留段且未被 scope 显式授权"。

    排除项不在此判断：调用方先查排除项，排除优先于私网阻断。
    解析结果不是合法 IP 时按最坏情况处理（fail closed）。
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    if not is_blocked_network(addr):
        return False
    authorized = (
        any(_target_covers_ip(x, ip) for x in engagement.ip_targets)
        or any(_target_covers_ip(x, ip) for x in engagement.cidr_targets)
    )
    return not authorized


def decide(
    engagement: Optional[Engagement],
    *,
    tool_name: str,
    action: Action,
    targets: Tuple[Target, ...],
    resolved: dict[str, Tuple[str, ...]],
    unresolvable: Tuple[str, ...],
    forbidden_hit: str = "",
    parse_error: str = "",
    now: datetime | None = None,
    rate_checker=None,
) -> Decision:
    """返回单条决策。rate_checker: (host) -> (bool, code, detail) 可注入。"""
    now = now or _now()

    if engagement is None:
        return _block("no_engagement",
                      "scope 未加载或校验失败，所有出网动作一律拒绝。请修复 scope.yaml 后重试。")

    eng = engagement
    head = f"[scope-gate] {eng.summary()}"

    # 2. 禁止项优先
    if forbidden_hit:
        return _block(f"forbidden_{forbidden_hit}",
                      f"{head}\n被拒绝：命令命中禁止类别 {forbidden_hit}。"
                      f"本作业不允许拒绝服务、数据外泄、持久化或横向移动类操作。")

    # 3. 时间窗
    if now < eng.window.start:
        return _block("window_not_started",
                      f"{head}\n被拒绝：作业尚未开始（{eng.window.start.isoformat()} 起）。")
    if now > eng.window.end:
        return _block("window_expired",
                      f"{head}\n被拒绝：作业已结束（{eng.window.end.isoformat()} 截止）。")

    # 4. 动作分级
    if action not in eng.allowed_actions:
        allowed = ", ".join(sorted(a.value for a in eng.allowed_actions))
        return _block("action_not_allowed",
                      f"{head}\n被拒绝：动作 {action.value} 不在允许范围（{allowed}）。")

    # 5. 解析失败
    if parse_error:
        return _block("unparsed_target",
                      f"{head}\n被拒绝：无法从工具调用中确定目标（{parse_error}）。"
                      f"请把目标显式写在参数里（URL/IP/CIDR），不要藏在脚本内部。")
    if not targets:
        # 委派类工具：子任务文本提不出可识别目标 -> 放行，交给子 Agent 的门禁把关
        # （TASK-005 缺陷 1：从"不认识就拒"改为"提得出就按目标判，提不出才交子层"）
        if is_delegate_tool(tool_name):
            return Decision(DecisionKind.ALLOW, "delegate_no_target", "")
        # 本地类工具（TASK-010）：不出网，无目标不算解析失败，直接放行
        if is_local_tool(tool_name):
            return Decision(DecisionKind.ALLOW, "local_tool", "")
        return _block("no_target",
                      f"{head}\n被拒绝：未解析到任何目标。")

    # 6. 逐目标校验
    for t in targets:
        if is_cloud_metadata(t.kind, t.normalized):
            return _block("cloud_metadata",
                          f"{head}\n被拒绝：{t} 是云元数据地址，任何作业都不允许访问。", str(t))

        port = t.ports[0] if t.ports else 0
        ips = resolved.get(t.normalized, ())

        if t.kind is TargetKind.DOMAIN:
            matched = next((x for x in eng.domain_targets if _target_matches_domain(x, t.normalized)), None)
            if matched is None:
                return _block("out_of_scope",
                              f"{head}\n被拒绝：{t.normalized} 不在授权范围内。"
                              f"不要尝试子域枚举到范围外的域名。", t.normalized)
            if not _port_allowed(matched, port):
                return _block("port_not_allowed",
                              f"{head}\n被拒绝：{t.normalized}:{port} 的端口不在授权端口列表 "
                              f"{list(matched.ports)} 内。", t.normalized)
            if t.normalized in unresolvable:
                return _block("unresolved_target",
                              f"{head}\n被拒绝：{t.normalized} 无法解析，可能是隧道或已失效目标。",
                              t.normalized)
            if len(ips) > MAX_IPS_PER_DOMAIN:
                return _block("too_many_ips",
                              f"{head}\n被拒绝：{t.normalized} 解析出 {len(ips)} 个地址，"
                              f"超出单域名上限 {MAX_IPS_PER_DOMAIN}，疑似泛解析。", t.normalized)
            for ip in ips:
                ex = _excluded(ip, t.normalized, eng.exclusions)
                if ex:
                    return _block("excluded_target",
                                  f"{head}\n被拒绝：{t.normalized} 解析到被排除的 {ip}。", t.normalized)
                if _unauthorized_private_ip(eng, ip):
                    return _block("private_network_resolution",
                                  f"{head}\n被拒绝：{t.normalized} 解析到未授权的私网/保留地址 {ip}。"
                                  f"域名解析到私网/保留段默认阻断；如确属授权内网目标，"
                                  f"请在 scope 中以显式 IP/CIDR 目标写明该地址。", t.normalized)
            continue

        # IP / CIDR 目标
        if t.kind is TargetKind.CIDR:
            # 允许对整个网段发起扫描，但必须是授权网段的子集
            try:
                requested = ipaddress.ip_network(t.normalized, strict=False)
            except ValueError:
                return _block("unparsed_target", f"{head}\n被拒绝：{t.normalized} 不是合法网段。")
            covering = None
            for x in eng.cidr_targets:
                try:
                    allowed_net = ipaddress.ip_network(x.normalized, strict=False)
                except ValueError:
                    continue
                if requested.subnet_of(allowed_net) or requested == allowed_net:
                    covering = x
                    break
            if covering is None:
                return _block("out_of_scope",
                              f"{head}\n被拒绝：网段 {t.normalized} 不是授权网段的子集。",
                              t.normalized)
            if not _port_allowed(covering, port):
                return _block("port_not_allowed",
                              f"{head}\n被拒绝：{t.normalized} 端口 {port} 不在授权列表内。",
                              t.normalized)
            # 网段与排除项有交集时，禁止整段扫描（避免打到排除主机）
            for ex in eng.exclusions:
                if ex.kind is TargetKind.IP:
                    try:
                        if ipaddress.ip_address(ex.normalized) in requested:
                            return _block(
                                "excluded_target",
                                f"{head}\n被拒绝：网段 {t.normalized} 含有被排除地址 {ex.normalized}，"
                                f"请改为逐主机扫描或缩小网段。", t.normalized)
                    except ValueError:
                        continue
                elif ex.kind is TargetKind.CIDR:
                    try:
                        if ipaddress.ip_network(ex.normalized, strict=False).overlaps(requested):
                            return _block(
                                "excluded_target",
                                f"{head}\n被拒绝：网段 {t.normalized} 与排除网段 {ex.normalized} 重叠。",
                                t.normalized)
                    except ValueError:
                        continue
            continue

        ip = t.normalized
        ex = _excluded(ip, "", eng.exclusions)
        if ex:
            reason = f"（{ex.reason}）" if ex.reason else ""
            return _block("excluded_target",
                          f"{head}\n被拒绝：{ip} 在排除列表中{reason}。", ip)
        covered = next((x for x in eng.ip_targets if _target_covers_ip(x, ip)), None) or \
                  next((x for x in eng.cidr_targets if _target_covers_ip(x, ip)), None)
        if covered is None:
            return _block("out_of_scope", f"{head}\n被拒绝：{ip} 不在授权范围内。", ip)
        if not _port_allowed(covered, port):
            return _block("port_not_allowed",
                          f"{head}\n被拒绝：{ip}:{port} 端口不在授权列表内。", ip)

    # 7. 限速
    if rate_checker is not None:
        hosts = sorted({t.normalized for t in targets})
        for host in hosts:
            ok, code, detail = rate_checker(host)
            if not ok:
                return _block(code, f"{head}\n被限速：{detail}")

    # 8. 高危动作升级人工
    if action is Action.EXPLOIT_PROOF:
        return Decision(
            DecisionKind.APPROVE,
            "exploit_requires_approval",
            f"{head}\n动作 {action.value} 需要人工确认。目标: "
            f"{', '.join(str(t) for t in targets)}。批准后本会话内同类目标不再重复询问。",
        )

    return Decision(DecisionKind.ALLOW, "ok", "")
