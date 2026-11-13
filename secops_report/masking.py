"""报告输出的敏感信息掩码（TASK-006 任务 3）。

报告会流转到授权交付名单之外（存档、评审、模板复用），Evidence 的响应片段
里常带 Authorization/Cookie/Token——原样渲染进报告等于二次泄露。本模块用
纯标准库正则对三类模式做统一掩码，渲染器（render.py）在输出前调用：

  - Header 形态：Authorization/Cookie/Set-Cookie/X-Api-Key 的值
    （name 不分大小写；值为 Bearer/Basic 等 scheme 开头时保留 scheme，只掩凭据）
  - Token 形态：sk-/em-sk-/ghp_ 前缀串、Bearer 后随 token、三段式 JWT（eyJ 开头）
  - URL 查询串：token/key/secret/password/api_key 参数值

掩码规则：保留前 4 后 2 字符，中间换 ***；总长 <= 8 全掩码。掩码只少不多：
header 值按"冒号后整行"处理，同一行跟随的说明文字会被一并掩码——宁可多掩，
不可漏掩。掩码产物含 *，不会命中任何凭据模式，重复调用结果不变，渲染器
重复处理无副作用。
"""

from __future__ import annotations

import re
from typing import Match

_MASKED = "***"

# Header 形态：name 不分大小写，值取"冒号后整行"（HTTP 头按行界定）。
# set-cookie 必须排在 cookie 之前，避免同一起点被短 alternatives 抢先。
_HEADER_RE = re.compile(
    r"(?i)\b(set-cookie|authorization|x-api-key|cookie)\s*:\s*([^\r\n]+)"
)

# Header 值里的 scheme 前缀（RFC 7235 credentials）：保留 scheme，只掩后面的凭据。
_SCHEME_RE = re.compile(r"(?i)^(bearer|basic|digest|negotiate)\s+(.+)$")

# Token 形态。JWT 要求第二段同样以 eyJ 开头（payload 是 JSON，首两字节恒为 eyJ）。
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")
# em-sk- 排在 sk- 之前，否则 sk- 会把 em-sk- 的后半截单独掩掉。
_PREFIXED_RE = re.compile(r"\b(?:em-sk|sk)-[A-Za-z0-9_-]{8,}")
_GHP_RE = re.compile(r"\bghp_[A-Za-z0-9]{8,}")
_BEARER_RE = re.compile(r"\b(Bearer\s+)([A-Za-z0-9._-]{8,})")

# URL 查询串：参数名不分大小写；值到 & 或空白为止。
_QUERY_RE = re.compile(
    r"([?&](?:token|key|secret|password|api_key)=)([^&\s]+)", re.IGNORECASE
)


def _mask(secret: str) -> str:
    """单段凭据的掩码形态：保留前 4 后 2，中间 ***；长度 <= 8 全掩。"""
    if len(secret) <= 8:
        return _MASKED
    return f"{secret[:4]}{_MASKED}{secret[-2:]}"


def _mask_header(match: Match[str]) -> str:
    """Authorization: Bearer sk-xxx -> Authorization: Bearer sk-a***90；
    Cookie: session=xxx -> Cookie: sess***op（无 scheme 时整值掩码）。"""
    name, value = match.group(1), match.group(2)
    scheme = _SCHEME_RE.match(value)
    if scheme:
        return f"{name}: {scheme.group(1)} {_mask(scheme.group(2))}"
    return f"{name}: {_mask(value)}"


def _mask_bearer(match: Match[str]) -> str:
    """Bearer <token>（header 值之外的散落形态）-> Bearer xxx***yy。"""
    return f"{match.group(1)}{_mask(match.group(2))}"


def _mask_query(match: Match[str]) -> str:
    """?token=<value> -> ?token=xxx***yy（?/参数名/= 原样保留）。"""
    return f"{match.group(1)}{_mask(match.group(2))}"


def mask_text(text: str) -> str:
    """对文本中的凭证形态做统一掩码，返回脱敏后的文本。

    应用顺序固定：先 header（整行值兜底），再各类散落 token，最后 URL 查询串；
    先掩出的产物含 * 不会命中后续模式，因此不重复掩码。
    """
    text = _HEADER_RE.sub(_mask_header, text)
    text = _JWT_RE.sub(lambda m: _mask(m.group(0)), text)
    text = _PREFIXED_RE.sub(lambda m: _mask(m.group(0)), text)
    text = _GHP_RE.sub(lambda m: _mask(m.group(0)), text)
    text = _BEARER_RE.sub(_mask_bearer, text)
    text = _QUERY_RE.sub(_mask_query, text)
    return text
