"""mask_text 的测试（TASK-006 任务 3）：凭证掩码 + 两个渲染器的集成。

自包含，不依赖 conftest 的任何夹具；纯内存构造 Finding，
不碰网络/时钟/文件系统。
"""

from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from secops_report import Evidence, Finding, render_markdown, render_sarif  # noqa: E402
from secops_report.masking import mask_text  # noqa: E402

DISCOVERED_AT = datetime(2026, 11, 14, 10, 30, 0)

# RFC 7519 附录里的示例 JWT（三段式，第二段同样以 eyJ 开头）
JWT = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
       "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
       "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")


# ---- 1-4：三类模式的掩码 -----------------------------------------------------


def test_case1_authorization_bearer_masked():
    """用例 1：Authorization: Bearer sk-... -> token 被掩码，scheme 保留。"""
    out = mask_text("Authorization: Bearer sk-abcdef1234567890")
    assert "sk-abcdef1234567890" not in out, "token 原文不得出现在输出里"
    assert "Bearer" in out, "scheme 保留，只掩凭据"
    assert out == "Authorization: Bearer sk-a***90"


def test_case2_cookie_masked():
    """用例 2：Cookie 值无 scheme，整值掩码（保留前 4 后 2）。"""
    out = mask_text("Cookie: session=abcdefghijklmnop")
    assert "abcdefghijklmnop" not in out
    assert out == "Cookie: sess***op"


def test_case3_jwt_masked():
    """用例 3：三段式 JWT 整体掩码，原文任何一段都不得残留。"""
    out = mask_text(f"认证头泄露：{JWT}")
    assert JWT not in out
    assert "eyJhbGciOi" not in out and "eyJzdWIiOi" not in out
    assert "eyJh***5c" in out


def test_case4_query_string_masked():
    """用例 4：URL 查询串的 token 掩码，参数名与结构保留。"""
    out = mask_text("https://x.com/a?token=secretvalue123")
    assert "secretvalue123" not in out
    assert out == "https://x.com/a?token=secr***23"


# ---- 5：不误伤 ---------------------------------------------------------------


def test_case5_normal_text_untouched():
    """用例 5：普通 HTML/文本不含敏感模式 -> 原样通过。

    覆盖五类易误伤形态：普通 HTML、不含敏感名的 HTTP 头、提到敏感头名但
    没有冒号值的中文说明、Bearer 后不跟 token 的叙述、普通查询串。
    """
    samples = [
        "<html><body><h1>Welcome</h1><p>login at /user/login</p></body></html>",
        "GET /api/v1/users HTTP/1.1\nHost: app.example.com\nUser-Agent: nmap",
        "Set-Cookie 头缺失时不能断言会话固定防护",
        "使用 Bearer 认证的接口在响应里回显了完整凭证",
        "https://x.com/a?tab=results&page=2",
    ]
    for text in samples:
        assert mask_text(text) == text, f"不该被掩码：{text!r}"


# ---- 6：render_markdown / render_sarif 集成 ----------------------------------


def _finding_with_sensitive_evidence() -> Finding:
    return Finding(
        title="会话 Cookie 未设 HttpOnly",
        target="https://app.example.com/login",
        severity="medium",
        status="observed",
        discovered_at=DISCOVERED_AT,
        evidence=[Evidence(
            kind="http_pair",
            summary="响应头缺少 HttpOnly；Set-Cookie: session=abcdefghijklmnop",
            artifact="inline:Cookie: session=abcdefghijklmnop; Path=/",
        )],
    )


def test_case6_render_markdown_masks_evidence():
    """用例 6：集成——evidence 带敏感 header，报告输出无原文。"""
    md = render_markdown(
        [_finding_with_sensitive_evidence()], {"engagement_id": "ENG-MASK-001"}
    )
    assert "abcdefghijklmnop" not in md, "evidence 原文不得进报告"
    assert "sess***op" in md, "summary 里的 Cookie 值以掩码形态出现"
    # PoC/负对照等所有经 _evidence_text 的路径同源，无需逐处重复断言


def test_case6b_render_sarif_masks_free_text():
    """SARIF 同样处理：title/target 带凭证形态时输出无原文。"""
    finding = Finding(
        title="URL 泄露凭证 https://x.com/a?token=secretvalue123",
        target="https://app.example.com/a?token=secretvalue123",
        severity="high",
        status="observed",
        discovered_at=DISCOVERED_AT,
    )
    data = json.loads(render_sarif([finding]))
    result = data["runs"][0]["results"][0]
    assert "secretvalue123" not in json.dumps(data)
    assert "secr***23" in result["message"]["text"]
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] \
        == "https://app.example.com/a?token=secr***23"


# ---- 7：幂等性 ----------------------------------------------------------------


def test_case7_mask_text_is_idempotent():
    """已掩码文本再过一遍结果不变（渲染器重复调用无副作用）。"""
    once = mask_text("Authorization: Bearer sk-abcdef1234567890")
    assert mask_text(once) == once
