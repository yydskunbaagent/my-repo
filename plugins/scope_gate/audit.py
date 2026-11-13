"""决策审计：哈希链式 JSONL。

为什么用哈希链而不是普通日志：门禁本身是"信任根"之一，如果日志可以被悄悄改写，
"事后可复现"就不成立。每条记录带 `prev_hash`，任何删改都会让后续链断裂，
`verify_chain()` 能定位到第一条坏记录。

写入用 `O_APPEND` + 单写锁 + fsync，保证多线程（8 个工具 worker）下不交错。
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_GENESIS = "0" * 64


def _canonical(payload: Dict[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _hash(prev_hash: str, payload: Dict[str, Any]) -> str:
    return hashlib.sha256((prev_hash + _canonical(payload)).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    records: int
    first_bad_seq: Optional[int] = None
    detail: str = ""


class AuditLog:
    def __init__(self, path: str | os.PathLike[str], *, fsync: bool = True):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fsync = fsync
        self._lock = threading.RLock()
        self._seq, self._prev = self._recover_tail()

    # -- 启动时续接链尾，避免进程重启后重新从 genesis 开始 ---------------------

    def _recover_tail(self) -> Tuple[int, str]:
        if not self.path.exists():
            return 0, _GENESIS
        seq, prev = 0, _GENESIS
        with self.path.open("rb") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    # 断电可能造成半行：保留文件，但链从最后一条完整记录续
                    break
                seq = int(rec.get("seq", seq))
                h = rec.get("hash")
                if isinstance(h, str):
                    prev = h
        return seq, prev

    # -- 写入 ---------------------------------------------------------------

    def append(self, event: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            self._seq += 1
            body = {
                "seq": self._seq,
                "ts": datetime.now(timezone.utc).isoformat(),
                "event": event,
                **payload,
            }
            body["prev_hash"] = self._prev
            digest = _hash(self._prev, body)
            body["hash"] = digest
            line = _canonical(body) + "\n"

            fd = os.open(str(self.path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            try:
                os.write(fd, line.encode("utf-8"))
                if self._fsync:
                    os.fsync(fd)
            finally:
                os.close(fd)

            self._prev = digest
            return body

    # -- 校验 ---------------------------------------------------------------

    def verify_chain(self) -> VerifyResult:
        if not self.path.exists():
            return VerifyResult(True, 0, detail="日志尚未创建")
        prev = _GENESIS
        count = 0
        expected_seq = 1
        with self.path.open("rb") as fh:
            for raw in fh:
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    rec = json.loads(raw)
                except json.JSONDecodeError as e:
                    return VerifyResult(False, count, expected_seq, f"第 {expected_seq} 条无法解析: {e}")
                recorded_hash = rec.pop("hash", None)
                recorded_prev = rec.pop("prev_hash", None)
                if recorded_prev != prev:
                    return VerifyResult(
                        False, count, rec.get("seq"), "prev_hash 与上一条的 hash 不匹配（记录被增删或改写）")
                # append 时 prev_hash 参与哈希，校验前必须还原，否则永远对不上
                rec["prev_hash"] = recorded_prev
                if _hash(prev, rec) != recorded_hash:
                    return VerifyResult(False, count, rec.get("seq"), "内容与自身 hash 不符")
                prev = recorded_hash
                count += 1
                expected_seq = int(rec.get("seq", expected_seq)) + 1
        return VerifyResult(True, count, detail=f"链完整，共 {count} 条")
