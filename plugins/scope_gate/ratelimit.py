"""按主机限速。持久化到 SQLite，重启不清零。

为什么必须持久化：Agent 会重启（cron、崩溃恢复、profile 切换）。如果计数器只在
内存里，一次重启就等于把"最多 2000 次请求"的承诺重置，对目标是不负责的。

实现是令牌桶 + 累计上限双约束：
  - 令牌桶管瞬时速率（rps / burst），防止把目标打挂
  - 累计上限管总量（per_host / total），防止长时间低速骚扰

并发：Hermes 单批最多 8 个工具线程，全部会走这里，因此用 `BEGIN IMMEDIATE`
做写锁，读改写在一个事务里完成，避免竞态导致超发。
"""

from __future__ import annotations

import sqlite3
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

_SCHEMA = """
CREATE TABLE IF NOT EXISTS buckets (
    key         TEXT PRIMARY KEY,
    tokens      REAL    NOT NULL,
    updated_at  REAL    NOT NULL,
    total       INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS counters (
    key   TEXT PRIMARY KEY,
    value INTEGER NOT NULL
);
"""


@dataclass(frozen=True)
class RateVerdict:
    allowed: bool
    code: str = ""
    detail: str = ""
    remaining_total: int = 0


class RateLimiter:
    """令牌桶限速器。线程安全；clock 可注入以便测试。"""

    def __init__(self, db_path: str | Path, *, clock=time.monotonic,
                 wall_clock=time.time):
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._clock = clock
        self._wall = wall_clock
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False,
                                     isolation_level=None, timeout=10.0)
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA busy_timeout=10000")
            self._conn.executescript(_SCHEMA)

    # -- 内部 ---------------------------------------------------------------

    def _get_counter(self, key: str) -> int:
        row = self._conn.execute("SELECT value FROM counters WHERE key=?", (key,)).fetchone()
        return int(row[0]) if row else 0

    def _bump_counter(self, key: str, delta: int = 1) -> int:
        self._conn.execute(
            "INSERT INTO counters(key,value) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=value+excluded.value",
            (key, delta),
        )
        return self._get_counter(key)

    # -- 主逻辑 -------------------------------------------------------------

    def check(self, *, engagement_id: str, host: str, rps: float, burst: int,
              max_per_host: int, max_total: int, cost: int = 1) -> RateVerdict:
        """尝试为一次请求扣配额。返回是否放行。"""
        key = f"{engagement_id}|{host}"
        now = self._clock()
        with self._lock:
            try:
                self._conn.execute("BEGIN IMMEDIATE")

                row = self._conn.execute(
                    "SELECT tokens, updated_at, total FROM buckets WHERE key=?", (key,)
                ).fetchone()
                if row:
                    tokens, updated, host_total = float(row[0]), float(row[1]), int(row[2])
                    # 按流逝时间补令牌，上限为 burst
                    tokens = min(float(burst), tokens + max(0.0, now - updated) * rps)
                else:
                    tokens, host_total = float(burst), 0

                global_total = self._get_counter(f"{engagement_id}|__total__")

                if host_total + cost > max_per_host:
                    self._conn.execute("COMMIT")
                    return RateVerdict(False, "rate_host_total",
                                       f"主机 {host} 已达累计上限 {max_per_host} 次")
                if global_total + cost > max_total:
                    self._conn.execute("COMMIT")
                    return RateVerdict(False, "rate_global_total",
                                       f"该作业累计请求已达上限 {max_total} 次")
                if tokens < cost:
                    need = (cost - tokens) / rps if rps > 0 else 0
                    self._conn.execute(
                        "UPDATE buckets SET tokens=?, updated_at=?, total=? WHERE key=?",
                        (tokens, now, host_total, key),
                    )
                    self._conn.execute("COMMIT")
                    return RateVerdict(
                        False, "rate_rps",
                        f"主机 {host} 速率超限（{rps:.1f} rps），请等待约 {need:.1f}s")

                tokens -= cost
                host_total += cost
                self._conn.execute(
                    "INSERT INTO buckets(key,tokens,updated_at,total) VALUES(?,?,?,?) "
                    "ON CONFLICT(key) DO UPDATE SET tokens=excluded.tokens, "
                    "updated_at=excluded.updated_at, total=excluded.total",
                    (key, tokens, now, host_total),
                )
                global_total = self._bump_counter(f"{engagement_id}|__total__", cost)
                self._conn.execute("COMMIT")
                return RateVerdict(True, remaining_total=max(0, max_total - global_total))
            except Exception:
                try:
                    self._conn.execute("ROLLBACK")
                except Exception:
                    pass
                # 限速状态异常时 fail closed：宁可拦下，也不要在计数失效的情况下继续打目标
                raise

    def snapshot(self, engagement_id: str, host: str) -> dict:
        with self._lock:
            row = self._conn.execute(
                "SELECT tokens, total FROM buckets WHERE key=?",
                (f"{engagement_id}|{host}",),
            ).fetchone()
            return {
                "tokens": float(row[0]) if row else None,
                "host_total": int(row[1]) if row else 0,
                "global_total": self._get_counter(f"{engagement_id}|__total__"),
            }

    def close(self) -> None:
        with self._lock:
            try:
                self._conn.close()
            except Exception:
                pass
