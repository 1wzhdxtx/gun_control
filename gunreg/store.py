"""链下数据区：业务数据库（模块私有）、Outbox、查询投影（可重建）。

按流程图 DATA 分区：
- DB   ：领域核心的私有仓储 + Outbox 表（与业务写入同一事务）
- VIEW ：查询投影，可从链上事件全量重建
- LOCAL：本地加密原件（见 crypto.LocalVault）
"""
from __future__ import annotations

import json
import sqlite3
import threading
from typing import Any, Iterable

from .common import NotFoundError


class Database:
    """模块私有数据库（每模块独立连接，实现按模块隔离）。"""

    def __init__(self, path: str = ":memory:", tables_sql: Iterable[str] = ()):
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        with self._lock:
            for sql in tables_sql:
                self._conn.executescript(sql)
            self._conn.commit()

    def execute(self, sql: str, params: tuple = ()) -> None:
        with self._lock:
            self._conn.execute(sql, params)
            self._conn.commit()

    def executescript(self, script: str) -> None:
        with self._lock:
            self._conn.executescript(script)
            self._conn.commit()

    def query(self, sql: str, params: tuple = ()) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    def one(self, sql: str, params: tuple = ()) -> dict | None:
        rows = self.query(sql, params)
        return rows[0] if rows else None

    def transaction(self):
        """上下文管理器：业务写入与 Outbox 写入同事务（Transactional Outbox）。"""
        return _Txn(self)

    def close(self) -> None:
        with self._lock:
            self._conn.close()


class _Txn:
    def __init__(self, db: Database):
        self.db = db

    def __enter__(self):
        self.db._lock.acquire()
        return self.db._conn

    def __exit__(self, exc_type, exc, tb):
        try:
            if exc_type is None:
                self.db._conn.commit()
            else:
                self.db._conn.rollback()
        finally:
            self.db._lock.release()
        return False


# ---------------------------------------------------------------------------
# Outbox 表结构
# ---------------------------------------------------------------------------

OUTBOX_SCHEMA = """
CREATE TABLE IF NOT EXISTS outbox (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    topic       TEXT NOT NULL,
    payload     TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'pending',   -- pending / published / failed
    attempts    INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL,
    published_at TEXT
);
CREATE TABLE IF NOT EXISTS outbox_dead (
    id          INTEGER PRIMARY KEY,
    topic       TEXT NOT NULL,
    payload     TEXT NOT NULL,
    attempts    INTEGER NOT NULL,
    error       TEXT,
    created_at  TEXT NOT NULL
);
"""


class OutboxStore:
    def __init__(self, db: Database, clock):
        self.db = db
        self.clock = clock
        db.executescript(OUTBOX_SCHEMA)

    def enqueue(self, conn, topic: str, payload: dict) -> int:
        """必须在业务事务内调用（conn 来自 Database.transaction()）。"""
        cur = conn.execute(
            "INSERT INTO outbox (topic, payload, status, attempts, created_at) VALUES (?,?,?,?,?)",
            (topic, json.dumps(payload, ensure_ascii=False), "pending", 0, self.clock.now_iso()),
        )
        return int(cur.lastrowid)

    def pending(self, limit: int = 100) -> list[dict]:
        rows = self.db.query(
            "SELECT * FROM outbox WHERE status='pending' ORDER BY id LIMIT ?", (limit,)
        )
        for r in rows:
            r["payload"] = json.loads(r["payload"])
        return rows

    def mark_published(self, row_id: int) -> None:
        self.db.execute(
            "UPDATE outbox SET status='published', published_at=? WHERE id=?",
            (self.clock.now_iso(), row_id),
        )

    def mark_failed(self, row_id: int, error: str, max_attempts: int = 5) -> None:
        row = self.db.one("SELECT * FROM outbox WHERE id=?", (row_id,))
        attempts = (row["attempts"] if row else 0) + 1
        if attempts >= max_attempts:
            # 死信：转入 outbox_dead
            self.db.execute(
                "INSERT INTO outbox_dead (id, topic, payload, attempts, error, created_at) "
                "VALUES (?,?,?,?,?,?)",
                (row_id, row["topic"], row["payload"], attempts, error, self.clock.now_iso()),
            )
            self.db.execute("DELETE FROM outbox WHERE id=?", (row_id,))
        else:
            self.db.execute("UPDATE outbox SET status='pending', attempts=? WHERE id=?",
                            (attempts, row_id))

    def stats(self) -> dict:
        return {
            "pending": self.db.one("SELECT COUNT(*) c FROM outbox WHERE status='pending'")["c"],
            "published": self.db.one("SELECT COUNT(*) c FROM outbox WHERE status='published'")["c"],
            "dead": self.db.one("SELECT COUNT(*) c FROM outbox_dead")["c"],
        }


# ---------------------------------------------------------------------------
# 查询投影（VIEW）：可从链上事件重建
# ---------------------------------------------------------------------------

VIEW_SCHEMA = """
CREATE TABLE IF NOT EXISTS gun_state (
    gun_code   TEXT PRIMARY KEY,
    status     TEXT NOT NULL,
    holder     TEXT DEFAULT '',
    unit       TEXT DEFAULT '',
    last_event TEXT DEFAULT '',
    last_ts    TEXT DEFAULT '',
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS timeline (
    event_id   TEXT PRIMARY KEY,
    gun_code   TEXT NOT NULL,
    event_type TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    actor      TEXT NOT NULL,
    device_id  TEXT NOT NULL,
    event_hash TEXT NOT NULL,
    prev_hash  TEXT NOT NULL,
    payload    TEXT NOT NULL,
    chain_tx   TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_timeline_gun ON timeline (gun_code, occurred_at);
CREATE TABLE IF NOT EXISTS stats_daily (
    day TEXT NOT NULL, event_type TEXT NOT NULL, unit TEXT NOT NULL,
    cnt INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (day, event_type, unit)
);
CREATE TABLE IF NOT EXISTS evidence_cache (
    gun_code TEXT NOT NULL, event_id TEXT NOT NULL,
    event_hash TEXT NOT NULL, chain_tx TEXT NOT NULL,
    PRIMARY KEY (gun_code, event_id)
);
"""


class QueryView:
    """查询与取证（流程图 QUERY）的物化视图。"""

    def __init__(self, clock, path: str = ":memory:"):
        self.clock = clock
        self.db = Database(path, [VIEW_SCHEMA])

    # -- 增量更新 -----------------------------------------------------------
    def apply_event(self, ev: dict) -> None:
        now = self.clock.now_iso()
        self.db.execute(
            "INSERT OR REPLACE INTO timeline (event_id, gun_code, event_type, occurred_at,"
            " actor, device_id, event_hash, prev_hash, payload, chain_tx)"
            " VALUES (?,?,?,?,?,?,?,?,?,?)",
            (ev["event_id"], ev["gun_code"], ev["event_type"], ev["occurred_at"],
             ev["actor"], ev["device_id"], ev["event_hash"], ev["prev_hash"],
             json.dumps(ev.get("payload", {}), ensure_ascii=False), ev.get("chain_tx", "")),
        )
        payload = ev.get("payload", {})
        et = ev["event_type"]
        holder = payload.get("holder", "")
        unit = payload.get("unit", "")
        # 状态转移投影：仅状态事件更新 status；预警/许可等事件保留既有状态，
        # 否则会污染在途/在用枪支的视图（此前 alert 事件把 in_use 刷回 in_stock）。
        new_status: str | None = None
        if et in ("manufacture", "checkout", "return", "repair", "status_change",
                  "transport", "scrap"):
            if et == "status_change":
                new_status = payload.get("status")
            elif et == "transport":
                new_status = ("in_stock" if payload.get("stage") == "arrive_verify"
                              else "in_transit")
            elif et == "scrap":
                # 报废分期：payload.status 已刻画 pending_destroy / sealed
                new_status = payload.get("status", "pending_destroy")
            else:
                new_status = {"manufacture": "in_stock", "checkout": "in_use",
                              "return": "in_stock", "repair": "repairing"}[et]
        if et == "return":
            # 归还必须无条件清空持有者（含新行 INSERT 的 sentinel 转换），
            # 避免视图里 holder 残留为已还枪的原领用人。
            self.db.execute(
                "INSERT INTO gun_state (gun_code, status, holder, unit, last_event, last_ts, updated_at)"
                " VALUES (?, 'in_stock', '', ?, ?, ?, ?)"
                " ON CONFLICT(gun_code) DO UPDATE SET status='in_stock', holder='',"
                " unit=CASE WHEN excluded.unit='' THEN gun_state.unit ELSE excluded.unit END,"
                " last_event=excluded.last_event, last_ts=excluded.last_ts, updated_at=excluded.updated_at",
                (ev["gun_code"], unit, ev["event_id"], ev["occurred_at"], now),
            )
        elif new_status is None:
            self.db.execute(
                "INSERT INTO gun_state (gun_code, status, holder, unit, last_event, last_ts, updated_at)"
                " VALUES (?, COALESCE((SELECT status FROM gun_state WHERE gun_code=?), 'in_stock'),"
                " ?, ?, ?, ?, ?)"
                " ON CONFLICT(gun_code) DO UPDATE SET"
                " holder=CASE WHEN excluded.holder='' THEN gun_state.holder ELSE excluded.holder END,"
                " unit=CASE WHEN excluded.unit='' THEN gun_state.unit ELSE excluded.unit END,"
                " last_event=excluded.last_event, last_ts=excluded.last_ts, updated_at=excluded.updated_at",
                (ev["gun_code"], ev["gun_code"], holder, unit,
                 ev["event_id"], ev["occurred_at"], now),
            )
        else:
            self.db.execute(
                "INSERT INTO gun_state (gun_code, status, holder, unit, last_event, last_ts, updated_at)"
                " VALUES (?,?,?,?,?,?,?)"
                " ON CONFLICT(gun_code) DO UPDATE SET status=excluded.status,"
                " holder=CASE WHEN excluded.holder='' THEN gun_state.holder ELSE excluded.holder END,"
                " unit=CASE WHEN excluded.unit='' THEN gun_state.unit ELSE excluded.unit END,"
                " last_event=excluded.last_event, last_ts=excluded.last_ts, updated_at=excluded.updated_at",
                (ev["gun_code"], new_status, holder, unit,
                 ev["event_id"], ev["occurred_at"], now),
            )
        day = ev["occurred_at"][:10]
        self.db.execute(
            "INSERT INTO stats_daily (day, event_type, unit, cnt) VALUES (?,?,?,1)"
            " ON CONFLICT(day, event_type, unit) DO UPDATE SET cnt=cnt+1",
            (day, ev["event_type"], unit or "unknown"),
        )
        if ev.get("chain_tx"):
            self.db.execute(
                "INSERT OR REPLACE INTO evidence_cache (gun_code, event_id, event_hash, chain_tx)"
                " VALUES (?,?,?,?)",
                (ev["gun_code"], ev["event_id"], ev["event_hash"], ev["chain_tx"]),
            )

    # -- 重建：全部视图可由链上事件重放 -------------------------------------
    def reset(self) -> None:
        for t in ("gun_state", "timeline", "stats_daily", "evidence_cache"):
            self.db.execute(f"DELETE FROM {t}")

    def rebuild(self, all_events: Iterable[dict]) -> int:
        """从链上事件全量重建台账与统计（视图是派生的、可丢弃的）。"""
        self.reset()
        n = 0
        for ev in all_events:
            self.apply_event(ev)
            n += 1
        return n

    # -- 查询接口 -----------------------------------------------------------
    def gun(self, gun_code: str) -> dict:
        row = self.db.one("SELECT * FROM gun_state WHERE gun_code=?", (gun_code,))
        if not row:
            raise NotFoundError(f"枪支不存在: {gun_code}")
        return row

    def timeline(self, gun_code: str) -> list[dict]:
        rows = self.db.query(
            "SELECT * FROM timeline WHERE gun_code=? ORDER BY rowid", (gun_code,))
        for r in rows:
            r["payload"] = json.loads(r["payload"])
        return rows

    def stats(self, day_from: str = "", day_to: str = "") -> list[dict]:
        sql = "SELECT * FROM stats_daily"
        params: tuple = ()
        if day_from or day_to:
            sql += " WHERE 1=1"
            if day_from:
                sql += " AND day>=?"
                params += (day_from,)
            if day_to:
                sql += " AND day<=?"
                params += (day_to,)
        return self.db.query(sql + " ORDER BY day", params)

    def ledger(self, unit: str = "", status: str = "", offset: int = 0, limit: int = 50) -> dict:
        sql, params = "SELECT * FROM gun_state WHERE 1=1", []
        if unit:
            sql += " AND unit=?"
            params.append(unit)
        if status:
            sql += " AND status=?"
            params.append(status)
        rows = self.db.query(sql + " ORDER BY gun_code LIMIT ? OFFSET ?",
                             tuple(params) + (limit, offset))
        cnt = self.db.one(
            "SELECT COUNT(*) c FROM gun_state WHERE 1=1"
            + (" AND unit=?" if unit else "") + (" AND status=?" if status else ""),
            tuple(params),
        )["c"]
        return {"items": rows, "total": cnt, "offset": offset, "limit": limit}
