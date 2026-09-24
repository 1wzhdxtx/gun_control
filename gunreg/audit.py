"""追加式审计日志（流程图 SECURITY 层 AUDIT：追加审计、可验证）。

每条记录含前序哈希，形成审计哈希链；提供全链校验。
"""
from __future__ import annotations

import json
import threading

from .common import chain_hash

GENESIS = "0" * 64


class AuditLog:
    def __init__(self, clock):
        self.clock = clock
        self._records: list[dict] = []
        self._lock = threading.RLock()

    def append(self, actor: str, action: str, target: str, detail: dict | None = None, result: str = "ok") -> dict:
        with self._lock:
            prev = self._records[-1]["hash"] if self._records else GENESIS
            rec = {
                "seq": len(self._records) + 1,
                "ts": self.clock.now_iso(),
                "actor": actor,
                "action": action,
                "target": target,
                "detail": detail or {},
                "result": result,
                "prev": prev,
            }
            rec["hash"] = chain_hash(prev, {k: v for k, v in rec.items() if k != "hash"})
            self._records.append(rec)
            return rec

    def records(self, actor: str | None = None, action: str | None = None) -> list[dict]:
        out = self._records
        if actor:
            out = [r for r in out if r["actor"] == actor]
        if action:
            out = [r for r in out if r["action"] == action]
        return list(out)

    def verify(self) -> tuple[bool, str]:
        prev = GENESIS
        for r in self._records:
            if r["prev"] != prev:
                return False, f"seq={r['seq']} 前序哈希断裂"
            expect = chain_hash(prev, {k: v for k, v in r.items() if k != "hash"})
            if r["hash"] != expect:
                return False, f"seq={r['seq']} 记录被篡改"
            prev = r["hash"]
        return True, f"审计链完整，共 {len(self._records)} 条"

    def export(self) -> list[dict]:
        return json.loads(json.dumps(self._records, ensure_ascii=False))
