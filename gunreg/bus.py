"""异步处理区：Outbox 转发器 → 事件总线（路由/重试/死信）→ 链适配器。

流程：DB(Outbox) → RELAY → MQ → ADAPTER → 合约/账本 → 回执 → MQ → DOMAIN/QUERY
"""
from __future__ import annotations

import json
import threading
import time
import traceback
from dataclasses import dataclass, field
from typing import Callable

from .common import gen_id
from .store import OutboxStore

# ---------------------------------------------------------------------------
# 事件总线：分类路由、重试、死信
# ---------------------------------------------------------------------------


@dataclass
class Message:
    msg_id: str
    topic: str
    payload: dict
    attempt: int = 0
    created_at: str = ""


class EventBus:
    """线程安全的进程内事件总线，支持订阅、失败重试与死信。"""

    def __init__(self, clock, max_attempts: int = 3, backoff: float = 0.0):
        self.clock = clock
        self.max_attempts = max_attempts
        self.backoff = backoff
        self._subs: dict[str, list[tuple[str, Callable[[Message], None]]]] = {}
        self._dead: list[dict] = []
        self._lock = threading.RLock()
        self.delivered = 0
        self.failed = 0

    def subscribe(self, topic: str, name: str, handler: Callable[[Message], None]) -> None:
        with self._lock:
            self._subs.setdefault(topic, []).append((name, handler))

    def publish(self, topic: str, payload: dict) -> list[str]:
        """同步投递给所有订阅者；失败的消息按订阅者维度重试，耗尽进死信。"""
        msg = Message(msg_id=gen_id("msg"), topic=topic, payload=payload,
                      created_at=self.clock.now_iso())
        dead: list[str] = []
        with self._lock:
            subs = list(self._subs.get(topic, []))
        for name, handler in subs:
            attempt = 0
            while True:
                attempt += 1
                msg.attempt = attempt
                try:
                    handler(msg)
                    self.delivered += 1
                    break
                except Exception as exc:  # noqa: BLE001 —— 订阅者失败必须隔离
                    self.failed += 1
                    if attempt >= self.max_attempts:
                        with self._lock:
                            self._dead.append({
                                "topic": topic, "subscriber": name,
                                "payload": payload, "attempts": attempt,
                                "error": f"{exc}", "trace": traceback.format_exc()[-800:],
                                "ts": self.clock.now_iso(),
                            })
                        dead.append(name)
                        break
                    if self.backoff:
                        time.sleep(self.backoff * attempt)
        return dead

    def dead_letters(self) -> list[dict]:
        with self._lock:
            return list(self._dead)

    def replay_dead(self, index: int) -> bool:
        """死信重放（人工处置后）。"""
        with self._lock:
            if index >= len(self._dead):
                return False
            item = self._dead.pop(index)
        return not bool(self.publish(item["topic"], item["payload"]))


# ---------------------------------------------------------------------------
# Outbox 转发器
# ---------------------------------------------------------------------------


class OutboxRelay:
    """轮询 Outbox 表，投递到事件总线；发布成功后标记，失败重试并可入死信。"""

    def __init__(self, outbox: OutboxStore, bus: EventBus, clock, batch: int = 50):
        self.outbox = outbox
        self.bus = bus
        self.clock = clock
        self.batch = batch

    def tick(self) -> int:
        """执行一轮转发，返回成功条数。"""
        rows = self.outbox.pending(self.batch)
        ok = 0
        for row in rows:
            dead = self.bus.publish(row["topic"], row["payload"])
            if dead:
                self.outbox.mark_failed(row["id"], f"dead subscribers: {','.join(dead)}")
            else:
                self.outbox.mark_published(row["id"])
                ok += 1
        return ok

    def drain(self, max_rounds: int = 20) -> int:
        total = 0
        for _ in range(max_rounds):
            n = self.tick()
            total += n
            if n == 0:
                break
        return total


# ---------------------------------------------------------------------------
# 链适配器：提交、回执、幂等与对账
# ---------------------------------------------------------------------------


class ChainAdapter:
    """ADAPTER <-> CONTRACT/LEDGER：提交签名交易、接收确认回执、幂等去重、定期对账。"""

    def __init__(self, ledger, bus: EventBus, clock, kms=None):
        self.ledger = ledger
        self.bus = bus
        self.clock = clock
        self.kms = kms
        self._receipts: dict[str, dict] = {}   # client_tx_id -> receipt（幂等）
        self._submitted: dict[str, str] = {}   # client_tx_id -> tx_hash
        self.submitted_count = 0
        self.duplicate_count = 0

    def submit(self, client_tx_id: str, event: dict, signer_key: str | None = None) -> dict:
        """提交交易；同 client_tx_id 重复提交直接返回原回执（幂等）。"""
        if client_tx_id in self._receipts:
            self.duplicate_count += 1
            return {**self._receipts[client_tx_id], "duplicate": True}

        tx_body = {
            "client_tx_id": client_tx_id,
            "event": event,
            "member": (event.get("payload") or {}).get("unit", "") or None,
            "submitted_at": self.clock.now_iso(),
            "adapter": "adapter-01",
        }
        sig = ""
        if self.kms and signer_key:
            from .common import canonical
            sig = self.kms.sign(signer_key, canonical(tx_body).encode("utf-8"))
        tx = {**tx_body, "sig": sig}

        try:
            receipt = self.ledger.append_tx(tx)
        except Exception as exc:  # noqa: BLE001
            # 链路异常不缓存：允许后续重试重新提交
            return {"status": "rejected", "error": str(exc), "client_tx_id": client_tx_id}

        if receipt.get("status") != "committed":
            # 链上拒绝/软拒（未达成共识）：不得缓存为幂等成功，交由 Outbox 重试，
            # 否则「链拒绝被当成功」——Outbox 会被标 published 而链上根本没有这条交易。
            return receipt

        self._receipts[client_tx_id] = receipt
        self._submitted[client_tx_id] = receipt.get("tx_hash", "")
        self.submitted_count += 1
        # 确认回执 → MQ
        self.bus.publish("chain.receipt", {"receipt": receipt, "event": event})
        return receipt

    def reconcile(self) -> dict:
        """对账：本地已提交交易 vs 账本实际收录。"""
        missing, mismatched = [], []
        for ctx_id, tx_hash in self._submitted.items():
            found = self.ledger.find_tx(tx_hash)
            if not found:
                missing.append(ctx_id)
            elif found.get("client_tx_id") != ctx_id:
                mismatched.append({"client_tx_id": ctx_id, "onchain": found.get("client_tx_id")})
        return {
            "submitted": len(self._submitted),
            "onchain": len(self.ledger.txs()),
            "missing": missing,
            "mismatched": mismatched,
            "consistent": not missing and not mismatched,
        }
