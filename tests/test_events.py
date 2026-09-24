"""事件哈希链：一事一记、顺序不可篡改、入侵检测。"""
import sys
sys.path.insert(0, ".")

from gunreg.common import gen_id
from gunreg.events import build_event, verify_chain


def _mk(seq: int, gun: str = "G1", prev: str = "") -> "GunEvent":
    return build_event(
        event_id=f"evt-{seq}", gun_code=gun, event_type="checkout" if seq % 2 else "return",
        actor=f"u{seq}", occurred_at=f"2026-01-0{1 + seq % 9}T10:00:00+00:00",
        location="shooting-range", device_id="reader-01",
        prev_hash=prev, signer_ids=["u1"],
    )


class TestHashChain:
    def test_chain_verify_ok(self):
        events = [_mk(1), _mk(2), _mk(3)]
        prev = ""
        for ev in events:
            ev.prev_hash = prev
            ev.event_hash = ev.compute_hash(prev)
            prev = ev.event_hash
        ok, msg = verify_chain(events)
        assert ok, msg

    def test_insert_event_breaks_chain(self):
        """插入事件 → 后续事件前序哈希不再匹配。"""
        a = _mk(1)
        a.event_hash = a.compute_hash()
        b = _mk(2, prev=a.event_hash)
        b.event_hash = b.compute_hash(a.event_hash)
        forged = _mk(999, prev=a.event_hash)          # 插入伪造事件
        forged.event_hash = forged.compute_hash(a.event_hash)
        c = _mk(3, prev=forged.event_hash)            # 因插入而被迫改动 b→换链
        c.event_hash = c.compute_hash(forged.event_hash)
        # b 与 c 之间断链：c.prev == forged.hash，但 b 仍记录其后继应为 c
        chain = [a, b, forged, c]
        ok, msg = verify_chain(chain)
        # b.event_hash != forged.prev → 链断裂
        assert not ok
        assert "断裂" in msg or "篡改" in msg

    def test_content_tamper_detected(self):
        a = _mk(1)
        a.event_hash = a.compute_hash()
        a.payload["holder"] = "evil"   # 篡改后未重算哈希
        ok, msg = verify_chain([a])
        assert not ok
        assert "篡改" in msg

    def test_reorder_detected(self):
        a, b = _mk(1), _mk(2)
        a.event_hash = a.compute_hash()
        b.event_hash = b.compute_hash(a.event_hash)
        ok, msg = verify_chain([b, a])  # 调换顺序
        assert not ok