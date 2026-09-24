"""事件结构（核心机制三：一事一记，业务动作自动上链）。

六类事件：领用 / 归还 / 携带运输 / 使用 / 维修 / 报废销毁，
统一结构：事件标识、整枪码或散件码、操作主体、事件类型、发生时间、
发生位置、采集设备标识、前序事件哈希、操作签名。
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict

from .common import ValidationError

EVENT_TYPES = ("checkout", "return", "transport", "use", "repair", "scrap")
# 扩展：制造赋码、状态变更等基础事件（作为链的起点/状态记录）
BASE_EVENT_TYPES = ("manufacture", "status_change", "alert", "permit")

ALL_EVENT_TYPES = EVENT_TYPES + BASE_EVENT_TYPES


@dataclass
class GunEvent:
    event_id: str
    gun_code: str            # 整枪码或散件码
    event_type: str
    actor: str               # 操作主体标识（人或单位）
    occurred_at: str         # 发生时间
    location: str            # 发生位置
    device_id: str           # 采集设备标识
    payload: dict = field(default_factory=dict)
    prev_hash: str = ""      # 前序事件哈希（同枪支内串联成哈希链）
    event_hash: str = ""     # 本事件哈希（计算时含 prev_hash）
    signatures: dict = field(default_factory=dict)  # signer_id -> sig（支持多签）
    source: str = "online"   # online / offline
    upload_at: str = ""      # 上链时间（离线事件与发生时间分离的双时间戳）
    time_flag: str = ""      # "verified" / "pending_verify"（时钟偏差标记）
    chain_tx: str = ""       # 上链后回填的交易标识

    def compute_hash(self, prev: str | None = None) -> str:
        from .common import hash_obj
        p = prev if prev is not None else self.prev_hash
        body = {
            "event_id": self.event_id,
            "gun_code": self.gun_code,
            "event_type": self.event_type,
            "actor": self.actor,
            "occurred_at": self.occurred_at,
            "location": self.location,
            "device_id": self.device_id,
            "payload": self.payload,
            "prev_hash": p,
            "source": self.source,
            "upload_at": self.upload_at,
        }
        return hash_obj(body)

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(d: dict) -> "GunEvent":
        return GunEvent(**d)

    def validate(self) -> None:
        if self.event_type not in ALL_EVENT_TYPES:
            raise ValidationError(f"未知事件类型: {self.event_type}")
        if not self.gun_code:
            raise ValidationError("事件必须关联枪支码")
        if not self.signatures:
            raise ValidationError("事件必须携带操作签名")


def build_event(*, event_id: str, gun_code: str, event_type: str, actor: str,
                occurred_at: str, location: str, device_id: str,
                payload: dict | None = None, prev_hash: str = "",
                source: str = "online", upload_at: str = "",
                time_flag: str = "", signer_ids: list[str] | None = None) -> GunEvent:
    ev = GunEvent(
        event_id=event_id, gun_code=gun_code, event_type=event_type, actor=actor,
        occurred_at=occurred_at, location=location, device_id=device_id,
        payload=payload or {}, prev_hash=prev_hash, source=source,
        upload_at=upload_at, time_flag=time_flag,
        signatures={sid: "" for sid in (signer_ids or [])},
    )
    ev.validate()
    ev.event_hash = ev.compute_hash()
    return ev


def verify_chain(events: list[GunEvent]) -> tuple[bool, str]:
    """校验同一对象的事件哈希链：顺序、前序哈希、内容哈希。"""
    prev = ""
    for i, ev in enumerate(events):
        if ev.prev_hash != prev:
            return False, f"第{i + 1}条事件前序哈希断裂（期望 {prev[:12]}…，实际 {ev.prev_hash[:12]}…）"
        if ev.compute_hash() != ev.event_hash:
            return False, f"第{i + 1}条事件内容被篡改（{ev.event_id}）"
        prev = ev.event_hash
    return True, f"哈希链完整，共 {len(events)} 条"
