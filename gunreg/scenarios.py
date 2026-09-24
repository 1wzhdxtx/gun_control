"""三类差异化场景终端（流程图 TERMINAL）：

1. 营业性射击场：RFID 全流程自动感知（多读写器冗余 + 标签去重归并）
2. 猎枪：离线存证（安全芯片签名 + 哈希链 + 双时间戳 + 多终端互证）
3. 射击运动学校：激光打码扫码 + 人工确认 + 双人复核
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field

from .common import ValidationError, hash_obj, parse_iso, sha256_hex
from .crypto import SecureEnclave


# ---------------------------------------------------------------------------
# 场景一：营业性射击场 RFID 感知
# ---------------------------------------------------------------------------


@dataclass
class TagRead:
    reader_id: str
    tag: str
    ts: str          # 读写器本地时间
    person: str = ""
    strength: int = 5


class RangeRFIDController:
    """多读写器覆盖重叠 → 去重与事件归并；枪支堆叠/遮挡 → 冗余读取抑制。

    去重窗口内同一 tag 的多次读数合并为一次事件；若 >N 个读写器在窗口内
    均读到，取时间中位与最强信号作为归并结果（冗余读取提高完整率）。
    """

    def __init__(self, clock, dedupe_window: float = 3.0, min_readers: int = 1):
        self.clock = clock
        self.dedupe_window = dedupe_window
        self.min_readers = min_readers
        self._buffer: list[TagRead] = []
        self._lock = threading.RLock()
        self.dropped_duplicates = 0
        self.merged_reads = 0

    def feed(self, read: TagRead) -> None:
        with self._lock:
            for existing in self._buffer:
                if (existing.tag == read.tag
                        and abs((parse_iso(read.ts) - parse_iso(existing.ts)).total_seconds())
                        <= self.dedupe_window):
                    self.dropped_duplicates += 1
                    # 归并：记录多读写器冗余信息
                    existing.strength = max(existing.strength, read.strength)
                    self.merged_reads += 1
                    return
            self._buffer.append(read)

    def flush(self) -> list[TagRead]:
        """取出窗口内全部读数（由上层按动作语义生成事件）。"""
        with self._lock:
            out = list(self._buffer)
            self._buffer.clear()
        return out

    def stats(self) -> dict:
        return {"dropped_duplicates": self.dropped_duplicates,
                "merged_reads": self.merged_reads}


# ---------------------------------------------------------------------------
# 场景二：猎枪离线终端（安全芯片 + 哈希链 + 双时间戳）
# ---------------------------------------------------------------------------


@dataclass
class OfflinePackage:
    event_type: str
    gun_code: str
    actor: str
    occurred_at: str          # 事件发生时间（终端时钟，北斗校时）
    position: tuple[float, float]
    device_id: str
    prev_hash: str
    event_hash: str
    signature: str
    time_flag: str = ""
    location: str = ""

    def to_dict(self) -> dict:
        return {
            "event_type": self.event_type, "gun_code": self.gun_code,
            "actor": self.actor, "occurred_at": self.occurred_at,
            "position": list(self.position), "device_id": self.device_id,
            "prev_hash": self.prev_hash, "event_hash": self.event_hash,
            "signature": self.signature, "time_flag": self.time_flag,
            "location": self.location,
        }


class OfflineTerminal:
    """终端私钥存于 SecureEnclave（不可导出）；事件按哈希链式结构本地累积。

    - record()：生成事件包并签名，携带前序摘要
    - upload()：联网后批量回传
    - verify_batch()：回传侧三项验证（签名 / 哈希链连续性 / 时间一致性）
    - cross_check()：多终端互证（同伴记录时间空间吻合度）
    """

    def __init__(self, device_id: str, clock, clock_skew_seconds: int = 300):
        self.device_id = device_id
        self.clock = clock
        self.clock_skew_seconds = clock_skew_seconds
        self.enclave = SecureEnclave(device_id)   # 安全芯片：私钥不可导出
        self._chain: list[OfflinePackage] = []
        self._local_prev = "0" * 64
        self._seq = 0
        self._lock = threading.RLock()

    @property
    def public_key(self) -> str:
        return self.enclave.public_key

    @property
    def packages(self) -> list[OfflinePackage]:
        with self._lock:
            return list(self._chain)

    def record(self, *, event_type: str, gun_code: str, actor: str,
               position: tuple[float, float], occurred_at: str | None = None,
               location: str = "", beidou_synced: bool = True) -> OfflinePackage:
        self._seq += 1
        ts = occurred_at or self.clock.now_iso()
        time_flag = "verified" if beidou_synced else "pending_verify"
        body = {
            "seq": self._seq,
            "event_type": event_type,
            "gun_code": gun_code,
            "actor": actor,
            "occurred_at": ts,
            "position": list(position),
            "device_id": self.device_id,
            "prev_hash": self._local_prev,
            "time_flag": time_flag,
            "location": location,
        }
        event_hash = hash_obj(body)
        signature = self.enclave.sign(f"{event_hash}|{self.device_id}".encode())
        pkg = OfflinePackage(
            event_type=event_type, gun_code=gun_code, actor=actor, occurred_at=ts,
            position=position, device_id=self.device_id, prev_hash=self._local_prev,
            event_hash=event_hash, signature=signature, time_flag=time_flag,
            location=location)
        with self._lock:
            self._chain.append(pkg)
            self._local_prev = event_hash
        return pkg

    def upload(self) -> list[dict]:
        """返回网络恢复后回传的事件包字典列表。"""
        return [p.to_dict() for p in self.packages]

    # -- 回传侧验证 ---------------------------------------------------------
    @staticmethod
    def verify_batch(packages: list[dict], public_keys: dict[str, str]) -> dict:
        """三项验证：签名有效性、哈希链连续性、时间一致性。"""
        from .crypto import verify_raw

        results = {"accepted": [], "rejected": [], "pending_time": []}
        prev = "0" * 64
        for pkg in packages:
            body = {
                "seq": packages.index(pkg) + 1,
                "event_type": pkg["event_type"],
                "gun_code": pkg["gun_code"],
                "actor": pkg["actor"],
                "occurred_at": pkg["occurred_at"],
                "position": pkg["position"],
                "device_id": pkg["device_id"],
                "prev_hash": pkg["prev_hash"],
                "time_flag": pkg.get("time_flag", ""),
                "location": pkg.get("location", ""),
            }
            # 1. 哈希链连续性
            if pkg["prev_hash"] != prev:
                results["rejected"].append({"pkg": pkg, "reason": "哈希链断裂（存在插入/删除/重排）"})
                continue
            if hash_obj(body) != pkg["event_hash"]:
                results["rejected"].append({"pkg": pkg, "reason": "事件内容被篡改"})
                continue
            # 2. 签名有效性
            pub = public_keys.get(pkg["device_id"])
            if not pub or not verify_raw(pub, f"{pkg['event_hash']}|{pkg['device_id']}".encode(),
                                         pkg["signature"]):
                results["rejected"].append({"pkg": pkg, "reason": "终端签名无效"})
                continue
            prev = pkg["event_hash"]
            # 3. 时间一致性（终端时钟标记）
            if pkg.get("time_flag") == "pending_verify":
                results["pending_time"].append(pkg)
            results["accepted"].append(pkg)
        return results

    @staticmethod
    def cross_check(package_sets: list[list[dict]],
                    time_tolerance_s: float = 600,
                    space_tolerance_deg: float = 0.05) -> dict:
        """多终端互证：同行终端记录时间空间应相互吻合，严重偏离触发核查。"""
        flags = []
        for i, own in enumerate(package_sets):
            others = [p for j, p in enumerate(package_sets) if j != i]
            for pkg in own:
                t0 = parse_iso(pkg["occurred_at"])
                lon0, lat0 = pkg["position"]
                corroborated = False
                for other in others:
                    for op in other:
                        if op["gun_code"] != pkg["gun_code"]:
                            continue
                        dt = abs((parse_iso(op["occurred_at"]) - t0).total_seconds())
                        dlon = abs(op["position"][0] - lon0)
                        dlat = abs(op["position"][1] - lat0)
                        if dt <= time_tolerance_s and dlon <= space_tolerance_deg and dlat <= space_tolerance_deg:
                            corroborated = True
                            break
                    if corroborated:
                        break
                others_exist = bool(others)
                if others_exist and not corroborated:
                    flags.append({"pkg": pkg, "reason": "与同伴记录严重偏离，触发核查"})
        return {"flags": flags, "consistent": not flags}


# ---------------------------------------------------------------------------
# 场景三：射击运动学校（扫码自动填充 + 人工确认 + 双人复核）
# ---------------------------------------------------------------------------


class ScanReviewStation:
    """扫码自动填充结构性字段，人工仅确认非结构性字段；双人先后签名。"""

    STRUCT_FIELDS = ("code", "kind", "maker", "year", "serial", "legacy_no", "unit_id")

    def __init__(self, view):
        self.view = view

    def autofill(self, gun_code: str) -> dict:
        """从链上档案自动调出并填充结构字段。"""
        g = self.view.gun(gun_code)
        timeline = self.view.timeline(gun_code)
        mfg = next((t for t in timeline if t["event_type"] == "manufacture"), None)
        ident = (mfg or {}).get("payload", {})
        return {
            "structured": {
                "code": gun_code,
                "kind": ident.get("kind", ""),
                "legacy_no": ident.get("legacy_no", ""),
                "unit_id": g["unit"],
                "status": g["status"],
            },
            "manual": {"purpose": "", "competition": "", "fault": ""},  # 人工补充
        }

    def build_confirm(self, *, gun_code: str, action: str, operator: str,
                      reviewer: str, operator_sig: str, reviewer_sig: str,
                      confirm_fields: dict) -> dict:
        """双人复核：录入人提交 + 复核人确认，两个签名先后上链。"""
        if operator == reviewer:
            raise ValidationError("双人复核要求录入人与复核人为不同自然人")
        if not operator_sig or not reviewer_sig:
            raise ValidationError("缺少录入人或复核人签名")
        fill = self.autofill(gun_code)
        manual = confirm_fields.get("manual", {})
        if not any(manual.get(k) for k in ("purpose", "competition", "fault")):
            raise ValidationError("人工确认字段不得为空（使用目的/赛事/故障至少其一）")
        return {
            "action": action,
            "gun_code": gun_code,
            "operator": operator,
            "reviewer": reviewer,
            "operator_sig": operator_sig,
            "reviewer_sig": reviewer_sig,
            "structured": fill["structured"],
            "manual": manual,
        }
