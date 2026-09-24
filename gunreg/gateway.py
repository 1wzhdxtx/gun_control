"""接入隔离区（流程图 ACCESS）：

- WAF/API 网关：限流、请求检查
- Web BFF：服务端会话、页面数据聚合
- 设备网关 DG：验签、防重放、协议转换 → 标准化事件
"""
from __future__ import annotations

import json
import threading
from collections import defaultdict, deque
from dataclasses import dataclass

from .common import AuthenticationError, RateLimited, ReplayError, ValidationError, gen_nonce, parse_iso, sha256_hex
from .crypto import CA
from .events import build_event
from .iam import IdentityService
from .common import gen_id

# ---------------------------------------------------------------------------
# WAF：令牌桶限流 + 请求检查
# ---------------------------------------------------------------------------


@dataclass
class RouteLimit:
    rate: float       # 每秒令牌
    burst: int        # 桶容量


class TokenBucket:
    def __init__(self, clock):
        self.clock = clock
        self._buckets: dict[str, tuple[float, float]] = {}  # key -> (tokens, last_ts)
        self._lock = threading.Lock()

    def allow(self, key: str, limit: RouteLimit) -> bool:
        now = self.clock.monotonic()
        with self._lock:
            tokens, last = self._buckets.get(key, (float(limit.burst), now))
            tokens = min(limit.burst, tokens + (now - last) * limit.rate)
            if tokens < 1:
                self._buckets[key] = (tokens, now)
                return False
            self._buckets[key] = (tokens - 1, now)
            return True


class WAF:
    """限流 + 基本请求检查（大小、时间窗、必需字段）。"""

    DEFAULT_LIMITS = {
        "auth": RouteLimit(rate=1.0, burst=5),
        "api": RouteLimit(rate=20.0, burst=60),
        "device": RouteLimit(rate=50.0, burst=200),
    }

    def __init__(self, clock, max_body: int = 64 * 1024, skew_seconds: int = 300):
        self.clock = clock
        self.bucket = TokenBucket(clock)
        self.max_body = max_body
        self.skew_seconds = skew_seconds
        self.blocked = 0
        self.rejected = 0

    def check(self, route: str, client: str, body: bytes | str | dict,
              timestamp: str | None = None) -> None:
        limit = self.DEFAULT_LIMITS.get(route, self.DEFAULT_LIMITS["api"])
        if not self.bucket.allow(f"{route}:{client}", limit):
            self.blocked += 1
            raise RateLimited(f"接口 {route} 限流触发（客户端 {client}）")

        raw = body if isinstance(body, (bytes, str)) else json.dumps(body, ensure_ascii=False)
        if len(raw.encode("utf-8") if isinstance(raw, str) else raw) > self.max_body:
            self.rejected += 1
            raise ValidationError(f"请求体超过 {self.max_body} 字节限制")

        if timestamp:
            try:
                ts = parse_iso(timestamp)
            except ValueError:
                self.rejected += 1
                raise ValidationError("时间戳格式非法") from None
            delta = abs((self.clock.now() - ts).total_seconds())
            if delta > self.skew_seconds:
                self.rejected += 1
                raise ReplayError(f"请求时间偏差 {delta:.0f}s 超出 {self.skew_seconds}s 窗口")


# ---------------------------------------------------------------------------
# Web BFF：服务端会话 + 页面数据聚合
# ---------------------------------------------------------------------------


class BFF:
    def __init__(self, identity: IdentityService, waf: WAF, clock):
        self.identity = identity
        self.waf = waf
        self.clock = clock

    def login(self, client: str, user_id: str, password: str, totp_code: str,
              require_mfa: bool = True) -> dict:
        self.waf.check("auth", client, {"user": user_id}, self.clock.now_iso())
        ticket = self.identity.auth_step1(user_id, password)
        sess = self.identity.auth_step2(ticket, totp_code, require_mfa=require_mfa)
        return {"token": sess.token, "expires_at": sess.expires_at,
                "user": {"id": sess.subject.user_id, "name": sess.subject.name,
                         "role": sess.subject.role, "org": sess.subject.org}}

    def logout(self, token: str) -> None:
        self.identity.logout(token)

    def overview(self, token: str, view, domain: str = "") -> dict:
        """工作台聚合数据：台账摘要 + 统计 + 待办预警。"""
        self.identity.require(token, "ledger:query")
        led = view.ledger(unit=domain) if domain else view.ledger()
        by_status: dict[str, int] = {}
        for item in view.db.query("SELECT status, COUNT(*) c FROM gun_state GROUP BY status"):
            by_status[item["status"]] = item["c"]
        return {
            "ledger_summary": {"total": led["total"], "by_status": by_status},
            "recent_stats": view.stats()[-10:],
            "pending_alerts": len(view.db.query(
                "SELECT 1 FROM gun_state LIMIT 0")) and 0 or 0,  # 占位，领域侧提供
        }


# ---------------------------------------------------------------------------
# 设备网关：验签 + 防重放 + 协议转换
# ---------------------------------------------------------------------------


@dataclass
class DeviceProfile:
    device_id: str
    cert_id: str
    public_key: str
    protocol: str          # rfid / offline / scan
    org: str


class DeviceGateway:
    """DG：设备双向认证后的事件接入。

    防重放三重手段：时间窗（timestamp）、一次性随机数（nonce）、设备会话序号。
    协议转换：把设备私有报文转为标准化 GunEvent。
    """

    def __init__(self, ca: CA, clock, kms=None, window_seconds: int = 120):
        self.ca = ca
        self.clock = clock
        self.kms = kms
        self.window_seconds = window_seconds
        self._devices: dict[str, DeviceProfile] = {}
        self._nonce_seen: dict[str, float] = {}   # nonce -> 过期时间(monotonic)
        self._device_seq: dict[str, int] = {}     # 设备会话序号
        self._lock = threading.RLock()

    # -- 设备注册（双向认证基础） -------------------------------------------
    def register_device(self, device_id: str, protocol: str, org: str,
                        public_key: str = "") -> DeviceProfile:
        cert = self.ca.issue(subject=f"device:{device_id}", cert_type="device",
                             public_key=public_key or "dev-pub", days=365)
        prof = DeviceProfile(device_id=device_id, cert_id=cert.cert_id,
                             public_key=cert.public_key, protocol=protocol, org=org)
        self._devices[device_id] = prof
        return prof

    def _sweep_nonce(self) -> None:
        now = self.clock.monotonic()
        expired = [n for n, exp in self._nonce_seen.items() if exp < now]
        for n in expired:
            del self._nonce_seen[n]

    def verify_envelope(self, device_id: str, timestamp: str, nonce: str,
                        seq: int, signature: str, body: bytes) -> None:
        """验签 + 防重放 + 时间窗。

        签名覆盖「消息头 + 正文摘要」，防止篡改载荷后原样重放。
        """
        prof = self._devices.get(device_id)
        if not prof:
            raise AuthenticationError(f"设备未注册: {device_id}")
        # 设备证书真校验：吊销/过期/非本 CA 签发一律拒绝（此前 if False 直接跳过）
        cert = self.ca._issued.get(prof.cert_id)
        if cert is None:
            raise AuthenticationError(f"设备证书缺失: {device_id}")
        cert_ok, cert_msg = self.ca.verify(cert)
        if not cert_ok:
            raise AuthenticationError(f"设备证书无效: {cert_msg}")

        try:
            ts = parse_iso(timestamp)
        except ValueError:
            raise ValidationError("设备时间戳格式非法") from None
        if abs((self.clock.now() - ts).total_seconds()) > self.window_seconds:
            raise ReplayError(f"设备时间偏差超出 ±{self.window_seconds}s 窗口")

        with self._lock:
            self._sweep_nonce()
            if nonce in self._nonce_seen:
                raise ReplayError(f"重复的随机数 nonce={nonce[:8]}…")
            self._nonce_seen[nonce] = self.clock.monotonic() + self.window_seconds * 2
            last = self._device_seq.get(device_id, -1)
            if seq <= last:
                raise ReplayError(f"设备序号回退：{seq} <= {last}")
            self._device_seq[device_id] = seq

        if self.kms and prof.public_key and prof.public_key != "dev-pub":
            # 设备以自身密钥对信封签名（设备密钥注册在 KMS: device:<id>）。
            # 签名必须覆盖正文摘要：否则载荷被篡改后签名依然合法。
            digest = sha256_hex(body)
            envelope = f"{device_id}|{timestamp}|{nonce}|{seq}|{digest}".encode()
            if not self.kms.verify(f"device:{device_id}", envelope, signature):
                raise AuthenticationError("设备报文验签失败")

    def new_envelope(self, device_id: str, body: dict) -> dict:
        """（测试/模拟侧）构造合法防重放信封。"""
        ts = self.clock.now_iso()
        nonce = gen_nonce()
        seq = self._device_seq.get(device_id, -1) + 1
        raw_body = json.dumps(body, sort_keys=True).encode("utf-8")
        digest = sha256_hex(raw_body)
        envelope = f"{device_id}|{ts}|{nonce}|{seq}|{digest}".encode()
        sig = self.kms.sign(f"device:{device_id}", envelope) if self.kms else ""
        return {"device_id": device_id, "timestamp": ts, "nonce": nonce,
                "seq": seq, "signature": sig, "body": body}

    # -- 协议转换 -----------------------------------------------------------
    def ingest(self, envelope: dict) -> list[dict]:
        """设备私有报文 → 标准化事件指令列表。"""
        body = envelope.get("body") or {}
        self.verify_envelope(
            device_id=envelope["device_id"], timestamp=envelope["timestamp"],
            nonce=envelope["nonce"], seq=int(envelope["seq"]),
            signature=envelope.get("signature", ""),
            body=json.dumps(body, sort_keys=True).encode("utf-8"),
        )
        prof = self._devices[envelope["device_id"]]
        kind = body.get("protocol", prof.protocol)

        if kind == "rfid":
            # RFID 读数：标签 + 动作 + 读写器位置 → 领用/归还/使用事件
            action = body.get("action")
            type_map = {"out": "checkout", "in": "return", "use": "use"}
            if action not in type_map:
                raise ValidationError(f"未知 RFID 动作: {action}")
            return [{
                "kind": type_map[action],
                "gun_code": body.get("tag"),
                "actor": body.get("person", ""),
                "device_id": envelope["device_id"],
                "location": body.get("reader", ""),
                "occurred_at": body.get("ts", envelope["timestamp"]),
                "raw": body,
            }]

        if kind == "offline":
            # 离线事件包（猎枪终端回传）：已是标准结构，仅补充来源标记
            pkgs = body.get("packages") or []
            out = []
            for i, pkg in enumerate(pkgs):
                # 离线包结构 → 标准事件（contract_ctx 由离线记录携带）
                out.append({
                    "kind": pkg.get("event_type", "use"),
                    "gun_code": pkg.get("gun_code"),
                    "actor": pkg.get("actor", ""),
                    "device_id": pkg.get("device_id", envelope["device_id"]),
                    "location": pkg.get("location", ""),
                    "occurred_at": pkg.get("occurred_at", envelope["timestamp"]),
                    "upload_at": envelope["timestamp"],
                    "source": "offline",
                    "time_flag": pkg.get("time_flag", ""),
                    "position": pkg.get("position", [0.0, 0.0]),
                    "contract_ctx": {"offline": True, "position": pkg.get("position")},
                    "payload": pkg,
                    "raw": pkg,
                    "index": i,
                })
            return out

        if kind == "scan":
            # 扫码复核：枪身二维码 + 人工确认字段 + 双人签名
            return [{
                "kind": body.get("action", "use"),
                "gun_code": body.get("tag"),
                "actor": body.get("operator", ""),
                "device_id": envelope["device_id"],
                "location": body.get("station", ""),
                "occurred_at": body.get("ts", envelope["timestamp"]),
                "confirm": body.get("confirm", {}),
                "signers": body.get("signers", []),
                "raw": body,
            }]

        raise ValidationError(f"未知设备协议: {kind}")


def make_event(cmd: dict, payload_extra: dict | None = None) -> "object":
    """标准化指令 → GunEvent（由 scenarios 层调用并完成签名）。"""
    payload = dict(cmd.get("raw") or {})
    if payload_extra:
        payload.update(payload_extra)
    return build_event(
        event_id=gen_id("evt"),
        gun_code=cmd["gun_code"],
        event_type=cmd["kind"],
        actor=cmd.get("actor") or "unknown",
        occurred_at=cmd["occurred_at"],
        location=cmd.get("location", ""),
        device_id=cmd.get("device_id", ""),
        payload={"unit": cmd.get("org", ""), **payload, **(cmd.get("payload") or {})},
        source=cmd.get("source", "online"),
        upload_at=cmd.get("upload_at", ""),
        time_flag=cmd.get("time_flag", ""),
        signer_ids=[cmd["device_id"]],
    )
