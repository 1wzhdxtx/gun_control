"""通用工具：规范化 JSON、哈希、时钟、标识生成、异常体系。"""
from __future__ import annotations

import hashlib
import json
import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

# ---------------------------------------------------------------------------
# 异常体系
# ---------------------------------------------------------------------------


class GunRegError(Exception):
    """系统根异常。"""


class ValidationError(GunRegError):
    """参数校验失败。"""


class PermissionDenied(GunRegError):
    """授权失败（RBAC/ABAC）。"""


class AuthenticationError(GunRegError):
    """认证失败。"""


class NotFoundError(GunRegError):
    """对象不存在。"""


class StateError(ValidationError):
    """状态机不允许的迁移（视为参数/资格校验失败，供上层统一捕获）。"""


class ContractRejected(GunRegError):
    """智能合约校验不通过，附带规则版本与拒绝原因。"""

    def __init__(self, contract: str, version: int, reasons: list[str]):
        self.contract = contract
        self.version = version
        self.reasons = reasons
        super().__init__(f"{contract}#v{version} rejected: {'; '.join(reasons)}")


class ReplayError(GunRegError):
    """防重放检测失败（nonce 重复或时间窗外）。"""


class RateLimited(GunRegError):
    """WAF/网关限流触发。"""


class IntegrityError(GunRegError):
    """哈希链/账本完整性校验失败。"""


# ---------------------------------------------------------------------------
# 规范化序列化与哈希
# ---------------------------------------------------------------------------


def canonical(obj: Any) -> str:
    """确定性 JSON：排序键 + 紧凑分隔符，保证哈希可复现。"""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=_fallback)


def _fallback(o: Any) -> Any:
    if isinstance(o, datetime):
        return o.astimezone(timezone.utc).isoformat()
    if isinstance(o, (set, frozenset)):
        return sorted(o)
    if hasattr(o, "to_dict"):
        return o.to_dict()
    raise TypeError(f"cannot canonicalize {type(o)}")


def sha256_hex(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def hash_obj(obj: Any) -> str:
    return sha256_hex(canonical(obj))


def chain_hash(prev: str, obj: Any) -> str:
    """链式哈希：H(prev || canonical(obj))。"""
    return sha256_hex(prev + canonical(obj))


# ---------------------------------------------------------------------------
# 时钟（可注入，便于测试时间窗口/时限约束）
# ---------------------------------------------------------------------------


class Clock:
    """系统时钟。测试中可子类化返回固定/可控时间。"""

    def now(self) -> datetime:
        return datetime.now(timezone.utc)

    def now_iso(self) -> str:
        return self.now().isoformat()

    def monotonic(self) -> float:
        return time.monotonic()


class ManualClock(Clock):
    """可控时钟：测试时限约束时手动推进。"""

    def __init__(self, start: datetime | None = None):
        self._now = start or datetime(2026, 1, 1, 9, 0, 0, tzinfo=timezone.utc)

    def now(self) -> datetime:
        return self._now

    def advance(self, **kwargs) -> None:
        self._now += timedelta(**kwargs)

    def set(self, dt: datetime) -> None:
        self._now = dt


def parse_iso(s: str) -> datetime:
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


# ---------------------------------------------------------------------------
# 标识生成
# ---------------------------------------------------------------------------


def gen_id(prefix: str) -> str:
    return f"{prefix}-{secrets.token_hex(8)}"


def gen_nonce() -> str:
    return secrets.token_hex(16)


@dataclass(frozen=True)
class Paged:
    items: list[Any]
    total: int
    offset: int
    limit: int
