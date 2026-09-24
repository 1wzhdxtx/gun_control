"""身份与权限（流程图 SECURITY 层 IAM：MFA、RBAC、ABAC）。

- 认证：口令 + TOTP 风格的第二因子（MFA）
- RBAC：角色 → 权限点
- ABAC：对象级授权——数据域隔离（按所属主体）、状态属性判定
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from dataclasses import dataclass, field

from .common import AuthenticationError, PermissionDenied, ValidationError

# 角色
ROLE_ADMIN = "admin"            # 监管工作台（公安机关）
ROLE_UNIT = "unit"              # 单位工作台（制造/配售/配置单位）
ROLE_PRACTITIONER = "practitioner"  # 从业人员
ROLE_AUDITOR = "auditor"        # 审计工作台
ROLE_DEVICE = "device"          # 设备主体（无 UI，仅事件提交）

ALL_ROLES = {ROLE_ADMIN, ROLE_UNIT, ROLE_PRACTITIONER, ROLE_AUDITOR, ROLE_DEVICE}

# 权限点
PERM = {
    "gun:create": {ROLE_ADMIN, ROLE_UNIT},
    "gun:read:all": {ROLE_ADMIN, ROLE_AUDITOR},
    "gun:read:domain": {ROLE_ADMIN, ROLE_UNIT, ROLE_PRACTITIONER, ROLE_AUDITOR},
    "event:submit": {ROLE_ADMIN, ROLE_UNIT, ROLE_PRACTITIONER, ROLE_DEVICE},
    "permit:approve": {ROLE_ADMIN},
    "permit:request": {ROLE_ADMIN, ROLE_UNIT},
    "scrap:confirm": {ROLE_ADMIN},
    "alert:handle": {ROLE_ADMIN, ROLE_UNIT},
    "audit:read": {ROLE_ADMIN, ROLE_AUDITOR},
    "audit:ops": {ROLE_ADMIN, ROLE_AUDITOR},  # 重建视图/泵送/Outbox 等运维类审计操作
    "ledger:query": {ROLE_ADMIN, ROLE_UNIT, ROLE_PRACTITIONER, ROLE_AUDITOR},
    "evidence:verify": {ROLE_ADMIN, ROLE_AUDITOR},
}


def check_rbac(role: str, perm: str) -> None:
    allowed = PERM.get(perm)
    if allowed is None:
        raise PermissionDenied(f"未知权限点: {perm}")
    if role not in allowed:
        raise PermissionDenied(f"角色 {role} 无权限 {perm}")


# ---------------------------------------------------------------------------
# ABAC：数据域与状态属性
# ---------------------------------------------------------------------------


@dataclass
class Subject:
    user_id: str
    name: str
    role: str
    org: str               # 所属主体（数据域），如 police:bureau-01 / unit:range-a
    mfa_secret: str = ""
    cert_id: str = ""
    attrs: dict = field(default_factory=dict)


def check_abac(subject: Subject, resource_domain: str, perm: str, resource_state: str | None = None) -> None:
    """对象级授权：先 RBAC，再按数据域隔离，再按状态属性。

    数据域必须与主体完全一致，或为「主体 org + ':' + 子域」层级前缀。
    去掉宽松的 startswith(org) 兜底：否则 range-a 可凭借前缀越权访问 range-abuse。
    """
    check_rbac(subject.role, perm)
    # 数据域隔离：非监管/审计角色只能访问本主体数据
    if subject.role in (ROLE_UNIT, ROLE_PRACTITIONER):
        if not (resource_domain == subject.org or resource_domain.startswith(subject.org + ":")):
            raise PermissionDenied(
                f"数据域隔离：{subject.org} 不可访问 {resource_domain}"
            )
    # 状态属性：已销毁枪支禁止任何写操作
    if resource_state in ("destroyed", "sealed") and perm not in (
        "gun:read:all", "gun:read:domain", "ledger:query", "evidence:verify",
        "audit:read", "audit:ops",
    ):
        raise PermissionDenied(f"对象状态 {resource_state} 只读")


# ---------------------------------------------------------------------------
# MFA：TOTP（RFC-6238 简化实现，6 位，30s 步长）
# ---------------------------------------------------------------------------

ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # Crockford 风格，去掉易混字符


def _b32_secret(n: int = 20) -> str:
    return base64.b32encode(secrets.token_bytes(n)).decode("ascii").rstrip("=")


def totp(secret: str, counter: int, digits: int = 6) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    msg = counter.to_bytes(8, "big")
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    off = digest[-1] & 0x0F
    code = (int.from_bytes(digest[off:off + 4], "big") & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def verify_totp(secret: str, code: str, counter: int, window: int = 1) -> bool:
    return any(hmac.compare_digest(totp(secret, counter + i), code) for i in range(-window, window + 1))


# ---------------------------------------------------------------------------
# 会话（BFF 服务端会话）
# ---------------------------------------------------------------------------


@dataclass
class Session:
    token: str
    subject: Subject
    created_at: str
    expires_at: str
    mfa_passed: bool = False


class IdentityService:
    """身份与权限服务：注册、认证（MFA 两步）、会话管理。"""

    def __init__(self, kms, ca, clock):
        self.kms = kms
        self.ca = ca
        self.clock = clock
        self._users: dict[str, Subject] = {}
        self._passwords: dict[str, str] = {}   # user_id -> pbkdf2 hash
        self._sessions: dict[str, Session] = {}

    # -- 注册 ---------------------------------------------------------------
    def register(self, user_id: str, name: str, role: str, org: str, password: str, attrs: dict | None = None) -> Subject:
        if role not in ALL_ROLES:
            raise ValidationError(f"未知角色: {role}")
        if user_id in self._users:
            raise ValidationError(f"用户已存在: {user_id}")
        sub = Subject(user_id=user_id, name=name, role=role, org=org, mfa_secret=_b32_secret(), attrs=attrs or {})
        key = self.kms.create_key(f"user:{user_id}", owner=user_id, purpose="sign")
        cert = self.ca.issue(subject=f"user:{user_id}", cert_type="user", public_key=key.public_key, days=730)
        sub.cert_id = cert.cert_id
        self._users[user_id] = sub
        self._passwords[user_id] = self._hash_pw(password)
        return sub

    @staticmethod
    def _hash_pw(password: str, salt: str | None = None) -> str:
        """每个用户独立随机盐的 PBKDF2 口令散列，存为 salt$digest。"""
        salt = salt or secrets.token_hex(8)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 120_000).hex()
        return f"{salt}${digest}"

    def get(self, user_id: str) -> Subject:
        if user_id not in self._users:
            raise AuthenticationError(f"用户不存在: {user_id}")
        return self._users[user_id]

    # -- 认证（第一步：口令；第二步：MFA） ----------------------------------
    def auth_step1(self, user_id: str, password: str) -> str:
        """返回临时挑战票，要求继续 MFA。"""
        stored = self._passwords.get(user_id)
        if not stored or "$" not in stored:
            raise AuthenticationError("用户名或口令错误")
        salt, digest = stored.split("$", 1)
        if not hmac.compare_digest(self._hash_pw(password, salt), stored):
            raise AuthenticationError("用户名或口令错误")
        ticket = secrets.token_urlsafe(24)
        self._pending = getattr(self, "_pending", {})
        self._pending[ticket] = (user_id, self.clock.now_iso())
        return ticket

    def auth_step2(self, ticket: str, totp_code: str, require_mfa: bool = True) -> Session:
        pending = getattr(self, "_pending", {})
        if ticket not in pending:
            raise AuthenticationError("挑战票无效")
        user_id, _ = pending.pop(ticket)
        sub = self._users[user_id]
        if require_mfa or totp_code:
            counter = int(self.clock.now().timestamp()) // 30
            if not verify_totp(sub.mfa_secret, totp_code, counter):
                raise AuthenticationError("MFA 校验失败")
        token = secrets.token_urlsafe(32)
        now = self.clock.now()
        from datetime import timedelta

        sess = Session(token=token, subject=sub, created_at=now.isoformat(),
                       expires_at=(now + timedelta(hours=8)).isoformat(), mfa_passed=True)
        self._sessions[token] = sess
        return sess

    def session(self, token: str | None) -> Session | None:
        if not token:
            return None
        s = self._sessions.get(token)
        if not s:
            return None
        if self.clock.now_iso() > s.expires_at:
            self._sessions.pop(token, None)
            return None
        return s

    def logout(self, token: str) -> None:
        self._sessions.pop(token, None)

    def require(self, token: str | None, perm: str, resource_domain: str | None = None,
                resource_state: str | None = None) -> tuple[Subject, Session]:
        sess = self.session(token)
        if not sess or not sess.mfa_passed:
            raise AuthenticationError("未认证会话")
        sub = sess.subject
        if resource_domain is not None or perm:
            check_abac(sub, resource_domain if resource_domain is not None else sub.org, perm, resource_state)
        return sub, sess
