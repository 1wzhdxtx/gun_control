"""证书与密钥体系（流程图 SECURITY 层 KEY：CA / KMS / HSM）。

- CA：为设备、用户、节点签发 X.509 风格的简化证书（Ed25519 自签）
- KMS：密钥登记、签名、轮换（私钥不出库）
- HSM：安全芯片抽象，私钥不可导出（离线终端用）
- Vault：本地加密原件（身份/影像/生物特征）的信封加密存储
"""
from __future__ import annotations

import base64
import json
import os
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from .common import sha256_hex

# ---------------------------------------------------------------------------
# 证书
# ---------------------------------------------------------------------------

_CERT_TYPE = {"user", "device", "node"}


@dataclass
class Certificate:
    cert_id: str
    subject: str            # 主体标识，如 device:reader-01
    cert_type: str          # user / device / node
    public_key: str         # base64 raw ed25519 public key
    issuer: str             # CA 标识
    not_before: str
    not_after: str
    serial: str
    signature: str = ""     # CA 对上述字段的签名

    def to_dict(self) -> dict:
        return {
            "cert_id": self.cert_id,
            "subject": self.subject,
            "cert_type": self.cert_type,
            "public_key": self.public_key,
            "issuer": self.issuer,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "serial": self.serial,
            "signature": self.signature,
        }

    @staticmethod
    def from_dict(d: dict) -> "Certificate":
        return Certificate(**d)


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def sign_raw(private_key: Ed25519PrivateKey, data: bytes) -> str:
    return _b64e(private_key.sign(data))


def verify_raw(public_key_b64: str, data: bytes, signature_b64: str) -> bool:
    try:
        pub = Ed25519PublicKey.from_public_bytes(_b64d(public_key_b64))
        pub.verify(_b64d(signature_b64), data)
        return True
    except (InvalidSignature, ValueError):
        return False


class CA:
    """简化 CA：自签证书，验证时校验签名与有效期。"""

    def __init__(self, name: str = "gunreg-root-ca", clock=None):
        from .common import Clock

        self.name = name
        self._key = Ed25519PrivateKey.generate()
        self.public_key = _b64e(self._key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
        self.clock = clock or Clock()
        self._serial = 0
        self._issued: dict[str, Certificate] = {}

    def issue(self, subject: str, cert_type: str, public_key: str, days: int = 365) -> Certificate:
        if cert_type not in _CERT_TYPE:
            raise ValueError(f"unknown cert type: {cert_type}")
        self._serial += 1
        now = self.clock.now()
        cert = Certificate(
            cert_id=f"cert-{self._serial:06d}",
            subject=subject,
            cert_type=cert_type,
            public_key=public_key,
            issuer=self.name,
            not_before=now.isoformat(),
            not_after=(now + timedelta(days=days)).isoformat(),
            serial=f"{self._serial:06d}",
        )
        body = {k: v for k, v in cert.to_dict().items() if k != "signature"}
        cert.signature = sign_raw(self._key, json.dumps(body, sort_keys=True).encode("utf-8"))
        self._issued[cert.cert_id] = cert
        return cert

    def verify(self, cert: Certificate) -> tuple[bool, str]:
        body = {k: v for k, v in cert.to_dict().items() if k != "signature"}
        if not verify_raw(self.public_key, json.dumps(body, sort_keys=True).encode("utf-8"), cert.signature):
            return False, "证书签名无效"
        now = self.clock.now()
        if now < datetime.fromisoformat(cert.not_before):
            return False, "证书尚未生效"
        if now > datetime.fromisoformat(cert.not_after):
            return False, "证书已过期"
        if cert.cert_id not in self._issued:
            return False, "证书非本 CA 签发"
        return True, "ok"


# ---------------------------------------------------------------------------
# 密钥
# ---------------------------------------------------------------------------


@dataclass
class KeyRecord:
    key_id: str
    owner: str
    purpose: str            # sign / device / node
    public_key: str
    created_at: str
    rotated_from: str | None = None
    active: bool = True


class KMS:
    """密钥管理服务：私钥不出库，只暴露 sign/verify 接口。"""

    def __init__(self, clock=None):
        from .common import Clock

        self.clock = clock or Clock()
        self._private: dict[str, Ed25519PrivateKey] = {}
        self._records: dict[str, KeyRecord] = {}
        self._lock = threading.RLock()

    def create_key(self, key_id: str, owner: str, purpose: str = "sign") -> KeyRecord:
        with self._lock:
            if key_id in self._records:
                raise ValueError(f"key exists: {key_id}")
            priv = Ed25519PrivateKey.generate()
            rec = KeyRecord(
                key_id=key_id,
                owner=owner,
                purpose=purpose,
                public_key=_b64e(priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)),
                created_at=self.clock.now_iso(),
            )
            self._private[key_id] = priv
            self._records[key_id] = rec
            return rec

    def rotate(self, key_id: str) -> KeyRecord:
        with self._lock:
            old = self._records[key_id]
            old.active = False
            new_id = f"{key_id}#r{len(self._records)}"
            rec = self.create_key(new_id, old.owner, old.purpose)
            rec.rotated_from = key_id
            return rec

    def sign(self, key_id: str, data: bytes) -> str:
        with self._lock:
            if key_id not in self._private:
                raise KeyError(f"unknown key: {key_id}")
            return sign_raw(self._private[key_id], data)

    def verify(self, key_id: str, data: bytes, signature: str) -> bool:
        rec = self._records.get(key_id)
        if not rec:
            return False
        return verify_raw(rec.public_key, data, signature)

    def has_key(self, key_id: str) -> bool:
        """该密钥是否已登记（签名人有 IAM 账号才持有可用签名密钥）。"""
        return key_id in self._private and self._records.get(key_id) is not None

    def get(self, key_id: str) -> KeyRecord:
        return self._records[key_id]

    def public_key(self, key_id: str) -> str:
        return self._records[key_id].public_key


class SecureEnclave:
    """HSM/安全芯片抽象：私钥生成后即被困在对象内，不可导出。

    离线终端（猎枪场景）使用：私钥不可复制、不可导出，只能 sign()。
    """

    def __init__(self, device_id: str):
        self.device_id = device_id
        self._key = Ed25519PrivateKey.generate()  # 私钥仅存在于本对象

    @property
    def public_key(self) -> str:
        return _b64e(self._key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))

    def sign(self, data: bytes) -> str:
        return sign_raw(self._key, data)

    def __reduce__(self):  # pragma: no cover - 防 pickle 导出
        raise TypeError("SecureEnclave is not serializable (private key must not leave the chip)")


# ---------------------------------------------------------------------------
# 本地加密原件（链下 LOCAL 存储：身份、影像、生物特征）
# ---------------------------------------------------------------------------


class LocalVault:
    """信封加密的本地原件库：AES 不可用时用 XOR 流的替代——这里直接用
    Fernet-like 方案：Ed25519 场景下用 ChaCha20 不在标准库，故采用
    简单但安全的方案：以 KMS 主密钥派生的流密钥做一次性填充哈希流加密。
    生产中应替换为 AES-GCM；此处保证接口与最小披露语义。
    """

    def __init__(self, kms: KMS, master_key_id: str = "vault-master", base_dir: str | None = None):
        self.kms = kms
        self.master_key_id = master_key_id
        if master_key_id not in kms._records:
            kms.create_key(master_key_id, owner="vault", purpose="wrap")
        self.base_dir = base_dir
        self._index: dict[str, dict] = {}  # ref -> {hash, type, owner, created_at}
        if base_dir:
            os.makedirs(base_dir, exist_ok=True)

    def _keystream(self, ref: str, length: int) -> bytes:
        # 由主密钥对 ref 的签名作为确定性伪随机流（HMAC 展开）
        out = b""
        counter = 0
        while len(out) < length:
            out += _b64d(self.kms.sign(self.master_key_id, f"{ref}:{counter}".encode("utf-8")))
            counter += 1
        return out[:length]

    def put(self, ref: str, plaintext: bytes, owner: str, data_type: str) -> str:
        """加密存入原件，返回内容哈希（链上只存该哈希）。"""
        stream = self._keystream(ref, len(plaintext))
        cipher = bytes(a ^ b for a, b in zip(plaintext, stream))
        digest = sha256_hex(plaintext)
        path = None
        if self.base_dir:
            path = os.path.join(self.base_dir, sha256_hex(ref)[:16] + ".bin")
            with open(path, "wb") as f:
                f.write(cipher)
        self._index[ref] = {
            "hash": digest,
            "type": data_type,
            "owner": owner,
            "created_at": None,
            "_cipher": None if path else cipher,
        }
        return digest

    def get(self, ref: str, requester_owner: str, allow: bool = True) -> bytes | None:
        """授权核验、最小披露：未授权时只返回哈希比对结论，不返回明文。"""
        rec = self._index.get(ref)
        if not rec:
            raise KeyError(ref)
        if not allow or rec["owner"] != requester_owner:
            return None  # 只给出“是否有权”结论，最小披露
        if rec.get("_cipher") is not None:
            cipher = rec["_cipher"]
        else:
            path = os.path.join(self.base_dir, sha256_hex(ref)[:16] + ".bin")  # type: ignore[arg-type]
            with open(path, "rb") as f:
                cipher = f.read()
        stream = self._keystream(ref, len(cipher))
        return bytes(a ^ b for a, b in zip(cipher, stream))

    def verify_hash(self, ref: str, candidate: bytes) -> bool:
        """哈希比对（可用于“影像是否被修改”的最小披露核验）。"""
        rec = self._index.get(ref)
        if not rec:
            return False
        return rec["hash"] == sha256_hex(candidate)
