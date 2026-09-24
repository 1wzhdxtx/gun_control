"""外部系统与本地数据适配（流程图 INTEGRATION + CONNECTOR/LEGACY/LOCAL）。

- LegacyBridge：与全国枪支管理信息系统的双轨并行同步（标准接口 + 签名结论）
- PrivacyOracle：隐私核验接口——只返回校验结论，不输出原始数据（最小披露）
- 本地加密原件（LocalVault）由 crypto 模块提供，此处编排授权核验路径
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .common import ValidationError, hash_obj, parse_iso
from .crypto import CA, KMS, LocalVault
from .iam import Subject


# ---------------------------------------------------------------------------
# 全国枪管系统衔接：标识贯通 → 双轨并行 → 职能分流
# ---------------------------------------------------------------------------


@dataclass
class SyncRecord:
    kind: str            # certificate / gun_status / approval
    ref: str             # 枪号或证件号
    payload: dict
    signature: str = ""
    synced_at: str = ""


class LegacyBridge:
    """标准接口同步关键状态字段；结论带签名，链上侧可验证来源。"""

    def __init__(self, kms: KMS, key_id: str, clock):
        self.kms = kms
        self.key_id = key_id
        self.clock = clock
        self._store: dict[str, SyncRecord] = {}
        self._inbound: list[SyncRecord] = []

    def _sign(self, payload: dict) -> str:
        from .common import canonical
        return self.kms.sign(self.key_id, canonical(payload).encode("utf-8"))

    def push(self, kind: str, ref: str, payload: dict) -> SyncRecord:
        rec = SyncRecord(kind=kind, ref=ref, payload=payload,
                         signature=self._sign({"kind": kind, "ref": ref, "payload": payload}),
                         synced_at=self.clock.now_iso())
        self._store[f"{kind}:{ref}"] = rec
        return rec

    def pull(self, kind: str, ref: str) -> SyncRecord | None:
        """外部系统回调本桥的写入（模拟枪管系统回写）。"""
        rec = SyncRecord(kind=kind, ref=ref, payload={},
                         signature="", synced_at=self.clock.now_iso())
        self._inbound.append(rec)
        return rec

    def verify_record(self, rec: SyncRecord) -> bool:
        expect = self._sign({"kind": rec.kind, "ref": rec.ref, "payload": rec.payload})
        return expect == rec.signature

    def mapping(self, gun_code: str, legacy_no: str) -> dict:
        """标识贯通：链上整枪码 ↔ 现行 GA1258 枪号映射。"""
        m = {"gun_code": gun_code, "legacy_no": legacy_no}
        m["signature"] = self._sign(m)
        return m

    def verify_mapping(self, m: dict) -> bool:
        body = {"gun_code": m["gun_code"], "legacy_no": m["legacy_no"]}
        return self._sign(body) == m.get("signature", "")

    @property
    def synced(self) -> dict[str, SyncRecord]:
        return dict(self._store)


# ---------------------------------------------------------------------------
# 隐私核验：只回结论，不回原始数据
# ---------------------------------------------------------------------------


@dataclass
class PrivateRecord:
    """存放在本域（公安/单位本地）的敏感原件，绝不出域。"""
    subject_id: str
    kind: str          # criminal_record / biometric / identity
    value: dict        # 原始值（只在本地比对，不外发）
    vault_ref: str = ""


class PrivacyOracle:
    """隐私计算的最小实现：输入是请求主体的授权与查询条件，
    输出只有 `通过/不通过 + 签名结论`，原始数据不离开本域。
    """

    def __init__(self, kms: KMS, key_id: str, clock, vault: LocalVault | None = None):
        self.kms = kms
        self.key_id = key_id
        self.clock = clock
        self.vault = vault
        self._records: dict[str, PrivateRecord] = {}
        self.queries: list[dict] = []

    def enroll(self, rec: "PrivateRecord | dict") -> None:
        if isinstance(rec, dict):
            rec = PrivateRecord(subject_id=rec["subject_id"], kind=rec["kind"],
                                value=rec["value"], vault_ref=rec.get("vault_ref", ""))
        self._records[f"{rec.kind}:{rec.subject_id}"] = rec

    def verify(self, *, subject_id: str, kind: str, condition: dict,
               requester: Subject, purpose: str) -> dict:
        """核验接口：调用方只得到布尔结论与签名，得不到原始记录。"""
        if not purpose:
            raise ValidationError("核验必须声明目的（目的限定）")
        key = f"{kind}:{subject_id}"
        rec = self._records.get(key)
        result = True
        if rec is None:
            result = False
        else:
            for k, v in condition.items():
                rv = rec.value.get(k)
                if isinstance(v, str) and k.endswith("_before"):
                    if rv and parse_iso(rv) > parse_iso(v):
                        result = False
                elif isinstance(rv, bool) or isinstance(v, bool):
                    if bool(rv) != bool(v):
                        result = False
                elif rv != v:
                    result = False

        conclusion = {
            "subject_id": subject_id,
            "kind": kind,
            "result": result,          # ← 只有结论
            "purpose": purpose,
            "requester": requester.user_id,
            "queried_at": self.clock.now_iso(),
        }
        from .common import canonical
        conclusion["signature"] = self.kms.sign(self.key_id, canonical(conclusion).encode())
        self.queries.append(dict(conclusion, domain=requester.org))
        return conclusion

    def verify_signature(self, conclusion: dict) -> bool:
        from .common import canonical
        body = {k: v for k, v in conclusion.items() if k != "signature"}
        return self.kms.sign(self.key_id, canonical(body).encode()) == conclusion.get("signature", "")

    def enroll_biometric(self, subject_id: str, template: bytes) -> str:
        """生物特征模板入本地加密原件库，链上只留哈希。"""
        if not self.vault:
            raise ValidationError("本地原件库未配置")
        ref = f"bio:{subject_id}"
        return self.vault.put(ref, template, owner="biometric-store", data_type="template")
