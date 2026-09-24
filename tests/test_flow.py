"""端到端流程：制造 → 领用 → 归还 → 上链 → 投影 → 取证。

验证 Transactional Outbox → 事件总线 → 链适配器 → 共识账本 → 派生视图的完整链路。
"""
import sys
sys.path.insert(0, ".")

import pytest

from gunreg import GunSystem, ManualClock
from gunreg.common import ContractRejected


@pytest.fixture()
def sys0():
    clock = ManualClock()
    s = GunSystem(clock=clock)
    s.register_unit("unit:range-a", "某营业性射击场", "shooting_range", risk_level=2)
    s.register_person("p-keeper", "保管员", "unit:range-a", duty="保管",
                      cert_kinds=["手枪"], cert_expire="2027-12-31T00:00:00+00:00")
    s.register_person("p-super", "监督员", "unit:range-a", duty="监督",
                      cert_kinds=["手枪"], cert_expire="2027-12-31T00:00:00+00:00")
    # 在册人员同时持有 IAM 密钥（签名主体）
    s.identity.register("p-keeper", "保管员", "practitioner", "unit:range-a", "pw1")
    s.identity.register("p-super", "监督员", "practitioner", "unit:range-a", "pw2")
    # 注册设备与密钥（用于设备网关验签）
    s.register_device("reader-01", "rfid", "unit:range-a")
    s.identity.register("u-keeper", "保管员", "unit", "unit:range-a", "pw1")
    s.identity.register("u-super", "监督员", "unit", "unit:range-a", "pw2")
    s.identity.register("u-police", "民警", "admin", "police:sd", "pw3")
    return s


def _mk_gun(s: GunSystem, serial: int = 1, kind: str = "手枪"):
    return s.domain.manufacture(maker="云南西南", kind=kind, year=2026, serial=serial,
                                legacy_no=f"GA1258-2026-{serial:04d}", unit_id="unit:range-a",
                                part_categories=["枪管", "撞针"], signer="u-keeper")


def _checkout_sigs(s: GunSystem, gun_code: str, person: str, action: str = "checkout"):
    sigs = []
    for uid, duty in (("p-keeper", "保管"), ("p-super", "监督")):
        payload = f"{action}:{gun_code}:{person}".encode()
        sigs.append({"signer": uid, "role": duty,
                     "sig": s.kms.sign(f"user:{uid}", payload)})
    return sigs


class TestFullFlow:
    def test_manufacture_checkout_return_onchain(self, sys0):
        s = sys0
        gun = _mk_gun(s)
        assert gun.status == "in_stock"

        ev = s.domain.checkout(gun_code=gun.code, person_id="p-keeper",
                               signers=_checkout_sigs(s, gun.code, "p-keeper"),
                               device_verified=True, due_hours=8)
        assert ev.event_type == "checkout"
        assert s.repo.get_gun(gun.code).status == "in_use"

        # 未 pump 前：链上还没有，Outbox 有待发
        assert s.outbox.stats()["pending"] >= 2  # manufacture + checkout
        assert s.ledger.txs() == []

        r = s.pump()
        assert r["published"] >= 2
        assert r["outbox"]["pending"] == 0
        assert r["bus_dead"] == 0
        assert s.adapter.reconcile()["consistent"]

        # 派生视图已更新
        state = s.view.gun(gun.code)
        assert state["status"] == "in_use"
        assert state["holder"] == "p-keeper"
        timeline = s.view.timeline(gun.code)
        assert len(timeline) == 2  # manufacture + checkout

        # 归还
        sigs = _checkout_sigs(s, gun.code, "p-keeper", action="return")
        s.domain.checkin(gun_code=gun.code, person_id="p-keeper", signers=sigs)
        s.pump()
        assert s.view.gun(gun.code)["status"] == "in_stock"
        assert s.repo.get_gun(gun.code).status == "in_stock"

        # 取证：发票据完整
        report = s.evidence.verify_gun(gun.code)
        assert report.ok, report.checks
        assert report.checks["coverage"]["onchain"] == 3

    def test_checkout_blocked_by_single_signature(self, sys0):
        """双人双锁：单人签名被多签合约拒绝。"""
        s = sys0
        gun = _mk_gun(s)
        sigs = [{"signer": "p-keeper", "role": "保管",
                 "sig": s.kms.sign("user:p-keeper", f"checkout:{gun.code}:p-keeper".encode())}]
        with pytest.raises(ContractRejected) as ei:
            s.domain.checkout(gun_code=gun.code, person_id="p-keeper", signers=sigs)
        assert ei.value.contract == "multisig"
        # 被拒绝的操作不入链
        assert s.outbox.stats()["pending"] == 1  # 仅 manufacture

    def test_checkout_blocked_by_invalid_person(self, sys0):
        s = sys0
        s.domain.update_qualification(person_id="p-keeper", cert_status="revoked")
        gun = _mk_gun(s)
        with pytest.raises(ContractRejected) as ei:
            s.domain.checkout(gun_code=gun.code, person_id="p-keeper",
                              signers=_checkout_sigs(s, gun.code, "p-keeper"))
        assert ei.value.contract == "compliance"

    def test_dual_signature_required_distinct_roles(self, sys0):
        """同岗位两人签名被多签的职责区分条件拒绝。"""
        s = sys0
        # 增加第二位“保管”岗人员（持有 IAM 密钥）
        s.register_person("p-keeper2", "保管员2", "unit:range-a", duty="保管",
                          cert_kinds=["手枪"], cert_expire="2027-12-31T00:00:00+00:00")
        s.identity.register("p-keeper2", "保管员2", "practitioner", "unit:range-a", "pw4")
        gun = _mk_gun(s)
        sigs = [
            {"signer": "p-keeper", "role": "保管",
             "sig": s.kms.sign("user:p-keeper", f"checkout:{gun.code}:p-keeper".encode())},
            {"signer": "p-keeper2", "role": "保管",
             "sig": s.kms.sign("user:p-keeper2", f"checkout:{gun.code}:p-keeper".encode())},
        ]
        with pytest.raises(ContractRejected):
            s.domain.checkout(gun_code=gun.code, person_id="p-keeper", signers=sigs)


class TestViewRebuild:
    def test_rebuild_from_ledger(self, sys0):
        s = sys0
        gun = _mk_gun(s, serial=11)
        s.domain.checkout(gun_code=gun.code, person_id="p-keeper",
                          signers=_checkout_sigs(s, gun.code, "p-keeper"))
        s.pump()
        assert s.view.gun(gun.code)["status"] == "in_use"

        # 伪造视图后全量重建（投影是派生的，可重建）
        s.view.db.execute("UPDATE gun_state SET status='tampered' WHERE gun_code=?", (gun.code,))
        n = s.rebuild_view()
        assert n == 2
        assert s.view.gun(gun.code)["status"] == "in_use"

    def test_ledger_tamper_detected_by_evidence(self, sys0):
        s = sys0
        gun = _mk_gun(s, serial=12)
        s.pump()
        report = s.evidence.verify_gun(gun.code)
        assert report.ok

        # 篡改账本中的一个事件哈希
        tx = s.ledger.txs()[0]
        tx["event"]["event_hash"] = "f" * 64
        report2 = s.evidence.verify_gun(gun.code)
        assert not report2.ok
        assert not report2.checks["evidence_match"]["ok"]