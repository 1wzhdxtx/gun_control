"""六类智能合约 + 版本化治理 + 人工干预通道。"""
import sys
sys.path.insert(0, ".")

from datetime import datetime, timedelta, timezone

import pytest

from gunreg.common import ContractRejected, ManualClock
from gunreg.contracts import (ComplianceContract, ContractRegistry,
                              MultiSigContract, ScrapConfirmContract,
                              SpaceTimeContract, TimeLimitContract,
                              TransportPermitContract)


def _registry():
    return ContractRegistry(ManualClock())


class TestCompliance:
    def test_reject_invalid_person(self):
        ctx = {"person": {"cert_status": "revoked"}, "unit": {"risk_level": 2,
               "status": "qualified"}, "device_verified": True}
        v = ComplianceContract().evaluate(ctx)
        assert not v.ok
        assert any("证件无效" in r for r in v.reasons)

    def test_reject_wrong_gun_kind(self):
        ctx = {"person": {"cert_status": "valid", "cert_kinds": ["手枪"]},
               "gun": {"kind": "猎枪", "status": "in_stock"},
               "unit": {"risk_level": 2, "status": "qualified"},
               "device_verified": True}
        v = ComplianceContract().evaluate(ctx)
        assert not v.ok
        assert any("枪种" in r for r in v.reasons)

    def test_reject_expired_cert(self):
        ctx = {"person": {"cert_status": "valid", "cert_expire": "2020-01-01T00:00:00+00:00"},
               "gun": {"status": "in_stock"},
               "unit": {"risk_level": 2, "status": "qualified"},
               "device_verified": True, "now": "2026-01-01T00:00:00+00:00"}
        v = ComplianceContract().evaluate(ctx)
        assert not v.ok
        assert any("过期" in r for r in v.reasons)

    def test_manual_entry_requires_voucher(self):
        ctx = {"person": {"cert_status": "valid"}, "gun": {"status": "in_stock"},
               "unit": {"risk_level": 2, "status": "qualified"},
               "device_verified": True, "manual_entry": True}
        v = ComplianceContract().evaluate(ctx)
        assert not v.ok
        assert any("人工录入" in r for r in v.reasons)


class TestSpaceTime:
    def test_outside_region_rejected(self):
        ctx = {"region": {"name": "猎区A", "lon_range": (100, 101), "lat_range": (20, 21)},
               "position": (105.0, 25.0), "now": "2026-01-01T00:00:00+00:00"}
        v = SpaceTimeContract().evaluate(ctx)
        assert not v.ok

    def test_offline_pos_check_is_warning_not_block(self):
        """离线场景事后核验：不阻断，仅提示（能力边界显性化）。"""
        ctx = {"region": {"name": "猎区A", "lon_range": (100, 101), "lat_range": (20, 21)},
               "position": (105.0, 25.0), "now": "2026-01-01T00:00:00+00:00",
               "offline": True}
        v = SpaceTimeContract().evaluate(ctx)
        assert v.ok
        assert v.outputs.get("post_check")

    def test_time_window(self):
        ctx = {"region": {"name": "R", "lon_range": (0, 1), "lat_range": (0, 1)},
               "position": (0.5, 0.5),
               "time_window": {"start": "2026-02-01", "end": "2026-02-28"},
               "now": "2026-01-15T00:00:00+00:00"}
        v = SpaceTimeContract().evaluate(ctx)
        assert not v.ok
        assert any("许可时段" in r for r in v.reasons)


class TestTimeLimit:
    def test_tiered_alerts(self):
        now = datetime(2026, 1, 10, tzinfo=timezone.utc)
        base = {"now": now.isoformat(), "returned": False}

        hint = TimeLimitContract().evaluate({**base, "due_at": (now - timedelta(hours=6)).isoformat()})
        assert hint.outputs["alert_level"] == "hint"

        concern = TimeLimitContract().evaluate({**base, "due_at": (now - timedelta(hours=24)).isoformat()})
        assert concern.outputs["alert_level"] == "concern"

        emergency = TimeLimitContract().evaluate({**base, "due_at": (now - timedelta(hours=72)).isoformat()})
        assert emergency.outputs["alert_level"] == "emergency"

    def test_block_new_checkout_when_overdue(self):
        c = TimeLimitContract()
        v = c.check_before_checkout({"outstanding_overdue": 2})
        assert not v.ok


class TestMultiSig:
    def test_requires_two_distinct(self):
        ok = MultiSigContract().evaluate({"signers": ["a", "b"], "signer_ids": ["a", "b"]})
        assert ok.ok
        bad = MultiSigContract().evaluate({"signers": ["a"], "signer_ids": ["a"]})
        assert not bad.ok

    def test_distinct_duty(self):
        v = MultiSigContract().evaluate(
            {"signers": ["a", "b"], "signer_ids": ["a", "b"],
             "signer_roles": ["保管", "保管"], "require_distinct_duty": True})
        assert not v.ok


class TestTransportPermit:
    def test_vehicle_mismatch_rejected(self):
        """第三章所述：实际承运车辆与许可证载明车辆不一致。"""
        ctx = {"permit": {"status": "approved", "vehicle": "鲁A-1234",
                          "carrier": "c1", "escort": "e1", "gun_codes": ["G1"],
                          "valid_from": "2026-01-01", "valid_end": "2026-01-31"},
               "vehicle": "鲁A-9999", "carrier": "c1", "escort": "e1",
               "gun_codes": ["G1"], "now": "2026-01-10T00:00:00+00:00"}
        v = TransportPermitContract().evaluate(ctx)
        assert not v.ok

    def test_no_permit_rejected(self):
        v = TransportPermitContract().evaluate({"vehicle": "x"})
        assert not v.ok and any("许可" in r for r in v.reasons)


class TestScrapConfirm:
    def test_destroy_node_needs_two_signers(self):
        v = ScrapConfirmContract().evaluate(
            {"stage": "destroy_submit", "signers": ["a"]})
        assert not v.ok

    def test_seal_requires_all_stages(self):
        v = ScrapConfirmContract().evaluate(
            {"stage": "destroy_archive", "signers": ["a", "b"],
             "require_seal": True,
             "done_stages": ["destroy_submit", "destroy_inventory"]})
        assert not v.ok
        assert any("未全部完成" in r for r in v.reasons)


class TestRegistryGovernance:
    def test_upgrade_requires_votes(self):
        reg = _registry()
        with pytest.raises(ContractRejected):
            reg.upgrade(SpaceTimeContract(), votes=["node-1"], min_votes=3)
        reg.upgrade(SpaceTimeContract(), votes=["node-1", "node-2", "node-3"], min_votes=3)
        assert reg.get("spacetime").version == 1
        assert len(reg.versions("spacetime")) >= 2

    def test_suspend_needs_multisig_and_is_audited(self):
        reg = _registry()
        with pytest.raises(ContractRejected):
            reg.suspend("compliance", "紧急情形", ["officer-1"])
        it = reg.suspend("compliance", "紧急情形", ["officer-1", "officer-2"])
        assert reg.is_suspended("compliance")
        assert it.signers == ["officer-1", "officer-2"]
        # 中止后执行不阻断，仅留痕
        v = reg.evaluate("compliance",
                         {"person": {"cert_status": "revoked"}, "device_verified": False})
        assert v.ok
        assert any("中止" in w for w in v.warnings)
        reg.resume("compliance", "情形解除", ["officer-1", "officer-2"])
        assert not reg.is_suspended("compliance")