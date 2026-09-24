"""三类差异化场景 + 设备网关（验签/防重放/协议转换）+ 外部衔接 + 隐私核验。"""
import sys
sys.path.insert(0, ".")

from datetime import datetime, timedelta, timezone

import pytest

from gunreg import GunSystem, ManualClock
from gunreg.common import AuthenticationError, ReplayError, ValidationError
from gunreg.scenarios import (OfflineTerminal, RangeRFIDController, ScanReviewStation,
                              TagRead)


def _mk_sys(clock=None):
    s = GunSystem(clock=clock or ManualClock())
    s.register_unit("unit:shooting", "射击场", "shooting_range", risk_level=2,
                    region={"name": "场内", "lon_range": (120.0, 120.5), "lat_range": (30.0, 30.5)})
    s.register_person("p1", "员工1", "unit:shooting", duty="保管", cert_kinds=["手枪"],
                      cert_expire="2027-12-31T00:00:00+00:00")
    s.register_person("p2", "员工2", "unit:shooting", duty="监督", cert_kinds=["手枪"],
                      cert_expire="2027-12-31T00:00:00+00:00")
    # 在册人员同时持有 IAM 密钥（签名主体）
    s.identity.register("p1", "员工1", "practitioner", "unit:shooting", "pw1")
    s.identity.register("p2", "员工2", "practitioner", "unit:shooting", "pw2")
    s.identity.register("u1", "员工1", "unit", "unit:shooting", "pw1")
    s.identity.register("u2", "员工2", "unit", "unit:shooting", "pw2")
    s.identity.register("u-police", "民警", "admin", "police:zj", "pw3")
    s.register_device("reader-ch1", "rfid", "unit:shooting")
    return s


class TestRangeRFID:
    def test_multireader_dedup_and_merge(self):
        s = _mk_sys()
        app = 3.0
        # 同一 tag 数毫秒间隔被 3 台读写器读到（覆盖重叠）
        base = datetime(2026, 1, 1, 9, 0, 0, tzinfo=timezone.utc)
        for i, rid in enumerate(("r1", "r2", "r3")):
            s.range_rfid.feed(TagRead(
                reader_id=rid, tag="yn-p-2026-000001X", person="p1",
                ts=(base + timedelta(milliseconds=i)).isoformat()))
        assert s.range_rfid.stats()["merged_reads"] == 2  # 后两次被归并
        flushed = s.range_rfid.flush()
        assert len(flushed) == 1

    def test_controller_to_ingest_to_domain(self):
        s = _mk_sys()
        gun = s.domain.manufacture(maker="云南西南", kind="手枪", year=2026, serial=1,
                                   legacy_no="N1", unit_id="unit:shooting", signer="u1")
        # 设备经网关上报出柜扫描
        kw = {"action": "out", "tag": gun.code, "person": "p1",
              "reader": "ch1", "ts": s.clock.now_iso()}
        env = s.device_gw.new_envelope("reader-ch1", {"protocol": "rfid", **kw})
        cmds = s.device_gw.ingest(env)
        assert cmds[0]["kind"] == "checkout"

        sigs = [
            {"signer": "p1", "role": "保管",
             "sig": s.kms.sign("user:p1", f"checkout:{gun.code}:p1".encode())},
            {"signer": "p2", "role": "监督",
             "sig": s.kms.sign("user:p2", f"checkout:{gun.code}:p1".encode())},
        ]
        ev = s.domain.checkout(gun_code=gun.code, person_id="p1", signers=sigs,
                               device_verified=True, location="ch1")
        s.pump()
        assert s.view.gun(gun.code)["status"] == "in_use"
        assert s.view.timeline(gun.code)[-1]["device_id"] == "cabinet-01"


class TestDeviceGatewayAntiReplay:
    def test_replay_nonce_rejected(self, s=None):
        s = s or _mk_sys()
        env = s.device_gw.new_envelope("reader-ch1", {"protocol": "rfid",
                                                      "action": "out", "tag": "G",
                                                      "person": "p1", "reader": "ch1",
                                                      "ts": s.clock.now_iso()})
        s.device_gw.ingest(env)               # 首次通过
        with pytest.raises(ReplayError):
            s.device_gw.ingest(env)           # nonce 重放 → 拒绝

    def test_sequence_rollback_rejected(self):
        s = _mk_sys()
        env1 = s.device_gw.new_envelope("reader-ch1", {"protocol": "rfid",
                                                       "action": "out", "tag": "G",
                                                       "person": "p1", "reader": "ch1",
                                                       "ts": s.clock.now_iso()})
        s.device_gw.ingest(env1)
        # 手工构造 seq 回退
        old = {**env1, "seq": int(env1["seq"]) - 1}
        with pytest.raises(ReplayError):
            s.device_gw.ingest(old)

    def test_unregistered_device_rejected(self):
        s = _mk_sys()
        env = {"device_id": "ghost", "timestamp": s.clock.now_iso(), "nonce": "x",
               "seq": 1, "signature": "sig", "body": {"protocol": "rfid"}}
        with pytest.raises(AuthenticationError):
            s.device_gw.ingest(env)

    def test_unknown_protocol_rejected(self):
        s = _mk_sys()
        env = s.device_gw.new_envelope("reader-ch1", {"protocol": "magic",
                                                      "action": "out", "tag": "G"})
        with pytest.raises(ValidationError):
            s.device_gw.ingest(env)


class TestOfflineTerminal:
    def test_offline_hash_chain_and_signature(self):
        clock = ManualClock(datetime(2026, 1, 2, 8, 0, 0, tzinfo=timezone.utc))
        terminal = OfflineTerminal("offterm-01", clock)
        terminal.record(event_type="use", gun_code="H001", actor="hunter-1",
                        position=(121.10, 30.20), location="猎区A")
        clock.advance(hours=2)
        terminal.record(event_type="use", gun_code="H001", actor="hunter-1",
                        position=(121.11, 30.21), location="猎区A")
        pkgs = terminal.upload()
        assert len(pkgs) == 2
        result = OfflineTerminal.verify_batch(pkgs, {"offterm-01": terminal.public_key})
        assert len(result["accepted"]) == 2, result["rejected"]

        # 篡改一条记录 → 拒绝
        pkgs[1]["position"][0] = 200.0
        result2 = OfflineTerminal.verify_batch(pkgs, {"offterm-01": terminal.public_key})
        assert len(result2["rejected"]) == 1
        assert any("篡改" in r["reason"] for r in result2["rejected"])

    def test_pending_time_flag(self):
        clock = ManualClock(datetime(2026, 1, 2, 8, 0, 0, tzinfo=timezone.utc))
        t = OfflineTerminal("offterm-02", clock)
        t.record(event_type="use", gun_code="H002", actor="hunter-2",
                 position=(121.0, 30.0), beidou_synced=False)   # 时钟未同步
        res = OfflineTerminal.verify_batch(t.upload(), {"offterm-02": t.public_key})
        assert len(res["accepted"]) == 1
        assert len(res["pending_time"]) == 1   # 双时间戳：标记待核验

    def test_multi_terminal_cross_check(self):
        """多终端互证：同伴记录吻合 → 通过；严重偏离 → 触发核查。"""
        clock = ManualClock(datetime(2026, 1, 2, 8, 0, 0, tzinfo=timezone.utc))
        a = OfflineTerminal("t-a", clock)
        b = OfflineTerminal("t-b", clock)
        a.record(event_type="use", gun_code="H003", actor="h1", position=(121.1, 30.2))
        b.record(event_type="use", gun_code="H003", actor="h2", position=(121.105, 30.205))
        res = OfflineTerminal.cross_check([a.upload(), b.upload()], space_tolerance_deg=0.01)
        assert res["consistent"]

        b2 = OfflineTerminal("t-b2", clock)
        b2.record(event_type="use", gun_code="H003", actor="h2", position=(180.0, -50.0))
        res2 = OfflineTerminal.cross_check([a.upload(), b2.upload()], space_tolerance_deg=0.01)
        assert not res2["consistent"]
        assert any("偏离" in f["reason"] for f in res2["flags"])


class TestScanReview:
    def test_autofill_and_dual_review(self):
        s = _mk_sys()
        gun = s.domain.manufacture(maker="云南西南", kind="手枪", year=2026, serial=9,
                                   legacy_no="SP-9", unit_id="unit:shooting",
                                   part_categories=["枪管"], signer="u1")
        s.pump()
        station = ScanReviewStation(s.view)
        fill = station.autofill(gun.code)
        assert fill["structured"]["code"] == gun.code
        assert fill["structured"]["legacy_no"] == "SP-9"

        with pytest.raises(ValidationError):
            station.build_confirm(gun_code=gun.code, action="use", operator="u1",
                                  reviewer="u1", operator_sig="s1", reviewer_sig="s2",
                                  confirm_fields={"manual": {"purpose": "训练"}})  # 同人复核
        confirm = station.build_confirm(gun_code=gun.code, action="use", operator="u1",
                                        reviewer="u-police", operator_sig="s1",
                                        reviewer_sig="s2",
                                        confirm_fields={"manual": {"purpose": "训练"}})
        assert confirm["operator"] != confirm["reviewer"]


class TestLegacyAndPrivacy:
    def test_legacy_mapping_signature(self):
        s = _mk_sys()
        m = s.legacy.mapping("YN-P-2026000001X", "GA1258-2026-0001")
        assert s.legacy.verify_mapping(m)
        m2 = dict(m, legacy_no="GA1258-2026-9999")
        assert not s.legacy.verify_mapping(m2)   # 篡改映射 → 验签失败

    def test_privacy_returns_only_conclusion(self):
        s = _mk_sys()
        s.privacy.enroll({"subject_id": "p1", "kind": "criminal_record",
                          "value": {"has_record": True, "expire_before": "2027-01-01"}})
        from gunreg.iam import Subject
        requester = Subject(user_id="u-police", name="民警", role="admin", org="police:zj")
        concl = s.privacy.verify(subject_id="p1", kind="criminal_record",
                                 condition={"has_record": True},
                                 requester=requester, purpose="持枪资格核验")
        assert concl["result"] is True
        assert "value" not in concl and "has_record" not in concl
        assert s.privacy.verify_signature(concl)

        # 有前科 → 核验不通过（不泄露原始记录内容）
        concl2 = s.privacy.verify(subject_id="p1", kind="criminal_record",
                                  condition={"has_record": False},
                                  requester=requester, purpose="持枪资格核验")
        assert concl2["result"] is False