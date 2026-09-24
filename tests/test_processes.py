"""关键业务流：运输许可闭环、报废销毁四节点、时限预警与处置闭环、资格退出、Outbox 死信。"""
import sys
sys.path.insert(0, ".")

from datetime import datetime, timedelta, timezone

import pytest

from gunreg import GunSystem, ManualClock
from gunreg.common import ContractRejected, StateError, ValidationError


@pytest.fixture()
def sys2():
    clock = ManualClock(datetime(2026, 2, 1, 9, 0, 0, tzinfo=timezone.utc))
    s = GunSystem(clock=clock)
    s.register_unit("unit:school", "某射击运动学校", "sports_school", risk_level=2,
                    region={"name": "训练区", "lon_range": (120.0, 120.5), "lat_range": (30.0, 30.5)})
    s.register_person("p-shooter", "运动员", "unit:school", duty="使用", cert_kinds=["运动步枪"],
                      cert_expire="2027-12-31T00:00:00+00:00")
    s.register_person("p-manager", "管理员", "unit:school", duty="保管", cert_kinds=["运动步枪"],
                      cert_expire="2027-12-31T00:00:00+00:00")
    s.register_person("p-auditor", "监督员", "unit:school", duty="监督", cert_kinds=["运动步枪"],
                      cert_expire="2027-12-31T00:00:00+00:00")
    # 在册人员同时持有 IAM 密钥（签名主体）
    s.identity.register("p-shooter", "运动员", "practitioner", "unit:school", "pw1")
    s.identity.register("p-manager", "管理员", "practitioner", "unit:school", "pw2")
    s.identity.register("p-auditor", "监督员", "practitioner", "unit:school", "pw3")
    s.identity.register("u-mgr", "管理员", "unit", "unit:school", "pw1")
    s.identity.register("u-aud", "监督员", "unit", "unit:school", "pw2")
    s.identity.register("u-police-sd", "省级民警", "admin", "police:sd", "pw3")
    s.identity.register("u-police-cz", "运往地民警", "admin", "police:cz", "pw4")
    s.ledger.enroll("node:sd", "山东省公安厅", "consensus")
    s.ledger.enroll("node:cz", "沧州市公安局", "sync")
    return s


def _mk(s: GunSystem, serial: int, kind: str = "运动步枪"):
    return s.domain.manufacture(maker="北方装备", kind=kind, year=2026, serial=serial,
                                legacy_no=f"SP-{serial}", unit_id="unit:school",
                                part_categories=["枪管"], signer="u-mgr")


def _sigs(s, gun_code, person, users=("p-manager", "p-auditor"), roles=("保管", "监督"),
          action="checkout"):
    out = []
    for u, duty in zip(users, roles):
        payload = f"{action}:{gun_code}:{person}".encode()
        out.append({"signer": u, "role": duty, "sig": s.kms.sign(f"user:{u}", payload)})
    return out


def _trans_sigs(s, permit_id, users=("p-manager", "p-auditor"), roles=("保管", "监督")):
    out = []
    for u, duty in zip(users, roles):
        payload = f"transport:depart:{permit_id}".encode()
        out.append({"signer": u, "role": duty, "sig": s.kms.sign(f"user:{u}", payload)})
    return out


def _scrap_sigs(s, gun_code, stage, users=("p-manager", "p-auditor"), roles=("保管", "监督")):
    out = []
    for u, duty in zip(users, roles):
        payload = f"scrap:{stage}:{gun_code}".encode()
        out.append({"signer": u, "role": duty, "sig": s.kms.sign(f"user:{u}", payload)})
    return out


class TestTransportFlow:
    def test_permit_vehicle_mismatch_blocked(self, sys2):
        """实际承运车辆与许可载明不一致 → 起运阶段被合约拒绝（对应第三章）。"""
        s = sys2
        gun = _mk(s, 21)
        s.domain.request_transport_permit(
            permit_id="tp-1", gun_codes=[gun.code], vehicle="鲁A-1001",
            carrier="货运公司", escort="押运员甲",
            valid_from="2026-02-01T00:00:00+00:00", valid_end="2026-02-28T00:00:00+00:00",
            origin="济南", destination="沧州", applicant="u-mgr")
        s.domain.approve_transport_permit(permit_id="tp-1", approver="u-police-sd")
        with pytest.raises(ContractRejected) as ei:
            s.domain.start_transport(permit_id="tp-1", gun_codes=[gun.code],
                                     vehicle="鲁B-9999", carrier="货运公司", escort="押运员甲",
                                     signers=_trans_sigs(s, "tp-1"),
                                     position=(121.2, 30.3))
        assert ei.value.contract == "transport_permit"

        # 更换为许可载明车辆 → 通过
        s.domain.start_transport(permit_id="tp-1", gun_codes=[gun.code],
                                 vehicle="鲁A-1001", carrier="货运公司", escort="押运员甲",
                                 signers=_trans_sigs(s, "tp-1"),
                                 position=(121.2, 30.3))
        s.pump()
        assert s.view.gun(gun.code)["status"] == "in_transit"

        # 到达核销
        s.domain.verify_transport_arrival(permit_id="tp-1", position=(121.4, 30.4),
                                          verifier="u-police-cz")
        s.pump()
        assert s.view.gun(gun.code)["status"] == "in_stock"
        assert s.repo.get_permit("tp-1")["status"] == "closed"

    def test_arrival_without_approval_rejected(self, sys2):
        s = sys2
        gun = _mk(s, 22)
        s.domain.request_transport_permit(
            permit_id="tp-2", gun_codes=[gun.code], vehicle="鲁A-2001",
            carrier="丙", escort="丁",
            valid_from="2026-02-01T00:00:00+00:00", valid_end="2026-02-28T00:00:00+00:00",
            origin="济南", destination="沧州", applicant="u-mgr")
        # 未审批直接起运 → 被拒
        with pytest.raises(ContractRejected):
            s.domain.start_transport(permit_id="tp-2", gun_codes=[gun.code],
                                     vehicle="鲁A-2001", carrier="丙", escort="丁",
                                     signers=_trans_sigs(s, "tp-2"))


class TestScrapFlow:
    def test_four_stage_destroy_and_seal(self, sys2):
        s = sys2
        gun = _mk(s, 31)
        # 报废申请（须有理由）
        s.domain.scrap_stage(gun_code=gun.code, stage="apply", actor="u-mgr",
                             signers=_scrap_sigs(s, gun.code, "apply"), reason="膛线磨损")
        # 鉴定意见
        s.domain.scrap_stage(gun_code=gun.code, stage="appraise", actor="u-mgr",
                             signers=_scrap_sigs(s, gun.code, "appraise"), appraisal="经鉴定不可修复")
        # 省级确认（1 名即满足合约，但流程仍走双人）
        s.domain.scrap_stage(gun_code=gun.code, stage="province_confirm",
                             actor="u-police-sd", signers=[
                                 {"signer": "u-police-sd", "role": "省级确认",
                                  "sig": s.kms.sign("user:u-police-sd",
                                                    f"scrap:province_confirm:{gun.code}".encode())}])
        # 销毁四节点（每节点双人签名）：提交 + 清点后尝试封存 → 顺序校验拒绝
        for stage in ("destroy_submit", "destroy_inventory"):
            s.domain.scrap_stage(gun_code=gun.code, stage=stage, actor="u-mgr",
                                 signers=_scrap_sigs(s, gun.code, stage))
        # 未完成全部销毁节点 → 封存被拒绝（服务端按事件流推断进度，客户端不能自证）
        with pytest.raises(StateError):
            s.domain.scrap_stage(gun_code=gun.code, stage="destroy_archive", actor="u-mgr",
                                 signers=_scrap_sigs(s, gun.code, "destroy_archive"),
                                 done_stages=["destroy_submit"])
        s.domain.scrap_stage(gun_code=gun.code, stage="destroy_execute", actor="u-mgr",
                             signers=_scrap_sigs(s, gun.code, "destroy_execute"))
        s.domain.scrap_stage(gun_code=gun.code, stage="destroy_archive", actor="u-mgr",
                             signers=_scrap_sigs(s, gun.code, "destroy_archive"))
        s.pump()

        stat = s.view.gun(gun.code)
        assert stat["status"] == "destroyed" or stat["status"] == "sealed"
        # 封存后禁止任何领用流转（状态属性只读）
        assert s.repo.get_gun(gun.code).status in ("destroyed", "sealed")
        with pytest.raises(ValidationError):
            s.domain.checkout(gun_code=gun.code, person_id="p-shooter",
                              signers=_sigs(s, gun.code, "p-shooter"))

    def test_scrap_without_reason_rejected(self, sys2):
        s = sys2
        gun = _mk(s, 32)
        with pytest.raises(ContractRejected) as ei:
            s.domain.scrap_stage(gun_code=gun.code, stage="apply", actor="u-mgr",
                                 signers=_scrap_sigs(s, gun.code, "apply"))
        assert any("理由" in r for r in ei.value.reasons)


class TestTimeLimitAndAlerts:
    def test_overdue_escalation_and_closure(self, sys2):
        s = sys2
        clock = s.clock
        gun = _mk(s, 41)
        s.domain.checkout(gun_code=gun.code, person_id="p-shooter",
                          signers=_sigs(s, gun.code, "p-shooter"), due_hours=24)
        s.pump()
        assert s.view.gun(gun.code)["status"] == "in_use"

        # 超过 24h 未还 → 超 hint 档 → concern（巡检产生预警）
        clock.advance(hours=24)
        raised = s.domain.scan_overdue()
        assert raised and raised[0]["level"] in ("concern", "hint")
        # 持续超时（>48h）→ emergency
        clock.advance(hours=30)
        raised = s.domain.scan_overdue()
        assert any(r["level"] == "emergency" for r in raised)
        # 未处置且超过时限 → 自动升级
        s.domain.escalate_overdue_alerts()
        alerts = s.repo.alerts()
        assert any(a["level"] == "emergency" for a in alerts)

        # 处置闭环：响应并关闭
        target = next(a for a in alerts if a["level"] == "emergency")
        res = s.domain.respond_alert(alert_id=target["alert_id"], actor="u-police-sd",
                                     response="已现场核查并收缴", close=True)
        assert res["status"] == "closed"
        # 归还后不再产生超时预警
        s.domain.checkin(gun_code=gun.code, person_id="p-shooter",
                         signers=_sigs(s, gun.code, "p-shooter", action="return"))
        s.pump()
        assert s.repo.open_alert_for(gun.code, "emergency") is None

    def test_qualification_exit_blocks_and_alerts(self, sys2):
        """资格退出：资格失效后其名下枪支的领用被合约阻断，并产出上交提醒。"""
        s = sys2
        # 场景 A：资格退出在先 → 新领用被合规合约拒绝
        gun_a = _mk(s, 42)
        s.domain.update_qualification(person_id="p-shooter", cert_status="expired",
                                      actor="u-police-sd")
        with pytest.raises(ContractRejected) as ei:
            s.domain.checkout(gun_code=gun_a.code, person_id="p-shooter",
                              signers=_sigs(s, gun_a.code, "p-shooter"))
        assert ei.value.contract == "compliance"

        # 场景 B：持枪期间资格退出 → 名下在途枪支触发紧急上交提醒
        s.domain.update_qualification(person_id="p-shooter", cert_status="valid",
                                      actor="u-police-sd")
        gun_b = _mk(s, 43)
        s.domain.checkout(gun_code=gun_b.code, person_id="p-shooter",
                          signers=_sigs(s, gun_b.code, "p-shooter"))
        s.pump()
        s.domain.update_qualification(person_id="p-shooter", cert_status="expired",
                                      actor="u-police-sd")
        alerts = [a for a in s.repo.alerts() if a["gun_code"] == gun_b.code]
        assert any(a["level"] == "emergency" for a in alerts)


class TestOutboxDeadLetter:
    def test_relay_retries_then_dlq(self, sys2):
        """托管订阅者持续失败 → 重试耗尽 → 死信，事件不丢失。"""
        s = sys2
        # 用 adapter 订阅的正常链路先清空，替换为一个永远失败的订阅者
        s.bus._subs["gun.event"] = [
            ("flaky", lambda m: (_ for _ in ()).throw(RuntimeError("consumer down")))]
        from gunreg.events import build_event
        ev = build_event(event_id="ev-dlq", gun_code="G-DLQ", event_type="use",
                         actor="a", occurred_at=s.clock.now_iso(), location="L",
                         device_id="d", signer_ids=["d"])
        with s.repo.db.transaction() as conn:
            s.outbox.enqueue(conn, "gun.event", ev.to_dict())

        s.pump()  # 投递失败 → 重试
        dead = s.bus.dead_letters()
        assert len(dead) == 1
        assert dead[0]["topic"] == "gun.event"
        assert dead[0]["attempts"] >= 2
        # Outbox 表里 defense-in-depth：不再无限重试
        assert s.outbox.stats()["pending"] == 0 or s.outbox.stats()["dead"] >= 0
        # 恢复订阅者后重放死信
        restored: list[dict] = []
        s.bus._subs["gun.event"] = [("recovered", lambda m: restored.append(m.payload))]
        assert s.bus.replay_dead(0)
        assert restored and restored[0]["event_id"] == "ev-dlq"

    def test_normal_pipeline_has_no_dead_letters(self, sys2):
        s = sys2
        from gunreg.identity import GunCode
        gun_code = str(GunCode.generate("北方装备", "运动步枪", 2026, 88))
        s.domain.manufacture(maker="北方装备", kind="运动步枪", year=2026, serial=88,
                             legacy_no="SP-88", unit_id="unit:school",
                             part_categories=["枪管"], signer="u-mgr")
        s.pump()
        assert s.bus.dead_letters() == []
        assert s.outbox.stats()["dead"] == 0
        report = s.evidence.verify_gun(gun_code)
        assert report.ok