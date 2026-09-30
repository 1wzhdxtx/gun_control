"""跨部门协同审批 + 一枪一档 + 监督检查 + 进出境（五类场景主线）。

分两层：
- 域层（进程内 GunSystem）：审批规则可配置（第九条 / 第十五条口径分离）· 部门链权限 ·
  多步会签 · 退回补正 · 前置条件（配售登记、企业证照）· 监督检查三态闭环 ·
  贸易 / 携带两种进出境情形 · 一枪一档节点与记录字段 · 全生命周期总览 · 重启可追溯。
- Webapp API 层（TestClient 真实接口）：部门账号分权办理（不可通用管理员包办）·
  单位数据域 · 缺件补正回路 · 前置条件在后台阻止后续业务（领用 / 进出境）。

API 层数据目录在导入 webapp.main 之前指定为独立临时目录，绝不触碰 webapp/data。
"""
import os
import sys
import tempfile
from datetime import datetime, timezone

# 必须在导入 webapp.main 之前设置：
# 本模块字母序先于 test_security 被收集，为整个 pytest 会话提供独立临时数据目录。
os.environ.setdefault("GUNREG_DATA_DIR", tempfile.mkdtemp(prefix="gunreg-bureau-"))
os.environ["GUNREG_RESET"] = "1"

sys.path.insert(0, ".")

import pytest  # noqa: E402

from gunreg import GunSystem, ManualClock  # noqa: E402
from gunreg.bureau import (  # noqa: E402
    AGENCIES,
    APPROVAL_RULES,
    SCENARIOS,
    PIPELINE_KEYS,
    PIPELINE_NAMES,
    BureauService,
    agency_of_org,
)
from gunreg.common import (  # noqa: E402
    NotFoundError,
    PermissionDenied,
    StateError,
    ValidationError,
)

NODE_STATUSES = {"已完成", "办理中", "待办理", "退回补正", "不适用"}
RECORD_FIELDS = ("matter", "applicant", "agency", "handler", "at", "opinion",
                 "license", "attachments", "evidence_no", "source", "status")


# ---------------------------------------------------------------------------
# 域层 fixture：两单位（射击场 + 制造企业）
# ---------------------------------------------------------------------------
@pytest.fixture()
def s0():
    clock = ManualClock(datetime(2026, 5, 1, 9, 0, tzinfo=timezone.utc))
    s = GunSystem(clock=clock)
    s.register_unit("unit:range-a", "某射击场", "shooting_range", risk_level=2)
    s.register_unit("unit:mfg-a", "某制造企业", "manufacture", risk_level=2)
    s.identity.register("u-rng", "射击场管理员", "unit", "unit:range-a", "pw")
    return s


def _mk(s: GunSystem, serial: int = 1, kind: str = "手枪"):
    return s.domain.manufacture(maker="云南西南", kind=kind, year=2026, serial=serial,
                                legacy_no=f"GA26-{serial:06d}", unit_id="unit:range-a",
                                part_categories=["枪管", "撞针"], signer="u-rng")


def _issue(s: GunSystem, matter: str, unit: str, *, handler: str = "op",
           gun_codes: list[str] | None = None,
           materials: list[str] | None = None,
           app_id: str | None = None) -> dict:
    """走完整部门链办结一个事项，返回申请视图（含签发的证照）。"""
    b = s.bureau
    rule = APPROVAL_RULES[matter]
    app = b.apply(matter=matter, applicant_unit=unit, gun_codes=gun_codes,
                  materials=(list(rule["materials"]) if materials is None
                             else materials), app_id=app_id)
    for step in rule["chain"]:
        app = b.process(app["app_id"], agency_id=step["agency"], handler=handler,
                        action="approve")
    return app


def _sale_certs(s: GunSystem, seller: str = "unit:mfg-a",
                buyer: str = "unit:range-a") -> tuple[str, str]:
    """签发配售双方资质：卖方制造许可证 + 买方配置单位资质（返回证照号）。"""
    lic_seller = _issue(s, "manufacture_license", seller)["license_id"]
    lic_buyer = _issue(s, "unit_qualification", buyer)["license_id"]
    return lic_seller, lic_buyer


# ---------------------------------------------------------------------------
# 1. 规则可配置：审批口径分离 / 部门登记 / 五类场景
# ---------------------------------------------------------------------------
class TestRuleConfig:
    def test_twelve_rules_and_categories(self):
        assert len(APPROVAL_RULES) == 12
        cats = {r["category"] for r in APPROVAL_RULES.values()}
        assert cats == {"资质审批", "计划备案", "配购配售", "进出境"}

    def test_legal_bases_not_merged(self):
        """第十五条（制造/配售许可分开发证）与第九条（林业批准 + 两级公安核发配购证）不可合并。"""
        mfg = APPROVAL_RULES["manufacture_license"]
        sale = APPROVAL_RULES["sale_license"]
        hunt = APPROVAL_RULES["hunt_config"]
        # 制造许可：国务院公安部门核发（第十五条），与配售许可分开建项
        assert [s["agency"] for s in mfg["chain"]] == ["police-national"]
        assert mfg["license_type"] == "mfg_license"
        assert "第十五条" in mfg["legal"] and "国务院公安部门" in mfg["legal"]
        assert "林业" not in mfg["legal"]
        # 配售许可：省级公安机关核发（第十五条），证照类型独立
        assert [s["agency"] for s in sale["chain"]] == ["police-province"]
        assert sale["license_type"] == "sale_license"
        assert "第十五条" in sale["legal"] and "省" in sale["legal"]
        assert "林业" not in sale["legal"]
        assert mfg["license_type"] != sale["license_type"]
        # 狩猎场配购（第九条）：林业批准在前 → 省级公安审批 → 市级公安核发
        assert [s["agency"] for s in hunt["chain"]] == [
            "forestry", "police-province", "police-city"]
        assert "第九条" in hunt["legal"] and "林业行政主管部门" in hunt["legal"]
        assert "设区的市级" in hunt["legal"]
        assert "林业主管部门批准文件" in hunt["materials"]

    def test_agency_registry_and_org_mapping(self):
        assert set(AGENCIES) == {"police-national", "police-province",
                                 "police-city", "forestry", "sports", "customs"}
        assert AGENCIES["police-national"]["group"] == "police"
        assert agency_of_org("police:national") == "police-national"
        assert agency_of_org("police:province") == "police-province"
        assert agency_of_org("police:bureau-01") == "police-city"
        assert agency_of_org("dept:forestry") == "forestry"
        assert agency_of_org("dept:sports") == "sports"
        assert agency_of_org("dept:customs") == "customs"
        assert agency_of_org("range-a") is None      # 非部门账号无办理权

    def test_matters_by_group(self):
        m = BureauService.matters_of_group
        assert {"manufacture_license", "sale_license", "hunt_config",
                "airport_plan"} <= m("police")
        assert "sport_plan" not in m("police")       # 体育事项不由公安办理
        assert "hunt_config" in m("forestry")
        assert "manufacture_license" not in m("forestry")
        assert "sale_license" not in m("forestry")
        assert "border_trade_out" in m("customs")
        assert "wildlife_plan" in m("forestry")

    def test_five_scenarios_and_seven_stages(self):
        assert set(SCENARIOS) == {"hunt", "sport", "airport", "wildlife", "range"}
        assert SCENARIOS["hunt"]["name"] == "民用猎枪"
        # 场景是业务入口，不替代枪械类型字段（各场景带业务信息字段）
        assert all(v.get("fields") for v in SCENARIOS.values())
        # 机场驱鸟适用规定标注待核实（字段由场景信息承载）
        assert "适用规定" in SCENARIOS["airport"]["fields"]
        assert PIPELINE_KEYS == ("enterprise", "manufacture", "sale", "transport",
                                 "use", "scrap", "border")
        assert PIPELINE_NAMES["sale"] == "配购与配售"


# ---------------------------------------------------------------------------
# 2. 部门链审批：逐部门办理 / 越权拒绝 / 补正闭环 / 退回
# ---------------------------------------------------------------------------
class TestApprovalChain:
    def test_multi_step_chain_needs_each_agency(self, s0):
        b = s0.bureau
        mats = list(APPROVAL_RULES["hunt_config"]["materials"])
        app = b.apply(matter="hunt_config", applicant_unit="unit:range-a",
                      materials=mats, title="狩猎场配置猎枪")
        assert app["status"] == "pending" and app["current_step"] == 0

        # 越权：省级公安不能替林业先批第一步
        with pytest.raises(PermissionDenied, match="林业"):
            b.process(app["app_id"], agency_id="police-province",
                      handler="admin2", action="approve")
        # 体育部门同样无权办理林草节点
        with pytest.raises(PermissionDenied):
            b.process(app["app_id"], agency_id="sports",
                      handler="sports1", action="approve")

        # 第一步：省林业和草原局出具批准文件
        app = b.process(app["app_id"], agency_id="forestry", handler="forestry1",
                        action="approve", opinion="狩猎区范围符合规定")
        assert app["status"] == "pending" and app["current_step"] == 1
        assert app["steps"][0]["handler"] == "forestry1"

        # 第二步：省级公安机关审批（第九条），尚未核发
        app = b.process(app["app_id"], agency_id="police-province", handler="admin2",
                        action="approve", opinion="依据第九条报省级公安机关审批通过")
        assert app["status"] == "pending" and app["current_step"] == 2
        assert app["license"] is None

        # 第三步：设区的市级公安机关核发配购证件（第九条）
        app = b.process(app["app_id"], agency_id="police-city", handler="admin1",
                        action="approve", opinion="依据第九条核发配购证件")
        assert app["status"] == "approved"
        assert app["license"]["license_type"] == "purchase_permit"
        assert app["license"]["holder_unit"] == "unit:range-a"

        # 已结办不可再办
        with pytest.raises(StateError):
            b.process(app["app_id"], agency_id="police-city",
                      handler="admin1", action="approve")

    def test_supplement_roundtrip(self, s0):
        b = s0.bureau
        full = list(APPROVAL_RULES["hunt_config"]["materials"])
        partial = [m for m in full if m != "林业主管部门批准文件"]
        app = b.apply(matter="hunt_config", applicant_unit="unit:range-a",
                      materials=partial)
        assert app["status"] == "supplement"
        assert app["missing"] == ["林业主管部门批准文件"]

        # 缺件状态不可办理
        with pytest.raises(StateError, match="补正"):
            b.process(app["app_id"], agency_id="forestry",
                      handler="forestry1", action="approve")
        # 未补齐仍为补正
        app = b.resubmit(app["app_id"], materials=partial)
        assert app["status"] == "supplement"
        # 补齐 → 回到部门审批链
        app = b.resubmit(app["app_id"], materials=full)
        assert app["status"] == "pending" and app["missing"] == []

        app = b.process(app["app_id"], agency_id="forestry",
                        handler="forestry1", action="approve")
        app = b.process(app["app_id"], agency_id="police-province",
                        handler="admin2", action="approve")
        app = b.process(app["app_id"], agency_id="police-city",
                        handler="admin1", action="approve")
        assert app["status"] == "approved"

    def test_department_supplement_requires_materials(self, s0):
        """办理部门也可退回补正并指定缺件。"""
        b = s0.bureau
        mats = list(APPROVAL_RULES["hunt_config"]["materials"])
        app = b.apply(matter="hunt_config", applicant_unit="unit:range-a",
                      materials=mats)
        app = b.process(app["app_id"], agency_id="forestry", handler="forestry1",
                        action="supplement", opinion="请补充库室面积证明",
                        materials=[m for m in mats if m != "库室与保管条件证明"])
        assert app["status"] == "supplement"
        assert "库室与保管条件证明" in app["missing"]

    def test_reject_returns_to_applicant(self, s0):
        b = s0.bureau
        mats = list(APPROVAL_RULES["manufacture_license"]["materials"])
        app = b.apply(matter="manufacture_license", applicant_unit="unit:mfg-a",
                      materials=mats)
        app = b.process(app["app_id"], agency_id="police-national",
                        handler="mps1", action="reject", opinion="材料不实")
        assert app["status"] == "rejected"
        assert app["status_label"] == "退回"
        with pytest.raises(StateError):
            b.process(app["app_id"], agency_id="police-national",
                      handler="mps1", action="approve")

    def test_dept_specified_material_survives_resubmit(self, s0):
        """部门另行指定的补正材料：原样重交不能过关，链视图经办人不错位。"""
        b = s0.bureau
        mats = list(APPROVAL_RULES["hunt_config"]["materials"])
        app = b.apply(matter="hunt_config", applicant_unit="unit:range-a",
                      materials=mats)
        # 林业节点批准后，省级公安退回补正并指定规则清单外的材料
        app = b.process(app["app_id"], agency_id="forestry", handler="forestry1",
                        action="approve")
        app = b.process(app["app_id"], agency_id="police-province", handler="admin2",
                        action="supplement", opinion="补开无重大违纪记录证明",
                        materials=mats + ["办理部门指定的补正材料"])
        assert app["status"] == "supplement"
        assert "办理部门指定的补正材料" in app["missing"]
        # 原样重交 → 仍为补正（缺件清单随轮次传递）
        app = b.resubmit(app["app_id"], materials=mats)
        assert app["status"] == "supplement"
        assert "办理部门指定的补正材料" in app["missing"]
        # 补交指定材料 → 回到审批链（当前节点仍为省级公安，不退回林业）
        app = b.resubmit(app["app_id"],
                         materials=mats + ["办理部门指定的补正材料"])
        assert app["status"] == "pending" and app["missing"] == []
        assert app["current_step"] == 1
        # 链视图按 step_index 对位：林业节点显示 forestry1，而不是错位
        chain = app["chain"]
        assert chain[0]["handler"] == "forestry1" and chain[0]["status"] == "已完成"
        assert chain[1]["status"] == "办理中"
        # 省级批准后 → 市级核发，经办人仍按节点对位
        app = b.process(app["app_id"], agency_id="police-province", handler="admin2",
                        action="approve")
        app = b.process(app["app_id"], agency_id="police-city", handler="admin1",
                        action="approve")
        assert app["status"] == "approved"
        assert [n["handler"] for n in app["chain"]] == ["forestry1", "admin2",
                                                        "admin1"]
        assert all(n["status"] == "已完成" for n in app["chain"])


# ---------------------------------------------------------------------------
# 3. 前置条件：配售登记 / 企业证照
# ---------------------------------------------------------------------------
class TestPreconditions:
    def test_sale_required_before_downstream(self, s0):
        b = s0.bureau
        gun = _mk(s0)
        with pytest.raises(ValidationError, match="前置条件未满足"):
            b.require_sale([gun.code], "运输申报")
        # 配售登记须双方资质 + 关联有效证照（P1-2）
        lic_seller, _ = _sale_certs(s0)
        b.create_sale(sale_id="SALE-T1", seller_unit="unit:mfg-a",
                      buyer_unit="unit:range-a", gun_codes=[gun.code],
                      license_id=lic_seller,
                      scenario="range", note="测试配售")
        # 通过后不再抛错（无返回值）
        assert b.require_sale([gun.code], "运输申报") is None
        # 其他枪仍被拦
        gun2 = _mk(s0, serial=2)
        with pytest.raises(ValidationError, match="前置条件未满足"):
            b.require_sale([gun.code, gun2.code], "运输申报")

    def test_sale_validations_reject_bypass(self, s0):
        """P1-2：配售登记不得绕过审批与所有权（多组负例）。"""
        b = s0.bureau
        gun = _mk(s0)
        # (1) 买方单位不存在
        with pytest.raises(NotFoundError, match="单位不存在"):
            b.create_sale(sale_id="S-N1", seller_unit="unit:mfg-a",
                          buyer_unit="unit:nope", gun_codes=[gun.code])
        # (2) 枪支不归属任何当事方
        s0.register_unit("unit:other", "第三方单位", "shooting_range")
        s0.repo.db.execute("UPDATE guns SET unit_id='unit:other' WHERE code=?",
                           (gun.code,))
        lic_seller, lic_buyer = _sale_certs(s0)
        with pytest.raises(PermissionDenied, match="归属"):
            b.create_sale(sale_id="S-N2", seller_unit="unit:mfg-a",
                          buyer_unit="unit:range-a", gun_codes=[gun.code],
                          license_id=lic_seller)
        s0.repo.db.execute("UPDATE guns SET unit_id='unit:range-a' WHERE code=?",
                           (gun.code,))
        # (3) 卖方无制造/配售许可 → 前置条件拦截
        b.db.execute("UPDATE bureau_licenses SET status='revoked' "
                     "WHERE license_id=?", (lic_seller,))
        with pytest.raises(ValidationError, match="配售方"):
            b.create_sale(sale_id="S-N3", seller_unit="unit:mfg-a",
                          buyer_unit="unit:range-a", gun_codes=[gun.code],
                          license_id=lic_seller)
        b.db.execute("UPDATE bureau_licenses SET status='active' "
                     "WHERE license_id=?", (lic_seller,))
        # (4) 未关联证照 → 不予受理
        with pytest.raises(ValidationError, match="须关联有效证照"):
            b.create_sale(sale_id="S-N4", seller_unit="unit:mfg-a",
                          buyer_unit="unit:range-a", gun_codes=[gun.code])
        # (5) 证照持证方非当事方 → 拒绝
        other_app = _issue(s0, "manufacture_license", "unit:other")
        with pytest.raises(PermissionDenied, match="持证单位"):
            b.create_sale(sale_id="S-N5", seller_unit="unit:mfg-a",
                          buyer_unit="unit:range-a", gun_codes=[gun.code],
                          license_id=other_app["license_id"])
        # (6) 关联配购审批未办结 → 拒绝
        partial = [m for m in APPROVAL_RULES["hunt_config"]["materials"]
                   if m != "林业主管部门批准文件"]
        pa = b.apply(matter="hunt_config", applicant_unit="unit:range-a",
                     materials=partial)
        assert pa["status"] == "supplement"
        with pytest.raises(ValidationError, match="未完成"):
            b.create_sale(sale_id="S-N6", seller_unit="unit:mfg-a",
                          buyer_unit="unit:range-a", gun_codes=[gun.code],
                          license_id=lic_seller, purchase_app_id=pa["app_id"])
        # (7) 合法情形：双方资质齐全 + 有效证照 → 登记成功
        sale = b.create_sale(sale_id="S-OK", seller_unit="unit:mfg-a",
                             buyer_unit="unit:range-a", gun_codes=[gun.code],
                             license_id=lic_seller, note="合规配售")
        assert sale["sale_id"] == "S-OK" and sale["gun_codes"] == [gun.code]
        assert b.require_sale([gun.code], "运输申报") is None
        _ = lic_buyer

    def test_buyer_purchase_authorization_must_cover_guns(self, s0):
        """P1-1：买方须有"覆盖本次枪支"的配购授权——证照类型对 ≠ 本次授权。"""
        b = s0.bureau
        gun_ok = _mk(s0, serial=21)      # 买方资质明确覆盖
        gun_out = _mk(s0, serial=22)     # 不在买方资质范围
        lic_seller = _issue(s0, "manufacture_license", "unit:mfg-a")["license_id"]
        # 买方配置资质只覆盖 gun_ok（显式枪支清单）
        _issue(s0, "unit_qualification", "unit:range-a", gun_codes=[gun_ok.code])
        # 无配购审批：授权范围内的枪 → 登记成功
        s1 = b.create_sale(sale_id="S-AUTH-1", seller_unit="unit:mfg-a",
                           buyer_unit="unit:range-a", gun_codes=[gun_ok.code],
                           license_id=lic_seller, note="授权范围内")
        assert s1["sale_id"] == "S-AUTH-1"
        # 评审复现：只引用卖方配售许可证、不填配购申请编号，
        # 但枪支不在买方配购授权范围 → 拒绝
        with pytest.raises(ValidationError, match="配购授权"):
            b.create_sale(sale_id="S-AUTH-2", seller_unit="unit:mfg-a",
                          buyer_unit="unit:range-a", gun_codes=[gun_out.code],
                          license_id=lic_seller, note="授权范围外")
        # 已批准且覆盖该枪的配购审批 → 放行
        pa = _issue(s0, "hunt_config", "unit:range-a", gun_codes=[gun_out.code])
        s2 = b.create_sale(sale_id="S-AUTH-3", seller_unit="unit:mfg-a",
                           buyer_unit="unit:range-a", gun_codes=[gun_out.code],
                           license_id=lic_seller, purchase_app_id=pa["app_id"])
        assert s2["purchase_app_id"] == pa["app_id"]
        # 配购审批的申请单位必须是买方（"买方本次配购授权"）
        other_pa = _issue(s0, "hunt_config", "unit:mfg-a",
                          gun_codes=[gun_out.code])
        with pytest.raises(ValidationError, match="申请单位"):
            b.create_sale(sale_id="S-AUTH-4", seller_unit="unit:mfg-a",
                          buyer_unit="unit:range-a", gun_codes=[gun_out.code],
                          license_id=lic_seller, purchase_app_id=other_pa["app_id"])

    def test_sale_handover_transfers_ownership_and_events(self, s0):
        """P1-2：配售登记即交接确认——归属过户 + 事件记录 + 查询视图同步。"""
        b = s0.bureau
        gun = _mk(s0, serial=31)
        # 枪支在卖方（制造企业）库存名下
        s0.repo.db.execute("UPDATE guns SET unit_id='unit:mfg-a' WHERE code=?",
                           (gun.code,))
        lic_seller = _issue(s0, "manufacture_license", "unit:mfg-a")["license_id"]
        _issue(s0, "unit_qualification", "unit:range-a")   # 买方资质（不限枪支）
        b.create_sale(sale_id="S-HAND", seller_unit="unit:mfg-a",
                      buyer_unit="unit:range-a", gun_codes=[gun.code],
                      license_id=lic_seller, note="交付登记", actor="u-rng")
        # 业务台账：归属移交买方（此前仅新增配售记录，买方档案 403）
        row = s0.repo.db.one("SELECT unit_id FROM guns WHERE code=?", (gun.code,))
        assert row["unit_id"] == "unit:range-a"
        # 事件记录：交接事件入链（带操作签名）
        evs = s0.repo.events_of(gun.code)
        assert evs[-1].event_type == "transfer"
        assert evs[-1].payload["unit"] == "unit:range-a"
        assert evs[-1].payload["from_unit"] == "unit:mfg-a"
        assert evs[-1].signatures
        # 查询视图：泵送后时间线与台账投影同步
        s0.pump()
        tl = s0.view.timeline(gun.code)
        assert any(e["event_type"] == "transfer" for e in tl)
        st = s0.view.db.one("SELECT unit FROM gun_state WHERE gun_code=?",
                            (gun.code,))
        assert st["unit"] == "unit:range-a"
        # 证据核验：交接过户事件上链覆盖
        rep = s0.evidence.verify_gun(gun.code)
        assert rep.ok, rep.checks

    def test_license_required_before_manufacture(self, s0):
        b = s0.bureau
        with pytest.raises(ValidationError, match="前置条件未满足"):
            b.require_license("unit:mfg-a", "mfg_license", "制造赋码")
        # 制造许可由国务院公安部门核发（第十五条）后放行
        app = _issue(s0, "manufacture_license", "unit:mfg-a", handler="mps1")
        assert app["status"] == "approved"
        lic = b.require_license("unit:mfg-a", "mfg_license", "制造赋码")
        assert lic["license_id"] == app["license_id"]
        assert lic["status"] == "active"
        assert lic["valid_to"] >= "2026-05-01"

        # 未办证照的单位仍然被拦
        with pytest.raises(ValidationError, match="前置条件未满足"):
            b.require_license("unit:range-a", "mfg_license", "制造赋码")

    def test_manufacture_requires_approved_plan(self, s0):
        """P2-4：制造赋码须有已批准的生产计划（批次备案 + 数量未用完）。"""
        b = s0.bureau
        # 无计划 → 拦
        with pytest.raises(ValidationError, match="生产计划"):
            b.require_plan("unit:mfg-a")
        # 批准生产计划 → 自动生成计划记录（批次与数量取自申请单）
        mats = list(APPROVAL_RULES["production_plan"]["materials"])
        app = b.apply(matter="production_plan", applicant_unit="unit:mfg-a",
                      materials=mats, title="2026 年度生产计划 · 批次 B-TEST",
                      batch_ref="B-TEST", planned_qty=2)
        app = b.process(app["app_id"], agency_id="police-city", handler="admin1",
                        action="approve")
        assert app["status"] == "approved"
        plans = b.plans("unit:mfg-a")
        assert len(plans) == 1
        assert plans[0]["batch_ref"] == "B-TEST" and plans[0]["planned_qty"] == 2
        # 重复批准不重复建计划（幂等）
        with pytest.raises(StateError):
            b.process(app["app_id"], agency_id="police-city", handler="admin1",
                      action="approve")
        assert len(b.plans("unit:mfg-a")) == 1
        # 未备案批次 → 拦
        with pytest.raises(ValidationError, match="批次"):
            b.require_plan("unit:mfg-a", batch_ref="B-OTHER")
        # 赋码 2 支后数量用完 → 拦
        p = b.require_plan("unit:mfg-a")
        assert p["batch_ref"] == "B-TEST"
        b.consume_plan(p["plan_id"], "GUN-1")
        p = b.require_plan("unit:mfg-a")
        b.consume_plan(p["plan_id"], "GUN-2")
        p = b.get_plan(p["plan_id"])
        assert p["gun_codes"] == ["GUN-1", "GUN-2"]
        with pytest.raises(ValidationError, match="数量已用完"):
            b.require_plan("unit:mfg-a")
        # 其他单位无计划仍被拦
        with pytest.raises(ValidationError, match="生产计划"):
            b.require_plan("unit:range-a")


# ---------------------------------------------------------------------------
# 4. 监督检查：检查 → 整改 → 复查 三态闭环 + 部门权限
# ---------------------------------------------------------------------------
class TestInspectionLoop:
    def test_three_state_loop_and_department_rights(self, s0):
        b = s0.bureau
        insp = b.create_inspection(
            agency_id="forestry", inspector="forestry1",
            target_unit="unit:range-a",
            findings=["二号库室视频监控存在盲区"],
            deadline="2026-05-20T00:00:00+00:00")
        assert insp["status"] == "pending_fix"
        assert insp["status_label"] == "待整改"

        # 他人单位不能代整改
        with pytest.raises(PermissionDenied):
            b.rectify(insp["insp_id"], note="已整改", actor_unit="unit:other")
        # 被检查单位提交整改
        insp = b.rectify(insp["insp_id"], note="已加装摄像头并复核台账",
                         actor_unit="unit:range-a")
        assert insp["status"] == "recheck" and insp["status_label"] == "待复查"

        # 复查须由原检查部门执行
        with pytest.raises(PermissionDenied, match="原检查部门"):
            b.recheck(insp["insp_id"], agency_id="sports", inspector="sports1",
                      result="复查合格", passed=True)
        insp = b.recheck(insp["insp_id"], agency_id="forestry",
                         inspector="forestry1", result="复查合格，隐患闭环",
                         passed=True)
        assert insp["status"] == "closed" and insp["status_label"] == "已闭环"
        assert insp["recheck_result"] == "复查合格，隐患闭环"
        assert insp["rounds"] == 1
        assert [h["type"] for h in insp["history"]] == ["rectify", "recheck"]

        # 已闭环不可再整改
        with pytest.raises(StateError):
            b.rectify(insp["insp_id"], note="重复整改")

    def test_failed_recheck_returns_to_rectify(self, s0):
        """P2-6：复查不合格退回整改，多轮历史全部保留；passed 必须显式给出。"""
        b = s0.bureau
        insp = b.create_inspection(
            agency_id="forestry", inspector="forestry1",
            target_unit="unit:range-a",
            findings=["台账与实物不符"],
            deadline="2026-05-20T00:00:00+00:00")
        insp = b.rectify(insp["insp_id"], note="第一轮整改",
                         actor_unit="unit:range-a")
        # passed 非布尔（缺省）→ 拒绝
        with pytest.raises(ValidationError, match="通过/不通过"):
            b.recheck(insp["insp_id"], agency_id="forestry", inspector="forestry1",
                      result="不合格", passed="yes")  # type: ignore[arg-type]
        # 不合格 → 退回整改（不闭环）
        insp = b.recheck(insp["insp_id"], agency_id="forestry", inspector="forestry1",
                         result="复查不合格，继续整改", passed=False)
        assert insp["status"] == "pending_fix" and insp["status_label"] == "待整改"
        assert insp["rounds"] == 1
        # 第二轮整改 → 复查通过 → 闭环，历史保留两轮
        insp = b.rectify(insp["insp_id"], note="第二轮整改",
                         actor_unit="unit:range-a")
        insp = b.recheck(insp["insp_id"], agency_id="forestry", inspector="forestry1",
                         result="复查合格，隐患闭环", passed=True)
        assert insp["status"] == "closed"
        assert insp["rounds"] == 2
        hist = insp["history"]
        assert [h["type"] for h in hist].count("rectify") == 2
        rechecks = [h for h in hist if h["type"] == "recheck"]
        assert [h["passed"] for h in rechecks] == [False, True]

    def test_findings_required(self, s0):
        with pytest.raises(ValidationError, match="问题"):
            s0.bureau.create_inspection(agency_id="forestry", inspector="forestry1",
                                        target_unit="unit:range-a", findings=[])


# ---------------------------------------------------------------------------
# 5. 进出境：贸易进出口 与 人员携带进出境 分开建项、分部门会签
# ---------------------------------------------------------------------------
class TestBorderModes:
    def test_trade_export_two_customs_steps(self, s0):
        b = s0.bureau
        gun = _mk(s0)
        lic_seller, _ = _sale_certs(s0)
        b.create_sale(sale_id="SALE-B1", seller_unit="unit:mfg-a",
                      buyer_unit="unit:range-a", gun_codes=[gun.code],
                      license_id=lic_seller)
        app = b.apply(matter="border_trade_out", applicant_unit="unit:mfg-a",
                      gun_codes=[gun.code], materials=list(
                          APPROVAL_RULES["border_trade_out"]["materials"]))
        assert app["category"] == "进出境" and app["mode"] == "贸易出口"
        # 第一节点是海关，公安无权代办
        with pytest.raises(PermissionDenied, match="海关"):
            b.process(app["app_id"], agency_id="police-province",
                      handler="admin2", action="approve")
        app = b.process(app["app_id"], agency_id="customs", handler="customs1",
                        action="approve", opinion="单证审核")
        assert app["current_step"] == 1
        app = b.process(app["app_id"], agency_id="customs", handler="customs1",
                        action="approve", opinion="查验放行")
        assert app["status"] == "approved"

    def test_carry_in_police_then_customs(self, s0):
        b = s0.bureau
        gun = _mk(s0, serial=3)
        lic_seller, _ = _sale_certs(s0)
        b.create_sale(sale_id="SALE-B2", seller_unit="unit:mfg-a",
                      buyer_unit="unit:range-a", gun_codes=[gun.code],
                      license_id=lic_seller)
        app = b.apply(matter="border_carry_in", applicant_unit="unit:range-a",
                      gun_codes=[gun.code], materials=list(
                          APPROVAL_RULES["border_carry_in"]["materials"]))
        assert app["mode"] == "携带入境"
        # 携带进出境：省级公安机关批准在前
        with pytest.raises(PermissionDenied, match="省公安厅"):
            b.process(app["app_id"], agency_id="customs",
                      handler="customs1", action="approve")
        app = b.process(app["app_id"], agency_id="police-province",
                        handler="admin2", action="approve",
                        opinion="依据第三十七条批准携带入境")
        app = b.process(app["app_id"], agency_id="customs", handler="customs1",
                        action="approve", opinion="出境（入境）申报登记完成")
        assert app["status"] == "approved"
        # 进出境事项不出签证照类许可（无 license_type）
        assert APPROVAL_RULES["border_carry_in"].get("license_type") is None


# ---------------------------------------------------------------------------
# 5b. 运输许可归属：批准/起运/核销全流程保留 domain（评审 P1-3）
# ---------------------------------------------------------------------------
class TestPermitDomain:
    def test_domain_survives_approve_depart_verify(self, s0):
        """P1-3：许可归属写入列并在各保存点延续——批准后单位列表不丢许可。"""
        gun = _mk(s0, serial=41)
        s0.domain.request_transport_permit(
            permit_id="PERMIT-T1", gun_codes=[gun.code], vehicle="云A·T9",
            carrier="承运员", escort="押运员", applicant="u-rng",
            valid_from="2026-04-01T00:00:00+00:00",
            valid_end="2026-12-31T00:00:00+00:00",
            origin="起点库", destination="终点库")
        assert s0.repo.get_permit("PERMIT-T1")["domain"] == "unit:range-a"
        # 批准：domain 不丢失（此前 get_permit 不读列 → 保存成空串）
        s0.domain.approve_transport_permit(permit_id="PERMIT-T1", approver="u-rng")
        p = s0.repo.get_permit("PERMIT-T1")
        assert p["status"] == "approved" and p["domain"] == "unit:range-a"
        col = s0.repo.db.one(
            "SELECT domain FROM permits WHERE permit_id='PERMIT-T1'")
        assert col["domain"] == "unit:range-a"
        # 起运 → 核销：归属持续保留（单位许可列表按 domain 过滤不丢）
        sig = s0.kms.sign("user:u-rng", b"transport:depart:PERMIT-T1")
        s0.domain.start_transport(
            permit_id="PERMIT-T1", gun_codes=[gun.code], vehicle="云A·T9",
            carrier="承运员", escort="押运员",
            signers=[{"signer": "u-rng", "role": "保管", "sig": sig}])
        assert s0.repo.get_permit("PERMIT-T1")["domain"] == "unit:range-a"
        s0.domain.verify_transport_arrival(permit_id="PERMIT-T1", verifier="u-rng")
        p = s0.repo.get_permit("PERMIT-T1")
        assert p["status"] == "closed" and p["domain"] == "unit:range-a"
        col = s0.repo.db.one(
            "SELECT domain FROM permits WHERE permit_id='PERMIT-T1'")
        assert col["domain"] == "unit:range-a"


# ---------------------------------------------------------------------------
# 6. 一枪一档：主线节点 / 记录字段 / 场景 / 总览
# ---------------------------------------------------------------------------
class TestArchive:
    def _filled_system(self, s0):
        b = s0.bureau
        gun = _mk(s0, serial=10)
        b.set_scenario(gun.code, "range",
                       info={"场所资质": "A 级", "监督检查": "季度全覆盖"},
                       source="real")
        # 配售登记的前置：卖方制造许可（第十五条）+ 买方配置单位资质
        lic_seller = _issue(s0, "manufacture_license", "unit:mfg-a")["license_id"]
        mats = list(APPROVAL_RULES["unit_qualification"]["materials"])
        app = b.apply(matter="unit_qualification", applicant_unit="unit:range-a",
                      materials=mats, gun_codes=[gun.code])
        b.process(app["app_id"], agency_id="police-city", handler="admin1",
                  action="approve", opinion="核发配置单位资质")
        b.create_sale(sale_id="SALE-A1", seller_unit="unit:mfg-a",
                      buyer_unit="unit:range-a", gun_codes=[gun.code],
                      license_id=lic_seller, scenario="range")
        b.create_inspection(agency_id="police-city", inspector="admin1",
                            target_unit="unit:range-a",
                            findings=["枪弹台账登记不及时"],
                            deadline="2026-05-30T00:00:00+00:00")
        return gun

    def test_pipeline_nodes_and_statuses(self, s0):
        gun = self._filled_system(s0)
        arch = s0.bureau.archive(gun.code)
        assert [n["key"] for n in arch["pipeline"]] == list(PIPELINE_KEYS)
        for n in arch["pipeline"]:
            assert n["status"] in NODE_STATUSES, (n["key"], n["status"])
            assert n["name"] == PIPELINE_NAMES[n["key"]]
            assert n["scope"] in ("企业级", "枪支级")
        # 制造事件存在 → 制造节点已完成；无进出境 → 不适用；无领用 → 待办理
        by_key = {n["key"]: n for n in arch["pipeline"]}
        assert by_key["manufacture"]["status"] == "已完成"
        assert by_key["use"]["status"] == "待办理"
        assert by_key["border"]["status"] == "不适用"
        assert by_key["border"]["note"]
        # 场景与时间线
        assert arch["scenario"]["key"] == "range"
        assert arch["scenario"]["info"]["场所资质"] == "A 级"
        assert arch["timeline"]

    def test_record_fields_uniform(self, s0):
        gun = self._filled_system(s0)
        arch = s0.bureau.archive(gun.code)
        records = [r for n in arch["pipeline"] for r in n["records"]]
        assert records, "至少应有制造/配售/审批/检查记录"
        for r in records:
            for f in RECORD_FIELDS:
                assert f in r, (r.get("matter"), f)
            assert r["source"] in ("real", "demo")
            assert r["matter"]
        # 审批记录含申请单位、办理部门、经办人、审批意见、存证编号
        app_recs = [r for r in records if "配置单位资质" in r["matter"]
                    or "unit_qualification" in r["matter"] or "资质" in r["matter"]]
        assert app_recs
        ar = app_recs[0]
        assert ar["applicant"] == "unit:range-a"
        assert ar["handler"] == "admin1"
        assert ar["opinion"]
        assert ar["evidence_no"].startswith("EV-")
        # 配售记录存在且关联
        sale_recs = [r for r in records if "配售交付" in r["matter"]]
        assert sale_recs and sale_recs[0]["evidence_no"].startswith("EV-")

    def test_lifecycle_overview(self, s0):
        gun = self._filled_system(s0)
        s0.bureau.apply(matter="hunt_config", applicant_unit="unit:range-a",
                        materials=[])     # 缺件 → 退回补正
        o = s0.bureau.lifecycle_overview()
        assert o["gun_total"] == 1
        assert [x["key"] for x in o["stages"]] == list(PIPELINE_KEYS)
        assert [x["key"] for x in o["scenarios"]] == list(SCENARIOS)
        assert o["apps_total"] == 3       # 制造许可 + 配置资质 + 狩猎配置缺件
        assert sum(o["apps_by_status"].values()) == o["apps_total"]
        assert o["apps_by_status"].get("退回补正") == 1
        assert o["apps_by_status"].get("已完成") == 2
        assert len(o["pending_apps"]) == 1
        assert o["inspections_total"] == 1
        assert o["licenses_active"] >= 1
        assert o["sales_total"] == 1
        # 场景卡片：射击场单位类型推导 range 场景
        range_card = next(c for c in o["scenarios"] if c["key"] == "range")
        assert range_card["guns"] == 1
        assert range_card["representative"] == gun.code

    def test_archive_enterprise_node_states(self, s0):
        """P2-7：赋码前的企业级申请按单位关联；仅驳回/证照失效不得显示已完成。"""
        b = s0.bureau
        gun = _mk(s0, serial=11)
        # 企业级申请（无枪号）按单位进入档案
        mats = list(APPROVAL_RULES["unit_qualification"]["materials"])
        rj = b.apply(matter="unit_qualification", applicant_unit="unit:range-a",
                     materials=mats)
        rj = b.process(rj["app_id"], agency_id="police-city", handler="admin1",
                       action="reject", opinion="材料不实")
        arch = b.archive(gun.code)
        assert rj["app_id"] in [a["app_id"] for a in arch["applications"]]
        ent = next(n for n in arch["pipeline"] if n["key"] == "enterprise")
        assert ent["status"] == "待办理"
        assert "已退回" in ent["note"]
        # 记录区分审批结果（驳回记录不是"已完成"）
        rj_recs = [r for r in ent["records"] if rj["app_id"] in r["matter"]]
        assert rj_recs and rj_recs[0]["status"] == "退回"
        # 批准核发有效证照 → 已完成
        lic_app = _issue(s0, "unit_qualification", "unit:range-a",
                         handler="admin1", app_id="APP-TEST-QUAL2")
        ent = next(n for n in b.archive(gun.code)["pipeline"]
                   if n["key"] == "enterprise")
        assert ent["status"] == "已完成"
        # 证照失效 → 待办理 + 失效提示（重新申请核发）
        b.db.execute(
            "UPDATE bureau_licenses SET valid_to='2026-04-01T00:00:00+00:00' "
            "WHERE license_id=?", (lic_app["license_id"],))
        ent = next(n for n in b.archive(gun.code)["pipeline"]
                   if n["key"] == "enterprise")
        assert ent["status"] == "待办理"
        assert "失效" in ent["note"]

    def test_archive_manufacturer_resolved_by_stable_id(self, s0):
        """P2-5：identity 固化制造单位稳定 ID，配置单位枪支档案关联
        制造企业的资质与生产计划（此前按名称反查失败返回 None）。"""
        s0.register_unit("unit:mfg-yn", "云南西南机电制造有限公司",
                         "manufacture", risk_level=2)
        gun = s0.domain.manufacture(maker="云南西南", kind="手枪", year=2026,
                                    serial=51, legacy_no="GA26-000051",
                                    unit_id="unit:range-a",
                                    part_categories=["枪管"], signer="u-rng")
        # 赋码时固化稳定制造单位 ID（内存对象与落库往返一致）
        assert gun.identity.maker_unit_id == "unit:mfg-yn"
        got = s0.repo.get_gun(gun.code)
        assert got.identity.maker_unit_id == "unit:mfg-yn"
        # 制造企业资质 + 生产计划 → 配置单位枪支档案可见
        lic = _issue(s0, "manufacture_license", "unit:mfg-yn")["license_id"]
        plan_app = s0.bureau.apply(
            matter="production_plan", applicant_unit="unit:mfg-yn",
            materials=list(APPROVAL_RULES["production_plan"]["materials"]),
            batch_ref="B-T1", planned_qty=3)
        plan_app = s0.bureau.process(plan_app["app_id"], agency_id="police-city",
                                     handler="admin1", action="approve")
        arch = s0.bureau.archive(gun.code)
        assert lic in [l["license_id"] for l in arch["licenses"]]
        assert plan_app["app_id"] in [a["app_id"] for a in arch["applications"]]
        ent = next(n for n in arch["pipeline"] if n["key"] == "enterprise")
        assert ent["records"], ent


# ---------------------------------------------------------------------------
# 6b. 历史事项兼容：旧 enterprise_license 记录可渲染可办理（评审 P2-4）
# ---------------------------------------------------------------------------
class TestLegacyMatterCompat:
    def test_legacy_enterprise_license_records_still_processable(self, s0):
        """旧库 enterprise_license（规则已拆分删除）不 KeyError、可见、可办理，
        且新实例 _migrate 做显式数据迁移——不靠清库解决。"""
        b = s0.bureau
        mats = list(APPROVAL_RULES["manufacture_license"]["materials"])
        app = b.apply(matter="manufacture_license", applicant_unit="unit:mfg-a",
                      materials=mats, app_id="APP-LEGACY-1")
        # 模拟旧版数据库记录（热插入，迁移早已跑过）
        b.db.execute("UPDATE bureau_apps SET matter='enterprise_license' "
                     "WHERE app_id='APP-LEGACY-1'")
        # 读取归一化：事项/链视图按现行规则渲染
        got = b.get_app("APP-LEGACY-1")
        assert got["matter"] == "manufacture_license"
        assert got["chain"] and got["chain"][0]["agency"] == "police-national"
        # 可见性过滤按归一化事项（警察组看得到）
        vis = b.list_apps(matters=b.matters_of_group("police"))
        assert "APP-LEGACY-1" in [a["app_id"] for a in vis]
        # 办理不再 KeyError（评审复现路径）
        got = b.process("APP-LEGACY-1", agency_id="police-national",
                        handler="mps1", action="approve")
        assert got["status"] == "approved" and got["license_id"]
        # 数据迁移：新服务实例启动时把旧事项改挂现行规则
        b.db.execute("UPDATE bureau_apps SET matter='enterprise_license' "
                     "WHERE app_id='APP-LEGACY-1'")
        b2 = BureauService(s0.repo, s0.clock, audit=s0.audit, domain=s0.domain)
        raw = b2.db.one("SELECT matter, category FROM bureau_apps "
                        "WHERE app_id='APP-LEGACY-1'")
        assert raw["matter"] == "manufacture_license"
        assert raw["category"] == APPROVAL_RULES["manufacture_license"]["category"]


# ---------------------------------------------------------------------------
# 7. 持久化：重启后审批、检查、场景仍可追溯
# ---------------------------------------------------------------------------
class TestPersistence:
    def test_bureau_state_survives_restart(self, tmp_path):
        db = str(tmp_path / "gunreg.sqlite3")
        view = str(tmp_path / "view.sqlite3")
        s1 = GunSystem(clock=ManualClock(datetime(2026, 5, 1, 9, 0,
                                                  tzinfo=timezone.utc)),
                       db_path=db, view_path=view)
        mats = list(APPROVAL_RULES["hunt_config"]["materials"])
        app = s1.bureau.apply(matter="hunt_config", applicant_unit="hunt-a",
                              materials=mats, source="real")
        s1.bureau.process(app["app_id"], agency_id="forestry",
                          handler="forestry1", action="approve")
        insp = s1.bureau.create_inspection(
            agency_id="forestry", inspector="forestry1", target_unit="hunt-a",
            findings=["台账与实物不符"], deadline="2026-06-01T00:00:00+00:00")

        # 重启：新实例共享同一业务库
        s2 = GunSystem(clock=ManualClock(datetime(2026, 5, 2, 9, 0,
                                                  tzinfo=timezone.utc)),
                       db_path=db, view_path=view)
        got = s2.bureau.get_app(app["app_id"])
        assert got["evidence_no"] == app["evidence_no"]
        assert got["status"] == "pending" and got["current_step"] == 1
        assert got["steps"][0]["handler"] == "forestry1"
        insps = s2.bureau.inspections(target_unit="hunt-a")
        assert any(i["insp_id"] == insp["insp_id"] for i in insps)
        assert s2.bureau.list_apps(applicant_unit="hunt-a")


# ---------------------------------------------------------------------------
# 8. Webapp API 层：部门分权办理 / 数据域 / 前置条件后台阻止
# ---------------------------------------------------------------------------
from gunreg.iam import totp  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from webapp.main import CLOCK, SYSTEM, app  # noqa: E402

# 每个账号独立 client IP，隔离 WAF 令牌桶
_API_ACCOUNTS = [("admin1", "admin123"),        # 市公安局·治安支队
                 ("admin2", "admin123"),        # 省公安厅·治安总队
                 ("forestry1", "dept123"),      # 省林业和草原局
                 ("customs1", "dept123"),       # 海关
                 ("unit-hunt", "unit123")]      # 狩猎场（申请单位）


@pytest.fixture(scope="module")
def api():
    out = {}
    for i, (uid, pw) in enumerate(_API_ACCOUNTS):
        c = TestClient(app, client=(f"10.9.10.{i + 1}", 52000 + i))
        sub = SYSTEM.identity.get(uid)
        code = totp(sub.mfa_secret, int(CLOCK.now().timestamp()) // 30)
        r = c.post("/api/login",
                   json={"user_id": uid, "password": pw, "totp": code})
        assert r.status_code == 200, f"login {uid}: {r.text}"
        out[uid] = c
    return out


def _no_sale_guns() -> list[str]:
    """种子故意无配售登记的枪支（hunt_g2）。"""
    covered: set[str] = set()
    for s in SYSTEM.bureau.sales():
        covered.update(s["gun_codes"])
    rows = SYSTEM.repo.db.query(
        "SELECT code FROM guns WHERE unit_id='hunt-a' ORDER BY rowid")
    return [r["code"] for r in rows if r["code"] not in covered]


class TestBureauAPI:
    def test_rules_and_overview_permission(self, api):
        r = api["admin1"].get("/api/bureau/rules")
        assert r.status_code == 200
        d = r.json()
        assert len(d["rules"]) == 12 and len(d["agencies"]) == 6
        assert len(d["scenarios"]) == 5 and len(d["stages"]) == 7
        # 单位账号可读规则（ledger:query 全角色）
        assert api["unit-hunt"].get("/api/bureau/rules").status_code == 200

        r = api["admin1"].get("/api/bureau/overview")
        assert r.status_code == 200
        ov = r.json()
        assert ov["gun_total"] == 25
        assert len(ov["scenarios"]) == 5
        assert [x["key"] for x in ov["stages"]] == list(PIPELINE_KEYS)
        # 总览须部门权限（gun:read:all domain=""）
        assert api["unit-hunt"].get("/api/bureau/overview").status_code == 403

    def test_sale_requires_covering_purchase_authorization(self, api):
        """P1-1 评审复现（排在扩展买方证照的用例之前，保持种子状态）：
        狩猎场配购申请处于"退回补正"，制造单位只引用自己的配售许可证、
        不填配购申请编号 → 拒绝（此前 200 成功）。"""
        uncovered = _no_sale_guns()
        assert uncovered, "种子应包含故意未登记配售的枪支（hunt_g2）"
        code = uncovered[0]
        sale_lic = next(l for l in SYSTEM.bureau.licenses("mfg-yn")
                        if l["license_type"] == "sale_license")
        r = api["unit-hunt"].post("/api/bureau/sales", json={
            "seller_unit": "mfg-yn", "buyer_unit": "hunt-a",
            "gun_codes": [code],
            "license_id": sale_lic["license_id"],
            "note": "仅引用卖方配售许可证"})
        assert r.status_code == 400, r.text
        assert "配购授权" in r.json()["detail"]
        # 登记确实未落库（枪支仍无配售记录）
        assert not any(code in s["gun_codes"] for s in SYSTEM.bureau.sales())

    def test_chain_processed_by_each_agency(self, api):
        """协同审批：哪个部门办理 → 逐节点办理，越权 403，最终核发证照。"""
        mats = list(APPROVAL_RULES["hunt_config"]["materials"])
        r = api["admin1"].post("/api/bureau/apps", json={
            "matter": "hunt_config", "applicant_unit": "hunt-a",
            "materials": mats, "title": "API 协同审批链测试"})
        assert r.status_code == 200, r.text
        app_id = r.json()["app"]["app_id"]

        # 第一步是林业：省公安厅/市公安局均无权代办
        r = api["admin2"].post(f"/api/bureau/apps/{app_id}/process",
                               json={"action": "approve", "opinion": "抢批"})
        assert r.status_code == 403 and "林业" in r.json()["detail"]
        # 林业办理第一步
        r = api["forestry1"].post(f"/api/bureau/apps/{app_id}/process",
                                  json={"action": "approve",
                                        "opinion": "林业主管部门批准"})
        assert r.status_code == 200, r.text
        assert r.json()["app"]["current_step"] == 1
        # 第二步是省级公安：市公安局无权代办
        r = api["admin1"].post(f"/api/bureau/apps/{app_id}/process",
                               json={"action": "approve"})
        assert r.status_code == 403 and "公安厅" in r.json()["detail"]
        # 省级办理第二步（第九条：省级审批）→ 仍在链上，待市级核发
        r = api["admin2"].post(f"/api/bureau/apps/{app_id}/process",
                               json={"action": "approve",
                                     "opinion": "依据第九条省级审批通过"})
        assert r.status_code == 200, r.text
        app = r.json()["app"]
        assert app["status"] == "pending" and app["current_step"] == 2
        # 第三步：设区的市级公安机关核发配购证件（第九条）
        r = api["admin1"].post(f"/api/bureau/apps/{app_id}/process",
                               json={"action": "approve",
                                     "opinion": "依据第九条核发配购证件"})
        assert r.status_code == 200, r.text
        app = r.json()["app"]
        assert app["status"] == "approved"
        assert app["license"]["license_type"] == "purchase_permit"
        # 链视图经办人按节点对位
        assert [n["handler"] for n in app["chain"]] == ["forestry1", "admin2",
                                                        "admin1"]

        # 单位端可见本单位申请与缺件提示
        items = api["unit-hunt"].get("/api/bureau/apps").json()["items"]
        assert all(a["applicant_unit"] == "hunt-a" for a in items)
        assert any(a["app_id"] == app_id for a in items)
        assert any(a["app_id"] == "APP-2026-006" for a in items)  # 种子补正件

    def test_unit_supplement_roundtrip_via_api(self, api):
        # 缺件申请 → 退回补正
        r = api["unit-hunt"].post("/api/bureau/apps", json={
            "matter": "hunt_config", "title": "补正回路测试"})
        assert r.status_code == 200
        app = r.json()["app"]
        assert app["status"] == "supplement" and app["missing"]
        # 不得为其他单位提交申请
        r = api["unit-hunt"].post("/api/bureau/apps", json={
            "matter": "unit_qualification", "applicant_unit": "range-a"})
        assert r.status_code == 403
        # 补齐材料 → 回到审批链
        r = api["unit-hunt"].post(f"/api/bureau/apps/{app['app_id']}/resubmit",
                                  json={"materials": list(
                                      APPROVAL_RULES["hunt_config"]["materials"])})
        assert r.status_code == 200
        assert r.json()["app"]["status"] == "pending"

    def test_inspection_loop_via_api(self, api):
        # 林业部门发起检查
        r = api["forestry1"].post("/api/bureau/inspections", json={
            "target_unit": "hunt-a", "findings": ["库室台账与实物不符"],
            "deadline": "2026-12-31T00:00:00+00:00"})
        assert r.status_code == 200, r.text
        insp_id = r.json()["inspection"]["insp_id"]
        # 单位端只看到本单位检查单
        items = api["unit-hunt"].get("/api/bureau/inspections").json()["items"]
        assert all(i["target_unit"] == "hunt-a" for i in items)
        assert any(i["insp_id"] == insp_id for i in items)
        # 非检查部门不能发起
        r = api["unit-hunt"].post("/api/bureau/inspections", json={
            "target_unit": "hunt-a", "findings": ["x"]})
        assert r.status_code == 403
        # 被检查单位整改
        r = api["unit-hunt"].post(f"/api/bureau/inspections/{insp_id}/rectify",
                                  json={"note": "已补充台账并复核"})
        assert r.status_code == 200
        assert r.json()["inspection"]["status"] == "recheck"
        # 复查须原检查部门（越权先 403，即使未带 passed 字段）
        r = api["customs1"].post(f"/api/bureau/inspections/{insp_id}/recheck",
                                 json={"result": "复查合格"})
        assert r.status_code == 403
        # 原检查部门缺 passed（通过/不通过）字段 → 400
        r = api["forestry1"].post(f"/api/bureau/inspections/{insp_id}/recheck",
                                  json={"result": "复查合格，隐患闭环"})
        assert r.status_code == 400
        assert "通过/不通过" in r.json()["detail"]
        # 显式通过 → 闭环
        r = api["forestry1"].post(f"/api/bureau/inspections/{insp_id}/recheck",
                                  json={"result": "复查合格，隐患闭环",
                                        "passed": True})
        assert r.status_code == 200, r.text
        assert r.json()["inspection"]["status"] == "closed"

    def test_police_only_regulatory_actions(self, api):
        """P1-1：运输审批/核销与报废确认为公安专属（非公安部门 role=admin 也 403）。"""
        rows = SYSTEM.repo.db.query(
            "SELECT permit_id FROM permits WHERE status='applied' ORDER BY rowid")
        assert rows, "种子应有待审批的运输许可（PERMIT-A）"
        pid = rows[0]["permit_id"]
        # 林草部门（admin 角色）无权批准运输、无权核销到达
        r = api["forestry1"].post("/api/permit/approve", json={"permit_id": pid})
        assert r.status_code == 403 and "公安" in r.json()["detail"]
        r = api["forestry1"].post("/api/permit/verify", json={"permit_id": pid})
        assert r.status_code == 403 and "公安" in r.json()["detail"]
        # 报废确认与销毁监督同样仅公安
        g = SYSTEM.repo.db.query("SELECT code FROM guns ORDER BY rowid")[0]["code"]
        r = api["forestry1"].post("/api/scrap",
                                  json={"gun_code": g, "stage": "province_confirm"})
        assert r.status_code == 403 and "公安" in r.json()["detail"]
        # 公安部门账号可正常批准
        r = api["admin1"].post("/api/permit/approve", json={"permit_id": pid})
        assert r.status_code == 200, r.text
        assert r.json()["permit"]["status"] == "approved"

    def test_sale_create_validated_via_api(self, api):
        """P1-2：配售登记接口不再绕过前置校验（负例）。"""
        uncovered = _no_sale_guns()
        assert uncovered, "种子应包含故意未登记配售的枪支（hunt_g2）"
        code = uncovered[0]
        # (1) 买方单位不存在 → 404
        r = api["unit-hunt"].post("/api/bureau/sales", json={
            "seller_unit": "hunt-a", "buyer_unit": "unit-nope",
            "gun_codes": [code]})
        assert r.status_code == 404
        assert "单位不存在" in r.json()["detail"]
        # (2) 未关联证照 → 400（枪支归属与双方资质均满足也不放行）
        r = api["unit-hunt"].post("/api/bureau/sales", json={
            "seller_unit": "mfg-yn", "buyer_unit": "hunt-a",
            "gun_codes": [code]})
        assert r.status_code == 400
        assert "证照" in r.json()["detail"]
        # (3) 本单位不是当事方 → 403
        r = api["unit-hunt"].post("/api/bureau/sales", json={
            "seller_unit": "mfg-yn", "buyer_unit": "range-a",
            "gun_codes": [code], "license_id": "LIC-ANY"})
        assert r.status_code == 403
        # (4) 合法登记：引用既有配购证件与配购审批（同枪再次交付登记）
        sales = [s for s in SYSTEM.bureau.sales()
                 if s["sale_id"] == "SALE-2026-07"]
        assert sales
        s7 = sales[0]
        r = api["unit-hunt"].post("/api/bureau/sales", json={
            "seller_unit": "mfg-yn", "buyer_unit": "hunt-a",
            "gun_codes": s7["gun_codes"],
            "license_id": s7["license_id"],
            "purchase_app_id": s7["purchase_app_id"],
            "note": "同一批次再次交付登记"})
        assert r.status_code == 200, r.text
        assert r.json()["sale"]["sale_id"]

    def test_precondition_gates_block_downstream(self, api):
        uncovered = _no_sale_guns()
        assert uncovered, "种子应包含故意未登记配售的枪支（hunt_g2）"
        code = uncovered[0]
        # 领用被后台阻止（配售配购登记缺失）
        r = api["unit-hunt"].post("/api/unit/checkout", json={
            "gun_code": code, "person_id": "hunt-user",
            "signers": [["hunt-keep", "保管"], ["hunt-sup", "监督"]],
            "due_hours": 8})
        assert r.status_code == 400
        assert "前置条件未满足" in r.json()["detail"]
        assert "配售" in r.json()["detail"]
        # 进出境申报同样被前置条件阻止
        r = api["admin1"].post("/api/bureau/apps", json={
            "matter": "border_trade_out", "applicant_unit": "hunt-a",
            "gun_codes": uncovered})
        assert r.status_code == 400
        assert "前置条件未满足" in r.json()["detail"]
        # 已登记配售的枪支可正常申报进出境
        covered = [s for s in SYSTEM.bureau.sales()
                   if s["sale_id"] == "SALE-2026-01"]
        assert covered
        r = api["admin1"].post("/api/bureau/apps", json={
            "matter": "border_carry_out", "applicant_unit": "hunt-a",
            "gun_codes": [covered[0]["gun_codes"][0]]})
        assert r.status_code == 200, r.text
        assert r.json()["app"]["category"] == "进出境"

    def test_archive_endpoint_and_domain(self, api):
        rows = SYSTEM.repo.db.query(
            "SELECT code, unit_id FROM guns WHERE unit_id='hunt-a' ORDER BY rowid")
        own = rows[0]["code"]
        other_rows = SYSTEM.repo.db.query(
            "SELECT code FROM guns WHERE unit_id<>'hunt-a' ORDER BY rowid")
        other_code = other_rows[0]["code"] if other_rows else None

        # 监管全量可查
        r = api["admin1"].get(f"/api/gun/{own}/archive")
        assert r.status_code == 200
        d = r.json()
        assert [n["key"] for n in d["pipeline"]] == list(PIPELINE_KEYS)
        assert d["scenario"]["key"] == "hunt"
        # 机场驱鸟场景：适用规定标注待核实
        air_rows = SYSTEM.repo.db.query(
            "SELECT code FROM guns WHERE unit_id='airport-a' ORDER BY rowid")
        if air_rows:
            air = api["admin1"].get(f"/api/gun/{air_rows[0]['code']}/archive").json()
            if air["scenario"]:
                assert air["scenario"]["info"].get("适用规定") == "待核实"
        # 单位：本单位档案可查
        assert api["unit-hunt"].get(f"/api/gun/{own}/archive").status_code == 200
        # 单位：跨单位档案 403
        if other_code:
            assert api["unit-hunt"].get(
                f"/api/gun/{other_code}/archive").status_code == 403
        # 不存在的枪 404
        assert api["admin1"].get("/api/gun/NOT-EXIST/archive").status_code == 404
