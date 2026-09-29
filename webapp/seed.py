"""内置模拟数据：四个角色的演示账号 + 覆盖全链条的预置场景。

场景设计（时钟时间线）：
- 制造赋码：三家单位共 18 支枪入账（制造/配售企业 6、射击场 10、运动学校 6）
- 五类业务场景：民用猎枪（狩猎场 2 支，一支全闭环到报废封存、一支卡在配购补正）、
  营业性射击场（10 支）、射击运动（5 支）、机场驱鸟（1 支）、野生动物管护（1 支）
  → 合计 25 支；跨部门审批（公安/林草/体育/海关）、监督检查、进出境同步预置
- 领用超时阶梯（射击场，due=8h）：
    枪 R1 于 t=0  领用 → t=18h 超时 10h → 提示级
    枪 R2 于 t=18h 领用 → t=50h 超时 24h → 关注级
    枪 R3 于 t=50h 领用 → 尚未超时（留给监管台推进时钟后触发）
- 预警：种子结束时扫描一次，R1(紧急) + R2(关注) 两条已开预警
- 运输：一条「已申请」待批（管理台审批）、一条「已批准并起运在途」（管理台核销）
- 报废：一支枪已完成 申请+鉴定 两节点，停在「待销毁」，供管理台走省级确认→四节点销毁→封存
"""
from __future__ import annotations

import os
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path

from gunreg import GunSystem
from gunreg.domain import Person
from gunreg.identity import GunCode

from .clock import DemoClock

DATA_DIR = Path(os.environ.get("GUNREG_DATA_DIR", str(Path(__file__).resolve().parent / "data"))).resolve()


def _reset_data() -> None:
    """清空数据目录，保证确定性演示。"""
    if DATA_DIR.exists():
        for p in DATA_DIR.rglob("*"):
            if p.is_file():
                p.unlink()
        for d in list(DATA_DIR.rglob("*"))[::-1]:
            if d.is_dir():
                d.rmdir()
    DATA_DIR.mkdir(parents=True, exist_ok=True)


def _should_reset() -> bool:
    """仅当显式要求（GUNREG_RESET=1）或数据尚未生成时重建种子。"""
    env = os.environ.get("GUNREG_RESET", "")
    if env not in ("", "0", "false", "no", "off"):
        return True
    return not (DATA_DIR / "gunreg.sqlite3").exists()


def _sign(kms, user_id: str, payload: str) -> str:
    return kms.sign(f"user:{user_id}", payload.encode("utf-8"))


def _valid_expire(clock) -> str:
    return (clock.now() + timedelta(days=365 * 3)).isoformat()


def demo_accounts() -> list[tuple[str, str, str, str, str]]:
    """演示账号表：(uid, 姓名, 角色, 所属, 口令)。"""
    accounts = [
        ("admin1", "治安支队·陈警官", "admin", "police:bureau-01", "admin123"),
        ("admin2", "省公安厅·郑处长", "admin", "police:province", "admin123"),
        ("mps1", "公安部·许司长", "admin", "police:national", "admin123"),
        ("forestry1", "省林草局·吴处长", "admin", "dept:forestry", "dept123"),
        ("sports1", "省体育局·赵主任", "admin", "dept:sports", "dept123"),
        ("customs1", "海关·钱关员", "admin", "dept:customs", "dept123"),
        ("audit1", "督察审计·孙科员", "auditor", "audit-01", "audit123"),
        ("unit-mfg", "制造基地管理员", "unit", "mfg-yn", "unit123"),
        ("unit-rng", "射击场管理员", "unit", "range-a", "unit123"),
        ("unit-spt", "运动学校管理员", "unit", "sport-a", "unit123"),
        ("unit-hunt", "狩猎场管理员", "unit", "hunt-a", "unit123"),
        ("unit-air", "机场驱鸟队管理员", "unit", "airport-a", "unit123"),
        ("unit-wild", "救护科研站管理员", "unit", "wild-a", "unit123"),
    ]
    for pid, name, org, pw in (("rng-wang", "王芳", "range-a", "user123"),
                               ("spt-liu", "刘洋", "sport-a", "user123"),
                               ("rng-zhang", "张伟", "range-a", "user123"),
                               ("rng-li", "李娜", "range-a", "user123"),
                               ("spt-chen", "陈刚", "sport-a", "user123"),
                               ("spt-zhao", "赵敏", "sport-a", "user123"),
                               ("hunt-keep", "赵守库", "hunt-a", "user123"),
                               ("hunt-sup", "钱监管", "hunt-a", "user123"),
                               ("hunt-user", "吴猎手", "hunt-a", "user123"),
                               ("air-keep", "褚守库", "airport-a", "user123"),
                               ("air-sup", "卫监管", "airport-a", "user123"),
                               ("air-user", "蒋驱鸟员", "airport-a", "user123"),
                               ("wild-keep", "沈守库", "wild-a", "user123"),
                               ("wild-sup", "韩监管", "wild-a", "user123"),
                               ("wild-user", "杨兽医", "wild-a", "user123")):
        accounts.append((pid, name, "practitioner", org, pw))
    return accounts


def demo_devices() -> list[tuple[str, str, str]]:
    """演示感知设备表：(设备号, 协议, 所属单位)。"""
    return [("reader-gate-01", "rfid", "range-a"),
            ("cabinet-01", "rfid", "range-a"),
            ("scanner-sport-01", "scan", "sport-a"),
            ("plc-mfg-01", "rfid", "mfg-yn")]


def _seed_accounts(sys: GunSystem) -> None:
    """重建身份层账号（进程内状态）：账目复用已有数据库时也必须执行，
    否则服务重启后 IAM 为空，登录全部报"用户名或口令错误"。"""
    from gunreg.common import ValidationError

    for uid, name, role, org, pw in demo_accounts():
        try:
            sys.identity.register(uid, name, role, org, pw, attrs={"demo": True})
        except ValidationError:
            pass  # 同一进程内重复初始化（幂等）


def _seed_devices(sys: GunSystem) -> None:
    """重建设备网关（进程内状态）：数据复用路径下同样需要。"""
    for dev, proto, org in demo_devices():
        try:
            sys.register_device(dev, proto, org)
        except ValueError:
            pass


def _add_person(sys: GunSystem, pid: str, name: str, unit_id: str, duty: str,
                kinds: list[str]) -> Person:
    p = Person(person_id=pid, name=name, unit_id=unit_id, cert_status="valid",
               cert_expire=_valid_expire(sys.clock), cert_kinds=kinds, duty=duty)
    sys.repo.save_person(p)
    return p


def _checkout(sys: GunSystem, gun_code: str, holder: str,
              signers: list[tuple[str, str]], location: str = "") -> None:
    """构造双人签名（保管+监督）并领用。sig 由各自私钥对 checkout payload 生成。"""
    sig_list = [{"signer": s, "role": r,
                 "sig": _sign(sys.kms, s, f"checkout:{gun_code}:{holder}")}
                for s, r in signers]
    sys.domain.checkout(gun_code=gun_code, person_id=holder, signers=sig_list,
                        location=location, due_hours=8)


def _has_event(sys: GunSystem, code: str, etype: str) -> bool:
    return any(e.event_type == etype for e in sys.repo.events_of(code))


def _seed_bureau(sys: GunSystem, clock: DemoClock) -> None:
    """五类业务场景 + 一枪一档 + 跨部门全生命周期监管（幂等种子）。

    数据复用路径（数据库已存在、bureau_* 表为空）同样执行：仅补齐协同审批、
    场景枪支与档案记录，不动已有 21 支枪的现场；bureau_apps 非空则整体跳过。
    所有预置记录 source="demo"（演示记录），运行期经 API 新建的为"真实业务记录"。
    """
    from gunreg.bureau import APPROVAL_RULES

    b = sys.bureau
    if b.db.one("SELECT app_id FROM bureau_apps LIMIT 1"):
        return
    now = clock.now()

    # ---- 场景配置单位与在册人员（复用旧库时补齐）
    for uid, name, utype in (("hunt-a", "某狩猎场（配置单位）", "hunter"),
                             ("airport-a", "国际机场·驱鸟队", "airport"),
                             ("wild-a", "野生动物救护科研站", "wildlife")):
        if not sys.repo.db.one("SELECT unit_id FROM units WHERE unit_id=?",
                               (uid,)):
            sys.register_unit(uid, name, utype, risk_level=2, region=None)
    for pid, name, uid, duty, kinds in (
            ("hunt-keep", "赵守库", "hunt-a", "保管", ["猎枪"]),
            ("hunt-sup", "钱监管", "hunt-a", "监督", ["猎枪"]),
            ("hunt-user", "吴猎手", "hunt-a", "使用", ["猎枪"]),
            ("air-keep", "褚守库", "airport-a", "保管", ["步枪"]),
            ("air-sup", "卫监管", "airport-a", "监督", ["步枪"]),
            ("air-user", "蒋驱鸟员", "airport-a", "使用", ["步枪"]),
            ("wild-keep", "沈守库", "wild-a", "保管", ["手枪"]),
            ("wild-sup", "韩监管", "wild-a", "监督", ["手枪"]),
            ("wild-user", "杨兽医", "wild-a", "使用", ["手枪"])):
        if not sys.repo.db.one("SELECT person_id FROM persons WHERE person_id=?",
                               (pid,)):
            _add_person(sys, pid, name, uid, duty, kinds)

    def gcode(maker: str, kind: str, serial: int) -> str:
        """已存在枪支的整枪码（跨年份兜底），用于配售/关联记录。"""
        for y in (now.year, now.year - 1):
            code = str(GunCode.generate(maker, kind, y, serial))
            if sys.repo.db.one("SELECT code FROM guns WHERE code=?", (code,)):
                return code
        return str(GunCode.generate(maker, kind, now.year, serial))

    def exists(code: str) -> bool:
        return bool(sys.repo.db.one("SELECT code FROM guns WHERE code=?", (code,)))

    # ---- 场景枪支：制造赋码（赋码后归属配置单位，与射击场/运动学校演示一致）
    signer_by_unit = {"hunt-a": "unit-hunt", "airport-a": "unit-air",
                      "wild-a": "unit-wild"}

    def ensure_gun(unit_id: str, maker: str, kind: str, serial: int) -> str:
        code = str(GunCode.generate(maker, kind, now.year, serial))
        if sys.repo.db.one("SELECT code FROM guns WHERE code=?", (code,)):
            return code
        gun = sys.domain.manufacture(
            maker=maker, kind=kind, year=now.year, serial=serial,
            legacy_no=f"GA{str(now.year)[2:]}·{serial:06d}", unit_id=unit_id,
            part_categories=["枪管", "撞针", "弹匣", "枪身"],
            signer=signer_by_unit[unit_id])
        return gun.code

    hunt_g1 = ensure_gun("hunt-a", "云南西南", "猎枪", 60)   # 全闭环演示枪
    hunt_g2 = ensure_gun("hunt-a", "云南西南", "猎枪", 61)   # 卡在配购补正
    air_gun = ensure_gun("airport-a", "云南西南", "步枪", 70)
    wild_gun = ensure_gun("wild-a", "云南西南", "手枪", 71)

    # ---- 跨部门协同审批（材料齐全→按部门链会签；缺件→退回补正）
    def mats(matter: str, drop: tuple[str, ...] = ()) -> list[str]:
        return [m for m in APPROVAL_RULES[matter]["materials"] if m not in drop]

    def apply_(app_id: str, matter: str, unit: str, *, guns: tuple[str, ...] = (),
               title: str = "", scenario: str = "",
               materials: list[str] | None = None,
               batch_ref: str = "", planned_qty: int = 0) -> None:
        b.apply(matter=matter, applicant_unit=unit, gun_codes=list(guns),
                materials=mats(matter) if materials is None else materials,
                scenario=scenario, title=title, source="demo", app_id=app_id,
                batch_ref=batch_ref, planned_qty=planned_qty)

    def approve(app_id: str, agency: str, handler: str, opinion: str) -> None:
        b.process(app_id, agency_id=agency, handler=handler,
                  action="approve", opinion=opinion)

    # 企业资质与计划（第十五条：制造许可由国务院公安部门核发、配售许可由省级公安
    # 机关核发——两类许可分开发证；生产计划批准后自动生成可执行计划记录）
    apply_("APP-2026-001", "manufacture_license", "mfg-yn",
           title="云南西南机电制造有限公司 · 民用枪支制造许可（2026）")
    approve("APP-2026-001", "police-national", "mps1",
            "材料齐全，厂区安全条件与质量管理体系符合第十五条许可要求，予以核发")
    lic_mfg = b.get_app("APP-2026-001")["license_id"]

    apply_("APP-2026-011", "sale_license", "mfg-yn",
           title="云南西南机电制造有限公司 · 民用枪支配售许可（2026）")
    approve("APP-2026-011", "police-province", "admin2",
            "配售场所与库室条件符合规定，由省级公安机关核发民用枪支配售许可证")
    lic_sale = b.get_app("APP-2026-011")["license_id"]

    apply_("APP-2026-002", "production_plan", "mfg-yn",
           title="2026 年度生产计划 · 批次 B2026-001",
           batch_ref="B2026-001", planned_qty=6)
    approve("APP-2026-002", "police-city", "admin1",
            "年度生产计划备案通过，批次赋码后逐支关联到枪支档案")

    # 配置单位资质（射击场 / 运动学校）
    apply_("APP-2026-003", "unit_qualification", "range-a",
           title="某市射击场 · 枪支配置单位资质")
    approve("APP-2026-003", "police-city", "admin1",
            "库室验收合格、保管人员在册，核发配置单位资质证书")
    apply_("APP-2026-004", "unit_qualification", "sport-a",
           title="省射击运动学校 · 枪支配置单位资质")
    approve("APP-2026-004", "police-city", "admin1",
            "训练库室验收合格，核发配置单位资质证书")

    # 狩猎场配置猎枪（第九条）：林业主管部门批准文件 → 省级公安机关审批 →
    # 设区的市级公安机关核发配购证件
    apply_("APP-2026-005", "hunt_config", "hunt-a", guns=(hunt_g1,),
           scenario="hunt", title="某狩猎场 · 猎枪配置（狩猎期作业）")
    approve("APP-2026-005", "forestry", "forestry1",
            "经审核狩猎场资质与猎区范围符合规定，出具林业主管部门批准文件")
    approve("APP-2026-005", "police-province", "admin2",
            "依据《枪支管理法》第九条，报省级人民政府公安机关审批通过")
    approve("APP-2026-005", "police-city", "admin1",
            "依据第九条，由设区的市级人民政府公安机关核发民用枪支配购证件")
    lic_purchase = b.get_app("APP-2026-005")["license_id"]

    # L2：缺林业主管部门批准文件 → 退回补正（演示前置条件与节点状态）
    apply_("APP-2026-006", "hunt_config", "hunt-a", guns=(hunt_g2,),
           scenario="hunt", title="某狩猎场 · 猎枪配置（第二批）",
           materials=mats("hunt_config", drop=("林业主管部门批准文件",)))

    # 办理中（当前由市公安局办理；批准后自动生成批次 B2026-002 计划）
    apply_("APP-2026-007", "production_plan", "mfg-yn",
           title="2026 年度生产计划 · 批次 B2026-002（追加）",
           batch_ref="B2026-002", planned_qty=4)

    # 射击运动任务 / 机场驱鸟任务 / 野生动物管护依据
    apply_("APP-2026-008", "sport_plan", "sport-a", scenario="sport",
           title="2026 年度射击运动训练与赛事任务")
    approve("APP-2026-008", "sports", "sports1",
            "训练与赛事任务及枪弹保管方案备案通过")
    apply_("APP-2026-009", "airport_plan", "airport-a", guns=(air_gun,),
           scenario="airport", title="跑道端净空驱鸟任务（2026 汛期）")
    approve("APP-2026-009", "police-city", "admin1",
            "驱鸟任务书与作业区域安全措施备案通过（适用规定另行核实）")
    apply_("APP-2026-010", "wildlife_plan", "wild-a", guns=(wild_gun,),
           scenario="wildlife", title="年度巡护与野生动物救护任务")
    approve("APP-2026-010", "forestry", "forestry1",
            "管护/科研任务依据与麻醉药品使用登记方案审核通过")

    # 进出境：贸易出口（海关两节点办结）与人员携带出境（停在海关申报登记）
    export_gun = gcode("云南西南", "手枪", 4)
    carry_gun = gcode("某运动器材厂", "运动步枪", 1)
    apply_("APP-2026-020", "border_trade_out", "mfg-yn",
           guns=(export_gun,) if exists(export_gun) else (),
           title="民用枪支贸易出口申报 · 2026-EX-01")
    approve("APP-2026-020", "customs", "customs1",
            "出口合同与最终用户证明齐全，受理申报")
    approve("APP-2026-020", "customs", "customs1",
            "查验相符，单证与实物一致，准予放行")
    apply_("APP-2026-021", "border_carry_out", "sport-a",
           guns=(carry_gun,) if exists(carry_gun) else (),
           scenario="sport", title="运动员携枪出境参赛 · 2026 亚锦赛")
    approve("APP-2026-021", "police-province", "admin2",
            "持枪证件与出境事由有效，批准携运（待海关出境申报登记）")

    # ---- 配售记录（覆盖除 L2 外的全部枪支；运输/领用的前置条件）
    def sale(sale_id: str, seller: str, buyer: str, guns: list[str],
             scenario: str, note: str, license_id: str = "",
             purchase_app_id: str = "") -> None:
        guns = [g for g in guns if exists(g)]
        if not guns:
            return
        b.create_sale(sale_id=sale_id, seller_unit=seller, buyer_unit=buyer,
                      gun_codes=guns, scenario=scenario, note=note,
                      license_id=license_id,
                      purchase_app_id=purchase_app_id, source="demo")

    lic_range = b.get_app("APP-2026-003")["license_id"]
    lic_sport = b.get_app("APP-2026-004")["license_id"]
    sale("SALE-2026-01", "mfg-yn", "sport-a",
         [gcode("云南西南", "步枪", 1), gcode("云南西南", "步枪", 2)],
         "sport", "2026 年度配售计划 · 省竞技射击训练中心（关联 PERMIT-A）",
         license_id=lic_sale)
    sale("SALE-2026-02", "mfg-yn", "range-a",
         [gcode("云南西南", "手枪", i) for i in (3, 4, 5, 6)],
         "range", "2026 年度配售计划 · 某市射击场（关联 PERMIT-B）",
         license_id=lic_sale)
    sale("SALE-2026-03", "range-a", "range-a",
         [gcode("北方装备", "手枪", i) for i in range(1, 11)],
         "range", "营业性射击场场内枪支配售配购登记", license_id=lic_range)
    sale("SALE-2026-04", "sport-a", "sport-a",
         [gcode("某运动器材厂", "气手枪", i) for i in (1, 2)]
         + [gcode("某运动器材厂", "运动步枪", i) for i in (1, 2, 3)],
         "sport", "射击运动学校训练用枪配售配购登记", license_id=lic_sport)
    sale("SALE-2026-05", "mfg-yn", "airport-a", [air_gun],
         "airport", "机场驱鸟任务用枪配售交付", license_id=lic_sale)
    sale("SALE-2026-06", "mfg-yn", "wild-a", [wild_gun],
         "wildlife", "野生动物管护/科研用枪配售交付", license_id=lic_sale)
    sale("SALE-2026-07", "mfg-yn", "hunt-a", [hunt_g1],
         "hunt", "狩猎场配购交付（第一批）", license_id=lic_purchase,
         purchase_app_id="APP-2026-005")
    # 注意：hunt_g2 故意不登记配售 → 运输/领用被前置条件拦截（演示点）

    # ---- L1 猎枪全闭环：运输交接 → 领用归还 → 报废销毁至档案封存
    if not _has_event(sys, hunt_g1, "transport"):
        sys.domain.request_transport_permit(
            permit_id="PERMIT-H1", gun_codes=[hunt_g1], vehicle="云C·H1001",
            carrier="林承运", escort="胡押运", applicant="unit-hunt",
            valid_from=(now - timedelta(hours=1)).isoformat(),
            valid_end=(now + timedelta(days=7)).isoformat(),
            origin="昆明制造基地", destination="某狩猎场")
        sys.domain.approve_transport_permit(permit_id="PERMIT-H1",
                                            approver="admin2")
        sys.domain.start_transport(
            permit_id="PERMIT-H1", gun_codes=[hunt_g1], vehicle="云C·H1001",
            carrier="林承运", escort="胡押运",
            signers=[{"signer": "unit-hunt", "role": "承运方",
                      "sig": _sign(sys.kms, "unit-hunt",
                                   "transport:depart:PERMIT-H1")}],
            position=(25.04, 102.72))
        sys.domain.verify_transport_arrival(permit_id="PERMIT-H1",
                                            position=(25.04, 102.72),
                                            verifier="admin2")

    if not _has_event(sys, hunt_g1, "checkout"):
        _checkout(sys, hunt_g1, "hunt-user",
                  [("hunt-keep", "保管"), ("hunt-sup", "监督")],
                  location="狩猎场库房")
        sys.domain.checkin(
            gun_code=hunt_g1, person_id="hunt-user",
            signers=[{"signer": s, "role": r,
                      "sig": _sign(sys.kms, s, f"return:{hunt_g1}:hunt-user")}
                     for s, r in (("hunt-keep", "保管"),
                                  ("hunt-sup", "监督"))],
            location="狩猎场库房")

    if not _has_event(sys, hunt_g1, "scrap"):
        scrap_flow = (
            ("apply", {"reason": "狩猎期结束，枪管达到使用年限"},
             [("hunt-keep", "保管"), ("hunt-sup", "监督")], "unit-hunt"),
            ("appraise",
             {"appraisal": "鉴定意见：枪管寿命到期、膛线磨损超差，建议报废"},
             [("hunt-keep", "保管"), ("hunt-sup", "监督")], "unit-hunt"),
            ("province_confirm", {},
             [("admin2", "省级确认")], "admin2"),
            ("destroy_submit", {},
             [("hunt-keep", "销毁执行"), ("hunt-sup", "监督")], "unit-hunt"),
            ("destroy_inventory", {},
             [("hunt-keep", "销毁执行"), ("hunt-sup", "监督")], "unit-hunt"),
            ("destroy_execute", {},
             [("hunt-keep", "销毁执行"), ("hunt-sup", "监督")], "unit-hunt"),
            ("destroy_archive", {},
             [("hunt-keep", "销毁执行"), ("hunt-sup", "监督")], "unit-hunt"),
        )
        for stage, kw, signers, actor in scrap_flow:
            sys.domain.scrap_stage(
                gun_code=hunt_g1, stage=stage, actor=actor,
                signers=[{"signer": s, "role": r,
                          "sig": _sign(sys.kms, s,
                                       f"scrap:{stage}:{hunt_g1}")}
                         for s, r in signers],
                **kw)

    # ---- 机场驱鸟 / 野生动物管护：任务作业领用与交回
    for gun, holder, keep, sup, loc in (
            (air_gun, "air-user", "air-keep", "air-sup", "机场驱鸟作业区"),
            (wild_gun, "wild-user", "wild-keep", "wild-sup", "巡护作业区")):
        if _has_event(sys, gun, "checkout"):
            continue
        _checkout(sys, gun, holder, [(keep, "保管"), (sup, "监督")], location=loc)
        sys.domain.checkin(
            gun_code=gun, person_id=holder,
            signers=[{"signer": s, "role": r,
                      "sig": _sign(sys.kms, s, f"return:{gun}:{holder}")}
                     for s, r in ((keep, "保管"), (sup, "监督"))],
            location=loc)

    # ---- 监督检查（检查 → 整改 → 复查 三态闭环）
    b.create_inspection(
        insp_id="INSP-2026-001", agency_id="police-city", inspector="admin1",
        target_unit="range-a", gun_codes=[gcode("北方装备", "手枪", 6)],
        findings=["二号库室视频监控存在盲区", "出入登记台账与领用记录不完全一致"],
        deadline=(now + timedelta(days=7)).isoformat(), source="demo")
    b.rectify("INSP-2026-001",
              note="已补装广角摄像头消除盲区，重新培训登记流程并连续一周抽查核对",
              actor_unit="range-a", actor="unit-rng")
    b.recheck("INSP-2026-001", agency_id="police-city", inspector="admin1",
              result="复查合格：监控覆盖完整、台账与链上记录一致，隐患闭环",
              passed=True)

    b.create_inspection(
        insp_id="INSP-2026-002", agency_id="police-province", inspector="admin2",
        target_unit="mfg-yn",
        findings=["废弹药暂存柜警示标识老化脱落"],
        deadline=(now + timedelta(days=3)).isoformat(), source="demo")
    b.rectify("INSP-2026-002",
              note="已更换反光警示标识并复核暂存量与台账一致",
              actor_unit="mfg-yn", actor="unit-mfg")
    # → 停在待复查（省公安厅复查中）

    b.create_inspection(
        insp_id="INSP-2026-003", agency_id="forestry", inspector="forestry1",
        target_unit="hunt-a", gun_codes=[hunt_g1],
        findings=["猎期外枪支暂存台账登记不及时"],
        deadline=(now + timedelta(days=5)).isoformat(), source="demo")
    # → 停在待整改（狩猎场整改中）

    # ---- 五类场景业务信息（一枪一档的场景字段）
    b.set_scenario(hunt_g1, "hunt", {
        "配置主体": "某狩猎场（hunt-a）",
        "批准用途": "经批准的狩猎期场内及指定猎区作业",
        "适用区域": "××猎区（林业主管部门批准范围）",
        "相关配置材料": "林业主管部门批准文件、配购证件、库室保管条件证明",
    }, source="demo")
    b.set_scenario(hunt_g2, "hunt", {
        "配置主体": "某狩猎场（hunt-a）",
        "批准用途": "狩猎期场内作业（申请中）",
        "适用区域": "××猎区（待批准）",
        "相关配置材料": "缺林业主管部门批准文件，已退回补正",
    }, source="demo")
    b.set_scenario(air_gun, "airport", {
        "机场单位": "国际机场·驱鸟队（airport-a）",
        "驱鸟任务": "航班高峰时段跑道端净空驱鸟",
        "作业区域": "东跑道端 500m 范围",
        "任务结束交回记录": "作业后当场交回库房并双人清点",
        "适用规定": "待核实",
    }, source="demo")
    b.set_scenario(wild_gun, "wildlife", {
        "保护或科研单位": "野生动物救护科研站（wild-a）",
        "任务依据": "年度巡护与野生动物救护任务书",
        "作业记录": "麻醉注射作业逐次登记（人员、剂量、对象）",
    }, source="demo")

    sys.pump(rounds=200)


def seed_system() -> tuple[GunSystem, DemoClock]:
    clock = DemoClock()
    needs_reset = _should_reset()
    if needs_reset:
        _reset_data()
    sys = GunSystem(base_dir=str(DATA_DIR),
                    db_path=str(DATA_DIR / "gunreg.sqlite3"),
                    view_path=str(DATA_DIR / "view.sqlite3"),
                    clock=clock)
    # IAM 账号/签名密钥/设备网关均为进程内状态：无论数据库是否复用，
    # 启动时都必须重建，否则服务重启后所有账号失效（登录报"用户名或口令错误"）。
    _seed_accounts(sys)
    # 复用已有种子数据（import 即自动 seed，但不清空演示现场）；
    # 只有显式 GUNREG_RESET=1 才重建。
    if not needs_reset and sys.repo.db.one("SELECT COUNT(*) c FROM units")["c"] > 0:
        _seed_devices(sys)   # 设备网关同样是内存态，重启后需重建
        _seed_bureau(sys, clock)   # 协同审批/场景档案为空时补齐（幂等）
        return sys, clock
    now = clock.now()

    # ------------------------------------------------------------------ 单位
    sys.register_unit("mfg-yn", "云南西南机电制造有限公司", "manufacture",
                      risk_level=2, region=None)
    sys.register_unit("range-a", "某市射击场（营业性）", "shooting_range",
                      risk_level=2, region=None)
    sys.register_unit("sport-a", "省射击运动学校", "sports_school",
                      risk_level=2, region=None)
    sys.register_unit("police-1", "属地公安机关", "police", risk_level=1)
    # 五类业务场景的配置单位（猎枪/机场驱鸟/野生动物管护）
    sys.register_unit("hunt-a", "某狩猎场（配置单位）", "hunter",
                      risk_level=2, region=None)
    sys.register_unit("airport-a", "国际机场·驱鸟队", "airport",
                      risk_level=2, region=None)
    sys.register_unit("wild-a", "野生动物救护科研站", "wildlife",
                      risk_level=2, region=None)

    # ------------------------------------------------------------------ 人员
    _add_person(sys, "rng-zhang", "张伟", "range-a", "保管", ["手枪"])
    _add_person(sys, "rng-li", "李娜", "range-a", "监督", ["手枪"])
    _add_person(sys, "rng-wang", "王芳", "range-a", "使用", ["手枪"])
    _add_person(sys, "spt-chen", "陈刚", "sport-a", "保管", ["气手枪", "运动步枪"])
    _add_person(sys, "spt-zhao", "赵敏", "sport-a", "监督", ["气手枪", "运动步枪"])
    _add_person(sys, "spt-liu", "刘洋", "sport-a", "使用", ["气手枪", "运动步枪"])
    _add_person(sys, "mfg-huang", "黄强", "mfg-yn", "保管", [])
    _add_person(sys, "hunt-keep", "赵守库", "hunt-a", "保管", ["猎枪"])
    _add_person(sys, "hunt-sup", "钱监管", "hunt-a", "监督", ["猎枪"])
    _add_person(sys, "hunt-user", "吴猎手", "hunt-a", "使用", ["猎枪"])
    _add_person(sys, "air-keep", "褚守库", "airport-a", "保管", ["步枪"])
    _add_person(sys, "air-sup", "卫监管", "airport-a", "监督", ["步枪"])
    _add_person(sys, "air-user", "蒋驱鸟员", "airport-a", "使用", ["步枪"])
    _add_person(sys, "wild-keep", "沈守库", "wild-a", "保管", ["手枪"])
    _add_person(sys, "wild-sup", "韩监管", "wild-a", "监督", ["手枪"])
    _add_person(sys, "wild-user", "杨兽医", "wild-a", "使用", ["手枪"])

    # ------------------------------------------------------------------ 设备
    _seed_devices(sys)

    # ------------------------------------------------------------------ 制造赋码（一枪一码）
    def make(unit_id: str, maker: str, kind: str, serial: int) -> str:
        gun = sys.domain.manufacture(maker=maker, kind=kind, year=now.year, serial=serial,
                                     legacy_no=f"GA{f'{now.year}'[2:]}·{serial:06d}",
                                     unit_id=unit_id,
                                     part_categories=["枪管", "撞针", "弹匣", "枪身"],
                                     signer={"mfg-yn": "unit-mfg", "range-a": "unit-rng",
                                             "sport-a": "unit-spt"}[unit_id])
        return gun.code

    mfg_rifle_1 = make("mfg-yn", "云南西南", "步枪", 1)
    mfg_rifle_2 = make("mfg-yn", "云南西南", "步枪", 2)
    mfg_pistol_1 = make("mfg-yn", "云南西南", "手枪", 3)   # 用于运输许可 B（起运）
    [make("mfg-yn", "云南西南", "手枪", 3 + i) for i in range(1, 4)]  # 库存

    r_serial = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
    range_guns = {i: make("range-a", "北方装备", "手枪", i) for i in r_serial}
    sport_g1 = make("sport-a", "某运动器材厂", "气手枪", 1)
    make("sport-a", "某运动器材厂", "气手枪", 2)
    make("sport-a", "某运动器材厂", "运动步枪", 1)
    make("sport-a", "某运动器材厂", "运动步枪", 2)
    make("sport-a", "某运动器材厂", "运动步枪", 3)

    # ------------------------------------------------------------------ 领用超时阶梯
    _checkout(sys, range_guns[1], "rng-wang", [("rng-zhang", "保管"), ("rng-li", "监督")],
              location="射击场库房")
    clock.advance(hours=18)                       # → 枪R1 超时 10h
    _checkout(sys, range_guns[2], "rng-zhang", [("rng-li", "监督"), ("rng-wang", "使用")],
              location="射击场库房")
    clock.advance(hours=22)                       # → 枪R1 超时 32h，枪R2 超时 14h
    _checkout(sys, range_guns[3], "rng-li", [("rng-zhang", "保管"), ("rng-wang", "使用")],
              location="射击场库房")
    clock.advance(hours=10)                       # → 枪R1 超时 42h（紧急级），枪R2 超时 24h（关注级），枪R3 超时 2h（提示级）

    # 运动学校：一支正常领用中的运动手枪
    _checkout(sys, sport_g1, "spt-liu", [("spt-chen", "保管"), ("spt-zhao", "监督")],
              location="训练场库房")

    # ------------------------------------------------------------------ 运输许可（一约一规·流转审批）
    sys.domain.request_transport_permit(
        permit_id="PERMIT-A", gun_codes=[mfg_rifle_1], vehicle="云A·T1001",
        carrier="张承运", escort="王押运", applicant="unit-mfg",
        valid_from=(now - timedelta(hours=1)).isoformat(),
        valid_end=(now + timedelta(days=7)).isoformat(),
        origin="昆明制造基地", destination="省竞技射击训练中心")
    sys.domain.request_transport_permit(
        permit_id="PERMIT-B", gun_codes=[mfg_pistol_1], vehicle="云A·T1002",
        carrier="李承运", escort="赵押运", applicant="unit-mfg",
        valid_from=(now - timedelta(hours=1)).isoformat(),
        valid_end=(now + timedelta(days=7)).isoformat(),
        origin="昆明制造基地", destination="省射击场")
    sys.domain.approve_transport_permit(permit_id="PERMIT-B", approver="admin1")
    sys.domain.start_transport(
        permit_id="PERMIT-B", gun_codes=[mfg_pistol_1], vehicle="云A·T1002",
        carrier="李承运", escort="赵押运",
        signers=[{"signer": "unit-mfg", "role": "承运方",
                  "sig": _sign(sys.kms, "unit-mfg", "transport:depart:PERMIT-B")}],
        position=(25.04, 102.72))

    # ------------------------------------------------------------------ 报废：申请+鉴定已完成，停在待销毁
    for _st, _kw in (("apply", {"reason": "枪管磨损超差，无法修复"}),
                     ("appraise", {"appraisal": "鉴定意见：膛线磨损超差，不满足精度要求，建议报废"})):
        sys.domain.scrap_stage(gun_code=range_guns[4], stage=_st, actor="unit-rng",
                               signers=[
                                   {"signer": "rng-zhang", "role": "保管",
                                    "sig": _sign(sys.kms, "rng-zhang", f"scrap:{_st}:{range_guns[4]}")},
                                   {"signer": "rng-li", "role": "监督",
                                    "sig": _sign(sys.kms, "rng-li", f"scrap:{_st}:{range_guns[4]}")}],
                               **_kw)

    # ------------------------------------------------------------------ 跨部门协同：五类业务场景 + 一枪一档
    _seed_bureau(sys, clock)

    # ------------------------------------------------------------------ 泵送 + 首次超期扫描
    sys.pump(rounds=200)
    sys.domain.scan_overdue()
    sys.pump(rounds=200)
    return sys, clock
