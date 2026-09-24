"""内置模拟数据：四个角色的演示账号 + 覆盖全链条的预置场景。

场景设计（时钟时间线）：
- 制造赋码：三家单位共 18 支枪入账（制造/配售企业 6、射击场 10、运动学校 6）
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
        ("audit1", "督察审计·孙科员", "auditor", "audit-01", "audit123"),
        ("unit-mfg", "制造基地管理员", "unit", "mfg-yn", "unit123"),
        ("unit-rng", "射击场管理员", "unit", "range-a", "unit123"),
        ("unit-spt", "运动学校管理员", "unit", "sport-a", "unit123"),
    ]
    for pid, name, org, pw in (("rng-wang", "王芳", "range-a", "user123"),
                               ("spt-liu", "刘洋", "sport-a", "user123"),
                               ("rng-zhang", "张伟", "range-a", "user123"),
                               ("rng-li", "李娜", "range-a", "user123"),
                               ("spt-chen", "陈刚", "sport-a", "user123"),
                               ("spt-zhao", "赵敏", "sport-a", "user123")):
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

    # ------------------------------------------------------------------ 人员
    _add_person(sys, "rng-zhang", "张伟", "range-a", "保管", ["手枪"])
    _add_person(sys, "rng-li", "李娜", "range-a", "监督", ["手枪"])
    _add_person(sys, "rng-wang", "王芳", "range-a", "使用", ["手枪"])
    _add_person(sys, "spt-chen", "陈刚", "sport-a", "保管", ["气手枪", "运动步枪"])
    _add_person(sys, "spt-zhao", "赵敏", "sport-a", "监督", ["气手枪", "运动步枪"])
    _add_person(sys, "spt-liu", "刘洋", "sport-a", "使用", ["气手枪", "运动步枪"])
    _add_person(sys, "mfg-huang", "黄强", "mfg-yn", "保管", [])

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

    # ------------------------------------------------------------------ 泵送 + 首次超期扫描
    sys.pump(rounds=200)
    sys.domain.scan_overdue()
    sys.pump(rounds=200)
    return sys, clock
