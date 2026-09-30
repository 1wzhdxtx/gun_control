"""领域核心（流程图 APP 分区 DOMAIN）：

- 生命周期：制造赋码 → 在库 → 领用 → 归还 → 携运 → 维修 → 报废销毁
- 资格：持枪人资格动态核验与退出
- 审批携运：运输许可闭环
- 风险处置：三级预警与处置闭环

所有业务写入与 Outbox 同事务（Transactional Outbox），保证上链不丢不重。
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field

from .common import StateError, ValidationError, gen_id, hash_obj, parse_iso
from .contracts import ContractRegistry, ScrapConfirmContract
from .crypto import CA, KMS, LocalVault
from .events import GunEvent, build_event
from .identity import GunCode, PartCode, GunIdentity
from .store import Database, OutboxStore


# ---------------------------------------------------------------------------
# 领域对象
# ---------------------------------------------------------------------------

GUN_STATUS = ("in_stock", "in_use", "in_transit", "repairing", "pending_destroy", "destroyed", "sealed")
PERSON_STATUS = ("valid", "qualified", "suspended", "revoked", "expired")


@dataclass
class Unit:
    unit_id: str
    name: str
    unit_type: str        # manufacture / distributor / shooting_range / sports_school / hunter / police
    status: str = "qualified"
    risk_level: int = 2   # 库室风险等级 1/2/3（GA 1016）
    region: dict | None = None   # 许可区域
    time_window: dict | None = None  # 许可时段（猎期）
    domain: str = ""      # 数据域

    def to_dict(self) -> dict:
        return {"unit_id": self.unit_id, "name": self.name, "unit_type": self.unit_type,
                "status": self.status, "risk_level": self.risk_level,
                "region": self.region, "time_window": self.time_window,
                "domain": self.domain or self.unit_id}


@dataclass
class Person:
    person_id: str
    name: str
    unit_id: str
    cert_status: str = "valid"
    cert_expire: str = ""
    cert_kinds: list[str] = field(default_factory=list)
    duty: str = "保管"     # 保管 / 监督 / 使用
    clearance: str = ""    # 省级确认权限等

    def to_dict(self) -> dict:
        return {"person_id": self.person_id, "name": self.name, "unit_id": self.unit_id,
                "cert_status": self.cert_status, "cert_expire": self.cert_expire,
                "cert_kinds": list(self.cert_kinds), "duty": self.duty,
                "clearance": self.clearance}


@dataclass
class Gun:
    code: str
    unit_id: str
    status: str = "in_stock"
    holder: str = ""
    identity: GunIdentity | None = None
    due_at: str = ""       # 应归还时间
    domain: str = ""

    def to_dict(self) -> dict:
        return {"code": self.code, "unit_id": self.unit_id, "status": self.status,
                "holder": self.holder, "due_at": self.due_at,
                "domain": self.domain or self.unit_id,
                "identity": self.identity.to_dict() if self.identity else None}


# ---------------------------------------------------------------------------
# 领域仓储（模块私有 DB）
# ---------------------------------------------------------------------------

DOMAIN_SCHEMA = """
CREATE TABLE IF NOT EXISTS units (
    unit_id TEXT PRIMARY KEY, name TEXT NOT NULL, unit_type TEXT NOT NULL,
    status TEXT NOT NULL, risk_level INTEGER NOT NULL,
    region TEXT, time_window TEXT, domain TEXT
);
CREATE TABLE IF NOT EXISTS persons (
    person_id TEXT PRIMARY KEY, name TEXT NOT NULL, unit_id TEXT NOT NULL,
    cert_status TEXT NOT NULL, cert_expire TEXT, cert_kinds TEXT,
    duty TEXT, clearance TEXT
);
CREATE TABLE IF NOT EXISTS guns (
    code TEXT PRIMARY KEY, unit_id TEXT NOT NULL, status TEXT NOT NULL,
    holder TEXT, due_at TEXT, domain TEXT, identity TEXT
);
CREATE TABLE IF NOT EXISTS gun_events (
    event_id TEXT PRIMARY KEY, gun_code TEXT NOT NULL, event_type TEXT NOT NULL,
    occurred_at TEXT NOT NULL, event_hash TEXT NOT NULL, data TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_gun_events_gun ON gun_events (gun_code, occurred_at);
CREATE TABLE IF NOT EXISTS permits (
    permit_id TEXT PRIMARY KEY, kind TEXT NOT NULL, status TEXT NOT NULL,
    data TEXT NOT NULL, domain TEXT
);
CREATE TABLE IF NOT EXISTS alerts (
    alert_id TEXT PRIMARY KEY, level TEXT NOT NULL, status TEXT NOT NULL,
    gun_code TEXT, subject TEXT, detail TEXT, created_at TEXT NOT NULL,
    deadline TEXT, closed_at TEXT, domain TEXT
);
"""


class DomainRepository:
    def __init__(self, clock, path: str = ":memory:"):
        self.clock = clock
        self.db = Database(path, [DOMAIN_SCHEMA])

    # units
    def save_unit(self, u: Unit) -> None:
        self.db.execute(
            "INSERT OR REPLACE INTO units VALUES (?,?,?,?,?,?,?,?)",
            (u.unit_id, u.name, u.unit_type, u.status, u.risk_level,
             json.dumps(u.region, ensure_ascii=False) if u.region else None,
             json.dumps(u.time_window, ensure_ascii=False) if u.time_window else None,
             u.domain or u.unit_id))

    def get_unit(self, unit_id: str) -> Unit:
        r = self.db.one("SELECT * FROM units WHERE unit_id=?", (unit_id,))
        if not r:
            raise ValidationError(f"单位不存在: {unit_id}")
        return Unit(r["unit_id"], r["name"], r["unit_type"], r["status"], r["risk_level"],
                    json.loads(r["region"]) if r["region"] else None,
                    json.loads(r["time_window"]) if r["time_window"] else None, r["domain"])

    # persons
    def save_person(self, p: Person) -> None:
        # 防止 INSERT OR REPLACE 跨单位覆盖：人员已存在且属于其他单位时拒绝
        existing = self.db.one("SELECT unit_id FROM persons WHERE person_id=?", (p.person_id,))
        if existing and existing["unit_id"] != p.unit_id:
            raise ValidationError(
                f"人员 {p.person_id} 已属于 {existing['unit_id']}，禁止跨单位覆盖")
        self.db.execute(
            "INSERT OR REPLACE INTO persons VALUES (?,?,?,?,?,?,?,?)",
            (p.person_id, p.name, p.unit_id, p.cert_status, p.cert_expire,
             json.dumps(p.cert_kinds, ensure_ascii=False), p.duty, p.clearance))

    def get_person(self, pid: str) -> Person:
        r = self.db.one("SELECT * FROM persons WHERE person_id=?", (pid,))
        if not r:
            raise ValidationError(f"人员不存在: {pid}")
        return Person(r["person_id"], r["name"], r["unit_id"], r["cert_status"],
                      r["cert_expire"] or "", json.loads(r["cert_kinds"] or "[]"),
                      r["duty"] or "保管", r["clearance"] or "")

    # guns
    def save_gun(self, g: Gun) -> None:
        self.db.execute(
            "INSERT OR REPLACE INTO guns VALUES (?,?,?,?,?,?,?)",
            (g.code, g.unit_id, g.status, g.holder, g.due_at, g.domain or g.unit_id,
             json.dumps(g.identity.to_dict(), ensure_ascii=False) if g.identity else None))

    def get_gun(self, code: str) -> Gun:
        r = self.db.one("SELECT * FROM guns WHERE code=?", (code,))
        if not r:
            raise ValidationError(f"枪支不存在: {code}")
        ident = GunIdentity.from_dict(json.loads(r["identity"])) if r["identity"] else None
        ident = GunIdentity.from_dict(json.loads(r["identity"])) if r["identity"] else None
        return Gun(r["code"], r["unit_id"], r["status"], r["holder"] or "",
                   ident, r["due_at"] or "", r["domain"])

    def guns_of(self, unit_id: str, status: str | None = None) -> list[Gun]:
        sql = "SELECT code FROM guns WHERE unit_id=?"
        params: tuple = (unit_id,)
        if status:
            sql += " AND status=?"
            params += (status,)
        return [self.get_gun(r["code"]) for r in self.db.query(sql, params)]

    # events（同一枪支的事件按时间串联成哈希链）
    def append_event(self, ev: GunEvent) -> GunEvent:
        rows = self.db.query(
            "SELECT event_hash FROM gun_events WHERE gun_code=? ORDER BY occurred_at DESC, event_id DESC LIMIT 1",
            (ev.gun_code,))
        prev = rows[0]["event_hash"] if rows else ""
        ev.prev_hash = prev
        ev.event_hash = ev.compute_hash(prev)
        self.db.execute(
            "INSERT INTO gun_events VALUES (?,?,?,?,?,?)",
            (ev.event_id, ev.gun_code, ev.event_type, ev.occurred_at,
             ev.event_hash, json.dumps(ev.to_dict(), ensure_ascii=False)))
        return ev

    def events_of(self, gun_code: str) -> list[GunEvent]:
        rows = self.db.query(
            "SELECT data FROM gun_events WHERE gun_code=? ORDER BY rowid", (gun_code,))
        return [GunEvent.from_dict(json.loads(r["data"])) for r in rows]

    # permits
    def save_permit(self, pid: str, kind: str, status: str, data: dict, domain: str) -> None:
        self.db.execute("INSERT OR REPLACE INTO permits VALUES (?,?,?,?,?)",
                        (pid, kind, status, json.dumps(data, ensure_ascii=False), domain))

    def get_permit(self, pid: str) -> dict | None:
        r = self.db.one("SELECT * FROM permits WHERE permit_id=?", (pid,))
        if not r:
            return None
        d = json.loads(r["data"])
        d.update({"permit_id": r["permit_id"], "kind": r["kind"],
                  "status": r["status"],
                  # 归属随许可全生命周期保留（评审 P1-3：批准/起运/核销
                  # 不得把 domain 读丢或写空，否则单位许可列表按归属过滤时丢失）
                  "domain": r["domain"] or d.get("domain", "")})
        return d

    # alerts
    def save_alert(self, a: dict) -> None:
        self.db.execute(
            "INSERT OR REPLACE INTO alerts VALUES (?,?,?,?,?,?,?,?,?,?)",
            (a["alert_id"], a["level"], a["status"], a.get("gun_code", ""),
             a.get("subject", ""), json.dumps(a.get("detail", {}), ensure_ascii=False),
             a["created_at"], a.get("deadline", ""), a.get("closed_at", ""),
             a.get("domain", "")))

    def alerts(self, status: str | None = None) -> list[dict]:
        sql = "SELECT * FROM alerts"
        params: tuple = ()
        if status:
            sql += " WHERE status=?"
            params = (status,)
        rows = self.db.query(sql + " ORDER BY created_at", params)
        for r in rows:
            r["detail"] = json.loads(r["detail"])
        return rows

    def open_alert_for(self, gun_code: str, level: str) -> dict | None:
        rows = self.db.query(
            "SELECT * FROM alerts WHERE gun_code=? AND level=? AND status!='closed' "
            "ORDER BY created_at DESC", (gun_code, level))
        if not rows:
            return None
        r = rows[0]
        r["detail"] = json.loads(r["detail"])
        return r


# ---------------------------------------------------------------------------
# 领域服务
# ---------------------------------------------------------------------------


class DomainService:
    """用例编排：合约前置校验 → 状态迁移 → 事件入链（经 Outbox）→ 审计。"""

    def __init__(self, repo: DomainRepository, outbox: OutboxStore, registry: ContractRegistry,
                 kms: KMS, ca: CA, audit, clock, vault: LocalVault | None = None):
        self.repo = repo
        self.outbox = outbox
        self.registry = registry
        self.kms = kms
        self.ca = ca
        self.audit = audit
        self.clock = clock
        self.vault = vault

    # -- 上下文组装 ---------------------------------------------------------
    def _ctx(self, gun: Gun | None, person: Person | None, unit: Unit | None, **extra) -> dict:
        ctx = {
            "now": self.clock.now_iso(),
            "gun": {"code": gun.code, "kind": gun.identity.kind if gun.identity else "",
                    "status": gun.status} if gun else {},
            "person": person.to_dict() if person else {},
            "unit": unit.to_dict() if unit else {},
            "device_verified": extra.pop("device_verified", True),
            "signers": extra.pop("signers", []),
            "signer_ids": extra.pop("signer_ids", []),
            "signer_roles": extra.pop("signer_roles", []),
        }
        ctx.update(extra)
        return ctx

    def _emit(self, conn, ev: GunEvent, gun: Gun, ctx: dict | None = None) -> None:
        """事件落库 + Outbox（同事务），等待异步上链。

        ctx：领域侧已执行的合约校验快照。随事件上链，链上以相同上下文
        重新执行当前版本合约（规则内嵌于数据写入过程——「以约行规」）。
        """
        if ctx:
            ev.payload["contract_ctx"] = {k: v for k, v in ctx.items()}
        cur = conn.execute(
            "INSERT INTO gun_events VALUES (?,?,?,?,?,?)",
            (ev.event_id, ev.gun_code, ev.event_type, ev.occurred_at,
             "",  # 先占位，append_event 时会用本地链，但事务里我们直接写最终值
             json.dumps(ev.to_dict(), ensure_ascii=False)))
        # 计算本地哈希链（读取前序需要同连接查询）
        row = conn.execute(
            "SELECT event_hash FROM gun_events WHERE gun_code=? AND event_id!=? "
            "ORDER BY rowid DESC LIMIT 1",
            (ev.gun_code, ev.event_id)).fetchone()
        prev = row[0] if row else ""
        ev.prev_hash = prev
        ev.event_hash = ev.compute_hash(prev)
        conn.execute("UPDATE gun_events SET event_hash=?, data=? WHERE event_id=?",
                     (ev.event_hash, json.dumps(ev.to_dict(), ensure_ascii=False), ev.event_id))
        self.outbox.enqueue(conn, "gun.event", ev.to_dict())

    def _signer_person_in_unit(self, s: dict, unit_id: str, strict_duty: bool = False) -> Person:
        """签名人必须是该单位的在册人员（纵深防御，与 API 层 _signers_with_duty 一致）。

        strict_duty=True 时（领用/归还），签名人申报岗位必须与在册岗位一致，
        防止借用他人签名冒充「保管 + 监督」双岗。
        """
        try:
            sp = self.repo.get_person(s["signer"])
        except Exception:
            raise ValidationError(f"签名人 {s['signer']} 不是本单位在册人员") from None
        if sp.unit_id != unit_id:
            raise ValidationError(
                f"签名人 {s['signer']} 属于 {sp.unit_id}，与本单位 {unit_id} 不一致")
        if strict_duty and s.get("role", "") != sp.duty:
            raise ValidationError(
                f"签名人 {s['signer']} 申报岗位 {s.get('role', '')} 与在册岗位 {sp.duty} 不一致")
        return sp

    # -- 1. 制造赋码（一枪一码） --------------------------------------------
    def manufacture(self, *, maker: str, kind: str, year: int, serial: int,
                    legacy_no: str, unit_id: str, part_categories: list[str] | None = None,
                    signer: str) -> Gun:
        unit = self.repo.get_unit(unit_id)
        code = str(GunCode.generate(maker, kind, year, serial))
        if self.repo.db.one("SELECT code FROM guns WHERE code=?", (code,)):
            raise ValidationError(f"整枪码重复: {code}")
        parts = [str(PartCode.generate(code, cat, i + 1))
                 for i, cat in enumerate(part_categories or [])]
        # 制造单位稳定 ID（评审 P2-5）：优先按企业名称匹配在册单位并在赋码时固化；
        # 匹配不到时，赋码单位本身是制造企业则以其为准，否则留空（不虚报制造主体）。
        mrow = self.repo.db.one(
            "SELECT unit_id FROM units WHERE name LIKE ? ORDER BY unit_id",
            (maker + "%",))
        maker_unit_id = (mrow["unit_id"] if mrow else
                         (unit_id if unit.unit_type == "manufacture" else ""))
        ident = GunIdentity(code=code, maker=maker, kind=kind, year=year, serial=serial,
                            legacy_no=legacy_no, parts=parts,
                            maker_unit_id=maker_unit_id)
        gun = Gun(code=code, unit_id=unit_id, status="in_stock", identity=ident)
        ev = build_event(
            event_id=gen_id("evt"), gun_code=code, event_type="manufacture",
            actor=unit_id, occurred_at=self.clock.now_iso(),
            location=maker, device_id="line-mfg-01",
            payload={"unit": unit_id, "legacy_no": legacy_no, "parts": parts,
                     "holder": "", "kind": kind},
            signer_ids=[signer])
        ev.signatures[signer] = self.kms.sign(f"user:{signer}", ev.event_hash.encode())
        with self.repo.db.transaction() as conn:
            self._emit(conn, ev, gun)
            conn.execute("INSERT INTO guns VALUES (?,?,?,?,?,?,?)",
                         (code, unit_id, "in_stock", "", "", unit.domain or unit_id,
                          json.dumps(ident.to_dict(), ensure_ascii=False)))
        self.audit.append(actor=signer, action="gun:manufacture", target=code,
                          detail={"legacy_no": legacy_no, "parts": parts})
        return gun

    # -- 2. 领用归还 --------------------------------------------------------
    def checkout(self, *, gun_code: str, person_id: str, signers: list[dict],
                 device_verified: bool = True, location: str = "", due_hours: int = 8,
                 manual_entry: bool = False, voucher_hash: str = "",
                 authorizer: str = "",
                 extra_ctx: dict | None = None) -> GunEvent:
        gun = self.repo.get_gun(gun_code)
        person = self.repo.get_person(person_id)
        unit = self.repo.get_unit(gun.unit_id)

        if gun.status != "in_stock":
            raise StateError(f"枪支状态 {gun.status} 不允许领用（须 in_stock）")

        # 超期未还阻断新领用
        overdue = [g for g in self.repo.guns_of(gun.unit_id, "in_use")
                   if g.holder == person_id and g.due_at and
                   parse_iso(g.due_at) < parse_iso(self.clock.now_iso())]

        signer_ids = [s["signer"] for s in signers]
        signer_roles = [s.get("role", "") for s in signers]
        sig_values = [s["sig"] for s in signers]
        # 验证每个签名确实由签名人私钥对枪码生成，且签名人必须是本单位在册人员、
        # 申报岗位与在册岗位一致（纵深防御：API 层已用 _signers_with_duty 约束）。
        for s in signers:
            payload = f"checkout:{gun_code}:{person_id}".encode()
            if not self.kms.verify(f"user:{s['signer']}", payload, s["sig"]):
                raise ValidationError(f"签名人 {s['signer']} 签名验证失败")
            sp = self._signer_person_in_unit(s, gun.unit_id, strict_duty=True)

        ctx = self._ctx(gun, person, unit,
                        signers=signer_ids, signer_ids=signer_ids, signer_roles=signer_roles,
                        device_verified=device_verified, manual_entry=manual_entry,
                        voucher_hash=voucher_hash, outstanding_overdue=len(overdue),
                        require_distinct_duty=True,
                        allowed_gun_status=("in_stock",),
                        **(extra_ctx or {}))
        verdicts = self.registry.evaluate_all(["compliance", "multisig"], ctx)
        # timelimit 的阻断入口：存在超期未还则禁止再次领用
        block = self.registry.get("timelimit").check_before_checkout(ctx)
        verdicts = verdicts + [block]
        self.registry.raise_all(verdicts)

        now = self.clock.now_iso()
        due = (self.clock.now().timestamp() + due_hours * 3600)
        from datetime import datetime, timezone
        due_at = datetime.fromtimestamp(due, tz=timezone.utc).isoformat()

        ev = build_event(
            event_id=gen_id("evt"), gun_code=gun_code, event_type="checkout",
            actor=person_id, occurred_at=now, location=location or unit.name,
            device_id=extra_ctx.get("device_id", "cabinet-01") if extra_ctx else "cabinet-01",
            payload={"unit": unit.unit_id, "holder": person_id, "due_at": due_at,
                     "signers": signer_ids, "manual_entry": manual_entry,
                     "voucher_hash": voucher_hash, "authorizer": authorizer},
            signer_ids=signer_ids)
        for s in signers:
            ev.signatures[s["signer"]] = s["sig"]

        with self.repo.db.transaction() as conn:
            self._emit(conn, ev, gun, ctx)
            conn.execute("UPDATE guns SET status='in_use', holder=?, due_at=? WHERE code=?",
                         (person_id, due_at, gun_code))

        self.audit.append(actor=person_id, action="gun:checkout", target=gun_code,
                          detail={"signers": signer_ids, "due_at": due_at})
        # 合约附带结论（如超时分级）产生预警
        for v in verdicts:
            if v.outputs.get("alert_level"):
                self.raise_alert(gun_code, v.outputs["alert_level"],
                                 f"领用合约提示：{v.warnings}", unit.unit_id)
        return ev

    def checkin(self, *, gun_code: str, person_id: str, signers: list[dict],
                location: str = "", device_verified: bool = True,
                authorizer: str = "") -> GunEvent:
        gun = self.repo.get_gun(gun_code)
        person = self.repo.get_person(person_id)
        unit = self.repo.get_unit(gun.unit_id)
        if gun.status != "in_use":
            raise StateError(f"枪支状态 {gun.status} 不允许归还（须 in_use）")
        if gun.holder != person_id:
            raise ValidationError(f"归还人 {person_id} 非当前持枪人 {gun.holder}")

        signer_ids = [s["signer"] for s in signers]
        for s in signers:
            payload = f"return:{gun_code}:{person_id}".encode()
            if not self.kms.verify(f"user:{s['signer']}", payload, s["sig"]):
                raise ValidationError(f"签名人 {s['signer']} 签名验证失败")
            self._signer_person_in_unit(s, gun.unit_id, strict_duty=True)

        ctx = self._ctx(gun, person, unit, signers=signer_ids, signer_ids=signer_ids,
                        signer_roles=[s.get("role", "") for s in signers],
                        device_verified=device_verified, returned=True,
                        require_distinct_duty=True,
                        allowed_gun_status=("in_use",))
        self.registry.raise_all(self.registry.evaluate_all(["compliance", "multisig"], ctx))

        ev = build_event(
            event_id=gen_id("evt"), gun_code=gun_code, event_type="return",
            actor=person_id, occurred_at=self.clock.now_iso(), location=location or unit.name,
            device_id="cabinet-01",
            payload={"unit": unit.unit_id, "holder": "", "signers": signer_ids,
                     "authorizer": authorizer},
            signer_ids=signer_ids)
        for s in signers:
            ev.signatures[s["signer"]] = s["sig"]

        with self.repo.db.transaction() as conn:
            self._emit(conn, ev, gun, ctx)
            conn.execute("UPDATE guns SET status='in_stock', holder='', due_at='' WHERE code=?",
                         (gun_code,))
        self.audit.append(actor=person_id, action="gun:return", target=gun_code,
                          detail={"signers": signer_ids})
        # 归还后关闭超时预警
        open_alert = self.repo.open_alert_for(gun_code, "hint")
        if open_alert and open_alert["status"] != "closed":
            open_alert["status"] = "closed"
            open_alert["closed_at"] = self.clock.now_iso()
            self.repo.save_alert(open_alert)
        return ev

    # -- 3. 携带运输（许可闭环） --------------------------------------------
    def request_transport_permit(self, *, permit_id: str, gun_codes: list[str],
                                 vehicle: str, carrier: str, escort: str,
                                 valid_from: str, valid_end: str,
                                 origin: str, destination: str, applicant: str) -> dict:
        if not gun_codes:
            raise ValidationError("运输许可须关联至少一支枪支")
        guns = [self.repo.get_gun(c) for c in gun_codes]
        units = {g.unit_id for g in guns}
        if len(units) > 1:
            raise ValidationError(f"一次运输须为同一单位枪支（涉及 {sorted(units)}）")
        for g in guns:
            if g.status != "in_stock":
                raise StateError(f"枪支 {g.code} 状态 {g.status} 不允许申报运输（须在库）")
        domain = guns[0].unit_id
        data = {"permit_id": permit_id, "gun_codes": gun_codes, "vehicle": vehicle,
                "carrier": carrier, "escort": escort, "valid_from": valid_from,
                "valid_end": valid_end, "origin": origin, "destination": destination,
                "applicant": applicant}
        self.repo.save_permit(permit_id, "transport", "applied", data, domain)
        ev = build_event(
            event_id=gen_id("evt"), gun_code=gun_codes[0], event_type="permit",
            actor=applicant, occurred_at=self.clock.now_iso(), location=origin,
            device_id="permit-portal", payload={"permit_id": permit_id, "stage": "apply",
                                                "unit": domain},
            signer_ids=[applicant])
        ev.signatures[applicant] = self.kms.sign(f"user:{applicant}", ev.event_hash.encode())
        with self.repo.db.transaction() as conn:
            self._emit(conn, ev, guns[0])
        self.audit.append(actor=applicant, action="permit:request", target=permit_id,
                          detail={"guns": gun_codes, "vehicle": vehicle})
        return data

    def approve_transport_permit(self, *, permit_id: str, approver: str) -> dict:
        p = self.repo.get_permit(permit_id)
        if not p:
            raise ValidationError(f"许可不存在: {permit_id}")
        if p["status"] != "applied":
            raise StateError(f"许可状态 {p['status']} 不可审批")
        p["status"] = "approved"
        self.repo.save_permit(permit_id, "transport", "approved", p, p.get("domain", ""))
        ev = build_event(
            event_id=gen_id("evt"), gun_code=p["gun_codes"][0], event_type="permit",
            actor=approver, occurred_at=self.clock.now_iso(), location=p["destination"],
            device_id="permit-portal",
            payload={"permit_id": permit_id, "stage": "approve", "status": "approved"},
            signer_ids=[approver])
        ev.signatures[approver] = self.kms.sign(f"user:{approver}", ev.event_hash.encode())
        gun = self.repo.get_gun(p["gun_codes"][0])
        with self.repo.db.transaction() as conn:
            self._emit(conn, ev, gun)
        self.audit.append(actor=approver, action="permit:approve", target=permit_id)
        return p

    def start_transport(self, *, permit_id: str, gun_codes: list[str], vehicle: str,
                        carrier: str, escort: str, signers: list[dict],
                        position: tuple[float, float] | None = None,
                        region: dict | None = None, time_window: dict | None = None,
                        offline: bool = False) -> list[GunEvent]:
        p = self.repo.get_permit(permit_id)
        if not p:
            raise ValidationError(f"许可不存在: {permit_id}")
        if not gun_codes:
            raise ValidationError("起运须关联至少一支枪支")
        # 起运签名密码学验证：每名签名人都必须对 transport:depart 载荷用本人私钥签名
        for s in signers:
            payload = f"transport:depart:{permit_id}".encode()
            if not s.get("sig") or not self.kms.verify(f"user:{s['signer']}", payload, s["sig"]):
                raise ValidationError(f"起运签名人 {s.get('signer')} 验签失败")
        # 逐枪在库校验（防跨单位/状态机绕过）
        for code in gun_codes:
            g = self.repo.get_gun(code)
            if g.status != "in_stock":
                raise StateError(f"枪支 {code} 状态 {g.status} 不允许起运（须在库）")
        signer_ids = [s["signer"] for s in signers]
        unit = self.repo.get_unit(self.repo.get_gun(gun_codes[0]).unit_id)
        permit_ok = (p["status"] == "approved" and p.get("vehicle") == vehicle
                     and all(g in (p.get("gun_codes") or []) for g in gun_codes))
        ctx = {"now": self.clock.now_iso(), "permit": dict(p), "vehicle": vehicle,
               "carrier": carrier, "escort": escort, "gun_codes": gun_codes,
               "stage": "depart", "signers": signer_ids, "signer_ids": signer_ids,
               "position": position, "region": None if permit_ok else (region or unit.region),
               "time_window": time_window or unit.time_window,
               "offline": offline, "device_verified": True,
               "person": {}, "gun": {}, "unit": unit.to_dict()}
        self.registry.raise_all(self.registry.evaluate_all(
            ["transport_permit", "spacetime"], ctx))

        p["status"] = "in_transit"
        # 起运保存保留原归属（评审 P1-3）
        self.repo.save_permit(permit_id, "transport", "in_transit", p,
                              p.get("domain", ""))
        events = []
        for code in gun_codes:
            gun = self.repo.get_gun(code)
            ev = build_event(
                event_id=gen_id("evt"), gun_code=code, event_type="transport",
                actor=carrier, occurred_at=self.clock.now_iso(),
                location=p["origin"], device_id=f"vehicle:{vehicle}",
                payload={"permit_id": permit_id, "stage": "depart", "vehicle": vehicle,
                         "carrier": carrier, "escort": escort, "unit": gun.unit_id,
                         "position": list(position) if position else None},
                signer_ids=signer_ids)
            for s in signers:
                ev.signatures[s["signer"]] = s["sig"]
            with self.repo.db.transaction() as conn:
                self._emit(conn, ev, gun, ctx)
                conn.execute("UPDATE guns SET status='in_transit' WHERE code=?", (code,))
            events.append(ev)
        self.audit.append(actor=carrier, action="transport:depart", target=permit_id,
                          detail={"guns": gun_codes, "vehicle": vehicle})
        return events

    def verify_transport_arrival(self, *, permit_id: str, position: tuple[float, float] | None = None,
                                 region: dict | None = None, time_window: dict | None = None,
                                 verifier: str = "") -> dict:
        p = self.repo.get_permit(permit_id)
        if not p:
            raise ValidationError(f"许可不存在: {permit_id}")
        unit = self.repo.get_unit(self.repo.get_gun(p["gun_codes"][0]).unit_id)
        permit_ok = p["status"] == "in_transit"
        ctx = {"now": self.clock.now_iso(), "permit": dict(p), "vehicle": p["vehicle"],
               "carrier": p["carrier"], "escort": p["escort"], "gun_codes": p["gun_codes"],
               "stage": "verify_arrival", "signers": [verifier], "signer_ids": [verifier],
               "position": position, "region": None if permit_ok else (region or unit.region),
               "time_window": time_window or unit.time_window, "device_verified": True,
               "person": {}, "gun": {}, "unit": unit.to_dict()}
        self.registry.raise_all(self.registry.evaluate_all(
            ["transport_permit", "spacetime"], ctx))
        p["status"] = "closed"
        # 核销保存保留原归属（评审 P1-3）
        self.repo.save_permit(permit_id, "transport", "closed", p,
                              p.get("domain", ""))
        for code in p["gun_codes"]:
            gun = self.repo.get_gun(code)
            ev = build_event(
                event_id=gen_id("evt"), gun_code=code, event_type="transport",
                actor=verifier or "dest-police", occurred_at=self.clock.now_iso(),
                location=p["destination"], device_id="dest-node",
                payload={"permit_id": permit_id, "stage": "arrive_verify",
                         "unit": gun.unit_id, "position": list(position) if position else None},
                signer_ids=[verifier] if verifier else [])
            if verifier:
                ev.signatures[verifier] = self.kms.sign(f"user:{verifier}", ev.event_hash.encode())
            with self.repo.db.transaction() as conn:
                self._emit(conn, ev, gun, ctx)
                conn.execute("UPDATE guns SET status='in_stock' WHERE code=?", (code,))
        self.audit.append(actor=verifier, action="transport:verify", target=permit_id)
        return p

    # -- 配售交接（评审 P1-2） -----------------------------------------------
    def handover(self, *, gun_codes: list[str], from_unit: str, to_unit: str,
                 actor: str, ref_id: str, location: str = "") -> list[GunEvent]:
        """配售交接确认：枪支归属移交买方（登记即交付完成）。

        同步更新三处：业务台账（guns.unit_id/domain）、查询视图（事件投影
        gun_state.unit）、事件记录（gun_events + Outbox 上链）。此前只新增
        配售记录不过户，买方访问本枪档案被 403。
        """
        if from_unit == to_unit or not gun_codes:
            return []
        to_unit_row = self.repo.get_unit(to_unit)
        events: list[GunEvent] = []
        for code in dict.fromkeys(gun_codes):
            gun = self.repo.get_gun(code)
            if gun.unit_id != from_unit:
                continue                      # 归属已在买方/他方，无需过户
            ev = build_event(
                event_id=gen_id("evt"), gun_code=code, event_type="transfer",
                actor=actor, occurred_at=self.clock.now_iso(),
                location=location or to_unit, device_id="handover",
                payload={"unit": to_unit, "from_unit": from_unit,
                         "holder": gun.holder, "ref": ref_id,
                         "stage": "handover"},
                signer_ids=[actor])
            # 操作主体有签名密钥则实签名；单位代录等无密钥主体保留占位
            # （与 alert 等系统事件一致，哈希链与上链覆盖不受影响）
            if self.kms.has_key(f"user:{actor}"):
                ev.signatures[actor] = self.kms.sign(
                    f"user:{actor}", ev.event_hash.encode())
            with self.repo.db.transaction() as conn:
                self._emit(conn, ev, gun)
                conn.execute("UPDATE guns SET unit_id=?, domain=? WHERE code=?",
                             (to_unit, to_unit_row.domain or to_unit, code))
            events.append(ev)
        if events:
            self.audit.append(actor=actor, action="gun:handover", target=ref_id,
                              detail={"guns": [e.gun_code for e in events],
                                      "from": from_unit, "to": to_unit})
        return events

    # -- 4. 维修 -------------------------------------------------------------
    def repair(self, *, gun_code: str, actor: str, content: str,
               replaced_parts: list[dict] | None = None, signers: list[dict],
               voucher_hash: str = "",
               authorizer: str = "") -> GunEvent:
        gun = self.repo.get_gun(gun_code)
        if gun.status not in ("in_stock", "repairing"):
            raise StateError(f"枪支状态 {gun.status} 不允许维修登记")
        # 维修签名密码学验证 + 签名人须为本单位在册人员
        signer_ids = [s["signer"] for s in signers]
        for s in signers:
            payload = f"repair:{gun_code}".encode()
            if not s.get("sig") or not self.kms.verify(f"user:{s['signer']}", payload, s["sig"]):
                raise ValidationError(f"签名人 {s.get('signer')} 签名验证失败")
            self._signer_person_in_unit(s, gun.unit_id, strict_duty=False)
        ctx = self._ctx(gun, self.repo.get_person(actor) if _exists(self.repo, actor) else None,
                        self.repo.get_unit(gun.unit_id),
                        signers=signer_ids, signer_ids=signer_ids, manual_entry=True,
                        voucher_hash=voucher_hash or hash_obj({"content": content}),
                        allowed_gun_status=("in_stock", "repairing"))
        self.registry.raise_all(self.registry.evaluate_all(["compliance", "multisig"], ctx))

        ev = build_event(
            event_id=gen_id("evt"), gun_code=gun_code, event_type="repair",
            actor=actor, occurred_at=self.clock.now_iso(), location=gun.unit_id,
            device_id="repair-bench",
            payload={"unit": gun.unit_id, "content": content,
                     "replaced_parts": replaced_parts or [], "signers": signer_ids,
                     "voucher_hash": voucher_hash or hash_obj({"content": content}),
                     "authorizer": authorizer},
            signer_ids=signer_ids)
        for s in signers:
            ev.signatures[s["signer"]] = s["sig"]
        with self.repo.db.transaction() as conn:
            self._emit(conn, ev, gun, ctx)
        self.audit.append(actor=actor, action="gun:repair", target=gun_code,
                          detail={"parts": replaced_parts or []})
        return ev

    # -- 5. 报废销毁 ---------------------------------------------------------
    def scrap_stage(self, *, gun_code: str, stage: str, actor: str, signers: list[dict],
                    reason: str = "", appraisal: str = "",
                    done_stages: list[str] | None = None) -> GunEvent:
        gun = self.repo.get_gun(gun_code)
        unit = self.repo.get_unit(gun.unit_id)
        stages = ScrapConfirmContract.STAGES
        if stage not in stages:
            raise ValidationError(f"未知销毁阶段: {stage}")
        # 已完成节点以链上事件为准（客户端自证的 done_stages 一律忽略）：
        # 服务端按事件流提取已完成的报废阶段，并强制严格顺序（下一节点必须精确匹配）。
        done = [ev.payload.get("stage")
                for ev in self.repo.events_of(gun_code)
                if ev.event_type == "scrap" and ev.payload.get("stage") in stages]
        if len(done) >= len(stages):
            raise StateError("报废流程已全部完成，不可重复提交")
        next_stage = stages[len(done)]
        if stage != next_stage:
            raise StateError(f"销毁阶段顺序错误：下一节点应为 {next_stage}，收到 {stage}")
        # 签名密码学验证：每名签名人须用本人私钥对 scrap:{stage}:{gun_code} 签名
        for s in signers:
            payload = f"scrap:{stage}:{gun_code}".encode()
            if not s.get("sig") or not self.kms.verify(f"user:{s['signer']}", payload, s["sig"]):
                raise ValidationError(f"签名人 {s.get('signer')} 验签失败")
        signer_ids = [s["signer"] for s in signers]
        ctx = {"now": self.clock.now_iso(), "stage": stage, "reason": reason,
               "appraisal": appraisal, "signers": signer_ids, "signer_ids": signer_ids,
               "done_stages": list(done), "require_seal": True,
               "person": {}, "gun": gun.to_dict(), "unit": unit.to_dict(),
               "device_verified": True}
        self.registry.raise_all([self.registry.evaluate("scrap_confirm", ctx)])

        status_after = {"apply": "pending_destroy", "appraise": "pending_destroy",
                        "province_confirm": "pending_destroy"}.get(stage, "destroyed")
        seal = stage == "destroy_archive"
        ev = build_event(
            event_id=gen_id("evt"), gun_code=gun_code, event_type="scrap",
            actor=actor, occurred_at=self.clock.now_iso(), location=gun.unit_id,
            device_id="scrap-node",
            payload={"unit": gun.unit_id, "stage": stage, "reason": reason,
                     "appraisal": appraisal, "signers": signer_ids,
                     "status": "sealed" if seal else status_after},
            signer_ids=signer_ids)
        for s in signers:
            ev.signatures[s["signer"]] = s["sig"]
        new_status = "sealed" if seal else status_after
        with self.repo.db.transaction() as conn:
            self._emit(conn, ev, gun, ctx)
            conn.execute("UPDATE guns SET status=? WHERE code=?", (new_status, gun_code))
        self.audit.append(actor=actor, action=f"scrap:{stage}", target=gun_code,
                          detail={"seal": seal})
        return ev

    # -- 6. 资格动态管理 -----------------------------------------------------
    def update_qualification(self, *, person_id: str, cert_status: str,
                             cert_expire: str = "", actor: str = "") -> Person:
        if cert_status not in PERSON_STATUS:
            raise ValidationError(f"非法资格状态: {cert_status}")
        p = self.repo.get_person(person_id)
        p.cert_status = cert_status
        if cert_expire:
            p.cert_expire = cert_expire
        self.repo.save_person(p)
        # 资格退出：阻止其名下枪支继续流转（状态字段变更为失效的自动回应）
        if cert_status in ("revoked", "expired", "suspended"):
            blocked = [g.code for g in self.repo.guns_of(p.unit_id, "in_use")
                       if g.holder == person_id]
            for code in blocked:
                self.raise_alert(code, "emergency",
                                 f"持枪人 {person_id} 资格 {cert_status}，须立即上交名下枪支",
                                 p.unit_id)
        self.audit.append(actor=actor or "system", action="person:qualify",
                          target=person_id, detail={"status": cert_status})
        return p

    # -- 7. 风险处置：三级预警闭环 -------------------------------------------
    ALERT_DEADLINES = {"hint": 48, "concern": 8, "emergency": 2}  # 小时

    def raise_alert(self, gun_code: str, level: str, message: str, domain: str) -> dict:
        from datetime import timedelta
        if level not in self.ALERT_DEADLINES:
            raise ValidationError(f"非法预警级别: {level}")
        a = {
            "alert_id": gen_id("alr"), "level": level, "status": "open",
            "gun_code": gun_code, "subject": gun_code,
            "detail": {"message": message}, "created_at": self.clock.now_iso(),
            "deadline": (self.clock.now() + timedelta(hours=self.ALERT_DEADLINES[level])).isoformat(),
            "closed_at": "", "domain": domain,
        }
        self.repo.save_alert(a)
        # 预警事件同样上链留痕
        try:
            gun = self.repo.get_gun(gun_code)
            ev = build_event(
                event_id=gen_id("evt"), gun_code=gun_code, event_type="alert",
                actor="system", occurred_at=self.clock.now_iso(), location=domain,
                device_id="risk-engine",
                payload={"unit": domain, "level": level, "message": message,
                         "alert_id": a["alert_id"], "holder": gun.holder},
                signer_ids=["risk-engine"])
            with self.repo.db.transaction() as conn:
                self._emit(conn, ev, gun)
        except ValidationError:
            pass
        self.audit.append(actor="system", action="alert:raise", target=a["alert_id"],
                          detail={"level": level, "gun": gun_code})
        return a

    def respond_alert(self, *, alert_id: str, actor: str, response: str,
                      close: bool = False) -> dict:
        rows = self.repo.alerts()
        target = next((r for r in rows if r["alert_id"] == alert_id), None)
        if not target:
            raise ValidationError(f"预警不存在: {alert_id}")
        target["detail"].setdefault("responses", []).append(
            {"actor": actor, "at": self.clock.now_iso(), "text": response})
        if close:
            target["status"] = "closed"
            target["closed_at"] = self.clock.now_iso()
        else:
            target["status"] = "responded"
        self.repo.save_alert(target)
        self.audit.append(actor=actor, action="alert:respond", target=alert_id,
                          detail={"close": close})
        return target

    def escalate_overdue_alerts(self) -> list[dict]:
        """未在时限内响应的预警自动升级（hint→concern→emergency）。"""
        now = parse_iso(self.clock.now_iso())
        order = ["hint", "concern", "emergency"]
        escalated = []
        for a in self.repo.alerts():
            if a["status"] == "closed" or not a.get("deadline"):
                continue
            if parse_iso(a["deadline"]) < now:
                idx = order.index(a["level"]) if a["level"] in order else 0
                if idx < 2:
                    a["level"] = order[idx + 1]
                    from datetime import timedelta
                    a["deadline"] = (self.clock.now() + timedelta(
                        hours=self.ALERT_DEADLINES[a["level"]])).isoformat()
                    a["detail"].setdefault("escalations", []).append(
                        {"at": self.clock.now_iso(), "to": a["level"]})
                    self.repo.save_alert(a)
                    self.audit.append(actor="system", action="alert:escalate",
                                      target=a["alert_id"], detail={"to": a["level"]})
                    escalated.append(a)
        return escalated

    # -- 8. 时限巡检：超时未归还分级提醒 -------------------------------------
    def scan_overdue(self) -> list[dict]:
        now = parse_iso(self.clock.now_iso())
        out = []
        for g in self.repo.db.query("SELECT code FROM guns WHERE status='in_use' AND due_at!=''"):
            gun = self.repo.get_gun(g["code"])
            ctx = {"now": self.clock.now_iso(), "due_at": gun.due_at, "returned": False}
            v = self.registry.evaluate("timelimit", ctx)
            if v.outputs.get("alert_level"):
                level = v.outputs["alert_level"]
                if not self.repo.open_alert_for(gun.code, level):
                    a = self.raise_alert(gun.code, level,
                                         f"枪支 {gun.code} 超时未归还 "
                                         f"{v.outputs['overdue_hours']} 小时",
                                         gun.unit_id)
                    out.append(a)
                else:
                    self.raise_alert(gun.code, level,
                                     f"枪支 {gun.code} 持续超时 "
                                     f"{v.outputs['overdue_hours']} 小时",
                                     gun.unit_id)
                    out.append({"gun_code": gun.code, "level": level, "dup": True})
        return out


def _exists(repo: DomainRepository, pid: str) -> bool:
    return repo.db.one("SELECT person_id FROM persons WHERE person_id=?", (pid,)) is not None
