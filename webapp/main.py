"""网页演示层：把 GunSystem 的四个工作台（监管/单位/从业人员/审计）暴露为 HTTP 界面。

登录复用 BFF 的 MFA 两步认证与服务端会话；业务接口在调用领域核心后自动泵送
Outbox→链→回执→视图，保持单页无刷新即可看到链上落账。
"""
from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path

from fastapi import Body, FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from gunreg.common import (
    AuthenticationError,
    ContractRejected,
    GunRegError,
    NotFoundError,
    PermissionDenied,
    StateError,
    ValidationError,
    parse_iso,
)
from gunreg.bureau import (
    AGENCIES,
    APPROVAL_RULES,
    PIPELINE_KEYS,
    PIPELINE_NAMES,
    SCENARIOS,
    agency_of_org,
)
from gunreg.iam import totp
from gunreg.identity import CALIBER_KIND, GunCode, MAKERS

from . import config as _cfg
from .config import COOKIE_SECURE, require_demo
from .seed import DATA_DIR, seed_system

# ---------------------------------------------------------------------------
# 全局系统实例（单进程演示；uvicorn 以 1 worker 运行）
# ---------------------------------------------------------------------------
SYSTEM, CLOCK = seed_system()

_app = FastAPI(title="民用枪支区块链智慧监管系统 · 演示台")
app = _app

STATIC_DIR = Path(__file__).resolve().parent / "static"

ROLE_PAGE = {
    "admin": "/admin.html",
    "unit": "/unit.html",
    "practitioner": "/practitioner.html",
    "auditor": "/audit.html",
}

MAKER_BY_UNIT = {"mfg-yn": "云南西南", "range-a": "北方装备", "sport-a": "某运动器材厂"}


# ---------------------------------------------------------------------------
# 异常映射（统一的中文提示 + 合约拒绝明细）
# ---------------------------------------------------------------------------
def _handler(status: int):
    def handler(request: Request, exc: Exception) -> JSONResponse:
        detail = str(exc)
        extra = {"code": type(exc).__name__}
        if isinstance(exc, ContractRejected):
            extra.update({"contract": exc.contract, "rule_version": exc.version,
                          "reasons": exc.reasons})
            detail = f"合约 {exc.contract} v{exc.version} 拒绝：{'；'.join(exc.reasons)}"
        return JSONResponse({"ok": False, "detail": detail, **extra}, status_code=status)
    return handler


for _exc, _st in ((AuthenticationError, 401), (PermissionDenied, 403),
                  (StateError, 409), (NotFoundError, 404),
                  (ValidationError, 400)):
    app.add_exception_handler(_exc, _handler(_st))
app.add_exception_handler(GunRegError, _handler(400))


# ---------------------------------------------------------------------------
# 认证与会话
# ---------------------------------------------------------------------------
def _require(request: Request, perm: str, domain: str | None = None,
             state: str | None = None):
    token = request.cookies.get("gunreg_session")
    return SYSTEM.identity.require(token, perm, domain, state)


@app.get("/api/me")
async def me(request: Request):
    try:
        sub, _ = _require(request, "ledger:query")
    except AuthenticationError:
        return JSONResponse({"ok": False, "reason": "未登录"}, status_code=401)
    person = None
    try:
        person = SYSTEM.repo.get_person(sub.user_id).to_dict()
    except Exception:
        pass
    return {"ok": True,
            "user": {"id": sub.user_id, "name": sub.name, "role": sub.role,
                     "org": sub.org},
            "person": person,
            "clock": CLOCK.now_iso()}


@app.get("/api/totp-demo")
async def totp_demo(user_id: str):
    """演示便利：返回该账号当前 TOTP 动态口令（模拟手机令牌，30s 步长）。"""
    require_demo()   # 生产（GUNREG_DEMO=0）时禁用免登录口令直显
    sub = SYSTEM.identity.get(user_id)
    counter = int(CLOCK.now().timestamp()) // 30
    return {"user_id": user_id, "code": totp(sub.mfa_secret, counter),
            "remaining": 30 - (int(CLOCK.now().timestamp()) % 30)}


@app.post("/api/login")
async def login(request: Request, payload: dict = Body(...)):
    client = request.client.host if request.client else "web"
    # 演示模式（GUNREG_DEMO=1）下允许仅账号+口令登录：totp 留空即跳过 MFA；
    # 生产模式（GUNREG_DEMO=0）仍强制双因子。
    result = SYSTEM.bff.login(client, payload.get("user_id", ""),
                              payload.get("password", ""),
                              payload.get("totp", ""),
                              require_mfa=not _cfg.DEMO)
    resp = JSONResponse({"ok": True, **result,
                         "redirect": ROLE_PAGE[result["user"]["role"]]})
    resp.set_cookie("gunreg_session", result["token"], httponly=True,
                    samesite="lax", secure=COOKIE_SECURE, path="/",
                    max_age=8 * 3600)
    return resp


@app.post("/api/logout")
async def logout(request: Request):
    token = request.cookies.get("gunreg_session")
    if token:
        SYSTEM.identity.logout(token)
    resp = JSONResponse({"ok": True})
    resp.delete_cookie("gunreg_session", path="/")
    return resp


# ---------------------------------------------------------------------------
# 公共只读：合约、单位
# ---------------------------------------------------------------------------
@app.get("/api/contracts")
async def contracts():
    metas = [c.meta() for c in SYSTEM.registry._contracts.values()]
    return {"contracts": metas, "history": SYSTEM.registry.history()}


@app.get("/api/units")
async def units():
    rows = SYSTEM.repo.db.query("SELECT * FROM units ORDER BY unit_id")
    return {"items": rows}


# ---------------------------------------------------------------------------
# 枪支台账与追溯
# ---------------------------------------------------------------------------
@app.get("/api/guns")
async def guns(request: Request, status: str = "", unit: str = "",
               q: str = "", scenario: str = "", limit: int = 300, offset: int = 0):
    sub, _ = _require(request, "ledger:query")
    if sub.role in ("admin", "auditor"):
        _require(request, "gun:read:all")
        dom = unit
    elif sub.role == "unit":
        _require(request, "gun:read:domain", domain=sub.org)
        dom = sub.org
    else:
        return JSONResponse({"ok": False, "detail": "从业人员使用 /api/my/guns"},
                            status_code=403)
    page = SYSTEM.view.ledger(unit=dom or "", status=status,
                              offset=offset, limit=limit)
    if scenario:
        keep = set()
        for r in SYSTEM.repo.db.query(
                "SELECT g.code, u.unit_type FROM guns g "
                "JOIN units u ON g.unit_id=u.unit_id"):
            s = SYSTEM.bureau.scenario_of_gun(r["code"], r["unit_type"])
            if s and s["key"] == scenario:
                keep.add(r["code"])
        page["items"] = [g for g in page["items"] if g["gun_code"] in keep]
    if q:
        q = q.strip()
        page["items"] = [g for g in page["items"]
                         if q in g["gun_code"] or q in g["unit"]]
    return page


@app.get("/api/gun/{code}/timeline")
async def gun_timeline(request: Request, code: str):
    sub, _ = _require(request, "ledger:query")
    rows = SYSTEM.repo.db.query("SELECT unit_id FROM guns WHERE code=?", (code,))
    if not rows:
        raise NotFoundError(f"枪支不存在: {code}")
    if sub.role in ("unit", "practitioner"):
        _require(request, "gun:read:domain", domain=rows[0]["unit_id"])
    return {"gun_code": code, "items": SYSTEM.view.timeline(code)}


@app.get("/api/gun/{code}/evidence")
async def gun_evidence(request: Request, code: str):
    _require(request, "evidence:verify")
    rep = SYSTEM.evidence.verify_gun(code)
    return {"gun_code": code, "ok": rep.ok, "checks": rep.checks}


@app.get("/api/gun/{code}/archive")
async def gun_archive(request: Request, code: str):
    """一枪一档：全生命周期档案（主线节点 + 证照/审批/检查/运输/时间线）。"""
    sub, _ = _require(request, "ledger:query")
    rows = SYSTEM.repo.db.query("SELECT unit_id FROM guns WHERE code=?", (code,))
    if not rows:
        raise NotFoundError(f"枪支不存在: {code}")
    if sub.role in ("unit", "practitioner"):
        _require(request, "gun:read:domain", domain=rows[0]["unit_id"])
    return {"ok": True, **SYSTEM.bureau.archive(code)}


# ---------------------------------------------------------------------------
# 监管工作台
# ---------------------------------------------------------------------------
def _alert_rows():
    rows = SYSTEM.repo.db.query("SELECT * FROM alerts ORDER BY created_at DESC")
    for r in rows:
        r["detail"] = json.loads(r["detail"])
    return rows


@app.get("/api/admin/overview")
async def admin_overview(request: Request):
    _require(request, "gun:read:all", domain="")
    by_status = SYSTEM.view.db.query(
        "SELECT status, COUNT(*) c FROM gun_state GROUP BY status")
    alerts = _alert_rows()
    from collections import Counter
    level_cnt = Counter(a.get("level") for a in alerts if a.get("status") != "closed")
    open_cnt = Counter(a.get("status") for a in alerts)
    return {
        "gun_total": sum(r["c"] for r in by_status),
        "by_status": {r["status"]: r["c"] for r in by_status},
        "alert_by_level": dict(level_cnt),
        "alert_by_status": dict(open_cnt),
        "recent_stats": SYSTEM.view.stats()[-15:],
        "clock": CLOCK.now_iso(),
        "outbox": SYSTEM.outbox.stats(),
        "receipts": len(SYSTEM._receipts),
        "ledger_blocks": len(SYSTEM.ledger.blocks()),
        "contracts": [c.meta() for c in SYSTEM.registry._contracts.values()],
    }


@app.get("/api/alerts")
async def alerts(request: Request, level: str = "", status: str = ""):
    sub, _ = _require(request, "alert:handle")
    rows = _alert_rows()
    if sub.role == "unit":
        rows = [a for a in rows if a.get("domain") == sub.org]
    if level:
        rows = [a for a in rows if a.get("level") == level]
    if status:
        rows = [a for a in rows if a.get("status") == status]
    return {"items": rows}


@app.post("/api/alerts/respond")
async def alert_respond(request: Request, payload: dict = Body(...)):
    sub, _ = _require(request, "alert:handle")
    # 对象级越权：单位用户只能处置本单位的预警
    row = SYSTEM.repo.db.one("SELECT domain FROM alerts WHERE alert_id=?",
                             (payload["alert_id"],))
    if not row:
        raise NotFoundError(f"预警不存在: {payload['alert_id']}")
    if sub.role == "unit" and row["domain"] != sub.org:
        raise PermissionDenied(f"仅可处置本单位预警（{row['domain']}）")
    result = SYSTEM.domain.respond_alert(
        alert_id=payload["alert_id"], actor=sub.user_id,
        response=payload.get("response", ""), close=payload.get("close", False))
    SYSTEM.pump(rounds=200)
    return {"ok": True, "alert": result}


@app.post("/api/overdue/scan")
async def overdue_scan(request: Request):
    sub, _ = _require(request, "alert:handle")
    if sub.role != "admin":
        raise PermissionDenied("超期扫描由监管工作台执行")
    found = SYSTEM.domain.scan_overdue()
    SYSTEM.pump(rounds=200)
    return {"ok": True, "found": found}


@app.post("/api/overdue/escalate")
async def overdue_escalate(request: Request):
    sub, _ = _require(request, "alert:handle")
    if sub.role != "admin":
        raise PermissionDenied("预警升级由监管工作台执行")
    upgraded = SYSTEM.domain.escalate_overdue_alerts()
    SYSTEM.pump(rounds=200)
    return {"ok": True, "upgraded": upgraded}


@app.get("/api/admin/persons")
async def admin_persons(request: Request):
    _require(request, "gun:read:all")
    rows = SYSTEM.repo.db.query(
        "SELECT * FROM persons ORDER BY unit_id, name")
    iam = set(SYSTEM.identity._users.keys())
    for r in rows:
        r["cert_kinds"] = json.loads(r.get("cert_kinds") or "[]")
        r["can_sign"] = r["person_id"] in iam
    return {"items": rows, "iam_users": sorted(iam)}


@app.post("/api/clock/advance")
async def clock_advance(request: Request, payload: dict = Body(...)):
    sub, _ = _require(request, "alert:handle")
    require_demo()   # 生产关闭时禁止演示时钟推进
    if sub.role != "admin":
        raise PermissionDenied("演示时间推进仅监管工作台可用")
    hours = float(payload.get("hours", 0))
    CLOCK.advance(hours=hours)
    # 演示时钟推进时，顺延所有会话有效期，避免事务推进导致登录态失效
    if hours:
        delta = timedelta(hours=hours)
        for sess in SYSTEM.identity._sessions.values():
            try:
                sess.expires_at = (parse_iso(sess.expires_at) + delta).isoformat()
            except Exception:
                pass
    return {"ok": True, "now": CLOCK.now_iso()}


# ---------------------------------------------------------------------------
# 运输许可（监管审批 / 单位申报）
# ---------------------------------------------------------------------------
@app.get("/api/permits")
async def permits(request: Request):
    sub, _ = _require(request, "ledger:query")
    rows = SYSTEM.repo.db.query("SELECT * FROM permits ORDER BY rowid")
    out = []
    for r in rows:
        d = json.loads(r["data"])
        d.update({"permit_id": r["permit_id"], "kind": r["kind"],
                  "status": r["status"], "domain": r["domain"]})
        # 单位/从业人员只能看到本单位域内的运输许可
        if sub.role in ("unit", "practitioner") and d.get("domain") != sub.org:
            continue
        out.append(d)
    return {"items": out}


@app.post("/api/permit/approve")
async def permit_approve(request: Request, payload: dict = Body(...)):
    # 评审问题 P1-1：运输许可审批为公安专属环节，非公安部门不可批准
    sub, _ = _require_police(request, "permit:approve", "运输许可审批")
    p = SYSTEM.domain.approve_transport_permit(permit_id=payload["permit_id"],
                                               approver=sub.user_id)
    SYSTEM.pump(rounds=200)
    return {"ok": True, "permit": p}


@app.post("/api/permit/verify")
async def permit_verify(request: Request, payload: dict = Body(...)):
    # 评审问题 P1-1：到达核销同属公安监管环节
    sub, _ = _require_police(request, "permit:approve", "运输到达核销")
    pos = payload.get("position")
    p = SYSTEM.domain.verify_transport_arrival(
        permit_id=payload["permit_id"],
        position=tuple(pos) if pos else None, verifier=sub.user_id)
    SYSTEM.pump(rounds=200)
    return {"ok": True, "permit": p}


@app.post("/api/permit/request")
async def permit_request(request: Request, payload: dict = Body(...)):
    sub, _ = _require(request, "permit:request")
    guns = payload.get("gun_codes") or []
    if not guns:
        raise ValidationError("请选择至少一支枪支")
    # 对象级校验：逐枪取单位，须同一数据域且均为在库枪
    units: set[str] = set()
    for code in guns:
        row = SYSTEM.repo.db.one("SELECT unit_id FROM guns WHERE code=?", (code,))
        if not row:
            raise NotFoundError(f"枪支不存在: {code}")
        units.add(row["unit_id"])
    if len(units) != 1:
        raise PermissionDenied(f"一次运输须为同一单位枪支（涉及 {sorted(units)}）")
    _require(request, "permit:request", domain=next(iter(units)))
    # 前置条件：配售配购到位（有配售登记）才允许申报运输
    SYSTEM.bureau.require_sale(guns, "运输申报")
    d = SYSTEM.domain.request_transport_permit(
        permit_id=payload.get("permit_id") or f"PERMIT-{int(CLOCK.now().timestamp())}",
        gun_codes=guns, vehicle=payload["vehicle"], carrier=payload["carrier"],
        escort=payload.get("escort", ""), applicant=sub.user_id,
        valid_from=payload["valid_from"], valid_end=payload["valid_end"],
        origin=payload.get("origin", ""), destination=payload.get("destination", ""))
    d["status"] = "applied"
    SYSTEM.pump(rounds=200)
    return {"ok": True, "permit": d}


@app.post("/api/permit/start")
async def permit_start(request: Request, payload: dict = Body(...)):
    sub, _ = _require(request, "permit:request")
    guns = payload.get("gun_codes") or []
    if not guns:
        raise ValidationError("请选择至少一支枪支")
    # 逐枪校验属于申请单位的数据域
    for code in guns:
        row = SYSTEM.repo.db.one("SELECT unit_id FROM guns WHERE code=?", (code,))
        if not row:
            raise NotFoundError(f"枪支不存在: {code}")
        _require(request, "permit:request", domain=row["unit_id"])
    permit_id = payload["permit_id"]
    # 服务端代签：起运签名须覆盖 transport:depart:{permit_id}，不能由客户端任意自签
    signers = _signers_with_duty([(sub.user_id, "承运方")],
                                 f"transport:depart:{permit_id}",
                                 org=sub.org, operator=sub.user_id, strict_duty=False)
    events = SYSTEM.domain.start_transport(
        permit_id=permit_id, gun_codes=guns,
        vehicle=payload["vehicle"], carrier=payload["carrier"],
        escort=payload.get("escort", ""), signers=signers,
        position=tuple(payload["position"]) if payload.get("position") else None)
    SYSTEM.pump(rounds=200)
    return {"ok": True, "events": len(events), "permit_id": permit_id}


# ---------------------------------------------------------------------------
# 报废销毁
# ---------------------------------------------------------------------------
SCRAP_STAGES = ("apply", "appraise", "province_confirm", "destroy_submit",
                "destroy_inventory", "destroy_execute", "destroy_archive")


@app.post("/api/scrap")
async def scrap(request: Request, payload: dict = Body(...)):
    code = payload["gun_code"]
    row = SYSTEM.repo.db.one("SELECT unit_id FROM guns WHERE code=?", (code,))
    if not row:
        raise NotFoundError(f"枪支不存在: {code}")
    stage = payload["stage"]
    if stage not in SCRAP_STAGES:
        raise ValidationError(f"未知销毁阶段: {stage}")
    if stage in ("apply", "appraise"):
        # 单位分支：单位用户（event:submit）对本单位枪支申报/鉴定
        sub, _ = _require(request, "event:submit", domain=row["unit_id"])
    else:
        # 监管分支：省级确认仅 admin，销毁四节点需 scrap:confirm；
        # 评审问题 P1-1：报废确认与销毁监督为公安专属环节，非公安部门不可执行
        sub, _ = _require_police(request, "scrap:confirm", "报废确认与销毁监督")
        if stage == "province_confirm" and sub.role != "admin":
            raise PermissionDenied("省级确认须由监管工作台执行")
    # 服务端代签：签名须覆盖 scrap:{stage}:{gun_code}，不能由客户端任意自签；
    # 申请/鉴定阶段的签名人必须是本单位在册人员。
    signers = []
    seen = set()
    for s, r in payload.get("signers", []):
        if s in seen:
            raise ValidationError(f"签名人重复: {s}")
        seen.add(s)
        if stage in ("apply", "appraise"):
            try:
                person = SYSTEM.repo.get_person(s)
            except Exception:
                raise ValidationError(f"签名人 {s} 不是本单位在册人员") from None
            if person.unit_id != row["unit_id"]:
                raise PermissionDenied(
                    f"签名人 {s} 属于 {person.unit_id}，不在本单位 {row['unit_id']}")
        if not SYSTEM.kms.has_key(f"user:{s}"):
            raise ValidationError(f"签名人 {s} 未配置签名密钥（无 IAM 账号）")
        sig = SYSTEM.kms.sign(f"user:{s}", f"scrap:{stage}:{code}".encode())
        signers.append({"signer": s, "role": r, "sig": sig})
    ev = SYSTEM.domain.scrap_stage(
        gun_code=code, stage=stage, actor=sub.user_id,
        reason=payload.get("reason", ""), appraisal=payload.get("appraisal", ""),
        signers=signers)
    SYSTEM.pump(rounds=200)
    return {"ok": True, "event": ev.to_dict(), "stage": stage}


# ---------------------------------------------------------------------------
# 单位工作台
# ---------------------------------------------------------------------------
@app.get("/api/unit/persons")
async def unit_persons(request: Request):
    sub, _ = _require(request, "gun:read:domain")
    _require(request, "gun:read:domain", domain=sub.org)
    rows = SYSTEM.repo.db.query("SELECT * FROM persons WHERE unit_id=? ORDER BY name",
                                (sub.org,))
    for r in rows:
        r["cert_kinds"] = json.loads(r.get("cert_kinds") or "[]")
    return {"items": rows}


@app.get("/api/unit/devices")
async def unit_devices(request: Request):
    sub, _ = _require(request, "gun:read:domain")
    _require(request, "gun:read:domain", domain=sub.org)
    items = [{"device_id": k, "protocol": v.protocol, "org": v.org}
             for k, v in SYSTEM.device_gw._devices.items()]
    return {"items": items}


@app.post("/api/unit/person")
async def unit_person_add(request: Request, payload: dict = Body(...)):
    sub, _ = _require(request, "event:submit")
    _require(request, "event:submit", domain=sub.org)
    pid = payload["person_id"]
    # 防 INSERT OR REPLACE 跨单位覆盖既有人员档案
    existing = SYSTEM.repo.db.one("SELECT unit_id FROM persons WHERE person_id=?", (pid,))
    if existing:
        if existing["unit_id"] != sub.org:
            raise PermissionDenied(
                f"人员 {pid} 已属于 {existing['unit_id']}，禁止覆盖其他单位档案")
        raise ValidationError(f"人员编号已存在: {pid}")
    p = SYSTEM.register_person(
        person_id=pid, name=payload["name"], unit_id=sub.org,
        duty=payload.get("duty", "使用"),
        cert_status=payload.get("cert_status", "valid"),
        cert_kinds=payload.get("cert_kinds", []),
        cert_expire=payload.get("cert_expire", ""))
    # 为新人员签发 IAM 账号（供扫码/签名使用）
    if payload.get("create_login"):
        SYSTEM.identity.register(p.person_id, p.name, "practitioner", sub.org,
                                 payload.get("password", "user123"))
    return {"ok": True, "person": p.to_dict()}


@app.post("/api/unit/device")
async def unit_device_add(request: Request, payload: dict = Body(...)):
    sub, _ = _require(request, "event:submit")
    _require(request, "event:submit", domain=sub.org)
    SYSTEM.register_device(payload["device_id"], payload.get("protocol", "scan"),
                           sub.org)
    return {"ok": True}


def _signers_with_duty(pairs: list[tuple[str, str]], payload_of,
                       *, org: str, operator: str = "",
                       strict_duty: bool = True) -> list[dict]:
    """服务端代签（模拟签名人设备私钥）——审计问题1「任意代签」的收敛。

    签名人必须是本单位在册人员（或操作者本人）；strict_duty=True（领用/归还）
    时申报岗位必须与在册岗位一致，防止借用他人签名冒充「保管+监督」双岗。
    payload 由调用方按业务构造（checkout:{code}:{holder} / transport:depart:{permit} …），
    签名由 KMS 以签名人密钥生成，域层会再次密码学验签（纵深防御）。
    """
    out = []
    seen: set[str] = set()
    for pid, role in pairs:
        if pid in seen:
            raise ValidationError(f"签名人重复: {pid}")
        seen.add(pid)
        if pid != operator:
            # 非操作者本人的签名人须是本单位在册人员
            try:
                person = SYSTEM.repo.get_person(pid)
            except Exception:
                raise ValidationError(f"签名人 {pid} 不是本单位在册人员") from None
            if person.unit_id != org:
                raise ValidationError(
                    f"签名人 {pid} 属于 {person.unit_id}，不在本单位 {org}")
            if strict_duty and role != person.duty:
                raise ValidationError(
                    f"签名人 {pid} 申报岗位 {role}，在册岗位为 {person.duty}，不一致")
        if not SYSTEM.kms.has_key(f"user:{pid}"):
            raise ValidationError(f"签名人 {pid} 未配置签名密钥（无 IAM 账号）")
        sig = SYSTEM.kms.sign(f"user:{pid}", payload_of.encode())
        out.append({"signer": pid, "role": role, "sig": sig})
    return out


@app.post("/api/unit/checkout")
async def unit_checkout(request: Request, payload: dict = Body(...)):
    sub, _ = _require(request, "event:submit")
    _require(request, "event:submit", domain=sub.org)
    code = payload["gun_code"]
    row = SYSTEM.repo.db.one("SELECT unit_id FROM guns WHERE code=?", (code,))
    if not row:
        raise NotFoundError(f"枪支不存在: {code}")
    _require(request, "event:submit", domain=row["unit_id"])
    holder = payload["person_id"]
    pairs = [tuple(x) for x in payload["signers"]]  # [(pid, role), ...]
    # 前置条件：配售配购到位（有配售登记）才允许领用
    SYSTEM.bureau.require_sale([code], "领用")
    sigs = _signers_with_duty(pairs, f"checkout:{code}:{holder}",
                              org=sub.org, operator=sub.user_id, strict_duty=True)
    ev = SYSTEM.domain.checkout(
        gun_code=code, person_id=holder, signers=sigs,
        location=payload.get("location", ""), due_hours=int(payload.get("due_hours", 8)),
        authorizer=sub.user_id)
    SYSTEM.pump(rounds=200)
    return {"ok": True, "event": ev.to_dict(), "due_at": ev.payload.get("due_at")}


@app.post("/api/unit/checkin")
async def unit_checkin(request: Request, payload: dict = Body(...)):
    sub, _ = _require(request, "event:submit")
    _require(request, "event:submit", domain=sub.org)
    code = payload["gun_code"]
    row = SYSTEM.repo.db.one("SELECT unit_id FROM guns WHERE code=?", (code,))
    if not row:
        raise NotFoundError(f"枪支不存在: {code}")
    _require(request, "event:submit", domain=row["unit_id"])
    holder = payload["person_id"]
    pairs = [tuple(x) for x in payload["signers"]]
    sigs = _signers_with_duty(pairs, f"return:{code}:{holder}",
                              org=sub.org, operator=sub.user_id, strict_duty=True)
    ev = SYSTEM.domain.checkin(gun_code=code, person_id=holder, signers=sigs,
                               location=payload.get("location", ""),
                               authorizer=sub.user_id)
    SYSTEM.pump(rounds=200)
    return {"ok": True, "event": ev.to_dict()}


@app.post("/api/unit/repair")
async def unit_repair(request: Request, payload: dict = Body(...)):
    sub, _ = _require(request, "event:submit")
    _require(request, "event:submit", domain=sub.org)
    code = payload["gun_code"]
    row = SYSTEM.repo.db.one("SELECT unit_id FROM guns WHERE code=?", (code,))
    if not row:
        raise NotFoundError(f"枪支不存在: {code}")
    _require(request, "event:submit", domain=row["unit_id"])
    pairs = [tuple(x) for x in payload["signers"]]
    sigs = _signers_with_duty(pairs, f"repair:{code}",
                              org=sub.org, operator=sub.user_id, strict_duty=False)
    # 维修责任主体 = 单位在册人员（UI 以 payload.actor 指定；合规合约要求
    # 操作主体通过身份核验，不能把非在册的单位管理员账号硬塞成 actor）。
    actor = payload.get("actor") or sub.user_id
    try:
        ev_actor = SYSTEM.repo.get_person(actor)
    except Exception:
        raise ValidationError(f"维修责任主体 {actor} 不是登记人员") from None
    if ev_actor.unit_id != row["unit_id"]:
        raise PermissionDenied(
            f"维修责任主体 {actor} 属于 {ev_actor.unit_id}，不在本单位 {row['unit_id']}")
    ev = SYSTEM.domain.repair(gun_code=code, actor=actor,
                              content=payload["content"], signers=sigs)
    SYSTEM.pump(rounds=200)
    return {"ok": True, "event": ev.to_dict()}


@app.get("/api/unit/manufacture/next")
async def manufacture_next(request: Request, kind: str = "手枪", year: int = 0):
    sub, _ = _require(request, "gun:create")
    year = year or CLOCK.now().year
    maker = MAKER_BY_UNIT.get(sub.org)
    if not maker:
        raise PermissionDenied("本单位无制造赋码权限")
    mx = 0
    for r in SYSTEM.repo.db.query("SELECT code FROM guns"):
        try:
            gc = GunCode.parse(r["code"])
        except Exception:
            continue
        if (gc.maker == MAKERS[maker] and gc.kind == CALIBER_KIND[kind]
                and gc.year == str(year)):
            mx = max(mx, int(gc.serial))
    return {"next_serial": mx + 1, "maker": maker}


@app.post("/api/unit/manufacture")
async def unit_manufacture(request: Request, payload: dict = Body(...)):
    sub, _ = _require(request, "gun:create")
    unit = SYSTEM.repo.get_unit(sub.org)
    if unit.unit_type != "manufacture":
        raise PermissionDenied("仅制造企业可赋码")
    # 前置条件一：有效制造许可证（《枪支管理法》第十五条，国务院公安部门核发）
    SYSTEM.bureau.require_license(sub.org, "mfg_license", "制造赋码")
    # 前置条件二：已批准的生产计划 + 批次备案 + 数量未用完（评审问题 P2-4）
    plan = SYSTEM.bureau.require_plan(sub.org, payload.get("batch_ref", ""))
    maker = MAKER_BY_UNIT[sub.org]
    gun = SYSTEM.domain.manufacture(
        maker=maker, kind=payload["kind"], year=int(payload.get("year", CLOCK.now().year)),
        serial=int(payload["serial"]),
        legacy_no=payload.get("legacy_no", f"GA{str(CLOCK.now().year)[2:]}·{payload['serial']:06d}"),
        unit_id=sub.org,
        part_categories=payload.get("part_categories", ["枪管", "撞针", "弹匣", "枪身"]),
        signer=sub.user_id)
    # 赋码成功后才消耗计划数量（失败不扣）
    SYSTEM.bureau.consume_plan(plan["plan_id"], gun.code)
    SYSTEM.pump(rounds=200)
    return {"ok": True, "gun": gun.to_dict(), "plan_id": plan["plan_id"],
            "batch_ref": plan["batch_ref"]}


# ---------------------------------------------------------------------------
# 从业人员端
# ---------------------------------------------------------------------------
@app.get("/api/my/guns")
async def my_guns(request: Request):
    sub, _ = _require(request, "gun:read:domain")
    _require(request, "gun:read:domain", domain=sub.org)
    rows = SYSTEM.repo.db.query("SELECT code, status, holder FROM guns WHERE holder=?",
                                (sub.user_id,))
    out = []
    for r in rows:
        try:
            g = SYSTEM.view.gun(r["code"])
            g["unit"] = SYSTEM.repo.db.one(
                "SELECT name FROM units WHERE unit_id=?", (g.get("unit", ""),))
            if g.get("unit"):
                g["unit_name"] = g["unit"]["name"]
            out.append(g)
        except Exception:
            continue
    return {"items": out}


@app.get("/api/my/events")
async def my_events(request: Request, limit: int = 50):
    sub, _ = _require(request, "gun:read:domain")
    _require(request, "gun:read:domain", domain=sub.org)
    rows = SYSTEM.repo.db.query("SELECT code FROM guns WHERE holder=?", (sub.user_id,))
    items = []
    for r in rows:
        for ev in SYSTEM.view.timeline(r["code"]):
            ev["gun_code"] = r["code"]
            items.append(ev)
    items.sort(key=lambda e: e.get("occurred_at", ""), reverse=True)
    return {"items": items[:limit]}


@app.post("/api/qualify")
async def qualify(request: Request, payload: dict = Body(...)):
    sub, _ = _require(request, "event:submit")
    _require(request, "event:submit", domain=sub.org)
    target = payload["person_id"]
    if sub.role == "practitioner" and target != sub.user_id:
        raise PermissionDenied("仅可维护本人资格")
    if sub.role == "unit":
        # 单位只能维护本单位人员的资格
        row = SYSTEM.repo.db.one("SELECT unit_id FROM persons WHERE person_id=?", (target,))
        if not row:
            raise NotFoundError(f"人员不存在: {target}")
        if row["unit_id"] != sub.org:
            raise PermissionDenied("仅可维护本单位人员资格")
    p = SYSTEM.domain.update_qualification(
        person_id=target, cert_status=payload["cert_status"],
        cert_expire=payload.get("cert_expire", ""), actor=sub.user_id)
    SYSTEM.pump(rounds=200)
    return {"ok": True, "person": p.to_dict()}


# ---------------------------------------------------------------------------
# 跨部门协同：五类业务场景 + 一枪一档 + 全生命周期监管
# ---------------------------------------------------------------------------
def _bureau_agency(request: Request, perm: str, domain: str | None = None):
    """认证并返回 (subject, agency_id)；非部门账号 agency_id 为 None。"""
    sub, _ = _require(request, perm, domain)
    return sub, agency_of_org(sub.org)


def _require_police(request: Request, perm: str, purpose: str):
    """公安专属环节（运输审批、报废确认与销毁等）：仅公安部门账号可办理。

    评审问题 P1-1：林草/体育/海关账号同为 role=admin，此前仅校验角色即可
    批准运输、报废节点——须同步加部门（分组）校验。
    """
    sub, agency = _bureau_agency(request, perm)
    if not agency or AGENCIES[agency]["group"] != "police":
        raise PermissionDenied(
            f"{purpose}由公安机关实施，"
            f"当前账号所属部门无此权限（{sub.org}）")
    return sub, agency


def _bureau_visible(sub, items: list[dict]) -> list[dict]:
    """部门权限过滤：单位看本单位申请；部门按事项分组（辖区）查看；审计全量。"""
    if sub.role in ("unit", "practitioner"):
        return [a for a in items if a["applicant_unit"] == sub.org]
    if sub.role == "auditor":
        return items
    agency = agency_of_org(sub.org)
    if not agency:
        return items                      # 通用监管管理员：全量可见
    matters = SYSTEM.bureau.matters_of_group(AGENCIES[agency]["group"])
    return [a for a in items if a["matter"] in matters]


@app.get("/api/bureau/rules")
async def bureau_rules(request: Request):
    """审批规则（可配置）：事项 → 部门链 + 材料 + 依据 + 五类场景 + 主线阶段。"""
    _require(request, "ledger:query")
    return {
        "rules": SYSTEM.bureau.rules(),
        "agencies": SYSTEM.bureau.agencies(),
        "scenarios": [{"key": k, **v} for k, v in SCENARIOS.items()],
        "stages": [{"key": k, "name": PIPELINE_NAMES[k]} for k in PIPELINE_KEYS],
    }


@app.get("/api/bureau/overview")
async def bureau_overview(request: Request):
    """全生命周期监管总览：五类场景入口、各阶段数量、待审批、检查整改。"""
    _require(request, "gun:read:all", domain="")
    return {"ok": True, **SYSTEM.bureau.lifecycle_overview()}


@app.get("/api/bureau/apps")
async def bureau_apps(request: Request, status: str = "", category: str = "",
                      matter: str = ""):
    sub, _ = _require(request, "ledger:query")
    items = SYSTEM.bureau.list_apps(status=status, category=category,
                                    matters={matter} if matter else None)
    return {"items": _bureau_visible(sub, items)}


@app.post("/api/bureau/apps")
async def bureau_apply(request: Request, payload: dict = Body(...)):
    sub, _ = _bureau_agency(request, "permit:request")
    matter = payload.get("matter", "")
    rule = APPROVAL_RULES.get(matter)
    if not rule:
        raise ValidationError(f"未知审批事项: {matter}")
    applicant = sub.org if sub.role in ("unit", "practitioner") \
        else payload.get("applicant_unit", "")
    if sub.role in ("unit", "practitioner") and \
            payload.get("applicant_unit") not in (None, "", sub.org):
        raise PermissionDenied("仅可为本单位提交申请")
    guns = payload.get("gun_codes") or []
    for code in guns:
        row = SYSTEM.repo.db.one("SELECT unit_id FROM guns WHERE code=?", (code,))
        if not row:
            raise NotFoundError(f"枪支不存在: {code}")
        if sub.role in ("unit", "practitioner") and row["unit_id"] != sub.org:
            raise PermissionDenied(f"枪支 {code} 不属于本单位")
    # 前置条件：进出境业务须先完成配售配购登记
    if rule["category"] == "进出境" and guns:
        SYSTEM.bureau.require_sale(guns, rule["name"])
    app = SYSTEM.bureau.apply(
        matter=matter, applicant_unit=applicant,
        applicant_person=payload.get("applicant_person", ""),
        gun_codes=guns, materials=payload.get("materials") or [],
        scenario=payload.get("scenario", ""), title=payload.get("title", ""),
        source="real", actor=sub.user_id,
        batch_ref=payload.get("batch_ref", ""),
        planned_qty=int(payload.get("planned_qty") or 0))
    return {"ok": True, "app": app}


@app.post("/api/bureau/apps/{app_id}/resubmit")
async def bureau_resubmit(request: Request, app_id: str, payload: dict = Body(...)):
    sub, _ = _require(request, "permit:request")
    cur = SYSTEM.bureau.get_app(app_id)
    if sub.role in ("unit", "practitioner") and cur["applicant_unit"] != sub.org:
        raise PermissionDenied("仅申请单位可提交补正材料")
    app = SYSTEM.bureau.resubmit(app_id, payload.get("materials"),
                                 actor=sub.user_id)
    return {"ok": True, "app": app}


@app.post("/api/bureau/apps/{app_id}/process")
async def bureau_process(request: Request, app_id: str, payload: dict = Body(...)):
    """按部门链办理当前节点；节点必须由链上对应部门处理（不可通用管理员包办）。"""
    sub, agency = _bureau_agency(request, "permit:approve")
    if not agency:
        raise PermissionDenied("该账号不属于任何审批部门，无办理权限")
    app = SYSTEM.bureau.process(
        app_id, agency_id=agency, handler=sub.user_id,
        action=payload.get("action", "approve"),
        opinion=payload.get("opinion", ""),
        materials=payload.get("materials"))
    return {"ok": True, "app": app}


@app.get("/api/bureau/licenses")
async def bureau_licenses(request: Request, unit_id: str = ""):
    sub, _ = _require(request, "ledger:query")
    holder = sub.org if sub.role in ("unit", "practitioner") else unit_id
    return {"items": SYSTEM.bureau.licenses(holder)}


@app.get("/api/bureau/plans")
async def bureau_plans(request: Request, unit_id: str = ""):
    """生产计划（含批次与已赋码数量）：制造赋码选批次、档案展示用。"""
    sub, _ = _require(request, "ledger:query")
    unit = sub.org if sub.role in ("unit", "practitioner") else unit_id
    return {"items": SYSTEM.bureau.plans(unit)}


@app.get("/api/bureau/sales")
async def bureau_sales(request: Request):
    sub, _ = _require(request, "ledger:query")
    items = SYSTEM.bureau.sales()
    if sub.role in ("unit", "practitioner"):
        items = [s for s in items
                 if sub.org in (s["seller_unit"], s["buyer_unit"])]
    return {"items": items}


@app.post("/api/bureau/sales")
async def bureau_sale_create(request: Request, payload: dict = Body(...)):
    sub, _ = _require(request, "permit:request")
    guns = payload.get("gun_codes") or []
    seller = payload.get("seller_unit", "")
    buyer = payload.get("buyer_unit", "")
    if sub.role == "unit" and sub.org not in (seller, buyer):
        raise PermissionDenied("本单位须作为配售方或配置方")
    sale = SYSTEM.bureau.create_sale(
        sale_id=payload.get("sale_id") or
        f"SALE-{int(CLOCK.now().timestamp())}",
        seller_unit=seller, buyer_unit=buyer, gun_codes=guns,
        scenario=payload.get("scenario", ""),
        license_id=payload.get("license_id", ""),
        purchase_app_id=payload.get("purchase_app_id", ""),
        note=payload.get("note", ""), source="real", actor=sub.user_id)
    # 配售登记含交接过户事件：泵送入链，查询视图（gun_state/timeline）即时更新
    SYSTEM.pump(rounds=200)
    return {"ok": True, "sale": sale}


@app.get("/api/bureau/inspections")
async def bureau_inspections(request: Request):
    sub, _ = _require(request, "ledger:query")
    items = SYSTEM.bureau.inspections()
    if sub.role in ("unit", "practitioner"):
        items = [i for i in items if i["target_unit"] == sub.org]
    return {"items": items}


@app.post("/api/bureau/inspections")
async def bureau_inspection_create(request: Request, payload: dict = Body(...)):
    sub, agency = _bureau_agency(request, "permit:approve")
    if not agency:
        raise PermissionDenied("仅检查部门可发起监督检查")
    insp = SYSTEM.bureau.create_inspection(
        agency_id=agency, inspector=sub.user_id,
        target_unit=payload["target_unit"],
        findings=payload.get("findings") or [],
        deadline=payload.get("deadline", ""),
        gun_codes=payload.get("gun_codes") or [], source="real")
    return {"ok": True, "inspection": insp}


@app.post("/api/bureau/inspections/{insp_id}/rectify")
async def bureau_rectify(request: Request, insp_id: str, payload: dict = Body(...)):
    sub, _ = _require(request, "alert:handle")
    insp = SYSTEM.bureau.rectify(
        insp_id, note=payload.get("note", ""),
        actor_unit=(sub.org if sub.role in ("unit", "practitioner") else ""),
        actor=sub.user_id)
    return {"ok": True, "inspection": insp}


@app.post("/api/bureau/inspections/{insp_id}/recheck")
async def bureau_recheck(request: Request, insp_id: str, payload: dict = Body(...)):
    sub, agency = _bureau_agency(request, "permit:approve")
    if not agency:
        raise PermissionDenied("仅检查部门可执行复查")
    # 评审问题 P2-6：复查须显式给出通过/不通过（不通过退回整改，留多轮记录）；
    # 字段校验放在领域层部门校验之后，越权仍先返回 403。
    insp = SYSTEM.bureau.recheck(insp_id, agency_id=agency,
                                 inspector=sub.user_id,
                                 result=payload.get("result", ""),
                                 passed=payload.get("passed"))
    return {"ok": True, "inspection": insp}


# ---------------------------------------------------------------------------
# 审计工作台
# ---------------------------------------------------------------------------
@app.get("/api/audit/log")
async def audit_log(request: Request):
    _require(request, "audit:read")
    return {"items": SYSTEM.audit.records()}


@app.post("/api/audit/log/verify")
async def audit_log_verify(request: Request):
    _require(request, "audit:read")
    ok, msg = SYSTEM.audit.verify()
    return {"ok": ok, "message": msg}


@app.get("/api/audit/ledger")
async def audit_ledger(request: Request):
    _require(request, "audit:read")
    return {"blocks": SYSTEM.ledger.blocks(),
            "txs": SYSTEM.ledger.txs(),
            "events": len(SYSTEM.ledger.events())}


@app.post("/api/audit/ledger/verify")
async def audit_ledger_verify(request: Request):
    _require(request, "audit:read")
    ok, msg = SYSTEM.ledger.verify()
    return {"ok": ok, "message": msg}


@app.post("/api/audit/rebuild")
async def audit_rebuild(request: Request):
    _require(request, "audit:ops")
    n = SYSTEM.rebuild_view()
    return {"ok": True, "rebuilt": n}


@app.get("/api/audit/outbox")
async def audit_outbox(request: Request):
    _require(request, "audit:read")
    return {"outbox": SYSTEM.outbox.stats(),
            "receipts": len(SYSTEM._receipts),
            "bus": {"delivered": SYSTEM.bus.delivered,
                    "failed": SYSTEM.bus.failed,
                    "dead": len(SYSTEM.bus.dead_letters())},
            "reconcile": SYSTEM.adapter.reconcile(),
            "queue": SYSTEM.outbox.pending(50)}


@app.get("/api/audit/stats")
async def audit_stats(request: Request):
    _require(request, "audit:read")
    return SYSTEM.view.stats()


@app.post("/api/audit/pump")
async def audit_pump(request: Request, payload: dict = Body(default={})):
    _require(request, "audit:ops")
    rounds = int(payload.get("rounds", 50))
    published = SYSTEM.pump(rounds=rounds)
    return {"ok": True, "published": published,
            "outbox": SYSTEM.outbox.stats(),
            "receipts": len(SYSTEM._receipts),
            "bus_dead": len(SYSTEM.bus.dead_letters())}


# ---------------------------------------------------------------------------
# 静态页面（登录页 + 四个工作台）
# ---------------------------------------------------------------------------
@app.get("/")
async def root():
    return RedirectResponse("/login.html")


app.mount("/", StaticFiles(directory=str(STATIC_DIR)), name="static")