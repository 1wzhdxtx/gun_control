"""安全回归测试：深入审计 10 项问题的修复进行纵深验证。

分两层：
- 域层（进程内 GunSystem）：签名伪造 / 跨单位签名 / 岗位冒充 / 运输与报废守卫 /
  链拒绝→死信（不静默成功）/ 设备报文防篡改·防重放 / 视图投影不被"过路事件"污染。
- Webapp API 层（TestClient 真实接口）：角色权限分档 / 数据域隔离 / 跨单位越权 /
  demo 门控。webapp 数据以 GUNREG_RESET=1 确定性重建（import 即 seed）。
"""
import os
import sys
from datetime import datetime, timezone

# 必须在导入 webapp.main 之前设置：API 测试需要确定性种子
os.environ["GUNREG_RESET"] = "1"

sys.path.insert(0, ".")

import pytest  # noqa: E402

from gunreg import GunSystem, ManualClock  # noqa: E402
from gunreg.common import (  # noqa: E402
    AuthenticationError,
    PermissionDenied,
    ReplayError,
    StateError,
    ValidationError,
)
from gunreg.iam import Subject, check_abac, check_rbac  # noqa: E402


# ---------------------------------------------------------------------------
# 域层 fixture：两单位 + 双人签名在册人员（全部持 IAM 密钥）
# ---------------------------------------------------------------------------
@pytest.fixture()
def ha():
    clock = ManualClock(datetime(2026, 3, 1, 9, 0, tzinfo=timezone.utc))
    s = GunSystem(clock=clock)
    s.register_unit("unit:range-a", "某射击场", "shooting_range", risk_level=2)
    s.register_unit("unit:sport-a", "某运动学校", "sports_school", risk_level=2)
    for pid, name, unit, duty in (
        ("ra-k", "保管A", "unit:range-a", "保管"),
        ("ra-s", "监督A", "unit:range-a", "监督"),
        ("ra-u", "使用A", "unit:range-a", "使用"),
        ("sp-k", "保管B", "unit:sport-a", "保管"),
        ("sp-s", "监督B", "unit:sport-a", "监督"),
    ):
        s.register_person(pid, name, unit, duty=duty, cert_kinds=["手枪"],
                          cert_expire="2028-12-31T00:00:00+00:00")
        s.identity.register(pid, name, "practitioner", unit, "pw-" + pid)
    s.identity.register("u-rng", "射击场管理员", "unit", "unit:range-a", "pw")
    s.identity.register("u-spt", "学校管理员", "unit", "unit:sport-a", "pw")
    s.identity.register("u-pol", "省级民警", "admin", "police:sd", "pw")
    return s


def _mk(s, unit_id, serial, maker="云南西南", kind="手枪"):
    signer = {"unit:range-a": "u-rng", "unit:sport-a": "u-spt"}[unit_id]
    return s.domain.manufacture(maker=maker, kind=kind, year=2026, serial=serial,
                                legacy_no=f"GA26-{serial:06d}", unit_id=unit_id,
                                part_categories=["枪管", "撞针"], signer=signer)


def _ck_sig(s, uid, role, gun_code, person, action="checkout"):
    return {"signer": uid, "role": role,
            "sig": s.kms.sign(f"user:{uid}", f"{action}:{gun_code}:{person}".encode())}


def _scrap_sig(s, uid, role, gun_code, stage):
    return {"signer": uid, "role": role,
            "sig": s.kms.sign(f"user:{uid}", f"scrap:{stage}:{gun_code}".encode())}


def _trans_sig(s, uid, role, permit_id):
    return {"signer": uid, "role": role,
            "sig": s.kms.sign(f"user:{uid}", f"transport:depart:{permit_id}".encode())}


# ---------------------------------------------------------------------------
# 1. 签名伪造 / 跨单位签名 / 岗位冒充（双人双锁纵深防御）
# ---------------------------------------------------------------------------
class TestSignatureIdentity:
    def test_checkout_forged_signature_rejected(self, ha):
        s = ha
        gun = _mk(s, "unit:range-a", 1)
        # 第二名签名人把签名签给"别人"的领用载荷 → 密码学验签失败
        bad = [
            _ck_sig(s, "ra-k", "保管", gun.code, "ra-u"),
            {"signer": "ra-s", "role": "监督",
             "sig": s.kms.sign("user:ra-s", f"checkout:{gun.code}:someone_else".encode())},
        ]
        with pytest.raises(ValidationError, match="签名验证失败"):
            s.domain.checkout(gun_code=gun.code, person_id="ra-u", signers=bad)
        # 枪保持原状，不产生任何事件
        assert s.repo.get_gun(gun.code).status == "in_stock"
        assert s.outbox.stats()["pending"] == 1  # 仅 manufacture

    def test_checkout_cross_unit_signer_rejected(self, ha):
        s = ha
        gun = _mk(s, "unit:range-a", 2)
        # 外单位在册人员（sport-a 的保管/监督）给 range-a 的枪签名 → 拒绝
        bad = [
            _ck_sig(s, "sp-k", "保管", gun.code, "ra-u"),
            _ck_sig(s, "sp-s", "监督", gun.code, "ra-u"),
        ]
        with pytest.raises(ValidationError, match="不一致"):
            s.domain.checkout(gun_code=gun.code, person_id="ra-u", signers=bad)

    def test_checkout_duty_impersonation_rejected(self, ha):
        s = ha
        gun = _mk(s, "unit:range-a", 3)
        # 使用岗的 ra-u 伪称"保管"签名 → 在册岗位不符
        bad = [
            _ck_sig(s, "ra-u", "保管", gun.code, "ra-u"),
            _ck_sig(s, "ra-s", "监督", gun.code, "ra-u"),
        ]
        with pytest.raises(ValidationError, match="岗位"):
            s.domain.checkout(gun_code=gun.code, person_id="ra-u", signers=bad)

    def test_checkout_legit_within_unit_succeeds(self, ha):
        """正向对照：同单位双人签名（保管+监督）正常领用。"""
        s = ha
        gun = _mk(s, "unit:range-a", 4)
        good = [
            _ck_sig(s, "ra-k", "保管", gun.code, "ra-u"),
            _ck_sig(s, "ra-s", "监督", gun.code, "ra-u"),
        ]
        s.domain.checkout(gun_code=gun.code, person_id="ra-u", signers=good, due_hours=8)
        assert s.repo.get_gun(gun.code).status == "in_use"


# ---------------------------------------------------------------------------
# 2. 运输守卫：空清单 / 混单位 / 非在库 / 起运签名伪造
# ---------------------------------------------------------------------------
class TestTransportGuards:
    def test_request_permit_cross_unit_and_nonstock_rejected(self, ha):
        s = ha
        g_range = _mk(s, "unit:range-a", 10)
        g_sport = _mk(s, "unit:sport-a", 20, maker="某运动器材厂", kind="气手枪")

        def req(gun_codes, permit_id):
            return s.domain.request_transport_permit(
                permit_id=permit_id, gun_codes=gun_codes, vehicle="云A·T0001",
                carrier="承运甲", escort="押运乙",
                valid_from="2026-03-01T00:00:00+00:00",
                valid_end="2026-03-31T00:00:00+00:00",
                origin="贵阳", destination="昆明", applicant="u-rng")

        with pytest.raises(ValidationError, match="至少一支"):
            req([], "P-EMPTY")
        with pytest.raises(ValidationError, match="同一单位"):
            req([g_range.code, g_sport.code], "P-MIXED")
        # 在库校验：领用后再申报运输 → 状态机拒绝
        s.domain.checkout(gun_code=g_range.code, person_id="ra-u",
                          signers=[_ck_sig(s, "ra-k", "保管", g_range.code, "ra-u"),
                                   _ck_sig(s, "ra-s", "监督", g_range.code, "ra-u")],
                          due_hours=8)
        with pytest.raises(StateError):
            req([g_range.code], "P-INSTOCK")

    def test_start_transport_forged_sig_and_cross_domain(self, ha):
        s = ha
        gun = _mk(s, "unit:range-a", 11)
        s.domain.request_transport_permit(
            permit_id="P-OK", gun_codes=[gun.code], vehicle="云A·T0002",
            carrier="承运甲", escort="押运乙",
            valid_from="2026-03-01T00:00:00+00:00",
            valid_end="2026-03-31T00:00:00+00:00",
            origin="贵阳", destination="昆明", applicant="u-rng")
        s.domain.approve_transport_permit(permit_id="P-OK", approver="u-pol")
        # 起运签名覆盖 transport:depart:{permit_id}：伪造别的许可 → 验签失败
        forged = [_trans_sig(s, "ra-k", "保管", "P-OTHER")]
        with pytest.raises(ValidationError, match="验签失败"):
            s.domain.start_transport(permit_id="P-OK", gun_codes=[gun.code],
                                     vehicle="云A·T0002", carrier="承运甲",
                                     escort="押运乙", signers=forged)
        # 签对了许可则通过（正向对照）
        good = [_trans_sig(s, "ra-k", "保管", "P-OK")]
        s.domain.start_transport(permit_id="P-OK", gun_codes=[gun.code],
                                 vehicle="云A·T0002", carrier="承运甲",
                                 escort="押运乙", signers=good)
        s.pump()
        assert s.view.gun(gun.code)["status"] == "in_transit"


# ---------------------------------------------------------------------------
# 3. 报废守卫：服务端推演阶段 / 伪造签名 / 视图分期投影
# ---------------------------------------------------------------------------
class TestScrapGuards:
    def test_scrap_stage_order_and_forged_signature(self, ha):
        s = ha
        gun = _mk(s, "unit:range-a", 12)

        def stage(st, **kw):
            return s.domain.scrap_stage(
                gun_code=gun.code, stage=st, actor="u-rng",
                signers=[_scrap_sig(s, "ra-k", "保管", gun.code, st),
                         _scrap_sig(s, "ra-s", "监督", gun.code, st)], **kw)

        with pytest.raises(ValidationError, match="未知销毁阶段"):
            stage("bogus_stage")
        with pytest.raises(StateError):
            stage("appraise", appraisal="x")            # 未申请直接鉴定 → 顺序错误
        stage("apply", reason="膛线磨损超差")
        with pytest.raises(StateError):
            stage("province_confirm")                    # 跳过鉴定 → 顺序错误
        stage("appraise", appraisal="不可修复")
        # 伪造签名：载荷阶段与实际阶段不符
        forged = [_scrap_sig(s, "u-pol", "省级确认", gun.code, "apply")]
        with pytest.raises(ValidationError, match="验签失败"):
            s.domain.scrap_stage(gun_code=gun.code, stage="province_confirm",
                                 actor="u-pol", signers=forged)
        # 正向对照：正确签名的省级确认通过
        good = [_scrap_sig(s, "u-pol", "省级确认", gun.code, "province_confirm")]
        s.domain.scrap_stage(gun_code=gun.code, stage="province_confirm",
                             actor="u-pol", signers=good)

    def test_scrap_view_projection_staged_not_destroyed(self, ha):
        """apply/appraise 后视图状态是 pending_destroy，而不是被硬编码成 destroyed。"""
        s = ha
        gun = _mk(s, "unit:range-a", 13)
        for st, kw in (("apply", {"reason": "锈蚀"}), ("appraise", {"appraisal": "建议报废"})):
            s.domain.scrap_stage(
                gun_code=gun.code, stage=st, actor="u-rng",
                signers=[_scrap_sig(s, "ra-k", "保管", gun.code, st),
                         _scrap_sig(s, "ra-s", "监督", gun.code, st)], **kw)
        s.pump()
        assert s.view.gun(gun.code)["status"] == "pending_destroy"
        assert s.repo.get_gun(gun.code).status == "pending_destroy"


# ---------------------------------------------------------------------------
# 4. 视图投影：return 清空 holder；"过路事件"（预警）不污染状态
# ---------------------------------------------------------------------------
class TestProjectionStore:
    def test_return_clears_holder_and_alert_not_pollute_status(self, ha):
        s = ha
        gun = _mk(s, "unit:range-a", 14)
        ck = [_ck_sig(s, "ra-k", "保管", gun.code, "ra-u"),
              _ck_sig(s, "ra-s", "监督", gun.code, "ra-u")]
        s.domain.checkout(gun_code=gun.code, person_id="ra-u", signers=ck, due_hours=8)
        s.pump()
        assert s.view.gun(gun.code)["status"] == "in_use"
        assert s.view.gun(gun.code)["holder"] == "ra-u"

        # 预警事件（无合约重判但同样过投递管道）不得把 in_use 刷回 in_stock
        s.domain.raise_alert(gun.code, "hint", "巡检提示", "unit:range-a")
        s.pump()
        assert s.view.gun(gun.code)["status"] == "in_use"
        assert s.view.gun(gun.code)["holder"] == "ra-u"

        rt = [_ck_sig(s, "ra-k", "保管", gun.code, "ra-u", action="return"),
              _ck_sig(s, "ra-s", "监督", gun.code, "ra-u", action="return")]
        s.domain.checkin(gun_code=gun.code, person_id="ra-u", signers=rt)
        s.pump()
        view = s.view.gun(gun.code)
        assert view["status"] == "in_stock"
        assert view["holder"] == ""                       # 归还必须清空持有者
        assert s.repo.get_gun(gun.code).holder == ""

    def test_save_person_cross_unit_overwrite_rejected(self, ha):
        s = ha
        with pytest.raises(ValidationError, match="跨单位覆盖"):
            s.register_person("ra-k", "恶意覆盖", "unit:sport-a", duty="保管",
                              cert_kinds=["手枪"],
                              cert_expire="2028-12-31T00:00:00+00:00")


# ---------------------------------------------------------------------------
# 5. IAM：ABAC 精确域匹配 / audit 权限分档
# ---------------------------------------------------------------------------
class TestIamAbac:
    def test_abac_domain_exact_match_blocks_prefix_escape(self):
        sub = Subject(user_id="u", name="u", role="unit", org="range-a")
        check_abac(sub, "range-a", "gun:read:domain")           # 精确命中
        check_abac(sub, "range-a:sub-zone", "gun:read:domain")  # 子域前缀放行
        for evil in ("range-abuse", "range-a_evil", "range-a2"):
            with pytest.raises(PermissionDenied):
                check_abac(sub, evil, "gun:read:domain")
        # 状态属性：已封存枪支任何写操作被拒
        with pytest.raises(PermissionDenied):
            check_abac(sub, "range-a", "event:submit", resource_state="sealed")

    def test_rbac_audit_ops_role_gated(self):
        check_rbac("admin", "audit:read")
        check_rbac("admin", "audit:ops")
        check_rbac("auditor", "audit:read")
        check_rbac("auditor", "audit:ops")
        for role in ("unit", "practitioner"):
            with pytest.raises(PermissionDenied):
                check_rbac(role, "audit:read")
            with pytest.raises(PermissionDenied):
                check_rbac(role, "audit:ops")
        with pytest.raises(PermissionDenied):
            check_rbac("unit", "scrap:confirm")


# ---------------------------------------------------------------------------
# 6. 链拒绝 → 重试 → 死信（绝不静默当成成功）
# ---------------------------------------------------------------------------
class TestChainRejectionToDlq:
    def test_onchain_rejected_event_lands_in_dead_letter_not_ledger(self, ha):
        s = ha
        from gunreg.events import build_event
        # 伪造一条链上重判会被 scrap_confirm 拒绝的事件（阶段非法、无合约上下文）
        ev = build_event(event_id="ev-forged-scrap", gun_code="FORGED-999",
                         event_type="scrap", actor="attacker",
                         occurred_at=s.clock.now_iso(), location="L",
                         device_id="attacker-dev",
                         payload={"stage": "bogus_stage", "unit": "unit:range-a"},
                         signer_ids=["attacker"])
        with s.repo.db.transaction() as conn:
            s.outbox.enqueue(conn, "gun.event", ev.to_dict())

        before = len(s.ledger.txs())
        for _ in range(5):
            s.pump()   # 每轮一次转发 → 订阅者 3 次重试 → 1 条死信 → outbox attempts+1
        # Outbox 5 次重试耗尽进 outbox_dead，不再无限重试
        assert s.outbox.stats()["dead"] == 1
        assert s.outbox.stats()["pending"] == 0
        # 事件总线死信 5 条（每轮一条），全部来自 gun.event 订阅
        dead = s.bus.dead_letters()
        assert len(dead) == 5
        assert all(dl["topic"] == "gun.event" for dl in dead)
        # 链上绝无该交易、视图绝无该枪——链拒绝没有被当成成功缓存
        assert len(s.ledger.txs()) == before
        assert all(t.get("client_tx_id") != "ev-forged-scrap" for t in s.ledger.txs())
        assert s.view.timeline("FORGED-999") == []


# ---------------------------------------------------------------------------
# 7. 设备网关：报文防篡改 / 防重放 / 证书真校验
# ---------------------------------------------------------------------------
class TestDeviceGateway:
    def test_envelope_tamper_and_replay_rejected(self, ha):
        s = ha
        s.register_device("dev-evil", "rfid", "unit:range-a")
        gw = s.device_gw
        body = {"action": "out", "tag": "G-1", "person": "ra-u", "reader": "R1"}
        env = gw.new_envelope("dev-evil", body)
        # 篡改正文后重发：签名覆盖正文摘要 → 验签失败
        env["body"]["tag"] = "G-EVIL"
        with pytest.raises(AuthenticationError, match="验签失败"):
            gw.ingest(env)
        # 合法信封可投递；重放同一信封 → nonce 防重放
        ok_env = gw.new_envelope("dev-evil", body)
        gw.ingest(ok_env)
        with pytest.raises(ReplayError):
            gw.ingest(ok_env)

    def test_device_certificate_untrusted_rejected(self, ha):
        s = ha
        s.register_device("dev-cert", "rfid", "unit:range-a")
        prof = s.device_gw._devices["dev-cert"]
        # 证书被吊销/缺失 → 网关拒绝接入（此前 if False 直接放行的修复点）
        del s.device_gw.ca._issued[prof.cert_id]
        env = s.device_gw.new_envelope("dev-cert",
                                       {"action": "out", "tag": "G-2",
                                        "person": "ra-u", "reader": "R1"})
        with pytest.raises(AuthenticationError, match="证书"):
            s.device_gw.ingest(env)


# ---------------------------------------------------------------------------
# 8. Webapp API 层：权限分档 + 数据域隔离（TestClient 直连真实接口）
# ---------------------------------------------------------------------------
from gunreg.iam import totp  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from webapp.main import CLOCK, SYSTEM, app  # noqa: E402

_API_ACCOUNTS = [("admin1", "admin123"), ("unit-rng", "unit123"),
                 ("audit1", "audit123"), ("rng-wang", "user123")]


@pytest.fixture(scope="module")
def clients():
    """每角色独立 TestClient（各自 Cookie jar），保证互不串登录态。"""
    out = {}
    for uid, pw in _API_ACCOUNTS:
        c = TestClient(app)
        sub = SYSTEM.identity.get(uid)
        code = totp(sub.mfa_secret, int(CLOCK.now().timestamp()) // 30)
        r = c.post("/api/login", json={"user_id": uid, "password": pw, "totp": code})
        assert r.status_code == 200, f"login {uid}: {r.text}"
        out[uid] = c
    return out


class TestWebappPermissionGating:
    def test_audit_endpoints_role_gated(self, clients):
        unit = clients["unit-rng"]
        denied = [
            ("get", "/api/audit/log"), ("get", "/api/audit/ledger"),
            ("get", "/api/audit/outbox"), ("get", "/api/audit/stats"),
            ("post", "/api/audit/rebuild"), ("post", "/api/audit/pump"),
        ]
        for method, path in denied:
            r = getattr(unit, method)(path, json={}) if method == "post" else getattr(unit, method)(path)
            assert r.status_code == 403, (method, path, r.status_code, r.text)
        # 未持有任何凭据 → 401
        assert TestClient(app).get("/api/audit/log").status_code == 401
        # 审计员与监管员有权（audit:read / audit:ops）
        assert clients["audit1"].get("/api/audit/ledger").status_code == 200
        assert clients["admin1"].get("/api/audit/ledger").status_code == 200
        assert clients["audit1"].post("/api/audit/rebuild", json={}).status_code == 200
        # 从业人员无审计权限
        assert clients["rng-wang"].get("/api/audit/log").status_code == 403

    def test_permits_domain_filtered_for_unit(self, clients):
        items = clients["unit-rng"].get("/api/permits").json()["items"]
        # 单位用户看不到其他单位域的运输许可（种子 PERMIT-A/B 属 mfg-yn）
        assert not any(x.get("domain") == "mfg-yn" for x in items)
        assert all(x.get("domain") == "range-a" for x in items)

    def test_permit_request_cross_unit_and_empty_rejected(self, clients):
        unit = clients["unit-rng"]
        sport_gun = SYSTEM.repo.db.one(
            "SELECT code FROM guns WHERE unit_id='sport-a' ORDER BY rowid LIMIT 1")["code"]
        r = unit.post("/api/permit/request", json={"gun_codes": []})
        assert r.status_code == 400, r.text
        r = unit.post("/api/permit/request", json={
            "gun_codes": [sport_gun], "vehicle": "云A·T9001", "carrier": "甲",
            "escort": "乙", "valid_from": "2026-09-24T00:00:00+00:00",
            "valid_end": "2026-10-05T00:00:00+00:00", "origin": "贵阳", "destination": "昆明"})
        assert r.status_code == 403, r.text   # 数据域隔离：range-a 不可申报 sport-a 枪支

    def test_checkout_foreign_signer_and_role_impersonation_rejected(self, clients):
        unit = clients["unit-rng"]
        gun = SYSTEM.repo.db.one(
            "SELECT code FROM guns WHERE unit_id='range-a' AND status='in_stock' "
            "ORDER BY rowid LIMIT 1")["code"]
        # 外来单位签名人（sport-a 在册人员）→ 400
        r = unit.post("/api/unit/checkout", json={
            "gun_code": gun, "person_id": "rng-wang",
            "signers": [["rng-zhang", "保管"], ["spt-liu", "监督"]]})
        assert r.status_code == 400, r.text
        # 岗位冒充：使用岗伪称保管 → 400
        r = unit.post("/api/unit/checkout", json={
            "gun_code": gun, "person_id": "rng-wang",
            "signers": [["rng-wang", "保管"], ["rng-li", "监督"]]})
        assert r.status_code == 400, r.text

    def test_unit_person_cross_unit_overwrite_rejected(self, clients):
        unit = clients["unit-rng"]
        # 覆盖其他单位已有档案 → 403
        r = unit.post("/api/unit/person", json={
            "person_id": "spt-liu", "name": "黑客", "duty": "使用",
            "cert_status": "valid", "cert_kinds": ["手枪"]})
        assert r.status_code == 403, r.text
        # 本单位重复编号 → 400
        r = unit.post("/api/unit/person", json={
            "person_id": "rng-wang", "name": "假名", "duty": "使用",
            "cert_status": "valid", "cert_kinds": ["手枪"]})
        assert r.status_code == 400, r.text
        # 新人员登记成功（正向对照）
        r = unit.post("/api/unit/person", json={
            "person_id": "sec-new-1", "name": "新进人员", "duty": "使用",
            "cert_status": "valid", "cert_kinds": ["手枪"]})
        assert r.status_code == 200, r.text

    def test_repair_actor_must_be_registered_person(self, clients):
        """维修责任主体必须是本单位在册人员：不得回退到非登记的单位管理员账号。"""
        unit = clients["unit-rng"]
        gun = SYSTEM.repo.db.one(
            "SELECT code FROM guns WHERE unit_id='range-a' AND status='in_stock' "
            "ORDER BY rowid LIMIT 1")["code"]
        # 缺省 actor（回退到单位账号 unit-rng，非登记人员）→ 400
        r = unit.post("/api/unit/repair", json={
            "gun_code": gun, "content": "更换撞针",
            "signers": [["rng-zhang", "维修"], ["rng-li", "复核"]]})
        assert r.status_code == 400, r.text
        # 指定在册人员 → 200
        r = unit.post("/api/unit/repair", json={
            "gun_code": gun, "actor": "rng-zhang", "content": "更换撞针并校验",
            "signers": [["rng-zhang", "维修"], ["rng-li", "复核"]]})
        assert r.status_code == 200, r.text
        # 跨单位人员 → 403
        r = unit.post("/api/unit/repair", json={
            "gun_code": gun, "actor": "spt-liu", "content": "越权维修",
            "signers": [["rng-zhang", "维修"], ["rng-li", "复核"]]})
        assert r.status_code == 403, r.text

    def test_qualify_cross_unit_and_self_only_guarded(self, clients):
        unit = clients["unit-rng"]
        pract = clients["rng-wang"]
        r = unit.post("/api/qualify", json={"person_id": "spt-liu",
                                            "cert_status": "suspended"})
        assert r.status_code == 403, r.text
        r = pract.post("/api/qualify", json={"person_id": "rng-zhang",
                                             "cert_status": "valid"})
        assert r.status_code == 403, r.text
        r = pract.post("/api/qualify", json={"person_id": "rng-wang",
                                             "cert_status": "valid",
                                             "cert_expire": "2029-09-24T00:00:00+00:00"})
        assert r.status_code == 200, r.text

    def test_alert_respond_cross_domain_rejected(self, clients):
        sport_gun = SYSTEM.repo.db.one(
            "SELECT code FROM guns WHERE unit_id='sport-a' ORDER BY rowid LIMIT 1")["code"]
        alert = SYSTEM.domain.raise_alert(sport_gun, "emergency", "安全回归测试预警", "sport-a")
        aid = alert["alert_id"]
        # range-a 单位处置 sport-a 预警 → 403
        r = clients["unit-rng"].post("/api/alerts/respond", json={"alert_id": aid})
        assert r.status_code == 403, r.text
        # 监管处置 → 200
        r = clients["admin1"].post("/api/alerts/respond", json={
            "alert_id": aid, "response": "已核查", "close": True})
        assert r.status_code == 200, r.text

    def test_clock_advance_role_gated_and_demo_switch(self, clients, monkeypatch):
        r = clients["unit-rng"].post("/api/clock/advance", json={"hours": 0})
        assert r.status_code == 403, r.text
        r = clients["admin1"].post("/api/clock/advance", json={"hours": 0})
        assert r.status_code == 200, r.text
        # 生产开关（DEMO=0）：即使 admin 也无法推进演示时钟
        import webapp.config as cfg
        monkeypatch.setattr(cfg, "DEMO", False)
        r = clients["admin1"].post("/api/clock/advance", json={"hours": 0})
        assert r.status_code == 403, r.text


# ---------------------------------------------------------------------------
# 9. 登录语义与启动健壮性：演示账号口令直登 / 生产强制 MFA / 重启复用数据
# ---------------------------------------------------------------------------
import webapp.seed as seed_mod  # noqa: E402


class TestLoginSemantics:
    """演示模式允许仅账号+口令登录（TOTP 可省）；生产模式强制双因子。
    各用例用独立 client IP 隔离 WAF 令牌桶，避免共享 testclient 桶触发限流。"""

    def test_demo_password_only_login(self):
        c = TestClient(app, client=("10.8.1.1", 50001))
        r = c.post("/api/login", json={"user_id": "admin1", "password": "admin123", "totp": ""})
        assert r.status_code == 200, r.text
        assert r.json()["user"]["role"] == "admin"
        assert "gunreg_session" in c.cookies

    def test_demo_rejects_wrong_totp_when_provided(self):
        c = TestClient(app, client=("10.8.1.2", 50002))
        r = c.post("/api/login", json={"user_id": "admin1", "password": "admin123", "totp": "000000"})
        assert r.status_code == 401, r.text

    def test_production_forces_mfa(self, monkeypatch):
        import webapp.config as cfg
        monkeypatch.setattr(cfg, "DEMO", False)
        # 缺动态口令 → 401（MFA 校验失败）
        c = TestClient(app, client=("10.8.1.3", 50003))
        r = c.post("/api/login", json={"user_id": "admin1", "password": "admin123", "totp": ""})
        assert r.status_code == 401, r.text
        assert "MFA" in r.json()["detail"]
        # 携带正确动态口令 → 200
        sub = SYSTEM.identity.get("admin1")
        code = totp(sub.mfa_secret, int(CLOCK.now().timestamp()) // 30)
        c2 = TestClient(app, client=("10.8.1.4", 50004))
        r2 = c2.post("/api/login", json={"user_id": "admin1", "password": "admin123", "totp": code})
        assert r2.status_code == 200, r2.text

    def test_seed_reuse_restores_identity_and_devices(self):
        """服务重启 + 复用已有数据（GUNREG_RESET 未置位）：账号/密钥/设备必须重建，
        否则登录全部报"用户名或口令错误"（历史回归，见 2026-09-24 记录）。"""
        old = os.environ.pop("GUNREG_RESET", None)
        try:
            sys2, _ = seed_mod.seed_system()
            for uid in ("admin1", "unit-rng", "audit1", "rng-wang", "rng-zhang"):
                assert uid in sys2.identity._users, uid
            assert sys2.kms.has_key("user:rng-zhang")
            assert "reader-gate-01" in sys2.device_gw._devices
            # 幂等：已存在账号再次注册必须拒绝而非报错
            with pytest.raises(ValidationError):
                sys2.identity.register("admin1", "x", "admin", "police:bureau-01", "x")
        finally:
            if "sys2" in locals():
                sys2.repo.db.close()
                sys2.view.db.close()
            if old is not None:
                os.environ["GUNREG_RESET"] = old
