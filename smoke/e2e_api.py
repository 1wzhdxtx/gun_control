"""临时端到端冒烟测试：登录页 → 四个工作台关键操作。"""
from __future__ import annotations

import json
import sys
import time

sys.stdout.reconfigure(encoding="utf-8")

from playwright.sync_api import sync_playwright

BASE = "http://127.0.0.1:8000"
results = []


def log(name, ok, detail=""):
    results.append((name, ok, detail))
    print(("[OK]" if ok else "[FAIL]"), name, detail)
    return ok


def totp_code(page, user_id):
    r = page.request.get(f"{BASE}/api/totp-demo?user_id={user_id}")
    return r.json()["code"]


def login(page, user_id, password):
    code = totp_code(page, user_id)
    r = page.request.post(f"{BASE}/api/login",
                          data=json.dumps({"user_id": user_id, "password": password, "totp": code}),
                          headers={"Content-Type": "application/json"})
    data = r.json()
    if not data.get("ok"):
        return None
    page.context.add_cookies([{"name": "gunreg_session", "value": data["token"],
                               "url": BASE}])
    return data


def api(page, path, body=None):
    if body is not None:
        return page.request.post(f"{BASE}{path}",
                                 data=json.dumps(body),
                                 headers={"Content-Type": "application/json"}).json()
    return page.request.get(f"{BASE}{path}").json()


def main():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        ctx = browser.new_context()
        page = ctx.new_page()

        # ---- 登录页 ----
        page.goto(f"{BASE}/login.html")
        page.wait_for_load_state("networkidle")
        log("登录页加载", "进入登录" in page.text_content("body") or "民用枪支" in page.text_content("body"))
        body_text = page.text_content("body")
        has_cards = all(k in body_text for k in ["监管工作台", "单位工作台", "从业人员端", "审计工作台"])
        log("四个工作台卡片", has_cards)
        # TOTP 自动填充
        totp_text = page.text_content("#totp-admin")
        log("TOTP 动态口令显示", bool(totp_text and totp_text.strip()))

        # ---- 监管登录 ----
        r = login(page, "admin1", "admin123")
        log("监管登录(口令+TOTP)", bool(r and r.get("ok")), str(r.get("redirect")))
        page.goto(f"{BASE}/admin.html")
        page.wait_for_load_state("networkidle")
        time.sleep(0.5)

        # 总览 KPI
        ov = api(page, "/api/admin/overview")
        log("总览API(在册枪支)", ov.get("gun_total") == 21, f"guns={ov.get('gun_total')}")
        log("总览API(预警分级)", len(ov.get("alert_by_level", {})) >= 2,
            json.dumps(ov.get("alert_by_level"), ensure_ascii=False))

        # 台账
        guns = api(page, "/api/guns")
        log("台账API(admin全量)", len(guns.get("items", [])) == 21)

        # 运输审批
        permits = api(page, "/api/permits")
        applied = [x for x in permits["items"] if x["status"] == "applied"]
        log("运输许可(已申请存在)", len(applied) >= 1)
        if applied:
            pid = applied[0]["permit_id"]
            ap = api(page, "/api/permit/approve", {"permit_id": pid})
            log("审批运输许可", ap.get("ok") and ap["permit"].get("status") == "approved",
                f"permit={pid}")

        # 扫描超期
        scan = api(page, "/api/overdue/scan", {})
        log("扫描超期", isinstance(scan.get("found"), list), f"found={len(scan.get('found', []))}")
        al = api(page, "/api/alerts")
        log("预警列表", len(al["items"]) >= 2, f"alerts={len(al['items'])}")
        # 升级
        esc = api(page, "/api/overdue/escalate", {})
        log("预警升级", isinstance(esc.get("upgraded"), list))

        # 时间推进 + 再扫描
        adv = api(page, "/api/clock/advance", {"hours": 24})
        log("演示时钟推进+24h", adv.get("ok"))
        scan2 = api(page, "/api/overdue/scan", {})
        log("推进后扫描", len(scan2.get("found", [])) >= 1)

        # 一链查证
        ev = api(page, "/api/gun/BFP20260000001/evidence".replace("BFP20260000001",
                                                                  guns["items"][0]["gun_code"]), None)
        code = guns["items"][0]["gun_code"]
        ev = api(page, f"/api/gun/{code}/evidence")
        log("证据核验", ev.get("ok") is True)

        # ---- 单位工作台 ----
        ctx2 = browser.new_context()
        page2 = ctx2.new_page()
        r = login(page2, "unit-rng", "unit123")
        log("单位登录", bool(r and r.get("ok")), str(r.get("redirect")))
        page2.goto(f"{BASE}/unit.html")
        page2.wait_for_load_state("networkidle")
        time.sleep(0.4)
        ug = api(page2, "/api/guns")
        own = [g for g in ug["items"]]
        log("单位台账(限本单位)", all(g.get("unit") == "range-a" for g in own), f"count={len(own)}")

        in_stock = [g for g in own if g["status"] == "in_stock"]
        log("单位在库枪可选", len(in_stock) >= 3)
        # 种子里的老持枪人（wang/zhang/li）名下都有超期在途枪，被时限合约正确阻断；
        # 演示「新增人员 → 领用」路径：注册一名无欠账的持枪人 p-e2e
        na = api(page2, "/api/unit/person", {
            "person_id": "p-e2e", "name": "端到端测试员", "duty": "使用",
            "cert_status": "valid", "cert_kinds": ["手枪", "步枪", "猎枪", "运动步枪", "气手枪", "气步枪"],
            "cert_expire": "2030-01-01T00:00:00+00:00", "create_login": True,
            "password": "user123"})
        log("单位新增人员", na.get("ok") and na["person"].get("unit_id") == "range-a",
            na.get("detail", ""))
        holders = api(page2, "/api/unit/persons")["items"]
        p_e2e = [h for h in holders if h["person_id"] == "p-e2e"]
        sign1 = [h for h in holders if h["duty"] == "保管"]
        sign2 = [h for h in holders if h["duty"] == "监督"]
        gun = in_stock[0]["gun_code"]
        if p_e2e and sign1 and sign2 and in_stock:
            co = api(page2, "/api/unit/checkout", {
                "gun_code": gun, "person_id": p_e2e[0]["person_id"],
                "signers": [[sign1[0]["person_id"], "保管"], [sign2[0]["person_id"], "监督"]],
                "due_hours": 8})
            log("领用(双人签名)", co.get("ok") and co["event"].get("event_type") == "checkout",
                f"gun={gun} detail={co.get('detail','')}")
            # 归还
            ci = api(page2, "/api/unit/checkin", {
                "gun_code": gun, "person_id": p_e2e[0]["person_id"],
                "signers": [[sign1[0]["person_id"], "保管"], [sign2[0]["person_id"], "监督"]]})
            log("归还(双人签名)", ci.get("ok") and ci["event"].get("event_type") == "return")
        else:
            log("领用(双人签名)", False, "degenerate seed")

        # 运输申报
        req = api(page2, "/api/permit/request", {
            "gun_codes": [in_stock[1]["gun_code"]],
            "vehicle": "云A·T9001", "carrier": "王承运", "escort": "李押运",
            "origin": "某市射击场", "destination": "省级训练中心",
            "valid_from": "2026-09-24T00:00:00+00:00", "valid_end": "2026-10-05T00:00:00+00:00"})
        log("运输申报(单位)", req.get("ok") and req["permit"]["status"] == "applied",
            req.get("detail", ""))

        # ---- 从业人员 ----
        ctx3 = browser.new_context()
        page3 = ctx3.new_page()
        r = login(page3, "rng-wang", "user123")
        log("从业人员登录", bool(r and r.get("ok")))
        mg = api(page3, "/api/my/guns")
        log("名下枪支", isinstance(mg.get("items"), list), f"held={len(mg.get('items', []))}")
        evts = api(page3, "/api/my/events")
        log("我的事件", isinstance(evts.get("items"), list), f"events={len(evts.get('items', []))}")
        q = api(page3, "/api/qualify", {"person_id": "rng-wang", "cert_status": "valid",
                                        "cert_expire": "2029-09-24T00:00:00+00:00"})
        log("资格续期", q.get("ok") and q["person"].get("cert_status") == "valid")

        # ---- 审计 ----
        ctx4 = browser.new_context()
        page4 = ctx4.new_page()
        r = login(page4, "audit1", "audit123")
        log("审计登录", bool(r and r.get("ok")))
        alog = api(page4, "/api/audit/log")
        log("审计日志", len(alog.get("items", [])) > 0, f"recs={len(alog.get('items', []))}")
        lv = api(page4, "/api/audit/ledger/verify", {})
        log("账本校验", lv.get("ok") is True, lv.get("message", ""))
        av = api(page4, "/api/audit/log/verify", {})
        log("审计链校验", av.get("ok") is True, av.get("message", ""))
        ob = api(page4, "/api/audit/outbox")
        log("对账信息", "reconcile" in ob and "outbox" in ob,
            json.dumps({k: ob.get(k) for k in ("outbox", "receipts")}, ensure_ascii=False))

        # 未授权尝试：审计查看审计日志用从业人员 token
        bad = api(page3, "/api/audit/log")
        log("越权防护(从业人员访问审计)", bad.get("ok") is not True, str(bad.get("detail"))[:40])

        browser.close()

    failed = [x for x in results if not x[1]]
    print("\n==== 汇总 ====")
    print(f"通过 {len(results) - len(failed)} / {len(results)}")
    for name, ok, detail in results:
        print(("[OK] " if ok else "[FAIL] ") + name + ("  " + str(detail) if detail else ""))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()