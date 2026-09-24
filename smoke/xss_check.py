"""浏览器级存储型 XSS 回归冒烟：注入攻击载荷 → 各工作台真实渲染，验证不执行、以文本呈现。

验证 Fix 7 的 {__html} 契约：
- 用户数据（姓名/事件内容）一律 esc/textContent 渲染 → 注入的标签不产生 DOM 节点、不触发 onerror；
- badge/mono 显式 HTML 仍正常渲染（正常功能不回归）。
"""
from __future__ import annotations

import json
import sys

sys.stdout.reconfigure(encoding="utf-8")

from playwright.sync_api import sync_playwright

BASE = "http://127.0.0.1:8000"
PAYLOAD_NAME = "<svg/onload=window.__xss='svg-name'>"
results = []


def log(name, ok, detail=""):
    results.append((name, ok, detail))
    print(("[OK]" if ok else "[FAIL]"), name, detail)
    return ok


def login(page, user_id, password):
    code = page.request.get(f"{BASE}/api/totp-demo?user_id={user_id}").json()["code"]
    r = page.request.post(f"{BASE}/api/login",
                          data=json.dumps({"user_id": user_id, "password": password, "totp": code}),
                          headers={"Content-Type": "application/json"}).json()
    assert r.get("ok"), f"login {user_id}: {r}"
    page.context.add_cookies([{"name": "gunreg_session", "value": r["token"], "url": BASE}])
    return r


def xss_state(page):
    """返回 (window.__xss 内容, 是否存在注入型标签节点)。"""
    return page.evaluate(
        "({ x: window.__xss || null,"
        "   injected: !!document.querySelector('img[src=x], svg[onload]') })")


def main():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)

        # ---------- 第一步：注入攻击载荷（存储型） ----------
        ctx = browser.new_context()
        inj = ctx.new_page()
        login(inj, "unit-rng", "unit123")

        r = inj.request.post(f"{BASE}/api/unit/person",
                             data=json.dumps({"person_id": "xss-probe",
                                              "name": PAYLOAD_NAME,
                                              "duty": "使用",
                                              "cert_kinds": ["手枪"]}),
                             headers={"Content-Type": "application/json"})
        log("注入:单位人员姓名", r.ok, f"status={r.status}")
        # 取一支在库本单位枪支用于维修内容注入
        guns = inj.request.get(f"{BASE}/api/guns?status=in_stock").json().get("items", [])
        target = next((g for g in guns if g.get("unit") == "range-a"), None)
        if target:
            r = inj.request.post(f"{BASE}/api/unit/repair",
                                 data=json.dumps({"gun_code": target["gun_code"],
                                                  "actor": "rng-zhang",
                                                  "content": "<img src=x onerror=\"window.__xss='repair-ct'\">",
                                                  "signers": [["rng-zhang", "维修"], ["rng-li", "复核"]]}),
                                 headers={"Content-Type": "application/json"})
            log("注入:维修内容", r.ok, f"status={r.status}")
        else:
            log("注入:维修内容", False, "无在库枪可注入")
        inj.close()

        # ---------- 第二步：单位工作台（人员姓名 → 单元表格 / 下拉；台账 → 时间线） ----------
        ctx = browser.new_context()
        page = ctx.new_page()
        errors = []
        page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
        page.on("pageerror", lambda e: errors.append(str(e)))
        login(page, "unit-rng", "unit123")
        page.goto(f"{BASE}/unit.html")
        page.wait_for_load_state("networkidle")
        page.wait_for_timeout(800)

        st = xss_state(page)
        log("unit:账台页无注入执行", st["x"] is None and not st["injected"])

        page.click("text=人员与设备")
        page.wait_for_timeout(900)
        body = page.text_content("body") or ""
        st = xss_state(page)
        log("unit:人员表注入未执行", st["x"] is None and not st["injected"],
            f"xss={st['x']}")
        log("unit:人员名单按文本呈现", PAYLOAD_NAME in body, "name 以文本可见")
        badge_ok = page.evaluate(
            "!!document.querySelector('#pp-list .badge')")
        log("unit:徽章(__html契约)正常渲染", badge_ok, "cert_status 徽章可见")

        # 台账 → 点击一行 → 时间线（mono/evBadge 显式 HTML 渲染路径）
        page.click("text=本部门台账")
        page.wait_for_timeout(900)
        row = page.query_selector("#ug-body tbody tr")
        if row:
            row.click()
            page.wait_for_timeout(900)
        st = xss_state(page)
        log("unit:时间线无注入执行", st["x"] is None and not st["injected"], f"xss={st['x']}")
        log("unit:无控制台错误", not errors, "; ".join(errors[:2]))
        ctx.close()

        # ---------- 第三步：监管工作台（注入的姓名同样流经 admin 人员数据） ----------
        ctx = browser.new_context()
        page = ctx.new_page()
        errors = []
        page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
        page.on("pageerror", lambda e: errors.append(str(e)))
        login(page, "admin1", "admin123")
        page.goto(f"{BASE}/admin.html")
        page.wait_for_load_state("networkidle")
        page.wait_for_timeout(1200)
        st = xss_state(page)
        log("admin:账台页无注入执行", st["x"] is None and not st["injected"])
        log("admin:无控制台错误", not errors, "; ".join(errors[:2]))
        ctx.close()

        # ---------- 第四步：从业人员 / 审计工作台 ----------
        for uid, pw, label, url, text in (
            ("rng-wang", "user123", "practitioner", "/practitioner.html", "我的档案"),
            ("audit1", "audit123", "audit", "/audit.html", "审计日志"),
        ):
            ctx = browser.new_context()
            page = ctx.new_page()
            errors = []
            page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
            page.on("pageerror", lambda e: errors.append(str(e)))
            login(page, uid, pw)
            page.goto(f"{BASE}{url}")
            page.wait_for_load_state("networkidle")
            page.wait_for_timeout(900)
            st = xss_state(page)
            txt = page.text_content("body") or ""
            log(f"{label}:页面加载", text in txt)
            log(f"{label}:无注入执行", st["x"] is None and not st["injected"])
            log(f"{label}:无控制台错误", not errors, "; ".join(errors[:2]))
            ctx.close()

        browser.close()

    bad = [r for r in results if not r[1]]
    print("\n==== 汇总 ====")
    print(f"通过 {len(results) - len(bad)} / {len(results)}")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()