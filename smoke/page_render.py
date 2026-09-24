"""网页层渲染冒烟测试：四工作台真实打开，收集 JS 报错 + 截图。"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")

from playwright.sync_api import sync_playwright

BASE = "http://127.0.0.1:8000"
SHOTS = Path(__file__).resolve().parent / "_shots"
SHOTS.mkdir(exist_ok=True)

REPORT = []


def login(page, user_id, password):
    code = page.request.get(f"{BASE}/api/totp-demo?user_id={user_id}").json()["code"]
    r = page.request.post(f"{BASE}/api/login",
                          data=json.dumps({"user_id": user_id, "password": password, "totp": code}),
                          headers={"Content-Type": "application/json"}).json()
    page.context.add_cookies([{"name": "gunreg_session", "value": r["token"], "url": BASE}])
    return r


def check_page(browser, label, url, user_id, password, expect_texts):
    ctx = browser.new_context()
    page = ctx.new_page()
    errors = []
    page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
    page.on("pageerror", lambda e: errors.append(str(e)))
    login(page, user_id, password)
    page.goto(f"{BASE}{url}")
    page.wait_for_load_state("networkidle")
    try:
        page.wait_for_selector("#root > *", timeout=5000)
    except Exception:
        pass
    page.wait_for_timeout(1200)
    body = page.text_content("body") or ""
    missing = [txt for txt in expect_texts if txt not in body]
    shot = SHOTS / f"{label}.png"
    page.screenshot(path=str(shot), full_page=True)
    status = "OK" if (not errors and not missing) else "FAIL"
    REPORT.append((status, label, errors, missing, shot.name))
    print(f"[{status}] {label}   console_errors={len(errors)} missing_text={missing}")
    for e in errors[:8]:
        print("      console: " + e)
    ctx.close()
    return shot


def main():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)

        # ---- 登录页 ----
        ctx = browser.new_context()
        page = ctx.new_page()
        page.goto(f"{BASE}/login.html")
        page.wait_for_load_state("networkidle")
        page.wait_for_timeout(800)
        page.screenshot(path=str(SHOTS / "login.png"), full_page=True)
        body = page.text_content("body")
        kinds = ["监管工作台", "单位工作台", "从业人员端", "审计工作台"]
        missing = [k for k in kinds if k not in body]
        REPORT.append(("OK" if not missing else "FAIL", "login", [], missing, "login.png"))
        print(f"[{'OK' if not missing else 'FAIL'}] 登录页  four_cards_missing={missing}")
        ctx.close()

        check_page(browser, "admin", "/admin.html", "admin1", "admin123",
                   ["在册枪支", "运输监管", "预警中心", "一链查证", "演示时钟推进"])

        check_page(browser, "unit", "/unit.html", "unit-rng", "unit123",
                   ["本部门台账", "领用 / 归还", "运输申报", "维修登记", "人员与设备"])

        check_page(browser, "practitioner", "/practitioner.html", "rng-wang", "user123",
                   ["我的档案", "名下枪支", "我的事件", "证件续期", "暂停资格"])

        check_page(browser, "audit", "/audit.html", "audit1", "audit123",
                   ["审计日志", "链上账本", "证据核验", "派生视图", "对账与泵送"])

        browser.close()

    bad = [r for r in REPORT if r[0] == "FAIL"]
    print("\n==== 汇总 ====")
    print(f"通过 {len(REPORT) - len(bad)} / {len(REPORT)}")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()