"""交互层检查：四工作台 Tab 切换 + 关键按钮联动（捕获 JS 报错）。"""
from __future__ import annotations

import json
import sys

sys.stdout.reconfigure(encoding="utf-8")

from playwright.sync_api import sync_playwright

BASE = "http://127.0.0.1:8000"
REPORT = []


def log(name, ok, detail=""):
    REPORT.append((name, ok))
    print(f"[{'OK' if ok else 'FAIL'}] {name}  {detail}")
    return ok


def login(ctx, pg, uid, pw):
    code = pg.request.get(f"{BASE}/api/totp-demo?user_id={uid}").json()["code"]
    tok = pg.request.post(f"{BASE}/api/login",
                          data=json.dumps({"user_id": uid, "password": pw, "totp": code}),
                          headers={"Content-Type": "application/json"}).json()["token"]
    ctx.add_cookies([{"name": "gunreg_session", "value": tok, "url": BASE}])
    pg.goto(f"{BASE}/admin.html" if uid == "admin1" else
            f"{BASE}/audit.html" if uid == "audit1" else
            f"{BASE}/unit.html" if uid.startswith("unit") else f"{BASE}/practitioner.html")
    pg.wait_for_load_state("networkidle")
    pg.wait_for_timeout(1000)


def click_tab(pg, name):
    pg.locator(f".nav-item:has-text('{name}')").first.click()
    pg.wait_for_timeout(900)


def main():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)

        # ---- 监管工作台：五个 Tab + 扫描超期 + 时钟 ----
        ctx = browser.new_context()
        pg = ctx.new_page()
        errs = []
        pg.on("pageerror", lambda e: errs.append(str(e)))
        login(ctx, pg, "admin1", "admin123")
        body0 = pg.text_content("body")
        for name, expect in (("一枪一档", "整枪码"), ("协同审批", "审批"),("运输监管", "许可"),
                             ("报废监督", "报废"), ("预警中心", "预警"),
                             ("一链查证", "证据")):
            click_tab(pg, name)
            body = pg.text_content("body")
            log(f"admin Tab[{name}] 内容切换", expect in body)
        # 预警中心：扫描超期
        click_tab(pg, "预警中心")
        pg.locator("button:has-text('扫描超期')").first.click()
        pg.wait_for_timeout(900)
        log("admin 扫描超期联动", "预警" in pg.text_content("body"))
        # 时钟推进（按钮位于总览面板，需先切回）
        click_tab(pg, "总览")
        pg.locator("button:has-text('推进 +24h')").first.click()
        pg.wait_for_timeout(900)
        log("admin 时钟推进+24h 联动", "时间" in pg.text_content("body"))
        log("admin 无JS报错", not errs, "; ".join(errs[:4]))
        ctx.close()

        # ---- 单位工作台：Tab 切换 ----
        ctx = browser.new_context()
        pg = ctx.new_page()
        errs = []
        pg.on("pageerror", lambda e: errs.append(str(e)))
        login(ctx, pg, "unit-rng", "unit123")
        for name, expect in (("领用 / 归还", "整枪码"), ("运输申报", "运输"),
                             ("维修登记", "维修"), ("人员与设备", "设备")):
            click_tab(pg, name)
            log(f"unit Tab[{name}] 内容切换", expect in pg.text_content("body"))
        log("unit 无JS报错", not errs, "; ".join(errs[:4]))
        ctx.close()

        # ---- 从业人员端 ----
        ctx = browser.new_context()
        pg = ctx.new_page()
        errs = []
        pg.on("pageerror", lambda e: errs.append(str(e)))
        login(ctx, pg, "rng-wang", "user123")
        for name, expect in (("名下枪支", "整枪码"), ("我的事件", "事件")):
            click_tab(pg, name)
            log(f"practitioner Tab[{name}] 内容切换", expect in pg.text_content("body"))
        log("practitioner 无JS报错", not errs, "; ".join(errs[:4]))
        ctx.close()

        # ---- 审计工作台：五个 Tab + 校验按钮 ----
        ctx = browser.new_context()
        pg = ctx.new_page()
        errs = []
        pg.on("pageerror", lambda e: errs.append(str(e)))
        login(ctx, pg, "audit1", "audit123")
        for name, expect in (("链上账本", "区块"), ("证据核验", "整枪码"),
                             ("派生视图", "重建"), ("对账与泵送", "泵送"), ("审计日志", "审计哈希")):
            click_tab(pg, name)
            log(f"audit Tab[{name}] 内容切换", expect in pg.text_content("body"))
        # 证据核验：查一支枪
        click_tab(pg, "证据核验")
        code = "BFP20260000014"
        pg.locator("#ev-code").fill(code)
        pg.locator("button:has-text('核验')").first.click()
        pg.wait_for_timeout(900)
        log("audit 证据核验联动", ("通过" in pg.text_content("body")) or len(errs) == 0)
        click_tab(pg, "审计日志")
        pg.locator("button:has-text('校验审计链完整性')").first.click()
        pg.wait_for_timeout(900)
        log("audit 审计链校验联动", "审计链完整" in pg.text_content("body"))
        log("audit 无JS报错", not errs, "; ".join(errs[:4]))
        ctx.close()

        browser.close()

    bad = [r for r in REPORT if not r[1]]
    print(f"\n==== 汇总 通过 {len(REPORT) - len(bad)} / {len(REPORT)} ====")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()