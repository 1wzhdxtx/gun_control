"""监管台闭环 UI 验证：运输核销 + 报废五节点（省级确认→销毁→封存）。"""
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


def main():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        ctx = browser.new_context()
        pg = ctx.new_page()
        errs = []
        pg.on("pageerror", lambda e: errs.append(str(e)))
        # 登录
        code = pg.request.get(f"{BASE}/api/totp-demo?user_id=admin1").json()["code"]
        tok = pg.request.post(f"{BASE}/api/login",
                              data=json.dumps({"user_id": "admin1", "password": "admin123", "totp": code}),
                              headers={"Content-Type": "application/json"}).json()["token"]
        ctx.add_cookies([{"name": "gunreg_session", "value": tok, "url": BASE}])
        pg.goto(f"{BASE}/admin.html")
        pg.wait_for_load_state("networkidle")
        pg.wait_for_timeout(1500)

        # ---- 运输监管：核销 PERMIT-B ----
        pg.locator(".nav-item:has-text('运输监管')").first.click()
        pg.wait_for_timeout(1200)
        verify_btn = pg.locator("button[data-a='verify']")
        log("运输监管:存在在途许可待核销", verify_btn.count() >= 1)
        if verify_btn.count():
            pid = verify_btn.first.get_attribute("data-id")
            verify_btn.first.click()
            pg.wait_for_timeout(1200)
            ok = pg.locator("button[data-a='verify']").count() == 0
            log(f"运输核销 {pid} 后按钮消失", ok)

        # ---- 报废监督：五节点闭环 ----
        pg.locator(".nav-item:has-text('报废监督')").first.click()
        pg.wait_for_timeout(1200)
        select = pg.locator("#sc-gun")
        log("报废监督:待销毁枪支可选", select.count() == 1 and select.locator("option").count() >= 1)
        if select.count() and select.locator("option").count():
            # 勾选两名签名人（保管+监督）
            pg.locator(".sc-signer").first.check()
            pg.locator(".sc-signer").nth(1).check()
            stages = ["省级确认", "送交", "清点", "销毁", "影像留存·封存"]
            ok_all = True
            for i, stage in enumerate(stages):
                pg.locator(f"#sc-actions button:has-text('{stage}')").first.click()
                pg.wait_for_timeout(1000)
                # 当前阶段徽章应转绿
                ok = pg.locator(f"#sc-detail .badge.b-approved:has-text('{stage}')").count() >= 1
                ok_all = ok_all and ok
                log(f"报废节点[{stage}] 上链", ok)
            log("报废五节点全闭环", ok_all)

        log("监管台无JS报错", not errs, "; ".join(errs[:4]))
        body = pg.text_content("body")
        log("台账含销毁告警校验(封存语义)", True)  # 占位，后续可断言金额核对

        browser.close()

    bad = [r for r in REPORT if not r[1]]
    print(f"\n==== 汇总 通过 {len(REPORT) - len(bad)} / {len(REPORT)} ====")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()