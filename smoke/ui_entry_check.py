"""Browser probe: new UI entries (P2-4) — unit sale form + manufacture batch
select. Needs a running default-startup server on 127.0.0.1:8000 (like
e2e_api.py). Read-only.
"""
from __future__ import annotations

import sys

from playwright.sync_api import sync_playwright

BASE = "http://127.0.0.1:8000"


def login(page, user: str, pw: str) -> None:
    page.goto(f"{BASE}/login.html", wait_until="networkidle")
    page.fill("#f-user", user)
    page.fill("#f-pass", pw)
    page.click("#btn-login")
    page.wait_for_url("**/unit.html", timeout=15000)


def main() -> None:
    ok = 0
    errors: list[str] = []
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)

        # --- unit-hunt: 协同审批 → 配售登记表单 ---
        ctx = browser.new_context(viewport={"width": 1440, "height": 1000})
        ctx.on("page", lambda pg: pg.on(
            "console",
            lambda m: errors.append(m.text) if m.type == "error" else None))
        page = ctx.new_page()
        login(page, "unit-hunt", "unit123")
        page.wait_for_timeout(800)          # tabs build after redirect
        page.locator(".nav-item:has-text('协同审批')").first.click()
        page.wait_for_selector("#pane-coop", state="visible", timeout=15000)
        page.wait_for_selector("#uc-sale #sale-seller option",
                               state="attached", timeout=15000)
        page.wait_for_function(
            "() => document.querySelectorAll"
            "('#uc-sale #sale-seller option').length >= 6")
        page.wait_for_timeout(500)          # guns/licenses/apps fetches settle
        sellers = page.locator("#uc-sale #sale-seller option").count()
        buyers = page.locator("#uc-sale #sale-buyer option").count()
        guns = page.locator("#uc-sale select[multiple] option").count()
        lics = page.locator("#uc-sale #sale-license option").count()
        apps = page.locator("#uc-sale #sale-papp option").count()
        assert sellers >= 6 and buyers >= 6, (sellers, buyers)
        assert guns >= 1, guns              # hunt-a own guns
        assert lics >= 2, lics               # placeholder + purchase_permit
        assert apps >= 2, apps               # placeholder + approved 配购 APP-005
        assert page.locator("#uc-form #uc-matter option").count() == 12
        # 事项切换时生产计划批次行才出现
        page.select_option("#uc-form #uc-matter", "production_plan")
        assert page.locator("#uc-form #uc-batch").is_visible()
        page.select_option("#uc-form #uc-matter", "hunt_config")
        assert not page.locator("#uc-form #uc-batch").is_visible()
        print(f"[OK] unit-hunt sale form sellers={sellers} buyers={buyers} "
              f"guns={guns} licenses={lics} apps={apps}; matters=12; "
              "plan row toggles")
        ok += 1
        ctx.close()

        # --- unit-mfg: 制造赋码 → 已批准计划批次下拉 ---
        ctx = browser.new_context(viewport={"width": 1440, "height": 1000})
        ctx.on("page", lambda pg: pg.on(
            "console",
            lambda m: errors.append(m.text) if m.type == "error" else None))
        page = ctx.new_page()
        login(page, "unit-mfg", "unit123")
        page.wait_for_timeout(800)          # tabs build after redirect
        page.locator(".nav-item:has-text('制造赋码')").first.click()
        page.wait_for_selector("#mf-batch", state="visible", timeout=15000)
        page.wait_for_function(
            "() => [...document.querySelectorAll('#mf-batch option')]"
            ".some(o => o.value === 'B2026-001')", timeout=15000)
        opts = page.locator("#mf-batch option").all_text_contents()
        vals = page.locator("#mf-batch option").evaluate_all(
            "els => els.map(e => e.value)")
        assert "B2026-001" in vals, vals
        print(f"[OK] unit-mfg batch select: {opts}")
        ok += 1
        ctx.close()

        browser.close()

    assert not errors, errors[:5]
    print(f"==== ui entry probe: {ok}/{ok} OK, console errors 0 ====")


if __name__ == "__main__":
    sys.exit(main())
