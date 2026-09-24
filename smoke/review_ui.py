"""Isolated browser review: fresh data per suite; desktop/mobile and all tabs.

Run: .venv/Scripts/python smoke/review_ui.py [page_render|ui_tabs|e2e_api|admin_flows|login_ui|xss_check]
No argument runs visual and response-shape regression checks.
"""
from __future__ import annotations

import os
from pathlib import Path
import runpy
import socket
import sys
import tempfile
import threading
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
SHOTS = ROOT / "artifacts" / "review"


def visual(base):
    from playwright.sync_api import sync_playwright

    SHOTS.mkdir(parents=True, exist_ok=True)
    accounts = [("admin1", "admin123", "admin"), ("unit-rng", "unit123", "unit"),
                ("rng-wang", "user123", "practitioner"), ("audit1", "audit123", "audit"),
                ("unit-mfg", "unit123", "unit")]
    checked = 0
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        for width in (1440, 390):
            page = browser.new_page(viewport={"width": width, "height": 1000})
            page.goto(base + "/login.html", wait_until="networkidle")
            assert page.locator(".role-card").count() == 4
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
            page.locator("#fill-admin").click()
            assert page.locator("#f-user").input_value() == "admin1"
            page.screenshot(path=str(SHOTS / f"login-{width}.png"), full_page=True)
            page.close()
            for uid, password, role in accounts:
                context = browser.new_context(viewport={"width": width, "height": 1000})
                response = context.request.post(base + "/api/login", data={"user_id": uid, "password": password})
                if response.status == 400 and response.json().get("code") == "RateLimited":
                    time.sleep(1.1)
                    response = context.request.post(base + "/api/login", data={"user_id": uid, "password": password})
                assert response.ok, response.text()
                page = context.new_page()
                errors = []
                page.on("pageerror", lambda e: errors.append(str(e)))
                page.goto(f"{base}/{role}.html", wait_until="networkidle")
                page.wait_for_selector(".pane.active[aria-busy=false]")
                page.screenshot(path=str(SHOTS / f"{uid}-{width}.png"), full_page=True)
                for index in range(page.locator(".nav-item").count()):
                    page.locator(".nav-item").nth(index).click()
                    page.wait_for_selector(".pane.active[aria-busy=false]")
                    assert page.locator("#page-title").inner_text().strip()
                    assert not page.locator(".toast.err").count(), page.locator(".toast.err").all_text_contents()
                    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), (uid, width, index)
                    assert "[object Object]" not in page.locator(".pane.active").inner_text(), (uid, width, index)
                    checked += 1
                if role == "audit":
                    page.locator(".nav-item", has_text="派生视图").click()
                    page.wait_for_selector("#rb-body tbody tr")
                    assert page.locator("#rb-body th").all_text_contents() == ["统计日期", "事件类型", "所属单位", "事件数"]
                    page.locator(".nav-item", has_text="对账与泵送").click()
                    page.wait_for_selector(".pane.active[aria-busy=false]")
                    page.locator("#ob-reconcile").click()
                    page.wait_for_function("document.querySelector('#ob-out').textContent.includes('对账完成')")
                    assert "undefined" not in page.locator("#ob-out").inner_text()
                    page.locator("#ob-pump").click()
                    page.wait_for_function("document.querySelector('#ob-out').textContent.includes('本轮发布')")
                    assert "[object Object]" not in page.locator("#ob-out").inner_text()
                    # A pending queue must render numeric IDs without .slice errors.
                    page.route("**/api/audit/outbox", lambda route: route.fulfill(json={
                        "outbox": {"pending": 1, "published": 0, "dead": 0}, "receipts": 0,
                        "bus": {"delivered": 0, "failed": 0, "dead": 0},
                        "reconcile": {"consistent": True, "submitted": 0, "onchain": 0, "missing": [], "mismatched": []},
                        "queue": [{"id": 12, "topic": "gun.event", "payload": {"event_type": "checkout"}, "created_at": "2026-09-24T00:00:00Z"}]}))
                    page.locator(".nav-item", has_text="对账与泵送").click()
                    page.wait_for_selector("#ob-queue tbody tr")
                    assert "12" in page.locator("#ob-queue").inner_text()
                assert not errors, errors
                context.close()
                print(f"PASS {uid} viewport={width}", flush=True)
        browser.close()
    print(f"PASS visual review: {checked} tab/viewport checks; screenshots in {SHOTS}")


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    with tempfile.TemporaryDirectory(prefix="gunreg-browser-") as data:
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        base = f"http://127.0.0.1:{port}"
        os.environ.update(GUNREG_DATA_DIR=data, GUNREG_RESET="1", GUNREG_DEMO="1", GUNREG_COOKIE_SECURE="0")
        import uvicorn
        from webapp.main import app, SYSTEM

        server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
        thread = threading.Thread(target=server.run, daemon=True)
        thread.start()
        try:
            try:
                for _ in range(100):
                    if not thread.is_alive():
                        raise RuntimeError("Review server stopped unexpectedly")
                    try:
                        with urllib.request.urlopen(base + "/login.html", timeout=1):
                            break
                    except OSError:
                        time.sleep(.15)
                else:
                    raise RuntimeError("Review server did not start")
                if len(sys.argv) > 1:
                    name = sys.argv[1]
                    assert name in {"page_render", "ui_tabs", "e2e_api", "admin_flows", "login_ui", "xss_check"}
                    module = runpy.run_path(str(ROOT / "smoke" / (name + ".py")))
                    module["main"].__globals__["BASE"] = base
                    module["main"]()
                else:
                    visual(base)
            finally:
                server.should_exit = True
                thread.join(timeout=15)
                SYSTEM.repo.db.close()
                SYSTEM.view.db.close()
        finally:
            server.should_exit = True


if __name__ == "__main__":
    main()
