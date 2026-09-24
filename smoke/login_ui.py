"""登录页 UI 冒烟：账号 + 口令即可登录（演示模式，TOTP 留空），错误口令有提示。

验证 2026-09-24 回归修复：
- 登录页为真实账号/口令表单（用户需求：账号和密码登录）；
- 服务重启复用已有数据后（进程内 IAM 重建）登录仍可用；
- 错误口令/错误动态口令仍被拒绝。
"""
from __future__ import annotations

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


def main():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()

        # ---------- 1. 登录页渲染：真实表单 + 动态口令卡片 ----------
        page.goto(BASE + "/login.html", wait_until="networkidle")
        log("登录页标题", "民用枪支" in page.title())
        log("账号输入框存在", page.locator("#f-user").count() == 1)
        log("口令输入框存在", page.locator("#f-pass").count() == 1)
        log("登录按钮存在", page.locator("#btn-login").count() == 1)
        # 动态口令卡片能取到实时口令（演示便利）
        page.wait_for_function(
            "() => [...document.querySelectorAll('.totp-big')].some(e => /^\\d{6}$/.test(e.textContent.trim()))",
            timeout=8000)
        log("TOTP 卡片实时口令", True)

        # ---------- 2. 账号+口令直登（TOTP 留空）→ 监管工作台 ----------
        page.fill("#f-user", "admin1")
        page.fill("#f-pass", "admin123")
        page.click("#btn-login")
        page.wait_for_url(BASE + "/admin.html", timeout=8000)
        log("admin1 口令直登跳转 /admin.html", True)

        # ---------- 3. 错误口令提示 ----------
        page.goto(BASE + "/login.html", wait_until="networkidle")
        page.fill("#f-user", "admin1")
        page.fill("#f-pass", "WRONG-PASS")
        page.click("#btn-login")
        page.wait_for_function(
            "() => (document.getElementById('f-err').textContent || '').includes('登录失败')",
            timeout=8000)
        log("错误口令给出失败提示", True)

        # ---------- 4. 错误 TOTP 仍被拒绝（演示模式下非空必须正确） ----------
        page.goto(BASE + "/login.html", wait_until="networkidle")
        page.fill("#f-user", "admin1")
        page.fill("#f-pass", "admin123")
        page.fill("#f-totp", "000000")
        page.click("#btn-login")
        page.wait_for_function(
            "() => (document.getElementById('f-err').textContent || '').includes('登录失败')",
            timeout=8000)
        log("错误 TOTP 拒绝", True)

        # ---------- 5. 单位角色口令直登 → 单位工作台 ----------
        page.goto(BASE + "/login.html", wait_until="networkidle")
        page.fill("#f-user", "unit-rng")
        page.fill("#f-pass", "unit123")
        page.click("#btn-login")
        page.wait_for_url(BASE + "/unit.html", timeout=8000)
        log("unit-rng 口令直登跳转 /unit.html", True)

        browser.close()

    bad = [r for r in results if not r[1]]
    print(f"\nRESULT {'PASS' if not bad else 'FAIL'}: {len(results)-len(bad)}/{len(results)}")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()