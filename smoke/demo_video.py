"""Record the product demo video (Playwright) and assemble it with ffmpeg.

Run:
    uv run python smoke/demo_video.py

Outputs:
    artifacts/demo/seg/*.webm       raw per-role segments (one context each)
    artifacts/demo/cards/*.png      title / chapter cards
    artifacts/demo/demo.srt         narration subtitles (generated from cap() marks)
    artifacts/demo/gunreg-demo.mp4  final video with burned-in subtitles (ffmpeg)

Isolation: fresh temp data dir + random port + in-process uvicorn (same
technique as review_ui.py); the real webapp/data demo database is untouched.

Story order (state dependent): unit -> practitioner -> admin -> audit.
"""
from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

DEMO = ROOT / "artifacts" / "demo"
SEG = DEMO / "seg"
CARDS = DEMO / "cards"
BUILD = DEMO / "build"
FINAL = DEMO / "gunreg-demo.mp4"
W, H = 1280, 720
CARD_SECONDS = 2.5

CARDS_HTML = [
    ("00-intro", "民用枪支全链条智慧监管系统",
     "产品演示 · 四角色工作台 · 一事一记全程链上留痕", True),
    ("01-unit", "01 · 单位工作台",
     "双人签名领用 · 超期阻断 · 归还闭环 · 运输申报", False),
    ("02-practitioner", "02 · 从业人员端",
     "资格暂停 -> 触发紧急预警 -> 阻断名下枪支流转", False),
    ("03-admin", "03 · 监管工作台",
     "时钟推进 · 预警闭环 · 运输审批核销 · 报废五节点 · 一链查证", False),
    ("04-audit", "04 · 审计工作台",
     "审计链校验 · 证据核验 · Outbox 泵送与链上对账", False),
    ("05-ending", "演示完毕", "一枪一码 · 一事一记 · 全程可追溯", True),
]

# chapter cards interleaved with segments in the final video
STORY = [
    ("card", "00-intro"),
    ("card", "01-unit"),
    ("seg", "unit"),
    ("card", "02-practitioner"),
    ("seg", "practitioner"),
    ("card", "03-admin"),
    ("seg", "admin"),
    ("card", "04-audit"),
    ("seg", "audit"),
    ("card", "05-ending"),
]


# ---------------- page helpers ----------------
def wait_active(page):
    page.wait_for_selector(".pane.active[aria-busy=false]", timeout=15000)


def clear_toasts(page):
    page.evaluate("document.querySelectorAll('#toast-wrap .toast').forEach(t => t.remove())")


def expect(page, part, kind="ok", timeout=8000):
    t = page.locator(".toast").last
    t.wait_for(state="visible", timeout=timeout)
    cls = t.get_attribute("class") or ""
    txt = t.inner_text()
    assert kind in cls, f"expected toast kind {kind}, got [{cls}]: {txt}"
    assert part in txt, f"expected {part!r} in toast, got: {txt!r}"
    return txt


def pause(page, ms=1400):
    page.wait_for_timeout(ms)


def login(page, base, fill_role, user_id, target):
    page.goto(base + "/login.html", wait_until="networkidle")
    page.locator("#fill-" + fill_role).click()
    assert page.locator("#f-user").input_value() == user_id
    for _ in range(4):
        clear_toasts(page)
        page.locator("#btn-login").click()
        try:
            page.wait_for_function(
                "(t) => location.pathname.endsWith(t)", arg=target, timeout=6000)
            break
        except Exception:
            page.wait_for_timeout(1600)  # WAF rate-limit cool down
    else:
        raise RuntimeError(f"login failed: {user_id}")
    page.wait_for_load_state("networkidle")
    wait_active(page)
    pause(page, 800)


# ---------------- segments ----------------
def seg_unit(page, base, cap):
    """Unit workbench: blocked checkout -> return -> checkout -> apply transport."""
    cap("打开单位工作台：以射击场管理员身份登录")
    login(page, base, "unit", "unit-rng", "/unit.html")
    rows = page.locator("#ug-body tbody tr")
    if rows.count():
        rows.first.click()
        pause(page, 1100)
    # checkout blocked by the timelimit contract (holder has overdue gun)
    page.locator(".nav-item", has_text="归还").click()
    wait_active(page)
    page.wait_for_selector("#co-form button")
    cap("持枪人名下已有超期枪支——再次领用将被智能合约拦截")
    clear_toasts(page)
    page.locator("#co-form button", has_text="领用（双人签名）").click()
    expect(page, "领用被拒", kind="err")
    pause(page, 2600)
    # return the overdue gun of rng-wang
    page.evaluate(
        "() => { const s = document.getElementById('ci-gun');"
        " const i = [...s.options].findIndex(o => o.text.includes('rng-wang'));"
        " if (i >= 0) s.selectedIndex = i; }")
    cap("先归还名下的超期枪支，清掉欠账")
    clear_toasts(page)
    page.locator("#ci-form button", has_text="归还（双人签名）").click()
    expect(page, "归还成功")
    pause(page)
    # retry checkout -> success
    cap("清欠后重新领用：保管+监督双人签名，校验通过")
    clear_toasts(page)
    page.locator("#co-form button", has_text="领用（双人签名）").click()
    expect(page, "领用成功")
    pause(page)
    # transport application
    page.locator(".nav-item", has_text="运输申报").click()
    wait_active(page)
    page.wait_for_selector("#tp-form button")
    page.fill("#tp-carrier", "滇运物流")
    page.fill("#tp-escort", "王押运")
    cap("提交运输许可申报，等待监管工作台审批")
    clear_toasts(page)
    page.locator("#tp-form button", has_text="提交申报").click()
    expect(page, "申报成功")
    pause(page, 1800)


def seg_practitioner(page, base, cap):
    """Practitioner: suspend qualification (fires emergency alert downstream)."""
    cap("登录从业人员端：一人一档，证件资格动态核验")
    login(page, base, "practitioner", "rng-wang", "/practitioner.html")
    cap("暂停持枪资格：名下枪支须立即上交，流转被阻断")
    clear_toasts(page)
    page.locator("#q-suspend").click()
    expect(page, "资格已更新")
    pause(page, 2200)
    page.locator(".nav-item", has_text="名下枪支").click()
    wait_active(page)
    page.wait_for_selector(".pane.active tbody tr")
    rows = page.locator(".pane.active tbody tr")
    if rows.count():
        rows.first.click(force=True)
    cap("名下枪支：状态、所属单位与最后事件")
    pause(page, 1200)
    page.locator(".nav-item", has_text="我的事件").click()
    wait_active(page)
    page.wait_for_selector(".pane.active tbody tr")
    cap("我的事件：每一步操作都哈希上链、不可篡改")
    pause(page, 1600)


def seg_admin(page, base, cap):
    """Regulator: clock advance, alert loop, approvals, scrap nodes, evidence."""
    cap("登录监管工作台：全量台账与预警态势一屏掌握")
    login(page, base, "admin", "admin1", "/admin.html")
    # overview: advance the demo clock
    cap("演示时钟 +24h：快速推演超时风险")
    clear_toasts(page)
    page.locator("#adv24").click()
    expect(page, "时钟")
    pause(page, 1600)
    # alerts: scan -> escalate -> respond
    page.locator(".nav-item", has_text="预警中心").click()
    wait_active(page)
    page.wait_for_selector("#al-scan")
    cap("扫描超期：按 12h / 24h 阶梯生成三级预警")
    clear_toasts(page)
    page.locator("#al-scan").click()
    expect(page, "扫描完成")
    pause(page, 1600)
    cap("升级未响应预警：提示 → 关注 → 紧急")
    clear_toasts(page)
    page.locator("#al-esc").click()
    expect(page, "升级完成")
    pause(page, 1600)
    resp = page.locator(".pane.active [data-resp]")
    resp.first.wait_for(state="visible", timeout=8000)
    cap("逐条响应处置：处置意见上链留痕、闭环管理")
    clear_toasts(page)
    resp.first.click()  # dialog handler fills the response text
    expect(page, "已响应")
    pause(page, 1800)
    # transport permits: approve all applied, verify the in-transit one
    page.locator(".nav-item", has_text="运输监管").click()
    wait_active(page)
    page.wait_for_selector("#pt-body tbody tr")
    cap("运输监管：审批单位申报的运输许可")
    for _ in range(3):
        approve = page.locator(".pane.active [data-a=approve]")
        if not approve.count():
            break
        clear_toasts(page)
        approve.first.click()
        expect(page, "已审批")
        pause(page, 1400)
    verify = page.locator(".pane.active [data-a=verify]")
    if verify.count():
        cap("在途枪支到达核销，回到在库")
        clear_toasts(page)
        verify.first.click()
        expect(page, "已核销")
        pause(page, 1800)
    # scrap: five signed nodes
    page.locator(".nav-item", has_text="报废监督").click()
    wait_active(page)
    page.wait_for_selector("#sc-gun option", state="attached")
    cap("报废销毁五节点：签名人须 ≥2 人")
    page.locator(".sc-signer").nth(0).check()
    page.locator(".sc-signer").nth(1).check()
    pause(page, 900)
    node_caps = ["节点① 省级确认，上链存证",
                 "节点② 送交",
                 "节点③ 清点",
                 "节点④ 销毁（双人签名）",
                 "节点⑤ 影像封存：标识永久留档"]
    for i in range(5):
        cap(node_caps[i])
        clear_toasts(page)
        page.locator("#sc-actions button").nth(i).click()
        if i == 4:
            expect(page, "销毁完成")
        else:
            expect(page, "已上链")
        pause(page, 1500)
    # evidence check on a gun code
    code = page.request.get(base + "/api/guns").json()["items"][0]["gun_code"]
    page.locator(".nav-item", has_text="一链查证").click()
    wait_active(page)
    page.wait_for_selector("#ev-code")
    page.fill("#ev-code", code)
    cap("一链查证：输入枪码，核验 5 项链上证据")
    clear_toasts(page)
    page.locator("#ev-form button", has_text="核验").click()
    page.wait_for_selector("#ev-tl tbody tr", timeout=10000)
    cap("哈希链 · 链上覆盖 · 交易比对 · 规则版本——全部通过")
    pause(page, 2000)


def seg_audit(page, base, cap):
    """Auditor: audit chain, ledger, evidence, outbox pump + reconcile."""
    cap("登录审计工作台：只读全量，监督监管行为本身")
    login(page, base, "auditor", "audit1", "/audit.html")
    cap("校验审计日志哈希链完整性")
    clear_toasts(page)
    page.locator("#al-verify").click()
    expect(page, "审计链校验通过")
    pause(page, 1600)
    page.locator(".nav-item", has_text="链上账本").click()
    wait_active(page)
    page.wait_for_selector("#lg-blocks-body tbody tr")
    page.wait_for_function(
        "document.querySelector('#lg-verify').textContent !== '...'", timeout=8000)
    cap("链上账本：区块明细 · 账本校验通过")
    pause(page, 1600)
    # evidence
    code = page.request.get(base + "/api/guns").json()["items"][0]["gun_code"]
    page.locator(".nav-item", has_text="证据核验").click()
    wait_active(page)
    page.wait_for_selector("#ev-code")
    page.fill("#ev-code", code)
    cap("单枪证据核验：本地哈希链与链上账本双向比对")
    clear_toasts(page)
    page.locator("#ev-form button", has_text="核验").click()
    page.wait_for_selector("#ev-checks .detail-grid", timeout=10000)
    pause(page, 2000)
    # outbox pump + reconcile
    page.locator(".nav-item", has_text="对账与泵送").click()
    wait_active(page)
    cap("Outbox 泵送：待上链事件批量提交共识")
    clear_toasts(page)
    page.locator("#ob-pump").click()
    expect(page, "泵送完成")
    pause(page, 1600)
    cap("链上—链下对账：已提交 / 链上 / 缺失 / 不一致")
    clear_toasts(page)
    page.locator("#ob-reconcile").click()
    page.wait_for_function(
        "document.querySelector('#ob-out').textContent.includes('对账完成')",
        timeout=8000)
    pause(page, 1800)
    # derived view stats (never click rebuild!)
    page.locator(".nav-item", has_text="派生视图").click()
    wait_active(page)
    cap("台账统计：派生视图可随时从链上事件全量重建")
    clear_toasts(page)
    page.locator("#rb-stats").click()
    page.wait_for_selector("#rb-body tbody tr", timeout=8000)
    pause(page, 1800)


SEGMENTS = [
    ("unit", seg_unit),
    ("practitioner", seg_practitioner),
    ("admin", seg_admin),
    ("audit", seg_audit),
]


# ---------------- recording ----------------
def record(base):
    from playwright.sync_api import sync_playwright

    SEG.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        for name, fn in SEGMENTS:
            context = browser.new_context(
                viewport={"width": W, "height": H},
                record_video_dir=str(SEG),
                record_video_size={"width": W, "height": H},
            )
            page = context.new_page()

            def on_dialog(d):
                if d.type == "prompt":
                    d.accept("现场核查，通知单位负责人")
                else:
                    d.accept()

            page.on("dialog", on_dialog)
            errors = []
            page.on("pageerror", lambda e: errors.append(str(e)))
            marks: list[list] = []
            t0 = time.monotonic()

            def cap(text):
                marks.append([round(time.monotonic() - t0, 3), text])

            try:
                fn(page, base, cap)
                assert not errors, f"{name} page errors: {errors}"
                (SEG / f"{name}.srtmarks.json").write_text(
                    json.dumps(marks, ensure_ascii=False, indent=1),
                    encoding="utf-8")
                print(f"PASS segment {name} ({len(marks)} caption marks)",
                      flush=True)
            finally:
                video = page.video
                page.close()
                context.close()
                if video is not None:
                    dst = SEG / f"{name}.webm"
                    if dst.exists():
                        dst.unlink()
                    shutil.move(video.path(), dst)
                    print(f"  saved {dst.relative_to(ROOT)}", flush=True)
        browser.close()


def make_cards():
    from playwright.sync_api import sync_playwright

    CARDS.mkdir(parents=True, exist_ok=True)
    css = """
    <style>
      html,body{margin:0;height:100%}
      body{background:linear-gradient(135deg,#0b1f3a 0%,#12325c 60%,#0d2a4d 100%);
           color:#fff;font-family:'Microsoft YaHei',sans-serif;
           display:flex;flex-direction:column;justify-content:center;padding:0 100px;
           box-sizing:border-box;height:720px}
      .kicker{color:#5eead4;font-size:24px;letter-spacing:6px;margin-bottom:24px}
      h1{font-size:56px;margin:0 0 22px;font-weight:700;line-height:1.25}
      .sub{font-size:26px;color:#b9d2f2;font-weight:400}
      .foot{position:absolute;bottom:44px;left:100px;color:#6f8fb8;font-size:18px}
      .accent{width:88px;height:6px;background:#5eead4;border-radius:3px;margin-bottom:34px}
    </style>"""
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": W, "height": H})
        for filename, title, sub, big in CARDS_HTML:
            kicker = "" if big else '<div class="kicker">民用枪支全链条智慧监管系统</div>'
            page.set_content(
                f"<!doctype html><html><head><meta charset='utf-8'>{css}</head>"
                f"<body>{kicker}<div class='accent'></div>"
                f"<h1>{title}</h1><div class='sub'>{sub}</div>"
                f"<div class='foot'>gun-supervision · 演示视频</div></body></html>",
                wait_until="load")
            page.screenshot(path=str(CARDS / f"{filename}.png"))
            print(f"  card {filename}.png", flush=True)
        browser.close()


# ---------------- assembly ----------------
def _to_mp4(src: Path, dst: Path, image=False):
    vf = ("scale=1280:720:force_original_aspect_ratio=decrease,"
          "pad=1280:720:(ow-iw)/2:(oh-ih)/2,fps=30,format=yuv420p")
    cmd = ["ffmpeg", "-y", "-hide_banner", "-loglevel", "error"]
    if image:
        cmd += ["-loop", "1", "-t", str(CARD_SECONDS), "-i", str(src)]
    else:
        cmd += ["-i", str(src)]
    cmd += ["-vf", vf, "-c:v", "libx264", "-preset", "veryfast",
            "-crf", "20", "-pix_fmt", "yuv420p", "-an", str(dst)]
    subprocess.run(cmd, check=True)


def _duration(path: Path) -> float:
    out = subprocess.run(
        ["ffprobe", "-v", "error", "-show_entries", "format=duration",
         "-of", "csv=p=0", str(path)],
        capture_output=True, text=True, check=True)
    return float(out.stdout.strip())


def _write_srt(entries, path: Path):
    def ts(t):
        ms = int(round(max(t, 0) * 1000))
        h, ms = divmod(ms, 3600000)
        m, ms = divmod(ms, 60000)
        s, ms = divmod(ms, 1000)
        return f"{h:02d}:{m:02d}:{s:02d},{ms:03d}"

    lines = []
    for i, (st, en, text) in enumerate(entries, 1):
        lines += [str(i), f"{ts(st)} --> {ts(en)}", text, ""]
    path.write_text("\n".join(lines), encoding="utf-8")


def assemble():
    if not shutil.which("ffmpeg"):
        print("SKIP assemble: ffmpeg not on PATH "
              "(segments and cards are still in artifacts/demo/)", flush=True)
        return
    BUILD.mkdir(parents=True, exist_ok=True)
    files = []  # (dst, kind, name)
    for kind, name in STORY:
        if kind == "card":
            src, dst, image = CARDS / f"{name}.png", BUILD / f"card-{name}.mp4", True
        else:
            src, dst, image = SEG / f"{name}.webm", BUILD / f"seg-{name}.mp4", False
        assert src.exists(), f"missing {src}"
        _to_mp4(src, dst, image=image)
        files.append((dst, kind, name))
        print(f"  encoded {dst.name}", flush=True)

    # shift per-segment caption marks onto the global timeline
    entries = []
    offset = 0.0
    for dst, kind, name in files:
        dur = _duration(dst)
        if kind == "seg":
            mf = SEG / f"{name}.srtmarks.json"
            marks = (json.loads(mf.read_text(encoding="utf-8"))
                     if mf.exists() else [])
            for i, (rel, text) in enumerate(marks):
                nxt = marks[i + 1][0] if i + 1 < len(marks) else dur
                st = offset + min(rel, dur)
                en = offset + min(max(nxt, rel + 0.8), dur)
                if en - st < 0.5:
                    en = st + 0.5
                entries.append((st, en, text))
        offset += dur
    srt = DEMO / "demo.srt"
    # cascade: never let two captions overlap (they would overprint when burned)
    fixed, prev_en = [], 0.0
    for st, en, text in entries:
        st = max(st, prev_en)
        en = max(en, st + 0.6)
        fixed.append((st, en, text))
        prev_en = en
    _write_srt(fixed, srt)
    print(f"  subtitles: {len(entries)} lines -> {srt.name}", flush=True)

    concat = BUILD / "concat.txt"
    concat.write_text(
        "".join(f"file '{f.as_posix()}'\n" for f, _, _ in files),
        encoding="utf-8")

    style = ("FontName=Microsoft YaHei,FontSize=16,PrimaryColour=&H00FFFFFF,"
             "OutlineColour=&H00000000,Outline=1,Shadow=0,MarginV=18,"
             "BorderStyle=1")
    srt_arg = srt.as_posix().replace(":", "\\:")
    vf = f"subtitles=filename='{srt_arg}':force_style='{style}'"
    try:
        subprocess.run(
            ["ffmpeg", "-y", "-hide_banner", "-loglevel", "error",
             "-f", "concat", "-safe", "0", "-i", str(concat),
             "-vf", vf, "-c:v", "libx264", "-preset", "veryfast",
             "-crf", "20", "-pix_fmt", "yuv420p", "-an", str(FINAL)],
            check=True)
    except subprocess.CalledProcessError:
        print("WARN: subtitle burn failed (libass missing?), "
              "falling back to plain concat", flush=True)
        subprocess.run(
            ["ffmpeg", "-y", "-hide_banner", "-loglevel", "error",
             "-f", "concat", "-safe", "0", "-i", str(concat),
             "-c", "copy", str(FINAL)], check=True)
    print(f"FINAL {FINAL}", flush=True)


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    for d in (SEG, CARDS, BUILD):
        if d.exists():
            shutil.rmtree(d)
    DEMO.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="gunreg-videodemo-") as data:
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        base = f"http://127.0.0.1:{port}"
        os.environ.update(GUNREG_DATA_DIR=data, GUNREG_RESET="1",
                          GUNREG_DEMO="1", GUNREG_COOKIE_SECURE="0")
        import uvicorn
        from webapp.main import app, SYSTEM

        server = uvicorn.Server(
            uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
        thread = threading.Thread(target=server.run, daemon=True)
        thread.start()
        try:
            for _ in range(100):
                if not thread.is_alive():
                    raise RuntimeError("demo server stopped unexpectedly")
                try:
                    with urllib.request.urlopen(base + "/login.html", timeout=1):
                        break
                except OSError:
                    time.sleep(0.15)
            else:
                raise RuntimeError("demo server did not start")
            t0 = time.time()
            make_cards()
            record(base)
            assemble()
            print(f"done in {time.time() - t0:.1f}s", flush=True)
        finally:
            server.should_exit = True
            thread.join(timeout=15)  # wait for in-flight requests
            # persistent sqlite handles must be closed before rmtree
            for obj in (SYSTEM.repo.db, SYSTEM.view.db):
                try:
                    obj.close()
                except Exception:
                    pass


if __name__ == "__main__":
    main()
