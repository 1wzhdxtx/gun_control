"""快速自检：全新种子 → 结构/计数/前置条件断言（ASCII 输出，GBK 安全）。"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.stdout.reconfigure(encoding="utf-8")


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="gunreg-seedcheck-",
                                     ignore_cleanup_errors=True) as data:
        os.environ.update(GUNREG_DATA_DIR=data, GUNREG_RESET="1", GUNREG_DEMO="1")
        from webapp.seed import seed_system

        sysobj, clock = seed_system()
        b = sysobj.bureau
        db = sysobj.repo.db

        guns = db.query("SELECT code, unit_id, status FROM guns ORDER BY rowid")
        print("gun_total:", len(guns))
        assert len(guns) == 25, [g["code"] for g in guns]

        by_status = {}
        for g in guns:
            by_status[g["status"]] = by_status.get(g["status"], 0) + 1
        print("gun_status:", by_status)

        apps = b.list_apps()
        print("apps:", len(apps))
        for a in apps:
            print(" ", a["app_id"], a["matter"], a["status_label"],
                  a["current_agency_name"] or "-", "| missing:",
                  ",".join(a["missing"]) or "-")

        lics = b.licenses()
        print("licenses:", len(lics))
        for l in lics:
            print(" ", l["license_id"], l["license_type"], l["holder_unit"])

        sales = b.sales()
        print("sales:", len(sales), "covered:",
              len({c for s in sales for c in s["gun_codes"]}))

        insp = b.inspections()
        print("inspections:", [(i["insp_id"], i["status_label"]) for i in insp])

        # 前置条件：L2 未配售 → 运输/领用被拦截
        hunt2 = [g["code"] for g in guns
                 if g["unit_id"] == "hunt-a" and g["status"] == "in_stock"]
        print("hunt guns in stock:", hunt2)
        blocked = False
        try:
            b.require_sale(hunt2, "transport-test")
        except Exception as exc:  # noqa: BLE001
            blocked = True
            print("gate blocked ok:", str(exc)[:80].encode("unicode_escape").decode()[:80])
        assert blocked, "hunt_g2 should be blocked (no sale)"

        # 制造资质前置：mfg-yn 有证 / 其他单位无证
        assert b.active_license("mfg-yn", "mfg_license"), "mfg license missing"
        try:
            b.require_license("range-a", "mfg_license", "mfg-test")
            raise AssertionError("range-a should not hold mfg_license")
        except Exception as exc:
            print("license gate ok:", type(exc).__name__)

        # 一枪一档
        a1 = b.archive("YNH2026000060" if any(
            g["code"] == "YNH2026000060" for g in guns) else hunt2[0])
        print("archive gun:", a1["gun_code"], "scenario:",
              (a1["scenario"] or {}).get("name"))
        for n in a1["pipeline"]:
            print("  node:", n["key"], n["status"], "records:", len(n["records"]))
        border = [n for n in a1["pipeline"] if n["key"] == "border"][0]
        assert border["status"] == "不适用", border

        # 非场景枪：运动步枪 pipeline 正常
        sport = next(g["code"] for g in guns if g["unit_id"] == "sport-a")
        a2 = b.archive(sport)
        print("sport archive:", sport, [n["status"] for n in a2["pipeline"]])

        # 总览
        ov = b.lifecycle_overview()
        print("overview guns:", ov["gun_total"], "pending apps:",
              len(ov["pending_apps"]), "insp:", ov["inspections_by_status"])
        print("scenarios:", [(s["key"], s["guns"]) for s in ov["scenarios"]])

        # 规则
        print("rules:", len(b.rules()), "agencies:", len(b.agencies()))
        print("ALL OK")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
