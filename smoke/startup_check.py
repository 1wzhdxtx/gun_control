"""Default-startup smoke against a running server (127.0.0.1:8000): login,
rules/chain/plans reads, P1-1 police-only probe (only mutating call is the
denied one, which changes no state). Run uvicorn first, same as e2e_api.py.
"""
from __future__ import annotations

import sys

import httpx

BASE = "http://127.0.0.1:8000"


def login(c: httpx.Client, user: str, pw: str) -> dict:
    r = c.post(f"{BASE}/api/login",
               json={"user_id": user, "password": pw, "totp": ""})
    assert r.status_code == 200, (user, r.status_code, r.text)
    return r.json()


def main() -> None:
    ok = 0
    with httpx.Client(timeout=30.0) as c:
        login(c, "admin1", "admin123")
        print("[OK] admin1 login")
        ok += 1

        d = c.get(f"{BASE}/api/bureau/rules").json()
        assert len(d["rules"]) == 12 and len(d["agencies"]) == 6, (
            len(d["rules"]), len(d["agencies"]))
        print("[OK] rules 12 agencies 6")
        ok += 1

        apps = c.get(f"{BASE}/api/bureau/apps").json()["items"]
        # 部门可见性按机关组过滤：admin1（警察组）看不到体育/林草/纯海关事项
        hidden = {a["app_id"] for a in apps}
        assert hidden == {"APP-2026-001", "APP-2026-002", "APP-2026-003",
                          "APP-2026-004", "APP-2026-005", "APP-2026-006",
                          "APP-2026-007", "APP-2026-009", "APP-2026-011",
                          "APP-2026-021"}, sorted(hidden)
        chain = next(a for a in apps if a["app_id"] == "APP-2026-005")
        assert [n["status"] for n in chain["chain"]][:2] == ["已完成", "已完成"]
        assert chain["chain"][0]["handler"] == "forestry1"
        assert chain["chain"][1]["handler"] == "admin2"
        assert chain["chain"][2]["handler"] == "admin1"
        print("[OK] admin1 sees 10 police-group apps; "
              "APP-005 chain handlers forestry1/admin2/admin1")
        ok += 1

        plans = c.get(f"{BASE}/api/bureau/plans").json()["items"]
        assert len(plans) == 1 and plans[0]["batch_ref"] == "B2026-001", plans
        assert plans[0]["planned_qty"] == 6 and plans[0]["status"] == "approved"
        print("[OK] plan PLAN-2026-002 B2026-001 qty=6 approved")
        ok += 1

        # P1-1: forestry (admin role, non-police) must be denied permit approval
        r = c.post(f"{BASE}/api/login",
                   json={"user_id": "forestry1", "password": "dept123",
                         "totp": ""})
        assert r.status_code == 200, r.text
        r = c.post(f"{BASE}/api/permit/approve", json={"permit_id": "PERMIT-A"})
        assert r.status_code == 403 and "公安" in r.json()["detail"], (
            r.status_code, r.text)
        print("[OK] forestry1 permit approve -> 403 police-only")
        ok += 1

        # unit login + unit data endpoints used by the new sale form
        login(c, "unit-hunt", "unit123")
        units = c.get(f"{BASE}/api/units").json()["items"]
        assert len(units) >= 6, len(units)
        lics = c.get(f"{BASE}/api/bureau/licenses").json()["items"]
        assert lics, "unit licenses"
        print(f"[OK] unit-hunt login; units={len(units)} licenses={len(lics)}")
        ok += 1

        # mps1 (new national police account) can log in
        login(c, "mps1", "admin123")
        print("[OK] mps1 login")
        ok += 1

    print(f"==== startup probe: {ok}/{ok} OK ====")


if __name__ == "__main__":
    sys.exit(main())
