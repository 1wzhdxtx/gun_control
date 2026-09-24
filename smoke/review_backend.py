"""Read-only-to-workspace diagnostic probes; all mutations use temporary data.

Prints observations, not a passing regression suite: unsafe behavior is evidence
to review. Run with .venv/Scripts/python smoke/review_backend.py.
"""
import os
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def main():
    with tempfile.TemporaryDirectory(prefix="gunreg-probes-") as data:
        os.environ.update(GUNREG_DATA_DIR=data, GUNREG_RESET="1", GUNREG_DEMO="1")
        from fastapi.testclient import TestClient
        from webapp.main import app, SYSTEM as s
        from webapp.seed import seed_system
        from gunreg.common import AuthenticationError

        clients = {}
        for i, (uid, pw) in enumerate((("admin1", "admin123"), ("unit-rng", "unit123"), ("rng-wang", "user123"), ("unit-mfg", "unit123"))):
            c = TestClient(app, raise_server_exceptions=False, client=(f"10.0.1.{i+1}", 10000+i))
            assert c.post("/api/login", json={"user_id": uid, "password": pw}).status_code == 200
            clients[uid] = c
        try:
            rng = clients["unit-rng"]
            stock = s.repo.guns_of("range-a", "in_stock")[0].code
            response = rng.post("/api/unit/checkout", json={"gun_code": stock, "person_id": "spt-chen", "signers": [["rng-zhang", "保管"], ["rng-li", "监督"]]})
            # spt-chen has incompatible kinds, use an in-unit newly created holder
            # for the no-independent-approval probe below instead.
            print("foreign_holder_original_kinds", response.status_code)
            s.register_person("foreign-review", "Probe", "sport-a", cert_kinds=["手枪"], duty="使用")
            response = rng.post("/api/unit/checkout", json={"gun_code": stock, "person_id": "foreign-review", "signers": [["rng-zhang", "保管"], ["rng-li", "监督"]]})
            print("foreign_holder_without_signer_sessions", response.status_code, s.repo.get_gun(stock).holder)
            response = clients["rng-wang"].post("/api/unit/person", json={"person_id": "practitioner-created", "name": "Probe", "duty": "保管", "create_login": True})
            print("practitioner_create_person_and_login", response.status_code)
            code = s.repo.guns_of("range-a", "in_stock")[0].code
            permit_data = {"gun_codes": [code], "permit_id": "PERMIT-A", "vehicle": "review", "carrier": "review", "valid_from": "2026-01-01T00:00:00Z", "valid_end": "2029-01-01T00:00:00Z"}
            response = rng.post("/api/permit/request", json=permit_data)
            print("overwrite_foreign_permit_id", response.status_code, s.repo.get_permit("PERMIT-A")["gun_codes"] == [code])
            response = clients["admin1"].post("/api/permit/approve", json={"permit_id": "PERMIT-A"})
            print("approved_permit_domain", repr(s.repo.db.one("SELECT domain FROM permits WHERE permit_id='PERMIT-A'")["domain"]))
            print("unit_sees_approved_permit", any(x["permit_id"] == "PERMIT-A" for x in rng.get("/api/permits").json()["items"]))
            response = rng.post("/api/unit/checkout", json={})
            print("empty_checkout_http_status", response.status_code)
            print("unknown_gun_evidence_ok", s.evidence.verify_gun("does-not-exist").ok)
            dev = "reader-gate-01"
            env = s.device_gw.new_envelope(dev, {"protocol": "rfid", "action": "out", "tag": "probe"})
            env["seq"] = 999999
            env["signature"] = "invalid"
            try:
                s.device_gw.ingest(env)
            except AuthenticationError:
                pass
            print("invalid_signature_changed_device_sequence", s.device_gw._device_seq.get(dev))
            # Updating the same event twice should not double-count daily stats.
            ev = s.ledger.events()[0]
            before = sum(x["cnt"] for x in s.view.stats())
            s.view.apply_event(ev)
            print("duplicate_event_added_stat_count", sum(x["cnt"] for x in s.view.stats()) - before)
            old_key = s.kms.public_key("user:admin1")
            os.environ["GUNREG_RESET"] = "0"
            s2, _ = seed_system()
            try:
                print("restart_events", len(s.repo.db.query("SELECT event_id FROM gun_events")), "ledger_txs", len(s2.ledger.txs()), "audit_records", len(s2.audit.records()))
                print("restart_changed_signing_key", old_key != s2.kms.public_key("user:admin1"))
                before = s2.view.ledger()["total"]
                s2.rebuild_view()
                print("restart_then_rebuild_gun_count", before, "->", s2.view.ledger()["total"])
            finally:
                s2.repo.db.close()
                s2.view.db.close()
        finally:
            for c in clients.values():
                c.close()
            s.repo.db.close()
            s.view.db.close()


if __name__ == "__main__":
    main()
