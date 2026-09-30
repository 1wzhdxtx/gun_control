"""系统组装：把流程图各分区装配为可运行系统 + 证据核验服务。

数据流（对应流程图）：
DOMAIN 写入(DB+Outbox) → RELAY → MQ → ADAPTER → CONTRACT/LEDGER
      → 回执 MQ → DOMAIN(确认事件) / QUERY(更新派生视图)
"""
from __future__ import annotations

import json
from dataclasses import dataclass

from .audit import AuditLog
from .bus import ChainAdapter, EventBus, OutboxRelay
from .bureau import BureauService
from .chain import Ledger
from .common import Clock, IntegrityError, ValidationError, canonical
from .contracts import ContractRegistry
from .crypto import CA, KMS, LocalVault
from .domain import DomainRepository, DomainService, Unit, Person
from .events import verify_chain
from .gateway import BFF, DeviceGateway, WAF
from .iam import IdentityService
from .integration import LegacyBridge, PrivacyOracle
from .scenarios import RangeRFIDController, ScanReviewStation
from .store import OutboxStore, QueryView


@dataclass
class EvidenceReport:
    ok: bool
    gun_code: str
    checks: dict

    def raise_if_failed(self) -> None:
        if not self.ok:
            raise IntegrityError(str(self.checks))


class EvidenceService:
    """一链查证：责任倒查与证据效力核验。"""

    def __init__(self, repo: DomainRepository, view: QueryView, ledger: Ledger, registry: ContractRegistry):
        self.repo = repo
        self.view = view
        self.ledger = ledger
        self.registry = registry

    def verify_gun(self, gun_code: str) -> EvidenceReport:
        checks: dict = {}

        # 1. 领域侧事件哈希链完整性（插入/删除/调换立即暴露）
        local_events = self.repo.events_of(gun_code)
        ok_chain, msg = verify_chain(local_events)
        checks["hash_chain"] = {"ok": ok_chain, "detail": msg}

        # 2. 链上账本完整性
        ok_ledger, msg_ledger = self.ledger.verify()
        checks["ledger"] = {"ok": ok_ledger, "detail": msg_ledger}

        # 3. 链上是否包含该枪全部事件（提交—上链对账）
        onchain = [e for e in self.ledger.events() if e.get("gun_code") == gun_code]
        local_ids = {e.event_id for e in local_events}
        onchain_ids = {e.get("event_id") for e in onchain}
        missing = sorted(local_ids - onchain_ids)
        checks["coverage"] = {"ok": not missing, "local": len(local_ids),
                              "onchain": len(onchain_ids), "missing": missing}

        # 4. 事件哈希与账本交易逐一比对（证据链）
        tx_by_event = {t["event"].get("event_id"): t for t in self.ledger.txs()
                       if t.get("event", {}).get("gun_code") == gun_code}
        mismatched = []
        for ev in local_events:
            tx = tx_by_event.get(ev.event_id)
            if tx and tx["event"].get("event_hash") != ev.event_hash:
                mismatched.append(ev.event_id)
        checks["evidence_match"] = {"ok": not mismatched, "mismatched": mismatched}

        # 5. 规则版本可回溯（任一历史时点的监管规则均可回溯）
        versions = {}
        for b in self.ledger.blocks():
            for name, ver in (b.get("rule_versions") or {}).items():
                versions.setdefault(name, set()).add(ver)
        checks["rule_versions"] = {"ok": True,
                                   "history": {k: sorted(v) for k, v in versions.items()}}

        ok = all(c.get("ok") for c in checks.values())
        return EvidenceReport(ok=ok, gun_code=gun_code, checks=checks)


class GunSystem:
    """把流程图各分区装配为一个可运行的整体。"""

    def __init__(self, base_dir: str | None = None, clock: Clock | None = None,
                 db_path: str = ":memory:", view_path: str = ":memory:"):
        self.clock = clock or Clock()
        # SECURITY: KEY
        self.kms = KMS(self.clock)
        self.ca = CA(clock=self.clock)
        self.vault = LocalVault(self.kms, base_dir=base_dir and f"{base_dir}/vault")
        # SECURITY: AUDIT
        self.audit = AuditLog(self.clock)
        # SECURITY: IAM
        self.identity = IdentityService(self.kms, self.ca, self.clock)
        # CHAIN + CONTRACT
        self.registry = ContractRegistry(self.clock, audit=self.audit)
        self.ledger = Ledger(self.clock, self.registry)
        # DATA
        self.repo = DomainRepository(self.clock, path=db_path)
        self.outbox = OutboxStore(self.repo.db, self.clock)
        self.view = QueryView(self.clock, path=view_path)
        # EVENT
        self.bus = EventBus(self.clock)
        self.relay = OutboxRelay(self.outbox, self.bus, self.clock)
        self.adapter = ChainAdapter(self.ledger, self.bus, self.clock, kms=self.kms)
        # ACCESS
        self.waf = WAF(self.clock)
        self.bff = BFF(self.identity, self.waf, self.clock)
        self.device_gw = DeviceGateway(self.ca, self.clock, kms=self.kms)
        # SCENARIOS
        self.range_rfid = RangeRFIDController(self.clock)
        self.scan_station = ScanReviewStation(self.view)
        # INTEGRATION
        self.legacy = LegacyBridge(self.kms, key_id="legacy-bridge", clock=self.clock)
        self.kms.create_key("legacy-bridge", owner="legacy", purpose="sign")
        self.privacy = PrivacyOracle(self.kms, key_id="privacy-oracle", clock=self.clock,
                                     vault=self.vault)
        self.kms.create_key("privacy-oracle", owner="privacy", purpose="sign")
        # DOMAIN
        self.domain = DomainService(self.repo, self.outbox, self.registry,
                                    self.kms, self.ca, self.audit, self.clock, self.vault)
        # 跨部门协同审批 + 一枪一档（持久化在业务库，重启后仍可追溯）
        self.bureau = BureauService(self.repo, self.clock, audit=self.audit,
                                    domain=self.domain)
        # QUERY 取证
        self.evidence = EvidenceService(self.repo, self.view, self.ledger, self.registry)

        # 订阅链回执 → 确认事件 → 更新派生视图
        self.bus.subscribe("chain.receipt", "query-view", self._on_receipt)
        self.bus.subscribe("gun.event", "chain-adapter", self._submit_to_chain)
        # 适配器与链签名密钥
        self.kms.create_key("adapter-01", owner="adapter", purpose="node")
        self.kms.create_key("chain-signer", owner="chain", purpose="node")
        self._receipts: list[dict] = []
        # 链恢复：账本是进程内状态，gun_events 事件日志才是权威记录。
        # 服务重启（或跨进程复用数据库）后必须从事件日志重放，
        # 否则「一链查证」的 coverage 恒缺开机前的全部事件。
        self.chain_recovered, self.chain_recover_failures = self._recover_chain()

    # -- 链恢复：从事件日志重放已确认事件 ------------------------------------
    def _recover_chain(self) -> tuple[int, list[str]]:
        """进程启动时把 gun_events 全量重放进内存账本（交易体与适配器一致、幂等）。

        不经事件总线：视图（stats_daily 等）已在首次上链时更新过，
        重放视图会重复计数；恢复只补账本本身。
        """
        recovered, failed = 0, []
        for row in self.repo.db.query("SELECT event_id, data FROM gun_events ORDER BY rowid"):
            try:
                ev = json.loads(row["data"])
            except (TypeError, ValueError):
                failed.append(row["event_id"])
                continue
            if not isinstance(ev, dict) or not ev.get("event_id"):
                failed.append(row["event_id"])
                continue
            # 数据域缺省逻辑与 _submit_to_chain 保持一致
            if not ev.get("domain"):
                ev["domain"] = (ev.get("payload") or {}).get("unit") or ev.get("gun_code", "")[:7]
            tx_body = {
                "client_tx_id": ev["event_id"],
                "event": ev,
                "member": (ev.get("payload") or {}).get("unit") or None,
                "submitted_at": self.clock.now_iso(),
                "adapter": "adapter-01",
            }
            tx = {**tx_body,
                  "sig": self.kms.sign("adapter-01", canonical(tx_body).encode("utf-8"))}
            rc = self.ledger.append_tx(tx)
            if rc.get("status") == "committed" and not rc.get("duplicate"):
                recovered += 1
            else:
                failed.append(ev["event_id"])
        return recovered, failed

    # -- Outbox 事件 → 链适配器（提交签名交易） -----------------------------
    def _submit_to_chain(self, msg) -> None:
        ev = msg.payload
        # 数据域补充：缺省以事件所属单位作为数据域（按所属主体隔离）
        if not ev.get("domain"):
            ev["domain"] = (ev.get("payload") or {}).get("unit") or ev.get("gun_code", "")[:7]
        rc = self.adapter.submit(client_tx_id=ev.get("event_id"),
                                 event=ev, signer_key="adapter-01")
        if rc.get("status") != "committed":
            # 链上拒绝（合约不通过/未达成共识）：抛错让事件总线重试，最终进死信。
            # 绝不能静默返回——否则 Outbox 会被标记 published 而链上无此交易。
            detail = rc.get("reasons") or rc.get("error") or rc.get("contract") or rc.get("status")
            raise RuntimeError(f"链上拒绝事件 {ev.get('event_id')}: {detail}")

    # -- 链回执处理 ---------------------------------------------------------
    def _on_receipt(self, msg) -> None:
        r = msg.payload["receipt"]
        ev = msg.payload["event"]
        if r.get("status") == "committed":
            ev = dict(ev)
            ev["chain_tx"] = r["tx_hash"]
            self.view.apply_event(ev)
            self._receipts.append({"tx": r, "event": ev})

    # -- 驱动异步管线 -------------------------------------------------------
    def pump(self, rounds: int = 5) -> dict:
        """执行 Outbox 转发与事件消费（生产中由后台循环承担）。"""
        published = self.relay.drain(rounds)
        return {"published": published, "outbox": self.outbox.stats(),
                "bus_dead": len(self.bus.dead_letters()),
                "receipts": len(self._receipts)}

    # -- 视图重建（可从链上事件全量恢复） -----------------------------------
    def rebuild_view(self) -> int:
        return self.view.rebuild(self.ledger.events())

    # -- 快捷注册 -----------------------------------------------------------
    def register_unit(self, unit_id, name, unit_type, risk_level=2,
                      region=None, time_window=None, domain="") -> Unit:
        u = Unit(unit_id=unit_id, name=name, unit_type=unit_type,
                 risk_level=risk_level, region=region, time_window=time_window,
                 domain=domain or unit_id)
        self.repo.save_unit(u)
        # 联盟链准入
        self.ledger.enroll(member_id=unit_id, org=name, role=unit_type)
        return u

    def register_person(self, person_id, name, unit_id, **kw) -> Person:
        p = Person(person_id=person_id, name=name, unit_id=unit_id, **kw)
        self.repo.save_person(p)
        return p

    def register_device(self, device_id: str, protocol: str, org: str) -> None:
        self.kms.create_key(f"device:{device_id}", owner=device_id, purpose="device")
        prof = self.device_gw.register_device(device_id, protocol, org,
                                              public_key=self.kms.public_key(f"device:{device_id}"))
        self.ledger.enroll(member_id=f"device:{device_id}", org=org, role="device")
        _ = prof
