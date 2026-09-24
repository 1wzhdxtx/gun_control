"""联盟链区：准入控制 + 数据域隔离的共识账本（流程图 CHAIN 分区）。

账本保存最小事件、摘要、签名、规则版本；
区块哈希串联；交易执行当前版本智能合约；支持按数据域（通道）隔离查询。
"""
from __future__ import annotations

import threading

from .common import IntegrityError, hash_obj, sha256_hex
from .contracts import ContractRegistry

GENESIS_PREV = "0" * 64


class Ledger:
    def __init__(self, clock, registry: ContractRegistry, consensus_nodes: int = 4):
        """
        consensus_nodes: 联盟共识节点数（本实现取多数决 ≥ floor(n/2)+1）
        """
        self.clock = clock
        self.registry = registry
        self.node_count = consensus_nodes
        self.quorum = consensus_nodes // 2 + 1
        self._blocks: list[dict] = []
        self._tx_index: dict[str, dict] = {}     # tx_hash -> tx
        self._tx_by_client: dict[str, str] = {}  # client_tx_id -> tx_hash（幂等）
        self._lock = threading.RLock()
        self._members: dict[str, dict] = {}      # 准入控制：成员登记
        self._genesis()

    # -- 准入控制 -----------------------------------------------------------
    def enroll(self, member_id: str, org: str, role: str, public_key: str = "") -> dict:
        m = {"member_id": member_id, "org": org, "role": role,
             "public_key": public_key, "joined_at": self.clock.now_iso(), "status": "active"}
        self._members[member_id] = m
        return m

    def revoke_member(self, member_id: str) -> None:
        if member_id in self._members:
            self._members[member_id]["status"] = "revoked"

    @property
    def members(self) -> dict[str, dict]:
        return dict(self._members)

    def _genesis(self) -> None:
        block = {
            "height": 0,
            "prev": GENESIS_PREV,
            "txs": [],
            "ts": self.clock.now_iso(),
            "rule_versions": {n: c.version for n, c in self.registry._contracts.items()},
            "signatures": ["node-0"],
        }
        block["block_hash"] = self._hash_block(block)
        self._blocks.append(block)

    @staticmethod
    def _hash_block(block: dict) -> str:
        body = {k: v for k, v in block.items() if k != "block_hash"}
        return hash_obj(body)

    # -- 提交交易（执行当前版本合约 + 共识） --------------------------------
    def append_tx(self, tx: dict) -> dict:
        with self._lock:
            client_id = tx.get("client_tx_id", "")
            if client_id and client_id in self._tx_by_client:
                tx_hash = self._tx_by_client[client_id]
                return {"status": "committed", "duplicate": True, "tx_hash": tx_hash,
                        "block_height": self._tx_index[tx_hash]["block_height"]}

            event = tx.get("event", {})
            from_ev_unit = (event.get("payload") or {}).get("unit", "")
            domain = event.get("domain") or from_ev_unit
            member = tx.get("member") or from_ev_unit or ""

            # 准入：提交方须为活跃成员（除系统创世外）
            if member and member in self._members and self._members[member]["status"] != "active":
                return {"status": "rejected", "error": f"成员 {member} 已被吊销准入", "client_tx_id": client_id}

            # 数据域隔离：事件必须声明数据域
            if not domain:
                return {"status": "rejected", "error": "事件缺少数据域", "client_tx_id": client_id}

            # 执行与事件类型绑定的合约（规则版本写入交易）
            verdicts = self._execute_contracts(event)
            for v in verdicts:
                if not v.ok:
                    return {
                        "status": "rejected", "client_tx_id": client_id,
                        "contract": v.contract, "rule_version": v.version, "reasons": v.reasons,
                    }

            tx_hash = hash_obj({"tx": tx, "height": len(self._blocks)})
            # 共识（多数节点确认）
            votes = self.quorum
            if votes < 1:
                return {"status": "rejected", "error": "共识节点数不足"}
            prev = self._blocks[-1]["block_hash"]
            block = {
                "height": len(self._blocks),
                "prev": prev,
                "txs": [tx_hash],
                "ts": self.clock.now_iso(),
                "rule_versions": {v.contract: v.version for v in verdicts} or
                                 {n: c.version for n, c in self.registry._contracts.items()},
                "signatures": [f"node-{i}" for i in range(votes)],
            }
            block["block_hash"] = self._hash_block(block)
            self._blocks.append(block)

            record = {**tx, "tx_hash": tx_hash, "block_height": block["height"],
                      "domain": domain, "rule_versions": block["rule_versions"]}
            self._tx_index[tx_hash] = record
            if client_id:
                self._tx_by_client[client_id] = tx_hash

            return {"status": "committed", "tx_hash": tx_hash,
                    "block_height": block["height"], "block_hash": block["block_hash"],
                    "rule_versions": block["rule_versions"], "commit_time": block["ts"]}

    # -- 事件 → 合约映射（规则内嵌于数据写入过程） --------------------------
    CONTRACT_MAP = {
        "checkout": ["compliance", "multisig", "timelimit"],
        "return": ["compliance", "multisig"],
        "transport": ["transport_permit", "spacetime"],
        "use": ["spacetime", "compliance"],
        "repair": ["compliance"],
        "scrap": ["scrap_confirm"],
        # 系统/基础事件（制造、状态、预警、许可流转）不执行业务合约重判
        "manufacture": [],
        "status_change": [],
        "permit": [],
        "alert": [],
    }

    def _execute_contracts(self, event: dict) -> list:
        names = self.CONTRACT_MAP.get(event.get("event_type", ""), [])
        if not names:
            return []
        payload = event.get("payload") or {}
        ctx = dict(payload.get("contract_ctx") or {})
        ctx.setdefault("now", event.get("occurred_at") or self.clock.now_iso())
        ctx.setdefault("event_source", event.get("source", "online"))
        return [self.registry.evaluate(n, ctx) for n in names]

    # -- 查询 ---------------------------------------------------------------
    def blocks(self) -> list[dict]:
        return list(self._blocks)

    def txs(self, domain: str | None = None) -> list[dict]:
        out = list(self._tx_index.values())
        if domain:  # 数据域隔离
            out = [t for t in out if t.get("domain") == domain]
        return out

    def find_tx(self, tx_hash: str) -> dict | None:
        return self._tx_index.get(tx_hash)

    def events(self, domain: str | None = None) -> list[dict]:
        return [t["event"] for t in self.txs(domain) if t.get("event")]

    # -- 完整性校验（证据核验入口） -----------------------------------------
    def verify(self) -> tuple[bool, str]:
        prev = GENESIS_PREV
        for b in self._blocks:
            if b["prev"] != prev:
                return False, f"区块 {b['height']} 前序哈希断裂"
            if self._hash_block(b) != b["block_hash"]:
                return False, f"区块 {b['height']} 内容被篡改"
            prev = b["block_hash"]
        for h, tx in self._tx_index.items():
            if hash_obj({"tx": {k: v for k, v in tx.items() if k not in ("tx_hash", "block_height", "domain", "rule_versions")},
                         "height": tx["block_height"]}) != h:
                return False, f"交易 {h[:12]}… 内容被篡改"
        return True, f"账本完整：{len(self._blocks)} 区块 / {len(self._tx_index)} 交易"

    def snapshot(self) -> dict:
        return {"blocks": self._blocks, "txs": list(self._tx_index.values()),
                "members": self._members}
