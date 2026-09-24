"""智能合约（核心机制四：一约一规）——六类版本化合约。

合约只执行法律已明确的条件，不创设义务、不替代裁量；
每条合约带版本号，拒绝时返回 (合约, 版本, 原因)；
提供人工干预通道：授权多签可中止合约执行，干预行为本身上链留痕。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from .common import ContractRejected, parse_iso

# ---------------------------------------------------------------------------
# 合约基类与结果
# ---------------------------------------------------------------------------


@dataclass
class Verdict:
    ok: bool
    contract: str
    version: int
    reasons: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    # 供合约向业务层传递的附带结论（如超时分级）
    outputs: dict = field(default_factory=dict)

    def raise_if_rejected(self) -> None:
        if not self.ok:
            raise ContractRejected(self.contract, self.version, self.reasons)


class Contract:
    """合约基类：name、version、evaluate(ctx) -> Verdict。"""

    name: str = "base"
    version: int = 1
    rule_text: str = ""        # 法规依据（明文上链，全联盟可见）

    def evaluate(self, ctx: dict) -> Verdict:
        raise NotImplementedError

    def meta(self) -> dict:
        return {"name": self.name, "version": self.version, "rule_text": self.rule_text}


# ---------------------------------------------------------------------------
# 1. 合规校验合约
# ---------------------------------------------------------------------------


class ComplianceContract(Contract):
    name = "compliance"
    version = 1
    rule_text = "《枪支管理法》：持枪须持有效证件；枪支须在证件载明范围内使用；库室符合 GA 1016 风险等级要求"

    def evaluate(self, ctx: dict) -> Verdict:
        reasons, warn = [], []
        person = ctx.get("person") or {}
        gun = ctx.get("gun") or {}
        unit = ctx.get("unit") or {}

        if not person:
            if ctx.get("event_source") == "offline":
                warn.append("离线事件未携带人档快照，以设备签名与事后核验为准")
            else:
                reasons.append("操作主体未通过身份核验")
        else:
            if person.get("cert_status") != "valid":
                reasons.append("持枪证件无效或已丧失资格")
            cert_end = person.get("cert_expire")
            if cert_end and ctx.get("now") and parse_iso(cert_end) < parse_iso(ctx["now"]):
                reasons.append(f"持枪证已过期（{cert_end}）")
            allowed = set(person.get("cert_kinds") or [])
            if gun and gun.get("kind") and allowed and gun["kind"] not in allowed:
                reasons.append(f"枪种 {gun['kind']} 不在证件载明范围 {sorted(allowed)} 内")

        if gun:
            if gun.get("status") not in (ctx.get("allowed_gun_status") or ("in_stock", "in_use")):
                reasons.append(f"枪支状态 {gun.get('status')} 不允许该操作")
        if unit and unit.get("status") != "qualified":
            reasons.append("配置单位资格不符合要求")
        if unit and unit.get("risk_level") not in (1, 2, 3):
            reasons.append("库室风险等级未评定（GA 1016）")
        if not ctx.get("device_verified"):
            reasons.append("采集设备未通过验签")
        if ctx.get("manual_entry") and not ctx.get("voucher_hash"):
            reasons.append("人工录入缺少原始凭证哈希")

        if ctx.get("risk_level") == 3 and ctx.get("unit", {}).get("risk_level") == 1:
            warn.append("三级风险操作发生在一级库室，建议人工复核（提示级）")
        return Verdict(not reasons, self.name, self.version, reasons, warn)


# ---------------------------------------------------------------------------
# 2. 时空约束合约
# ---------------------------------------------------------------------------


class SpaceTimeContract(Contract):
    name = "spacetime"
    version = 1
    rule_text = "《枪支管理法》及狩猎管理规定：枪支使用须在许可区域与时段内（猎区/猎期）"

    def evaluate(self, ctx: dict) -> Verdict:
        reasons, warn = [], []
        region = ctx.get("region")           # {'name','lon_range','lat_range'} 或 None
        pos = ctx.get("position")            # (lon, lat) 或 None
        allowed_window = ctx.get("time_window")  # {'start','end'} 或 None
        now = ctx.get("now")

        if region and pos:
            lon, lat = pos
            lo = region["lon_range"]
            la = region["lat_range"]
            if not (lo[0] <= lon <= lo[1] and la[0] <= lat <= la[1]):
                reasons.append(f"位置 ({lon},{lat}) 超出许可区域 {region['name']}")
        if allowed_window and now:
            if not (parse_iso(allowed_window["start"]) <= parse_iso(now) <= parse_iso(allowed_window["end"])):
                reasons.append(f"当前时间 {now} 不在许可时段内")
        if ctx.get("require_position") and not pos and not ctx.get("offline"):
            warn.append("缺少定位数据（提示级）")
        if ctx.get("offline"):
            # 离线场景：时空校验只能事后执行，仅给出提示，不阻断
            if reasons:
                warn.append("离线记录事后核验不通过：" + "；".join(reasons))
                return Verdict(True, self.name, self.version, [], warn, outputs={"post_check": reasons})
        return Verdict(not reasons, self.name, self.version, reasons, warn)


# ---------------------------------------------------------------------------
# 3. 时限约束合约
# ---------------------------------------------------------------------------


class TimeLimitContract(Contract):
    name = "timelimit"
    version = 1
    rule_text = "枪支领用后应在规定期限内归还；超时分级提醒（提示→关注→紧急）"

    # 分级阈值（小时）：<= hint 提示；<= concern 关注；> concern 紧急
    HINT_HOURS = 12
    CONCERN_HOURS = 24

    def evaluate(self, ctx: dict) -> Verdict:
        due = ctx.get("due_at")
        now = ctx.get("now")
        returned = ctx.get("returned", False)
        if not due or not now or returned:
            return Verdict(True, self.name, self.version)

        overdue_hours = (parse_iso(now) - parse_iso(due)).total_seconds() / 3600
        if overdue_hours < 0:
            return Verdict(True, self.name, self.version, outputs={"overdue_hours": 0})

        if overdue_hours <= self.HINT_HOURS:
            level = "hint"
        elif overdue_hours <= self.CONCERN_HOURS:
            level = "concern"
        else:
            level = "emergency"
        # 未归还本身不阻断新事件（如补登记），但必须产出分级预警
        return Verdict(True, self.name, self.version,
                       warnings=[f"超时未归还 {overdue_hours:.1f} 小时，触发 {level} 级预警"],
                       outputs={"overdue_hours": round(overdue_hours, 2), "alert_level": level})

    def check_before_checkout(self, ctx: dict) -> Verdict:
        """新领用前：存在超期未还则阻断（合规性由法律文本支撑）。"""
        if ctx.get("outstanding_overdue"):
            return Verdict(False, self.name, self.version,
                           [f"存在超期未归还枪支（{ctx['outstanding_overdue']}），暂停再次领用"])
        return Verdict(True, self.name, self.version)


# ---------------------------------------------------------------------------
# 4. 多签名合约
# ---------------------------------------------------------------------------


class MultiSigContract(Contract):
    name = "multisig"
    version = 1
    rule_text = "枪支库室双人双锁制度：库室开启、领用与交接须两名以上授权主体共同签名"

    def __init__(self, required: int = 2):
        self.required = required

    def evaluate(self, ctx: dict) -> Verdict:
        signers = set(ctx.get("signers") or [])
        distinct_roles = set(ctx.get("signer_roles") or [])
        reasons = []
        if len(signers) < self.required:
            reasons.append(f"需 {self.required} 名授权主体签名，当前 {len(signers)} 名")
        if len(signers) != len(ctx.get("signer_ids") or signers):
            reasons.append("签名主体重复（须为不同自然人）")
        if ctx.get("require_distinct_duty") and not ({"保管", "监督"} <= distinct_roles or len(distinct_roles) >= 2):
            reasons.append("须包含不同职责岗位（如保管人 + 监督人）")
        return Verdict(not reasons, self.name, self.version, reasons)


# ---------------------------------------------------------------------------
# 5. 流转审批合约
# ---------------------------------------------------------------------------


class TransportPermitContract(Contract):
    name = "transport_permit"
    version = 1
    rule_text = "枪支（弹药）运输许可制度：许可与车辆、承运人、押运人绑定，到达核销"

    def evaluate(self, ctx: dict) -> Verdict:
        reasons = []
        permit = ctx.get("permit")
        if not permit:
            reasons.append("未取得枪支运输许可")
            return Verdict(False, self.name, self.version, reasons)
        if ctx.get("stage") != "verify_arrival" and permit.get("status") != "approved":
            reasons.append(f"许可状态为 {permit.get('status')}，不可执行运输")
        if permit.get("vehicle") != ctx.get("vehicle"):
            reasons.append(f"实际承运车辆 {ctx.get('vehicle')} 与许可载明 {permit.get('vehicle')} 不一致")
        if permit.get("carrier") != ctx.get("carrier"):
            reasons.append("实际承运人与许可载明不一致")
        if permit.get("escort") != ctx.get("escort"):
            reasons.append("实际押运人与许可载明不一致")
        guns = set(permit.get("gun_codes") or [])
        for code in ctx.get("gun_codes") or []:
            if code not in guns:
                reasons.append(f"枪支 {code} 不在许可清单内")
        now, start, end = ctx.get("now"), permit.get("valid_from"), permit.get("valid_end")
        if now and start and end and not (start <= now <= end):
            reasons.append(f"运输不在许可有效期内（{start} ~ {end}）")
        if ctx.get("stage") == "verify_arrival" and permit.get("status") != "in_transit":
            reasons.append("到达核销前须处于在途状态")
        return Verdict(not reasons, self.name, self.version, reasons)


# ---------------------------------------------------------------------------
# 6. 报废确认合约
# ---------------------------------------------------------------------------


class ScrapConfirmContract(Contract):
    name = "scrap_confirm"
    version = 1
    rule_text = "枪支报废销毁须申请、鉴定、省级确认；销毁四节点逐项签名；标识永久封存"

    STAGES = ("apply", "appraise", "province_confirm", "destroy_submit",
              "destroy_inventory", "destroy_execute", "destroy_archive")

    def evaluate(self, ctx: dict) -> Verdict:
        reasons = []
        stage = ctx.get("stage")
        if stage not in self.STAGES:
            reasons.append(f"未知销毁阶段: {stage}")
        signers = set(ctx.get("signers") or [])
        if stage == "apply" and not ctx.get("reason"):
            reasons.append("报废申请须载明理由")
        if stage == "appraise" and not ctx.get("appraisal"):
            reasons.append("须附具鉴定意见")
        if stage == "province_confirm" and len(signers) < 1:
            reasons.append("须经省级公安机关确认")
        if stage and stage.startswith("destroy") and len(signers) < 2:
            reasons.append("销毁节点须两名以上授权人员共同签名")
        if ctx.get("require_seal") and stage == "destroy_archive":
            # 最终节点：确认前序四节点齐备
            done = set(ctx.get("done_stages") or [])
            need = {"destroy_submit", "destroy_inventory", "destroy_execute", "destroy_archive"}
            if not need.issubset(done | {stage}):
                reasons.append("销毁节点未全部完成，不得封存")
        return Verdict(not reasons, self.name, self.version, reasons)


# ---------------------------------------------------------------------------
# 合约注册表：版本化 + 人工干预通道
# ---------------------------------------------------------------------------


@dataclass
class Intervention:
    """人工干预记录：授权主体多签中止合约执行，干预本身上链留痕。"""

    contract: str
    action: str            # suspend / resume
    reason: str
    signers: list[str]
    ts: str


class ContractRegistry:
    """版本化合约注册表：治理程序升级版本；人工干预须 ≥2 授权主体多签。"""

    def __init__(self, clock, audit=None):
        self.clock = clock
        self.audit = audit
        self._contracts: dict[str, Contract] = {}
        self._history: list[dict] = []
        self._suspended: dict[str, Intervention] = {}
        for c in (ComplianceContract(), SpaceTimeContract(), TimeLimitContract(),
                  MultiSigContract(), TransportPermitContract(), ScrapConfirmContract()):
            self.register(c)

    def register(self, contract: Contract) -> None:
        self._contracts[contract.name] = contract
        self._history.append({"action": "register", "ts": self.clock.now_iso(), **contract.meta()})

    def upgrade(self, contract: Contract, votes: list[str], min_votes: int = 2) -> None:
        """治理程序表决升级版本（保留完整历史，可回溯任一历史时点）。"""
        if len(set(votes)) < min_votes:
            raise ContractRejected("governance", contract.version, ["升级须经治理程序规定比例节点同意"])
        self._history.append({
            "action": "upgrade", "ts": self.clock.now_iso(),
            "old_version": self._contracts.get(contract.name, Contract()).version,
            "votes": sorted(set(votes)), **contract.meta(),
        })
        self._contracts[contract.name] = contract

    def get(self, name: str) -> Contract:
        return self._contracts[name]

    def versions(self, name: str) -> list[dict]:
        return [h for h in self._history if h.get("name") == name]

    # -- 人工干预通道 --------------------------------------------------------
    def suspend(self, name: str, reason: str, signers: list[str]) -> Intervention:
        if len(set(signers)) < 2:
            raise ContractRejected(name, self._contracts[name].version,
                                   ["人工干预须两名以上授权主体多签确认"])
        it = Intervention(contract=name, action="suspend", reason=reason,
                          signers=sorted(set(signers)), ts=self.clock.now_iso())
        self._suspended[name] = it
        self._history.append({"action": "suspend", "ts": it.ts, "name": name,
                              "reason": reason, "signers": it.signers})
        if self.audit:
            self.audit.append(actor="|".join(it.signers), action="contract:suspend",
                              target=name, detail={"reason": reason})
        return it

    def resume(self, name: str, reason: str, signers: list[str]) -> Intervention:
        if len(set(signers)) < 2:
            raise ContractRejected(name, self._contracts[name].version,
                                   ["恢复执行须两名以上授权主体多签确认"])
        it = Intervention(contract=name, action="resume", reason=reason,
                          signers=sorted(set(signers)), ts=self.clock.now_iso())
        self._suspended.pop(name, None)
        self._history.append({"action": "resume", "ts": it.ts, "name": name,
                              "reason": reason, "signers": it.signers})
        return it

    def is_suspended(self, name: str) -> bool:
        return name in self._suspended

    # -- 统一评估入口 --------------------------------------------------------
    def evaluate(self, name: str, ctx: dict) -> Verdict:
        """执行合约；若已被授权中止，仅留痕不阻断（保留人工裁量）。"""
        contract = self.get(name)
        verdict = contract.evaluate(ctx)
        if self.is_suspended(name):
            # 人工干预通道：授权中止后只提示留痕，不再自动阻断
            verdict.ok = True
            verdict.reasons = []
            verdict.warnings.append(
                f"合约 {name} 已被授权中止（{self._suspended[name].reason}），本次仅留痕不阻断"
            )
            verdict.outputs["suspended"] = True
        return verdict

    def evaluate_all(self, names: list[str], ctx: dict) -> list[Verdict]:
        return [self.evaluate(n, ctx) for n in names]

    @staticmethod
    def raise_all(verdicts: list[Verdict]) -> None:
        for v in verdicts:
            v.raise_if_rejected()

    def history(self) -> list[dict]:
        return list(self._history)
