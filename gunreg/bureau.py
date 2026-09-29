"""跨部门协同审批与「一枪一档」全生命周期档案。

系统主线：五类业务场景 + 一枪一档 + 跨部门全生命周期监管。

- 审批规则可配置：事项 → 部门链（含节点动作）+ 材料清单 + 法规依据 + 签发证照；
- 部门权限：公安 / 林草 / 体育 / 海关按事项与辖区（部门分组）查看、办理，
  办理节点必须由部门链上对应部门处理，不能由通用管理员包办；
- 前置条件：企业资质、配售配购登记缺失时，后台阻止后续业务（制造 / 运输 / 领用）；
- 监督检查：检查 → 整改 → 复查 三态闭环；
- 进出境：贸易进出口与人员携带进出境分开建项、分部门会签（《枪支管理法》三十五至三十七条）；
- 全部记录落在业务库（sqlite），重启后仍可追溯。

档案节点状态统一为：已完成 / 办理中 / 待办理 / 退回补正 / 不适用；
节点明细统一展示：办理事项、申请单位、办理部门、经办人、办理时间、审批意见、
证件及有效期、附件、存证编号，并区分「真实业务记录」与「演示记录」。
"""
from __future__ import annotations

import json
import re
from datetime import timedelta

from .common import NotFoundError, PermissionDenied, StateError, ValidationError, hash_obj
from .identity import MAKERS

# ---------------------------------------------------------------------------
# 部门登记（可配置：名称、分组、辖区）
# ---------------------------------------------------------------------------
AGENCIES: dict[str, dict] = {
    "police-national": {"name": "公安部·治安管理局", "group": "police", "region": "全国"},
    "police-province": {"name": "省公安厅·治安总队", "group": "police", "region": "全省"},
    "police-city": {"name": "市公安局·治安支队", "group": "police", "region": "本市"},
    "forestry": {"name": "省林业和草原局", "group": "forestry", "region": "全省"},
    "sports": {"name": "省体育局", "group": "sports", "region": "全省"},
    "customs": {"name": "海关·枪支进出境监管", "group": "customs", "region": "口岸"},
}

# 登录账号 org → 部门。行政边界（部/省/市）体现在 org 上。
_ORG_AGENCY = {
    "police:national": "police-national",
    "police:province": "police-province",
    "dept:forestry": "forestry",
    "dept:sports": "sports",
    "dept:customs": "customs",
}


def agency_of_org(org: str) -> str | None:
    """账号所属 org → 部门 id（非部门账号返回 None）。"""
    if org in _ORG_AGENCY:
        return _ORG_AGENCY[org]
    if org.startswith("police:"):
        return "police-city"
    return None


# ---------------------------------------------------------------------------
# 审批规则（可配置：事项 → 部门链 + 材料 + 依据 + 证照）
#   依据：《枪支管理法》第九条（狩猎场配置猎枪：省级以上林业行政主管部门批准文件 →
#         省级以上公安机关审批 → 设区的市级公安机关核发配购证件）、
#         第十五条（制造许可证由国务院公安部门核发；配售许可证由省级公安机关核发，
#         两类许可分开发证、不得合并）、
#         第三十五至三十七条（人员携带进出境的批准、登记、申报环节）。
#   各场景主管部门、审批层级与材料为演示可配置规则，落地时应结合项目所在地
#   现行办事指南核实。
# ---------------------------------------------------------------------------
APPROVAL_RULES: dict[str, dict] = {
    "manufacture_license": {
        "name": "民用枪支制造许可核发", "category": "资质审批",
        "chain": [{"agency": "police-national", "action": "国务院公安部门核发"}],
        "materials": ["营业执照", "厂区安全条件说明", "质量管理体系文件", "法定代表人身份证明"],
        "license_type": "mfg_license", "license_name": "民用枪支制造许可证",
        "years": 3,
        "legal": "《枪支管理法》第十五条：制造民用枪支的企业，"
                 "由国务院公安部门核发民用枪支制造许可证",
    },
    "sale_license": {
        "name": "民用枪支配售许可核发", "category": "资质审批",
        "chain": [{"agency": "police-province", "action": "省级审批核发"}],
        "materials": ["营业执照", "配售场所与库室条件说明", "质量管理体系文件",
                      "法定代表人身份证明"],
        "license_type": "sale_license", "license_name": "民用枪支配售许可证",
        "years": 3,
        "legal": "《枪支管理法》第十五条：配售民用枪支的企业，"
                 "由省、自治区、直辖市人民政府公安机关核发民用枪支配售许可证",
    },
    "unit_qualification": {
        "name": "配置单位资质核发", "category": "资质审批",
        "chain": [{"agency": "police-city", "action": "属地审核核发"}],
        "materials": ["场所验收合格证明", "库室防盗防火证明", "保管人员名册"],
        "license_type": "unit_qualification", "license_name": "枪支配置单位资质证书",
        "years": 3,
        "legal": "《枪支管理法》及 GA 1016 库室风险等级要求",
    },
    "production_plan": {
        "name": "生产计划与批次备案", "category": "计划备案",
        "chain": [{"agency": "police-city", "action": "属地备案审核"}],
        "materials": ["年度生产计划", "批次数量清单", "原料来源说明"],
        "license_type": None, "license_name": "", "years": 0,
        "legal": "生产批次须事前备案，赋码后关联到具体枪支",
        "creates_plan": True,   # 批准后自动生成可执行的生产计划记录
    },
    "hunt_config": {
        "name": "狩猎场配置猎枪（配购）", "category": "配购配售",
        "chain": [{"agency": "forestry", "action": "林业主管部门批准文件核发"},
                  {"agency": "police-province", "action": "省级公安机关审批"},
                  {"agency": "police-city", "action": "设区的市级公安机关核发配购证件"}],
        "materials": ["狩猎场营业执照", "林业主管部门批准文件", "配置用途与区域说明",
                      "库室与保管条件证明"],
        "license_type": "purchase_permit", "license_name": "民用枪支配购证件",
        "years": 3,
        "legal": "《枪支管理法》第九条：狩猎场配置猎枪，凭省级以上人民政府林业行政"
                 "主管部门的批准文件，报省级以上人民政府公安机关审批，由设区的市级"
                 "人民政府公安机关核发民用枪支配购证件",
    },
    "sport_plan": {
        "name": "射击运动任务备案", "category": "计划备案",
        "chain": [{"agency": "sports", "action": "任务备案审核"}],
        "materials": ["运动训练/赛事任务书", "运动员名册", "枪弹保管方案"],
        "license_type": "task_license", "license_name": "射击运动任务备案凭证",
        "years": 1,
        "legal": "射击运动枪支按任务用途管理（演示可配置规则）",
    },
    "airport_plan": {
        "name": "机场驱鸟任务备案", "category": "计划备案",
        "chain": [{"agency": "police-city", "action": "任务备案审核"}],
        "materials": ["机场驱鸟任务书", "作业区域与时段说明", "现场安全措施"],
        "license_type": "task_license", "license_name": "机场驱鸟任务备案凭证",
        "years": 1,
        "legal": "演示规则（机场驱鸟用枪适用规定须另行核实）",
    },
    "wildlife_plan": {
        "name": "野生动物管护/科研用枪依据", "category": "计划备案",
        "chain": [{"agency": "forestry", "action": "作业依据审核"}],
        "materials": ["管护或科研任务依据", "麻醉药品使用登记方案", "作业人员资格证明"],
        "license_type": "task_license", "license_name": "野生动物管护用枪作业凭证",
        "years": 1,
        "legal": "野生动物保护/科研用途按林草主管部门依据管理（演示可配置规则）",
    },
    "border_trade_out": {
        "name": "贸易出口（枪支出口申报）", "category": "进出境", "mode": "贸易出口",
        "chain": [{"agency": "customs", "action": "出口申报受理"},
                  {"agency": "customs", "action": "查验与放行"}],
        "materials": ["出口合同", "最终用户和最终用途证明", "出口许可证件"],
        "license_type": None, "license_name": "", "years": 0,
        "legal": "贸易进出口以海关申报查验为主线（可配置规则）",
    },
    "border_trade_in": {
        "name": "贸易进口（枪支进口审批）", "category": "进出境", "mode": "贸易进口",
        "chain": [{"agency": "customs", "action": "进口申报受理"},
                  {"agency": "police-province", "action": "进口审批"},
                  {"agency": "customs", "action": "查验与放行"}],
        "materials": ["进口合同", "进口许可证件", "收货单位资质证明"],
        "license_type": None, "license_name": "", "years": 0,
        "legal": "进口枪支须公安机关审批 + 海关查验放行（可配置规则）",
    },
    "border_carry_out": {
        "name": "人员携带枪支出境", "category": "进出境", "mode": "携带出境",
        "chain": [{"agency": "police-province", "action": "携运批准"},
                  {"agency": "customs", "action": "出境申报登记"}],
        "materials": ["持枪证件", "出境事由与行程证明", "枪支携运申请"],
        "license_type": None, "license_name": "", "years": 0,
        "legal": "《枪支管理法》第三十五至三十七条：人员携带进出境须经批准、"
                 "登记与申报，环节与贸易进出口不同",
    },
    "border_carry_in": {
        "name": "人员携带枪支入境", "category": "进出境", "mode": "携带入境",
        "chain": [{"agency": "police-province", "action": "入境批准登记"},
                  {"agency": "customs", "action": "入境申报查验"}],
        "materials": ["持枪证件", "入境事由证明", "枪支申报单"],
        "license_type": None, "license_name": "", "years": 0,
        "legal": "《枪支管理法》第三十五至三十七条（批准、登记、申报分环节）",
    },
}

BORDER_MATTERS = tuple(k for k, v in APPROVAL_RULES.items() if v["category"] == "进出境")

# ---------------------------------------------------------------------------
# 五类业务场景（研究对象/业务场景入口，不替代枪械类型字段）
# ---------------------------------------------------------------------------
SCENARIOS: dict[str, dict] = {
    "hunt": {"name": "民用猎枪", "unit_types": ["hunter"],
             "fields": ["配置主体", "批准用途", "适用区域", "相关配置材料"]},
    "sport": {"name": "射击运动枪支", "unit_types": ["sports_school"],
              "fields": ["运动单位", "训练或赛事任务", "领用及归还记录"]},
    "airport": {"name": "机场驱鸟枪", "unit_types": ["airport"],
                "fields": ["机场单位", "驱鸟任务", "作业区域", "任务结束交回记录",
                           "适用规定"]},
    "wildlife": {"name": "野生动物麻醉枪", "unit_types": ["wildlife"],
                 "fields": ["保护或科研单位", "任务依据", "作业记录"]},
    "range": {"name": "营业性射击场枪支", "unit_types": ["shooting_range"],
              "fields": ["场所资质", "场内使用", "交接盘点", "监督检查"]},
}

# 档案主线（业务主线展示，不要求所有业务严格串行）
PIPELINE_KEYS = ("enterprise", "manufacture", "sale", "transport", "use", "scrap", "border")
PIPELINE_NAMES = {
    "enterprise": "企业资质与计划",
    "manufacture": "制造赋码",
    "sale": "配购与配售",
    "transport": "运输交接",
    "use": "持有使用",
    "scrap": "报废销毁",
    "border": "进出境",
}

S_DONE, S_DOING, S_TODO, S_SUPP, S_NA = "已完成", "办理中", "待办理", "退回补正", "不适用"

APP_STATUS_LABEL = {"pending": S_DOING, "supplement": S_SUPP,
                    "approved": S_DONE, "rejected": "退回"}
INSP_STATUS_LABEL = {"pending_fix": "待整改", "recheck": "待复查", "closed": "已闭环"}

SOURCE_LABEL = {"real": "真实业务记录", "demo": "演示记录"}

SCHEMA = """
CREATE TABLE IF NOT EXISTS bureau_apps (
  app_id TEXT PRIMARY KEY,
  matter TEXT NOT NULL,
  category TEXT NOT NULL,
  scenario TEXT DEFAULT '',
  applicant_unit TEXT NOT NULL,
  applicant_person TEXT DEFAULT '',
  title TEXT DEFAULT '',
  gun_codes TEXT DEFAULT '[]',
  materials TEXT DEFAULT '[]',
  missing TEXT DEFAULT '[]',
  status TEXT NOT NULL,
  current_step INTEGER DEFAULT 0,
  steps TEXT DEFAULT '[]',
  license_id TEXT DEFAULT '',
  evidence_no TEXT DEFAULT '',
  source TEXT DEFAULT 'real',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  domain TEXT DEFAULT '',
  batch_ref TEXT DEFAULT '',
  planned_qty INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS bureau_licenses (
  license_id TEXT PRIMARY KEY,
  license_type TEXT NOT NULL,
  name TEXT NOT NULL,
  holder_unit TEXT NOT NULL,
  agency_id TEXT NOT NULL,
  scenario TEXT DEFAULT '',
  app_id TEXT DEFAULT '',
  gun_codes TEXT DEFAULT '[]',
  valid_from TEXT,
  valid_to TEXT,
  status TEXT DEFAULT 'active',
  scope TEXT DEFAULT '',
  evidence_no TEXT DEFAULT '',
  source TEXT DEFAULT 'real',
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS bureau_sales (
  sale_id TEXT PRIMARY KEY,
  scenario TEXT DEFAULT '',
  seller_unit TEXT NOT NULL,
  buyer_unit TEXT NOT NULL,
  license_id TEXT DEFAULT '',
  purchase_app_id TEXT DEFAULT '',
  gun_codes TEXT NOT NULL DEFAULT '[]',
  status TEXT DEFAULT 'delivered',
  note TEXT DEFAULT '',
  evidence_no TEXT DEFAULT '',
  source TEXT DEFAULT 'real',
  created_at TEXT NOT NULL,
  domain TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS bureau_inspections (
  insp_id TEXT PRIMARY KEY,
  agency_id TEXT NOT NULL,
  inspector TEXT NOT NULL,
  target_unit TEXT NOT NULL,
  gun_codes TEXT DEFAULT '[]',
  findings TEXT DEFAULT '[]',
  deadline TEXT DEFAULT '',
  status TEXT NOT NULL,
  fix_note TEXT DEFAULT '',
  fix_at TEXT DEFAULT '',
  recheck_result TEXT DEFAULT '',
  recheck_at TEXT DEFAULT '',
  checked_at TEXT NOT NULL,
  evidence_no TEXT DEFAULT '',
  source TEXT DEFAULT 'real',
  domain TEXT DEFAULT '',
  history TEXT DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS bureau_plans (
  plan_id TEXT PRIMARY KEY,
  unit_id TEXT NOT NULL,
  license_id TEXT DEFAULT '',
  scenario TEXT DEFAULT '',
  batch_ref TEXT NOT NULL,
  planned_qty INTEGER DEFAULT 0,
  status TEXT DEFAULT 'approved',
  evidence_no TEXT DEFAULT '',
  source TEXT DEFAULT 'real',
  created_at TEXT NOT NULL,
  gun_codes TEXT DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS bureau_gun_scenarios (
  gun_code TEXT PRIMARY KEY,
  scenario TEXT NOT NULL,
  info TEXT DEFAULT '{}',
  evidence_no TEXT DEFAULT '',
  source TEXT DEFAULT 'real',
  created_at TEXT NOT NULL
);
"""


def _loads(text, default):
    if not isinstance(text, (str, bytes, bytearray)):
        # 已解码对象（视图里的 list/dict）直接透传：不能再走 json.loads，
        # 否则 TypeError 会吞掉数据返回 default（历史记录被覆盖丢失）。
        return default if text is None else text
    try:
        v = json.loads(text)
    except (TypeError, ValueError):
        return default
    return default if v is None else v


class BureauService:
    """跨部门协同审批 + 一枪一档档案（数据全部持久化在业务库）。"""

    def __init__(self, repo, clock, audit=None):
        self.repo = repo
        self.clock = clock
        self.audit = audit
        self.db = repo.db
        self.db.executescript(SCHEMA)
        self._migrate()

    def _migrate(self) -> None:
        """旧库补列（CREATE TABLE IF NOT EXISTS 不会更新已有表结构）。"""
        wanted = (
            ("bureau_apps", {"batch_ref": "TEXT DEFAULT ''",
                             "planned_qty": "INTEGER DEFAULT 0"}),
            ("bureau_inspections", {"history": "TEXT DEFAULT '[]'"}),
            ("bureau_plans", {"gun_codes": "TEXT DEFAULT '[]'"}),
        )
        for table, cols in wanted:
            have = {r["name"] for r in self.db.query(f"PRAGMA table_info({table})")}
            for name, ddl in cols.items():
                if name not in have:
                    self.db.execute(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}")

    # ------------------------------------------------------------------ 基础
    def _now(self) -> str:
        return self.clock.now_iso()

    @staticmethod
    def _ev(prefix: str, obj) -> str:
        h = hash_obj(obj)[:16].upper()
        return f"{prefix}-{h}" if prefix else h

    def _log(self, actor: str, action: str, target: str, detail: dict | None = None) -> None:
        if self.audit is not None:
            self.audit.append(actor=actor, action=action, target=target, detail=detail or {})

    # -------------------------------------------------------------- 规则视图
    def rules(self) -> list[dict]:
        out = []
        for code, r in APPROVAL_RULES.items():
            out.append({
                "matter": code, "name": r["name"], "category": r["category"],
                "mode": r.get("mode", ""),
                "chain": [{"agency": s["agency"],
                           "agency_name": AGENCIES[s["agency"]]["name"],
                           "action": s["action"]} for s in r["chain"]],
                "materials": list(r["materials"]),
                "legal": r["legal"],
                "license_name": r.get("license_name") or "",
            })
        return out

    @staticmethod
    def agencies() -> list[dict]:
        return [{"agency_id": k, **v} for k, v in AGENCIES.items()]

    @staticmethod
    def matters_of_group(group: str) -> set[str]:
        """某分组（公安/林草/体育/海关）可查看的事项集合。"""
        return {code for code, r in APPROVAL_RULES.items()
                if any(AGENCIES[s["agency"]]["group"] == group for s in r["chain"])}

    # -------------------------------------------------------------- 协同审批
    def apply(self, *, matter: str, applicant_unit: str, applicant_person: str = "",
              gun_codes: list[str] | None = None, materials: list[str] | None = None,
              scenario: str = "", title: str = "", source: str = "real",
              actor: str = "", app_id: str | None = None,
              region: str = "", batch_ref: str = "",
              planned_qty: int = 0) -> dict:
        rule = APPROVAL_RULES.get(matter)
        if not rule:
            raise ValidationError(f"未知审批事项: {matter}")
        if not applicant_unit:
            raise ValidationError("须载明申请单位")
        mats = list(dict.fromkeys(materials or []))
        missing = [m for m in rule["materials"] if m not in mats]
        now = self._now()
        app_id = app_id or f"APP-{now[:10].replace('-', '')}-" + \
            self._ev("", {"matter": matter, "unit": applicant_unit,
                          "guns": gun_codes, "now": now})[:6]
        app = {
            "app_id": app_id, "matter": matter, "category": rule["category"],
            "scenario": scenario, "applicant_unit": applicant_unit,
            "applicant_person": applicant_person, "title": title or rule["name"],
            "gun_codes": list(gun_codes or []), "materials": mats, "missing": missing,
            "status": "pending" if not missing else "supplement", "current_step": 0,
            "steps": [], "license_id": "", "source": source,
            "evidence_no": self._ev("EV", {"app": app_id, "matter": matter,
                                           "unit": applicant_unit}),
            "created_at": now, "updated_at": now,
            "domain": applicant_unit, "region": region,
            "batch_ref": batch_ref or "", "planned_qty": int(planned_qty or 0),
        }
        self.db.execute(
            "INSERT INTO bureau_apps (app_id,matter,category,scenario,applicant_unit,"
            "applicant_person,title,gun_codes,materials,missing,status,current_step,"
            "steps,license_id,evidence_no,source,created_at,updated_at,domain,"
            "batch_ref,planned_qty) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (app["app_id"], app["matter"], app["category"], app["scenario"],
             app["applicant_unit"], app["applicant_person"], app["title"],
             _js(app["gun_codes"]), _js(app["materials"]), _js(app["missing"]),
             app["status"], app["current_step"], _js(app["steps"]), "",
             app["evidence_no"], app["source"], now, now, app["domain"],
             app["batch_ref"], app["planned_qty"]))
        self._log(actor or applicant_unit, "bureau:apply", app_id,
                  {"matter": matter, "missing": missing})
        return self.get_app(app_id)

    def get_app(self, app_id: str) -> dict:
        row = self.db.one("SELECT * FROM bureau_apps WHERE app_id=?", (app_id,))
        if not row:
            raise NotFoundError(f"审批事项不存在: {app_id}")
        return self._app_view(row)

    def list_apps(self, matters: set[str] | None = None,
                  applicant_unit: str | None = None,
                  status: str = "", category: str = "") -> list[dict]:
        rows = self.db.query("SELECT * FROM bureau_apps ORDER BY created_at DESC, rowid DESC")
        out = []
        for r in rows:
            if matters is not None and r["matter"] not in matters:
                continue
            if applicant_unit is not None and r["applicant_unit"] != applicant_unit:
                continue
            if status and r["status"] != status:
                continue
            if category and r["category"] != category:
                continue
            out.append(self._app_view(r))
        return out

    def resubmit(self, app_id: str, materials: list[str] | None, actor: str = "") -> dict:
        app = self.get_app(app_id)
        if app["status"] != "supplement":
            raise StateError(f"事项 {app_id} 当前状态 {app['status_label']}，无需补正")
        rule = APPROVAL_RULES[app["matter"]]
        mats = list(dict.fromkeys((materials if materials is not None else app["materials"])))
        # 补正要求 = 规则材料 + 部门另行指定的补正材料（不含在规则清单里的缺件），
        # 未补齐的额外缺件会随补正轮次继续传递，不能"原样重交"蒙混过关。
        required = list(dict.fromkeys(
            list(rule["materials"]) + [m for m in app["missing"]
                                       if m not in rule["materials"]]))
        missing = [m for m in required if m not in mats]
        status = "pending" if not missing else "supplement"
        self.db.execute(
            "UPDATE bureau_apps SET materials=?, missing=?, status=?, updated_at=? "
            "WHERE app_id=?", (_js(mats), _js(missing), status, self._now(), app_id))
        self._log(actor or app["applicant_unit"], "bureau:resubmit", app_id,
                  {"missing": missing})
        return self.get_app(app_id)

    def process(self, app_id: str, *, agency_id: str, handler: str,
                action: str, opinion: str = "",
                materials: list[str] | None = None) -> dict:
        """按部门链办理当前节点：approve 放行 / supplement 退回补正 / reject 退回。"""
        app = self.get_app(app_id)
        rule = APPROVAL_RULES[app["matter"]]
        if agency_id not in AGENCIES:
            raise ValidationError(f"未知部门: {agency_id}")
        if app["status"] != "pending":
            raise StateError(
                f"事项 {app_id} 当前状态 {app['status_label']}，不可办理"
                + ("（须先补正材料）" if app["status"] == "supplement" else ""))
        idx = app["current_step"]
        step_def = rule["chain"][idx]
        if step_def["agency"] != agency_id:
            holder = AGENCIES[step_def["agency"]]["name"]
            raise PermissionDenied(
                f"该节点由 {holder} 办理（当前 {AGENCIES[agency_id]['name']} 无权办理）")
        if action not in ("approve", "supplement", "reject"):
            raise ValidationError(f"未知办理动作: {action}")
        now = self._now()
        # step_index 记录本条操作针对链上哪个节点，链视图按此对位，
        # 不按数组位置推断（补正→重新批准会产生多条同节点记录）。
        step = {"agency": agency_id, "agency_name": AGENCIES[agency_id]["name"],
                "action": step_def["action"], "handler": handler, "opinion": opinion,
                "action_type": action, "at": now, "step_index": idx}
        steps = app["steps"] + [step]
        status = app["status"]
        license_id = app["license_id"]
        if action == "approve":
            if idx + 1 >= len(rule["chain"]):
                status = "approved"
                if rule.get("license_type"):
                    lic = self._issue_license(app, rule, agency_id, handler, now)
                    license_id = lic["license_id"]
                if rule.get("creates_plan"):
                    self._plan_from_app(app)
            else:
                idx += 1
        elif action == "supplement":
            status = "supplement"
            mats = materials if materials is not None else app["materials"]
            missing = [m for m in rule["materials"] if m not in mats] or \
                ["办理部门指定的补正材料"]
            self.db.execute(
                "UPDATE bureau_apps SET materials=?, missing=? WHERE app_id=?",
                (_js(list(mats)), _js(missing), app_id))
        else:
            status = "rejected"
        self.db.execute(
            "UPDATE bureau_apps SET steps=?, status=?, current_step=?, license_id=?, "
            "updated_at=? WHERE app_id=?",
            (_js(steps), status, idx, license_id, now, app_id))
        self._log(handler, f"bureau:{action}", app_id,
                  {"matter": app["matter"], "step": step_def["action"], "opinion": opinion})
        return self.get_app(app_id)

    def _issue_license(self, app: dict, rule: dict, agency_id: str,
                       handler: str, now: str) -> dict:
        lic_id = f"LIC-{now[:10].replace('-', '')}-" + \
            self._ev("", {"app": app["app_id"], "now": now})[:6]
        valid_from = now
        valid_to = (self.clock.now() + timedelta(days=365 * int(rule.get("years") or 3))
                    ).isoformat()
        ev = self._ev("EV", {"lic": lic_id, "app": app["app_id"]})
        self.db.execute(
            "INSERT INTO bureau_licenses (license_id,license_type,name,holder_unit,"
            "agency_id,scenario,app_id,gun_codes,valid_from,valid_to,status,scope,"
            "evidence_no,source,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (lic_id, rule["license_type"], rule["license_name"], app["applicant_unit"],
             agency_id, app["scenario"], app["app_id"], _js(app["gun_codes"]),
             valid_from, valid_to, "active", rule["name"], ev, app["source"], now))
        self._log(handler, "bureau:issue_license", lic_id,
                  {"holder": app["applicant_unit"], "type": rule["license_type"]})
        return {"license_id": lic_id, "valid_from": valid_from, "valid_to": valid_to,
                "evidence_no": ev}

    # ---------------------------------------------------------------- 证照
    def licenses(self, holder_unit: str = "") -> list[dict]:
        sql = "SELECT * FROM bureau_licenses"
        params: tuple = ()
        if holder_unit:
            sql += " WHERE holder_unit=?"
            params = (holder_unit,)
        return [self._lic_view(r) for r in
                self.db.query(sql + " ORDER BY created_at DESC, rowid DESC", params)]

    def active_license(self, holder_unit: str, license_type: str) -> dict | None:
        now = self._now()
        for r in self.db.query(
                "SELECT * FROM bureau_licenses WHERE holder_unit=? AND license_type=? "
                "ORDER BY created_at DESC", (holder_unit, license_type)):
            if r["status"] == "active" and (r["valid_to"] or "") >= now:
                return self._lic_view(r)
        return None

    def require_license(self, holder_unit: str, license_type: str, purpose: str) -> dict:
        """前置条件：无有效证照则阻止后续业务。"""
        lic = self.active_license(holder_unit, license_type)
        if not lic:
            rule = next((r for r in APPROVAL_RULES.values()
                         if r.get("license_type") == license_type), None)
            need = rule["license_name"] if rule else license_type
            raise ValidationError(
                f"前置条件未满足：{purpose}需要有效《{need}》。"
                f"单位 {holder_unit} 当前无有效证照，请先在「协同审批」办理并等待核发。")
        return lic

    # ---------------------------------------------------------------- 计划
    def plans(self, unit_id: str = "") -> list[dict]:
        sql = "SELECT * FROM bureau_plans"
        params: tuple = ()
        if unit_id:
            sql += " WHERE unit_id=?"
            params = (unit_id,)
        rows = self.db.query(sql + " ORDER BY created_at DESC, rowid DESC", params)
        for r in rows:
            r["planned_qty"] = int(r["planned_qty"] or 0)
            r["gun_codes"] = _loads(r.get("gun_codes"), [])
        return rows

    def create_plan(self, *, plan_id: str, unit_id: str, batch_ref: str,
                    license_id: str = "", scenario: str = "", planned_qty: int = 0,
                    status: str = "approved", source: str = "real") -> dict:
        now = self._now()
        ev = self._ev("EV", {"plan": plan_id, "batch": batch_ref})
        self.db.execute(
            "INSERT INTO bureau_plans (plan_id,unit_id,license_id,scenario,batch_ref,"
            "planned_qty,status,evidence_no,source,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (plan_id, unit_id, license_id, scenario, batch_ref, int(planned_qty),
             status, ev, source, now))
        rows = [r for r in self.plans() if r["plan_id"] == plan_id]
        return rows[0]

    def _plan_from_app(self, app: dict) -> dict | None:
        """生产计划申请批准 → 自动生成可执行计划（批次与数量取自申请单）。"""
        plan_id = "PLAN-" + str(app["app_id"]).removeprefix("APP-")
        if self.db.one("SELECT plan_id FROM bureau_plans WHERE plan_id=?", (plan_id,)):
            return None  # 幂等：同一申请只生成一次
        batch = app.get("batch_ref") or ""
        if not batch:
            m = re.search(r"批次\s*([A-Za-z0-9\-]+)", app.get("title") or "")
            batch = m.group(1) if m else f"BATCH-{app['app_id']}"
        lic = self.active_license(app["applicant_unit"], "mfg_license")
        plan = self.create_plan(
            plan_id=plan_id, unit_id=app["applicant_unit"],
            license_id=lic["license_id"] if lic else "", scenario=app.get("scenario", ""),
            batch_ref=batch, planned_qty=int(app.get("planned_qty") or 0),
            source=app.get("source", "real"))
        self._log(app.get("applicant_unit") or "system", "bureau:plan_from_app",
                  plan_id, {"app": app["app_id"], "batch": batch,
                            "qty": plan["planned_qty"]})
        return plan

    def require_plan(self, unit_id: str, batch_ref: str = "") -> dict:
        """前置条件：制造赋码须有已批准的生产计划，批次备案且数量未用完。"""
        plans = [p for p in self.plans(unit_id) if p["status"] == "approved"]
        if not plans:
            raise ValidationError(
                f"前置条件未满足：制造赋码需要已批准的生产计划备案。"
                f"单位 {unit_id} 暂无已批准计划，请先在「协同审批」办理"
                "「生产计划与批次备案」并等待批准。")
        if batch_ref:
            matched = [p for p in plans if p["batch_ref"] == batch_ref]
            if not matched:
                raise ValidationError(
                    f"前置条件未满足：批次 {batch_ref} 未在已批准的生产计划中备案。"
                    f"可选批次：{'、'.join(p['batch_ref'] for p in plans)}")
            plans = matched
        usable = [p for p in plans
                  if len(p.get("gun_codes") or []) < int(p["planned_qty"] or 0)]
        if not usable:
            p = plans[0]
            raise ValidationError(
                f"前置条件未满足：计划批次 {p['batch_ref']} 数量已用完"
                f"（计划 {p['planned_qty']} 支，已赋码 "
                f"{len(p.get('gun_codes') or [])} 支）。")
        return usable[0]

    def consume_plan(self, plan_id: str, gun_code: str) -> dict:
        """赋码成功后把枪支记入计划批次，消耗计划数量。"""
        row = self.db.one("SELECT gun_codes FROM bureau_plans WHERE plan_id=?",
                          (plan_id,))
        if not row:
            raise NotFoundError(f"生产计划不存在: {plan_id}")
        codes = _loads(row["gun_codes"], [])
        if gun_code not in codes:
            codes.append(gun_code)
        self.db.execute(
            "UPDATE bureau_plans SET gun_codes=? WHERE plan_id=?",
            (_js(codes), plan_id))
        return self.get_plan(plan_id)

    def get_plan(self, plan_id: str) -> dict:
        row = self.db.one("SELECT * FROM bureau_plans WHERE plan_id=?", (plan_id,))
        if not row:
            raise NotFoundError(f"生产计划不存在: {plan_id}")
        out = self.plans()
        return next(p for p in out if p["plan_id"] == plan_id)

    # ---------------------------------------------------------------- 配售
    def _active_license_types(self, unit: str) -> set[str]:
        """单位当前有效的证照类型集合（配售登记的双方资质校验用）。"""
        now = self._now()
        return {r["license_type"] for r in self.db.query(
            "SELECT license_type, status, valid_to FROM bureau_licenses "
            "WHERE holder_unit=?", (unit,))
            if r["status"] == "active" and (r["valid_to"] or "") >= now}

    def create_sale(self, *, sale_id: str, seller_unit: str, buyer_unit: str,
                    gun_codes: list[str], scenario: str = "", license_id: str = "",
                    purchase_app_id: str = "", note: str = "", status: str = "delivered",
                    source: str = "real") -> dict:
        if not gun_codes:
            raise ValidationError("配售记录须关联至少一支枪支")
        if not seller_unit or not buyer_unit:
            raise ValidationError("配售记录须载明配售单位与配置单位")
        # 1) 双方单位必须真实存在
        for u in dict.fromkeys([seller_unit, buyer_unit]):
            if not self.db.one("SELECT unit_id FROM units WHERE unit_id=?", (u,)):
                raise NotFoundError(f"单位不存在: {u}")
        # 2) 枪支必须真实存在，且归属配售当事方（不能替第三方枪支登记配售）
        for c in dict.fromkeys(gun_codes):
            row = self.db.one("SELECT code, unit_id FROM guns WHERE code=?", (c,))
            if not row:
                raise NotFoundError(f"枪支不存在: {c}")
            if row["unit_id"] not in (seller_unit, buyer_unit):
                raise PermissionDenied(
                    f"枪支 {c} 归属 {row['unit_id']}，不在本次配售当事方"
                    f"（{seller_unit} / {buyer_unit}）范围内，无权登记配售")
        # 3) 双方资质：跨单位配售的配售方须持制造/配售许可证，
        #    配置方须持配置资质或配购证件；同单位场内登记须持有效证照。
        seller_types = self._active_license_types(seller_unit)
        buyer_types = self._active_license_types(buyer_unit)
        if seller_unit != buyer_unit:
            if not {"mfg_license", "sale_license"} & seller_types:
                raise ValidationError(
                    f"前置条件未满足：配售方 {seller_unit} 须持有效的"
                    "《民用枪支制造许可证》或《民用枪支配售许可证》，"
                    "请先在「协同审批」办理对应许可事项。")
            if not {"unit_qualification", "purchase_permit", "task_license"} & buyer_types:
                raise ValidationError(
                    f"前置条件未满足：配置方 {buyer_unit} 须持有效配置资质或"
                    "民用枪支配购证件，请先完成配购审批。")
        else:
            if not {"unit_qualification", "purchase_permit", "task_license",
                    "mfg_license", "sale_license"} & seller_types:
                raise ValidationError(
                    f"前置条件未满足：场内配售配购登记须持有效证照（{seller_unit}）。")
        # 4) 关联证照：必填、有效、由当事方持有、覆盖所配售枪支，
        #    且其签发来源（审批记录）状态须为已批准。
        if not license_id:
            raise ValidationError(
                "配售登记须关联有效证照（配售许可证 / 配置资质 / 配购证件），"
                "未提供证照的配售申请不予受理。")
        row = self.db.one("SELECT * FROM bureau_licenses WHERE license_id=?",
                          (license_id,))
        if not row:
            raise NotFoundError(f"证照不存在: {license_id}")
        lic = self._lic_view(row)
        now = self._now()
        if not (lic["status"] == "active" and (lic["valid_to"] or "") >= now):
            raise ValidationError(
                f"证照 {license_id}（{lic['name']}）已失效，"
                "不可作为配售登记依据。")
        if lic["holder_unit"] not in (seller_unit, buyer_unit):
            raise PermissionDenied(
                f"证照 {license_id} 持证单位 {lic['holder_unit']} 非本次配售当事方，"
                "不可引用。")
        if lic["gun_codes"] and not set(gun_codes) <= set(lic["gun_codes"]):
            raise ValidationError(
                f"证照 {license_id} 未覆盖本次配售枪支。"
                f"证照范围：{'、'.join(lic['gun_codes'])}")
        if lic["app_id"]:
            app_row = self.db.one("SELECT status FROM bureau_apps WHERE app_id=?",
                                  (lic["app_id"],))
            if app_row and app_row["status"] != "approved":
                raise ValidationError(
                    f"证照 {license_id} 对应的审批记录 {lic['app_id']} 状态为 "
                    f"{APP_STATUS_LABEL.get(app_row['status'], app_row['status'])}，"
                    "须已批准方可作为配售依据。")
        # 5) 关联配购审批（如有）：须为已批准的配购/配售申请且覆盖枪支
        if purchase_app_id:
            pa = self.db.one("SELECT * FROM bureau_apps WHERE app_id=?",
                             (purchase_app_id,))
            if not pa:
                raise NotFoundError(f"审批事项不存在: {purchase_app_id}")
            if pa["status"] != "approved":
                raise ValidationError(
                    f"配购审批 {purchase_app_id} 未完成（当前 "
                    f"{APP_STATUS_LABEL.get(pa['status'], pa['status'])}），"
                    "须批准后方可登记配售。")
            pa_guns = _loads(pa["gun_codes"], [])
            if pa_guns and not set(gun_codes) <= set(pa_guns):
                raise ValidationError(
                    f"配购审批 {purchase_app_id} 未覆盖本次配售枪支："
                    f"{'、'.join(pa_guns)}")
        now = self._now()
        ev = self._ev("EV", {"sale": sale_id, "guns": gun_codes})
        self.db.execute(
            "INSERT INTO bureau_sales (sale_id,scenario,seller_unit,buyer_unit,"
            "license_id,purchase_app_id,gun_codes,status,note,evidence_no,source,"
            "created_at,domain) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (sale_id, scenario, seller_unit, buyer_unit, license_id, purchase_app_id,
             _js(gun_codes), status, note, ev, source, now, seller_unit))
        self._log(seller_unit, "bureau:sale", sale_id, {"guns": len(gun_codes)})
        return self.get_sale(sale_id)

    def sales(self) -> list[dict]:
        rows = self.db.query("SELECT * FROM bureau_sales ORDER BY created_at DESC, rowid DESC")
        return [self._sale_view(r) for r in rows]

    def get_sale(self, sale_id: str) -> dict:
        row = self.db.one("SELECT * FROM bureau_sales WHERE sale_id=?", (sale_id,))
        if not row:
            raise NotFoundError(f"配售记录不存在: {sale_id}")
        return self._sale_view(row)

    def sales_of(self, gun_code: str) -> list[dict]:
        return [s for s in self.sales() if gun_code in s["gun_codes"]]

    def require_sale(self, gun_codes: list[str], purpose: str) -> None:
        """前置条件：配售配购到位（有配售登记）才允许运输/领用等后续业务。"""
        covered: set[str] = set()
        for s in self.sales():
            covered.update(s["gun_codes"])
        missing = [c for c in dict.fromkeys(gun_codes) if c not in covered]
        if missing:
            hint = []
            for c in missing:
                unit = self.db.one("SELECT unit_id FROM guns WHERE code=?", (c,))
                if unit:
                    pend = self.list_apps(applicant_unit=unit["unit_id"])
                    bad = [a for a in pend if a["status"] in ("pending", "supplement")]
                    if bad:
                        hint.append(f"{c}（{bad[0]['app_id']} {bad[0]['status_label']}）")
                    else:
                        hint.append(c)
            raise ValidationError(
                f"前置条件未满足：{purpose}须先完成配售配购登记。"
                f"未登记配售的枪支：{'、'.join(hint)}。"
                "请在「协同审批」完成配购事项并登记配售记录后再办理。")

    # ------------------------------------------------------------ 监督检查
    def create_inspection(self, *, agency_id: str, inspector: str, target_unit: str,
                          findings: list[str], deadline: str = "",
                          gun_codes: list[str] | None = None, insp_id: str | None = None,
                          source: str = "real") -> dict:
        if agency_id not in AGENCIES:
            raise ValidationError(f"未知检查部门: {agency_id}")
        if not findings:
            raise ValidationError("检查记录须载明问题清单")
        now = self._now()
        insp_id = insp_id or f"INSP-{now[:10].replace('-', '')}-" + \
            self._ev("", {"u": target_unit, "now": now, "f": findings})[:6]
        ev = self._ev("EV", {"insp": insp_id})
        self.db.execute(
            "INSERT INTO bureau_inspections (insp_id,agency_id,inspector,target_unit,"
            "gun_codes,findings,deadline,status,checked_at,evidence_no,source,domain) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (insp_id, agency_id, inspector, target_unit, _js(list(gun_codes or [])),
             _js(findings), deadline, "pending_fix", now, ev, source, target_unit))
        self._log(inspector, "bureau:inspect", insp_id, {"target": target_unit})
        return self.get_inspection(insp_id)

    def get_inspection(self, insp_id: str) -> dict:
        row = self.db.one("SELECT * FROM bureau_inspections WHERE insp_id=?", (insp_id,))
        if not row:
            raise NotFoundError(f"检查单不存在: {insp_id}")
        return self._insp_view(row)

    def inspections(self, target_unit: str = "") -> list[dict]:
        sql = "SELECT * FROM bureau_inspections"
        params: tuple = ()
        if target_unit:
            sql += " WHERE target_unit=?"
            params = (target_unit,)
        rows = self.db.query(sql + " ORDER BY checked_at DESC, rowid DESC", params)
        return [self._insp_view(r) for r in rows]

    def rectify(self, insp_id: str, *, note: str, actor_unit: str = "",
                actor: str = "") -> dict:
        insp = self.get_inspection(insp_id)
        if insp["status"] != "pending_fix":
            raise StateError(f"检查单 {insp_id} 当前 {insp['status_label']}，无需整改")
        if actor_unit and insp["target_unit"] != actor_unit:
            raise PermissionDenied(
                f"仅被检查单位 {insp['target_unit']} 可提交整改（当前 {actor_unit}）")
        if not note:
            raise ValidationError("整改反馈须载明整改措施")
        now = self._now()
        hist = _loads(insp.get("history"), [])
        hist.append({"type": "rectify", "round": sum(
            1 for h in hist if h.get("type") == "rectify") + 1,
            "note": note, "at": now, "actor": actor or actor_unit,
            "agency_id": insp["agency_id"]})
        self.db.execute(
            "UPDATE bureau_inspections SET status='recheck', fix_note=?, fix_at=?, "
            "history=? WHERE insp_id=?", (note, now, _js(hist), insp_id))
        self._log(actor or actor_unit, "bureau:rectify", insp_id,
                  {"round": hist[-1]["round"]})
        return self.get_inspection(insp_id)

    def recheck(self, insp_id: str, *, agency_id: str, inspector: str,
                result: str, passed: bool) -> dict:
        """复查须显式给出通过/不通过：不通过退回整改，多轮记录全部留痕。"""
        insp = self.get_inspection(insp_id)
        if insp["status"] != "recheck":
            raise StateError(f"检查单 {insp_id} 当前 {insp['status_label']}，不可复查")
        if insp["agency_id"] != agency_id:
            raise PermissionDenied(
                f"复查须由原检查部门 {AGENCIES[insp['agency_id']]['name']} 执行"
                f"（当前 {AGENCIES.get(agency_id, {}).get('name', agency_id)}）")
        if not result:
            raise ValidationError("复查须载明复查结论")
        if not isinstance(passed, bool):
            raise ValidationError("复查须给出显式的通过/不通过字段（passed）")
        now = self._now()
        hist = _loads(insp.get("history"), [])
        hist.append({"type": "recheck", "result": result, "passed": passed,
                     "at": now, "actor": inspector, "agency_id": agency_id})
        status = "closed" if passed else "pending_fix"
        self.db.execute(
            "UPDATE bureau_inspections SET status=?, recheck_result=?, "
            "recheck_at=?, history=? WHERE insp_id=?",
            (status, result, now, _js(hist), insp_id))
        self._log(inspector, "bureau:recheck", insp_id,
                  {"result": result, "passed": passed})
        return self.get_inspection(insp_id)

    # ------------------------------------------------------------ 场景映射
    def set_scenario(self, gun_code: str, scenario: str, info: dict | None = None,
                     source: str = "real") -> dict:
        if scenario not in SCENARIOS:
            raise ValidationError(f"未知业务场景: {scenario}")
        now = self._now()
        ev = self._ev("EV", {"gun": gun_code, "scen": scenario, "info": info})
        self.db.execute(
            "INSERT OR REPLACE INTO bureau_gun_scenarios "
            "(gun_code,scenario,info,evidence_no,source,created_at) VALUES (?,?,?,?,?,?)",
            (gun_code, scenario, _js(info or {}), ev, source, now))
        return {"gun_code": gun_code, "scenario": scenario, "info": info or {},
                "evidence_no": ev, "source": source}

    def scenario_of_gun(self, gun_code: str, unit_type: str = "") -> dict | None:
        row = self.db.one("SELECT * FROM bureau_gun_scenarios WHERE gun_code=?",
                          (gun_code,))
        if row:
            key = row["scenario"]
            meta = SCENARIOS.get(key, {"name": key, "fields": []})
            return {"key": key, "name": meta["name"], "fields": meta["fields"],
                    "info": _loads(row["info"], {}),
                    "evidence_no": row["evidence_no"], "source": row["source"]}
        for key, meta in SCENARIOS.items():
            if unit_type in meta["unit_types"]:
                return {"key": key, "name": meta["name"], "fields": meta["fields"],
                        "info": {}, "evidence_no": "", "source": "derived"}
        return None

    # ------------------------------------------------------------ 一枪一档
    def archive(self, gun_code: str, with_timeline: bool = True) -> dict:
        row = self.db.one("SELECT * FROM guns WHERE code=?", (gun_code,))
        if not row:
            raise NotFoundError(f"枪支不存在: {gun_code}")
        unit = self.repo.get_unit(row["unit_id"])
        identity = _loads(row.get("identity") or "{}", {})
        events = [e.to_dict() for e in self.repo.events_of(gun_code)]
        permits = self._permits_of(gun_code)
        sales = self.sales_of(gun_code)
        maker_unit = self._maker_unit(identity.get("maker", ""))
        unit_ids = [u for u in dict.fromkeys([row["unit_id"], maker_unit]) if u]
        # 一枪一档：逐枪直接关联的申请 + 赋码之前的企业级申请
        # （资质审批/计划备案按所属企业关联，不按枪支编号关联）
        apps = [a for a in self.list_apps()
                if gun_code in a["gun_codes"]
                or (a["applicant_unit"] in unit_ids
                    and a["category"] in ("资质审批", "计划备案"))]
        inspections = [i for i in self.inspections()
                       if i["target_unit"] == row["unit_id"] or gun_code in i["gun_codes"]]
        scen = self.scenario_of_gun(gun_code, unit.unit_type)
        lic_rows = list(self.licenses(row["unit_id"]))
        if maker_unit and maker_unit != row["unit_id"]:
            lic_rows += self.licenses(maker_unit)
        nodes = self._pipeline(row, unit, identity, events, permits, sales, apps,
                               inspections, lic_rows)
        out = {
            "gun_code": gun_code,
            "gun": {"code": gun_code, "unit_id": row["unit_id"], "unit_name": unit.name,
                    "unit_type": unit.unit_type, "status": row["status"],
                    "holder": row.get("holder") or "", "domain": row.get("domain") or "",
                    "identity": identity},
            "scenario": scen,
            "pipeline": nodes,
            "licenses": lic_rows,
            "applications": apps,
            "sales": sales,
            "transports": permits,
            "inspections": inspections,
            "border": [a for a in apps if a["category"] == "进出境"],
            "alerts": [a for a in self.repo.alerts() if a.get("gun_code") == gun_code],
        }
        if with_timeline:
            out["timeline"] = events
        return out

    def _permits_of(self, gun_code: str) -> list[dict]:
        out = []
        for r in self.db.query("SELECT * FROM permits ORDER BY rowid"):
            data = _loads(r["data"], {})
            if gun_code in (data.get("gun_codes") or []):
                data.update({"permit_id": r["permit_id"], "status": r["status"],
                             "domain": r["domain"]})
                out.append(data)
        return out

    def _maker_unit(self, maker_code: str) -> str | None:
        """整枪码企业代码 → 注册企业单位（演示企业名与单位名对应）。"""
        maker_name = next((n for n, c in MAKERS.items() if c == maker_code), "")
        if not maker_name:
            return None
        row = self.db.one("SELECT unit_id FROM units WHERE name LIKE ?",
                          (maker_name + "%",))
        return row["unit_id"] if row else None

    def _pipeline(self, gun_row, unit, identity, events, permits, sales, apps,
                  inspections, licenses) -> list[dict]:
        manu_unit = gun_row["unit_id"]
        maker_unit = self._maker_unit(identity.get("maker", ""))
        unit_ids = [u for u in dict.fromkeys([manu_unit, maker_unit]) if u]

        # 1. 企业资质与计划（企业级：赋码后关联到本枪，不随单枪重复审批）
        ent_lics = [l for l in licenses if l["holder_unit"] in unit_ids]
        ent_plans = [p for u in unit_ids for p in self.plans(u)]
        ent_apps = [a for a in apps
                    if a["applicant_unit"] in unit_ids
                    and a["category"] in ("资质审批", "计划备案", "配购配售")]
        now = self._now()
        ent_active = [l for l in ent_lics
                      if l["status"] == "active" and l["valid_to"] >= now]
        ent_rejected = [a for a in ent_apps if a["status"] == "rejected"]
        ent_note = "企业/批次级记录，赋码后关联到本枪，不随单枪重复审批"
        if ent_active:
            st = S_DONE
        elif any(a["status"] == "pending" for a in ent_apps):
            st = S_DOING
        elif any(a["status"] == "supplement" for a in ent_apps):
            st = S_SUPP
        elif any(a["status"] == "approved" for a in ent_apps) and ent_lics:
            # 曾批准但证照已全部失效：不算完成
            st, ent_note = S_TODO, ent_note + "；证照已失效，须重新申请核发"
        elif any(a["status"] == "approved" for a in ent_apps):
            st = S_DONE
        elif ent_rejected:
            st, ent_note = S_TODO, ent_note + \
                f"；存在已退回的申请（{ent_rejected[0]['app_id']}），须重新申报"
        else:
            st = S_TODO
        ent_records = [self._app_record(a) for a in ent_apps] + \
            [self._lic_record(l) for l in ent_lics] + \
            [self._plan_record(p) for p in ent_plans] + \
            [self._insp_record(i) for i in inspections]
        nodes = [self._node("enterprise", st, records=ent_records,
                            note=ent_note,
                            scope="企业级")]

        # 2. 制造赋码
        manu_events = [e for e in events if e.get("event_type") == "manufacture"]
        manu_records = [{
            "matter": "制造赋码（一枪一码）",
            "applicant": manu_unit, "agency": "属地公安机关（赋码备案）",
            "handler": (manu_events[0].get("actor") if manu_events else ""),
            "at": (manu_events[0].get("occurred_at") if manu_events else ""),
            "opinion": "整枪码 + 散件码两级标识登记，全生命周期不变",
            "license": f"整枪码 {gun_row['code']}",
            "attachments": (manu_events[0].get("payload") or {}).get("parts", [])
            if manu_events else [],
            "evidence_no": (manu_events[0].get("event_hash") or "")[:16],
            "source": "real",
            "status": S_DONE if manu_events else S_TODO,
            "steps": [],
        }] if manu_events else []
        nodes.append(self._node("manufacture",
                                S_DONE if manu_events else S_TODO,
                                records=manu_records,
                                note=f"制造企业代码 {identity.get('maker', '-')} · "
                                     f"旧枪号 {identity.get('legacy_no', '-')}"))

        # 3. 配购与配售
        sale_apps = [a for a in apps if a["category"] == "配购配售"]
        if sales:
            st = S_DONE
        elif any(a["status"] == "supplement" for a in sale_apps):
            st = S_SUPP
        elif any(a["status"] == "pending" for a in sale_apps):
            st = S_DOING
        elif sale_apps:
            st = S_DOING   # 配购已批准，待登记配售交付
        else:
            st = S_TODO
        sale_records = [self._app_record(a) for a in sale_apps] + \
            [self._sale_record(s) for s in sales]
        nodes.append(self._node("sale", st, records=sale_records,
                                note="" if sales else
                                "配售交付登记完成后方可办理运输与领用"))

        # 4. 运输交接（可能多次，每次单独关联许可与交接记录）
        trans_records = [self._permit_record(p, sales) for p in permits]
        if not permits:
            st = S_TODO
        elif all(p["status"] == "closed" for p in permits):
            st = S_DONE
        else:
            st = S_DOING
        nodes.append(self._node("transport", st, records=trans_records,
                                note=f"共 {len(permits)} 次运输，逐次关联许可与上下游业务"
                                     if permits else "尚未发生跨主体运输交接"))

        # 5. 持有使用（公安检查贯穿制造、配售、保管与使用）
        use_events = [e for e in events
                      if e.get("event_type") in ("checkout", "return", "repair")]
        use_records = [self._event_record(e) for e in use_events] + \
            [self._insp_record(i) for i in inspections]
        holder = gun_row.get("holder") or ""
        nodes.append(self._node("use", S_DONE if use_events else S_TODO,
                                records=use_records,
                                note=("当前持用人 " + holder) if holder else
                                ("尚未发生领用" if not use_events else "已归还在库")))

        # 6. 报废销毁（档案终点）
        scrap_events = [e for e in events if e.get("event_type") == "scrap"]
        done_stages = [(e.get("payload") or {}).get("stage")
                       for e in scrap_events]
        if gun_row["status"] in ("sealed", "destroyed"):
            st, note = S_DONE, "标识永久封存，档案终点已达成"
        elif gun_row["status"] == "pending_destroy" or scrap_events:
            st, note = S_DOING, f"已完成 {len(done_stages)}/7 节点"
        else:
            st, note = S_TODO, "在役，报废流程未启动"
        scrap_records = [self._event_record(e) for e in scrap_events]
        nodes.append(self._node("scrap", st, records=scrap_records, note=note))

        # 7. 进出境（条件分支：国内流转显示不适用）
        border_apps = [a for a in apps if a["category"] == "进出境"]
        if border_apps:
            st = (S_DONE if all(a["status"] == "approved" for a in border_apps)
                  else S_DOING if all(a["status"] in ("approved", "pending")
                                      for a in border_apps) else S_SUPP)
            note = "贸易进出口与人员携带进出境分别建项办理"
        else:
            st, note = S_NA, "国内流转，不涉及进出境"
        nodes.append(self._node("border", st,
                                records=[self._app_record(a) for a in border_apps],
                                note=note))
        return nodes

    # ----------------------------------------------------------- 记录组装
    @staticmethod
    def _node(key: str, status: str, records: list[dict] | None = None,
              note: str = "", scope: str = "枪支级") -> dict:
        return {"key": key, "name": PIPELINE_NAMES[key], "status": status,
                "scope": scope, "note": note, "records": records or []}

    @staticmethod
    def _rec(**kw) -> dict:
        base = {"matter": "", "applicant": "", "agency": "", "handler": "",
                "at": "", "opinion": "", "license": "", "attachments": [],
                "evidence_no": "", "source": "real", "status": S_TODO, "steps": []}
        base.update(kw)
        return base

    def _chain_view(self, app: dict) -> list[dict]:
        rule = APPROVAL_RULES.get(app["matter"])
        if not rule:
            return []
        steps = app.get("steps") or []
        # 按 step_index 对位：补正/驳回/重新批准会产生多条同节点记录，
        # 数组位置会错位（例如补正后公安节点显示成林草经办人）。
        latest: dict[int, dict] = {}
        approves: dict[int, dict] = {}
        for pos, rec in enumerate(steps):
            node = rec.get("step_index", pos)   # 兼容旧数据：无 step_index 按位置
            latest[node] = rec
            if rec.get("action_type") == "approve":
                approves[node] = rec
        out = []
        for i, sd in enumerate(rule["chain"]):
            done_rec = approves.get(i)
            act_rec = latest.get(i)
            if done_rec:
                status = S_DONE
            elif (app["status"] == "rejected" and act_rec
                  and act_rec.get("action_type") == "reject"):
                status = "退回"
            elif (app["status"] == "supplement" and act_rec
                  and act_rec.get("action_type") == "supplement"):
                status = S_SUPP
            elif i == app["current_step"] and app["status"] == "pending":
                status = S_DOING
            else:
                status = S_TODO
            rec = done_rec or act_rec
            out.append({
                "agency": sd["agency"], "agency_name": AGENCIES[sd["agency"]]["name"],
                "action": sd["action"],
                "handler": rec["handler"] if rec else "",
                "opinion": rec["opinion"] if rec else "",
                "at": rec["at"] if rec else "",
                "status": status,
            })
        return out

    def _app_record(self, app: dict) -> dict:
        rule = APPROVAL_RULES.get(app["matter"]) or {"name": app["matter"], "chain": []}
        chain = rule.get("chain") or []
        last = app["steps"][-1] if app["steps"] else None
        if app["status"] == "pending" and chain and app["current_step"] < len(chain):
            # 办理中：显示当前节点部门与"待办理"，
            # 不能显示上一节点经办人（否则补正后会错位成他部门人员）
            cur = chain[app["current_step"]]
            agency_name = AGENCIES[cur["agency"]]["name"]
            handler, at = "待办理", app["updated_at"]
            opinion = f"已受理，待 {agency_name} · {cur['action']}"
        elif last:
            agency_name = last["agency_name"]
            handler, at, opinion = last["handler"], last["at"], last["opinion"]
        else:
            agency_name = (AGENCIES[chain[-1]["agency"]]["name"] if chain else "")
            handler, at = "待办理", app["created_at"]
            opinion = ("材料缺失：" + "、".join(app["missing"])
                       if app["status"] == "supplement" else "已受理，等待办理")
        lic = None
        if app["license_id"]:
            lic = next((l for l in self.licenses() if l["license_id"] == app["license_id"]),
                       None)
        return self._rec(
            matter=f"{rule['name']}（{app['app_id']}）",
            applicant=app["applicant_unit"] + (
                f" · {app['applicant_person']}" if app["applicant_person"] else ""),
            agency=agency_name,
            handler=handler,
            at=at,
            opinion=opinion,
            license=(f"{lic['name']} {lic['license_id']}（{lic['valid_from'][:10]} ~ "
                     f"{lic['valid_to'][:10]}）" if lic else ""),
            attachments=app["materials"],
            evidence_no=app["evidence_no"], source=app["source"],
            status=app["status_label"], steps=self._chain_view(app))

    def _lic_record(self, lic: dict) -> dict:
        return self._rec(
            matter=f"证照 · {lic['name']}",
            applicant=lic["holder_unit"],
            agency=AGENCIES.get(lic["agency_id"], {}).get("name", lic["agency_id"]),
            handler="签发", at=lic["created_at"],
            opinion=f"适用对象：{lic['scope'] or '-'}",
            license=f"{lic['name']} {lic['license_id']}（{lic['valid_from'][:10]} ~ "
                    f"{lic['valid_to'][:10]} · {'有效' if lic['status'] == 'active' and lic['valid_to'] >= self._now() else '失效'}）",
            attachments=[], evidence_no=lic["evidence_no"], source=lic["source"],
            status=S_DONE if lic["status"] == "active" else "已失效")

    def _plan_record(self, plan: dict) -> dict:
        used = len(plan.get("gun_codes") or [])
        return self._rec(
            matter=f"生产/任务计划 · {plan['batch_ref']}",
            applicant=plan["unit_id"], agency="属地公安机关（备案）",
            handler="备案", at=plan["created_at"],
            opinion=f"计划数量 {plan['planned_qty']}，已赋码 {used}，"
                    f"状态 {plan['status']}",
            license="", attachments=[plan["batch_ref"]],
            evidence_no=plan["evidence_no"], source=plan["source"], status=S_DONE)

    def _sale_record(self, sale: dict) -> dict:
        lic = None
        if sale["license_id"]:
            lic = next((l for l in self.licenses() if l["license_id"] == sale["license_id"]),
                       None)
        return self._rec(
            matter=f"配售交付 · {sale['sale_id']}",
            applicant=f"{sale['seller_unit']} → {sale['buyer_unit']}",
            agency="属地公安机关（配售监管）",
            handler=sale["seller_unit"], at=sale["created_at"],
            opinion=sale["note"] or "配售配购登记完成",
            license=(f"{lic['name']} {lic['license_id']}" if lic else ""),
            attachments=sale["gun_codes"], evidence_no=sale["evidence_no"],
            source=sale["source"], status=S_DONE)

    def _permit_record(self, permit: dict, sales: list[dict]) -> dict:
        linked = [s["sale_id"] for s in sales
                  if set(permit.get("gun_codes") or []) & set(s["gun_codes"])]
        label = {"applied": S_DOING, "approved": S_DOING,
                 "in_transit": S_DOING, "closed": S_DONE}
        return self._rec(
            matter=f"运输许可 {permit['permit_id']}",
            applicant=permit.get("applicant", ""),
            agency="公安机关（运输审批）",
            handler=permit.get("carrier", ""), at=permit.get("valid_from", ""),
            opinion=f"{permit.get('origin', '')} → {permit.get('destination', '')}"
                    f" · 状态 {permit['status']}"
                    + (f" · 关联上游配售 {'、'.join(linked)}" if linked else ""),
            license=f"有效期 {str(permit.get('valid_from', ''))[:10]} ~ "
                    f"{str(permit.get('valid_end', ''))[:10]}",
            attachments=[permit.get("vehicle", ""), permit.get("carrier", ""),
                         permit.get("escort", "")],
            evidence_no=permit["permit_id"], source="real",
            status=label.get(permit["status"], S_DOING))

    def _event_record(self, ev: dict) -> dict:
        payload = ev.get("payload") or {}
        et = ev.get("event_type", "")
        names = {"manufacture": "制造赋码", "checkout": "领用", "return": "归还",
                 "repair": "维修", "transport": "运输交接", "permit": "运输审批",
                 "scrap": "报废销毁", "status_change": "状态变更", "alert": "预警",
                 "use": "使用"}
        detail = payload.get("stage") or payload.get("content") or \
            payload.get("holder") or payload.get("permit_id") or ""
        if detail and et == "scrap":
            detail = SCRAP_STAGE_NAMES.get(detail, detail)
        return self._rec(
            matter=(names.get(et, et) + (f" · {detail}" if detail else "")),
            applicant=payload.get("unit", ""), agency="链上存证",
            handler=ev.get("actor", ""), at=ev.get("occurred_at", ""),
            opinion=payload.get("reason") or payload.get("appraisal")
            or payload.get("message") or "事件已上链存证",
            license="", attachments=payload.get("signers", []) or [],
            evidence_no=(ev.get("event_hash") or "")[:16], source="real",
            status=S_DONE)

    def _insp_record(self, insp: dict) -> dict:
        hist = insp.get("history") or []
        fails = [h for h in hist if h.get("type") == "recheck" and not h.get("passed")]
        rounds = insp.get("rounds") or sum(
            1 for h in hist if h.get("type") == "rectify")
        extra = ""
        if rounds > 1:
            extra += f"（累计整改 {rounds} 轮）"
        if fails:
            extra += f"（历史复查不合格 {len(fails)} 次）"
        return self._rec(
            matter=f"监督检查 {insp['insp_id']}",
            applicant=insp["target_unit"],
            agency=AGENCIES.get(insp["agency_id"], {}).get("name", insp["agency_id"]),
            handler=insp["inspector"], at=insp["checked_at"],
            opinion="；".join(insp["findings"])
            + (f"（整改：{insp['fix_note']}）" if insp["fix_note"] else "")
            + (f"（复查：{insp['recheck_result']}）" if insp["recheck_result"] else "")
            + extra,
            license=f"整改期限 {str(insp['deadline'] or '')[:10]}",
            attachments=insp["findings"], evidence_no=insp["evidence_no"],
            source=insp["source"], status=INSP_STATUS_LABEL[insp["status"]])

    # ------------------------------------------------------------ 视图解码
    def _app_view(self, row: dict) -> dict:
        d = dict(row)
        d["gun_codes"] = _loads(d.get("gun_codes"), [])
        d["materials"] = _loads(d.get("materials"), [])
        d["missing"] = _loads(d.get("missing"), [])
        d["steps"] = _loads(d.get("steps"), [])
        d["status_label"] = APP_STATUS_LABEL.get(d["status"], d["status"])
        rule = APPROVAL_RULES.get(d["matter"], {})
        d["matter_name"] = rule.get("name", d["matter"])
        d["category"] = rule.get("category", d.get("category", ""))
        d["mode"] = rule.get("mode", "")
        chain = rule.get("chain", [])
        if d["status"] == "pending" and d["current_step"] < len(chain):
            cur = chain[d["current_step"]]
            d["current_agency"] = cur["agency"]
            d["current_agency_name"] = AGENCIES[cur["agency"]]["name"]
            d["current_action"] = cur["action"]
        else:
            last = d["steps"][-1] if d["steps"] else None
            d["current_agency"] = last["agency"] if last else ""
            d["current_agency_name"] = last["agency_name"] if last else ""
            d["current_action"] = last["action"] if last else ""
        lic = None
        if d["license_id"]:
            lic = next((l for l in self.licenses() if l["license_id"] == d["license_id"]),
                       None)
        d["license"] = lic
        d["rule_materials"] = rule.get("materials", [])
        d["legal"] = rule.get("legal", "")
        # 链视图由后端按 step_index 计算，前端按此渲染（不按 steps 数组位置）
        d["chain"] = self._chain_view(d)
        return d

    @staticmethod
    def _lic_view(row: dict) -> dict:
        d = dict(row)
        d["gun_codes"] = _loads(d.get("gun_codes"), [])
        return d

    def _sale_view(self, row: dict) -> dict:
        d = dict(row)
        d["gun_codes"] = _loads(d.get("gun_codes"), [])
        return d

    @staticmethod
    def _insp_view(row: dict) -> dict:
        d = dict(row)
        d["gun_codes"] = _loads(d.get("gun_codes"), [])
        d["findings"] = _loads(d.get("findings"), [])
        d["history"] = _loads(d.get("history"), [])
        d["rounds"] = sum(1 for h in d["history"] if h.get("type") == "rectify")
        d["status_label"] = INSP_STATUS_LABEL.get(d["status"], d["status"])
        d["agency_name"] = AGENCIES.get(d["agency_id"], {}).get("name", d["agency_id"])
        return d

    # ------------------------------------------------------------ 全局总览
    def lifecycle_overview(self) -> dict:
        guns = self.db.query("SELECT code, unit_id, status FROM guns ORDER BY rowid")
        stage_counts: dict[str, dict[str, int]] = {k: {} for k in PIPELINE_KEYS}
        scen_cards: dict[str, dict] = {k: {"key": k, "name": v["name"], "guns": 0,
                                           "representative": ""}
                                       for k, v in SCENARIOS.items()}
        unassigned = 0
        for g in guns:
            unit = self.repo.get_unit(g["unit_id"])
            scen = self.scenario_of_gun(g["code"], unit.unit_type)
            if scen:
                card = scen_cards.setdefault(scen["key"],
                                             {"key": scen["key"], "name": scen["name"],
                                              "guns": 0, "representative": ""})
                card["guns"] += 1
                card["representative"] = card["representative"] or g["code"]
            else:
                unassigned += 1
            nodes = self.archive(g["code"], with_timeline=False)["pipeline"]
            for n in nodes:
                stage_counts[n["key"]][n["status"]] = \
                    stage_counts[n["key"]].get(n["status"], 0) + 1
        apps = self.list_apps()
        app_by_status: dict[str, int] = {}
        for a in apps:
            app_by_status[a["status_label"]] = app_by_status.get(a["status_label"], 0) + 1
        pending = [a for a in apps if a["status"] in ("pending", "supplement")]
        insp = self.inspections()
        insp_by_status: dict[str, int] = {}
        for i in insp:
            insp_by_status[i["status_label"]] = insp_by_status.get(i["status_label"], 0) + 1
        border_by_mode = {}
        for a in apps:
            if a["category"] == "进出境":
                m = a["mode"] or a["matter"]
                border_by_mode[m] = border_by_mode.get(m, 0) + 1
        return {
            "stages": [{"key": k, "name": PIPELINE_NAMES[k], "counts": stage_counts[k]}
                       for k in PIPELINE_KEYS],
            "scenarios": [scen_cards[k] for k in SCENARIOS],
            "unassigned_guns": unassigned,
            "gun_total": len(guns),
            "apps_total": len(apps),
            "apps_by_status": app_by_status,
            "pending_apps": pending,
            "inspections_total": len(insp),
            "inspections_by_status": insp_by_status,
            "licenses_active": sum(
                1 for l in self.licenses()
                if l["status"] == "active" and l["valid_to"] >= self._now()),
            "sales_total": len(self.sales()),
            "border_by_mode": border_by_mode,
        }


SCRAP_STAGE_NAMES = {"apply": "申请", "appraise": "鉴定", "province_confirm": "省级确认",
                     "destroy_submit": "送交", "destroy_inventory": "清点",
                     "destroy_execute": "销毁", "destroy_archive": "影像留存·封存"}


def _js(v) -> str:
    return json.dumps(v, ensure_ascii=False)
