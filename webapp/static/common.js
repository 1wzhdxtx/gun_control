/* 工作台公共库：API、渲染、控件。 */

const $ = (id) => document.getElementById(id);

/* ---------------- XSS 转义 ---------------- */
function esc(v) {
  return String(v ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}
/* 将「用户数据 → 显式 HTML」收敛为同一契约：
 * 返回 { __html } 的对象才允许 innerHTML 渲染，且调用方必须用 esc() 转义拼接值；
 * 返回普通字符串的一律按 textContent 渲染（默认安全）。
 */

async function api(path, body) {
  const opt = { method: body === undefined ? "GET" : "POST", headers: {} };
  if (body !== undefined) {
    opt.headers["Content-Type"] = "application/json";
    opt.body = JSON.stringify(body);
  }
  const resp = await fetch(path, opt);
  let data = null;
  try { data = await resp.json(); } catch (e) { /* ignore */ }
  if (!resp.ok || !data || data.ok === false) {
    const msg = (data && data.detail) ? data.detail : ("请求失败 " + resp.status);
    throw new ApiError(msg, data || {});
  }
  return data;
}

class ApiError extends Error {
  constructor(message, meta) { super(message); this.meta = meta || {}; }
}

/* ---------------- 提示 ---------------- */
function notify(title, body, kind) {
  let wrap = $("toast-wrap");
  if (!wrap) { wrap = document.createElement("div"); wrap.id = "toast-wrap"; document.body.appendChild(wrap); }
  const t = document.createElement("div");
  t.className = "toast " + (kind || "ok");
  t.innerHTML = `<div class="t-title"></div><div class="t-body"></div>`;
  t.querySelector(".t-title").textContent = title;
  t.querySelector(".t-body").textContent = body || "";
  wrap.appendChild(t);
  setTimeout(() => t.remove(), kind === "err" ? 6000 : 4000);
}
const ok = (m, b) => notify(m, b, "ok");
const err = (m, b) => notify(m, b, "err");

/* ---------------- 状态与徽章 ---------------- */
const GUN_STATUS = {
  in_stock: "在库", in_use: "领用中", in_transit: "在途",
  repairing: "维修中", pending_destroy: "待销毁", destroyed: "已销毁", sealed: "已封存",
};
const ALERT_LEVEL = { hint: "提示", concern: "关注", emergency: "紧急" };
const ALERT_STATUS = { open: "待处置", responded: "已响应", closed: "已闭环" };
const PERMIT_STATUS = { applied: "已申请", approved: "已批准", in_transit: "运输中", closed: "已核销" };
const EVENT_TYPE = {
  manufacture: "制造赋码", checkout: "领用", return: "归还", transport: "携运",
  repair: "维修", scrap: "报废", permit: "许可", alert: "预警",
  status_change: "状态变更", use: "使用", transfer: "配售交接",
};
const UNIT_TYPE = {
  manufacture: "制造企业", distributor: "配售企业", shooting_range: "营业性射击场",
  sports_school: "射击运动学校", hunter: "猎民", police: "公安机关",
};

function badge(text, cls) {
  const c = cls ? "b-" + esc(cls) : "b-in_stock";
  return { __html: `<span class="badge ${c}">${esc(text)}</span>` };
}
function gunBadge(st) { return badge(GUN_STATUS[st] || st, st); }
function alertBadge(lv) { return badge(ALERT_LEVEL[lv] || lv, lv); }
function alertStBadge(st) { return badge(ALERT_STATUS[st] || st, st === "open" ? "open" : st === "responded" ? "responded" : "closed"); }
function permitBadge(st) { return badge(PERMIT_STATUS[st] || st, st === "closed" ? "closed" : st === "approved" ? "approved" : "applied"); }
function evBadge(t) { return { __html: `<span class="badge b-in_transit">${esc(EVENT_TYPE[t] || t)}</span>` }; }
function mono(v) { return { __html: `<span class="mono">${esc(v)}</span>` }; }
function monoTitle(v) { return { __html: `<span class="mono" title="${esc(v)}">${esc(shortHash(v))}</span>` }; }

function fmtTime(iso) {
  if (!iso) return "-";
  const d = new Date(iso);
  if (isNaN(d)) return iso;
  const p = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}
function shortHash(h) { return h ? h.slice(0, 12) + "…" : "-"; }

/* ---------------- DOM 构造 ---------------- */
function el(tag, attrs, ...children) {
  const node = document.createElement(tag);
  if (attrs) { for (const k in attrs) { if (k === "class") node.className = attrs[k]; else node.setAttribute(k, attrs[k]); } }
  for (const c of children.flat(Infinity)) {
    if (c === null || c === undefined) continue;
    node.append(c.nodeType ? c : document.createTextNode(c));
  }
  return node;
}

function renderTable(container, columns, rows, emptyText) {
  container.innerHTML = "";
  if (!rows || rows.length === 0) {
    container.appendChild(el("div", { class: "empty" }, emptyText || "暂无数据"));
    return;
  }
  const table = el("table");
  const thead = el("thead");
  const tr = el("tr");
  for (const col of columns) tr.appendChild(el("th", {}, col.label));
  thead.appendChild(tr);
  table.appendChild(thead);
  const tbody = el("tbody");
  for (const row of rows) {
    const r = el("tr", row.link ? { class: "rowlink" } : {});
    for (const col of columns) {
      const cell = el("td");
      const v = row[col.key];
      let out = v;
      if (col.fmt) out = col.fmt(v, row);
      if (out && typeof out === "object" && out.__html !== undefined) {
        // 显式 HTML 契约：调用方负责用 esc() 转义拼接的用户数据
        cell.innerHTML = out.__html;
      } else {
        // 默认文本渲染（自动转义，杜绝存储型 XSS）
        cell.textContent = (out === null || out === undefined) ? "-" : String(out);
      }
      r.appendChild(cell);
    }
    if (row.link) {
      r.tabIndex = 0;
      r.setAttribute("aria-label", "查看 " + (row.gun_code || "记录") + " 详情");
      r.addEventListener("click", row.link);
      r.addEventListener("keydown", e => {
        if (e.target === r && (e.key === "Enter" || e.key === " ")) { e.preventDefault(); row.link(); }
      });
    }
    tbody.appendChild(r);
  }
  table.appendChild(tbody);
  const scroll = el("div", { class: "table-scroll", tabindex: "0", role: "region", "aria-label": "数据表格，可横向滚动" }, table);
  container.appendChild(scroll);
}

function pane(title, desc) {
  const section = el("section", { class: "pane" });
  section.dataset.title = title;
  section.dataset.description = desc || "";
  section.appendChild(el("div", { class: "pane-title" }, title));
  if (desc) section.appendChild(el("div", { class: "pane-desc" }, desc));
  return section;
}

function field(labelText, inputEl) {
  const f = el("div", { class: "field" });
  if (!inputEl.id) inputEl.id = "field-" + (++field.counter);
  f.appendChild(el("label", { for: inputEl.id }, labelText));
  f.appendChild(inputEl);
  return f;
}
field.counter = 0;

function selectEl(options, selected) {
  const sel = document.createElement("select");
  for (const [v, t] of options) {
    const o = document.createElement("option");
    o.value = v; o.textContent = t;
    if (selected !== undefined && String(v) === String(selected)) o.selected = true;
    sel.appendChild(o);
  }
  return sel;
}

function inputEl(value, placeholder, type) {
  const inp = document.createElement("input");
  inp.value = value || "";
  if (placeholder) inp.placeholder = placeholder;
  if (type) inp.type = type;
  return inp;
}

function btnEl(text, onClick, cls) {
  const b = document.createElement("button");
  b.textContent = text;
  if (cls) b.className = cls;
  b.addEventListener("click", onClick);
  return b;
}

/* ---------------- 工作台骨架 ---------------- */
const S = { me: null, tabs: {}, navItems: [] };

const ICONS = {
  overview: "M3 3h7v7H3z M14 3h7v7h-7z M3 14h7v7H3z M14 14h7v7h-7z",
  guns: "M4 4h16v16H4z M8 8h8 M8 12h8 M8 16h5",
  permits: "M3 6h12v12H3z M15 10h4l3 4v4h-7 M6 18v2 M18 18v2",
  scrap: "M4 7h16 M9 7V4h6v3 M6 7l1 14h10l1-14 M10 11v6 M14 11v6",
  alerts: "M12 3L2 21h20L12 3z M12 9v5 M12 17v1",
  evidence: "M10 3a7 7 0 1 0 0 14a7 7 0 0 0 0-14 M15 15l6 6 M7 10l2 2l4-4",
  people: "M9 3a4 4 0 1 0 0 8a4 4 0 0 0 0-8 M2 21v-3a7 7 0 0 1 14 0v3 M17 4a4 4 0 0 1 0 8 M19 16a5 5 0 0 1 3 5",
  check: "M3 7h16 M15 3l4 4l-4 4 M21 17H5 M9 13l-4 4l4 4",
  repair: "M14 4l-3 3l3 3l3-3 M17 3a6 6 0 0 1-7 9L3 19l2 2l7-7a6 6 0 0 0 9-7",
  profile: "M12 3a4 4 0 1 0 0 8a4 4 0 0 0 0-8 M4 21v-2a8 8 0 0 1 16 0v2",
  ledger: "M4 3h16v18H4z M8 7h8 M8 12h8 M8 17h5",
};
function icon(name) {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  for (const [k, v] of Object.entries({ viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", "stroke-width": "1.6", "stroke-linecap": "round", "stroke-linejoin": "round", "aria-hidden": "true" })) svg.setAttribute(k, v);
  const path = document.createElementNS(svg.namespaceURI, "path");
  path.setAttribute("d", ICONS[name] || ICONS.ledger);
  svg.appendChild(path);
  return svg;
}

async function loadMe() {
  let m;
  try { m = await api("/api/me"); } catch (e) {
    window.location.href = "/login.html"; return null;
  }
  if (!m.ok) { window.location.href = "/login.html"; return null; }
  S.me = m;
  return m;
}

function renderShell(tabDefs, titleTs) {
  const me = S.me;
  const app = el("div", { id: "app" });

  // 侧栏
  const sb = el("div", { id: "sidebar" });
  sb.appendChild(el("div", { class: "brand" },
    el("div", { class: "logo" }, "盾"),
    el("div", {},
      el("div", { class: "t1" }, "民用枪支全链条监管"),
      el("div", { class: "t2" }, "区块链智慧监管演示台"))));
  sb.appendChild(el("div", { class: "nav-label" }, "工作空间 / WORKSPACE"));
  const nav = el("nav", { "aria-label": "工作台导航" });
  for (const t of tabDefs) {
    const item = el("button", { class: "nav-item", type: "button", "aria-controls": "pane-" + t.id }, icon(t.id === "transport" ? "permits" : t.id), t.title);
    t.pane.id = "pane-" + t.id;
    item.addEventListener("click", () => switchTab(t.id));
    t._item = item; nav.appendChild(item);
    S.tabs[t.id] = t;
  }
  sb.appendChild(nav);
  const roleName = { admin: "监管工作台", unit: "单位工作台", practitioner: "从业人员端", auditor: "审计工作台" }[me.user.role] || me.user.role;
  sb.appendChild(el("div", { class: "side-foot" },
    el("div", {}, titleTs || "全链条：制造 → 领用 → 运输 → 报废 → 预警"),
    el("div", { class: "side-status" }, "全生命周期 · 可追溯")));
  app.appendChild(sb);

  // 主区
  const main = el("main", { id: "main" });
  const top = el("div", { id: "topbar" });
  top.appendChild(el("div", {}, el("div", { class: "userbox" },
    el("div", { class: "avatar" }, me.user.name[0]),
    el("div", {},
      el("div", { class: "uname" }, me.user.name + "（" + roleName + "）"),
      el("div", { class: "urole" }, me.user.id + " · " + me.user.org)))));
  const clockChip = el("div", { class: "clock-chip" }, "时间 " + fmtTime(me.clock));
  const t = el("button", { class: "sm" }, "退出登录");
  t.addEventListener("click", async () => { await api("/api/logout", {}); window.location.href = "/login.html"; });
  top.appendChild(el("div", { class: "userbox" }, clockChip, t));
  main.appendChild(top);
  const heading = el("header", { class: "page-heading" },
    el("div", {}, el("div", { class: "eyebrow" }, "智慧监管平台 / " + roleName),
      el("h1", { id: "page-title" }), el("p", { id: "page-description" })),
    el("span", { class: "workspace-tag" }, "全链条监管"));
  main.appendChild(heading);
  for (const t of tabDefs) main.appendChild(t.pane);

  app.appendChild(main);
  document.getElementById("root").appendChild(app);
  S.liveClock = clockChip;
  window.setInterval(async () => {
    try { const m = await api("/api/me"); clockChip.textContent = "时间 " + fmtTime(m.clock); } catch (e) {}
  }, 15000);
}

async function switchTab(id) {
  if (!S.tabs[id]) return;
  S.tabs[id]._item.classList.add("active");
  for (const k in S.tabs) {
    const item = S.tabs[k]._item;
    item.classList.toggle("active", k === id);
    if (k === id) item.setAttribute("aria-current", "page"); else item.removeAttribute("aria-current");
  }
  for (const k in S.tabs) { S.tabs[k].pane.classList.remove("active"); }
  const tab = S.tabs[id];
  tab.pane.classList.add("active");
  $("page-title").textContent = tab.pane.dataset.title || tab.title;
  $("page-description").textContent = tab.pane.dataset.description || "";
  tab.pane.setAttribute("aria-busy", "true");
  try { if (tab.load) await tab.load(); }
  catch (e) { err("页面加载失败", e.message); }
  finally { tab.pane.setAttribute("aria-busy", "false"); }
}

function findGun(code) {
  for (const k in GUN_STATUS) if (k === code) return true;
  return false;
}

/* ---------------- 跨部门协同 / 一枪一档 ---------------- */
const PIPELINE_ST = {
  "已完成": "approved", "办理中": "applied", "待办理": "in_use",
  "退回补正": "emergency", "退回": "emergency", "不适用": "closed",
  "已失效": "closed",
};
function stageBadge(st) { return badge(st, PIPELINE_ST[st] || "in_stock"); }
/* 状态徽章 + 数量：如「已完成 25」 */
function stageCountBadge(st, n) {
  return { __html: stageBadge(st).__html.replace("</span>", " " + n + "</span>") };
}
const SOURCE_LABEL = { real: "真实业务记录", demo: "演示记录", derived: "按单位类型推导" };
function sourceBadge(src) {
  return badge(SOURCE_LABEL[src] || src,
    src === "real" ? "approved" : src === "demo" ? "applied" : "closed");
}
function archiveHref(code) { return "/archive.html?code=" + encodeURIComponent(code); }
function archiveLink(code) {
  return { __html: `<a class="inline-link" href="${archiveHref(code)}">一枪一档</a>` };
}
/* 角色 → 个人工作台（档案页返回入口） */
const ROLE_HOME = {
  admin: "/admin.html", unit: "/unit.html",
  practitioner: "/practitioner.html", auditor: "/audit.html",
};

function makeTimelineTable(containerId, rows) {
  const holder = document.createElement("div");
  renderTable(holder, [
    { key: "event_type", label: "事件", fmt: (v) => evBadge(v) },
    { key: "occurred_at", label: "发生时间", fmt: (v) => fmtTime(v) },
    { key: "actor", label: "操作主体" },
    { key: "device_id", label: "采集设备", fmt: (v) => mono(v) },
    { key: "event_hash", label: "事件哈希", fmt: (v) => monoTitle(v) },
  ], rows, "该枪支尚无事件");
  const box = document.getElementById(containerId);
  box.innerHTML = "";
  box.appendChild(holder.firstChild || el("div", { class: "empty" }, "该枪支尚无事件"));
}
