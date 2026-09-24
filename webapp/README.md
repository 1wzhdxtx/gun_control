# 民用枪支全链条智慧监管 · 网页演示层

四个角色工作台的 FastAPI 演示版，复用 `gunreg` 后端（制造→领用→运输→报废→预警→链上追溯），
内置模拟数据（首次启动或显式设置 `GUNREG_RESET=1` 时重建），按设计文档四工作台矩阵展开：
**监管（全量/审批/取证）· 单位（领用归还/申报/制造）· 从业人员（档案/资格）· 审计（账本/审计/对账）**。

## 启动

```bash
uv run uvicorn webapp.main:app --host 127.0.0.1 --port 8000
```

打开 http://127.0.0.1:8000/login.html

> 使用单进程 uvicorn。默认数据目录为 `webapp/data/`，可通过 `GUNREG_DATA_DIR` 指定独立目录。`GUNREG_RESET=1` 会清空该目录，请只对可丢弃的演示数据使用。当前链账本、审计、密钥仍在内存中，重启不会恢复这些内容；因此重启后不要执行派生视图重建，详见根目录 `CODE_REVIEW.md`。

## 前端与隔离验证

共享样式由 `common.css` 和 `theme.css` 组成，适配桌面及手机；页面交互使用 `common.js`。
以下浏览器检查会自动启动随机本地端口并使用临时数据，结束后关闭服务；无需运行或重置现有演示服务。

```bash
uv run pytest -q -p no:cacheprovider
uv run python smoke/review_ui.py
uv run python smoke/review_ui.py page_render
uv run python smoke/review_ui.py ui_tabs
uv run python smoke/review_ui.py e2e_api
uv run python smoke/review_ui.py admin_flows
uv run python smoke/review_ui.py login_ui
uv run python smoke/review_ui.py xss_check
uv run python smoke/review_backend.py
```

`review_backend.py` 输出待修复问题的诊断观测，不是验收通过测试。视觉检查截图保存到 `artifacts/review/`。pytest 在收集测试之前将 `GUNREG_DATA_DIR` 指向临时目录。

## 演示账号

| 角色 | 账号 | 口令 | 说明 |
| --- | --- | --- | --- |
| 监管 | admin1 | admin123 | 治安支队（全量·审批·取证）+ 演示时钟推进 |
| 审计 | audit1 | audit123 | 督察审计（只读全量·链上核验） |
| 单位 | unit-mfg / unit-rng / unit-spt | unit123 | 制造基地·射击场·运动学校 |
| 从业人员 | rng-wang / spt-liu | user123 | 射击场 / 学校用枪人 |

登录页一键登录（自动取 TOTP 动态口令，令牌 HttpOnly Cookie）。
签名人 rng-zhang / rng-li / spt-chen / spt-zhao 已注册 IAM（作为领用/归还/报废的双人签名人）。

## 种子数据（启动时即就绪）

- 21 支枪入账（制造赋码一枪一码）、链上 34 区块
- **三级预警阶梯**（射击场，时限合约 hint≤12h / concern≤24h / emergency>24h，due=8h）：
  枪R1 t=0 领用 → 超时 42h（紧急）· 枪R2 t=18h 领用 → 超时 24h（关注）· 枪R3 t=40h 领用 → 超时 2h（提示）；t=50h 已扫描建警
- 运输许可：**PERMIT-A 已申请待批**（监管台审批）、**PERMIT-B 已批准在途**（监管台核销）
- 报废：一支枪停在「申请+鉴定」待批准销毁（监管台走 省级确认→送交→清点→销毁→影像留存·封存 五节点）
- 运动学校一支枪正常领用中（时限演示对照）

## 推荐演示路径

1. **监管**：总览看预警态势 → 推进时钟(+6/24/72h) → 预警中心「扫描超期」→「升级未响应预警」→ 处置闭环；
   运输监管审批 PERMIT-A / 核销 PERMIT-B；报废监督走完五节点；一链查证验单枪证据链。
2. **单位**：射击场台账 → 领用/归还（双人签名=保管+监督，服务端验签）；
   > 注意：三级阶梯的持枪人名下都有超期枪，会被时限合约正确阻断新领用——先归还名下超期枪，或在「人员与设备」新增一名无欠账的持枪人再领用（这正是"超期未还阻断流转"的合规演示）。
   - 运输申报成功后，回监管台审批、单位「运输申报」起运。
3. **从业人员**：查名下枪支/事件；资格续期/暂停（暂停资格会触发紧急预警并阻断名下枪支流转）。
4. **审计**：审计日志全文检索 + 校验审计链完整性；链上账本区块明细 + 账本校验；单枪证据核验（领域哈希链/链上覆盖/交易比对/规则版本）；派生视图重建；Outbox 泵送与对账。

## 冒烟测试

```bash
uv run pytest tests -q                        # 后端单元测试（52 passed）
uv run python smoke/e2e_api.py                # API 全链路（需先重启服务拿干净种子）
uv run python smoke/page_render.py            # 四工作台渲染 + 截图
uv run python smoke/ui_tabs.py                # Tab 切换 + 关键按钮联动
uv run python smoke/admin_flows.py            # 运输核销 + 报废五节点闭环
```

> 烟雾脚本会改写服务端状态（审批/领用/推进时钟），跑前请重启 uvicorn。
