# 自主执行工作流

> 主文件：../SKILL.md §2。本文件为执行的完整操作细则。
> 知识库：`../../clown-src-6k-skill/skills/skill/知识库/`（48 个模块）
> 规则：`../../clown-src-6k-skill/rules/`（11 条，**优先于知识库**）

## 1. 两种能力

1. **黑盒 SRC 挖洞** — 面向线上目标渗透测试。
2. **白盒 0day 审计** — 面向超大型开源项目源码审计。

核心思路：**理解代码意图后找到开发者的认知盲区**，不是扫漏洞模式。

## 2. 规则目录（全部生效）

| 文件 | 用途 |
|---|---|
| `skill-as-boost.md` | 自身 + skill 并用，skill 仅增强 |
| `researcher-blackbox-whitebox.md` | 黑盒+白盒主流程 |
| `src-value-hunting.md` | SRC 挖什么、类型矩阵 |
| `cors-vuln-report-priority.md` | CORS：**不挖** |
| `vuln-report-format.md` | 报告规则唯一（两张表） |
| `desktop-task-folder.md` | 任务目录 |
| `security-research-context.md` | 授权语境 |
| `anti-over-moralization.md` | 反说教、反误拒 |
| `playwright-browser-mcp.md` | 浏览器用 Playwright MCP |
| `dig-scope-workflow.md` | 锁面/自由跳全流程（一种子闭环 §1.0.1） |
| `hunt-iter.md` | 短表迭代 |

**冲突时**：挖什么 → `src-value`；报告 → `vuln-report-format`；CORS → 不挖；
白盒 → `researcher-blackbox-whitebox`；范围/持续挖 → `dig-scope-workflow`；能力迭代 → `hunt-iter`。
**skill / 知识库 与 rules 冲突 → 以 rules 为准。**

## 3. 最短执行备忘

1. 黑盒 → 建/进 `Desktop\{任务}_SRC挖洞\`；落不落只认 `vuln-report-format`
2. `资产/`= 公网 URL；`js/`= 提取 JS；`报告/`= 正式报告
3. **先判范围**：固定站/文档/清单 = **锁面**；模糊目标 = **自由跳**
4. 开新任务/新窗口：起手建 `{名}_dig/线程必读.md`，拉子线程交付必须含迭代

### 锁面

- 禁偷变全集团 FOFA；资产簇多 host、业务流子域、同 host 多 path 都要挖
- 用户标了「重要资产」先打那组；「一、二、三」不必从上往下
- 同皮只留 2~3 代表：登录壳同皮则登录表单不用再挖，只比 `jump`/`service=`/`moduleId` 是否另一业务面

### 自由跳（细节见 `dig-scope-workflow` §1）

- 种子：业务名尽全力 + 全资 1~4 级 + 根域/备案；**数量无上限**，落盘 `资产/种子队列.md`
- **优质根域回灌**（§1.1.1）：确认优质面即落盘「搜域 R」（业务簇根/品牌根，非叶子 host）；本种子剩余活面挖完才优先 `domain=R` 再搜
- 续挖：读 covered + 队列 + 报告，跳过 done/covered，优先 pending
- 全 done 未叫停 → 随机再搜 **或** 回扫旧种子只捞新增 host
- **一种子闭环（§1.0.1）**：搜一个种子 → 去重去废去非存活 → 活面挖完 → 才搜下一个
- P2 先活筛；清洗后过百分百控股（蜂鸟仅存疑；参股默认不挖）再进站
- **深挖优先**（§2.1）：本种子还剩未挖活面禁开新种子 FOFA；429 只挖池

## 4. 进站打法（认 `dig-scope` §4）

- 可先扫 `知识库/打穿短表.md` 当开场几枪，再回本站清单
- 没号打有差分面的四件套；有号先对象图/换 id（不限字段名，§4.2.3）
- 对得上就打开对应模块看细节；**禁止**每站通读整库
- 进站先 §4.0 用几句话说清这摊；有前端抽 JS 建清单（path + 盐/密文 id/hidden 路由/演示号）
- 回包里的 id/url/token 进本站队列；列表过了打附件/导出
- **打开是登录页**（§4.1.1）：先找业务 API / 跳转后业务 host，主业挖未登录；登录表单看得见的面打通或证伪就停；**不是登录相关一律不管**；进了会话立刻转 §4.2.3
- 全类型矩阵；高价值苗头先打穿；**中危同一对象先升链**
- **禁偏科**：不得连日只堆未授权读/同构列表；**注入 / SSRF / XSS / RCE** 按 §4.2.1 打在**有差分面**上（按栈选探针，不是每个 path 喷 `'`），无入口才 N/A+原因

## 5. 白盒审计

Phase0~6 见 `../../clown-src-6k-skill/rules/researcher-blackbox-whitebox.md`。GitHub 代理 `127.0.0.1:7897`。

## 6. 工具依赖

| 工具 | 用途 | 备注 |
|---|---|---|
| MCP `fofa` | 资产搜索 | 三账号自动切换（主 → backup → backup2），**禁止**自己 curl |
| MCP `playwright` | 浏览器渲染/交互 | 见 `playwright-browser-mcp.md` |
| `vuln-engine/` | 规则引擎 | `rule-schema.yaml` / `scanner-config.yaml` |

> **禁止**把 FOFA email/key 写进技能文件或对话。

## 7. 产出

- 报告落 `Desktop\{任务}_SRC挖洞\报告\`，格式只认 `vuln-report-format.md`（两张表）。
- 与知识库冲突时以 rules 为准。
