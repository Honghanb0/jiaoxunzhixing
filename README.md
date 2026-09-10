# 交巡智星——面向网站安全风险评估与敏感信息防泄露的智能巡检智能体

> 一个融合「自动化漏洞扫描 + 大语言模型（LLM）智能研判」的网站安全风险评估与敏感信息防泄露巡检平台。
> 后端 Go + Gin + Neo4j，前端为单文件 SPA；通过 AI 巡检规则把「爬取 → 检测 → AI 风险分级 → 工单」串成闭环。

---

![Logo](logo.jpeg)

## 一、平台定位

交巡智星——面向网站安全风险评估与敏感信息防泄露的智能巡检智能体（简称「交巡智星」）面向**授权范围内的网站资产**，提供：

- **安全风险评估**：自动发现页面与接口，检测 SQL 注入、XSS、敏感文件泄露、页面篡改、敏感信息泄露（关键词/正则）等风险。
- **敏感信息防泄露**：基于关键词与正则规则识别源码、私钥、配置、账号口令等敏感数据外泄。
- **AI 智能研判**：将扫描结果交给 DeepSeek / Kimi / GLM 等兼容 OpenAI 协议的模型，自动完成风险定级、归因分析与处置建议。
- **可审计的闭环**：漏洞去重统计、误报工单、分级权限、CLI 风格运行日志，便于安全运营与合规审计。

---

## 二、核心特性

- **授权域名资产管理**：对需要巡检的域名进行登记、编辑、手动扫描与删除。
- **AI 巡检规则（统一调度 + 多资产绑定）**：以「巡检规则」为载体配置目标资产、AI 模型与 cron 周期；**支持一个规则绑定多个域名**（`domain_ids` 数组），同周期对多资产批量巡检；支持手动触发与定时触发，取代原先分散的域名级定时扫描，避免功能重复。
- **页面发现与资源爬取**：并发爬虫，支持深度与页面数限制、robots 协议遵从。
- **多类型漏洞检测**：SQL 注入、XSS、敏感文件泄露、页面篡改、敏感信息泄露（关键词/正则）。
- **漏洞去重与累计计数**：以「域名 + 漏洞类型 + 受影响 URL/参数」为指纹去重；Dashboard 同时展示「去重后漏洞数」与「累计扫描命中次数」。
- **AI 智能分析与风险分级**：基于 LLM 的风险等级（高/中/低）、摘要、结构化发现项与处置建议；AI 不可用时自动降级为本地兜底结果（`partial`）。
- **误报工单管理**：工单按同一去重指纹聚合，重复命中只累加命中次数与最近扫描时间，不重复建单。
- **CLI 风格日志页**：终端风格（等宽、深色、按级别着色）实时查看服务端/前端日志，支持级别/关键字/时间过滤、暂停刷新；权限等级 ≥ 2 可见。
- **多级权限控制**：4 级角色（访客/操作员/审计员/管理员），JWT 携带数值权限声明。
- **用户自助注册**：登录页支持注册普通账号（默认访客/操作员级别，由管理员按需提权）。
- **自主安全运维智能体（Agent）**：在现有多模型接入层之上，构建了支持「多轮工具调用 + 自主规划」的执行引擎（参考 earendil-works/pi 的双层调用循环）。Agent 可连接并分析本平台 Neo4j 数据库（统计/聚合/自定义 Cypher 推理），并直接驱动平台动作（发起扫描、等待结果、触发巡检、创建/更新/删除工单与告警、新建/删除巡检规则、延时/定时等待、读取近期任务复盘），具备任务拆解、状态跟踪与结果回写能力。近三十个内置工具覆盖定时扫描（`get_current_time` + `wait_until`）、一次性扫描清理（`delete_inspection_rule`）、历史任务复盘（`list_recent_tasks`）、弱口令探测与验证（`weak_password_scan` / `verify_credentials` / `manage_password_dict`）等场景，详见「九、自主智能体（Agent）」。
- **企业级漏洞发现引擎（vuln-engine）**：基于结构化 YAML 规则库（14 条 OWASP Top 10 全覆盖规则）驱动的规则引擎，实现 SAST/DAST/IAST 三种检测模式。采用三层特异性信号匹配（high/medium/low）+ 多层确认机制（≥2 信号命中才上报）+ 置信度评分（0.0-1.0）+ 误报过滤器 + URL/Type 去重，将误报率从 92.1% 降至 0%。内置 CVSS 3.1 评分器（8 指标向量解析）、PoC 自动生成器（HTTP 请求模板）、三格式报告生成（Markdown/JSON/HTML），并预留 nuclei/sqlmap/burp 框架集成与 Jira/Linear/GitHub 工单系统 Webhook 接口。详见「六、关键设计 §6.6」。
- **网络资产发现与拓扑可视化**：参考 `wanpinglingtan` 集成专业的网络暴露面扫描工具，配置全面扫描策略（DNS 解析 + crt.sh 子域名枚举 + 并发 TCP 端口扫描 + 服务识别），自动发现并记录域名、子域名、IP、开放端口、应用服务等各类资产。利用 Neo4j 图数据库构建 Domain→Subdomain→IP→Port→Service 层级关联模型，参考 [scanopy](https://github.com/scanopy/scanopy) 基于 ReactFlow 实现直观的资产拓扑图，支持层级展开、搜索过滤、节点详情查看、缩略图导航。功能已合并至「域名管理」页面（Tab 切换）。详见「六、关键设计 §6.7」。

---

## 三、快速开始

### 3.1 环境要求

| 组件 | 版本 | 说明 |
|------|------|------|
| Go | 1.21+ | 编译运行后端（**唯一必需运行时**，无需 Python） |
| Neo4j | 4.4+ | 图数据库（存储域名、漏洞、工单、巡检记录） |
| DeepSeek / Kimi / GLM API Key | — | AI 研判功能（可多供应商，OpenAI 兼容协议） |

> **运行时说明**：项目已完全 Go 化，构建与全部运维脚本（`cmd/resetdb`、`cmd/genfingerprints`、`cmd/mockai`、`cmd/preflight`）均为 Go 实现，**不依赖 Python 3 / pip / venv**。仅本地漏洞靶场 `verify_site/`（3.5 节）可用 Python 标准库 `http.server` 临时承载，属一次性调试便利，非项目依赖。

### 3.2 安装与启动

```bash
# 1. 拉取依赖
go mod download

# 2. 配置 Neo4j 与 AI（编辑 config.yaml）
#    database.neo4j.uri / username / password
#    ai.provider / api_key / model / base_url

# 3. 编译运行（默认读取同目录 config.yaml，监听 :8030）
go build -o ./bin/security-agent ./cmd/server
./bin/security-agent
# 或指定配置：./bin/security-agent -config config.test.yaml
```

**跨平台构建**：后端为纯 Go 单二进制，可交叉编译到 Linux / macOS / Windows：

```bash
# Linux amd64
CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build -o ./bin/security-agent-linux   ./cmd/server
# macOS arm64 (Apple Silicon)
CGO_ENABLED=0 GOOS=darwin  GOARCH=arm64 go build -o ./bin/security-agent-darwin  ./cmd/server
# Windows amd64
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o ./bin/security-agent.exe     ./cmd/server
```

**启动顺序（Neo4j 直启 + 服务）**：本机开发推荐「先以 Neo4j Desktop 直接启动图库，再启动服务」：
1. 启动 Neo4j（Docker 见 3.3，或本机 Neo4j Desktop / 直接启动），确保 `bolt://localhost:7687` 可达。
2. 启动服务：`./bin/security-agent`（配置见 3.1）。若数据库无用户，会自动创建管理员账号。
3. 浏览器访问 `http://localhost:8030`，前端为单文件 `web/index.html`（已配置背景图与平台 Logo 品牌化展示）。

> 前端由后端 `c.File` 实时读盘返回，**修改前端无需重新编译**，硬刷新浏览器即可生效；**修改 Go 后端必须重启进程**。

**自主智能体启用**：`config.yaml` 的 `agent` 段控制（见 七）。`enabled: true` 且已配置可用 AI Key 时，智能体即可通过 `/api/agent/run` 提交任务。AI 未就绪时该接口返回 503 并提示原因。

### 3.3 Neo4j 启动

```bash
# Docker
docker run -d --name neo4j -p 7474:7474 -p 7687:7687 \
  -e NEO4J_AUTH=neo4j/your_password neo4j:5
```

### 3.4 首次登录

首次启动若数据库无用户，服务会自动创建管理员账号（具体凭据见 `.env.example` / 部署文档，请于首次登录后立即修改密码并妥善保管；**登录界面不再展示默认凭据**）。
新用户可在登录页点击「立即注册」自助注册普通账号。

### 3.5 本地漏洞靶场（8099）

仓库内置 `verify_site/` 漏洞夹具（首页明确标注"本页面刻意植入若干安全缺陷，用于验证扫描器能否检出"），可作为带标签的 ground truth 目标，量化扫描器的检测率与误报率。

> ⚠️ **关键坑位**：平台对未匹配路由的 GET 请求会回退到 SPA `index.html`（NoRoute 兜底），因此不能直接用平台实例在裸路径（如 `/xss.html`）暴露夹具——裸路径只会返回首页。靶场必须用**独立静态服务**承载 `verify_site/`，才能以真实路径暴露漏洞。

```bash
# 1) 起主控制台（默认配置，监听 8030）
./bin/security-agent                       # 或 ./bin/security-agent -config config.yaml

# 2) 另起一个进程，用纯静态服务承载靶场夹具（务必绑定 127.0.0.1，勿暴露到公网）
python -m http.server 8099 --bind 127.0.0.1 --directory verify_site

# 3) 在平台登记靶场域名并发起扫描
#    POST /api/domains        {"name":"http://127.0.0.1:8099"}
#    POST /api/scan/start     {"domain_id":"<上一步返回的 id>"}
#    轮询 GET /api/scan/:id/status → GET /api/scan/:id/results
```

> `config.8099.yaml` 是平台的另一份全量拷贝（端口 8099），但其 `scheduler`/`agent` 已设为 `false`（标注"靶场角色：被动目标"），**不用于对外服务靶场**，仅作配置示例；靶场静态服务用上面的 `python -m http.server` 即可。详见 `测试报告.md` 的「漏洞检测能力 / 误报率」一节。

---

## 四、用户权限模型

系统采用 4 级权限（JWT 中以数值 `rl` 声明）：

| 权限值 | 角色 | 能力 |
|--------|------|------|
| 0 | 访客 | 查看域名、扫描结果、漏洞详情（只读） |
| 1 | 操作员 | 在 0 基础上发起扫描、创建/处理工单 |
| 2 | 审计员 | 在 1 基础上查看「系统日志」页（排障/审计，只读） |
| 3 | 管理员 | 完全控制：用户管理、角色调整、AI 默认模型设定、删除数据 |

> 权限门控示例：AI 巡检规则管理 ≥ 1；自主智能体 `/api/agent/*` ≥ 1（因会对平台执行扫描/建单等写操作）；系统日志页与 `/api/logs` 接口 ≥ 2；用户删除/角色调整 ≥ 3。

---

## 五、主要 API

> 所有业务接口需在 Header 携带 `Authorization: Bearer <token>`；`/api/auth/*` 公开。

| 分组 | 方法 | 路径 | 说明 | 权限 |
|------|------|------|------|------|
| 认证 | POST | /api/auth/register | 注册 | 公开 |
| 认证 | POST | /api/auth/login | 登录（返回携带 `rl` 的 JWT） | 公开 |
| 认证 | GET | /api/auth/me | 当前用户 | 认证 |
| 域名 | GET/POST | /api/domains | 列表 / 创建 | 认证 / ≥1 |
| 域名 | PUT/DELETE | /api/domains/:id | 更新 / 删除 | ≥1 / ≥3 |
| 网络资产 | POST | /api/assets/scan/:domain_id | 触发资产扫描（异步） | ≥1 |
| 网络资产 | GET | /api/assets/list/:domain_id | 资产明细列表 | 认证 |
| 网络资产 | GET | /api/assets/graph/:domain_id | 资产图数据（节点+边） | 认证 |
| 扫描 | POST | /api/scan/start | 发起扫描 | ≥1 |
| 扫描 | GET | /api/scan/:id/{progress,results,status,logs} | 进度/结果/状态/日志 | 认证 |
| 扫描 | GET | /api/scan/rules | 列出全部漏洞规则（含 CVSS/OWASP/CWE） | 认证 |
| 扫描 | GET | /api/scan/:id/report?format=markdown\|json\|html | 下载扫描报告（三格式） | 认证 |
| 漏洞 | GET | /api/vulnerabilities | 漏洞列表（含去重统计） | 认证 |
| 统计 | GET | /api/stats | Dashboard 统计（去重数 + 累计命中） | 认证 |
| 工单 | GET/POST | /api/tickets | 列表 / 创建 | 认证 / ≥1 |
| 工单 | PATCH/POST/DELETE | /api/tickets/:id(/notes) | 状态更新 / 备注 / 删除 | ≥1 |
| 工单 | POST | /api/tickets/batch-delete | 批量删除 | ≥3 |
| 工单 | POST | /api/tickets/merge | 批量合并 | ≥3 |
| AI 模型 | GET/POST | /api/admin/ai(/default) | 模型列表 / 设默认 | ≥1 / ≥3 |
| 巡检规则 | GET/POST | /api/inspections/rules | 规则列表 / 创建 | ≥1 |
| 巡检规则 | POST | /api/inspections/rules/:id/run | 手动触发巡检 | ≥1 |
| 巡检记录 | GET | /api/inspections/records | 巡检记录（状态含 running/analyzing/success/partial/failed） | 认证 |
| 调度校验 | POST | /api/schedules/validate | 校验 cron 并预览下次运行 | 认证 |
| 日志 | GET | /api/logs?after=&limit= | CLI 日志增量拉取 | ≥2 |
| 智能体 | POST | /api/agent/run | 提交自主任务（目标 + 可选 provider），异步执行 | ≥1 |
| 智能体 | GET | /api/agent/tasks | 近期任务列表 | ≥1 |
| 智能体 | GET | /api/agent/tasks/:id | 任务详情（含步骤与对话上下文） | ≥1 |
| 智能体 | POST | /api/agent/tasks/:id/stop | 中止运行中的任务 | ≥1 |
| 智能体 | GET | /api/agent/tools | 查看智能体可用工具清单 | ≥1 |
| 后台 | GET/PATCH/DELETE | /api/admin/users(/:id/role) | 用户管理 | ≥2 / ≥3 |

### 巡检记录状态流转

`pending`（已创建）→ `running`（扫描中）→ `analyzing`（AI 分析中）→ `success`（成功）/ `partial`（扫描成功但 AI 不可用，已落本地兜底）/ `failed`（失败）。

---

## 六、关键设计

### 6.1 漏洞去重与工单聚合
- **去重指纹**：`sha256(domainID \x1f 漏洞类型 \x1f URL \x1f 参数)`，统一小写、URL 去尾斜杠。
- **Dashboard**：`/api/stats` 用 `COALESCE(fingerprint, id)` 做 `DISTINCT` 计数得到「去重后漏洞数」，同时保留「累计扫描命中次数」。
- **工单**：同指纹命中时仅 `hit_count + 1`、刷新 `last_seen_at/updated_at`，不重复建单。
- **历史兼容**：旧漏洞 `fingerprint` 为空时回退节点 `id` 单独计数；旧工单空指纹不误命中。

### 6.2 AI 巡检闭环
`inspection.Runner`：准备扫描结果（按需先扫描或复用最近一次）→ 将扫描上下文送入 LLM → 解析结构化发现项与风险等级 → 落 `InspectionRecord` 并据指纹生成/聚合工单。服务启动时回收停留超过 30 分钟的 `running/analyzing` 孤儿记录。

### 6.3 日志采集
`logutil` 环形缓冲（最近 5000 条）接管标准库 `log`，按关键字启发式识别级别；`/api/logs` 支持 `after` 增量拉取；前端 `hookConsole` 把浏览器端日志合并到同一视图。

### 6.4 多供应商 AI
`ai` 包以 OpenAI 兼容协议适配 **DeepSeek / Kimi / GLM**，支持默认模型设定与不可用自动降级。

### 6.5 自主智能体（Agent）架构

参考 [earendil-works/pi](https://github.com/earendil-works/pi) 的调用循环设计，在 `ai.Manager` 之上构建「多轮工具调用 + 自主规划」执行引擎，把「分析 → 行动 → 结果落库」串成闭环。

#### 6.5.1 模块划分（`internal/agent`）

| 模块 | 文件 | 职责 |
|------|------|------|
| `Agent` | `agent.go` | 执行核心：以**双层调用循环**驱动模型推理与工具调用；构建系统提示词、组装请求、判定终止条件、落定终态 |
| `ToolRegistry` | `tool.go` | 工具注册表：注册/查找/罗列全部工具，导出工具描述（供系统提示词与 `/api/agent/tools`） |
| `Tool` | `tool.go` | 原子能力接口：`Name / Description / Schema / Execute`；`ParseToolCalls` 解析 `<tool_calls>`、`RenderToolResult` 渲染 `<tool_result>` |
| `Task` | `types.go` | 任务状态机：pending→running→completed/failed/cancelled；并发安全（内嵌 `sync.Mutex`），支持内存快照与步骤跟踪 |
| `taskRepo` | `task.go` | 任务持久化：`:AgentTask` 节点 + `:HAS_STEP->:AgentStep` 子节点写入 Neo4j，进程重启后仍可回看 |
| `ContextManager` | `context.go` | 上下文管理：按 token 预算估算与压缩，保留 system + 首条目标 + 近期消息，防止上下文溢出 |
| `Manager` | `manager.go` | 生命周期：构建依赖集合 `Deps`、注册工具、提交/查询/中止任务，持有运行中与已取消任务的上下文 |
| `Deps` + 工具实现 | `tools.go` / `tools_action.go` / `tools_weakpass.go` | 平台依赖聚合与 30 个内置工具（只读分析 + 平台动作 + 弱口令探测） |

#### 6.5.2 调用循环机制（双层循环）

外层 `runLoop`（受 `max_turns` 上限约束，默认 24）：

1. 取压缩后的消息上下文 → 组装请求（system + 历史消息，工具结果角色归一为 `user` 以保证跨厂商兼容）。
2. 调用 LLM（复用 `ai.Manager` 的降级/重试）：`ChatWith(provider)` 或 `Chat(default)`。
3. 解析模型输出：
   - 若含 `<tool_calls>[{name,arguments}]</tool_calls>` → **内层 `executeToolCalls`** 依次执行每个工具：`tool.Execute`（每个调用 `recover` 捕获 panic，失败以 `IsError=true` 的 `<tool_result>` 回写，让模型自我纠正）→ 渲染 `<tool_result>` 追加进消息 → 若调用 `finish_task` 则终止。
   - 若无工具调用（纯文本）→ 视为最终结论，任务完成。
   - 若解析失败 → 记为 `reasoning` 步骤；连续两轮无工具调用则主动收尾，避免死循环。

停止条件（对应 pi 的 terminate / error / shouldStopAfterTurn / abort）：`finish_task` 调用、纯文本结论、`ctx` 被取消（用户中止）、LLM 连续失败、达到 `max_turns`。

#### 6.5.3 与数据库及平台服务的集成

工具分为两类，直连本平台 Neo4j 与引擎/调度器：

- **只读分析**（连接并分析数据库）：`get_stats`、`list_domains`、`get_domain`、`list_vulnerabilities`、`get_vulnerability`、`list_sensitive_info`、`list_inspection_rules`、`list_inspection_records`、`get_inspection_record`、`list_alerts`、`list_tickets`、`get_current_time`、`list_recent_tasks`、`query_neo4j`。
  - `query_neo4j` 为沙箱化只读 Cypher：拒绝 `;` 拼接与写关键字（`CREATE/MERGE/DELETE/DROP/SET/REMOVE/INSERT/CALL dbms./CALL db./LOAD` 等），仅返回聚合/推理结果。
  - `get_current_time` 返回服务器 RFC3339 时间戳，配合 `wait_until` 实现「25 分 30 秒后扫描」「今晚 20:00 扫描一次」类精确定时。
  - `list_recent_tasks` 按回溯小时数读取近期任务（目标/状态/结论），支持「把昨天的主要任务重新干一遍」类复盘场景。
- **平台动作**（执行复杂多步骤任务并回写）：`start_scan`、`get_scan_status`、`wait_scan`、`wait`、`wait_until`、`run_inspection_rule`、`create_ticket`、`update_ticket_status`、`create_inspection_rule`、`delete_inspection_rule`、`send_alert`、`create_domain`、`finish_task`。
  - 动作结果（扫描摘要、工单 ID、告警 ID 等）回写平台，形成「分析 → 行动 → 结果落库」闭环；`wait_scan` 阻塞等待扫描完成（30~300s）再返回精简摘要，避免把海量原始数据塞回上下文。
  - `delete_inspection_rule` 适用于「就扫一次，之后不要扫了」：触发一次性扫描后调用本工具清理规则，避免后续周期重复执行；`create_inspection_rule` 支持 `domain_ids` 数组绑定多资产。
  - `wait_until` 阻塞等待到指定 RFC3339 时刻（上限 24h，可被任务取消），等待期间平台不关闭、定时任务照常执行。

`Deps` 聚合 `Store / Engine / Sched / AI` 及各仓储（`Domain/Vuln/Sensitive/Rule/Record/Alert/Ticket/ScanJob/Task`），由 `Manager.NewManager` 在 `cmd/server/main.go` 装配并注入 `api.NewServerWithEngine`。

#### 6.5.4 错误处理与上下文管理策略

- **工具级容错**：每个工具调用 `defer recover`，panic 转错误并以错误型 `tool_result` 回写，模型可据错误修正参数重试。
- **LLM 级容错**：复用 `ai.Manager` 的不可达/超时自动降级与重试；单次 LLM 失败直接标记任务 `failed` 并落 `error`。
- **上下文管理**：`ContextManager` 按 ~3-4 字符/token 估算，超预算（默认 12000）时保留 system + 首条目标 + 近期消息，裁剪中间历史。
- **状态与审计**：任务与每一步持久化到 Neo4j（`:AgentTask` / `:AgentStep`），内存快照与持久层双写，支持运行中被查询、重启后回看、用户主动中止（`stop` 取消 context 并置 `cancelled`）。
- **权限与隔离**：`/api/agent/*` 需 `role_level ≥ 1`（操作符），因智能体会对平台执行扫描/建单等写操作；`Agent` 包仅依赖 `ai/scanner/scheduler/storage/models`，HTTP 层在 `api` 包，避免循环依赖。

### 6.6 企业级漏洞发现引擎（vuln-engine）

vuln-engine 将 `clown-src-6k-skill` 知识库中的实战漏洞方法论形式化为结构化 YAML 规则，通过 Go 规则引擎在扫描流程中动态加载与执行，实现「规则驱动 + 多层确认 + 置信度评分」的企业级检测能力。

#### 6.6.1 目录结构

```
clown-src-6k-skill/vuln-engine/
├── scanner-config.yaml              # 全局扫描配置（SAST/DAST/IAST 模式 + 可配置参数）
├── rule-schema.yaml                 # YAML 规则 Schema 定义
├── rules/                           # 14 条 OWASP Top 10 结构化规则
│   ├── injection-sqli.yaml          # SQL 注入 (A03)
│   ├── xss-reflected.yaml           # 反射型 XSS (A03)
│   ├── broken-access-control.yaml   # 越权访问 IDOR (A01)
│   ├── broken-authentication.yaml   # 认证失效 (A07)
│   ├── sensitive-file-exposure.yaml # 敏感文件暴露 (A05)
│   ├── xml-external-entities.yaml   # XXE (A05)
│   ├── insecure-deserialization.yaml # 不安全反序列化 (A08)
│   ├── ssrf.yaml                    # 服务端请求伪造 (A10)
│   ├── command-injection.yaml       # 命令注入 (A03)
│   ├── security-misconfiguration.yaml # 安全配置错误 (A05)
│   ├── known-vulnerable-components.yaml # 已知漏洞组件 (A06)
│   ├── server-side-template-injection.yaml # SSTI (A03)
│   ├── path-traversal.yaml          # 路径穿越 (A01)
│   └── file-upload.yaml             # 任意文件上传 (A04)
└── integrations/
    ├── nuclei-profiles.yaml         # Nuclei 模板集成配置
    └── ticketing-webhook.yaml       # 工单系统集成（Jira/Linear/GitHub/GitLab/自定义）

internal/scanner/
├── rule_engine.go                   # 规则引擎核心（embed 加载 + DAST 匹配 + 多层确认 + CVSS）
├── reporter.go                      # 报告生成器（Markdown/JSON/HTML 三格式）
├── rules/                           # go:embed 内嵌规则副本（14 文件）
└── rule_engine_test.go              # 9 个单元测试
```

#### 6.6.2 规则 Schema

每条 YAML 规则包含以下核心字段：

```yaml
id: "rule-injection-sqli"            # 唯一规则 ID
name: "SQL Injection"                # 英文名
name_cn: "SQL 注入"                  # 中文名
owasp_category: "A03-injection"      # OWASP 2021 Top 10 分类
cwe_id: "CWE-89"                     # CWE 编号
cvss:
  vector: "CVSS:3.1/AV:N/AC:L/..."   # CVSS 3.1 向量
  base_score: 9.8                    # 基础评分
  severity: "critical"               # 严重等级
detection:
  methods: ["DAST", "SAST"]          # 支持的检测模式
  dast_signals:                      # 三层特异性信号
    high_specificity: [...]          # 高特异性（单命中可上报）
    medium_specificity: [...]        # 中特异性
    low_specificity: [...]           # 低特异性
  multi_layer:
    enabled: true                    # 多层确认开关
    min_signals: 2                   # 最少命中信号数
    high_specificity_skips_min: true # 高特异性跳过阈值
  false_positive_filters: [...]     # 误报过滤条件
poc:
  enabled: true
  request_template: "GET {{url}}..." # HTTP 请求模板
  payloads: [...]                    # Payload 列表（含风险等级）
  verification: [...]                # 验证条件
remediation:
  priority: "P0"
  summary: "..."                     # 修复摘要
  details: [...]                     # 修复详情
  references: [...]                  # 参考链接
```

#### 6.6.3 检测流水线

```
页面爬取 → 传统检测器（指纹/篡改/SQLi/XSS/敏感文件）
                ↓
         RuleEngine.MatchDAST(page)
                ↓
    遍历 14 条规则 → 匹配三层信号（high/medium/low）
                ↓
         多层确认决策（≥2 信号 或 1 个 high）
                ↓
         置信度评分（0.0-1.0 → high/medium/low）
                ↓
         误报过滤器（FP filters）
                ↓
         URL + Type 去重（与传统检测器结果合并去重）
                ↓
         转换为 Vulnerability 模型（含 CVSS/CWE/修复建议）
                ↓
         Reporter 生成三格式报告 + PoC
```

#### 6.6.4 CVSS 3.1 评分器

完整解析 CVSS 3.1 向量的 8 个指标（AV/AC/PR/UI/S/C/I/A），自动计算 Base Score 并映射 severity：

| 向量示例 | 分数 | 等级 |
|----------|------|------|
| CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | 9.8 | critical |
| CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N | 7.5 | high |
| CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N | 5.3 | medium |

#### 6.6.5 误报降低机制

| 机制 | 说明 |
|------|------|
| 三层特异性信号 | high/medium/low 分层，避免宽泛正则误匹配 |
| 多层确认 | ≥2 信号命中才上报，高特异性单命中跳过阈值 |
| 置信度评分 | low 置信度不上报，仅记录 |
| FP 过滤器 | 每条规则内置误报过滤条件（如 auth_required 降级） |
| URL+Type 去重 | 与传统检测器结果合并时去重，避免重复上报 |

#### 6.6.6 报告生成

`Reporter` 支持三种输出格式：

- **Markdown**：对齐 SRC 漏洞报告格式（标题/URL/等级/描述/危害/接口清单/复现步骤/PoC/修复建议）
- **JSON**：机器可读，含统计摘要（total/critical/high/medium/low + by_type + by_confidence）
- **HTML**：可视化统计卡片 + 漏洞卡片（按 severity 排序）

通过 API `GET /api/scan/:id/report?format=markdown|json|html` 下载。

#### 6.6.7 框架与工单集成（配置就绪）

- **Nuclei 模板**：`integrations/nuclei-profiles.yaml` 定义规则与 Nuclei 标签映射，自动导入命中结果
- **工单系统**：`integrations/ticketing-webhook.yaml` 支持 Jira / Linear / GitHub Issues / GitLab Issues / 自定义 Webhook，含 CVSS→优先级映射、去重策略、限流配置

### 6.7 网络资产发现与拓扑可视化

参考 `wanpinglingtan` 的暴露面扫描能力与 [scanopy](https://github.com/scanopy/scanopy) 的图谱可视化设计，构建从扫描到可视化的完整资产发现链路：

#### 6.7.1 扫描策略（`internal/scanner/asset_scanner.go`）

- **DNS 解析**：`net.LookupIP` 解析域名到 IP；裸 IP 目标跳过子域名枚举。
- **子域名枚举**：crt.sh 证书透明日志 API + 内置字典爆破（`commonSubdomainWords`），去重合并。
- **并发 TCP 端口扫描**：50 goroutine 并发，`net.DialTimeout` 连接探测 1000+ 常见端口（含 8099 调试端口），1s 超时。
- **服务识别**：Banner 抓取（TCP 前 1024 字节）+ HTTP 指纹分析（GET 请求 + 响应头/Title/Server 解析），识别服务名称、版本、应用标题、技术栈。
- **异步执行**：扫描任务使用 `context.Background()` + 10 分钟超时，HTTP 响应立即返回，后台 goroutine 执行，避免请求取消导致中断。

#### 6.7.2 Neo4j 资产图模型（`internal/storage/asset_repo.go`）

```
(:Domain)-[:HAS_SUBDOMAIN]->(:Subdomain)
(:Domain)-[:RESOLVES_TO]->(:IP)
(:IP)-[:EXPOSES]->(:Port)
(:Port)-[:RUNS]->(:Service)
```

- **节点**：Domain / Subdomain / IP（含 version/is_alive）/ Port（含 protocol/state/service_name/banner）/ Service（含 name/version/title/status_code/tech）
- **仓储**：`SaveAssetScan`（MERGE 幂等写入）+ `GetAssetGraph`（OPTIONAL MATCH 多跳查询 + UNION 边查询）+ `ListAssets`（扁平列表）

#### 6.7.3 前端拓扑可视化（`web/index.html`）

- **ReactFlow UMD CDN**：`reactflow@11.10.4` + `react@18.2.0` + `react-dom@18.2.0`，无需构建工具链。
- **分层布局**：domain(x=80) → subdomain(x=280) → ip(x=480) → port(x=680) → service(x=880)，按节点类型自动排列。
- **节点样式**：按类型着色（域名紫/子域青/IP蓝/端口橙/服务绿），纯文本标签 + CSS class，smoothstep 边带动画。
- **交互功能**：搜索过滤（实时匹配 label/sublabel）、节点点击详情面板、缩略图（MiniMap）导航、缩放控件（Controls）。
- **大规模渲染**：已验证 3998 节点 / 3997 边图谱正常渲染。
- **页面合并**：网络资产拓扑图已作为 Tab 合并至「域名管理」页面，与域名列表共享域名选择器，减少导航层级。

---


## 七、配置（config.yaml 要点）

```yaml
server:
  host: "0.0.0.0"
  port: 8030
  mode: "release"
database:
  neo4j:
    uri: "bolt://localhost:7687"
    username: "neo4j"
    password: "your_password"
    database: "neo4j"
ai:
  provider: "deepseek"
  api_key: "${DEEPSEEK_API_KEY}"
  model: "deepseek-chat"
  base_url: "https://api.deepseek.com"
  timeout: 30
scanner:
  concurrency: 5
  timeout: 300
  user_agent: "SecurityScanner/1.0"
  max_depth: 5
  max_pages: 1000
  respect_robots: true
scheduler:
  enabled: true
  max_concurrent_scans: 3
sensitive:
  keywords: ["password", "secret", "api_key", "token"]
  regex_patterns:
    - "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b"
    - "-----BEGIN (RSA |EC )?PRIVATE KEY-----"
  file_extensions: [".sql", ".bak", ".env"]
alerts:
  enabled: true
  channels:
    - type: "webhook"
      url: "${WEBHOOK_URL}"
agent:
  enabled: true        # 是否启用自主智能体
  max_turns: 24        # 单任务最大推理轮次（达到上限仍未完成则标记 failed，防失控）
  model: ""            # 可选：覆盖默认模型供应商（留空则用 ai.default）
```

环境变量：`DEEPSEEK_API_KEY`（AI 必填）、`WEBHOOK_URL`（可选）等。

---

## 八、项目结构

```
.
├── cmd/
│   ├── server/         # 平台主服务入口：装配配置/存储/调度/路由/日志，监听 :8030
│   ├── dbcheck/        # Neo4j 连通性自检（运维排障）
│   ├── resetdb/        # 重置图库：清空域名/漏洞/工单/巡检/资产等节点（--confirm/--dry-run）
│   ├── genfingerprints/ # 由 clown-src-6k-skill 指纹源生成 fingerprints.json（go:embed 用）
│   ├── mockai/         # 本地 Mock AI 服务（/chat/completions，支持 JWT/静态 Key 鉴权 + SSE）
│   └── preflight/      # 安全运维前置门禁：检查 rules/MCP/vuln-engine/知识库/产物目录等
├── internal/
│   ├── api/                    # HTTP 层：server/handlers/scan_handler/inspection_handler/
│   │                           #   ticket_handler/alert_handler/ai_handler/log_handler/
│   │                           #   stats_handler/schedule_handler/auth_handler/middleware
│   │                           #   agent_handler（自主智能体接口 /api/agent/*）
│   │                           #   asset_handler（网络资产接口 /api/assets/*）
│   ├── ai/                     # 多供应商 AI（DeepSeek/Kimi/GLM，OpenAI 兼容）
│   ├── agent/                  # 自主智能体：agent(调用循环)/tool(工具协议)/types(任务状态机)/
│   │                           #   task(持久化)/context(上下文压缩)/manager(生命周期)/
│   │                           #   tools(只读分析)/tools_action(平台动作)
│   ├── config/                 # 配置加载
│   ├── inspection/             # 巡检 Runner（扫描 + AI 研判 + 记录/工单）
│   ├── logutil/                # 环形缓冲日志采集
│   ├── models/                 # 数据模型（用户/域名/漏洞/工单/巡检记录/资产 asset.go）
│   ├── ops/                    # 运维工具库：resetdb/genfingerprints/mockai/preflight 共享逻辑 + 统一日志
│   ├── scanner/                # 扫描引擎：engine/crawler/detector/fingerprint/
│   │                           #   rule_engine(YAML 规则引擎)/reporter(报告生成)/rules(embed)
│   │                           #   asset_scanner(网络资产扫描器：DNS/端口/服务识别)
│   ├── scheduler/              # 巡检规则 cron 调度 + 告警
│   └── storage/                # Neo4j 仓储：repository/user_repo/vulnerability_repo/
│                               #   ticket_repo/inspection_repo/alert_repo/neo4j
│                               #   asset_repo(资产图仓储)
├── clown-src-6k-skill/         # SRC 漏洞挖掘知识库 + vuln-engine 企业级规则引擎（YAML 规则源）
│   └── vuln-engine/            #   scanner-config.yaml/rules(14 条 OWASP Top 10)/integrations
├── security-ops-skill/         #   安全运维智能体（单一「自主执行」模式，无外部编排依赖）
│   ├── SKILL.md                #   触发条件、自主执行工作流、工具清单
│   ├── AGENTS.md               #   智能体编排配置：阶段 DAG、工具调用顺序、边界约束
│   └── references/             #   autonomous-workflow / error-handling / output-contract
├── web/index.html              # 单文件前端（实时读盘）
├── config.yaml                 # 运行配置
├── logo.jpeg                   # 平台 Logo
└── README.md
```

---

## 九、常见问题

- **Neo4j 连不上？** 确认服务已启动、uri/账号/密码正确、bolt 端口 7687 未被防火墙拦截。
- **AI 研判不可用？** 配置 `DEEPSEEK_API_KEY` 或对应 provider 的 key；网络不可达时记录自动标记为 `partial`（本地兜底）。
- **扫描启动失败？** 域名格式正确且状态为 active，且当前账号权限 ≥ 1。
- **巡检记录长期 running/analyzing？** 多为服务重启中断了在途巡检；重启时平台会自动回收超时的孤儿记录。
- **需要重置数据？** 运行 `go run ./cmd/resetdb --confirm`（或 `--dry-run` 仅预览），会清空图库的全部节点与关系，谨慎使用。
- **提交智能体任务提示 503「AI 模型未就绪」？** 确认 `config.yaml` 的 `ai.providers.*.enabled` 为 true 且对应 `api_key` 已配置；服务启动日志会显示已加载的 provider。
- **智能体任务一直 running 不结束？** 单任务受 `agent.max_turns`（默认 24）上限与 LLM 超时约束；可在前端/接口 `POST /api/agent/tasks/:id/stop` 主动中止。步骤与结论持久化在 Neo4j（`:AgentTask` / `:AgentStep`），重启后仍可 `GET /api/agent/tasks/:id` 回看。
- **智能体调用工具报错？** 工具调用 `recover` 捕获异常并以错误型 `<tool_result>` 回写，模型通常能自我纠正；若反复失败，检查目标实体是否存在（如 `get_domain` 先核实域名）与 Neo4j 连通性。

---

## 十、近期更新

### v1.2.0(2026-09-10)

智能体交付契约体系（enforceDeliverables）

针对任务「声称完成但实际零交付」的历史缺陷（完结却零工单、零规则），构建结构化交付保障：

- **交付契约（`DeliverableContract`）**：任务启动时解析目标串，提取建单需求（`NeedsTicket`）、类别筛选（`TicketCategories`）、排他模式（`Exclusive`）、规则需求（`NeedsRule`）、周期（`Schedule`）、目标资产（`TargetHost`），作为终止校验的唯一可信来源，取代散落的关键词硬编码。
- **九类漏洞语义分类**：弱口令/数据泄露/注入类/权限配置/依赖组件/逻辑缺陷/信息泄露/Webshell/其他，与扫描器实际输出（`vulnTypeToCategory`）对齐；webshell 独立分类（不再误并入 data_leak）。
- **强制交付校验（`enforceDeliverables`）**：收尾前硬性检查——模型声称建单/建规则但步骤无成功记录时打回补齐；连续 5 次仍未满足则触发安全阀（Safety Valve）强制收尾并写明未满足原因。
- **假完成对账（`reconcileFinishClaim`）**：模型在 `finish_task` 摘要中声称完成交付但步骤无记录时，判定为假完成并拒绝收尾，防止模型「口头交付」。
- **字段规范化（`normalizeTicketFields`）**：智能体建单时自动校验并补全必填字段（vuln_type/title/risk_level/asset_url/evidence/retest_method），缺失时使用可追溯默认值（`unknown`/`未命名安全工单`/`(scan_job:xxx)`），并记录补填说明便于审计。
- **工单去重指纹（`ticketFingerprint`）**：基于「漏洞类型 + 影响资产 URL + 扫描作业」三要素 sha1 生成，同一扫描作业内同类型同 URL 视为同一条，复用而非新建，避免重复建单。

**配套测试**：`contract_test.go`（交付契约解析/校验/安全阀/假完成对账）+ `ticket_coverage_test.go`（九类漏洞全覆盖/字段规范化/去重指纹/关键词回退），共 40+ 用例。

工单系统增强（`/api/tickets/merge`）

- **批量合并工单（`POST /api/tickets/merge`）**：将多个工单合并为一个，保留目标工单标题（`target_title`），支持 `source_ids` 数组批量指定来源；合并后自动归档来源工单，保留操作记录便于审计。
- **批量删除工单（`POST /api/tickets/batch-delete`）**：一次性删除多个工单，管理员权限控制，避免逐个删除的低效操作。
- **基线研判自动填充（`triageFromRisk`）**：工单创建时若未提供研判信息，根据 `risk_level`（high/medium/low）自动填充 `remediation_priority`（P0/P1/P2）、`harm_description`（危害描述）、`mitigation_measures`（处置建议）、`retest_method`（复检方法）。

智能体运行稳定性提升

- **任务硬超时（`taskHardTimeout`）**：单次任务受 30 分钟硬墙钟上限约束，防止 LLM 客户端无 deadline 时永久挂起导致任务永远停在 `running` 并拖垮服务进程。
- **迭代上限（`maxIterations`）**：循环内存在多条不推进轮次的路径（parse_error 纠正/纯推理文本/nudge），该上限保证任何情况下都能退出，远大于真实轮询预算，不影响正常任务。
- **首轮纯文本不直接收尾**：只有「连续两轮」纯文本才视为模型已给出结论并收尾，避免首轮纯文本（模型在「思考/预告下一步」）被误判为已完成。
- **JSON 解析失败自纠正**：模型试图输出 `<tool_calls>` 但 JSON 解析失败时，将错误回写为纠正信号，让模型重新输出合法数组，而非直接当成「已给出结论」收尾。

围绕「定时一次性扫描、历史任务复盘、多资产批量巡检」等真实运维场景，对智能体与巡检规则做能力增强：
- **新增 4 个智能体工具**（内置工具总数 →30）：
  - `get_current_time`：查询服务器当前时间（RFC3339 + Unix），供定时计算。
  - `wait_until`：精确等待到指定 RFC3339 时刻（上限 24h，可取消），与 `get_current_time` 组合覆盖「25 分 30 秒后扫描」「今晚 20:00 扫一次」。
  - `delete_inspection_rule`：删除巡检规则并即时摘除调度任务，覆盖「就扫一次，之后不要扫了」。
  - `list_recent_tasks`：按回溯小时数读取近期自主任务，覆盖「把昨天的主要任务重新干一遍」。
- **巡检规则支持多资产绑定**：`InspectionRule` 新增 `DomainIDs []string` 字段（保留 `DomainID` 兼容），一次配置即可让同一规则按 cron 周期对多个域名批量巡检；Runner 触发时为每个域名分别生成巡检记录，调度器/仓储/API/前端全链路适配（前端规则表单由单域名下拉改为多资产勾选）。
- **系统提示词增强**：明确定时/延时、一次性扫描、复盘三类场景的工具组合用法，降低模型编排出错率。

为自主智能体补齐「授权范围内的弱口令探测与有效性验证」能力，新增 3 个工具（内置工具总数 25 → 30），与既有只读分析 / 平台动作工具共用同一调用循环与错误回写：
- **`manage_password_dict`**：弱口令字典管理，支持 list/show/add/reset/load；内置 `users`(34 条)/`passwords`(89 条) 字典（`go:embed`），运行时可追加或文件载入。
- **`weak_password_scan`**：并发「用户名×口令」字典爆破（默认并发 10、超时 5s、组合上限 20000），命中即记录并默认二次复验；支持 ssh/ftp/pop3/smtp/redis/http(Basic Auth) 六类协议；可 `stop_on_first` 命中即停。
- **`verify_credentials`**：对单条「用户名+口令」即时有效性验证（复验扫描命中或人工指定凭据），校验过程出错以 `error` 字段回写而非抛错，便于模型自纠正。
- **集成与约束**：随 `RegisterBuiltinTools` 自动注册，无需改动 `agent.go` 主循环；命中凭据建议经 `create_ticket`/`send_alert` 回写闭环；仅可在授权范围内对显式 `target`+`service` 发起探测。详见 6.5.5。

将 `clown-src-6k-skill` 知识库中的实战漏洞方法论形式化为结构化 YAML 规则库，并扩展 Go 后端扫描引擎消费这些规则，实现企业级漏洞发现能力：

- **规则库**：14 条 OWASP Top 10 全覆盖结构化 YAML 规则（SQLi/XSS/IDOR/敏感文件/XXE/反序列化/SSRF/命令注入/安全配置/已知漏洞组件/认证失效/SSTI/路径穿越/文件上传），每条规则含 CVSS 3.1 向量、三层检测信号、误报过滤器、PoC 模板、修复建议。
- **规则引擎**（`internal/scanner/rule_engine.go`）：`//go:embed` 内嵌加载 + 三层特异性信号匹配 + 多层确认（≥2 信号命中才上报）+ 置信度评分 + CVSS 3.1 八指标向量解析 + URL/Type 去重，将误报率从 92.1% 降至 0%。
- **报告生成器**（`internal/scanner/reporter.go`）：Markdown（对齐 SRC 报告格式）/ JSON（机器可读统计）/ HTML（可视化卡片）三格式输出，含 PoC 自动生成。
- **API 端点**：新增 `GET /api/scan/rules`（规则列表）与 `GET /api/scan/:id/report?format=markdown|json|html`（报告下载）。
- **框架与工单集成配置**：`integrations/nuclei-profiles.yaml`（Nuclei 模板映射）+ `integrations/ticketing-webhook.yaml`（Jira/Linear/GitHub/GitLab/自定义 Webhook，含 CVSS→优先级映射）。
- **测试验证**：18 个单元测试全 PASS（含 9 个规则引擎专项测试）+ 端到端扫描验证（15 漏洞，0 重复，0 误报）。

针对用户普遍存在的网络资产认知不清晰问题，参考 `wanpinglingtan` 集成专业的网络暴露面扫描工具，并利用 Neo4j 图数据库与 ReactFlow 实现直观的资产拓扑可视化：

- **网络资产扫描器**（`internal/scanner/asset_scanner.go`）：DNS 解析 + crt.sh 子域名枚举 + 50 并发 TCP 端口扫描（1000+ 常见端口）+ Banner/HTTP 服务识别（名称/版本/Title/技术栈）；异步执行（`context.Background()` + 10 分钟超时），裸 IP 目标自动跳过子域名枚举。
- **Neo4j 资产图模型**（`internal/models/asset.go` + `internal/storage/asset_repo.go`）：新增 Subdomain / IP / Port / Service 四类节点与 HAS_SUBDOMAIN / RESOLVES_TO / EXPOSES / RUNS 四类关系；MERGE 幂等写入 + 多跳 OPTIONAL MATCH 图查询 + UNION 边查询。
- **API 端点**：`POST /api/assets/scan/:domain_id`（异步触发）、`GET /api/assets/list/:domain_id`（资产明细列表）、`GET /api/assets/graph/:domain_id`（图数据节点+边）。
- **ReactFlow 拓扑可视化**（`web/index.html`）：基于 ReactFlow@11 UMD CDN，分层布局（domain→subdomain→ip→port→service）、按类型着色、smoothstep 动画边；支持搜索过滤、节点点击详情、缩略图导航、缩放控件。已验证 3998 节点 / 3997 边大规模图谱正常渲染。
- **页面合并**：网络资产拓扑图已作为 Tab 合并至「域名管理」页面，与域名列表共享域名选择器，减少导航层级，提升操作连贯性。
- **测试验证**：功能测试（127.0.0.1: 4 端口/4 服务；example.com: 48 子域/41 IP/1995 端口/1913 服务）+ 性能测试（图谱 API 2s 返回 845KB 数据，前端 20s 渲染 4k 节点）+ UX 测试（搜索过滤/详情面板/缩略图全部通过）。

将平台从「Go 主服务 + Python 运维脚本」改造为**可独立运行的纯 Go 项目**，消除 Python 运行耦合。

### v1.1.0(2026-09-03)

**跨平台兼容**：后端改为纯 Go 单二进制，补充 Linux / macOS / Windows 交叉编译命令（`CGO_ENABLED=0 GOOS=... GOARCH=...`），部署不再受平台限制。

**前端背景与品牌化**：单文件前端 `web/index.html` 增加背景图与平台 Logo（`logo.jpeg`）展示，登录与仪表盘页视觉统一。

**启动方式文档化**：明确「Neo4j 直启 + 服务启动」的本机开发启动链路（见 3.2），并区分 Docker 与生产两种 Neo4j 启动方式。

参考 [earendil-works/pi](https://github.com/earendil-works/pi) 的调用循环架构，将平台 AI 能力从「单次研判」升级为「多轮工具调用 + 自主规划」执行模式：

- **模块划分**：`internal/agent` 下 `Agent`（调用循环）/ `ToolRegistry`（分发）/ `Tool`（原子能力）/ `Task`（状态机，持久化到 Neo4j）/ `ContextManager`（上下文压缩）/ `Manager`（生命周期）/ `tools`（只读分析）/ `tools_action`（平台动作）。详见 6.5。
- **调用循环**：双层循环——外层按轮次推理，模型以 `<tool_calls>` 请求工具，内层依次执行并回写 `<tool_result>`；`finish_task` 或纯文本结论即终止；超轮次/取消/LLM 失败即收尾。
- **数据库与平台集成**：27 个内置工具，直连本平台 Neo4j（统计/聚合/只读 Cypher 推理）与引擎/调度器（扫描、巡检、工单、告警、巡检规则），实现「分析 → 行动 → 结果回写」闭环。
- **错误与上下文**：工具级 `recover` + 错误回写自纠正、LLM 级降级重试、token 预算压缩、任务与步骤双写 Neo4j 便于审计与重启回看。
- **接口与配置**：新增 `/api/agent/{run,tasks,tasks/:id,tools}` 与 `POST /api/agent/tasks/:id/stop`（权限 ≥1）；`config.yaml` 新增 `agent` 段（`enabled/max_turns/model`）。

**巡检规则支持多资产绑定**：`InspectionRule` 新增 `DomainIDs []string` 字段（保留 `DomainID` 兼容），一次配置即可让同一规则按 cron 周期对多个域名批量巡检；Runner 触发时为每个域名分别生成巡检记录，调度器/仓储/API/前端全链路适配（前端规则表单由单域名下拉改为多资产勾选）。

将 `clown-src-6k-skill` 知识库中的实战漏洞方法论形式化为结构化 YAML 规则库，并扩展 Go 后端扫描引擎消费这些规则，实现企业级漏洞发现能力：

- **规则库**：14 条 OWASP Top 10 全覆盖结构化 YAML 规则（SQLi/XSS/IDOR/敏感文件/XXE/反序列化/SSRF/命令注入/安全配置/已知漏洞组件/认证失效/SSTI/路径穿越/文件上传），每条规则含 CVSS 3.1 向量、三层检测信号、误报过滤器、PoC 模板、修复建议。
- **规则引擎**（`internal/scanner/rule_engine.go`）：`//go:embed` 内嵌加载 + 三层特异性信号匹配 + 多层确认（≥2 信号命中才上报）+ 置信度评分 + CVSS 3.1 八指标向量解析 + URL/Type 去重，将误报率从 92.1% 降至 0%。
- **报告生成器**（`internal/scanner/reporter.go`）：Markdown（对齐 SRC 报告格式）/ JSON（机器可读统计）/ HTML（可视化卡片）三格式输出，含 PoC 自动生成。
- **API 端点**：新增 `GET /api/scan/rules`（规则列表）与 `GET /api/scan/:id/report?format=markdown|json|html`（报告下载）。
- **框架与工单集成配置**：`integrations/nuclei-profiles.yaml`（Nuclei 模板映射）+ `integrations/ticketing-webhook.yaml`（Jira/Linear/GitHub/GitLab/自定义 Webhook，含 CVSS→优先级映射）。
- **测试验证**：18 个单元测试全 PASS（含 9 个规则引擎专项测试）+ 端到端扫描验证（15 漏洞，0 重复，0 误报）。

针对用户普遍存在的网络资产认知不清晰问题，集成专业的网络暴露面扫描工具，并利用 Neo4j 图数据库与 ReactFlow 实现直观的资产拓扑可视化：

- **网络资产扫描器**（`internal/scanner/asset_scanner.go`）：DNS 解析 + crt.sh 子域名枚举 + 50 并发 TCP 端口扫描（1000+ 常见端口）+ Banner/HTTP 服务识别（名称/版本/Title/技术栈）；异步执行（`context.Background()` + 10 分钟超时），裸 IP 目标自动跳过子域名枚举。
- **Neo4j 资产图模型**（`internal/models/asset.go` + `internal/storage/asset_repo.go`）：新增 Subdomain / IP / Port / Service 四类节点与 HAS_SUBDOMAIN / RESOLVES_TO / EXPOSES / RUNS 四类关系；MERGE 幂等写入 + 多跳 OPTIONAL MATCH 图查询 + UNION 边查询。
- **API 端点**：`POST /api/assets/scan/:domain_id`（异步触发）、`GET /api/assets/list/:domain_id`（资产明细列表）、`GET /api/assets/graph/:domain_id`（图数据节点+边）。
- **ReactFlow 拓扑可视化**（`web/index.html`）：基于 ReactFlow@11 UMD CDN，分层布局（domain→subdomain→ip→port→service）、按类型着色、smoothstep 动画边；支持搜索过滤、节点点击详情、缩略图导航、缩放控件。已验证 3998 节点 / 3997 边大规模图谱正常渲染。
- **页面合并**：网络资产拓扑图已作为 Tab 合并至「域名管理」页面，与域名列表共享域名选择器，减少导航层级，提升操作连贯性。
- **测试验证**：功能测试（127.0.0.1: 4 端口/4 服务；example.com: 48 子域/41 IP/1995 端口/1913 服务）+ 性能测试（图谱 API 2s 返回 845KB 数据，前端 20s 渲染 4k 节点）+ UX 测试（搜索过滤/详情面板/缩略图全部通过）。

### v1.0.0(2026-08-31)

初始版本发布。

## 十一、许可证

[Apache-2.0 license](https://github.com/Honghanb0/jiaoxunzhixing?tab=Apache-2.0-1-ov-file#)

## 十二、参考项目

https://github.com/0x727/FingerprintHub

https://github.com/google/osv

https://github.com/Honghanb0/wanpingqiuzhen

https://github.com/earendil-works/pi

https://github.com/scanopy/scanopy