# 交巡智星——面向网站安全风险评估与敏感信息防泄露的智能巡检智能体

> 一个融合「自动化漏洞扫描 + 大语言模型（LLM）智能研判」的网站安全风险评估与敏感信息防泄露巡检平台。
> 后端 Go + Gin + Neo4j，前端为单文件 SPA；通过 AI 巡检规则把「爬取 → 检测 → AI 风险分级 → 工单」串成闭环。

---

![Logo](logo.jpeg)

## 一、平台定位

交巡智星（简称「交巡智星」）面向**授权范围内的网站资产**，提供：

- **安全风险评估**：自动发现页面与接口，检测 SQL 注入、XSS、敏感文件泄露、页面篡改、敏感信息泄露（关键词/正则）等风险。
- **敏感信息防泄露**：基于关键词与正则规则识别源码、私钥、配置、账号口令等敏感数据外泄。
- **AI 智能研判**：将扫描结果交给 DeepSeek / Kimi / GLM 等兼容 OpenAI 协议的模型，自动完成风险定级、归因分析与处置建议。
- **可审计的闭环**：漏洞去重统计、误报工单、分级权限、CLI 风格运行日志，便于安全运营与合规审计。

---

## 二、核心特性

- **授权域名资产管理**：对需要巡检的域名进行登记、编辑、手动扫描与删除。
- **AI 巡检规则（统一调度）**：以「巡检规则」为载体配置目标域名、AI 模型、提示词与 cron 周期；支持手动触发与定时触发，取代原先分散的域名级定时扫描，避免功能重复。
- **页面发现与资源爬取**：并发爬虫，支持深度与页面数限制、robots 协议遵从。
- **多类型漏洞检测**：SQL 注入、XSS、敏感文件泄露、页面篡改、敏感信息泄露（关键词/正则）。
- **漏洞去重与累计计数**：以「域名 + 漏洞类型 + 受影响 URL/参数」为指纹去重；Dashboard 同时展示「去重后漏洞数」与「累计扫描命中次数」。
- **AI 智能分析与风险分级**：基于 LLM 的风险等级（高/中/低）、摘要、结构化发现项与处置建议；AI 不可用时自动降级为本地兜底结果（`partial`）。
- **误报工单管理**：工单按同一去重指纹聚合，重复命中只累加命中次数与最近扫描时间，不重复建单。
- **CLI 风格日志页**：终端风格（等宽、深色、按级别着色）实时查看服务端/前端日志，支持级别/关键字/时间过滤、暂停刷新；权限等级 ≥ 2 可见。
- **多级权限控制**：4 级角色（访客/操作员/审计员/管理员），JWT 携带数值权限声明。
- **用户自助注册**：登录页支持注册普通账号（默认访客/操作员级别，由管理员按需提权）。

---

## 三、快速开始

### 3.1 环境要求

| 组件 | 版本 | 说明 |
|------|------|------|
| Go | 1.21+ | 编译运行后端 |
| Neo4j | 4.4+ | 图数据库（存储域名、漏洞、工单、巡检记录） |
| DeepSeek / Kimi / GLM API Key | — | AI 研判功能（可多供应商，OpenAI 兼容协议） |

### 3.2 安装与启动

```bash
# 1. 拉取依赖
go mod download

# 2. 配置 Neo4j 与 AI（编辑 config.yaml）
#    database.neo4j.uri / username / password
#    ai.provider / api_key / model / base_url

# 3. 编译运行
go build -o ./bin/security-agent ./cmd/server
./bin/security-agent            # 默认读取同目录 config.yaml，监听 :8080
# 或指定配置：./bin/security-agent -config config.test.yaml
```

前端为单文件 `web/index.html`，由后端 `c.File` 实时读盘返回，**修改前端无需重新编译**，硬刷新浏览器即可生效；**修改 Go 后端必须重启进程**。

### 3.3 Neo4j 启动

```bash
# Docker
docker run -d --name neo4j -p 7474:7474 -p 7687:7687 \
  -e NEO4J_AUTH=neo4j/your_password neo4j:5
```

### 3.4 首次登录

首次启动若数据库无用户，服务会自动创建管理员账号（具体凭据见 `.env.example` / 部署文档，请于首次登录后立即修改密码并妥善保管；**登录界面不再展示默认凭据**）。
新用户可在登录页点击「立即注册」自助注册普通账号。

---

## 四、用户权限模型

系统采用 4 级权限（JWT 中以数值 `rl` 声明）：

| 权限值 | 角色 | 能力 |
|--------|------|------|
| 0 | 访客 | 查看域名、扫描结果、漏洞详情（只读） |
| 1 | 操作员 | 在 0 基础上发起扫描、创建/处理工单 |
| 2 | 审计员 | 在 1 基础上查看「系统日志」页（排障/审计，只读） |
| 3 | 管理员 | 完全控制：用户管理、角色调整、AI 默认模型设定、删除数据 |

> 权限门控示例：AI 巡检规则管理 ≥ 1；系统日志页与 `/api/logs` 接口 ≥ 2；用户删除/角色调整 ≥ 3。

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
| 扫描 | POST | /api/scan/start | 发起扫描 | ≥1 |
| 扫描 | GET | /api/scan/:id/{progress,results,status,logs} | 进度/结果/状态/日志 | 认证 |
| 漏洞 | GET | /api/vulnerabilities | 漏洞列表（含去重统计） | 认证 |
| 统计 | GET | /api/stats | Dashboard 统计（去重数 + 累计命中） | 认证 |
| 工单 | GET/POST | /api/tickets | 列表 / 创建 | 认证 / ≥1 |
| 工单 | PATCH/POST | /api/tickets/:id(/notes) | 状态更新 / 备注 | ≥1 |
| AI 模型 | GET/POST | /api/admin/ai(/default) | 模型列表 / 设默认 | ≥1 / ≥3 |
| 巡检规则 | GET/POST | /api/inspections/rules | 规则列表 / 创建 | ≥1 |
| 巡检规则 | POST | /api/inspections/rules/:id/run | 手动触发巡检 | ≥1 |
| 巡检记录 | GET | /api/inspections/records | 巡检记录（状态含 running/analyzing/success/partial/failed） | 认证 |
| 调度校验 | POST | /api/schedules/validate | 校验 cron 并预览下次运行 | 认证 |
| 日志 | GET | /api/logs?after=&limit= | CLI 日志增量拉取 | ≥2 |
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

---

## 七、配置（config.yaml 要点）

```yaml
server:
  host: "0.0.0.0"
  port: 8080
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
```

环境变量：`DEEPSEEK_API_KEY`（AI 必填）、`WEBHOOK_URL`（可选）等。

---

## 八、项目结构

```
.
├── cmd/server/main.go          # 入口：装配配置、存储、调度、路由、日志
├── internal/
│   ├── api/                    # HTTP 层：server/handlers/scan_handler/inspection_handler/
│   │                           #   ticket_handler/alert_handler/ai_handler/log_handler/
│   │                           #   stats_handler/schedule_handler/auth_handler/middleware
│   ├── ai/                     # 多供应商 AI（DeepSeek/Kimi/GLM，OpenAI 兼容）
│   ├── config/                 # 配置加载
│   ├── inspection/             # 巡检 Runner（扫描 + AI 研判 + 记录/工单）
│   ├── logutil/                # 环形缓冲日志采集
│   ├── models/                 # 数据模型（用户/域名/漏洞/工单/巡检记录）
│   ├── scanner/                # 扫描引擎：engine/crawler/detector/fingerprint
│   ├── scheduler/              # 巡检规则 cron 调度 + 告警
│   └── storage/                # Neo4j 仓储：repository/user_repo/vulnerability_repo/
│                               #   ticket_repo/inspection_repo/alert_repo/neo4j
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
- **需要重置数据？** 参见仓库根目录 `reset_db.py`（独立脚本，谨慎使用，会清空图库）。

---

## 十、更新日志

### v1.0.0（2026-08-31）

初始版本发布。