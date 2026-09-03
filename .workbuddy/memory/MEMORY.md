# 项目长期记忆：shengsaizuoping（AI 安全巡检智能体）

## 技术栈
Go 1.21+ / Gin / Neo4j(golang-neo4j-driver v5) / viper / golang-jwt v5。分层：cmd/server / api / scheduler / scanner(Engine/Detector) / storage / models / inspection / ai / config / logutil / **agent(自主智能体：双层调用循环+26 工具，参考 earendil-works/pi)**。前端单文件 SPA web/index.html（router.Static("/web", webRoot) + c.File 实时读盘）。

## 关键架构事实（易踩坑）
- **巡检结果判定按 AI 相关性分类**（`inspection/runner.go` 的 `judge()`，2026-09-03 重构）：`triggered_by` 分 `schedule`/`manual`/`agent` 三类；**非 AI 相关（schedule/manual）扫描成功即 `success`**（不再一律 partial）；**agent 触发**且智能体可用（`aiMgr.Ready()` 任一供应商可用）→ `success`，**仅当智能体不可用且兜底扫描成功 → `partial`**，扫描无数据 → `failed`。原 `applyFallback` 已删除。巡检规则无 provider/model/prompt_template（AI 研判交智能体）。agent 触发入口：`scheduler.TriggerByAgent` ← 智能体工具 `run_inspection_rule`。
- **智能体工具调用是提示词协议**：要求模型输出 `<tool_calls>` 围栏+JSON 数组（`agent.go:227-234`），**不是** OpenAI function calling → 任何遵循指令的模型都能驱动循环。
- `ai.Manager` 三策略（single/fallback/parallel）；供应商常量与 BuiltinOrder 在 `ai/provider.go`，工厂 switch 在 `ai/providers.go:25-36`（新增供应商需改这两处）；`openai_compat.go:313` 端点＝base_url+`/chat/completions`。
- 多资产巡检规则：`models/inspection.go` 的 `DomainIDs` + `EffectiveDomainIDs()`，触发时按域名**并发**展开。

## 启动本机 Neo4j（重要，已踩坑）
`neo4j.ps1`/`neo4j.bat` 在本机必报 "已添加了具有相同键的项"（PowerShell 环境哈希表重复键 bug），且 PowerShell 工具禁 cmd.exe、Bash 工具禁 powershell.exe。
**绕过方案：直接 java 启动 Neo4j 服务器进程**：
- 必须 Java 21：`C:\Users\Jeff_Hong\.Neo4jDesktop2\Cache\runtime\zulu21.50.19-ca-jre21.0.11-win_x64\bin\java.exe`（zulu17 报 class version 65.0 不支持）。
- 命令：`java -cp "<HOME>\lib\*" -Dbasedir=<HOME> -Dneo4j.home=<HOME> org.neo4j.server.startup.Neo4jCommand console`
  - HOME=`C:\Users\Jeff_Hong\.Neo4jDesktop2\Data\dbmss\dbms-3fd02bb9-631f-46d3-8956-a5bb491a8aa3`
  - 类路径通配符必须用 **Windows 反斜杠** `<HOME>\lib\*`（正斜杠会 ClassNotFoundException；显式列全部 jar 超 32KB 命令行上限）。
- 子命令：console(前台)/start(守护)/status/stop。Bolt 7687、HTTP 7474。

## 服务与鉴权
- 构建：`go build -o ./bin/security-agent ./cmd/server`（go 在 /c/Program Files/Go/bin/go，1.26.6）。
- 启动：项目根目录运行，读 config.yaml，监听 0.0.0.0:8030（原 8080，2026-09-03 改）；连 neo4j://127.0.0.1:7687（user neo4j / 密码见 config.yaml:15，@Cuz123456789）。
- 登录：POST /api/auth/login（非 /api/login）；默认管理员 admin / Admin@123；鉴权头 `Authorization: Bearer <token>`。
- 受限页：/api/logs 需 rl≥2（admin rl=3 默认满足）。

## 恒脑接入（设计见 hengnao/恒脑接入.md V2）
- **红线**：自研智能体＝编排层不可删除/不可替换（强制兜底）；恒脑＝能力层优先调用，**方向是"自研兜恒脑"，不是"恒脑主、自研降级"**。
- **两套鉴权完全不同的接口**：A 类开放服务接口（appKey + HmacSHA256 sign，`/open/api/v2/agent/execute`，无工具调用能力，**不能驱动本平台循环**）；B 类 OpenAI 兼容（`Authorization: Bearer <LLMKey>`，`{host}/api/openai/v1/chat/completions`，支持 tool_calls）。
- **M1 主线**＝B 类注册为 `ai.Provider` 名 hengnao 置于 fallback_order 首位（只换大脑不换身体）；M2＝A 类作为智能体工具 `hengnao_judge`。
- **陷阱**：恒脑 B 类错误是 HTTP 200 + body `code` 非 0，而 `openai_compat.go:148/371` 只看 HTTP 状态码 → 限流会被误判为"空响应"且不重试不降级，接入前必改。
- **P0 阻塞**：LLMKey 未获取（参数.txt 只有 appKey/appSecret/userAppKey）；A/B 两类生产 base_url 未确认；异步接口路径官方自相矛盾。
- agentId 获取：平台 bug 下用 `POST /open/api/v2/agent/search`（keyword 模糊搜索）绕过，须校验命中唯一性。
- `hengnao/参数.txt` 明文存密钥，**待入 .gitignore**。
