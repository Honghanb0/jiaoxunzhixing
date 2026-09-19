# 恒脑「API 工具」注册清单

> 由线上 `/api/open/tools` 实时生成，共 **27** 个工具。

## 一、这份清单是干什么的

把本平台的智能体工具注册成恒脑的「API 工具」，恒脑侧编排的智能体就能调用我们的
扫描 / 检索能力（对应《企业命题》答题要求⑥ 的编排侧落地）。

## 二、⚠️ 关键概念（实测踩出来的，务必先读）

**恒脑的模型是「一个 API 工具 = 一个服务」，工具里再分「能力」= 一个个接口。**

| 项 | 结论 |
|---|---|
| 请求地址 | **只能填基础地址，不能带路径**（带路径会报"请求地址不能包含路径"）|
| 接口路径 | 在「能力」里单独填，如 `/api/open/tools/list_domains` |
| 能力数量上限 | **每个 API 工具最多 20 个能力** → 本清单 27 个工具需拆成 **2 个 API 工具** |
| 能力导入 | 支持**粘贴 cURL 命令**自动填充路径/方法/请求头，是最快的注册方式 |
| 调试状态 | 走完 3 步向导会自动真实调用一次并填入输出参数——**绿勾即代表已打通** |

## 三、注册步骤（已实测跑通）

1. 恒脑 → 安全智能体开发 → **API工具** → **创建**
2. 填写：名称（如「交巡智星-巡检工具」）、描述、**请求地址填 `http://124.221.227.243`**（不带路径）
3. 点 **保存并配置能力** → 进入「工具能力配置」
4. 点 **能力导入**，粘贴下面这条 cURL（把 `<服务密钥>` 换成真实值）：

   ```bash
   curl -X POST 'http://124.221.227.243/api/open/tools/list_domains' \
     -H 'Content-Type: application/json' \
     -H 'X-API-Key: <服务密钥>' -d '{}'
   ```

5. 点 **提交** → 填「能力名称」「能力描述」→ 再 **提交**
6. 重复 4-5 注册其余能力（**每个 API 工具最多 20 个**，超了就再建一个工具）
7. 完成后点右上角 **发布**，可见范围选「租户共享」→ 提交

**服务密钥**：由部署方在 `config.yaml` 的 `open_service.api_key` 配置（推荐用环境变量
`OPEN_SERVICE_API_KEY` 注入）。出于安全考虑不在本文档中明文给出，向部署同学索取。

⚠️ 密钥与平台用户 JWT 是**两套鉴权**：前者面向机器调用（恒脑），后者面向前端用户。

## 四、已验证的链路

实测已跑通（2026-09-19）：

```
恒脑平台服务器 (183.129.153.157)
      └─► POST http://124.221.227.243/api/open/tools/list_domains   返回 200
          └─► 恒脑侧「调试状态」显示绿勾，并自动填入输出参数
```

对应我们服务器侧审计日志：

```
[OpenService] POST /api/open/tools/list_domains -> 200 (1ms) ip=183.129.153.157 auth=有
```

> 该审计日志由 `internal/api/open_audit.go` 输出，可用它排查"恒脑是否真的调过来了"。

## 五、接口约定

**请求**：`POST http://124.221.227.243/api/open/tools/<工具名>`，请求头 `X-API-Key: <服务密钥>`，
body 为该工具的入参 JSON 对象（无参传 `{}`）。

**响应**：`{"ok":true,"name":"<工具名>","result":"<工具输出>"}`
或 `{"ok":false,"name":"<工具名>","error":"<失败原因>"}`。
`result` 是工具输出的文本（通常是 JSON 字符串），可作为工具观察结果继续推理。

## 六、工具清单

| # | 工具名 | 说明 | 入参 |
|---|---|---|---|
| 1 | `get_stats` | 返回仪表盘聚合统计：域名数、累计扫描次数、去重后漏洞数（按高/中/低）、敏感信息数、待处理告警数。 | 无 |
| 2 | `list_domains` | 列出全部已登记域名（含 id/name/status/max_depth/max_pages）。 | 无 |
| 3 | `get_domain` | 按 id 查询单个域名详情。 | `id`:string(可选) |
| 4 | `list_vulnerabilities` | 按域名/严重度过滤列出漏洞（默认最近 50 条，最大 200）。 | `domain_id`:string(可选)、`limit`:integer(可选)、`severity`:string(可选) |
| 5 | `get_vulnerability` | 按 id 查询单个漏洞详情。 | `id`:string(可选) |
| 6 | `list_sensitive_info` | 按域名过滤列出敏感信息泄露（默认最近 50 条，最大 200）。 | `domain_id`:string(可选)、`limit`:integer(可选) |
| 7 | `list_inspection_rules` | 列出全部 AI 巡检规则（含域名、cron、模型、启用状态）。 | 无 |
| 8 | `list_inspection_records` | 按域名/规则/状态过滤列出巡检记录。 | `domain_id`:string(可选)、`limit`:integer(可选)、`rule_id`:string(可选)、`status`:string(可选) |
| 9 | `get_inspection_record` | 按 id 查询单次巡检记录（含状态、风险等级、摘要、结构化结果）。 | `id`:string(可选) |
| 10 | `list_alerts` | 列出告警（可按状态过滤，默认 50 条）。 | `limit`:integer(可选)、`status`:string(可选) |
| 11 | `list_tickets` | 列出安全工单（可按状态过滤，默认 50 条）。 | `limit`:integer(可选)、`status`:string(可选) |
| 12 | `get_current_time` | 查询服务器当前时间（RFC3339 格式 + Unix 时间戳），用于计算定时任务、延时扫描与「今晚 20:00」类场景的目标时刻。 | 无 |
| 13 | `list_recent_tasks` | 读取近期自主智能体任务（目标/状态/结论/时间），用于「把昨天的主要任务重新干一遍」类复盘场景。可按回溯小时数过滤（如 24=近一天，0=全部）。 | `hours_back`:integer(可选)、`limit`:integer(可选) |
| 14 | `query_neo4j` | 执行只读 Cypher 查询（MATCH/RETURN/WITH/OPTIONAL MATCH/UNWIND），用于自定义聚合与推理。禁止任何写操作。 | `cypher`:string(可选) |
| 15 | `start_scan` | 对指定域名发起一次安全扫描，返回扫描任务 ID（异步执行，需用 get_scan_status / wait_scan 跟进）。 | `domain_id`:string(可选) |
| 16 | `get_scan_status` | 查询扫描任务进度（状态/阶段/已爬页数/已发现漏洞数）。 | `scan_job_id`:string(可选) |
| 17 | `wait_scan` | 阻塞等待扫描任务完成（超时秒数默认 120，上限 300），返回扫描结果摘要（页面数/漏洞分级/敏感信息）。 | `scan_job_id`:string(可选)、`timeout_sec`:integer(可选) |
| 18 | `run_inspection_rule` | 由自主智能体触发一条 AI 巡检规则，标记为 agent 来源并返回巡检记录 ID（异步执行，用 get_inspection_record 跟进）。结果判定会区分智能体可用(success)/不可用(仅兜底扫描成功才 partial)。 | `rule_id`:string(可选) |
| 19 | `create_ticket` | 创建一条安全工单（结果回写）。可由巡检发现或分析结论生成，便于后续处置跟踪。支持所有漏洞类型（注入/权限配置/组件/逻辑/信息泄露/数据泄露/弱口令/未知类型），缺失字段将以可追溯默认值补齐。 | `asset_name`:string(可选)、`asset_url`:string(可选)、`description`:string(可选)、`evidence`:string(可选)、`fingerprint`:string(可选)、`harm_description`:string(可选)、`mitigation_measures`:string(可选)、`remediation_priority`:string(可选)、`retest_method`:string(可选)、`risk_level`:string(可选)、`scan_job_id`:string(可选)、`source`:string(可选)、`title`:string(可选)、`vuln_description`:string(可选)、`vuln_id`:string(可选)、`vuln_name`:string(可选)、`vuln_type`:string(可选) |
| 20 | `update_ticket_status` | 更新工单状态（pending/confirmed/excluded/resolved），可选追加处理备注。 | `note`:string(可选)、`status`:string(可选)、`ticket_id`:string(可选) |
| 21 | `create_inspection_rule` | 创建一条巡检规则（结果回写/规划）。平台将按 cron 周期自动对绑定资产执行「扫描 + 本地兜底评估」，支持多资产绑定（domain_ids 数组，一次配置多域名同周期巡检）。AI 研判交由自主智能体执行。 | `alert_on_failure`:boolean(可选)、`domain_id`:string(可选)、`domain_ids`:array(可选)、`name`:string(可选)、`run_scan`:boolean(可选)、`schedule`:string(可选)、`severity_threshold`:string(可选) |
| 22 | `delete_inspection_rule` | 删除一条巡检规则（并即时从调度器摘除定时任务）。适用于「就扫一次，之后不要扫了」：先创建/触发一次性扫描，完成后调用本工具清理规则，避免后续周期重复执行。 | `rule_id`:string(可选) |
| 23 | `send_alert` | 创建一条告警（结果回写）。可用于把重大风险主动推送出来。 | `content`:string(可选)、`domain_id`:string(可选)、`scan_job_id`:string(可选)、`severity`:string(可选)、`title`:string(可选)、`type`:string(可选) |
| 24 | `create_domain` | 新建一个巡检/扫描域名（结果回写）。会做格式与 DNS 可解析性校验，校验通过后才落库；可用于编排「先建域名、再建巡检规则、最后触发巡检」的完整流程。 | `description`:string(可选)、`max_depth`:integer(可选)、`max_pages`:integer(可选)、`name`:string(可选) |
| 25 | `manage_password_dict` | 弱口令字典管理：列出/追加/查看/重置/从文件加载口令字典（内置 users、passwords）。用于为弱口令扫描准备或扩充字典。action=list 列出全部字典及词条数；action=show 查看某字典内容；action=add 向某字典追加词条；action=reset 重置为内置值；action=load 从文件载入词条。 | `action`:string(可选)、`dict`:string(可选)、`limit`:integer(可选)、`source_file`:string(可选)、`words`:array(可选) |
| 26 | `weak_password_scan` | 对目标服务的弱口令探测：用「用户名×口令」字典发起并发登录尝试，命中即记录有效凭据并默认二次复验。需显式提供 target（host 或 host:port）与 service（ssh/ftp/pop3/smtp/redis/http）。未提供 usernames/passwords 时自动使用内置 users/passwords 字典；可用 use_dict 指定单一字典名。注意：仅可在授权范围内对目标发起探测，禁止对未授权目标扫描。命中结果建议经 create_ticket / send_alert 回写。 | `concurrency`:integer(可选)、`passwords`:array(可选)、`service`:string(可选)、`stop_on_first`:boolean(可选)、`target`:string(可选)、`timeout_sec`:integer(可选)、`use_dict`:string(可选)、`usernames`:array(可选)、`verify`:boolean(可选) |
| 27 | `verify_credentials` | 对单条「用户名+口令」做有效性验证（确认该凭据能否登录目标服务）。用于复验弱口令扫描的命中项，或人工指定凭据的即时判定。返回 authenticated 布尔与所用 service/target/username。 | `password`:string(可选)、`service`:string(可选)、`target`:string(可选)、`timeout_sec`:integer(可选)、`username`:string(可选) |

## 七、接入状态

- [x] 后端对外工具服务已实现并验证（`GET /api/open/tools`、`POST /api/open/tools/:name`）
- [x] 服务密钥鉴权（`X-API-Key`，定长比较防时序侧信道）+ 调用审计日志
- [x] 流程控制类工具默认不外露（`finish_task` / `wait` / `wait_until`）
- [x] 恒脑侧已注册并发布 1 个 API 工具 + 1 个能力（`list_domains`），调试状态绿勾、链路打通
- [ ] 其余工具按上面步骤补齐（每个 API 工具上限 20 个能力）

## 八、验证方法

```bash
# 拉清单
curl -s http://124.221.227.243/api/open/tools -H 'X-API-Key: <服务密钥>'

# 执行一个读类工具
curl -s -X POST http://124.221.227.243/api/open/tools/list_domains \
  -H 'X-API-Key: <服务密钥>' -H 'Content-Type: application/json' -d '{}'
```
