package agent

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"security-agent/internal/ai"
	"security-agent/internal/models"
	"security-agent/internal/scanner"
	"security-agent/internal/scheduler"
	"security-agent/internal/storage"
)

// TicketStore 是智能体侧工单仓储的最小接口（便于在单测中注入内存桩）。
// storage.TicketRepository 已实现这些方法，可直接赋值给 Deps.TicketRepo。
type TicketStore interface {
	Create(ticket *models.Ticket) error
	List(status, scanJobID string) ([]*models.Ticket, error)
	FindByFingerprint(fp string) (*models.Ticket, error)
	UpdateStatus(id, status string) error
	AddNotes(id, notes string) error
}

// Deps 是工具执行所需的平台依赖集合。直连本平台数据库与平台服务，
// 实现「连接并分析本平台数据库中的数据」与「执行平台内复杂多步骤任务」。
type Deps struct {
	Store       *storage.Neo4jStore
	Engine      *scanner.Engine
	Sched       *scheduler.Scheduler
	AI         *ai.Manager
	DomainRepo  *storage.DomainRepository
	VulnRepo    *storage.VulnerabilityRepository
	SensRepo    *storage.SensitiveInfoRepository
	RuleRepo    *storage.InspectionRuleRepository
	RecordRepo  *storage.InspectionRecordRepository
	AlertRepo   *storage.AlertRepository
	TicketRepo   TicketStore
	ScanJobRepo *storage.ScanJobRepository
	TaskRepo    *taskRepo // 任务仓储：读取近期自主任务供「复盘/重跑」

	// VulnLister / SensLister 为可注入的列表查询函数，便于在单测中提供内存桩数据；
	// 缺省为 nil，此时 listVulns / listSens 回退到基于 Neo4j 的 listVulnerabilities / listSensitiveInfo。
	VulnLister func(domainID string, limit int) (string, error)
	SensLister func(domainID string, limit int) (string, error)
}

// listVulns 返回目标域名的漏洞列表 JSON；VulnLister 为空时回退到 Neo4j 查询。
func (d Deps) listVulns(domainID string, limit int) (string, error) {
	if d.VulnLister != nil {
		return d.VulnLister(domainID, limit)
	}
	return d.listVulnerabilities(domainID, "", limit)
}

// listVulnsByJobs 返回目标域名在指定扫描作业集合内的漏洞列表 JSON（缺陷 E 修复）。
func (d Deps) listVulnsByJobs(domainID string, jobSet map[string]bool, limit int) (string, error) {
	// VulnLister 为单测桩，不支持按作业过滤，回退到全量查询
	if d.VulnLister != nil {
		return d.VulnLister(domainID, limit)
	}
	return d.listVulnerabilitiesByJobs(domainID, jobSet, limit)
}

// listSens 返回目标域名的敏感信息列表 JSON；SensLister 为空时回退到 Neo4j 查询。
func (d Deps) listSens(domainID string, limit int) (string, error) {
	if d.SensLister != nil {
		return d.SensLister(domainID, limit)
	}
	return d.listSensitiveInfo(domainID, limit)
}

// listSensByJobs 返回目标域名在指定扫描作业集合内的敏感信息列表 JSON（缺陷 E 修复）。
func (d Deps) listSensByJobs(domainID string, jobSet map[string]bool, limit int) (string, error) {
	// SensLister 为单测桩，不支持按作业过滤，回退到全量查询
	if d.SensLister != nil {
		return d.SensLister(domainID, limit)
	}
	return d.listSensitiveInfoByJobs(domainID, jobSet, limit)
}

// RegisterBuiltinTools 注册全部内置工具（只读分析 + 平台动作 + 弱口令探测）。
func RegisterBuiltinTools(reg *ToolRegistry, d Deps) {
	registerReadOnlyTools(reg, d)
	registerActionTools(reg, d)
	registerWeakPassTools(reg, d)
}

// ---------- 只读分析工具 ----------

func registerReadOnlyTools(reg *ToolRegistry, d Deps) {
	reg.Register(toolFunc{
		name:        "get_stats",
		description: "返回仪表盘聚合统计：域名数、累计扫描次数、去重后漏洞数（按高/中/低）、敏感信息数、待处理告警数。",
		schema:      map[string]any{"type": "object", "properties": map[string]any{}},
		fn: func(ctx context.Context, args map[string]any) (string, error) {
			return d.getStats(ctx)
		},
	})

	reg.Register(toolFunc{
		name:        "list_domains",
		description: "列出全部已登记域名（含 id/name/status/max_depth/max_pages）。",
		schema:      map[string]any{"type": "object", "properties": map[string]any{}},
		fn: func(ctx context.Context, args map[string]any) (string, error) {
			domains, err := d.DomainRepo.List()
			if err != nil {
				return "", err
			}
			return toJSON(domains), nil
		},
	})

	reg.Register(toolFunc{
		name:        "get_domain",
		description: "按 id 查询单个域名详情。",
		schema: map[string]any{"type": "object", "properties": map[string]any{
			"id": map[string]any{"type": "string", "description": "域名节点 id"}}},
		fn: func(ctx context.Context, args map[string]any) (string, error) {
			id := getString(args, "id")
			if id == "" {
				return "", fmt.Errorf("缺少参数 id")
			}
			dom, err := d.DomainRepo.GetByID(id)
			if err != nil {
				return "", err
			}
			return toJSON(dom), nil
		},
	})

	reg.Register(toolFunc{
		name:        "list_vulnerabilities",
		description: "按域名/严重度过滤列出漏洞（默认最近 50 条，最大 200）。",
		schema: map[string]any{"type": "object", "properties": map[string]any{
			"domain_id": map[string]any{"type": "string"},
			"severity":  map[string]any{"type": "string", "description": "high/medium/low"},
			"limit":     map[string]any{"type": "integer"},
		}},
		fn: func(ctx context.Context, args map[string]any) (string, error) {
			return d.listVulnerabilities(getString(args, "domain_id"), getString(args, "severity"), getInt(args, "limit", 50))
		},
	})

	reg.Register(toolFunc{
		name:        "get_vulnerability",
		description: "按 id 查询单个漏洞详情。",
		schema: map[string]any{"type": "object", "properties": map[string]any{
			"id": map[string]any{"type": "string"}}},
		fn: func(ctx context.Context, args map[string]any) (string, error) {
			id := getString(args, "id")
			if id == "" {
				return "", fmt.Errorf("缺少参数 id")
			}
			v, err := d.VulnRepo.GetByID(id)
			if err != nil {
				return "", err
			}
			return toJSON(v), nil
		},
	})

	reg.Register(toolFunc{
		name:        "list_sensitive_info",
		description: "按域名过滤列出敏感信息泄露（默认最近 50 条，最大 200）。",
		schema: map[string]any{"type": "object", "properties": map[string]any{
			"domain_id": map[string]any{"type": "string"},
			"limit":     map[string]any{"type": "integer"},
		}},
		fn: func(ctx context.Context, args map[string]any) (string, error) {
			return d.listSensitiveInfo(getString(args, "domain_id"), getInt(args, "limit", 50))
		},
	})

	reg.Register(toolFunc{
		name:        "list_inspection_rules",
		description: "列出全部 AI 巡检规则（含域名、cron、模型、启用状态）。",
		schema:      map[string]any{"type": "object", "properties": map[string]any{}},
		fn: func(ctx context.Context, args map[string]any) (string, error) {
			rules, err := d.RuleRepo.List()
			if err != nil {
				return "", err
			}
			return toJSON(rules), nil
		},
	})

	reg.Register(toolFunc{
		name:        "list_inspection_records",
		description: "按域名/规则/状态过滤列出巡检记录。",
		schema: map[string]any{"type": "object", "properties": map[string]any{
			"domain_id": map[string]any{"type": "string"},
			"rule_id":   map[string]any{"type": "string"},
			"status":    map[string]any{"type": "string"},
			"limit":     map[string]any{"type": "integer"},
		}},
		fn: func(ctx context.Context, args map[string]any) (string, error) {
			recs, err := d.RecordRepo.List(getString(args, "domain_id"), getString(args, "rule_id"),
				getString(args, "status"), getInt(args, "limit", 50))
			if err != nil {
				return "", err
			}
			return toJSON(recs), nil
		},
	})

	reg.Register(toolFunc{
		name:        "get_inspection_record",
		description: "按 id 查询单次巡检记录（含状态、风险等级、摘要、结构化结果）。",
		schema: map[string]any{"type": "object", "properties": map[string]any{
			"id": map[string]any{"type": "string"}}},
		fn: func(ctx context.Context, args map[string]any) (string, error) {
			id := getString(args, "id")
			if id == "" {
				return "", fmt.Errorf("缺少参数 id")
			}
			rec, err := d.RecordRepo.GetByID(id)
			if err != nil {
				return "", err
			}
			return toJSON(rec), nil
		},
	})

	reg.Register(toolFunc{
		name:        "list_alerts",
		description: "列出告警（可按状态过滤，默认 50 条）。",
		schema: map[string]any{"type": "object", "properties": map[string]any{
			"status": map[string]any{"type": "string", "description": "new/acknowledged/resolved/false_positive"},
			"limit":  map[string]any{"type": "integer"},
		}},
		fn: func(ctx context.Context, args map[string]any) (string, error) {
			status := getString(args, "status")
			limit := getInt(args, "limit", 50)
			alerts, err := d.AlertRepo.List(limit, 0)
			if err != nil {
				return "", err
			}
			if status == "" {
				return toJSON(alerts), nil
			}
			out := make([]any, 0)
			for _, a := range alerts {
				if a.Status == status {
					out = append(out, a)
				}
			}
			return toJSON(out), nil
		},
	})

	reg.Register(toolFunc{
		name:        "list_tickets",
		description: "列出安全工单（可按状态过滤，默认 50 条）。",
		schema: map[string]any{"type": "object", "properties": map[string]any{
			"status": map[string]any{"type": "string"},
			"limit":  map[string]any{"type": "integer"},
		}},
		fn: func(ctx context.Context, args map[string]any) (string, error) {
			tickets, err := d.TicketRepo.List(getString(args, "status"), "")
			if err != nil {
				return "", err
			}
			return toJSON(tickets), nil
		},
	})

	reg.Register(toolFunc{
		name:        "get_current_time",
		description: "查询服务器当前时间（RFC3339 格式 + Unix 时间戳），用于计算定时任务、延时扫描与「今晚 20:00」类场景的目标时刻。",
		schema:      map[string]any{"type": "object", "properties": map[string]any{}},
		fn: func(ctx context.Context, args map[string]any) (string, error) {
			now := time.Now()
			return toJSON(map[string]any{
				"now_rfc3339": now.Format(time.RFC3339),
				"now_unix":    now.Unix(),
				"now_local":   now.Format("2006-01-02 15:04:05"),
				"timezone":    now.Location().String(),
			}), nil
		},
	})

	reg.Register(toolFunc{
		name:        "list_recent_tasks",
		description: "读取近期自主智能体任务（目标/状态/结论/时间），用于「把昨天的主要任务重新干一遍」类复盘场景。可按回溯小时数过滤（如 24=近一天，0=全部）。",
		schema: map[string]any{"type": "object", "properties": map[string]any{
			"hours_back": map[string]any{"type": "integer", "description": "仅返回最近 N 小时内创建的任务（0=不限）"},
			"limit":      map[string]any{"type": "integer", "description": "最多返回条数（默认 20，上限 100）"},
		}},
		fn: func(ctx context.Context, args map[string]any) (string, error) {
			if d.TaskRepo == nil {
				return "", fmt.Errorf("任务仓储未初始化")
			}
			limit := getInt(args, "limit", 20)
			if limit <= 0 || limit > 100 {
				limit = 20
			}
			hoursBack := getInt(args, "hours_back", 0)
			tasks, err := d.TaskRepo.List(limit)
			if err != nil {
				return "", err
			}
			if hoursBack > 0 {
				cutoff := time.Now().Add(-time.Duration(hoursBack) * time.Hour)
				filtered := make([]*Task, 0, len(tasks))
				for _, t := range tasks {
					if t != nil && t.CreatedAt.After(cutoff) {
						filtered = append(filtered, t)
					}
				}
				tasks = filtered
			}
			// 精简字段，避免把对话上下文整段塞回
			out := make([]map[string]any, 0, len(tasks))
			for _, t := range tasks {
				if t == nil {
					continue
				}
				out = append(out, map[string]any{
					"id":         t.ID,
					"goal":       t.Goal,
					"status":     string(t.Status),
					"result":     truncate(t.Result, 300),
					"created_at": t.CreatedAt.Format(time.RFC3339),
					"turns":      t.Turns,
				})
			}
			return toJSON(map[string]any{"count": len(out), "tasks": out}), nil
		},
	})

	reg.Register(toolFunc{
		name:        "query_neo4j",
		description: "执行只读 Cypher 查询（MATCH/RETURN/WITH/OPTIONAL MATCH/UNWIND），用于自定义聚合与推理。禁止任何写操作。",
		schema: map[string]any{"type": "object", "properties": map[string]any{
			"cypher": map[string]any{"type": "string", "description": "只读 Cypher 语句"}}},
		fn: func(ctx context.Context, args map[string]any) (string, error) {
			cypher := getString(args, "cypher")
			if cypher == "" {
				return "", fmt.Errorf("缺少参数 cypher")
			}
			return d.runReadOnlyCypher(cypher)
		},
	})
}

// ---------- 只读查询实现 ----------

func (d Deps) getStats(ctx context.Context) (string, error) {
	if d.Store == nil {
		return "", fmt.Errorf("数据库未初始化")
	}
	session := d.Store.Session()
	defer session.Close()
	const q = `
		MATCH (d:Domain) WITH count(d) AS domains
		OPTIONAL MATCH (j:ScanJob) WITH domains, count(j) AS scans
		OPTIONAL MATCH (v:Vulnerability) WITH domains, scans, count(v) AS total_vulns
		CALL {
			OPTIONAL MATCH (vv:Vulnerability)
			WITH DISTINCT COALESCE(vv.fingerprint, vv.id) AS fp, vv.severity AS sev
			RETURN count(fp) AS deduped,
				sum(CASE WHEN sev = 'high' THEN 1 ELSE 0 END) AS high,
				sum(CASE WHEN sev = 'medium' THEN 1 ELSE 0 END) AS medium,
				sum(CASE WHEN sev = 'low' THEN 1 ELSE 0 END) AS low
		}
		OPTIONAL MATCH (s:SensitiveInfo) WITH domains, scans, total_vulns, deduped, high, medium, low, count(s) AS sensitive
		OPTIONAL MATCH (a:Alert) WHERE a.status IN ['new','acknowledged']
		WITH domains, scans, total_vulns, deduped, high, medium, low, sensitive, count(a) AS pending_alerts
		RETURN domains, scans, total_vulns, deduped, high, medium, low, sensitive, pending_alerts`
	res, err := session.Run(q, nil)
	if err != nil {
		return "", err
	}
	stats := map[string]any{
		"domains": 0, "scans": 0, "total_vulnerabilities": 0, "deduped_vulnerabilities": 0,
		"high_severity": 0, "medium_severity": 0, "low_severity": 0, "sensitive_found": 0, "pending_alerts": 0,
	}
	if res.Next() {
		rec := res.Record()
		if v, ok := rec.Get("domains"); ok {
			stats["domains"] = toIntAny(v)
		}
		if v, ok := rec.Get("scans"); ok {
			stats["scans"] = toIntAny(v)
		}
		if v, ok := rec.Get("total_vulns"); ok {
			stats["total_vulnerabilities"] = toIntAny(v)
		}
		if v, ok := rec.Get("deduped"); ok {
			stats["deduped_vulnerabilities"] = toIntAny(v)
		}
		if v, ok := rec.Get("high"); ok {
			stats["high_severity"] = toIntAny(v)
		}
		if v, ok := rec.Get("medium"); ok {
			stats["medium_severity"] = toIntAny(v)
		}
		if v, ok := rec.Get("low"); ok {
			stats["low_severity"] = toIntAny(v)
		}
		if v, ok := rec.Get("sensitive"); ok {
			stats["sensitive_found"] = toIntAny(v)
		}
		if v, ok := rec.Get("pending_alerts"); ok {
			stats["pending_alerts"] = toIntAny(v)
		}
	}
	return toJSON(stats), nil
}

func (d Deps) listVulnerabilities(domainID, severity string, limit int) (string, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	q := "MATCH (v:Vulnerability) WHERE true"
	params := map[string]any{}
	if domainID != "" {
		q += " AND v.domain_id = $domain_id"
		params["domain_id"] = domainID
	}
	if severity != "" {
		q += " AND v.severity = $severity"
		params["severity"] = strings.ToLower(severity)
	}
	q += " RETURN v ORDER BY v.severity DESC, v.found_at DESC LIMIT $limit"
	params["limit"] = limit
	session := d.Store.Session()
	defer session.Close()
	res, err := session.Run(q, params)
	if err != nil {
		return "", err
	}
	return nodesToJSON(res, "v")
}

// listVulnerabilitiesByJobs 返回目标域名在指定扫描作业集合内的漏洞列表（缺陷 E 修复）。
func (d Deps) listVulnerabilitiesByJobs(domainID string, jobSet map[string]bool, limit int) (string, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if len(jobSet) == 0 {
		// 无作业集合，回退到全量查询
		return d.listVulnerabilities(domainID, "", limit)
	}
	// 构建 scan_job_id IN [...] 条件
	jobList := make([]string, 0, len(jobSet))
	for j := range jobSet {
		jobList = append(jobList, j)
	}
	q := "MATCH (v:Vulnerability) WHERE v.domain_id = $domain_id AND v.scan_job_id IN $job_ids"
	params := map[string]any{
		"domain_id": domainID,
		"job_ids":   jobList,
		"limit":     limit,
	}
	q += " RETURN v ORDER BY v.severity DESC, v.found_at DESC LIMIT $limit"
	session := d.Store.Session()
	defer session.Close()
	res, err := session.Run(q, params)
	if err != nil {
		return "", err
	}
	return nodesToJSON(res, "v")
}

func (d Deps) listSensitiveInfo(domainID string, limit int) (string, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	q := "MATCH (s:SensitiveInfo) WHERE true"
	params := map[string]any{}
	if domainID != "" {
		q += " AND s.domain_id = $domain_id"
		params["domain_id"] = domainID
	}
	q += " RETURN s ORDER BY s.found_at DESC LIMIT $limit"
	params["limit"] = limit
	session := d.Store.Session()
	defer session.Close()
	res, err := session.Run(q, params)
	if err != nil {
		return "", err
	}
	return nodesToJSON(res, "s")
}

// listSensitiveInfoByJobs 返回目标域名在指定扫描作业集合内的敏感信息列表（缺陷 E 修复）。
func (d Deps) listSensitiveInfoByJobs(domainID string, jobSet map[string]bool, limit int) (string, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if len(jobSet) == 0 {
		// 无作业集合，回退到全量查询
		return d.listSensitiveInfo(domainID, limit)
	}
	// 构建 scan_job_id IN [...] 条件
	jobList := make([]string, 0, len(jobSet))
	for j := range jobSet {
		jobList = append(jobList, j)
	}
	q := "MATCH (s:SensitiveInfo) WHERE s.domain_id = $domain_id AND s.scan_job_id IN $job_ids"
	params := map[string]any{
		"domain_id": domainID,
		"job_ids":   jobList,
		"limit":     limit,
	}
	q += " RETURN s ORDER BY s.found_at DESC LIMIT $limit"
	session := d.Store.Session()
	defer session.Close()
	res, err := session.Run(q, params)
	if err != nil {
		return "", err
	}
	return nodesToJSON(res, "s")
}

// runReadOnlyCypher 执行只读 Cypher 并返回表格 JSON（最多 200 行）。
func (d Deps) runReadOnlyCypher(cypher string) (string, error) {
	if err := assertReadOnly(cypher); err != nil {
		return "", err
	}
	session := d.Store.Session()
	defer session.Close()
	res, err := session.Run(cypher, nil)
	if err != nil {
		return "", err
	}
	rows := make([]map[string]any, 0)
	limit := 200
	n := 0
	for res.Next() {
		rec := res.Record()
		row := map[string]any{}
		for _, key := range rec.Keys {
			if v, ok := rec.Get(key); ok {
				row[key] = convertNeo4jVal(v)
			}
		}
		rows = append(rows, row)
		n++
		if n >= limit {
			break
		}
	}
	if err := res.Err(); err != nil {
		return "", err
	}
	return toJSON(map[string]any{"count": n, "truncated": n >= limit, "rows": rows}), nil
}

// readonlyWriteKWRe 匹配写操作关键字（关键字须以空白或语句起始为前缀，避免 CREATE( 绕过，
// 也避免把 :Create 这类节点标签误判为写操作）。
var readonlyWriteKWRe = regexp.MustCompile(`(?i)(?:^|\s)(CREATE|MERGE|DELETE|DETACH|DROP|SET|REMOVE|INSERT|FOREACH|LOAD|UNION|USE|PERIODIC\s+COMMIT)\b`)

// assertReadOnly 确保 Cypher 仅含只读语义，禁止任何写操作或分号拼接。
// 防御目标：query_neo4j 工具的沙箱化只读查询，避免模型通过关键字拼接/绕过修改图库。
// 允许的只读结构：MATCH / OPTIONAL MATCH / WITH / RETURN / UNWIND / CALL { 子查询 } /
// ORDER BY / SKIP / LIMIT / AS / WHERE / YIELD。
func assertReadOnly(cypher string) error {
	// 1) 禁止语句拼接（含全角分号）
	for _, sep := range []string{";", "；"} {
		if strings.Contains(cypher, sep) {
			return fmt.Errorf("仅允许单条只读语句，禁止分号拼接")
		}
	}

	// 2) 写操作关键字（正则单词边界，避免 CREATE( / CREATE\t 之类绕过）
	if readonlyWriteKWRe.MatchString(cypher) {
		return fmt.Errorf("仅允许只读查询，禁止包含写操作关键字（CREATE/MERGE/DELETE/SET/REMOVE/DROP/FOREACH/LOAD 等）")
	}

	// 3) CALL 仅允许纯读子查询 CALL { ... }，禁止调用任何过程（db.* / apoc.* 等有副作用）
	if strings.Contains(strings.ToUpper(cypher), "CALL") {
		compact := strings.ToUpper(strings.ReplaceAll(cypher, " ", ""))
		if !strings.Contains(compact, "CALL{") {
			return fmt.Errorf("仅允许只读查询，禁止调用存储过程（CALL <proc>）；只读子查询请使用 CALL { ... } 形式")
		}
	}

	return nil
}

// ---------- Neo4j 值转换 ----------

func nodesToJSON(res neo4j.Result, key string) (string, error) {
	rows := make([]map[string]any, 0)
	limit := 200
	n := 0
	for res.Next() {
		if v, ok := res.Record().Get(key); ok {
			if node, ok := v.(neo4j.Node); ok {
				row := map[string]any{"id": getStr(node.Props, "id")}
				for k, val := range node.Props {
					if k == "id" {
						continue
					}
					row[k] = convertNeo4jVal(val)
				}
				rows = append(rows, row)
				n++
			}
		}
		if n >= limit {
			break
		}
	}
	if err := res.Err(); err != nil {
		return "", err
	}
	return toJSON(map[string]any{"count": n, "rows": rows}), nil
}

func convertNeo4jVal(v any) any {
	switch x := v.(type) {
	case neo4j.Node:
		return map[string]any{"labels": x.Labels, "props": x.Props}
	case neo4j.Relationship:
		return map[string]any{"type": x.Type, "props": x.Props, "start": x.StartId, "end": x.EndId}
	case neo4j.Path:
		nodes := make([]any, len(x.Nodes))
		for i, n := range x.Nodes {
			nodes[i] = convertNeo4jVal(n)
		}
		rels := make([]any, len(x.Relationships))
		for i, r := range x.Relationships {
			rels[i] = convertNeo4jVal(r)
		}
		return map[string]any{"nodes": nodes, "relationships": rels}
	case []any:
		return convertSlice(x)
	default:
		return v
	}
}

func convertSlice(s []any) []any {
	out := make([]any, len(s))
	for i, e := range s {
		out[i] = convertNeo4jVal(e)
	}
	return out
}

func toIntAny(v any) int {
	switch x := v.(type) {
	case int64:
		return int(x)
	case int:
		return x
	case float64:
		return int(x)
	}
	return 0
}
