package agent

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/url"
	"strings"
	"time"

	"security-agent/internal/models"
	"security-agent/internal/scanner"
	"security-agent/internal/scheduler"
)

// registerActionTools 注册「平台动作」类工具：发起扫描、等待扫描、触发巡检、
// 创建/更新工单与告警、创建巡检规则、结束任务。这些工具把模型的分析结论「回写」到平台，
// 形成「分析 → 行动 → 结果落库」的闭环，即复杂多步骤任务的执行能力。
func registerActionTools(reg *ToolRegistry, d Deps) {
	reg.Register(toolFunc{
		name:        "start_scan",
		description: "对指定域名发起一次安全扫描，返回扫描任务 ID（异步执行，需用 get_scan_status / wait_scan 跟进）。",
		schema: map[string]any{"type": "object", "properties": map[string]any{
			"domain_id": map[string]any{"type": "string", "description": "域名节点 id"}}},
		fn: func(ctx context.Context, args map[string]any) (string, error) {
			domainID := getString(args, "domain_id")
			if domainID == "" {
				return "", fmt.Errorf("缺少参数 domain_id")
			}
			if _, err := d.DomainRepo.GetByID(domainID); err != nil {
				return "", fmt.Errorf("域名不存在: %s", domainID)
			}
			job, err := d.Engine.Scan(domainID)
			if err != nil {
				return "", err
			}
			return toJSON(map[string]any{"scan_job_id": job.ID, "domain_id": domainID, "status": job.Status}), nil
		},
	})

	reg.Register(toolFunc{
		name:        "get_scan_status",
		description: "查询扫描任务进度（状态/阶段/已爬页数/已发现漏洞数）。",
		schema: map[string]any{"type": "object", "properties": map[string]any{
			"scan_job_id": map[string]any{"type": "string"}}},
		fn: func(ctx context.Context, args map[string]any) (string, error) {
			jobID := getString(args, "scan_job_id")
			if jobID == "" {
				return "", fmt.Errorf("缺少参数 scan_job_id")
			}
			p, err := d.Engine.GetScanProgress(jobID)
			if err != nil {
				return "", err
			}
			return toJSON(p), nil
		},
	})

	reg.Register(toolFunc{
		name:        "wait_scan",
		description: "阻塞等待扫描任务完成（超时秒数默认 120，上限 300），返回扫描结果摘要（页面数/漏洞分级/敏感信息）。",
		schema: map[string]any{"type": "object", "properties": map[string]any{
			"scan_job_id": map[string]any{"type": "string"},
			"timeout_sec": map[string]any{"type": "integer", "description": "等待超时秒数（30~300）"}}},
		fn: func(ctx context.Context, args map[string]any) (string, error) {
			jobID := getString(args, "scan_job_id")
			if jobID == "" {
				return "", fmt.Errorf("缺少参数 scan_job_id")
			}
			timeout := getInt(args, "timeout_sec", 120)
			if timeout < 30 {
				timeout = 30
			}
			if timeout > 300 {
				timeout = 300
			}
			res, err := d.Engine.WaitForScanCompletion(jobID, time.Duration(timeout)*time.Second)
			if err != nil {
				// 即使超时/失败，也尽量返回已采集的部分结果
				if res != nil {
					return toJSON(summarizeScan(res)), nil
				}
				return "", err
			}
			return toJSON(summarizeScan(res)), nil
		},
	})

	reg.Register(toolFunc{
		name:        "run_inspection_rule",
		description: "由自主智能体触发一条 AI 巡检规则，标记为 agent 来源并返回巡检记录 ID（异步执行，用 get_inspection_record 跟进）。结果判定会区分智能体可用(success)/不可用(仅兜底扫描成功才 partial)。",
		schema: map[string]any{"type": "object", "properties": map[string]any{
			"rule_id": map[string]any{"type": "string"}}},
		fn: func(ctx context.Context, args map[string]any) (string, error) {
			ruleID := getString(args, "rule_id")
			if ruleID == "" {
				return "", fmt.Errorf("缺少参数 rule_id")
			}
			recordID, err := d.Sched.TriggerByAgent(ruleID)
			if err != nil {
				return "", err
			}
			return toJSON(map[string]any{"record_id": recordID, "rule_id": ruleID}), nil
		},
	})

	reg.Register(toolFunc{
		name:        "create_ticket",
		description: "创建一条安全工单（结果回写）。可由巡检发现或分析结论生成，便于后续处置跟踪。",
		schema: map[string]any{"type": "object", "properties": map[string]any{
			"title":                map[string]any{"type": "string"},
			"risk_level":           map[string]any{"type": "string", "description": "high/medium/low"},
			"asset_name":           map[string]any{"type": "string"},
			"asset_url":            map[string]any{"type": "string"},
			"vuln_name":            map[string]any{"type": "string"},
			"description":          map[string]any{"type": "string"},
			"evidence":             map[string]any{"type": "string"},
			"harm_description":     map[string]any{"type": "string"},
			"remediation_priority": map[string]any{"type": "string", "description": "P0/P1/P2"},
			"mitigation_measures":  map[string]any{"type": "string"},
			"retest_method":        map[string]any{"type": "string"},
			"scan_job_id":          map[string]any{"type": "string"},
		}},
		fn: func(ctx context.Context, args map[string]any) (string, error) {
			log.Printf("[Agent][create_ticket] 调用开始 args=%+v", args)
			title := getString(args, "title")
			if title == "" {
				title = "智能体创建的工单"
			}
			now := time.Now()
			ticket := &models.Ticket{
				Title:               title,
				Type:                "investigation",
				Status:              models.TicketStatusPending,
				RiskLevel:           normRisk(getString(args, "risk_level")),
				AssetName:           getString(args, "asset_name"),
				AssetURL:            getString(args, "asset_url"),
				VulnName:            getString(args, "vuln_name"),
				Description:         getString(args, "description"),
				Evidence:            getString(args, "evidence"),
				HarmDescription:     getString(args, "harm_description"),
				RemediationPriority: getString(args, "remediation_priority"),
				MitigationMeasures:  getString(args, "mitigation_measures"),
				RetestMethod:        getString(args, "retest_method"),
				ScanJobID:           getString(args, "scan_job_id"),
				CreatorID:           "agent",
				Notes:               "由自主智能体创建",
				CreatedAt:           now,
				UpdatedAt:           now,
			}
			if err := d.TicketRepo.Create(ticket); err != nil {
				log.Printf("[Agent][create_ticket] 创建失败 title=%q risk=%s scan_job=%s err=%v",
					title, ticket.RiskLevel, ticket.ScanJobID, err)
				return "", err
			}
			log.Printf("[Agent][create_ticket] 创建成功 ticket_id=%s title=%q risk=%s", ticket.ID, title, ticket.RiskLevel)
			return toJSON(map[string]any{"ticket_id": ticket.ID, "status": ticket.Status}), nil
		},
	})

	reg.Register(toolFunc{
		name:        "update_ticket_status",
		description: "更新工单状态（pending/confirmed/excluded/resolved），可选追加处理备注。",
		schema: map[string]any{"type": "object", "properties": map[string]any{
			"ticket_id": map[string]any{"type": "string"},
			"status":    map[string]any{"type": "string"},
			"note":      map[string]any{"type": "string"}}},
		fn: func(ctx context.Context, args map[string]any) (string, error) {
			id := getString(args, "ticket_id")
			status := getString(args, "status")
			if id == "" || status == "" {
				return "", fmt.Errorf("缺少参数 ticket_id / status")
			}
			if err := d.TicketRepo.UpdateStatus(id, status); err != nil {
				return "", err
			}
			if note := getString(args, "note"); note != "" {
				_ = d.TicketRepo.AddNotes(id, note)
			}
			return toJSON(map[string]any{"ticket_id": id, "status": status, "ok": true}), nil
		},
	})

	reg.Register(toolFunc{
		name:        "create_inspection_rule",
		description: "创建一条巡检规则（结果回写/规划）。平台将按 cron 周期自动对绑定资产执行「扫描 + 本地兜底评估」，支持多资产绑定（domain_ids 数组，一次配置多域名同周期巡检）。AI 研判交由自主智能体执行。",
		schema: map[string]any{"type": "object", "properties": map[string]any{
			"name":               map[string]any{"type": "string"},
			"domain_id":          map[string]any{"type": "string", "description": "单资产域名 id（向后兼容）"},
			"domain_ids":         map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "多资产域名 id 列表（优先于 domain_id）"},
			"schedule":           map[string]any{"type": "string", "description": "cron 表达式(5/6字段)"},
			"run_scan":           map[string]any{"type": "boolean", "description": "巡检前是否先扫描，默认 true"},
			"severity_threshold": map[string]any{"type": "string"},
			"alert_on_failure":   map[string]any{"type": "boolean"},
		}},
		fn: func(ctx context.Context, args map[string]any) (string, error) {
			name := getString(args, "name")
			schedule := getString(args, "schedule")
			// 归一化目标域名：优先 domain_ids 数组，其次单值 domain_id
			domainIDs := getStringSlice(args, "domain_ids")
			if len(domainIDs) == 0 {
				if did := getString(args, "domain_id"); did != "" {
					domainIDs = []string{did}
				}
			}
			if name == "" || len(domainIDs) == 0 || schedule == "" {
				return "", fmt.Errorf("缺少参数 name / domain_id(或 domain_ids) / schedule")
			}
			for _, did := range domainIDs {
				if _, err := d.DomainRepo.GetByID(did); err != nil {
					return "", fmt.Errorf("域名不存在: %s", did)
				}
			}
			if _, err := scheduler.ParseSchedule(schedule); err != nil {
				return "", fmt.Errorf("cron 表达式无效: %w", err)
			}
			enabled := true
			rule := &models.InspectionRule{
				Name:              name,
				DomainID:          domainIDs[0],
				DomainIDs:         domainIDs,
				Enabled:           enabled,
				Schedule:          schedule,
				SeverityThreshold: getString(args, "severity_threshold"),
				RunScan:           boolArg(args, "run_scan", true),
				AlertOnFailure:    boolArg(args, "alert_on_failure", false),
			}
			if err := d.RuleRepo.Create(rule); err != nil {
				return "", err
			}
			if err := d.Sched.AddRuleTask(rule); err != nil {
				// 规则已落库，仅注册到调度器失败（如 cron 边界），记录但不阻断
				return toJSON(map[string]any{"rule_id": rule.ID, "registered": false, "warning": err.Error()}), nil
			}
			return toJSON(map[string]any{"rule_id": rule.ID, "registered": true, "domain_count": len(domainIDs)}), nil
		},
	})

	reg.Register(toolFunc{
		name:        "delete_inspection_rule",
		description: "删除一条巡检规则（并即时从调度器摘除定时任务）。适用于「就扫一次，之后不要扫了」：先创建/触发一次性扫描，完成后调用本工具清理规则，避免后续周期重复执行。",
		schema: map[string]any{"type": "object", "properties": map[string]any{
			"rule_id": map[string]any{"type": "string", "description": "巡检规则 id"}}},
		fn: func(ctx context.Context, args map[string]any) (string, error) {
			ruleID := getString(args, "rule_id")
			if ruleID == "" {
				return "", fmt.Errorf("缺少参数 rule_id")
			}
			// 先确认存在，避免误删/误导
			if _, err := d.RuleRepo.GetByID(ruleID); err != nil {
				return "", fmt.Errorf("巡检规则不存在: %s", ruleID)
			}
			if err := d.RuleRepo.Delete(ruleID); err != nil {
				return "", err
			}
			// 即时从运行中的调度器摘除，不再触发
			if d.Sched != nil {
				d.Sched.RemoveRuleTask(ruleID)
			}
			log.Printf("[Agent][delete_inspection_rule] 已删除规则 rule_id=%s", ruleID)
			return toJSON(map[string]any{"rule_id": ruleID, "deleted": true}), nil
		},
	})

	reg.Register(toolFunc{
		name:        "send_alert",
		description: "创建一条告警（结果回写）。可用于把重大风险主动推送出来。",
		schema: map[string]any{"type": "object", "properties": map[string]any{
			"title":       map[string]any{"type": "string"},
			"content":     map[string]any{"type": "string"},
			"severity":    map[string]any{"type": "string", "description": "high/medium/low"},
			"type":        map[string]any{"type": "string"},
			"domain_id":   map[string]any{"type": "string"},
			"scan_job_id": map[string]any{"type": "string"},
		}},
		fn: func(ctx context.Context, args map[string]any) (string, error) {
			title := getString(args, "title")
			if title == "" {
				return "", fmt.Errorf("缺少参数 title")
			}
			alert := &models.Alert{
				Title:     title,
				Content:   getString(args, "content"),
				Severity:  normRisk(getString(args, "severity")),
				Type:      getString(args, "type"),
				DomainID:  getString(args, "domain_id"),
				ScanJobID: getString(args, "scan_job_id"),
				Status:    "new",
				CreatedAt: time.Now(),
			}
			if alert.Type == "" {
				alert.Type = "agent"
			}
			if err := d.AlertRepo.Create(alert); err != nil {
				return "", err
			}
			return toJSON(map[string]any{"alert_id": alert.ID}), nil
		},
	})

	reg.Register(toolFunc{
		name:        "wait",
		description: "延时待机：在后台静默等待指定秒数（上限 3600 秒）。等待期间平台不关闭、定时任务照常执行，用户也可在界面继续填写/提交新的巡检任务。等待结束后再继续后续步骤，适合编排「先等一段时间再继续」的流程。",
		schema: map[string]any{"type": "object", "properties": map[string]any{
			"duration_sec": map[string]any{"type": "integer", "description": "等待秒数（1~3600）"},
			"reason":       map[string]any{"type": "string", "description": "可选：等待原因备注"}}},
		fn: func(ctx context.Context, args map[string]any) (string, error) {
			dur := getInt(args, "duration_sec", 60)
			if dur < 1 {
				dur = 1
			}
			if dur > 3600 {
				dur = 3600
			}
			reason := getString(args, "reason")
			log.Printf("[Agent][wait] 开始静默等待 duration=%ds reason=%q", dur, reason)

			timer := time.NewTimer(time.Duration(dur) * time.Second)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				log.Printf("[Agent][wait] 等待被取消（任务终止）")
				return toJSON(map[string]any{"waited": false, "reason": "cancelled", "requested_sec": dur}), nil
			case <-timer.C:
			}
			log.Printf("[Agent][wait] 等待结束 duration=%ds", dur)
			return toJSON(map[string]any{"waited": true, "duration_sec": dur}), nil
		},
	})

	reg.Register(toolFunc{
		name:        "wait_until",
		description: "精确等待到指定时刻再继续（上限 24 小时）。直接支持「请在 25 分 30 秒后扫描」「今晚 20:00 扫描一次」类需求：先用 get_current_time 计算目标 RFC3339 时刻，再调用本工具。等待期间平台不关闭、定时任务照常执行。",
		schema: map[string]any{"type": "object", "properties": map[string]any{
			"target_time": map[string]any{"type": "string", "description": "目标时刻 RFC3339，如 2026-09-02T20:00:00+08:00"},
			"reason":      map[string]any{"type": "string", "description": "可选：等待原因备注"}}},
		fn: func(ctx context.Context, args map[string]any) (string, error) {
			target := getString(args, "target_time")
			if target == "" {
				return "", fmt.Errorf("缺少参数 target_time（RFC3339 格式）")
			}
			t, err := time.Parse(time.RFC3339, target)
			if err != nil {
				return "", fmt.Errorf("target_time 格式非法，需 RFC3339（如 2026-09-02T20:00:00+08:00）: %w", err)
			}
			now := time.Now()
			delay := t.Sub(now)
			if delay <= 0 {
				return toJSON(map[string]any{"waited": false, "reason": "target_time 已过", "target_time": target}), nil
			}
			// 上限 24 小时，避免无限挂起
			maxDelay := 24 * time.Hour
			capped := false
			if delay > maxDelay {
				delay = maxDelay
				capped = true
			}
			reason := getString(args, "reason")
			log.Printf("[Agent][wait_until] 开始等待 target=%s delay=%v capped=%v reason=%q", target, delay, capped, reason)

			timer := time.NewTimer(delay)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				log.Printf("[Agent][wait_until] 等待被取消（任务终止）")
				return toJSON(map[string]any{"waited": false, "reason": "cancelled", "target_time": target}), nil
			case <-timer.C:
			}
			log.Printf("[Agent][wait_until] 等待结束 target=%s", target)
			return toJSON(map[string]any{
				"waited":         true,
				"target_time":    target,
				"actual_delay_s": int(delay.Seconds()),
				"capped":         capped,
			}), nil
		},
	})

	reg.Register(toolFunc{
		name:        "create_domain",
		description: "新建一个巡检/扫描域名（结果回写）。会做格式与 DNS 可解析性校验，校验通过后才落库；可用于编排「先建域名、再建巡检规则、最后触发巡检」的完整流程。",
		schema: map[string]any{"type": "object", "properties": map[string]any{
			"name":        map[string]any{"type": "string", "description": "域名或 URL，如 example.com 或 https://example.com"},
			"description": map[string]any{"type": "string"},
			"max_depth":   map[string]any{"type": "integer", "description": "爬取最大深度（默认 3）"},
			"max_pages":   map[string]any{"type": "integer", "description": "爬取最大页面数（默认 100）"}}},
		fn: func(ctx context.Context, args map[string]any) (string, error) {
			raw := getString(args, "name")
			if raw == "" {
				return "", fmt.Errorf("缺少参数 name")
			}
			name, err := validateDomainName(raw)
			if err != nil {
				return "", err
			}
			maxDepth := getInt(args, "max_depth", 3)
			if maxDepth <= 0 {
				maxDepth = 3
			}
			maxPages := getInt(args, "max_pages", 100)
			if maxPages <= 0 {
				maxPages = 100
			}
			domain := &models.Domain{
				Name:        name,
				Description: getString(args, "description"),
				Status:      "active",
				MaxDepth:    maxDepth,
				MaxPages:    maxPages,
			}
			if err := d.DomainRepo.Create(domain); err != nil {
				return "", err
			}
			log.Printf("[Agent][create_domain] 已创建域名 name=%s id=%s", name, domain.ID)
			return toJSON(map[string]any{"domain_id": domain.ID, "name": name, "status": domain.Status}), nil
		},
	})

	reg.Register(toolFunc{
		name:        "finish_task",
		description: "【控制工具】模型完成目标后调用，携带 summary 作为最终结论，结束本次任务。",
		schema: map[string]any{"type": "object", "properties": map[string]any{
			"summary": map[string]any{"type": "string", "description": "任务最终结论/摘要"}}},
		fn: func(ctx context.Context, args map[string]any) (string, error) {
			return "任务结束信号已接收，正在汇总结果。", nil
		},
	})
}

// validateDomainName 校验域名/URL 合法性（格式 + DNS 可解析性），与 api.validateDomainTarget 对齐。
// 智能体在创建域名前复用同一套规则，避免登记根本不存在的目标。
func validateDomainName(raw string) (string, error) {
	name := strings.TrimSpace(raw)
	if name == "" {
		return "", fmt.Errorf("域名不能为空")
	}
	if strings.ContainsAny(name, " \t\r\n") {
		return "", fmt.Errorf("域名不能包含空格")
	}
	host := name
	if strings.Contains(name, "://") {
		u, err := url.Parse(name)
		if err != nil || u.Hostname() == "" {
			return "", fmt.Errorf("域名格式不合法，示例：example.com 或 https://example.com")
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return "", fmt.Errorf("仅支持 http/https 协议")
		}
		host = u.Hostname()
	} else if strings.Contains(name, "/") {
		// 形如 115.236.69.0/24 的网段无法作为爬取目标
		return "", fmt.Errorf("域名格式不合法：请填写单个域名或 IP，暂不支持 CIDR 网段")
	}
	if net.ParseIP(host) == nil && !isHostnameLike(host) {
		return "", fmt.Errorf("域名格式不合法，示例：example.com / 127.0.0.1 / https://example.com")
	}
	// 可解析性：解析不了的域名没有巡检意义（IP 与 localhost 例外）
	if net.ParseIP(host) == nil && host != "localhost" {
		if _, err := net.LookupHost(host); err != nil {
			return "", fmt.Errorf("域名 %q 无法解析（DNS 查询失败），请确认目标真实存在", host)
		}
	}
	return name, nil
}

func isHostnameLike(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-'
			if !ok {
				return false
			}
		}
	}
	return true
}

// summarizeScan 把扫描结果压成精简摘要，避免把海量漏洞原始文本塞回上下文。
func summarizeScan(res *scanner.ScanResults) map[string]any {
	summary := res.Summary
	if summary == nil {
		summary = &models.ScanSummary{}
	}
	out := map[string]any{
		"total_pages":           summary.TotalPages,
		"total_vulnerabilities": summary.TotalVulns,
		"high_severity":         summary.HighSeverity,
		"medium_severity":       summary.MediumSeverity,
		"low_severity":          summary.LowSeverity,
		"sensitive_found":       summary.SensitiveFound,
		"vulnerability_count":   len(res.Vulnerabilities),
		"sensitive_count":       len(res.SensitiveInfos),
	}
	return out
}

// normRisk 归一化风险等级字符串。
func normRisk(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "high", "严重":
		return "high"
	case "medium", "中", "mid":
		return "medium"
	case "low", "低":
		return "low"
	default:
		return ""
	}
}
