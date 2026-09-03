package scanner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"strings"
	"time"

	"security-agent/internal/models"
)

// =============================================================================
// 漏洞报告生成器 (Vulnerability Reporter)
// =============================================================================
// 支持 Markdown / JSON / HTML 三种格式
// Markdown 格式严格对齐 clown-src-6k-skill/rules/vuln-report-format.md
// 支持工单系统 Webhook 集成
// =============================================================================

// Reporter 报告生成器
type Reporter struct {
	ruleEngine *RuleEngine
}

// NewReporter 创建报告生成器
func NewReporter(re *RuleEngine) *Reporter {
	return &Reporter{ruleEngine: re}
}

// ReportBundle 完整报告包
type ReportBundle struct {
	Markdown string                 `json:"markdown"`
	JSON     map[string]interface{} `json:"json"`
	HTML     string                 `json:"html"`
	Summary  ReportSummary          `json:"summary"`
}

// ReportSummary 报告摘要
type ReportSummary struct {
	GeneratedAt     time.Time `json:"generated_at"`
	TargetURL       string    `json:"target_url"`
	TotalVulns      int       `json:"total_vulns"`
	CriticalCount   int       `json:"critical_count"`
	HighCount       int       `json:"high_count"`
	MediumCount     int       `json:"medium_count"`
	LowCount        int       `json:"low_count"`
	ByType          map[string]int `json:"by_type"`
	ByConfidence    map[string]int `json:"by_confidence"`
}

// GenerateReport 生成完整报告包
func (r *Reporter) GenerateReport(vulns []*models.Vulnerability, targetURL string) *ReportBundle {
	summary := r.buildSummary(vulns, targetURL)

	return &ReportBundle{
		Markdown: r.GenerateMarkdown(vulns, targetURL, summary),
		JSON:     r.GenerateJSON(vulns, targetURL, summary),
		HTML:     r.GenerateHTML(vulns, targetURL, summary),
		Summary:  summary,
	}
}

// -----------------------------------------------------------------------------
// Markdown 报告（严格对齐 vuln-report-format.md）
// -----------------------------------------------------------------------------

// GenerateMarkdown 生成 SRC 格式 Markdown 报告
func (r *Reporter) GenerateMarkdown(vulns []*models.Vulnerability, targetURL string, summary ReportSummary) string {
	var sb strings.Builder

	sb.WriteString("# 漏洞扫描报告\n\n")
	sb.WriteString(fmt.Sprintf("**扫描目标**: %s\n", targetURL))
	sb.WriteString(fmt.Sprintf("**生成时间**: %s\n", time.Now().Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("**漏洞总数**: %d (严重:%d 高危:%d 中危:%d 低危:%d)\n\n",
		summary.TotalVulns, summary.CriticalCount, summary.HighCount,
		summary.MediumCount, summary.LowCount))
	sb.WriteString("---\n\n")

	// 按严重等级排序：critical > high > medium > low
	sortedVulns := sortVulnsBySeverity(vulns)

	for i, v := range sortedVulns {
		sb.WriteString(fmt.Sprintf("## %d. %s\n\n", i+1, v.Name))
		sb.WriteString(fmt.Sprintf("**目标网站URL**: %s\n", v.URL))

		// 等级映射
		severityCN := severityToCN(v.Severity)
		sb.WriteString(fmt.Sprintf("**漏洞等级**: %s\n\n", severityCN))

		// 漏洞描述
		sb.WriteString("**漏洞描述**:\n")
		sb.WriteString(v.Description + "\n\n")

		// 漏洞危害
		sb.WriteString("**漏洞危害**:\n")
		sb.WriteString(fmt.Sprintf("该漏洞可导致 %s，攻击者可能利用此漏洞进一步获取系统权限或泄露敏感数据。\n\n", severityCN))

		// 涉及接口清单
		sb.WriteString("**涉及接口清单**:\n")
		sb.WriteString(fmt.Sprintf("1. %s\n\n", v.URL))

		// 复现步骤 + PoC
		sb.WriteString("**复现步骤**:\n")
		pocRequest := r.generatePoCRequest(v)
		sb.WriteString(fmt.Sprintf("1. 发送以下请求验证漏洞：\n\n```http\n%s\n```\n\n", pocRequest))

		// 修复建议
		sb.WriteString("**修复建议**:\n")
		sb.WriteString(v.Remediation + "\n\n")

		// 置信度和证据
		sb.WriteString(fmt.Sprintf("**置信度**: %s\n", v.Confidence))
		if v.Evidence != "" {
			sb.WriteString(fmt.Sprintf("**证据**: %s\n", v.Evidence))
		}
		if len(v.CVEIDs) > 0 {
			sb.WriteString(fmt.Sprintf("**关联CVE**: %s\n", strings.Join(v.CVEIDs, ", ")))
		}
		sb.WriteString("\n---\n\n")
	}

	return sb.String()
}

// generatePoCRequest 生成 PoC HTTP 请求
func (r *Reporter) generatePoCRequest(v *models.Vulnerability) string {
	if r.ruleEngine != nil {
		rules := r.ruleEngine.ListRules()
		for _, rule := range rules {
			if ruleMatchesVuln(rule, v) {
				return r.ruleEngine.GeneratePoC(rule.ID, v.URL, -1)
			}
		}
	}
	// 通用 PoC
	return fmt.Sprintf("GET %s HTTP/1.1\nHost: %s\nUser-Agent: Mozilla/5.0\nAccept: */*\nConnection: close",
		v.URL, extractHostForPoC(v.URL))
}

// ruleMatchesVuln 检查规则是否匹配漏洞
func ruleMatchesVuln(rule *VulnRule, v *models.Vulnerability) bool {
	return strings.Contains(strings.ToLower(rule.Name), strings.ToLower(v.Type)) ||
		strings.Contains(strings.ToLower(rule.NameCN), strings.ToLower(v.Name))
}

// -----------------------------------------------------------------------------
// JSON 报告（机器可读，含完整 CVSS + PoC + 修复信息）
// -----------------------------------------------------------------------------

// GenerateJSON 生成 JSON 报告
func (r *Reporter) GenerateJSON(vulns []*models.Vulnerability, targetURL string, summary ReportSummary) map[string]interface{} {
	vulnsJSON := make([]map[string]interface{}, 0, len(vulns))
	for _, v := range vulns {
		entry := map[string]interface{}{
			"id":          v.ID,
			"type":        v.Type,
			"name":        v.Name,
			"severity":    v.Severity,
			"confidence":  v.Confidence,
			"description": v.Description,
			"evidence":    v.Evidence,
			"url":         v.URL,
			"parameter":   v.Parameter,
			"remediation": v.Remediation,
			"cve_ids":     v.CVEIDs,
			"affected_versions": v.AffectedVersions,
			"fingerprint": v.Fingerprint,
			"found_at":    v.FoundAt,
		}

		// 关联规则信息
		if r.ruleEngine != nil {
			rules := r.ruleEngine.ListRules()
			for _, rule := range rules {
				if ruleMatchesVuln(rule, v) {
					entry["rule_id"] = rule.ID
					entry["owasp_category"] = rule.OWASPCategory
					entry["cwe_id"] = rule.CWEID
					entry["cvss_vector"] = rule.CVSS.Vector
					entry["cvss_base_score"] = rule.CVSS.BaseScore
					entry["poc_payloads"] = rule.PoC.Payloads
					break
				}
			}
		}

		vulnsJSON = append(vulnsJSON, entry)
	}

	return map[string]interface{}{
		"report_version": "1.0",
		"generated_at":   summary.GeneratedAt,
		"target_url":     targetURL,
		"summary": map[string]interface{}{
			"total":     summary.TotalVulns,
			"critical":  summary.CriticalCount,
			"high":      summary.HighCount,
			"medium":    summary.MediumCount,
			"low":       summary.LowCount,
			"by_type":   summary.ByType,
			"by_confidence": summary.ByConfidence,
		},
		"vulnerabilities": vulnsJSON,
	}
}

// -----------------------------------------------------------------------------
// HTML 报告（可视化）
// -----------------------------------------------------------------------------

const htmlTemplate = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<title>漏洞扫描报告 - {{.Summary.TargetURL}}</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; color: #333; }
  .container { max-width: 1200px; margin: 0 auto; }
  .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 20px; }
  .header h1 { margin: 0 0 10px 0; }
  .summary { display: flex; gap: 15px; flex-wrap: wrap; margin-bottom: 20px; }
  .stat-card { background: white; padding: 20px; border-radius: 8px; flex: 1; min-width: 150px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); text-align: center; }
  .stat-card .number { font-size: 2em; font-weight: bold; }
  .stat-card.critical .number { color: #dc3545; }
  .stat-card.high .number { color: #fd7e14; }
  .stat-card.medium .number { color: #ffc107; }
  .stat-card.low .number { color: #28a745; }
  .vuln-card { background: white; padding: 25px; border-radius: 8px; margin-bottom: 15px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); border-left: 4px solid #667eea; }
  .vuln-card.critical { border-left-color: #dc3545; }
  .vuln-card.high { border-left-color: #fd7e14; }
  .vuln-card.medium { border-left-color: #ffc107; }
  .vuln-card.low { border-left-color: #28a745; }
  .vuln-card h3 { margin-top: 0; }
  .badge { display: inline-block; padding: 3px 10px; border-radius: 4px; font-size: 0.85em; font-weight: bold; color: white; }
  .badge.critical { background: #dc3545; }
  .badge.high { background: #fd7e14; }
  .badge.medium { background: #ffc107; }
  .badge.low { background: #28a745; }
  pre { background: #f8f9fa; padding: 15px; border-radius: 6px; overflow-x: auto; }
  .meta { color: #666; font-size: 0.9em; margin: 5px 0; }
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>漏洞扫描报告</h1>
    <p>目标: {{.Summary.TargetURL}} | 生成时间: {{.Summary.GeneratedAt}}</p>
  </div>
  <div class="summary">
    <div class="stat-card critical"><div class="number">{{.Summary.CriticalCount}}</div><div>严重</div></div>
    <div class="stat-card high"><div class="number">{{.Summary.HighCount}}</div><div>高危</div></div>
    <div class="stat-card medium"><div class="number">{{.Summary.MediumCount}}</div><div>中危</div></div>
    <div class="stat-card low"><div class="number">{{.Summary.LowCount}}</div><div>低危</div></div>
    <div class="stat-card"><div class="number">{{.Summary.TotalVulns}}</div><div>总计</div></div>
  </div>
  {{range .Vulns}}
  <div class="vuln-card {{.Severity}}">
    <h3>{{.Name}} <span class="badge {{.Severity}}">{{severityCN .Severity}}</span></h3>
    <div class="meta"><strong>URL:</strong> {{.URL}}</div>
    <div class="meta"><strong>置信度:</strong> {{.Confidence}} | <strong>类型:</strong> {{.Type}}</div>
    <p><strong>描述:</strong> {{.Description}}</p>
    {{if .Evidence}}<p><strong>证据:</strong> {{.Evidence}}</p>{{end}}
    {{if .Remediation}}<p><strong>修复建议:</strong> {{.Remediation}}</p>{{end}}
    {{if .CVEIDs}}<p><strong>关联CVE:</strong> {{range .CVEIDs}}<span class="badge medium">{{.}}</span> {{end}}</p>{{end}}
  </div>
  {{end}}
</div>
</body>
</html>`

// HTMLData HTML 模板数据
type HTMLData struct {
	Summary ReportSummary
	Vulns   []*models.Vulnerability
}

// GenerateHTML 生成 HTML 报告
func (r *Reporter) GenerateHTML(vulns []*models.Vulnerability, targetURL string, summary ReportSummary) string {
	sortedVulns := sortVulnsBySeverity(vulns)

	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"severityCN": severityToCN,
	}).Parse(htmlTemplate)
	if err != nil {
		return fmt.Sprintf("<html><body><h1>报告生成失败</h1><p>%s</p></body></html>", err.Error())
	}

	var buf bytes.Buffer
	data := HTMLData{Summary: summary, Vulns: sortedVulns}
	if err := tmpl.Execute(&buf, data); err != nil {
		return fmt.Sprintf("<html><body><h1>报告渲染失败</h1><p>%s</p></body></html>", err.Error())
	}
	return buf.String()
}

// -----------------------------------------------------------------------------
// 工单集成 (Ticketing Webhook)
// -----------------------------------------------------------------------------

// TicketPayload 工单系统通用 payload
type TicketPayload struct {
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
	Confidence  string   `json:"confidence"`
	URL         string   `json:"url"`
	CVEIDs      []string `json:"cve_ids,omitempty"`
	CVSSVector  string   `json:"cvss_vector,omitempty"`
	CVSSScore   float64  `json:"cvss_score,omitempty"`
	PoC         string   `json:"poc,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	Labels      []string `json:"labels"`
	Source      string   `json:"source"`
}

// BuildTicketPayload 构建工单 payload
func (r *Reporter) BuildTicketPayload(v *models.Vulnerability) *TicketPayload {
	title := v.Name
	if len(v.CVEIDs) > 0 {
		title = fmt.Sprintf("[%s] %s", v.CVEIDs[0], v.Name)
	}

	poc := ""
	if r.ruleEngine != nil {
		rules := r.ruleEngine.ListRules()
		for _, rule := range rules {
			if ruleMatchesVuln(rule, v) {
				poc = r.ruleEngine.GeneratePoC(rule.ID, v.URL, -1)
				break
			}
		}
	}

	return &TicketPayload{
		Title:       title,
		Description: fmt.Sprintf("%s\n\nURL: %s\n证据: %s", v.Description, v.URL, v.Evidence),
		Severity:    v.Severity,
		Confidence:  v.Confidence,
		URL:         v.URL,
		CVEIDs:      v.CVEIDs,
		PoC:         poc,
		Remediation: v.Remediation,
		Labels:      []string{"security", "vulnerability-scan", "auto-generated"},
		Source:      "clown-vuln-engine",
	}
}

// MarshalJSON 序列化工单 payload
func (tp *TicketPayload) MarshalJSON() ([]byte, error) {
	type Alias TicketPayload
	return json.Marshal(&struct {
		*Alias
		TicketURL string `json:"ticket_url,omitempty"`
	}{
		Alias: (*Alias)(tp),
	})
}

// -----------------------------------------------------------------------------
// 辅助函数
// -----------------------------------------------------------------------------

func (r *Reporter) buildSummary(vulns []*models.Vulnerability, targetURL string) ReportSummary {
	summary := ReportSummary{
		GeneratedAt:  time.Now(),
		TargetURL:    targetURL,
		TotalVulns:   len(vulns),
		ByType:       make(map[string]int),
		ByConfidence: make(map[string]int),
	}

	for _, v := range vulns {
		switch strings.ToLower(v.Severity) {
		case "critical":
			summary.CriticalCount++
		case "high":
			summary.HighCount++
		case "medium":
			summary.MediumCount++
		case "low":
			summary.LowCount++
		}
		summary.ByType[v.Type]++
		summary.ByConfidence[v.Confidence]++
	}

	return summary
}

// sortVulnsBySeverity 按严重等级排序
func sortVulnsBySeverity(vulns []*models.Vulnerability) []*models.Vulnerability {
	severityOrder := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
	sorted := make([]*models.Vulnerability, len(vulns))
	copy(sorted, vulns)
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			si := severityOrder[strings.ToLower(sorted[i].Severity)]
			sj := severityOrder[strings.ToLower(sorted[j].Severity)]
			if sj < si {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}
	return sorted
}

// severityToCN 等级中文映射
func severityToCN(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "严重"
	case "high":
		return "高危"
	case "medium":
		return "中危"
	case "low":
		return "低危"
	default:
		return severity
	}
}
