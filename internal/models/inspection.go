package models

import "time"

// ============================================================
// AI 自动巡检：规则(InspectionRule) 与 记录(InspectionRecord)
// ============================================================
//
// InspectionRule 描述“对哪个域名、按什么周期、做什么检查”。
// 它由调度器按 schedule(cron) 注册为定时任务；保存配置后即热更新到运行中的调度器。
//
// InspectionRecord 是一次巡检的结构化结果落地，供前端“查看历史记录与执行状态”。

// InspectionRule 巡检规则（持久化到 Neo4j :InspectionRule 节点）
type InspectionRule struct {
	ID                string     `json:"id" neo4j:"id"`
	Name              string     `json:"name" neo4j:"name"`                                       // 规则名称
	DomainID          string     `json:"domain_id" neo4j:"domain_id"`                             // 主关联域名（向后兼容：多资产时取第一个）
	DomainIDs         []string   `json:"domain_ids" neo4j:"domain_ids"`                           // 关联域名列表（多资产绑定，触发时逐个巡检）
	Enabled           bool       `json:"enabled" neo4j:"enabled"`                                 // 是否启用（false=暂停）
	Schedule          string     `json:"schedule" neo4j:"schedule"`                               // Cron 表达式（5/6 字段）
	SeverityThreshold string     `json:"severity_threshold,omitempty" neo4j:"severity_threshold"` // 仅达到该级别才发失败告警
	RunScan           bool       `json:"run_scan" neo4j:"run_scan"`                               // 巡检前是否先执行一次扫描
	RetryCount        int        `json:"retry_count" neo4j:"retry_count"`                         // AI 调用失败重试次数
	RetryBackoffSec   int        `json:"retry_backoff_sec" neo4j:"retry_backoff_sec"`
	AlertOnFailure    bool       `json:"alert_on_failure" neo4j:"alert_on_failure"` // 失败是否发告警
	LastRunAt         *time.Time `json:"last_run_at,omitempty" neo4j:"last_run_at"`
	NextRunAt         *time.Time `json:"next_run_at,omitempty" neo4j:"next_run_at"`
	CreatedAt         time.Time  `json:"created_at" neo4j:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at" neo4j:"updated_at"`
}

// EffectiveDomainIDs 返回规则实际巡检的域名列表：优先 DomainIDs，为空时回退到单值 DomainID。
// 统一入口，避免各调用方重复实现回退逻辑。
func (r *InspectionRule) EffectiveDomainIDs() []string {
	if len(r.DomainIDs) > 0 {
		out := make([]string, 0, len(r.DomainIDs))
		for _, id := range r.DomainIDs {
			if id != "" {
				out = append(out, id)
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	if r.DomainID != "" {
		return []string{r.DomainID}
	}
	return nil
}

// 巡检记录状态
const (
	InspectionStatusPending   = "pending"
	InspectionStatusRunning   = "running"
	InspectionStatusAnalyzing = "analyzing" // 扫描已完成，正在进行 AI 分析（区别于 scanning，避免前端长期显示 running）
	InspectionStatusSuccess   = "success"
	InspectionStatusPartial   = "partial" // 扫描成功但 AI 不可用/解析失败，已落本地兜底结果
	InspectionStatusFailed    = "failed"
)

// 巡检触发来源
const (
	InspectionTriggerSchedule = "schedule"
	InspectionTriggerManual   = "manual"
	InspectionTriggerAgent    = "agent" // 由自主智能体调用触发
)

// InspectionRecord 一次巡检的结构化结果（持久化到 Neo4j :InspectionRecord 节点）
type InspectionRecord struct {
	ID            string     `json:"id" neo4j:"id"`
	RuleID        string     `json:"rule_id,omitempty" neo4j:"rule_id"`
	RuleName      string     `json:"rule_name,omitempty" neo4j:"rule_name"`
	DomainID      string     `json:"domain_id" neo4j:"domain_id"`
	DomainName    string     `json:"domain_name,omitempty" neo4j:"domain_name"`
	ScanJobID     string     `json:"scan_job_id,omitempty" neo4j:"scan_job_id"`
	TriggeredBy   string     `json:"triggered_by" neo4j:"triggered_by"` // schedule | manual | agent
	Provider      string     `json:"provider,omitempty" neo4j:"provider"`
	Model         string     `json:"model,omitempty" neo4j:"model"`
	Status        string     `json:"status" neo4j:"status"`
	RiskLevel     string     `json:"risk_level,omitempty" neo4j:"risk_level"` // high|medium|low|none
	Summary       string     `json:"summary,omitempty" neo4j:"summary"`
	ResultJSON    string     `json:"result_json,omitempty" neo4j:"result_json"`   // 模型返回的结构化结果(JSON)
	RawResponse   string     `json:"raw_response,omitempty" neo4j:"raw_response"` // 模型原始文本
	FindingsCount int        `json:"findings_count" neo4j:"findings_count"`
	HighCount     int        `json:"high_count" neo4j:"high_count"`
	MediumCount   int        `json:"medium_count" neo4j:"medium_count"`
	LowCount      int        `json:"low_count" neo4j:"low_count"`
	Error         string     `json:"error,omitempty" neo4j:"error"`
	RetryCount    int        `json:"retry_count" neo4j:"retry_count"`
	StartedAt     time.Time  `json:"started_at" neo4j:"started_at"`
	CompletedAt   *time.Time `json:"completed_at,omitempty" neo4j:"completed_at"`
	CreatedAt     time.Time  `json:"created_at" neo4j:"created_at"`
}

// InspectionFinding 单条发现（结构化结果里的数组元素）
type InspectionFinding struct {
	Title          string `json:"title"`
	Severity       string `json:"severity"` // high|medium|low
	URL            string `json:"url,omitempty"`
	Description    string `json:"description,omitempty"`
	Recommendation string `json:"recommendation,omitempty"`
	// 研判建议（可选，由 AI 返回；缺省时由 inspection.generateTriage 兜底生成）
	Harm       string `json:"harm,omitempty"`       // 危害说明
	Priority   string `json:"priority,omitempty"`   // 修复优先级 P0/P1/P2
	Mitigation string `json:"mitigation,omitempty"` // 临时缓解措施
	Retest     string `json:"retest,omitempty"`     // 复测方式
}

// InspectionResult AI 返回的结构化巡检结果
type InspectionResult struct {
	OverallRisk     string              `json:"overall_risk"` // high|medium|low|none
	Summary         string              `json:"summary"`
	Findings        []InspectionFinding `json:"findings"`
	Recommendations []string            `json:"recommendations"`
}
