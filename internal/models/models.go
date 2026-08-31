package models

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"
)

// Domain 授权巡检的域名
type Domain struct {
	ID          string    `json:"id" neo4j:"id"`
	Name        string    `json:"name" neo4j:"name"`                 // 域名
	Description string    `json:"description" neo4j:"description"`   // 描述
	Status      string    `json:"status" neo4j:"status"`             // active, paused, disabled
	MaxDepth    int       `json:"max_depth" neo4j:"max_depth"`       // 最大爬取深度
	MaxPages    int       `json:"max_pages" neo4j:"max_pages"`       // 最大页面数
	CreatedAt   time.Time `json:"created_at" neo4j:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" neo4j:"updated_at"`
}

// ScanJob 巡检任务
type ScanJob struct {
	ID          string    `json:"id" neo4j:"id"`
	DomainID    string    `json:"domain_id" neo4j:"domain_id"`
	Status      string    `json:"status" neo4j:"status"`             // pending, running, completed, failed
	StartedAt   time.Time `json:"started_at" neo4j:"started_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty" neo4j:"completed_at"`
	CreatedAt   time.Time `json:"created_at" neo4j:"created_at"`
	Summary     *ScanSummary `json:"summary,omitempty" neo4j:"-"`
	// 聚合摘要（持久化到节点，便于列表/统计快速读取）
	TotalPages     int `json:"total_pages" neo4j:"total_pages"`
	CurrentPage    int `json:"current_page" neo4j:"current_page"`
	TotalVulns     int `json:"total_vulnerabilities" neo4j:"total_vulnerabilities"`
	HighSeverity   int `json:"high_severity" neo4j:"high_severity"`
	MediumSeverity int `json:"medium_severity" neo4j:"medium_severity"`
	LowSeverity    int `json:"low_severity" neo4j:"low_severity"`
	SensitiveFound int `json:"sensitive_found" neo4j:"sensitive_found"`
}

// ScanSummary 巡检摘要
type ScanSummary struct {
	TotalPages    int `json:"total_pages"`
	TotalVulns    int `json:"total_vulnerabilities"`
	HighSeverity  int `json:"high_severity"`
	MediumSeverity int `json:"medium_severity"`
	LowSeverity   int `json:"low_severity"`
	SensitiveFound int `json:"sensitive_found"`
}

// Page 发现的页面
type Page struct {
	ID         string    `json:"id" neo4j:"id"`
	DomainID   string    `json:"domain_id" neo4j:"domain_id"`
	URL        string    `json:"url" neo4j:"url"`
	Title      string    `json:"title" neo4j:"title"`
	StatusCode int       `json:"status_code" neo4j:"status_code"`
	ContentHash string   `json:"content_hash" neo4j:"content_hash"` // 内容指纹
	CrawledAt  time.Time `json:"crawled_at" neo4j:"crawled_at"`
	Depth      int       `json:"depth" neo4j:"depth"`
	Links      []string  `json:"links,omitempty" neo4j:"-"`
}

// Vulnerability 安全漏洞
type Vulnerability struct {
	ID          string    `json:"id" neo4j:"id"`
	ScanJobID   string    `json:"scan_job_id" neo4j:"scan_job_id"`
	PageID      string    `json:"page_id" neo4j:"page_id"`
	DomainID    string    `json:"domain_id,omitempty" neo4j:"domain_id"` // 所属域名（落库时填充，便于去重与统计）
	Type        string    `json:"type" neo4j:"type"`               // xss, sqli, csrf, etc.
	Name        string    `json:"name" neo4j:"name"`
	Severity    string    `json:"severity" neo4j:"severity"`       // high, medium, low
	Description string    `json:"description" neo4j:"description"`
	Evidence     string    `json:"evidence" neo4j:"evidence"`       // 证据
	URL         string    `json:"url" neo4j:"url"`
	Parameter   string    `json:"parameter" neo4j:"parameter"`
	Remediation string    `json:"remediation" neo4j:"remediation"`  // 修复建议
	Verified    bool      `json:"verified" neo4j:"verified"`
	FoundAt     time.Time `json:"found_at" neo4j:"found_at"`
	// Fingerprint 去重指纹：维度为「域名 + 漏洞类型 + 受影响 URL + 参数」。
	// 由 VulnFingerprint 计算；历史存量（未落库指纹）为 ""，统计时回退到节点 id 单算，互不影响。
	Fingerprint string `json:"fingerprint,omitempty" neo4j:"fingerprint"`
}

// VulnFingerprint 计算漏洞唯一标识（去重指纹）。
// 维度：域名(DomainID) + 漏洞类型(Type) + 受影响 URL + 参数(Parameter)。
// 用于 Dashboard 去重统计与工单去重：同一域名多次扫描命中相同漏洞，指纹一致只计一次。
// 字段统一做大小写归一与尾部斜杠裁剪，保证跨扫描结果稳定。
func VulnFingerprint(domainID, vulnType, url, param string) string {
	norm := func(s string) string {
		s = strings.ToLower(strings.TrimSpace(s))
		s = strings.TrimSuffix(s, "/")
		// 去除查询串差异过大的情况：URL 仅保留 path 之前的主机+路径，参数单独作为维度
		return s
	}
	parts := []string{norm(domainID), norm(vulnType), norm(url), norm(param)}
	raw := strings.Join(parts, "\x1f") // 单元分隔符，避免字段拼接歧义
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// SensitiveInfo 敏感信息泄露
type SensitiveInfo struct {
	ID         string    `json:"id" neo4j:"id"`
	ScanJobID   string    `json:"scan_job_id" neo4j:"scan_job_id"`
	PageID      string    `json:"page_id" neo4j:"page_id"`
	Type        string    `json:"type" neo4j:"type"`               // email, api_key, private_key, etc.
	Value       string    `json:"value" neo4j:"value"`             // 脱敏后的值
	Location    string    `json:"location" neo4j:"location"`       // 在页面中的位置
	URL         string    `json:"url" neo4j:"url"`
	Severity    string    `json:"severity" neo4j:"severity"`
	Remediation string    `json:"remediation" neo4j:"remediation"`
	FoundAt     time.Time `json:"found_at" neo4j:"found_at"`
}

// SensitiveRule 敏感信息检测规则
type SensitiveRule struct {
	ID          string   `json:"id" neo4j:"id"`
	DomainID    string   `json:"domain_id" neo4j:"domain_id"`      // null表示全局规则
	Name        string   `json:"name" neo4j:"name"`
	Type        string   `json:"type" neo4j:"type"`               // keyword, regex, file_extension
	Pattern     string   `json:"pattern" neo4j:"pattern"`         // 关键词或正则
	Severity    string   `json:"severity" neo4j:"severity"`
	Enabled     bool     `json:"enabled" neo4j:"enabled"`
	CreatedAt   time.Time `json:"created_at" neo4j:"created_at"`
}

// Alert 告警
type Alert struct {
	ID           string    `json:"id" neo4j:"id"`
	DomainID     string    `json:"domain_id" neo4j:"domain_id"`
	ScanJobID    string    `json:"scan_job_id" neo4j:"scan_job_id"`
	Type         string    `json:"type" neo4j:"type"`              // vulnerability, sensitive_info
	ReferenceID  string    `json:"reference_id" neo4j:"reference_id"` // 关联的漏洞或敏感信息ID
	Title        string    `json:"title" neo4j:"title"`
	Content      string    `json:"content" neo4j:"content"`
	Severity     string    `json:"severity" neo4j:"severity"`
	Status       string    `json:"status" neo4j:"status"`          // new, acknowledged, resolved, false_positive
	ResolvedAt   *time.Time `json:"resolved_at,omitempty" neo4j:"resolved_at"`
	ResolvedBy   string    `json:"resolved_by,omitempty" neo4j:"resolved_by"`
	CreatedAt    time.Time `json:"created_at" neo4j:"created_at"`
}

// Report 巡检报告
type Report struct {
	ID          string    `json:"id" neo4j:"id"`
	ScanJobID   string    `json:"scan_job_id" neo4j:"scan_job_id"`
	DomainID    string    `json:"domain_id" neo4j:"domain_id"`
	Title       string    `json:"title" neo4j:"title"`
	Content     string    `json:"content" neo4j:"content"`         // Markdown格式
	GeneratedAt time.Time `json:"generated_at" neo4j:"generated_at"`
	CreatedAt   time.Time `json:"created_at" neo4j:"created_at"`
}

// User 系统用户（注册/登录/角色权限）
type User struct {
	ID           string    `json:"id" neo4j:"id"`
	Username     string    `json:"username" neo4j:"username"`
	PasswordHash string    `json:"-" neo4j:"password_hash"` // 不对外暴露
	Role         string    `json:"role" neo4j:"role"`       // admin | user
	RoleLevel    int       `json:"role_level" neo4j:"role_level"` // 权限级别 0-3
	Email        string    `json:"email,omitempty" neo4j:"email"`
	CreatedAt    time.Time `json:"created_at" neo4j:"created_at"`
	UpdatedAt    time.Time `json:"updated_at" neo4j:"updated_at"`
}

// 角色常量
const (
	RoleAdmin = "admin"
	RoleUser  = "user"
)

// 权限级别常量
const (
	RoleLevelViewOnly    = 0 // 只能查看扫描结果
	RoleLevelScanner     = 1 // 可以进行扫描
	RoleLevelViewAdmin   = 2 // 可以查看后台账号管理系统但无法操作
	RoleLevelAdmin       = 3 // 可以操作后台账号管理系统并更改其他账号的权限值 (默认admin)
)

// RoleLevelMap 角色字符串到权限值的映射
var RoleLevelMap = map[string]int{
	RoleAdmin: RoleLevelAdmin,
	RoleUser:  RoleLevelViewOnly,
}

// GetRoleLevel 获取角色的权限级别
func GetRoleLevel(role string) int {
	if level, ok := RoleLevelMap[role]; ok {
		return level
	}
	return RoleLevelViewOnly
}

// Ticket 安全工单（误报研判 / 自动巡检发现均可创建）
//
// 为保证列表与详情无需额外 join 即可完整展示，工单采用“自包含”设计：
// 资产信息、漏洞名称/描述、风险等级、证据与研判建议在创建时一次性写入并持久化。
// 旧工单（仅含 vuln_id/notes）这些字段为空，前端以“暂无”占位，不破坏已有数据。
type Ticket struct {
	ID        string    `json:"id" neo4j:"id"`
	VulnID    string    `json:"vuln_id" neo4j:"vuln_id"`           // 关联的漏洞ID（自动化工单可为空）
	ScanJobID string    `json:"scan_job_id" neo4j:"scan_job_id"`   // 关联的扫描任务ID
	Status    string    `json:"status" neo4j:"status"`             // pending, confirmed, excluded, resolved
	Assignee  string    `json:"assignee,omitempty" neo4j:"assignee"` // 处理人
	Notes     string    `json:"notes,omitempty" neo4j:"notes"`     // 处理备注 / 误报理由
	CreatorID string    `json:"creator_id" neo4j:"creator_id"`     // 创建者ID
	CreatedAt time.Time `json:"created_at" neo4j:"created_at"`
	UpdatedAt time.Time `json:"updated_at" neo4j:"updated_at"`

	// 自包含展示字段（创建时一次性填充，前端直接渲染，无需 join 漏洞表）
	Title             string `json:"title,omitempty" neo4j:"title"`                     // 工单标题
	Type              string `json:"type,omitempty" neo4j:"type"`                       // 工单类别：false_positive(误报) / real_attack(真实攻击) / investigation(调查中)
	Description       string `json:"description,omitempty" neo4j:"description"`         // 问题描述（手动填写 / 自动从发现填充）
	AssetName         string `json:"asset_name,omitempty" neo4j:"asset_name"`           // 资产（域名/站点）
	AssetURL          string `json:"asset_url,omitempty" neo4j:"asset_url"`             // 资产URL
	VulnName          string `json:"vuln_name,omitempty" neo4j:"vuln_name"`             // 漏洞名称
	VulnType          string `json:"vuln_type,omitempty" neo4j:"vuln_type"`             // 漏洞类型（xss/sqli/component...）
	RiskLevel         string `json:"risk_level,omitempty" neo4j:"risk_level"`          // 风险等级 high|medium|low
	VulnDescription   string `json:"vuln_description,omitempty" neo4j:"vuln_description"` // 漏洞描述
	Evidence          string `json:"evidence,omitempty" neo4j:"evidence"`               // 证据数据
	// 研判建议（基于扫描结果给出的可执行结论）
	HarmDescription     string `json:"harm_description,omitempty" neo4j:"harm_description"`       // 危害说明
	RemediationPriority string `json:"remediation_priority,omitempty" neo4j:"remediation_priority"` // 修复优先级 P0/P1/P2
	MitigationMeasures  string `json:"mitigation_measures,omitempty" neo4j:"mitigation_measures"`    // 临时缓解措施
	RetestMethod        string `json:"retest_method,omitempty" neo4j:"retest_method"`              // 复测方式

	// 去重相关：与漏洞同维度（域名 + 漏洞类型 + 受影响 URL/参数）的指纹。
	// 自动巡检命中相同指纹的漏洞时，复用同一条工单而非新建；仅更新命中次数与最近扫描时间。
	// 历史存量工单（未落库指纹）为空字符串，每条独立计，不与新工单冲突。
	Fingerprint  string    `json:"fingerprint,omitempty" neo4j:"fingerprint"`     // 去重指纹
	HitCount     int       `json:"hit_count,omitempty" neo4j:"hit_count"`         // 累计命中次数（同指纹被扫描命中的次数）
	LastSeenAt   time.Time `json:"last_seen_at,omitempty" neo4j:"last_seen_at"`   // 最近一次命中时间
}

// TicketStatus 常量
const (
	TicketStatusPending   = "pending"   // 待审核
	TicketStatusConfirmed = "confirmed" // 已确认
	TicketStatusExcluded  = "excluded"  // 已排除（误报/不处理）
	TicketStatusResolved  = "resolved"  // 已处理
)

