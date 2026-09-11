package models

import "time"

// Baseline 巡检基线：某个域名在某一次扫描时确认的「正常状态快照」。
//
// 命题要求巡检支持「基线对比」。做法是把某次扫描的页面集合（URL + 内容指纹）
// 与漏洞集合（指纹）固化为基线，之后每次扫描都与它比对，
// 从而回答两个运维最关心的问题：
//   - 站点**多了/少了/变了**哪些页面（页面篡改、暗链、被挂马页面）
//   - **新增**了哪些漏洞、哪些漏洞**已修复**
//
// 存储上把快照序列化成 JSON 挂在单个 :Baseline 节点上（每域名一条）。
// 相比为每个页面建 :BaselinePage 节点，这种形态写入/读取都是一次往返，
// 且基线本身是「一次性快照」、不需要被图查询遍历，用图关系反而是负担。
type Baseline struct {
	ID        string    `json:"id" neo4j:"id"`
	DomainID  string    `json:"domain_id" neo4j:"domain_id"`
	ScanJobID string    `json:"scan_job_id" neo4j:"scan_job_id"` // 基线取自哪次扫描
	CreatedAt time.Time `json:"created_at" neo4j:"created_at"`
	Note      string    `json:"note,omitempty" neo4j:"note"`

	PageCount int `json:"page_count" neo4j:"page_count"`
	VulnCount int `json:"vuln_count" neo4j:"vuln_count"`

	// PagesJSON：{"页面URL": "内容指纹"}
	PagesJSON string `json:"-" neo4j:"pages_json"`
	// VulnsJSON：[{"fingerprint":..,"type":..,"severity":..,"url":..,"name":..}]
	VulnsJSON string `json:"-" neo4j:"vulns_json"`
}

// BaselinePageChange 单个页面的内容变化。
type BaselinePageChange struct {
	URL      string `json:"url"`
	OldHash  string `json:"old_hash"`
	NewHash  string `json:"new_hash"`
	Title    string `json:"title,omitempty"`
	Severity string `json:"severity"` // high / medium / low：按变化性质定级
	Reason   string `json:"reason"`   // 变化说明（如「页面内容较基线发生变更」）
}

// BaselineVulnBrief 漏洞/风险条目的精简视图（用于差异清单展示）。
type BaselineVulnBrief struct {
	Fingerprint string `json:"fingerprint"`
	Type        string `json:"type"`
	Name        string `json:"name,omitempty"`
	Severity    string `json:"severity,omitempty"`
	URL         string `json:"url,omitempty"`
}

// BaselineDiff 基线与当前扫描的差异结果。
type BaselineDiff struct {
	DomainID   string    `json:"domain_id"`
	BaselineID string    `json:"baseline_id"`
	BaselineAt time.Time `json:"baseline_at"`
	CurrentAt  time.Time `json:"current_at"`
	ScanJobID  string    `json:"scan_job_id"`

	PagesAdded   []BaselineVulnBrief  `json:"pages_added"`   // 新出现的页面
	PagesRemoved []BaselineVulnBrief  `json:"pages_removed"` // 消失的页面
	PagesChanged []BaselinePageChange `json:"pages_changed"` // 内容指纹变化的页面（疑似篡改）

	VulnsAdded []BaselineVulnBrief `json:"vulns_added"` // 新增风险
	VulnsFixed []BaselineVulnBrief `json:"vulns_fixed"` // 已修复（基线有、本次无）

	// HasDrift 是否存在任何漂移，便于告警/巡检判定「是否需要人工介入」
	HasDrift bool `json:"has_drift"`
	// Summary 一句话结论，直接可写入告警与报告
	Summary string `json:"summary"`
}
