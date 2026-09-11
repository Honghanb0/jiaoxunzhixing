package models

import "time"

// 复测状态取值。语义清晰、可直接进报告与前端展示。
const (
	RetestNotRetested  = "not_retested"  // 尚未复测
	RetestStillPresent = "still_present" // 复测确认问题仍然存在
	RetestFixed        = "fixed"         // 复测确认已修复
	RetestInconclusive = "inconclusive"  // 目标不可达/无法判定，需要人工复核
)

// RetestResult 单条风险的复测结果。
//
// 命题要求巡检支持"复测"与对结果"验证"：修复动作做完之后，
// 必须能重新确认问题是否真的消失，而不是只看工单状态被人工改成"已处理"。
// 复测的做法是重新抓取该风险对应的 URL，用同一套检测逻辑重跑一遍，
// 看同类型发现是否复现——复现即仍存在，不复现即已修复。
type RetestResult struct {
	VulnerabilityID string    `json:"vulnerability_id"`
	URL             string    `json:"url"`
	VulnType        string    `json:"vuln_type"`
	Status          string    `json:"status"`   // 见上方 Retest* 常量
	Verified        bool      `json:"verified"` // 复测通过（问题仍存在）则为 true，代表"已验证的真实风险"
	Message         string    `json:"message"`
	CheckedAt       time.Time `json:"checked_at"`
	// HTTPStatus 复测时的响应状态码，便于解释 inconclusive 的原因
	HTTPStatus int `json:"http_status,omitempty"`
	// RetestCount 累计复测次数
	RetestCount int `json:"retest_count"`
}
