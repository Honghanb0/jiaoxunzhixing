package agent

import (
	"crypto/sha1"
	"fmt"
	"strings"
	"time"

	"security-agent/internal/models"
)

// ticketFingerprint 生成工单去重指纹：以「漏洞类型 + 影响资产 URL + 扫描作业」三要素归一化拼接后取 sha1。
// 同一扫描作业内、同类型且同 URL 的漏洞视为同一条，复用而非新建，避免重复建单；
// 不同扫描作业（不同 scan_job_id）指纹不同，因此「每次确有发现的运行都应留下自己的工单」不受影响。
func ticketFingerprint(vulnType, assetURL, scanJobID string) string {
	h := sha1.New()
	h.Write([]byte(strings.ToLower(strings.TrimSpace(vulnType)) + "|" +
		strings.ToLower(strings.TrimSpace(assetURL)) + "|" +
		strings.TrimSpace(scanJobID)))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// normalizeTicketContext 提供给字段规范化的上下文（目标资产等）。
type normalizeTicketContext struct {
	TargetHost string // 目标资产 host（用于资产字段兜底）
}

// normalizeTicketFields 统一校验并补全工单必填字段，缺失时使用可追溯的默认值填充。
// 返回「本次补填说明」列表，便于调用方记录到步骤结果 / 日志，保证每条工单处理结果可追踪。
//
// 校验项（对应需求 3）：标题、漏洞类型、严重程度、影响资产、来源、复现信息。
func normalizeTicketFields(t *models.Ticket, ctx normalizeTicketContext) []string {
	var notes []string

	// 1) 漏洞类型：缺失 -> "unknown"（而非留空，避免被 vulnTypeToCategory 当成非漏洞）
	if strings.TrimSpace(t.VulnType) == "" {
		t.VulnType = "unknown"
		notes = append(notes, "vuln_type 缺失，已置为 unknown（请模型补充具体类型）")
	}

	// 2) 标题：缺失 -> 按类型生成可追溯默认标题
	if strings.TrimSpace(t.Title) == "" {
		t.Title = fmt.Sprintf("未命名安全工单（类型：%s）", t.VulnType)
		notes = append(notes, "title 缺失，已用默认标题")
	}

	// 3) 严重程度：先归一化模型给定值，无法识别则按类别兜底，仍无则中危（绝不置空）
	risk := normRisk(t.RiskLevel)
	if risk == "" {
		risk = defaultRiskForCategory(vulnTypeToCategory(t.VulnType))
	}
	if risk == "" {
		risk = "medium"
	}
	if risk != strings.TrimSpace(t.RiskLevel) {
		notes = append(notes, fmt.Sprintf("risk_level 缺失/非法(%q)，已置为 %s", t.RiskLevel, risk))
	}
	t.RiskLevel = risk

	// 4) 影响资产：asset_url / asset_name 缺失 -> 用目标 host 兜底，再无则用 scan_job 占位（可追溯）
	switch {
	case t.AssetURL == "" && t.AssetName == "":
		asset := ctx.TargetHost
		if asset == "" {
			asset = fmt.Sprintf("(scan_job:%s)", t.ScanJobID)
		}
		t.AssetURL = asset
		t.AssetName = asset
		notes = append(notes, fmt.Sprintf("影响资产缺失，已用 %s 兜底", asset))
	case t.AssetName == "":
		t.AssetName = t.AssetURL
	case t.AssetURL == "":
		t.AssetURL = t.AssetName
	}

	// 5) 来源：标记智能体创建，缺失时补齐
	if t.CreatorID == "" {
		t.CreatorID = "agent"
	}
	if t.Type == "" {
		t.Type = "investigation"
	}
	if t.Notes == "" {
		t.Notes = "由自主智能体创建"
	}

	// 6) 复现信息：Evidence 缺失 -> 用资产+类型兜底；RetestMethod 缺失 -> 给出复扫建议
	if strings.TrimSpace(t.Evidence) == "" {
		t.Evidence = fmt.Sprintf("影响资产：%s；漏洞类型：%s（模型未提供复现细节，请补充完整 PoC）", t.AssetURL, t.VulnType)
		notes = append(notes, "复现信息(Evidence)缺失，已用资产/类型兜底")
	}
	if strings.TrimSpace(t.RetestMethod) == "" {
		t.RetestMethod = fmt.Sprintf("修复后重新扫描 %s 验证", t.AssetURL)
	}

	// 去重指纹：即便模型未传，也基于三要素自动生成，保证后续幂等判定可用
	if t.Fingerprint == "" {
		t.Fingerprint = ticketFingerprint(t.VulnType, t.AssetURL, t.ScanJobID)
	}
	if t.HitCount == 0 {
		t.HitCount = 1
	}
	now := time.Now()
	if t.LastSeenAt.IsZero() {
		t.LastSeenAt = now
	}
	return notes
}
