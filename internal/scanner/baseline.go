package scanner

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"security-agent/internal/models"
)

// baselinePageSnapshot 基线中的单个页面（序列化用）。
type baselinePageSnapshot struct {
	URL         string `json:"url"`
	ContentHash string `json:"content_hash"`
	Title       string `json:"title,omitempty"`
}

// baselineVulnSnapshot 基线中的单条风险（序列化用）。
type baselineVulnSnapshot struct {
	Fingerprint string `json:"fingerprint"`
	Type        string `json:"type"`
	Name        string `json:"name,omitempty"`
	Severity    string `json:"severity,omitempty"`
	URL         string `json:"url,omitempty"`
}

// BuildBaselineSnapshot 把某次扫描的结果固化为基线快照。
//
// 页面取"该批次抓到的页面"（按 scan_job_id 过滤），而不是域名下所有历史页面，
// 否则基线会把历次爬取的结果混在一起，对比出来的差异毫无意义。
func BuildBaselineSnapshot(domainID, scanJobID string, pages []*models.Page, vulns []*models.Vulnerability, note string) (*models.Baseline, error) {
	ps := make([]baselinePageSnapshot, 0, len(pages))
	seen := map[string]bool{}
	for _, p := range pages {
		if p == nil || p.URL == "" || seen[p.URL] {
			continue
		}
		seen[p.URL] = true
		ps = append(ps, baselinePageSnapshot{URL: p.URL, ContentHash: p.ContentHash, Title: p.Title})
	}
	sort.Slice(ps, func(i, j int) bool { return ps[i].URL < ps[j].URL })

	vs := make([]baselineVulnSnapshot, 0, len(vulns))
	seenV := map[string]bool{}
	for _, v := range vulns {
		if v == nil || v.Fingerprint == "" || seenV[v.Fingerprint] {
			continue
		}
		seenV[v.Fingerprint] = true
		vs = append(vs, baselineVulnSnapshot{
			Fingerprint: v.Fingerprint, Type: v.Type, Name: v.Name,
			Severity: v.Severity, URL: v.URL,
		})
	}

	pj, err := json.Marshal(ps)
	if err != nil {
		return nil, fmt.Errorf("序列化页面快照失败: %w", err)
	}
	vj, err := json.Marshal(vs)
	if err != nil {
		return nil, fmt.Errorf("序列化风险快照失败: %w", err)
	}

	return &models.Baseline{
		DomainID:  domainID,
		ScanJobID: scanJobID,
		Note:      note,
		CreatedAt: time.Now(), // 快照生成时刻；仓储落库时会再统一覆盖一次
		PageCount: len(ps),
		VulnCount: len(vs),
		PagesJSON: string(pj),
		VulnsJSON: string(vj),
	}, nil
}

// DiffAgainstBaseline 计算当前扫描结果相对基线的漂移。
//
// 覆盖命题要求的"基线对比"与"页面篡改"两条：
//   - 页面维度：新增 / 消失 / 内容指纹变化（指纹变化即疑似篡改）
//   - 风险维度：新增 / 已修复
func DiffAgainstBaseline(base *models.Baseline, curScanJobID string, pages []*models.Page, vulns []*models.Vulnerability) (*models.BaselineDiff, error) {
	diff := &models.BaselineDiff{
		DomainID:     base.DomainID,
		BaselineID:   base.ID,
		BaselineAt:   base.CreatedAt,
		CurrentAt:    time.Now(),
		ScanJobID:    curScanJobID,
		PagesAdded:   []models.BaselineVulnBrief{},
		PagesRemoved: []models.BaselineVulnBrief{},
		PagesChanged: []models.BaselinePageChange{},
		VulnsAdded:   []models.BaselineVulnBrief{},
		VulnsFixed:   []models.BaselineVulnBrief{},
	}

	var basePages []baselinePageSnapshot
	if base.PagesJSON != "" {
		if err := json.Unmarshal([]byte(base.PagesJSON), &basePages); err != nil {
			return nil, fmt.Errorf("解析基线页面快照失败: %w", err)
		}
	}
	var baseVulns []baselineVulnSnapshot
	if base.VulnsJSON != "" {
		if err := json.Unmarshal([]byte(base.VulnsJSON), &baseVulns); err != nil {
			return nil, fmt.Errorf("解析基线风险快照失败: %w", err)
		}
	}

	basePageByURL := make(map[string]string, len(basePages))
	for _, p := range basePages {
		basePageByURL[p.URL] = p.ContentHash
	}
	curPageByURL := make(map[string]*models.Page, len(pages))
	for _, p := range pages {
		if p == nil || p.URL == "" {
			continue
		}
		curPageByURL[p.URL] = p
	}

	// 页面：新增 / 内容变化
	for url, p := range curPageByURL {
		oldHash, existed := basePageByURL[url]
		switch {
		case !existed:
			diff.PagesAdded = append(diff.PagesAdded, models.BaselineVulnBrief{
				Type: "page_added", URL: url, Name: p.Title, Severity: "medium",
			})
		case oldHash != "" && p.ContentHash != "" && oldHash != p.ContentHash:
			diff.PagesChanged = append(diff.PagesChanged, models.BaselinePageChange{
				URL: url, OldHash: oldHash, NewHash: p.ContentHash, Title: p.Title,
				Severity: "high",
				Reason:   "页面内容指纹较基线发生变化，疑似被篡改或暗链注入，需人工确认",
			})
		}
	}
	// 页面：消失
	for _, p := range basePages {
		if _, ok := curPageByURL[p.URL]; !ok {
			diff.PagesRemoved = append(diff.PagesRemoved, models.BaselineVulnBrief{
				Type: "page_removed", URL: p.URL, Name: p.Title, Severity: "low",
			})
		}
	}

	baseVulnByFP := make(map[string]baselineVulnSnapshot, len(baseVulns))
	for _, v := range baseVulns {
		baseVulnByFP[v.Fingerprint] = v
	}
	curVulnByFP := make(map[string]*models.Vulnerability, len(vulns))
	for _, v := range vulns {
		if v == nil || v.Fingerprint == "" {
			continue
		}
		curVulnByFP[v.Fingerprint] = v
	}

	for fp, v := range curVulnByFP {
		if _, ok := baseVulnByFP[fp]; !ok {
			diff.VulnsAdded = append(diff.VulnsAdded, models.BaselineVulnBrief{
				Fingerprint: fp, Type: v.Type, Name: v.Name, Severity: v.Severity, URL: v.URL,
			})
		}
	}
	for fp, v := range baseVulnByFP {
		if _, ok := curVulnByFP[fp]; !ok {
			diff.VulnsFixed = append(diff.VulnsFixed, models.BaselineVulnBrief{
				Fingerprint: fp, Type: v.Type, Name: v.Name, Severity: v.Severity, URL: v.URL,
			})
		}
	}

	// 稳定排序，保证同一份数据每次输出顺序一致（便于比对与归档）
	sortBriefs(diff.PagesAdded)
	sortBriefs(diff.PagesRemoved)
	sortBriefs(diff.VulnsAdded)
	sortBriefs(diff.VulnsFixed)
	sort.Slice(diff.PagesChanged, func(i, j int) bool { return diff.PagesChanged[i].URL < diff.PagesChanged[j].URL })

	diff.HasDrift = len(diff.PagesAdded)+len(diff.PagesRemoved)+len(diff.PagesChanged)+
		len(diff.VulnsAdded)+len(diff.VulnsFixed) > 0
	diff.Summary = baselineDiffSummary(diff)
	return diff, nil
}

func sortBriefs(list []models.BaselineVulnBrief) {
	sort.Slice(list, func(i, j int) bool {
		if list[i].URL != list[j].URL {
			return list[i].URL < list[j].URL
		}
		return list[i].Fingerprint < list[j].Fingerprint
	})
}

// baselineDiffSummary 生成一句话结论，可直接用于告警内容与报告摘要。
func baselineDiffSummary(d *models.BaselineDiff) string {
	if !d.HasDrift {
		return "与基线一致，未发现站点变更或新增风险"
	}
	var parts []string
	if n := len(d.PagesChanged); n > 0 {
		parts = append(parts, fmt.Sprintf("页面内容变更 %d 个（疑似篡改，建议优先核实）", n))
	}
	if n := len(d.PagesAdded); n > 0 {
		parts = append(parts, fmt.Sprintf("新增页面 %d 个", n))
	}
	if n := len(d.PagesRemoved); n > 0 {
		parts = append(parts, fmt.Sprintf("页面消失 %d 个（也可能是本轮爬取范围变化，需确认）", n))
	}
	if n := len(d.VulnsAdded); n > 0 {
		parts = append(parts, fmt.Sprintf("新增风险 %d 条", n))
	}
	if n := len(d.VulnsFixed); n > 0 {
		parts = append(parts, fmt.Sprintf("已修复 %d 条", n))
	}
	return "基线对比发现漂移：" + strings.Join(parts, "；")
}
