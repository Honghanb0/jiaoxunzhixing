package scanner

import (
	"testing"

	"security-agent/internal/models"
)

func mkPage(url, hash string) *models.Page {
	return &models.Page{URL: url, ContentHash: hash, Title: "t-" + url}
}

func mkVuln(fp, typ, sev, url string) *models.Vulnerability {
	return &models.Vulnerability{Fingerprint: fp, Type: typ, Severity: sev, URL: url, Name: typ + "-name"}
}

func TestBaselineDiff(t *testing.T) {
	basePages := []*models.Page{
		mkPage("https://a.com/", "h1"),
		mkPage("https://a.com/x", "h2"),
		mkPage("https://a.com/gone", "h3"),
	}
	baseVulns := []*models.Vulnerability{
		mkVuln("fp-1", "xss", "high", "https://a.com/x"),
		mkVuln("fp-2", "sqli", "high", "https://a.com/x"),
	}

	base, err := BuildBaselineSnapshot("d1", "job-base", basePages, baseVulns, "首次巡检确认正常")
	if err != nil {
		t.Fatalf("构建基线失败: %v", err)
	}
	if base.PageCount != 3 || base.VulnCount != 2 {
		t.Fatalf("基线计数错误: pages=%d vulns=%d", base.PageCount, base.VulnCount)
	}

	// 当前扫描：a.com/ 内容变了、x 不变、gone 消失、新增 new 页面
	curPages := []*models.Page{
		mkPage("https://a.com/", "h1-CHANGED"),
		mkPage("https://a.com/x", "h2"),
		mkPage("https://a.com/new", "h9"),
	}
	// 风险：fp-1 仍在、fp-2 已修复、新增 fp-3
	curVulns := []*models.Vulnerability{
		mkVuln("fp-1", "xss", "high", "https://a.com/x"),
		mkVuln("fp-3", "csrf", "medium", "https://a.com/new"),
	}

	diff, err := DiffAgainstBaseline(base, "job-cur", curPages, curVulns)
	if err != nil {
		t.Fatalf("基线对比失败: %v", err)
	}

	if len(diff.PagesChanged) != 1 || diff.PagesChanged[0].URL != "https://a.com/" {
		t.Errorf("页面变更判定错误: %+v", diff.PagesChanged)
	}
	if len(diff.PagesAdded) != 1 || diff.PagesAdded[0].URL != "https://a.com/new" {
		t.Errorf("新增页面判定错误: %+v", diff.PagesAdded)
	}
	if len(diff.PagesRemoved) != 1 || diff.PagesRemoved[0].URL != "https://a.com/gone" {
		t.Errorf("消失页面判定错误: %+v", diff.PagesRemoved)
	}
	if len(diff.VulnsAdded) != 1 || diff.VulnsAdded[0].Fingerprint != "fp-3" {
		t.Errorf("新增风险判定错误: %+v", diff.VulnsAdded)
	}
	if len(diff.VulnsFixed) != 1 || diff.VulnsFixed[0].Fingerprint != "fp-2" {
		t.Errorf("已修复风险判定错误: %+v", diff.VulnsFixed)
	}
	if !diff.HasDrift {
		t.Error("存在差异时 HasDrift 应为 true")
	}
	if diff.Summary == "" {
		t.Error("Summary 不应为空")
	}
}

func TestBaselineDiffNoDrift(t *testing.T) {
	pages := []*models.Page{mkPage("https://b.com/", "h1")}
	vulns := []*models.Vulnerability{mkVuln("fp-1", "xss", "high", "https://b.com/")}

	base, err := BuildBaselineSnapshot("d2", "job-1", pages, vulns, "")
	if err != nil {
		t.Fatalf("构建基线失败: %v", err)
	}
	if base.CreatedAt.IsZero() {
		t.Error("基线应带创建时间")
	}

	diff, err := DiffAgainstBaseline(base, "job-2", pages, vulns)
	if err != nil {
		t.Fatalf("基线对比失败: %v", err)
	}
	if diff.HasDrift {
		t.Errorf("完全一致时不应判定为漂移: %+v", diff)
	}
	if len(diff.PagesAdded)+len(diff.PagesRemoved)+len(diff.PagesChanged) != 0 {
		t.Error("页面维度不应有差异")
	}
	if len(diff.VulnsAdded)+len(diff.VulnsFixed) != 0 {
		t.Error("风险维度不应有差异")
	}
}

func TestBaselineSnapshotDedup(t *testing.T) {
	// 同一 URL 在一次扫描里重复出现（理论上不该有，但爬虫边界情况下可能），
	// 快照必须去重，否则 diff 会把同一页面重复计入。
	pages := []*models.Page{
		mkPage("https://c.com/", "h1"),
		mkPage("https://c.com/", "h1"),
	}
	vulns := []*models.Vulnerability{
		mkVuln("fp-1", "xss", "high", "https://c.com/"),
		mkVuln("fp-1", "xss", "high", "https://c.com/"),
	}
	base, err := BuildBaselineSnapshot("d3", "job-1", pages, vulns, "")
	if err != nil {
		t.Fatalf("构建基线失败: %v", err)
	}
	if base.PageCount != 1 {
		t.Errorf("页面快照未去重: %d", base.PageCount)
	}
	if base.VulnCount != 1 {
		t.Errorf("风险快照未去重: %d", base.VulnCount)
	}
}

func TestBaselineDiffEmptyHashNotTreatedAsChange(t *testing.T) {
	// 内容指纹为空表示"该次没抓到可用的内容哈希"，不能据此判定页面被篡改，
	// 否则会产生大量假告警。
	base, _ := BuildBaselineSnapshot("d4", "job-1",
		[]*models.Page{mkPage("https://d.com/", "h1")},
		[]*models.Vulnerability{}, "")
	diff, err := DiffAgainstBaseline(base, "job-2",
		[]*models.Page{mkPage("https://d.com/", "")}, nil)
	if err != nil {
		t.Fatalf("基线对比失败: %v", err)
	}
	if len(diff.PagesChanged) != 0 {
		t.Errorf("空内容指纹不应判为篡改: %+v", diff.PagesChanged)
	}
}
