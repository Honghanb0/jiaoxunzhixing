package inspection

import (
	"strings"
	"testing"

	"security-agent/internal/models"
	"security-agent/internal/scanner"
)

func TestParseInspectionResult_Valid(t *testing.T) {
	raw := `{"overall_risk":"high","summary":"存在高危漏洞","findings":[{"title":"SQLi","severity":"high","url":"http://x/a","recommendation":"预编译"}],"recommendations":["升级WAF"]}`
	res, err := parseInspectionResult(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.OverallRisk != "high" {
		t.Errorf("overall_risk = %q, want high", res.OverallRisk)
	}
	if len(res.Findings) != 1 || res.Findings[0].Severity != "high" {
		t.Errorf("findings parse wrong: %+v", res.Findings)
	}
}

func TestParseInspectionResult_MarkdownWrapped(t *testing.T) {
	raw := "```json\n" + `{"overall_risk":"medium","summary":"中危","findings":[]}` + "\n```"
	res, err := parseInspectionResult(raw)
	if err != nil {
		t.Fatalf("markdown-wrapped parse failed: %v", err)
	}
	if res.OverallRisk != "medium" {
		t.Errorf("overall_risk = %q", res.OverallRisk)
	}
}

func TestParseInspectionResult_Garbage(t *testing.T) {
	if _, err := parseInspectionResult("这根本不是 JSON 只是一段中文说明"); err == nil {
		t.Fatal("expected error for non-JSON content")
	}
}

func TestCountBySeverity(t *testing.T) {
	findings := []models.InspectionFinding{
		{Severity: "high"}, {Severity: "HIGH"}, {Severity: "medium"},
		{Severity: "low"}, {Severity: "none"},
	}
	h, m, l := countBySeverity(findings)
	if h != 2 || m != 1 || l != 1 {
		t.Errorf("countBySeverity = (%d,%d,%d), want (2,1,1)", h, m, l)
	}
}

func TestNormalizeRisk(t *testing.T) {
	cases := map[string]string{"high": "high", "严重": "high", "Medium": "medium", "低": "low", "none": "none", "": "none", "xxx": "none"}
	for in, want := range cases {
		if got := normalizeRisk(in); got != want {
			t.Errorf("normalizeRisk(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFallbackFromScan(t *testing.T) {
	res := &scanner.ScanResults{
		Summary: &models.ScanSummary{TotalPages: 5, TotalVulns: 3, HighSeverity: 1, MediumSeverity: 2, LowSeverity: 0, SensitiveFound: 1},
		Vulnerabilities: []*models.Vulnerability{
			{Name: "SQLi", Severity: "high", URL: "http://x/1"},
			{Name: "XSS", Severity: "medium", URL: "http://x/2"},
		},
	}
	out := fallbackFromScan(res)
	if out.OverallRisk != "high" {
		t.Errorf("overall_risk = %q, want high", out.OverallRisk)
	}
	if len(out.Findings) != 2 {
		t.Errorf("findings = %d, want 2", len(out.Findings))
	}
	if !strings.Contains(out.Summary, "高危 1") {
		t.Errorf("summary missing high count: %q", out.Summary)
	}
}

func TestFallbackFromScan_Nil(t *testing.T) {
	out := fallbackFromScan(nil)
	if out.OverallRisk != "none" {
		t.Errorf("nil scan overall_risk = %q, want none", out.OverallRisk)
	}
}
