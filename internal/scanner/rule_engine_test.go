package scanner

import (
	"strings"
	"testing"
	"time"

	"security-agent/internal/models"
)

// TestRuleEngineLoad 验证规则引擎能正确加载内嵌规则
func TestRuleEngineLoad(t *testing.T) {
	re := NewRuleEngine("")
	rules := re.ListRules()
	if len(rules) == 0 {
		t.Fatal("规则引擎未加载任何规则")
	}
	t.Logf("成功加载 %d 条规则", len(rules))

	// 验证关键 OWASP Top 10 规则存在
	expectedIDs := []string{
		"rule-injection-sqli",
		"rule-xss-reflected",
		"rule-broken-access-control-idor",
		"rule-sensitive-file-exposure",
		"rule-xxe",
		"rule-insecure-deserialization",
		"rule-ssrf",
		"rule-command-injection",
		"rule-security-misconfiguration",
		"rule-known-vulnerable-components",
		"rule-broken-authentication",
		"rule-ssti",
		"rule-path-traversal",
	}
	for _, id := range expectedIDs {
		if _, ok := re.GetRule(id); !ok {
			t.Errorf("预期规则 %s 未加载", id)
		}
	}
}

// TestRuleEngineDASTMatch 验证 DAST 规则匹配
func TestRuleEngineDASTMatch(t *testing.T) {
	re := NewRuleEngine("")

	// 模拟一个包含 SQL 注入特征的页面
	page := &PageInfo{
		URL:        "http://test.com/sqli?id=1' OR '1'='1",
		StatusCode: 200,
		RawContent: `<html><body>
			<div class="error">You have an error in your SQL syntax near "' OR '1'='1"</div>
			<div>id=1 OR 1=1 returned 100 results</div>
		</body></html>`,
	}

	results := re.MatchDAST(page)
	if len(results) == 0 {
		t.Fatal("预期匹配到 SQL 注入规则，但未匹配到任何结果")
	}

	foundSQLi := false
	for _, r := range results {
		t.Logf("匹配规则: %s, 置信度: %.2f, 等级: %s",
			r.Rule.ID, r.Confidence, r.ConfidenceLevel)
		if r.Rule.ID == "rule-injection-sqli" {
			foundSQLi = true
			if r.Confidence < 0.60 {
				t.Errorf("SQL 注入置信度过低: %.2f", r.Confidence)
			}
		}
	}
	if !foundSQLi {
		t.Error("未匹配到 SQL 注入规则")
	}
}

// TestRuleEngineXSSMatch 验证 XSS 规则匹配
func TestRuleEngineXSSMatch(t *testing.T) {
	re := NewRuleEngine("")

	page := &PageInfo{
		URL:        "http://test.com/xss?q=<img src=x onerror=alert(document.cookie)>",
		StatusCode: 200,
		RawContent: `<html><body>
			<img src=x onerror=alert(document.cookie)>
			<script>document.cookie steal</script>
		</body></html>`,
	}

	results := re.MatchDAST(page)
	foundXSS := false
	for _, r := range results {
		if r.Rule.ID == "rule-xss-reflected" {
			foundXSS = true
			t.Logf("XSS 匹配: 置信度=%.2f 等级=%s", r.Confidence, r.ConfidenceLevel)
		}
	}
	if !foundXSS {
		t.Error("未匹配到 XSS 规则")
	}
}

// TestRuleEngineSensitiveFile 验证敏感文件规则
func TestRuleEngineSensitiveFile(t *testing.T) {
	re := NewRuleEngine("")

	page := &PageInfo{
		URL:        "http://test.com/.env",
		StatusCode: 200,
		RawContent: "DB_PASSWORD=secret123\nAPI_KEY=sk-abc123\nSECRET_KEY=jwt-secret",
	}

	results := re.MatchDAST(page)
	foundSensitive := false
	for _, r := range results {
		if r.Rule.ID == "rule-sensitive-file-exposure" {
			foundSensitive = true
			t.Logf("敏感文件匹配: 置信度=%.2f", r.Confidence)
		}
	}
	if !foundSensitive {
		t.Error("未匹配到敏感文件规则")
	}
}

// TestRuleEngineNoFalsePositive 验证正常页面不误报
func TestRuleEngineNoFalsePositive(t *testing.T) {
	re := NewRuleEngine("")

	// 正常页面，不应触发高危规则
	page := &PageInfo{
		URL:        "http://test.com/index.html",
		StatusCode: 200,
		RawContent: `<html><head><title>Welcome</title></head><body>
			<nav><a href="/about">About</a></nav>
			<p>Welcome to our website.</p>
		</body></html>`,
	}

	results := re.MatchDAST(page)
	for _, r := range results {
		if r.ConfidenceLevel == "high" {
			t.Errorf("正常页面误报高危规则: %s", r.Rule.ID)
		}
	}
}

// TestCVSSParsing 验证 CVSS 向量解析
func TestCVSSParsing(t *testing.T) {
	tests := []struct {
		vector   string
		minScore float64
		severity string
	}{
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.0, "critical"},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.0, "high"},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 4.0, "medium"},
	}

	for _, tt := range tests {
		score, severity := ParseCVSSVector(tt.vector)
		t.Logf("向量 %s => 分数 %.1f 等级 %s", tt.vector, score, severity)
		if score < tt.minScore {
			t.Errorf("CVSS 分数 %.1f 低于预期最小值 %.1f", score, tt.minScore)
		}
		if severity != tt.severity {
			t.Errorf("CVSS 等级 %s 不等于预期 %s", severity, tt.severity)
		}
	}
}

// TestPoCGeneration 验证 PoC 生成
func TestPoCGeneration(t *testing.T) {
	re := NewRuleEngine("")

	poc := re.GeneratePoC("rule-injection-sqli", "http://test.com/search?q=test", 0)
	if poc == "" {
		t.Error("PoC 生成失败")
	}
	if !strings.Contains(poc, "test.com") {
		t.Error("PoC 中未包含目标 host")
	}
	if !strings.Contains(poc, "HTTP/1.1") {
		t.Error("PoC 不是有效的 HTTP 请求")
	}
	t.Logf("生成的 PoC:\n%s", poc)
}

// TestReporterGeneration 验证报告生成
func TestReporterGeneration(t *testing.T) {
	re := NewRuleEngine("")
	reporter := NewReporter(re)

	vulns := createTestVulns()
	bundle := reporter.GenerateReport(vulns, "http://test.com")

	if bundle.Markdown == "" {
		t.Error("Markdown 报告为空")
	}
	if bundle.HTML == "" {
		t.Error("HTML 报告为空")
	}
	if bundle.JSON == nil {
		t.Error("JSON 报告为空")
	}
	if bundle.Summary.TotalVulns != 3 {
		t.Errorf("漏洞总数应为 3, 实际 %d", bundle.Summary.TotalVulns)
	}
	if bundle.Summary.CriticalCount != 1 {
		t.Errorf("严重数应为 1, 实际 %d", bundle.Summary.CriticalCount)
	}

	t.Logf("Markdown 报告长度: %d 字符", len(bundle.Markdown))
	t.Logf("HTML 报告长度: %d 字符", len(bundle.HTML))
	t.Logf("漏洞统计: %+v", bundle.Summary)
}

func createTestVulns() []*models.Vulnerability {
	return []*models.Vulnerability{
		{
			ID:          "v1",
			Type:        "sqli",
			Name:        "SQL Injection",
			Severity:    "critical",
			Confidence:  "high",
			URL:         "http://test.com/sqli?id=1",
			Description: "检测到 SQL 注入漏洞",
			Evidence:    "MySQL 错误回显",
			Remediation: "使用参数化查询",
			CVEIDs:      []string{"CVE-2023-1234"},
			FoundAt:     mustParseTime("2026-09-02T10:00:00Z"),
		},
		{
			ID:          "v2",
			Type:        "xss",
			Name:        "Cross-Site Scripting",
			Severity:    "high",
			Confidence:  "high",
			URL:         "http://test.com/xss?q=<script>alert(1)</script>",
			Description: "检测到反射型 XSS",
			Remediation: "输出编码 + CSP",
			FoundAt:     mustParseTime("2026-09-02T10:00:00Z"),
		},
		{
			ID:          "v3",
			Type:        "sensitive_file",
			Name:        "Sensitive File Exposure",
			Severity:    "medium",
			Confidence:  "medium",
			URL:         "http://test.com/.env",
			Description: ".env 文件可访问",
			Remediation: "禁止访问敏感路径",
			FoundAt:     mustParseTime("2026-09-02T10:00:00Z"),
		},
	}
}

func mustParseTime(s string) time.Time {
	t, _ := time.Parse(time.RFC3339, s)
	return t
}

// TestRuleEngineByCategory 验证按分类查询规则
func TestRuleEngineByCategory(t *testing.T) {
	re := NewRuleEngine("")

	injectionRules := re.RulesByCategory("A03-injection")
	if len(injectionRules) == 0 {
		t.Error("未找到注入类规则")
	}
	t.Logf("注入类规则数: %d", len(injectionRules))

	dastRules := re.RulesByMethod("DAST")
	if len(dastRules) == 0 {
		t.Error("未找到 DAST 规则")
	}
	t.Logf("DAST 规则数: %d", len(dastRules))
}
