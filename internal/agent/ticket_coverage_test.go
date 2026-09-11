package agent

import (
	"strings"
	"testing"

	"security-agent/internal/models"
)

// 扫描器实际产出的漏洞类型（见 detector.go ruleIDToVulnType）到期望语义类别。
var vulnTypeToCategoryCases = []struct {
	in   string // 漏洞类型
	want string // 期望语义类别
}{
	{"", ""},                               // 空类型：非漏洞行，不参与判定
	{"weak_password", catWeakPassword},     // 弱口令
	{"sensitive_file", catDataLeak},        // 数据泄露
	{"sensitive_info", catDataLeak},        // 数据泄露
	{"sqli", catInjection},                 // 注入类
	{"command_injection", catInjection},    // 注入类
	{"ssti", catInjection},                 // 注入类
	{"xxe", catInjection},                  // 注入类
	{"idor", catAuthConfig},                // 权限与配置错误
	{"broken_auth", catAuthConfig},         // 权限与配置错误
	{"misconfiguration", catAuthConfig},    // 权限与配置错误
	{"ssrf", catAuthConfig},                // 权限与配置错误
	{"vulnerable_component", catComponent}, // 依赖组件漏洞
	{"logic", catLogic},                    // 逻辑缺陷
	{"file_upload", catLogic},              // 逻辑缺陷
	{"deserialization", catLogic},          // 逻辑缺陷
	{"info_disclosure", catInfoLeak},       // 信息泄露
	{"path_traversal", catInfoLeak},        // 信息泄露
	{"directory_listing", catInfoLeak},     // 信息泄露
	{"webshell", catWebshell},              // Webshell / 后门（独立类别，不并入数据泄露）
	{"backdoor", catWebshell},              // 后门
	{"malicious_file", catWebshell},        // 恶意文件
	{"totally_new_type_2026", catOther},    // 未知 / 新增类型 -> 兜底 other（禁止漏单）
	{"some_weird_cve_thing", catOther},     // 未知 / 新增类型 -> 兜底 other
}

// TestVulnTypeToCategoryCoverage 验证分类体系：已知类型归位、未知类型兜底、空类型不参与。
func TestVulnTypeToCategoryCoverage(t *testing.T) {
	for _, c := range vulnTypeToCategoryCases {
		if got := vulnTypeToCategory(c.in); got != c.want {
			t.Errorf("vulnTypeToCategory(%q) = %q, want %q", c.in, got, c.want)
		}
		// 非空类型一律可建单（isTicketableVulnType），空类型不可建单
		if c.in != "" && !isTicketableVulnType(c.in) {
			t.Errorf("isTicketableVulnType(%q) = false, want true", c.in)
		}
	}
	if isTicketableVulnType("") {
		t.Errorf("isTicketableVulnType(\"\") 应为 false（非漏洞行不参与建单）")
	}
}

// TestBuildFallbackTicketAllCategories 验证安全阀兜底建单对每一类都返回可用工单，
// 尤其 unknown/other 等未知类型不再返回 nil（历史漏单主因）。
func TestBuildFallbackTicketAllCategories(t *testing.T) {
	a := newTestAgent()
	steps := []Step{mkStep("start_scan", "done", `{"domain_id":"d1","scan_job_id":"sj1"}`)}
	cats := []string{
		catWeakPassword, catDataLeak, catInjection, catAuthConfig,
		catComponent, catLogic, catInfoLeak, catWebshell, catOther,
	}
	for _, cat := range cats {
		tk := a.buildFallbackTicket(&Task{ID: "t1", Goal: "scan"}, cat, steps, []string{"d1"}, "http://127.0.0.1:8099")
		if tk == nil {
			t.Fatalf("buildFallbackTicket(%s) 返回 nil，未知/未归类类型被漏单", cat)
		}
		if strings.TrimSpace(tk.Title) == "" {
			t.Errorf("buildFallbackTicket(%s) 标题为空", cat)
		}
		if !sliceContains([]string{"high", "medium", "low"}, tk.RiskLevel) {
			t.Errorf("buildFallbackTicket(%s) 风险等级非法: %q", cat, tk.RiskLevel)
		}
		if strings.TrimSpace(tk.AssetURL) == "" {
			t.Errorf("buildFallbackTicket(%s) 影响资产为空，无法追溯", cat)
		}
		// 未知类型应明确标为 unknown，而不是空类型导致被 vulnTypeToCategory 当成非漏洞
		if cat == catOther && tk.VulnType != "unknown" {
			t.Errorf("buildFallbackTicket(catOther) vuln_type=%q, want unknown", tk.VulnType)
		}
	}
}

// TestNormalizeTicketFieldsDefaults 验证必填字段缺失时的可追溯默认值填充。
func TestNormalizeTicketFieldsDefaults(t *testing.T) {
	tk := &models.Ticket{
		// 刻意全部留空：模拟模型未提供任何字段
		VulnType:  "",
		RiskLevel: "garbage", // 非法风险等级
		ScanJobID: "sj-9",
	}
	notes := normalizeTicketFields(tk, normalizeTicketContext{TargetHost: "http://h/"})

	// vuln_type 缺失 -> unknown
	if tk.VulnType != "unknown" {
		t.Errorf("VulnType 应为 unknown，实际 %q", tk.VulnType)
	}
	// 标题兜底
	if tk.Title == "" {
		t.Errorf("标题不应为空")
	}
	// 风险等级非法 -> 按类别(unknow->other->medium)兜底为 medium
	if tk.RiskLevel != "medium" {
		t.Errorf("RiskLevel 应为 medium，实际 %q", tk.RiskLevel)
	}
	// 影响资产缺失 -> 用 TargetHost 兜底
	if tk.AssetURL != "http://h/" {
		t.Errorf("AssetURL 应为兜底 host，实际 %q", tk.AssetURL)
	}
	if tk.AssetName != "http://h/" {
		t.Errorf("AssetName 应为兜底 host，实际 %q", tk.AssetName)
	}
	// 复现信息缺失 -> 兜底
	if tk.Evidence == "" {
		t.Errorf("Evidence(复现信息) 不应为空")
	}
	if tk.RetestMethod == "" {
		t.Errorf("RetestMethod 不应为空")
	}
	// 指纹自动生成，且可复现
	fp1 := tk.Fingerprint
	if fp1 == "" {
		t.Fatalf("Fingerprint 应自动生成")
	}
	_ = normalizeTicketFields(tk, normalizeTicketContext{TargetHost: "http://h/"})
	if tk.Fingerprint != fp1 {
		t.Errorf("Fingerprint 应稳定（再次规范化不应改变）")
	}
	// 至少应记录若干补填说明，确保「补填」可见可追踪
	if len(notes) == 0 {
		t.Errorf("应至少产生一条补填说明，便于审计")
	}
}

// TestNormalizeTicketFieldsNoUnwantedOverride 验证已有合法字段不被默认值覆盖。
func TestNormalizeTicketFieldsNoUnwantedOverride(t *testing.T) {
	tk := &models.Ticket{
		Title:     "SQL 注入命中登录接口",
		VulnType:  "sqli",
		RiskLevel: "high",
		AssetURL:  "http://127.0.0.1:8099/login",
		Evidence:  "payload ' OR 1=1",
		ScanJobID: "sj-9",
	}
	_ = normalizeTicketFields(tk, normalizeTicketContext{})
	if tk.Title != "SQL 注入命中登录接口" || tk.VulnType != "sqli" || tk.RiskLevel != "high" {
		t.Errorf("已有合法字段被错误覆盖: title=%q type=%q risk=%q", tk.Title, tk.VulnType, tk.RiskLevel)
	}
}

// TestTicketFingerprint 验证去重指纹：相同输入稳定、要素任一变化即不同。
func TestTicketFingerprint(t *testing.T) {
	a := ticketFingerprint("sqli", "http://h/x", "sj1")
	b := ticketFingerprint("sqli", "http://h/x", "sj1")
	if a != b {
		t.Errorf("相同输入指纹应稳定: %q vs %q", a, b)
	}
	if ticketFingerprint("sqli", "http://h/x", "sj2") == a {
		t.Errorf("不同 scan_job 指纹应不同（每次运行应留独立工单）")
	}
	if ticketFingerprint("xss", "http://h/x", "sj1") == a {
		t.Errorf("不同 vuln_type 指纹应不同")
	}
}

// TestTicketCategoryKeywordFallback 验证无 VulnType 时按关键词也能归类到新增类别（去重判定需要）。
func TestTicketCategoryKeywordFallback(t *testing.T) {
	cases := map[string]string{
		"发现 SQL 注入漏洞":     catInjection,
		"存在越权访问/权限配置错误":   catAuthConfig,
		"依赖组件存在已知漏洞":      catComponent,
		"业务逻辑缺陷导致重复下单":    catLogic,
		"目录遍历导致信息泄露":      catInfoLeak,
		"Webshell 后门文件落地": catWebshell,
		"未知类型漏洞 xzy":      catOther,
	}
	for title, want := range cases {
		tk := &models.Ticket{Title: title}
		if got := ticketCategory(tk); got != want {
			t.Errorf("ticketCategory(%q) = %q, want %q", title, got, want)
		}
	}
}

// TestParseRequestedCategoriesAll 验证未点名时默认覆盖全部类别（含未知类型），点名时收窄。
func TestParseRequestedCategoriesAll(t *testing.T) {
	all := parseRequestedCategories("请对该资产提交工单")
	if len(all) != len(knownContractCategories) {
		t.Errorf("未点名时默认类别数=%d, want %d (%v)", len(all), len(knownContractCategories), all)
	}
	// 点名弱口令 -> 仅弱口令
	wp := parseRequestedCategories("提交弱口令工单")
	if len(wp) != 1 || wp[0] != catWeakPassword {
		t.Errorf("点名弱口令应仅返回弱口令类，实际 %v", wp)
	}
	// 点名注入 -> 仅注入类
	inj := parseRequestedCategories("上报所有注入类漏洞")
	if len(inj) != 1 || inj[0] != catInjection {
		t.Errorf("点名注入应仅返回注入类，实际 %v", inj)
	}
}
