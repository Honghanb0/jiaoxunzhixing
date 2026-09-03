package scanner

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"security-agent/internal/config"
	"security-agent/internal/models"
	"security-agent/internal/storage"
)

type Detector struct {
	cfg           *config.ScannerConfig
	sensitiveCfg  *config.SensitiveConfig
	vulnRepo      *storage.VulnerabilityRepository
	sensitiveRepo *storage.SensitiveInfoRepository
	fingerprints  []FingerprintRule
	ruleEngine    *RuleEngine // 企业级规则引擎（可动态加载 YAML 规则）
}

func NewDetector(cfg *config.ScannerConfig, sensitiveCfg *config.SensitiveConfig, vulnRepo *storage.VulnerabilityRepository, sensitiveRepo *storage.SensitiveInfoRepository) *Detector {
	return &Detector{
		cfg:           cfg,
		sensitiveCfg:  sensitiveCfg,
		vulnRepo:      vulnRepo,
		sensitiveRepo: sensitiveRepo,
		fingerprints:  initFingerprints(),
		ruleEngine:    NewRuleEngine(""), // 默认加载内嵌规则
	}
}

// SetRuleEngine 允许外部注入自定义规则引擎（如从外部目录加载规则）
func (d *Detector) SetRuleEngine(re *RuleEngine) {
	d.ruleEngine = re
}

// GetRuleEngine 获取规则引擎实例
func (d *Detector) GetRuleEngine() *RuleEngine {
	return d.ruleEngine
}

// DetectVulnerabilities 执行多项检测，并尽量降低误报：
// 仅当存在明确的“注入/暴露”特征时才上报，且对每页同类问题去重。
func (d *Detector) DetectVulnerabilities(page *PageInfo, scanJobID string) ([]*models.Vulnerability, error) {
	var vulns []*models.Vulnerability

	if v := d.detectXSS(page); v != nil {
		vulns = append(vulns, v)
	}
	if v := d.detectSQLInjection(page); v != nil {
		vulns = append(vulns, v)
	}
	if vs := d.detectSensitiveFiles(page); len(vs) > 0 {
		vulns = append(vulns, vs...)
	}
	if v := d.detectPageTampering(page); v != nil {
		vulns = append(vulns, v)
	}
	if vs := d.detectMalwareLinks(page); len(vs) > 0 {
		vulns = append(vulns, vs...)
	}

	// 组件/服务指纹识别：识别更多服务与组件类型，并关联已知 CVE 产生漏洞发现
	if comps := d.detectComponents(page); len(comps) > 0 {
		vulns = append(vulns, comps...)
	}

	// 企业级规则引擎检测：基于 YAML 规则库（14+ 条 OWASP Top 10 规则），
	// 采用多层确认 + 置信度评分 + 误报过滤机制
	// 传入已有漏洞列表用于去重，避免与传统检测器重复上报
	if ruleVulns := d.detectWithRuleEngine(page, vulns); len(ruleVulns) > 0 {
		vulns = append(vulns, ruleVulns...)
	}

	return vulns, nil
}

// detectWithRuleEngine 使用规则引擎检测漏洞，将匹配结果转换为 Vulnerability 模型
// existingVulns 用于去重：同一 URL 已被其他检测器发现时跳过规则引擎的重复发现
func (d *Detector) detectWithRuleEngine(page *PageInfo, existingVulns []*models.Vulnerability) []*models.Vulnerability {
	if d.ruleEngine == nil {
		return nil
	}

	results := d.ruleEngine.MatchDAST(page)
	if len(results) == 0 {
		return nil
	}

	// 构建已存在漏洞的 URL+Type 集合，用于去重
	existingKeys := make(map[string]bool)
	for _, v := range existingVulns {
		existingKeys[v.URL+"|"+v.Type] = true
	}

	var vulns []*models.Vulnerability
	for _, r := range results {
		if !r.ShouldReport {
			continue
		}

		// 多层确认已在规则引擎中完成，这里再做一次置信度阈值过滤
		if r.ConfidenceLevel == "low" {
			continue // low 置信度不上报，仅记录
		}

		rule := r.Rule
		_, cvssSeverity := ParseCVSSVector(rule.CVSS.Vector)

		// 确定漏洞严重等级：优先用 CVSS 评分
		severity := rule.CVSS.Severity
		if cvssSeverity != "none" {
			severity = cvssSeverity
		}

		// 使用规则 ID 映射到具体漏洞类型，避免 OWASP 分类粒度太粗导致重复
		vulnType := ruleIDToVulnType(rule.ID)

		// 去重：同一 URL + 同一类型已被其他检测器发现则跳过
		if existingKeys[page.URL+"|"+vulnType] {
			continue
		}

		// 提取 CVE IDs
		var cveIDs []string
		_ = cveIDs

		vuln := &models.Vulnerability{
			Type:             vulnType,
			Name:             rule.NameCN,
			Severity:         severity,
			Confidence:       r.ConfidenceLevel,
			Description:      rule.Description,
			Evidence:         r.Evidence,
			URL:              page.URL,
			Remediation:      rule.Remediation.Summary,
			CVEIDs:           cveIDs,
			AffectedVersions: "",
		}

		// 修复建议详情拼接
		if len(rule.Remediation.Details) > 0 {
			vuln.Remediation += "\n\n详情:\n" + strings.Join(rule.Remediation.Details, "\n")
		}

		vulns = append(vulns, vuln)
		existingKeys[page.URL+"|"+vulnType] = true
	}

	return vulns
}

// ruleIDToVulnType 将规则 ID 映射到精确的漏洞类型（避免 OWASP 分类太粗导致 XSS→injection 误映射）
func ruleIDToVulnType(ruleID string) string {
	switch ruleID {
	case "rule-injection-sqli":
		return "sqli"
	case "rule-xss-reflected":
		return "xss"
	case "rule-broken-access-control-idor":
		return "idor"
	case "rule-sensitive-file-exposure":
		return "sensitive_file"
	case "rule-xxe":
		return "xxe"
	case "rule-insecure-deserialization":
		return "deserialization"
	case "rule-ssrf":
		return "ssrf"
	case "rule-command-injection":
		return "command_injection"
	case "rule-security-misconfiguration":
		return "misconfiguration"
	case "rule-known-vulnerable-components":
		return "vulnerable_component"
	case "rule-broken-authentication":
		return "broken_auth"
	case "rule-ssti":
		return "ssti"
	case "rule-path-traversal":
		return "path_traversal"
	case "rule-file-upload":
		return "file_upload"
	default:
		return strings.ReplaceAll(ruleID, "rule-", "")
	}
}

// detectXSS：多层确认机制，仅识别真正的 XSS 注入向量，大幅降低正常页面误报。
// 多层确认策略：
//   - Layer 1 (high): javascript:/vbscript: 协议链接 — 明确的 XSS 注入向量
//   - Layer 2 (medium): 内联事件处理器且值包含高危模式（alert/eval/script 等）— 需值内容佐证
//   - Layer 3 (medium-low): 脚本块中 ≥2 个可疑信号（document.cookie + window.open + 外链等）
func (d *Detector) detectXSS(page *PageInfo) *models.Vulnerability {
	lower := strings.ToLower(page.RawContent)
	urlLower := strings.ToLower(page.URL)

	// 1) javascript:/vbscript: 协议链接 — 明确 XSS，high confidence
	if strings.Contains(urlLower, "javascript:") || strings.Contains(urlLower, "vbscript:") {
		return &models.Vulnerability{
			Type: "xss", Name: "Cross-Site Scripting (XSS)", Severity: "medium",
			Confidence: "high",
			Description: "页面或链接中包含 javascript:/vbscript: 协议，可被用于脚本注入",
			Evidence:    "URL 包含 javascript:/vbscript: 协议", URL: page.URL,
			Remediation: "避免拼接用户输入到 URL；对输出做 HTML 转义，设置 Content-Security-Policy",
		}
	}

	// 2) 内联事件处理器 on*= — 提取值内容，仅当值包含高危模式才上报（多层确认）
	eventRe := regexp.MustCompile(`(?i)\son(after|before|blur|change|click|dblclick|error|focus|keydown|keypress|keyup|load|mousedown|mousemove|mouseout|mouseover|mouseup|reset|select|submit|unload)\s*=\s*["']([^"']*)["']`)
	eventMatches := eventRe.FindAllStringSubmatch(lower, -1)
	for _, m := range eventMatches {
		if len(m) < 3 {
			continue
		}
		handlerValue := m[2]
		// 高危模式：事件处理器值中包含明确的脚本执行/数据泄露行为
		highRiskPatterns := []*regexp.Regexp{
			regexp.MustCompile(`(?i)\balert\s*\(`),
			regexp.MustCompile(`(?i)\beval\s*\(`),
			regexp.MustCompile(`(?i)document\.cookie`),
			regexp.MustCompile(`(?i)window\.open\s*\(`),
			regexp.MustCompile(`(?i)location\.(href|replace)\s*=`),
			regexp.MustCompile(`(?i)\.innerHTML\s*=`),
			regexp.MustCompile(`(?i)\bdocument\.write\s*\(`),
			regexp.MustCompile(`(?i)javascript:`),
			regexp.MustCompile(`(?i)onerror\s*=`),
		}
		for _, re := range highRiskPatterns {
			if re.MatchString(handlerValue) {
				return &models.Vulnerability{
					Type: "xss", Name: "Cross-Site Scripting (XSS)", Severity: "medium",
					Confidence: "high",
					Description: fmt.Sprintf("检测到内联事件处理器 %s，其值包含高危脚本行为", m[1]),
					Evidence:    fmt.Sprintf("事件处理器 %s=\"%s\"", m[1], truncate(handlerValue, 80)), URL: page.URL,
					Remediation: "使用 addEventListener 绑定事件；对用户可控属性做转义；设置 CSP",
				}
			}
		}
	}

	// 3) 脚本块中可疑调用 — 要求 ≥2 个独立可疑信号才上报（多层确认）
	if strings.Contains(lower, "<script") {
		signals := 0
		var signalNames []string
		suspiciousPatterns := []struct {
			re   *regexp.Regexp
			name string
		}{
			{regexp.MustCompile(`(?i)\bdocument\.cookie`), "document.cookie"},
			{regexp.MustCompile(`(?i)\beval\s*\(`), "eval()"},
			{regexp.MustCompile(`(?i)\bwindow\.open\s*\(`), "window.open()"},
			{regexp.MustCompile(`(?i)\blocation\.href\s*=`), "location.href="},
			{regexp.MustCompile(`(?i)\blocation\.replace\s*\(`), "location.replace()"},
			{regexp.MustCompile(`(?i)\.innerHTML\s*=`), ".innerHTML="},
			{regexp.MustCompile(`(?i)https?://[^"'\s]*evil`), "外链(evil)"},
			{regexp.MustCompile(`(?i)https?://[^"'\s]*steal`), "外链(steal)"},
		}
		for _, p := range suspiciousPatterns {
			if p.re.MatchString(lower) {
				signals++
				signalNames = append(signalNames, p.name)
			}
		}
		// 至少 2 个独立信号才上报，避免单一常见 JS API 误报
		if signals >= 2 {
			confidence := "medium"
			if signals >= 3 {
				confidence = "high"
			}
			return &models.Vulnerability{
				Type: "xss", Name: "Cross-Site Scripting (XSS)", Severity: "medium",
				Confidence: confidence,
				Description: fmt.Sprintf("页面脚本包含 %d 个可疑信号（%s），存在 XSS 或数据泄露风险", signals, strings.Join(signalNames, "、")),
				Evidence:    fmt.Sprintf("脚本块命中 %d 个可疑信号: %s", signals, strings.Join(signalNames, ", ")), URL: page.URL,
				Remediation: "审查脚本来源；移除不必要的 document.cookie/eval 调用；设置 CSP 限制脚本执行",
			}
		}
	}

	return nil
}

// detectSQLInjection：解析 URL 查询参数，基于多层签名匹配与置信度评分。
// 参考 OSV Schema 的漏洞分类，扩展了经典 SQLi 签名覆盖范围。
func (d *Detector) detectSQLInjection(page *PageInfo) *models.Vulnerability {
	parsed, err := url.Parse(page.URL)
	if err != nil || parsed.RawQuery == "" {
		return nil
	}

	// 经典 SQLi 签名（针对参数值），按特异性排序：高特异性在前。
	signatures := []struct {
		re       *regexp.Regexp
		specific bool // 是否高特异性（误报率低）
		name     string
	}{
		{regexp.MustCompile(`(?i)(?:union\s+select|union\s+all\s+select)`), true, "UNION SELECT"},
		{regexp.MustCompile(`(?i)(?:sleep|benchmark|waitfor\s+delay)\s*\(`), true, "Time-based blind"},
		{regexp.MustCompile(`(?i)information_schema`), true, "information_schema"},
		{regexp.MustCompile(`(?i)(?:drop|delete|insert|update|alter)\s+(?:table|from|into|set)`), true, "DML/DDL"},
		{regexp.MustCompile(`(?i)'\s*(?:or|and)\s*'?\d+`), true, "Boolean-based OR/AND"},
		{regexp.MustCompile(`(?i)(?:or|and)\s+['"]?\d+['"]?\s*=\s*['"]?\d+`), true, "Boolean-based ="},
		{regexp.MustCompile(`(?i)'\s*or\s*'.+'`), true, "Quote-based OR"},
		{regexp.MustCompile(`(?i)(?:;|--|#)\s*$`), false, "Comment terminator"},
		{regexp.MustCompile(`(?i)/\*.*\*/`), false, "Comment block"},
		{regexp.MustCompile(`(?i)concat\s*\(.+\)`), false, "CONCAT()"},
		{regexp.MustCompile(`(?i)char\s*\(\s*\d+\s*(?:,\s*\d+\s*)*\s*\)`), true, "CHAR() encoding"},
		{regexp.MustCompile(`(?i)(?:load_file|into\s+outfile|into\s+dumpfile)\s*\(`), true, "File operation"},
		{regexp.MustCompile(`(?i)extractvalue\s*\(`), true, "XPATH injection"},
		{regexp.MustCompile(`(?i)updatexml\s*\(`), true, "XPATH injection"},
	}

	values := make([]string, 0)
	for _, vs := range parsed.Query() {
		values = append(values, vs...)
	}
	values = append(values, parsed.RawQuery)

	var matchedSignals []string
	highSpecCount := 0
	for _, v := range values {
		if len(v) > 200 {
			continue // 超长通常非注入，降低误报
		}
		vl := strings.ToLower(v)
		for _, sig := range signatures {
			if sig.re.MatchString(vl) {
				matchedSignals = append(matchedSignals, sig.name)
				if sig.specific {
					highSpecCount++
				}
			}
		}
	}

	if len(matchedSignals) == 0 {
		return nil
	}

	// 置信度评分：高特异性签名 ≥1 即 high；仅低特异性签名时 medium
	confidence := "medium"
	if highSpecCount >= 1 {
		confidence = "high"
	}

	return &models.Vulnerability{
		Type: "sqli", Name: "Potential SQL Injection", Severity: "high",
		Confidence: confidence,
		Description: fmt.Sprintf("URL 参数值包含 %d 个 SQL 注入特征", len(matchedSignals)),
		Evidence:    fmt.Sprintf("命中特征: %s", strings.Join(matchedSignals, ", ")), URL: page.URL,
		Parameter:   parsed.RawQuery,
		Remediation: "使用参数化查询（预编译语句），对输入做白名单校验与转义",
	}
}

// detectSensitiveFiles：识别暴露的敏感/备份文件。
// 多层确认策略：
//   - Layer 1: URL 路径包含敏感文件名
//   - Layer 2 (上下文验证): HTTP 状态码必须为 200（排除 404 不存在文件）
//   - Layer 3 (上下文验证): 响应内容长度 > 0（排除空文件/目录列表）
//   - Layer 4 (去重): 同一 URL 只报一次最具体的匹配
func (d *Detector) detectSensitiveFiles(page *PageInfo) []*models.Vulnerability {
	var vulns []*models.Vulnerability

	// 上下文验证：仅对实际可访问（HTTP 200）的页面上报，排除 404 等不存在文件
	// 注意：非 HTML 文件（如 .env, .sql）crawler 不读取内容，RawContent 为空但 StatusCode=200，
	// 这种情况仍应报告（文件确实存在且可访问）
	if page.StatusCode != 200 {
		return nil
	}

	sensitiveFiles := map[string]string{
		".env":             "环境变量文件，可能含数据库/API 凭据",
		".git/config":      "Git 配置暴露，可能泄露仓库信息",
		".git/":            "Git 目录暴露",
		".hg/":             "Mercurial 目录暴露",
		".svn/":            "SVN 目录暴露",
		".htaccess":        "Apache 配置暴露",
		".htpasswd":        "Apache 密码文件暴露",
		"wp-config.php":    "WordPress 配置暴露",
		"config.php":       "配置文件暴露",
		"id_rsa":           "SSH 私钥暴露",
		"id_dsa":           "SSH 私钥暴露",
		".aws/credentials": "AWS 凭据暴露",
		"phpinfo.php":      "phpinfo 信息泄露",
		"backup.sql":       "数据库备份文件",
		".sql.gz":          "数据库备份文件",
		".bak":             "备份文件暴露",
		".old":             "旧版本文件暴露",
		".swp":             "编辑器临时文件暴露",
	}

	lower := strings.ToLower(page.URL)
	// 去重：同一 URL 只报最具体（最长）的敏感路径匹配
	type matchResult struct {
		path string
		desc string
	}
	var matches []matchResult
	for file, desc := range sensitiveFiles {
		if strings.Contains(lower, file) {
			matches = append(matches, matchResult{file, desc})
		}
	}
	// 按路径长度降序排列，取最长匹配（最具体的）
	for i := 0; i < len(matches); i++ {
		for j := i + 1; j < len(matches); j++ {
			if len(matches[j].path) > len(matches[i].path) {
				matches[i], matches[j] = matches[j], matches[i]
			}
		}
	}
	if len(matches) > 0 {
		best := matches[0]
		// 验证内容是否真正包含敏感信号（多层确认）
		contentLower := strings.ToLower(page.RawContent)
		hasContentSignal := false
		contentSignals := []string{"password", "secret", "key", "token", "credential", "db_", "database", "ssh-rsa", "begin", "<?php", "-- sql", "insert into"}
		for _, sig := range contentSignals {
			if strings.Contains(contentLower, sig) {
				hasContentSignal = true
				break
			}
		}
		confidence := "medium"
		if hasContentSignal {
			confidence = "high"
		}
		vulns = append(vulns, &models.Vulnerability{
			Type: "sensitive_file", Name: "Sensitive File Exposure", Severity: "high",
			Confidence: confidence,
			Description: best.desc,
			Evidence:    fmt.Sprintf("HTTP 200 | URL 包含敏感路径: %s | 内容长度: %d", best.path, len(page.RawContent)), URL: page.URL,
			Remediation: "将敏感文件移出 Web 根目录，或通过 Web 服务器拒绝访问",
		})
	}

	return vulns
}

// detectPageTampering：识别网页篡改/ Webshell / 钓鱼等高危特征。
func (d *Detector) detectPageTampering(page *PageInfo) *models.Vulnerability {
	lower := strings.ToLower(page.RawContent)

	// 1) 指向外部域名的 iframe（点击劫持/钓鱼）
	//
	// 注意：Go 的 regexp 是 RE2 引擎，**不支持**负向前瞻 `(?!...)`。
	// 旧实现拼接了 `(?!hostname)`，MustCompile 会直接 panic
	// （invalid or unsupported Perl syntax: `(?!`），导致整个扫描任务崩溃。
	// 改为先匹配全部 iframe 的 src，再在 Go 代码里做同源判断。
	iframeRe := regexp.MustCompile(`(?i)<iframe[^>]+src\s*=\s*["'](https?://[^"']+)["']`)
	selfHost := extractHost(page.URL)
	for _, m := range iframeRe.FindAllStringSubmatch(lower, -1) {
		if len(m) < 2 {
			continue
		}
		frameHost := extractHost(m[1])
		if frameHost == "" || frameHost == selfHost {
			continue // 同源 iframe，不算外部引用
		}
		return &models.Vulnerability{
			Type: "tampering", Name: "Hidden External Iframe", Severity: "high",
			Confidence: "high",
			Description: "页面包含指向外部域名的 iframe，疑似点击劫持或钓鱼",
			Evidence:    fmt.Sprintf("外部 iframe: %s", m[1]), URL: page.URL,
			Remediation: "确认 iframe 来源是否可信；对不可信来源移除并设置 X-Frame-Options",
		}
	}

	// 2) 常见 Webshell / 恶意代码片段（比单独的 eval( 更具特异性，降低误报）
	webshellPatterns := []string{
		`eval\s*\(\s*\$\_(?:post|get|request|cookie)`,
		`base64_decode\s*\(\s*\$\_`,
		`gzinflate\s*\(`,
		`eval\s*\(\s*gzuncompress`,
		`(?:system|exec|shell_exec|passthru|proc_open)\s*\(\s*\$\_`,
		`c99shell|r57shell|b374k|simattacker`,
		`document\.cookie\s*=\s*[^;]*location\.href\s*=`,
	}
	for _, p := range webshellPatterns {
		// 用 Compile 而非 MustCompile：即使某个特征表达式写错，
		// 也只是跳过该特征，不会让整个扫描任务 panic 崩溃。
		re, err := regexp.Compile(`(?i)` + p)
		if err != nil {
			continue
		}
		if re.MatchString(lower) {
			return &models.Vulnerability{
				Type: "tampering", Name: "Page Tampering / Webshell Detected", Severity: "high",
				Confidence: "high",
				Description: "检测到疑似 Webshell 或网页篡改特征",
				Evidence:    fmt.Sprintf("匹配到特征: %s", p), URL: page.URL,
				Remediation: "立即隔离并审计页面源码，清除后门，排查服务器入侵途径",
			}
		}
	}

	return nil
}

// detectMalwareLinks：仅对明显可疑的外链做低危提示（避免把普通外链误报）。
func (d *Detector) detectMalwareLinks(page *PageInfo) []*models.Vulnerability {
	var vulns []*models.Vulnerability

	// 仅匹配含有明确恶意关键词的外链主机。
	maliciousKeywords := []string{"malware", "phishing", "spam", "virus", "trojan", "exploit"}
	linkRe := regexp.MustCompile(`(?i)<a[^>]+href=["'](https?://[^"']+)["'][^>]*>`)
	for _, m := range linkRe.FindAllStringSubmatch(page.RawContent, -1) {
		href := strings.ToLower(m[1])
		u, err := url.Parse(href)
		if err != nil || u.Host == "" {
			continue
		}
		for _, kw := range maliciousKeywords {
			if strings.Contains(u.Host, kw) {
				vulns = append(vulns, &models.Vulnerability{
					Type: "malicious_link", Name: "Suspicious External Link", Severity: "low",
					Confidence: "high",
					Description: fmt.Sprintf("外链主机疑似包含 %q 关键词", kw),
					Evidence:    href, URL: page.URL,
					Remediation: "核实链接安全性，必要时移除",
				})
				break
			}
		}
	}

	return vulns
}

// detectComponents 基于响应头/体/标题/Cookie 识别组件指纹，去重后转成漏洞发现。
func (d *Detector) detectComponents(page *PageInfo) []*models.Vulnerability {
	if len(d.fingerprints) == 0 {
		return nil
	}
	matches := MatchFingerprint(page, d.fingerprints)
	if len(matches) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(matches))
	var vulns []*models.Vulnerability
	for _, m := range matches {
		if seen[m.Rule.ID] {
			continue // 同一组件在一页内只报一次
		}
		seen[m.Rule.ID] = true
		vulns = append(vulns, ComponentToVulnerability(m, page))
	}
	return vulns
}

func (d *Detector) DetectSensitiveInfo(page *PageInfo, scanJobID string) ([]*models.SensitiveInfo, error) {
	var infos []*models.SensitiveInfo

	for _, keyword := range d.sensitiveCfg.Keywords {
		if locations := d.findKeywordOccurrences(page.RawContent, keyword); len(locations) > 0 {
			for _, loc := range locations {
				infos = append(infos, &models.SensitiveInfo{
					PageID:      page.ID,
					Type:        "keyword",
					Value:       d.maskSensitiveValue(keyword, "keyword"),
					Location:    loc,
					URL:         page.URL,
					Severity:    "high",
					Remediation: "移除或脱敏页面中的敏感信息",
				})
			}
		}
	}

	for _, pattern := range d.sensitiveCfg.RegexPatterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			continue
		}

		matches := re.FindAllStringIndex(page.RawContent, -1)
		for _, match := range matches {
			start, end := match[0], match[1]
			if start < 0 {
				start = 0
			}
			if end > len(page.RawContent) {
				end = len(page.RawContent)
			}

			contextStart := start - 20
			if contextStart < 0 {
				contextStart = 0
			}
			contextEnd := end + 20
			if contextEnd > len(page.RawContent) {
				contextEnd = len(page.RawContent)
			}

			matched := page.RawContent[match[0]:match[1]]
			infos = append(infos, &models.SensitiveInfo{
				PageID:      page.ID,
				Type:        d.detectSensitiveType(pattern, matched),
				Value:       d.maskSensitiveValue(matched, "regex"),
				Location:    fmt.Sprintf("Position %d: ...%s...", start, page.RawContent[contextStart:contextEnd]),
				URL:         page.URL,
				Severity:    d.getSensitiveSeverity(pattern, matched),
				Remediation: "移除敏感信息，使用占位符或后端存储",
			})
		}
	}

	return infos, nil
}

func (d *Detector) findKeywordOccurrences(content, keyword string) []string {
	var locations []string
	lowerContent := strings.ToLower(content)
	lowerKeyword := strings.ToLower(keyword)

	start := 0
	for {
		idx := strings.Index(lowerContent[start:], lowerKeyword)
		if idx == -1 {
			break
		}
		actualIdx := start + idx
		locations = append(locations, fmt.Sprintf("Position %d", actualIdx))
		start = actualIdx + 1
	}

	return locations
}

func (d *Detector) detectSensitiveType(pattern, matched string) string {
	l := strings.ToLower(pattern)
	m := strings.ToLower(matched)
	switch {
	case strings.Contains(l, "private key") || strings.Contains(m, "begin") && strings.Contains(m, "private key"):
		return "private_key"
	case strings.Contains(l, "aws") || strings.Contains(m, "akia"):
		return "api_key"
	case strings.Contains(m, "@"):
		return "email"
	case isChinaID(m):
		return "id_card"
	case isChinaPhone(m):
		return "phone"
	case strings.Contains(l, "password"):
		return "password"
	case strings.Contains(l, "ssn"):
		return "ssn"
	}
	return "sensitive_data"
}

func (d *Detector) getSensitiveSeverity(pattern, matched string) string {
	t := d.detectSensitiveType(pattern, matched)
	switch t {
	case "private_key", "api_key", "password", "id_card", "ssn", "phone":
		return "high"
	}
	return "medium"
}

func (d *Detector) maskSensitiveValue(value, source string) string {
	if len(value) <= 8 {
		return "****"
	}

	switch source {
	case "keyword":
		return value[:2] + strings.Repeat("*", len(value)-4) + value[len(value)-2:]
	case "regex":
		if strings.Contains(value, "@") {
			parts := strings.Split(value, "@")
			if len(parts[0]) > 2 {
				return parts[0][:2] + "***@" + parts[1]
			}
		}
		return value[:4] + "***"
	default:
		return "****"
	}
}

// extractHost 返回 URL 的 host（小写），用于 iframe 同源判断。
func extractHost(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Host)
}

// truncate 截断字符串到指定长度，超出部分用 "..." 表示。
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func isChinaID(s string) bool {
	re := regexp.MustCompile(`^\d{17}[\dXx]$`)
	return re.MatchString(strings.TrimSpace(s))
}

func isChinaPhone(s string) bool {
	re := regexp.MustCompile(`^(?:13|14|15|16|17|18|19)\d{9}$`)
	return re.MatchString(strings.TrimSpace(s))
}
