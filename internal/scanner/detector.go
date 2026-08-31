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
}

func NewDetector(cfg *config.ScannerConfig, sensitiveCfg *config.SensitiveConfig, vulnRepo *storage.VulnerabilityRepository, sensitiveRepo *storage.SensitiveInfoRepository) *Detector {
	return &Detector{
		cfg:           cfg,
		sensitiveCfg:  sensitiveCfg,
		vulnRepo:      vulnRepo,
		sensitiveRepo: sensitiveRepo,
		fingerprints:  initFingerprints(),
	}
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

	return vulns, nil
}

// detectXSS：仅识别真正的 XSS 注入向量，避免把正常页面中的 <script> 误报。
func (d *Detector) detectXSS(page *PageInfo) *models.Vulnerability {
	lower := strings.ToLower(page.RawContent)
	urlLower := strings.ToLower(page.URL)

	// 1) javascript:/vbscript: 协议链接
	if strings.Contains(urlLower, "javascript:") || strings.Contains(urlLower, "vbscript:") {
		return &models.Vulnerability{
			Type: "xss", Name: "Cross-Site Scripting (XSS)", Severity: "medium",
			Description: "页面或链接中包含 javascript: 协议，可被用于脚本注入",
			Evidence:    "URL 包含 javascript:/vbscript: 协议", URL: page.URL,
			Remediation: "避免拼接用户输入到 URL；对输出做 HTML 转义，设置 Content-Security-Policy",
		}
	}

	// 2) 内联事件处理器 on*=
	eventRe := regexp.MustCompile(`(?i)\son(after|before|blur|change|click|dblclick|error|focus|keydown|keypress|keyup|load|mousedown|mousemove|mouseout|mouseover|mouseup|reset|select|submit|unload)\s*=\s*["']?[^>]*`)
	if eventRe.MatchString(lower) {
		return &models.Vulnerability{
			Type: "xss", Name: "Cross-Site Scripting (XSS)", Severity: "medium",
			Description: "检测到内联事件处理器（on* 属性），若其值含用户输入可造成 XSS",
			Evidence:    "匹配到 on* 事件处理器", URL: page.URL,
			Remediation: "使用 addEventListener 绑定事件；对用户可控属性做转义",
		}
	}

	// 3) 脚本块中出现高危调用（仅当脚本内容可疑时才报，降低正常 JS 的误报）
	suspiciousScript := regexp.MustCompile(`(?i)(document\.cookie|eval\s*\(|location\.href\s*=|location\.replace\s*\(|window\.open\s*\()`)
	if strings.Contains(lower, "<script") && suspiciousScript.MatchString(lower) {
		return &models.Vulnerability{
			Type: "xss", Name: "Cross-Site Scripting (XSS)", Severity: "medium",
			Description: "页面脚本包含可疑调用（document.cookie / eval / 跳转），存在 XSS 或钓鱼风险",
			Evidence:    "脚本块中包含可疑函数调用", URL: page.URL,
			Remediation: "审查脚本来源；对用户可控内容做转义并设置 CSP",
		}
	}

	return nil
}

// detectSQLInjection：解析 URL 查询参数，仅在参数值出现经典 SQLi 特征时上报。
func (d *Detector) detectSQLInjection(page *PageInfo) *models.Vulnerability {
	parsed, err := url.Parse(page.URL)
	if err != nil || parsed.RawQuery == "" {
		return nil
	}

	// 经典 SQLi 特征（针对参数值）。
	signatures := []*regexp.Regexp{
		regexp.MustCompile(`(?i)(?:union\s+select|union\s+all\s+select)`),
		regexp.MustCompile(`(?i)(?:or|and)\s+['"]?\d+['"]?\s*=\s*['"]?\d+`),
		regexp.MustCompile(`(?i)'\s*or\s*'.+'`),
		regexp.MustCompile(`(?i)'\s*=\s*'`),
		regexp.MustCompile(`(?i)(?:;|--|#)\s*$`),
		regexp.MustCompile(`(?i)/\*.*\*/`),
		regexp.MustCompile(`(?i)(?:sleep|benchmark|waitfor\s+delay)\s*\(`),
		regexp.MustCompile(`(?i)(?:drop|delete|insert|update|alter)\s+(?:table|from|into|set)`),
		regexp.MustCompile(`(?i)information_schema`),
		regexp.MustCompile(`(?i)concat\s*\(.+\)`),
	}

	values := make([]string, 0)
	for _, vs := range parsed.Query() {
		values = append(values, vs...)
	}
	// 也检查原始查询串中的可疑片段
	values = append(values, parsed.RawQuery)

	for _, v := range values {
		if len(v) > 200 {
			continue // 超长通常非注入，降低误报
		}
		vl := strings.ToLower(v)
		for _, re := range signatures {
			if re.MatchString(vl) {
				return &models.Vulnerability{
					Type: "sqli", Name: "Potential SQL Injection", Severity: "high",
					Description: "URL 参数值包含 SQL 注入特征",
					Evidence:    fmt.Sprintf("命中特征: %s", re.String()), URL: page.URL,
					Parameter:   parsed.RawQuery,
					Remediation: "使用参数化查询（预编译语句），对输入做白名单校验与转义",
				}
			}
		}
	}

	return nil
}

// detectSensitiveFiles：识别暴露的敏感/备份文件。
func (d *Detector) detectSensitiveFiles(page *PageInfo) []*models.Vulnerability {
	var vulns []*models.Vulnerability

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
	for file, desc := range sensitiveFiles {
		if strings.Contains(lower, file) {
			vulns = append(vulns, &models.Vulnerability{
				Type: "sensitive_file", Name: "Sensitive File Exposure", Severity: "high",
				Description: desc,
				Evidence:    fmt.Sprintf("URL 包含敏感路径: %s", file), URL: page.URL,
				Remediation: "将敏感文件移出 Web 根目录，或通过 Web 服务器拒绝访问",
			})
		}
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

func isChinaID(s string) bool {
	re := regexp.MustCompile(`^\d{17}[\dXx]$`)
	return re.MatchString(strings.TrimSpace(s))
}

func isChinaPhone(s string) bool {
	re := regexp.MustCompile(`^(?:13|14|15|16|17|18|19)\d{9}$`)
	return re.MatchString(strings.TrimSpace(s))
}
