package scanner

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"

	"security-agent/internal/models"
)

//go:embed fingerprints.json
var embeddedFingerprints []byte

// FingerprintRule 统一化的组件/服务指纹规则（与 wanpinglingtan 指纹库兼容，已归一化）。
// 来源通过 Source 字段标注（wanpinglingtan:fingerprint_db / high_risk / fingerprint_hub / ext）。
type FingerprintRule struct {
	ID          string                  `json:"id"`
	ProductCN   string                  `json:"product_cn"`
	ProductEN   string                  `json:"product_en"`
	Category    string                  `json:"category"`
	Vendor      string                  `json:"vendor"`
	RiskLevel   string                  `json:"risk_level"` // Critical|High|Medium|Low|Info
	CVSSBase    float64                 `json:"cvss_base"`
	Priority    int                     `json:"priority"`
	MatchType   string                  `json:"match_type"` // or|and
	MatchRules  FingerprintMatchRules    `json:"match_rules"`
	VerifyPaths []string                `json:"verify_paths"`
	Vulnerabilities []CriticalVulnerability `json:"critical_vulnerabilities"`
	AffectedVersions string             `json:"affected_versions"`
	Remediation string                  `json:"remediation"`
	Source      string                  `json:"source"`
}

// FingerprintMatchRules 命中维度（任意维度命中即算命中，match_type=or）。
type FingerprintMatchRules struct {
	HeaderServer  []string `json:"header_server"`  // Server 响应头包含
	HeaderCustom  []string `json:"header_custom"`  // 其它响应头正则（大小写不敏感，作用于 "Name: Value"）
	BodyKeywords  []string `json:"body_keywords"`  // 响应体包含
	CookieKeywords []string `json:"cookie_keywords"` // Set-Cookie 包含
	TitleKeywords []string `json:"title_keywords"` // <title> 包含
	PathKeywords  []string `json:"path_keywords"`  // 当前页面路径包含（弱命中，仅供参考）
}

// CriticalVulnerability 关联的真实 CVE（仅收录公开确认项）。
type CriticalVulnerability struct {
	CVEID            string  `json:"cve_id"`
	VulnName         string  `json:"vuln_name"`
	Type             string  `json:"type"`
	CVSS             float64 `json:"cvss"`
	AffectedVersions string  `json:"affected_versions"`
	PocAvailable     bool    `json:"poc_available"`
}

// MatchedComponent 单次命中结果。
type MatchedComponent struct {
	Rule    FingerprintRule
	Matched string // 命中的维度，如 "body_keywords"
}

// LoadEmbeddedFingerprintRules 读取内嵌指纹库（编译期嵌入，无需外部路径）。
func LoadEmbeddedFingerprintRules() ([]FingerprintRule, error) {
	var db struct {
		Fingerprints []FingerprintRule `json:"fingerprints"`
	}
	if err := json.Unmarshal(embeddedFingerprints, &db); err != nil {
		return nil, err
	}
	return db.Fingerprints, nil
}

// MatchFingerprint 基于 HTTP 响应（Server 头 / 其它响应头 / 响应体 / Cookie / 标题）识别组件。
// 不发起额外请求：path_keywords 仅按当前页面路径做弱匹配。
func MatchFingerprint(page *PageInfo, rules []FingerprintRule) []MatchedComponent {
	if len(rules) == 0 || page == nil {
		return nil
	}
	server := strings.ToLower(headerValue(page.Headers, "Server"))
	headerBlob := strings.ToLower(headerBlob(page.Headers))
	body := strings.ToLower(page.RawContent)
	title := strings.ToLower(page.Title)
	cookies := strings.ToLower(strings.Join(page.Cookies, " "))
	url := strings.ToLower(page.URL)

	var out []MatchedComponent
	for _, rule := range rules {
		var hit string
		r := rule.MatchRules
		switch {
		case matchAnySubstr(server, r.HeaderServer):
			hit = "header_server"
		case matchAnyRegex(headerBlob, r.HeaderCustom):
			hit = "header_custom"
		case matchAnySubstr(body, r.BodyKeywords):
			hit = "body_keywords"
		case matchAnySubstr(cookies, r.CookieKeywords):
			hit = "cookie_keywords"
		case matchAnySubstr(title, r.TitleKeywords):
			hit = "title_keywords"
		case matchAnySubstr(url, r.PathKeywords):
			hit = "path_keywords"
		}
		if hit != "" {
			out = append(out, MatchedComponent{Rule: rule, Matched: hit})
		}
	}
	return out
}

// ComponentToVulnerability 将命中的组件转换为漏洞发现（含关联 CVE 与处置建议）。
func ComponentToVulnerability(m MatchedComponent, page *PageInfo) *models.Vulnerability {
	rule := m.Rule
	name := rule.ProductCN
	if name == "" {
		name = rule.ProductEN
	}
	if name == "" {
		name = rule.ID
	}

	desc := fmt.Sprintf("识别到组件 %s（分类：%s / 厂商：%s）", name, rule.Category, rule.Vendor)
	if len(rule.Vulnerabilities) > 0 {
		var sb strings.Builder
		sb.WriteString(desc + "。关联已知漏洞：")
		for i, c := range rule.Vulnerabilities {
			if i > 0 {
				sb.WriteString("；")
			}
			fmt.Fprintf(&sb, "%s %s", c.CVEID, c.VulnName)
		}
		desc = sb.String()
	}

	evidence := fmt.Sprintf("命中维度=%s", m.Matched)
	if rule.AffectedVersions != "" {
		evidence += "；影响版本：" + rule.AffectedVersions
	}

	remediation := rule.Remediation
	if strings.TrimSpace(remediation) == "" {
		remediation = "升级至官方安全版本；收敛公网暴露面；关注该组件历史 CVE 的加固建议"
	}

	return &models.Vulnerability{
		Type:        "fingerprint",
		Name:        "组件识别: " + name,
		Severity:    normalizeFingerprintRisk(rule.RiskLevel),
		Description: desc,
		Evidence:    evidence,
		URL:         page.URL,
		Remediation: remediation,
	}
}

// --- 工具函数 ---

func headerValue(h http.Header, key string) string {
	if h == nil {
		return ""
	}
	return h.Get(key)
}

func headerBlob(h http.Header) string {
	if h == nil {
		return ""
	}
	var sb strings.Builder
	for k, vs := range h {
		for _, v := range vs {
			fmt.Fprintf(&sb, "%s: %s\n", k, v)
		}
	}
	return sb.String()
}

func matchAnySubstr(blob string, keys []string) bool {
	for _, k := range keys {
		if k == "" {
			continue
		}
		if strings.Contains(blob, strings.ToLower(k)) {
			return true
		}
	}
	return false
}

func matchAnyRegex(blob string, patterns []string) bool {
	for _, p := range patterns {
		if p == "" {
			continue
		}
		// 用 Compile 而非 MustCompile：单个特征表达式有误只跳过该特征，不崩溃。
		re, err := compileCaseInsensitive(p)
		if err != nil {
			continue
		}
		if re.MatchString(blob) {
			return true
		}
	}
	return false
}

// compileCaseInsensitive 编译大小写不敏感的正则（用于 header_custom 等维度）。
func compileCaseInsensitive(p string) (*regexp.Regexp, error) {
	return regexp.Compile("(?i)" + p)
}

// normalizeFingerprintRisk 将中英风险等级归一化为 high|medium|low。
func normalizeFingerprintRisk(level string) string {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "critical", "high", "严重", "高":
		return "high"
	case "medium", "中":
		return "medium"
	case "low", "info", "低", "n/a", "":
		return "low"
	default:
		return "low"
	}
}

// initFingerprints 供 Detector 构造时加载内嵌指纹库；失败仅记录日志，不影响主扫描流程。
func initFingerprints() []FingerprintRule {
	rules, err := LoadEmbeddedFingerprintRules()
	if err != nil {
		log.Printf("[Detector] 加载指纹库失败（跳过组件识别）: %v", err)
		return nil
	}
	log.Printf("[Detector] 已加载指纹库规则 %d 条", len(rules))
	return rules
}
