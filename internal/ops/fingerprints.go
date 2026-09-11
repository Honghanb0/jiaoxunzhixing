// fingerprints.go 实现指纹库归一化生成
// （对应原 gen_fingerprints.py）：读取 wanpinglingtan 的三份指纹库与
// ext_fingerprints.js，归一化为本项目统一格式后写入 internal/scanner/fingerprints.json。
package ops

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// 源指纹库（顺序即合并顺序，保证产出稳定）。
var fingerprintSources = []struct {
	source string
	rel    string
}{
	{"wanpinglingtan:fingerprint_db", filepath.Join("wanpinglingtan", "src", "secscan", "data", "fingerprint_db.json")},
	{"wanpinglingtan:high_risk", filepath.Join("wanpinglingtan", "src", "secscan", "data", "high_risk_fingerprint_db.json")},
	{"wanpinglingtan:fingerprint_hub", filepath.Join("wanpinglingtan", "src", "secscan", "data", "fingerprint_db_fh.json")},
}

var extJSRel = filepath.Join("wanpinglingtan", "src", "secscan", "ext_fingerprints.js")

// assetQueriesPattern 用于剔除 wanpinglingtan 部分库中的非标准 asset_queries 块。
var assetQueriesPattern = regexp.MustCompile(`(?s)"asset_queries"\s*:\s*\{[^{}]*\}\s*,?`)

// CVEEntry 为归一化后的 CVE 条目。
type CVEEntry struct {
	CVEID            string  `json:"cve_id"`
	VulnName         string  `json:"vuln_name"`
	Type             string  `json:"type"`
	CVSS             float64 `json:"cvss"`
	AffectedVersions string  `json:"affected_versions"`
	PoCAvailable     bool    `json:"poc_available"`
}

// MatchRules 为归一化后的匹配规则。
type MatchRules struct {
	HeaderServer   []string `json:"header_server"`
	HeaderCustom   []string `json:"header_custom"`
	BodyKeywords   []string `json:"body_keywords"`
	CookieKeywords []string `json:"cookie_keywords"`
	TitleKeywords  []string `json:"title_keywords"`
	PathKeywords   []string `json:"path_keywords"`
}

// Fingerprint 为归一化后的单条指纹。
type Fingerprint struct {
	ID                      string     `json:"id"`
	ProductCN               string     `json:"product_cn"`
	ProductEN               string     `json:"product_en"`
	Category                string     `json:"category"`
	Vendor                  string     `json:"vendor"`
	RiskLevel               string     `json:"risk_level"`
	CVSSBase                float64    `json:"cvss_base"`
	Priority                any        `json:"priority"`
	MatchType               string     `json:"match_type"`
	MatchRules              MatchRules `json:"match_rules"`
	VerifyPaths             []any      `json:"verify_paths"`
	CriticalVulnerabilities []CVEEntry `json:"critical_vulnerabilities"`
	AffectedVersions        string     `json:"affected_versions"`
	Remediation             string     `json:"remediation"`
	Source                  string     `json:"source"`
}

// FingerprintStats 为生成结果统计。
type FingerprintStats struct {
	Total    int            `json:"total"`
	BySource map[string]int `json:"by_source"`
	ByRisk   map[string]int `json:"by_risk"`
	WithCVE  int            `json:"with_cve"`
	Output   string         `json:"output"`
}

// GenerateFingerprints 生成指纹库并写入 outPath（为空时用默认路径 internal/scanner/fingerprints.json）。
func GenerateFingerprints(repoRoot, outPath string) (*FingerprintStats, error) {
	if repoRoot == "" {
		root, err := FindRepoRoot()
		if err != nil {
			return nil, err
		}
		repoRoot = root
	}
	if outPath == "" {
		outPath = filepath.Join(repoRoot, "internal", "scanner", "fingerprints.json")
	}

	var rules []Fingerprint
	seen := make(map[string]struct{})

	for _, src := range fingerprintSources {
		records, err := loadFingerprintFile(filepath.Join(repoRoot, src.rel))
		if err != nil {
			Warnf("读取 %s 失败，已跳过：%v", src.rel, err)
			continue
		}
		for _, rec := range records {
			fp := normalizeFingerprint(rec, src.source)
			if fp.ID == "" {
				continue
			}
			if _, dup := seen[fp.ID]; dup {
				continue
			}
			seen[fp.ID] = struct{}{}
			rules = append(rules, fp)
		}
	}

	extRecords, err := loadExtFingerprints(filepath.Join(repoRoot, extJSRel))
	if err != nil {
		Warnf("读取 ext_fingerprints.js 失败，已跳过：%v", err)
	}
	for _, rec := range extRecords {
		fp := normalizeFingerprint(rec, "wanpinglingtan:ext")
		if fp.ID == "" {
			continue
		}
		if _, dup := seen[fp.ID]; dup {
			continue
		}
		seen[fp.ID] = struct{}{}
		rules = append(rules, fp)
	}

	if err := writeFingerprints(outPath, rules); err != nil {
		return nil, err
	}

	stats := &FingerprintStats{
		Total:    len(rules),
		BySource: map[string]int{},
		ByRisk:   map[string]int{},
		Output:   outPath,
	}
	for _, r := range rules {
		stats.BySource[r.Source]++
		stats.ByRisk[r.RiskLevel]++
		if len(r.CriticalVulnerabilities) > 0 {
			stats.WithCVE++
		}
	}
	return stats, nil
}

// loadFingerprintFile 读取单个指纹库文件，兼容 {"fingerprints":[...]} 与 [...] 两种顶层结构。
func loadFingerprintFile(path string) ([]map[string]any, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cleaned := assetQueriesPattern.ReplaceAll(raw, []byte(""))

	var decoded any
	if err := json.Unmarshal(cleaned, &decoded); err != nil {
		return nil, fmt.Errorf("解析 JSON 失败: %w", err)
	}

	var list []any
	switch v := decoded.(type) {
	case map[string]any:
		if inner, ok := v["fingerprints"].([]any); ok {
			list = inner
		}
	case []any:
		list = v
	default:
		return nil, fmt.Errorf("未知的顶层结构: %T", decoded)
	}

	records := make([]map[string]any, 0, len(list))
	for _, item := range list {
		if m, ok := item.(map[string]any); ok {
			records = append(records, m)
		}
	}
	return records, nil
}

// loadExtFingerprints 用 node 求值 ext_fingerprints.js（module.exports = { EXT_FINGERPRINTS }）。
func loadExtFingerprints(path string) ([]map[string]any, error) {
	node, err := findNode()
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("未找到 %s: %w", path, err)
	}
	quoted, err := json.Marshal(path) // 负责转义路径分隔符，Windows 反斜杠同样安全
	if err != nil {
		return nil, err
	}
	script := fmt.Sprintf("const m=require(%s);process.stdout.write(JSON.stringify(m.EXT_FINGERPRINTS||[]));", quoted)

	out, err := exec.Command(node, "-e", script).Output()
	if err != nil {
		return nil, fmt.Errorf("执行 node 失败: %w", err)
	}

	var list []map[string]any
	if err := json.Unmarshal(out, &list); err != nil {
		return nil, fmt.Errorf("解析 node 输出失败: %w", err)
	}
	return list, nil
}

func findNode() (string, error) {
	for _, name := range []string{"node", "node.exe"} {
		if path, err := exec.LookPath(name); err == nil {
			return path, nil
		}
	}
	return "", fmt.Errorf("未在 PATH 中找到 node，跳过 ext_fingerprints.js")
}

// normalizeFingerprint 把一条原始记录归一化为统一格式。
func normalizeFingerprint(rec map[string]any, source string) Fingerprint {
	mr, _ := rec["match_rules"].(map[string]any)
	return Fingerprint{
		ID:                      stringField(rec, "id"),
		ProductCN:               firstString(rec, "product_cn", "product"),
		ProductEN:               firstString(rec, "product_en", "product"),
		Category:                stringField(rec, "category"),
		Vendor:                  stringField(rec, "vendor"),
		RiskLevel:               defaultString(stringField(rec, "risk_level"), "Info"),
		CVSSBase:                asFloat(rec["cvss_base"]),
		Priority:                priorityOf(rec),
		MatchType:               defaultString(stringField(rec, "match_type"), "or"),
		MatchRules:              normalizeMatchRules(mr),
		VerifyPaths:             anySlice(rec["verify_paths"]),
		CriticalVulnerabilities: normalizeCVEs(rec["critical_vulnerabilities"]),
		AffectedVersions:        stringField(rec, "affected_versions"),
		Remediation:             stringField(rec, "remediation"),
		Source:                  source,
	}
}

func normalizeMatchRules(mr map[string]any) MatchRules {
	custom := append(stringSlice(mr["header_custom"]), stringSlice(mr["header_keywords"])...) //nolint:gocritic
	return MatchRules{
		HeaderServer:   stringSlice(mr["header_server"]),
		HeaderCustom:   nonNilStrings(custom),
		BodyKeywords:   stringSlice(mr["body_keywords"]),
		CookieKeywords: stringSlice(mr["cookie_keywords"]),
		TitleKeywords:  stringSlice(mr["title_keywords"]),
		PathKeywords:   stringSlice(mr["path_keywords"]),
	}
}

func normalizeCVEs(value any) []CVEEntry {
	items, ok := value.([]any)
	if !ok || len(items) == 0 {
		return []CVEEntry{}
	}
	out := make([]CVEEntry, 0, len(items))
	for _, item := range items {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		out = append(out, CVEEntry{
			CVEID:            firstString(m, "cve_id", "cve", "id"),
			VulnName:         firstString(m, "vuln_name", "name"),
			Type:             stringField(m, "type"),
			CVSS:             asFloat(firstNonNil(m["cvss"], m["cvss_base"])),
			AffectedVersions: stringField(m, "affected_versions"),
			PoCAvailable:     boolField(m, "poc_available"),
		})
	}
	return out
}

func writeFingerprints(path string, rules []Fingerprint) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("创建输出目录失败: %w", err)
	}
	var buf strings.Builder
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", " ") // 与原脚本 indent=1 一致
	if err := enc.Encode(map[string]any{"fingerprints": rules}); err != nil {
		return fmt.Errorf("序列化指纹库失败: %w", err)
	}
	if err := os.WriteFile(path, []byte(buf.String()), 0o644); err != nil {
		return fmt.Errorf("写入 %s 失败: %w", path, err)
	}
	return nil
}

// ReportFingerprintStats 按原脚本格式打印统计信息。
func ReportFingerprintStats(stats *FingerprintStats) {
	Plainf("总规则数: %d", stats.Total)
	Plainf("按来源: %s", formatCountMap(stats.BySource))
	Plainf("按风险: %s", formatCountMap(stats.ByRisk))
	Plainf("含关联CVE的规则数: %d", stats.WithCVE)
	Plainf("已写入: %s", stats.Output)
}

func formatCountMap(m map[string]int) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s: %d", k, m[k]))
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

// ---- 类型安全的小工具（容忍源数据字段类型不一致）----

func stringField(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func firstString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v := stringField(m, k); v != "" {
			return v
		}
	}
	return ""
}

func defaultString(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

func asFloat(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case float32:
		return float64(n)
	case int:
		return float64(n)
	case int64:
		return float64(n)
	case string:
		var f float64
		if _, err := fmt.Sscanf(n, "%f", &f); err == nil {
			return f
		}
	}
	return 0
}

func boolField(m map[string]any, key string) bool {
	if v, ok := m[key].(bool); ok {
		return v
	}
	return false
}

func priorityOf(m map[string]any) any {
	if v, ok := m["priority"]; ok && v != nil {
		return v
	}
	return 0
}

func firstNonNil(values ...any) any {
	for _, v := range values {
		if v != nil {
			return v
		}
	}
	return nil
}

func stringSlice(v any) []string {
	items, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func nonNilStrings(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}

func anySlice(v any) []any {
	if items, ok := v.([]any); ok {
		return items
	}
	return []any{}
}
