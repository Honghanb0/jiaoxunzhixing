package scanner

import (
	"embed"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// =============================================================================
// 企业级漏洞发现引擎 — 规则引擎 (Rule Engine)
// =============================================================================
// 将 clown-src-6k-skill/vuln-engine/rules/ 下的 YAML 规则加载为 Go 结构，
// 提供：规则匹配、多层确认、置信度评分、PoC 生成、CVSS 评分。
// 与现有 Detector 集成，复用已有的误报过滤机制。
// =============================================================================

// Embed rules directory for compiled-in rules (可选，部署时不依赖外部文件)
//go:embed rules/*.yaml
var embeddedRulesFS embed.FS

// -----------------------------------------------------------------------------
// 规则数据结构（对应 rule-schema.yaml）
// -----------------------------------------------------------------------------

// VulnRule 单条漏洞规则
type VulnRule struct {
	ID              string          `yaml:"id"`
	Name            string          `yaml:"name"`
	NameCN          string          `yaml:"name_cn"`
	Description     string          `yaml:"description"`
	OWASPCategory   string          `yaml:"owasp_category"`
	OWASPSubcat     string          `yaml:"owasp_subcategory"`
	CWEID           string          `yaml:"cwe_id"`
	CVSS            CVSSInfo        `yaml:"cvss"`
	Detection       DetectionConfig `yaml:"detection"`
	PoC             PoCConfig       `yaml:"poc"`
	Remediation     RemediationInfo `yaml:"remediation"`
	KnowledgeSource KnowledgeSource `yaml:"knowledge_source"`
}

// CVSSInfo CVSS 3.1 评分信息
type CVSSInfo struct {
	Vector    string  `yaml:"vector"`
	BaseScore float64 `yaml:"base_score"`
	Severity  string  `yaml:"severity"` // critical/high/medium/low
}

// DetectionConfig 检测配置
type DetectionConfig struct {
	Methods              []string         `yaml:"methods"`
	DASTSignals          DASTSignals      `yaml:"dast_signals"`
	SASTPatterns         []SASTPattern    `yaml:"sast_patterns"`
	MultiLayer           MultiLayerConfig `yaml:"multi_layer"`
	FalsePositiveFilters []FPFilter       `yaml:"false_positive_filters"`
}

// DASTSignals DAST 检测信号（按特异性分层）
type DASTSignals struct {
	HighSpecificity   []Signal `yaml:"high_specificity"`
	MediumSpecificity []Signal `yaml:"medium_specificity"`
	LowSpecificity    []Signal `yaml:"low_specificity"`
}

// Signal 单个检测信号
type Signal struct {
	Type       string  `yaml:"type"`
	Pattern    string  `yaml:"pattern"`
	Confidence float64 `yaml:"confidence"`
	// 编译后的正则（懒加载）
	compiledRegex *regexp.Regexp
}

// Match 检测信号是否匹配给定内容
func (s *Signal) Match(content string) bool {
	if s.compiledRegex == nil && s.Pattern != "" {
		re, err := regexp.Compile(s.Pattern)
		if err == nil {
			s.compiledRegex = re
		}
	}
	if s.compiledRegex != nil {
		return s.compiledRegex.MatchString(content)
	}
	return false
}

// SASTPattern SAST 源码匹配模式
type SASTPattern struct {
	Language   string  `yaml:"language"`
	Pattern    string  `yaml:"pattern"`
	Confidence float64 `yaml:"confidence"`
}

// MultiLayerConfig 多层确认配置
type MultiLayerConfig struct {
	Enabled                 bool `yaml:"enabled"`
	MinSignals              int  `yaml:"min_signals"`
	HighSpecificitySkipsMin bool `yaml:"high_specificity_skips_min"`
}

// FPFilter 误报过滤器
type FPFilter struct {
	Filter           string `yaml:"filter"`
	Condition        string `yaml:"condition"`
	Action           string `yaml:"action"` // discard / downgrade
	TargetConfidence string `yaml:"target_confidence"`
}

// PoCConfig PoC 生成配置
type PoCConfig struct {
	Enabled         bool           `yaml:"enabled"`
	RequestTemplate string         `yaml:"request_template"`
	Payloads        []PoCPayload   `yaml:"payloads"`
	Verification    []Verification `yaml:"verification"`
}

// PoCPayload 单个 PoC payload
type PoCPayload struct {
	Name        string `yaml:"name"`
	Value       string `yaml:"value"`
	Description string `yaml:"description"`
	Risk        string `yaml:"risk"`
}

// Verification PoC 验证条件
type Verification struct {
	Type        string `yaml:"type"`
	Pattern     string `yaml:"pattern"`
	Description string `yaml:"description"`
}

// RemediationInfo 修复建议
type RemediationInfo struct {
	Priority   string   `yaml:"priority"`
	Summary    string   `yaml:"summary"`
	Details    []string `yaml:"details"`
	References []string `yaml:"references"`
}

// KnowledgeSource 知识来源
type KnowledgeSource struct {
	File         string `yaml:"file"`
	Methodology  string `yaml:"methodology"`
	LastReviewed string `yaml:"last_reviewed"`
}

// -----------------------------------------------------------------------------
// 规则引擎
// -----------------------------------------------------------------------------

// RuleEngine 规则引擎：加载、管理、匹配漏洞规则
type RuleEngine struct {
	mu       sync.RWMutex
	rules    map[string]*VulnRule // rule.ID -> rule
	rulesDir string
}

// NewRuleEngine 创建规则引擎。rulesDir 为空时使用 embed 内嵌规则。
func NewRuleEngine(rulesDir string) *RuleEngine {
	re := &RuleEngine{
		rules:    make(map[string]*VulnRule),
		rulesDir: rulesDir,
	}
	re.LoadRules()
	return re
}

// LoadRules 加载规则：优先从外部目录加载，失败则用 embed 内嵌规则
func (re *RuleEngine) LoadRules() error {
	re.mu.Lock()
	defer re.mu.Unlock()

	loaded := 0

	// 1. 从外部目录加载（支持热更新）
	if re.rulesDir != "" {
		entries, err := os.ReadDir(re.rulesDir)
		if err == nil {
			for _, entry := range entries {
				if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
					continue
				}
				path := filepath.Join(re.rulesDir, entry.Name())
				data, err := os.ReadFile(path)
				if err != nil {
					log.Printf("[RuleEngine] 读取规则文件失败 %s: %v", path, err)
					continue
				}
				// 跳过空文件（可能被杀毒软件拦截）
				if len(data) == 0 {
					log.Printf("[RuleEngine] 跳过空规则文件 %s", path)
					continue
				}
				var rule VulnRule
				if err := yaml.Unmarshal(data, &rule); err != nil {
					log.Printf("[RuleEngine] 解析规则文件失败 %s: %v", path, err)
					continue
				}
				re.rules[rule.ID] = &rule
				loaded++
			}
		}
	}

	// 2. 如果外部目录加载失败或为空，使用 embed 内嵌规则
	if loaded == 0 {
		entries, err := embeddedRulesFS.ReadDir("rules")
		if err == nil {
			for _, entry := range entries {
				if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
					continue
				}
				data, err := embeddedRulesFS.ReadFile("rules/" + entry.Name())
				if err != nil {
					continue
				}
				var rule VulnRule
				if err := yaml.Unmarshal(data, &rule); err != nil {
					log.Printf("[RuleEngine] 解析内嵌规则失败 %s: %v", entry.Name(), err)
					continue
				}
				re.rules[rule.ID] = &rule
				loaded++
			}
		}
	}

	log.Printf("[RuleEngine] 已加载 %d 条漏洞规则", loaded)
	return nil
}

// GetRule 获取指定规则
func (re *RuleEngine) GetRule(ruleID string) (*VulnRule, bool) {
	re.mu.RLock()
	defer re.mu.RUnlock()
	r, ok := re.rules[ruleID]
	return r, ok
}

// ListRules 列出所有规则
func (re *RuleEngine) ListRules() []*VulnRule {
	re.mu.RLock()
	defer re.mu.RUnlock()
	out := make([]*VulnRule, 0, len(re.rules))
	for _, r := range re.rules {
		out = append(out, r)
	}
	return out
}

// RulesByCategory 按 OWASP 分类获取规则
func (re *RuleEngine) RulesByCategory(category string) []*VulnRule {
	re.mu.RLock()
	defer re.mu.RUnlock()
	var out []*VulnRule
	for _, r := range re.rules {
		if r.OWASPCategory == category {
			out = append(out, r)
		}
	}
	return out
}

// RulesByMethod 按检测方法获取规则（DAST/SAST/IAST）
func (re *RuleEngine) RulesByMethod(method string) []*VulnRule {
	re.mu.RLock()
	defer re.mu.RUnlock()
	var out []*VulnRule
	for _, r := range re.rules {
		for _, m := range r.Detection.Methods {
			if strings.EqualFold(m, method) {
				out = append(out, r)
				break
			}
		}
	}
	return out
}

// -----------------------------------------------------------------------------
// 匹配与评分
// -----------------------------------------------------------------------------

// MatchResult 规则匹配结果
type MatchResult struct {
	Rule            *VulnRule
	MatchedSignals  []Signal
	Confidence      float64 // 0.0 ~ 1.0
	ConfidenceLevel string  // high / medium / low
	ShouldReport    bool
	Evidence        string // 匹配证据
	PoCPayload      string // 推荐的 PoC payload
}

// MatchDAST 对 PageInfo 执行 DAST 规则匹配
// 返回所有匹配且 ShouldReport=true 的结果
func (re *RuleEngine) MatchDAST(page *PageInfo) []*MatchResult {
	re.mu.RLock()
	rules := make([]*VulnRule, 0, len(re.rules))
	for _, r := range re.rules {
		// 仅匹配支持 DAST 的规则
		supportsDAST := false
		for _, m := range r.Detection.Methods {
			if strings.EqualFold(m, "DAST") {
				supportsDAST = true
				break
			}
		}
		if supportsDAST {
			rules = append(rules, r)
		}
	}
	re.mu.RUnlock()

	content := page.RawContent
	if content == "" {
		content = page.Title
	}

	var results []*MatchResult
	for _, rule := range rules {
		result := re.matchSingleRule(rule, content, page)
		if result != nil && result.ShouldReport {
			results = append(results, result)
		}
	}
	return results
}

// matchSingleRule 匹配单条规则的 DAST 信号
func (re *RuleEngine) matchSingleRule(rule *VulnRule, content string, page *PageInfo) *MatchResult {
	if content == "" {
		return nil
	}

	var matchedSignals []Signal
	totalConfidence := 0.0

	// 高特异性信号
	for _, sig := range rule.Detection.DASTSignals.HighSpecificity {
		if sig.Match(content) {
			matchedSignals = append(matchedSignals, sig)
			totalConfidence += sig.Confidence
		}
	}

	// 中特异性信号
	for _, sig := range rule.Detection.DASTSignals.MediumSpecificity {
		if sig.Match(content) {
			matchedSignals = append(matchedSignals, sig)
			totalConfidence += sig.Confidence
		}
	}

	// 低特异性信号（仅辅助，不计入主置信度）
	lowHits := 0
	for _, sig := range rule.Detection.DASTSignals.LowSpecificity {
		if sig.Match(content) {
			lowHits++
		}
	}

	if len(matchedSignals) == 0 {
		return nil
	}

	// 多层确认决策
	shouldReport := false
	confidence := 0.0

	if rule.Detection.MultiLayer.Enabled {
		highHits := countHighHits(rule, matchedSignals)

		// 高特异性信号单命中即报告
		if highHits >= 1 && rule.Detection.MultiLayer.HighSpecificitySkipsMin {
			shouldReport = true
			confidence = 0.85
		} else if len(matchedSignals) >= rule.Detection.MultiLayer.MinSignals {
			shouldReport = true
			confidence = totalConfidence / float64(len(matchedSignals))
		} else if len(matchedSignals)+lowHits >= rule.Detection.MultiLayer.MinSignals {
			// 中低特异性组合达到阈值
			shouldReport = true
			confidence = 0.55
		}
	} else {
		shouldReport = true
		confidence = totalConfidence / float64(len(matchedSignals))
	}

	// 置信度上下限
	if confidence > 1.0 {
		confidence = 1.0
	}
	if confidence < 0.0 {
		confidence = 0.0
	}

	// 误报过滤器应用
	for _, fp := range rule.Detection.FalsePositiveFilters {
		switch fp.Action {
		case "discard":
			if re.evaluateFilter(fp, page, content) {
				return nil
			}
		case "downgrade":
			if re.evaluateFilter(fp, page, content) {
				confidence = 0.35
			}
		}
	}

	confidenceLevel := confidenceToLevel(confidence)

	// 生成证据
	evidence := fmt.Sprintf("规则 %s 命中 %d 个信号 (高:%d 中:%d 低:%d)，置信度 %.2f",
		rule.ID, len(matchedSignals),
		countHighHits(rule, matchedSignals),
		len(matchedSignals)-countHighHits(rule, matchedSignals),
		lowHits, confidence)

	// 推荐 PoC payload（取第一个非低风险的 payload）
	recommendedPayload := ""
	if rule.PoC.Enabled && len(rule.PoC.Payloads) > 0 {
		for _, p := range rule.PoC.Payloads {
			if p.Risk == "medium" || p.Risk == "high" {
				recommendedPayload = p.Value
				break
			}
		}
		if recommendedPayload == "" {
			recommendedPayload = rule.PoC.Payloads[0].Value
		}
	}

	return &MatchResult{
		Rule:            rule,
		MatchedSignals:  matchedSignals,
		Confidence:      confidence,
		ConfidenceLevel: confidenceLevel,
		ShouldReport:    shouldReport,
		Evidence:        evidence,
		PoCPayload:      recommendedPayload,
	}
}

// evaluateFilter 评估误报过滤条件
func (re *RuleEngine) evaluateFilter(fp FPFilter, page *PageInfo, content string) bool {
	switch fp.Filter {
	case "status_code":
		// condition: "status_code != 200"
		if page.StatusCode != 200 {
			return true
		}
	case "content_validation":
		// 简化实现：检查内容是否为空或纯 HTML 错误页
		if strings.TrimSpace(content) == "" {
			return true
		}
	case "empty_content":
		if len(strings.TrimSpace(content)) == 0 {
			return true
		}
	}
	return false
}

// countHighHits 统计高特异性信号命中数
func countHighHits(rule *VulnRule, matched []Signal) int {
	highTypes := make(map[string]bool)
	for _, s := range rule.Detection.DASTSignals.HighSpecificity {
		highTypes[s.Type] = true
	}
	count := 0
	for _, s := range matched {
		if highTypes[s.Type] {
			count++
		}
	}
	return count
}

// confidenceToLevel 将置信度数值转换为等级
func confidenceToLevel(c float64) string {
	if c >= 0.85 {
		return "high"
	}
	if c >= 0.60 {
		return "medium"
	}
	return "low"
}

// -----------------------------------------------------------------------------
// PoC 生成
// -----------------------------------------------------------------------------

// GeneratePoC 根据规则和目标 URL 生成 PoC 请求
func (re *RuleEngine) GeneratePoC(ruleID string, targetURL string, payloadIndex int) string {
	rule, ok := re.GetRule(ruleID)
	if !ok || !rule.PoC.Enabled {
		return ""
	}

	tmpl := rule.PoC.RequestTemplate
	host := extractHostForPoC(targetURL)
	param := extractParamNameForPoC(targetURL)
	payload := ""

	if payloadIndex >= 0 && payloadIndex < len(rule.PoC.Payloads) {
		payload = rule.PoC.Payloads[payloadIndex].Value
	} else if len(rule.PoC.Payloads) > 0 {
		payload = rule.PoC.Payloads[0].Value
	}

	result := strings.ReplaceAll(tmpl, "{{url}}", targetURL)
	result = strings.ReplaceAll(result, "{{host}}", host)
	result = strings.ReplaceAll(result, "{{param}}", param)
	result = strings.ReplaceAll(result, "{{payload}}", payload)

	return result
}

// extractHostForPoC 从 URL 提取 host
func extractHostForPoC(rawURL string) string {
	// 简化实现：从 URL 提取 host:port
	if idx := strings.Index(rawURL, "://"); idx >= 0 {
		rest := rawURL[idx+3:]
		if slash := strings.Index(rest, "/"); slash >= 0 {
			return rest[:slash]
		}
		return rest
	}
	return rawURL
}

// extractParamNameForPoC 从 URL 提取第一个参数名
func extractParamNameForPoC(rawURL string) string {
	if q := strings.Index(rawURL, "?"); q >= 0 {
		params := rawURL[q+1:]
		if eq := strings.Index(params, "="); eq >= 0 {
			return params[:eq]
		}
	}
	return "param"
}

// -----------------------------------------------------------------------------
// CVSS 评分
// -----------------------------------------------------------------------------

// CVSSVector 解析 CVSS 3.1 向量并计算分数
// 参考: https://www.first.org/cvss/v3.1/specification-document
func ParseCVSSVector(vector string) (baseScore float64, severity string) {
	// 简化实现：直接使用规则中预定义的分数
	// 完整实现需要解析 AV/AC/PR/UI/S/C/I/A 指标
	parts := strings.Split(vector, "/")
	if len(parts) < 9 {
		return 0, "none"
	}

	metrics := make(map[string]string)
	for _, p := range parts[1:] {
		kv := strings.SplitN(p, ":", 2)
		if len(kv) == 2 {
			metrics[kv[0]] = kv[1]
		}
	}

	// 可利用性指标
	av := metricValue(metrics["AV"], map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2})
	ac := metricValue(metrics["AC"], map[string]float64{"L": 0.77, "H": 0.44})
	pr := metricValue(metrics["PR"], map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27})
	ui := metricValue(metrics["UI"], map[string]float64{"N": 0.85, "R": 0.62})

	// 影响指标
	ciaScale := map[string]float64{"H": 0.56, "L": 0.22, "N": 0.0}
	c := ciaScale[metrics["C"]]
	i := ciaScale[metrics["I"]]
	a := ciaScale[metrics["A"]]

	iss := 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))
	impact := 0.0
	if metrics["S"] == "U" {
		impact = 6.42 * iss
	} else {
		impact = 7.52*(iss-0.029) - 3.25*(iss-0.02)
	}

	exploitability := 8.22 * av * ac * pr * ui

	if impact <= 0 {
		baseScore = 0
	} else if metrics["S"] == "U" {
		baseScore = round1(min(impact+exploitability, 10.0))
	} else {
		baseScore = round1(min(1.08*(impact+exploitability), 10.0))
	}

	return baseScore, cvssSeverity(baseScore)
}

func metricValue(v string, m map[string]float64) float64 {
	if val, ok := m[v]; ok {
		return val
	}
	return 0.0
}

func cvssSeverity(score float64) string {
	switch {
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	case score >= 0.1:
		return "low"
	default:
		return "none"
	}
}

func round1(v float64) float64 {
	return float64(int(v*10+0.5)) / 10
}

func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
