package ai

import (
	"context"
	"fmt"
	"strings"

	"security-agent/internal/config"
	"security-agent/internal/models"
)

const defaultSystemPrompt = "你是一名资深网络安全分析师，输出需准确、可执行、避免臆测。"

// AIModule 面向业务层（扫描引擎）的 AI 门面。
// 内部委托给 Manager，从而自动获得多模型切换、降级与并行能力。
type AIModule struct {
	mgr *Manager
}

// NewAIModule 由配置构建（内部创建 Manager）
func NewAIModule(cfg *config.AIConfig) *AIModule {
	return &AIModule{mgr: NewManager(cfg)}
}

// NewAIModuleWithManager 复用已有的 Manager（推荐，避免重复构建连接池）
func NewAIModuleWithManager(mgr *Manager) *AIModule {
	if mgr == nil {
		mgr = NewManager(nil)
	}
	return &AIModule{mgr: mgr}
}

// Manager 暴露底层路由中心，供 HTTP 层复用
func (a *AIModule) Manager() *Manager { return a.mgr }

// Available 是否存在至少一个可用模型；无 Key 时业务方应直接走降级逻辑，
// 避免为了注定失败的请求白白消耗超时时间。
func (a *AIModule) Available() bool { return a.mgr != nil && a.mgr.Ready() }

// Chat 单条 prompt 对话（上下文超时由 Manager 的 timeout 控制）
func (a *AIModule) Chat(prompt string) (string, error) {
	if a.mgr == nil {
		return "", ErrNoProvider
	}
	ctx, cancel := context.WithTimeout(context.Background(), a.mgr.Timeout())
	defer cancel()
	return a.mgr.SimpleChat(ctx, prompt, defaultSystemPrompt)
}

// AnalyzeResults 对扫描结果做聚合分析与误报识别
func (a *AIModule) AnalyzeResults(vulns []*models.Vulnerability, sensitiveInfos []*models.SensitiveInfo) {
	if len(vulns) == 0 && len(sensitiveInfos) == 0 {
		return
	}
	if !a.Available() {
		return
	}

	prompt := a.buildAnalysisPrompt(vulns, sensitiveInfos)
	ctx, cancel := context.WithTimeout(context.Background(), a.mgr.Timeout())
	defer cancel()

	resp, err := a.mgr.Chat(ctx, NewChatRequest(prompt, defaultSystemPrompt))
	if err != nil {
		fmt.Printf("AI analysis error: %v\n", err)
		return
	}
	a.applyAnalysisSuggestions(resp.Content, vulns, sensitiveInfos)
}

// GenerateReport 生成扫描报告；任一模型不可用时回落到本地模板报告
func (a *AIModule) GenerateReport(scanJob *models.ScanJob, domain *models.Domain, vulns []*models.Vulnerability, sensitiveInfos []*models.SensitiveInfo) string {
	if !a.Available() {
		return a.generateFallbackReport(scanJob, domain, vulns, sensitiveInfos)
	}

	prompt := a.buildReportPrompt(scanJob, domain, vulns, sensitiveInfos)
	ctx, cancel := context.WithTimeout(context.Background(), a.mgr.Timeout())
	defer cancel()

	resp, err := a.mgr.Chat(ctx, NewChatRequest(prompt, defaultSystemPrompt))
	if err != nil {
		fmt.Printf("AI report error (fallback to template): %v\n", err)
		return a.generateFallbackReport(scanJob, domain, vulns, sensitiveInfos)
	}
	if strings.TrimSpace(resp.Content) == "" {
		return a.generateFallbackReport(scanJob, domain, vulns, sensitiveInfos)
	}
	return resp.Content
}

// AnalyzeMulti 并行调用全部可用模型做交叉分析，返回各家结论。
// 适用于需要多模型投票/对比的高价值场景。
func (a *AIModule) AnalyzeMulti(prompt string) ([]*ProviderResult, error) {
	if a.mgr == nil {
		return nil, ErrNoProvider
	}
	ctx, cancel := context.WithTimeout(context.Background(), a.mgr.Timeout()*2)
	defer cancel()
	return a.mgr.ChatParallel(ctx, NewChatRequest(prompt, defaultSystemPrompt))
}

// ---------- Prompt 构造 ----------

func (a *AIModule) buildAnalysisPrompt(vulns []*models.Vulnerability, sensitiveInfos []*models.SensitiveInfo) string {
	var sb strings.Builder

	sb.WriteString("请分析以下安全扫描结果，并按 JSON 数组格式输出（每项含 url/name/action 三个字段）：\n")
	sb.WriteString("1. 归并同类漏洞，避免重复计数\n")
	sb.WriteString("2. 标记可能的误报并简述理由\n")
	sb.WriteString("3. 给出风险处置优先级（P0/P1/P2）\n\n")

	if len(vulns) > 0 {
		sb.WriteString("## 漏洞列表\n")
		for _, v := range vulns {
			sb.WriteString(fmt.Sprintf("- [%s] %s @ %s\n", strings.ToUpper(v.Severity), v.Name, v.URL))
		}
	}

	if len(sensitiveInfos) > 0 {
		sb.WriteString("\n## 敏感信息\n")
		for _, s := range sensitiveInfos {
			sb.WriteString(fmt.Sprintf("- [%s] %s @ %s\n", strings.ToUpper(s.Severity), s.Type, s.URL))
		}
	}

	return sb.String()
}

func (a *AIModule) buildReportPrompt(scanJob *models.ScanJob, domain *models.Domain, vulns []*models.Vulnerability, sensitiveInfos []*models.SensitiveInfo) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("# 安全巡检报告：%s\n\n", domain.Name))
	sb.WriteString(fmt.Sprintf("- 任务 ID：%s\n", scanJob.ID))
	sb.WriteString(fmt.Sprintf("- 扫描时间：%s\n\n", scanJob.CreatedAt.Format("2006-01-02 15:04:05")))

	high, medium, low := 0, 0, 0
	for _, v := range vulns {
		switch strings.ToLower(v.Severity) {
		case "high":
			high++
		case "medium":
			medium++
		case "low":
			low++
		}
	}

	sb.WriteString(fmt.Sprintf("共发现漏洞 %d 个（高危 %d / 中危 %d / 低危 %d），敏感信息 %d 处。\n\n",
		len(vulns), high, medium, low, len(sensitiveInfos)))

	if len(vulns) > 0 {
		sb.WriteString("## 漏洞明细\n")
		for _, v := range vulns {
			sb.WriteString(fmt.Sprintf("### %s（%s）\n", v.Name, strings.ToUpper(v.Severity)))
			sb.WriteString(fmt.Sprintf("- URL：%s\n", v.URL))
			if v.Description != "" {
				sb.WriteString(fmt.Sprintf("- 描述：%s\n", v.Description))
			}
			if v.Remediation != "" {
				sb.WriteString(fmt.Sprintf("- 修复建议：%s\n", v.Remediation))
			}
			sb.WriteString("\n")
		}
	}

	sb.WriteString("请输出一份结构化的 Markdown 报告，包含：风险综述、高危项逐条说明、修复优先级建议。\n")
	return sb.String()
}

func (a *AIModule) generateFallbackReport(scanJob *models.ScanJob, domain *models.Domain, vulns []*models.Vulnerability, sensitiveInfos []*models.SensitiveInfo) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("# 安全巡检报告：%s\n\n", domain.Name))
	sb.WriteString(fmt.Sprintf("**扫描时间**：%s\n\n", scanJob.CreatedAt.Format("2006-01-02 15:04:05")))

	high, medium, low := 0, 0, 0
	for _, v := range vulns {
		switch strings.ToLower(v.Severity) {
		case "high":
			high++
		case "medium":
			medium++
		case "low":
			low++
		}
	}

	sb.WriteString("## 汇总\n\n")
	sb.WriteString("| 严重级别 | 数量 |\n|---------|------|\n")
	sb.WriteString(fmt.Sprintf("| 高危 | %d |\n", high))
	sb.WriteString(fmt.Sprintf("| 中危 | %d |\n", medium))
	sb.WriteString(fmt.Sprintf("| 低危 | %d |\n\n", low))
	sb.WriteString(fmt.Sprintf("敏感信息：%d 处\n\n", len(sensitiveInfos)))
	sb.WriteString("> 说明：未配置可用的大模型 API Key，本报告由本地模板生成。\n")
	sb.WriteString("> 在 config.yaml 的 `ai.providers` 中配置 DeepSeek / Kimi / GLM 任意一家后即可获得 AI 增强报告。\n")

	return sb.String()
}

// applyAnalysisSuggestions 解析模型给出的处置建议。
// 当前阶段落盘到运行日志，后续可接入结构化解析回写漏洞字段。
func (a *AIModule) applyAnalysisSuggestions(response string, vulns []*models.Vulnerability, sensitiveInfos []*models.SensitiveInfo) {
	trimmed := strings.TrimSpace(response)
	if trimmed == "" {
		return
	}
	fmt.Printf("[AI] 分析完成：%d 个漏洞 / %d 处敏感信息，建议摘要 %d 字符\n",
		len(vulns), len(sensitiveInfos), len([]rune(trimmed)))
}
