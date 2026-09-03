package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"security-agent/internal/scanner"
	"security-agent/internal/scheduler"
)

type ScanHandler struct {
	engine    *scanner.Engine
	scheduler *scheduler.Scheduler
}

func NewScanHandler(engine *scanner.Engine, sched *scheduler.Scheduler) *ScanHandler {
	return &ScanHandler{
		engine:    engine,
		scheduler: sched,
	}
}

func (h *ScanHandler) StartScan(c *gin.Context) {
	var req StartScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	scanJob, err := h.scheduler.TriggerManualScan(req.DomainID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusAccepted, StartScanResponse{
		JobID:   scanJob.ID,
		Status:  scanJob.Status,
		Message: "Scan started successfully",
	})
}

func (h *ScanHandler) GetScanResults(c *gin.Context) {
	scanJobID := c.Param("id")
	results, err := h.engine.GetScanResults(scanJobID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, results)
}

func (h *ScanHandler) GetScanStatus(c *gin.Context) {
	scanJobID := c.Param("id")
	progress, err := h.engine.GetScanProgress(scanJobID)
	if err == nil && progress != nil {
		c.JSON(http.StatusOK, gin.H{"status": progress.Status})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "unknown"})
}

// GetScanProgress 获取扫描进度
func (h *ScanHandler) GetScanProgress(c *gin.Context) {
	scanJobID := c.Param("id")
	progress, err := h.engine.GetScanProgress(scanJobID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "扫描任务不存在"})
		return
	}
	c.JSON(http.StatusOK, progress)
}

// GetScanLogs 获取扫描日志
func (h *ScanHandler) GetScanLogs(c *gin.Context) {
	scanJobID := c.Param("id")
	logs, err := h.engine.GetScanLogs(scanJobID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "扫描任务不存在"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"logs": logs})
}

type StartScanRequest struct {
	DomainID string `json:"domain_id" binding:"required"`
}

type StartScanResponse struct {
	JobID   string `json:"job_id"`
	Status  string `json:"status"`
	Message string `json:"message"`
}

// GetReport 生成扫描报告，支持 markdown/json/html 格式
// GET /api/scan/:id/report?format=markdown|json|html
func (h *ScanHandler) GetReport(c *gin.Context) {
	scanJobID := c.Param("id")
	format := c.DefaultQuery("format", "markdown")

	// 获取扫描结果以确定目标 URL
	results, err := h.engine.GetScanResults(scanJobID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "扫描任务不存在: " + err.Error()})
		return
	}

	// 从漏洞列表提取目标 URL（取第一个漏洞的 origin）
	targetURL := ""
	if len(results.Vulnerabilities) > 0 {
		targetURL = extractOrigin(results.Vulnerabilities[0].URL)
	}

	bundle, err := h.engine.GenerateReport(scanJobID, targetURL)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "报告生成失败: " + err.Error()})
		return
	}

	switch format {
	case "json":
		jsonBytes, _ := json.MarshalIndent(bundle.JSON, "", "  ")
		c.Data(http.StatusOK, "application/json; charset=utf-8", jsonBytes)
	case "html":
		c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(bundle.HTML))
	default:
		c.Data(http.StatusOK, "text/markdown; charset=utf-8", []byte(bundle.Markdown))
	}
}

// extractOrigin 从 URL 中提取 origin（scheme://host:port），用于报告标题
func extractOrigin(rawURL string) string {
	if rawURL == "" {
		return ""
	}
	idx := strings.Index(rawURL, "://")
	if idx < 0 {
		return rawURL
	}
	rest := rawURL[idx+3:]
	end := strings.IndexAny(rest, "/?#")
	if end < 0 {
		return rawURL[:idx+3+len(rest)]
	}
	return rawURL[:idx+3+end]
}

// ListRules 列出当前加载的所有漏洞规则
// GET /api/scan/rules
func (h *ScanHandler) ListRules(c *gin.Context) {
	ruleEngine := h.engine.GetRuleEngine()
	if ruleEngine == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "规则引擎未初始化"})
		return
	}

	rules := ruleEngine.ListRules()
	type RuleSummary struct {
		ID            string `json:"id"`
		Name          string `json:"name"`
		NameCN        string `json:"name_cn"`
		OWASPCategory string `json:"owasp_category"`
		CVSSSeverity  string `json:"cvss_severity"`
		CVSSScore     float64 `json:"cvss_score"`
		CWEID         string `json:"cwe_id"`
		Methods       []string `json:"methods"`
	}

	var summaries []RuleSummary
	for _, r := range rules {
		summaries = append(summaries, RuleSummary{
			ID:            r.ID,
			Name:          r.Name,
			NameCN:        r.NameCN,
			OWASPCategory: r.OWASPCategory,
			CVSSSeverity:  r.CVSS.Severity,
			CVSSScore:     r.CVSS.BaseScore,
			CWEID:         r.CWEID,
			Methods:       r.Detection.Methods,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"total": len(summaries),
		"rules": summaries,
	})
}
