package api

import (
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"security-agent/internal/ai"
	"security-agent/internal/models"
	"security-agent/internal/scheduler"
	"security-agent/internal/storage"
)

// InspectionHandler 暴露 AI 自动巡检的 HTTP 接口：
//   - 巡检规则(rule) 的 CRUD 与手动触发
//   - 巡检记录(record) 的列表 / 详情 / 统计
type InspectionHandler struct {
	ruleRepo   *storage.InspectionRuleRepository
	recordRepo *storage.InspectionRecordRepository
	domainRepo *storage.DomainRepository
	sched      *scheduler.Scheduler
	aiMgr      *ai.Manager
}

func NewInspectionHandler(
	ruleRepo *storage.InspectionRuleRepository,
	recordRepo *storage.InspectionRecordRepository,
	domainRepo *storage.DomainRepository,
	sched *scheduler.Scheduler,
	aiMgr *ai.Manager,
) *InspectionHandler {
	return &InspectionHandler{
		ruleRepo: ruleRepo, recordRepo: recordRepo, domainRepo: domainRepo,
		sched: sched, aiMgr: aiMgr,
	}
}

// ---------- 请求结构体 ----------

type createRuleRequest struct {
	Name              string   `json:"name" binding:"required"`
	DomainID          string   `json:"domain_id"`  // 单资产（向后兼容）
	DomainIDs         []string `json:"domain_ids"` // 多资产绑定（优先于 domain_id）
	Enabled           *bool    `json:"enabled"`    // 缺省=true（启用）
	Schedule          string   `json:"schedule" binding:"required"`
	SeverityThreshold string   `json:"severity_threshold"`
	RunScan           *bool    `json:"run_scan"` // 缺省=true（先扫描）
	RetryCount        int      `json:"retry_count"`
	RetryBackoffSec   int      `json:"retry_backoff_sec"`
	AlertOnFailure    *bool    `json:"alert_on_failure"`
}

// resolveDomainIDs 归一化请求中的目标域名列表：优先 domain_ids，其次单值 domain_id。
func (req *createRuleRequest) resolveDomainIDs() []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(req.DomainIDs)+1)
	for _, id := range req.DomainIDs {
		id = strings.TrimSpace(id)
		if id != "" && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	if len(out) == 0 && strings.TrimSpace(req.DomainID) != "" {
		out = append(out, strings.TrimSpace(req.DomainID))
	}
	return out
}

// ---------- 规则 CRUD ----------

func (h *InspectionHandler) ListRules(c *gin.Context) {
	rules, err := h.ruleRepo.List()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if rules == nil {
		rules = []*models.InspectionRule{}
	}
	c.JSON(http.StatusOK, rules)
}

func (h *InspectionHandler) GetRule(c *gin.Context) {
	rule, err := h.ruleRepo.GetByID(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "rule not found"})
		return
	}
	c.JSON(http.StatusOK, rule)
}

func (h *InspectionHandler) CreateRule(c *gin.Context) {
	var req createRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	domainIDs := req.resolveDomainIDs()
	if len(domainIDs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请至少选择一个关联域名"})
		return
	}
	// 校验所有关联域名均存在
	for _, did := range domainIDs {
		if _, err := h.domainRepo.GetByID(did); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "关联的域名不存在: " + did})
			return
		}
	}

	// 校验 cron 表达式（提前暴露格式错误，避免注册到调度器后才失败）
	if _, err := scheduler.ParseSchedule(req.Schedule); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Cron 表达式无效: " + err.Error()})
		return
	}

	rule := &models.InspectionRule{
		Name:              req.Name,
		DomainID:          domainIDs[0],
		DomainIDs:         domainIDs,
		Enabled:           req.Enabled == nil || *req.Enabled, // 缺省启用
		Schedule:          req.Schedule,
		SeverityThreshold: req.SeverityThreshold,
		RunScan:           req.RunScan == nil || *req.RunScan, // 缺省先扫描
		RetryCount:        req.RetryCount,
		RetryBackoffSec:   req.RetryBackoffSec,
		AlertOnFailure:    req.AlertOnFailure != nil && *req.AlertOnFailure,
	}

	if err := h.ruleRepo.Create(rule); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 若启用，立即注册到运行中的调度器（保存即生效，无需重启）
	if rule.Enabled && rule.Schedule != "" {
		if err := h.sched.AddRuleTask(rule); err != nil {
			log.Printf("注册巡检规则失败(rule=%s): %v", rule.ID, err)
		}
	}

	c.JSON(http.StatusCreated, rule)
}

func (h *InspectionHandler) UpdateRule(c *gin.Context) {
	id := c.Param("id")
	rule, err := h.ruleRepo.GetByID(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "rule not found"})
		return
	}

	var req createRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	domainIDs := req.resolveDomainIDs()
	if len(domainIDs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请至少选择一个关联域名"})
		return
	}
	for _, did := range domainIDs {
		if _, err := h.domainRepo.GetByID(did); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "关联的域名不存在: " + did})
			return
		}
	}
	if _, err := scheduler.ParseSchedule(req.Schedule); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Cron 表达式无效: " + err.Error()})
		return
	}

	rule.Name = req.Name
	rule.DomainID = domainIDs[0]
	rule.DomainIDs = domainIDs
	if req.Enabled != nil {
		rule.Enabled = *req.Enabled
	}
	rule.Schedule = req.Schedule
	rule.SeverityThreshold = req.SeverityThreshold
	if req.RunScan != nil {
		rule.RunScan = *req.RunScan
	}
	rule.RetryCount = req.RetryCount
	rule.RetryBackoffSec = req.RetryBackoffSec
	if req.AlertOnFailure != nil {
		rule.AlertOnFailure = *req.AlertOnFailure
	}

	if err := h.ruleRepo.Update(rule); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 热更新：重建调度任务（启用/暂停/改周期即时反映到运行中的调度器）
	h.sched.UpdateRuleTask(rule)

	c.JSON(http.StatusOK, rule)
}

func (h *InspectionHandler) DeleteRule(c *gin.Context) {
	id := c.Param("id")
	if err := h.ruleRepo.Delete(id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	h.sched.RemoveRuleTask(id)
	c.Status(http.StatusNoContent)
}

// RunRule 手动立即触发一条巡检规则。返回新建的巡检记录 ID（实际结果异步生成）。
func (h *InspectionHandler) RunRule(c *gin.Context) {
	recordID, err := h.sched.TriggerManual(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusAccepted, gin.H{"record_id": recordID, "status": "running", "message": "巡检已触发，请稍后查看记录"})
}

// ---------- 记录查询 ----------

func (h *InspectionHandler) ListRecords(c *gin.Context) {
	domainID := c.Query("domain_id")
	ruleID := c.Query("rule_id")
	status := c.Query("status")
	limit := 50
	if v := c.Query("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	records, err := h.recordRepo.List(domainID, ruleID, status, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if records == nil {
		records = []*models.InspectionRecord{}
	}
	c.JSON(http.StatusOK, records)
}

func (h *InspectionHandler) GetRecord(c *gin.Context) {
	rec, err := h.recordRepo.GetByID(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "record not found"})
		return
	}
	c.JSON(http.StatusOK, rec)
}

func (h *InspectionHandler) Stats(c *gin.Context) {
	counts, err := h.recordRepo.CountByStatus()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if counts == nil {
		counts = map[string]int{}
	}
	c.JSON(http.StatusOK, gin.H{"by_status": counts})
}
