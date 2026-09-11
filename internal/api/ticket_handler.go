package api

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"security-agent/internal/models"
	"security-agent/internal/storage"
)

type TicketHandler struct {
	ticketRepo *storage.TicketRepository
	vulnRepo   *storage.VulnerabilityRepository
}

func NewTicketHandler(ticketRepo *storage.TicketRepository, vulnRepo *storage.VulnerabilityRepository) *TicketHandler {
	return &TicketHandler{
		ticketRepo: ticketRepo,
		vulnRepo:   vulnRepo,
	}
}

type CreateTicketRequest struct {
	VulnID      string `json:"vuln_id,omitempty"`
	ScanJobID   string `json:"scan_job_id,omitempty"`
	Title       string `json:"title,omitempty"`
	Type        string `json:"type,omitempty"`
	RiskLevel   string `json:"risk_level,omitempty"`
	Description string `json:"description,omitempty"`
	Notes       string `json:"notes,omitempty"`
}

type UpdateTicketRequest struct {
	Status   string `json:"status"`
	Assignee string `json:"assignee"`
}

type AddNoteRequest struct {
	Note string `json:"note" binding:"required"`
}

type DeleteBatchRequest struct {
	IDs []string `json:"ids" binding:"required,min=1"`
}

type MergeTicketsRequest struct {
	SourceIDs   []string `json:"source_ids" binding:"required,min=2"`
	TargetTitle string   `json:"target_title"`
}

// Create 创建工单
func (h *TicketHandler) Create(c *gin.Context) {
	roleLevel := GetRoleLevelFromContext(c)
	if roleLevel < models.RoleLevelScanner {
		c.JSON(http.StatusForbidden, gin.H{"error": "权限不足，需要权限级别1或以上"})
		return
	}

	var req CreateTicketRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 描述/备注至少其一必填，避免创建空工单
	if strings.TrimSpace(req.Description) == "" && strings.TrimSpace(req.Notes) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "工单描述不能为空"})
		return
	}

	// 关联漏洞时补全扫描任务与漏洞上下文（自包含，列表/详情可直接展示）
	var vuln *models.Vulnerability
	if req.VulnID != "" {
		if v, err := h.vulnRepo.GetByID(req.VulnID); err == nil && v != nil {
			vuln = v
		}
		if req.ScanJobID == "" && vuln != nil {
			req.ScanJobID = vuln.ScanJobID
		}
	}

	ticket := &models.Ticket{
		VulnID:    req.VulnID,
		ScanJobID: req.ScanJobID,
		Status:    models.TicketStatusPending,
		Type:      req.Type,
		Title:     req.Title,
		// risk_level 优先取调用方显式传入（智能体 create_ticket 会带 high/medium/low）；
		// 若未传则留空，待下方「关联漏洞」或「triageFromRisk」环节自动补全，保持向后兼容。
		RiskLevel:   req.RiskLevel,
		Description: req.Description,
		Notes:       req.Notes,
		CreatorID:   CurrentUserID(c),
	}

	// 从关联漏洞补全展示字段；未提供则给基线研判
	if vuln != nil {
		if ticket.VulnName == "" {
			ticket.VulnName = vuln.Name
		}
		if ticket.VulnType == "" {
			ticket.VulnType = vuln.Type
		}
		if ticket.RiskLevel == "" {
			ticket.RiskLevel = vuln.Severity
		}
		if ticket.VulnDescription == "" {
			ticket.VulnDescription = vuln.Description
		}
		if ticket.Evidence == "" {
			ticket.Evidence = vuln.Evidence
		}
		if ticket.AssetURL == "" {
			ticket.AssetURL = vuln.URL
		}
		if ticket.Title == "" {
			name := vuln.Name
			if name == "" {
				name = "漏洞工单"
			}
			ticket.Title = name
		}
		if ticket.Description == "" {
			ticket.Description = vuln.Description
		}
	}
	priority, harm, mitigation, retest := triageFromRisk(ticket.RiskLevel)
	if ticket.HarmDescription == "" {
		ticket.HarmDescription = harm
	}
	if ticket.RemediationPriority == "" {
		ticket.RemediationPriority = priority
	}
	if ticket.MitigationMeasures == "" {
		ticket.MitigationMeasures = mitigation
	}
	if ticket.RetestMethod == "" {
		ticket.RetestMethod = retest
	}

	if err := h.ticketRepo.Create(ticket); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "创建工单失败: " + err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "工单创建成功",
		"ticket":  ticket,
	})
}

// List 获取工单列表
func (h *TicketHandler) List(c *gin.Context) {
	status := c.Query("status")
	scanJobID := c.Query("scan_job_id")

	tickets, err := h.ticketRepo.List(status, scanJobID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "获取工单列表失败: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, tickets)
}

// Get 获取工单详情
func (h *TicketHandler) Get(c *gin.Context) {
	id := c.Param("id")

	ticket, err := h.ticketRepo.GetByID(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "工单不存在"})
		return
	}

	c.JSON(http.StatusOK, ticket)
}

// Update 更新工单状态
func (h *TicketHandler) Update(c *gin.Context) {
	roleLevel := GetRoleLevelFromContext(c)
	if roleLevel < models.RoleLevelAdmin {
		c.JSON(http.StatusForbidden, gin.H{"error": "权限不足，需要权限级别3"})
		return
	}

	id := c.Param("id")
	var req UpdateTicketRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ticket, err := h.ticketRepo.GetByID(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "工单不存在"})
		return
	}

	if req.Status != "" {
		if req.Status != models.TicketStatusPending &&
			req.Status != models.TicketStatusConfirmed &&
			req.Status != models.TicketStatusExcluded &&
			req.Status != models.TicketStatusResolved {
			c.JSON(http.StatusBadRequest, gin.H{"error": "无效的工单状态"})
			return
		}
		if err := h.ticketRepo.UpdateStatus(id, req.Status); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "更新工单状态失败: " + err.Error()})
			return
		}
		ticket.Status = req.Status
	}

	if req.Assignee != "" {
		if err := h.ticketRepo.UpdateAssignee(id, req.Assignee); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "更新处理人失败: " + err.Error()})
			return
		}
		ticket.Assignee = req.Assignee
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "工单更新成功",
		"ticket":  ticket,
	})
}

// AddNote 添加备注
func (h *TicketHandler) AddNote(c *gin.Context) {
	id := c.Param("id")
	var req AddNoteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	creatorName := CurrentUsername(c)
	note := creatorName + ": " + req.Note

	if err := h.ticketRepo.AddNotes(id, note); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "添加备注失败: " + err.Error()})
		return
	}

	ticket, _ := h.ticketRepo.GetByID(id)
	c.JSON(http.StatusOK, gin.H{
		"message": "备注添加成功",
		"ticket":  ticket,
	})
}

// Delete 删除工单
func (h *TicketHandler) Delete(c *gin.Context) {
	roleLevel := GetRoleLevelFromContext(c)
	if roleLevel < models.RoleLevelAdmin {
		c.JSON(http.StatusForbidden, gin.H{"error": "权限不足，需要权限级别3"})
		return
	}

	id := c.Param("id")
	if err := h.ticketRepo.Delete(id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "删除工单失败: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "工单删除成功"})
}

// DeleteBatch 批量删除工单
func (h *TicketHandler) DeleteBatch(c *gin.Context) {
	roleLevel := GetRoleLevelFromContext(c)
	if roleLevel < models.RoleLevelAdmin {
		c.JSON(http.StatusForbidden, gin.H{"error": "权限不足，需要权限级别3"})
		return
	}

	var req DeleteBatchRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if len(req.IDs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请选择要删除的工单"})
		return
	}

	deleted, err := h.ticketRepo.DeleteBatch(req.IDs)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "批量删除工单失败: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": fmt.Sprintf("成功删除 %d 个工单", deleted),
		"deleted": deleted,
	})
}

// Merge 批量合并工单（将多个工单合并为一个）
func (h *TicketHandler) Merge(c *gin.Context) {
	roleLevel := GetRoleLevelFromContext(c)
	if roleLevel < models.RoleLevelAdmin {
		c.JSON(http.StatusForbidden, gin.H{"error": "权限不足，需要权限级别3"})
		return
	}

	var req MergeTicketsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if len(req.SourceIDs) < 2 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "合并至少需要2个工单"})
		return
	}

	result, err := h.ticketRepo.MergeTickets(req.SourceIDs, req.TargetTitle)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "合并工单失败: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": fmt.Sprintf("成功合并 %d 个工单为新工单", len(req.SourceIDs)),
		"ticket":  result,
	})
}

// GetRoleLevelFromContext 从上下文获取用户权限级别。
// 优先取 JWT 中携带的数值 role_level（精确），但 rl==0 视为「未携带」而回退到
// Role 字符串映射——因为中间件会把 claims.RoleLevel 的零值（旧令牌未设置 rl 时）
// 原样注入上下文，若不区分会令旧管理员令牌被误判为级别 0。
func GetRoleLevelFromContext(c *gin.Context) int {
	if v, ok := c.Get(ctxUserRoleLvl); ok {
		if lvl, ok := v.(int); ok && lvl > 0 {
			return lvl
		}
	}
	if v, ok := c.Get(ctxUserRole); ok {
		if role, ok := v.(string); ok {
			return models.GetRoleLevel(role)
		}
	}
	return 0
}

// triageFromRisk 根据风险等级给出基线研判建议（自动化工单缺省时填充）。
func triageFromRisk(risk string) (priority, harm, mitigation, retest string) {
	switch strings.ToLower(strings.TrimSpace(risk)) {
	case "high":
		priority = "P0"
		harm = "可被直接利用导致服务器失陷、数据泄露或权限提升，危害极高，需立即处置。"
		mitigation = "修复前通过 WAF/访问控制限制相关入口，必要时下线问题功能，并启用访问审计与告警。"
		retest = "修复后重新发起针对性扫描或 PoC 验证，确认原利用路径不可达，并观察一段时间无异常。"
	case "medium":
		priority = "P1"
		harm = "在特定条件下可被利用，可能造成信息泄露或权限提升，建议优先处理。"
		mitigation = "临时通过输入校验、访问控制或配置加固降低可利用性，避免敏感接口直接暴露。"
		retest = "修复后复测对应请求/页面，确认问题已修复且无绕过。"
	case "low":
		priority = "P2"
		harm = "风险较低但属安全隐患，建议在后续版本中规范修复。"
		mitigation = "按安全开发规范整改，并纳入常态化安全测试。"
		retest = "随版本迭代回归测试确认。"
	default:
		priority, harm, mitigation, retest = "P2", "风险待评估。", "建议人工复核并参考通用加固措施。", "人工复核确认。"
	}
	return
}
