package api

import (
	"log"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"security-agent/internal/agent"
)

// AgentHandler 暴露自主智能体的 HTTP 接口：
//   - 提交任务（run）、查询任务列表/详情、中止任务、查看工具清单
//
// 权限：需登录且 role_level >= 1（操作员），因为智能体会对平台执行扫描/建单等动作。
type AgentHandler struct {
	mgr *agent.Manager
}

func NewAgentHandler(mgr *agent.Manager) *AgentHandler {
	return &AgentHandler{mgr: mgr}
}

type agentRunRequest struct {
	Goal     string `json:"goal" binding:"required"`
	Provider string `json:"provider,omitempty"` // 可选：指定模型供应商
}

// Run 提交一个新的自主任务。立即返回任务 ID，实际执行异步进行。
// POST /api/agent/run
func (h *AgentHandler) Run(c *gin.Context) {
	if h.mgr == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "智能体未启用"})
		return
	}
	var req agentRunRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	task, err := h.mgr.Run(req.Goal, req.Provider)
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusAccepted, gin.H{
		"task_id": task.ID,
		"status":  task.Status,
		"message": "任务已提交，可轮询 /api/agent/tasks/:id 查看进度与结果",
	})
}

// ListTasks 列出近期任务。
// GET /api/agent/tasks
func (h *AgentHandler) ListTasks(c *gin.Context) {
	if h.mgr == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "智能体未启用"})
		return
	}
	limit := 50
	if v := c.Query("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	tasks, err := h.mgr.List(limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if tasks == nil {
		tasks = []*agent.Task{}
	}
	c.JSON(http.StatusOK, tasks)
}

// GetTask 查询单个任务（含执行步骤与对话上下文）。
// GET /api/agent/tasks/:id
func (h *AgentHandler) GetTask(c *gin.Context) {
	if h.mgr == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "智能体未启用"})
		return
	}
	task, err := h.mgr.Get(c.Param("id"))
	if err != nil {
		// 记录真实底层错误，便于定位 404 根因（原实现直接返回 404 会掩盖 DB/查询异常）
		log.Printf("[API][Agent] GetTask 未找到任务 id=%s err=%v", c.Param("id"), err)
		c.JSON(http.StatusNotFound, gin.H{"error": "task not found"})
		return
	}
	c.JSON(http.StatusOK, task)
}

// StopTask 中止运行中的任务。
// POST /api/agent/tasks/:id/stop
func (h *AgentHandler) StopTask(c *gin.Context) {
	if h.mgr == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "智能体未启用"})
		return
	}
	if err := h.mgr.Stop(c.Param("id")); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "已发送中止信号"})
}

// ListTools 列出智能体可用工具（名称/描述/入参 Schema）。
// GET /api/agent/tools
func (h *AgentHandler) ListTools(c *gin.Context) {
	if h.mgr == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "智能体未启用"})
		return
	}
	tools := make([]gin.H, 0)
	for _, t := range h.mgr.Registry().All() {
		tools = append(tools, gin.H{
			"name":        t.Name(),
			"description": t.Description(),
			"schema":      t.Schema(),
		})
	}
	c.JSON(http.StatusOK, gin.H{"tools": tools})
}
