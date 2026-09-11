package api

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"security-agent/internal/scanner"
	"security-agent/internal/storage"
)

// RetestHandler 风险复测接口。
//
// 对应命题"支持…复测"与"对结果去重、验证、分级"两条要求：
// 修复动作做完之后，需要重新确认问题是否真的消失，而不是凭工单状态判断。
type RetestHandler struct {
	engine   *scanner.Engine
	vulnRepo *storage.VulnerabilityRepository
}

func NewRetestHandler(engine *scanner.Engine, vulnRepo *storage.VulnerabilityRepository) *RetestHandler {
	return &RetestHandler{engine: engine, vulnRepo: vulnRepo}
}

// Retest 对指定风险执行一次复测，并返回判定结果。
// 会真实发起一次对目标 URL 的 GET（受扫描限速约束、非破坏性），
// 因此要求调用方已获得该目标的授权。
func (h *RetestHandler) Retest(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "缺少风险 id"})
		return
	}
	if h.engine == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "扫描引擎不可用，无法复测"})
		return
	}

	res, err := h.engine.RetestVulnerability(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, res)
}

// Get 返回单条风险详情（含 verified 与复测进度），供前端展示与报告引用。
func (h *RetestHandler) Get(c *gin.Context) {
	id := c.Param("id")
	v, err := h.vulnRepo.GetByID(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "风险不存在"})
		return
	}
	c.JSON(http.StatusOK, v)
}
