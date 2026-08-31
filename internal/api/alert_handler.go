package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"security-agent/internal/models"
	"security-agent/internal/storage"
)

type AlertHandler struct {
	alertRepo *storage.AlertRepository
}

func NewAlertHandler(alertRepo *storage.AlertRepository) *AlertHandler {
	return &AlertHandler{alertRepo: alertRepo}
}

func (h *AlertHandler) List(c *gin.Context) {
	alerts, err := h.alertRepo.List(50, 0)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	// 空列表必须序列化为 [] 而不是 null：
	// 前端 fetchAPI 在“请求失败”时同样返回 null，若后端也返回 null，
	// 就无法区分「无数据」与「加载失败」，空页面会被误判为故障（或反之）。
	if alerts == nil {
		alerts = []*models.Alert{}
	}
	c.JSON(http.StatusOK, alerts)
}

func (h *AlertHandler) Get(c *gin.Context) {
	id := c.Param("id")
	alert, err := h.alertRepo.GetByID(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if alert == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "alert not found"})
		return
	}
	c.JSON(http.StatusOK, alert)
}

func (h *AlertHandler) UpdateStatus(c *gin.Context) {
	id := c.Param("id")

	var req UpdateAlertStatusRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.alertRepo.UpdateStatus(id, req.Status); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	alert, _ := h.alertRepo.GetByID(id)
	c.JSON(http.StatusOK, alert)
}

func (h *AlertHandler) Verify(c *gin.Context) {
	id := c.Param("id")
	c.JSON(http.StatusOK, gin.H{
		"alert_id": id,
		"status":   "verified",
		"message":  "Alert verified",
	})
}

func (h *AlertHandler) GetStats(c *gin.Context) {
	counts, err := h.alertRepo.CountByStatus()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	total := 0
	for _, v := range counts {
		total += v
	}

	c.JSON(http.StatusOK, gin.H{
		"total":     total,
		"by_status": counts,
	})
}

type UpdateAlertStatusRequest struct {
	Status string `json:"status" binding:"required"`
}
