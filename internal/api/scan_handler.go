package api

import (
	"net/http"

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
