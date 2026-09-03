package api

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"security-agent/internal/scanner"
)

// AssetHandler 网络资产扫描与图谱接口
type AssetHandler struct {
	engine    *scanner.Engine
	scanLocks sync.Map // domainID -> bool，防止同一域名重复扫描
}

func NewAssetHandler(engine *scanner.Engine) *AssetHandler {
	return &AssetHandler{engine: engine}
}

// ScanAssets 触发资产扫描（异步执行，立即返回）
// POST /api/assets/scan/:domain_id
func (h *AssetHandler) ScanAssets(c *gin.Context) {
	domainID := c.Param("domain_id")
	if domainID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "缺少域名 ID"})
		return
	}

	// 防止同一域名重复扫描
	if _, loaded := h.scanLocks.LoadOrStore(domainID, true); loaded {
		c.JSON(http.StatusConflict, gin.H{"error": "该域名正在扫描中，请稍候"})
		return
	}

	// 异步执行扫描（使用独立 context，避免 HTTP 响应返回后被取消）
	go func() {
		defer h.scanLocks.Delete(domainID)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		_, err := h.engine.ScanAssets(ctx, domainID)
		if err != nil {
			// 错误已在引擎层记录日志
		}
	}()

	c.JSON(http.StatusAccepted, gin.H{
		"message": "资产扫描已启动，请稍后刷新图谱查看结果",
	})
}

// GetAssetGraph 获取域名的资产拓扑图数据（节点 + 边）
// GET /api/assets/graph/:domain_id
func (h *AssetHandler) GetAssetGraph(c *gin.Context) {
	domainID := c.Param("domain_id")
	if domainID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "缺少域名 ID"})
		return
	}

	graph, err := h.engine.GetAssetGraph(domainID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": graph})
}

// ListAssets 列出域名下所有资产明细
// GET /api/assets/list/:domain_id
func (h *AssetHandler) ListAssets(c *gin.Context) {
	domainID := c.Param("domain_id")
	if domainID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "缺少域名 ID"})
		return
	}

	assets, err := h.engine.ListAssets(domainID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": assets})
}
