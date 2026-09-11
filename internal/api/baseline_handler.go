package api

import (
	"net/http"
	"sort"

	"github.com/gin-gonic/gin"

	"security-agent/internal/models"
	"security-agent/internal/scanner"
	"security-agent/internal/storage"
)

// BaselineHandler 巡检基线的设置、查询与对比。
//
// 命题要求巡检支持「基线对比」。语义约定：
//   - 基线 = 某域名在「已确认正常」的那次扫描时的状态快照（页面 + 风险）
//   - 之后每次扫描都可与该基线比对，得到新增/消失/变更的站点页面与新增/已修复的风险
//
// 权限上沿用管理侧：设置/删除基线属于会改变巡检判定基准的操作，因此要求 role_level >= 2。
type BaselineHandler struct {
	engine       *scanner.Engine
	baselineRepo *storage.BaselineRepository
	scanJobRepo  *storage.ScanJobRepository
	domainRepo   *storage.DomainRepository
}

func NewBaselineHandler(engine *scanner.Engine, baselineRepo *storage.BaselineRepository,
	scanJobRepo *storage.ScanJobRepository, domainRepo *storage.DomainRepository) *BaselineHandler {
	return &BaselineHandler{
		engine:       engine,
		baselineRepo: baselineRepo,
		scanJobRepo:  scanJobRepo,
		domainRepo:   domainRepo,
	}
}

// SetBaselineRequest 设置基线的请求体。两项都可省略：
// 不传 scan_job_id 时自动取该域名最近一次成功的扫描。
type SetBaselineRequest struct {
	ScanJobID string `json:"scan_job_id"`
	Note      string `json:"note"`
}

// Set 将该域名某次扫描的结果固化为基线（覆盖旧基线）。
func (h *BaselineHandler) Set(c *gin.Context) {
	domainID := c.Param("id")
	if domainID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "缺少域名 id"})
		return
	}

	var req SetBaselineRequest
	_ = c.ShouldBindJSON(&req) // 允许空 body

	scanJobID := req.ScanJobID
	if scanJobID == "" {
		job := h.latestCompletedJob(domainID)
		if job == nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "该域名还没有成功的扫描记录，无法设置基线；请先执行一次扫描"})
			return
		}
		scanJobID = job.ID
	}

	base, err := h.engine.SetBaselineFromScan(scanJobID, domainID, req.Note)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "基线已设置",
		"baseline": gin.H{
			"domain_id":   base.DomainID,
			"scan_job_id": base.ScanJobID,
			"created_at":  base.CreatedAt,
			"note":        base.Note,
			"page_count":  base.PageCount,
			"vuln_count":  base.VulnCount,
		},
	})
}

// Get 查询域名当前基线（不存在时 baseline 为 null）。
func (h *BaselineHandler) Get(c *gin.Context) {
	domainID := c.Param("id")
	base, err := h.baselineRepo.GetByDomain(domainID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "读取基线失败"})
		return
	}
	if base == nil {
		c.JSON(http.StatusOK, gin.H{"baseline": nil, "message": "该域名尚未设置基线"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"baseline": gin.H{
			"domain_id":   base.DomainID,
			"scan_job_id": base.ScanJobID,
			"created_at":  base.CreatedAt,
			"note":        base.Note,
			"page_count":  base.PageCount,
			"vuln_count":  base.VulnCount,
		},
	})
}

// Delete 删除域名基线。
func (h *BaselineHandler) Delete(c *gin.Context) {
	domainID := c.Param("id")
	if err := h.baselineRepo.DeleteByDomain(domainID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "删除基线失败"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "基线已删除"})
}

// Diff 返回「某次扫描」相对基线的差异。
// 不传 scan_job_id 时取最近一次成功的扫描；未设置基线时返回 409，提示先设基线。
func (h *BaselineHandler) Diff(c *gin.Context) {
	domainID := c.Param("id")

	scanJobID := c.Query("scan_job_id")
	if scanJobID == "" {
		job := h.latestCompletedJob(domainID)
		if job == nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "该域名还没有成功的扫描记录"})
			return
		}
		scanJobID = job.ID
	}

	diff, err := h.engine.BaselineDiffForScan(scanJobID, domainID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "基线对比失败: " + err.Error()})
		return
	}
	if diff == nil {
		c.JSON(http.StatusConflict, gin.H{
			"error":       "该域名尚未设置基线，无法对比",
			"hint":        "先调用 POST /api/domains/:id/baseline 以某次扫描结果建立基线",
			"scan_job_id": scanJobID,
		})
		return
	}

	c.JSON(http.StatusOK, diff)
}

// latestCompletedJob 返回该域名最近一次成功的扫描任务；没有则返回 nil。
func (h *BaselineHandler) latestCompletedJob(domainID string) *models.ScanJob {
	jobs, err := h.scanJobRepo.ListByDomain(domainID)
	if err != nil {
		return nil
	}
	var done []*models.ScanJob
	for _, j := range jobs {
		if j != nil && j.Status == scanner.StatusDone {
			done = append(done, j)
		}
	}
	if len(done) == 0 {
		return nil
	}
	// 按创建时间取最新（ListByDomain 未保证顺序，这里显式排序）
	sort.Slice(done, func(i, j int) bool { return done[i].CreatedAt.After(done[j].CreatedAt) })
	return done[0]
}
