package api

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"security-agent/internal/models"
	"security-agent/internal/scheduler"
	"security-agent/internal/storage"
)

// validateDomainTarget 校验巡检目标是否是合法的域名 / IP / URL。
// 背景：像 "inspection-verify.local" 这种根本不存在的字符串一旦登记，
// 定时任务会周期性地去“巡检”它，每次都扫不到任何页面，只会产出 findings=0 的空记录，
// 自然也不会生成工单。这里从格式与可解析性两道关把它挡在创建之前。
func validateDomainTarget(raw string) (string, error) {
	name := strings.TrimSpace(raw)
	if name == "" {
		return "", errors.New("域名不能为空")
	}
	if strings.ContainsAny(name, " \t\r\n") {
		return "", errors.New("域名不能包含空格")
	}

	host := name
	if strings.Contains(name, "://") {
		u, err := url.Parse(name)
		if err != nil || u.Hostname() == "" {
			return "", errors.New("域名格式不合法，示例：example.com 或 https://example.com")
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return "", errors.New("仅支持 http/https 协议")
		}
		host = u.Hostname()
	} else if strings.Contains(name, "/") {
		// 形如 115.236.69.0/24 的网段无法作为爬取目标
		return "", errors.New("域名格式不合法：请填写单个域名或 IP，暂不支持 CIDR 网段")
	}

	if net.ParseIP(host) == nil && !isHostname(host) {
		return "", errors.New("域名格式不合法，示例：example.com / 127.0.0.1 / https://example.com")
	}

	// 可解析性：解析不了的域名没有巡检意义（IP 与 localhost 例外）
	if net.ParseIP(host) == nil && host != "localhost" {
		if _, err := net.LookupHost(host); err != nil {
			return "", fmt.Errorf("域名 %q 无法解析（DNS 查询失败），请确认目标真实存在", host)
		}
	}
	return name, nil
}

// isHostname 判断是否为合法主机名（允许 localhost 这类无点名称）。
func isHostname(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-'
			if !ok {
				return false
			}
		}
	}
	return true
}

type DomainHandler struct {
	domainRepo  *storage.DomainRepository
	scanJobRepo *storage.ScanJobRepository
	sched       *scheduler.Scheduler
}

func NewDomainHandler(domainRepo *storage.DomainRepository, scanJobRepo *storage.ScanJobRepository, sched *scheduler.Scheduler) *DomainHandler {
	return &DomainHandler{
		domainRepo:  domainRepo,
		scanJobRepo: scanJobRepo,
		sched:       sched,
	}
}

func (h *DomainHandler) List(c *gin.Context) {
	domains, err := h.domainRepo.List()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, domains)
}

func (h *DomainHandler) Create(c *gin.Context) {
	var req CreateDomainRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	name, err := validateDomainTarget(req.Name)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	domain := &models.Domain{
		Name:        name,
		Description: req.Description,
		Status:      "active",
		MaxDepth:    req.MaxDepth,
		MaxPages:    req.MaxPages,
	}

	if err := h.domainRepo.Create(domain); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, domain)
}

func (h *DomainHandler) Get(c *gin.Context) {
	id := c.Param("id")
	domain, err := h.domainRepo.GetByID(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "domain not found"})
		return
	}
	c.JSON(http.StatusOK, domain)
}

func (h *DomainHandler) Update(c *gin.Context) {
	id := c.Param("id")

	var req CreateDomainRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	domain, err := h.domainRepo.GetByID(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "domain not found"})
		return
	}

	name, err := validateDomainTarget(req.Name)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	domain.Name = name
	domain.Description = req.Description
	domain.MaxDepth = req.MaxDepth
	domain.MaxPages = req.MaxPages

	if err := h.domainRepo.Update(domain); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, domain)
}

func (h *DomainHandler) Delete(c *gin.Context) {
	id := c.Param("id")
	if err := h.domainRepo.Delete(id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 同步解绑定时任务（域名周期 + 关联巡检规则）。此前遗漏这一步，
	// 导致域名删除后 cron 仍在触发，对着不存在的目标反复巡检并产出空记录。
	if h.sched != nil {
		h.sched.RemoveDomainTasks(id)
	}

	c.Status(http.StatusNoContent)
}

func (h *DomainHandler) GetScanJobs(c *gin.Context) {
	id := c.Param("id")
	jobs, err := h.scanJobRepo.ListByDomain(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, jobs)
}

type CreateDomainRequest struct {
	Name        string `json:"name" binding:"required"`
	Description string `json:"description"`
	MaxDepth    int    `json:"max_depth"`
	MaxPages    int    `json:"max_pages"`
}
