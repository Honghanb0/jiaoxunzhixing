package scanner

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"security-agent/internal/ai"
	"security-agent/internal/config"
	"security-agent/internal/models"
	"security-agent/internal/storage"
)

// 扫描终态之外的运行态
const (
	StatusRunning = "running"
	StatusFailed  = "failed"
	StatusTimeout = "timeout"
	StatusDone    = "completed"
)

// ScanProgress 扫描进度信息
type ScanProgress struct {
	mu             sync.Mutex
	ScanJobID      string    `json:"scan_job_id"`
	Status         string    `json:"status"`
	Phase          string    `json:"phase"` // crawling / detecting / done
	CurrentPage    int       `json:"current_page"`
	TotalPages     int       `json:"total_pages"`
	VulnFound      int       `json:"vuln_found"`
	SensitiveFound int       `json:"sensitive_found"`
	CurrentURL     string    `json:"current_url,omitempty"`
	StartedAt      time.Time `json:"started_at"`
	LastUpdatedAt  time.Time `json:"last_updated_at"`
	Logs           []string  `json:"logs,omitempty"`

	lastPersistAt time.Time // 落库节流（不参与序列化）
}

// snapshot 返回进度快照。
// 注意不能直接 `cp := *p` —— ScanProgress 含 sync.Mutex，拷贝锁值会被 vet 报错，
// 且这样返回的是脱离锁保护的对象，可安全交给 HTTP 层序列化。
func (p *ScanProgress) snapshot() *ScanProgress {
	p.mu.Lock()
	defer p.mu.Unlock()
	return &ScanProgress{
		ScanJobID:      p.ScanJobID,
		Status:         p.Status,
		Phase:          p.Phase,
		CurrentPage:    p.CurrentPage,
		TotalPages:     p.TotalPages,
		VulnFound:      p.VulnFound,
		SensitiveFound: p.SensitiveFound,
		CurrentURL:     p.CurrentURL,
		StartedAt:      p.StartedAt,
		LastUpdatedAt:  p.LastUpdatedAt,
		Logs:           append([]string(nil), p.Logs...),
		lastPersistAt:  p.lastPersistAt,
	}
}

// ScanProgressStore 全局扫描进度存储
var ScanProgressStore = sync.Map{}

type Engine struct {
	cfg           *config.Config
	crawler       *Crawler
	detector      *Detector
	assetScanner  *AssetScanner // 网络资产扫描器（端口/服务/子域名）
	domainRepo    *storage.DomainRepository
	scanJobRepo   *storage.ScanJobRepository
	vulnRepo      *storage.VulnerabilityRepository
	sensitiveRepo *storage.SensitiveInfoRepository
	pageRepo      *storage.PageRepository
	assetRepo     *storage.AssetRepository    // 资产图仓储
	baselineRepo  *storage.BaselineRepository // 巡检基线仓储
	aiModule      *ai.AIModule
	ruleEngine    *RuleEngine // 企业级漏洞规则引擎
	reporter      *Reporter   // 漏洞报告生成器（Markdown/JSON/HTML + 工单集成）

	// 运行中任务的取消函数：scanJobID -> context.CancelFunc
	cancels  sync.Map
	stopCh   chan struct{}
	stopOnce sync.Once
}

// NewEngine 构建扫描引擎。
// aiMgr 为多模型路由中心；传 nil 时按配置自行构建，
// 但推荐由上层（api.NewServer）传入，与 HTTP 层共享同一份连接池与运行时状态。
func NewEngine(cfg *config.Config, store *storage.Neo4jStore, aiMgr *ai.Manager) *Engine {
	domainRepo := storage.NewDomainRepository(store)
	scanJobRepo := storage.NewScanJobRepository(store)
	vulnRepo := storage.NewVulnerabilityRepository(store)
	sensitiveRepo := storage.NewSensitiveInfoRepository(store)
	pageRepo := storage.NewPageRepository(store)
	assetRepo := storage.NewAssetRepository(store)

	crawler := NewCrawler(&cfg.Scanner, domainRepo, pageRepo)
	detector := NewDetector(&cfg.Scanner, &cfg.Sensitive, vulnRepo, sensitiveRepo)
	assetScanner := NewAssetScanner()

	// 初始化企业级规则引擎和报告生成器
	ruleEngine := NewRuleEngine("")
	detector.SetRuleEngine(ruleEngine)
	reporter := NewReporter(ruleEngine)

	if aiMgr == nil {
		aiMgr = ai.NewManager(&cfg.AI)
	}
	aiModule := ai.NewAIModuleWithManager(aiMgr)

	return &Engine{
		cfg:           cfg,
		crawler:       crawler,
		detector:      detector,
		assetScanner:  assetScanner,
		domainRepo:    domainRepo,
		scanJobRepo:   scanJobRepo,
		vulnRepo:      vulnRepo,
		sensitiveRepo: sensitiveRepo,
		pageRepo:      pageRepo,
		assetRepo:     assetRepo,
		baselineRepo:  storage.NewBaselineRepository(store),
		aiModule:      aiModule,
		ruleEngine:    ruleEngine,
		reporter:      reporter,
		stopCh:        make(chan struct{}),
	}
}

// BaselineDiffForScan 计算某次扫描结果相对域名基线的差异。
// 返回 (nil, nil) 表示该域名尚未设置基线——这不是错误，调用方据此提示用户先设基线。
func (e *Engine) BaselineDiffForScan(scanJobID string, domainID string) (*models.BaselineDiff, error) {
	base, err := e.baselineRepo.GetByDomain(domainID)
	if err != nil {
		return nil, err
	}
	if base == nil {
		return nil, nil
	}
	pages, err := e.pageRepo.ListByScanJob(scanJobID)
	if err != nil {
		return nil, err
	}
	vulns, err := e.vulnRepo.ListByScanJob(scanJobID)
	if err != nil {
		return nil, err
	}
	return DiffAgainstBaseline(base, scanJobID, pages, vulns)
}

// SetBaselineFromScan 把某次扫描的结果设为该域名的巡检基线。
func (e *Engine) SetBaselineFromScan(scanJobID string, domainID string, note string) (*models.Baseline, error) {
	pages, err := e.pageRepo.ListByScanJob(scanJobID)
	if err != nil {
		return nil, err
	}
	vulns, err := e.vulnRepo.ListByScanJob(scanJobID)
	if err != nil {
		return nil, err
	}
	if len(pages) == 0 {
		return nil, fmt.Errorf("该次扫描没有抓到任何页面，不适合作为基线（请确认扫描是否成功、目标是否可达）")
	}
	base, err := BuildBaselineSnapshot(domainID, scanJobID, pages, vulns, note)
	if err != nil {
		return nil, err
	}
	if err := e.baselineRepo.Save(base); err != nil {
		return nil, err
	}
	return base, nil
}

// retestTimeout 单次复测的墙钟上限。
// 复测只打一个 URL，正常情况下秒级返回；给 60s 是为了容忍目标站偶发慢响应，
// 同时又不会让"目标站 hang 住"把复测请求无限挂起。
const retestTimeout = 60 * time.Second

// RetestVulnerability 对单条风险执行复测。
//
// 命题要求巡检支持"复测"，并对结果做"验证"。复测的实现思路是：
// 重新抓取该风险对应的 URL → 用同一套检测逻辑重跑 → 看同类型发现是否复现。
//
//	复现  → still_present（风险仍在，Verified=true，代表"已验证的真实风险"）
//	不复现 → fixed（判定已修复）
//	抓不到 → inconclusive（目标不可达，宁可判"无法判定"也不误判为"已修复"）
//
// 复测复用爬虫的 HTTP 客户端与限速器，因此同样受速率约束、只发 GET，保持非破坏性。
func (e *Engine) RetestVulnerability(ctx context.Context, vulnID string) (*models.RetestResult, error) {
	v, err := e.vulnRepo.GetByID(vulnID)
	if err != nil {
		return nil, fmt.Errorf("风险不存在: %w", err)
	}

	res := &models.RetestResult{
		VulnerabilityID: v.ID,
		URL:             v.URL,
		VulnType:        v.Type,
		Status:          models.RetestInconclusive,
		CheckedAt:       time.Now(),
		RetestCount:     v.RetestCount + 1,
	}

	// 没有 URL 的风险（如纯配置类发现）无法自动复测，如实标注而非假装成功
	if strings.TrimSpace(v.URL) == "" {
		res.Message = "该风险未关联具体 URL，无法自动复测，需人工复核"
		_ = e.vulnRepo.UpdateRetest(v.ID, res.Status, false, res.Message, res.CheckedAt)
		return res, nil
	}

	if ctx == nil {
		ctx = context.Background()
	}
	rctx, cancel := context.WithTimeout(ctx, retestTimeout)
	defer cancel()

	rr := e.crawler.FetchOnce(rctx, v.URL)
	if rr == nil || rr.Error != nil {
		res.Message = "目标不可达或请求失败，无法判定是否已修复，需人工复核"
		_ = e.vulnRepo.UpdateRetest(v.ID, res.Status, false, res.Message, res.CheckedAt)
		return res, nil
	}

	page := rr.Page
	res.HTTPStatus = page.StatusCode

	found, _ := e.detector.DetectVulnerabilities(page, v.ScanJobID)
	stillPresent := false
	for _, nv := range found {
		if nv == nil || !strings.EqualFold(nv.Type, v.Type) {
			continue
		}
		// 参数维度也对上才算同一处风险；两侧任一为空视为通配
		if v.Parameter != "" && nv.Parameter != "" && nv.Parameter != v.Parameter {
			continue
		}
		stillPresent = true
		break
	}

	if stillPresent {
		res.Status = models.RetestStillPresent
		res.Verified = true
		res.Message = "复测确认该风险仍然存在，建议按修复建议继续处置"
	} else {
		res.Status = models.RetestFixed
		res.Verified = false
		res.Message = "复测未再检出同类型风险，判定为已修复；如需可再次复测交叉确认"
	}

	if err := e.vulnRepo.UpdateRetest(v.ID, res.Status, res.Verified, res.Message, res.CheckedAt); err != nil {
		log.Printf("[Retest] %s 写入复测结果失败: %v", v.ID, err)
	}
	return res, nil
}

// GenerateReport 为指定扫描任务生成多格式报告（Markdown/JSON/HTML）
func (e *Engine) GenerateReport(scanJobID string, targetURL string) (*ReportBundle, error) {
	results, err := e.GetScanResults(scanJobID)
	if err != nil {
		return nil, fmt.Errorf("获取扫描结果失败: %w", err)
	}
	if e.reporter == nil {
		return nil, fmt.Errorf("报告生成器未初始化")
	}
	return e.reporter.GenerateReport(results.Vulnerabilities, targetURL), nil
}

// GetRuleEngine 获取规则引擎实例（供 API 层暴露规则查询接口）
func (e *Engine) GetRuleEngine() *RuleEngine {
	return e.ruleEngine
}

// maxScanDuration 单次扫描的最长允许时长
func (e *Engine) maxScanDuration() time.Duration {
	if e.cfg != nil && e.cfg.Scanner.MaxScanMinutes > 0 {
		return time.Duration(e.cfg.Scanner.MaxScanMinutes) * time.Minute
	}
	return 2 * time.Hour
}

// staleJobAge 运行多久以上的任务被视为僵死
func (e *Engine) staleJobAge() time.Duration {
	if e.cfg != nil && e.cfg.Scanner.StaleJobMinutes > 0 {
		return time.Duration(e.cfg.Scanner.StaleJobMinutes) * time.Minute
	}
	return 3 * time.Hour
}

// RecoverStaleJobs 回收僵死任务。
// 进程重启后，原先 running 的 goroutine 已不存在，若不处理这些任务会永远停在
// running 状态（前端就会显示"跑了 271 小时还是 0 页"）。
func (e *Engine) RecoverStaleJobs() {
	n, err := e.scanJobRepo.MarkStaleRunning(e.staleJobAge(), StatusTimeout)
	if err != nil {
		log.Printf("[Scan] 回收僵死任务失败: %v", err)
		return
	}
	if n > 0 {
		log.Printf("[Scan] 已回收 %d 个僵死的运行任务（超过 %v 未完成）", n, e.staleJobAge())
	}
}

// StartWatchdog 启动看门狗：定期检查是否有任务超时未结束并强制中止。
func (e *Engine) StartWatchdog() {
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-e.stopCh:
				return
			case <-ticker.C:
				e.checkTimeouts()
			}
		}
	}()
	log.Printf("[Scan] 看门狗已启动（单次扫描上限 %v）", e.maxScanDuration())
}

// Stop 停止后台协程
func (e *Engine) Stop() {
	e.stopOnce.Do(func() { close(e.stopCh) })
}

// checkTimeouts 中止超过最大时长的任务
func (e *Engine) checkTimeouts() {
	limit := e.maxScanDuration()
	e.cancels.Range(func(key, value any) bool {
		jobID, _ := key.(string)
		cancel, ok := value.(context.CancelFunc)
		if !ok {
			return true
		}
		if v, ok := ScanProgressStore.Load(jobID); ok {
			p, ok := v.(*ScanProgress)
			if !ok {
				return true
			}
			p.mu.Lock()
			started := p.StartedAt
			status := p.Status
			p.mu.Unlock()

			if status == StatusRunning && time.Since(started) > limit {
				log.Printf("[Scan] 任务 %s 运行超过 %v，强制中止", jobID, limit)
				cancel()
			}
		}
		return true
	})
}

// CancelScan 中止指定扫描任务
func (e *Engine) CancelScan(scanJobID string) bool {
	if v, ok := e.cancels.Load(scanJobID); ok {
		if cancel, ok := v.(context.CancelFunc); ok {
			log.Printf("[Scan] 收到中止请求: %s", scanJobID)
			cancel()
			return true
		}
	}
	return false
}

func (e *Engine) Scan(domainID string) (*models.ScanJob, error) {
	domain, err := e.domainRepo.GetByID(domainID)
	if err != nil {
		return nil, fmt.Errorf("failed to get domain: %w", err)
	}

	scanJob := &models.ScanJob{
		DomainID:  domainID,
		Status:    "pending",
		StartedAt: time.Now(),
	}

	if err := e.scanJobRepo.Create(scanJob); err != nil {
		return nil, fmt.Errorf("failed to create scan job: %w", err)
	}

	e.scanJobRepo.UpdateStatus(scanJob.ID, StatusRunning)
	scanJob.Status = StatusRunning

	// 初始化扫描进度
	ScanProgressStore.Store(scanJob.ID, &ScanProgress{
		ScanJobID:      scanJob.ID,
		Status:         StatusRunning,
		Phase:          "crawling",
		CurrentPage:    0,
		TotalPages:     domain.MaxPages,
		VulnFound:      0,
		SensitiveFound: 0,
		StartedAt:      time.Now(),
		LastUpdatedAt:  time.Now(),
		Logs:           []string{},
	})

	// 扫描级超时：保证任何情况下任务都会结束，不会无限挂起
	scanCtx, cancel := context.WithTimeout(context.Background(), e.maxScanDuration())
	e.cancels.Store(scanJob.ID, cancel)

	// 绑定爬取进度回调：实时同步爬取阶段的进度
	e.crawler.SetProgressCallback(func(crawled, total int, currentURL string) {
		e.updateProgress(scanJob.ID, StatusRunning, "crawling", crawled, total, 0, currentURL)
	})

	go e.runScan(scanCtx, scanJob, domain)

	return scanJob, nil
}

// runScan 执行扫描主体。
// 任何路径退出时都会清理取消函数；发生 panic 时也会把任务标记为失败，
// 避免任务停留在 running 成为僵尸。
func (e *Engine) runScan(scanCtx context.Context, scanJob *models.ScanJob, domain *models.Domain) {
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("[Scan] %s 内部异常: %v", scanJob.ID, rec)
			e.scanJobRepo.Fail(scanJob.ID, StatusFailed, fmt.Sprintf("内部错误: %v", rec))
			e.updateProgress(scanJob.ID, StatusFailed, "failed", 0, 0, 0, "")
		}
		// 释放取消函数，防止 cancel 泄漏
		if v, ok := e.cancels.Load(scanJob.ID); ok {
			if fn, ok := v.(context.CancelFunc); ok {
				fn()
			}
			e.cancels.Delete(scanJob.ID)
		}
	}()

	e.addLog(scanJob.ID, fmt.Sprintf("Starting scan job %s for domain %s", scanJob.ID, domain.Name))

	startURL := domain.Name
	// CIDR 段或单 IP 不补 scheme；只有主机名/域名形式才补 https://
	if !hasScheme(startURL) && !strings.Contains(startURL, "/") && !isBareIP(startURL) {
		startURL = "https://" + startURL
	}

	// 未显式设置 MaxDepth/MaxPages（值为 0）时回退到配置默认，
	// 避免被当成“硬上限 0”而整站不爬（历史坑：建域名未传这两个字段则爬取 0 页）。
	md := domain.MaxDepth
	if md <= 0 {
		md = e.cfg.Scanner.MaxDepth
	}
	mp := domain.MaxPages
	if mp <= 0 {
		mp = e.cfg.Scanner.MaxPages
	}
	crawlCtx := &CrawlContext{
		Ctx:       scanCtx, // 外部可取消（超时 / 用户中止）
		Domain:    &Domain{ID: domain.ID, Name: domain.Name, MaxDepth: md, MaxPages: mp, Concurrency: e.cfg.Scanner.Concurrency},
		StartURL:  startURL,
		Pages:     make([]*PageInfo, 0),
		PageCount: 0,
	}

	if err := e.crawler.Start(crawlCtx); err != nil {
		log.Printf("Crawl error: %v", err)
		e.addLog(scanJob.ID, fmt.Sprintf("Crawl error: %v", err))
		e.scanJobRepo.UpdateStatus(scanJob.ID, StatusFailed)
		e.updateProgress(scanJob.ID, StatusFailed, "failed", 0, 0, 0, "")
		return
	}

	// 爬取结束后若已被取消（超时/中止），不应继续走检测与报告
	if scanCtx.Err() != nil {
		e.abort(scanJob, crawlCtx, scanCtx.Err())
		return
	}

	e.addLog(scanJob.ID, fmt.Sprintf("Crawled %d pages", len(crawlCtx.Pages)))
	e.updateProgress(scanJob.ID, StatusRunning, "detecting", 0, domain.MaxPages, 0, "Processing crawled pages...")

	vulns := make([]*models.Vulnerability, 0)
	sensitiveInfos := make([]*models.SensitiveInfo, 0)

	for i, page := range crawlCtx.Pages {
		// 每页都检查取消信号，保证中止能及时生效
		if scanCtx.Err() != nil {
			e.abort(scanJob, crawlCtx, scanCtx.Err())
			return
		}

		page.DomainID = domain.ID

		pageModel := &models.Page{
			ID:          page.ID,
			DomainID:    page.DomainID,
			ScanJobID:   scanJob.ID, // 记录批次归属：基线对比与跨次篡改检测都依赖它
			URL:         page.URL,
			Title:       page.Title,
			StatusCode:  page.StatusCode,
			ContentHash: page.ContentHash,
			Depth:       page.Depth,
		}
		e.pageRepo.Create(pageModel)

		pageVulns, _ := e.detector.DetectVulnerabilities(page, scanJob.ID)
		for _, v := range pageVulns {
			v.ScanJobID = scanJob.ID
			v.PageID = page.ID
			v.DomainID = domain.ID
			v.Fingerprint = models.VulnFingerprint(domain.ID, v.Type, v.URL, v.Parameter)
			// 验证标记：只有经过多层信号确认（confidence=high）的发现才标记为"已验证"。
			// 单信号命中的发现保留为待验证，避免把疑似项直接当结论上报；
			// 后续可由复测接口（POST /api/vulnerabilities/:id/retest）确认。
			v.Verified = strings.EqualFold(v.Confidence, "high")
			v.RetestStatus = models.RetestNotRetested
			e.vulnRepo.Create(v)
			vulns = append(vulns, v)
		}

		pageSensitive, _ := e.detector.DetectSensitiveInfo(page, scanJob.ID)
		for _, s := range pageSensitive {
			s.ScanJobID = scanJob.ID
			s.PageID = page.ID
			// 补齐归属域名：敏感信息需能按域名检索（与漏洞一致），否则按域名查询恒为空。
			s.DomainID = domain.ID
			e.sensitiveRepo.Create(s)
			sensitiveInfos = append(sensitiveInfos, s)
		}

		e.updateProgress(scanJob.ID, StatusRunning, "detecting", i+1, len(crawlCtx.Pages), len(vulns), page.URL)
	}

	if len(vulns) > 0 || len(sensitiveInfos) > 0 {
		e.aiModule.AnalyzeResults(vulns, sensitiveInfos)
	}

	e.aiModule.GenerateReport(scanJob, domain, vulns, sensitiveInfos)

	// 聚合统计并落库，便于列表/仪表盘快速展示，无需逐条回表。
	summary := &models.ScanSummary{
		TotalPages:     len(crawlCtx.Pages),
		TotalVulns:     len(vulns),
		SensitiveFound: len(sensitiveInfos),
	}
	for _, v := range vulns {
		switch strings.ToLower(v.Severity) {
		case "high":
			summary.HighSeverity++
		case "medium":
			summary.MediumSeverity++
		case "low":
			summary.LowSeverity++
		}
	}
	if err := e.scanJobRepo.Complete(scanJob.ID, summary); err != nil {
		log.Printf("[Scan] %s 写入完成状态失败: %v", scanJob.ID, err)
	}
	e.updateProgress(scanJob.ID, StatusDone, "done", len(crawlCtx.Pages), len(crawlCtx.Pages), len(vulns), "")
	e.addLog(scanJob.ID, fmt.Sprintf("Scan job %s completed: %d pages, %d vulns (H:%d M:%d L:%d), %d sensitive infos",
		scanJob.ID, summary.TotalPages, summary.TotalVulns,
		summary.HighSeverity, summary.MediumSeverity, summary.LowSeverity, summary.SensitiveFound))

	// 基线对比：若该域名已设置基线，则自动比对本次扫描的漂移并写入扫描日志，
	// 让"站点是否被改动、风险是否新增"在巡检结果里直接可见，无需人工翻两次报告。
	if diff, derr := e.BaselineDiffForScan(scanJob.ID, domain.ID); derr != nil {
		log.Printf("[Baseline] %s 基线对比失败: %v", scanJob.ID, derr)
	} else if diff != nil {
		e.addLog(scanJob.ID, "[基线对比] "+diff.Summary)
		for _, c := range diff.PagesChanged {
			e.addLog(scanJob.ID, fmt.Sprintf("[基线对比] 页面变更: %s", c.URL))
		}
	}
}

// abort 被取消/超时时的统一收尾
func (e *Engine) abort(scanJob *models.ScanJob, crawlCtx *CrawlContext, cause error) {
	reason := fmt.Sprintf("扫描已中止: %v", cause)
	log.Printf("[Scan] %s %s", scanJob.ID, reason)
	e.addLog(scanJob.ID, reason)

	status := StatusFailed
	if cause == context.DeadlineExceeded {
		status = StatusTimeout
	}
	e.scanJobRepo.Fail(scanJob.ID, status, reason)

	pages := 0
	if crawlCtx != nil {
		pages = len(crawlCtx.Pages)
	}
	e.updateProgress(scanJob.ID, status, "aborted", pages, pages, 0, "")
}

func (e *Engine) updateProgress(scanJobID, status, phase string, currentPage, totalPages, vulnFound int, currentURL string) {
	v, ok := ScanProgressStore.Load(scanJobID)
	if !ok {
		return
	}
	p := v.(*ScanProgress)

	p.mu.Lock()
	p.Status = status
	p.Phase = phase
	p.CurrentPage = currentPage
	p.TotalPages = totalPages
	p.VulnFound = vulnFound
	p.CurrentURL = currentURL
	p.LastUpdatedAt = time.Now()
	// 落库节流：至少间隔 3 秒，或进入终态时立即写入
	needPersist := time.Since(p.lastPersistAt) >= 3*time.Second ||
		status == StatusDone || status == StatusFailed || status == StatusTimeout
	if needPersist {
		p.lastPersistAt = time.Now()
	}
	p.mu.Unlock()

	if needPersist {
		// 进度写入数据库，进程重启后仍可读到，而不是一律显示 0
		if err := e.scanJobRepo.UpdateProgress(scanJobID, currentPage, totalPages); err != nil {
			log.Printf("[Scan] %s 写入进度失败: %v", scanJobID, err)
		}
	}
}

func (e *Engine) addLog(scanJobID, message string) {
	v, ok := ScanProgressStore.Load(scanJobID)
	if !ok {
		return
	}
	p := v.(*ScanProgress)

	p.mu.Lock()
	defer p.mu.Unlock()
	p.Logs = append(p.Logs, fmt.Sprintf("[%s] %s", time.Now().Format("15:04:05"), message))
	if len(p.Logs) > 100 {
		p.Logs = p.Logs[len(p.Logs)-100:]
	}
}

// GetScanProgress 获取扫描进度
func (e *Engine) GetScanProgress(scanJobID string) (*ScanProgress, error) {
	if v, ok := ScanProgressStore.Load(scanJobID); ok {
		// 返回快照，避免调用方与扫描协程并发读写同一对象
		return v.(*ScanProgress).snapshot(), nil
	}

	// 无内存进度（如进程已重启）：从数据库读取，尽量还原真实状态，
	// 而不是一律返回 0——否则前端会显示"跑了很久仍是 0 页"。
	job, err := e.scanJobRepo.GetByID(scanJobID)
	if err != nil {
		return nil, err
	}

	status := job.Status
	// 数据库里仍是 running，但本机并没有对应协程 → 判定为中断
	if status == StatusRunning {
		status = StatusFailed
	}

	return &ScanProgress{
		ScanJobID:      scanJobID,
		Status:         status,
		Phase:          "done",
		CurrentPage:    job.CurrentPage,
		TotalPages:     job.TotalPages,
		VulnFound:      job.TotalVulns,
		SensitiveFound: job.SensitiveFound,
		StartedAt:      job.StartedAt,
		LastUpdatedAt:  time.Now(),
	}, nil
}

// GetScanLogs 获取扫描日志
func (e *Engine) GetScanLogs(scanJobID string) ([]string, error) {
	if v, ok := ScanProgressStore.Load(scanJobID); ok {
		p := v.(*ScanProgress)
		p.mu.Lock()
		defer p.mu.Unlock()
		return append([]string(nil), p.Logs...), nil
	}
	return []string{}, nil
}

func (e *Engine) GetScanResults(scanJobID string) (*ScanResults, error) {
	vulns, err := e.vulnRepo.ListByScanJob(scanJobID)
	if err != nil {
		return nil, err
	}

	sensitiveInfos, err := e.sensitiveRepo.ListByScanJob(scanJobID)
	if err != nil {
		return nil, err
	}

	stats, _ := e.vulnRepo.GetStatsByScanJob(scanJobID)
	if stats == nil {
		stats = &models.ScanSummary{}
	}

	// 补充页面数：漏洞统计里不含 total_pages，
	// 而"扫描了多少页"正是用户最关心的指标，从任务记录里取。
	if stats.TotalPages == 0 {
		if job, err := e.scanJobRepo.GetByID(scanJobID); err == nil && job != nil {
			stats.TotalPages = job.TotalPages
		}
	}

	return &ScanResults{
		Vulnerabilities: vulns,
		SensitiveInfos:  sensitiveInfos,
		Summary:         stats,
	}, nil
}

type ScanResults struct {
	Vulnerabilities []*models.Vulnerability `json:"vulnerabilities"`
	SensitiveInfos  []*models.SensitiveInfo `json:"sensitive_infos"`
	Summary         *models.ScanSummary     `json:"summary"`
}

// ScanTimeout 单次扫描允许的最长时长（含看门狗上限），供巡检编排等待扫描结束时设超时。
func (e *Engine) ScanTimeout() time.Duration {
	return e.maxScanDuration()
}

// WaitForScanCompletion 阻塞等待指定扫描任务进入终态（completed/failed/timeout），
// 或直到 timeout 到期。返回扫描结果（即使失败也尽量返回已采集的部分），以及错误。
// 供 AI 巡检在“先扫描后分析”流程中同步等待扫描结束使用。
func (e *Engine) WaitForScanCompletion(jobID string, timeout time.Duration) (*ScanResults, error) {
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		p, err := e.GetScanProgress(jobID)
		if err == nil {
			switch p.Status {
			case StatusDone:
				res, rerr := e.GetScanResults(jobID)
				if rerr != nil {
					return nil, fmt.Errorf("扫描 %s 已完成但读取结果失败: %w", jobID, rerr)
				}
				return res, nil
			case StatusFailed, StatusTimeout:
				// 扫描已失败：仍尝试返回已采集的部分结果
				res, _ := e.GetScanResults(jobID)
				return res, fmt.Errorf("扫描 %s 以 %s 结束", jobID, p.Status)
			}
		}

		if time.Now().After(deadline) {
			return nil, fmt.Errorf("等待扫描 %s 完成超时（%v）", jobID, timeout)
		}

		select {
		case <-ticker.C:
		}
	}
}

// ScanAssets 对指定域名执行网络资产扫描（子域名枚举→DNS→端口扫描→服务识别）
// 扫描结果异步保存到 Neo4j 图谱，返回扫描结果摘要。
func (e *Engine) ScanAssets(ctx context.Context, domainID string) (*AssetScanSummary, error) {
	domain, err := e.domainRepo.GetByID(domainID)
	if err != nil {
		return nil, fmt.Errorf("获取域名失败: %w", err)
	}

	// 提取纯域名/IP（去除 scheme/path/端口）
	target := domain.Name
	target = strings.TrimPrefix(target, "https://")
	target = strings.TrimPrefix(target, "http://")
	if idx := strings.Index(target, "/"); idx > 0 {
		target = target[:idx]
	}
	// 去除端口号（如 127.0.0.1:8099 → 127.0.0.1）
	if idx := strings.LastIndex(target, ":"); idx > 0 && !strings.Contains(target[idx+1:], ".") {
		// 检查冒号后面是否是数字（端口）而不是 IPv6 的一部分
		portPart := target[idx+1:]
		isPort := true
		for _, ch := range portPart {
			if ch < '0' || ch > '9' {
				isPort = false
				break
			}
		}
		if isPort {
			target = target[:idx]
		}
	}

	log.Printf("[Asset] 开始资产扫描: domain=%s id=%s", target, domainID)

	// 使用清理后的目标名创建副本传给扫描器
	scanDomain := &models.Domain{
		ID:   domain.ID,
		Name: target,
	}
	result, err := e.assetScanner.ScanDomain(ctx, scanDomain)
	if err != nil {
		return nil, fmt.Errorf("资产扫描失败: %w", err)
	}

	// 保存到 Neo4j 图谱
	if err := e.assetRepo.SaveAssetScan(domainID, result.Subdomains, result.IPs, result.Ports, result.Services); err != nil {
		log.Printf("[Asset] 保存资产结果部分失败: %v", err)
		// 不返回错误，部分结果仍可用
	}

	summary := &AssetScanSummary{
		DomainID:       domainID,
		DomainName:     target,
		SubdomainCount: len(result.Subdomains),
		IPCount:        len(result.IPs),
		PortCount:      len(result.Ports),
		ServiceCount:   len(result.Services),
		Subdomains:     result.Subdomains,
		IPs:            result.IPs,
		Ports:          result.Ports,
		Services:       result.Services,
	}

	log.Printf("[Asset] 资产扫描完成: %s 子域名=%d IP=%d 端口=%d 服务=%d",
		target, summary.SubdomainCount, summary.IPCount, summary.PortCount, summary.ServiceCount)

	return summary, nil
}

// AssetScanSummary 资产扫描结果摘要
type AssetScanSummary struct {
	DomainID       string              `json:"domain_id"`
	DomainName     string              `json:"domain_name"`
	SubdomainCount int                 `json:"subdomain_count"`
	IPCount        int                 `json:"ip_count"`
	PortCount      int                 `json:"port_count"`
	ServiceCount   int                 `json:"service_count"`
	Subdomains     []*models.Subdomain `json:"subdomains"`
	IPs            []*models.IP        `json:"ips"`
	Ports          []*models.Port      `json:"ports"`
	Services       []*models.Service   `json:"services"`
}

// GetAssetGraph 获取域名的资产拓扑图数据
func (e *Engine) GetAssetGraph(domainID string) (*models.AssetGraph, error) {
	return e.assetRepo.GetAssetGraph(domainID)
}

// ListAssets 列出域名下所有资产明细
func (e *Engine) ListAssets(domainID string) ([]map[string]any, error) {
	return e.assetRepo.ListAssets(domainID)
}

func hasScheme(url string) bool {
	return len(url) > 8 && (url[:7] == "http://" || url[:8] == "https://")
}

// isBareIP 判断是否为纯 IPv4（不做 CIDR，所以不含 '/'）
func isBareIP(s string) bool {
	if strings.Contains(s, "/") {
		return false
	}
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
		for _, ch := range p {
			if ch < '0' || ch > '9' {
				return false
			}
		}
		n := 0
		for _, ch := range p {
			n = n*10 + int(ch-'0')
		}
		if n > 255 {
			return false
		}
	}
	return true
}
