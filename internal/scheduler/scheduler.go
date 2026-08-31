package scheduler

import (
	"log"
	"sync"
	"time"

	"github.com/robfig/cron/v3"
	"security-agent/internal/ai"
	"security-agent/internal/config"
	"security-agent/internal/inspection"
	"security-agent/internal/models"
	"security-agent/internal/scanner"
	"security-agent/internal/storage"
)

// cronParser 支持 5 字段（分 时 日 月 周）与 6 字段（秒 分 时 日 月 周）两种写法。
// SecondOptional 让“秒”字段可选，从而兼容 legacy 的 5 字段配置，
// 同时允许“每月30日 15:24:52”这类需要秒级精度的精准定时。
var cronParser = cron.NewParser(
	cron.SecondOptional | cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow,
)

type Scheduler struct {
	cron       *cron.Cron
	cfg        *config.SchedulerConfig
	store      *storage.Neo4jStore
	domainRepo *storage.DomainRepository
	ruleRepo   *storage.InspectionRuleRepository
	recordRepo *storage.InspectionRecordRepository
	runner     *inspection.Runner
	running    map[string]cron.EntryID
	mu         sync.Mutex
}

// NewSchedulerWithInspection 构建调度器并装配 AI 巡检编排器。
// 注意：调用方（main）应只构建一个实例，Start() 后将其同时注入 HTTP 层，
// 否则界面保存配置只会更新“未启动”的副本 —— 这正是此前 Cron 表达式不生效的根因。
func NewSchedulerWithInspection(
	cfg *config.SchedulerConfig,
	store *storage.Neo4jStore,
	engine *scanner.Engine,
	alertSvc *AlertService,
	aiMgr *ai.Manager,
) *Scheduler {
	domainRepo := storage.NewDomainRepository(store)
	ruleRepo := storage.NewInspectionRuleRepository(store)
	recordRepo := storage.NewInspectionRecordRepository(store)
	scanJobRepo := storage.NewScanJobRepository(store)
	vulnRepo := storage.NewVulnerabilityRepository(store)
	sensRepo := storage.NewSensitiveInfoRepository(store)
	ticketRepo := storage.NewTicketRepository(store)

	runner := inspection.NewRunner(
		engine, aiMgr, ruleRepo, recordRepo, domainRepo,
		scanJobRepo, vulnRepo, sensRepo, ticketRepo, alertSvc, cfg,
	)

	return &Scheduler{
		cron:       cron.New(cron.WithParser(cronParser)),
		cfg:        cfg,
		store:      store,
		domainRepo: domainRepo,
		ruleRepo:   ruleRepo,
		recordRepo: recordRepo,
		runner:     runner,
		running:    make(map[string]cron.EntryID),
	}
}

// ParseSchedule 解析 cron 表达式（兼容 5/6 字段）。
func ParseSchedule(expr string) (cron.Schedule, error) {
	return cronParser.Parse(expr)
}

// NextRuns 计算接下来 n 次执行时间，用于界面预览“下次运行”。
func NextRuns(expr string, n int) ([]time.Time, error) {
	sched, err := ParseSchedule(expr)
	if err != nil {
		return nil, err
	}
	out := make([]time.Time, 0, n)
	t := time.Now()
	for i := 0; i < n; i++ {
		t = sched.Next(t)
		out = append(out, t)
	}
	return out, nil
}

// Start 加载已启用的巡检规则与带 cron 的活跃域名，注册定时任务并启动调度器。
func (s *Scheduler) Start() error {
	if !s.cfg.Enabled {
		log.Println("[Scheduler] 调度器已禁用（scheduler.enabled=false）")
		return nil
	}

	// 0) 先回收上一次进程遗留的僵死巡检记录（running/analyzing），
	//    避免服务重启后这些记录永远停在“运行中/分析中”。
	if s.runner != nil {
		s.runner.RecoverStaleRecords(30 * time.Minute)
	}

	// 1) 巡检规则（InspectionRule）—— AI 巡检（含定时触发）统一走这里，
	//    不再为“域名”单独维护周期扫描任务，避免与 AI 巡检规则功能重复。
	rules, err := s.ruleRepo.ListEnabled()
	if err != nil {
		log.Printf("[Scheduler] 加载巡检规则失败: %v", err)
	} else {
		for _, rule := range rules {
			if err := s.AddRuleTask(rule); err != nil {
				log.Printf("[Scheduler] 注册巡检规则失败(rule=%s): %v", rule.ID, err)
			}
		}
	}

	s.mu.Lock()
	taskCount := len(s.running)
	s.mu.Unlock()

	s.cron.Start()
	log.Printf("[Scheduler] 调度器已启动，已注册 %d 个定时任务", taskCount)
	return nil
}

// Stop 平滑停止调度器。
func (s *Scheduler) Stop() {
	ctx := s.cron.Stop()
	<-ctx.Done()
	log.Println("[Scheduler] 调度器已停止")
}

// AddRuleTask 注册一条巡检规则的 cron 任务。
func (s *Scheduler) AddRuleTask(rule *models.InspectionRule) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if rule.Schedule == "" {
		return nil
	}
	if _, exists := s.running[rule.ID]; exists {
		return nil // 已注册，避免重复
	}
	if _, err := ParseSchedule(rule.Schedule); err != nil {
		return err // 表达式非法：跳过，不阻断其它任务
	}

	entryID, err := s.cron.AddFunc(rule.Schedule, func() {
		s.runner.Run(rule, models.InspectionTriggerSchedule)
	})
	if err != nil {
		return err
	}
	s.running[rule.ID] = entryID

	if next := s.cron.Entry(entryID).Next; !next.IsZero() {
		_ = s.ruleRepo.UpdateRunTimes(rule.ID, nil, &next)
		log.Printf("[Scheduler] 已注册巡检规则 %s(%s) cron=%q 下次运行=%s",
			rule.Name, rule.ID, rule.Schedule, next.Format("2006-01-02 15:04:05"))
	} else {
		log.Printf("[Scheduler] 已注册巡检规则 %s(%s) cron=%q", rule.Name, rule.ID, rule.Schedule)
	}
	return nil
}

// RemoveRuleTask 移除一条巡检规则的 cron 任务。
func (s *Scheduler) RemoveRuleTask(ruleID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if entryID, exists := s.running[ruleID]; exists {
		s.cron.Remove(entryID)
		delete(s.running, ruleID)
		log.Printf("[Scheduler] 已移除巡检规则任务 %s", ruleID)
	}
}

// RemoveDomainTasks 删除域名时统一清理：摘掉引用该域名的巡检规则 cron 任务，
// 避免目标虽已删除、cron 仍周期性触发引用它的规则，对着一个不存在的目标反复巡检。
// （域名自身不再持有独立周期任务，故无需处理域名级 cron。）
func (s *Scheduler) RemoveDomainTasks(domainID string) {
	rules, err := s.ruleRepo.List()
	if err != nil {
		log.Printf("[Scheduler] 清理域名关联规则失败(domain=%s): %v", domainID, err)
		return
	}
	for _, r := range rules {
		if r != nil && r.DomainID == domainID {
			s.RemoveRuleTask(r.ID)
		}
	}
}

// UpdateRuleTask 在规则变更后重建调度任务（启用/暂停/改周期即时生效）。
func (s *Scheduler) UpdateRuleTask(rule *models.InspectionRule) {
	s.RemoveRuleTask(rule.ID)
	if rule.Enabled && rule.Schedule != "" {
		if err := s.AddRuleTask(rule); err != nil {
			log.Printf("[Scheduler] 更新巡检规则任务失败(rule=%s): %v", rule.ID, err)
		}
	}
}

// TriggerManual 手动立即触发一条巡检规则，返回巡检记录 ID。
func (s *Scheduler) TriggerManual(ruleID string) (string, error) {
	rule, err := s.ruleRepo.GetByID(ruleID)
	if err != nil {
		return "", err
	}
	return s.runner.Run(rule, models.InspectionTriggerManual), nil
}

// TriggerManualScan 纯扫描（供“扫描任务”页手动触发，不触发 AI 巡检），返回扫描任务。
// 保留既有的扫描能力，与 AI 巡检互不干扰。
func (s *Scheduler) TriggerManualScan(domainID string) (*models.ScanJob, error) {
	// engine 通过 runner 暴露；这里直接复用 engine 的 Scan。
	return s.runner.Engine().Scan(domainID)
}
