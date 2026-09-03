package agent

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"security-agent/internal/ai"
	"security-agent/internal/config"
	"security-agent/internal/scanner"
	"security-agent/internal/scheduler"
	"security-agent/internal/storage"
)

// Manager 管理智能体生命周期：持有工具注册表、运行中的任务与取消函数，
// 对外提供「提交任务 / 查询 / 中止」以及工具清单。任务在独立 goroutine 中由 Agent 驱动，
// 状态同时持久化到 Neo4j，进程重启后仍可回看。
type Manager struct {
	cfg      *config.AgentConfig
	agent    *Agent
	registry *ToolRegistry
	repo     *taskRepo

	mu      sync.Mutex
	tasks   map[string]*Task
	cancels map[string]context.CancelFunc
}

// NewManager 装配智能体：构建依赖集合、注册全部内置工具、初始化任务仓储与执行核心。
// 任一依赖为 nil 时相关的工具会在执行期安全报错（不会在构建期 panic）。
func NewManager(cfg *config.AgentConfig, aiMgr *ai.Manager, store *storage.Neo4jStore, engine *scanner.Engine, sched *scheduler.Scheduler) *Manager {
	deps := Deps{
		Store:       store,
		Engine:      engine,
		Sched:       sched,
		AI:          aiMgr,
		DomainRepo:  storage.NewDomainRepository(store),
		VulnRepo:    storage.NewVulnerabilityRepository(store),
		SensRepo:    storage.NewSensitiveInfoRepository(store),
		RuleRepo:    storage.NewInspectionRuleRepository(store),
		RecordRepo:  storage.NewInspectionRecordRepository(store),
		AlertRepo:   storage.NewAlertRepository(store),
		TicketRepo:  storage.NewTicketRepository(store),
		ScanJobRepo: storage.NewScanJobRepository(store),
		TaskRepo:    newTaskRepo(store),
	}
	reg := NewToolRegistry()
	RegisterBuiltinTools(reg, deps)

	repo := newTaskRepo(store)
	maxTurns := 24
	if cfg != nil && cfg.MaxTurns > 0 {
		maxTurns = cfg.MaxTurns
	}
	return &Manager{
		cfg:      cfg,
		registry: reg,
		repo:     repo,
		agent:    NewAgent(aiMgr, reg, repo, maxTurns),
		tasks:    map[string]*Task{},
		cancels:  map[string]context.CancelFunc{},
	}
}

// Run 提交一个新任务并异步执行，立即返回任务 ID。provider 为空时使用默认模型。
func (m *Manager) Run(goal, provider string) (*Task, error) {
	if strings.TrimSpace(goal) == "" {
		return nil, fmt.Errorf("任务目标(goal)不能为空")
	}
	if m.agent == nil || m.agent.mgr == nil || !m.agent.mgr.Ready() {
		return nil, fmt.Errorf("AI 模型未就绪（未配置可用 API Key），无法运行自主智能体")
	}
	task := &Task{
		ID:        uuid.New().String(),
		Goal:      goal,
		Status:    TaskStatusPending,
		Provider:  provider,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := m.repo.Create(task); err != nil {
		return nil, err
	}

	m.mu.Lock()
	m.tasks[task.ID] = task
	ctx, cancel := context.WithCancel(context.Background())
	m.cancels[task.ID] = cancel
	m.mu.Unlock()

	go m.agent.Run(ctx, task, provider)
	return task, nil
}

// Get 查询任务；运行中的任务返回内存实时快照，已结束的从持久层读取。
func (m *Manager) Get(id string) (*Task, error) {
	m.mu.Lock()
	if t, ok := m.tasks[id]; ok {
		snap := t.Snapshot()
		m.mu.Unlock()
		log.Printf("[Agent][Manager.Get] 命中内存实时快照 id=%s status=%s", id, snap.Status)
		return snap, nil
	}
	m.mu.Unlock()
	log.Printf("[Agent][Manager.Get] 内存无快照，回退 Neo4j 持久层 id=%s", id)
	return m.repo.Get(id)
}

// List 列出近期任务（默认 50 条）。
func (m *Manager) List(limit int) ([]*Task, error) {
	return m.repo.List(limit)
}

// Stop 中止运行中的任务（取消执行上下文并落定 cancelled 状态）。
func (m *Manager) Stop(id string) error {
	m.mu.Lock()
	cancel, ok := m.cancels[id]
	m.mu.Unlock()
	if ok {
		cancel()
	}
	if t, err := m.repo.Get(id); err == nil {
		if t.Status == TaskStatusRunning || t.Status == TaskStatusPending {
			t.Status = TaskStatusCancelled
			t.Error = "用户主动取消"
			_ = m.repo.Update(t)
		}
	}
	return nil
}

// Registry 暴露工具注册表（供 HTTP 层展示工具清单）。
func (m *Manager) Registry() *ToolRegistry { return m.registry }
