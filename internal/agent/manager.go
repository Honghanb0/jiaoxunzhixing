package agent

import (
	"context"
	"fmt"
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
	// 注入列表查询函数（缺省回退到 Neo4j 查询）；便于单测替换为内存桩数据。
	deps.VulnLister = func(did string, limit int) (string, error) { return deps.listVulnerabilities(did, "", limit) }
	deps.SensLister = func(did string, limit int) (string, error) { return deps.listSensitiveInfo(did, limit) }
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
		agent:    NewAgent(aiMgr, reg, repo, deps, maxTurns),
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
		// 注意：此处前端会按秒级轮询（3s/次），绝不能无条件打日志——
		// 高频日志会淹没日志通道/管道，曾导致 stdout 被采集时写满阻塞、
		// 进而使所有调用 log 的 HTTP 处理器挂死（任务详情接口 15s 超时）。
		return snap, nil
	}
	m.mu.Unlock()
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
