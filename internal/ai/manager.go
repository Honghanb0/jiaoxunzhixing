package ai

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"security-agent/internal/config"
)

// Manager 多模型路由中心：
//   - 注册并持有各厂商适配器
//   - 按策略（single / fallback / parallel）分发请求
//   - 统一超时、重试、降级与并行聚合
//
// 并发安全：providers 与路由参数都通过读写锁保护，支持运行时切换默认模型。
type Manager struct {
	mu        sync.RWMutex
	providers map[string]Provider
	order     []string // 降级链/并行时的调用顺序
	defName   string
	strategy  string
	fallback  bool
	timeout   time.Duration
}

// NewManager 依据配置构建路由中心。
// 旧版扁平配置（ai.provider/api_key/model/base_url）会自动兼容为同名供应商。
func NewManager(cfg *config.AIConfig) *Manager {
	m := &Manager{
		providers: make(map[string]Provider),
		order:     make([]string, 0, len(BuiltinOrder)),
		strategy:  StrategySingle,
		fallback:  true,
		timeout:   60 * time.Second,
	}
	if cfg == nil {
		return m
	}

	m.strategy = normalizeStrategy(cfg.Strategy)
	m.fallback = cfg.Fallback
	if cfg.Timeout > 0 {
		m.timeout = time.Duration(cfg.Timeout) * time.Second
	}

	// 按固定顺序注册，保证列表展示与降级链稳定
	for _, name := range BuiltinOrder {
		pc, ok := cfg.Providers[name]
		if !ok {
			continue
		}
		// 未显式关闭即视为启用（默认开）
		enabled := true
		if pc.Enabled != nil {
			enabled = *pc.Enabled
		}

		p, err := NewProvider(name, ProviderOptions{
			Enabled:      enabled,
			APIKey:       pc.APIKey,
			Model:        pc.Model,
			BaseURL:      pc.BaseURL,
			TimeoutSec:   orInt(pc.Timeout, cfg.Timeout),
			MaxRetries:   cfg.MaxRetries,
			RetryBackoff: time.Duration(orInt(cfg.RetryBackoffMs, 500)) * time.Millisecond,
		})
		if err != nil {
			continue
		}
		m.providers[name] = p
		m.order = append(m.order, name)
	}

	// 默认模型：优先 ai.default，其次旧版 ai.provider
	m.defName = strings.ToLower(strings.TrimSpace(cfg.Default))
	if m.defName == "" {
		m.defName = strings.ToLower(strings.TrimSpace(cfg.Provider))
	}
	if _, ok := m.providers[m.defName]; !ok {
		// 回落到第一个可用供应商
		for _, name := range m.order {
			if m.usable(name) {
				m.defName = name
				break
			}
		}
		if m.defName == "" && len(m.order) > 0 {
			m.defName = m.order[0]
		}
	}

	// 用户在配置中指定的降级顺序优先
	if len(cfg.FallbackOrder) > 0 {
		custom := make([]string, 0, len(cfg.FallbackOrder))
		for _, name := range cfg.FallbackOrder {
			n := strings.ToLower(strings.TrimSpace(name))
			if _, ok := m.providers[n]; ok {
				custom = append(custom, n)
			}
		}
		for _, name := range m.order {
			if !contains(custom, name) {
				custom = append(custom, name)
			}
		}
		m.order = custom
	}

	return m
}

// ---------- 元信息 ----------

func (m *Manager) DefaultName() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.defName
}

func (m *Manager) Strategy() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.strategy
}

func (m *Manager) FallbackEnabled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.fallback
}

func (m *Manager) Timeout() time.Duration {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.timeout
}

// Ready 是否存在至少一个真正可用（已启用且有 Key）的模型
func (m *Manager) Ready() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, name := range m.order {
		if m.usableLocked(name) {
			return true
		}
	}
	return false
}

// List 返回全部已注册供应商的运行时信息
func (m *Manager) List() []ProviderInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	infos := make([]ProviderInfo, 0, len(m.order))
	for _, name := range m.order {
		infos = append(infos, m.providers[name].Info())
	}
	return infos
}

// Get 获取指定供应商
func (m *Manager) Get(name string) (Provider, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key := strings.ToLower(strings.TrimSpace(name))
	p, ok := m.providers[key]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrProviderNotFound, name)
	}
	return p, nil
}

// SetDefault 运行时切换默认模型与调用策略（空字符串表示不修改）
func (m *Manager) SetDefault(name, strategy string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if s := strings.TrimSpace(strategy); s != "" {
		m.strategy = normalizeStrategy(s)
	}
	if n := strings.ToLower(strings.TrimSpace(name)); n != "" {
		if _, ok := m.providers[n]; !ok {
			return fmt.Errorf("%w: %s", ErrProviderNotFound, name)
		}
		m.defName = n
	}
	return nil
}

// ---------- 调用入口 ----------

// Chat 按当前策略发起对话。
//
//	single   —— 只用默认模型；开启 fallback 时失败后沿降级链继续
//	fallback —— 依次尝试降级链，返回首个成功结果
//	parallel —— 并行调用全部可用模型，返回首个成功结果（完整结果见 ChatParallel）
func (m *Manager) Chat(ctx context.Context, req *ChatRequest) (*ChatResponse, error) {
	strategy, _ := m.snapshot()
	if strings.EqualFold(strategy, StrategyParallel) {
		results, err := m.ChatParallel(ctx, req)
		if err != nil {
			return nil, err
		}
		for _, r := range results {
			if r.OK {
				return &ChatResponse{
					Provider:  r.Provider,
					Model:     r.Model,
					Content:   r.Content,
					Usage:     r.Usage,
					LatencyMs: r.LatencyMs,
				}, nil
			}
		}
		return nil, fmt.Errorf("%w: %s", ErrAllProvidersFailed, joinErrors(results))
	}
	return m.chatSequential(ctx, req)
}

// ChatWith 指定供应商发起对话，忽略策略
func (m *Manager) ChatWith(ctx context.Context, name string, req *ChatRequest) (*ChatResponse, error) {
	p, err := m.Get(name)
	if err != nil {
		return nil, err
	}
	if !p.Info().Configured {
		return nil, fmt.Errorf("%w: %s 未配置 API Key", ErrProviderNotFound, name)
	}
	return p.Chat(ctx, req)
}

// ChatParallel 并行调用全部可用模型，返回每家的结果（成功与失败都会返回）
func (m *Manager) ChatParallel(ctx context.Context, req *ChatRequest) ([]*ProviderResult, error) {
	targets := m.targets(false)
	if len(targets) == 0 {
		return nil, ErrNoProvider
	}

	results := make([]*ProviderResult, len(targets))
	var wg sync.WaitGroup

	for i, name := range targets {
		wg.Add(1)
		go func(idx int, n string) {
			defer wg.Done()
			// 单个供应商 panic 不应拖垮整体调用
			defer func() {
				if rec := recover(); rec != nil {
					results[idx] = &ProviderResult{
						Provider: n,
						OK:       false,
						Error:    fmt.Sprintf("内部错误: %v", rec),
					}
				}
			}()

			p := m.providers[n]
			start := time.Now()
			resp, err := p.Chat(ctx, req)

			r := &ProviderResult{
				Provider:  n,
				Model:     p.Info().Model,
				LatencyMs: time.Since(start).Milliseconds(),
			}
			if err != nil {
				r.OK = false
				r.Error = err.Error()
			} else {
				r.OK = true
				r.Content = resp.Content
				r.Usage = resp.Usage
				if resp.Model != "" {
					r.Model = resp.Model
				}
				r.LatencyMs = resp.LatencyMs
			}
			results[idx] = r
		}(i, name)
	}

	wg.Wait()
	return results, nil
}

// Stream 指定供应商的流式对话；name 为空时使用默认模型
func (m *Manager) Stream(ctx context.Context, name string, req *ChatRequest) (<-chan StreamChunk, error) {
	if strings.TrimSpace(name) == "" {
		name = m.DefaultName()
	}
	p, err := m.Get(name)
	if err != nil {
		return nil, err
	}
	if !p.Info().Configured {
		return nil, fmt.Errorf("%w: %s 未配置 API Key", ErrProviderNotFound, name)
	}
	return p.ChatStream(ctx, req)
}

// SimpleChat 便捷方法：单条 prompt 进、纯文本出
func (m *Manager) SimpleChat(ctx context.Context, prompt, systemPrompt string) (string, error) {
	resp, err := m.Chat(ctx, NewChatRequest(prompt, systemPrompt))
	if err != nil {
		return "", err
	}
	return resp.Content, nil
}

// ---------- 内部实现 ----------

// chatSequential 沿降级链依次尝试
func (m *Manager) chatSequential(ctx context.Context, req *ChatRequest) (*ChatResponse, error) {
	m.mu.RLock()
	fallback := m.fallback
	candidates := m.resolveOrderLocked()
	providers := m.providers
	m.mu.RUnlock()

	if len(candidates) == 0 {
		return nil, ErrNoProvider
	}

	var errs []string
	attempted := 0
	for _, name := range candidates {
		p, ok := providers[name]
		if !ok || !p.Info().Configured {
			continue
		}
		attempted++

		resp, err := p.Chat(ctx, req)
		if err == nil && resp != nil {
			return resp, nil
		}
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", name, err))
		} else {
			errs = append(errs, fmt.Sprintf("%s: 空响应", name))
		}
		if !fallback {
			break
		}
	}

	if len(errs) > 0 {
		return nil, fmt.Errorf("%w: %s", ErrAllProvidersFailed, strings.Join(errs, " | "))
	}
	if attempted == 0 {
		return nil, ErrNoProvider
	}
	return nil, ErrEmptyResponse
}

// targets 计算实际要调用的供应商列表。
// parallelAll=true 时返回全部可用项；否则返回降级链（默认模型打头）。
func (m *Manager) targets(parallelAll bool) []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make([]string, 0, len(m.order))
	for _, name := range m.order {
		if !m.usableLocked(name) {
			continue
		}
		if !parallelAll && contains(out, name) {
			continue
		}
		out = append(out, name)
	}
	return out
}

// resolveOrderLocked 默认模型排首位，其后按注册/配置顺序
func (m *Manager) resolveOrderLocked() []string {
	out := make([]string, 0, len(m.order))
	if m.defName != "" {
		if _, ok := m.providers[m.defName]; ok {
			out = append(out, m.defName)
		}
	}
	for _, name := range m.order {
		if !contains(out, name) {
			out = append(out, name)
		}
	}
	return out
}

func (m *Manager) usable(name string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.usableLocked(name)
}

// usableLocked 调用方必须已持有锁
func (m *Manager) usableLocked(name string) bool {
	p, ok := m.providers[name]
	if !ok {
		return false
	}
	info := p.Info()
	return info.Enabled && info.Configured
}

func (m *Manager) snapshot() (string, string) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.strategy, m.defName
}

func normalizeStrategy(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case StrategyFallback:
		return StrategyFallback
	case StrategyParallel:
		return StrategyParallel
	default:
		return StrategySingle
	}
}

func contains(list []string, v string) bool {
	for _, item := range list {
		if item == v {
			return true
		}
	}
	return false
}

func joinErrors(results []*ProviderResult) string {
	parts := make([]string, 0, len(results))
	for _, r := range results {
		if r.Error != "" {
			parts = append(parts, fmt.Sprintf("%s: %s", r.Provider, r.Error))
		}
	}
	return strings.Join(parts, " | ")
}
