package agent

import (
	"context"
	"strconv"
	"strings"
	"testing"

	"security-agent/internal/ai"
	"security-agent/internal/models"
)

// memTicketStore 最小内存工单仓储桩，用于验证「轮询预算将尽时安全阀自动补建工单」。
type memTicketStore struct {
	created []*models.Ticket
}

func (m *memTicketStore) Create(t *models.Ticket) error {
	if t.ID == "" {
		t.ID = "tk-auto-" + strconv.Itoa(len(m.created)+1)
	}
	m.created = append(m.created, t)
	return nil
}
func (m *memTicketStore) List(status, scanJobID string) ([]*models.Ticket, error) {
	if status == "" && scanJobID == "" {
		return m.created, nil
	}
	var out []*models.Ticket
	for _, t := range m.created {
		if status != "" && t.Status != status {
			continue
		}
		if scanJobID != "" && t.ScanJobID != scanJobID {
			continue
		}
		out = append(out, t)
	}
	return out, nil
}
func (m *memTicketStore) FindByFingerprint(fp string) (*models.Ticket, error) { return nil, nil }
func (m *memTicketStore) UpdateStatus(id, status string) error                { return nil }
func (m *memTicketStore) AddNotes(id, notes string) error                     { return nil }

func ticketTypes(ts []*models.Ticket) []string {
	var out []string
	for _, t := range ts {
		out = append(out, t.VulnType)
	}
	return out
}

// newScriptedAgent 构造一个用脚本化 LLM 驱动完整 Run 循环的 Agent（无需真实模型 / Neo4j）。
// llmFn 每次被调用应返回一条 LLM 响应；其他依赖均用最小桩。
func newScriptedAgent(llmFn func(ctx context.Context, req *ai.ChatRequest, provider string) (*ai.ChatResponse, error)) *Agent {
	return &Agent{
		registry: NewToolRegistry(),
		repo:     newFakeTaskRepo(),
		ctxMgr:   NewContextManager(12000),
		deps:     Deps{},
		maxTurns: 10,
		llmFn:    llmFn,
	}
}

// TestRun_PureTextNotInstantlyCompleted 回归 task dc376848：
// 模型首轮仅返回纯文本（无工具调用、无 finish_task），此前循环会在首轮即 finalize(completed)、
// 导致「轮次 0、零步骤却 completed」的假完成。修复后要求「连续两轮纯文本」才收尾，因此首轮
// 纯文本应被继续（记为 reasoning 步骤），直到第二轮纯文本才收尾。
func TestRun_PureTextNotInstantlyCompleted(t *testing.T) {
	const goal = "扫描127.0.0.1:8099靶场的webshell漏洞，只上报这个工单，其他问题全部忽略或者直接判为误报"
	// 脚本化 LLM：始终返回纯文本（模拟模型「先开口思考/预告」的习惯），不输出任何工具调用。
	plain := "我来处理这个任务：进入排他模式——只为 webshell 建单，其他发现忽略或判误报。第一步：查找平台中是否已存在该域名资产。"
	a := newScriptedAgent(func(ctx context.Context, req *ai.ChatRequest, provider string) (*ai.ChatResponse, error) {
		return &ai.ChatResponse{Content: plain}, nil
	})

	task := &Task{
		ID:       "t-loop",
		Goal:     goal,
		Contract: a.parseContractIntent(goal), // 排他模式：ticket_categories=[webshell]
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a.Run(ctx, task, "")

	if task.Status != TaskStatusCompleted {
		t.Fatalf("最终状态=%s, want completed", task.Status)
	}
	// 关键：纯文本路径下至少应有 1 条 reasoning 步骤（修复前首轮即 completed 且 steps=0）。
	if len(task.Steps) < 1 {
		t.Fatalf("纯文本路径下应有 >=1 推理步骤（修复前首轮即 completed 且 0 步骤），实际 steps=%d", len(task.Steps))
	}
	foundReasoning := false
	for _, s := range task.Steps {
		if s.Name == "reasoning" {
			foundReasoning = true
		}
	}
	if !foundReasoning {
		t.Errorf("应记录 reasoning 步骤，实际 steps=%v", task.Steps)
	}
}

// TestRun_PureTextThenToolCallsCompletes 进一步验证：首轮纯文本（不收尾）后，第二轮模型
// 正常输出工具调用并继续推进，最终经 finish_task 真正完成——证明修复不会把「有后续动作的纯文本」
// 误杀，也不会回到旧版的「首轮纯文本即完成」。
func TestRun_PureTextThenToolCallsCompletes(t *testing.T) {
	const goal = "扫描127.0.0.1:8099靶场的webshell漏洞，只上报这个工单，其他问题全部忽略或者直接判为误报"
	plain := "我来处理这个任务：进入排他模式。第一步：查找平台中是否已存在该域名资产。"
	calls := 0
	a := newScriptedAgent(func(ctx context.Context, req *ai.ChatRequest, provider string) (*ai.ChatResponse, error) {
		calls++
		if calls == 1 {
			// 首轮纯文本
			return &ai.ChatResponse{Content: plain}, nil
		}
		// 第二轮起：输出 finish_task（纯 JSON 数组形式，无围栏），让任务正常收尾。
		return &ai.ChatResponse{Content: `[{"name":"finish_task","arguments":{"summary":"已确认靶场无 webshell 落地，未发现需建单项；其余发现按用户要求忽略/判为误报。"}}]`}, nil
	})

	task := &Task{
		ID:       "t-loop2",
		Goal:     goal,
		Contract: a.parseContractIntent(goal),
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a.Run(ctx, task, "")

	if task.Status != TaskStatusCompleted {
		t.Fatalf("最终状态=%s, want completed", task.Status)
	}
	// 必须至少经历过首轮纯文本（reasoning 步骤），证明没有在首轮被误收尾。
	foundReasoning := false
	for _, s := range task.Steps {
		if s.Name == "reasoning" {
			foundReasoning = true
		}
	}
	if !foundReasoning {
		t.Errorf("应至少记录 1 条首轮纯文本 reasoning 步骤，实际 steps=%v", task.Steps)
	}
	if task.Result == "" {
		t.Errorf("完成结果不应为空")
	}
}

// TestRun_BudgetExhaustionAutoCreatesTickets 回归 task 50f1c931：
// 模型陷入反复重扫、从不建单/收尾，此前会在「达到最大轮次上限」失败时零工单结束；
// 修复后，当真实轮询逼近 maxTurns、且确有未满足交付（且有证据）时，平台直接补齐工单并收尾。
func TestRun_BudgetExhaustionAutoCreatesTickets(t *testing.T) {
	const goal = "对127.0.0.1:8099扫描，重点排查弱口令和数据泄露，务必提交相关工单"
	fake := &memTicketStore{}
	a := newScriptedAgent(func(ctx context.Context, req *ai.ChatRequest, provider string) (*ai.ChatResponse, error) {
		// 模型每轮只重扫、从不建单/收尾：复现 50f1c931 的卡死行为。
		return &ai.ChatResponse{Content: `[{"name":"start_scan","arguments":{"domain_id":"d1"}}]`}, nil
	})
	a.maxTurns = 8
	a.deps.TicketRepo = fake
	// 平台状态：目标 d1 确有数据泄露（敏感文件）。
	a.deps.VulnLister = func(domainID string, limit int) (string, error) {
		return `{"rows":[{"type":"sensitive_file","name":".env","url":"http://127.0.0.1:8099/.env"}]}`, nil
	}
	// 预置一条弱口令命中会话证据，使 catWeakPassword 也进入未满足集合。
	task := &Task{
		ID:    "t-budget",
		Goal:  goal,
		Steps: []Step{mkStep("weak_password_scan", "done", `{"found_count":2}`)},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a.Run(ctx, task, "")

	if task.Status != TaskStatusCompleted {
		t.Fatalf("最终状态=%s, want completed（不应以‘达到最大轮次上限’失败）", task.Status)
	}
	if strings.Contains(task.Result, "达到最大轮次上限") {
		t.Errorf("任务不应以‘达到最大轮次上限’失败；result=%s", task.Result)
	}
	has := map[string]bool{}
	for _, tk := range fake.created {
		has[tk.VulnType] = true
	}
	if !has["weak_password"] {
		t.Errorf("安全阀应自动补建弱口令工单；已建=%v", ticketTypes(fake.created))
	}
	if !has["sensitive_file"] {
		t.Errorf("安全阀应自动补建数据泄露工单；已建=%v", ticketTypes(fake.created))
	}
}

// TestAutoCreateMissingTickets_RespectsNarrowing 回归 task a51e01af：
// 用户要求「重点排查弱口令和数据泄露…其他漏洞可忽略」，契约收窄为 [weak_password, data_leak]。
// 但扫描中若存在无法识别类型的漏洞（经 vulnTypeToCategory 兜底为 catOther），findingCategories 会包含 catOther。
// 修复前 autoCreateMissingTickets 遍历全部 findingCategories、无视契约收窄，会多补建一张「未知类型」工单，
// 违背用户「其他漏洞可忽略」的明确要求。修复后：仅点名类别才由平台自动补建。
func TestAutoCreateMissingTickets_RespectsNarrowing(t *testing.T) {
	a := newTestAgent()
	fake := &memTicketStore{}
	a.deps.TicketRepo = fake
	// 目标 d1 确有：数据泄露（sensitive_file）+ 一个无法识别的漏洞类型（兜底为 catOther）。
	a.deps.VulnLister = func(domainID string, limit int) (string, error) {
		return `{"rows":[{"type":"sensitive_file","name":".env"},{"type":"weird_unmapped_type","name":"x"}]}`, nil
	}
	goal := "对127.0.0.1:8099扫描，重点排查弱口令和数据泄露，务必提交相关工单，其他漏洞可忽略"
	task := &Task{
		ID:       "t-narrow",
		Goal:     goal,
		Contract: a.parseContractIntent(goal), // TicketCategories=[weak_password, data_leak]
		Steps:    []Step{mkStep("start_scan", "done", `{"domain_id":"d1"}`)},
	}
	a.autoCreateMissingTickets(task)

	has := map[string]bool{}
	for _, tk := range fake.created {
		has[tk.VulnType] = true
	}
	if !has["sensitive_file"] {
		t.Errorf("收窄契约下应为 data_leak 补建工单；已建=%v", ticketTypes(fake.created))
	}
	if has["unknown"] {
		t.Errorf("收窄契约下（『其他漏洞可忽略』）不应为未点名的未知类型补建工单；已建=%v", ticketTypes(fake.created))
	}
}
