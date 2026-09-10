// Package agent 实现「自主安全运维智能体」：参考 earendil-works/pi 的双层调用循环，
// 在现有多模型接入层（ai.Manager）之上构建「多轮工具调用 + 自主规划」执行模式。
//
// 设计要点：
//   - 模块划分：Agent（调用循环） / ToolRegistry（工具注册与分发） / Tool（原子能力）
//     / Task（任务状态机，持久化到 Neo4j） / ContextManager（上下文压缩） / Manager（生命周期）。
//   - 调用循环：外层 runLoop 迭代「轮次」，每轮让模型推理；模型以结构化 <tool_calls> 块请求工具，
//     内层 executeToolCalls 依次执行并回写 <tool_result>；模型调用 finish_task 或返回纯文本即终止。
//   - 数据库与平台服务集成：工具分为「只读分析」（Cypher 查询/聚合/各实体列表）与「平台动作」
//     （发起扫描、等待扫描完成、触发巡检、创建工单/告警/巡检规则、更新工单状态），直连本平台 Neo4j 与引擎/调度器。
//   - 错误处理与上下文管理：每个工具调用包 recover，失败时以错误型 tool_result 回写让模型自我纠正；
//     LLM 调用复用 ai.Manager 的降级/重试；达到最大轮次或上下文取消即终止；超预算时压缩历史消息。
package agent

import (
	"sync"
	"time"
)

// 消息角色（与 ai.Message 对齐；工具结果以 user 角色回写，保证跨厂商兼容）
const (
	RoleSystem    = "system"
	RoleUser      = "user"
	RoleAssistant = "assistant"
	RoleTool      = "tool"
)

// 任务状态机
type TaskStatus string

const (
	TaskStatusPending   TaskStatus = "pending"
	TaskStatusRunning   TaskStatus = "running"
	TaskStatusCompleted TaskStatus = "completed"
	TaskStatusFailed    TaskStatus = "failed"
	TaskStatusCancelled TaskStatus = "cancelled"
)

// 单步状态（任务拆解后的子步骤）
type StepStatus string

const (
	StepPending  StepStatus = "pending"
	StepRunning  StepStatus = "running"
	StepDone     StepStatus = "done"
	StepFailed   StepStatus = "failed"
)

// Message 任务对话中的一条消息（角色 + 内容）。
// 工具结果统一以 RoleTool 角色承载，渲染为 <tool_result> 块回写给模型。
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// Step 任务拆解后的一步；既用于状态跟踪，也持久化到 Neo4j(:AgentStep) 供审计回看。
type Step struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"` // 工具名 或 "reasoning"
	Status    StepStatus `json:"status"`
	Detail    string     `json:"detail,omitempty"`
	Result    string     `json:"result,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// Task 一次自主智能体任务的完整状态。并发安全由 mu 保护（Agent 写入、Manager 读取快照）。
type Task struct {
	mu          sync.Mutex `json:"-"`
	ID          string     `json:"id"`
	Goal        string     `json:"goal"`
	Status      TaskStatus `json:"status"`
	Provider    string     `json:"provider,omitempty"`
	Model       string     `json:"model,omitempty"`
	Messages    []Message  `json:"messages,omitempty"`
	Steps       []Step     `json:"steps,omitempty"`
	Result      string     `json:"result,omitempty"`
	Error       string     `json:"error,omitempty"`
	Turns       int        `json:"turns"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	// Contract 是任务目标的「结构化交付契约」：把自然语言目标解析为机器可校验的交付义务
	// （建单类别 / 定时巡检 cron / 目标资产），任务终止时按契约逐项校验，取代关键词硬编码判定。
	Contract *DeliverableContract `json:"contract,omitempty"`
}

// Snapshot 返回任务的安全副本（拷贝切片，避免与写入协程竞争）。
// 调用方无需额外加锁。
func (t *Task) Snapshot() *Task {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.snapshotLocked()
}

func (t *Task) snapshotLocked() *Task {
	cp := &Task{
		ID:          t.ID,
		Goal:        t.Goal,
		Status:      t.Status,
		Provider:    t.Provider,
		Model:       t.Model,
		Messages:    append([]Message(nil), t.Messages...),
		Steps:       append([]Step(nil), t.Steps...),
		Result:      t.Result,
		Error:       t.Error,
		Turns:       t.Turns,
		CreatedAt:   t.CreatedAt,
		UpdatedAt:   t.UpdatedAt,
		CompletedAt: t.CompletedAt,
		// 交付契约在任务启动时由 parseContractIntent 解析一次并写入，之后只读（resolveContract 仅拷贝其字段），
		// 因此快照直接共享指针是安全的；此前遗漏此字段会导致运行中的任务在 GET /tasks/:id 时 contract 恒为 null。
		Contract: t.Contract,
	}
	return cp
}

// appendMessage 在锁内追加一条消息并刷新更新时间。
func (t *Task) appendMessage(role, content string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.Messages = append(t.Messages, Message{Role: role, Content: content})
	t.UpdatedAt = time.Now()
}

// appendStep 在锁内追加一个执行步骤，使内存快照与持久层都持有步骤状态（满足「状态跟踪」）。
func (t *Task) appendStep(s Step) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.Steps = append(t.Steps, s)
	t.UpdatedAt = time.Now()
}

// updateStep 在锁内更新某步骤的状态与结果（与持久层 UpdateStep 同步），保证内存快照准确反映进度。
func (t *Task) updateStep(id string, status StepStatus, result string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for i := range t.Steps {
		if t.Steps[i].ID == id {
			t.Steps[i].Status = status
			if result != "" {
				t.Steps[i].Result = result
			}
			break
		}
	}
	t.UpdatedAt = time.Now()
}

// lastAssistantHasToolCalls 判断最近若干条 assistant 消息是否包含 <tool_calls>。
// 用于「连续两轮纯文本」时主动收尾，避免死循环。
func (t *Task) lastAssistantHasToolCalls() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	count := 0
	for i := len(t.Messages) - 1; i >= 0; i-- {
		if t.Messages[i].Role == RoleAssistant {
			count++
			if containsStr(t.Messages[i].Content, "<tool_calls>") {
				return true
			}
			if count >= 2 {
				return false
			}
		}
	}
	return false
}
