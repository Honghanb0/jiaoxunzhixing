package agent

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"security-agent/internal/ai"
)

// Agent 是自主智能体的执行核心：以「双层调用循环」驱动模型推理与工具调用。
//
// 外层 runLoop：每轮让模型基于当前上下文推理；若模型以 <tool_calls> 请求工具，
// 内层 executeToolCalls 依次执行并把 <tool_result> 回写上下文；模型调用 finish_task
// 或返回纯文本结论即终止（对应 pi 的 terminate / shouldStopAfterTurn 停止条件）。
// LLM 调用复用 ai.Manager 的降级与重试；轮次上限与上下文压缩防止失控。
type Agent struct {
	mgr      *ai.Manager
	registry *ToolRegistry
	repo     *taskRepo
	ctxMgr   *ContextManager
	maxTurns int
}

func NewAgent(mgr *ai.Manager, registry *ToolRegistry, repo *taskRepo, maxTurns int) *Agent {
	if maxTurns <= 0 {
		maxTurns = 24
	}
	return &Agent{
		mgr:      mgr,
		registry: registry,
		repo:     repo,
		ctxMgr:   NewContextManager(12000),
		maxTurns: maxTurns,
	}
}

// Run 执行任务到终态（completed/failed/cancelled）或达到轮次上限。
// 在整个过程中持续持久化任务与步骤状态，便于外部查询与审计。
func (a *Agent) Run(ctx context.Context, task *Task, provider string) {
	task.mu.Lock()
	task.Status = TaskStatusRunning
	task.mu.Unlock()
	_ = a.repo.Update(task)

	system := a.buildSystemPrompt()

	task.mu.Lock()
	if len(task.Messages) == 0 {
		task.Messages = append(task.Messages, Message{Role: RoleUser, Content: task.Goal})
	}
	task.mu.Unlock()

	for turn := 0; turn < a.maxTurns; turn++ {
		select {
		case <-ctx.Done():
			a.finalize(task, TaskStatusCancelled, "任务被取消（上下文已取消）")
			return
		default:
		}

		// 取压缩后的上下文构造请求
		task.mu.Lock()
		reqMessages := a.ctxMgr.Compact(task.Messages)
		task.mu.Unlock()
		req := a.buildRequest(reqMessages, system, provider)

		resp, err := a.callLLM(ctx, req, provider)
		if err != nil {
			a.finalize(task, TaskStatusFailed, fmt.Sprintf("LLM 调用失败: %v", err))
			return
		}

		content := strings.TrimSpace(resp.Content)
		task.mu.Lock()
		if resp.Model != "" {
			task.Model = resp.Model
		}
		task.Turns = turn + 1
		task.Messages = append(task.Messages, Message{Role: RoleAssistant, Content: content})
		task.mu.Unlock()
		_ = a.repo.Update(task)

		calls, perr := ParseToolCalls(content)
		if perr != nil {
			// 模型返回的内容不是合法工具调用块：记为推理步骤并继续，
			// 若连续两轮纯文本（无工具调用）则视为已给出结论，主动收尾。
			step := &Step{ID: uuid.New().String(), Name: "reasoning", Status: StepDone, Detail: "模型返回内容（非标准工具调用）", Result: truncate(content, 500)}
			task.appendStep(*step)
			_ = a.repo.AppendStep(task.ID, step)
			task.mu.Lock()
			noTC := !task.lastAssistantHasToolCalls()
			task.mu.Unlock()
			if noTC {
				a.finalize(task, TaskStatusCompleted, content)
				return
			}
			continue
		}
		if len(calls) == 0 {
			// 无工具调用、纯文本 -> 作为最终结论
			a.finalize(task, TaskStatusCompleted, content)
			return
		}

		// 内层：依次执行工具并回写结果（错误以 error=true 的 tool_result 让模型自我纠正）
		terminate := false
		finishSummary := ""
		for _, call := range calls {
			step := &Step{ID: uuid.New().String(), Name: call.Name, Status: StepRunning, Detail: truncate(toJSON(call.Arguments), 500)}
			task.appendStep(*step)
			_ = a.repo.AppendStep(task.ID, step)

			result, terr := a.executeTool(ctx, call)
			isErr := terr != nil
			if isErr {
				result = fmt.Sprintf("工具执行异常: %v", terr)
			}
			_ = a.repo.UpdateStep(task.ID, step.ID, StepDone, truncate(result, 2000))
			task.updateStep(step.ID, StepDone, truncate(result, 2000))

			task.mu.Lock()
			task.Messages = append(task.Messages, Message{
				Role:    RoleTool,
				Content: RenderToolResult(ToolResult{CallID: call.CallID, Name: call.Name, Content: result, IsError: isErr}),
			})
			task.mu.Unlock()

			if call.Name == "finish_task" {
				terminate = true
				if s := getString(call.Arguments, "summary"); strings.TrimSpace(s) != "" {
					finishSummary = s
				} else {
					finishSummary = content
				}
			}
		}
		_ = a.repo.Update(task)

		if terminate {
			if finishSummary == "" {
				finishSummary = task.Goal + "（已完成）"
			}
			a.finalize(task, TaskStatusCompleted, finishSummary)
			return
		}
	}

	a.finalize(task, TaskStatusFailed, fmt.Sprintf("达到最大轮次上限 %d，任务未在其内完成", a.maxTurns))
}

// executeTool 分发并执行单个工具调用；捕获工具内部 panic，避免单点失败拖垮整个循环。
func (a *Agent) executeTool(ctx context.Context, call ToolCall) (result string, err error) {
	t, ok := a.registry.Get(call.Name)
	if !ok {
		return "", fmt.Errorf("未知工具: %s", call.Name)
	}
	defer func() {
		if rec := recover(); rec != nil {
			err = fmt.Errorf("工具 %s 内部异常: %v", call.Name, rec)
		}
	}()
	result, err = t.Execute(ctx, call.Arguments)
	return
}

func (a *Agent) callLLM(ctx context.Context, req *ai.ChatRequest, provider string) (*ai.ChatResponse, error) {
	if provider != "" {
		return a.mgr.ChatWith(ctx, provider, req)
	}
	return a.mgr.Chat(ctx, req)
}

// buildRequest 把内部消息转换为 ai.ChatRequest。工具结果（RoleTool）以 user 角色承载，
// 保证在 DeepSeek / Kimi / GLM 等各家均被稳定接受（均兼容 OpenAI 协议）。
func (a *Agent) buildRequest(msgs []Message, system, provider string) *ai.ChatRequest {
	out := make([]ai.Message, 0, len(msgs))
	for _, m := range msgs {
		role := m.Role
		if role == RoleTool {
			role = RoleUser
		}
		out = append(out, ai.Message{Role: role, Content: m.Content})
	}
	return &ai.ChatRequest{
		Messages: out,
		Options:  &ai.ChatOptions{SystemPrompt: system, Model: provider},
	}
}

// finalize 落定任务终态并持久化。
func (a *Agent) finalize(task *Task, status TaskStatus, result string) {
	task.mu.Lock()
	task.Status = status
	if result != "" {
		task.Result = result
	}
	now := time.Now()
	if status == TaskStatusCompleted || status == TaskStatusFailed || status == TaskStatusCancelled {
		task.CompletedAt = &now
	}
	if (status == TaskStatusFailed || status == TaskStatusCancelled) && task.Error == "" {
		task.Error = result
	}
	task.mu.Unlock()
	_ = a.repo.Update(task)
}

// buildSystemPrompt 构造系统提示词：角色、工作准则、工具调用协议、可用工具清单。
func (a *Agent) buildSystemPrompt() string {
	return `你是一名「网站安全运维自主智能体」，运行在交巡智星安全巡检平台中。
你的职责：连接并分析平台 Neo4j 数据库中的安全数据（域名、漏洞、敏感信息、巡检记录、工单、告警），
按需执行平台内复杂多步骤任务（如：发起扫描 → 等待结果 → 研判 → 生成工单/告警/巡检规则），并回写结果。

工作准则：
1. 先理解目标，再制定执行计划（任务拆解），逐步调用工具推进；每完成一步都用工具结果验证。
2. 需要数据时优先用专用列表/统计工具；自定义聚合或跨实体分析可用 query_neo4j（只读）。
3. 需要改变平台状态时，使用平台动作工具（start_scan / wait_scan / run_inspection_rule / create_ticket / update_ticket_status / create_inspection_rule / delete_inspection_rule / send_alert / wait / wait_until / create_domain）。
   - 定时/延时类需求（「25 分 30 秒后扫描」「今晚 20:00 扫一次」）：先用 get_current_time 算出目标时刻，再用 wait_until 等到点，随后 start_scan；若基于规则触发「就扫一次」，触发后用 delete_inspection_rule 清理避免后续重复。
   - 复盘类需求（「把昨天的主要任务重新干一遍」）：先用 list_recent_tasks(hours_back=24) 读取近期任务目标，再逐项重跑。
4. 不要在工具之外臆造数据；所有结论必须基于工具返回。
5. 涉及写操作前，先确认目标实体存在（如先用 get_domain / list_inspection_rules 核实）。
6. 任务完成后必须调用 finish_task 并给出中文结论摘要；若信息不足需要澄清，可先向用户提问。

工具调用协议（重要）：
- 当需要调用工具时，在回复中输出一个 <tool_calls> 围栏块，内容为 JSON 数组，每个元素含 name 与 arguments：
<tool_calls>
[{"name": "get_stats", "arguments": {}}, {"name": "query_neo4j", "arguments": {"cypher": "MATCH (d:Domain) RETURN d.name LIMIT 5"}}]
</tool_calls>
- 可以一次调用多个工具（并行推进同一子目标）。
- 工具执行结果会以 <tool_result name="..." call_id="..." error="false">...</tool_result> 形式回传，请基于结果继续推理或调用下一步工具。
- 若无需工具即可直接回答（或已无法继续），可输出纯文本结论；但更推荐显式调用 finish_task 结束任务。

可用工具：
` + a.registry.Descriptions()
}
