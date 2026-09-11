package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"security-agent/internal/ai"
	"security-agent/internal/models"
	"security-agent/internal/scheduler"
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
	repo     taskRepository // 任务状态持久化接口（便于单测替换为内存实现）
	ctxMgr   *ContextManager
	deps     Deps
	maxTurns int
	// llmFn 是可注入的 LLM 调用桩，仅供单测使用；为 nil 时回退到真实的 a.mgr.Chat。
	llmFn func(ctx context.Context, req *ai.ChatRequest, provider string) (*ai.ChatResponse, error)
}

// taskRepository 是 Agent 持久化任务状态所需的最小接口。将具体 *taskRepo 抽象为接口，
// 使 enforceDeliverables 等逻辑可在单测中用内存桩替代 Neo4j，无需真实数据库。
type taskRepository interface {
	Create(t *Task) error
	Update(t *Task) error
	AppendStep(taskID string, step *Step) error
	UpdateStep(taskID, stepID string, status StepStatus, result string) error
	Get(id string) (*Task, error)
	List(limit int) ([]*Task, error)
}

func NewAgent(mgr *ai.Manager, registry *ToolRegistry, repo taskRepository, deps Deps, maxTurns int) *Agent {
	if maxTurns <= 0 {
		maxTurns = 24
	}
	return &Agent{
		mgr:      mgr,
		registry: registry,
		repo:     repo,
		ctxMgr:   NewContextManager(12000),
		deps:     deps,
		maxTurns: maxTurns,
	}
}

// Run 执行任务到终态（completed/failed/cancelled）或达到轮次上限。
// 在整个过程中持续持久化任务与步骤状态，便于外部查询与审计。
// taskHardTimeout 是单个自主任务的硬墙钟上限，防止 LLM 供应商调用在无 deadline 的
// HTTP 客户端下永久挂起，导致任务永远停在 running 并拖垮整个服务进程（此前 d7a7fdcb
// 任务因 glm 429 / deepseek·kimi deadline exceeded 卡在 running 2.5h，使 /tasks/:id
// 路由全部超时）。任何超过该上限的运行都会被强制以 cancelled 终态结束。
const taskHardTimeout = 30 * time.Minute

func (a *Agent) Run(ctx context.Context, task *Task, provider string) {
	// 套一层硬超时上下文：即便外部 ctx 无 deadline、LLM 客户端也无超时，单次运行也必须在上限内结束。
	runCtx, cancel := context.WithTimeout(ctx, taskHardTimeout)
	defer cancel()
	// 外部 ctx 取消时一并取消本运行。
	go func() {
		select {
		case <-ctx.Done():
			cancel()
		case <-runCtx.Done():
		}
	}()

	task.mu.Lock()
	task.Status = TaskStatusRunning
	task.mu.Unlock()
	_ = a.repo.Update(task)

	system := a.buildSystemPrompt()

	task.mu.Lock()
	if len(task.Messages) == 0 {
		task.Messages = append(task.Messages, Message{Role: RoleUser, Content: task.Goal})
	}
	// 解析「交付契约」：把自然语言目标转为结构化义务，写入 task.Contract。
	// 后续终止校验与假完成对账均基于契约做机器校验，彻底移除关键词硬编码判定。
	task.Contract = a.parseContractIntent(task.Goal)
	task.mu.Unlock()

	// genuineRounds 是「实际轮询次数」（即真正调用 LLM 的轮次），作为 maxTurns 的上限；
	// 交付校验未通过而退回模型补齐的「nudge 轮」不计入此数（缺陷2：否则反复校验会快速耗尽
	// 轮询预算、在安全阀触发前就以「达到最大轮次」截断，导致任务完结却零工单、零新规则）。
	genuineRounds := 0
	// stepsWithoutDelivery 累计「连续没有任何交付动作（建单/建规则/收尾）」的轮数，
	// 用于交付停滞干预，避免模型反复只读探索直到轮次耗尽。
	stepsWithoutDelivery := 0
	// callCounts 统计本运行每个「工具名 + 入参」签名的执行次数，
	// warnedDuplicates 记录已提示过的签名，避免重复打扰模型。
	callCounts := map[string]int{}
	warnedDuplicates := map[string]bool{}
	// consecutiveNoToolRounds 统计「连续多少轮模型未输出任何工具调用（仅纯文本）」。
	// 仅当连续两轮纯文本时才视为模型已给出结论并收尾；首轮纯文本通常只是模型在
	// 「思考 / 预告下一步」，不应直接收尾（此前首轮纯文本即 finalize，导致任务刚开口就被
	// 误判为 completed，见 task dc376848：轮次 0、零步骤却 completed）。
	consecutiveNoToolRounds := 0
	// iterations 是总迭代硬上限（安全阀中的安全阀）：循环内存在多条 continue 路径
	// （parse_error 纠正、纯推理文本、nudge 等）不会推进 genuineRounds，若只以 genuineRounds
	// 为界，模型持续输出「纯文本 + 无工具调用」时循环将永不终止（此前仅靠 30min 硬超时兜底）。
	// 该上限保证任何情况下都能退出，且远大于真实轮询预算，不影响正常任务。
	iterations := 0
	maxIterations := a.maxTurns*3 + 10
	for genuineRounds < a.maxTurns && iterations < maxIterations {
		iterations++
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

		resp, err := a.callLLM(runCtx, req, provider)
		if err != nil {
			a.finalize(task, TaskStatusFailed, fmt.Sprintf("LLM 调用失败: %v", err))
			return
		}

		content := strings.TrimSpace(resp.Content)
		task.mu.Lock()
		if resp.Model != "" {
			task.Model = resp.Model
		}
		task.Messages = append(task.Messages, Message{Role: RoleAssistant, Content: content})
		task.mu.Unlock()
		_ = a.repo.Update(task)

		calls, perr := ParseToolCalls(content)
		if perr != nil {
			// 模型试图输出 <tool_calls> 但 JSON 解析失败：把错误回写为纠正信号，
			// 让模型重新输出合法的工具调用数组，而不是直接当成「已给出结论」收尾——
			// 否则会丢失模型本打算执行的工具调用，导致建单/定时巡检等硬性交付被漏掉、任务被误判为完成。
			if containsStr(content, "<tool_calls>") {
				task.mu.Lock()
				task.Messages = append(task.Messages, Message{
					Role: RoleUser,
					Content: RenderToolResult(ToolResult{
						CallID:  "parse_error",
						Name:    "system",
						Content: fmt.Sprintf("你输出的 <tool_calls> 块 JSON 解析失败：%v。请修正后重新输出一个合法的 JSON 数组（注意字符串引号转义、不要有尾随逗号、数组元素用逗号分隔）。", perr),
						IsError: true,
					}),
				})
				task.mu.Unlock()
				step := &Step{ID: uuid.New().String(), Name: "parse_error", Status: StepDone, Detail: "工具调用 JSON 解析失败，已退回模型纠正", Result: truncate(perr.Error(), 500)}
				task.appendStep(*step)
				_ = a.repo.AppendStep(task.ID, step)
				continue
			}
			// 纯推理文本（不含 <tool_calls> 块）：记为推理步骤并继续。
			// 注意：首轮纯文本通常只是模型在「思考 / 预告下一步」，不应直接收尾——
			// 只有「连续两轮」纯文本（模型确实不再打算调用工具）才视为已给出结论，
			// 此时再做硬性交付校验并收尾。此前在首轮纯文本即 finalize，导致模型刚开口就被
			// 误判为已完成（task dc376848：轮次 0、零步骤却 completed）。
			step := &Step{ID: uuid.New().String(), Name: "reasoning", Status: StepDone, Detail: "模型返回内容（非标准工具调用）", Result: truncate(content, 500)}
			task.appendStep(*step)
			_ = a.repo.AppendStep(task.ID, step)
			consecutiveNoToolRounds++
			if consecutiveNoToolRounds >= 2 {
				// 收尾前硬性交付校验：未满足则退回补齐（不计入实际轮询次数）。
				switch a.enforceDeliverables(task) {
				case enforceNudged:
					continue
				case enforceSafetyValveFired:
					return
				}
				a.finalize(task, TaskStatusCompleted, content)
				return
			}
			continue
		}
		if len(calls) == 0 {
			// 无工具调用、纯文本：记为推理步骤。首轮纯文本只是模型在「思考 / 预告下一步」，
			// 不直接收尾；连续两轮纯文本才视为已给出结论，再做硬性交付校验后收尾。
			step := &Step{ID: uuid.New().String(), Name: "reasoning", Status: StepDone, Detail: "模型返回内容（非标准工具调用）", Result: truncate(content, 500)}
			task.appendStep(*step)
			_ = a.repo.AppendStep(task.ID, step)
			consecutiveNoToolRounds++
			if consecutiveNoToolRounds >= 2 {
				switch a.enforceDeliverables(task) {
				case enforceNudged:
					continue
				case enforceSafetyValveFired:
					return
				}
				a.finalize(task, TaskStatusCompleted, content)
				return
			}
			continue
		}

		// 内层：依次执行工具并回写结果（错误以 error=true 的 tool_result 让模型自我纠正）
		terminate := false
		finishSummary := ""
		// 本轮确有工具调用：重置「连续纯文本」计数，避免上一轮纯文本误累计触发收尾。
		consecutiveNoToolRounds = 0
		for _, call := range calls {
			step := &Step{ID: uuid.New().String(), Name: call.Name, Status: StepRunning, Detail: truncate(toJSON(call.Arguments), 500)}
			task.appendStep(*step)
			_ = a.repo.AppendStep(task.ID, step)

			result, terr := a.executeTool(runCtx, call)
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

			callCounts[callSignature(call)]++

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

		// 交付停滞干预：模型可能长时间反复调用只读工具（如反复 list_domains / start_scan）
		// 却从不尝试 create_ticket / create_inspection_rule / finish_task。
		// 此时每轮 assistant 消息都带 <tool_calls>，现有的「纯文本收尾」分支永不触发，
		// 交付校验（nudge / 安全阀）一次都跑不到，任务最终只会以「达到最大轮次上限」失败
		// （任务 7755460c：34 步里 start_scan 跑了 5 次，工单始终未建）。
		// 这里在确有交付证据时主动提示，把模型推向真正需要的交付动作。
		// 缺陷 D 修复：nudge 轮通过 continue 跳过 genuineRounds++，不再计入实际轮询次数——
		// 否则 nudge 本身会消耗轮次，使模型更快逼近 maxTurns，反而提前触发强制补齐。
		if a.maybeNudgeDeliverableProgress(task, stepsWithoutDelivery) {
			stepsWithoutDelivery = 0
			continue // nudge 轮不计入真实轮询次数
		}

		// 重复调用干预：同一「工具名 + 入参」被反复执行（任务 7755460c 中 start_scan 同参跑了 5 次），
		// 模型已陷入无效循环。此项与上面不同：即便确无交付证据也须打断——
		// 否则模型会一直重复到轮次耗尽，任务以「达到最大轮次上限」失败。
		a.maybeNudgeRepeatedCalls(task, callCounts, warnedDuplicates)

		if terminate {
			// 预算逼近上限兜底（统一判据）：
			// 当真实轮询已逼近上限、且用户硬性交付（建单/建规则）仍未落地、并且确有交付证据时，
			// 直接由平台补齐并收尾——不再依赖「模型主动纯文本/主动 finish_task」来触发 enforceDeliverables 安全阀。
			// 统一判据：unmet 非空 + 确有证据/需规则 + 预算将尽。
			// 与主工具路径（缺陷 C 修复）保持一致，避免 finish_task 分支过于宽松导致在交付已满足时
			// 仍跑一遍 autoCreateMissing*（多余动作且语义上把"已满足"当成"需兜底"）。
			if genuineRounds >= a.maxTurns-1 {
				contract := a.resolveContract(task)
				if contract.NeedsTicket || contract.NeedsRule {
					steps := a.snapshotSteps(task)
					if len(a.findingCategories(steps, contract.TargetDomains)) > 0 || contract.NeedsRule {
						if len(a.unmetDeliverables(task)) > 0 {
							a.forceDeliverAndFinalize(task)
							return
						}
					}
				}
			}
			// 收尾前硬性交付校验：用户显式要求的建单 / 定时巡检若尚未落地，退回模型补齐（不计入实际轮询次数）。
			switch a.enforceDeliverables(task) {
			case enforceNudged:
				continue
			case enforceSafetyValveFired:
				return
			}
			// 假完成对账：模型在 finish_task 摘要中声称的交付须与实际步骤一致。
			// 发现「假完成」（声称已建单/建规则，但步骤无对应成功记录且义务确未满足）直接打回重做。
			contract := a.resolveContract(task)
			steps := a.snapshotSteps(task)
			if bad, msg := a.reconcileFinishClaim(contract, finishSummary, steps); bad {
				task.mu.Lock()
				task.Messages = append(task.Messages, Message{
					Role:    RoleUser,
					Content: RenderToolResult(ToolResult{CallID: "deliverable_check", Name: "system", Content: msg, IsError: true}),
				})
				task.mu.Unlock()
				step := &Step{ID: uuid.New().String(), Name: "deliverable_check", Status: StepDone,
					Detail: "完成前假完成对账未通过", Result: truncate(msg, 500)}
				task.appendStep(*step)
				_ = a.repo.AppendStep(task.ID, step)
				continue
			}
			if finishSummary == "" {
				finishSummary = task.Goal + "（已完成）"
			}
			a.finalize(task, TaskStatusCompleted, finishSummary)
			return
		}

		// 预算兜底安全阀（任务 50f1c931 修复核心）：
		// 当真实轮询已逼近上限、且用户硬性交付（建单/建规则）仍未落地、并且确有交付证据时，
		// 直接由平台补齐并收尾——不再依赖「模型主动纯文本/主动 finish_task」来触发 enforceDeliverables 安全阀，
		// 否则模型一旦陷入反复重扫/只读探索（从不建单/收尾），genuineRounds 会被耗尽，
		// 任务以「达到最大轮次上限」失败、而用户硬性要求被静默丢弃。
		// 仅在确有未满足交付且有证据时触发；若模型本就在最后一轮正常补齐（unmet 已空），则不抢跑、放行正常收尾。
		if genuineRounds >= a.maxTurns-1 {
			contract := a.resolveContract(task)
			if contract.NeedsTicket || contract.NeedsRule {
				steps := a.snapshotSteps(task)
				if len(a.findingCategories(steps, contract.TargetDomains)) > 0 || contract.NeedsRule {
					if len(a.unmetDeliverables(task)) > 0 {
						a.forceDeliverAndFinalize(task)
						return
					}
				}
			}
		}

		// 本轮未发生任何交付动作（建单 / 建规则 / 收尾），累计停滞轮数。
		if a.hadDeliveryAction(task) {
			stepsWithoutDelivery = 0
		} else {
			stepsWithoutDelivery++
		}

		// 本轮模型确实推进了工作（产生了工具调用 / 文本），计入一次实际轮询。
		// nudge 轮通过上面的 continue 跳过此处，不计入。
		genuineRounds++
		task.Turns = genuineRounds
		_ = a.repo.Update(task)
	}
	if iterations >= maxIterations {
		a.finalize(task, TaskStatusFailed, fmt.Sprintf("迭代次数达到硬上限 %d（实际轮询 %d 次），任务未正常收敛", maxIterations, genuineRounds))
		return
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
	if a.llmFn != nil {
		return a.llmFn(ctx, req, provider)
	}
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

// ticketableVulnTypes 已废弃：任何非空（可归类）的漏洞类型都需建单，判定统一走 isTicketableVulnType。
// 保留空定义仅为兼容既有引用；新代码请勿再使用。
var ticketableVulnTypes = map[string]bool{}

// unmetDeliverables 基于「交付契约」机器校验硬性交付是否已落地，彻底取代原先散落各处、基于
// 目标串关键词硬编码的判定逻辑：
//   - 本运行已成功调用对应工具；或
//   - 平台中已存在覆盖同一资产、归属本运行扫描作业的既有交付（幂等，避免重复建单 / 重复建规则）；或
//   - 交付义务真空满足（例如确无任何弱口令 / 数据泄露发现，则无需建单）。
//
// 契约由 parseContractIntent 在任务启动时解析并写入 task.Contract；此处只读契约字段，不重新扫描目标串。
// 返回尚未满足的交付项描述（空表示均已满足）。
func (a *Agent) unmetDeliverables(task *Task) []string {
	contract := a.resolveContract(task)
	steps := a.snapshotSteps(task)

	var missing []string
	if contract.NeedsTicket && !a.ticketDeliverableSatisfied(contract, steps, contract.TargetDomains, contract.TargetHost) {
		missing = append(missing, "create_ticket（目标要求提交工单/建单，但当前既未成功建单，平台中也无覆盖该资产本运行扫描作业的工单，且确实发现了需建单的弱口令/数据泄露）")
	}
	if contract.NeedsRule && !a.ruleDeliverableSatisfied(contract, steps, contract.TargetDomains) {
		missing = append(missing, "create_inspection_rule（目标要求定时/每天/日常巡检，但当前未成功创建巡检规则，且平台中也不存在已覆盖该资产、cron 一致的启用规则）")
	}
	return missing
}

// enforceDeliverableResult 区分 enforceDeliverables 的三种结果，使调用方（Run 循环 / finish 路径）
// 能正确决定是否消耗「实际轮询次数」：
//   - Nudged：已退回模型补齐（追加 deliverable_check 消息与步骤），调用方应 continue 且不计入实际轮询轮次；
//   - Satisfied：交付已满足，可正常收尾；
//   - SafetyValveFired：安全阀已强制收尾（finalize 已调用），调用方应直接 return。
type enforceDeliverableResult int

const (
	enforceNudged enforceDeliverableResult = iota
	enforceSatisfied
	enforceSafetyValveFired
)

// enforceDeliverables 收尾前的硬性交付校验：未满足则退回模型补齐；若已多次校验仍无法补齐
// （模型不配合，或确无可交付内容但判定存在分歧），安全阀强制收尾并明确标注未满足项，避免无限循环 / 触达轮次上限。
// 关键修正：nudge 轮（交付校验未通过、退回模型补齐）不再计入「实际轮询次数」（task.Turns），
// 否则模型在补齐建单/建规则前的反复校验会快速耗尽轮询预算、在未达安全阀前就被 maxTurns 截断，
// 导致「任务完结却零工单、零新规则」。只有真正调用 LLM 的轮次（扫描、工具执行、结论）才计入 task.Turns。
func (a *Agent) enforceDeliverables(task *Task) enforceDeliverableResult {
	missing := a.unmetDeliverables(task)
	if len(missing) == 0 {
		return enforceSatisfied
	}
	if a.deliverableNudgeCount(task) >= 5 {
		// 安全阀前兜底：模型多次未补齐硬性交付、但目标资产确有需交付的发现/要求时，
		// 由平台直接补建工单与巡检规则，避免「用户硬性要求」被静默丢弃（此前反复出现：
		// 模型始终不调用 create_ticket / create_inspection_rule，安全阀直接收尾，任务虽 completed 却零工单、零新规则）。
		a.autoCreateMissingTickets(task)
		a.autoCreateMissingRules(task)
		if len(a.unmetDeliverables(task)) == 0 {
			return enforceSatisfied
		}
		a.finalize(task, TaskStatusCompleted,
			"任务已收尾，但以下用户硬性交付在多次校验后仍未能自动补齐（建议人工跟进）：\n- "+strings.Join(missing, "\n- "))
		return enforceSafetyValveFired
	}
	a.nudgeUnmetDeliverables(task, missing)
	return enforceNudged
}

// deliveryWaitRounds 是「允许模型连续多少轮不做任何交付动作」的阈值；
// 超过后若确有交付证据，则主动提示模型转向交付（见 maybeNudgeDeliverableProgress）。
const deliveryWaitRounds = 3

// deliveryToolNames 是被视为「交付动作」的工具名。
var deliveryToolNames = []string{"create_ticket", "create_inspection_rule", "finish_task"}

// hadDeliveryAction 判断最近若干步骤中是否出现过交付动作（建单 / 建规则 / 收尾）。
// 只看尾部若干步：同一轮可能连续调用多个工具（如 create_ticket 后再 list_tickets），
// 因此不能用「最后一步」判断。
func (a *Agent) hadDeliveryAction(task *Task) bool {
	return hasAnyStep(a.recentSteps(task, 4), deliveryToolNames...)
}

// recentSteps 在锁内取任务步骤的尾部 n 条。
func (a *Agent) recentSteps(task *Task, n int) []Step {
	task.mu.Lock()
	defer task.mu.Unlock()
	if n <= 0 || len(task.Steps) == 0 {
		return nil
	}
	if len(task.Steps) < n {
		n = len(task.Steps)
	}
	out := make([]Step, n)
	copy(out, task.Steps[len(task.Steps)-n:])
	return out
}

// hasAnyStep 判断给定步骤中是否存在指定名称的步骤。
func hasAnyStep(steps []Step, names ...string) bool {
	for _, s := range steps {
		for _, n := range names {
			if s.Name == n {
				return true
			}
		}
	}
	return false
}

// maybeNudgeDeliverableProgress 交付停滞干预：
// 当模型连续多轮反复调用只读/探索类工具（如反复 list_domains / start_scan），
// 既没有 create_ticket / create_inspection_rule，也不 finish_task 时，交付校验
// （nudge / 安全阀）永远不会被执行——因为每一轮 assistant 消息都带 <tool_calls>，
// 「纯文本收尾」分支不触发。任务于是只会因「达到最大轮次上限」失败，工单始终未建。
// 这里在确有交付证据的前提下主动提示，把模型推向真正的交付动作。
// 返回 true 表示已发出提示（调用方应重置停滞计数）。
func (a *Agent) maybeNudgeDeliverableProgress(task *Task, stepsWithoutDelivery int) bool {
	if stepsWithoutDelivery < deliveryWaitRounds {
		return false
	}
	contract := a.resolveContract(task)
	if !contract.NeedsTicket && !contract.NeedsRule {
		return false
	}
	steps := a.snapshotSteps(task)
	// 已有任何交付动作（含尝试）则不再提示，避免干扰模型的正常推进
	if hasAnyStep(steps, deliveryToolNames...) {
		return false
	}
	// 无证据时不提示：此时模型可能仍在收集信息，强行要求建单会造成误报
	if len(a.findingCategories(steps, contract.TargetDomains)) == 0 && !contract.NeedsRule {
		return false
	}
	msg := "你已经连续多轮只做查询/扫描，尚未执行任何交付动作。"
	if contract.NeedsTicket {
		msg += "目标明确要求提交工单：请立即对本次发现的漏洞调用 create_ticket 建单（同一目标同类问题合并为一张），不要再重复扫描或查询。"
	}
	if contract.NeedsRule {
		msg += "目标明确要求定时巡检：请立即调用 create_inspection_rule 配置 cron。"
	}
	msg += "完成交付后再调用 finish_task 给出中文结论；不要再重复调用只读工具。"
	task.mu.Lock()
	task.Messages = append(task.Messages, Message{
		Role:    RoleUser,
		Content: RenderToolResult(ToolResult{CallID: "deliverable_progress", Name: "system", Content: msg, IsError: true}),
	})
	task.mu.Unlock()
	step := &Step{ID: uuid.New().String(), Name: "deliverable_progress", Status: StepDone,
		Detail: "交付停滞干预：多轮未执行交付动作", Result: truncate(msg, 500)}
	task.appendStep(*step)
	_ = a.repo.AppendStep(task.ID, step)
	return true
}

// duplicateCallThreshold 同一「工具名 + 入参」签名重复执行达到该次数即判定为无效重复循环。
const duplicateCallThreshold = 3

// callSignature 生成工具调用签名：工具名 + 规范化入参 JSON。
// 入参以 map 序列化，Go 的 encoding/json 对 map 按键排序，因此同参调用签名稳定。
func callSignature(call ToolCall) string {
	return call.Name + "|" + toJSON(call.Arguments)
}

// maybeNudgeRepeatedCalls 重复调用干预：
// 模型可能用完全相同的入参反复调用同一工具（任务 7755460c：start_scan 同参执行 5 次，
// 期间穿插 list_vulnerabilities / list_domains，34 步后撞上 24 轮上限失败）。
// 这类调用返回值不会变化，纯属无效消耗。与「交付停滞干预」不同，这里即便确无交付证据
// 也必须打断，否则模型会一直重复到轮次耗尽。
// counts 为签名计数，warned 记录已提示过的签名（每个签名只提示一次）。
// 返回 true 表示已发出提示。
func (a *Agent) maybeNudgeRepeatedCalls(task *Task, counts map[string]int, warned map[string]bool) bool {
	for sig, n := range counts {
		if n < duplicateCallThreshold || warned[sig] {
			continue
		}
		warned[sig] = true
		name := sig
		if i := strings.Index(sig, "|"); i >= 0 {
			name = sig[:i]
		}
		msg := fmt.Sprintf(
			"你已用完全相同的入参重复调用 `%s` %d 次，返回值不会有任何变化，继续重复无法推进任务。\n"+
				"请立即改变策略：\n"+
				"1. 若已获得足够信息 —— 执行交付动作（create_ticket / create_inspection_rule）或调用 finish_task 给出中文结论；\n"+
				"2. 若信息仍不足 —— 换用不同入参或其他工具（如 query_neo4j 直接查库核实）。\n"+
				"不要再以相同入参调用 %s。", name, n, name)
		task.mu.Lock()
		task.Messages = append(task.Messages, Message{
			Role:    RoleUser,
			Content: RenderToolResult(ToolResult{CallID: "duplicate_call", Name: "system", Content: msg, IsError: true}),
		})
		task.mu.Unlock()
		step := &Step{ID: uuid.New().String(), Name: "duplicate_call", Status: StepDone,
			Detail: fmt.Sprintf("重复调用干预：%s 同参执行 %d 次", name, n), Result: truncate(msg, 500)}
		task.appendStep(*step)
		_ = a.repo.AppendStep(task.ID, step)
		return true
	}
	return false
}

// resolveTargetDomains 计算兜底建单 / 建规则所需的目标域名集合：
// 优先用契约中由步骤反查出的 TargetDomains；为空时回退到步骤里解析 domain_id / scan_job_id；
// 仍为空且存在目标 host 时，再回退到按 host 反查 DomainRepo（如 127.0.0.1:8099 -> 归属域名），
// 保证「扫完后建工单 / 建周期巡检规则」在仅知 host、步骤未带 domain_id 时也能正确关联资产，
// 不至于因 TargetDomains 为空而静默跳过（此前 autoCreateMissingRules 在 TargetDomains 为空时直接 return，导致 14:40 规则未建立）。
func (a *Agent) resolveTargetDomains(task *Task, steps []Step) []string {
	contract := a.resolveContract(task)
	if len(contract.TargetDomains) > 0 {
		return contract.TargetDomains
	}
	if ids := a.extractTargetDomainIDs(steps); len(ids) > 0 {
		return ids
	}
	if a.deps.DomainRepo != nil {
		host := contract.TargetHost
		if host == "" {
			host = a.extractTargetHost(task.Goal)
		}
		if host != "" {
			if dom, err := a.deps.DomainRepo.GetByHost(host); err == nil && dom.ID != "" {
				return []string{dom.ID}
			}
		}
	}
	return nil
}

// autoCreateMissingTickets 安全阀兜底建单：针对目标资产确有发现、但本运行未成功建单的语义类别
// （弱口令 / 数据泄露），由平台直接补建工单。判定「未建单」只看本运行步骤是否已有成功的
// create_ticket（见 runCreatedTicketForCategory），不依赖平台既有工单，从而不会因历史工单
// 被误判为「已满足」而漏建——每一次确有发现的运行都应留下自己的工单。
func (a *Agent) autoCreateMissingTickets(task *Task) {
	task.mu.Lock()
	steps := make([]Step, len(task.Steps))
	copy(steps, task.Steps)
	goal := task.Goal
	task.mu.Unlock()

	if a.deps.TicketRepo == nil {
		log.Printf("[Agent][autoCreateMissingTickets] 缺 TicketRepo，无法补建工单")
		return
	}

	contract := a.resolveContract(task)
	targetDomains := a.resolveTargetDomains(task, steps)
	targetHost := a.extractTargetHost(goal)
	cats := a.findingCategories(steps, targetDomains)
	for cat := range cats {
		// 收窄：仅当用户点名要求提交该类工单时才由平台自动补建，与 ticketDeliverableSatisfied 的
		// 收窄口径保持一致。否则「其他漏洞可忽略 / 收窄建单」目标下，平台仍会为未点名类别
		// （如 catOther/未知类型——由扫描中无法识别的漏洞类型经 vulnTypeToCategory 兜底而来）补建工单，
		// 违背用户「其他漏洞可忽略」的明确要求（任务 a51e01af 因此被多补建了一张「未归类/未知类型」工单）。
		// 仅当契约显式点名了类别集合（非空）时才做此收窄；空集合表示「全部类别都要建单」，保持原行为。
		if contract.NeedsTicket && len(contract.TicketCategories) > 0 && !sliceContains(contract.TicketCategories, cat) {
			continue
		}
		if a.runCreatedTicketForCategory(steps, targetHost, cat) {
			continue
		}
		ticket := a.buildFallbackTicket(task, cat, steps, targetDomains, targetHost)
		if ticket == nil {
			continue
		}
		if err := a.deps.TicketRepo.Create(ticket); err != nil {
			log.Printf("[Agent][autoCreateMissingTickets] 类别=%s 补建工单失败: %v", cat, err)
			continue
		}
		// 记入步骤，便于审计与后续覆盖判定
		detail := truncate(toJSON(map[string]any{
			"title":      ticket.Title,
			"risk_level": ticket.RiskLevel,
			"asset_url":  ticket.AssetURL,
			"vuln_type":  ticket.VulnType,
		}), 500)
		step := &Step{ID: uuid.New().String(), Name: "create_ticket", Status: StepDone,
			Detail: detail, Result: "平台自动补建工单（模型未调用 create_ticket）：" + ticket.Title}
		task.appendStep(*step)
		_ = a.repo.AppendStep(task.ID, step)
	}
}

// autoCreateMissingRules 安全阀兜底建规则：用户要求定时/每天/日常巡检，但本运行未成功创建巡检规则时，
// 由平台直接补建一条覆盖目标资产的 cron 周期规则。判定「未建规则」先看本运行步骤是否已有成功的
// create_inspection_rule（见 doneTool），再检查平台既有规则是否覆盖该资产且 cron 一致；都不满足才补建。
// 这样即使在多次 nudge 后模型仍不调用 create_inspection_rule，安全阀也能保证用户的周期巡检要求被落地，
// 不会因「任务完结却零新规则」而需要人工补救。
func (a *Agent) autoCreateMissingRules(task *Task) {
	contract := a.resolveContract(task)
	targetDomains := a.resolveTargetDomains(task, a.snapshotSteps(task))
	if len(targetDomains) == 0 {
		log.Printf("[Agent][autoCreateMissingRules] 无目标域名（host/步骤均未提供），跳过补建巡检规则")
		return
	}
	// 已满足（本运行已建，或平台已有覆盖该资产、cron 一致的启用规则）→ 无需补建
	if a.ruleDeliverableSatisfied(contract, nil, targetDomains) {
		return
	}
	if a.deps.RuleRepo == nil || a.deps.Sched == nil {
		log.Printf("[Agent][autoCreateMissingRules] 缺 RuleRepo/Sched，无法补建巡检规则")
		return
	}

	// 定时时刻取自交付契约（由 parseContractIntent 解析目标串得到），默认每天 16:00
	schedule := contract.Schedule
	if schedule == "" {
		schedule = "0 16 * * *"
	}
	if _, err := scheduler.ParseSchedule(schedule); err != nil {
		log.Printf("[Agent][autoCreateMissingRules] cron 表达式非法 schedule=%s err=%v，回退默认", schedule, err)
		schedule = "0 16 * * *"
	}

	host := contract.TargetHost
	name := fmt.Sprintf("%s 每日巡检规则（安全阀补建）", host)
	if host == "" {
		name = "目标资产每日巡检规则（安全阀补建）"
	}
	rule := &models.InspectionRule{
		Name:              name,
		DomainID:          targetDomains[0],
		DomainIDs:         targetDomains,
		Enabled:           true,
		Schedule:          schedule,
		SeverityThreshold: "medium",
		RunScan:           true,
		AlertOnFailure:    false,
	}
	if err := a.deps.RuleRepo.Create(rule); err != nil {
		log.Printf("[Agent][autoCreateMissingRules] 补建巡检规则失败: %v", err)
		return
	}
	if err := a.deps.Sched.AddRuleTask(rule); err != nil {
		// 规则已落库，仅注册调度任务失败（如 cron 边界），记录但不阻断
		log.Printf("[Agent][autoCreateMissingRules] 规则已落库但注册调度任务失败 rule_id=%s err=%v", rule.ID, err)
	} else {
		log.Printf("[Agent][autoCreateMissingRules] 已补建巡检规则 rule_id=%s schedule=%s domain=%s", rule.ID, schedule, targetDomains[0])
	}
	detail := truncate(toJSON(map[string]any{
		"rule_id":  rule.ID,
		"schedule": schedule,
		"domain":   targetDomains[0],
	}), 500)
	step := &Step{ID: uuid.New().String(), Name: "create_inspection_rule", Status: StepDone,
		Detail: detail, Result: "平台自动补建巡检规则（模型未调用 create_inspection_rule）：" + rule.Name}
	task.appendStep(*step)
	_ = a.repo.AppendStep(task.ID, step)
}

// forceDeliverAndFinalize 预算逼近上限时的兜底收尾：由平台直接补齐用户硬性交付（建单/建规则）后收尾，
// 避免任务以「达到最大轮次上限」失败、导致用户硬性要求被静默丢弃（任务 50f1c931：模型反复重扫、
// 从不建单/收尾，24 轮耗尽却零工单——安全阀因模型既不纯文本也不 finish_task 而从未被触发）。
// 与 enforceDeliverables 的区别：本函数不依赖「模型先纯文本/先 finish_task」即可在轮询预算将尽时强制交付，
// 且只作一次补齐+收尾（不退回模型多轮 nudge），保证任务一定收敛。
func (a *Agent) forceDeliverAndFinalize(task *Task) {
	a.autoCreateMissingTickets(task)
	a.autoCreateMissingRules(task)
	if missing := a.unmetDeliverables(task); len(missing) == 0 {
		a.finalize(task, TaskStatusCompleted, "已逼近轮询上限，平台已代您补齐尚未完成的硬性交付（建单/建规则）。如仍有遗漏建议人工跟进。")
	} else {
		a.finalize(task, TaskStatusCompleted, "已逼近轮询上限，平台已尽力补齐交付；以下项仍未能自动补齐（建议人工跟进）：\n- "+strings.Join(missing, "\n- "))
	}
}

// runCreatedTicketForCategory 判断本运行是否已经为该类别成功建单（只看步骤，不查平台既有工单）。
func (a *Agent) runCreatedTicketForCategory(steps []Step, targetHost, category string) bool {
	for _, s := range steps {
		if s.Name == "create_ticket" && s.Status == StepDone && !strings.HasPrefix(s.Result, "工具执行异常") {
			if a.createTicketStepCovers(s, nil, targetHost, category) {
				return true
			}
		}
	}
	return false
}

// buildFallbackTicket 构造一条兜底工单（按语义类别填充标题/描述/证据/危害/优先级）。
func (a *Agent) buildFallbackTicket(task *Task, cat string, steps []Step, targetDomains []string, targetHost string) *models.Ticket {
	now := time.Now()
	scanJobID := extractScanJobIDFromSteps(steps)
	ticket := &models.Ticket{
		Status:    models.TicketStatusPending,
		Type:      "investigation",
		CreatorID: "agent",
		Notes:     "由自主智能体安全阀自动补建（模型未调用 create_ticket）",
		ScanJobID: scanJobID,
		CreatedAt: now,
		UpdatedAt: now,
	}
	switch cat {
	case catWeakPassword:
		ticket.Title = "弱口令风险（HTTP 基础认证/弱口令探测命中）"
		ticket.VulnType = "weak_password"
		ticket.RiskLevel = "high"
		ticket.AssetName = targetHost
		ticket.AssetURL = targetHost
		ticket.Description = a.describeWeakPassword(steps)
		ticket.HarmDescription = "弱口令/默认口令可被暴力破解或直接使用，导致未授权访问与敏感数据泄露，危害极高，需立即处置。"
		ticket.RemediationPriority = "P0"
	case catDataLeak:
		ticket.Title = "数据泄露风险（敏感文件/信息暴露）"
		ticket.VulnType = "sensitive_file"
		ticket.RiskLevel = "high"
		ticket.AssetName = targetHost
		ticket.AssetURL = targetHost
		ticket.Description = a.describeDataLeak(targetDomains)
		ticket.HarmDescription = "源码/备份/密钥/配置文件等敏感文件可直接访问，可能导致凭据泄露、源代码外泄与进一步渗透。"
		ticket.RemediationPriority = "P0"
	case catInjection:
		ticket.Title = "注入类漏洞（SQL/命令/SSTI/XXE 等）"
		ticket.VulnType = "injection"
		ticket.RiskLevel = "high"
		ticket.AssetName = targetHost
		ticket.AssetURL = targetHost
		ticket.Description = a.describeCategoryFindings(targetDomains, catInjection, scanJobID)
		ticket.HarmDescription = "注入类漏洞可被攻击者构造恶意输入执行非预期命令或读取/篡改数据，危害极高。"
		ticket.RemediationPriority = "P0"
	case catAuthConfig:
		ticket.Title = "权限与配置错误（越权/认证缺陷/配置不当/SSRF）"
		ticket.VulnType = "auth_config"
		ticket.RiskLevel = "high"
		ticket.AssetName = targetHost
		ticket.AssetURL = targetHost
		ticket.Description = a.describeCategoryFindings(targetDomains, catAuthConfig, scanJobID)
		ticket.HarmDescription = "权限与配置缺陷可导致未授权访问、权限提升或服务被滥用，需结合具体发现评估影响面。"
		ticket.RemediationPriority = "P1"
	case catComponent:
		ticket.Title = "依赖组件漏洞（已知漏洞组件）"
		ticket.VulnType = "vulnerable_component"
		ticket.RiskLevel = "medium"
		ticket.AssetName = targetHost
		ticket.AssetURL = targetHost
		ticket.Description = a.describeCategoryFindings(targetDomains, catComponent, scanJobID)
		ticket.HarmDescription = "第三方组件已知漏洞可被利用进行远程代码执行或敏感信息获取，需及时升级到安全版本。"
		ticket.RemediationPriority = "P1"
	case catLogic:
		ticket.Title = "逻辑缺陷（业务逻辑/文件上传/反序列化等）"
		ticket.VulnType = "logic"
		ticket.RiskLevel = "medium"
		ticket.AssetName = targetHost
		ticket.AssetURL = targetHost
		ticket.Description = a.describeCategoryFindings(targetDomains, catLogic, scanJobID)
		ticket.HarmDescription = "逻辑缺陷可被用于绕过业务校验、越权操作或上传恶意文件，需结合业务逻辑修复。"
		ticket.RemediationPriority = "P1"
	case catInfoLeak:
		ticket.Title = "信息泄露（目录遍历/报错泄露/源码暴露）"
		ticket.VulnType = "info_disclosure"
		ticket.RiskLevel = "medium"
		ticket.AssetName = targetHost
		ticket.AssetURL = targetHost
		ticket.Description = a.describeCategoryFindings(targetDomains, catInfoLeak, scanJobID)
		ticket.HarmDescription = "信息泄露可暴露系统路径、版本或源码片段，为攻击者提供进一步渗透线索。"
		ticket.RemediationPriority = "P2"
	case catWebshell:
		ticket.Title = "Webshell/后门检出（恶意文件落地）"
		ticket.VulnType = "webshell"
		ticket.RiskLevel = "high"
		ticket.AssetName = targetHost
		ticket.AssetURL = targetHost
		ticket.Description = a.describeCategoryFindings(targetDomains, catWebshell, scanJobID)
		ticket.HarmDescription = "Webshell/后门意味着攻击者已在目标服务器获得命令执行能力，可进一步提权、横向移动与持久化，危害极高，需立即隔离排查。"
		ticket.RemediationPriority = "P0"
	default:
		// 兜底：未知 / 未归类类型（catOther 或任何新增类型）—— 禁止因分类失败而跳过建单。
		// 缺陷 F 修复：保留原始漏洞类型和扫描作业信息，提升工单可用性。
		originalType := extractOriginalVulnType(steps, cat)
		ticket.Title = categoryLabel(cat) + "（智能体兜底建单）"
		ticket.VulnType = "unknown"
		ticket.RiskLevel = defaultRiskForCategory(cat)
		ticket.AssetName = targetHost
		ticket.AssetURL = targetHost
		desc := a.describeCategoryFindings(targetDomains, cat, scanJobID)
		if originalType != "" {
			ticket.Description = fmt.Sprintf("发现需人工复核的安全隐患[原始漏洞类型: %s]，详见关联扫描任务 %s。\n%s",
				originalType, scanJobID, desc)
		} else {
			ticket.Description = desc + "\n（注：该漏洞类型未能映射到已知语义类别，已按「未知/未归类」兜底建单，请人工复核类型与处置。）"
		}
		ticket.HarmDescription = "发现需人工复核的安全隐患，具体危害取决于该漏洞的实际情况，请结合扫描证据评估。"
		ticket.RemediationPriority = "P1"
	}
	if strings.TrimSpace(ticket.Description) == "" {
		ticket.Description = "目标资产存在 " + cat + " 类风险，详见关联扫描任务 " + scanJobID + "。"
	}
	ticket.Evidence = ticket.Description
	ticket.MitigationMeasures = "立即移除或限制访问敏感文件；对基础认证改用强口令并启用账户锁定；配置目录遍历与敏感路径的访问控制。"
	ticket.RetestMethod = "修复后复扫确认敏感路径返回 404/403，且弱口令探测无命中。"
	return ticket
}

// extractOriginalVulnType 从步骤中提取原始漏洞类型（缺陷 F 修复）。
// 当 cat 为 catOther 时，需要从漏洞列表中找出该类型的原始名称。
func extractOriginalVulnType(steps []Step, cat string) string {
	if cat != catOther {
		return ""
	}
	// 从 start_scan 步骤获取 domain_id
	var domainID string
	for _, s := range steps {
		if s.Name == "start_scan" {
			var m map[string]any
			if err := json.Unmarshal([]byte(s.Detail), &m); err == nil {
				if v, ok := m["domain_id"].(string); ok && v != "" {
					domainID = v
					break
				}
			}
		}
	}
	if domainID == "" {
		return ""
	}
	// 从步骤中提取本运行的 scan_job_id
	scanJobIDs := thisRunScanJobIDs(steps)
	if len(scanJobIDs) == 0 {
		return ""
	}
	// 从 list_vulnerabilities 结果中查找未归类的漏洞类型
	for _, s := range steps {
		if s.Name == "list_vulnerabilities" || s.Name == "get_vulnerability" {
			// 尝试从 Result 中解析类型
			var m map[string]any
			if err := json.Unmarshal([]byte(s.Result), &m); err == nil {
				if rows, ok := m["rows"].([]any); ok {
					for _, r := range rows {
						if rm, ok := r.(map[string]any); ok {
							t, _ := rm["type"].(string)
							if t != "" && vulnTypeToCategory(t) == catOther {
								return t // 返回第一个未归类的原始类型
							}
						}
					}
				}
				// 单个漏洞的情况
				if t, ok := m["type"].(string); ok && t != "" && vulnTypeToCategory(t) == catOther {
					return t
				}
			}
		}
	}
	return ""
}

// extractScanJobIDFromSteps 从已执行步骤（start_scan / weak_password_scan）中提取关联的扫描任务 ID。
func extractScanJobIDFromSteps(steps []Step) string {
	for _, s := range steps {
		var m map[string]any
		if err := json.Unmarshal([]byte(s.Detail), &m); err != nil {
			continue
		}
		if v, ok := m["scan_job_id"].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

// describeWeakPassword 从弱口令探测步骤汇总命中情况作为工单描述。
func (a *Agent) describeWeakPassword(steps []Step) string {
	var b strings.Builder
	b.WriteString("智能体执行弱口令探测，命中情况如下：\n")
	found := false
	for _, s := range steps {
		if s.Name == "weak_password_scan" && s.Status == StepDone {
			cnt := jsonIntField(s.Result, "found_count")
			if cnt > 0 {
				found = true
				b.WriteString(fmt.Sprintf("- 探测命中 %d 条弱口令/默认口令。\n", cnt))
			}
		}
	}
	if !found {
		b.WriteString("- 目标存在 .htpasswd 等基础认证凭据文件，存在弱口令/默认口令风险。\n")
	}
	return b.String()
}

// describeCategoryFindings 汇总目标资产属于指定语义类别的漏洞列表，作为兜底工单的描述。
// 复用 listVulns（与 describeDataLeak 一致的取数路径），按 vulnTypeToCategory 过滤类别，
// 保证注入/权限/组件等任意类别都能在兜底工单中列出真实证据。
func (a *Agent) describeCategoryFindings(targetDomains []string, cat, scanJobID string) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("扫描发现以下「%s」类风险：\n", categoryLabel(cat)))
	foundAny := false
	for _, did := range targetDomains {
		if a.deps.VulnLister == nil && a.deps.VulnRepo == nil {
			continue
		}
		if out, err := a.deps.listVulns(did, 200); err == nil {
			var m map[string]any
			if json.Unmarshal([]byte(out), &m) == nil {
				if rows, ok := m["rows"].([]any); ok {
					for _, r := range rows {
						if rm, ok := r.(map[string]any); ok {
							t, _ := rm["type"].(string)
							if vulnTypeToCategory(t) == cat {
								foundAny = true
								name, _ := rm["name"].(string)
								url, _ := rm["url"].(string)
								b.WriteString(fmt.Sprintf("- [%s] %s %s\n", t, name, url))
							}
						}
					}
				}
			}
		}
	}
	if !foundAny {
		b.WriteString(fmt.Sprintf("- （平台漏洞记录中未检索到该类别明细，请参阅关联扫描作业 %s）\n", scanJobID))
	}
	return b.String()
}

// describeDataLeak 汇总目标资产可直达访问的敏感文件/信息，作为数据泄露工单描述。
func (a *Agent) describeDataLeak(targetDomains []string) string {
	var b strings.Builder
	b.WriteString("扫描发现以下敏感文件/信息可直接访问（数据泄露风险）：\n")
	for _, did := range targetDomains {
		if a.deps.VulnLister != nil || a.deps.VulnRepo != nil {
			if out, err := a.deps.listVulns(did, 200); err == nil {
				var m map[string]any
				if json.Unmarshal([]byte(out), &m) == nil {
					if rows, ok := m["rows"].([]any); ok {
						for _, r := range rows {
							if rm, ok := r.(map[string]any); ok {
								t, _ := rm["type"].(string)
								if vulnTypeToCategory(t) == catDataLeak {
									name, _ := rm["name"].(string)
									url, _ := rm["url"].(string)
									b.WriteString(fmt.Sprintf("- [%s] %s %s\n", t, name, url))
								}
							}
						}
					}
				}
			}
		}
		if a.deps.SensLister != nil || a.deps.SensRepo != nil {
			if out, err := a.deps.listSens(did, 200); err == nil {
				if c := jsonIntField(out, "count"); c > 0 {
					b.WriteString(fmt.Sprintf("- 命中 %d 条敏感信息（关键词/内容匹配）。\n", c))
				}
			}
		}
	}
	return b.String()
}

func (a *Agent) deliverableNudgeCount(task *Task) int {
	task.mu.Lock()
	defer task.mu.Unlock()
	n := 0
	for _, s := range task.Steps {
		if s.Name == "deliverable_check" {
			n++
		}
	}
	return n
}

// 建单义务的语义类别：弱口令 / 数据泄露。两类发现需各自独立建单，
// 不能因「存在某一类工单（如弱口令）」就认为整个建单义务已满足，否则会漏交数据泄露工单。
// 语义类别常量与 vulnTypeToCategory 映射已迁移到 vuln_taxonomy.go，集中维护。

// ticketCategory 推断工单所属语义类别：优先看 VulnType（模型现在会正确填写），
// 缺失时按标题/漏洞名/描述关键词兜底（覆盖所有语义类别，保证去重判定准确）。
func ticketCategory(t *models.Ticket) string {
	if c := vulnTypeToCategory(t.VulnType); c != "" {
		return c
	}
	// 标题/漏洞名/描述关键词兜底：覆盖全部语义类别，避免 VulnType 缺失时误判类别。
	hay := strings.ToLower(t.Title + " " + t.VulnName + " " + t.Description)
	if containsAny(hay, []string{"弱口令", "弱密码", "weak", "默认口令", "default password", "口令"}) {
		return catWeakPassword
	}
	if containsAny(hay, []string{"数据泄露", "数据泄漏", "敏感文件", "敏感信息", "sensitive", "备份文件", ".git", "源码", "配置文件泄露"}) {
		return catDataLeak
	}
	if containsAny(hay, []string{"注入", "sql注入", "命令注入", "sqli", "xss", "ssti", "xxe", "injection"}) {
		return catInjection
	}
	if containsAny(hay, []string{"越权", "权限", "认证", "认证缺陷", "配置错误", "配置不当", "misconfiguration", "ssrf", "csrf", "idor", "访问控制"}) {
		return catAuthConfig
	}
	if containsAny(hay, []string{"组件", "依赖", "vulnerable component", "第三方组件", "已知漏洞组件"}) {
		return catComponent
	}
	if containsAny(hay, []string{"逻辑", "业务逻辑", "文件上传", "反序列化", "race", "并发"}) {
		return catLogic
	}
	if containsAny(hay, []string{"信息泄露", "目录遍历", "报错泄露", "debug", "路径遍历", "信息暴露"}) {
		return catInfoLeak
	}
	if containsAny(hay, []string{"webshell", "后门", "木马", "恶意文件", "backdoor", "malicious", "webshell文件"}) {
		return catWebshell
	}
	return catOther
}

// ticketDeliverableSatisfied 判断建单义务是否已按「类别」满足：
// 用户要求提交工单时，凡目标资产确实存在发现的类别（弱口令 / 数据泄露），
// 都必须有覆盖该资产且类别匹配的工单（本次成功建单或平台既有工单）。
// 仅当目标资产确无任何需建单发现时，才真空满足（无需建单）。
// 关键：不能因「存在某类别工单（如弱口令）」就认为整个建单义务已满足——
// 数据泄露类发现若无对应工单，仍须补齐，否则会漏交。
// ticketDeliverableSatisfied 基于「交付契约」判断建单义务是否已满足（结果导向）：
// 仅当用户点名要求的类别（contract.TicketCategories）确有发现时，才必须存在覆盖该资产的工单
// （本运行成功建单或平台既有工单归属本运行扫描作业）。支持「其他漏洞可忽略」收窄——未点名的类别不强制建单。
// 排他模式（contract.Exclusive）：当用户明确要求「只上报 X / 仅 X」「其他忽略 / 全部忽略 / 判为误报」时，
// 除点名类别外的一切发现都视为用户已主动要求忽略，绝不应因这些发现未建单而阻塞 finish_task。
// 此前「只上报 webshell 工单，其他忽略」因 webshell 被误归入 data_leak、且敏感文件确有发现，
// 导致 deliverable_check 永远失败、任务在重新扫描中死循环——该模式即为此而生。
func (a *Agent) ticketDeliverableSatisfied(contract *DeliverableContract, steps []Step, targetDomains []string, targetHost string) bool {
	if !contract.NeedsTicket {
		return true
	}
	cats := a.findingCategories(steps, targetDomains)
	if len(cats) == 0 {
		// 真空满足：目标资产确无任何弱口令 / 数据泄露发现，无需建单。
		return true
	}
	for cat := range cats {
		// 仅校验用户点名要求的类别（支持「其他漏洞可忽略」收窄范围）。
		// 排他模式下，未点名的类别一律视为用户已要求忽略，直接跳过、不阻塞收尾。
		if !sliceContains(contract.TicketCategories, cat) {
			if contract.Exclusive {
				// 点名类别之外的一切发现，用户已明确要求忽略，视为已满足（无需建单）。
				continue
			}
			// 非排他模式下，未点名类别同样不强制（点名语义即「只对这些建单」）。
			continue
		}
		if !a.categoryCoveredByTicket(steps, targetDomains, targetHost, cat) {
			return false
		}
	}
	return true
}

// findingCategories 返回目标资产当前确实存在的发现类别集合（弱口令 / 数据泄露）。
// 综合会话证据（弱口令探测命中）与平台状态（漏洞 / 敏感信息）判断。
// 缺陷 E 修复：平台状态查询仅统计本运行 scan_job_id 集合内的漏洞/敏感信息，
// 避免历史遗留数据被当作本次发现（漏建/错建风险）。
func (a *Agent) findingCategories(steps []Step, targetDomains []string) map[string]bool {
	cats := map[string]bool{}
	// 1) 会话证据：弱口令探测命中
	for _, s := range steps {
		if s.Name == "weak_password_scan" && s.Status == StepDone {
			if jsonIntField(s.Result, "found_count") > 0 {
				cats[catWeakPassword] = true
			}
		}
	}
	// 2) 平台状态：仅统计本运行扫描作业的漏洞/敏感信息（缺陷 E 修复）
	thisRunJobs := thisRunScanJobIDs(steps)
	if len(thisRunJobs) == 0 {
		// 无本运行扫描作业时，回退到原行为（查询目标域名全部漏洞）
		// 这是合理的：若模型未发起扫描，平台中的任何发现都可视作「本次发现」。
		if a.deps.VulnLister != nil || a.deps.VulnRepo != nil || a.deps.SensLister != nil || a.deps.SensRepo != nil {
			for _, did := range targetDomains {
				if a.deps.VulnLister != nil || a.deps.VulnRepo != nil {
					if out, err := a.deps.listVulns(did, 200); err == nil {
						for _, c := range vulnCategoriesIn(out) {
							cats[c] = true
						}
					}
				}
				if a.deps.SensLister != nil || a.deps.SensRepo != nil {
					if out, err := a.deps.listSens(did, 200); err == nil && jsonIntField(out, "count") > 0 {
						cats[catDataLeak] = true
					}
				}
			}
		}
		return cats
	}
	// 本运行有扫描作业：仅统计这些作业产生的漏洞/敏感信息
	jobSet := map[string]bool{}
	for _, j := range thisRunJobs {
		jobSet[j] = true
	}
	if a.deps.VulnLister != nil || a.deps.VulnRepo != nil {
		for _, did := range targetDomains {
			if out, err := a.deps.listVulnsByJobs(did, jobSet, 200); err == nil {
				for _, c := range vulnCategoriesIn(out) {
					cats[c] = true
				}
			}
		}
	}
	if a.deps.SensLister != nil || a.deps.SensRepo != nil {
		for _, did := range targetDomains {
			if out, err := a.deps.listSensByJobs(did, jobSet, 200); err == nil && jsonIntField(out, "count") > 0 {
				cats[catDataLeak] = true
			}
		}
	}
	return cats
}

// categoryCoveredByTicket 判断某一发现类别是否已有覆盖目标资产的工单：
// 1) 本运行已成功为该类别创建工单；或 2) 平台既有工单覆盖该资产且类别匹配。
func (a *Agent) categoryCoveredByTicket(steps []Step, targetDomains []string, targetHost, category string) bool {
	// 1) 本运行已成功为该类别建单（覆盖目标）
	for _, s := range steps {
		if s.Name == "create_ticket" && s.Status == StepDone && !strings.HasPrefix(s.Result, "工具执行异常") {
			if a.createTicketStepCovers(s, targetDomains, targetHost, category) {
				return true
			}
		}
	}
	// 2) 平台既有工单：覆盖该资产且类别匹配。
	// 关键修正：仅当该工单归属「本运行扫描作业」时才算本次交付已满足，
	// 否则历史工单（先前运行创建）会误导判定为「已满足」，导致本运行漏建单（此前反复出现的缺陷）。
	// 若本运行无任何扫描作业（sjs 为空），则退化为接受任意覆盖该资产的工单以保幂等。
	if a.deps.TicketRepo != nil {
		sjs := thisRunScanJobIDs(steps)
		sjSet := map[string]bool{}
		for _, x := range sjs {
			sjSet[x] = true
		}
		if tickets, err := a.deps.TicketRepo.List("", ""); err == nil {
			for _, t := range tickets {
				if a.ticketCoversTarget(t, targetDomains, targetHost) && ticketCategory(t) == category {
					if len(sjSet) == 0 || sjSet[t.ScanJobID] {
						return true
					}
				}
			}
		}
	}
	return false
}

// thisRunScanJobIDs 从已执行步骤的参数里抽取本运行涉及的扫描作业 ID（start_scan / weak_password_scan / create_ticket 等）。
func thisRunScanJobIDs(steps []Step) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range steps {
		var m map[string]any
		if err := json.Unmarshal([]byte(s.Detail), &m); err != nil {
			continue
		}
		if v, ok := m["scan_job_id"].(string); ok && v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

// createTicketStepCovers 判断一条 create_ticket 步骤是否已就该类别覆盖目标资产。
// 步骤 Detail 存的是调用参数 JSON（被截断，但 vuln_name/title/asset 等关键字段通常足够），
// 据此推断类别与资产覆盖。
func (a *Agent) createTicketStepCovers(s Step, targetDomains []string, targetHost, category string) bool {
	var args map[string]any
	if err := json.Unmarshal([]byte(s.Detail), &args); err != nil || args == nil {
		return false
	}
	cat := ""
	if vt, ok := args["vuln_type"].(string); ok {
		cat = vulnTypeToCategory(vt)
	}
	if cat == "" {
		hay := strings.ToLower(getString(args, "title") + " " + getString(args, "vuln_name") + " " + getString(args, "description"))
		if containsAny(hay, []string{"弱口令", "弱密码", "weak", "默认口令", "default password", "口令"}) {
			cat = catWeakPassword
		} else if containsAny(hay, []string{"数据泄露", "数据泄漏", "敏感", "sensitive", "泄露", "信息泄露", "备份文件", "源码泄露", "源码泄漏", "配置文件", ".git", "目录遍历", "敏感文件", "敏感信息"}) {
			cat = catDataLeak
		} else if containsAny(hay, []string{"webshell", "后门", "木马", "恶意文件", "backdoor", "malicious", "webshell文件"}) {
			cat = catWebshell
		}
	}
	if cat != category {
		return false
	}
	// 资产覆盖：asset_url / asset_name 命中目标 host，或 scan_job 反查命中目标域名
	if targetHost != "" {
		if strings.Contains(getString(args, "asset_url"), targetHost) || strings.Contains(getString(args, "asset_name"), targetHost) {
			return true
		}
	}
	if sj, ok := args["scan_job_id"].(string); ok && sj != "" && a.deps.ScanJobRepo != nil {
		if job, err := a.deps.ScanJobRepo.GetByID(sj); err == nil {
			for _, d := range targetDomains {
				if job.DomainID == d {
					return true
				}
			}
		}
	}
	return false
}

// vulnCategoriesIn 从 list_vulnerabilities 的 JSON 输出中提取存在的语义建单类别集合。
func vulnCategoriesIn(s string) []string {
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		return nil
	}
	rows, ok := m["rows"].([]any)
	if !ok {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, r := range rows {
		if rm, ok := r.(map[string]any); ok {
			if t, ok := rm["type"].(string); ok {
				if c := vulnTypeToCategory(t); c != "" && !seen[c] {
					seen[c] = true
					out = append(out, c)
				}
			}
		}
	}
	return out
}

// ruleDeliverableSatisfied 基于「交付契约」判断定时巡检义务是否已满足。
func (a *Agent) ruleDeliverableSatisfied(contract *DeliverableContract, steps []Step, targetDomains []string) bool {
	if !contract.NeedsRule {
		return true
	}
	// 1) 本运行已成功创建巡检规则
	if a.doneTool(steps, "create_inspection_rule") {
		return true
	}
	// 2) 幂等：平台已存在覆盖该资产、cron 一致的启用周期规则 -> 视为已满足
	if a.deps.RuleRepo == nil || len(targetDomains) == 0 {
		// 无法核验平台既有规则：仅以本运行步骤判定（保持原行为，避免误放行）
		return false
	}
	rules, err := a.deps.RuleRepo.List()
	if err != nil {
		return false
	}
	hasTime := contract.Schedule != ""
	var reqHour, reqMin int
	if hasTime {
		reqHour, reqMin, _ = parseCronHourMinute(contract.Schedule)
	}
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		if !domainOverlap(r.EffectiveDomainIDs(), targetDomains) {
			continue
		}
		if hasTime {
			if rh, rm, ok := parseCronHourMinute(r.Schedule); ok && rh == reqHour && rm == reqMin {
				return true
			}
		} else {
			// 用户未指定具体时刻：存在覆盖该资产的启用周期规则即视为已满足
			return true
		}
	}
	return false
}

// doneTool 判断某个工具是否已有「执行成功」的步骤（排除工具执行异常的结果）。
func (a *Agent) doneTool(steps []Step, name string) bool {
	for _, s := range steps {
		if s.Name == name && s.Status == StepDone && !strings.HasPrefix(s.Result, "工具执行异常") {
			return true
		}
	}
	return false
}

// hasTicketableFindings 判断当前是否存在需建单的发现（弱口令命中 / 数据泄露类漏洞 / 敏感信息）。
func (a *Agent) hasTicketableFindings(steps []Step, targetDomains []string) bool {
	// 1) 会话证据：弱口令探测命中
	for _, s := range steps {
		if s.Name == "weak_password_scan" && s.Status == StepDone {
			if jsonIntField(s.Result, "found_count") > 0 {
				return true
			}
		}
	}
	// 2) 平台状态：目标资产存在弱口令/数据泄露类漏洞或敏感信息
	if a.deps.VulnLister != nil || a.deps.VulnRepo != nil || a.deps.SensLister != nil || a.deps.SensRepo != nil {
		for _, did := range targetDomains {
			if a.deps.VulnLister != nil || a.deps.VulnRepo != nil {
				if out, err := a.deps.listVulns(did, 200); err == nil && jsonHasTicketableVuln(out) {
					return true
				}
			}
			if a.deps.SensLister != nil || a.deps.SensRepo != nil {
				if out, err := a.deps.listSens(did, 200); err == nil && jsonIntField(out, "count") > 0 {
					return true
				}
			}
		}
	}
	return false
}

// extractTargetDomainIDs 从已执行步骤的参数里抽取本次任务涉及的目标域名 id。
func (a *Agent) extractTargetDomainIDs(steps []Step) []string {
	seen := map[string]bool{}
	var out []string
	add := func(id string) {
		if id != "" && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	for _, s := range steps {
		// 关键修复：必须同时解析 Detail（工具入参）与 Result（工具输出）。
		// 不同工具把 domain_id / scan_job_id 放在不同字段：
		//   - start_scan 的 domain_id 在入参 Detail，而 scan_job_id 在输出 Result；
		//   - list_vulnerabilities / wait_scan 等则常把标识写在 Result。
		// 旧实现只读 Detail，一旦步骤链里 domain_id 未被提取，TargetDomains 就为空，
		// 平台侧漏洞/敏感信息证据被整片漏查，交付校验因此「真空满足」并静默放行，
		// 表现为「任务 completed 却零工单」（任务 211dbe05 的真实根因）。
		for _, payload := range []string{s.Detail, s.Result} {
			if strings.TrimSpace(payload) == "" {
				continue
			}
			var m map[string]any
			if err := json.Unmarshal([]byte(payload), &m); err != nil {
				continue
			}
			if v, ok := m["domain_id"].(string); ok {
				add(v)
			}
			if arr, ok := m["domain_ids"].([]any); ok {
				for _, e := range arr {
					if s, ok := e.(string); ok {
						add(s)
					}
				}
			}
			// 通过 scan_job_id 反查域名
			if v, ok := m["scan_job_id"].(string); ok && v != "" && a.deps.ScanJobRepo != nil {
				if job, err := a.deps.ScanJobRepo.GetByID(v); err == nil && job.DomainID != "" {
					add(job.DomainID)
				}
			}
		}
	}
	return out
}

// extractTargetHost 从目标文本中抽出 host 或 host:port（用于和工单 asset_url/asset_name 对齐）。
func (a *Agent) extractTargetHost(goal string) string {
	if m := regexp.MustCompile(`\b([\w.-]+:\d{2,5})\b`).FindString(goal); m != "" {
		return m
	}
	if m := regexp.MustCompile(`\b(https?://[\w.-]+(?::\d+)?)\b`).FindString(goal); m != "" {
		return m
	}
	return ""
}

// ticketCoversTarget 判断工单是否覆盖本次目标资产。
func (a *Agent) ticketCoversTarget(t *models.Ticket, targetDomains []string, targetHost string) bool {
	if t == nil {
		return false
	}
	if targetHost != "" && (strings.Contains(t.AssetURL, targetHost) || strings.Contains(t.AssetName, targetHost)) {
		return true
	}
	// 通过工单 scan_job_id 反查域名是否命中目标集合
	if t.ScanJobID != "" && a.deps.ScanJobRepo != nil {
		if job, err := a.deps.ScanJobRepo.GetByID(t.ScanJobID); err == nil {
			for _, d := range targetDomains {
				if job.DomainID == d {
					return true
				}
			}
		}
	}
	return false
}

func domainOverlap(a, b []string) bool {
	set := map[string]bool{}
	for _, x := range a {
		set[x] = true
	}
	for _, x := range b {
		if set[x] {
			return true
		}
	}
	return false
}

// extractRequestedTime 从目标文本解析用户要求的定时时刻（每天 16:00 / 每晚 20 点 等）。
// 缺陷 G 修复：增强对非标准中文时间表达的支持。
func extractRequestedTime(goal string) (hour, minute int, ok bool) {
	// 注意：目标串常以「127.0.0.1:8099」这类 host:port 开头，若只取第一个 \d{1,2}:\d{2} 匹配，
	// 会命中 IP 末段 + 端口前缀（如 "1:80"），其分钟数 80 非法，导致函数直接放弃、
	// 真正的时刻（如 "14:40"）被漏掉（缺陷：每日14:40巡检规则未建立）。
	// 因此这里遍历全部匹配，跳过紧邻 IP 片段的匹配（前一字节为 '.'），取第一个合法的 时:分。
	re := regexp.MustCompile(`(\d{1,2})[:：](\d{2})`)
	for _, loc := range re.FindAllStringSubmatchIndex(goal, -1) {
		if len(loc) < 6 {
			continue
		}
		start := loc[0]
		if start > 0 && goal[start-1] == '.' {
			// 形如 127.0.0.1:8099 中的 ".1:80" 片段，属于 host:port，不是时刻
			continue
		}
		h, _ := strconv.Atoi(goal[loc[2]:loc[3]])
		mi, _ := strconv.Atoi(goal[loc[4]:loc[5]])
		if h >= 0 && h < 24 && mi >= 0 && mi < 60 {
			return h, mi, true
		}
	}
	if m := re.FindStringSubmatch(goal); m != nil {
		h, _ := strconv.Atoi(m[1])
		mi, _ := strconv.Atoi(m[2])
		if h >= 0 && h < 24 && mi >= 0 && mi < 60 {
			return h, mi, true
		}
	}
	// 缺陷 G 修复：增加对非标准中文时间表达的支持
	// 匹配 "下午/晚上/早上/中午/傍晚 + 数字 + 点/点钟/时" 模式
	// 如："下午4点"、"晚上8点钟"、"下午14:30"
	if m := regexp.MustCompile(`(?:下午|晚上|夜里|傍晚|晚上|中午|早上|上午)(?:(\d{1,2})[:：](\d{2})|(\d{1,2})\s*(?:点|点钟|时))`).FindStringSubmatch(goal); m != nil {
		var h, mi int
		if m[1] != "" && m[2] != "" {
			// 形如 "下午14:30"
			h, _ = strconv.Atoi(m[1])
			mi, _ = strconv.Atoi(m[2])
		} else if m[3] != "" {
			// 形如 "下午4点"
			h, _ = strconv.Atoi(m[3])
			mi = 0
		}
		// 下午/晚上/傍晚/夜里 需加 12（但 13 点以后不加）
		if h < 12 && (strings.Contains(goal[:len(goal)], "下午") || strings.Contains(goal[:len(goal)], "晚上") || strings.Contains(goal[:len(goal)], "傍晚") || strings.Contains(goal[:len(goal)], "夜里")) {
			h += 12
		}
		if h >= 0 && h < 24 && mi >= 0 && mi < 60 {
			return h, mi, true
		}
	}
	if m := regexp.MustCompile(`(\d{1,2})\s*点`).FindStringSubmatch(goal); m != nil {
		h, _ := strconv.Atoi(m[1])
		if h >= 0 && h < 24 {
			return h, 0, true
		}
	}
	// 匹配 "整点" 或 "每小时" —— 任意整点
	if strings.Contains(goal, "整点") || strings.Contains(goal, "每小时") {
		return 0, 0, true // 返回 ok=true，hour=0，调用方会处理
	}
	return 0, 0, false
}

// parseCronHourMinute 解析 cron 表达式的前两个字段（分、时）。
func parseCronHourMinute(schedule string) (hour, minute int, ok bool) {
	fields := strings.Fields(schedule)
	if len(fields) < 2 {
		return 0, 0, false
	}
	mi, err1 := strconv.Atoi(fields[0])
	h, err2 := strconv.Atoi(fields[1])
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return h, mi, true
}

// jsonIntField 从 JSON 字符串中读取整型字段。
func jsonIntField(s, key string) int {
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		return 0
	}
	if v, ok := m[key]; ok {
		switch n := v.(type) {
		case float64:
			return int(n)
		case int:
			return n
		case int64:
			return int(n)
		}
	}
	return 0
}

// jsonHasTicketableVuln 判断 list_vulnerabilities 的 JSON 输出中是否含需建单类型漏洞。
func jsonHasTicketableVuln(s string) bool {
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		return false
	}
	rows, ok := m["rows"].([]any)
	if !ok {
		return false
	}
	for _, r := range rows {
		if rm, ok := r.(map[string]any); ok {
			if t, ok := rm["type"].(string); ok && isTicketableVulnType(t) {
				return true
			}
		}
	}
	return false
}

// nudgeUnmetDeliverables 把「硬性交付未完成」作为纠正信号回写给模型，并记入步骤，促使其补齐后再结束。
func (a *Agent) nudgeUnmetDeliverables(task *Task, missing []string) {
	msg := "任务尚未完成以下用户硬性要求，禁止提前结束：\n- " + strings.Join(missing, "\n- ") +
		"\n请继续调用相应工具完成上述交付（例如对本次发现的弱口令/数据泄露调用 create_ticket；对每天/定时巡检调用 create_inspection_rule 配置 cron）后，再调用 finish_task。" +
		"\n重要：必须基于【本次运行】的发现与要求来交付，不要因为平台中存在历史工单 / 历史巡检规则就认为本任务的交付已满足。每一次确有发现的扫描都应留下属于自己的工单（归属本运行的扫描作业）；定时巡检规则须覆盖本次目标资产、且 cron 时刻与本次要求一致（如每天 16:00 对应 '0 16 * * *'）。"
	task.mu.Lock()
	task.Messages = append(task.Messages, Message{
		Role:    RoleUser,
		Content: RenderToolResult(ToolResult{CallID: "deliverable_check", Name: "system", Content: msg, IsError: true}),
	})
	task.mu.Unlock()
	step := &Step{ID: uuid.New().String(), Name: "deliverable_check", Status: StepDone, Detail: "完成前硬性交付校验未通过", Result: truncate(strings.Join(missing, "; "), 500)}
	task.appendStep(*step)
	_ = a.repo.AppendStep(task.ID, step)
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
7. 扫描结果读取纪律：调用 start_scan / run_inspection_rule 后，必须先用 wait_scan / get_scan_status 等待其 completed，再调用 list_vulnerabilities / list_sensitive_info 读取结果；禁止在扫描/巡检仍处于 running 时读取（会读到空或陈旧数据）。
8. 建单义务（硬性）：用户明确要求「提交工单 / 建单 / 务必提交相关工单」时，必须为**目标资产上发现的每一类漏洞**调用 create_ticket，覆盖全部语义类别：弱口令(weak_password)、数据泄露(sensitive_file/sensitive_info)、注入类(sqli/命令注入/ssti/xxe)、权限与配置错误(idor/认证缺陷/配置不当/ssrf)、依赖组件漏洞(vulnerable_component)、逻辑缺陷(文件上传/反序列化/业务逻辑)、信息泄露(目录遍历/报错泄露/源码暴露)，以及任何**未归类 / 未知类型**（归入 other，仍须建单，禁止因分类失败而静默跳过）。finish_task 前不得跳过。若某类发现确实存在却未建单，视为任务未完成。同一扫描作业内同类型同 URL 的漏洞按指纹幂等，已存在同指纹工单则复用，不要重复建单；若平台已存在覆盖同一资产（同 host / 同 scan_job 域名）且类别匹配的既有工单，则视为已满足；若确无任何发现，则建单义务真空满足，无需建单（在结论中说明「未发现需建单项」）。
9. 范围约束（排他/收窄建单）：
   - 用户说「仅上报 X 类 / 只上报 X / 仅 X / 只看 X」「其他忽略 / 忽略其他 / 全部忽略 / 其他问题全部忽略 / 直接判为误报 / 误报」时，进入**排他模式**：只为点名的类别（如 webshell、XSS→注入类）建单；其余类别即使确有发现，也按用户要求**判为误报或忽略，不建单**，并在结论中明确说明「已将其他 N 类发现判为误报/已忽略」，随后即可 finish_task（无需为它们建单，交付校验不会因此阻塞）。
   - 若用户点名的类别（如 webshell）在本次扫描中**确无发现**，则该类建单义务「真空满足」，无需建单，直接 finish 并在结论中说明「未检出 webshell，未发现需建单项」即可。
   - 注意类别归属：本平台建单类别**不含**「XSS」独立项——XSS 归入注入类(injection)；**webshell / 后门 / 木马 / 恶意文件** 归入独立的 webshell 类别（高危 P0），**不属于**数据泄露(sensitive_file)。不要因"webshell 是数据泄露"而误建单或漏分类。
   - 用户**未显式缩窄**时（如只说「提交工单」「扫描并建单」），默认**所有类型都要建单**。
10. 定时巡检义务（硬性）：用户要求「定时巡检 / 每天 X 点巡检 / 这次扫好后每天 16:00 都要日常巡检扫描」等周期需求时，必须调用 create_inspection_rule 配置 cron 周期任务，并确认返回 registered:true（若 false 需排查 cron 边界后重试）。cron 速查：每天 16:00 为 '0 16 * * *'、每晚 20:00 为 '0 20 * * *'、每周一 9 点 为 '0 9 * * 1'；绑定目标 domain_ids（数组，可多域名同周期）。若平台已存在覆盖该资产、cron 一致的启用巡检规则（即先前已配置），则视为已满足，不要重复创建。
11. 复用资产：优先从 list_domains / get_domain 找到与目标 URL 一致的已有域名，避免重复建域名；找不到再用 create_domain。
12. 完成前自检（防漏交）：调用 finish_task 前，回读用户原始指令，逐项确认上述硬性交付（建单 / 定时巡检）满足：① 建单——已有 create_ticket 成功步骤、或平台已有覆盖该资产的工单、或确无相关发现（真空满足）；② 定时巡检——已有 create_inspection_rule 成功步骤、或平台已有覆盖该资产的同类周期规则。缺失任何一项则继续调用工具，禁止提前结束。

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
