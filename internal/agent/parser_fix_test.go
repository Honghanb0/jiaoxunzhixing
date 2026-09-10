package agent

import (
	"strings"
	"testing"
)

// TestParseToolCallsMultiBlock 验证根因修复：模型若在多个 <tool_calls> 块中分次输出工具调用
// （例如 parse_error 纠正轮后补发 create_inspection_rule），解析器必须合并所有块而非只取第一个，
// 否则后续工具调用会被静默丢弃，导致建单/定时巡检等硬性交付漏做。
func TestParseToolCallsMultiBlock(t *testing.T) {
	content := "先发起扫描：\n<tool_calls>\n" +
		"[{\"name\":\"start_scan\",\"arguments\":{\"domain_id\":\"x\"}}]\n" +
		"</tool_calls>\n再建规则：\n<tool_calls>\n" +
		"[{\"name\":\"create_inspection_rule\",\"arguments\":{\"name\":\"n\",\"domain_ids\":[\"x\"],\"schedule\":\"0 16 * * *\"}}]\n" +
		"</tool_calls>"
	calls, err := ParseToolCalls(content)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(calls) != 2 {
		t.Fatalf("expected 2 calls (merged across blocks), got %d: %+v", len(calls), calls)
	}
	if calls[0].Name != "start_scan" || calls[1].Name != "create_inspection_rule" {
		t.Fatalf("unexpected call order/names: %+v", calls)
	}
}

// TestParseToolCallsUnclosedFence 固化「围栏闭合标签被截断」的修复：
// 模型输出被 max_tokens 截断成 `...</tool_calls`（缺少 '>'）时，解析器必须抢救出其中的工具调用，
// 而不是返回 0 个调用且无错误——后者会让外层循环把这段畸形 JSON 误当成「最终结论」收尾，
// 表现为「任务 completed 但执行结果是一段裸 <tool_calls> JSON，工具从未执行」。
func TestParseToolCallsUnclosedFence(t *testing.T) {
	content := "数据已初步获取。<tool_calls>\n" +
		`[{"name": "list_domains", "arguments": {}}, {"name": "list_alerts", "arguments": {"limit": 50}}]` +
		"\n</tool_calls"
	calls, err := ParseToolCalls(content)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(calls) != 2 {
		t.Fatalf("expected 2 recovered calls from unclosed fence, got %d: %+v", len(calls), calls)
	}
	if calls[0].Name != "list_domains" || calls[1].Name != "list_alerts" {
		t.Fatalf("unexpected names: %+v", calls)
	}
}

// TestParseToolCallsFenceWithoutParsableCall 固化：输出含 <tool_calls> 却解析不出任何调用时，
// 必须返回错误（触发 parse_error 纠正轮让模型重发），而非返回 (nil, nil) 被当作「已给出结论」。
func TestParseToolCallsFenceWithoutParsableCall(t *testing.T) {
	content := "<tool_calls>\n这不是合法 JSON，也不是工具调用\n</tool_calls>"
	calls, err := ParseToolCalls(content)
	if err == nil {
		t.Fatalf("expected error when fence present but no parsable call, got calls=%+v", calls)
	}
}

// TestExtractTargetDomainIDs_FromResult 固化根因修复：
// 步骤的工具输出（Result）里同样可能携带 domain_id / scan_job_id，
// 旧实现只解析 Detail（入参），导致 start_scan 这类「domain_id 在入参、scan_job_id 在输出」
// 的步骤链无法凑齐目标域名，TargetDomains 为空 -> 平台侧漏洞证据被漏查 ->
// 交付校验「真空满足」静默放行 -> 任务 completed 却零工单（任务 211dbe05）。
func TestExtractTargetDomainIDs_FromResult(t *testing.T) {
	a := newTestAgent()
	steps := []Step{
		// start_scan：domain_id 在入参(Detail)，scan_job_id 在输出(Result)
		mkStepRW("start_scan", "done",
			`{"domain_id":"f0695872-a85d-4309-8794-2bed13b51469"}`,
			`{"domain_id":"f0695872-a85d-4309-8794-2bed13b51469","scan_job_id":"5841fe14-97a2-4942-91b8-906eca57f321","status":"running"}`),
		// list_vulnerabilities：标识只出现在输出
		mkStepRW("list_vulnerabilities", "done",
			`{"domain_id":"f0695872-a85d-4309-8794-2bed13b51469","limit":200}`,
			`{"count":200,"rows":[{"type":"sensitive_file"}]}`),
	}
	got := a.extractTargetDomainIDs(steps)
	if len(got) != 1 || got[0] != "f0695872-a85d-4309-8794-2bed13b51469" {
		t.Fatalf("应从 Detail/Result 中提取到目标域名，实际 %v", got)
	}
}

// TestExtractTargetDomainIDs_ResultOnly 覆盖「domain_id 只出现在 Result」的情形。
func TestExtractTargetDomainIDs_ResultOnly(t *testing.T) {
	a := newTestAgent()
	steps := []Step{
		mkStepRW("wait_scan", "done",
			`{"scan_job_id":"5841fe14","timeout_sec":300}`,
			`{"domain_id":"d-result-only","status":"completed"}`),
	}
	got := a.extractTargetDomainIDs(steps)
	if len(got) != 1 || got[0] != "d-result-only" {
		t.Fatalf("应能从 Result 提取 domain_id，实际 %v", got)
	}
}

// TestMaybeNudgeDeliverableProgress 固化「交付停滞干预」：
// 模型连续多轮只做只读探索（反复 list_domains / start_scan），既无 create_ticket
// 也无 finish_task 时，每轮 assistant 消息都带 <tool_calls>，交付校验永不触发，
// 任务只会以「达到最大轮次上限」失败而工单未建（任务 7755460c）。此时应主动提示。
func TestMaybeNudgeDeliverableProgress(t *testing.T) {
	a := newTestAgent()
	goal := "扫描127.0.0.1:8099靶场的XSS漏洞，只上报这个工单"
	task := &Task{ID: "t-prog", Goal: goal, Contract: a.parseContractIntent(goal)}
	// 模拟反复扫描：只有只读步骤，但确有需建单的发现（weak_password_scan 命中）
	task.Steps = []Step{
		mkStep("list_domains", "done", `{}`),
		mkStep("start_scan", "done", `{"domain_id":"d1"}`),
		mkStep("weak_password_scan", "done", `{"found_count":5}`),
	}

	// 停滞轮数不足 -> 不提示
	if a.maybeNudgeDeliverableProgress(task, deliveryWaitRounds-1) {
		t.Fatalf("未达阈值时不应提示")
	}
	// 达到阈值且有证据 -> 应提示
	if !a.maybeNudgeDeliverableProgress(task, deliveryWaitRounds) {
		t.Fatalf("连续多轮无交付动作且确有发现时应提示")
	}
	if !hasAnyStep(task.Steps, "deliverable_progress") {
		t.Errorf("应记录 deliverable_progress 步骤，实际 %v", stepNames(task.Steps))
	}

	// 已有交付动作 -> 不再提示
	task2 := &Task{ID: "t-prog2", Goal: goal, Contract: a.parseContractIntent(goal)}
	task2.Steps = []Step{
		mkStep("start_scan", "done", `{"domain_id":"d1"}`),
		mkStep("create_ticket", "done", `{"vuln_type":"xss"}`),
	}
	if a.maybeNudgeDeliverableProgress(task2, deliveryWaitRounds) {
		t.Fatalf("已存在建单动作时不应重复提示")
	}
}

// TestCallSignature 验证调用签名：同参同工具签名一致，入参不同则不同（map 序列化按键排序）。
func TestCallSignature(t *testing.T) {
	c1 := ToolCall{Name: "start_scan", Arguments: map[string]any{"domain_id": "d1", "limit": 10}}
	c2 := ToolCall{Name: "start_scan", Arguments: map[string]any{"limit": 10, "domain_id": "d1"}}
	c3 := ToolCall{Name: "start_scan", Arguments: map[string]any{"domain_id": "d2", "limit": 10}}
	if callSignature(c1) != callSignature(c2) {
		t.Errorf("入参键顺序不同但内容相同，签名应一致: %q vs %q", callSignature(c1), callSignature(c2))
	}
	if callSignature(c1) == callSignature(c3) {
		t.Errorf("入参不同，签名应不同")
	}
}

// TestMaybeNudgeRepeatedCalls 验证重复调用干预：
// 任务 7755460c 的失败形态——start_scan 以完全相同的入参执行 5 次，最终撞上轮次上限。
func TestMaybeNudgeRepeatedCalls(t *testing.T) {
	a := newTestAgent()
	task := &Task{ID: "t-dup", Goal: "扫描127.0.0.1:8099靶场的XSS漏洞"}
	counts := map[string]int{}
	warned := map[string]bool{}

	sig := callSignature(ToolCall{Name: "start_scan", Arguments: map[string]any{"domain_id": "d1"}})

	// 未达阈值 -> 不提示
	counts[sig] = duplicateCallThreshold - 1
	if a.maybeNudgeRepeatedCalls(task, counts, warned) {
		t.Fatalf("未达重复阈值时不应提示")
	}

	// 达到阈值 -> 应提示，并记录 duplicate_call 步骤
	counts[sig] = duplicateCallThreshold
	if !a.maybeNudgeRepeatedCalls(task, counts, warned) {
		t.Fatalf("同参重复调用达到阈值时应提示")
	}
	if !hasAnyStep(task.Steps, "duplicate_call") {
		t.Errorf("应记录 duplicate_call 步骤，实际 %v", stepNames(task.Steps))
	}
	last := task.Steps[len(task.Steps)-1]
	if !strings.Contains(last.Result, "start_scan") {
		t.Errorf("提示内容应指出被重复调用的工具名，实际: %s", last.Result)
	}

	// 同一签名只提示一次，避免反复打扰
	n := len(task.Steps)
	counts[sig] = duplicateCallThreshold + 5
	if a.maybeNudgeRepeatedCalls(task, counts, warned) {
		t.Fatalf("同一签名已提示过，不应重复提示")
	}
	if len(task.Steps) != n {
		t.Errorf("重复提示不应新增步骤")
	}

	// 不同入参的同名工具不算重复
	task2 := &Task{ID: "t-dup2", Goal: "g"}
	counts2 := map[string]int{
		callSignature(ToolCall{Name: "start_scan", Arguments: map[string]any{"domain_id": "d1"}}): 1,
		callSignature(ToolCall{Name: "start_scan", Arguments: map[string]any{"domain_id": "d2"}}): 1,
	}
	warned2 := map[string]bool{}
	if a.maybeNudgeRepeatedCalls(task2, counts2, warned2) {
		t.Fatalf("入参不同的同名调用不应判定为重复")
	}
}

// TestHadDeliveryAction 验证交付动作识别（同一轮多工具时只看尾部若干步）。
func TestHadDeliveryAction(t *testing.T) {
	a := newTestAgent()
	task := &Task{ID: "t-hd", Goal: "g"}
	task.Steps = []Step{
		mkStep("list_domains", "done", `{}`),
		mkStep("create_ticket", "done", `{"vuln_type":"xss"}`),
		mkStep("list_tickets", "done", `{}`),
	}
	if !a.hadDeliveryAction(task) {
		t.Errorf("尾部若干步内存在 create_ticket 应识别为交付动作")
	}
	task2 := &Task{ID: "t-hd2", Goal: "g"}
	task2.Steps = []Step{
		mkStep("list_domains", "done", `{}`),
		mkStep("start_scan", "done", `{"domain_id":"d1"}`),
	}
	if a.hadDeliveryAction(task2) {
		t.Errorf("仅只读步骤不应识别为交付动作")
	}
}

// stepNames 取步骤名列表，便于断言输出。
func stepNames(steps []Step) []string {
	out := make([]string, 0, len(steps))
	for _, s := range steps {
		out = append(out, s.Name)
	}
	return out
}

// TestParseToolCallsSkipsMalformedBlock 验证：某个块 JSON 损坏时整体不应失败，
// 应跳过坏块、保留好块，而非整批丢弃（旧逻辑 FindStringSubmatch 只取第一块且坏块直接报错）。
func TestParseToolCallsSkipsMalformedBlock(t *testing.T) {
	content := "<tool_calls>\n[{\"name\":\"create_ticket\",\"arguments\":{BROKEN}}]\n</tool_calls>\n" +
		"<tool_calls>\n[{\"name\":\"create_inspection_rule\",\"arguments\":{\"schedule\":\"0 16 * * *\"}}]\n</tool_calls>"
	calls, err := ParseToolCalls(content)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(calls) != 1 {
		t.Fatalf("expected 1 valid call (malformed block skipped), got %d: %+v", len(calls), calls)
	}
	if !strings.Contains(calls[0].Name, "create_inspection_rule") {
		t.Fatalf("expected the good block's call, got %+v", calls)
	}
}
