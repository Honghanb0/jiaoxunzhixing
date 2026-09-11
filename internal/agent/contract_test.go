package agent

import (
	"fmt"
	"sync"
	"testing"
)

// ---------------- 内存桩：taskRepository ----------------

type fakeTaskRepo struct {
	mu    sync.Mutex
	tasks map[string]*Task
	steps map[string][]*Step
}

func newFakeTaskRepo() *fakeTaskRepo {
	return &fakeTaskRepo{tasks: map[string]*Task{}, steps: map[string][]*Step{}}
}

func (f *fakeTaskRepo) Create(t *Task) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tasks[t.ID] = t
	return nil
}
func (f *fakeTaskRepo) Update(t *Task) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tasks[t.ID] = t
	return nil
}
func (f *fakeTaskRepo) AppendStep(taskID string, step *Step) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.steps[taskID] = append(f.steps[taskID], step)
	return nil
}
func (f *fakeTaskRepo) UpdateStep(taskID, stepID string, status StepStatus, result string) error {
	return nil
}
func (f *fakeTaskRepo) Get(id string) (*Task, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if t, ok := f.tasks[id]; ok {
		return t, nil
	}
	return nil, fmt.Errorf("not found")
}
func (f *fakeTaskRepo) List(limit int) ([]*Task, error) { return nil, nil }

// newTestAgent 构造一个无外部依赖的 Agent，便于单测交付校验逻辑。
func newTestAgent() *Agent {
	return &Agent{deps: Deps{}, repo: newFakeTaskRepo(), maxTurns: 10}
}

// mkStep 构造一个测试步骤。
// 注意：生产代码对 Detail / Result 的读取位置不同——
//   - createTicketStepCovers 从 Detail 解析工具入参（vuln_type / asset_url ...）
//   - findingCategories 从 Result 解析工具输出（found_count ...）
//
// 因此测试助手把同一段 JSON 同时写入两个字段，使两类断言都能读到，
// 且 Result 不以「工具执行异常」开头，doneTool 才会认为步骤执行成功。
func mkStep(name, status, detail string) Step {
	return Step{ID: "s-" + name, Name: name, Status: StepStatus(status), Detail: detail, Result: detail}
}

// mkStepRW 在需要区分「入参」与「输出」时使用。
func mkStepRW(name, status, detail, result string) Step {
	return Step{ID: "s-" + name, Name: name, Status: StepStatus(status), Detail: detail, Result: result}
}

// ---------------- 1) 交付契约解析 ----------------

func TestParseContractIntent(t *testing.T) {
	cases := []struct {
		goal       string
		wantTicket bool
		wantRule   bool
		wantCats   []string
		wantSched  string
		wantHost   string
	}{
		{
			goal:       "对127.0.0.1:8099扫描，重点排查弱口令和数据泄露，务必提交相关工单",
			wantTicket: true,
			wantCats:   []string{catWeakPassword, catDataLeak},
			wantHost:   "127.0.0.1:8099",
		},
		{
			goal:      "这次扫好后每天16:00都要日常巡检扫描",
			wantRule:  true,
			wantSched: "0 16 * * *",
		},
		{
			goal:       "提交工单", // 未点名类别 -> 覆盖全部需建单类别
			wantTicket: true,
			wantCats:   []string{catWeakPassword, catDataLeak},
		},
		{
			goal: "普通查询域名列表", // 无交付意图
		},
	}
	a := newTestAgent()
	for _, c := range cases {
		contract := a.parseContractIntent(c.goal)
		if contract.NeedsTicket != c.wantTicket {
			t.Errorf("goal=%q NeedsTicket=%v want %v", c.goal, contract.NeedsTicket, c.wantTicket)
		}
		if contract.NeedsRule != c.wantRule {
			t.Errorf("goal=%q NeedsRule=%v want %v", c.goal, contract.NeedsRule, c.wantRule)
		}
		if c.wantSched != "" && contract.Schedule != c.wantSched {
			t.Errorf("goal=%q Schedule=%q want %q", c.goal, contract.Schedule, c.wantSched)
		}
		if c.wantHost != "" && contract.TargetHost != c.wantHost {
			t.Errorf("goal=%q TargetHost=%q want %q", c.goal, contract.TargetHost, c.wantHost)
		}
		for _, w := range c.wantCats {
			if !sliceContains(contract.TicketCategories, w) {
				t.Errorf("goal=%q TicketCategories=%v missing %q", c.goal, contract.TicketCategories, w)
			}
		}
	}
}

// TestParseContractIntent_WebshellExclusive 复现 task 82f62699 卡死根因：
// 目标「只上报 webshell 工单，其他问题全部忽略或者直接判为误报」应被解析为
// 排他模式、点名类别仅 webshell（绝非 data_leak），从而不会因敏感文件确有发现而强制要求建单。
func TestParseContractIntent_WebshellExclusive(t *testing.T) {
	a := newTestAgent()
	goal := "扫描127.0.0.1:8099靶场的webshell漏洞，只上报这个工单，其他问题全部忽略或者直接判为误报"
	c := a.parseContractIntent(goal)
	if !c.NeedsTicket {
		t.Fatalf("NeedsTicket=false, want true")
	}
	if !c.Exclusive {
		t.Errorf("Exclusive=false, want true（用户要求「只上报 / 其他忽略 / 判为误报」）")
	}
	// 关键：webshell 绝不能落入 data_leak 桶，否则会因敏感文件确有发现而死循环。
	if sliceContains(c.TicketCategories, catDataLeak) {
		t.Errorf("TicketCategories 误含 data_leak: %v（webshell 不应并入数据泄露）", c.TicketCategories)
	}
	if !sliceContains(c.TicketCategories, catWebshell) {
		t.Errorf("TicketCategories 应含 webshell: %v", c.TicketCategories)
	}
	if c.TargetHost != "127.0.0.1:8099" {
		t.Errorf("TargetHost=%q want 127.0.0.1:8099", c.TargetHost)
	}
}

// TestTicketDeliverableSatisfied_ExclusiveIgnoresOthers 验证：排他模式下，即使目标资产确有
// 敏感文件(data_leak)/XSS(injection) 等「其他」发现，只要点名类别(webshell)无发现，交付即满足，
// 不会因非点名类别未建单而阻塞 finish_task（这正是 82f62699 卡死的根因）。
func TestTicketDeliverableSatisfied_ExclusiveIgnoresOthers(t *testing.T) {
	a := newTestAgent()
	// 模拟平台状态：目标资产确有敏感文件(XSS 等)——对应 data_leak / injection 发现。
	a.deps.VulnLister = func(domainID string, limit int) (string, error) {
		return `{"rows":[{"type":"sensitive_file","name":".env"},{"type":"xss","name":"x"}]}`, nil
	}
	contract := &DeliverableContract{
		NeedsTicket:      true,
		TicketCategories: []string{catWebshell}, // 用户只点名 webshell
		Exclusive:        true,                  // 其他忽略 / 判为误报
	}
	steps := []Step{} // 本运行未建任何工单
	sat := a.ticketDeliverableSatisfied(contract, steps, []string{"d1"}, "127.0.0.1:8099")
	if !sat {
		t.Errorf("排他模式下，点名类别(webshell)无发现时交付应视为满足（其他发现被忽略），实际未满足")
	}

	// 反例：非排他模式（默认），点名类别缺省为全部，data_leak 有发现且无工单 -> 未满足。
	contractNE := &DeliverableContract{
		NeedsTicket:      true,
		TicketCategories: []string{catWeakPassword, catDataLeak, catInjection, catAuthConfig, catComponent, catLogic, catInfoLeak, catWebshell, catOther},
		Exclusive:        false,
	}
	if a.ticketDeliverableSatisfied(contractNE, steps, []string{"d1"}, "127.0.0.1:8099") {
		t.Errorf("非排他模式下，data_leak 有发现且无工单时交付应未满足")
	}
}

// ---------------- 2) findingCategories ----------------

func TestFindingCategories(t *testing.T) {
	a := newTestAgent()

	// (a) 会话证据：弱口令探测命中
	steps := []Step{mkStep("weak_password_scan", "done", `{"found_count":3}`)}
	cats := a.findingCategories(steps, nil)
	if !cats[catWeakPassword] {
		t.Errorf("期望含 weak_password，实际 %v", cats)
	}

	// (b) 平台状态：敏感文件漏洞（经可注入 VulnLister，无需真实 Neo4j）
	a2 := newTestAgent()
	a2.deps.VulnLister = func(domainID string, limit int) (string, error) {
		return `{"rows":[{"type":"sensitive_file","name":".env","url":"http://x/.env"},{"type":"xss","name":"x"}]}`, nil
	}
	cats2 := a2.findingCategories(nil, []string{"d1"})
	if !cats2[catDataLeak] {
		t.Errorf("期望含 data_leak，实际 %v", cats2)
	}

	// (c) 无任何证据 -> 空
	empty := a.findingCategories(nil, nil)
	if len(empty) != 0 {
		t.Errorf("期望无类别，实际 %v", empty)
	}
}

// ---------------- 3) enforceDeliverables ----------------

func TestEnforceDeliverables_Vacuous(t *testing.T) {
	a := newTestAgent()
	task := &Task{ID: "t1", Goal: "提交工单", Contract: a.parseContractIntent("提交工单")}
	// 无发现、无步骤 -> 真空满足，应返回 enforceSatisfied（无需补齐）
	if a.enforceDeliverables(task) != enforceSatisfied {
		t.Errorf("真空满足时应返回 enforceSatisfied（无未满足交付）")
	}
}

func TestEnforceDeliverables_Nudge(t *testing.T) {
	a := newTestAgent()
	goal := "对127.0.0.1:8099扫描，重点排查弱口令，务必提交工单"
	task := &Task{ID: "t2", Goal: goal, Contract: a.parseContractIntent(goal)}
	// 有弱口令发现但无建单步骤 -> 应退回（nudge），返回 enforceNudged
	task.Steps = []Step{mkStep("weak_password_scan", "done", `{"found_count":2}`)}
	if a.enforceDeliverables(task) != enforceNudged {
		t.Fatalf("应退回补齐，返回 enforceNudged")
	}
	// 记一次 deliverable_check
	if got := a.deliverableNudgeCount(task); got != 1 {
		t.Errorf("nudge 计数=%d 期望 1", got)
	}
}

func TestEnforceDeliverables_SatisfiedByStep(t *testing.T) {
	a := newTestAgent()
	goal := "对127.0.0.1:8099扫描，重点排查弱口令，务必提交工单"
	task := &Task{ID: "t3", Goal: goal, Contract: a.parseContractIntent(goal)}
	task.Steps = []Step{
		mkStep("weak_password_scan", "done", `{"found_count":2}`),
		mkStep("create_ticket", "done", `{"vuln_type":"weak_password","asset_url":"127.0.0.1:8099"}`),
	}
	if a.enforceDeliverables(task) != enforceSatisfied {
		t.Errorf("已有覆盖本资产的建单步骤，应返回 enforceSatisfied（已满足）")
	}
}

func TestEnforceDeliverables_SafetyValve(t *testing.T) {
	a := newTestAgent()
	goal := "对127.0.0.1:8099扫描，重点排查弱口令，务必提交工单"
	task := &Task{ID: "t4", Goal: goal, Contract: a.parseContractIntent(goal)}
	task.Steps = []Step{mkStep("weak_password_scan", "done", `{"found_count":2}`)}

	// 计数在校验之后才自增，因此前 5 次均为 nudge，任务不得被收尾。
	for i := 1; i <= 5; i++ {
		if a.enforceDeliverables(task) != enforceNudged {
			t.Fatalf("第 %d 次校验应退回补齐，返回 enforceNudged", i)
		}
		if task.Status == TaskStatusCompleted {
			t.Fatalf("第 %d 次校验不应收尾任务", i)
		}
		if got := a.deliverableNudgeCount(task); got != i {
			t.Fatalf("第 %d 次后 nudge 计数=%d 期望 %d", i, got, i)
		}
	}
	// 第 6 次：nudge 计数已达 5 触发安全阀。本测试未注入 TicketRepo/RuleRepo，
	// 自动补建会跳过，因此应强制收尾为 completed 并写明未满足交付。
	if a.enforceDeliverables(task) != enforceSafetyValveFired {
		t.Fatalf("第 6 次应触发安全阀强制收尾，返回 enforceSafetyValveFired")
	}
	if task.Status != TaskStatusCompleted {
		t.Errorf("安全阀收尾后任务状态=%q 期望 %q", task.Status, TaskStatusCompleted)
	}
	if task.Result == "" {
		t.Errorf("安全阀收尾应把未满足交付写入任务结果")
	}
}

// 建单工具调用失败（Result 以「工具执行异常」开头）不得被当成已交付。
func TestEnforceDeliverables_FailedTicketStepNotSatisfied(t *testing.T) {
	a := newTestAgent()
	goal := "对127.0.0.1:8099扫描，重点排查弱口令，务必提交工单"
	task := &Task{ID: "t5", Goal: goal, Contract: a.parseContractIntent(goal)}
	task.Steps = []Step{
		mkStep("weak_password_scan", "done", `{"found_count":2}`),
		mkStepRW("create_ticket", "done",
			`{"vuln_type":"weak_password","asset_url":"127.0.0.1:8099"}`,
			"工具执行异常: connection refused"),
	}
	if a.enforceDeliverables(task) != enforceNudged {
		t.Errorf("建单步骤执行失败时不应视为已交付，应退回补齐")
	}
}

// ---------------- 4) 假完成对账 ----------------

func TestReconcileFinishClaim_FakeTicket(t *testing.T) {
	a := newTestAgent()
	goal := "对127.0.0.1:8099扫描，重点排查弱口令，务必提交工单"
	contract := a.parseContractIntent(goal)
	steps := []Step{mkStep("weak_password_scan", "done", `{"found_count":2}`)}
	// 模型声称已建单，但步骤无 create_ticket -> 假完成，应打回
	bad, msg := a.reconcileFinishClaim(contract, "已提交工单，发现弱口令命中", steps)
	if !bad {
		t.Errorf("应识别假完成（声称建单但无步骤）")
	}
	if msg == "" {
		t.Errorf("纠正信息不应为空")
	}
}

func TestReconcileFinishClaim_HonestTicket(t *testing.T) {
	a := newTestAgent()
	goal := "对127.0.0.1:8099扫描，重点排查弱口令，务必提交工单"
	contract := a.parseContractIntent(goal)
	steps := []Step{
		mkStep("weak_password_scan", "done", `{"found_count":2}`),
		mkStep("create_ticket", "done", `{"vuln_type":"weak_password","asset_url":"127.0.0.1:8099"}`),
	}
	bad, _ := a.reconcileFinishClaim(contract, "已提交工单，发现弱口令命中", steps)
	if bad {
		t.Errorf("已有真实建单步骤，不应判为假完成")
	}
}

func TestReconcileFinishClaim_FakeRule(t *testing.T) {
	a := newTestAgent()
	goal := "这次扫好后每天16:00都要日常巡检扫描"
	contract := a.parseContractIntent(goal)
	// 仅 claim，无 create_inspection_rule 步骤
	bad, _ := a.reconcileFinishClaim(contract, "已创建每日16:00巡检规则", nil)
	if !bad {
		t.Errorf("应识别假完成（声称建规则但无步骤）")
	}
	// 有真实步骤则通过
	steps := []Step{mkStep("create_inspection_rule", "done", `{"rule_id":"r1"}`)}
	if bad2, _ := a.reconcileFinishClaim(contract, "已创建每日16:00巡检规则", steps); bad2 {
		t.Errorf("已有真实建规则步骤，不应判为假完成")
	}
}

// ---------------- 5) ruleDeliverableSatisfied ----------------

func TestRuleDeliverableSatisfied(t *testing.T) {
	a := newTestAgent()
	goal := "这次扫好后每天16:00都要日常巡检扫描"
	contract := a.parseContractIntent(goal)

	// 无步骤、无平台规则（nil RuleRepo）-> 未满足
	if a.ruleDeliverableSatisfied(contract, nil, nil) {
		t.Errorf("无步骤且无平台规则时应未满足")
	}
	// 本运行已有 create_inspection_rule 步骤 -> 满足
	if !a.ruleDeliverableSatisfied(contract, []Step{mkStep("create_inspection_rule", "done", `{"rule_id":"r1"}`)}, nil) {
		t.Errorf("本运行已建规则步骤时应满足")
	}
}

// ---------------- 6) ParseToolCalls 补充覆盖 ----------------

func TestParseToolCallsSingleObject(t *testing.T) {
	content := "<tool_calls>\n{\"name\":\"get_stats\",\"arguments\":{}}\n</tool_calls>"
	calls, err := ParseToolCalls(content)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(calls) != 1 || calls[0].Name != "get_stats" {
		t.Fatalf("期望单条 get_stats，实际 %+v", calls)
	}
}

func TestParseToolCallsBareJSON(t *testing.T) {
	// 无 <tool_calls> 围栏的裸 JSON 数组也应能解析（部分模型可能省略围栏）
	content := `[{"name":"start_scan","arguments":{"domain_id":"x"}}]`
	calls, err := ParseToolCalls(content)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(calls) != 1 || calls[0].Name != "start_scan" {
		t.Fatalf("期望单条 start_scan，实际 %+v", calls)
	}
}
