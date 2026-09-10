package agent

import (
	"fmt"
	"strings"
)

// sliceContains 判断字符串切片是否包含指定元素。
func sliceContains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// DeliverableContract 是任务目标的「结构化交付契约」：把自然语言目标解析为机器可校验的
// 交付义务集合，任务终止时由 enforceDeliverables / reconcileFinishClaim 按契约逐项校验，
// 彻底取代原先散落在多处、基于目标串关键词硬编码的判定逻辑。
//
// 生命周期：
//   - 任务启动时由 parseContractIntent 解析目标串生成「意图」部分（写入 task.Contract）；
//   - 终止校验时由 resolveContract 结合已执行步骤补全 TargetDomains，得到完整契约。
type DeliverableContract struct {
	NeedsTicket      bool     `json:"needs_ticket"`      // 目标是否要求提交工单/建单
	TicketCategories []string `json:"ticket_categories"` // 用户点名的建单语义类别（弱口令/数据泄露）；为空表示「全部需建单类别」
	Exclusive        bool     `json:"exclusive"`         // 排他模式：仅 TicketCategories 要求建单，其余（即使确有发现）一律视为「用户已要求忽略」，不阻塞收尾
	NeedsRule        bool     `json:"needs_rule"`        // 目标是否要求定时/每天/日常巡检
	Schedule         string   `json:"schedule"`          // 解析出的 cron（如 "0 16 * * *"）；空表示「任意周期/未指定时刻」
	TargetHost       string   `json:"target_host"`       // 目标资产文本（host 或 host:port），用于与工单 asset 对齐
	TargetDomains    []string `json:"target_domains"`    // 本运行实际涉及的目标域名 id（由步骤反查，校验时补全）
}

// knownContractCategories 是所有已知建单语义类别（与 vulnTypeToCategory 对齐）。
// 凡是确有的发现类别，用户未显式排除时都应建单 —— 这是「禁止因分类失败而漏单」的契约层保障。
var knownContractCategories = []string{
	catWeakPassword, catDataLeak,
	catInjection, catAuthConfig, catComponent, catLogic, catInfoLeak, catWebshell, catOther,
}

// parseContractIntent 仅解析目标串中的「意图」，不涉及运行期步骤。在任务启动、目标确定后调用一次。
// 这里集中承载原先分散在 unmetDeliverables / ticketDeliverableSatisfied / ruleDeliverableSatisfied 中的
// 关键词判定，使「用户到底要求了什么」成为单一可信来源。
func (a *Agent) parseContractIntent(goal string) *DeliverableContract {
	c := &DeliverableContract{}
	needsTicket := strings.Contains(goal, "工单") || strings.Contains(goal, "建单")
	// 周期巡检意图：覆盖「每天/每日/每周/每月/定时/定期/周期/每隔」等多种自然语言表述，
	// 以及「日常巡检」这类组合说法；同时排除「就扫一次 / 只扫一次」等一次性意图，
	// 避免把一次性扫描误判为需要建立周期规则。
	recurrenceKW := []string{"每天", "每日", "每周", "每月", "每小时", "定时", "定期", "周期", "每隔", "循环"}
	oneShotKW := []string{"就扫一次", "只扫一次", "仅扫一次", "扫一次即可", "一次性"}
	needsRule := false
	for _, kw := range recurrenceKW {
		if strings.Contains(goal, kw) {
			needsRule = true
			break
		}
	}
	if !needsRule && containsStr(goal, "日常") && containsStr(goal, "巡检") {
		needsRule = true
	}
	if needsRule {
		for _, kw := range oneShotKW {
			if strings.Contains(goal, kw) {
				needsRule = false
				break
			}
		}
	}
	c.NeedsTicket = needsTicket
	c.NeedsRule = needsRule
	if needsTicket {
		c.TicketCategories = parseRequestedCategories(goal)
		// 排他模式识别：用户要求「只上报 X」「仅上报 X」「只看 X」或「其他忽略 / 忽略其他 / 全部忽略 /
		// 判为误报 / 直接判为误报」时，除点名类别外的一切发现都视为用户已明确要求忽略，
		// 不应因此类发现未建单而阻塞 finish_task（此前「只上报 webshell 工单，其他忽略」会因
		// webshell 被误归入数据泄露、且敏感文件确有发现而陷入 deliverable_check 死循环）。
		gl := strings.ToLower(goal)
		if containsAny(gl, []string{
			"只上报", "只报告", "只建", "只提交", "只扫描", "只查", "只看", "只建单",
			"仅上报", "仅报告", "仅建", "仅提交", "仅扫描", "仅查", "仅看", "仅建单",
			"其他忽略", "其余忽略", "其它忽略", "忽略其他", "忽略其余", "忽略其它",
			"其他问题全部忽略", "全部忽略", "其他一律忽略", "其余一律忽略",
			"判为误报", "直接判为误报", "判误报", "误报", "当作误报", "视为误报",
		}) {
			c.Exclusive = true
		}
	}
	if needsRule {
		if h, m, ok := extractRequestedTime(goal); ok {
			c.Schedule = fmt.Sprintf("%d %d * * *", m, h)
		}
	}
	c.TargetHost = a.extractTargetHost(goal)
	return c
}

// parseRequestedCategories 从目标串抽取用户点名的建单类别。
// 若明确点名（如「弱口令」「数据泄露」「注入」），则只列点名类别（配合「其他漏洞可忽略」收窄范围）；
// 若仅泛泛要求「提交工单」而未点名，则返回全部已知类别（与原行为一致：任何发现都需建单）。
func parseRequestedCategories(goal string) []string {
	g := strings.ToLower(goal)
	var cats []string
	if containsAny(g, []string{"弱口令", "弱密码", "weak"}) {
		cats = append(cats, catWeakPassword)
	}
	// 注意：webshell / 后门 / 木马 / 恶意文件 不在数据泄露桶内 —— 此前误把它们并入 data_leak，
	// 导致「只上报 webshell 工单」被解析为「要求数据泄露工单」，与敏感文件确有发现叠加后陷入死循环。
	if containsAny(g, []string{"数据泄露", "数据泄漏", "敏感", "泄露", "sensitive"}) {
		cats = append(cats, catDataLeak)
	}
	if containsAny(g, []string{"webshell", "后门", "木马", "恶意文件", "malicious", "backdoor", "webshell文件"}) {
		cats = append(cats, catWebshell)
	}
	if containsAny(g, []string{"注入", "sql注入", "命令注入", "sqli", "xss", "ssti", "xxe", "injection", "注入类"}) {
		cats = append(cats, catInjection)
	}
	if containsAny(g, []string{"权限", "越权", "认证", "配置错误", "配置不当", "配置错误", "misconfiguration", "ssrf", "csrf", "访问控制", "权限与配置"}) {
		cats = append(cats, catAuthConfig)
	}
	if containsAny(g, []string{"组件", "依赖", "第三方组件", "vulnerable", "已知漏洞组件", "依赖组件"}) {
		cats = append(cats, catComponent)
	}
	if containsAny(g, []string{"逻辑", "业务逻辑", "逻辑缺陷", "文件上传", "反序列化"}) {
		cats = append(cats, catLogic)
	}
	if containsAny(g, []string{"信息泄露", "信息披露", "目录遍历", "路径遍历", "报错泄露"}) {
		cats = append(cats, catInfoLeak)
	}
	if len(cats) == 0 {
		// 未点名具体类别：默认覆盖全部需建单类别（含未知类型，禁止漏单）
		cats = append(cats, knownContractCategories...)
	}
	return cats
}

// resolveContract 在终止校验时调用：合并启动时解析的意图与运行期步骤反查出的目标域名，得到完整契约。
func (a *Agent) resolveContract(task *Task) *DeliverableContract {
	task.mu.Lock()
	base := task.Contract
	steps := make([]Step, len(task.Steps))
	copy(steps, task.Steps)
	task.mu.Unlock()
	if base == nil {
		base = &DeliverableContract{}
	}
	c := *base
	c.TargetDomains = a.extractTargetDomainIDs(steps)
	if c.TargetHost == "" {
		c.TargetHost = a.extractTargetHost(task.Goal)
	}
	return &c
}

// snapshotSteps 在锁内拷贝当前步骤，供终止校验/对账使用，避免与写入协程竞争。
func (a *Agent) snapshotSteps(task *Task) []Step {
	task.mu.Lock()
	defer task.mu.Unlock()
	steps := make([]Step, len(task.Steps))
	copy(steps, task.Steps)
	return steps
}

// reconcileFinishClaim 对账「模型自述的交付」与「任务步骤中的事实」：若模型在 finish_task 摘要中
// 声称已完成某交付（建单 / 建规则），但步骤中并无对应成功记录，则判定为「假完成」并返回纠正信息，
// 由调用方打回重做。
//
// 关键：仅当该交付义务确实未满足时才拦截（已满足，含安全阀兜底已补建的情形，则不拦截），
// 以避免模型措辞差异（如「已创建每日16:00巡检规则」与规则名不完全一致）导致无限打回。
func (a *Agent) reconcileFinishClaim(contract *DeliverableContract, summary string, steps []Step) (bool, string) {
	low := strings.ToLower(summary)
	claimsTicket := containsAny(low, []string{"已提交工单", "已建单", "已创建工单", "工单已", "已开单", "工单创建", "已生成工单"})
	claimsRule := containsAny(low, []string{"已创建巡检规则", "已建巡检规则", "已配置巡检", "巡检规则已", "已添加巡检规则", "已设置定时巡检", "已创建每日", "已建每日"})

	if contract.NeedsTicket && claimsTicket {
		if !a.ticketDeliverableSatisfied(contract, steps, contract.TargetDomains, contract.TargetHost) {
			return true, "你在 finish_task 结论中声称「已提交/创建工单」，但任务步骤中并无成功建单记录，且目标资产确有需建单的发现（弱口令/数据泄露）。请勿虚构交付——请实际调用 create_ticket 完成工单后再次 finish_task；若确无相关发现，请在结论中明确说明「未发现需建单项」，不要声称已建单。"
		}
	}
	if contract.NeedsRule && claimsRule {
		if !a.ruleDeliverableSatisfied(contract, steps, contract.TargetDomains) {
			return true, "你在 finish_task 结论中声称「已创建巡检规则」，但步骤中并无成功的 create_inspection_rule 记录，平台上也无覆盖该资产、cron 一致的启用规则。请勿虚构交付——请实际调用 create_inspection_rule 配置 cron 后再次 finish_task；若平台已有同域同 cron 的启用规则，请在结论中说明其 rule_id。"
		}
	}
	return false, ""
}
