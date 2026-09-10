package inspection

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/robfig/cron/v3"
	"security-agent/internal/ai"
	"security-agent/internal/config"
	"security-agent/internal/models"
	"security-agent/internal/scanner"
	"security-agent/internal/storage"
)

// AlertSender 失败告警发送接口（用接口而非具体 *scheduler.AlertService，避免包循环依赖）。
type AlertSender interface {
	SendAlert(alert *models.Alert) error
}

// Runner 巡检编排器：把“规则 → 扫描 → AI 分析 → 结构化结果 → 持久化”串成一次自动巡检，
// 并负责重试、失败告警与全程日志。被调度器（定时/手动）触发。
type Runner struct {
	engine      *scanner.Engine
	aiMgr       *ai.Manager
	ruleRepo    *storage.InspectionRuleRepository
	recordRepo  *storage.InspectionRecordRepository
	domainRepo  *storage.DomainRepository
	scanJobRepo *storage.ScanJobRepository
	vulnRepo    *storage.VulnerabilityRepository
	sensRepo    *storage.SensitiveInfoRepository
	ticketRepo  *storage.TicketRepository
	alertSender AlertSender
	cfg         *config.SchedulerConfig
}

func NewRunner(
	engine *scanner.Engine,
	aiMgr *ai.Manager,
	ruleRepo *storage.InspectionRuleRepository,
	recordRepo *storage.InspectionRecordRepository,
	domainRepo *storage.DomainRepository,
	scanJobRepo *storage.ScanJobRepository,
	vulnRepo *storage.VulnerabilityRepository,
	sensRepo *storage.SensitiveInfoRepository,
	ticketRepo *storage.TicketRepository,
	alertSender AlertSender,
	cfg *config.SchedulerConfig,
) *Runner {
	return &Runner{
		engine: engine, aiMgr: aiMgr, ruleRepo: ruleRepo, recordRepo: recordRepo,
		domainRepo: domainRepo, scanJobRepo: scanJobRepo, vulnRepo: vulnRepo,
		sensRepo: sensRepo, ticketRepo: ticketRepo, alertSender: alertSender, cfg: cfg,
	}
}

// Engine 暴露底层扫描引擎（供调度器复用，避免重复持有）。
func (r *Runner) Engine() *scanner.Engine { return r.engine }

// Run 准备并异步执行一次巡检，立即返回记录 ID（供手动触发接口快速响应）。
// 定时触发时 triggeredBy=InspectionTriggerSchedule；手动触发时为 InspectionTriggerManual。
// 多资产规则会对每个绑定域名分别生成巡检记录并并发执行，返回首条记录 ID（其余记录可在列表查看）。
func (r *Runner) Run(rule *models.InspectionRule, triggeredBy string) string {
	domainIDs := rule.EffectiveDomainIDs()
	if len(domainIDs) == 0 {
		// 没有可巡检的域名：仍创建一条失败记录，便于用户感知
		rec := r.prepareForDomain(rule, "", triggeredBy)
		go r.execute(rec, rule, "", triggeredBy)
		return rec.ID
	}
	var firstID string
	// 限制单条多资产规则的最大并发巡检数，避免瞬时大量并发扫描/AI 调用拖垮
	// Neo4j 连接池（默认 50）或触发 AI 供应商限流。
	const maxConcurrentInspections = 3
	sem := make(chan struct{}, maxConcurrentInspections)
	for _, did := range domainIDs {
		rec := r.prepareForDomain(rule, did, triggeredBy)
		if firstID == "" {
			firstID = rec.ID
		}
		sem <- struct{}{}
		go func(rec *models.InspectionRecord, did string) {
			defer func() { <-sem }()
			r.execute(rec, rule, did, triggeredBy)
		}(rec, did)
	}
	return firstID
}

// RecoverStaleRecords 进程启动时回收可能僵死的巡检记录。
// 服务重启会直接杀掉进行中的 execute goroutine，对应记录会永远停在 running/analyzing，
// 必须在此将其回收为 failed，否则前端会一直显示“运行中/分析中”。
func (r *Runner) RecoverStaleRecords(maxAge time.Duration) {
	n, err := r.recordRepo.MarkStaleRunning(maxAge, models.InspectionStatusFailed)
	if err != nil {
		log.Printf("[Inspection] 回收僵死巡检记录失败: %v", err)
		return
	}
	if n > 0 {
		log.Printf("[Inspection] 已回收 %d 条僵死巡检记录（running/analyzing → failed）", n)
	}
}

// prepareForDomain 为单个域名创建“运行中”的巡检记录，并写回规则的 last_run_at。
func (r *Runner) prepareForDomain(rule *models.InspectionRule, domainID, triggeredBy string) *models.InspectionRecord {
	now := time.Now()
	domainName := ""
	if domainID != "" {
		if d, err := r.domainRepo.GetByID(domainID); err == nil && d != nil {
			domainName = d.Name
		}
	}

	rec := &models.InspectionRecord{
		RuleID:      rule.ID,
		RuleName:    rule.Name,
		DomainID:    domainID,
		DomainName:  domainName,
		TriggeredBy: triggeredBy,
		Status:      models.InspectionStatusRunning,
		StartedAt:   now,
		CreatedAt:   now,
	}
	if err := r.recordRepo.Create(rec); err != nil {
		log.Printf("[Inspection] 创建巡检记录失败(rule=%s domain=%s): %v", rule.ID, domainID, err)
	}

	// 写回最近执行时间（next_run_at 由 execute 在结束时计算）
	_ = r.ruleRepo.UpdateRunTimes(rule.ID, &now, nil)
	return rec
}

// execute 巡检主体：扫描 → AI → 解析 → 持久化。任何 panic 都会被兜底为“失败”记录。
func (r *Runner) execute(rec *models.InspectionRecord, rule *models.InspectionRule, domainID, triggeredBy string) {
	defer func() {
		if p := recover(); p != nil {
			log.Printf("[Inspection] %s 执行异常: %v", rec.ID, p)
			r.finalizeFailure(rec, rule, fmt.Sprintf("内部错误: %v", p))
		}
	}()

	timeout := r.inspectionTimeout()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	log.Printf("[Inspection] 开始巡检 rule=%s(%s) domain=%s 触发=%s 超时=%v",
		rule.ID, rule.Name, domainID, triggeredBy, timeout)

	// ---- 1) 准备扫描结果（按需先扫描，或复用最近一次扫描）----
	scanResults, scanJobID := r.collectScanResults(ctx, rule, domainID)
	if scanJobID != "" {
		rec.ScanJobID = scanJobID
	}

	// 扫描阶段已结束（Dashboard 的扫描任务此时已 completed）。进入 AI 分析阶段前先把
	// 状态翻成 analyzing 并落库，避免前端在 AI 耗时（可能数分钟）期间一直显示 running，
	// 造成「扫描已完成却仍是 running」的观感不一致。
	rec.Status = models.InspectionStatusAnalyzing
	if err := r.recordRepo.Update(rec); err != nil {
		log.Printf("[Inspection] %s 写入 analyzing 状态失败: %v", rec.ID, err)
	}

	// ---- 2) 结果判定：AI 相关（智能体调用）与非 AI 相关（定时/手动规则）分类判定 ----
	now := time.Now()
	rec.CompletedAt = &now

	if scanResults == nil {
		// 无任何扫描数据：无法评估，直接标记失败（不进入 partial/success 任一分支，避免误判）
		r.finalizeFailure(rec, rule, "无可用扫描数据，无法评估风险")
		return
	}

	// 分类：由智能体调用触发 vs 常规定时/手动规则巡检。二者判定边界互不干扰。
	isAgentDriven := rec.TriggeredBy == models.InspectionTriggerAgent
	finalResult := r.judge(rec, rule, scanResults, isAgentDriven)

	log.Printf("[Inspection] %s 完成(agentDriven=%v): 状态=%s 风险=%s 发现=%d(H:%d M:%d L:%d)",
		rec.ID, isAgentDriven, rec.Status, rec.RiskLevel, rec.FindingsCount, rec.HighCount, rec.MediumCount, rec.LowCount)


	if err := r.recordRepo.Update(rec); err != nil {
		log.Printf("[Inspection] %s 写入最终结果失败: %v", rec.ID, err)
	}

	// 巡检完成：依据发现自动创建工单（高危/中危按规则阈值）
	if finalResult != nil {
		r.createTicketsForRecord(rec, rule, finalResult)
	}

	// 写回下次预计执行时间，便于界面预览
	_ = r.ruleRepo.UpdateRunTimes(rule.ID, nil, nextRun(rule.Schedule))
}

// collectScanResults 依据规则决定是否先扫描；返回扫描结果与（若有）扫描任务 ID。
func (r *Runner) collectScanResults(ctx context.Context, rule *models.InspectionRule, domainID string) (*scanner.ScanResults, string) {
	if !rule.RunScan {
		return r.latestScanResults(domainID)
	}

	job, err := r.engine.Scan(domainID)
	if err != nil {
		log.Printf("[Inspection] %s 触发扫描失败(domain=%s): %v，尝试复用最近扫描", rule.ID, domainID, err)
		return r.latestScanResults(domainID)
	}

	waitTimeout := r.engine.ScanTimeout() + 60*time.Second
	res, werr := r.engine.WaitForScanCompletion(job.ID, waitTimeout)
	if werr != nil {
		log.Printf("[Inspection] %s 等待扫描完成超时/失败(job=%s): %v", rule.ID, job.ID, werr)
	}
	if res == nil {
		// 扫描未产出结果：仍然尝试取一次，避免空巡检
		if got, gerr := r.engine.GetScanResults(job.ID); gerr == nil {
			res = got
		}
	}
	return res, job.ID
}

// latestScanResults 取该域名最近一次扫描的结果（RunScan=false 或扫描失败时的兜底）。
func (r *Runner) latestScanResults(domainID string) (*scanner.ScanResults, string) {
	jobs, err := r.scanJobRepo.ListByDomain(domainID)
	if err != nil || len(jobs) == 0 {
		return nil, ""
	}
	// ListByDomain 已按 created_at DESC 排序，取第一条
	latest := jobs[0]
	res, err := r.engine.GetScanResults(latest.ID)
	if err != nil {
		return nil, latest.ID
	}
	return res, latest.ID
}

// judge 依据巡检来源与智能体可用性，明确判定巡检记录状态，确保 AI 相关与非 AI 相关分类互不干扰：
//   - 非 AI 相关（定时/手动规则巡检）：扫描成功即判定 success（结果不依赖 AI，无 partial 概念）。
//   - AI 相关（由智能体调用触发）：
//       * 智能体可用   → success：扫描结果已就绪，AI 研判交由智能体完成。
//       * 智能体不可用 → 触发兜底扫描（即本次扫描），仅当兜底扫描成功时才标注 partial；
//         若兜底扫描也无数据，已在上方 scanResults==nil 分支标记为 failed，不会落入本函数。
//
// 调用前必须保证 scanResults != nil（无数据分支已在 execute 中提前返回 failed）。
func (r *Runner) judge(rec *models.InspectionRecord, rule *models.InspectionRule, scanResults *scanner.ScanResults, agentDriven bool) *models.InspectionResult {
	res := fallbackFromScan(scanResults)
	rec.RiskLevel = res.OverallRisk
	rec.Summary = res.Summary
	rec.FindingsCount = len(res.Findings)
	rec.HighCount, rec.MediumCount, rec.LowCount = countBySeverity(res.Findings)
	if b, err := json.Marshal(res); err == nil {
		rec.ResultJSON = string(b)
	}

	switch {
	case !agentDriven:
		// 非 AI 相关：扫描成功即成功，不受智能体可用性影响
		rec.Status = models.InspectionStatusSuccess
	case r.agentAvailable():
		// AI 相关且智能体可用：扫描结果交由智能体做 AI 研判，本记录判定成功
		rec.Status = models.InspectionStatusSuccess
	default:
		// AI 相关且智能体不可用：仅兜底扫描成功，标注部分成功
		rec.Status = models.InspectionStatusPartial
		rec.Summary = res.Summary + "（智能体不可用，已触发兜底扫描，仅含本地评估，建议由智能体补做 AI 研判）"
	}
	return &res
}

// agentAvailable 判断智能体（及其依赖的 AI 层）当前是否可用。
// 智能体能力依赖至少一个「已启用且已配置」的 AI 供应商；无可用供应商即视为智能体不可用。
func (r *Runner) agentAvailable() bool {
	return r.aiMgr != nil && r.aiMgr.Ready()
}


// finalizeFailure 标记失败并（按规则）发送告警。
func (r *Runner) finalizeFailure(rec *models.InspectionRecord, rule *models.InspectionRule, reason string) {
	now := time.Now()
	rec.Status = models.InspectionStatusFailed
	rec.CompletedAt = &now
	rec.Error = reason
	if err := r.recordRepo.Update(rec); err != nil {
		log.Printf("[Inspection] %s 写入失败状态失败: %v", rec.ID, err)
	}
	log.Printf("[Inspection] %s 失败: %s", rec.ID, reason)

	if rule.AlertOnFailure && r.alertSender != nil {
		alert := &models.Alert{
			DomainID:  rule.DomainID,
			ScanJobID: rec.ScanJobID,
			Type:      "inspection_failed",
			Title:     fmt.Sprintf("[巡检失败] %s", rule.Name),
			Content:   fmt.Sprintf("巡检规则 %s 执行失败：%s", rule.Name, reason),
			Severity:  "high",
			Status:    "new",
			CreatedAt: now,
		}
		if err := r.alertSender.SendAlert(alert); err != nil {
			log.Printf("[Inspection] %s 发送失败告警出错: %v", rec.ID, err)
		} else {
			log.Printf("[Inspection] %s 已发送失败告警", rec.ID)
		}
	}
}

// severityRank 风险等级权重（用于阈值判断）。
func severityRank(s string) int {
	switch normalizeRisk(s) {
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// createTicketsForRecord 巡检完成后，对达到规则严重度阈值的发现自动创建工单，
// 并完整填充资产/漏洞/证据/研判建议等字段，无需人工二次录入。
func (r *Runner) createTicketsForRecord(rec *models.InspectionRecord, rule *models.InspectionRule, result *models.InspectionResult) {
	if r.ticketRepo == nil || result == nil {
		return
	}
	// 阈值：规则 SeverityThreshold 缺省按 medium（高危+中危建单），避免低危噪声刷屏
	minRank := severityRank(rule.SeverityThreshold)
	if minRank == 0 {
		minRank = 2
	}

	created := 0
	for _, f := range result.Findings {
		if severityRank(f.Severity) < minRank {
			continue
		}

		// 去重指纹：维度 = 域名 + 漏洞类型(以发现标题表征) + 受影响 URL + 参数。
		// 同一域名多次巡检命中相同漏洞 → 指纹一致 → 复用已有工单，仅更新命中次数与最近扫描时间。
		fp := models.VulnFingerprint(rec.DomainID, f.Title, f.URL, "")
		if r.ticketRepo != nil {
			if existing, ferr := r.ticketRepo.FindByFingerprint(fp); ferr == nil && existing != nil {
				if terr := r.ticketRepo.Touch(fp, time.Now()); terr != nil {
					log.Printf("[Inspection] %s 更新工单命中次数失败(工单=%s): %v", rec.ID, existing.ID, terr)
				} else {
					log.Printf("[Inspection] %s 命中已有工单(指纹=%s…, 工单=%s)，命中次数 %d→累计+1，已跳过新建",
						rec.ID, fp[:8], existing.ID, existing.HitCount)
				}
				continue
			}
		}

		ticket := r.findingToTicket(rec, rule, f)
		ticket.Fingerprint = fp
		ticket.HitCount = 1
		ticket.LastSeenAt = time.Now()
		if err := r.ticketRepo.Create(ticket); err != nil {
			log.Printf("[Inspection] %s 自动化工单失败(finding=%q): %v", rec.ID, f.Title, err)
			continue
		}
		created++
	}
	if created > 0 {
		log.Printf("[Inspection] %s 自动创建工单 %d 个（阈值=%s，已启用去重）", rec.ID, created, rule.SeverityThreshold)
	}
}

// findingToTicket 将单条发现转换为自包含工单。
func (r *Runner) findingToTicket(rec *models.InspectionRecord, rule *models.InspectionRule, f models.InspectionFinding) *models.Ticket {
	harm, mitigation, retest, priority := r.generateTriage(f)

	title := f.Title
	if title == "" {
		title = "巡检安全发现"
	}
	desc := f.Description
	if desc == "" {
		desc = f.Recommendation
	}
	evidence := f.URL
	if evidence == "" {
		evidence = rec.DomainName
	}

	return &models.Ticket{
		ScanJobID:           rec.ScanJobID,
		Status:              models.TicketStatusPending,
		Type:                "investigation",
		Title:               title,
		Description:         desc,
		AssetName:           rec.DomainName,
		AssetURL:            rec.DomainName,
		VulnName:            f.Title,
		VulnType:            f.Title,
		RiskLevel:           normalizeRisk(f.Severity),
		VulnDescription:     f.Description,
		Evidence:            evidence,
		HarmDescription:     harm,
		RemediationPriority: priority,
		MitigationMeasures:  mitigation,
		RetestMethod:        retest,
		CreatorID:           "inspection-auto",
		Notes:               fmt.Sprintf("由自动巡检生成（规则：%s / 记录：%s）", rule.Name, rec.ID),
	}
}

// generateTriage 生成研判建议：优先采用 AI 返回的危害/缓解/复测，缺省时用规则兜底。
func (r *Runner) generateTriage(f models.InspectionFinding) (harm, mitigation, retest, priority string) {
	priority = f.Priority
	harm = f.Harm
	mitigation = f.Mitigation
	retest = f.Retest
	if priority == "" || harm == "" || mitigation == "" || retest == "" {
		dp, dh, dm, dr := triageBaseline(normalizeRisk(f.Severity))
		if priority == "" {
			priority = dp
		}
		if harm == "" {
			harm = dh
		}
		if mitigation == "" {
			mitigation = dm
		}
		if retest == "" {
			retest = dr
		}
	}
	return
}

// triageBaseline 按风险等级给出基线研判（AI 未提供时兜底）。
func triageBaseline(risk string) (priority, harm, mitigation, retest string) {
	switch risk {
	case "high":
		priority = "P0"
		harm = "该问题可被直接利用导致服务器失陷、数据泄露或权限提升，危害极高，需立即处置。"
		mitigation = "修复前通过 WAF/访问控制限制相关入口，必要时下线问题功能，并启用访问审计与告警。"
		retest = "修复后重新发起针对性扫描或 PoC 验证，确认原利用路径不可达，并观察一段时间无异常。"
	case "medium":
		priority = "P1"
		harm = "在特定条件下可被利用，可能造成信息泄露或权限提升，建议优先处理。"
		mitigation = "临时通过输入校验、访问控制或配置加固降低可利用性，避免敏感接口直接暴露。"
		retest = "修复后复测对应请求/页面，确认问题已修复且无绕过。"
	case "low":
		priority = "P2"
		harm = "风险较低但属安全隐患，建议在后续版本中规范修复。"
		mitigation = "按安全开发规范整改，并纳入常态化安全测试。"
		retest = "随版本迭代回归测试确认。"
	default:
		priority, harm, mitigation, retest = "P2", "风险待评估。", "建议人工复核并参考通用加固措施。", "人工复核确认。"
	}
	return
}

func (r *Runner) inspectionTimeout() time.Duration {
	if r.cfg != nil && r.cfg.InspectionTimeoutSec > 0 {
		return time.Duration(r.cfg.InspectionTimeoutSec) * time.Second
	}
	return 30 * time.Minute
}

// ---------- 解析与兜底 ----------

func parseInspectionResult(content string) (*models.InspectionResult, error) {
	raw := strings.TrimSpace(content)
	// 去除可能的 ```json ... ``` 包裹
	if strings.HasPrefix(raw, "```") {
		if i := strings.Index(raw, "{"); i >= 0 {
			if j := strings.LastIndex(raw, "}"); j > i {
				raw = raw[i : j+1]
			}
		}
	}
	start := strings.Index(raw, "{")
	end := strings.LastIndex(raw, "}")
	if start < 0 || end <= start {
		return nil, fmt.Errorf("响应中未找到 JSON 对象")
	}
	jsonStr := raw[start : end+1]

	var res models.InspectionResult
	if err := json.Unmarshal([]byte(jsonStr), &res); err != nil {
		return nil, err
	}
	if res.OverallRisk == "" {
		res.OverallRisk = deriveRisk(res.Findings)
	}
	return &res, nil
}

func normalizeRisk(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "high", "严重":
		return "high"
	case "medium", "中", "mid":
		return "medium"
	case "low", "低":
		return "low"
	case "none", "无":
		return "none"
	default:
		return "none"
	}
}

func countBySeverity(findings []models.InspectionFinding) (int, int, int) {
	h, m, l := 0, 0, 0
	for _, f := range findings {
		switch normalizeRisk(f.Severity) {
		case "high":
			h++
		case "medium":
			m++
		case "low":
			l++
		}
	}
	return h, m, l
}

func deriveRisk(findings []models.InspectionFinding) string {
	h, m, l := countBySeverity(findings)
	if h > 0 {
		return "high"
	}
	if m > 0 {
		return "medium"
	}
	if l > 0 {
		return "low"
	}
	return "none"
}

func fallbackFromScan(scanResults *scanner.ScanResults) models.InspectionResult {
	res := models.InspectionResult{}
	if scanResults == nil {
		res.OverallRisk = "none"
		res.Summary = "无可用扫描数据，无法评估风险。"
		return res
	}
	s := scanResults.Summary
	res.OverallRisk = deriveRisk(nil)
	if s.HighSeverity > 0 {
		res.OverallRisk = "high"
	} else if s.MediumSeverity > 0 {
		res.OverallRisk = "medium"
	} else if s.LowSeverity > 0 || s.SensitiveFound > 0 {
		res.OverallRisk = "low"
	} else {
		res.OverallRisk = "none"
	}
	res.Summary = fmt.Sprintf("本地评估：共发现漏洞 %d（高危 %d/中危 %d/低危 %d），敏感信息 %d 处。",
		s.TotalVulns, s.HighSeverity, s.MediumSeverity, s.LowSeverity, s.SensitiveFound)

	for _, v := range scanResults.Vulnerabilities {
		res.Findings = append(res.Findings, models.InspectionFinding{
			Title: v.Name, Severity: v.Severity, URL: v.URL,
			Description: v.Description, Recommendation: v.Remediation,
		})
	}
	res.Recommendations = []string{"配置可用的大模型 API Key 以获得 AI 增强分析", "对高危项优先修复并复查"}
	return res
}

// fallbackFromRaw 解析失败但确有返回内容时的兜底：尽量抽取 findings。
func fallbackFromRaw(content string, scanResults *scanner.ScanResults) models.InspectionResult {
	res := fallbackFromScan(scanResults)
	res.Summary = "AI 返回内容未能解析为结构化 JSON，已保留原始文本供人工查看。"
	if content != "" {
		// 截断，避免原始文本过长
		if len([]rune(content)) > 4000 {
			content = string([]rune(content)[:4000])
		}
		res.Recommendations = append(res.Recommendations, "模型返回非标准 JSON："+content)
	}
	return res
}

func nextRun(expr string) *time.Time {
	if strings.TrimSpace(expr) == "" {
		return nil
	}
	p := cron.NewParser(cron.SecondOptional | cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
	sched, err := p.Parse(expr)
	if err != nil {
		return nil
	}
	t := sched.Next(time.Now())
	return &t
}

func recID(rec *models.InspectionRecord) string {
	if rec == nil {
		return "<nil>"
	}
	return rec.ID
}
