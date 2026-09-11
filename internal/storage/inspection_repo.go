package storage

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"security-agent/internal/models"
)

// ============================================================
// InspectionRuleRepository —— 巡检规则 CRUD
// ============================================================

type InspectionRuleRepository struct {
	store *Neo4jStore
}

func NewInspectionRuleRepository(store *Neo4jStore) *InspectionRuleRepository {
	return &InspectionRuleRepository{store: store}
}

func (r *InspectionRuleRepository) Create(rule *models.InspectionRule) error {
	if rule.ID == "" {
		rule.ID = uuid.New().String()
	}
	rule.CreatedAt = time.Now()
	rule.UpdatedAt = time.Now()

	query := `CREATE (n:InspectionRule {
		id: $id, name: $name, domain_id: $domain_id, domain_ids: $domain_ids, enabled: $enabled, schedule: $schedule,
		severity_threshold: $severity_threshold, run_scan: $run_scan,
		retry_count: $retry_count, retry_backoff_sec: $retry_backoff_sec,
		alert_on_failure: $alert_on_failure, created_at: datetime($created_at), updated_at: datetime($updated_at)
	})`

	domainIDs := rule.EffectiveDomainIDs()
	// DomainID 作为主域名（第一个）持久化，保持向后兼容
	primaryDomainID := rule.DomainID
	if primaryDomainID == "" && len(domainIDs) > 0 {
		primaryDomainID = domainIDs[0]
	}
	session := r.store.Session()
	defer session.Close()
	_, err := session.Run(query, map[string]any{
		"id": rule.ID, "name": rule.Name, "domain_id": primaryDomainID, "domain_ids": domainIDs, "enabled": rule.Enabled,
		"schedule": rule.Schedule, "severity_threshold": rule.SeverityThreshold,
		"run_scan": rule.RunScan, "retry_count": rule.RetryCount, "retry_backoff_sec": rule.RetryBackoffSec,
		"alert_on_failure": rule.AlertOnFailure,
		"created_at":       rule.CreatedAt.Format(time.RFC3339), "updated_at": rule.UpdatedAt.Format(time.RFC3339),
	})
	return err
}

func (r *InspectionRuleRepository) GetByID(id string) (*models.InspectionRule, error) {
	query := `MATCH (n:InspectionRule {id: $id}) RETURN n`
	session := r.store.Session()
	defer session.Close()
	result, err := session.Run(query, map[string]any{"id": id})
	if err != nil {
		return nil, err
	}
	if result.Next() {
		if val, ok := result.Record().Get("n"); ok {
			if node, ok := val.(neo4j.Node); ok {
				return r.nodeToRule(node), nil
			}
		}
	}
	return nil, fmt.Errorf("inspection rule not found")
}

func (r *InspectionRuleRepository) List() ([]*models.InspectionRule, error) {
	query := `MATCH (n:InspectionRule) RETURN n ORDER BY n.created_at DESC`
	return r.listByQuery(query, nil)
}

// ListEnabled 返回所有启用的规则（调度器启动时注册定时任务用）
func (r *InspectionRuleRepository) ListEnabled() ([]*models.InspectionRule, error) {
	query := `MATCH (n:InspectionRule {enabled: true}) RETURN n ORDER BY n.created_at DESC`
	return r.listByQuery(query, nil)
}

func (r *InspectionRuleRepository) listByQuery(query string, params map[string]any) ([]*models.InspectionRule, error) {
	session := r.store.Session()
	defer session.Close()
	result, err := session.Run(query, params)
	if err != nil {
		return nil, err
	}
	var rules []*models.InspectionRule
	for result.Next() {
		if val, ok := result.Record().Get("n"); ok {
			if node, ok := val.(neo4j.Node); ok {
				rules = append(rules, r.nodeToRule(node))
			}
		}
	}
	return rules, result.Err()
}

func (r *InspectionRuleRepository) Update(rule *models.InspectionRule) error {
	rule.UpdatedAt = time.Now()
	domainIDs := rule.EffectiveDomainIDs()
	primaryDomainID := rule.DomainID
	if primaryDomainID == "" && len(domainIDs) > 0 {
		primaryDomainID = domainIDs[0]
	}
	query := `MATCH (n:InspectionRule {id: $id})
		SET n.name=$name, n.domain_id=$domain_id, n.domain_ids=$domain_ids, n.enabled=$enabled, n.schedule=$schedule,
		    n.severity_threshold=$severity_threshold, n.run_scan=$run_scan,
		    n.retry_count=$retry_count, n.retry_backoff_sec=$retry_backoff_sec,
		    n.alert_on_failure=$alert_on_failure, n.updated_at=datetime($updated_at)`
	session := r.store.Session()
	defer session.Close()
	_, err := session.Run(query, map[string]any{
		"id": rule.ID, "name": rule.Name, "domain_id": primaryDomainID, "domain_ids": domainIDs, "enabled": rule.Enabled,
		"schedule": rule.Schedule, "severity_threshold": rule.SeverityThreshold,
		"run_scan": rule.RunScan, "retry_count": rule.RetryCount, "retry_backoff_sec": rule.RetryBackoffSec,
		"alert_on_failure": rule.AlertOnFailure, "updated_at": rule.UpdatedAt.Format(time.RFC3339),
	})
	return err
}

func (r *InspectionRuleRepository) Delete(id string) error {
	query := `MATCH (n:InspectionRule {id: $id}) DETACH DELETE n`
	session := r.store.Session()
	defer session.Close()
	_, err := session.Run(query, map[string]any{"id": id})
	return err
}

// UpdateRunTimes 写回最近一次执行时间与下次预计执行时间（仅展示用，不影响 cron 触发）
func (r *InspectionRuleRepository) UpdateRunTimes(id string, lastRun, nextRun *time.Time) error {
	query := `MATCH (n:InspectionRule {id: $id})
		SET n.last_run_at = CASE WHEN $last_run IS NULL THEN NULL ELSE datetime($last_run) END,
		    n.next_run_at = CASE WHEN $next_run IS NULL THEN NULL ELSE datetime($next_run) END`
	session := r.store.Session()
	defer session.Close()
	_, err := session.Run(query, map[string]any{
		"id":       id,
		"last_run": nullableTime(lastRun),
		"next_run": nullableTime(nextRun),
	})
	return err
}

func nullableTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.Format(time.RFC3339)
}

func (r *InspectionRuleRepository) nodeToRule(node neo4j.Node) *models.InspectionRule {
	props := node.Props
	rule := &models.InspectionRule{
		ID: ruleStr(props, "id"), Name: ruleStr(props, "name"), DomainID: ruleStr(props, "domain_id"),
		DomainIDs:         getStringSlice(props, "domain_ids"),
		Enabled:           getBool(props, "enabled"),
		Schedule:          ruleStr(props, "schedule"),
		SeverityThreshold: ruleStr(props, "severity_threshold"),
		RunScan:           getBool(props, "run_scan"),
		RetryCount:        getInt(props, "retry_count"),
		RetryBackoffSec:   getInt(props, "retry_backoff_sec"),
		AlertOnFailure:    getBool(props, "alert_on_failure"),
		CreatedAt:         getTimeVal(props, "created_at"),
		UpdatedAt:         getTimeVal(props, "updated_at"),
	}
	// 兼容旧数据：若未存 domain_ids 但有 domain_id，补成单元素列表
	if len(rule.DomainIDs) == 0 && rule.DomainID != "" {
		rule.DomainIDs = []string{rule.DomainID}
	}
	if t := timeValPtr(props, "last_run_at"); t != nil {
		rule.LastRunAt = t
	}
	if t := timeValPtr(props, "next_run_at"); t != nil {
		rule.NextRunAt = t
	}
	return rule
}

// ruleStr 与 getStr 一致，仅别名以保持语义清晰
func ruleStr(props map[string]any, key string) string { return getStr(props, key) }

func timeValPtr(props map[string]any, key string) *time.Time {
	if v, ok := props[key].(time.Time); ok && !v.IsZero() {
		t := v
		return &t
	}
	return nil
}

// ============================================================
// InspectionRecordRepository —— 巡检记录 CRUD / 查询
// ============================================================

type InspectionRecordRepository struct {
	store *Neo4jStore
}

func NewInspectionRecordRepository(store *Neo4jStore) *InspectionRecordRepository {
	return &InspectionRecordRepository{store: store}
}

func (r *InspectionRecordRepository) Create(rec *models.InspectionRecord) error {
	if rec.ID == "" {
		rec.ID = uuid.New().String()
	}
	if rec.CreatedAt.IsZero() {
		rec.CreatedAt = time.Now()
	}
	if rec.StartedAt.IsZero() {
		rec.StartedAt = rec.CreatedAt
	}
	query := `CREATE (n:InspectionRecord {
		id: $id, rule_id: $rule_id, rule_name: $rule_name, domain_id: $domain_id, domain_name: $domain_name,
		scan_job_id: $scan_job_id, triggered_by: $triggered_by, provider: $provider, model: $model,
		status: $status, risk_level: $risk_level, summary: $summary, result_json: $result_json,
		raw_response: $raw_response, 
		findings_count: $findings_count, high_count: $high_count,
		medium_count: $medium_count, low_count: $low_count, error: $error, retry_count: $retry_count,
		started_at: datetime($started_at), created_at: datetime($created_at)
	})`
	session := r.store.Session()
	defer session.Close()
	_, err := session.Run(query, map[string]any{
		"id": rec.ID, "rule_id": rec.RuleID, "rule_name": rec.RuleName, "domain_id": rec.DomainID,
		"domain_name": rec.DomainName, "scan_job_id": rec.ScanJobID, "triggered_by": rec.TriggeredBy,
		"provider": rec.Provider, "model": rec.Model, "status": rec.Status, "risk_level": rec.RiskLevel,
		"summary": rec.Summary, "result_json": rec.ResultJSON, "raw_response": rec.RawResponse,

		"findings_count": rec.FindingsCount, "high_count": rec.HighCount, "medium_count": rec.MediumCount,
		"low_count": rec.LowCount, "error": rec.Error, "retry_count": rec.RetryCount,
		"started_at": rec.StartedAt.Format(time.RFC3339), "created_at": rec.CreatedAt.Format(time.RFC3339),
	})
	return err
}

// Update 写入最终状态（执行完成后调用）
func (r *InspectionRecordRepository) Update(rec *models.InspectionRecord) error {
	query := `MATCH (n:InspectionRecord {id: $id})
		SET n.status=$status, n.risk_level=$risk_level, n.summary=$summary, n.result_json=$result_json,
		    n.raw_response=$raw_response, 
		    n.findings_count=$findings_count, n.high_count=$high_count,
		    n.medium_count=$medium_count, n.low_count=$low_count, n.error=$error, n.retry_count=$retry_count,
		    n.provider=$provider, n.model=$model, n.scan_job_id=$scan_job_id,
		    n.completed_at=CASE WHEN $completed_at IS NULL THEN NULL ELSE datetime($completed_at) END`
	session := r.store.Session()
	defer session.Close()
	_, err := session.Run(query, map[string]any{
		"id": rec.ID, "status": rec.Status, "risk_level": rec.RiskLevel, "summary": rec.Summary,
		"result_json": rec.ResultJSON, "raw_response": rec.RawResponse,

		"findings_count": rec.FindingsCount, "high_count": rec.HighCount, "medium_count": rec.MediumCount,
		"low_count": rec.LowCount, "error": rec.Error, "retry_count": rec.RetryCount,
		"provider": rec.Provider, "model": rec.Model, "scan_job_id": rec.ScanJobID,
		"completed_at": nullableTime(rec.CompletedAt),
	})
	return err
}

// MarkStaleRunning 回收僵死巡检记录：把启动时间早于阈值、仍处于 running/analyzing
// 的记录标记为失败。进程重启后原先的 execute goroutine 已不存在，若不回收，这些记录
// 会永远停留在 running/analyzing（前端表现为“扫描已完成却仍是 running/分析中”）。
func (r *InspectionRecordRepository) MarkStaleRunning(maxAge time.Duration, status string) (int, error) {
	cutoff := time.Now().Add(-maxAge).Format(time.RFC3339)
	query := `MATCH (n:InspectionRecord)
		WHERE n.status IN ['running','analyzing'] AND n.started_at < datetime($cutoff)
		SET n.status = $status, n.completed_at = datetime($now), n.error = '巡检超时或服务重启，已被系统回收'
		RETURN count(n) AS cnt`
	session := r.store.Session()
	defer session.Close()
	result, err := session.Run(query, map[string]any{
		"cutoff": cutoff, "status": status, "now": time.Now().Format(time.RFC3339),
	})
	if err != nil {
		return 0, err
	}
	if result.Next() {
		if v, ok := result.Record().Get("cnt"); ok {
			if n, ok := v.(int64); ok {
				return int(n), nil
			}
		}
	}
	return 0, nil
}

func (r *InspectionRecordRepository) GetByID(id string) (*models.InspectionRecord, error) {
	query := `MATCH (n:InspectionRecord {id: $id}) RETURN n`
	session := r.store.Session()
	defer session.Close()
	result, err := session.Run(query, map[string]any{"id": id})
	if err != nil {
		return nil, err
	}
	if result.Next() {
		if val, ok := result.Record().Get("n"); ok {
			if node, ok := val.(neo4j.Node); ok {
				return r.nodeToRecord(node), nil
			}
		}
	}
	return nil, fmt.Errorf("inspection record not found")
}

// List 支持按 domain_id / rule_id / status 过滤，limit 控制返回条数（最近优先）
func (r *InspectionRecordRepository) List(domainID, ruleID, status string, limit int) ([]*models.InspectionRecord, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	where := ""
	params := map[string]any{"limit": limit}
	if domainID != "" {
		where += " AND n.domain_id = $domain_id"
		params["domain_id"] = domainID
	}
	if ruleID != "" {
		where += " AND n.rule_id = $rule_id"
		params["rule_id"] = ruleID
	}
	if status != "" {
		where += " AND n.status = $status"
		params["status"] = status
	}
	query := `MATCH (n:InspectionRecord) WHERE true` + where + ` RETURN n ORDER BY n.created_at DESC LIMIT $limit`
	session := r.store.Session()
	defer session.Close()
	result, err := session.Run(query, params)
	if err != nil {
		return nil, err
	}
	var recs []*models.InspectionRecord
	for result.Next() {
		if val, ok := result.Record().Get("n"); ok {
			if node, ok := val.(neo4j.Node); ok {
				recs = append(recs, r.nodeToRecord(node))
			}
		}
	}
	return recs, result.Err()
}

// CountByStatus 统计各状态数量（仪表盘/概览用）
func (r *InspectionRecordRepository) CountByStatus() (map[string]int, error) {
	query := `MATCH (n:InspectionRecord) RETURN n.status AS status, count(n) AS cnt`
	session := r.store.Session()
	defer session.Close()
	result, err := session.Run(query, nil)
	if err != nil {
		return nil, err
	}
	counts := make(map[string]int)
	for result.Next() {
		rec := result.Record()
		st, _ := rec.Get("status")
		cnt, _ := rec.Get("cnt")
		if s, ok := st.(string); ok {
			if c, ok := cnt.(int64); ok {
				counts[s] = int(c)
			}
		}
	}
	return counts, result.Err()
}

func (r *InspectionRecordRepository) nodeToRecord(node neo4j.Node) *models.InspectionRecord {
	props := node.Props
	rec := &models.InspectionRecord{
		ID: ruleStr(props, "id"), RuleID: ruleStr(props, "rule_id"), RuleName: ruleStr(props, "rule_name"),
		DomainID: ruleStr(props, "domain_id"), DomainName: ruleStr(props, "domain_name"),
		ScanJobID: ruleStr(props, "scan_job_id"), TriggeredBy: ruleStr(props, "triggered_by"),
		Provider: ruleStr(props, "provider"), Model: ruleStr(props, "model"), Status: ruleStr(props, "status"),
		RiskLevel: ruleStr(props, "risk_level"), Summary: ruleStr(props, "summary"),
		ResultJSON: ruleStr(props, "result_json"), RawResponse: ruleStr(props, "raw_response"),
		FindingsCount: getInt(props, "findings_count"), HighCount: getInt(props, "high_count"),
		MediumCount: getInt(props, "medium_count"), LowCount: getInt(props, "low_count"),
		Error: ruleStr(props, "error"), RetryCount: getInt(props, "retry_count"),
		StartedAt: getTimeVal(props, "started_at"), CreatedAt: getTimeVal(props, "created_at"),
	}
	if t := timeValPtr(props, "completed_at"); t != nil {
		rec.CompletedAt = t
	}
	return rec
}
