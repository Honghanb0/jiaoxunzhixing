package storage

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"security-agent/internal/models"
)

type DomainRepository struct {
	store *Neo4jStore
}

func NewDomainRepository(store *Neo4jStore) *DomainRepository {
	return &DomainRepository{store: store}
}

func (r *DomainRepository) Create(domain *models.Domain) error {
	if domain.ID == "" {
		domain.ID = uuid.New().String()
	}
	domain.CreatedAt = time.Now()
	domain.UpdatedAt = time.Now()

	query := `CREATE (d:Domain {id: $id, name: $name, description: $description, status: $status, max_depth: $max_depth, max_pages: $max_pages, created_at: datetime($created_at), updated_at: datetime($updated_at)})`

	session := r.store.Session()
	defer session.Close()

	_, err := session.Run(query, map[string]any{
		"id": domain.ID, "name": domain.Name, "description": domain.Description,
		"status": domain.Status, "max_depth": domain.MaxDepth, "max_pages": domain.MaxPages,
		"created_at": domain.CreatedAt.Format(time.RFC3339), "updated_at": domain.UpdatedAt.Format(time.RFC3339),
	})
	return err
}

func (r *DomainRepository) GetByID(id string) (*models.Domain, error) {
	query := `MATCH (d:Domain {id: $id}) RETURN d`
	session := r.store.Session()
	defer session.Close()

	result, err := session.Run(query, map[string]any{"id": id})
	if err != nil {
		return nil, err
	}
	if result.Next() {
		if val, ok := result.Record().Get("d"); ok {
			if node, ok := val.(neo4j.Node); ok {
				return r.nodeToDomain(node), nil
			}
		}
	}
	return nil, fmt.Errorf("domain not found")
}

func (r *DomainRepository) List() ([]*models.Domain, error) {
	query := `MATCH (d:Domain) RETURN d ORDER BY d.created_at DESC`
	session := r.store.Session()
	defer session.Close()

	result, err := session.Run(query, nil)
	if err != nil {
		return nil, err
	}
	var domains []*models.Domain
	for result.Next() {
		if val, ok := result.Record().Get("d"); ok {
			if node, ok := val.(neo4j.Node); ok {
				domains = append(domains, r.nodeToDomain(node))
			}
		}
	}
	return domains, result.Err()
}

func (r *DomainRepository) Update(domain *models.Domain) error {
	domain.UpdatedAt = time.Now()
	query := `MATCH (d:Domain {id: $id}) SET d.name=$name, d.description=$description, d.status=$status, d.max_depth=$max_depth, d.max_pages=$max_pages, d.updated_at=datetime($updated_at)`
	session := r.store.Session()
	defer session.Close()
	_, err := session.Run(query, map[string]any{
		"id": domain.ID, "name": domain.Name, "description": domain.Description,
		"status": domain.Status, "max_depth": domain.MaxDepth, "max_pages": domain.MaxPages,
		"updated_at": domain.UpdatedAt.Format(time.RFC3339),
	})
	return err
}

func (r *DomainRepository) Delete(id string) error {
	query := `MATCH (d:Domain {id: $id}) DETACH DELETE d`
	session := r.store.Session()
	defer session.Close()
	_, err := session.Run(query, map[string]any{"id": id})
	return err
}

func (r *DomainRepository) nodeToDomain(node neo4j.Node) *models.Domain {
	props := node.Props
	return &models.Domain{
		ID: getStr(props, "id"), Name: getStr(props, "name"),
		Description: getStr(props, "description"), Status: getStr(props, "status"),
		MaxDepth: getInt(props, "max_depth"), MaxPages: getInt(props, "max_pages"),
		CreatedAt: getTimeVal(props, "created_at"), UpdatedAt: getTimeVal(props, "updated_at"),
	}
}

type ScanJobRepository struct {
	store *Neo4jStore
}

func NewScanJobRepository(store *Neo4jStore) *ScanJobRepository {
	return &ScanJobRepository{store: store}
}

func (r *ScanJobRepository) Create(job *models.ScanJob) error {
	if job.ID == "" {
		job.ID = uuid.New().String()
	}
	job.CreatedAt = time.Now()
	query := `CREATE (s:ScanJob {id: $id, domain_id: $domain_id, status: $status, started_at: datetime($started_at), created_at: datetime($created_at)})`
	session := r.store.Session()
	defer session.Close()
	_, err := session.Run(query, map[string]any{
		"id": job.ID, "domain_id": job.DomainID, "status": job.Status,
		"started_at": job.StartedAt.Format(time.RFC3339), "created_at": job.CreatedAt.Format(time.RFC3339),
	})
	return err
}

func (r *ScanJobRepository) UpdateStatus(id, status string) error {
	query := fmt.Sprintf(`MATCH (s:ScanJob {id: $id}) SET s.status = '%s'`, status)
	session := r.store.Session()
	defer session.Close()
	_, err := session.Run(query, map[string]any{"id": id, "status": status})
	return err
}

// UpdateProgress 写入实时进度，使进程重启后仍能读到"爬到第几页"，
// 而不是一律回落到 0。
func (r *ScanJobRepository) UpdateProgress(id string, currentPage, totalPages int) error {
	query := `MATCH (s:ScanJob {id: $id}) SET s.current_page = $current, s.total_pages = $total`
	session := r.store.Session()
	defer session.Close()
	_, err := session.Run(query, map[string]any{
		"id": id, "current": currentPage, "total": totalPages,
	})
	return err
}

// Fail 标记扫描失败并记录原因
func (r *ScanJobRepository) Fail(id, status, reason string) error {
	now := time.Now().Format(time.RFC3339)
	query := `MATCH (s:ScanJob {id: $id}) SET s.status = $status, s.completed_at = datetime($completed_at), s.error = $reason`
	session := r.store.Session()
	defer session.Close()
	_, err := session.Run(query, map[string]any{
		"id": id, "status": status, "completed_at": now, "reason": reason,
	})
	return err
}

// MarkStaleRunning 回收僵死任务：把启动时间早于阈值、状态仍为 running 的任务
// 标记为指定状态。进程重启后原先的扫描 goroutine 已不存在，若不回收，
// 这些任务会永远停留在 running（前端表现为"跑了 271 小时还是 0 页"）。
func (r *ScanJobRepository) MarkStaleRunning(maxAge time.Duration, status string) (int, error) {
	cutoff := time.Now().Add(-maxAge).Format(time.RFC3339)
	query := `MATCH (s:ScanJob {status: 'running'})
	          WHERE s.started_at < datetime($cutoff)
	          SET s.status = $status, s.completed_at = datetime($now), s.error = '扫描超时，已被系统回收'
	          RETURN count(s) AS cnt`
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

// ListRunning 返回全部处于 running 状态的任务
func (r *ScanJobRepository) ListRunning() ([]*models.ScanJob, error) {
	query := `MATCH (s:ScanJob {status: 'running'}) RETURN s`
	session := r.store.Session()
	defer session.Close()
	result, err := session.Run(query, nil)
	if err != nil {
		return nil, err
	}
	jobs := make([]*models.ScanJob, 0)
	for result.Next() {
		if val, ok := result.Record().Get("s"); ok {
			if node, ok := val.(neo4j.Node); ok {
				jobs = append(jobs, r.nodeToJob(node))
			}
		}
	}
	return jobs, nil
}

// Complete 标记扫描完成，写入完成时间与聚合摘要，供列表/仪表盘直接读取。
func (r *ScanJobRepository) Complete(id string, summary *models.ScanSummary) error {
	now := time.Now().Format(time.RFC3339)
	query := `MATCH (s:ScanJob {id: $id}) SET s.status = 'completed', s.completed_at = datetime($completed_at), s.total_pages = $total_pages, s.total_vulnerabilities = $total, s.high_severity = $high, s.medium_severity = $medium, s.low_severity = $low, s.sensitive_found = $sensitive`
	session := r.store.Session()
	defer session.Close()
	_, err := session.Run(query, map[string]any{
		"id": id, "completed_at": now, "total_pages": summary.TotalPages,
		"total": summary.TotalVulns, "high": summary.HighSeverity,
		"medium": summary.MediumSeverity, "low": summary.LowSeverity,
		"sensitive": summary.SensitiveFound,
	})
	return err
}

func (r *ScanJobRepository) GetByID(id string) (*models.ScanJob, error) {
	query := `MATCH (s:ScanJob {id: $id}) RETURN s`
	session := r.store.Session()
	defer session.Close()

	result, err := session.Run(query, map[string]any{"id": id})
	if err != nil {
		return nil, err
	}
	if result.Next() {
		if val, ok := result.Record().Get("s"); ok {
			if node, ok := val.(neo4j.Node); ok {
				return r.nodeToJob(node), nil
			}
		}
	}
	return nil, fmt.Errorf("scan job not found")
}

func (r *ScanJobRepository) ListByDomain(domainID string) ([]*models.ScanJob, error) {
	query := `MATCH (s:ScanJob {domain_id: $domain_id}) RETURN s ORDER BY s.created_at DESC`
	session := r.store.Session()
	defer session.Close()

	result, err := session.Run(query, map[string]any{"domain_id": domainID})
	if err != nil {
		return nil, err
	}
	var jobs []*models.ScanJob
	for result.Next() {
		if val, ok := result.Record().Get("s"); ok {
			if node, ok := val.(neo4j.Node); ok {
				jobs = append(jobs, r.nodeToJob(node))
			}
		}
	}
	return jobs, result.Err()
}

func (r *ScanJobRepository) nodeToJob(node neo4j.Node) *models.ScanJob {
	props := node.Props
	job := &models.ScanJob{
		ID: getStr(props, "id"), DomainID: getStr(props, "domain_id"),
		Status: getStr(props, "status"), CreatedAt: getTimeVal(props, "created_at"), StartedAt: getTimeVal(props, "started_at"),
		TotalPages:     getInt(props, "total_pages"),
		CurrentPage:    getInt(props, "current_page"),
		TotalVulns:     getInt(props, "total_vulnerabilities"),
		HighSeverity:   getInt(props, "high_severity"),
		MediumSeverity: getInt(props, "medium_severity"),
		LowSeverity:    getInt(props, "low_severity"),
		SensitiveFound: getInt(props, "sensitive_found"),
	}
	if t := getTimeVal(props, "completed_at"); !t.IsZero() {
		job.CompletedAt = &t
	}
	job.Summary = &models.ScanSummary{
		TotalPages:     getInt(props, "total_pages"),
		TotalVulns:     job.TotalVulns,
		HighSeverity:   job.HighSeverity,
		MediumSeverity: job.MediumSeverity,
		LowSeverity:    job.LowSeverity,
		SensitiveFound: job.SensitiveFound,
	}
	return job
}

func getInt(props map[string]any, key string) int {
	if v, ok := props[key]; ok {
		switch val := v.(type) {
		case int64:
			return int(val)
		case int:
			return val
		}
	}
	return 0
}
