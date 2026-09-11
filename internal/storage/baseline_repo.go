package storage

import (
	"time"

	"github.com/google/uuid"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"security-agent/internal/models"
)

// BaselineRepository 巡检基线仓储。每个域名最多保留一条基线
// （基线代表"已确认的正常状态"，同时存在多条会让对比结果失去唯一解释）。
type BaselineRepository struct {
	store *Neo4jStore
}

func NewBaselineRepository(store *Neo4jStore) *BaselineRepository {
	return &BaselineRepository{store: store}
}

// Save 覆盖式保存域名基线（按 domain_id 唯一）。
func (r *BaselineRepository) Save(b *models.Baseline) error {
	if b.ID == "" {
		b.ID = uuid.New().String()
	}
	b.CreatedAt = time.Now()

	// MERGE 保证每域名只有一条；ON MATCH 时整体替换快照与来源扫描。
	query := `
MERGE (b:Baseline {domain_id: $domain_id})
ON CREATE SET b.id = $id, b.created_at = datetime($created_at)
SET b.scan_job_id = $scan_job_id,
    b.note = $note,
    b.page_count = $page_count,
    b.vuln_count = $vuln_count,
    b.pages_json = $pages_json,
    b.vulns_json = $vulns_json,
    b.updated_at = datetime($created_at)`
	session := r.store.Session()
	defer session.Close()
	_, err := session.Run(query, map[string]any{
		"id": b.ID, "domain_id": b.DomainID, "scan_job_id": b.ScanJobID,
		"note": b.Note, "page_count": b.PageCount, "vuln_count": b.VulnCount,
		"pages_json": b.PagesJSON, "vulns_json": b.VulnsJSON,
		"created_at": b.CreatedAt.Format(time.RFC3339),
	})
	return err
}

// GetByDomain 读取域名基线；不存在时返回 (nil, nil)，调用方据此判空。
func (r *BaselineRepository) GetByDomain(domainID string) (*models.Baseline, error) {
	query := `MATCH (b:Baseline {domain_id: $domain_id}) RETURN b LIMIT 1`
	session := r.store.Session()
	defer session.Close()

	result, err := session.Run(query, map[string]any{"domain_id": domainID})
	if err != nil {
		return nil, err
	}
	if result.Next() {
		if val, ok := result.Record().Get("b"); ok {
			if node, ok := val.(neo4j.Node); ok {
				return nodeToBaseline(node.Props), nil
			}
		}
	}
	return nil, result.Err()
}

// DeleteByDomain 删除域名基线。
func (r *BaselineRepository) DeleteByDomain(domainID string) error {
	query := `MATCH (b:Baseline {domain_id: $domain_id}) DELETE b`
	session := r.store.Session()
	defer session.Close()
	_, err := session.Run(query, map[string]any{"domain_id": domainID})
	return err
}

func nodeToBaseline(props map[string]any) *models.Baseline {
	return &models.Baseline{
		ID:        getStr(props, "id"),
		DomainID:  getStr(props, "domain_id"),
		ScanJobID: getStr(props, "scan_job_id"),
		Note:      getStr(props, "note"),
		CreatedAt: getTimeVal(props, "created_at"),
		PageCount: getInt(props, "page_count"),
		VulnCount: getInt(props, "vuln_count"),
		PagesJSON: getStr(props, "pages_json"),
		VulnsJSON: getStr(props, "vulns_json"),
	}
}
