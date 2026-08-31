package storage

import (
	"time"

	"github.com/google/uuid"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"security-agent/internal/models"
)

type AlertRepository struct {
	store *Neo4jStore
}

func NewAlertRepository(store *Neo4jStore) *AlertRepository {
	return &AlertRepository{store: store}
}

func (r *AlertRepository) Create(alert *models.Alert) error {
	if alert.ID == "" {
		alert.ID = uuid.New().String()
	}
	if alert.CreatedAt.IsZero() {
		alert.CreatedAt = time.Now()
	}

	query := `CREATE (a:Alert {id: $id, domain_id: $domain_id, scan_job_id: $scan_job_id, type: $type, reference_id: $reference_id, title: $title, content: $content, severity: $severity, status: $status, created_at: datetime($created_at)})`

	session := r.store.Session()
	defer session.Close()

	_, err := session.Run(query, map[string]any{
		"id": alert.ID, "domain_id": alert.DomainID, "scan_job_id": alert.ScanJobID,
		"type": alert.Type, "reference_id": alert.ReferenceID, "title": alert.Title,
		"content": alert.Content, "severity": alert.Severity, "status": alert.Status,
		"created_at": alert.CreatedAt.Format(time.RFC3339),
	})
	return err
}

func (r *AlertRepository) List(limit, offset int) ([]*models.Alert, error) {
	query := `MATCH (a:Alert) RETURN a ORDER BY a.created_at DESC SKIP $offset LIMIT $limit`
	session := r.store.Session()
	defer session.Close()

	result, err := session.Run(query, map[string]any{"offset": offset, "limit": limit})
	if err != nil {
		return nil, err
	}

	var alerts []*models.Alert
	for result.Next() {
		if val, ok := result.Record().Get("a"); ok {
			if node, ok := val.(neo4j.Node); ok {
				alerts = append(alerts, r.nodeToAlert(node))
			}
		}
	}
	return alerts, result.Err()
}

func (r *AlertRepository) GetByID(id string) (*models.Alert, error) {
	query := `MATCH (a:Alert {id: $id}) RETURN a`
	session := r.store.Session()
	defer session.Close()

	result, err := session.Run(query, map[string]any{"id": id})
	if err != nil {
		return nil, err
	}
	if result.Next() {
		if val, ok := result.Record().Get("a"); ok {
			if node, ok := val.(neo4j.Node); ok {
				return r.nodeToAlert(node), nil
			}
		}
	}
	return nil, nil
}

func (r *AlertRepository) UpdateStatus(id, status string) error {
	query := `MATCH (a:Alert {id: $id}) SET a.status = $status`
	session := r.store.Session()
	defer session.Close()
	_, err := session.Run(query, map[string]any{"id": id, "status": status})
	return err
}

func (r *AlertRepository) CountByStatus() (map[string]int, error) {
	query := `MATCH (a:Alert) RETURN a.status, count(a)`
	session := r.store.Session()
	defer session.Close()

	result, err := session.Run(query, nil)
	if err != nil {
		return nil, err
	}

	counts := make(map[string]int)
	for result.Next() {
		record := result.Record()
		if status, _ := record.Get("a.status"); status != nil {
			if count, _ := record.Get("count(a)"); count != nil {
				counts[status.(string)] = int(count.(int64))
			}
		}
	}
	return counts, result.Err()
}

func (r *AlertRepository) nodeToAlert(node neo4j.Node) *models.Alert {
	props := node.Props
	alert := &models.Alert{
		ID: getStr(props, "id"), DomainID: getStr(props, "domain_id"),
		ScanJobID: getStr(props, "scan_job_id"), Type: getStr(props, "type"),
		ReferenceID: getStr(props, "reference_id"), Title: getStr(props, "title"),
		Content: getStr(props, "content"), Severity: getStr(props, "severity"),
		Status: getStr(props, "status"), ResolvedBy: getStr(props, "resolved_by"),
		CreatedAt: getTimeVal(props, "created_at"),
	}
	if t := getTimeVal(props, "resolved_at"); !t.IsZero() {
		alert.ResolvedAt = &t
	}
	return alert
}

func getStr(props map[string]any, key string) string {
	if v, ok := props[key].(string); ok {
		return v
	}
	return ""
}

func getTimeVal(props map[string]any, key string) time.Time {
	if v, ok := props[key].(time.Time); ok {
		return v
	}
	return time.Time{}
}
