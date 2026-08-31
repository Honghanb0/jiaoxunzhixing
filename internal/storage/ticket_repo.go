package storage

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"security-agent/internal/models"
)

type TicketRepository struct {
	store *Neo4jStore
}

func NewTicketRepository(store *Neo4jStore) *TicketRepository {
	return &TicketRepository{store: store}
}

func (r *TicketRepository) Create(ticket *models.Ticket) error {
	if ticket.ID == "" {
		ticket.ID = uuid.New().String()
	}
	now := time.Now()
	ticket.CreatedAt = now
	ticket.UpdatedAt = now
	if ticket.Status == "" {
		ticket.Status = models.TicketStatusPending
	}
	if ticket.HitCount == 0 {
		ticket.HitCount = 1
	}
	if ticket.LastSeenAt.IsZero() {
		ticket.LastSeenAt = now
	}

	query := `CREATE (t:Ticket {
		id: $id, vuln_id: $vuln_id, scan_job_id: $scan_job_id, status: $status, assignee: $assignee, notes: $notes, creator_id: $creator_id,
		title: $title, type: $type, description: $description, asset_name: $asset_name, asset_url: $asset_url,
		vuln_name: $vuln_name, vuln_type: $vuln_type, risk_level: $risk_level, vuln_description: $vuln_description, evidence: $evidence,
		harm_description: $harm_description, remediation_priority: $remediation_priority, mitigation_measures: $mitigation_measures, retest_method: $retest_method,
		fingerprint: $fingerprint, hit_count: $hit_count, last_seen_at: datetime($last_seen_at),
		created_at: datetime($created_at), updated_at: datetime($updated_at)})`
	session := r.store.Session()
	defer session.Close()

	_, err := session.Run(query, map[string]any{
		"id": ticket.ID, "vuln_id": ticket.VulnID, "scan_job_id": ticket.ScanJobID,
		"status": ticket.Status, "assignee": ticket.Assignee, "notes": ticket.Notes,
		"creator_id": ticket.CreatorID, "created_at": now.Format(time.RFC3339), "updated_at": now.Format(time.RFC3339),
		"title": ticket.Title, "type": ticket.Type, "description": ticket.Description,
		"asset_name": ticket.AssetName, "asset_url": ticket.AssetURL, "vuln_name": ticket.VulnName,
		"vuln_type": ticket.VulnType, "risk_level": ticket.RiskLevel, "vuln_description": ticket.VulnDescription,
		"evidence": ticket.Evidence, "harm_description": ticket.HarmDescription, "remediation_priority": ticket.RemediationPriority,
		"mitigation_measures": ticket.MitigationMeasures, "retest_method": ticket.RetestMethod,
		"fingerprint": ticket.Fingerprint, "hit_count": ticket.HitCount, "last_seen_at": ticket.LastSeenAt.Format(time.RFC3339),
	})
	return err
}

// FindByFingerprint 按去重指纹查找已存在的工单（用于自动巡检去重工单）。
// 指纹为空（历史存量工单）时返回 nil，避免误命中。
func (r *TicketRepository) FindByFingerprint(fp string) (*models.Ticket, error) {
	if fp == "" {
		return nil, nil
	}
	query := `MATCH (t:Ticket {fingerprint: $fp}) RETURN t LIMIT 1`
	session := r.store.Session()
	defer session.Close()

	result, err := session.Run(query, map[string]any{"fp": fp})
	if err != nil {
		return nil, err
	}
	if result.Next() {
		if val, ok := result.Record().Get("t"); ok {
			if node, ok := val.(neo4j.Node); ok {
				return r.nodeToTicket(node), nil
			}
		}
	}
	return nil, nil
}

// Touch 命中同指纹漏洞时更新工单：命中次数 +1、刷新最近扫描时间与更新时间。
// 不改动既有研判/处置结论，仅在原工单上累加证据，避免重复建单刷屏。
func (r *TicketRepository) Touch(fp string, now time.Time) error {
	query := `MATCH (t:Ticket {fingerprint: $fp})
		SET t.hit_count = t.hit_count + 1, t.last_seen_at = datetime($last_seen_at), t.updated_at = datetime($updated_at)`
	session := r.store.Session()
	defer session.Close()
	_, err := session.Run(query, map[string]any{
		"fp": fp,
		"last_seen_at": now.Format(time.RFC3339),
		"updated_at":   now.Format(time.RFC3339),
	})
	return err
}

func (r *TicketRepository) GetByID(id string) (*models.Ticket, error) {
	query := `MATCH (t:Ticket {id: $id}) RETURN t`
	session := r.store.Session()
	defer session.Close()

	result, err := session.Run(query, map[string]any{"id": id})
	if err != nil {
		return nil, err
	}
	if result.Next() {
		if val, ok := result.Record().Get("t"); ok {
			if node, ok := val.(neo4j.Node); ok {
				return r.nodeToTicket(node), nil
			}
		}
	}
	return nil, fmt.Errorf("ticket not found")
}

func (r *TicketRepository) List(status, scanJobID string) ([]*models.Ticket, error) {
	query := `MATCH (t:Ticket) WHERE true`
	params := map[string]any{}

	if status != "" {
		query += ` AND t.status = $status`
		params["status"] = status
	}
	if scanJobID != "" {
		query += ` AND t.scan_job_id = $scan_job_id`
		params["scan_job_id"] = scanJobID
	}
	query += ` RETURN t ORDER BY t.created_at DESC`

	session := r.store.Session()
	defer session.Close()

	result, err := session.Run(query, params)
	if err != nil {
		return nil, err
	}
	var tickets []*models.Ticket
	for result.Next() {
		if val, ok := result.Record().Get("t"); ok {
			if node, ok := val.(neo4j.Node); ok {
				tickets = append(tickets, r.nodeToTicket(node))
			}
		}
	}
	return tickets, result.Err()
}

func (r *TicketRepository) UpdateStatus(id, status string) error {
	query := `MATCH (t:Ticket {id: $id}) SET t.status = $status, t.updated_at = datetime($updated_at)`
	session := r.store.Session()
	defer session.Close()
	_, err := session.Run(query, map[string]any{
		"id": id, "status": status, "updated_at": time.Now().Format(time.RFC3339),
	})
	return err
}

func (r *TicketRepository) UpdateAssignee(id, assignee string) error {
	query := `MATCH (t:Ticket {id: $id}) SET t.assignee = $assignee, t.updated_at = datetime($updated_at)`
	session := r.store.Session()
	defer session.Close()
	_, err := session.Run(query, map[string]any{
		"id": id, "assignee": assignee, "updated_at": time.Now().Format(time.RFC3339),
	})
	return err
}

func (r *TicketRepository) AddNotes(id, notes string) error {
	query := `MATCH (t:Ticket {id: $id}) SET t.notes = t.notes + '\n' + $notes, t.updated_at = datetime($updated_at)`
	session := r.store.Session()
	defer session.Close()
	_, err := session.Run(query, map[string]any{
		"id": id, "notes": notes, "updated_at": time.Now().Format(time.RFC3339),
	})
	return err
}

func (r *TicketRepository) Delete(id string) error {
	query := `MATCH (t:Ticket {id: $id}) DETACH DELETE t`
	session := r.store.Session()
	defer session.Close()
	_, err := session.Run(query, map[string]any{"id": id})
	return err
}

func (r *TicketRepository) nodeToTicket(node neo4j.Node) *models.Ticket {
	props := node.Props
	return &models.Ticket{
		ID:        getStr(props, "id"),
		VulnID:    getStr(props, "vuln_id"),
		ScanJobID: getStr(props, "scan_job_id"),
		Status:    getStr(props, "status"),
		Assignee:  getStr(props, "assignee"),
		Notes:     getStr(props, "notes"),
		CreatorID: getStr(props, "creator_id"),
		CreatedAt: getTimeVal(props, "created_at"),
		UpdatedAt: getTimeVal(props, "updated_at"),
		Title:             getStr(props, "title"),
		Type:              getStr(props, "type"),
		Description:       getStr(props, "description"),
		AssetName:         getStr(props, "asset_name"),
		AssetURL:          getStr(props, "asset_url"),
		VulnName:          getStr(props, "vuln_name"),
		VulnType:          getStr(props, "vuln_type"),
		RiskLevel:         getStr(props, "risk_level"),
		VulnDescription:   getStr(props, "vuln_description"),
		Evidence:          getStr(props, "evidence"),
		HarmDescription:     getStr(props, "harm_description"),
		RemediationPriority: getStr(props, "remediation_priority"),
		MitigationMeasures:  getStr(props, "mitigation_measures"),
		RetestMethod:        getStr(props, "retest_method"),
		Fingerprint:         getStr(props, "fingerprint"),
		HitCount:            getInt(props, "hit_count"),
		LastSeenAt:          getTimeVal(props, "last_seen_at"),
	}
}
