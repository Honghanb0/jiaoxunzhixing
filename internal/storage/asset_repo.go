package storage

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"security-agent/internal/models"
)

// AssetRepository 网络资产仓储 - 管理 IP/Port/Service/Subdomain 节点与关系
type AssetRepository struct {
	store *Neo4jStore
}

func NewAssetRepository(store *Neo4jStore) *AssetRepository {
	return &AssetRepository{store: store}
}

// SaveAssetScan 保存资产扫描结果到 Neo4j 图谱
// 关系链: Domain -> RESOLVES_TO -> IP -> EXPOSES -> Port -> RUNS -> Service
//
//	Domain -> HAS_SUBDOMAIN -> Subdomain
func (r *AssetRepository) SaveAssetScan(domainID string, subdomains []*models.Subdomain, ips []*models.IP, ports []*models.Port, services []*models.Service) error {
	session := r.store.Session()
	defer session.Close()

	now := time.Now().Format(time.RFC3339)

	// 1. 保存子域名并建立 Domain -> Subdomain 关系
	for _, sub := range subdomains {
		if sub.ID == "" {
			sub.ID = uuid.New().String()
		}
		query := `
			MATCH (d:Domain {id: $domain_id})
			MERGE (s:Subdomain {name: $name})
			ON CREATE SET s.id = $id, s.source = $source, s.last_scanned = datetime($now), s.created_at = datetime($now)
			ON MATCH SET s.last_scanned = datetime($now)
			MERGE (d)-[:HAS_SUBDOMAIN]->(s)
		`
		if _, err := session.Run(query, map[string]any{
			"domain_id": domainID, "id": sub.ID, "name": sub.Name,
			"source": sub.Source, "now": now,
		}); err != nil {
			return fmt.Errorf("保存子域名失败 %s: %w", sub.Name, err)
		}
	}

	// 2. 保存 IP 并建立 Domain -> IP 关系
	for _, ip := range ips {
		if ip.ID == "" {
			ip.ID = uuid.New().String()
		}
		query := `
			MERGE (i:IP {address: $address})
			ON CREATE SET i.id = $id, i.version = $version, i.is_alive = $is_alive,
				i.last_scanned = datetime($now), i.created_at = datetime($now)
			ON MATCH SET i.is_alive = $is_alive, i.last_scanned = datetime($now)
			WITH i
			MATCH (d:Domain {id: $domain_id})
			MERGE (d)-[:RESOLVES_TO]->(i)
		`
		if _, err := session.Run(query, map[string]any{
			"address": ip.Address, "id": ip.ID, "version": ip.Version,
			"is_alive": ip.IsAlive, "now": now, "domain_id": domainID,
		}); err != nil {
			return fmt.Errorf("保存 IP 失败 %s: %w", ip.Address, err)
		}
	}

	// 3. 保存 Port 并建立 IP -> Port 关系
	portNodeIDs := make(map[string]string) // "ip:port" -> node ID
	for _, port := range ports {
		if port.ID == "" {
			port.ID = uuid.New().String()
		}
		key := fmt.Sprintf("%s:%d", port.IPAddress, port.Port)
		portNodeIDs[key] = port.ID

		query := `
			MATCH (i:IP {address: $ip_address})
			MERGE (p:Port {port: $port, ip_address: $ip_address})
			ON CREATE SET p.id = $id, p.protocol = $protocol, p.state = $state,
				p.service_name = $service_name, p.banner = $banner,
				p.last_scanned = datetime($now), p.created_at = datetime($now)
			ON MATCH SET p.state = $state, p.service_name = $service_name,
				p.banner = $banner, p.last_scanned = datetime($now)
			MERGE (i)-[:EXPOSES]->(p)
		`
		if _, err := session.Run(query, map[string]any{
			"ip_address": port.IPAddress, "port": port.Port, "id": port.ID,
			"protocol": port.Protocol, "state": port.State,
			"service_name": port.ServiceName, "banner": port.Banner, "now": now,
		}); err != nil {
			return fmt.Errorf("保存端口失败 %s:%d: %w", port.IPAddress, port.Port, err)
		}
	}

	// 4. 保存 Service 并建立 Port -> Service 关系
	for _, svc := range services {
		if svc.ID == "" {
			svc.ID = uuid.New().String()
		}
		portKey := fmt.Sprintf("%s:%d", svc.IPAddress, svc.PortNum)
		portNodeID := portNodeIDs[portKey]
		if portNodeID == "" {
			continue // 端口未保存则跳过服务
		}

		query := `
			MATCH (p:Port {id: $port_id})
			MERGE (s:Service {id: $id})
			ON CREATE SET s.name = $name, s.version = $version, s.banner = $banner,
				s.title = $title, s.status_code = $status_code, s.tech = $tech,
				s.last_scanned = datetime($now), s.created_at = datetime($now)
			ON MATCH SET s.version = $version, s.banner = $banner, s.title = $title,
				s.status_code = $status_code, s.tech = $tech, s.last_scanned = datetime($now)
			MERGE (p)-[:RUNS]->(s)
		`
		if _, err := session.Run(query, map[string]any{
			"port_id": portNodeID, "id": svc.ID, "name": svc.Name,
			"version": svc.Version, "banner": svc.Banner, "title": svc.Title,
			"status_code": svc.StatusCode, "tech": svc.Tech, "now": now,
		}); err != nil {
			return fmt.Errorf("保存服务失败 %s: %w", svc.Name, err)
		}
	}

	return nil
}

// GetAssetGraph 获取指定域名的完整资产图（节点 + 边）
func (r *AssetRepository) GetAssetGraph(domainID string) (*models.AssetGraph, error) {
	session := r.store.Session()
	defer session.Close()

	graph := &models.AssetGraph{
		Nodes: []models.GraphNode{},
		Edges: []models.GraphEdge{},
	}

	// 1. 查询所有相关节点
	nodeQuery := `
		MATCH (d:Domain {id: $domain_id})
		OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->(s:Subdomain)
		OPTIONAL MATCH (d)-[:RESOLVES_TO]->(i:IP)
		OPTIONAL MATCH (i)-[:EXPOSES]->(p:Port)
		OPTIONAL MATCH (p)-[:RUNS]->(svc:Service)
		RETURN d, s, i, p, svc
	`
	result, err := session.Run(nodeQuery, map[string]any{"domain_id": domainID})
	if err != nil {
		return nil, err
	}

	nodeMap := make(map[string]bool)
	addNode := func(n models.GraphNode) {
		if !nodeMap[n.ID] && n.ID != "" {
			nodeMap[n.ID] = true
			graph.Nodes = append(graph.Nodes, n)
		}
	}

	for result.Next() {
		record := result.Record()
		// Domain
		if val, ok := record.Get("d"); ok {
			if node, ok := val.(neo4j.Node); ok {
				addNode(models.GraphNode{ID: getStr(node.Props, "id"), Label: getStr(node.Props, "name"), Type: "domain"})
			}
		}
		// Subdomain
		if val, ok := record.Get("s"); ok && val != nil {
			if node, ok := val.(neo4j.Node); ok {
				addNode(models.GraphNode{ID: getStr(node.Props, "id"), Label: getStr(node.Props, "name"), Type: "subdomain", SubLabel: getStr(node.Props, "source")})
			}
		}
		// IP
		if val, ok := record.Get("i"); ok && val != nil {
			if node, ok := val.(neo4j.Node); ok {
				alive := ""
				if v, ok := node.Props["is_alive"]; ok {
					if b, ok := v.(bool); ok && b {
						alive = "alive"
					} else {
						alive = "down"
					}
				}
				addNode(models.GraphNode{ID: getStr(node.Props, "id"), Label: getStr(node.Props, "address"), Type: "ip", SubLabel: getStr(node.Props, "version"), Status: alive})
			}
		}
		// Port
		if val, ok := record.Get("p"); ok && val != nil {
			if node, ok := val.(neo4j.Node); ok {
				portNum := getInt(node.Props, "port")
				addNode(models.GraphNode{ID: getStr(node.Props, "id"), Label: fmt.Sprintf("%d", portNum), Type: "port", SubLabel: getStr(node.Props, "service_name"), Status: getStr(node.Props, "state")})
			}
		}
		// Service
		if val, ok := record.Get("svc"); ok && val != nil {
			if node, ok := val.(neo4j.Node); ok {
				name := getStr(node.Props, "name")
				version := getStr(node.Props, "version")
				label := name
				if version != "" {
					label = name + " " + version
				}
				addNode(models.GraphNode{ID: getStr(node.Props, "id"), Label: label, Type: "service", SubLabel: getStr(node.Props, "title")})
			}
		}
	}

	// 2. 查询关系边
	edgeQuery := `
		MATCH (d:Domain {id: $domain_id})-[:HAS_SUBDOMAIN]->(s:Subdomain)
		RETURN d.id AS source, s.id AS target, 'HAS_SUBDOMAIN' AS label
		UNION
		MATCH (d:Domain {id: $domain_id})-[:RESOLVES_TO]->(i:IP)
		RETURN d.id AS source, i.id AS target, 'RESOLVES_TO' AS label
		UNION
		MATCH (d:Domain {id: $domain_id})-[:RESOLVES_TO]->(i:IP)-[:EXPOSES]->(p:Port)
		RETURN i.id AS source, p.id AS target, 'EXPOSES' AS label
		UNION
		MATCH (d:Domain {id: $domain_id})-[:RESOLVES_TO]->(i:IP)-[:EXPOSES]->(p:Port)-[:RUNS]->(svc:Service)
		RETURN p.id AS source, svc.id AS target, 'RUNS' AS label
	`
	edgeResult, err := session.Run(edgeQuery, map[string]any{"domain_id": domainID})
	if err == nil {
		for edgeResult.Next() {
			record := edgeResult.Record()
			source, _ := record.Get("source")
			target, _ := record.Get("target")
			label, _ := record.Get("label")
			if s := anyToString(source); s != "" {
				if t := anyToString(target); t != "" {
					graph.Edges = append(graph.Edges, models.GraphEdge{Source: s, Target: t, Label: anyToString(label)})
				}
			}
		}
	}

	return graph, nil
}

// anyToString 从 neo4j 值安全提取字符串
func anyToString(v any) string {
	if v == nil {
		return ""
	}
	switch val := v.(type) {
	case string:
		return val
	case int64:
		return fmt.Sprintf("%d", val)
	default:
		return fmt.Sprintf("%v", val)
	}
}

// ListAssets 列出指定域名下所有资产明细
func (r *AssetRepository) ListAssets(domainID string) ([]map[string]any, error) {
	session := r.store.Session()
	defer session.Close()

	query := `
		MATCH (d:Domain {id: $domain_id})-[:RESOLVES_TO]->(i:IP)
		OPTIONAL MATCH (i)-[:EXPOSES]->(p:Port)
		OPTIONAL MATCH (p)-[:RUNS]->(svc:Service)
		RETURN i.address AS ip, i.version AS ip_version, i.is_alive AS alive,
			p.port AS port, p.service_name AS service, p.state AS state,
			svc.name AS svc_name, svc.version AS svc_version, svc.title AS svc_title, svc.tech AS tech
		ORDER BY i.address, p.port
	`
	result, err := session.Run(query, map[string]any{"domain_id": domainID})
	if err != nil {
		return nil, err
	}

	var assets []map[string]any
	for result.Next() {
		record := result.Record()
		ip, _ := record.Get("ip")
		ipVersion, _ := record.Get("ip_version")
		alive, _ := record.Get("alive")
		port, _ := record.Get("port")
		service, _ := record.Get("service")
		state, _ := record.Get("state")
		svcName, _ := record.Get("svc_name")
		svcVersion, _ := record.Get("svc_version")
		svcTitle, _ := record.Get("svc_title")
		asset := map[string]any{
			"ip":          anyToString(ip),
			"ip_version":  anyToString(ipVersion),
			"alive":       anyToString(alive),
			"port":        anyToString(port),
			"service":     anyToString(service),
			"state":       anyToString(state),
			"svc_name":    anyToString(svcName),
			"svc_version": anyToString(svcVersion),
			"svc_title":   anyToString(svcTitle),
		}
		assets = append(assets, asset)
	}
	return assets, nil
}
