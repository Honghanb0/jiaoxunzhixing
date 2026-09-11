package models

import "time"

// IP 网络资产 - IP 地址节点
type IP struct {
	ID          string    `json:"id" neo4j:"id"`
	Address     string    `json:"address" neo4j:"address"`   // IPv4/IPv6 地址
	Version     string    `json:"version" neo4j:"version"`   // ipv4 / ipv6
	Geo         string    `json:"geo,omitempty" neo4j:"geo"` // 地理位置
	ISP         string    `json:"isp,omitempty" neo4j:"isp"` // 运营商/云厂商
	IsAlive     bool      `json:"is_alive" neo4j:"is_alive"` // 是否存活
	LastScanned time.Time `json:"last_scanned" neo4j:"last_scanned"`
	CreatedAt   time.Time `json:"created_at" neo4j:"created_at"`
}

// Port 端口资产
type Port struct {
	ID          string    `json:"id" neo4j:"id"`
	IPID        string    `json:"ip_id" neo4j:"ip_id"`               // 所属 IP 节点 ID
	IPAddress   string    `json:"ip_address" neo4j:"ip_address"`     // 所属 IP 地址（扫描时填充，便于仓储关联）
	Port        int       `json:"port" neo4j:"port"`                 // 端口号
	Protocol    string    `json:"protocol" neo4j:"protocol"`         // tcp / udp
	State       string    `json:"state" neo4j:"state"`               // open / closed / filtered
	ServiceName string    `json:"service_name" neo4j:"service_name"` // 服务名称 (http/ssh/...)
	Banner      string    `json:"banner,omitempty" neo4j:"banner"`   // 服务 banner
	LastScanned time.Time `json:"last_scanned" neo4j:"last_scanned"`
	CreatedAt   time.Time `json:"created_at" neo4j:"created_at"`
}

// Service 应用服务
type Service struct {
	ID          string    `json:"id" neo4j:"id"`
	PortID      string    `json:"port_id" neo4j:"port_id"`                   // 所属端口节点 ID
	IPAddress   string    `json:"ip_address" neo4j:"ip_address"`             // 所属 IP 地址（扫描时填充，便于仓储关联）
	PortNum     int       `json:"port_num" neo4j:"port_num"`                 // 端口号（扫描时填充，便于仓储关联）
	Name        string    `json:"name" neo4j:"name"`                         // 服务名称 (nginx/apache/tomcat...)
	Version     string    `json:"version,omitempty" neo4j:"version"`         // 版本号
	CPE         string    `json:"cpe,omitempty" neo4j:"cpe"`                 // CPE 标识
	Banner      string    `json:"banner,omitempty" neo4j:"banner"`           // 完整 banner
	Title       string    `json:"title,omitempty" neo4j:"title"`             // HTTP 页面标题
	StatusCode  int       `json:"status_code,omitempty" neo4j:"status_code"` // HTTP 状态码
	Tech        []string  `json:"tech,omitempty" neo4j:"tech"`               // 技术栈指纹
	LastScanned time.Time `json:"last_scanned" neo4j:"last_scanned"`
	CreatedAt   time.Time `json:"created_at" neo4j:"created_at"`
}

// Subdomain 子域名
type Subdomain struct {
	ID          string    `json:"id" neo4j:"id"`
	DomainID    string    `json:"domain_id" neo4j:"domain_id"` // 父域名 ID
	Name        string    `json:"name" neo4j:"name"`           // 子域名完整名称
	Source      string    `json:"source" neo4j:"source"`       // crtsh / brute / dns
	LastScanned time.Time `json:"last_scanned" neo4j:"last_scanned"`
	CreatedAt   time.Time `json:"created_at" neo4j:"created_at"`
}

// AssetScanJob 资产扫描任务
type AssetScanJob struct {
	ID             string     `json:"id" neo4j:"id"`
	DomainID       string     `json:"domain_id" neo4j:"domain_id"`
	Status         string     `json:"status" neo4j:"status"` // pending/running/completed/failed
	SubdomainCount int        `json:"subdomain_count" neo4j:"subdomain_count"`
	IPCount        int        `json:"ip_count" neo4j:"ip_count"`
	PortCount      int        `json:"port_count" neo4j:"port_count"`
	ServiceCount   int        `json:"service_count" neo4j:"service_count"`
	StartedAt      time.Time  `json:"started_at" neo4j:"started_at"`
	CompletedAt    *time.Time `json:"completed_at,omitempty" neo4j:"completed_at"`
	CreatedAt      time.Time  `json:"created_at" neo4j:"created_at"`
}

// GraphNode 资产图节点（前端拓扑用）
type GraphNode struct {
	ID       string                 `json:"id"`
	Label    string                 `json:"label"`
	Type     string                 `json:"type"` // domain / ip / port / service / subdomain
	SubLabel string                 `json:"sub_label,omitempty"`
	Status   string                 `json:"status,omitempty"` // open / closed / alive / dead
	Data     map[string]interface{} `json:"data,omitempty"`
}

// GraphEdge 资产图边
type GraphEdge struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Label  string `json:"label,omitempty"`
}

// AssetGraph 完整资产图数据
type AssetGraph struct {
	Nodes []GraphNode `json:"nodes"`
	Edges []GraphEdge `json:"edges"`
}
