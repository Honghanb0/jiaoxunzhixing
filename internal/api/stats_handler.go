package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"security-agent/internal/storage"
)

type StatsHandler struct{}

func NewStatsHandler() *StatsHandler {
	return &StatsHandler{}
}

// Get 返回仪表盘所需的聚合统计：域名数、累计扫描次数、漏洞按严重度（去重后）、
// 敏感信息、待处理告警。
//
// 去重口径：以「域名 + 漏洞类型 + 受影响 URL + 参数」为指纹（Vulnerability.fingerprint）。
// 同一域名多次扫描命中的相同漏洞只计 1 个；历史存量漏洞（未落库指纹）回退到节点 id 单独计数，互不影响。
// total_vulnerabilities 为累计命中次数（不去重），deduped_vulnerabilities 为去重后漏洞数。
func (h *StatsHandler) Get(c *gin.Context) {
	if storage.Store == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "数据库未初始化"})
		return
	}
	session := storage.Store.Session()
	defer session.Close()

	const query = `
		MATCH (d:Domain) WITH count(d) AS domains
		OPTIONAL MATCH (j:ScanJob) WITH domains, count(j) AS scans
		OPTIONAL MATCH (v:Vulnerability) WITH domains, scans, count(v) AS total_vulns
		CALL {
			OPTIONAL MATCH (vv:Vulnerability)
			WITH DISTINCT COALESCE(vv.fingerprint, vv.id) AS fp, vv.severity AS sev
			RETURN
				count(fp) AS deduped,
				sum(CASE WHEN sev = 'high' THEN 1 ELSE 0 END) AS high,
				sum(CASE WHEN sev = 'medium' THEN 1 ELSE 0 END) AS medium,
				sum(CASE WHEN sev = 'low' THEN 1 ELSE 0 END) AS low
		}
		OPTIONAL MATCH (s:SensitiveInfo) WITH domains, scans, total_vulns, deduped, high, medium, low, count(s) AS sensitive
		OPTIONAL MATCH (a:Alert) WHERE a.status IN ['new','acknowledged'] WITH domains, scans, total_vulns, deduped, high, medium, low, sensitive, count(a) AS pending_alerts
		RETURN domains, scans, total_vulns, deduped, high, medium, low, sensitive, pending_alerts`

	result, err := session.Run(query, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	stats := gin.H{
		"domains": 0, "scans": 0, "total_vulnerabilities": 0, "deduped_vulnerabilities": 0,
		"high_severity": 0, "medium_severity": 0, "low_severity": 0,
		"sensitive_found": 0, "pending_alerts": 0,
	}
	if result.Next() {
		rec := result.Record()
		if v, ok := rec.Get("domains"); ok {
			stats["domains"] = toInt(v)
		}
		if v, ok := rec.Get("scans"); ok {
			stats["scans"] = toInt(v)
		}
		if v, ok := rec.Get("total_vulns"); ok {
			stats["total_vulnerabilities"] = toInt(v)
		}
		if v, ok := rec.Get("deduped"); ok {
			stats["deduped_vulnerabilities"] = toInt(v)
		}
		if v, ok := rec.Get("high"); ok {
			stats["high_severity"] = toInt(v)
		}
		if v, ok := rec.Get("medium"); ok {
			stats["medium_severity"] = toInt(v)
		}
		if v, ok := rec.Get("low"); ok {
			stats["low_severity"] = toInt(v)
		}
		if v, ok := rec.Get("sensitive"); ok {
			stats["sensitive_found"] = toInt(v)
		}
		if v, ok := rec.Get("pending_alerts"); ok {
			stats["pending_alerts"] = toInt(v)
		}
	}

	c.JSON(http.StatusOK, stats)
}

// toInt 将 Neo4j 返回的整型（int64/float64/int）安全转换为 int。
func toInt(v any) int {
	if v == nil {
		return 0
	}
	switch val := v.(type) {
	case int64:
		return int(val)
	case int:
		return val
	case float64:
		return int(val)
	}
	return 0
}
