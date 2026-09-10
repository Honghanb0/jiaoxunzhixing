package agent

import "strings"

// 建单语义类别：把扫描器产出的具体漏洞类型（sqli/xss/idor/...）归并为若干个「需建单的语义类别」。
// 设计原则（关键）：
//  1. 任何「有类型、但无法识别」的漏洞一律归入 catOther，禁止返回空字符串 —— 空类别会被
//     findingCategories / ticketDeliverableSatisfied 当成「无发现」而静默跳过，是历史漏单主因。
//  2. 仅当 type 为空（非漏洞行，如 URL 节点）时才返回 ""，不参与建单判定。
//  3. 类别集合与扫描器实际产出对齐（见 detector.go ruleIDToVulnType）。
const (
	catWeakPassword = "weak_password"  // 弱口令 / 默认口令
	catDataLeak     = "data_leak"      // 数据泄露（敏感文件 / 敏感信息）
	catInjection    = "injection"      // 注入类：SQLi / 命令注入 / SSTI / XXE
	catAuthConfig   = "auth_config"    // 权限与配置错误：越权 / 认证缺陷 / 配置不当 / SSRF
	catComponent    = "component"      // 依赖组件漏洞（已知漏洞组件）
	catLogic        = "logic"          // 逻辑缺陷（业务逻辑 / 文件上传 / 反序列化 ...）
	catInfoLeak     = "info_leak"      // 信息泄露（目录遍历 / 报错泄露 / 源码 / 备份文件）
	catWebshell     = "webshell"       // Webshell / 后门 / 木马 / 恶意文件（独立于数据泄露，避免与敏感文件混淆）
	catOther        = "other"          // 未归类 / 未知类型（兜底，绝不静默跳过）
)

// vulnTypeToCategory 将具体漏洞类型映射到语义建单类别。
// 返回 "" 仅当 type 本身为空（非漏洞行）；任何非空但无法识别的类型一律归入 catOther。
func vulnTypeToCategory(vulnType string) string {
	t := strings.ToLower(strings.TrimSpace(vulnType))
	if t == "" {
		return ""
	}
	switch t {
	case "weak_password":
		return catWeakPassword
	case "sensitive_file", "sensitive_info":
		return catDataLeak
	// 注入类
	case "sqli", "sql_injection", "command_injection", "ssti", "xxe",
		"ldap_injection", "xpath_injection", "nosql_injection", "header_injection", "crlf_injection":
		return catInjection
	// 权限与配置错误
	case "idor", "broken_auth", "misconfiguration", "unauthorized", "access_control",
		"privilege_escalation", "ssrf", "csrf", "security_misconfiguration":
		return catAuthConfig
	// 依赖组件漏洞
	case "vulnerable_component", "component", "outdated_component", "known_vulnerable_components":
		return catComponent
	// 逻辑缺陷
	case "logic", "race_condition", "business_logic", "file_upload", "deserialization",
		"insecure_deserialization", "tampering":
		return catLogic
	// 信息泄露
	case "info_disclosure", "directory_listing", "error_message", "backup_file",
		"source_leak", "path_traversal", "source_code_exposure", "debug_exposure":
		return catInfoLeak
	// Webshell / 后门 / 木马 / 恶意文件：独立的语义类别，不应并入数据泄露（敏感文件）桶，
	// 否则「只上报 webshell」会被误解析为「要求数据泄露工单」，与用户「其他忽略」的意图冲突。
	case "webshell", "web_shell", "backdoor", "malicious_file", "malware", "trojan",
		"后门", "木马", "恶意文件", "webshell文件":
		return catWebshell
	// 未归类 / 新增 / 未知类型：归入 other，确保任何一条有类型的漏洞都不会因分类失败而被静默跳过。
	default:
		return catOther
	}
}

// isTicketableVulnType 判断某漏洞类型是否需要建单：任何非空（即可归类）的类型都需要。
func isTicketableVulnType(vulnType string) bool {
	return vulnTypeToCategory(vulnType) != ""
}

// categoryLabel 返回语义类别的中文展示名（用于兜底工单标题 / 日志）。
func categoryLabel(cat string) string {
	switch cat {
	case catWeakPassword:
		return "弱口令/默认口令"
	case catDataLeak:
		return "数据泄露（敏感文件/信息）"
	case catInjection:
		return "注入类漏洞"
	case catAuthConfig:
		return "权限与配置错误"
	case catComponent:
		return "依赖组件漏洞"
	case catLogic:
		return "逻辑缺陷"
	case catInfoLeak:
		return "信息泄露"
	case catWebshell:
		return "Webshell/后门/恶意文件"
	case catOther:
		return "未归类/未知类型漏洞"
	default:
		return "安全漏洞"
	}
}

// defaultRiskForCategory 在漏洞未提供严重程度时，按类别给出可追溯的默认风险等级。
// （注入 / 权限 / 数据泄露危害最高，组件 / 逻辑 / 信息泄露默认中危，未知类型保守取中危。）
func defaultRiskForCategory(cat string) string {
	switch cat {
	case catWeakPassword, catDataLeak, catInjection, catAuthConfig, catWebshell:
		return "high"
	case catComponent, catLogic, catInfoLeak, catOther:
		return "medium"
	default:
		return "medium"
	}
}
