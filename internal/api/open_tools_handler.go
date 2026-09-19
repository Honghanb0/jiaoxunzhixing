package api

import (
	"crypto/hmac"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"security-agent/internal/agent"
	"security-agent/internal/config"
)

// OpenToolsHandler 把本平台的智能体工具以 HTTP 形式开放给第三方平台调用。
//
// 用途：对接恒脑平台的「API 工具」——让恒脑侧编排的智能体能调用我们的
// 扫描/检索能力（《企业命题》答题要求⑥ 的编排侧落地）。
//
// 与 /api/agent/* 的区别（刻意分开，不要混用）：
//   - /api/agent/*   面向本平台前端，用户 JWT 鉴权 + 角色等级校验；
//   - /api/open/*    面向机器（第三方平台），**服务密钥**鉴权，
//     只暴露"工具清单 + 执行入口"，不涉及任务、工单等平台内部概念。
//
// 只依赖 ToolRegistry（而不是整个 Manager）：本组接口只做"列工具 / 执行工具"，
// 不碰任务、工单等平台内部概念，依赖面越小越不容易被后续改动带偏。
type OpenToolsHandler struct {
	reg *agent.ToolRegistry
	cfg *config.OpenServiceConfig
}

// NewOpenToolsHandler 构造处理器。
func NewOpenToolsHandler(reg *agent.ToolRegistry, cfg *config.OpenServiceConfig) *OpenToolsHandler {
	return &OpenToolsHandler{reg: reg, cfg: cfg}
}

// DefaultServiceKeyHeader 服务密钥默认放在名为 X-API-Key 的请求头里。
const DefaultServiceKeyHeader = "X-API-Key"

// KeyHeaderName 返回实际使用的请求头名。
func KeyHeaderName(cfg *config.OpenServiceConfig) string {
	if cfg != nil && strings.TrimSpace(cfg.Header) != "" {
		return strings.TrimSpace(cfg.Header)
	}
	return DefaultServiceKeyHeader
}

// RequireServiceKey 校验第三方调用方携带的服务密钥。
//
// 用 hmac.Equal 做**定长比较**，避免按字节短路带来的时序侧信道
// （普通 == 比较在第一个不同字节就返回，理论上可被逐字节探测）。
func RequireServiceKey(cfg *config.OpenServiceConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		if cfg == nil || !cfg.Enabled {
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "对外工具服务未启用"})
			return
		}
		want := strings.TrimSpace(cfg.APIKey)
		if want == "" {
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "未配置服务密钥（open_service.api_key），拒绝所有外部调用"})
			return
		}
		got := strings.TrimSpace(c.GetHeader(KeyHeaderName(cfg)))
		if got == "" || !hmac.Equal([]byte(got), []byte(want)) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "服务密钥无效"})
			return
		}
		c.Next()
	}
}

// blocked 判断某工具是否被禁止外露。
func (h *OpenToolsHandler) blocked(name string) bool {
	if h.cfg == nil {
		return false
	}
	for _, b := range h.cfg.BlockedTools {
		if strings.EqualFold(strings.TrimSpace(b), name) {
			return true
		}
	}
	return false
}

// ToolSpec 对外暴露的工具描述。
type ToolSpec struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Schema      map[string]any `json:"schema"`
}

// ListTools 返回可被第三方平台注册的工具清单。
//
// GET /api/open/tools
//
// 第三方（恒脑「API 工具」）按本清单逐个建工具即可，不需要人工抄参数表。
func (h *OpenToolsHandler) ListTools(c *gin.Context) {
	if h.reg == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "智能体未启用，无可用工具"})
		return
	}
	specs := make([]ToolSpec, 0, 32)
	for _, t := range h.reg.All() {
		if h.blocked(t.Name()) {
			continue
		}
		specs = append(specs, ToolSpec{Name: t.Name(), Description: t.Description(), Schema: t.Schema()})
	}
	c.JSON(http.StatusOK, gin.H{"count": len(specs), "tools": specs})
}

// ExecuteToolResponse 工具执行结果。
type ExecuteToolResponse struct {
	OK     bool   `json:"ok"`
	Name   string `json:"name"`
	Result string `json:"result,omitempty"`
	Error  string `json:"error,omitempty"`
}

// Execute 执行指定工具。
//
// POST /api/open/tools/:name     body = 该工具的入参 JSON 对象
//
// 返回：{ok:true, result:"..."} 或 {ok:false, error:"..."}。
// 工具自身返回的文本（通常是 JSON 字符串）原样放在 result 里，
// 以便第三方智能体把它当作工具观察结果继续推理。
func (h *OpenToolsHandler) Execute(c *gin.Context) {
	if h.reg == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "智能体未启用，无可用工具"})
		return
	}
	name := strings.TrimSpace(c.Param("name"))
	if name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "缺少工具名"})
		return
	}
	if h.blocked(name) {
		// 明说原因，避免第三方侧反复重试一个永远不可用的工具
		c.JSON(http.StatusForbidden, gin.H{"error": "该工具不对外开放（属于智能体流程控制类）: " + name})
		return
	}
	tool, ok := h.reg.Get(name)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "工具不存在: " + name})
		return
	}

	// 入参允许为空对象（部分工具无参）
	args := map[string]any{}
	if c.Request.ContentLength > 0 {
		if err := c.ShouldBindJSON(&args); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "入参必须是 JSON 对象: " + err.Error()})
			return
		}
	}

	result, err := tool.Execute(c.Request.Context(), args)
	if err != nil {
		// 工具执行失败属于业务结果，仍返回 200 + ok:false，
		// 这样第三方智能体可以读到失败原因并调整后续动作（而不是只看到一个 HTTP 错误码）。
		c.JSON(http.StatusOK, ExecuteToolResponse{OK: false, Name: name, Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, ExecuteToolResponse{OK: true, Name: name, Result: result})
}
