package api

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"security-agent/internal/config"
	"security-agent/internal/henghao"
)

// HengnaoHandler 恒脑能力接入接口。
//
// 安全约定：**appSecret 永远留在服务端**。平台文档明确要求"不要把 appKey / appSecret / sign
// 硬编码到客户端程序"，所以前端拿到的是本服务端用签名换来的**短期 token**，
// 再拿 token 去拼 iframe 地址。
type HengnaoHandler struct {
	cfg    *config.HengnaoConfig
	client *henghao.Client
}

// NewHengnaoHandler 构造处理器。未配置或未启用时 client 为 nil，
// 各接口会返回明确的"未启用"提示而不是 panic。
func NewHengnaoHandler(cfg *config.HengnaoConfig) *HengnaoHandler {
	h := &HengnaoHandler{cfg: cfg}
	if cfg != nil && cfg.Enabled {
		h.client = henghao.NewClient(henghao.Config{
			BaseURL:   cfg.BaseURL,
			AppKey:    cfg.AppKey,
			AppSecret: cfg.AppSecret,
			AgentID:   cfg.AgentID,
			Timeout:   time.Duration(cfg.TimeoutMs) * time.Millisecond,
		})
	}
	return h
}

// ready 判断是否具备对外提供能力（未配置时各接口据此返回可用提示）。
func (h *HengnaoHandler) ready() bool {
	return h.client != nil && h.client.CredentialsReady()
}

// Status 返回恒脑接入状态，供前端决定是否展示入口。
func (h *HengnaoHandler) Status(c *gin.Context) {
	st := gin.H{
		"enabled":     h.ready(),
		"base_url":    "",
		"agent_id":    "",
		"chatbot":     false,
		"chatbot_url": "",
	}
	if h.cfg != nil {
		st["base_url"] = h.cfg.BaseURL
		st["agent_id"] = h.cfg.AgentID
		st["chatbot"] = h.ready() && h.cfg.ChatbotBaseURL != ""
		st["chatbot_url"] = h.cfg.ChatbotBaseURL
	}
	c.JSON(http.StatusOK, st)
}

// ChatbotTokenResponse 前端嵌入所需的全部信息。
type ChatbotTokenResponse struct {
	Token      string `json:"token"`
	ChatbotURL string `json:"chatbot_url"` // 可直接塞进 iframe 的 src
	UserID     string `json:"user_id"`     // 恒脑侧会话隔离用的集成方用户标识
}

// GetChatbotToken 为当前登录用户换取 Chatbot iframe 访问凭证。
//
// userId 传我们自己的用户 ID：恒脑据此隔离各用户的会话，
// 因此不同用户嵌同一个 iframe 看到的也是各自独立的对话。
func (h *HengnaoHandler) GetChatbotToken(c *gin.Context) {
	if !h.ready() {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "恒脑开放服务未配置或未启用"})
		return
	}
	if h.cfg.ChatbotBaseURL == "" {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "未配置 henghao.chatbot_base_url（小恒插件宿主地址），无法生成嵌入地址"})
		return
	}

	uid := CurrentUserID(c)
	if uid == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未认证"})
		return
	}

	token, err := h.client.GetAssistantToken(c.Request.Context(), uid)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "获取恒脑对话凭证失败: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, ChatbotTokenResponse{
		Token:      token,
		ChatbotURL: henghao.ChatbotURL(h.cfg.ChatbotBaseURL, token),
		UserID:     uid,
	})
}

// LogoutChatbotRequest 注销请求体。
type LogoutChatbotRequest struct {
	Token string `json:"token" binding:"required"`
}

// LogoutChatbot 注销 token：用户退出时调用，避免凭证悬挂。
func (h *HengnaoHandler) LogoutChatbot(c *gin.Context) {
	if !h.ready() {
		c.JSON(http.StatusOK, gin.H{"message": "恒脑未启用，无需注销"})
		return
	}
	var req LogoutChatbotRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "缺少 token"})
		return
	}
	if err := h.client.DelAssistantToken(c.Request.Context(), req.Token); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "注销恒脑凭证失败: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "已注销恒脑对话凭证"})
}
