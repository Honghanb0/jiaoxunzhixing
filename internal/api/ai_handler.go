package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"security-agent/internal/ai"
)

// AIHandler 暴露多模型统一接入层的 HTTP 接口
type AIHandler struct {
	mgr *ai.Manager
}

func NewAIHandler(mgr *ai.Manager) *AIHandler {
	return &AIHandler{mgr: mgr}
}

type aiChatRequest struct {
	Prompt      string   `json:"prompt"`
	System      string   `json:"system,omitempty"`
	Provider    string   `json:"provider,omitempty"`
	Model       string   `json:"model,omitempty"`
	Temperature *float64 `json:"temperature,omitempty"`
	MaxTokens   int      `json:"max_tokens,omitempty"`
	Providers   []string `json:"providers,omitempty"` // compare 时指定参与对比的模型
}

type aiDefaultRequest struct {
	Provider string `json:"provider"`
	Strategy string `json:"strategy"`
}

// ListProviders 列出全部已注册模型及其配置状态
// GET /api/ai/providers
func (h *AIHandler) ListProviders(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"default":   h.mgr.DefaultName(),
		"strategy":  h.mgr.Strategy(),
		"fallback":  h.mgr.FallbackEnabled(),
		"ready":     h.mgr.Ready(),
		"providers": h.mgr.List(),
	})
}

// SetDefault 运行时切换默认模型与调用策略（管理员）
// PUT /api/ai/default
func (h *AIHandler) SetDefault(c *gin.Context) {
	var req aiDefaultRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求格式错误: " + err.Error()})
		return
	}
	if err := h.mgr.SetDefault(req.Provider, req.Strategy); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message":  "已更新",
		"default":  h.mgr.DefaultName(),
		"strategy": h.mgr.Strategy(),
	})
}

// Chat 按当前策略（或指定模型）发起对话
// POST /api/ai/chat
func (h *AIHandler) Chat(c *gin.Context) {
	var req aiChatRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求格式错误: " + err.Error()})
		return
	}
	if strings.TrimSpace(req.Prompt) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "prompt 不能为空"})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), h.mgr.Timeout()+5*time.Second)
	defer cancel()

	cr := h.buildRequest(&req)

	var (
		resp *ai.ChatResponse
		err  error
	)
	if strings.TrimSpace(req.Provider) != "" {
		resp, err = h.mgr.ChatWith(ctx, req.Provider, cr)
	} else {
		resp, err = h.mgr.Chat(ctx, cr)
	}
	if err != nil {
		status := http.StatusBadGateway
		if strings.Contains(err.Error(), ai.ErrNoProvider.Error()) ||
			strings.Contains(err.Error(), ai.ErrProviderNotFound.Error()) {
			status = http.StatusServiceUnavailable
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"provider":      resp.Provider,
		"model":         resp.Model,
		"content":       resp.Content,
		"usage":         resp.Usage,
		"latency_ms":    resp.LatencyMs,
		"finish_reason": resp.FinishReason,
	})
}

// Stream 流式对话（SSE）
// POST /api/ai/chat/stream
func (h *AIHandler) Stream(c *gin.Context) {
	var req aiChatRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求格式错误: " + err.Error()})
		return
	}
	if strings.TrimSpace(req.Prompt) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "prompt 不能为空"})
		return
	}

	ctx, cancel := context.WithCancel(c.Request.Context())
	defer cancel()

	ch, err := h.mgr.Stream(ctx, req.Provider, h.buildRequest(&req))
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": err.Error()})
		return
	}

	c.Header("Content-Type", "text/event-stream; charset=utf-8")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("X-Accel-Buffering", "no")

	c.Stream(func(w io.Writer) bool {
		select {
		case chunk, ok := <-ch:
			if !ok {
				return false
			}
			payload, _ := json.Marshal(chunk)
			fmt.Fprintf(w, "data: %s\n\n", payload)
			return !chunk.Done
		case <-ctx.Done():
			// 客户端断开：立即结束，避免 goroutine 悬挂
			return false
		}
	})
}

// Compare 并行调用多个模型并对比结果
// POST /api/ai/compare
func (h *AIHandler) Compare(c *gin.Context) {
	var req aiChatRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求格式错误: " + err.Error()})
		return
	}
	if strings.TrimSpace(req.Prompt) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "prompt 不能为空"})
		return
	}

	// 每家最多等 timeout，整体再放宽一些
	ctx, cancel := context.WithTimeout(c.Request.Context(), h.mgr.Timeout()+10*time.Second)
	defer cancel()

	cr := h.buildRequest(&req)

	// 显式指定了参与方时，仅对比这几家（并发执行，按入参顺序回填）
	if len(req.Providers) > 0 {
		filtered := make([]*ai.ProviderResult, len(req.Providers))
		var wg sync.WaitGroup
		for i, name := range req.Providers {
			wg.Add(1)
			go func(idx int, n string) {
				defer wg.Done()
				defer func() {
					if rec := recover(); rec != nil {
						filtered[idx] = &ai.ProviderResult{Provider: n, OK: false, Error: fmt.Sprintf("内部错误: %v", rec)}
					}
				}()
				r := &ai.ProviderResult{Provider: n}
				resp, err := h.mgr.ChatWith(ctx, n, cr)
				if err != nil {
					r.OK = false
					r.Error = err.Error()
				} else {
					r.OK = true
					r.Content = resp.Content
					r.Model = resp.Model
					r.Usage = resp.Usage
					r.LatencyMs = resp.LatencyMs
				}
				filtered[idx] = r
			}(i, name)
		}
		wg.Wait()
		c.JSON(http.StatusOK, gin.H{"default": h.mgr.DefaultName(), "results": filtered})
		return
	}

	results, err := h.mgr.ChatParallel(ctx, cr)
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"default": h.mgr.DefaultName(), "results": results})
}

// TestProvider 对指定模型做一次极短请求，验证 Key 与连通性
// POST /api/ai/providers/:name/test
func (h *AIHandler) TestProvider(c *gin.Context) {
	name := strings.ToLower(strings.TrimSpace(c.Param("name")))
	p, err := h.mgr.Get(name)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	info := p.Info()
	if !info.Configured {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"provider": name,
			"ok":       false,
			"error":    "未配置 API Key",
		})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	start := time.Now()
	resp, err := h.mgr.ChatWith(ctx, name, ai.NewChatRequest("回复 OK 两个字，不要输出其他内容。", ""))
	latency := time.Since(start).Milliseconds()

	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{
			"provider":   name,
			"ok":         false,
			"error":      err.Error(),
			"latency_ms": latency,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"provider":   name,
		"ok":         true,
		"model":      resp.Model,
		"content":    resp.Content,
		"latency_ms": latency,
	})
}

func (h *AIHandler) buildRequest(req *aiChatRequest) *ai.ChatRequest {
	system := req.System
	if system == "" {
		system = "你是一名专业的安全分析助手，回答简洁准确。"
	}
	cr := ai.NewChatRequest(req.Prompt, system)
	cr.Options.Model = req.Model
	cr.Options.Temperature = req.Temperature
	cr.Options.MaxTokens = req.MaxTokens
	return cr
}
