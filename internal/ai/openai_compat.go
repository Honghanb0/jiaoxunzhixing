package ai

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// 三家厂商都采用 OpenAI 兼容的 /chat/completions 协议，
// 差异集中在 base_url 与鉴权头的生成方式上，因此抽出一个通用传输层，
// 由各厂商只提供 spec（端点、模型、token 生成器）。

type compatSpec struct {
	name         string
	displayName  string
	authMode     string
	model        string
	baseURL      string
	enabled      bool
	timeout      time.Duration
	maxRetries   int
	retryBackoff time.Duration
	// token 返回 Authorization 头的值；JWT 类鉴权需在此做缓存
	token func() (string, error)
}

type compatProvider struct {
	spec    compatSpec
	client  *http.Client
	enabled bool
	hasKey  bool
}

func newCompatProvider(spec compatSpec) *compatProvider {
	if spec.timeout <= 0 {
		spec.timeout = 60 * time.Second
	}
	if spec.maxRetries < 0 {
		spec.maxRetries = 0
	}
	if spec.retryBackoff <= 0 {
		spec.retryBackoff = 500 * time.Millisecond
	}
	p := &compatProvider{
		spec: spec,
		client: &http.Client{
			Timeout: spec.timeout,
			Transport: &http.Transport{
				MaxIdleConns:        64,
				MaxIdleConnsPerHost: 8,
				IdleConnTimeout:     90 * time.Second,
				ForceAttemptHTTP2:   true,
			},
		},
	}

	// 探测 Key 是否可用：能成功生成鉴权令牌即视为已配置
	p.enabled = spec.enabled
	if spec.token != nil {
		if _, err := spec.token(); err == nil {
			p.hasKey = true
		}
	}
	return p
}

// ---------- 线路格式 ----------

type wireMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type wireRequest struct {
	Model       string        `json:"model"`
	Messages    []wireMessage `json:"messages"`
	Stream      bool          `json:"stream,omitempty"`
	Temperature *float64      `json:"temperature,omitempty"`
	TopP        *float64      `json:"top_p,omitempty"`
	MaxTokens   int           `json:"max_tokens,omitempty"`
	Stop        []string      `json:"stop,omitempty"`
}

type wireResponse struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	Model   string `json:"model"`
	Choices []struct {
		Index        int         `json:"index"`
		Message      wireMessage `json:"message"`
		Delta        wireMessage `json:"delta"`
		FinishReason string      `json:"finish_reason"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		TotalTokens      int `json:"total_tokens"`
	} `json:"usage"`
	Error *struct {
		Message string `json:"message"`
		Type    string `json:"type"`
		Code    string `json:"code"`
	} `json:"error"`
}

// ---------- Provider 实现 ----------

func (p *compatProvider) Name() string { return p.spec.name }

func (p *compatProvider) Info() ProviderInfo {
	return ProviderInfo{
		Name:        p.spec.name,
		DisplayName: p.spec.displayName,
		Model:       p.spec.model,
		BaseURL:     p.spec.baseURL,
		AuthMode:    p.spec.authMode,
		Enabled:     p.enabled,
		Configured:  p.hasKey,
		TimeoutMs:   p.spec.timeout.Milliseconds(),
	}
}

func (p *compatProvider) Chat(ctx context.Context, req *ChatRequest) (*ChatResponse, error) {
	body, err := p.marshal(req, false)
	if err != nil {
		return nil, err
	}

	start := time.Now()
	resp, err := p.post(ctx, body, false)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, fmt.Errorf("%s: 读取响应失败: %w", p.spec.name, err)
	}
	if resp.StatusCode >= 400 {
		return nil, p.parseError(resp.StatusCode, raw)
	}

	var out wireResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("%s: 解析响应失败: %w (原文: %s)", p.spec.name, err, truncate(string(raw), 300))
	}
	if out.Error != nil {
		return nil, fmt.Errorf("%s: %s", p.spec.name, out.Error.Message)
	}
	if len(out.Choices) == 0 {
		return nil, fmt.Errorf("%s: %w", p.spec.name, ErrEmptyResponse)
	}

	content := out.Choices[0].Message.Content
	if content == "" {
		// 个别厂商在某些模型上只回填 delta，这里做一次兼容
		content = out.Choices[0].Delta.Content
	}
	if content == "" {
		return nil, fmt.Errorf("%s: %w", p.spec.name, ErrEmptyResponse)
	}

	model := out.Model
	if model == "" {
		model = p.effectiveModel(req)
	}

	res := &ChatResponse{
		Provider:     p.spec.name,
		Model:        model,
		Content:      content,
		FinishReason: out.Choices[0].FinishReason,
		ID:           out.ID,
		Usage: Usage{
			PromptTokens:     out.Usage.PromptTokens,
			CompletionTokens: out.Usage.CompletionTokens,
			TotalTokens:      out.Usage.TotalTokens,
		},
		Latency:   time.Since(start),
		LatencyMs: time.Since(start).Milliseconds(),
	}
	return res, nil
}

func (p *compatProvider) ChatStream(ctx context.Context, req *ChatRequest) (<-chan StreamChunk, error) {
	body, err := p.marshal(req, true)
	if err != nil {
		return nil, err
	}
	resp, err := p.post(ctx, body, true)
	if err != nil {
		return nil, err
	}

	ch := make(chan StreamChunk, 32)
	model := p.effectiveModel(req)

	go func() {
		// 无论正常结束还是异常退出，都要收尾，避免调用方永久阻塞
		defer close(ch)
		defer resp.Body.Close()

		streamCtx, cancel := context.WithCancel(ctx)
		defer cancel()

		scanner := bufio.NewScanner(resp.Body)
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

		send := func(c StreamChunk) bool {
			select {
			case ch <- c:
				return true
			case <-streamCtx.Done():
				return false
			}
		}

		for scanner.Scan() {
			select {
			case <-streamCtx.Done():
				return
			default:
			}

			line := strings.TrimSpace(scanner.Text())
			if line == "" || !strings.HasPrefix(line, "data:") {
				continue
			}
			data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			if data == "" {
				continue
			}
			if data == "[DONE]" {
				send(StreamChunk{Provider: p.spec.name, Model: model, Done: true})
				return
			}

			var out wireResponse
			if err := json.Unmarshal([]byte(data), &out); err != nil {
				continue
			}
			if out.Error != nil {
				send(StreamChunk{Provider: p.spec.name, Model: model, Done: true, Err: fmt.Errorf("%s", out.Error.Message), Error: out.Error.Message})
				return
			}
			for _, c := range out.Choices {
				if c.Delta.Content == "" {
					continue
				}
				if !send(StreamChunk{Provider: p.spec.name, Model: model, Content: c.Delta.Content}) {
					return
				}
			}
		}
		send(StreamChunk{Provider: p.spec.name, Model: model, Done: true})
	}()

	return ch, nil
}

// ---------- 内部方法 ----------

func (p *compatProvider) effectiveModel(req *ChatRequest) string {
	if req != nil && req.Options != nil && req.Options.Model != "" {
		return req.Options.Model
	}
	return p.spec.model
}

func (p *compatProvider) marshal(req *ChatRequest, stream bool) ([]byte, error) {
	if req == nil || len(req.Messages) == 0 {
		return nil, fmt.Errorf("%s: 请求内容为空", p.spec.name)
	}

	msgs := make([]wireMessage, 0, len(req.Messages)+1)
	if req.Options != nil && req.Options.SystemPrompt != "" {
		msgs = append(msgs, wireMessage{Role: RoleSystem, Content: req.Options.SystemPrompt})
	}
	for _, m := range req.Messages {
		if m.Role == "" {
			m.Role = RoleUser
		}
		msgs = append(msgs, wireMessage{Role: m.Role, Content: m.Content})
	}

	wr := wireRequest{
		Model:    p.effectiveModel(req),
		Messages: msgs,
		Stream:   stream,
	}
	if req.Options != nil {
		wr.Temperature = req.Options.Temperature
		wr.TopP = req.Options.TopP
		wr.MaxTokens = req.Options.MaxTokens
		wr.Stop = req.Options.Stop
	}

	return json.Marshal(wr)
}

// post 发起请求并在可重试错误上做指数退避重试。
// 返回值为 nil 错误时，调用方负责关闭 resp.Body。
func (p *compatProvider) post(ctx context.Context, body []byte, stream bool) (*http.Response, error) {
	endpoint := strings.TrimSuffix(p.spec.baseURL, "/") + "/chat/completions"

	var lastErr error
	for attempt := 0; ; attempt++ {
		// 上下文已取消（超时/客户端断开）→ 立即放弃，不做无意义重试
		if ctx.Err() != nil {
			if lastErr == nil {
				lastErr = ctx.Err()
			}
			return nil, lastErr
		}

		if attempt > 0 {
			wait := p.spec.retryBackoff * time.Duration(1<<(attempt-1))
			if wait > 8*time.Second {
				wait = 8 * time.Second
			}
			select {
			case <-ctx.Done():
				return nil, lastErr
			case <-time.After(wait):
			}
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("%s: 构造请求失败: %w", p.spec.name, err)
		}
		req.Header.Set("Content-Type", "application/json")
		if stream {
			req.Header.Set("Accept", "text/event-stream")
		} else {
			req.Header.Set("Accept", "application/json")
		}

		token, err := p.spec.token()
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := p.client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("%s: 请求失败: %w", p.spec.name, err)
			if attempt >= p.spec.maxRetries || ctx.Err() != nil {
				return nil, lastErr
			}
			continue
		}

		if resp.StatusCode < 400 {
			return resp, nil
		}

		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8*1024))
		resp.Body.Close()
		lastErr = p.parseError(resp.StatusCode, raw)

		if attempt >= p.spec.maxRetries || !retryable(resp.StatusCode) {
			return nil, lastErr
		}
	}
}

func (p *compatProvider) parseError(status int, raw []byte) error {
	msg := strings.TrimSpace(string(raw))
	if msg != "" {
		var out wireResponse
		if err := json.Unmarshal(raw, &out); err == nil && out.Error != nil && out.Error.Message != "" {
			return fmt.Errorf("%s: HTTP %d - %s", p.spec.name, status, out.Error.Message)
		}
		return fmt.Errorf("%s: HTTP %d - %s", p.spec.name, status, truncate(msg, 300))
	}
	return fmt.Errorf("%s: HTTP %d", p.spec.name, status)
}

func retryable(status int) bool {
	switch status {
	case http.StatusTooManyRequests, // 429
		http.StatusInternalServerError, // 500
		http.StatusBadGateway,          // 502
		http.StatusServiceUnavailable,  // 503
		http.StatusGatewayTimeout,      // 504
		http.StatusRequestTimeout:      // 408
		return true
	}
	return false
}

func truncate(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n]) + "..."
}

// staticToken 静态 Bearer Key（DeepSeek / Kimi）
func staticToken(key string) func() (string, error) {
	return func() (string, error) {
		if key == "" {
			return "", fmt.Errorf("API Key 未配置")
		}
		return key, nil
	}
}

// 供 GLM 复用的并发安全 token 缓存骨架
type tokenCache struct {
	mu    sync.Mutex
	token string
	until time.Time
}
