// mockai.go 实现本地 OpenAI 兼容 Mock 服务
// （对应原 tools/mock_ai_server.py），用于验证多模型统一接入层：
//   - POST /chat/completions 非流式响应
//   - POST /chat/completions + stream  SSE 流式响应
//   - 校验 Authorization 头：缺头 / 无效 Key 返回 401
//   - `flaky-<n>` Key 前 n 次返回 500，用于验证指数退避重试
//   - 返回内容回显所用模型与鉴权形态，便于确认 GLM 的 JWT 签发是否生效
package ops

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DefaultMockAIPort 为默认监听端口（与原脚本一致）。
const DefaultMockAIPort = 8899

// mockAI 持有一个监听实例的运行时状态。
type mockAI struct {
	addr string

	mu     sync.Mutex
	flaky  map[string]int
	logger func(format string, args ...any)
}

// RunMockAI 启动 Mock 服务直到 ctx 取消。
// port <= 0 时使用 DefaultMockAIPort；host 为空时监听 127.0.0.1。
func RunMockAI(ctx context.Context, host string, port int) error {
	if host == "" {
		host = "127.0.0.1"
	}
	if port <= 0 {
		port = DefaultMockAIPort
	}

	m := &mockAI{
		addr:   net.JoinHostPort(host, strconv.Itoa(port)),
		flaky:  make(map[string]int),
		logger: func(format string, args ...any) { fmt.Fprintf(os.Stderr, "[mock] "+format+"\n", args...) },
	}

	srv := &http.Server{
		Addr:              m.addr,
		Handler:           m.routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		m.logger("OpenAI 兼容 Mock 服务监听于 %s", m.addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("Mock 服务异常退出: %w", err)
			return
		}
		errCh <- nil
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("关闭 Mock 服务失败: %w", err)
		}
		return <-errCh
	}
}

func (m *mockAI) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/chat/completions", m.handleChatCompletions)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		m.logger("404 %s %s", r.Method, r.URL.Path)
		writeJSON(w, http.StatusNotFound, errorBody("not found: "+r.URL.Path))
	})
	return mux
}

func (m *mockAI) handleChatCompletions(w http.ResponseWriter, r *http.Request) {
	m.logger("%s %s", r.Method, r.URL.Path)
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, errorBody("method not allowed: "+r.Method))
		return
	}

	var req struct {
		Model    string `json:"model"`
		Stream   bool   `json:"stream"`
		Messages []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"messages"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody("invalid json"))
		return
	}

	auth := r.Header.Get("Authorization")
	if auth == "" || !strings.HasPrefix(auth, "Bearer ") {
		writeJSON(w, http.StatusUnauthorized, errorBody("missing bearer token"))
		return
	}
	token := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
	if token == "" || token == "invalid-key" {
		writeJSON(w, http.StatusUnauthorized, errorBody("invalid api key"))
		return
	}

	kind := authKind(auth)

	if strings.HasPrefix(token, "flaky-") {
		total := 1
		if parts := strings.Split(token, "-"); len(parts) > 1 {
			if n, err := strconv.Atoi(parts[1]); err == nil {
				total = n
			}
		}
		m.mu.Lock()
		seen := m.flaky[token] + 1
		m.flaky[token] = seen
		m.mu.Unlock()
		if seen <= total {
			writeJSON(w, http.StatusInternalServerError,
				errorBody(fmt.Sprintf("simulated upstream failure #%d", seen)))
			return
		}
	}

	model := req.Model
	if model == "" {
		model = "unknown-model"
	}
	userText := ""
	for i := len(req.Messages) - 1; i >= 0; i-- {
		if req.Messages[i].Role == "user" {
			userText = req.Messages[i].Content
			break
		}
	}

	content := fmt.Sprintf("[model=%s][auth=%s] echo: %s", model, kind, truncateRunes(userText, 120))

	if req.Stream {
		m.writeSSE(w, model, content)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"id":      "chatcmpl-mock",
		"object":  "chat.completion",
		"created": time.Now().Unix(),
		"model":   model,
		"choices": []any{map[string]any{
			"index":         0,
			"message":       map[string]any{"role": "assistant", "content": content},
			"finish_reason": "stop",
		}},
		"usage": map[string]any{
			"prompt_tokens":     runeLen(userText),
			"completion_tokens": runeLen(content),
			"total_tokens":      runeLen(userText) + runeLen(content),
		},
	})
}

func (m *mockAI) writeSSE(w http.ResponseWriter, model, content string) {
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	flusher, canFlush := w.(http.Flusher)
	emit := func(payload any) {
		line, err := json.Marshal(payload)
		if err != nil {
			return
		}
		fmt.Fprintf(w, "data: %s\n\n", line)
		if canFlush {
			flusher.Flush()
		}
	}

	pieces := splitRunes(content, 24)
	if len(pieces) == 0 {
		pieces = []string{"(empty)"}
	}
	for _, piece := range pieces {
		emit(map[string]any{
			"id":      "chatcmpl-mock",
			"object":  "chat.completion.chunk",
			"model":   model,
			"choices": []any{map[string]any{"index": 0, "delta": map[string]any{"role": "assistant", "content": piece}, "finish_reason": nil}},
		})
		time.Sleep(50 * time.Millisecond)
	}

	emit(map[string]any{
		"id":      "chatcmpl-mock",
		"model":   model,
		"choices": []any{map[string]any{"index": 0, "delta": map[string]any{}, "finish_reason": "stop"}},
	})
	fmt.Fprint(w, "data: [DONE]\n\n")
	if canFlush {
		flusher.Flush()
	}
}

// authKind 判断鉴权形态：JWT（GLM）还是静态 sk- Key（DeepSeek/Kimi）。
func authKind(header string) string {
	if header == "" {
		return "none"
	}
	token := strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
	switch {
	case strings.HasPrefix(token, "eyJ"):
		return fmt.Sprintf("jwt(len=%d)", len(token))
	case strings.HasPrefix(token, "sk-"):
		return fmt.Sprintf("static-key(len=%d)", len(token))
	default:
		return fmt.Sprintf("other(len=%d)", len(token))
	}
}

func errorBody(message string) map[string]any {
	return map[string]any{"error": map[string]any{"message": message}}
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	payload, err := json.Marshal(body)
	if err != nil {
		http.Error(w, `{"error":{"message":"marshal failed"}}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(payload)
}

func runeLen(s string) int { return len([]rune(s)) }

func truncateRunes(s string, limit int) string {
	runes := []rune(s)
	if len(runes) <= limit {
		return s
	}
	return string(runes[:limit])
}

func splitRunes(s string, size int) []string {
	runes := []rune(s)
	if len(runes) == 0 {
		return nil
	}
	var out []string
	for i := 0; i < len(runes); i += size {
		end := i + size
		if end > len(runes) {
			end = len(runes)
		}
		out = append(out, string(runes[i:end]))
	}
	return out
}
