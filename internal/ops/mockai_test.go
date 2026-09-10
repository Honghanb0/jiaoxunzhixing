package ops_test

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"security-agent/internal/ops"
)

// startMockAI 在指定端口启动 Mock 服务，返回取消函数。
func startMockAI(t *testing.T, port int) context.CancelFunc {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- ops.RunMockAI(ctx, "127.0.0.1", port) }()

	// 等待服务就绪
	addr := httpURL(port)
	for i := 0; i < 50; i++ {
		conn, err := http.Get(addr + "/healthz") //nolint:noctx
		if err == nil {
			_ = conn.Body.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("Mock 服务未能在超时时间内退出")
		}
	})
	return cancel
}

func httpURL(port int) string {
	return fmt.Sprintf("http://127.0.0.1:%d", port)
}

func post(t *testing.T, port int, token, body string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, httpURL(port)+"/chat/completions", strings.NewReader(body))
	if err != nil {
		t.Fatalf("构造请求失败: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	defer resp.Body.Close()
	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("读取响应失败: %v", err)
	}
	return resp, string(payload)
}

func TestMockAI_ChatCompletions(t *testing.T) {
	const port = 18899
	startMockAI(t, port)

	resp, body := post(t, port, "sk-unit-test", `{"model":"unit-model","messages":[{"role":"user","content":"ping"}]}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("期望 200，实际 %d，body=%s", resp.StatusCode, body)
	}

	var decoded struct {
		ID      string `json:"id"`
		Object  string `json:"object"`
		Model   string `json:"model"`
		Choices []struct {
			Index   int `json:"index"`
			Message struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
		Usage struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
			TotalTokens      int `json:"total_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal([]byte(body), &decoded); err != nil {
		t.Fatalf("响应不是合法 JSON: %v，body=%s", err, body)
	}
	if decoded.Object != "chat.completion" || decoded.Model != "unit-model" {
		t.Errorf("object/model 不符合预期: %+v", decoded)
	}
	if len(decoded.Choices) != 1 || decoded.Choices[0].Message.Role != "assistant" {
		t.Fatalf("choices 不符合预期: %+v", decoded.Choices)
	}
	want := "[model=unit-model][auth=static-key(len=12)] echo: ping"
	if got := decoded.Choices[0].Message.Content; got != want {
		t.Errorf("content 不匹配\nwant=%q\ngot =%q", want, got)
	}
	if decoded.Usage.PromptTokens != 4 || decoded.Usage.TotalTokens <= 0 {
		t.Errorf("usage 统计异常: %+v", decoded.Usage)
	}
}

func TestMockAI_Auth(t *testing.T) {
	const port = 18900
	startMockAI(t, port)

	cases := []struct {
		name  string
		token string
		want  int
	}{
		{"缺 Authorization 头", "", http.StatusUnauthorized},
		{"无效 Key", "invalid-key", http.StatusUnauthorized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, _ := post(t, port, tc.token, `{"model":"m","messages":[]}`)
			if resp.StatusCode != tc.want {
				t.Errorf("期望 %d，实际 %d", tc.want, resp.StatusCode)
			}
		})
	}
}

func TestMockAI_FlakyRetry(t *testing.T) {
	const port = 18901
	startMockAI(t, port)

	first, _ := post(t, port, "flaky-1", `{"model":"m","messages":[]}`)
	if first.StatusCode != http.StatusInternalServerError {
		t.Fatalf("flaky Key 首次应返回 500，实际 %d", first.StatusCode)
	}
	second, body := post(t, port, "flaky-1", `{"model":"m","messages":[]}`)
	if second.StatusCode != http.StatusOK {
		t.Fatalf("flaky Key 第二次应返回 200，实际 %d，body=%s", second.StatusCode, body)
	}
}

func TestMockAI_Stream(t *testing.T) {
	const port = 18902
	startMockAI(t, port)

	// 流式响应需要边收边读，不能使用会一次性读完 body 的 post 辅助函数。
	req, err := http.NewRequest(http.MethodPost, httpURL(port)+"/chat/completions",
		strings.NewReader(`{"model":"stream-model","messages":[{"role":"user","content":"hello stream"}],"stream":true}`))
	if err != nil {
		t.Fatalf("构造请求失败: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer sk-unit")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("流式请求应返回 200，实际 %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/event-stream") {
		t.Errorf("Content-Type 应为 text/event-stream，实际 %q", ct)
	}

	scanner := bufio.NewScanner(resp.Body)
	var dataLines int
	var sawDone bool
	var content strings.Builder
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		payload := strings.TrimPrefix(line, "data: ")
		if payload == "[DONE]" {
			sawDone = true
			continue
		}
		dataLines++
		var chunk struct {
			Choices []struct {
				Delta struct {
					Content string `json:"content"`
				} `json:"delta"`
			} `json:"choices"`
		}
		if err := json.Unmarshal([]byte(payload), &chunk); err != nil {
			t.Fatalf("SSE 数据块解析失败: %v，payload=%s", err, payload)
		}
		if len(chunk.Choices) > 0 {
			content.WriteString(chunk.Choices[0].Delta.Content)
		}
	}
	if dataLines == 0 || !sawDone {
		t.Fatalf("SSE 输出不完整：数据块 %d 条，收到 [DONE]=%v", dataLines, sawDone)
	}
	if !strings.Contains(content.String(), "echo: hello stream") {
		t.Errorf("流式内容未包含回显: %q", content.String())
	}
}
