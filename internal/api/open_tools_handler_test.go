package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"security-agent/internal/agent"
	"security-agent/internal/config"
)

// fakeTool 用于测试的最小工具实现。
type fakeTool struct {
	name string
	desc string
	fn   func(ctx context.Context, args map[string]any) (string, error)
}

func (f fakeTool) Name() string           { return f.name }
func (f fakeTool) Description() string    { return f.desc }
func (f fakeTool) Schema() map[string]any { return map[string]any{"type": "object"} }
func (f fakeTool) Execute(ctx context.Context, args map[string]any) (string, error) {
	if f.fn != nil {
		return f.fn(ctx, args)
	}
	return `{"ok":true}`, nil
}

func newTestRegistry() *agent.ToolRegistry {
	reg := agent.NewToolRegistry()
	reg.Register(fakeTool{name: "list_domains", desc: "列出域名"})
	reg.Register(fakeTool{name: "start_scan", desc: "发起扫描", fn: func(ctx context.Context, args map[string]any) (string, error) {
		// 回显入参，便于断言参数确实传到了工具
		b, _ := json.Marshal(args)
		return "scan:" + string(b), nil
	}})
	reg.Register(fakeTool{name: "boom", desc: "总是失败", fn: func(ctx context.Context, args map[string]any) (string, error) {
		return "", fmt.Errorf("目标不可达")
	}})
	// 流程控制类：默认应被屏蔽
	reg.Register(fakeTool{name: "finish_task", desc: "结束任务"})
	reg.Register(fakeTool{name: "wait", desc: "等待"})
	reg.Register(fakeTool{name: "wait_until", desc: "等到某时刻"})
	return reg
}

func newTestRouter(cfg *config.OpenServiceConfig) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := NewOpenToolsHandler(newTestRegistry(), cfg)
	g := r.Group("/api/open")
	g.Use(RequireServiceKey(cfg))
	g.GET("/tools", h.ListTools)
	g.POST("/tools/:name", h.Execute)
	return r
}

func defaultCfg() *config.OpenServiceConfig {
	return &config.OpenServiceConfig{
		Enabled:      true,
		APIKey:       "test-service-key-123",
		Header:       "X-API-Key",
		BlockedTools: []string{"finish_task", "wait", "wait_until"},
	}
}

// TestRequireServiceKey 校验服务密钥鉴权（这是对外接口唯一的门，必须严）。
func TestRequireServiceKey(t *testing.T) {
	r := newTestRouter(defaultCfg())

	cases := []struct {
		name   string
		header string
		value  string
		want   int
	}{
		{"不带密钥", "", "", http.StatusUnauthorized},
		{"密钥错误", "X-API-Key", "wrong-key", http.StatusUnauthorized},
		{"密钥前缀错误", "X-API-Key", "test-service-key-12", http.StatusUnauthorized},
		{"密钥正确", "X-API-Key", "test-service-key-123", http.StatusOK},
	}
	for _, c := range cases {
		req := httptest.NewRequest(http.MethodGet, "/api/open/tools", nil)
		if c.header != "" {
			req.Header.Set(c.header, c.value)
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != c.want {
			t.Errorf("%s: 状态码 = %d, 期望 %d", c.name, w.Code, c.want)
		}
	}
}

// TestRequireServiceKey_DisabledOrNoKey 未启用 / 未配密钥时必须拒绝，
// 不能出现"忘配密钥反而全开放"的情况。
func TestRequireServiceKey_DisabledOrNoKey(t *testing.T) {
	for _, cfg := range []*config.OpenServiceConfig{
		{Enabled: false, APIKey: "k"},
		{Enabled: true, APIKey: ""},
	} {
		r := newTestRouter(cfg)
		req := httptest.NewRequest(http.MethodGet, "/api/open/tools", nil)
		req.Header.Set("X-API-Key", "k")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusServiceUnavailable {
			t.Errorf("cfg=%+v: 状态码 = %d, 期望 503", cfg, w.Code)
		}
	}
}

// TestListTools_BlocksProcessControl 流程控制类工具不得外露。
func TestListTools_BlocksProcessControl(t *testing.T) {
	r := newTestRouter(defaultCfg())
	req := httptest.NewRequest(http.MethodGet, "/api/open/tools", nil)
	req.Header.Set("X-API-Key", "test-service-key-123")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("状态码 = %d", w.Code)
	}
	var resp struct {
		Count int        `json:"count"`
		Tools []ToolSpec `json:"tools"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	got := map[string]bool{}
	for _, s := range resp.Tools {
		got[s.Name] = true
	}
	for _, blocked := range []string{"finish_task", "wait", "wait_until"} {
		if got[blocked] {
			t.Errorf("流程控制类工具 %s 不应出现在对外清单中", blocked)
		}
	}
	for _, want := range []string{"list_domains", "start_scan", "boom"} {
		if !got[want] {
			t.Errorf("工具 %s 应出现在对外清单中", want)
		}
	}
	if resp.Count != len(resp.Tools) {
		t.Errorf("count(%d) 与 tools 长度(%d) 不一致", resp.Count, len(resp.Tools))
	}
}

// TestExecute_ArgsAndResult 参数应原样传给工具，结果放在 result 里。
func TestExecute_ArgsAndResult(t *testing.T) {
	r := newTestRouter(defaultCfg())
	body := `{"domain_id":"d-1","depth":2}`
	req := httptest.NewRequest(http.MethodPost, "/api/open/tools/start_scan", strings.NewReader(body))
	req.Header.Set("X-API-Key", "test-service-key-123")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("状态码 = %d, body=%s", w.Code, w.Body.String())
	}
	var resp ExecuteToolResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if !resp.OK || resp.Name != "start_scan" {
		t.Errorf("响应异常: %+v", resp)
	}
	if !strings.Contains(resp.Result, `"domain_id":"d-1"`) {
		t.Errorf("入参未传到工具: %s", resp.Result)
	}
}

// TestExecute_ErrorPaths 工具不存在 / 被屏蔽 / 执行失败 / 入参非法。
func TestExecute_ErrorPaths(t *testing.T) {
	r := newTestRouter(defaultCfg())

	// 工具不存在 -> 404
	req := httptest.NewRequest(http.MethodPost, "/api/open/tools/not_exist", strings.NewReader("{}"))
	req.Header.Set("X-API-Key", "test-service-key-123")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("不存在的工具应返回 404，实际 %d", w.Code)
	}

	// 被屏蔽的工具 -> 403
	req = httptest.NewRequest(http.MethodPost, "/api/open/tools/finish_task", strings.NewReader("{}"))
	req.Header.Set("X-API-Key", "test-service-key-123")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("被屏蔽的工具应返回 403，实际 %d", w.Code)
	}

	// 工具执行失败 -> 200 + ok:false（让第三方智能体读到失败原因继续推理）
	req = httptest.NewRequest(http.MethodPost, "/api/open/tools/boom", strings.NewReader("{}"))
	req.Header.Set("X-API-Key", "test-service-key-123")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("工具业务失败应返回 200，实际 %d", w.Code)
	}
	var resp ExecuteToolResponse
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.OK || !strings.Contains(resp.Error, "目标不可达") {
		t.Errorf("失败响应异常: %+v", resp)
	}

	// 入参不是 JSON 对象 -> 400
	req = httptest.NewRequest(http.MethodPost, "/api/open/tools/list_domains", strings.NewReader("[1,2,3]"))
	req.Header.Set("X-API-Key", "test-service-key-123")
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("非法入参应返回 400，实际 %d", w.Code)
	}
}
