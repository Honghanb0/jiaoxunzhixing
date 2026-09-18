package henghao

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestSign_CrossLanguage 校验签名算法与平台文档一致。
//
// 期望值不是"用 Go 自己算一遍再对比自己"（那是循环论证），而是用 Python 按文档
// 给出的示例代码独立实现后算出来的，因此能真正验出实现是否忠于文档：
//
//	data = f"{timestamp}\n{secret}\n{key}"
//	sign = f"{timestamp}{base64(hmac_sha256(secret, data))}"
func TestSign_CrossLanguage(t *testing.T) {
	cases := []struct {
		key, secret string
		ts          int64
		want        string
	}{
		{
			key: "testAppKey", secret: "testSecret", ts: 1709703938860,
			want: "1709703938860yj988ODfQwldmxTKla9E+u1jcAZ2TpcxrThD4XQiN84=",
		},
		{
			key: "henghnaoG2rFOgq0HAeFAzgv2JXj", secret: "mySecret123", ts: 1700000000000,
			want: "1700000000000rIlkMM//6hjeduOHXazBIoyexzUIWJvpo+zPp+yiWzw=",
		},
	}
	for i, c := range cases {
		if got := Sign(c.key, c.secret, c.ts); got != c.want {
			t.Errorf("用例 %d: Sign() = %q, 期望 %q", i+1, got, c.want)
		}
	}
}

// TestSign_Format 校验签名的结构约束：13 位毫秒时间戳前缀 + base64。
func TestSign_Format(t *testing.T) {
	ts := time.Now().UnixMilli()
	s := Sign("k", "s", ts)
	prefix := fmt.Sprintf("%d", ts)
	if !strings.HasPrefix(s, prefix) {
		t.Fatalf("签名未以时间戳开头: %q", s)
	}
	rest := strings.TrimPrefix(s, prefix)
	if rest == "" {
		t.Fatal("签名缺少 base64 部分")
	}
}

// TestExecute_NonStream 用 mock 服务验证非流式执行：请求头/请求体正确、能解析文档中的响应结构。
func TestExecute_NonStream(t *testing.T) {
	var gotHeaders http.Header
	var gotBody map[string]any

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != PathExecute {
			t.Errorf("请求路径错误: %s", r.URL.Path)
		}
		gotHeaders = r.Header.Clone()
		_ = json.NewDecoder(r.Body).Decode(&gotBody)

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"code":"0","msg":"成功","data":{
			"token_usage":{"prompt_tokens":2,"completion_tokens":1,"total_tokens":3},
			"session":{"id":"sess-1","messages":[
				{"role":"user","content":"你好"},{"role":"assistant","content":"PONG"}]},
			"results":{"arg":"12345"}}}`)
	}))
	defer srv.Close()

	c := NewClient(Config{BaseURL: srv.URL, AppKey: "ak", AppSecret: "sk"})
	resp, err := c.Execute(context.Background(), ExecuteRequest{ID: "agent-1", Input: "你好"})
	if err != nil {
		t.Fatalf("Execute 失败: %v", err)
	}

	// 鉴权头：appKey 原样、sign 必须是「13 位毫秒时间戳 + base64」形态
	if got := gotHeaders.Get("appKey"); got != "ak" {
		t.Errorf("appKey 头错误: %q", got)
	}
	sign := gotHeaders.Get("sign")
	if len(sign) <= 13 {
		t.Fatalf("sign 头过短: %q", sign)
	}
	if _, err := strconv.ParseInt(sign[:13], 10, 64); err != nil {
		t.Errorf("sign 未以 13 位毫秒时间戳开头: %q", sign)
	}
	if gotHeaders.Get("appSecret") != "" {
		t.Error("appSecret 不得出现在请求头中")
	}

	// 请求体：sid 必须是 UUID、非流式请求不应带 stream=true
	sid, _ := gotBody["sid"].(string)
	if len(sid) != 36 || strings.Count(sid, "-") != 4 {
		t.Errorf("sid 不是 UUID 形态: %q", sid)
	}
	if gotBody["id"] != "agent-1" {
		t.Errorf("请求体 id 错误: %v", gotBody["id"])
	}
	// Stream 字段带 omitempty：为 false 时该键会被省略，因此"缺失或 false"都算正确
	if v, ok := gotBody["stream"]; ok && v != false {
		t.Errorf("非流式请求不应带 stream=true: %v", v)
	}

	// 响应解析
	if resp.Data.TokenUsage.TotalTokens != 3 {
		t.Errorf("token_usage 解析错误: %+v", resp.Data.TokenUsage)
	}
	if len(resp.Data.Session.Messages) != 2 || resp.Data.Session.Messages[1].Content != "PONG" {
		t.Errorf("session.messages 解析错误: %+v", resp.Data.Session.Messages)
	}
	if resp.Data.Results["arg"] != "12345" {
		t.Errorf("results 解析错误: %+v", resp.Data.Results)
	}
}

// TestExecuteStream 验证流式事件解析与分阶段回调。
func TestExecuteStream(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		// 平台会带 ext 头控制推理过程返回方式
		if r.Header.Get("ext") == "" {
			t.Error("流式请求应带 ext 头（reason=1）")
		}
		flusher, _ := w.(http.Flusher)
		events := []string{
			`{"code":"0","data":{"mode":"preview","type":"inline","from":"react_think","name":"巡检智能体","message_id":"m1","content":"正在分析目标站点"}}`,
			`{"code":"0","data":{"mode":"preview","type":"inline","from":"react_action","name":"巡检智能体","message_id":"m2","content":"调用 start_scan"}}`,
			`{"code":"0","data":{"mode":"preview","type":"custom","from":"execute_result","name":"巡检智能体","message_id":"m3","results":{"vulns":3}}}`,
		}
		for _, e := range events {
			fmt.Fprintf(w, "data: %s\n\n", e)
			if flusher != nil {
				flusher.Flush()
			}
		}
		fmt.Fprint(w, "data: [DONE]\n\n")
	}))
	defer srv.Close()

	c := NewClient(Config{BaseURL: srv.URL, AppKey: "ak", AppSecret: "sk"})

	var stages []string
	var finalResults map[string]any
	err := c.ExecuteStream(context.Background(), ExecuteRequest{ID: "agent-1", Input: "巡检"},
		func(ev StreamEvent) error {
			stages = append(stages, ev.From)
			if ev.From == FromExecuteResult {
				finalResults = ev.Results
			}
			return nil
		})
	if err != nil {
		t.Fatalf("ExecuteStream 失败: %v", err)
	}

	want := []string{FromReactThink, FromReactAction, FromExecuteResult}
	if strings.Join(stages, ",") != strings.Join(want, ",") {
		t.Errorf("事件阶段顺序错误: %v, 期望 %v", stages, want)
	}
	// execute_result 阶段应带最终结构化结果
	if finalResults["vulns"] == nil {
		t.Errorf("未捕获最终结果: %+v", finalResults)
	}
}

// TestExecute_Errors 覆盖缺参数、业务失败码、未配置凭据三类错误。
func TestExecute_Errors(t *testing.T) {
	// 未配置凭据
	c := NewClient(Config{BaseURL: "https://example.com"})
	if _, err := c.Execute(context.Background(), ExecuteRequest{ID: "x"}); err == nil {
		t.Error("未配置 appKey/appSecret 时应报错")
	}

	// 未指定智能体 ID
	c2 := NewClient(Config{BaseURL: "https://example.com", AppKey: "a", AppSecret: "b"})
	if _, err := c2.Execute(context.Background(), ExecuteRequest{}); err == nil {
		t.Error("未指定智能体 ID 时应报错")
	}

	// 业务失败码非 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"code":"R24C01","msg":"智能体不存在"}`)
	}))
	defer srv.Close()
	c3 := NewClient(Config{BaseURL: srv.URL, AppKey: "a", AppSecret: "b"})
	_, err := c3.Execute(context.Background(), ExecuteRequest{ID: "x"})
	if err == nil || !strings.Contains(err.Error(), "R24C01") {
		t.Errorf("业务失败码应回传错误码，实际: %v", err)
	}
}

// TestCredentialsReady 凭据完整性判定。
func TestCredentialsReady(t *testing.T) {
	if NewClient(Config{BaseURL: "u"}).CredentialsReady() {
		t.Error("缺 appKey/appSecret 时不应判定为就绪")
	}
	if !NewClient(Config{BaseURL: "u", AppKey: "a", AppSecret: "s"}).CredentialsReady() {
		t.Error("凭据齐全时应判定为就绪")
	}
}
