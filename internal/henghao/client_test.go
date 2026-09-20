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

// TestCode_DocVsRealWorld 覆盖一个真实的坑：
//
// 平台文档写 `{"code":"0"}`（字符串），但**线上实测返回 `{"code":0}`（数字）**。
// 若按文档把 Code 声明成 string，真机上 json.Unmarshal 会直接失败。
// 这里两种形态都必须能解析。
func TestCode_DocVsRealWorld(t *testing.T) {
	parse := func(raw string) (ExecuteResponse, error) {
		var r ExecuteResponse
		err := json.Unmarshal([]byte(raw), &r)
		return r, err
	}

	// 线上真实形态：数字 code
	real, err := parse(`{"msg":"恭喜您，操作成功","code":0,"data":{"token_usage":{"prompt_tokens":41,"completion_tokens":3,"total_tokens":44}}}`)
	if err != nil {
		t.Fatalf("解析线上数字 code 失败: %v", err)
	}
	if !real.Code.OK() {
		t.Errorf("数字 0 应判定为成功，实际 code=%q", real.Code)
	}
	if real.Data.TokenUsage.TotalTokens != 44 {
		t.Errorf("token_usage 解析错误: %+v", real.Data.TokenUsage)
	}

	// 文档形态：字符串 code
	doc, err := parse(`{"code":"0","msg":"成功"}`)
	if err != nil {
		t.Fatalf("解析文档字符串 code 失败: %v", err)
	}
	if !doc.Code.OK() {
		t.Errorf("字符串 \"0\" 应判定为成功，实际 code=%q", doc.Code)
	}

	// 线上真实错误码：数字 -16（无权限）
	bad, err := parse(`{"code":-16,"msg":"异常：无权限使用智能体"}`)
	if err != nil {
		t.Fatalf("解析数字错误码失败: %v", err)
	}
	if bad.Code.OK() {
		t.Errorf("数字 -16 不应判定为成功，实际 code=%q", bad.Code)
	}
}

// TestSearch_RealWorldShape 用线上真实响应结构验证搜索解析。
// 注意两点真实差异：列表在 data.data（不是 data.list）；total 是字符串 "1165"。
func TestSearch_RealWorldShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != PathSearch {
			t.Errorf("请求路径错误: %s", r.URL.Path)
		}
		fmt.Fprint(w, `{"msg":"成功","code":0,"flag":0,"data":{"total":"1165","size":5,"page":1,
			"data":[
				{"id":"db0ae189-b3df-b8ac-714c-2f2329524ca0","name":"交巡智星-连通性测试","title":"","forbid":false,"type":1},
				{"id":"1da3469f-233c-486d-a6de-13b666050d46","name":"告警研判智能体","forbid":true,"type":1}
			]}}`)
	}))
	defer srv.Close()

	c := NewClient(Config{BaseURL: srv.URL, AppKey: "ak", AppSecret: "sk"})
	agents, total, err := c.Search(context.Background(), SearchRequest{Keyword: "交巡智星"})
	if err != nil {
		t.Fatalf("Search 失败: %v", err)
	}
	if total != 1165 {
		t.Errorf("total 应能解析字符串 \"1165\"，实际 %d", total)
	}
	if len(agents) != 2 {
		t.Fatalf("智能体条数错误: %d", len(agents))
	}
	if agents[0].ID != "db0ae189-b3df-b8ac-714c-2f2329524ca0" || agents[0].Forbid {
		t.Errorf("首条解析错误: %+v", agents[0])
	}
	if !agents[1].Forbid {
		t.Error("forbid=true 的智能体应被正确标记")
	}
	// 名称字段线上是 name（文档写 title）——必须能取到
	if agents[0].DisplayName() != "交巡智星-连通性测试" {
		t.Errorf("DisplayName 应兼容 name 字段，实际 %q", agents[0].DisplayName())
	}

	// ResolveAgentID 必须跳过无权限的，取第一个可用的
	id, err := c.ResolveAgentID(context.Background(), "交巡智星")
	if err != nil {
		t.Fatalf("ResolveAgentID 失败: %v", err)
	}
	if id != "db0ae189-b3df-b8ac-714c-2f2329524ca0" {
		t.Errorf("ResolveAgentID 结果错误: %q", id)
	}
}

// TestChatbotURL 校验 iframe 地址拼装（含 token 转义）。
func TestChatbotURL(t *testing.T) {
	// 路径 /chatBot/ 为实测结果（大写 B、带结尾斜杠），见 ChatbotPath 注释
	got := ChatbotURL("https://www.das-ai.com/", "eyJhbGci+Oi/x=")
	want := "https://www.das-ai.com/chatBot/?appType=assistants&token=eyJhbGci%2BOi%2Fx%3D"
	if got != want {
		t.Errorf("ChatbotURL 拼装错误:\n got=%q\nwant=%q", got, want)
	}
	// 缺任一项都返回空串，避免前端嵌出一个坏 iframe
	if ChatbotURL("", "tok") != "" || ChatbotURL("https://x", "") != "" {
		t.Error("base 或 token 为空时应返回空串")
	}
}

// TestAssistantToken_Mock 覆盖 token 获取 / 校验 / 注销三个接口的解析。
func TestAssistantToken_Mock(t *testing.T) {
	var gotPaths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPaths = append(gotPaths, r.URL.Path)
		switch r.URL.Path {
		case PathAssistantToken:
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["userId"] == "" {
				fmt.Fprint(w, `{"code":-1,"msg":"userId 不能为空"}`)
				return
			}
			fmt.Fprint(w, `{"code":0,"msg":"成功","data":"eyJhbGciOiJIUzI1NiJ9.tok"}`)
		case PathAssistantTokenCheck:
			fmt.Fprint(w, `{"code":0,"msg":"成功","data":true}`)
		case PathAssistantTokenDel:
			fmt.Fprint(w, `{"code":0,"msg":"成功","data":null}`)
		default:
			t.Errorf("未预期的路径: %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	c := NewClient(Config{BaseURL: srv.URL, AppKey: "ak", AppSecret: "sk"})
	ctx := context.Background()

	// 1) 获取 token：data 是裸字符串
	tok, err := c.GetAssistantToken(ctx, "user-123")
	if err != nil {
		t.Fatalf("GetAssistantToken 失败: %v", err)
	}
	if tok != "eyJhbGciOiJIUzI1NiJ9.tok" {
		t.Errorf("token 解析错误: %q", tok)
	}

	// userId 为空应前置拦截，不发起请求
	if _, err := c.GetAssistantToken(ctx, "  "); err == nil {
		t.Error("userId 为空应报错")
	}

	// 2) 校验：data 是布尔
	ok, err := c.CheckAssistantToken(ctx, tok, true)
	if err != nil || !ok {
		t.Errorf("CheckAssistantToken 失败: ok=%v err=%v", ok, err)
	}
	if ok, err := c.CheckAssistantToken(ctx, "", false); err != nil || ok {
		t.Errorf("空 token 应返回 false 且无错误: ok=%v err=%v", ok, err)
	}

	// 3) 注销：data 为 null 也要能正常返回
	if err := c.DelAssistantToken(ctx, tok); err != nil {
		t.Errorf("DelAssistantToken 失败: %v", err)
	}
	if err := c.DelAssistantToken(ctx, ""); err != nil {
		t.Errorf("空 token 注销应为 no-op: %v", err)
	}

	// 三个接口都应被真实调用到（除空参数短路外）
	if len(gotPaths) < 3 {
		t.Errorf("接口调用次数偏少，实际路径: %v", gotPaths)
	}
}

// TestAssistantToken_ErrorFlag 平台用 flag 区分「可跳过」与「需重试」，
// 出错时错误信息里应带上 flag，便于上层决策。
func TestAssistantToken_ErrorFlag(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"msg":"签名验证失败，请查看本地服务器时间是否正确","code":-402,"flag":2,"data":null}`)
	}))
	defer srv.Close()

	c := NewClient(Config{BaseURL: srv.URL, AppKey: "ak", AppSecret: "sk"})
	_, err := c.GetAssistantToken(context.Background(), "u1")
	if err == nil {
		t.Fatal("失败码应返回错误")
	}
	if !strings.Contains(err.Error(), "-402") || !strings.Contains(err.Error(), "flag=2") {
		t.Errorf("错误信息应包含 code 与 flag，实际: %v", err)
	}
}
