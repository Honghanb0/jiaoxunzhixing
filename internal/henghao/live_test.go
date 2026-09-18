package henghao

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestLive_SearchAndExecute 联调测试：打真实恒脑开放服务接口。
//
// 默认**跳过**（不设环境变量即 skip），因此不会影响 CI 与离线开发；
// 需要真机验证时这样跑：
//
//	export HENGNAO_APP_KEY=... HENGNAO_APP_SECRET=... HENGNAO_AGENT_KEYWORD=交巡智星
//	go test ./internal/henghao/ -run TestLive -v
//
// 它会顺带验证一个关键约定：配置文件里该填的 agent id **不是**平台界面 URL 里的
// 那串 19 位数字，而是 /agent/search 返回的 UUID —— 传错会得到 code=-16「无权限」。
func TestLive_SearchAndExecute(t *testing.T) {
	key := os.Getenv("HENGNAO_APP_KEY")
	secret := os.Getenv("HENGNAO_APP_SECRET")
	if key == "" || secret == "" {
		t.Skip("未设置 HENGNAO_APP_KEY / HENGNAO_APP_SECRET，跳过真实接口联调")
	}
	base := os.Getenv("HENGNAO_BASE_URL")
	if base == "" {
		base = "https://www.das-ai.com"
	}
	keyword := os.Getenv("HENGNAO_AGENT_KEYWORD")
	if keyword == "" {
		keyword = "交巡智星"
	}

	c := NewClient(Config{BaseURL: base, AppKey: key, AppSecret: secret, Timeout: 120 * time.Second})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	// 1) 查得到智能体（同时验证 total 字符串、data.data 列表等真实结构）
	agents, total, err := c.Search(ctx, SearchRequest{Keyword: keyword, Size: 10})
	if err != nil {
		t.Fatalf("Search 失败: %v", err)
	}
	t.Logf("搜索 [%s]：total=%d，本页 %d 条", keyword, total, len(agents))
	if len(agents) == 0 {
		t.Fatalf("未搜索到智能体 [%s]（请确认已发布且可见范围允许当前凭据）", keyword)
	}
	for _, a := range agents {
		t.Logf("  id=%s forbid=%v title=%s", a.ID, a.Forbid, a.Title)
	}

	// 2) 解析出可调用的 UUID 形态 id
	agentID, err := c.ResolveAgentID(ctx, keyword)
	if err != nil {
		t.Fatalf("ResolveAgentID 失败: %v", err)
	}
	t.Logf("解析到可调用智能体 ID: %s", agentID)

	// 3) 真实执行一次（输入保持极短，控制 token 消耗）
	resp, err := c.Execute(ctx, ExecuteRequest{ID: agentID, Input: "ping"})
	if err != nil {
		t.Fatalf("Execute 失败: %v", err)
	}
	t.Logf("code=%s msg=%s", resp.Code, resp.Msg)
	t.Logf("token_usage: prompt=%d completion=%d total=%d",
		resp.Data.TokenUsage.PromptTokens, resp.Data.TokenUsage.CompletionTokens, resp.Data.TokenUsage.TotalTokens)
	for _, m := range resp.Data.Session.Messages {
		t.Logf("message[%s] = %q", m.Role, m.Content)
	}

	if len(resp.Data.Session.Messages) == 0 {
		t.Error("执行成功但未返回会话消息")
	}
}
