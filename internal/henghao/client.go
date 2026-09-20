// Package henghao 封装恒脑安全智能体平台的「开放服务接口」。
//
// 与 internal/ai 下的 LLM Provider 刻意分开：恒脑对外提供的是**智能体执行**能力
// （POST /open/api/v2/agent/execute，按 agent id 执行，返回会话记录与结构化 results），
// 而不是 chat/completions 形态。混进 LLM Provider 抽象会把「一轮对话」和
// 「一次智能体任务」两种语义搅在一起，因此单独成包。
//
// 协议来源：平台「开放服务」文档《智能体服务-开放服务接口》。
// 关键约定：
//   - 鉴权：请求头 appKey + sign，sign = 时间戳(ms) 前缀 + base64(HmacSHA256(secret, "{ts}\n{secret}\n{key}"))
//   - 成功判定：响应体 code == "0"
//   - 执行可分「非流式」与「流式(SSE)」两种，流式事件的 from 字段标识推理阶段
//     （react_think / react_action / react_observe / react_answer / execute_result 等）
package henghao

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Code 是响应里的状态码。
//
// 这里刻意不用 string：平台**文档写的是字符串**（`{"code":"0"}`），
// 但**真实响应返回的是数字**（实测 `{"code":0,"msg":"恭喜您，操作成功"}`）。
// 若按文档声明成 string，json.Unmarshal 在真机上会直接报
// "cannot unmarshal number into Go struct field ... of type string"。
// 用自定义类型同时接受两种形态，避免被「文档与实现不一致」坑到。
type Code string

// UnmarshalJSON 同时接受 0 / "0" / null。
func (c *Code) UnmarshalJSON(b []byte) error {
	s := strings.TrimSpace(string(b))
	if s == "null" {
		*c = ""
		return nil
	}
	*c = Code(strings.Trim(s, `"`))
	return nil
}

// OK 判断是否为成功码（平台约定 0 成功）。
func (c Code) OK() bool { return c == "" || c == "0" }

// 开放服务接口路径（与平台文档一致）
const (
	PathExecute     = "/open/api/v2/agent/execute"
	PathExecuteStop = "/open/api/v2/agent/execute/stop"
	PathSearch      = "/open/api/v2/agent/search"
	PathStatistics  = "/open/api/v2/agent/statistics"

	// Chatbot 扩展插件（「小恒插件」）相关：把恒脑对话窗以 iframe 嵌进第三方系统。
	// 关键安全约定：**appSecret 只留在服务端**，前端拿到的仅是短期 token。
	PathAssistantToken      = "/open/api/assistants/token"
	PathAssistantTokenDel   = "/open/api/assistants/token/delToken"
	PathAssistantTokenCheck = "/open/api/assistants/token/checkWithRefresh"

	// ChatbotPath 是 iframe 里要访问的页面路径（配合 chatbot base 使用）。
	//
	// ⚠️ 实测结论（2026-09-20）：正确路径是 **/chatBot/**（大写 B、带结尾斜杠），
	// 且宿主就是开放服务同一台公网主机 https://www.das-ai.com ——
	// 平台资料里给的 https://gc.das-ai.com:9094/dasChat 会 301 跳到
	// https://www.das-ai.com/chatBot/…；而 gc.das-ai.com 的 9094/9092 两个端口
	// 无论公网还是公司内网都只有 TCP 通、应用层不响应（实测 443 正常但 9094/9092 无服务）。
	// 平台文档写的 /chatbot 与实测不符，以实测为准。
	ChatbotPath = "/chatBot/"
	// ChatbotAppType Chatbot 页面要求的固定参数。
	ChatbotAppType = "assistants"
)

// 流式事件 from 取值：标识消息来自哪个推理阶段，前端可据此分阶段展示。
const (
	FromBasicLLM      = "basic_llm"
	FromReactThink    = "react_think"
	FromReactAction   = "react_action"
	FromReactObserve  = "react_observe"
	FromReactAnswer   = "react_answer"
	FromExecuteResult = "execute_result" // 任务最终结果所在的阶段
)

// Sign 生成访问签名。
//
// 算法（严格对齐平台文档给出的 Java/Python 示例）：
//
//	data = fmt.Sprintf("%d\n%s\n%s", timestampMs, secret, key)
//	sign = fmt.Sprintf("%d%s", timestampMs, base64(HmacSHA256(key=secret, msg=data)))
//
// 注意 data 里的三段顺序是「时间戳、secret、key」，且用 \n 分隔；
// 中间任何一项顺序或分隔符写错都会导致签名不匹配（且平台只返回鉴权失败，不提示原因）。
func Sign(appKey, appSecret string, timestampMs int64) string {
	data := fmt.Sprintf("%d\n%s\n%s", timestampMs, appSecret, appKey)
	mac := hmac.New(sha256.New, []byte(appSecret))
	mac.Write([]byte(data))
	return fmt.Sprintf("%d%s", timestampMs, base64.StdEncoding.EncodeToString(mac.Sum(nil)))
}

// Config 恒脑开放服务配置。
type Config struct {
	BaseURL   string        // 平台地址（开放服务接口在 www.das-ai.com，与门户 gc.das-ai.com 不同域）
	AppKey    string        // 凭据 appKey
	AppSecret string        // 凭据 appSecret（不随请求发送，仅用于本地签名）
	AgentID   string        // 默认智能体 ID（可在单次请求中覆盖）
	Timeout   time.Duration // 单次请求超时
}

// Client 恒脑开放服务客户端。
type Client struct {
	cfg Config
	hc  *http.Client
}

// NewClient 构造客户端。Timeout <= 0 时取 60s（智能体执行通常比普通 API 慢）。
func NewClient(cfg Config) *Client {
	cfg.BaseURL = strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	if cfg.Timeout <= 0 {
		cfg.Timeout = 60 * time.Second
	}
	return &Client{cfg: cfg, hc: &http.Client{Timeout: cfg.Timeout}}
}

// CredentialsReady 判断是否已具备调用条件（未配置时上层应跳过而非报错）。
func (c *Client) CredentialsReady() bool {
	return c != nil && c.cfg.BaseURL != "" && c.cfg.AppKey != "" && c.cfg.AppSecret != ""
}

// ExecuteRequest 智能体执行入参。
type ExecuteRequest struct {
	SID         string         `json:"sid"`                   // 会话标识，须为 UUID
	ID          string         `json:"id"`                    // 智能体 ID
	Input       string         `json:"input,omitempty"`       // 用户输入（与 inputs 同时存在时优先 input）
	Inputs      map[string]any `json:"inputs,omitempty"`      // 结构化入参，键见智能体清单的 input_parameters
	Stream      bool           `json:"stream,omitempty"`      // 是否流式
	Order       string         `json:"order,omitempty"`       // routine / priority
	DebugSwitch bool           `json:"debugSwitch,omitempty"` // 调试模式
}

// TokenUsage 模型用量。
type TokenUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// Message 会话消息。
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// Session 会话信息。
type Session struct {
	ID       string    `json:"id"`
	Messages []Message `json:"messages"`
}

// ExecuteData 执行结果主体。
type ExecuteData struct {
	TokenUsage TokenUsage     `json:"token_usage"`
	Session    Session        `json:"session"`
	Results    map[string]any `json:"results"`
}

// ExecuteResponse 非流式执行响应。
type ExecuteResponse struct {
	Code Code        `json:"code"`
	Msg  string      `json:"msg"`
	Data ExecuteData `json:"data"`
}

// StreamEvent 流式执行事件。
//
// MessageID 相同的分片需要拼接（平台约定）；From 标识推理阶段，
// Type=execute_result 的那条即任务最终结果。
type StreamEvent struct {
	Mode      string         `json:"mode"`
	Type      string         `json:"type"`
	From      string         `json:"from"`
	Name      string         `json:"name"`
	Timestamp string         `json:"timestamp"`
	MessageID string         `json:"message_id"`
	Content   string         `json:"content"`
	Results   map[string]any `json:"results"`
}

// streamEnvelope 流式事件的信封（与外层保持相同的 code/msg/data 结构）。
type streamEnvelope struct {
	Code Code        `json:"code"`
	Msg  string      `json:"msg"`
	Data StreamEvent `json:"data"`
}

// newSID 生成符合平台要求的 UUID 会话标识。
func newSID() string { return uuid.New().String() }

// doPost 发送带签名的 POST 请求。appSecret 只参与本地签名，不进入请求头。
func (c *Client) doPost(ctx context.Context, path string, body any, extraHeaders map[string]string) (*http.Response, error) {
	if !c.CredentialsReady() {
		return nil, fmt.Errorf("恒脑开放服务未配置（需要 base_url / app_key / app_secret）")
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("序列化请求体失败: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.BaseURL+path, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("构造请求失败: %w", err)
	}

	ts := time.Now().UnixMilli()
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("appKey", c.cfg.AppKey)
	req.Header.Set("sign", Sign(c.cfg.AppKey, c.cfg.AppSecret, ts))
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}

	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求恒脑开放服务失败: %w", err)
	}
	return resp, nil
}

// Execute 非流式执行智能体，直接返回最终结果。
func (c *Client) Execute(ctx context.Context, req ExecuteRequest) (*ExecuteResponse, error) {
	if req.SID == "" {
		req.SID = newSID()
	}
	if req.ID == "" {
		req.ID = c.cfg.AgentID
	}
	if req.ID == "" {
		return nil, fmt.Errorf("未指定智能体 ID（配置 henghao.agent_id 或在请求中传入）")
	}
	req.Stream = false

	resp, err := c.doPost(ctx, PathExecute, req, map[string]string{"Accept": "application/json"})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("恒脑开放服务返回 HTTP %d: %s", resp.StatusCode, truncate(string(raw), 300))
	}

	var out ExecuteResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("解析响应失败: %w（原文: %s）", err, truncate(string(raw), 200))
	}
	if !out.Code.OK() {
		return nil, fmt.Errorf("恒脑智能体执行失败（code=%s）: %s", out.Code, out.Msg)
	}
	return &out, nil
}

// ExecuteStream 流式执行智能体，逐条回调事件。
// onEvent 返回错误会中断读取（用于上层主动终止）。
func (c *Client) ExecuteStream(ctx context.Context, req ExecuteRequest, onEvent func(StreamEvent) error) error {
	if req.SID == "" {
		req.SID = newSID()
	}
	if req.ID == "" {
		req.ID = c.cfg.AgentID
	}
	if req.ID == "" {
		return fmt.Errorf("未指定智能体 ID（配置 henghao.agent_id 或在请求中传入）")
	}
	req.Stream = true

	// reason=1：让推理过程单独放在 reasoning_content，不拼进正文，便于后端分离「结果」与「思考」
	resp, err := c.doPost(ctx, PathExecute, req, map[string]string{
		"Accept": "text/event-stream",
		"ext":    "reason:1",
	})
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("恒脑开放服务返回 HTTP %d: %s", resp.StatusCode, truncate(string(raw), 300))
	}

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), 4<<20) // 单条事件可能较长
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, ":") { // 空行与 SSE 注释心跳
			continue
		}
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if payload == "[DONE]" {
			return nil
		}

		var env streamEnvelope
		if err := json.Unmarshal([]byte(payload), &env); err != nil {
			continue // 容忍单条畸形事件，不因一个分片中断整个流
		}
		if !env.Code.OK() {
			return fmt.Errorf("恒脑智能体执行失败（code=%s）: %s", env.Code, env.Msg)
		}
		if err := onEvent(env.Data); err != nil {
			return err
		}
	}
	return scanner.Err()
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// flexInt 兼容「文档写 int、实际返回字符串」的计数字段（如 total 实测为 "1165"）。
type flexInt int

func (n *flexInt) UnmarshalJSON(b []byte) error {
	s := strings.Trim(strings.TrimSpace(string(b)), `"`)
	if s == "" || s == "null" {
		*n = 0
		return nil
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		*n = 0 // 统计字段解析失败不该中断主流程
		return nil
	}
	*n = flexInt(v)
	return nil
}

// SearchRequest 智能体查询入参。
type SearchRequest struct {
	Keyword    string `json:"keyword,omitempty"`    // 按名称 / 介绍 / 智能体 ID 模糊搜索
	Scope      int    `json:"scope,omitempty"`      // 0 全部 / 1 仅官方 / 2 非官方
	WithForbid bool   `json:"withForbid,omitempty"` // 是否包含未授权项（默认 false，仅返回有权限的）
	Page       int    `json:"page,omitempty"`
	Size       int    `json:"size,omitempty"`
}

// AgentBrief 智能体摘要。
//
// 名称字段的坑：文档写的是 title，但**线上实测返回的是 name**（title 为空串）。
// 两个都收，取用时以 Name 优先（见 DisplayName）。
type AgentBrief struct {
	ID       string `json:"id"`
	Name     string `json:"name"`   // 线上真实字段
	Title    string `json:"title"`  // 文档字段（部分场景返回）
	Forbid   bool   `json:"forbid"` // true = 当前凭据无权限调用
	Type     int    `json:"type"`
	Prologue string `json:"prologue"`
}

// DisplayName 返回可展示的名称，兼容 name / title 两种返回。
func (a AgentBrief) DisplayName() string {
	if a.Name != "" {
		return a.Name
	}
	return a.Title
}

type searchData struct {
	Total flexInt      `json:"total"`
	Page  flexInt      `json:"page"`
	Size  flexInt      `json:"size"`
	Data  []AgentBrief `json:"data"`
}

type searchResponse struct {
	Code Code       `json:"code"`
	Msg  string     `json:"msg"`
	Data searchData `json:"data"`
}

// Search 查询当前凭据可调用的智能体。
//
// ⚠️ 关键：`/agent/execute` 的 id **必须是本方法返回的 id（UUID 形态）**，
// 而不是平台界面 URL 里那串 19 位数字 id —— 那是草稿/内部 id，
// 直接传进去会返回 `code=-16 无权限使用智能体`（实测踩过）。
// 配置 henghao.agent_id 前，先用本方法确认真实 id。
//
// WithForbid=false 时只返回**有权限**的智能体；置 true 可用 Forbid 字段区分。
func (c *Client) Search(ctx context.Context, req SearchRequest) ([]AgentBrief, int, error) {
	if req.Page <= 0 {
		req.Page = 1
	}
	if req.Size <= 0 {
		req.Size = 20
	}
	resp, err := c.doPost(ctx, PathSearch, req, nil)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, 0, fmt.Errorf("读取响应失败: %w", err)
	}
	var out searchResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, 0, fmt.Errorf("解析响应失败: %w（原文: %s）", err, truncate(string(raw), 200))
	}
	if !out.Code.OK() {
		return nil, 0, fmt.Errorf("恒脑智能体查询失败（code=%s）: %s", out.Code, out.Msg)
	}
	return out.Data.Data, int(out.Data.Total), nil
}

// ResolveAgentID 按名称解析出可调用的智能体 ID（UUID）。
// 常用于把配置里的"人能看懂的名称"换成接口真正需要的 id。
func (c *Client) ResolveAgentID(ctx context.Context, keyword string) (string, error) {
	agents, _, err := c.Search(ctx, SearchRequest{Keyword: keyword, Size: 20})
	if err != nil {
		return "", err
	}
	for _, a := range agents {
		if !a.Forbid && a.ID != "" {
			return a.ID, nil
		}
	}
	return "", fmt.Errorf("未找到可调用的智能体（关键词: %s）", keyword)
}

// ---------- Chatbot 扩展插件（小恒插件）----------

// genericResponse 用于 data 形态各异的接口（字符串 token / 布尔 / null）。
type genericResponse struct {
	Code Code            `json:"code"`
	Msg  string          `json:"msg"`
	Flag flexInt         `json:"flag"`
	Data json.RawMessage `json:"data"`
}

// callGeneric 发送请求并校验 code，返回 data 原文。
func (c *Client) callGeneric(ctx context.Context, path string, body any) (json.RawMessage, error) {
	resp, err := c.doPost(ctx, path, body, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %w", err)
	}
	var out genericResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("解析响应失败: %w（原文: %s）", err, truncate(string(raw), 200))
	}
	if !out.Code.OK() {
		// flag=2 表示服务端异常、应等待后重试；一并带出来，便于上层决定是否重试
		return nil, fmt.Errorf("恒脑接口失败（code=%s flag=%d）: %s", out.Code, int(out.Flag), out.Msg)
	}
	return out.Data, nil
}

// GetAssistantToken 获取 Chatbot iframe 的访问凭证 token。
//
// userId 是"集成方用户的唯一标识"——即在我们系统里的用户身份，
// 恒脑用它来隔离各用户的会话。**appSecret 只在这里本地签名，不下发给前端**。
func (c *Client) GetAssistantToken(ctx context.Context, userID string) (string, error) {
	if strings.TrimSpace(userID) == "" {
		return "", fmt.Errorf("userId 不能为空（需为集成方用户唯一标识）")
	}
	data, err := c.callGeneric(ctx, PathAssistantToken, map[string]string{"userId": userID})
	if err != nil {
		return "", err
	}
	var token string
	if err := json.Unmarshal(data, &token); err != nil {
		return "", fmt.Errorf("解析 token 失败: %w（原文: %s）", err, truncate(string(data), 120))
	}
	if token == "" {
		return "", fmt.Errorf("平台返回了空 token")
	}
	return token, nil
}

// DelAssistantToken 注销 token（用户登出时调用，避免凭证悬挂）。
func (c *Client) DelAssistantToken(ctx context.Context, token string) error {
	if token == "" {
		return nil
	}
	_, err := c.callGeneric(ctx, PathAssistantTokenDel, map[string]string{"token": token})
	return err
}

// CheckAssistantToken 校验 token 是否有效，refresh=true 时会续期。
func (c *Client) CheckAssistantToken(ctx context.Context, token string, refresh bool) (bool, error) {
	if token == "" {
		return false, nil
	}
	data, err := c.callGeneric(ctx, PathAssistantTokenCheck, map[string]any{"token": token, "refresh": refresh})
	if err != nil {
		return false, err
	}
	var valid bool
	if err := json.Unmarshal(data, &valid); err != nil {
		return false, fmt.Errorf("解析校验结果失败: %w（原文: %s）", err, truncate(string(data), 120))
	}
	return valid, nil
}

// ChatbotURL 拼装 Chatbot iframe 地址。
//
// chatbotBase 是插件宿主（形如 https://gc.das-ai.com:9094），来自平台的"小恒插件集成"信息；
// 注意它与开放服务地址（www.das-ai.com）**不是同一个域**，需分别配置。
func ChatbotURL(chatbotBase, token string) string {
	base := strings.TrimRight(strings.TrimSpace(chatbotBase), "/")
	if base == "" || token == "" {
		return ""
	}
	return fmt.Sprintf("%s%s?appType=%s&token=%s", base, ChatbotPath, ChatbotAppType, url.QueryEscape(token))
}
