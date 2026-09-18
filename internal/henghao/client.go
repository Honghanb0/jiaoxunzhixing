// Package henghao 封装恒脑安全智能体平台（gc.das-ai.com）的「开放服务接口」。
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
	"strings"
	"time"

	"github.com/google/uuid"
)

// 开放服务接口路径（与平台文档一致）
const (
	PathExecute     = "/open/api/v2/agent/execute"
	PathExecuteStop = "/open/api/v2/agent/execute/stop"
	PathSearch      = "/open/api/v2/agent/search"
	PathStatistics  = "/open/api/v2/agent/statistics"
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
	BaseURL   string        // 平台地址，如 https://gc.das-ai.com
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
	Code string      `json:"code"`
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
	Code string      `json:"code"`
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
	if out.Code != "0" {
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
		if env.Code != "" && env.Code != "0" {
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
