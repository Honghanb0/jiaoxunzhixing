// Package ai 提供统一的大模型接入层。
//
// 设计目标：把 DeepSeek、Kimi(Moonshot)、GLM(智谱) 三家在
//   - 端点路径（base_url）
//   - 鉴权方式（DeepSeek/Kimi 为静态 Bearer，GLM 需由 id.secret 签发 JWT）
//   - 请求/响应字段细节
//
// 上的差异收敛到同一个 Provider 接口后面，上层业务只依赖统一模型，
// 可在配置中灵活切换默认模型，也可并行调用多家做结果对比。
package ai

import (
	"context"
	"errors"
	"time"
)

// 对话角色
const (
	RoleSystem    = "system"
	RoleUser      = "user"
	RoleAssistant = "assistant"
)

// 内置供应商标识
const (
	ProviderDeepSeek = "deepseek"
	ProviderKimi     = "kimi"
	ProviderGLM      = "glm"
)

// 调用策略
const (
	StrategySingle   = "single"   // 只调用默认模型
	StrategyFallback = "fallback" // 依次降级，直到有一个成功
	StrategyParallel = "parallel" // 并行调用全部可用模型，取最先成功的结果
)

// 供应商元信息（默认值，可被配置覆盖）
type providerMeta struct {
	DisplayName string
	BaseURL     string
	Model       string
	AuthMode    string // 展示用：bearer / zhipu-jwt
	EnvKeys     []string
}

var defaultProviderMeta = map[string]providerMeta{
	ProviderDeepSeek: {
		DisplayName: "DeepSeek",
		BaseURL:     "https://api.deepseek.com",
		Model:       "deepseek-chat",
		AuthMode:    "bearer",
		EnvKeys:     []string{"DEEPSEEK_API_KEY"},
	},
	ProviderKimi: {
		DisplayName: "Kimi (Moonshot AI)",
		BaseURL:     "https://api.moonshot.cn/v1",
		Model:       "moonshot-v1-32k",
		AuthMode:    "bearer",
		EnvKeys:     []string{"KIMI_API_KEY", "MOONSHOT_API_KEY"},
	},
	ProviderGLM: {
		DisplayName: "GLM (智谱 AI)",
		BaseURL:     "https://open.bigmodel.cn/api/paas/v4",
		Model:       "glm-4.6",
		AuthMode:    "zhipu-jwt",
		EnvKeys:     []string{"GLM_API_KEY", "ZHIPU_API_KEY", "ZHIPUAI_API_KEY"},
	},
}

// 内置供应商的固定注册顺序（用于降级链与列表展示）
var BuiltinOrder = []string{ProviderDeepSeek, ProviderKimi, ProviderGLM}

var (
	// ErrNoProvider 配置中没有任何可用（已启用且已配置 Key）的模型
	ErrNoProvider = errors.New("ai: 没有可用的模型供应商")
	// ErrProviderNotFound 指定名称的供应商未注册
	ErrProviderNotFound = errors.New("ai: 未找到指定的模型供应商")
	// ErrAllProvidersFailed 所有候选模型都调用失败
	ErrAllProvidersFailed = errors.New("ai: 所有模型供应商均调用失败")
	// ErrEmptyResponse 模型返回了空内容
	ErrEmptyResponse = errors.New("ai: 模型返回内容为空")
)

// Message 统一对话消息
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// ChatOptions 可选生成参数，零值表示不覆盖供应商默认行为
type ChatOptions struct {
	Model        string   // 临时覆盖模型名
	Temperature  *float64 // 0~2
	TopP         *float64
	MaxTokens    int
	Stop         []string
	SystemPrompt string
}

// ChatRequest 统一请求体
type ChatRequest struct {
	Messages []Message
	Options  *ChatOptions
}

// NewChatRequest 构造一个「可选 system + 单条 user」的简易请求
func NewChatRequest(prompt, systemPrompt string) *ChatRequest {
	msgs := make([]Message, 0, 2)
	if systemPrompt != "" {
		msgs = append(msgs, Message{Role: RoleSystem, Content: systemPrompt})
	}
	msgs = append(msgs, Message{Role: RoleUser, Content: prompt})
	return &ChatRequest{Messages: msgs, Options: &ChatOptions{SystemPrompt: systemPrompt}}
}

// Usage 统一 token 统计
type Usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// ChatResponse 统一响应
type ChatResponse struct {
	Provider     string        `json:"provider"`
	Model        string        `json:"model"`
	Content      string        `json:"content"`
	FinishReason string        `json:"finish_reason,omitempty"`
	ID           string        `json:"id,omitempty"`
	Usage        Usage         `json:"usage"`
	Latency      time.Duration `json:"-"`
	LatencyMs    int64         `json:"latency_ms"`
}

// StreamChunk 流式输出分片；Done=true 表示流结束，Err!=nil 表示出错
type StreamChunk struct {
	Provider string `json:"provider"`
	Model    string `json:"model"`
	Content  string `json:"content,omitempty"`
	Done     bool   `json:"done"`
	Err      error  `json:"-"`
	Error    string `json:"error,omitempty"`
}

// ProviderInfo 供应商运行时信息（对外暴露，不含密钥）
type ProviderInfo struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Model       string `json:"model"`
	BaseURL     string `json:"base_url"`
	AuthMode    string `json:"auth_mode"`
	Enabled     bool   `json:"enabled"`
	Configured  bool   `json:"configured"` // 是否已拿到可用的 API Key
	TimeoutMs   int64  `json:"timeout_ms"`
}

// Provider 统一模型供应商接口。
// 所有适配三家差异的代码都实现在这个接口之后。
type Provider interface {
	// Name 供应商标识，如 deepseek / kimi / glm
	Name() string
	// Info 运行时信息
	Info() ProviderInfo
	// Chat 阻塞式对话
	Chat(ctx context.Context, req *ChatRequest) (*ChatResponse, error)
	// ChatStream SSE 流式对话；返回的 channel 一定会被关闭
	ChatStream(ctx context.Context, req *ChatRequest) (<-chan StreamChunk, error)
}

// ProviderResult 并行调用时单家模型的产出
type ProviderResult struct {
	Provider  string `json:"provider"`
	Model     string `json:"model"`
	Content   string `json:"content,omitempty"`
	Usage     Usage  `json:"usage,omitempty"`
	LatencyMs int64  `json:"latency_ms"`
	OK        bool   `json:"ok"`
	Error     string `json:"error,omitempty"`
}
