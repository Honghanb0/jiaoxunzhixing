package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"strings"
)

// Tool 是智能体可调用的一项原子能力。
// 实现方只需关注 Name/Description/Schema/Execute；分发、解析、错误回写由 Agent 统一处理。
type Tool interface {
	Name() string
	Description() string
	// Schema 以 JSON Schema(object) 形式描述入参，用于写入系统提示词。
	Schema() map[string]any
	Execute(ctx context.Context, args map[string]any) (string, error)
}

// toolFunc 用闭包快速实现 Tool 接口。
type toolFunc struct {
	name        string
	description string
	schema      map[string]any
	fn          func(ctx context.Context, args map[string]any) (string, error)
}

func (t toolFunc) Name() string           { return t.name }
func (t toolFunc) Description() string    { return t.description }
func (t toolFunc) Schema() map[string]any { return t.schema }
func (t toolFunc) Execute(ctx context.Context, args map[string]any) (string, error) {
	return t.fn(ctx, args)
}

// ToolCall 模型请求的一次工具调用（从 <tool_calls> 块解析得到）。
type ToolCall struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
	CallID    string         `json:"call_id,omitempty"`
}

// ToolResult 工具执行结果（回写为 <tool_result> 块）。
type ToolResult struct {
	CallID  string `json:"call_id"`
	Name    string `json:"name"`
	Content string `json:"content"`
	IsError bool   `json:"is_error"`
}

// ToolRegistry 按名称注册与查询工具。
type ToolRegistry struct {
	tools map[string]Tool
	order []string
}

func NewToolRegistry() *ToolRegistry {
	return &ToolRegistry{tools: map[string]Tool{}}
}

func (r *ToolRegistry) Register(t Tool) {
	if _, ok := r.tools[t.Name()]; !ok {
		r.order = append(r.order, t.Name())
	}
	r.tools[t.Name()] = t
}

func (r *ToolRegistry) Get(name string) (Tool, bool) {
	t, ok := r.tools[name]
	return t, ok
}

func (r *ToolRegistry) All() []Tool {
	out := make([]Tool, 0, len(r.order))
	for _, n := range r.order {
		out = append(out, r.tools[n])
	}
	return out
}

// Descriptions 生成所有工具的文本化说明，嵌入系统提示词。
func (r *ToolRegistry) Descriptions() string {
	var sb strings.Builder
	for _, t := range r.All() {
		sb.WriteString(fmt.Sprintf("- %s: %s\n", t.Name(), t.Description()))
		sb.WriteString("  参数(JSON Schema): " + toJSON(t.Schema()) + "\n")
	}
	return sb.String()
}

// ---------- 工具调用协议解析 / 渲染 ----------

// 模型以如下结构发出工具调用（放在 <tool_calls> 围栏内，内容为 JSON 数组）：
//
//	<tool_calls>
//	[
//	  {"name": "query_neo4j", "arguments": {"cypher": "MATCH (d:Domain) RETURN d.name LIMIT 5"}},
//	  {"name": "finish_task", "arguments": {"summary": "已完成分析"}}
//	]
//	</tool_calls>
//
// 工具结果回写为（以 user 角色消息承载）：
//
//	<tool_result name="query_neo4j" call_id="call_1" error="false">
//	{...json...}
//	</tool_result>
//
// 允许 <tool_calls> / </tool_calls> 之间夹带分词器产物（如 </｜｜DSML｜｜tool_calls>）：
// 开头与结尾的标签均可包含任意非 '>' 字符前缀，从而容忍模型偶发的畸形闭合标签，
// 避免 wait_scan 等工具调用被整段丢弃导致后续步骤无法读取结果。
var toolCallsRe = regexp.MustCompile(`(?s)<[^>]*tool_calls>(.*?)</[^>]*tool_calls>`)

// toolCallsUnclosedRe 兜底匹配「围栏有头无尾 / 闭合标签被截断」的输出，
// 例如模型输出被 max_tokens 截断成 `...</tool_calls`（缺少 '>'），或干脆没有闭合标签。
// 此时把围栏起点之后的内容全部视为负载，尽量抢救出其中的工具调用——否则这些调用会被
// 静默丢弃（解析出 0 个调用且无错误），外层循环会误把这段畸形 JSON 当成「最终结论」收尾。
var toolCallsUnclosedRe = regexp.MustCompile(`(?s)<[^>]*tool_calls>(.*)$`)

// ParseToolCalls 从模型输出中解析工具调用；无调用块时返回 (nil, nil)。
// 注意：模型可能在一次回复里输出多个 <tool_calls> 块（尤其在 JSON 解析纠正轮次后），
// 这里用 FindAll 提取「所有」块并合并其中的调用，避免第二个块里的工具调用被整段静默丢弃
// （此前仅用 FindStringSubmatch 取首个块，导致 create_inspection_rule 等调用被无声跳过）。
func ParseToolCalls(content string) ([]ToolCall, error) {
	blocks := toolCallsRe.FindAllStringSubmatch(content, -1)
	var rawBlocks []string
	for _, m := range blocks {
		rawBlocks = append(rawBlocks, strings.TrimSpace(m[1]))
	}
	// 兜底1：围栏有头无尾 / 闭合标签被截断（如 "</tool_calls" 少了 '>'）——
	// 取围栏起点之后的全部内容作为负载，抢救其中的工具调用。
	if len(rawBlocks) == 0 {
		if m := toolCallsUnclosedRe.FindStringSubmatch(content); m != nil {
			payload := strings.TrimSpace(m[1])
			// 去掉可能残留的残缺闭合标签前缀（如 "</tool_calls"、"</｜｜DSML｜｜tool_calls"）
			if idx := strings.LastIndex(payload, "</"); idx >= 0 {
				payload = strings.TrimSpace(payload[:idx])
			}
			if payload != "" {
				log.Printf("[Agent][ParseToolCalls] 检测到未闭合的 <tool_calls> 围栏，按截断负载抢救解析")
				rawBlocks = []string{payload}
			}
		}
	}
	// 兜底2：部分模型可能省略 <tool_calls> 围栏，直接输出 JSON 数组/对象。
	if len(rawBlocks) == 0 {
		trimmed := strings.TrimSpace(content)
		if strings.HasPrefix(trimmed, "[") || strings.HasPrefix(trimmed, "{") {
			rawBlocks = []string{trimmed}
		}
	}
	var calls []ToolCall
	var firstErr error
	for _, raw := range rawBlocks {
		if raw == "" {
			continue
		}
		block, err := parseToolCallPayload(raw)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("工具调用 JSON 解析失败: %w", err)
			}
			continue // 跳过该块，但继续解析其他块，避免一个畸形块拖垮整批调用
		}
		calls = append(calls, block...)
	}
	if len(calls) == 0 {
		if firstErr != nil {
			return nil, firstErr
		}
		// 输出里出现了 <tool_calls> 围栏却解析不出任何调用（JSON 非法/被截断）：
		// 必须返回错误，让外层把错误回写为纠正信号要求模型重发，
		// 而不是返回 (nil, nil) 让循环把这段畸形 JSON 误当成「最终结论」收尾。
		if len(rawBlocks) > 0 {
			return nil, fmt.Errorf("检测到 <tool_calls> 块但未能解析出任何工具调用（内容可能非法或被截断）")
		}
		return nil, nil
	}
	return finalizeCalls(calls), nil
}

// parseToolCallPayload 解析单个工具调用负载：优先按数组解析，失败再按单对象解析。
func parseToolCallPayload(raw string) ([]ToolCall, error) {
	var block []ToolCall
	if err := json.Unmarshal([]byte(raw), &block); err != nil {
		// 兼容单对象（非数组）写法
		var single ToolCall
		if err2 := json.Unmarshal([]byte(raw), &single); err2 == nil && single.Name != "" {
			return []ToolCall{single}, nil
		}
		return nil, err
	}
	return block, nil
}

// finalizeCalls 补全每条调用的缺省字段（CallID / Arguments）。
func finalizeCalls(calls []ToolCall) []ToolCall {
	for i := range calls {
		if calls[i].CallID == "" {
			calls[i].CallID = fmt.Sprintf("call_%d", i+1)
		}
		if calls[i].Arguments == nil {
			calls[i].Arguments = map[string]any{}
		}
	}
	return calls
}

// RenderToolResult 将工具结果渲染为回写文本。
func RenderToolResult(r ToolResult) string {
	return fmt.Sprintf("<tool_result name=\"%s\" call_id=\"%s\" error=\"%v\">\n%s\n</tool_result>",
		r.Name, r.CallID, r.IsError, r.Content)
}

// ---------- 小工具 ----------

func toJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(b)
}

func containsStr(s, sub string) bool { return strings.Contains(s, sub) }

func containsAny(s string, subs []string) bool {
	for _, sub := range subs {
		if sub != "" && strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "...(已截断)"
}

// getString 从工具参数里取字符串（兼容 string / json.Number / 其他）。
func getString(args map[string]any, key string) string {
	if v, ok := args[key]; ok && v != nil {
		switch x := v.(type) {
		case string:
			return strings.TrimSpace(x)
		case fmt.Stringer:
			return strings.TrimSpace(x.String())
		default:
			return strings.TrimSpace(fmt.Sprintf("%v", x))
		}
	}
	return ""
}

// getInt 从工具参数里取整数（兼容 number / string）。
func getInt(args map[string]any, key string, def int) int {
	if v, ok := args[key]; ok && v != nil {
		switch x := v.(type) {
		case int:
			return x
		case int64:
			return int(x)
		case float64:
			return int(x)
		case json.Number:
			if n, err := x.Int64(); err == nil {
				return int(n)
			}
		case string:
			if n, err := fmt.Sscanf(strings.TrimSpace(x), "%d", new(int)); err == nil {
				return n
			}
		}
	}
	return def
}

func boolArg(args map[string]any, key string, def bool) bool {
	if v, ok := args[key]; ok && v != nil {
		switch x := v.(type) {
		case bool:
			return x
		case string:
			return strings.EqualFold(strings.TrimSpace(x), "true")
		}
	}
	return def
}

// getStringSlice 从工具参数读取字符串数组，兼容 []any / []string / 单个字符串。
func getStringSlice(args map[string]any, key string) []string {
	v, ok := args[key]
	if !ok || v == nil {
		return nil
	}
	out := make([]string, 0)
	switch x := v.(type) {
	case []any:
		for _, e := range x {
			if s, ok := e.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
	case []string:
		for _, s := range x {
			if strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
	case string:
		if strings.TrimSpace(x) != "" {
			out = append(out, strings.TrimSpace(x))
		}
	}
	return out
}
