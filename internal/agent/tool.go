package agent

import (
	"context"
	"encoding/json"
	"fmt"
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

func (t toolFunc) Name() string                             { return t.name }
func (t toolFunc) Description() string                      { return t.description }
func (t toolFunc) Schema() map[string]any                   { return t.schema }
func (t toolFunc) Execute(ctx context.Context, args map[string]any) (string, error) {
	return t.fn(ctx, args)
}

// ToolCall 模型请求的一次工具调用（从 <tool_calls> 块解析得到）。
type ToolCall struct {
	Name     string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
	CallID   string         `json:"call_id,omitempty"`
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
var toolCallsRe = regexp.MustCompile(`(?s)<tool_calls>(.*?)</tool_calls>`)

// ParseToolCalls 从模型输出中解析工具调用；无调用块时返回 (nil, nil)。
func ParseToolCalls(content string) ([]ToolCall, error) {
	m := toolCallsRe.FindStringSubmatch(content)
	if m == nil {
		return nil, nil
	}
	raw := strings.TrimSpace(m[1])
	if raw == "" {
		return nil, nil
	}
	var calls []ToolCall
	if err := json.Unmarshal([]byte(raw), &calls); err != nil {
		// 兼容单对象（非数组）写法
		var single ToolCall
		if err2 := json.Unmarshal([]byte(raw), &single); err2 == nil && single.Name != "" {
			calls = []ToolCall{single}
		} else {
			return nil, fmt.Errorf("工具调用 JSON 解析失败: %w", err)
		}
	}
	for i := range calls {
		if calls[i].CallID == "" {
			calls[i].CallID = fmt.Sprintf("call_%d", i+1)
		}
		if calls[i].Arguments == nil {
			calls[i].Arguments = map[string]any{}
		}
	}
	return calls, nil
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
