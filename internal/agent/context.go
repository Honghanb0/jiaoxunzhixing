package agent

import "strings"

// estimateTokens 粗略估算 token 数（中英文混合约 3~4 字符/token）。
func estimateTokens(s string) int {
	n := len([]rune(s))/3 + 1
	return n
}

// ContextManager 在对话历史超出预算时压缩，保留 system 与首条 user（任务目标），
// 并尽可能保留最近的消息。对应 pi 的 prepareNextTurn 上下文压缩策略。
type ContextManager struct {
	Budget int
}

func NewContextManager(budget int) *ContextManager {
	if budget <= 0 {
		budget = 12000
	}
	return &ContextManager{Budget: budget}
}

// Compact 返回适配预算的消息切片。
func (m *ContextManager) Compact(msgs []Message) []Message {
	total := 0
	for _, msg := range msgs {
		total += estimateTokens(msg.Content)
	}
	if total <= m.Budget {
		return msgs
	}

	// 分离 system、首条 user（目标），其余进入 rest
	var system, goal, rest []Message
	firstUser := false
	for _, msg := range msgs {
		switch {
		case msg.Role == RoleSystem:
			system = append(system, msg)
		case msg.Role == RoleUser && !firstUser:
			goal = append(goal, msg)
			firstUser = true
		default:
			rest = append(rest, msg)
		}
	}

	// 从 rest 尾部向前保留，直到预算耗尽
	budgetLeft := m.Budget - estimateTokens(joinContent(system)) - estimateTokens(joinContent(goal))
	kept := make([]Message, 0, len(rest))
	for i := len(rest) - 1; i >= 0; i-- {
		cost := estimateTokens(rest[i].Content)
		if budgetLeft <= 0 && len(kept) > 0 {
			break
		}
		kept = append([]Message{rest[i]}, kept...)
		budgetLeft -= cost
	}

	return append(append(system, goal...), kept...)
}

func joinContent(msgs []Message) string {
	var sb strings.Builder
	for _, m := range msgs {
		sb.WriteString(m.Content)
	}
	return sb.String()
}
