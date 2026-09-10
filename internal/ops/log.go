// Package ops 提供本项目各类运维命令（重置数据库、生成指纹库、Mock AI 服务、
// 技能前置门禁）的共享实现，供 cmd/ 下的可执行程序调用。
//
// 设计约定：
//   - 统一日志：人读输出走 ops.Infof / ops.Warnf / ops.Errorf，格式与前缀固定；
//   - 显式错误：所有实现返回 error，由 cmd 层决定退出码，不在库内调用 os.Exit；
//   - 统一信封：需要机器消费的结果用 ops.Envelope 输出 JSON。
package ops

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"
)

// 日志前缀，与历史 Python 脚本的 [ok]/[warn]/[error] 风格保持一致。
const (
	prefixInfo  = "[info] "
	prefixOK    = "[ok] "
	prefixWarn  = "[warn] "
	prefixError = "[error] "
)

// Infof 输出常规信息。
func Infof(format string, args ...any) {
	fmt.Fprintf(os.Stdout, prefixInfo+format+"\n", args...)
}

// OKf 输出成功信息（原脚本的 [ok] 前缀）。
func OKf(format string, args ...any) {
	fmt.Fprintf(os.Stdout, prefixOK+format+"\n", args...)
}

// Warnf 输出告警信息。
func Warnf(format string, args ...any) {
	fmt.Fprintf(os.Stdout, prefixWarn+format+"\n", args...)
}

// Errorf 输出错误信息。
func Errorf(format string, args ...any) {
	fmt.Fprintf(os.Stdout, prefixError+format+"\n", args...)
}

// Plainf 输出无前缀的纯文本（用于分隔线、标题等）。
func Plainf(format string, args ...any) {
	fmt.Fprintf(os.Stdout, format+"\n", args...)
}

// Envelope 是面向机器消费的统一输出信封。
type Envelope struct {
	Skill     string    `json:"skill"`
	Timestamp time.Time `json:"timestamp"`
	Data      any       `json:"data"`
}

// WriteEnvelope 把 data 以 JSON 信封形式写入 w（关闭 HTML 转义，保证中文与 URL 原样输出）。
func WriteEnvelope(w io.Writer, skill string, data any) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return enc.Encode(Envelope{
		Skill:     skill,
		Timestamp: time.Now(),
		Data:      data,
	})
}
