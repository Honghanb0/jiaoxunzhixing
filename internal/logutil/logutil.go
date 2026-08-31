// Package logutil 提供面向调试的轻量级日志聚合：
//   - 接管标准库 log 的输出，写入环形缓冲（最近 N 条）并可选落盘到文件；
//   - 按关键字启发式识别日志级别（ERROR/WARN/INFO/DEBUG），便于前端着色与过滤；
//   - 暴露 Tail 供 HTTP 接口增量拉取，支撑“CLI 风格日志页”的滚动与暂停刷新。
//
// 说明：标准库 log 不带级别/时间戳，级别由行内容启发式判定，时间戳在写入缓冲时打上。
// 历史存量日志无需迁移；环形缓冲为空时接口返回空列表即可。
package logutil

import (
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Level 日志级别（数值越大越严重）。
type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

// ParseLevel 将级别字符串归一为 Level（未知归为 INFO）。
func ParseLevel(s string) Level {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "DEBUG", "TRACE", "VERBOSE":
		return LevelDebug
	case "WARN", "WARNING":
		return LevelWarn
	case "ERROR", "ERR", "FATAL", "PANIC":
		return LevelError
	default:
		return LevelInfo
	}
}

func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "DEBUG"
	case LevelWarn:
		return "WARN"
	case LevelError:
		return "ERROR"
	default:
		return "INFO"
	}
}

// Entry 单条日志记录。
type Entry struct {
	Seq    int64     `json:"seq"`    // 单调递增序号，用于增量拉取
	Ts     time.Time `json:"ts"`     // 写入时间
	Level  string    `json:"level"`  // ERROR / WARN / INFO / DEBUG
	Source string    `json:"source"` // server（后端）
	Msg    string    `json:"msg"`    // 日志内容
}

const maxEntries = 5000

var (
	mu      sync.Mutex
	buf     []Entry
	seq     int64
	installed bool
)

// detectLevel 启发式识别日志级别。
func detectLevel(line string) Level {
	u := strings.ToUpper(line)
	// 错误类关键词
	for _, k := range []string{"ERROR", "FATAL", "PANIC", "FAIL", "失败", "错误", "异常", "拒绝", "DENIED", "FORBIDDEN"} {
		if strings.Contains(u, k) {
			return LevelError
		}
	}
	for _, k := range []string{"WARN", "WARNING", "警告", "慎用", "DEPRECATED"} {
		if strings.Contains(u, k) {
			return LevelWarn
		}
	}
	for _, k := range []string{"DEBUG", "TRACE", "VERBOSE", "调试"} {
		if strings.Contains(u, k) {
			return LevelDebug
		}
	}
	return LevelInfo
}

// appendLine 写入一行日志（自动补级别与时间戳），并裁剪环形缓冲。
func appendLine(line string) {
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	seq++
	buf = append(buf, Entry{
		Seq:    seq,
		Ts:     time.Now(),
		Level:  detectLevel(line).String(),
		Source: "server",
		Msg:    line,
	})
	if len(buf) > maxEntries {
		buf = buf[len(buf)-maxEntries:]
	}
}

// writer 实现 io.Writer：按行缓冲，跨多行也能正确切分。
type writer struct {
	pending []byte
	file    io.Writer
	stdout  io.Writer
}

func (w *writer) Write(p []byte) (int, error) {
	// 同时原样输出到 stdout 与文件，便于本地排查（控制台仍可看到）。
	if w.stdout != nil {
		_, _ = w.stdout.Write(p)
	}
	if w.file != nil {
		_, _ = w.file.Write(p)
	}

	w.pending = append(w.pending, p...)
	for {
		idx := strings.IndexByte(string(w.pending), '\n')
		if idx < 0 {
			break
		}
		line := string(w.pending[:idx])
		w.pending = w.pending[idx+1:]
		appendLine(line)
	}
	return len(p), nil
}

// Install 接管标准库 log 输出：写入环形缓冲（供 /api/logs 拉取），
// 并可选落盘到 logsDir/server.log、同时保留 stdout。
// 多次调用安全（仅首次生效）。
func Install(logsDir string) {
	mu.Lock()
	if installed {
		mu.Unlock()
		return
	}
	installed = true
	mu.Unlock()

	w := &writer{stdout: os.Stdout}
	if logsDir != "" {
		_ = os.MkdirAll(logsDir, 0o755)
		f, err := os.OpenFile(filepath.Join(logsDir, "server.log"),
			os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err == nil {
			w.file = f
		}
	}
	// 接管标准库 log 输出：后续所有 log 输出进入环形缓冲（并保留 stdout/落盘）。
	log.SetOutput(w)
}

// Tail 返回序号大于 after 的最近 entries（最多 limit 条），用于增量拉取。
// after <= 0 时返回最近 limit 条。
func Tail(after int64, limit int) []Entry {
	mu.Lock()
	defer mu.Unlock()
	if limit <= 0 || limit > maxEntries {
		limit = 500
	}
	var out []Entry
	for _, e := range buf {
		if after <= 0 || e.Seq > after {
			out = append(out, e)
		}
	}
	if len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out
}

// Len 当前缓冲条数。
func Len() int {
	mu.Lock()
	defer mu.Unlock()
	return len(buf)
}
