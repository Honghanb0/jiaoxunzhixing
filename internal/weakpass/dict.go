// Package weakpass 提供弱口令探测所需的口令字典管理与多协议登录校验能力，
// 供自主智能体的弱口令扫描工具（manage_password_dict / weak_password_scan / verify_credentials）调用。
//
// 设计要点：
//   - 内置默认字典（users / passwords）通过 go:embed 打包，与二进制一同发布，不依赖运行时工作目录；
//   - 字典可在运行时通过 manage_password_dict 追加 / 重置 / 从文件加载；
//   - 校验器（Checker）按服务类型注册，覆盖 ssh/ftp/pop3/smtp/redis/http 等常见协议；
//   - 所有网络操作均带超时与上下文取消，避免任务被中止时悬挂连接。
package weakpass

import (
	_ "embed"
	"os"
	"strings"
	"sync"
)

//go:embed dicts/users.txt
var defaultUsers string

//go:embed dicts/passwords.txt
var defaultPasswords string

// DictManager 管理命名口令字典。内置 users / passwords 两个默认字典，
// 运行时可对其追加词、重置为内置值，或新建/加载自定义字典。
type DictManager struct {
	mu      sync.Mutex
	dicts   map[string][]string
	builtin map[string][]string
}

// NewDictManager 构造一个含内置默认字典的管理器。
func NewDictManager() *DictManager {
	u := splitLines(defaultUsers)
	p := splitLines(defaultPasswords)
	return &DictManager{
		dicts:   map[string][]string{"users": u, "passwords": p},
		builtin: map[string][]string{"users": u, "passwords": p},
	}
}

// splitLines 将文本按行拆词，跳过空行与 # 注释行。
func splitLines(s string) []string {
	out := make([]string, 0)
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(strings.TrimRight(line, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}

// List 返回各字典名称与其词条数。
func (m *DictManager) List() map[string]int {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]int, len(m.dicts))
	for k, v := range m.dicts {
		out[k] = len(v)
	}
	return out
}

// Get 取回某字典的副本（避免外部修改内部切片）。
func (m *DictManager) Get(name string) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.dicts[name]
	if !ok {
		return nil
	}
	out := make([]string, len(v))
	copy(out, v)
	return out
}

// Add 向指定字典追加词条（自动去重），返回实际新增条数。
// 字典不存在时自动新建。
func (m *DictManager) Add(name string, words []string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.dicts[name]; !ok {
		m.dicts[name] = make([]string, 0)
	}
	seen := make(map[string]struct{}, len(m.dicts[name]))
	for _, w := range m.dicts[name] {
		seen[w] = struct{}{}
	}
	n := 0
	for _, w := range words {
		w = strings.TrimSpace(w)
		if w == "" {
			continue
		}
		if _, dup := seen[w]; dup {
			continue
		}
		seen[w] = struct{}{}
		m.dicts[name] = append(m.dicts[name], w)
		n++
	}
	return n
}

// Reset 将字典重置为内置值；非内置字典则删除。返回是否命中内置字典。
func (m *DictManager) Reset(name string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if b, ok := m.builtin[name]; ok {
		cp := make([]string, len(b))
		copy(cp, b)
		m.dicts[name] = cp
		return true
	}
	delete(m.dicts, name)
	return false
}

// LoadFile 从外部文件加载词条到指定字典（追加，去重），返回新增条数。
func (m *DictManager) LoadFile(name, path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return m.Add(name, splitLines(string(data))), nil
}
