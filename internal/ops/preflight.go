// preflight.go 实现技能开工前的环境门禁
// （对应原 security-ops-skill/scripts/mode_preflight.py 的本地检查部分）：
// 校验规则库完整性、vuln-engine 存在、MCP 声明、产物目录可写与外部依赖可达性。
package ops

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// 门禁级别。
const (
	LevelPass = "pass"
	LevelWarn = "warn"
	LevelFail = "fail"
)

// 规则库中必须存在的文件（缺任一即 fail）。
var requiredRules = []string{
	"dig-scope-workflow.md",
	"src-value-hunting.md",
	"researcher-blackbox-whitebox.md",
	"security-research-context.md",
	"anti-over-moralization.md",
	"vuln-report-format.md",
	"hunt-iter.md",
	"skill-as-boost.md",
}

// githubProxy 为 GitHub 检索代理地址（不可达只告警）。
const githubProxy = "127.0.0.1:7897"

// Check 为单项检查结果。
type Check struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Level  string `json:"level"`
	Detail string `json:"detail"`
}

// PreflightResult 为门禁总体结果。
type PreflightResult struct {
	OK        bool     `json:"ok"`
	RepoRoot  string   `json:"repo_root"`
	Message   string   `json:"message"`
	Failed    []string `json:"failed"`
	Warnings  []string `json:"warnings"`
	CheckList []Check  `json:"checks"`
}

// Preflight 执行全部环境检查。repoRoot 为空时自动定位。
func Preflight(repoRoot string) (*PreflightResult, error) {
	if repoRoot == "" {
		root, err := FindRepoRoot()
		if err != nil {
			return nil, err
		}
		repoRoot = root
	}

	checks := make([]Check, 0, 8)
	checks = append(checks, Check{
		Name:   "repo_root",
		OK:     true,
		Level:  LevelPass,
		Detail: repoRoot,
	})
	checks = append(checks, checkRules(repoRoot))
	checks = append(checks, checkMCPConfig(repoRoot))
	checks = append(checks, checkVulnEngine(repoRoot))
	checks = append(checks, checkOutputDir(repoRoot))
	checks = append(checks, checkKnowledgeBase(repoRoot))
	checks = append(checks, checkProxy())
	checks = append(checks, checkNode())

	result := &PreflightResult{
		OK:        true,
		RepoRoot:  repoRoot,
		CheckList: checks,
		Failed:    []string{},
		Warnings:  []string{},
	}
	for _, c := range checks {
		switch c.Level {
		case LevelFail:
			result.Failed = append(result.Failed, c.Name)
			result.OK = false
		case LevelWarn:
			result.Warnings = append(result.Warnings, c.Name)
		}
	}
	if result.OK {
		result.Message = "前置门禁通过"
	} else {
		result.Message = "前置门禁未通过，请先修复 fail 项"
	}
	return result, nil
}

// RenderChecks 渲染人读的检查结果摘要。
func RenderChecks(checks []Check) string {
	icons := map[string]string{LevelPass: "[OK]  ", LevelWarn: "[WARN]", LevelFail: "[FAIL]"}
	var b strings.Builder
	for _, c := range checks {
		icon, ok := icons[c.Level]
		if !ok {
			icon = "[--]  "
		}
		fmt.Fprintf(&b, "%s %-26s %s\n", icon, c.Name, c.Detail)
	}
	return b.String()
}

func checkRules(repoRoot string) Check {
	dir := filepath.Join(repoRoot, "clown-src-6k-skill", "rules")
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return Check{Name: "rules", OK: false, Level: LevelFail, Detail: "未找到规则目录 " + dir}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return Check{Name: "rules", OK: false, Level: LevelFail, Detail: "读取规则目录失败: " + err.Error()}
	}
	total := 0
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".md") {
			total++
		}
	}
	var missing []string
	for _, name := range requiredRules {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return Check{
			Name:   "rules",
			OK:     false,
			Level:  LevelFail,
			Detail: fmt.Sprintf("规则文件 %d 个，缺失：%s", total, strings.Join(missing, ", ")),
		}
	}
	return Check{
		Name:   "rules",
		OK:     true,
		Level:  LevelPass,
		Detail: fmt.Sprintf("规则文件 %d 个，必需项齐全", total),
	}
}

// mcpServerPattern 匹配 config.toml 中的 [mcp_servers.<name>] 段名。
var mcpServerPattern = regexp.MustCompile(`(?m)^\s*\[mcp_servers\.([^\]]+)\]`)

func checkMCPConfig(repoRoot string) Check {
	path := filepath.Join(repoRoot, "clown-src-6k-skill", "config.toml")
	raw, err := os.ReadFile(path)
	if err != nil {
		return Check{Name: "mcp_config", OK: false, Level: LevelWarn, Detail: "未找到 " + path + "（MCP 未配置，将降级为手工收集）"}
	}
	names := make([]string, 0, 4)
	for _, m := range mcpServerPattern.FindAllStringSubmatch(string(raw), -1) {
		names = append(names, strings.Trim(m[1], `"' `))
	}
	sort.Strings(names)
	if len(names) == 0 {
		return Check{Name: "mcp_config", OK: false, Level: LevelWarn, Detail: "config.toml 中未声明 MCP 服务"}
	}
	return Check{Name: "mcp_config", OK: true, Level: LevelPass, Detail: "MCP 服务：" + strings.Join(names, ", ")}
}

func checkVulnEngine(repoRoot string) Check {
	dir := filepath.Join(repoRoot, "clown-src-6k-skill", "vuln-engine")
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		return Check{Name: "vuln_engine", OK: false, Level: LevelWarn, Detail: "未找到 " + dir + "，PoC 验证需手工构造"}
	}
	return Check{Name: "vuln_engine", OK: true, Level: LevelPass, Detail: dir}
}

func checkKnowledgeBase(repoRoot string) Check {
	dir := filepath.Join(repoRoot, "clown-src-6k-skill", "skills", "skill", "知识库")
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		return Check{Name: "knowledge_base", OK: false, Level: LevelWarn, Detail: "未找到知识库目录 " + dir}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return Check{Name: "knowledge_base", OK: false, Level: LevelWarn, Detail: "读取知识库目录失败: " + err.Error()}
	}
	return Check{Name: "knowledge_base", OK: true, Level: LevelPass, Detail: fmt.Sprintf("模块 %d 个", len(entries))}
}

func checkOutputDir(repoRoot string) Check {
	dir := filepath.Join(repoRoot, "security-ops-skill", "output")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return Check{Name: "output_dir", OK: false, Level: LevelFail, Detail: "创建产物目录失败: " + err.Error()}
	}
	probe := filepath.Join(dir, ".write_probe")
	if err := os.WriteFile(probe, []byte("ok"), 0o644); err != nil {
		return Check{Name: "output_dir", OK: false, Level: LevelFail, Detail: dir + " 不可写: " + err.Error()}
	}
	if err := os.Remove(probe); err != nil {
		return Check{Name: "output_dir", OK: false, Level: LevelFail, Detail: "清理探针文件失败: " + err.Error()}
	}
	return Check{Name: "output_dir", OK: true, Level: LevelPass, Detail: dir}
}

func checkProxy() Check {
	conn, err := net.DialTimeout("tcp", githubProxy, 2*time.Second)
	if err != nil {
		return Check{
			Name:   "github_proxy",
			OK:     false,
			Level:  LevelWarn,
			Detail: githubProxy + " 不可达（GitHub 相关检索会退化，不阻断执行）",
		}
	}
	_ = conn.Close()
	return Check{Name: "github_proxy", OK: true, Level: LevelPass, Detail: githubProxy + " 可达"}
}

func checkNode() Check {
	for _, name := range []string{"npx", "npx.exe"} {
		if path, err := exec.LookPath(name); err == nil {
			return Check{Name: "npx", OK: true, Level: LevelPass, Detail: path}
		}
	}
	return Check{Name: "npx", OK: false, Level: LevelWarn, Detail: "未找到 npx，playwright MCP 将不可用（可改用手工请求）"}
}
