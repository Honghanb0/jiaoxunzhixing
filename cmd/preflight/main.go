// preflight 是安全运营技能开工前的环境门禁
// （原 security-ops-skill/scripts/mode_preflight.py 的 Go 版本）。
//
// 检查项：规则库完整性、知识库模块、vuln-engine、MCP 声明、产物目录可写、
// GitHub 代理与 npx 可达性（后两者仅告警）。
//
// 用法：
//
//	go run ./cmd/preflight            # 人读摘要 + JSON 信封
//	go run ./cmd/preflight --json     # 仅输出 JSON 信封
//
// 退出码：0 = 全部通过；1 = 存在 fail 项。
package main

import (
	"flag"
	"os"

	"security-agent/internal/ops"
)

func main() {
	jsonOnly := flag.Bool("json", false, "仅输出 JSON 信封（关闭人读摘要）")
	repo := flag.String("repo", "", "仓库根目录（默认自动向上查找 go.mod）")
	flag.Parse()

	result, err := ops.Preflight(*repo)
	if err != nil {
		ops.Errorf("前置门禁执行失败：%v", err)
		os.Exit(1)
	}

	if !*jsonOnly {
		ops.Plainf("=== security-ops-skill 前置门禁 ===")
		ops.Plainf("%s", ops.RenderChecks(result.CheckList))
		ops.Plainf("\n结论：%s | 失败 %d 项，告警 %d 项",
			map[bool]string{true: "就绪", false: "未通过"}[result.OK],
			len(result.Failed), len(result.Warnings))
	}

	if err := ops.WriteEnvelope(os.Stdout, "security-ops-skill", result); err != nil {
		ops.Errorf("输出 JSON 信封失败：%v", err)
		os.Exit(1)
	}

	if !result.OK {
		os.Exit(1)
	}
}
