// paths.go 提供仓库根目录定位能力。
//
// cmd/ 下的工具既可能以 `go run ./cmd/xxx` 方式在项目根目录执行，
// 也可能以编译后的二进制在其它目录执行，因此统一从「当前工作目录向上」
// 查找 go.mod（模块名 security-agent）来定位仓库根，避免硬编码绝对路径。
package ops

import (
	"fmt"
	"os"
	"path/filepath"
)

const moduleName = "security-agent"

// FindRepoRoot 从当前工作目录逐级向上查找包含 go.mod 的目录作为仓库根。
// 若 go.mod 存在但模块名不匹配，仍然返回该目录（允许多模块化场景）。
func FindRepoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("获取当前工作目录失败: %w", err)
	}
	for {
		candidate := filepath.Join(dir, "go.mod")
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("未能在当前目录及其上级目录中找到 go.mod，请在项目仓库内运行本命令")
		}
		dir = parent
	}
}
