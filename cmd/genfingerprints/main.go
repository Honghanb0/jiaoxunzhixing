// genfingerprints 是指纹库归一化生成工具（原 gen_fingerprints.py 的 Go 版本）。
//
// 读取 wanpinglingtan 的三份指纹库与 ext_fingerprints.js，归一化后写入
// internal/scanner/fingerprints.json（编译期由 go:embed 内嵌）。
//
// 用法：
//
//	go run ./cmd/genfingerprints
//
// 退出码：0 = 成功；1 = 生成或写入失败。
package main

import (
	"flag"
	"os"

	"security-agent/internal/ops"
)

func main() {
	repo := flag.String("repo", "", "仓库根目录（默认自动向上查找 go.mod）")
	out := flag.String("out", "", "输出文件路径（默认 internal/scanner/fingerprints.json）")
	flag.Parse()

	stats, err := ops.GenerateFingerprints(*repo, *out)
	if err != nil {
		ops.Errorf("生成指纹库失败：%v", err)
		os.Exit(1)
	}
	ops.ReportFingerprintStats(stats)
}
