// resetdb 是 Neo4j 图数据库重置工具（原 reset_db.py 的 Go 版本）。
//
// ⚠️ 警告：本命令在显式确认后会清空整个 Neo4j 图数据库中的所有节点与关系
// （含用户、域名、漏洞、工单、巡检记录等全部数据），且不可恢复。
//
// 用法：
//
//	# 1) 查看将要执行的操作（dry-run，不做任何修改）
//	go run ./cmd/resetdb --dry-run
//
//	# 2) 真正执行清空（必须显式传 --confirm）
//	go run ./cmd/resetdb --confirm
//
//	# 3) 自定义连接（也可用环境变量 NEO4J_URI / NEO4J_USER / NEO4J_PASSWORD / NEO4J_DATABASE）
//	go run ./cmd/resetdb --confirm --uri bolt://localhost:7687 --user neo4j --password 密码 --database neo4j
//
// 连接参数优先级：命令行参数 > config.yaml > 环境变量 > 内置默认值。
//
// 退出码：0 = 成功（含 dry-run）；1 = 执行失败。
package main

import (
	"context"
	"errors"
	"flag"
	"os"
	"os/signal"
	"syscall"
	"time"

	"security-agent/internal/ops"
)

func main() {
	var (
		uri       = flag.String("uri", "", "Neo4j bolt 地址")
		user      = flag.String("user", "", "Neo4j 用户名")
		password  = flag.String("password", "", "Neo4j 密码")
		database  = flag.String("database", "", "Neo4j 数据库名")
		confirm   = flag.Bool("confirm", false, "必须显式指定才会真正执行删除（否则仅 dry-run）")
		dryRun    = flag.Bool("dry-run", false, "只打印将要执行的操作，不做任何修改")
		configDir = flag.String("config-dir", "", "config.yaml 所在目录（默认当前目录）")
	)
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	result, err := ops.ResetDB(ctx, ops.ResetOptions{
		URI:       *uri,
		Username:  *user,
		Password:  *password,
		Database:  *database,
		Confirm:   *confirm,
		DryRun:    *dryRun,
		ConfigDir: *configDir,
	})
	if err != nil {
		if errors.Is(err, ops.ErrNotConfirmed) {
			return // dry-run 属于正常路径
		}
		ops.Errorf("操作失败：%v", err)
		os.Exit(1)
	}
	if result == nil {
		os.Exit(1)
	}
}
