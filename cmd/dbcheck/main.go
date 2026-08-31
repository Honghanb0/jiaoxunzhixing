// dbcheck 是一个独立的连接自检命令：
// 用于在不启动完整 Web 服务的前提下，验证 Neo4j 连接配置是否正确。
//
// 用法：
//
//	NEO4J_PASSWORD=你的密码 go run cmd/dbcheck/main.go
//
// 退出码 0 表示连接成功，非 0 表示失败并打印原因。
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"security-agent/internal/config"
	"security-agent/internal/storage"
)

func main() {
	cfg, err := config.Load("")
	if err != nil {
		log.Fatalf("加载配置失败: %v", err)
	}

	store, err := storage.NewNeo4jStore(&cfg.Database.Neo4j)
	if err != nil {
		fmt.Printf("✗ Neo4j 连接失败: %v\n", err)
		os.Exit(1)
	}
	defer store.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := store.HealthCheck(ctx); err != nil {
		fmt.Printf("✗ Neo4j 健康检查失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("✓ Neo4j 连接成功，数据库可正常访问。")
}
