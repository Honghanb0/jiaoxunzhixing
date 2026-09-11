// Package ops 中 resetdb.go 实现 Neo4j 图数据库重置能力
// （对应原 reset_db.py）：默认 dry-run，必须显式 --confirm 才会真正清空。
package ops

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"security-agent/internal/config"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

// ResetOptions 为重置操作的全部输入。
type ResetOptions struct {
	URI       string // bolt 地址
	Username  string
	Password  string
	Database  string
	Confirm   bool   // 真正执行删除
	DryRun    bool   // 仅打印将要执行的操作
	ConfigDir string // config.yaml 所在目录（空表示当前目录）
}

// ResetResult 为重置操作的执行结果。
type ResetResult struct {
	URI         string `json:"uri"`
	Database    string `json:"database"`
	Executed    bool   `json:"executed"` // false 表示本次为 dry-run
	NodesBefore int64  `json:"nodes_before"`
	RelsBefore  int64  `json:"rels_before"`
	NodesAfter  int64  `json:"nodes_after"`
	RelsAfter   int64  `json:"rels_after"`
}

// ErrNotConfirmed 表示未显式确认，本次为 dry-run（非错误，调用方据此退出码 0）。
var ErrNotConfirmed = errors.New("未指定 --confirm，仅执行 dry-run")

// ResolveResetOptions 按「命令行参数 > 环境变量 > config.yaml > 内置默认值」填充缺省项。
func ResolveResetOptions(opt ResetOptions) (ResetOptions, error) {
	// 缺省值：环境变量优先于内置字面量（与原脚本 DEFAULT_* 定义一致）
	defURI := envOr("NEO4J_URI", "bolt://localhost:7687")
	defUser := envOr("NEO4J_USER", "neo4j")
	defPass := envOr("NEO4J_PASSWORD", "your_password")
	defDB := envOr("NEO4J_DATABASE", "neo4j")

	// config.yaml 用于补充未显式指定的项；读取失败只告警，不阻断。
	cfgValues, err := loadNeo4jFromConfig(opt.ConfigDir)
	if err != nil {
		Warnf("读取 config.yaml 失败，使用默认值：%v", err)
	}

	// 优先级：命令行参数 > config.yaml > 环境变量/内置默认值
	if opt.URI == "" {
		opt.URI = firstNonEmpty(cfgValues.URI, defURI)
	}
	if opt.Username == "" {
		opt.Username = firstNonEmpty(cfgValues.Username, defUser)
	}
	if opt.Password == "" {
		opt.Password = firstNonEmpty(cfgValues.Password, defPass)
	}
	if opt.Database == "" {
		opt.Database = firstNonEmpty(cfgValues.Database, defDB)
	}
	return opt, nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

// loadNeo4jFromConfig 复用平台配置加载器读取 config.yaml 中的 database.neo4j 段。
func loadNeo4jFromConfig(dir string) (config.Neo4jConfig, error) {
	path := "config.yaml"
	if dir != "" {
		path = dir + string(os.PathSeparator) + "config.yaml"
	}
	if _, err := os.Stat(path); err != nil {
		return config.Neo4jConfig{}, nil // 文件不存在视为无配置，不算错误
	}
	cfg, err := config.Load(path)
	if err != nil {
		return config.Neo4jConfig{}, err
	}
	return cfg.Database.Neo4j, nil
}

// ResetDB 执行数据库重置。未显式 Confirm 时只打印计划并返回 ErrNotConfirmed。
func ResetDB(ctx context.Context, opt ResetOptions) (*ResetResult, error) {
	opt, err := ResolveResetOptions(opt)
	if err != nil {
		return nil, err
	}

	result := &ResetResult{URI: opt.URI, Database: opt.Database}

	Plainf("============================================================")
	Plainf("交巡智星 - Neo4j 数据库重置")
	Plainf("============================================================")
	Plainf("  目标 URI   : %s", opt.URI)
	Plainf("  用户名     : %s", opt.Username)
	Plainf("  数据库     : %s", opt.Database)
	mode := "DRY-RUN（不修改）"
	if opt.Confirm && !opt.DryRun {
		mode = "CONFIRM（将清空全部数据!）"
	}
	Plainf("  模式       : %s", mode)
	Plainf("============================================================")

	if opt.DryRun || !opt.Confirm {
		Infof("未提供 --confirm，不会执行任何删除操作。")
		Infof("若确实要清空，请重新运行并附加 --confirm 参数。")
		return result, ErrNotConfirmed
	}

	driver, err := neo4j.NewDriverWithContext(opt.URI, neo4j.BasicAuth(opt.Username, opt.Password, ""))
	if err != nil {
		return nil, fmt.Errorf("创建 Neo4j 驱动失败: %w", err)
	}
	defer func() {
		if cerr := driver.Close(ctx); cerr != nil {
			Warnf("关闭 Neo4j 驱动失败: %v", cerr)
		}
	}()

	if err := driver.VerifyConnectivity(ctx); err != nil {
		return nil, fmt.Errorf("Neo4j 连接失败: %w", err)
	}
	OKf("已连接到 Neo4j。")

	session := driver.NewSession(ctx, neo4j.SessionConfig{DatabaseName: opt.Database})
	defer func() {
		if cerr := session.Close(ctx); cerr != nil {
			Warnf("关闭会话失败: %v", cerr)
		}
	}()

	nodesBefore, err := countNodes(ctx, session)
	if err != nil {
		return nil, err
	}
	relsBefore, err := countRels(ctx, session)
	if err != nil {
		return nil, err
	}
	Infof("删除前：节点 %d 个，关系 %d 条。", nodesBefore, relsBefore)

	if _, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		_, err := tx.Run(ctx, "MATCH (n) DETACH DELETE n", nil)
		return nil, err
	}); err != nil {
		return nil, fmt.Errorf("清空数据库失败: %w", err)
	}

	nodesAfter, err := countNodes(ctx, session)
	if err != nil {
		return nil, err
	}
	relsAfter, err := countRels(ctx, session)
	if err != nil {
		return nil, err
	}

	result.Executed = true
	result.NodesBefore, result.RelsBefore = nodesBefore, relsBefore
	result.NodesAfter, result.RelsAfter = nodesAfter, relsAfter
	OKf("删除后：节点 %d 个，关系 %d 条。", nodesAfter, relsAfter)
	Infof("重启服务后，若数据库无用户，平台会自动重建默认管理员账号。")
	return result, nil
}

func countNodes(ctx context.Context, session neo4j.SessionWithContext) (int64, error) {
	return countSingle(ctx, session, "MATCH (n) RETURN count(n) AS c")
}

func countRels(ctx context.Context, session neo4j.SessionWithContext) (int64, error) {
	return countSingle(ctx, session, "MATCH ()-[r]->() RETURN count(r) AS c")
}

func countSingle(ctx context.Context, session neo4j.SessionWithContext, cypher string) (int64, error) {
	count, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		res, err := tx.Run(ctx, cypher, nil)
		if err != nil {
			return nil, err
		}
		record, err := res.Single(ctx)
		if err != nil {
			return nil, err
		}
		value, _ := record.Get("c")
		switch v := value.(type) {
		case int64:
			return v, nil
		case int:
			return int64(v), nil
		default:
			return int64(0), fmt.Errorf("无法解析统计值: %#v", value)
		}
	})
	if err != nil {
		return 0, fmt.Errorf("执行统计失败（%s）: %w", cypher, err)
	}
	return count.(int64), nil
}
