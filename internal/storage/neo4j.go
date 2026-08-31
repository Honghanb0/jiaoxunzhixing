package storage

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/url"
	"strings"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"security-agent/internal/config"
)

// Neo4jStore 封装 Neo4j 驱动与数据库连接配置。
type Neo4jStore struct {
	driver neo4j.Driver
	cfg    config.Neo4jConfig
}

// Store 是全局单例，供各 Repository 直接取用。
var Store *Neo4jStore

// 连接相关默认值（启动重试，应对“数据库尚未就绪”的竞态）。
const (
	defaultMaxRetries   = 5
	defaultRetryBackoff = 2 * time.Second
)

// NewNeo4jStore 建立并校验与 Neo4j 的连接。
// 流程：校验配置 -> 创建驱动 -> 带重试地 VerifyConnectivity -> 初始化 Schema。
func NewNeo4jStore(cfg *config.Neo4jConfig) (*Neo4jStore, error) {
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}

	driver, err := neo4j.NewDriver(cfg.URI,
		neo4j.BasicAuth(cfg.Username, cfg.Password, ""),
		func(c *neo4j.Config) {
			if cfg.MaxConnectionPoolSize > 0 {
				c.MaxConnectionPoolSize = cfg.MaxConnectionPoolSize
			}
			if cfg.ConnectionAcquisitionTimeout > 0 {
				c.ConnectionAcquisitionTimeout = cfg.ConnectionAcquisitionTimeout
			}
			if cfg.MaxTransactionRetryTime > 0 {
				c.MaxTransactionRetryTime = cfg.MaxTransactionRetryTime
			}
		},
	)
	if err != nil {
		return nil, fmt.Errorf("创建 Neo4j 驱动失败: %w", err)
	}

	// 启动阶段重试：应对数据库刚启动、端口尚未就绪等竞态。
	maxRetries := cfg.MaxRetryAttempts
	if maxRetries <= 0 {
		maxRetries = defaultMaxRetries
	}
	backoff := cfg.RetryBackoff
	if backoff <= 0 {
		backoff = defaultRetryBackoff
	}

	var lastErr error
	for attempt := 1; attempt <= maxRetries; attempt++ {
		if err := driver.VerifyConnectivity(); err != nil {
			lastErr = err
			if attempt < maxRetries {
				log.Printf("[Neo4j] 第 %d/%d 次连接失败，%s 后重试: %s",
					attempt, maxRetries, backoff, classifyError(err))
				time.Sleep(backoff)
				continue
			}
		} else {
			lastErr = nil
			break
		}
	}

	if lastErr != nil {
		_ = driver.Close()
		return nil, fmt.Errorf("无法连接到 Neo4j (%s): %w", cfg.URI, lastErr)
	}

	log.Printf("[Neo4j] 连接成功: %s | 数据库: %s | 用户: %s",
		cfg.URI, dbName(cfg), maskUser(cfg.Username))

	store := &Neo4jStore{driver: driver, cfg: *cfg}

	// Schema 初始化失败不致命：仅告警，业务表会在写入时按需创建。
	if err := store.initSchema(); err != nil {
		log.Printf("[Neo4j] 警告: 初始化 Schema 时出现问题（已忽略）: %v", err)
	}

	Store = store
	return store, nil
}

// validateConfig 在建立连接前做基础校验，尽早暴露配置错误。
func validateConfig(cfg *config.Neo4jConfig) error {
	if cfg == nil {
		return errors.New("neo4j 配置为空（config.database.neo4j）")
	}
	if strings.TrimSpace(cfg.URI) == "" {
		return errors.New("neo4j.uri 不能为空")
	}

	u, err := url.Parse(cfg.URI)
	if err != nil {
		return fmt.Errorf("neo4j.uri 格式非法: %w", err)
	}
	switch u.Scheme {
	case "neo4j", "bolt", "neo4j+s", "bolt+s", "neo4j+ssc", "bolt+ssc":
		// 支持的协议
	default:
		return fmt.Errorf("neo4j.uri 协议不支持: %q（应使用 neo4j:// 或 bolt://）", u.Scheme)
	}

	if strings.TrimSpace(cfg.Username) == "" {
		return errors.New("neo4j.username 不能为空")
	}
	if strings.TrimSpace(cfg.Password) == "" {
		return errors.New("neo4j.password 不能为空（建议通过环境变量 NEO4J_PASSWORD 提供，配置中写 ${NEO4J_PASSWORD}）")
	}
	return nil
}

// initSchema 创建唯一性约束。使用 Neo4j 5 命名约束语法，失败不致命。
func (s *Neo4jStore) initSchema() error {
	constraints := []string{
		"CREATE CONSTRAINT domain_id_unique IF NOT EXISTS FOR (d:Domain) REQUIRE (d.id) IS UNIQUE",
		"CREATE CONSTRAINT scanjob_id_unique IF NOT EXISTS FOR (s:ScanJob) REQUIRE (s.id) IS UNIQUE",
		"CREATE CONSTRAINT vuln_id_unique IF NOT EXISTS FOR (v:Vulnerability) REQUIRE (v.id) IS UNIQUE",
		"CREATE CONSTRAINT sensitive_id_unique IF NOT EXISTS FOR (s:SensitiveInfo) REQUIRE (s.id) IS UNIQUE",
		"CREATE CONSTRAINT alert_id_unique IF NOT EXISTS FOR (a:Alert) REQUIRE (a.id) IS UNIQUE",
	}

	session := s.driver.NewSession(neo4j.SessionConfig{DatabaseName: s.cfg.Database})
	defer session.Close()

	var firstErr error
	for _, cypher := range constraints {
		if _, err := session.Run(cypher, nil); err != nil {
			log.Printf("[Neo4j] 警告: 创建约束失败: %v", err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

// Session 返回一个指向配置数据库的会话（供各 Repository 使用）。
func (s *Neo4jStore) Session() neo4j.Session {
	return s.driver.NewSession(neo4j.SessionConfig{DatabaseName: s.cfg.Database})
}

// HealthCheck 用于运行期健康检查（如 /health 端点、定时探活）。
func (s *Neo4jStore) HealthCheck(_ context.Context) error {
	if err := s.driver.VerifyConnectivity(); err != nil {
		return fmt.Errorf("neo4j 健康检查失败: %w", err)
	}
	return nil
}

// Driver 暴露底层驱动，便于高级用法（如 ExecuteQuery）。
func (s *Neo4jStore) Driver() neo4j.Driver {
	return s.driver
}

// Close 关闭驱动并释放连接池。
func (s *Neo4jStore) Close() error {
	return s.driver.Close()
}

// classifyError 把底层错误分类为可读的中文提示，便于排错。
func classifyError(err error) string {
	var neoErr *neo4j.Neo4jError
	switch {
	case neo4j.IsConnectivityError(err):
		return "网络不可达（请确认 Neo4j 已启动且 7687 端口可访问）"
	case errors.As(err, &neoErr):
		code := neoErr.Code
		switch {
		case strings.HasPrefix(code, "Neo.ClientError.Security."):
			return "认证失败（用户名或密码错误，请检查 NEO4J_PASSWORD）"
		case strings.HasPrefix(code, "Neo.ClientError.Schema."),
			strings.HasPrefix(code, "Neo.ClientError.Statement."):
			return fmt.Sprintf("语句/模式错误 [%s] %s", code, neoErr.Msg)
		default:
			return fmt.Sprintf("Neo4j 错误 [%s] %s", code, neoErr.Msg)
		}
	default:
		return err.Error()
	}
}

func dbName(cfg *config.Neo4jConfig) string {
	if strings.TrimSpace(cfg.Database) == "" {
		return "neo4j(默认)"
	}
	return cfg.Database
}

func maskUser(u string) string {
	if u == "" {
		return ""
	}
	r := []rune(u)
	if len(r) <= 1 {
		return "*"
	}
	return string(r[0]) + strings.Repeat("*", len(r)-1)
}
