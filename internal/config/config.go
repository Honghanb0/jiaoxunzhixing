package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	Server    ServerConfig    `mapstructure:"server"`
	Database  DatabaseConfig  `mapstructure:"database"`
	AI        AIConfig        `mapstructure:"ai"`
	Scanner   ScannerConfig   `mapstructure:"scanner"`
	Scheduler SchedulerConfig `mapstructure:"scheduler"`
	Sensitive SensitiveConfig `mapstructure:"sensitive"`
	Alerts    AlertsConfig    `mapstructure:"alerts"`
	Logging   LoggingConfig   `mapstructure:"logging"`
	Auth      AuthConfig      `mapstructure:"auth"`
}

type ServerConfig struct {
	Host    string `mapstructure:"host"`
	Port    int    `mapstructure:"port"`
	Mode    string `mapstructure:"mode"`
	WebRoot string `mapstructure:"web_root"`
}

type DatabaseConfig struct {
	Neo4j Neo4jConfig `mapstructure:"neo4j"`
}

type Neo4jConfig struct {
	URI                          string        `mapstructure:"uri"`
	Username                     string        `mapstructure:"username"`
	Password                     string        `mapstructure:"password"`
	Database                     string        `mapstructure:"database"`
	MaxConnectionPoolSize        int           `mapstructure:"max_connection_pool_size"`
	ConnectionAcquisitionTimeout time.Duration `mapstructure:"connection_acquisition_timeout"`
	MaxTransactionRetryTime      time.Duration `mapstructure:"max_transaction_retry_time"`
	MaxRetryAttempts             int           `mapstructure:"max_retry_attempts"`
	RetryBackoff                 time.Duration `mapstructure:"retry_backoff"`
}

// AIConfig 大模型接入配置。
// 支持同时接入 DeepSeek / Kimi / GLM 三家：
//   - ai.default   指定默认模型
//   - ai.strategy  调用策略：single(只用默认) / fallback(失败降级) / parallel(并行取优)
//   - ai.providers 各家的独立配置（Key、模型、端点、超时）
//
// 旧版扁平字段（provider/api_key/model/base_url）仍然生效，会自动并入对应供应商。
type AIConfig struct {
	// ---- 旧版扁平配置（保留兼容）----
	Provider string `mapstructure:"provider"`
	APIKey   string `mapstructure:"api_key"`
	Model    string `mapstructure:"model"`
	BaseURL  string `mapstructure:"base_url"`

	// ---- 多模型统一配置 ----
	Default       string                    `mapstructure:"default"`
	Strategy      string                    `mapstructure:"strategy"`
	Fallback      bool                      `mapstructure:"fallback"`
	FallbackOrder []string                  `mapstructure:"fallback_order"`
	Providers     map[string]ProviderConfig `mapstructure:"providers"`

	Timeout        int `mapstructure:"timeout"`
	MaxRetries     int `mapstructure:"max_retries"`
	RetryBackoffMs int `mapstructure:"retry_backoff_ms"`
}

// ProviderConfig 单家模型供应商的配置
type ProviderConfig struct {
	// Enabled 为 nil 表示未显式配置，按「启用」处理
	Enabled *bool  `mapstructure:"enabled"`
	APIKey  string `mapstructure:"api_key"`
	Model   string `mapstructure:"model"`
	BaseURL string `mapstructure:"base_url"`
	Timeout int    `mapstructure:"timeout"`
	Alias   string `mapstructure:"alias"`
}

// 内置供应商名称
const (
	AIProviderDeepSeek = "deepseek"
	AIProviderKimi     = "kimi"
	AIProviderGLM      = "glm"
)

type ScannerConfig struct {
	Concurrency   int    `mapstructure:"concurrency"`
	Timeout       int    `mapstructure:"timeout"`
	UserAgent     string `mapstructure:"user_agent"`
	MaxDepth      int    `mapstructure:"max_depth"`
	MaxPages      int    `mapstructure:"max_pages"`
	RespectRobots bool   `mapstructure:"respect_robots"`
	// MaxScanMinutes 单次扫描最长时长，超时由看门狗强制中止（0 = 默认 120 分钟）
	MaxScanMinutes int `mapstructure:"max_scan_minutes"`
	// StaleJobMinutes 启动回收阈值：启动时间早于该值且仍为 running 的任务判为僵死（0 = 默认 180 分钟）
	StaleJobMinutes int `mapstructure:"stale_job_minutes"`
}

type SchedulerConfig struct {
	Enabled              bool `mapstructure:"enabled"`
	MaxConcurrentScans   int  `mapstructure:"max_concurrent_scans"`
	InspectionTimeoutSec int  `mapstructure:"inspection_timeout_sec"` // 单次巡检总超时（含扫描+AI），默认 1800
	DefaultRetryCount    int  `mapstructure:"default_retry_count"`    // AI 调用失败默认重试次数
	DefaultRetryBackoffSec int `mapstructure:"default_retry_backoff_sec"` // 重试退避秒数
}

type SensitiveConfig struct {
	Keywords       []string `mapstructure:"keywords"`
	RegexPatterns  []string `mapstructure:"regex_patterns"`
	FileExtensions []string `mapstructure:"file_extensions"`
}

type AlertsConfig struct {
	Enabled  bool           `mapstructure:"enabled"`
	Channels []AlertChannel `mapstructure:"channels"`
}

type AuthConfig struct {
	JwtSecret        string `mapstructure:"jwt_secret"`
	TokenExpireHours int    `mapstructure:"token_expire_hours"`
}

type AlertChannel struct {
	Type     string `mapstructure:"type"`
	URL      string `mapstructure:"url"`
	SMTPHost string `mapstructure:"smtp_host"`
	SMTPPort int    `mapstructure:"smtp_port"`
	From     string `mapstructure:"from"`
	To       string `mapstructure:"to"`
}

type LoggingConfig struct {
	Level  string `mapstructure:"level"`
	Format string `mapstructure:"format"`
	Output string `mapstructure:"output"`
}

var GlobalConfig *Config

func Load(configPath string) (*Config, error) {
	v := viper.New()

	if configPath != "" {
		v.SetConfigFile(configPath)
	} else {
		v.SetConfigName("config")
		v.SetConfigType("yaml")
		v.AddConfigPath(".")
		v.AddConfigPath("./config")
	}

	// 读取环境变量并替换占位符
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// 读取配置文件
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("failed to read config: %w", err)
		}
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// 处理环境变量替换
	cfg.AI.APIKey = resolveEnvVar(cfg.AI.APIKey)
	cfg.AI.BaseURL = resolveEnvVar(cfg.AI.BaseURL)

	// 多模型：逐家解析 ${ENV} 占位符
	for name, pc := range cfg.AI.Providers {
		pc.APIKey = resolveEnvVar(pc.APIKey)
		pc.BaseURL = resolveEnvVar(pc.BaseURL)
		cfg.AI.Providers[name] = pc
	}

	normalizeAIConfig(&cfg.AI, v)

	// Neo4j 凭据同样支持 ${ENV} 占位符（如密码从 NEO4J_PASSWORD 注入，避免明文落盘）
	cfg.Database.Neo4j.Username = resolveEnvVar(cfg.Database.Neo4j.Username)
	cfg.Database.Neo4j.Password = resolveEnvVar(cfg.Database.Neo4j.Password)

	// JWT 密钥同样支持 ${ENV} 占位符（如从 JWT_SECRET 注入，避免明文落盘）
	cfg.Auth.JwtSecret = resolveEnvVar(cfg.Auth.JwtSecret)

	GlobalConfig = &cfg
	return &cfg, nil
}

// normalizeAIConfig 补齐多模型配置的默认值，并把旧版扁平配置并入对应供应商。
// 这样老配置（ai.provider + ai.api_key）无需修改即可继续工作。
func normalizeAIConfig(ai *AIConfig, v *viper.Viper) {
	if ai.Providers == nil {
		ai.Providers = map[string]ProviderConfig{}
	}

	// 旧版扁平配置兜底注入
	if name := strings.ToLower(strings.TrimSpace(ai.Provider)); name != "" {
		pc, ok := ai.Providers[name]
		if !ok {
			pc = ProviderConfig{}
		}
		if pc.APIKey == "" {
			pc.APIKey = ai.APIKey
		}
		if pc.Model == "" {
			pc.Model = ai.Model
		}
		if pc.BaseURL == "" {
			pc.BaseURL = ai.BaseURL
		}
		ai.Providers[name] = pc
	}

	// 三家内置供应商始终注册，便于界面展示“未配置”状态
	for _, name := range []string{AIProviderDeepSeek, AIProviderKimi, AIProviderGLM} {
		if _, ok := ai.Providers[name]; !ok {
			ai.Providers[name] = ProviderConfig{}
		}
	}

	// 默认模型
	ai.Default = strings.ToLower(strings.TrimSpace(ai.Default))
	if ai.Default == "" {
		ai.Default = strings.ToLower(strings.TrimSpace(ai.Provider))
	}
	if ai.Default == "" {
		ai.Default = AIProviderDeepSeek
	}

	// 调用策略
	switch strings.ToLower(strings.TrimSpace(ai.Strategy)) {
	case "fallback", "parallel":
		ai.Strategy = strings.ToLower(strings.TrimSpace(ai.Strategy))
	default:
		ai.Strategy = "single"
	}

	// 未显式配置时默认开启失败降级，避免单家故障导致整体不可用
	if !v.IsSet("ai.fallback") {
		ai.Fallback = true
	}

	// 降级链
	if len(ai.FallbackOrder) == 0 {
		ai.FallbackOrder = []string{AIProviderDeepSeek, AIProviderKimi, AIProviderGLM}
	}

	if ai.Timeout <= 0 {
		ai.Timeout = 60
	}
	if !v.IsSet("ai.max_retries") {
		ai.MaxRetries = 2
	}
	if ai.RetryBackoffMs <= 0 {
		ai.RetryBackoffMs = 500
	}
}

func resolveEnvVar(value string) string {
	if strings.HasPrefix(value, "${") && strings.HasSuffix(value, "}") {
		inner := value[2 : len(value)-1]
		// 支持 ${VAR} 与 ${VAR:-default} 两种形式
		var envKey, def string
		if idx := strings.Index(inner, ":-"); idx >= 0 {
			envKey = inner[:idx]
			def = inner[idx+2:]
		} else {
			envKey = inner
		}
		if envValue := os.Getenv(envKey); envValue != "" {
			return envValue
		}
		if def != "" {
			return def
		}
	}
	return value
}

func (c *Config) GetServerAddr() string {
	return fmt.Sprintf("%s:%d", c.Server.Host, c.Server.Port)
}
