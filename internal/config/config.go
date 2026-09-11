package config

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"path/filepath"
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
	Agent     AgentConfig     `mapstructure:"agent"`
}

// AgentConfig 自主智能体（多轮工具调用 + 自主规划）配置。
type AgentConfig struct {
	Enabled  bool   `mapstructure:"enabled"`   // 是否启用自主智能体
	MaxTurns int    `mapstructure:"max_turns"` // 单任务最大推理轮次（防失控），默认 24
	Model    string `mapstructure:"model"`     // 可选：覆盖默认模型供应商
}

type ServerConfig struct {
	Host    string `mapstructure:"host"`
	Port    int    `mapstructure:"port"`
	Mode    string `mapstructure:"mode"`
	WebRoot string `mapstructure:"web_root"`

	// CORSAllowedOrigins 允许跨域访问的源白名单。
	// 留空表示"仅同源"——前端由本服务直接托管（web/index.html），
	// 同源场景不需要任何 CORS 响应头，这也是最安全的默认值。
	// 只有前后端分离部署时，才在这里显式列出前端域名。
	CORSAllowedOrigins []string `mapstructure:"cors_allowed_origins"`

	// TrustedProxies 可信反向代理地址（CIDR 或 IP）。
	// 留空表示不信任任何代理，客户端 IP 一律取 TCP 连接的真实来源（RemoteAddr），
	// 避免攻击者伪造 X-Forwarded-For 绕过登录限速与审计。
	// 部署在 nginx / 负载均衡之后时，必须填入代理地址。
	TrustedProxies []string `mapstructure:"trusted_proxies"`
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

	// RateLimit 扫描限速：对被测站点做速率约束（安全合规要求，也避免被目标 WAF 封禁）
	RateLimit ScannerRateLimit `mapstructure:"rate_limit"`
}

// ScannerRateLimit 爬取阶段的速率约束。
type ScannerRateLimit struct {
	Enabled *bool `mapstructure:"enabled"` // 默认 true

	// RequestsPerSec 全局限速：整轮扫描每秒最多发出的请求数（默认 5）。
	RequestsPerSec float64 `mapstructure:"requests_per_sec"`

	// Burst 瞬时突发容量。留 0 则自动取 RequestsPerSec 向上取整。
	Burst int `mapstructure:"burst"`

	// MinGapMs 对同一主机两次请求之间的最小间隔（毫秒，默认 200），
	// 用于把请求摊开、避免形成突发流。
	MinGapMs int `mapstructure:"min_gap_ms"`
}

// RateLimitEnabled 返回扫描限速开关（未显式配置时默认开启）。
func (s *ScannerConfig) RateLimitEnabled() bool {
	return s.RateLimit.Enabled == nil || *s.RateLimit.Enabled
}

// RateLimitOrDefaults 返回补齐默认值后的限速参数（5 req/s、同主机间隔 200ms）。
func (s *ScannerConfig) RateLimitOrDefaults() (rps float64, burst int, minGap time.Duration) {
	rps = s.RateLimit.RequestsPerSec
	if rps <= 0 {
		rps = 5
	}
	burst = s.RateLimit.Burst
	minGap = time.Duration(s.RateLimit.MinGapMs) * time.Millisecond
	if minGap < 0 {
		minGap = 0
	}
	return
}

type SchedulerConfig struct {
	Enabled                bool `mapstructure:"enabled"`
	MaxConcurrentScans     int  `mapstructure:"max_concurrent_scans"`
	InspectionTimeoutSec   int  `mapstructure:"inspection_timeout_sec"`    // 单次巡检总超时（含扫描+AI），默认 1800
	DefaultRetryCount      int  `mapstructure:"default_retry_count"`       // AI 调用失败默认重试次数
	DefaultRetryBackoffSec int  `mapstructure:"default_retry_backoff_sec"` // 重试退避秒数
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

	// 登录失败限速：防止对 /api/auth/login 的无限次口令爆破。
	RateLimit RateLimitConfig `mapstructure:"rate_limit"`
}

// RateLimitConfig 登录接口失败限速配置。
// 采用「IP」与「IP+账号」双维度计数：前者挡住单机爆破，
// 后者挡住换 IP 轮询同一个账号的分布式爆破（且不会因单账号被锁而波及其他用户）。
type RateLimitConfig struct {
	Enabled     *bool `mapstructure:"enabled"`      // 默认 true
	MaxFailures int   `mapstructure:"max_failures"` // 窗口内允许的失败次数，默认 5
	WindowSec   int   `mapstructure:"window_sec"`   // 统计窗口（秒），默认 300
	LockSec     int   `mapstructure:"lock_sec"`     // 触发后锁定时长（秒），默认 900
}

// MinJWTSecretLen 是 JWT 签名密钥的最小长度要求。
// HS256 的密钥强度直接决定令牌能否被离线爆破，64 位熵是底线。
const MinJWTSecretLen = 32

// EnsureJWTSecret 校验 JWT 签名密钥强度，必要时生成一个随机密钥。
//
// 背景（安全）：配置里缺失 auth.jwt_secret 时该字段为空字符串，而 HS256 允许空密钥——
// 意味着任何人拿到源码就能自签一个 role=admin 的令牌直接登入后台。
// 这里做两层保护：
//  1. 完全未配置（空串，或仍是 "${VAR}" 占位符没被环境变量替换）→ 生成 48 字节随机密钥。
//     服务照常启动（不因漏配置而阻塞部署），但重启后旧令牌失效，同时打印醒目警告。
//  2. 显式配置了但长度不足 → 返回错误拒绝启动。"以为自己配了"的弱密钥比没配更危险。
func (a *AuthConfig) EnsureJWTSecret() error {
	s := strings.TrimSpace(a.JwtSecret)
	if s == "" || (strings.HasPrefix(s, "${") && strings.HasSuffix(s, "}")) {
		buf := make([]byte, 48)
		if _, err := rand.Read(buf); err != nil {
			return fmt.Errorf("生成随机 JWT 签名密钥失败: %w", err)
		}
		a.JwtSecret = base64.RawURLEncoding.EncodeToString(buf)
		log.Printf("[Auth] ⚠️  未配置 auth.jwt_secret（或环境变量 JWT_SECRET 未注入），" +
			"已临时生成随机签名密钥。进程重启后所有登录态将失效——" +
			"请显式配置 JWT_SECRET（>= 32 字符）以保持会话稳定。")
		return nil
	}
	if len(s) < MinJWTSecretLen {
		return fmt.Errorf("auth.jwt_secret 过短（当前 %d 字符，要求 >= %d 字符）："+
			"HS256 弱密钥可被离线爆破并用于伪造管理员令牌，请改用随机生成的密钥", len(s), MinJWTSecretLen)
	}
	return nil
}

// RateLimitEnabled 返回限速开关（未显式配置时默认开启）。
func (a *AuthConfig) RateLimitEnabled() bool {
	return a.RateLimit.Enabled == nil || *a.RateLimit.Enabled
}

// RateLimitOrDefaults 返回补齐默认值后的限速参数。
func (a *AuthConfig) RateLimitOrDefaults() (maxFailures int, window, lock time.Duration) {
	maxFailures, window, lock = a.RateLimit.MaxFailures, time.Duration(a.RateLimit.WindowSec)*time.Second, time.Duration(a.RateLimit.LockSec)*time.Second
	if maxFailures <= 0 {
		maxFailures = 5
	}
	if window <= 0 {
		window = 5 * time.Minute
	}
	if lock <= 0 {
		lock = 15 * time.Minute
	}
	return
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
		// 跨平台搜索顺序：
		//   1) 当前工作目录（开发态，Windows/Linux 通用）
		//   2) ./config 子目录（仓库约定）
		//   3) ./configs 子目录（部分发行版/团队习惯）
		//   4) 可执行文件同级目录（服务化部署、工作目录不确定的场景）
		//   5) /etc/security-agent（Linux 系统级配置约定；Windows 上该路径不存在，
		//      viper 会安全跳过，不影响 Windows 行为）
		//   6) $HOME/.security-agent（免 root 部署；Windows 上解析为用户目录，同样安全）
		v.AddConfigPath(".")
		v.AddConfigPath("./config")
		v.AddConfigPath("./configs")
		if exe, err := os.Executable(); err == nil {
			v.AddConfigPath(filepath.Dir(exe))
		}
		v.AddConfigPath("/etc/security-agent")
		if home, err := os.UserHomeDir(); err == nil {
			v.AddConfigPath(filepath.Join(home, ".security-agent"))
		}
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
