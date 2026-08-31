package ai

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ProviderOptions 构造供应商所需的全部参数（与配置层解耦，便于测试与复用）
type ProviderOptions struct {
	Enabled      bool
	APIKey       string
	Model        string
	BaseURL      string
	TimeoutSec   int
	MaxRetries   int
	RetryBackoff time.Duration
}

// NewProvider 按名称创建供应商适配器。
// name 为 deepseek / kimi / glm，未知名称返回 ErrProviderNotFound。
func NewProvider(name string, opts ProviderOptions) (Provider, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case ProviderDeepSeek:
		return NewDeepSeek(opts), nil
	case ProviderKimi:
		return NewKimi(opts), nil
	case ProviderGLM:
		return NewGLM(opts), nil
	default:
		return nil, fmt.Errorf("%w: %s", ErrProviderNotFound, name)
	}
}

// NewDeepSeek DeepSeek：OpenAI 兼容，静态 Bearer Key
func NewDeepSeek(opts ProviderOptions) Provider {
	meta := defaultProviderMeta[ProviderDeepSeek]
	key := resolveKey(opts.APIKey, meta.EnvKeys)
	return newCompatProvider(compatSpec{
		name:         ProviderDeepSeek,
		displayName:  meta.DisplayName,
		authMode:     meta.AuthMode,
		model:        pick(opts.Model, meta.Model),
		baseURL:      pick(opts.BaseURL, meta.BaseURL),
		enabled:      opts.Enabled,
		timeout:      time.Duration(orInt(opts.TimeoutSec, 60)) * time.Second,
		maxRetries:   opts.MaxRetries,
		retryBackoff: opts.RetryBackoff,
		token:        staticToken(key),
	})
}

// NewKimi Kimi(Moonshot AI)：OpenAI 兼容，静态 Bearer Key
func NewKimi(opts ProviderOptions) Provider {
	meta := defaultProviderMeta[ProviderKimi]
	key := resolveKey(opts.APIKey, meta.EnvKeys)
	return newCompatProvider(compatSpec{
		name:         ProviderKimi,
		displayName:  meta.DisplayName,
		authMode:     meta.AuthMode,
		model:        pick(opts.Model, meta.Model),
		baseURL:      pick(opts.BaseURL, meta.BaseURL),
		enabled:      opts.Enabled,
		timeout:      time.Duration(orInt(opts.TimeoutSec, 60)) * time.Second,
		maxRetries:   opts.MaxRetries,
		retryBackoff: opts.RetryBackoff,
		token:        staticToken(key),
	})
}

// NewGLM GLM(智谱 AI)：OpenAI 兼容协议，但鉴权需由 API Key 签发 JWT。
// 官方 Key 形如 "{id}.{secret}"：
//   - header: {"alg":"HS256","sign_type":"SIGN"}
//   - claims: {"api_key": id, "exp": <毫秒时间戳>, "timestamp": <毫秒时间戳>}
//   - HMAC-SHA256 签名密钥为 secret
//
// 新版直传型 Key（不含 "."）则直接作为 Bearer 使用。
func NewGLM(opts ProviderOptions) Provider {
	meta := defaultProviderMeta[ProviderGLM]
	key := resolveKey(opts.APIKey, meta.EnvKeys)
	return newCompatProvider(compatSpec{
		name:         ProviderGLM,
		displayName:  meta.DisplayName,
		authMode:     meta.AuthMode,
		model:        pick(opts.Model, meta.Model),
		baseURL:      pick(opts.BaseURL, meta.BaseURL),
		enabled:      opts.Enabled,
		timeout:      time.Duration(orInt(opts.TimeoutSec, 60)) * time.Second,
		maxRetries:   opts.MaxRetries,
		retryBackoff: opts.RetryBackoff,
		token:        glmTokenFunc(key),
	})
}

// glmTokenFunc 生成带缓存的智谱鉴权令牌
func glmTokenFunc(apiKey string) func() (string, error) {
	cache := &tokenCache{}
	return func() (string, error) {
		if apiKey == "" {
			return "", fmt.Errorf("GLM API Key 未配置")
		}

		cache.mu.Lock()
		defer cache.mu.Unlock()

		if cache.token != "" && time.Now().Before(cache.until) {
			return cache.token, nil
		}

		// 不含 "." 视为新版直传 Key，无需签发 JWT
		if !strings.Contains(apiKey, ".") {
			cache.token = apiKey
			cache.until = time.Now().Add(time.Hour)
			return cache.token, nil
		}

		parts := strings.SplitN(apiKey, ".", 2)
		id, secret := parts[0], parts[1]
		if id == "" || secret == "" {
			return "", fmt.Errorf("GLM API Key 格式非法，期望 {id}.{secret}")
		}

		now := time.Now()
		claims := jwt.MapClaims{
			"api_key":   id,
			"exp":       now.Add(3 * time.Minute).UnixMilli(),
			"timestamp": now.UnixMilli(),
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tok.Header["sign_type"] = "SIGN"

		signed, err := tok.SignedString([]byte(secret))
		if err != nil {
			return "", fmt.Errorf("GLM 签发鉴权令牌失败: %w", err)
		}

		cache.token = signed
		// 提前 30s 过期，留出时钟误差余量
		cache.until = now.Add(3*time.Minute - 30*time.Second)
		return cache.token, nil
	}
}

// resolveKey 若配置中的 Key 为空或仍是未解析的 ${ENV} 占位符，则回退到环境变量
func resolveKey(configured string, envKeys []string) string {
	if configured != "" && !isPlaceholder(configured) {
		return configured
	}
	for _, k := range envKeys {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
	}
	// 仍是占位符说明环境变量没注入，返回空表示未配置
	return ""
}

// isPlaceholder 判断是否形如 ${VAR} / ${VAR:-default} 的未解析占位符
func isPlaceholder(s string) bool {
	return strings.HasPrefix(s, "${") && strings.HasSuffix(s, "}")
}

func pick(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

func orInt(v, fallback int) int {
	if v <= 0 {
		return fallback
	}
	return v
}
