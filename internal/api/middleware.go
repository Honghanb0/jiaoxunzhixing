package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"security-agent/internal/models"
)

// 上下文键，用于在中间件与 handler 之间传递已认证用户。
const (
	ctxUserID      = "userID"
	ctxUsername    = "username"
	ctxUserRole    = "userRole"
	ctxUserRoleLvl = "userRoleLevel"
)

// Claims 是 JWT 载荷。
type Claims struct {
	UserID    string `json:"uid"`
	Username  string `json:"username"`
	Role      string `json:"role"`
	RoleLevel int    `json:"rl"` // 权限级别 0-3，用于 RequireRoleLevel 精确判定
	jwt.RegisteredClaims
}

// GenerateToken 为指定用户签发 HS256 JWT。
func GenerateToken(secret string, user *models.User, expireHours int) (string, error) {
	if expireHours <= 0 {
		expireHours = 24
	}
	now := time.Now()
	claims := Claims{
		UserID:    user.ID,
		Username:  user.Username,
		Role:      user.Role,
		RoleLevel: user.RoleLevel,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Duration(expireHours) * time.Hour)),
			Subject:   user.ID,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

// ParseToken 校验并解析 JWT，返回 Claims。
func ParseToken(secret, tokenString string) (*Claims, error) {
	claims := &Claims{}
	_, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return []byte(secret), nil
	})
	if err != nil {
		return nil, err
	}
	return claims, nil
}

// AuthMiddleware 校验 Authorization: Bearer <token>，并将用户信息注入上下文。
func AuthMiddleware(secret string) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "未提供认证令牌"})
			c.Abort()
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "认证头格式错误，应为 Bearer <token>"})
			c.Abort()
			return
		}

		claims, err := ParseToken(secret, parts[1])
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "令牌无效或已过期"})
			c.Abort()
			return
		}

		c.Set(ctxUserID, claims.UserID)
		c.Set(ctxUsername, claims.Username)
		c.Set(ctxUserRole, claims.Role)
		c.Set(ctxUserRoleLvl, claims.RoleLevel)
		c.Next()
	}
}

// RequireRole 限制仅指定角色可访问（必须在 AuthMiddleware 之后使用）。
func RequireRole(roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		role, ok := c.Get(ctxUserRole)
		if !ok {
			c.JSON(http.StatusForbidden, gin.H{"error": "无访问权限"})
			c.Abort()
			return
		}
		cur, _ := role.(string)
		for _, r := range roles {
			if r == cur {
				c.Next()
				return
			}
		}
		c.JSON(http.StatusForbidden, gin.H{"error": "权限不足，需要角色: " + strings.Join(roles, "/")})
		c.Abort()
	}
}

// CurrentUserID 从上下文取当前用户 ID。
func CurrentUserID(c *gin.Context) string {
	if v, ok := c.Get(ctxUserID); ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// CurrentUsername 从上下文取当前用户名。
func CurrentUsername(c *gin.Context) string {
	if v, ok := c.Get(ctxUsername); ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// RequireRoleLevel 限制仅指定权限级别或以上可访问（必须在 AuthMiddleware 之后使用）。
func RequireRoleLevel(minLevel int) gin.HandlerFunc {
	return func(c *gin.Context) {
		roleLevel := GetRoleLevelFromContext(c)
		if roleLevel < minLevel {
			c.JSON(http.StatusForbidden, gin.H{"error": "权限不足"})
			c.Abort()
			return
		}
		c.Next()
	}
}
