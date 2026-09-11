package api

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"security-agent/internal/config"
	"security-agent/internal/models"
	"security-agent/internal/storage"
)

type AuthHandler struct {
	userRepo *storage.UserRepository
	cfg      *config.AuthConfig
	limiter  *loginLimiter
}

func NewAuthHandler(userRepo *storage.UserRepository, cfg *config.AuthConfig) *AuthHandler {
	h := &AuthHandler{userRepo: userRepo, cfg: cfg}
	// 登录失败限速：默认开启（可在 config.yaml 的 auth.rate_limit.enabled 关闭）
	if cfg != nil && cfg.RateLimitEnabled() {
		maxFails, window, lockFor := cfg.RateLimitOrDefaults()
		h.limiter = newLoginLimiter(maxFails, window, lockFor)
	}
	return h
}

type RegisterRequest struct {
	Username string `json:"username" binding:"required,min=3,max=32"`
	Password string `json:"password" binding:"required,min=6,max=128"`
	Email    string `json:"email"`
	Role     string `json:"role"` // 仅管理员可指定；普通注册强制为 user
}

type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type UpdateRoleRequest struct {
	// 允许只传 role_level：本 handler 优先按 role_level 更新（见下方逻辑），
	// 此处若强制 required，会让「只改权限级别」的调用直接 400。
	Role      string `json:"role,omitempty"`
	RoleLevel int    `json:"role_level"`
}

// ChangePasswordRequest 改密码请求。
// 改自己时需要 current_password 校验；管理员改他人可不传（管理员覆盖）。
type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password" binding:"required,min=6,max=128"`
}

// Register 注册新用户。普通访客只能注册为 user 角色；
// 已登录的管理员可在请求体中指定 role 创建其它角色账号。
func (h *AuthHandler) Register(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	role := models.RoleUser
	// 仅当调用者为管理员且显式指定了合法角色时，才采用该角色。
	if req.Role != "" && req.Role != models.RoleUser {
		if CurrentUserID(c) != "" {
			if r, _ := c.Get(ctxUserRole); r == models.RoleAdmin {
				role = req.Role
			}
		}
	}

	exists, err := h.userRepo.ExistsByUsername(req.Username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "查询用户失败: " + err.Error()})
		return
	}
	if exists {
		c.JSON(http.StatusConflict, gin.H{"error": "用户名已存在"})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "密码加密失败"})
		return
	}

	user := &models.User{
		Username:     req.Username,
		PasswordHash: string(hash),
		Role:         role,
		Email:        req.Email,
	}
	if err := h.userRepo.Create(user); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "创建用户失败: " + err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "注册成功",
		"user":    sanitizeUser(user),
	})
}

// Login 校验凭据并签发 JWT。
// 失败限速在口令校验之前生效：锁定期内直接返回 429，既阻断爆破也避免 bcrypt 空转。
func (h *AuthHandler) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if !h.checkLoginAllowed(c, req.Username) {
		return
	}

	user, err := h.userRepo.GetByUsername(req.Username)
	if err != nil {
		// 用户不存在与口令错误返回同一文案，避免账号枚举；
		// 同样计入失败次数，防止用"探测用户名"绕过限速。
		h.recordLoginFailure(c, req.Username)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "用户名或密码错误"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		h.recordLoginFailure(c, req.Username)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "用户名或密码错误"})
		return
	}

	h.resetLoginFailures(c, req.Username)

	token, err := GenerateToken(h.cfg.JwtSecret, user, h.cfg.TokenExpireHours)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "签发令牌失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token": token,
		"user":  sanitizeUser(user),
	})
}

// Logout 当前为无状态实现：服务端不保留会话，由客户端丢弃令牌即可。
func (h *AuthHandler) Logout(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "已退出登录"})
}

// Me 返回当前登录用户信息。
func (h *AuthHandler) Me(c *gin.Context) {
	uid := CurrentUserID(c)
	if uid == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未认证"})
		return
	}
	user, err := h.userRepo.GetByID(uid)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "用户不存在"})
		return
	}
	c.JSON(http.StatusOK, sanitizeUser(user))
}

// ListUsers 仅管理员可查看用户列表。
func (h *AuthHandler) ListUsers(c *gin.Context) {
	users, err := h.userRepo.List()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	out := make([]*models.User, 0, len(users))
	for _, u := range users {
		out = append(out, sanitizeUser(u))
	}
	c.JSON(http.StatusOK, out)
}

// UpdateRole 仅管理员可修改用户角色。
func (h *AuthHandler) UpdateRole(c *gin.Context) {
	id := c.Param("id")
	var req UpdateRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Role != models.RoleAdmin && req.Role != models.RoleUser && req.Role != "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "角色只能是 admin 或 user"})
		return
	}

	user, err := h.userRepo.GetByID(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "用户不存在"})
		return
	}

	// 如果指定了 role_level，优先使用
	if req.RoleLevel >= 0 {
		if err := h.userRepo.UpdateRoleLevel(id, req.RoleLevel); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		user.RoleLevel = req.RoleLevel
	}

	// 如果指定了 role，同时更新 role 字段
	if req.Role != "" {
		if err := h.userRepo.UpdateRole(id, req.Role); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		user.Role = req.Role
		user.RoleLevel = models.GetRoleLevel(req.Role)
	}

	c.JSON(http.StatusOK, sanitizeUser(user))
}

// DeleteUser 仅管理员可删除用户。
func (h *AuthHandler) DeleteUser(c *gin.Context) {
	id := c.Param("id")

	// 不能删除自己
	currentUserID := CurrentUserID(c)
	if currentUserID == id {
		c.JSON(http.StatusBadRequest, gin.H{"error": "不能删除自己的账号"})
		return
	}

	user, err := h.userRepo.GetByID(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "用户不存在"})
		return
	}

	if err := h.userRepo.Delete(id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "删除用户失败: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "用户已删除", "user": sanitizeUser(user)})
}

// ChangePassword 修改用户密码。
//   - 改自己：需提供 current_password 且校验通过（任何已登录用户均可改自己）。
//   - 改他人：需管理员权限（role_level>=3），无需当前密码（管理员覆盖）。
func (h *AuthHandler) ChangePassword(c *gin.Context) {
	id := c.Param("id")

	var req ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	currentUserID := CurrentUserID(c)
	if currentUserID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未认证"})
		return
	}

	selfChange := currentUserID == id
	if !selfChange && GetRoleLevelFromContext(c) < models.RoleLevelAdmin {
		c.JSON(http.StatusForbidden, gin.H{"error": "仅管理员可修改其他用户密码"})
		return
	}

	user, err := h.userRepo.GetByID(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "用户不存在"})
		return
	}

	if selfChange {
		if req.CurrentPassword == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "修改自身密码需提供当前密码"})
			return
		}
		if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.CurrentPassword)); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "当前密码错误"})
			return
		}
	}

	if len(req.NewPassword) < 6 || len(req.NewPassword) > 128 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "新密码长度需为 6~128 位"})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "密码加密失败"})
		return
	}
	user.PasswordHash = string(hash)
	if err := h.userRepo.Update(user); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "更新密码失败: " + err.Error()})
		return
	}

	log.Printf("[Auth] 密码已更新 id=%s username=%s self=%v", id, user.Username, selfChange)
	c.JSON(http.StatusOK, gin.H{"message": "密码已更新", "user": sanitizeUser(user)})
}

// sanitizeUser 去除敏感字段后返回用户对象。
func sanitizeUser(u *models.User) *models.User {
	return &models.User{
		ID:        u.ID,
		Username:  u.Username,
		Role:      u.Role,
		RoleLevel: u.RoleLevel,
		Email:     u.Email,
		CreatedAt: u.CreatedAt,
		UpdatedAt: u.UpdatedAt,
	}
}
