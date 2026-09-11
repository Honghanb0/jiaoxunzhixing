package api

import (
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// loginLimiter 登录接口失败限速器（内存实现，单实例部署够用）。
//
// 设计要点：
//   - 双维度计数：key1 = "ip:<客户端IP>"，key2 = "user:<IP>|<账号>"。
//     前者挡单机爆破；后者挡"换 IP 轮询同一账号"的分布式爆破。
//     刻意不做「纯账号」维度，否则攻击者可以随便输错密码把正常用户锁死（拒绝服务）。
//   - 窗口内失败次数达到阈值 → 锁定 lockFor，期间直接拒绝，不再校验口令（也省掉 bcrypt 开销）。
//   - 登录成功清零，避免正常用户被历史失败拖累。
//   - 惰性清理：过期条目在访问时顺带删除，条目数超过阈值时触发一次全表清扫，避免内存无界增长。
type loginLimiter struct {
	mu       sync.Mutex
	entries  map[string]*failureEntry
	maxFails int
	window   time.Duration
	lockFor  time.Duration
}

type failureEntry struct {
	count int       // 窗口内失败次数
	first time.Time // 窗口起点
	until time.Time // 非零 = 锁定截止时间
}

// newLoginLimiter 创建限速器。参数非法时回落到安全默认值。
func newLoginLimiter(maxFails int, window, lockFor time.Duration) *loginLimiter {
	if maxFails <= 0 {
		maxFails = 5
	}
	if window <= 0 {
		window = 5 * time.Minute
	}
	if lockFor <= 0 {
		lockFor = 15 * time.Minute
	}
	return &loginLimiter{
		entries:  make(map[string]*failureEntry),
		maxFails: maxFails,
		window:   window,
		lockFor:  lockFor,
	}
}

// blocked 返回是否处于锁定期，以及还需等待多久。
func (l *loginLimiter) blocked(key string) (bool, time.Duration) {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	e, ok := l.entries[key]
	if !ok {
		return false, 0
	}
	if !e.until.IsZero() && now.Before(e.until) {
		return true, e.until.Sub(now)
	}
	// 锁定已过期 / 窗口已滑出 → 视为未锁定，顺带清掉过期条目
	if (!e.until.IsZero() && !now.Before(e.until)) || now.Sub(e.first) > l.window {
		delete(l.entries, key)
	}
	return false, 0
}

// fail 记录一次失败；达到阈值则进入锁定期。
func (l *loginLimiter) fail(key string) {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	if len(l.entries) > 10000 { // 防内存无界增长
		l.sweepLocked(now)
	}

	e, ok := l.entries[key]
	if !ok || now.Sub(e.first) > l.window {
		l.entries[key] = &failureEntry{count: 1, first: now}
		return
	}
	e.count++
	if e.count >= l.maxFails {
		e.until = now.Add(l.lockFor)
	}
}

// reset 登录成功后清除该 key 的失败记录。
func (l *loginLimiter) reset(key string) {
	l.mu.Lock()
	delete(l.entries, key)
	l.mu.Unlock()
}

// sweepLocked 清理所有已过期条目。调用方必须已持锁。
func (l *loginLimiter) sweepLocked(now time.Time) {
	for k, e := range l.entries {
		locked := !e.until.IsZero() && now.Before(e.until)
		stale := now.Sub(e.first) > l.window
		if !locked && stale {
			delete(l.entries, k)
		}
	}
}

// ---------- 与 gin 的对接 ----------

// loginLimitKeys 生成本次登录请求的限速键：客户端 IP 维度 + IP·账号 维度。
func loginLimitKeys(c *gin.Context, username string) (ipKey, userKey string) {
	ip := c.ClientIP()
	return "ip:" + ip, "user:" + ip + "|" + username
}

// checkLoginAllowed 在口令校验之前调用。若已锁定则直接写 429 并返回 false。
func (h *AuthHandler) checkLoginAllowed(c *gin.Context, username string) bool {
	if h.limiter == nil {
		return true
	}
	ipKey, userKey := loginLimitKeys(c, username)
	for _, k := range []string{ipKey, userKey} {
		if blocked, retry := h.limiter.blocked(k); blocked {
			secs := int(retry.Seconds()) + 1
			c.Header("Retry-After", strconv.Itoa(secs))
			c.JSON(429, gin.H{
				"error":       "登录失败次数过多，账号已临时锁定，请稍后再试",
				"retry_after": secs,
			})
			return false
		}
	}
	return true
}

// recordLoginFailure 口令错误时调用，累计失败次数。
func (h *AuthHandler) recordLoginFailure(c *gin.Context, username string) {
	if h.limiter == nil {
		return
	}
	ipKey, userKey := loginLimitKeys(c, username)
	h.limiter.fail(ipKey)
	h.limiter.fail(userKey)
}

// resetLoginFailures 登录成功后调用，清除失败计数。
func (h *AuthHandler) resetLoginFailures(c *gin.Context, username string) {
	if h.limiter == nil {
		return
	}
	ipKey, userKey := loginLimitKeys(c, username)
	h.limiter.reset(ipKey)
	h.limiter.reset(userKey)
}
