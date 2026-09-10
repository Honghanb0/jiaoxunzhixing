package weakpass

import (
	"context"
	"strings"
	"time"
)

// checkRedis 尝试 Redis AUTH 验证。target 形如 host 或 host:port（默认 6379）。
// 若实例未设密码（PING 直接返回 +PONG），且传入口令为空，则视为弱口令（空口令）。
func checkRedis(ctx context.Context, target, user, pass string, timeout time.Duration) (bool, error) {
	addr := normalizeTarget(target, "redis")
	return withTimeout(ctx, timeout, func() (bool, error) {
		conn, err := dial(ctx, addr, timeout)
		if err != nil {
			return false, err
		}
		defer conn.Close()

		// 先探测是否需要密码
		if err := writeLine(conn, "PING"); err != nil {
			return false, err
		}
		line, err := readLine(conn, timeout)
		if err != nil {
			return false, err
		}
		switch {
		case strings.HasPrefix(line, "+PONG"):
			// 无需密码：传入空口令即视为命中（空口令弱点是 Redis 最常见风险）
			return pass == "", nil
		case strings.Contains(line, "NOAUTH"):
			// 需要密码
		default:
			return false, nil
		}
		if pass == "" {
			return false, nil
		}
		if err := writeLine(conn, "AUTH "+pass); err != nil {
			return false, err
		}
		line, err = readLine(conn, timeout)
		if err != nil {
			return false, err
		}
		return strings.HasPrefix(line, "+OK"), nil
	})
}
