package weakpass

import (
	"context"
	"time"
)

// checkFTP 尝试 FTP 密码登录。target 形如 host 或 host:port（默认 21）。
func checkFTP(ctx context.Context, target, user, pass string, timeout time.Duration) (bool, error) {
	addr := normalizeTarget(target, "ftp")
	return withTimeout(ctx, timeout, func() (bool, error) {
		conn, err := dial(ctx, addr, timeout)
		if err != nil {
			return false, err
		}
		defer conn.Close()

		// 欢迎语
		if _, err := readLine(conn, timeout); err != nil {
			return false, err
		}
		// USER
		if err := writeLine(conn, "USER "+user); err != nil {
			return false, err
		}
		line, err := readLine(conn, timeout)
		if err != nil {
			return false, err
		}
		switch code3(line) {
		case "230": // 无需密码即登录（匿名或空密码）
			return true, nil
		case "331": // 需要密码
			// 继续
		default: // 530 等：认证失败
			return false, nil
		}
		// PASS
		if err := writeLine(conn, "PASS "+pass); err != nil {
			return false, err
		}
		line, err = readLine(conn, timeout)
		if err != nil {
			return false, err
		}
		return code3(line) == "230", nil
	})
}
