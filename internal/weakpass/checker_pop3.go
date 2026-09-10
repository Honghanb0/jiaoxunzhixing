package weakpass

import (
	"context"
	"time"
)

// checkPOP3 尝试 POP3 密码登录。target 形如 host 或 host:port（默认 110）。
func checkPOP3(ctx context.Context, target, user, pass string, timeout time.Duration) (bool, error) {
	addr := normalizeTarget(target, "pop3")
	return withTimeout(ctx, timeout, func() (bool, error) {
		conn, err := dial(ctx, addr, timeout)
		if err != nil {
			return false, err
		}
		defer conn.Close()

		if _, err := readLine(conn, timeout); err != nil { // +OK 欢迎
			return false, err
		}
		if err := writeLine(conn, "USER "+user); err != nil {
			return false, err
		}
		line, err := readLine(conn, timeout)
		if err != nil {
			return false, err
		}
		if len(line) < 1 || line[0] != '+' { // -ERR
			return false, nil
		}
		if err := writeLine(conn, "PASS "+pass); err != nil {
			return false, err
		}
		line, err = readLine(conn, timeout)
		if err != nil {
			return false, err
		}
		return len(line) >= 1 && line[0] == '+', nil
	})
}
