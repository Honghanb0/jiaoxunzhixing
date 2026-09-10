package weakpass

import (
	"context"
	"encoding/base64"
	"strings"
	"time"
)

// checkSMTP 尝试 SMTP AUTH LOGIN 密码登录。target 形如 host 或 host:port（默认 25）。
func checkSMTP(ctx context.Context, target, user, pass string, timeout time.Duration) (bool, error) {
	addr := normalizeTarget(target, "smtp")
	return withTimeout(ctx, timeout, func() (bool, error) {
		conn, err := dial(ctx, addr, timeout)
		if err != nil {
			return false, err
		}
		defer conn.Close()

		if _, err := readLine(conn, timeout); err != nil { // 220 欢迎
			return false, err
		}
		if err := writeLine(conn, "EHLO localhost"); err != nil {
			return false, err
		}
		// 读取 EHLO 多行回复，确认服务器支持 AUTH
		supportsAuth := false
		for {
			line, err := readLine(conn, timeout)
			if err != nil {
				return false, err
			}
			if strings.Contains(strings.ToUpper(line), "AUTH") {
				supportsAuth = true
			}
			// 末行状态码后跟空格（非 '-'）表示结束
			if len(line) >= 4 && line[3] == ' ' {
				break
			}
			if !strings.HasPrefix(line, "250") {
				break
			}
		}
		if !supportsAuth {
			// 服务器不支持 AUTH，无法用本方法判定，按连接错误上报由上层处理
			return false, errSMTPNoAuth
		}

		if err := writeLine(conn, "AUTH LOGIN"); err != nil {
			return false, err
		}
		line, err := readLine(conn, timeout)
		if err != nil {
			return false, err
		}
		if code3(line) != "334" { // 期望 base64 用户名挑战
			return false, nil
		}
		if err := writeLine(conn, base64.StdEncoding.EncodeToString([]byte(user))); err != nil {
			return false, err
		}
		line, err = readLine(conn, timeout)
		if err != nil {
			return false, err
		}
		if code3(line) != "334" { // 期望 base64 密码挑战
			return false, nil
		}
		if err := writeLine(conn, base64.StdEncoding.EncodeToString([]byte(pass))); err != nil {
			return false, err
		}
		line, err = readLine(conn, timeout)
		if err != nil {
			return false, err
		}
		return code3(line) == "235", nil
	})
}

// errSMTPNoAuth 标记服务器不支持 SMTP AUTH。
var errSMTPNoAuth = errSMTPNoAuthType("服务器不支持 AUTH，无法用密码方式验证")

type errSMTPNoAuthType string

func (e errSMTPNoAuthType) Error() string { return string(e) }
