package weakpass

import (
	"context"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// checkSSH 用密码方式尝试 SSH 登录。target 形如 host 或 host:port。
func checkSSH(ctx context.Context, target, user, pass string, timeout time.Duration) (bool, error) {
	addr := normalizeTarget(target, "ssh")
	return withTimeout(ctx, timeout, func() (bool, error) {
		config := &ssh.ClientConfig{
			User:            user,
			Auth:            []ssh.AuthMethod{ssh.Password(pass)},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         timeout,
		}
		client, err := ssh.Dial("tcp", addr, config)
		if err != nil {
			// 区分「认证失败」与「连接/握手错误」：认证失败视为凭据无效（非错误）。
			if isAuthFailure(err) {
				return false, nil
			}
			return false, err
		}
		defer client.Close()
		return true, nil
	})
}

// isAuthFailure 判断 ssh 错误是否为凭据认证失败（而非网络/主机不可达）。
func isAuthFailure(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, kw := range []string{
		"unable to authenticate",
		"authentication",
		"password auth",
		"no supported methods",
		"permission denied",
	} {
		if strings.Contains(msg, kw) {
			return true
		}
	}
	return false
}
