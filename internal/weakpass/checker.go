package weakpass

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// Checker 尝试用给定凭据登录目标服务。
// 返回值语义：authed=true 表示凭据有效；err 仅在网络/协议层失败时返回，
// 以便上层把「认证失败（凭据无效）」与「连接错误」区分开。
type Checker func(ctx context.Context, target, user, pass string, timeout time.Duration) (authed bool, err error)

var (
	checkerMu sync.RWMutex
	checkers  = map[string]Checker{}
)

// RegisterChecker 注册某服务类型的校验器（供测试或扩展协议使用）。
func RegisterChecker(service string, c Checker) {
	checkerMu.Lock()
	defer checkerMu.Unlock()
	checkers[service] = c
}

// SupportedServices 返回当前已注册的服务类型（小写，无序副本）。
func SupportedServices() []string {
	checkerMu.RLock()
	defer checkerMu.RUnlock()
	out := make([]string, 0, len(checkers))
	for k := range checkers {
		out = append(out, k)
	}
	return out
}

// Check 校验单个凭据。service 未注册时返回错误。
func Check(ctx context.Context, service, target, user, pass string, timeout time.Duration) (bool, error) {
	checkerMu.RLock()
	c, ok := checkers[service]
	checkerMu.RUnlock()
	if !ok {
		return false, fmt.Errorf("不支持的服务类型 %q（支持: %s）", service, strings.Join(SupportedServices(), "/"))
	}
	return c(ctx, target, user, pass, timeout)
}

func init() {
	RegisterChecker("ssh", checkSSH)
	RegisterChecker("ftp", checkFTP)
	RegisterChecker("pop3", checkPOP3)
	RegisterChecker("smtp", checkSMTP)
	RegisterChecker("redis", checkRedis)
	RegisterChecker("http", checkHTTPBasic)
}

// defaultPort 返回各服务的默认端口（target 未显式带端口时使用）。
func defaultPort(service string) string {
	switch strings.ToLower(service) {
	case "ssh":
		return "22"
	case "ftp":
		return "21"
	case "pop3":
		return "110"
	case "smtp":
		return "25"
	case "redis":
		return "6379"
	case "http":
		return "80"
	case "https":
		return "443"
	default:
		return "0"
	}
}

// normalizeTarget 把 host 或 host:port 归一化为 host:port（缺端口时按服务补默认）。
func normalizeTarget(target, service string) string {
	if strings.Contains(target, ":") {
		return target
	}
	return net.JoinHostPort(target, defaultPort(service))
}

// dial 在 ctx/超时约束下建立 TCP 连接，并设置读写截止时间。
func dial(ctx context.Context, addr string, timeout time.Duration) (net.Conn, error) {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	return conn, nil
}

// readLine 读取一行（至 \n），剥离结尾 \r\n。
func readLine(conn net.Conn, timeout time.Duration) (string, error) {
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	r := bufio.NewReader(conn)
	line, err := r.ReadString('\n')
	return strings.TrimRight(line, "\r\n"), err
}

// writeLine 发送一行（追加 \r\n）。
func writeLine(conn net.Conn, s string) error {
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err := conn.Write([]byte(s + "\r\n"))
	return err
}

// code3 取 SMTP/POP3/FTP 回复行的三位状态码（如 "230"、"535"）。
func code3(line string) string {
	if len(line) >= 3 && line[0] >= '0' && line[0] <= '9' {
		return line[:3]
	}
	return ""
}

// withTimeout 在独立 goroutine 中执行 fn，受 ctx 与 timeout 双重约束。
func withTimeout(ctx context.Context, timeout time.Duration, fn func() (bool, error)) (bool, error) {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	c, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	type res struct {
		authed bool
		err    error
	}
	done := make(chan res, 1)
	go func() {
		a, e := fn()
		done <- res{a, e}
	}()
	select {
	case <-c.Done():
		return false, fmt.Errorf("校验超时(%v)", timeout)
	case r := <-done:
		return r.authed, r.err
	}
}
