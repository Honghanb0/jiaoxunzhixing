package weakpass

import (
	"context"
	"encoding/base64"
	"net/http"
	"strings"
	"time"
)

// checkHTTPBasic 尝试 HTTP Basic Auth 验证（适用于带基本认证的后台/管理端点）。
// target 可为 host、host:port 或完整 URL；缺省补 http:// 与默认端口 80。
//
// 判定规则（修复「静态 http 靶场误报大量命中」的 bug）：
//   - 先做无凭据的「基线探测」。若端点根本不要求认证（返回 2xx/3xx 而非 401/403），
//     则任何凭据都不会改变响应——单纯服务可达 ≠ 弱口令。此时直接判为非命中，
//     避免把开放页面的 HTTP 200 误判为认证成功、进而把整本字典全部报成弱密码漏洞。
//   - 仅当基线返回 401/403 且带 `WWW-Authenticate: Basic` 挑战时，才说明该端点强制 Basic Auth；
//     此时用待验凭据再请求，返回 2xx/3xx 才视为「凭据确实有效」，即弱口令命中。
func checkHTTPBasic(ctx context.Context, target, user, pass string, timeout time.Duration) (bool, error) {
	url := target
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "http://" + target
	}

	// 1) 基线探测：不带 Authorization，确认端点是否真的在强制 Basic Auth。
	baseline, err := doHTTPRequest(ctx, url, "", timeout)
	if err != nil {
		// 连接/协议层失败：交给上层按错误处理，不误判为命中。
		return false, err
	}
	defer baseline.Body.Close()

	// 端点不要求认证（开放可达）：凭据无意义，非弱口令。
	if !isBasicAuthChallenge(baseline) {
		return false, nil
	}

	// 2) 端点强制 Basic Auth：用待验凭据请求，成功状态码才认定为认证通过。
	cred, err := doHTTPRequest(ctx, url, basicAuth(user, pass), timeout)
	if err != nil {
		return false, err
	}
	defer cred.Body.Close()

	if cred.StatusCode >= 200 && cred.StatusCode < 400 {
		return true, nil
	}
	return false, nil
}

// doHTTPRequest 发送一次 GET 请求；auth 为空表示不带 Authorization 头。
// 不自动跟随重定向（ErrUseLastResponse），以便按最终状态码判断认证结果。
func doHTTPRequest(ctx context.Context, url, auth string, timeout time.Duration) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if auth != "" {
		req.Header.Set("Authorization", "Basic "+auth)
	}

	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// isBasicAuthChallenge 判断「无凭据响应」是否表示服务端在强制 HTTP Basic Auth。
// 必须是 401/403 且带有 WWW-Authenticate: Basic 挑战；否则视为开放端点或其他鉴权方式，
// 不应由本校验器判为弱口令命中。
func isBasicAuthChallenge(resp *http.Response) bool {
	if resp == nil {
		return false
	}
	if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden {
		return false
	}
	for _, h := range resp.Header.Values("WWW-Authenticate") {
		if strings.Contains(strings.ToLower(h), "basic") {
			return true
		}
	}
	return false
}

func basicAuth(user, pass string) string {
	return base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
}
