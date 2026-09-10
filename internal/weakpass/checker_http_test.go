package weakpass

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// 开放端点：任何请求都返回 200，且不带 WWW-Authenticate 挑战。
// 修复前会把这种「可达」误判为认证成功 → 整本字典全部命中。
func TestCheckHTTPBasic_OpenEndpoint_NoFalsePositive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	host := srv.Listener.Addr().String() // host:port
	for _, cred := range [][2]string{{"admin", "123456"}, {"root", "toor"}, {"", ""}} {
		authed, err := Check(context.Background(), "http", host, cred[0], cred[1], 5*time.Second)
		if err != nil {
			t.Fatalf("open endpoint 不应返回错误: %v", err)
		}
		if authed {
			t.Fatalf("开放端点被误判为弱口令命中 (user=%q pass=%q)，这是要修复的误报", cred[0], cred[1])
		}
	}
}

// 强制 Basic Auth 的端点：无凭据返回 401+WWW-Authenticate: Basic；
// 仅正确凭据（admin/secret）返回 200，错误凭据返回 401。
func TestCheckHTTPBasic_RealChallenge(t *testing.T) {
	const validUser, validPass = "admin", "secret"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != validUser || p != validPass {
			w.Header().Set("WWW-Authenticate", `Basic realm="restricted"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	host := srv.Listener.Addr().String()

	// 正确凭据 → 命中
	if authed, err := Check(context.Background(), "http", host, validUser, validPass, 5*time.Second); err != nil || !authed {
		t.Fatalf("正确凭据应命中，got authed=%v err=%v", authed, err)
	}
	// 错误凭据 → 不命中
	if authed, err := Check(context.Background(), "http", host, validUser, "wrong", 5*time.Second); err != nil || authed {
		t.Fatalf("错误凭据不应命中，got authed=%v err=%v", authed, err)
	}
}

// 端点返回 403 但无 Basic 挑战（如 IP 封禁/其他鉴权）：不应误判为命中，也不应误判为挑战。
func TestCheckHTTPBasic_ForbiddenWithoutBasicChallenge(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden) // 无 WWW-Authenticate
	}))
	defer srv.Close()
	host := srv.Listener.Addr().String()

	if authed, err := Check(context.Background(), "http", host, "admin", "123456", 5*time.Second); err != nil || authed {
		t.Fatalf("非 Basic 挑战的 403 不应命中，got authed=%v err=%v", authed, err)
	}
}
