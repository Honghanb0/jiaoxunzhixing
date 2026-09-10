package weakpass

import (
	"context"
	"testing"
	"time"
)

// 测试用假校验器：口令等于 "open" 或 "letmein" 时认证成功。
func init() {
	RegisterChecker("faketest", func(ctx context.Context, target, user, pass string, timeout time.Duration) (bool, error) {
		return pass == "open" || pass == "letmein", nil
	})
}

func TestDictManager(t *testing.T) {
	m := NewDictManager()
	list := m.List()
	if list["users"] == 0 || list["passwords"] == 0 {
		t.Fatalf("内置字典不应为空: %v", list)
	}
	// add 去重
	n := m.Add("passwords", []string{"open", "open", "newpw"})
	if n != 2 {
		t.Fatalf("Add 去重后应为 2，实际 %d", n)
	}
	// reset
	if !m.Reset("passwords") {
		t.Fatalf("reset 内置字典应返回 true")
	}
	if len(m.Get("passwords")) != list["passwords"] {
		t.Fatalf("reset 后词条数应恢复为内置值")
	}
}

func TestScanBasic(t *testing.T) {
	ctx := context.Background()
	res, err := Scan(ctx, ScanOptions{
		Target:      "127.0.0.1:9",
		Service:     "faketest",
		Users:       []string{"admin", "root"},
		Passwords:   []string{"open", "closed", "letmein"},
		Concurrency: 4,
		Timeout:     2 * time.Second,
		Verify:      true,
	})
	if err != nil {
		t.Fatalf("Scan 失败: %v", err)
	}
	if res.Attempts != 6 {
		t.Fatalf("尝试数应为 6，实际 %d", res.Attempts)
	}
	// admin/open, admin/letmein, root/open, root/letmein 共 4 个命中
	if len(res.Found) != 4 {
		t.Fatalf("命中数应为 4，实际 %d (%+v)", len(res.Found), res.Found)
	}
}

func TestScanStopOnFirst(t *testing.T) {
	ctx := context.Background()
	res, err := Scan(ctx, ScanOptions{
		Target:      "127.0.0.1:9",
		Service:     "faketest",
		Users:       []string{"admin", "root"},
		Passwords:   []string{"open", "closed"},
		Concurrency: 1,
		Timeout:     2 * time.Second,
		StopOnFirst: true,
		Verify:      true,
	})
	if err != nil {
		t.Fatalf("Scan 失败: %v", err)
	}
	if !res.StoppedOnFirst {
		t.Fatalf("应触发 stopped_on_first")
	}
	if len(res.Found) != 1 {
		t.Fatalf("stop_on_first 应仅 1 个命中，实际 %d", len(res.Found))
	}
}

func TestScanMaxAttempts(t *testing.T) {
	ctx := context.Background()
	users := make([]string, 200)
	passes := make([]string, 200)
	for i := range users {
		users[i] = "u"
		passes[i] = "p"
	}
	_, err := Scan(ctx, ScanOptions{Target: "x", Service: "faketest", Users: users, Passwords: passes})
	if err == nil {
		t.Fatalf("超过 MaxAttempts 应报错")
	}
}

func TestCheckUnsupported(t *testing.T) {
	_, err := Check(context.Background(), "nonexistent", "h", "u", "p", time.Second)
	if err == nil {
		t.Fatalf("不支持的服务应返回错误")
	}
}
