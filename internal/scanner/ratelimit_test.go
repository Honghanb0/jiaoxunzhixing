package scanner

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestHostPacerMinGap 验证同一主机的两次请求之间会强制留出最小间隔。
// 令牌桶给足（rate/burst 很大），此时唯一生效的是 min_gap。
func TestHostPacerMinGap(t *testing.T) {
	const gap = 120 * time.Millisecond
	p := newHostPacer(1000, 1000, gap)
	ctx := context.Background()

	start := time.Now()
	for i := 0; i < 3; i++ {
		if err := p.wait(ctx, "example.com"); err != nil {
			t.Fatalf("第 %d 次 wait 失败: %v", i+1, err)
		}
	}
	// 第 1 次不等待，后两次各至少等 1 个 gap
	elapsed := time.Since(start)
	if elapsed < 2*gap {
		t.Fatalf("同主机 3 次请求耗时 %v，短于期望的 %v（最小间隔未生效）", elapsed, 2*gap)
	}
}

// TestHostPacerDifferentHosts 验证不同主机互不影响对方的间隔配额。
func TestHostPacerDifferentHosts(t *testing.T) {
	p := newHostPacer(1000, 1000, 500*time.Millisecond)
	ctx := context.Background()

	start := time.Now()
	for _, h := range []string{"a.example.com", "b.example.com", "c.example.com"} {
		if err := p.wait(ctx, h); err != nil {
			t.Fatalf("wait(%s) 失败: %v", h, err)
		}
	}
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Fatalf("不同主机被互相阻塞，耗时 %v", elapsed)
	}
}

// TestHostPacerGlobalRate 验证全局令牌桶的速率上限（burst=1 时需逐个补充令牌）。
func TestHostPacerGlobalRate(t *testing.T) {
	const rps = 50 // 每 20ms 补 1 个令牌
	p := newHostPacer(rps, 1, 0)
	ctx := context.Background()

	const n = 5
	start := time.Now()
	for i := 0; i < n; i++ {
		if err := p.wait(ctx, "host-"+strings.Repeat("x", i)); err != nil { // 用不同 host 排除 min_gap 影响
			t.Fatalf("第 %d 次 wait 失败: %v", i+1, err)
		}
	}
	elapsed := time.Since(start)
	// 第 1 次用初始令牌，之后 4 次各需等 ~20ms，共 ~80ms；给 2 倍容差
	if elapsed < 60*time.Millisecond {
		t.Fatalf("%d 次请求仅耗时 %v，全局限速未生效", n, elapsed)
	}
}

// TestHostPacerContextCancel 验证上下文取消时 wait 立即返回错误，不阻塞扫描退出。
func TestHostPacerContextCancel(t *testing.T) {
	p := newHostPacer(1, 1, time.Second)
	ctx, cancel := context.WithCancel(context.Background())

	if err := p.wait(ctx, "slow.example.com"); err != nil {
		t.Fatalf("首次 wait 不应失败: %v", err)
	}
	cancel() // 取消后第二次必然处于等待状态

	done := make(chan error, 1)
	go func() { done <- p.wait(ctx, "slow.example.com") }()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("上下文取消后 wait 应返回错误，实际返回 nil")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("上下文取消后 wait 仍阻塞，扫描无法及时退出")
	}
}

// TestPacerHost 验证限速分组键的解析与兜底。
func TestPacerHost(t *testing.T) {
	cases := map[string]string{
		"https://a.example.com/path?q=1": "a.example.com",
		"http://127.0.0.1:8099/x":        "127.0.0.1:8099",
		"example.com":                    "example.com", // 无 scheme，Parse 后 Host 为空 -> 回退原串
	}
	for in, want := range cases {
		if got := pacerHost(in); got != want {
			t.Errorf("pacerHost(%q) = %q, 期望 %q", in, got, want)
		}
	}
}

// TestNewHostPacerDefaults 验证非法参数回落到保守默认值，避免出现"无限速"。
func TestNewHostPacerDefaults(t *testing.T) {
	p := newHostPacer(0, 0, -1)
	if p.rate <= 0 {
		t.Fatalf("rate 未回落到正值: %v", p.rate)
	}
	if p.burst <= 0 {
		t.Fatalf("burst 未回落到正值: %v", p.burst)
	}
	if p.minGap < 0 {
		t.Fatalf("minGap 未回落到非负值: %v", p.minGap)
	}
}
