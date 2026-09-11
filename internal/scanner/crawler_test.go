package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"security-agent/internal/config"
)

// 搭建一个小型站点：/ -> /a -> /b -> /c，外加一个环回链接 / 验证去重不会死循环
func newTestSite(t *testing.T) *httptest.Server {
	mux := http.NewServeMux()
	page := func(title string, links string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprintf(w, `<html><head><title>%s</title></head><body>%s</body></html>`, title, links)
		}
	}
	mux.HandleFunc("/", page("home", `<a href="/a">a</a><a href="/">self</a>`))
	mux.HandleFunc("/a", page("a", `<a href="/b">b</a><a href="/">home</a>`))
	mux.HandleFunc("/b", page("b", `<a href="/c">c</a>`))
	mux.HandleFunc("/c", page("c", `<a href="/">home</a>`))

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func newTestCrawler() *Crawler {
	cfg := &config.ScannerConfig{
		Concurrency: 4,
		Timeout:     5,
		UserAgent:   "TestCrawler/1.0",
		MaxDepth:    5,
		MaxPages:    100,
	}
	// Start() 不依赖这两个仓储，测试里传 nil 即可
	return NewCrawler(cfg, nil, nil)
}

// withTimeout 在限定时间内执行 fn，超时即判定为挂死
func withTimeout(t *testing.T, d time.Duration, what string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("%s 在 %v 内未返回 —— 疑似死锁/挂起", what, d)
	}
}

// TestCrawler_Terminates 回归：旧实现存在循环等待死锁
// （worker 等 close(queue)，而 close(queue) 又在 wg.Wait() 之后），
// 且 results 通道从未关闭，Start() 永不返回。
func TestCrawler_Terminates(t *testing.T) {
	srv := newTestSite(t)
	c := newTestCrawler()

	withTimeout(t, 20*time.Second, "Start()", func() {
		ctx := &CrawlContext{
			Domain:   &Domain{Name: "127.0.0.1", MaxDepth: 5, MaxPages: 100, Concurrency: 4},
			StartURL: srv.URL + "/",
			Pages:    make([]*PageInfo, 0),
		}
		if err := c.Start(ctx); err != nil {
			t.Errorf("Start() 返回错误: %v", err)
			return
		}
		if len(ctx.Pages) == 0 {
			t.Errorf("应至少抓到首页，实际 0 页")
		}
		t.Logf("抓取完成：%d 页", len(ctx.Pages))
	})
}

// TestCrawler_RepeatedScanKeepsResults 回归：旧实现用 Crawler 实例级
// visited 缓存且从不清理，导致同一域名第二次扫描时所有 URL 被判定为
// "已访问"而跳过，页面数恒为 0。
func TestCrawler_RepeatedScanKeepsResults(t *testing.T) {
	srv := newTestSite(t)
	c := newTestCrawler() // 关键：复用同一个 Crawler 实例

	run := func(round int) int {
		ctx := &CrawlContext{
			Domain:   &Domain{Name: "127.0.0.1", MaxDepth: 5, MaxPages: 100, Concurrency: 4},
			StartURL: srv.URL + "/",
			Pages:    make([]*PageInfo, 0),
		}
		if err := c.Start(ctx); err != nil {
			t.Fatalf("第 %d 轮 Start() 失败: %v", round, err)
		}
		return len(ctx.Pages)
	}

	withTimeout(t, 30*time.Second, "两轮扫描", func() {
		first := run(1)
		second := run(2)

		if first == 0 {
			t.Fatalf("第一轮应抓到页面，实际 0")
		}
		if second == 0 {
			t.Fatalf("第二轮抓到 0 页 —— visited 缓存未清理的 bug 复现")
		}
		if first != second {
			t.Errorf("两轮结果应一致（去重应限定在单轮内），实际 %d vs %d", first, second)
		}
		t.Logf("两轮均抓到 %d 页", second)
	})
}

// TestCrawler_RespectsMaxPages 达到页数上限后应正常结束，不会挂起
func TestCrawler_RespectsMaxPages(t *testing.T) {
	srv := newTestSite(t)
	c := newTestCrawler()

	withTimeout(t, 20*time.Second, "MaxPages 限制", func() {
		ctx := &CrawlContext{
			Domain:   &Domain{Name: "127.0.0.1", MaxDepth: 9, MaxPages: 2, Concurrency: 4},
			StartURL: srv.URL + "/",
			Pages:    make([]*PageInfo, 0),
		}
		if err := c.Start(ctx); err != nil {
			t.Fatalf("Start() 失败: %v", err)
		}
		if ctx.PageCount > 2 {
			t.Errorf("已处理任务数应不超过 MaxPages=2，实际 %d", ctx.PageCount)
		}
	})
}

// TestCrawler_Cancel 外部取消应立即停止，不得挂起
func TestCrawler_Cancel(t *testing.T) {
	srv := newTestSite(t)
	c := newTestCrawler()

	cancelCtx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	withTimeout(t, 20*time.Second, "取消后的 Start()", func() {
		ctx := &CrawlContext{
			Ctx:      cancelCtx,
			Domain:   &Domain{Name: "127.0.0.1", MaxDepth: 9, MaxPages: 200, Concurrency: 4},
			StartURL: srv.URL + "/",
			Pages:    make([]*PageInfo, 0),
		}
		// 取消后应尽快返回；结果数量不做断言
		if err := c.Start(ctx); err != nil {
			t.Fatalf("Start() 失败: %v", err)
		}
		t.Logf("取消后返回，已处理 %d 个任务", ctx.PageCount)
	})
}

// TestCrawler_ProgressCallback 进度回调应随爬取推进被调用
func TestCrawler_ProgressCallback(t *testing.T) {
	srv := newTestSite(t)
	c := newTestCrawler()

	var last int
	c.SetProgressCallback(func(crawled, total int, currentURL string) {
		last = crawled
	})

	withTimeout(t, 20*time.Second, "进度回调", func() {
		ctx := &CrawlContext{
			Domain:   &Domain{Name: "127.0.0.1", MaxDepth: 5, MaxPages: 100, Concurrency: 4},
			StartURL: srv.URL + "/",
			Pages:    make([]*PageInfo, 0),
		}
		if err := c.Start(ctx); err != nil {
			t.Fatalf("Start() 失败: %v", err)
		}
	})
	if last == 0 {
		t.Errorf("进度回调未被调用或计数为 0")
	}
}
