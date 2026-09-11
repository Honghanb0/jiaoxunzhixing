package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDetectPageTampering_ExternalIframe(t *testing.T) {
	d := &Detector{}

	// 外域 iframe 应被识别
	page := &PageInfo{
		URL:        "https://example.com/index.html",
		RawContent: `<html><body><iframe src="https://evil.example.net/frame" width="0" height="0"></iframe></body></html>`,
		StatusCode: 200,
	}
	v := d.detectPageTampering(page)
	if v == nil {
		t.Fatalf("应检测到外部 iframe，实际未检出")
	}
	if v.Severity != "high" {
		t.Errorf("严重级别应为 high，实际 %s", v.Severity)
	}
	t.Logf("检出: %s | %s", v.Name, v.Evidence)
}

func TestDetectPageTampering_SameOriginIframeNotFlagged(t *testing.T) {
	d := &Detector{}

	// 同源 iframe 不应误报
	page := &PageInfo{
		URL:        "https://example.com/index.html",
		RawContent: `<html><body><iframe src="https://example.com/widget"></iframe></body></html>`,
		StatusCode: 200,
	}
	if v := d.detectPageTampering(page); v != nil {
		t.Errorf("同源 iframe 不应被标记为外部 iframe，实际检出: %s", v.Evidence)
	}
}

// TestDetectPageTampering_NoPanic 回归：旧实现拼接了 `(?!host)` 负向前瞻，
// 而 Go 的 RE2 不支持该语法，MustCompile 会 panic 并让整个扫描任务崩溃。
func TestDetectPageTampering_NoPanic(t *testing.T) {
	defer func() {
		if rec := recover(); rec != nil {
			t.Fatalf("detectPageTampering 发生 panic（正则语法不受支持？）: %v", rec)
		}
	}()

	d := &Detector{}
	pages := []*PageInfo{
		{URL: "https://example.com/", RawContent: `<iframe src="https://a.b.c/x"></iframe>`},
		{URL: "https://115.236.69.5/", RawContent: `<iframe src='http://1.2.3.4/y'></iframe>`},
		{URL: "https://example.com/", RawContent: `<iframe src="/relative"></iframe>`},
		{URL: "https://example.com/", RawContent: ``},
		{URL: "https://example.com/", RawContent: `<IFRAME SRC="HTTPS://EVIL.COM"></IFRAME>`},
	}
	for i, p := range pages {
		p.StatusCode = 200
		_ = d.detectPageTampering(p) // 只要求不 panic
		if i < 0 {
			t.Fatal("unreachable")
		}
	}
}

// TestNoUnsupportedRegexSyntax 源码级防护：
// Go 的 regexp 基于 RE2，不支持前瞻/后顾。若有人再次引入这类 Perl 语法，
// 编译期不会报错，但运行时 MustCompile 会 panic 并让扫描任务崩溃。
func TestNoUnsupportedRegexSyntax(t *testing.T) {
	bad := []string{`(?!`, `(?<!`, `(?=`}
	roots := []string{".", "../config"}

	for _, root := range roots {
		files, err := filepath.Glob(filepath.Join(root, "*.go"))
		if err != nil {
			continue
		}
		for _, f := range files {
			data, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			for i, line := range strings.Split(string(data), "\n") {
				trimmed := strings.TrimSpace(line)
				if !strings.Contains(trimmed, "regexp.") {
					continue
				}
				for _, token := range bad {
					if strings.Contains(trimmed, token) {
						t.Errorf("%s:%d 使用了 RE2 不支持的正则语法 %q，运行时会 panic：\n  %s",
							f, i+1, token, trimmed)
					}
				}
			}
		}
	}
}
