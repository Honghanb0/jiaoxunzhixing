package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/PuerkitoBio/goquery"
	"security-agent/internal/config"
	"security-agent/internal/storage"
)

type Crawler struct {
	client     *http.Client
	cfg        *config.ScannerConfig
	domainRepo *storage.DomainRepository
	pageRepo   *storage.PageRepository
	// 进度回调：crawled 当前已爬页面数，total 当前最大页面数（会随爬取动态调整）
	onProgress func(crawled, total int, currentURL string)
	// pacer 请求限速器；限速关闭时为 nil
	pacer *hostPacer
}

// SetProgressCallback 设置进度回调
func (c *Crawler) SetProgressCallback(cb func(crawled, total int, currentURL string)) {
	c.onProgress = cb
}

// FetchOnce 抓取单个 URL 并返回页面信息，供"复测"使用。
//
// 与爬取流程的区别：不走队列、不做作用域判断、不写库、不递归，
// 只发一次 GET 并解析出标题/内容指纹/原文，用于确认某条风险是否仍然存在。
// 仍然复用同一个 HTTP 客户端与限速器，因此复测流量同样受速率约束、同样非破坏性。
func (c *Crawler) FetchOnce(ctx context.Context, url string) *CrawlResult {
	return c.crawlPage(&CrawlContext{Ctx: ctx}, &CrawlTask{URL: url, Depth: 0})
}

type CrawlResult struct {
	Page  *PageInfo
	Links []string
	Error error
}

type PageInfo struct {
	ID          string
	DomainID    string
	URL         string
	Title       string
	StatusCode  int
	ContentHash string
	Depth       int
	Links       []string
	RawContent  string
	// 响应元数据（供指纹识别使用，不持久化）
	Headers http.Header `json:"-"`
	Cookies []string    `json:"-"`
}

func NewCrawler(cfg *config.ScannerConfig, domainRepo *storage.DomainRepository, pageRepo *storage.PageRepository) *Crawler {
	// 复用 TCP 连接，显著提升高并发爬取性能与稳定性（避免频繁建连）。
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     90 * time.Second,
		DisableKeepAlives:   false,
		ForceAttemptHTTP2:   true,
	}
	return &Crawler{
		client: &http.Client{
			Transport: transport,
			Timeout:   time.Duration(cfg.Timeout) * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		cfg:        cfg,
		domainRepo: domainRepo,
		pageRepo:   pageRepo,
		pacer:      newCrawlerPacer(cfg),
	}
}

// newCrawlerPacer 按配置构造限速器；未启用时返回 nil（调用方需判空）。
func newCrawlerPacer(cfg *config.ScannerConfig) *hostPacer {
	if cfg == nil || !cfg.RateLimitEnabled() {
		return nil
	}
	rps, burst, minGap := cfg.RateLimitOrDefaults()
	return newHostPacer(rps, burst, minGap)
}

// Start 执行爬取。
//
// 历史 Bug（必须避免再次引入）：
//  1. 死锁：worker 用 `for task := range queue` 等待 close(queue)，
//     而 close(queue) 又放在 `wg.Wait()` 之后 —— 二者循环等待，
//     且 results 通道从未关闭，主循环永久阻塞，任务永远不结束。
//  2. 跨扫描缓存：Crawler 实例级 visited 从不清理，导致同一域名第二次扫描
//     时所有 URL 都被判为"已访问"而跳过，页面数恒为 0。
//
// 现在的实现：
//   - 去重放在本轮扫描的局部 seen 集合（单 goroutine 访问，无需加锁）
//   - 入队一律非阻塞；队列满时暂存到 pending 积压区，下一轮再试，绝不丢任务
//   - 以 inflight（已入队未回收）+ pending 双计数判空，为 0 时关闭队列
//   - worker 全部退出后由专门 goroutine 关闭 results，主循环得以正常结束
//   - 支持外部通过 ctx.Ctx 取消，取消时立即停止并释放 goroutine
func (c *Crawler) Start(ctx *CrawlContext) error {
	domain := ctx.Domain
	if domain == nil || domain.MaxPages <= 0 {
		return nil
	}

	concurrency := domain.Concurrency
	if concurrency <= 0 {
		concurrency = c.cfg.Concurrency
	}
	if concurrency <= 0 {
		concurrency = 5
	}

	const bufSize = 4096
	queue := make(chan *CrawlTask, bufSize)
	results := make(chan *CrawlResult, bufSize)
	sem := make(chan struct{}, concurrency)

	var pageCount atomic.Int64
	seen := make(map[string]bool)

	// 积压区：队列满时暂存，保证链接不丢失
	pending := make([]*CrawlTask, 0, 256)

	// 发现一个新 URL（只登记，不直接入队）
	addPending := func(u string, depth int) {
		if int(pageCount.Load())+len(pending) >= domain.MaxPages {
			return
		}
		u = normalizeURL(u)
		if u == "" || seen[u] {
			return
		}
		if !c.shouldCrawl(u, domain.Name) {
			return
		}
		seen[u] = true
		pending = append(pending, &CrawlTask{URL: u, Depth: depth})
	}

	done := ctx.Done()

	// worker 池：并发度由信号量控制，不再叠加人为限速
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for task := range queue {
				select {
				case sem <- struct{}{}:
				case <-done:
					return
				}

				result := c.crawlPage(ctx, task)

				select {
				case results <- result:
				case <-done:
					<-sem
					return
				}
				<-sem
			}
		}()
	}

	// worker 全部退出后关闭 results，让主循环的 range 正常结束
	go func() {
		wg.Wait()
		close(results)
	}()

	// 种子：CIDR 段会展开成多个 IP 并发扫描
	if ips := ipsForScope(ctx.StartURL); len(ips) > 0 {
		if len(ips) > domain.MaxPages {
			ips = ips[:domain.MaxPages]
		}
		for _, ip := range ips {
			addPending("https://"+ip, 0)
		}
	} else {
		addPending(ctx.StartURL, 0)
	}

	inflight := 0
	queueClosed := false
	// 幂等收尾：确保队列只被关闭一次
	finish := func() {
		if !queueClosed {
			close(queue)
			queueClosed = true
		}
	}

	// 尽量把积压任务推入队列；推不进的留在 pending 等下一轮
	flush := func() {
		if len(pending) == 0 {
			return
		}
		remain := pending[:0]
		for _, t := range pending {
			select {
			case queue <- t:
				inflight++
			default:
				remain = append(remain, t)
			}
		}
		pending = remain
	}

	flush()

	// 一个任务都没有（例如 StartURL 不可爬），直接收尾
	if inflight == 0 && len(pending) == 0 {
		finish()
	}

mainLoop:
	for {
		select {
		case result, ok := <-results:
			if !ok {
				break mainLoop // results 已关闭，全部完成
			}
			inflight--
			if inflight < 0 {
				inflight = 0
			}

			// 无论成功失败都累加（pageCount 即"已处理任务数"）
			pageCount.Add(1)
			ctx.PageCount = int(pageCount.Load())
			if result.Error == nil && result.Page != nil && result.Page.StatusCode != 0 {
				ctx.Pages = append(ctx.Pages, result.Page)
			}

			// 实时上报进度（失败也上报，便于前端看到确实在干活）
			if c.onProgress != nil {
				url := ""
				if result.Page != nil {
					url = result.Page.URL
				}
				c.onProgress(ctx.PageCount, domain.MaxPages, url)
			}

			// 未达深度/页数上限时继续发现新链接
			if result.Page != nil && result.Page.Depth < domain.MaxDepth &&
				pageCount.Load() < int64(domain.MaxPages) {
				for _, link := range result.Links {
					if int(pageCount.Load())+len(pending) >= domain.MaxPages {
						break
					}
					addPending(link, result.Page.Depth+1)
				}
			}

			flush()

			// 终止条件：无在途任务且无积压任务，或已达页数上限
			if (inflight == 0 && len(pending) == 0) ||
				(pageCount.Load() >= int64(domain.MaxPages) && inflight == 0) {
				finish()
			}

		case <-done:
			// 外部取消（任务超时 / 用户中止）
			finish()
			break mainLoop
		}
	}

	finish()

	// 兜底排空：让仍在往 results 写入的 worker 能顺利退出，避免 goroutine 泄漏
	go func() {
		for range results {
		}
	}()

	return nil
}

// CrawlContext 一次爬取任务的上下文
type CrawlContext struct {
	// Ctx 可为 nil；非 nil 时用于外部取消（任务超时或用户中止）
	Ctx       context.Context
	Domain    *Domain
	StartURL  string
	Pages     []*PageInfo
	PageCount int
}

// Done 返回取消信号通道；未设置 Ctx 时返回 nil（select 中永不被选中）
func (c *CrawlContext) Done() <-chan struct{} {
	if c == nil || c.Ctx == nil {
		return nil
	}
	return c.Ctx.Done()
}

type CrawlTask struct {
	URL   string
	Depth int
}

func (c *Crawler) crawlPage(ctx *CrawlContext, task *CrawlTask) *CrawlResult {
	result := &CrawlResult{Page: &PageInfo{URL: task.URL, Depth: task.Depth}, Links: []string{}}

	// 注意：这里不再做实例级去重。
	// 曾经的 `c.visited` 是 Crawler 字段且从不清理，导致同一域名第二次扫描时
	// 所有 URL 都被判为"已访问"而直接跳过，页面数恒为 0。
	// 去重已收敛到 Start() 中本轮扫描的局部 seen 集合。

	// 单请求上下文超时（取配置的爬虫超时，至少为 5s），保证可取消、不挂死。
	reqTimeout := time.Duration(c.cfg.Timeout) * time.Second
	if reqTimeout < 5*time.Second {
		reqTimeout = 5 * time.Second
	}
	// 挂载到扫描级 Context，外部取消时能立刻中断在途请求
	parent := context.Background()
	if ctx != nil && ctx.Ctx != nil {
		parent = ctx.Ctx
	}
	reqCtx, cancel := context.WithTimeout(parent, reqTimeout)
	defer cancel()

	var resp *http.Response
	var err error
	// 对瞬时网络错误进行有限重试，提升稳定性。
	for attempt := 0; attempt <= 2; attempt++ {
		req, buildErr := http.NewRequestWithContext(reqCtx, "GET", task.URL, nil)
		if buildErr != nil {
			result.Error = buildErr
			return result
		}
		req.Header.Set("User-Agent", c.cfg.UserAgent)
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")

		// 限速：真正发包前等待配额。放在重试循环内，重试流量同样受限，
		// 避免"失败重试"绕过速率约束把目标站打爆。
		if c.pacer != nil {
			if werr := c.pacer.wait(reqCtx, pacerHost(task.URL)); werr != nil {
				result.Error = werr
				return result
			}
		}

		resp, err = c.client.Do(req)
		if err == nil {
			break
		}
		if attempt < 2 {
			time.Sleep(time.Duration(attempt+1) * 200 * time.Millisecond)
		}
	}
	if err != nil {
		result.Error = err
		return result
	}
	defer resp.Body.Close()

	result.Page.StatusCode = resp.StatusCode
	result.Page.Headers = resp.Header
	for _, c := range resp.Cookies() {
		result.Page.Cookies = append(result.Page.Cookies, c.Name+"="+c.Value)
	}

	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "text/html") && !strings.Contains(contentType, "application/xhtml") {
		return result
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		result.Error = err
		return result
	}

	result.Page.RawContent = string(body)
	result.Page.ContentHash = c.hashContent(body)

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(result.Page.RawContent))
	if err != nil {
		result.Error = err
		return result
	}

	result.Page.Title = strings.TrimSpace(doc.Find("title").First().Text())

	// 提取可爬链接：a[href]、area[href]、form[action]，以及 frame/iframe 的 src。
	doc.Find("a[href], area[href], form[action]").Each(func(i int, s *goquery.Selection) {
		if href, exists := s.Attr("href"); exists {
			if abs := c.resolveURL(task.URL, href); abs != "" {
				result.Links = append(result.Links, abs)
			}
		}
		if action, exists := s.Attr("action"); exists {
			if abs := c.resolveURL(task.URL, action); abs != "" {
				result.Links = append(result.Links, abs)
			}
		}
	})
	doc.Find("frame[src], iframe[src]").Each(func(i int, s *goquery.Selection) {
		if src, exists := s.Attr("src"); exists {
			if abs := c.resolveURL(task.URL, src); abs != "" {
				result.Links = append(result.Links, abs)
			}
		}
	})

	return result
}

func (c *Crawler) shouldCrawl(u, domain string) bool {
	parsed, err := url.Parse(u)
	if err != nil {
		return false
	}

	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return false
	}

	// 域名匹配：精确匹配 / 子域匹配 / CIDR 段匹配
	host := parsed.Hostname()
	// scope 可能是纯域名（example.com）、裸 IP（127.0.0.1），
	// 也可能是完整 URL（http://127.0.0.1:8099）。统一取到 host 再比较，
	// 否则带 scheme/端口的 scope 永远匹配不上，导致页面数为 0。
	scopeHost := domain
	if sp, err := url.Parse(domain); err == nil && sp.Hostname() != "" {
		scopeHost = sp.Hostname()
	}
	if !hostMatchesScope(host, scopeHost) {
		return false
	}

	skipExts := []string{".jpg", ".jpeg", ".png", ".gif", ".css", ".js", ".ico", ".svg", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".webm", ".pdf", ".zip", ".gz"}
	lowerPath := strings.ToLower(parsed.Path)
	for _, ext := range skipExts {
		if strings.HasSuffix(lowerPath, ext) {
			return false
		}
	}

	return true
}

// hostMatchesScope 支持 4 种 scope 形式：
//  1. 精确域名 (example.com)
//  2. 子域通配 (example.com 同样匹配 a.example.com)
//  3. IPv4 CIDR (115.236.69.0/24)
//  4. 单 IP (115.236.69.5)
func hostMatchesScope(host, scope string) bool {
	if host == scope {
		return true
	}
	if strings.HasSuffix(host, "."+scope) {
		return true
	}
	// CIDR
	if strings.Contains(scope, "/") {
		_, ipnet, err := net.ParseCIDR(scope)
		if err == nil {
			if ip := net.ParseIP(host); ip != nil && ipnet.Contains(ip) {
				return true
			}
		}
		return false
	}
	// 单 IP
	if ip := net.ParseIP(scope); ip != nil {
		if hip := net.ParseIP(host); hip != nil && hip.Equal(ip) {
			return true
		}
	}
	return false
}

// ipsForScope 枚举 CIDR 内的 IP（排除网络号与广播号，超过 1024 个时取前 1024）
func ipsForScope(scope string) []string {
	if !strings.Contains(scope, "/") {
		if net.ParseIP(scope) != nil {
			return []string{scope}
		}
		return nil
	}
	_, ipnet, err := net.ParseCIDR(scope)
	if err != nil {
		return nil
	}
	net4 := ipnet.IP.To4()
	if net4 == nil {
		return nil
	}
	mask := ipnet.Mask
	ones, bits := mask.Size()
	if bits != 32 {
		return nil
	}
	// 太大的网段（>1024）只截取前 1024 个，避免爆炸
	size := 1 << uint(32-ones)
	if size > 1024 {
		size = 1024
	}
	var ips []string
	for i := 1; i < size-1 && i < size; i++ { // 跳过 .0 网络号与 .255 广播号
		ip := make(net.IP, 4)
		ip[0] = net4[0]
		ip[1] = net4[1]
		ip[2] = net4[2]
		ip[3] = net4[3] + byte(i)
		// 处理跨字节进位
		if ip[3] < net4[3] {
			ip[2]++
			if ip[2] == 0 {
				ip[1]++
				if ip[1] == 0 {
					ip[0]++
				}
			}
		}
		ips = append(ips, ip.String())
	}
	return ips
}

func (c *Crawler) resolveURL(base, href string) string {
	parsed, err := url.Parse(href)
	if err != nil {
		return ""
	}

	baseURL, err := url.Parse(base)
	if err != nil {
		return ""
	}

	if parsed.Scheme == "javascript" || parsed.Scheme == "mailto" || parsed.Scheme == "tel" {
		return ""
	}

	resolved := baseURL.ResolveReference(parsed)
	// 规范化：小写 host，去除 fragment。
	resolved.Host = strings.ToLower(resolved.Host)
	resolved.Fragment = ""
	return resolved.String()
}

func (c *Crawler) hashContent(content []byte) string {
	hash := sha256.Sum256(content)
	return hex.EncodeToString(hash[:])
}

func normalizeURL(u string) string {
	u = strings.TrimSpace(u)
	if u != "/" && strings.HasSuffix(u, "/") {
		u = strings.TrimSuffix(u, "/")
	}
	return u
}

type Domain struct {
	ID          string
	Name        string
	MaxDepth    int
	MaxPages    int
	Concurrency int
}
