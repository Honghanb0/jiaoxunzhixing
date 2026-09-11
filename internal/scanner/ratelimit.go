package scanner

import (
	"context"
	"math"
	"net/url"
	"strings"
	"sync"
	"time"
)

// pacerHost 从 URL 中取出用于限速分组的 host（含端口）。
// 解析失败时回退为原始字符串，保证"解析不出来也不会被当成同一个 host 无限放行"。
func pacerHost(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return strings.TrimSpace(rawURL)
	}
	return u.Host
}

// hostPacer 爬取请求限速器。
//
// 为什么需要：本平台的扫描对象是"已授权"的站点，但纯并发爬取仍可能把目标站打挂，
// 或被 WAF 判定为攻击流量直接封禁；竞赛「安全合规」评分也明确要求限速。
// 此前代码注释写明"不再叠加人为限速"，这里补回可控的速率约束：
//   - 全局令牌桶：限制整轮扫描每秒发出的请求总数
//   - 单主机最小间隔：同一站点的两次请求之间强制间隔，避免形成突发流
//
// 两者叠加后表现为"整体不快、对单个站点更慢"，既满足合规要求，
// 也显著降低触发目标站限流/封禁的概率。
type hostPacer struct {
	mu         sync.Mutex
	rate       float64              // 每秒补充的令牌数
	burst      float64              // 桶容量（允许的瞬时突发）
	tokens     float64              // 当前令牌数
	lastRefill time.Time            // 上次补充时间
	minGap     time.Duration        // 同一主机两次请求的最小间隔
	hostNext   map[string]time.Time // 每个主机下一次允许请求的时间点
}

// newHostPacer 创建限速器。参数非法时回落到保守默认值（5 req/s，间隔 200ms）。
func newHostPacer(rps float64, burst int, minGap time.Duration) *hostPacer {
	if rps <= 0 || math.IsNaN(rps) {
		rps = 5
	}
	if burst <= 0 {
		burst = int(math.Max(1, math.Ceil(rps)))
	}
	if minGap < 0 {
		minGap = 0
	}
	return &hostPacer{
		rate:       rps,
		burst:      float64(burst),
		tokens:     float64(burst),
		lastRefill: time.Now(),
		minGap:     minGap,
		hostNext:   make(map[string]time.Time),
	}
}

// wait 阻塞直到允许对 host 发起下一次请求；ctx 取消时立即返回其错误。
// 调用方必须在真正发出 HTTP 请求之前调用本方法。
func (p *hostPacer) wait(ctx context.Context, host string) error {
	for {
		p.mu.Lock()
		now := time.Now()

		// 按经过的时间补充令牌（上限为桶容量）
		if elapsed := now.Sub(p.lastRefill).Seconds(); elapsed > 0 {
			p.tokens = math.Min(p.burst, p.tokens+elapsed*p.rate)
			p.lastRefill = now
		}

		hostReady := p.hostNext[host]
		if p.tokens >= 1 && !now.Before(hostReady) {
			p.tokens--
			p.hostNext[host] = now.Add(p.minGap)
			p.mu.Unlock()
			return nil
		}

		// 还需要等多久：取"等令牌"与"等本主机间隔"中的较大者
		var d time.Duration
		if p.tokens < 1 {
			d = time.Duration((1 - p.tokens) / p.rate * float64(time.Second))
		}
		if gapWait := hostReady.Sub(now); gapWait > d {
			d = gapWait
		}
		if d < 10*time.Millisecond { // 避免忙等
			d = 10 * time.Millisecond
		}
		p.mu.Unlock()

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(d):
		}
	}
}
