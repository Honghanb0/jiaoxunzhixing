package weakpass

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// 默认与上限参数。
const (
	DefaultConcurrency = 10
	MaxConcurrency     = 50
	DefaultTimeout     = 5 * time.Second
	MaxTimeout         = 30 * time.Second
	MaxAttempts        = 20000 // 单次扫描尝试上限，防止字典组合失控
)

// FoundCred 一条命中（有效的 用户名+口令）。
type FoundCred struct {
	Service  string `json:"service"`
	Target   string `json:"target"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// ScanResult 一次弱口令扫描的结果。
type ScanResult struct {
	Target         string       `json:"target"`
	Service        string       `json:"service"`
	Attempts       int          `json:"attempts"`
	Found          []FoundCred  `json:"found"`
	Errors         []string     `json:"errors,omitempty"`
	ElapsedSec     float64      `json:"elapsed_sec"`
	StoppedOnFirst bool         `json:"stopped_on_first"`
}

// ScanOptions 弱口令扫描参数。
type ScanOptions struct {
	Target      string        // 必填：host 或 host:port
	Service     string        // 必填：ssh/ftp/pop3/smtp/redis/http
	Users       []string      // 用户名列表（为空则调用方需先用字典填充）
	Passwords   []string      // 口令列表（为空则调用方需先用字典填充）
	Concurrency int           // 并发数（1~50，默认 10）
	Timeout     time.Duration // 单条尝试超时（≤30s，默认 5s）
	StopOnFirst bool          // 命中即停止
	Verify      bool          // 对命中凭据二次复验（默认 true）
}

// Scan 并发执行 用户名×口令 组合登录尝试，命中即记录并可选复验。
// 任何依赖必须在调用前已填充（本函数不读取字典）。
func Scan(ctx context.Context, opts ScanOptions) (*ScanResult, error) {
	if opts.Target == "" {
		return nil, fmt.Errorf("缺少目标 target")
	}
	if opts.Service == "" {
		return nil, fmt.Errorf("缺少服务类型 service")
	}
	if len(opts.Users) == 0 || len(opts.Passwords) == 0 {
		return nil, fmt.Errorf("用户名字典与口令字典均不能为空")
	}
	concurrency := opts.Concurrency
	if concurrency <= 0 {
		concurrency = DefaultConcurrency
	}
	if concurrency > MaxConcurrency {
		concurrency = MaxConcurrency
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	if timeout > MaxTimeout {
		timeout = MaxTimeout
	}
	verify := opts.Verify

	// 构造任务列表
	tasks := make([]struct{ user, pass string }, 0, len(opts.Users)*len(opts.Passwords))
	for _, u := range opts.Users {
		for _, p := range opts.Passwords {
			tasks = append(tasks, struct{ user, pass string }{u, p})
		}
	}
	if len(tasks) > MaxAttempts {
		return nil, fmt.Errorf("尝试组合数 %d 超过上限 %d，请缩小字典或显式指定 usernames/passwords", len(tasks), MaxAttempts)
	}

	res := &ScanResult{Target: opts.Target, Service: opts.Service}
	var (
		mu     sync.Mutex
		sem    = make(chan struct{}, concurrency)
		wg     sync.WaitGroup
		stopped int32
		start  = time.Now()
	)

	for _, t := range tasks {
		// 上下文取消或命中即停
		select {
		case <-ctx.Done():
			res.Errors = append(res.Errors, "任务被取消: "+ctx.Err().Error())
			goto done
		default:
		}
		if opts.StopOnFirst && atomic.LoadInt32(&stopped) == 1 {
			break
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(t struct{ user, pass string }) {
			defer wg.Done()
			defer func() { <-sem }()

			authed, err := Check(ctx, opts.Service, opts.Target, t.user, t.pass, timeout)
			mu.Lock()
			defer mu.Unlock()
			res.Attempts++
			if err != nil {
				// 仅保留前若干错误，避免结果过大
				if len(res.Errors) < 30 {
					res.Errors = append(res.Errors, fmt.Sprintf("%s/%s: %v", t.user, t.pass, err))
				}
				return
			}
			if authed {
				if verify {
					// 二次复验：用全新连接确认凭据确实有效
					if v, verr := Check(ctx, opts.Service, opts.Target, t.user, t.pass, timeout); !v || verr != nil {
						return
					}
				}
				res.Found = append(res.Found, FoundCred{
					Service:  opts.Service,
					Target:   opts.Target,
					Username: t.user,
					Password: t.pass,
				})
				if opts.StopOnFirst {
					atomic.StoreInt32(&stopped, 1)
				}
			}
		}(t)
	}

done:
	wg.Wait()
	res.ElapsedSec = time.Since(start).Seconds()
	res.StoppedOnFirst = opts.StopOnFirst && atomic.LoadInt32(&stopped) == 1
	return res, nil
}
