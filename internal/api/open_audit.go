package api

import (
	"log"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"security-agent/internal/config"
)

// AuditOpenService 记录对外工具服务的每一次调用。
//
// 为什么单独做这个而不是直接套 gin.Logger：
//  1. **可追溯性**：对外接口是给第三方平台（恒脑）调用的，属于"外部主体访问本系统"，
//     安全平台必须能回答"谁、何时、调了什么、结果如何"。这是交付物的一部分。
//  2. **兼容既有教训**：本项目的日志通道对高频写入敏感（历史上任务详情接口按秒轮询
//     打日志曾把 stdout 写满导致处理器挂死）。对外接口调用频率低，但这里仍刻意
//     只记录必要字段、不打印请求体与响应体，避免大对象刷屏。
//  3. **绝不记录密钥**：只记录请求头里"是否带了鉴权头"，不记录其值。
func AuditOpenService(cfg *config.OpenServiceConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()

		// 客户端 IP：优先取 X-Forwarded-For（若部署在反向代理后），否则用 RemoteAddr
		ip := c.ClientIP()
		keyHeader := KeyHeaderName(cfg)
		authState := "无"
		if c.GetHeader(keyHeader) != "" {
			authState = "有"
		}

		log.Printf("[OpenService] %s %s %s -> %d (%s) ip=%s auth=%s",
			c.Request.Method,
			c.Request.URL.Path,
			strings.TrimSpace(c.Request.URL.RawQuery),
			c.Writer.Status(),
			time.Since(start).Round(time.Millisecond),
			ip,
			authState,
		)
	}
}
