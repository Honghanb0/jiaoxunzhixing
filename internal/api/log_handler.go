package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"security-agent/internal/logutil"
)

// LogHandler 提供服务端运行日志的增量拉取接口，供“CLI 风格日志页”使用。
// 级别/关键字/时间过滤统一在前端对「服务端日志 + 前端 console 日志」合并后的列表进行，
// 故此处仅做增量（after）与条数（limit）裁剪，保证前端 after 指针连续不丢行。
type LogHandler struct{}

func NewLogHandler() *LogHandler { return &LogHandler{} }

// Get 返回服务端日志条目（环形缓冲）。权限：role_level >= 2（审计员 / 管理员）。
//
// 查询参数：
//   - after: 仅返回序号大于该值的条目（增量拉取；缺省返回最近 limit 条）
//   - limit: 单次返回最大条数（默认 500，上限 2000）
func (h *LogHandler) Get(c *gin.Context) {
	after, _ := strconv.ParseInt(c.Query("after"), 10, 64)
	limit := 500
	if v := c.Query("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > 2000 {
		limit = 2000
	}

	entries := logutil.Tail(after, limit)
	c.JSON(http.StatusOK, gin.H{
		"entries": entries,
		"total":   logutil.Len(),
	})
}
