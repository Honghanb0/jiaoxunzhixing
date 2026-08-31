package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"security-agent/internal/scheduler"
)

type ScheduleHandler struct{}

func NewScheduleHandler() *ScheduleHandler {
	return &ScheduleHandler{}
}

type ValidateCronRequest struct {
	Cron string `json:"cron" binding:"required"`
}

type ValidateCronResponse struct {
	Valid     bool     `json:"valid"`
	Error     string   `json:"error,omitempty"`
	HumanDesc string   `json:"human_desc,omitempty"`
	NextRuns  []string `json:"next_runs,omitempty"`
}

// Validate 校验 cron 表达式并返回未来 5 次执行时间（前端“下次运行”预览）。
func (h *ScheduleHandler) Validate(c *gin.Context) {
	var req ValidateCronRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	runs, err := scheduler.NextRuns(req.Cron, 5)
	if err != nil {
		c.JSON(http.StatusOK, ValidateCronResponse{Valid: false, Error: err.Error()})
		return
	}

	next := make([]string, 0, len(runs))
	for _, t := range runs {
		next = append(next, t.Format("2006-01-02 15:04:05"))
	}

	c.JSON(http.StatusOK, ValidateCronResponse{
		Valid:     true,
		HumanDesc: describeCron(req.Cron),
		NextRuns:  next,
	})
}

// describeCron 对常见周期模式生成中文描述（尽力而为，非完整 cron 解释器）。
func describeCron(expr string) string {
	fields := strings.Fields(strings.TrimSpace(expr))
	if len(fields) < 5 {
		return ""
	}

	// 6 字段: 秒 分 时 日 月 周 ; 5 字段: 分 时 日 月 周
	hasSecond := len(fields) == 6
	min := fields[0]
	hour := fields[1]
	dom := fields[2]
	month := fields[3]
	dow := fields[4]
	if hasSecond {
		min = fields[1]
		hour = fields[2]
		dom = fields[3]
		month = fields[4]
		dow = fields[5]
	}

	timePart := ""
	if h, err := parseFieldHour(hour); err == nil {
		if m, err2 := parseFieldMinute(min); err2 == nil {
			timePart = h + ":" + m
		}
	}

	dowNames := map[string]string{"0": "周日", "1": "周一", "2": "周二", "3": "周三", "4": "周四", "5": "周五", "6": "周六", "7": "周日"}

	switch {
	case dom == "*" && month == "*" && dow != "*" && dow != "?":
		if name, ok := dowNames[strings.TrimPrefix(dow, "0")]; ok {
			return "每周" + name + " " + timePart
		}
		return "每周（周" + dow + "） " + timePart
	case dom != "*" && dom != "?" && month == "*" && dow == "*" || dow == "?":
		if dom != "*" && dom != "?" {
			return "每月 " + dom + " 日 " + timePart
		}
		return "每月 " + timePart
	case dom == "*" && month == "*" && dow == "*":
		return "每天 " + timePart
	case dom == "*" && month == "*" && (dow == "1-5"):
		return "每个工作日 " + timePart
	}
	return ""
}

func parseFieldHour(s string) (string, error) {
	if s == "*" {
		return "00", nil
	}
	return pad2(s), nil
}

func parseFieldMinute(s string) (string, error) {
	if s == "*" {
		return "00", nil
	}
	return pad2(s), nil
}

func pad2(s string) string {
	s = strings.TrimSpace(s)
	if len(s) == 1 {
		return "0" + s
	}
	return s
}

// nowRFC 方便其它 handler 复用当前时间格式化。
func nowRFC() string {
	return time.Now().Format(time.RFC3339)
}
