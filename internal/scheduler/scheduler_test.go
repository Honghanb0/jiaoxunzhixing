package scheduler

import (
	"testing"
	"time"
)

// TestParseSchedule_SixField 验证 6 字段（含秒）表达式能被正确解析。
func TestParseSchedule_SixField(t *testing.T) {
	sched, err := ParseSchedule("*/20 * * * * *")
	if err != nil {
		t.Fatalf("6字段表达式解析失败: %v", err)
	}
	next := sched.Next(time.Now())
	if next.Sub(time.Now()) > 21*time.Second || next.Before(time.Now()) {
		t.Errorf("下次执行时间异常: %v", next)
	}
	// 相邻两次间隔应≈20s
	runs, err := NextRuns("*/20 * * * * *", 2)
	if err != nil {
		t.Fatalf("NextRuns 失败: %v", err)
	}
	if len(runs) != 2 {
		t.Fatalf("NextRuns 返回 %d 条", len(runs))
	}
	diff := runs[1].Sub(runs[0])
	if diff < 19*time.Second || diff > 21*time.Second {
		t.Errorf("相邻两次间隔=%v, 期望≈20s", diff)
	}
}

// TestParseSchedule_FiveField 验证传统 5 字段（分 时 日 月 周）表达式兼容。
func TestParseSchedule_FiveField(t *testing.T) {
	if _, err := ParseSchedule("0 2 * * 1"); err != nil {
		t.Fatalf("5字段表达式解析失败: %v", err)
	}
	if _, err := ParseSchedule("bad expr"); err == nil {
		t.Fatal("非法表达式应返回错误")
	}
}
