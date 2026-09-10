// mockai 是本地 OpenAI 兼容 Mock 服务（原 tools/mock_ai_server.py 的 Go 版本），
// 用于验证多模型统一接入层。
//
// 能力：
//   - POST /chat/completions         非流式响应
//   - POST /chat/completions+stream  SSE 流式响应
//   - 校验 Authorization 头，缺头/无效 Key 返回 401
//   - `flaky-<n>` Key 前 n 次返回 500，用于验证指数退避重试
//   - 返回内容回显所用模型与鉴权形态，便于确认 GLM 的 JWT 签发是否生效
//
// 用法：
//
//	go run ./cmd/mockai 8899
//
// 端口缺省为 8899；仅监听 127.0.0.1。Ctrl+C 优雅退出。
package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"security-agent/internal/ops"
)

func main() {
	flag.Parse()

	port := ops.DefaultMockAIPort
	if arg := flag.Arg(0); arg != "" {
		parsed, err := strconv.Atoi(arg)
		if err != nil || parsed <= 0 || parsed > 65535 {
			ops.Errorf("端口号非法：%q（应为 1-65535 的整数）", arg)
			os.Exit(1)
		}
		port = parsed
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := ops.RunMockAI(ctx, "127.0.0.1", port); err != nil {
		ops.Errorf("Mock 服务退出：%v", err)
		os.Exit(1)
	}
}
