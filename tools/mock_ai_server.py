#!/usr/bin/env python3
"""本地 OpenAI 兼容 mock 服务，用于验证多模型统一接入层。

能力：
  - POST /chat/completions        非流式响应
  - POST /chat/completions stream  SSE 流式响应
  - 校验 Authorization 头，缺头/无效 Key 返回 401（验证鉴权链路）
  - 特殊 Key 触发 500，用于验证指数退避重试
  - 在返回内容中回显所用模型与鉴权头前缀，便于确认 GLM 的 JWT 签发是否生效

启动： python tools/mock_ai_server.py 8899
"""

import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# key -> 首次调用返回 500 的次数
FLAKY_STATE = {}
LOCK = threading.Lock()


def auth_kind(header):
    """判断鉴权形态：JWT（GLM）还是静态 sk- Key（DeepSeek/Kimi）"""
    if not header:
        return "none"
    token = header.replace("Bearer ", "").strip()
    if token.startswith("eyJ"):
        return "jwt(len=%d)" % len(token)
    if token.startswith("sk-"):
        return "static-key(len=%d)" % len(token)
    return "other(len=%d)" % len(token)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        sys.stderr.write("[mock %s] %s\n" % (self.path, fmt % args))

    def _send_json(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if not self.path.rstrip("/").endswith("/chat/completions"):
            self._send_json(404, {"error": {"message": "not found: %s" % self.path}})
            return

        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            req = json.loads(raw or b"{}")
        except Exception:
            self._send_json(400, {"error": {"message": "invalid json"}})
            return

        auth = self.headers.get("Authorization")
        kind = auth_kind(auth)

        # 鉴权校验
        if not auth or not auth.startswith("Bearer "):
            self._send_json(401, {"error": {"message": "missing bearer token"}})
            return
        token = auth.replace("Bearer ", "").strip()
        if token in ("", "invalid-key"):
            self._send_json(401, {"error": {"message": "invalid api key"}})
            return

        # 模拟不稳定：flaky-<n> 的 Key 前 n 次返回 500
        if token.startswith("flaky-"):
            try:
                total = int(token.split("-")[1])
            except Exception:
                total = 1
            with LOCK:
                seen = FLAKY_STATE.get(token, 0) + 1
                FLAKY_STATE[token] = seen
            if seen <= total:
                self._send_json(500, {"error": {"message": "simulated upstream failure #%d" % seen}})
                return

        model = req.get("model") or "unknown-model"
        messages = req.get("messages") or []
        user_text = ""
        for m in reversed(messages):
            if m.get("role") == "user":
                user_text = m.get("content", "")
                break

        content = "[model=%s][auth=%s] echo: %s" % (model, kind, user_text[:120])

        if req.get("stream"):
            self._send_sse(model, content)
            return

        self._send_json(200, {
            "id": "chatcmpl-mock",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": model,
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": "stop",
            }],
            "usage": {"prompt_tokens": len(user_text), "completion_tokens": len(content), "total_tokens": len(user_text) + len(content)},
        })

    def _send_sse(self, model, content):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()

        pieces = [content[i:i + 24] for i in range(0, len(content), 24)] or ["(empty)"]
        for p in pieces:
            chunk = {
                "id": "chatcmpl-mock",
                "object": "chat.completion.chunk",
                "model": model,
                "choices": [{"index": 0, "delta": {"role": "assistant", "content": p}, "finish_reason": None}],
            }
            self.wfile.write(("data: %s\n\n" % json.dumps(chunk, ensure_ascii=False)).encode("utf-8"))
            self.wfile.flush()
            time.sleep(0.05)

        done = {"id": "chatcmpl-mock", "model": model, "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]}
        self.wfile.write(("data: %s\n\n" % json.dumps(done, ensure_ascii=False)).encode("utf-8"))
        self.wfile.write(b"data: [DONE]\n\n")
        self.wfile.flush()


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8899
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    sys.stderr.write("mock AI server listening on 127.0.0.1:%d\n" % port)
    sys.stderr.flush()
    srv.serve_forever()


if __name__ == "__main__":
    main()
