#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""脚本化 mock LLM（OpenAI 兼容）——复现「重复调用死循环」失败形态。

对应真实失败任务 7755460c：模型用**完全相同的入参**反复调用 start_scan / list_domains，
从不 create_ticket 也从不 finish_task，最终以「达到最大轮次上限 24」失败。

本 mock 的行为：
  1. list_domains 一次；
  2. 之后**一直**以相同入参重复调用 start_scan（模拟卡死）；
  3. 一旦在对话历史中看到平台注入的 duplicate_call 干预提示，就转向 finish_task 收尾。

这样既能验证「重复调用干预确实被触发」，也能验证「触发后任务能正常收敛」。
若平台没有该干预，本 mock 会一直重复到轮次上限，任务必然 failed。

用法： DOMAIN_IDS=<domain_id> python tools/mock_llm_loop.py --port 8902
"""
import argparse
import os
import re
import json
from http.server import BaseHTTPRequestHandler, HTTPServer


def tool_calls(calls):
    payload = [{"name": n, "arguments": a} for n, a in calls]
    body = "<tool_calls>\n" + json.dumps(payload, ensure_ascii=False) + "\n</tool_calls>"
    return {
        "id": "chatcmpl-mock-loop",
        "object": "chat.completion",
        "model": "mock-agent-loop",
        "choices": [{"index": 0, "finish_reason": "stop",
                     "message": {"role": "assistant", "content": body}}],
    }


def plan(messages):
    parts = []
    for m in messages:
        c = m.get("content") if isinstance(m, dict) else None
        if isinstance(c, str):
            parts.append(c)
    text = "\n".join(parts) + "\n" + json.dumps(messages, ensure_ascii=False)

    def done_count(name):
        return len(re.findall(r'<tool_result\s+name="%s"(?:\s[^>]*)?>' % name, text))

    # 平台是否已注入「重复调用干预」。
    # 注意：干预消息由系统注入，渲染为 <tool_result name="system" call_id="duplicate_call">，
    # 因此只能按 call_id 匹配，不能按 name 匹配（name 恒为 system）。
    if text.count('call_id="duplicate_call"') > 0:
        return tool_calls([("finish_task", {
            "summary": "收到重复调用干预提示，停止无效重复扫描并收尾（mock 验证）。"
        })])

    domain_id = ""
    env_ids = [x.strip() for x in os.environ.get("DOMAIN_IDS", "").split(",") if x.strip()]
    if env_ids:
        domain_id = env_ids[0]

    if done_count("list_domains") == 0:
        return tool_calls([("list_domains", {})])

    # 卡死形态：始终以**相同入参**重复调用 start_scan
    return tool_calls([("start_scan", {"domain_id": domain_id})])


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def _send(self, obj, code=200):
        data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        self._send({"status": "ok", "service": "mock-llm-loop"})

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8", errors="replace") if length else "{}"
        try:
            req = json.loads(raw)
        except Exception:
            req = {}
        messages = req.get("messages") or []
        if "/chat/completions" not in self.path:
            self._send({"error": {"message": "not found: %s" % self.path}}, 404)
            return
        try:
            resp = plan(messages)
        except Exception as e:
            resp = tool_calls([("finish_task", {"summary": "mock 计划异常: %s" % e})])
        self._send(resp)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8902)
    args = ap.parse_args()
    print("[mock-llm-loop] 监听 127.0.0.1:%d/chat/completions" % args.port, flush=True)
    HTTPServer(("127.0.0.1", args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
