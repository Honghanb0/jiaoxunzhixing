#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""脚本化 mock LLM（OpenAI 兼容），仅用于本地验证「智能体工作流」本身。

它按固定剧本返回 <tool_calls>，从而在不依赖真实（且当前额度耗尽/超时的）
模型供应商的情况下，验证智能体是否能真正：
  扫描 -> 建工单（弱口令/数据泄露）-> 建周期巡检规则 -> finish_task

用法： python tools/mock_llm_agent.py --port 8901
"""
import argparse
import os
import json
import re
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer

DOMAIN_RE = re.compile(r'"id"\s*:\s*"([0-9a-fA-F-]{8,})"')


def tool_calls(calls):
    payload = [{"name": n, "arguments": a} for n, a in calls]
    body = "<tool_calls>\n" + json.dumps(payload, ensure_ascii=False) + "\n</tool_calls>"
    return {
        "id": "chatcmpl-mock",
        "object": "chat.completion",
        "model": "mock-agent",
        "choices": [{"index": 0, "finish_reason": "stop",
                     "message": {"role": "assistant", "content": body}}],
    }


def finish(summary):
    return tool_calls([("finish_task", {"summary": summary})])


def plan(messages):
    """根据对话历史决定下一步：一个极简的状态机。"""
    # 必须先把每条消息拼成「未转义」的文本：json.dumps 会把 < 转义成 \u003c，
    # 导致按 <tool_result ...> 做正则匹配时永远命中不了。
    parts = []
    for m in messages:
        c = m.get("content") if isinstance(m, dict) else None
        if isinstance(c, str):
            parts.append(c)
    text = "\n".join(parts) + "\n" + json.dumps(messages, ensure_ascii=False)

    def called(name):
        return ('"name":"%s"' % name) in text or ('"name": "%s"' % name) in text

    # 统计每种工具已被调用的次数（通过 tool_result 回写判断已完成）
    def done_count(name):
        # 注意工具结果实际格式为 <tool_result name="X" call_id="..." error="...">，
        # 因此匹配时必须容忍标签内的其余属性。
        return len(re.findall(r'<tool_result\s+name="%s"(?:\s[^>]*)?>' % name, text))

    if done_count("list_domains") == 0:
        return tool_calls([("list_domains", {})])

    # 从 list_domains 的结果里抓一个真实 domain id；
    # 可用环境变量 DOMAIN_IDS 直接指定（逗号分隔），避免从结果里误抓到其它 UUID。
    domain_id = ""
    env_ids = [x.strip() for x in os.environ.get("DOMAIN_IDS", "").split(",") if x.strip()]
    if env_ids:
        domain_id = env_ids[0]
    else:
        m = DOMAIN_RE.search(text)
        domain_id = m.group(1) if m else ""

    if done_count("start_scan") == 0 and domain_id:
        return tool_calls([("start_scan", {"domain_id": domain_id})])
    if done_count("wait_scan") == 0:
        return tool_calls([("wait_scan", {"timeout_seconds": 120})])
    if done_count("list_vulnerabilities") == 0 and domain_id:
        return tool_calls([("list_vulnerabilities", {"domain_id": domain_id, "limit": 50})])
    if done_count("create_ticket") < 2:
        # 依次建两类工单：弱口令、数据泄露
        n = done_count("create_ticket")
        if n == 0:
            return tool_calls([("create_ticket", {
                "title": "弱口令风险（mock 验证）",
                "vuln_type": "weak_password",
                "risk_level": "high",
                "asset_url": "http://127.0.0.1:8099",
                "description": "由 mock LLM 驱动的端到端验证工单：弱口令。",
            })])
        return tool_calls([("create_ticket", {
            "title": "数据泄露风险（mock 验证）",
            "vuln_type": "sensitive_file",
            "risk_level": "high",
            "asset_url": "http://127.0.0.1:8099",
            "description": "由 mock LLM 驱动的端到端验证工单：数据泄露/敏感文件。",
        })])
    if done_count("create_inspection_rule") == 0:
        return tool_calls([("create_inspection_rule", {
            "name": "每日14:40日常巡检（mock 验证）",
            "domain_ids": [domain_id] if domain_id else [],
            "schedule": "40 14 * * *",
            "enabled": True,
            "run_scan": True,
            "severity_threshold": "medium",
        })])
    return finish("已完成扫描，并针对弱口令与数据泄露提交工单，同时建立每日14:40周期巡检规则。")


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
        self._send({"status": "ok", "service": "mock-llm-agent"})

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
        except Exception as e:  # 剧本异常也要给出可用响应，避免智能体卡死
            resp = finish("mock 计划异常: %s" % e)
        self._send(resp)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8901)
    args = ap.parse_args()
    print("[mock-llm] 监听 127.0.0.1:%d/chat/completions" % args.port, flush=True)
    HTTPServer(("127.0.0.1", args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
