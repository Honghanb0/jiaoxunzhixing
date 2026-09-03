#!/usr/bin/env bash
# Agent 智能体测试套件驱动脚本
# 目标服务: http://127.0.0.1:8099  (需 Bearer 鉴权, role_level>=1)
set -u
BASE="http://127.0.0.1:8099"
OUT="/tmp/agent_test_results"
mkdir -p "$OUT"

# ---------- 鉴权 ----------
login() {
  curl -s --noproxy localhost -X POST "$BASE/api/auth/login" -H 'Content-Type: application/json' -d "$1" \
    | python -c "import sys,json;print(json.load(sys.stdin).get('token',''))" 2>/dev/null
}
ADMIN=$(login '{"username":"admin","password":"Admin@123"}')
echo "ADMIN_TOKEN_LEN=${#ADMIN}"

# 注册一个低权限(访客 rl=0)账号用于权限否定测试
TS=$(date +%s)
VISUSER="vis_$TS"
VISPW="visitor123"
curl -s --noproxy localhost -X POST "$BASE/api/auth/register" -H 'Content-Type: application/json' \
  -d "{\"username\":\"$VISUSER\",\"password\":\"$VISPW\"}" -o /dev/null -w "register_visitor HTTP %{http_code}\n"
VISITOR=$(login "{\"username\":\"$VISUSER\",\"password\":\"$VISPW\"}")
echo "VISITOR_TOKEN_LEN=${#VISITOR}"

# ---------- 提交一个 agent 任务并轮询至终态 ----------
run_agent() {
  local goal="$1"; local token="$2"; local label="$3"
  local run
  run=$(curl -s --noproxy localhost -X POST "$BASE/api/agent/run" -H "Authorization: Bearer $token" \
    -H 'Content-Type: application/json' -d "{\"goal\":$(python -c "import json,sys;print(json.dumps(sys.argv[1]))" "$goal")}")
  local tid
  tid=$(echo "$run" | python -c "import sys,json;print(json.load(sys.stdin).get('task_id',''))" 2>/dev/null)
  echo "$tid" > "$OUT/${label}.tid"
  echo "$run" > "$OUT/${label}.submit.json"
  # 轮询
  local i=0 status=""
  while [ $i -lt 30 ]; do
    sleep 6
    i=$((i+1))
    status=$(curl -s --noproxy localhost "$BASE/api/agent/tasks/$tid" -H "Authorization: Bearer $token" \
      | python -c "import sys,json;d=json.load(sys.stdin);print(d.get('status','?'))" 2>/dev/null)
    if [ "$status" = "completed" ] || [ "$status" = "failed" ] || [ "$status" = "cancelled" ]; then
      break
    fi
  done
  # 抓取完整任务详情
  curl -s --noproxy localhost "$BASE/api/agent/tasks/$tid" -H "Authorization: Bearer $token" > "$OUT/${label}.task.json"
  echo "${label}: tid=$tid final_status=$status polls=$i"
}

echo "=== TC-01 多步骤推理(只读综合分析) ==="
run_agent '请全面分析平台当前安全态势：先用 get_stats 获取整体统计，再用 list_vulnerabilities 查看最近的高危漏洞，再用 list_alerts 查看待处理告警，最后用 finish_task 给出包含风险优先级建议的中文摘要。' "$ADMIN" tc01

echo "=== TC-02 工具调用闭环(创建工单+回写核对) ==="
run_agent '请创建一条安全工单：标题「Agent测试工单-TC02」，风险等级 high，资产名「测试资产」，漏洞名「SQL注入」，描述「验证智能体结果回写能力」；创建后用 list_tickets 核对其是否存在，最后用 finish_task 给出结论。' "$ADMIN" tc02

echo "=== TC-03 异常处理-无效参数(不存在的域名发起扫描) ==="
run_agent '请对域名 id 为 nonexistent-domain-id-xyz 的域名发起一次扫描（start_scan），并将结果用 finish_task 汇报。' "$ADMIN" tc03

echo "=== TC-04 异常处理-只读沙箱(写语句被拦截) ==="
run_agent '请用 query_neo4j 执行以下 Cypher 创建一个测试节点并返回：CREATE (n:TempTest) RETURN n' "$ADMIN" tc04

echo "=== TC-07 综合复杂任务(跨实体推理+自定义聚合) ==="
run_agent '请做面向运维的处置规划：先用 get_stats 了解整体情况，再用 query_neo4j 统计各域名的高危漏洞数(MATCH (v:Vulnerability) WHERE v.severity="high" RETURN v.domain_id AS dom, count(*) AS c ORDER BY c DESC LIMIT 10)，再用 list_inspection_rules 看现有巡检规则，最后用 finish_task 给出优先扫描哪些域名的建议。' "$ADMIN" tc07

echo "=== TC-05 边界-空目标(输入校验) ==="
curl -s --noproxy localhost -X POST "$BASE/api/agent/run" -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d '{"goal":""}' -w "\nHTTP %{http_code}\n" -o "$OUT/tc05.body.json"
cat "$OUT/tc05.body.json"

echo "=== TC-06 权限-未鉴权(无 token) ==="
curl -s --noproxy localhost -X POST "$BASE/api/agent/run" -H 'Content-Type: application/json' \
  -d '{"goal":"test"}' -w "\nHTTP %{http_code}\n" -o "$OUT/tc06.body.json"
cat "$OUT/tc06.body.json"

echo "=== TC-08 权限-低权限访客(rl=0) ==="
curl -s --noproxy localhost -X POST "$BASE/api/agent/run" -H "Authorization: Bearer $VISITOR" -H 'Content-Type: application/json' \
  -d '{"goal":"test"}' -w "\nHTTP %{http_code}\n" -o "$OUT/tc08.body.json"
cat "$OUT/tc08.body.json"

echo "ALL_DONE"
