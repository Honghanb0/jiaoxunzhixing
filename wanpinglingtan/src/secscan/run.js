'use strict';
/*
 * run.js — 安全扫描编排器（人工审计确认后的资产）
 * ---------------------------------------------------------------------------
 * 复用 wanpingqiuzhen 的连通性检测(connectivity.js)与高危指纹安全扫描(security.js)，
 * 对「人工审计确认为真实资产」的目标逐个执行：
 *   1) 连通性测试：ICMP 可达性、响应延迟、解析 IP、地理位置、登录界面识别
 *   2) 高危指纹扫描：敏感端口开放、未授权访问、明文传输、已知高危组件/CVE 特征
 * 通过 hooks 流式回传：onStart / onProgress / onResult / onDone / onError。
 *
 * 目标格式：{ kind:'domain'|'ip', value, raw, port:null }
 *   - kind/ip/value 用于探测；raw 用于展示。
 */

const { runPool } = require('./util');
const { probeConnectivity } = require('./connectivity');
const { scanTarget } = require('./security');

async function runSecScan(targets, opts = {}, hooks = {}) {
  const onStart = hooks.onStart || (() => {});
  const onProgress = hooks.onProgress || (() => {});
  const onResult = hooks.onResult || (() => {});
  const onDone = hooks.onDone || (() => {});
  const onError = hooks.onError || (() => {});
  const log = hooks.log || (() => {});

  const list = Array.isArray(targets) ? targets : [];
  const total = list.length;
  if (!total) {
    onStart({ total: 0 });
    onDone({ rows: [] });
    return [];
  }
  onStart({ total });
  log('info', `安全扫描启动：共 ${total} 个确认资产`);

  const results = [];
  await runPool(
    list,
    async (t) => {
      try {
        const connectivity = await probeConnectivity(t, opts);
        const security = await scanTarget(t, opts);
        const row = {
          target: t.raw,
          type: t.kind === 'domain' ? '域名' : 'IPv4',
          resolvedIp: connectivity.resolvedIp || '-',
          alive: connectivity.alive,
          latency: connectivity.latency,
          geo: connectivity.geo,
          hasLogin: connectivity.hasLogin,
          openPorts: security.openPorts,
          fingerprints: security.fingerprints,
          riskLevel: security.riskLevel,
          detail: security.detail,
          vulns: security.vulns || [],
        };
        results.push(row);
        onResult(row);
        return row;
      } catch (e) {
        const message = String((e && e.message) ? e.message : e);
        log('error', `安全扫描失败 ${t.raw}: ${message}`);
        onError({ target: t.raw, message });
        const row = {
          target: t.raw,
          type: t.kind === 'domain' ? '域名' : 'IPv4',
          resolvedIp: '-',
          alive: '不可达',
          latency: '超时',
          geo: '未知',
          hasLogin: '未检测',
          openPorts: '无',
          fingerprints: '无',
          riskLevel: '未知',
          detail: `扫描异常：${message}`,
        };
        results.push(row);
        onResult(row);
        return row;
      }
    },
    opts.concurrency || 8,
    (done, _total, row) => onProgress({ done, total, row })
  );

  onDone({ rows: results });
  return results;
}

module.exports = { runSecScan };
