'use strict';
/*
 * connectivity.js — 批量连通性检测
 * 输出：延迟、响应 IP、地理位置、页面是否含登录界面
 */
const dns = require('dns').promises;
const ping = require('ping');
const geo = require('./geo');
const { fetchWithTimeout } = require('./util');

// 强信号（命中即可判定为登录页）
const STRONG_PATTERNS = [
  /<input[^>]+(type\s*=\s*["']?password["']?)/i,
  /(<title>[^<]*登录)/i,
  /(用户?(名|账号)?\s*(登录|登陆))/i,
];

async function detectLoginPage(host, timeoutMs) {
  const candidates = [`https://${host}`, `http://${host}`];
  for (const url of candidates) {
    try {
      const res = await fetchWithTimeout(url, {
        method: 'GET',
        redirect: 'follow',
        headers: { 'User-Agent': 'Mozilla/5.0 (compatible; WanpingQiuzhen/1.0)' },
      }, timeoutMs);
      if (!res.ok && res.status >= 400 && res.status !== 401 && res.status !== 403) {
        // 4xx 通常也代表有 Web 服务，仍检查内容
      }
      const text = await res.text();
      const snippet = text.slice(0, 200000);
      const strong = STRONG_PATTERNS.some((re) => re.test(snippet));
      if (strong) return '是';
      // 弱信号：需要同时出现表单与登录相关词
      const hasForm = /<form/i.test(snippet);
      const hasLoginWord = /登录|log\s*in|sign\s*in|用户名|账号/i.test(snippet);
      if (hasForm && hasLoginWord) return '是';
      if (hasLoginWord && /password/i.test(snippet)) return '是';
      return '否';
    } catch (e) {
      // 尝试下一个协议
      continue;
    }
  }
  return '无法访问';
}

async function resolveIp(target, numericHost) {
  if (numericHost && /^\d{1,3}(\.\d{1,3}){3}$/.test(numericHost)) return numericHost;
  if (target.kind === 'domain') {
    try {
      const r = await dns.lookup(target.value);
      return r && r.address ? r.address : null;
    } catch (e) {
      return null;
    }
  }
  return null;
}

async function probeConnectivity(target, opts = {}) {
  const loginCheck = opts.loginCheck !== false;
  const timeout = opts.timeout || 5; // ping 超时（秒）
  const httpTimeout = opts.httpTimeout || 6000;
  const host = target.value;

  let alive = false;
  let time = null;
  let numericHost = null;
  try {
    const r = await ping.promise.probe(host, { timeout, min_reply: 1, extra: [] });
    alive = !!r.alive;
    time = r.time;
    numericHost = r.numeric_host;
  } catch (e) {
    alive = false;
  }

  const resolvedIp = await resolveIp(target, numericHost);
  const geoStr = resolvedIp ? geo.lookup(resolvedIp) : '未知';
  const latencyStr = alive ? (typeof time === 'number' ? `${Math.round(time)} ms` : '未知') : '超时';

  let hasLogin = '未检测';
  if (loginCheck) {
    hasLogin = await detectLoginPage(host, httpTimeout);
  }

  return {
    target: target.raw,
    type: target.kind === 'domain' ? '域名' : 'IPv4',
    resolvedIp: resolvedIp || '-',
    latency: latencyStr,
    alive: alive ? '可达' : '不可达',
    geo: geoStr,
    hasLogin,
    status: alive ? '成功' : '不可达',
  };
}

module.exports = { probeConnectivity, detectLoginPage };
