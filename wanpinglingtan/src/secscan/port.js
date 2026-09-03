'use strict';
/*
 * port.js — 端口开放检测（批量 "IPv4:端口" / "域名:端口"）
 * 通过 TCP 连接确认端口是否对外开放
 */
const net = require('net');
const dns = require('dns').promises;
const geo = require('./geo');

function tcpConnect(host, port, timeoutMs) {
  return new Promise((resolve) => {
    const sock = new net.Socket();
    let settled = false;
    const done = (open, err) => {
      if (settled) return;
      settled = true;
      try { sock.destroy(); } catch (e) {}
      resolve({ open, err });
    };
    sock.setTimeout(timeoutMs);
    sock.once('connect', () => done(true, null));
    sock.once('timeout', () => done(false, 'timeout'));
    sock.once('error', (err) => done(false, err.code || err.message));
    try {
      sock.connect(port, host);
    } catch (e) {
      done(false, e.message);
    }
  });
}

async function resolveIpFor(host, kind) {
  if (kind === 'ip') return host;
  try {
    const r = await dns.lookup(host);
    return r && r.address ? r.address : host;
  } catch (e) {
    return null;
  }
}

async function probePort(target, opts = {}) {
  const timeoutMs = opts.timeout || 3000;
  const { host, port, kind } = target;
  const { open, err } = await tcpConnect(host, port, timeoutMs);
  const resolvedIp = await resolveIpFor(host, kind);
  const geoStr = resolvedIp ? geo.lookup(resolvedIp) : '未知';

  let openStr;
  if (open) openStr = '开放';
  else if (err === 'timeout') openStr = '超时(疑似过滤)';
  else openStr = '关闭';

  return {
    target: target.raw,
    host,
    port,
    kind: kind === 'domain' ? '域名' : 'IPv4',
    open: openStr,
    resolvedIp: resolvedIp || '-',
    geo: geoStr,
    note: open ? '' : (err === 'timeout' ? '连接超时' : (err === 'ECONNREFUSED' ? '连接被拒绝' : (err || ''))),
  };
}

module.exports = { probePort, tcpConnect };
