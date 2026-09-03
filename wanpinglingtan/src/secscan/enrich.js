'use strict';
/*
 * enrich.js — 人工审计资产轻量 enrichment
 * 对 IP / 域名类资产做：DNS 解析（解析 IP）、地理库定位（地理位置）、ICMP 连通性探测（可达状态）。
 * 用于辅助研判资产是否为「真实资产 / 误报」，不触发指纹/深度扫描（省时）。
 * 邮箱 / 泄露 / 企业信息类资产不参与（仅人工研判真实性，不触发扫描）。
 */

const { probeConnectivity } = require('./connectivity');

// targets: [{ id, kind:'domain'|'ip', value }]
// 返回：{ items: [{ id, resolvedIp, geo, alive }] }
async function enrichTargets(targets) {
  const list = Array.isArray(targets) ? targets : [];
  const items = [];
  for (const t of list) {
    try {
      const c = await probeConnectivity(
        { kind: t.kind, value: t.value, raw: t.value },
        // 不探测登录页，仅解析 IP / 地理位置 / 连通性，大幅降低耗时
        { loginCheck: false, timeout: 3, httpTimeout: 3000 }
      );
      items.push({
        id: t.id,
        resolvedIp: c.resolvedIp || '-',
        geo: c.geo || '未知',
        alive: c.alive || '不可达',
      });
    } catch (e) {
      items.push({ id: t.id, resolvedIp: '-', geo: '未知', alive: '不可达' });
    }
  }
  return { items };
}

module.exports = { enrichTargets };
