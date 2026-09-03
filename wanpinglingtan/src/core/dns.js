'use strict';

/**
 * DNS 解析工具：基于 Node dns/promises，支持自定义公共解析器（提升沙箱/受限环境可用性）。
 * 所有解析均容错：失败返回空数组，不影响主流程（宁缺毋滥）。
 */

const dns = require('dns').promises;
const { isValidIPv4 } = require('../utils/cidr');

let resolvers = null; // 默认使用系统解析器
function setResolvers(list) {
  if (Array.isArray(list) && list.length) {
    try {
      dns.setServers(list);
      resolvers = list;
    } catch (_) {
      resolvers = null;
    }
  }
}
function getResolvers() {
  return resolvers;
}

async function resolveA(host) {
  try {
    const r = await dns.resolve(host, 'A');
    return Array.isArray(r) ? r.filter(isValidIPv4) : [];
  } catch (_) {
    return [];
  }
}

async function resolveAaaa(host) {
  try {
    const r = await dns.resolve(host, 'AAAA');
    return Array.isArray(r) ? r : [];
  } catch (_) {
    return [];
  }
}

async function resolvePtr(ip) {
  try {
    const r = await dns.reverse(ip);
    return Array.isArray(r) ? r : [];
  } catch (_) {
    return [];
  }
}

async function resolveMx(domain) {
  try {
    const r = await dns.resolveMx(domain);
    return Array.isArray(r) ? r : [];
  } catch (_) {
    return [];
  }
}

async function resolveTxt(domain) {
  try {
    const r = await dns.resolveTxt(domain);
    return Array.isArray(r) ? r.map((rec) => (Array.isArray(rec) ? rec.join('') : rec)) : [];
  } catch (_) {
    return [];
  }
}

async function resolveNs(domain) {
  try {
    const r = await dns.resolveNs(domain);
    return Array.isArray(r) ? r : [];
  } catch (_) {
    return [];
  }
}

module.exports = {
  setResolvers,
  getResolvers,
  resolveA,
  resolveAaaa,
  resolvePtr,
  resolveMx,
  resolveTxt,
  resolveNs,
};
