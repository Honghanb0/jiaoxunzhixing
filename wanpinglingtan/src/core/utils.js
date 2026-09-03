'use strict';

/**
 * 公共工具：输入解析、域名/IP 归一化、去重、集合运算、计时。
 * 公网判定复用 src/utils/cidr.js，避免重复实现。
 */

const { isPublicIPv4, ipScope } = require('../utils/cidr');

function splitList(text) {
  if (!text) return [];
  return String(text)
    .split(/[\n,;，；\s]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

/** 清洗域名为小写裸域名（去掉协议/路径/端口/www.） */
function cleanDomain(input) {
  return String(input || '')
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, '')
    .replace(/^www\./, '')
    .replace(/\/.*$/, '')
    .replace(/:\d+$/, '');
}

/** 按分隔符拆分关键字并去空白 */
function splitKeywords(text) {
  return splitList(text).filter((s) => s.length > 1);
}

/** 基于 key 函数去重，保留首次出现 */
function dedupByKey(items, keyFn) {
  const map = new Map();
  for (const it of items || []) {
    let k;
    try {
      k = keyFn(it);
    } catch (_) {
      k = null;
    }
    if (k == null || k === '') continue;
    if (!map.has(k)) map.set(k, it);
  }
  return Array.from(map.values());
}

function uniq(arr) {
  return Array.from(new Set(arr || []));
}

function uniqBy(arr, keyFn) {
  const seen = new Set();
  const out = [];
  for (const it of arr || []) {
    const k = keyFn(it);
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(it);
  }
  return out;
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function safeJsonParse(s) {
  if (s == null) return null;
  try {
    return typeof s === 'string' ? JSON.parse(s) : s;
  } catch (_) {
    return null;
  }
}

/** 合并两个集合并返回新增部分（用于阶段间发现量统计） */
function diffSet(prev, next) {
  const prevSet = prev instanceof Set ? prev : new Set(prev);
  const added = [];
  for (const x of next) if (!prevSet.has(x)) added.push(x);
  return added;
}

module.exports = {
  isPublicIPv4,
  ipScope,
  splitList,
  splitKeywords,
  cleanDomain,
  dedupByKey,
  uniq,
  uniqBy,
  sleep,
  safeJsonParse,
  diffSet,
};
