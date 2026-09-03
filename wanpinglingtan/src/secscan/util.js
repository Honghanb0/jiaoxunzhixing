'use strict';
/*
 * util.js — 通用工具：并发池、带超时的 fetch、CSV 转义
 */

// 带超时的 fetch（Node 18+ 内置 fetch）
async function fetchWithTimeout(url, options = {}, timeoutMs = 6000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, { ...options, signal: controller.signal });
    return res;
  } finally {
    clearTimeout(timer);
  }
}

// 简易并发池：对 items 应用 worker，限制并发数，边执行边回调 onProgress(done, total)
async function runPool(items, worker, concurrency = 24, onProgress) {
  const total = items.length;
  let index = 0;
  let done = 0;
  const results = new Array(total);

  async function runOne() {
    while (index < total) {
      const i = index++;
      try {
        results[i] = await worker(items[i], i);
      } catch (e) {
        results[i] = { __error: String(e && e.message ? e.message : e) };
      }
      done++;
      if (onProgress) onProgress(done, total, results[i], i);
    }
  }

  const pool = [];
  const n = Math.min(concurrency, total);
  for (let i = 0; i < n; i++) pool.push(runOne());
  await Promise.all(pool);
  return results;
}

// CSV 字段转义
function csvField(v) {
  if (v === null || v === undefined) v = '';
  const s = String(v);
  if (/[",\n\r]/.test(s)) {
    return '"' + s.replace(/"/g, '""') + '"';
  }
  return s;
}

// CSV 生成：keys 为行对象字段名（英文），headers 为导出表头（中文），二者顺序一一对应
function toCsv(keys, headers, rows) {
  const keyArr = Array.isArray(keys) ? keys : headers;
  const headArr = Array.isArray(headers) ? headers : keys;
  const lines = [headArr.map(csvField).join(',')];
  for (const r of rows) {
    lines.push(keyArr.map((k) => csvField(r == null ? '' : r[k])).join(','));
  }
  // 加 BOM 以便 Excel 正确识别 UTF-8
  return '﻿' + lines.join('\r\n');
}

module.exports = { fetchWithTimeout, runPool, csvField, toCsv };
