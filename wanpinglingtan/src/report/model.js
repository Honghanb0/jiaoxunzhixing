'use strict';
/*
 * model.js — EASM 报告数据归一化（HTML / Markdown / DOCX 共用）
 * 将渲染进程传入的 reportData 整理为一致的模型：概览、审计结论、安全扫描、漏洞明细、资产清单，
 * 并合并「采集阶段漏洞」与「安全扫描派生漏洞」到统一的 vulns 列表。
 */

const { CATEGORY_COLUMNS } = require('./easm');

function buildReportModel(data) {
  data = data || {};
  const meta = data.meta || {};
  const generatedAt = (data.generatedAt || new Date().toISOString()).replace('T', ' ').slice(0, 19);
  const input = data.input || {};
  const summary = data.summary || {};
  const audit = data.audit || {};
  const security = data.security || [];
  const assets = data.assets || {};

  // 合并漏洞：采集阶段漏洞 + 安全扫描派生漏洞（统一结构）
  const vulns = [];
  for (const v of (assets.vulns || [])) vulns.push(v);
  for (const r of security) {
    for (const v of (r.vulns || [])) vulns.push(v);
  }

  // 各分类计数（用于漏洞分布概览）
  const catCount = {};
  for (const v of vulns) {
    const c = v.category || '其他';
    catCount[c] = (catCount[c] || 0) + 1;
  }

  return {
    appName: meta.appName || '万平灵探',
    version: meta.version || '1.0.0',
    generatedAt,
    input,
    summary,
    audit,
    security,
    assets,
    vulns,
    catCount,
    confirmedTargets: data.confirmedTargets || [],
    categoryColumns: CATEGORY_COLUMNS,
  };
}

function sevLabel(sev) {
  return { high: '高危', medium: '中危', low: '低危', info: '提示' }[sev] || '提示';
}

module.exports = { buildReportModel, sevLabel };
