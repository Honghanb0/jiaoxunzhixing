'use strict';
/*
 * easm.js — 格式化 EASM（外部攻击面管理）报告生成
 * 输入由渲染进程组装的 reportData，输出自包含 HTML 字符串（内联样式 + 打印样式）。
 * 报告中含：概览、资产发现清单、人工审计结论、安全扫描结果、风险分布、免责声明。
 */

function esc(v) {
  if (v === null || v === undefined) return '';
  return String(v)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function riskClass(level) {
  if (level === '高') return 'risk-high';
  if (level === '中') return 'risk-mid';
  if (level === '低') return 'risk-low';
  if (level === '安全') return 'risk-safe';
  return 'risk-unknown';
}

function sevLabelV(sev) {
  return { high: '高危', medium: '中危', low: '低危', info: '提示' }[sev] || '提示';
}

// 各资产分类的展示列配置（key -> 中文表头），按重要性取前若干字段
const CATEGORY_COLUMNS = {
  subdomains: { label: '子域名', cols: [['host', '子域名'], ['ips', '解析IP'], ['source', '来源']] },
  domains: { label: '根域名', cols: [['host', '域名'], ['source', '来源']] },
  ips: { label: 'IP资产', cols: [['ip', 'IP'], ['hosts', '关联域名'], ['scope', '归属'], ['confidence', '置信']] },
  emails: { label: '邮箱', cols: [['email', '邮箱'], ['source', '来源'], ['confidence', '置信']] },
  leaks: { label: '敏感信息', cols: [['title', '标题'], ['source', '来源'], ['confidence', '置信']] },
  records: { label: 'DNS记录', cols: [['type', '类型'], ['host', '主机'], ['value', '记录值']] },
  whois: { label: 'WHOIS', cols: [['domain', '域名'], ['registrar', '注册商'], ['registrant', '注册人']] },
  ports: { label: '端口', cols: [['target', '目标'], ['port', '端口'], ['service', '服务'], ['state', '状态']] },
  fingerprints: { label: '指纹', cols: [['target', '目标'], ['tech', '技术栈'], ['waf', 'WAF']] },
  vulns: { label: '漏洞/配置', cols: [['target', '目标'], ['type', '类型'], ['severity', '严重度'], ['detail', '说明']] },
  enterprise: { label: '企业信息', cols: [['name', '名称'], ['icp', 'ICP备案'], ['source', '来源']] },
  search: { label: '资产搜索', cols: [['title', '标题'], ['ip', 'IP'], ['port', '端口'], ['source', '来源']] },
};

function renderAssetTables(data) {
  const assets = data.assets || {};
  let html = '';
  for (const [key, cfg] of Object.entries(CATEGORY_COLUMNS)) {
    const rows = assets[key] || [];
    if (!rows.length) continue;
    html += `<section class="block"><h2>${esc(cfg.label)}（${rows.length}）</h2>`;
    html += '<table><thead><tr>';
    for (const [, label] of cfg.cols) html += `<th>${esc(label)}</th>`;
    html += '</tr></thead><tbody>';
    for (const r of rows) {
      html += '<tr>';
      for (const [field] of cfg.cols) {
        let val = r[field];
        if (Array.isArray(val)) val = val.join(', ');
        html += `<td>${esc(val)}</td>`;
      }
      html += '</tr>';
    }
    html += '</tbody></table></section>';
  }
  if (!html) html = '<section class="block"><p class="muted">本次采集未产生资产清单数据。</p></section>';
  return html;
}

function renderSummaryCards(data) {
  const s = data.summary || {};
  const cards = [
    ['子域名', s.subdomains || 0],
    ['IP资产', s.ips || 0],
    ['邮箱', s.emails || 0],
    ['敏感信息', s.leaks || 0],
    ['端口', s.ports || 0],
    ['指纹', s.fingerprints || 0],
    ['漏洞/配置', s.vulns || 0],
    ['确认资产', s.confirmedAssets || 0],
    ['高危项', s.riskHigh || 0],
  ];
  return '<div class="cards">' + cards.map(([k, v]) =>
    `<div class="card"><div class="card-v">${esc(v)}</div><div class="card-k">${esc(k)}</div></div>`
  ).join('') + '</div>';
}

function renderAuditSection(data) {
  const a = data.audit || {};
  const real = a.real || 0;
  const fp = a.falsePositive || 0;
  const pend = a.pending || 0;
  const total = a.total || (real + fp + pend);
  let html = `<section class="block"><h2>人工审计结论</h2>`;
  html += `<div class="audit-summary">共 <b>${esc(total)}</b> 项待审计资产 · 确认为真实资产 <b class="ok">${esc(real)}</b> · 判定为误报 <b class="bad">${esc(fp)}</b> · 未判定 <b>${esc(pend)}</b></div>`;
  if (data.confirmedTargets && data.confirmedTargets.length) {
    html += '<p class="muted">已对以下确认资产执行安全扫描：</p><ul class="target-list">';
    for (const t of data.confirmedTargets) {
      html += `<li>${esc(t.target)} <span class="tag">${esc(t.type)}</span></li>`;
    }
    html += '</ul>';
  }
  html += '</section>';
  return html;
}

function renderSecuritySection(data) {
  const sec = data.security || [];
  if (!sec.length) {
    return '<section class="block"><h2>安全扫描结果</h2><p class="muted">未执行安全扫描（请先在「人工审计」中确认资产并启动扫描）。</p></section>';
  }
  let high = 0, mid = 0, low = 0;
  for (const r of sec) {
    if (r.riskLevel === '高') high++;
    else if (r.riskLevel === '中') mid++;
    else if (r.riskLevel === '低') low++;
  }
  let html = `<section class="block"><h2>安全扫描结果（${sec.length}）</h2>`;
  html += `<div class="risk-dist">风险分布：<span class="risk-high">高危 ${high}</span> · <span class="risk-mid">中危 ${mid}</span> · <span class="risk-low">低危 ${low}</span></div>`;
  html += '<table><thead><tr><th>目标</th><th>类型</th><th>可达性</th><th>延迟</th><th>地理位置</th><th>开放端口</th><th>高危指纹/发现</th><th>风险</th></tr></thead><tbody>';
  for (const r of sec) {
    html += `<tr>
      <td>${esc(r.target)}</td>
      <td>${esc(r.type)}</td>
      <td>${esc(r.alive)}</td>
      <td>${esc(r.latency)}</td>
      <td>${esc(r.geo)}</td>
      <td>${esc(r.openPorts)}</td>
      <td>${esc(r.fingerprints)}</td>
      <td class="${riskClass(r.riskLevel)}">${esc(r.riskLevel)}</td>
    </tr>`;
    if (r.detail && r.detail !== '未发现高危指纹') {
      html += `<tr class="detail-row"><td colspan="8"><div class="detail">${esc(r.detail)}</div></td></tr>`;
    }
    // 该目标关联出的漏洞（带分类标签 + 严重度）
    if (r.vulns && r.vulns.length) {
      const vhtml = r.vulns.map((v) => {
        const sevCls = { high: 'risk-high', medium: 'risk-mid', low: 'risk-low', info: '' }[v.severity] || '';
        const cat = v.category ? `<span class="tag cat-tag cat-${esc(v.category)}">${esc(v.category)}</span>` : '';
        return `<div class="vuln-row"><span class="${sevCls}">[${esc(sevLabelV(v.severity))}]</span>${cat} ${esc(v.title || v.type || '')}</div>`;
      }).join('');
      html += `<tr class="detail-row"><td colspan="8"><div class="detail"><b>关联漏洞（${r.vulns.length}）：</b>${vhtml}</div></td></tr>`;
    }
  }
  html += '</tbody></table></section>';
  return html;
}

function renderVulnSection(data) {
  const assets = (data.assets || {});
  const security = data.security || [];
  const vulns = [];
  for (const v of (assets.vulns || [])) vulns.push(v);
  for (const r of security) {
    for (const v of (r.vulns || [])) vulns.push(v);
  }
  if (!vulns.length) {
    return '<section class="block"><h2>漏洞 / 配置明细</h2><p class="muted">未发现漏洞/配置风险。</p></section>';
  }
  const catCount = {};
  for (const v of vulns) {
    const c = v.category || '其他';
    catCount[c] = (catCount[c] || 0) + 1;
  }
  let html = `<section class="block"><h2>漏洞 / 配置明细（${vulns.length}）</h2>`;
  const stat = Object.entries(catCount).map(([c, n]) => `${esc(c)} ${n}`).join('　|　');
  html += `<div class="risk-dist">分类统计：${stat}</div>`;
  html += '<table><thead><tr><th>目标</th><th>严重度</th><th>分类</th><th>标题</th><th>说明</th></tr></thead><tbody>';
  for (const v of vulns) {
    const sevCls = { high: 'risk-high', medium: 'risk-mid', low: 'risk-low', info: '' }[v.severity] || '';
    const cat = v.category ? `<span class="cat-tag cat-${esc(v.category)}">${esc(v.category)}</span>` : '';
    html += `<tr><td>${esc(v.host)}</td><td class="${sevCls}">${sevLabelV(v.severity)}</td><td>${cat}</td><td>${esc(v.title)}</td><td>${esc(v.detail)}</td></tr>`;
  }
  html += '</tbody></table></section>';
  return html;
}

function buildEasmReportHtml(data) {
  data = data || {};
  const input = data.input || {};
  const meta = data.meta || {};
  const generatedAt = (data.generatedAt || new Date().toISOString()).replace('T', ' ').slice(0, 19);
  const appName = meta.appName || '万平灵探';
  const version = meta.version || '1.0.0';

  const css = `
    * { box-sizing: border-box; }
    body { font-family: -apple-system, "Segoe UI", "Microsoft YaHei", sans-serif; color:#1f2937; margin:0; background:#f5f7fa; }
    .page { max-width: 1180px; margin: 0 auto; padding: 28px 32px 60px; background:#fff; }
    header.top { border-bottom: 3px solid #2563eb; padding-bottom: 14px; margin-bottom: 18px; }
    header.top h1 { margin:0; font-size: 26px; color:#0f172a; }
    header.top .sub { color:#64748b; margin-top:6px; font-size:13px; }
    h2 { font-size: 17px; color:#1e3a8a; border-left: 4px solid #2563eb; padding-left:10px; margin: 26px 0 12px; }
    .cards { display:flex; flex-wrap:wrap; gap:12px; margin: 10px 0 6px; }
    .card { background:#f1f5f9; border:1px solid #e2e8f0; border-radius:10px; padding:12px 16px; min-width:96px; text-align:center; }
    .card-v { font-size: 22px; font-weight:700; color:#0f172a; }
    .card-k { font-size: 12px; color:#64748b; margin-top:4px; }
    table { width:100%; border-collapse: collapse; font-size:13px; margin-bottom: 8px; }
    th, td { border:1px solid #e5e7eb; padding:7px 9px; text-align:left; vertical-align:top; }
    th { background:#f8fafc; color:#334155; font-weight:600; }
    tbody tr:nth-child(even) { background:#fafbfc; }
    .detail-row td { background:#fff7ed; }
    .detail { white-space: pre-wrap; font-size:12px; color:#7c2d12; }
    .risk-high { color:#dc2626; font-weight:700; }
    .risk-mid { color:#d97706; font-weight:700; }
    .risk-low { color:#2563eb; font-weight:600; }
    .risk-safe { color:#16a34a; font-weight:600; }
    .risk-unknown { color:#64748b; }
    .audit-summary { font-size:14px; }
    .ok { color:#16a34a; } .bad { color:#dc2626; }
    .target-list { columns: 3; font-size:12px; color:#334155; }
    .tag { background:#e0e7ff; color:#3730a3; border-radius:4px; padding:1px 6px; font-size:11px; margin-left:4px; }
    .muted { color:#94a3b8; font-size:12px; }
    .vuln-row { font-size:12px; margin:3px 0; }
    .cat-tag { display:inline-block; padding:1px 7px; border-radius:10px; font-size:11px; font-weight:600; margin-left:4px; border:1px solid transparent; }
    .cat-文件上传 { color:#b45309; background:rgba(245,158,11,.16); }
    .cat-反序列化 { color:#7c3aed; background:rgba(124,58,237,.16); }
    .cat-SSRF { color:#0d9488; background:rgba(13,148,136,.16); }
    .cat-CSRF { color:#2563eb; background:rgba(37,99,235,.16); }
    .cat-未授权访问 { color:#dc2626; background:rgba(220,38,38,.16); }
    .cat-SQL注入 { color:#ea580c; background:rgba(234,88,12,.16); }
    .cat-XSS { color:#db2777; background:rgba(219,39,119,.16); }
    .cat-整数溢出 { color:#4f46e5; background:rgba(79,70,229,.16); }
    .cat-代码注入 { color:#be123c; background:rgba(190,18,60,.16); }
    .cat-路径遍历 { color:#0891b2; background:rgba(8,145,178,.16); }
    .cat-缓冲区溢出 { color:#6d28d9; background:rgba(109,40,217,.16); }
    .cat-其他 { color:#64748b; background:rgba(100,116,139,.16); }
    .disclaimer { margin-top: 30px; padding:14px 16px; background:#f8fafc; border:1px dashed #cbd5e1; border-radius:8px; font-size:12px; color:#475569; }
    @media print { body { background:#fff; } .page { padding:0; } h2 { page-break-after: avoid; } table { page-break-inside: avoid; } }
  `;

  const inputLine = [
    input.rootDomain && `根域名：${input.rootDomain}`,
    input.ipRange && `IP范围：${input.ipRange}`,
    input.companyShort && `企业简称：${input.companyShort}`,
    input.emailSuffix && `邮箱后缀：${input.emailSuffix}`,
  ].filter(Boolean).join('　|　');

  return `<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<title>${esc(appName)} EASM 报告</title>
<style>${css}</style></head>
<body><div class="page">
  <header class="top">
    <h1>${esc(appName)} · 外部攻击面（EASM）测绘报告</h1>
    <div class="sub">版本 ${esc(version)}　|　生成时间 ${esc(generatedAt)}　|　目标：${esc(input.rootDomain || input.ipRange || '—')}</div>
  </header>
  ${inputLine ? `<div class="sub" style="margin-bottom:14px">${esc(inputLine)}</div>` : ''}
  <h2>一、概览</h2>
  ${renderSummaryCards(data)}
  <h2>二、人工审计结论</h2>
  ${renderAuditSection(data)}
  <h2>三、安全扫描结果</h2>
  ${renderSecuritySection(data)}
  <h2>四、漏洞 / 配置明细</h2>
  ${renderVulnSection(data)}
  <h2>五、资产发现清单</h2>
  ${renderAssetTables(data)}
  <div class="disclaimer">
    <b>合规与免责声明：</b>本报告由 ${esc(appName)} 自动生成，仅用于已授权资产的安全评估与攻击面管理。
    所有探测均为被动/只读式，不含任何破坏性操作。请确保对扫描目标拥有合法授权，遵守《网络安全法》等相关法律法规，
    不得将本报告用于未授权目标。报告中的风险判定为初步筛查结果，最终以人工复核为准。
  </div>
</div></body></html>`;
}

module.exports = { buildEasmReportHtml, esc, CATEGORY_COLUMNS };
