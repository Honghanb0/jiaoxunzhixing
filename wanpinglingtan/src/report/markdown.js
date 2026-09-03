'use strict';
/*
 * markdown.js — 将报告模型渲染为 Markdown 文本
 * 与 HTML 报告结构对齐：概览、人工审计结论、安全扫描结果、漏洞明细（带分类标签）、资产清单、免责声明。
 */

const { buildReportModel, sevLabel } = require('./model');
const { VULN_CATEGORIES } = require('../core/vuln-categories');

// 转义表格单元格中的特殊字符（反斜杠、竖线、换行）
function cell(s) {
  return String(s == null ? '' : s)
    .replace(/\\/g, '\\\\')
    .replace(/\|/g, '\\|')
    .replace(/\r?\n/g, ' ')
    .trim();
}

function mdTable(headers, rows) {
  const lines = [];
  lines.push('| ' + headers.join(' | ') + ' |');
  lines.push('| ' + headers.map(() => '---').join(' | ') + ' |');
  for (const r of rows) lines.push('| ' + r.map(cell).join(' | ') + ' |');
  return lines.join('\n');
}

function buildEasmReportMarkdown(data) {
  const m = buildReportModel(data);
  const L = [];
  const app = m.appName;

  L.push(`# ${app} · 外部攻击面（EASM）测绘报告`);
  L.push('', `> 版本 ${m.version}　|　生成时间 ${m.generatedAt}　|　目标：${m.input.rootDomain || m.input.ipRange || '—'}`);
  const inParts = [
    m.input.rootDomain && `根域名：${m.input.rootDomain}`,
    m.input.ipRange && `IP范围：${m.input.ipRange}`,
    m.input.companyShort && `企业简称：${m.input.companyShort}`,
    m.input.emailSuffix && `邮箱后缀：${m.input.emailSuffix}`,
  ].filter(Boolean);
  if (inParts.length) L.push('', inParts.join('　|　'));

  // 一、概览
  L.push('', '## 一、概览');
  const s = m.summary;
  const cards = [
    ['子域名', s.subdomains || 0], ['IP资产', s.ips || 0], ['邮箱', s.emails || 0],
    ['敏感信息', s.leaks || 0], ['端口', s.ports || 0], ['指纹', s.fingerprints || 0],
    ['漏洞/配置', s.vulns || 0], ['确认资产', s.confirmedAssets || 0], ['高危项', s.riskHigh || 0],
  ];
  L.push('', mdTable(['指标', '数量'], cards.map(([k, v]) => [k, String(v)])));

  // 二、人工审计结论
  const a = m.audit;
  L.push('', '## 二、人工审计结论');
  L.push('', `共 **${a.total || 0}** 项待审计资产 · 确认为真实资产 **${a.real || 0}** · 判定为误报 **${a.falsePositive || 0}** · 未判定 **${a.pending || 0}**`);
  if (m.confirmedTargets.length) {
    L.push('', '已对以下确认资产执行安全扫描：');
    for (const t of m.confirmedTargets) L.push(`- ${t.target} \`${t.type}\``);
  }

  // 三、安全扫描结果
  L.push('', '## 三、安全扫描结果');
  if (!m.security.length) {
    L.push('', '未执行安全扫描（请先在「人工审计」中确认资产并启动扫描）。');
  } else {
    let h = 0, mid = 0, low = 0;
    for (const r of m.security) {
      if (r.riskLevel === '高') h++;
      else if (r.riskLevel === '中') mid++;
      else if (r.riskLevel === '低') low++;
    }
    L.push('', `风险分布：高危 ${h} · 中危 ${mid} · 低危 ${low}`);
    L.push('', mdTable(
      ['目标', '类型', '可达', '延迟', '地理位置', '开放端口', '风险'],
      m.security.map((r) => [r.target, r.type, r.alive, r.latency, r.geo, r.openPorts, r.riskLevel])
    ));
    for (const r of m.security) {
      if (r.detail && r.detail !== '未发现高危指纹') {
        L.push('', `**${cell(r.target)} 详情：**`);
        for (const line of String(r.detail).split('|')) {
          const t = line.trim();
          if (t) L.push(`  - ${cell(t)}`);
        }
      }
    }
  }

  // 四、漏洞 / 配置明细
  L.push('', '## 四、漏洞 / 配置明细');
  if (!m.vulns.length) {
    L.push('', '未发现漏洞/配置风险。');
  } else {
    L.push('', '**分类统计：** ' + VULN_CATEGORIES.map((c) => `${c} ${m.catCount[c] || 0}`).join('，'));
    L.push('', mdTable(
      ['目标', '严重度', '分类', '标题', '说明'],
      m.vulns.map((v) => [v.host, sevLabel(v.severity), v.category, v.title, v.detail])
    ));
  }

  // 五、资产发现清单
  L.push('', '## 五、资产发现清单');
  for (const [key, cfg] of Object.entries(m.categoryColumns)) {
    const rows = m.assets[key] || [];
    if (!rows.length) continue;
    L.push('', `### ${cfg.label}（${rows.length}）`);
    L.push('', mdTable(
      cfg.cols.map(([, label]) => label),
      rows.map((r) => cfg.cols.map(([field]) => {
        let val = r[field];
        if (Array.isArray(val)) val = val.join(', ');
        return val;
      }))
    ));
  }

  // 免责声明
  L.push('', '---', '', `**合规与免责声明：** 本报告由 ${app} 自动生成，仅用于已授权资产的安全评估与攻击面管理。`
    + '所有探测均为被动/只读式，不含任何破坏性操作。请确保对扫描目标拥有合法授权，遵守《网络安全法》等相关法律法规，'
    + '不得将本报告用于未授权目标。报告中的风险判定为初步筛查结果，最终以人工复核为准。');

  return L.join('\n');
}

module.exports = { buildEasmReportMarkdown };
