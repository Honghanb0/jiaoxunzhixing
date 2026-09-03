'use strict';
/*
 * docx.js — 将报告模型渲染为真实的 .docx 文档（无第三方依赖）
 * 方案：手写最小 OOXML 包（[Content_Types].xml / _rels / word/document.xml / word/styles.xml），
 * 并用 Node 内置 zlib 的 deflate 自行组装 ZIP 容器（含 CRC32 校验）。
 * 这样无需安装 jszip / docx / archiver，在受限环境下也能稳定产出可被 Word / WPS 打开的 .docx。
 */

const zlib = require('zlib');
const { buildReportModel, sevLabel } = require('./model');
const { VULN_CATEGORIES } = require('../core/vuln-categories');

// ---------------------------------------------------------------------------
// ZIP（仅 deflate 存储，无需外部库）
// ---------------------------------------------------------------------------
function crc32(buf) {
  let c = ~0;
  for (let i = 0; i < buf.length; i++) {
    c ^= buf[i];
    for (let k = 0; k < 8; k++) c = (c >>> 1) ^ (0xEDB88320 & -(c & 1));
  }
  return (~c) >>> 0;
}

function zipSync(files) {
  const local = [];
  const central = [];
  let offset = 0;
  for (const f of files) {
    const nameBuf = Buffer.from(f.name, 'utf8');
    const data = f.data;
    const comp = zlib.deflateRawSync(data);
    const crc = crc32(data);
    const size = data.length;
    const compSize = comp.length;

    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0);
    lh.writeUInt16LE(20, 4);     // version needed
    lh.writeUInt16LE(0x0800, 6); // flags: UTF-8 文件名
    lh.writeUInt16LE(8, 8);      // method: deflate
    lh.writeUInt16LE(0, 10);     // mod time
    lh.writeUInt16LE(0, 12);     // mod date
    lh.writeUInt32LE(crc, 14);
    lh.writeUInt32LE(compSize, 18);
    lh.writeUInt32LE(size, 22);
    lh.writeUInt16LE(nameBuf.length, 26);
    lh.writeUInt16LE(0, 28);     // extra len
    local.push(lh, nameBuf, comp);

    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0);
    ch.writeUInt16LE(20, 4);     // version made by
    ch.writeUInt16LE(20, 6);     // version needed
    ch.writeUInt16LE(0x0800, 8); // flags: UTF-8
    ch.writeUInt16LE(8, 10);     // method: deflate
    ch.writeUInt16LE(0, 12);
    ch.writeUInt16LE(0, 14);
    ch.writeUInt32LE(crc, 16);
    ch.writeUInt32LE(compSize, 20);
    ch.writeUInt32LE(size, 24);
    ch.writeUInt16LE(nameBuf.length, 28);
    ch.writeUInt16LE(0, 30);
    ch.writeUInt16LE(0, 32);
    ch.writeUInt16LE(0, 34);
    ch.writeUInt16LE(0, 36);
    ch.writeUInt32LE(0, 38);
    ch.writeUInt32LE(offset, 42);
    central.push(ch, nameBuf);

    offset += lh.length + nameBuf.length + comp.length;
  }
  const centralBuf = Buffer.concat(central);
  const localBuf = Buffer.concat(local);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(0, 4);
  end.writeUInt16LE(0, 6);
  end.writeUInt16LE(files.length, 8);
  end.writeUInt16LE(files.length, 10);
  end.writeUInt32LE(centralBuf.length, 12);
  end.writeUInt32LE(offset, 16);
  end.writeUInt16LE(0, 20);
  return Buffer.concat([localBuf, centralBuf, end]);
}

// ---------------------------------------------------------------------------
// OOXML 构建
// ---------------------------------------------------------------------------
const W = 'http://schemas.openxmlformats.org/wordprocessingml/2006/main';

function escXml(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function runXml(text, bold) {
  const rPr = bold ? '<w:rPr><w:b/></w:rPr>' : '';
  return `<w:r>${rPr}<w:t xml:space="preserve">${escXml(text)}</w:t></w:r>`;
}

function paraXml(innerRuns, opts) {
  opts = opts || {};
  const pPr = opts.style ? `<w:pPr><w:pStyle w:val="${opts.style}"/></w:pPr>` : '';
  return `<w:p>${pPr}${innerRuns}</w:p>`;
}

function para(text, opts) {
  if (Array.isArray(text)) return paraXml(text.map((r) => runXml(r.text, r.bold)).join(''), opts);
  return paraXml(runXml(text), opts);
}

function heading(text, level) {
  const style = level === 0 ? 'Title' : 'Heading' + level;
  return paraXml(runXml(text, level === 0), { style });
}

function bullet(text) {
  return paraXml(runXml('•  ' + text), {});
}

function tableXml(headers, rows) {
  const n = headers.length;
  const colW = Math.floor(9026 / n);
  const grid = headers.map(() => `<w:gridCol w:w="${colW}"/>`).join('');
  const cell = (content, isHeader) => {
    const shd = isHeader ? '<w:shd w:val="clear" w:color="auto" w:fill="D9E2F3"/>' : '';
    return `<w:tc><w:tcPr><w:tcW w:w="${colW}" w:type="dxa"/>${shd}</w:tcPr><w:p>${runXml(String(content == null ? '' : content), isHeader)}</w:p></w:tc>`;
  };
  const headerTr = `<w:tr>${headers.map((h) => cell(String(h), true)).join('')}</w:tr>`;
  const bodyTrs = rows.map((r) => `<w:tr>${r.map((c) => cell(c, false)).join('')}</w:tr>`).join('');
  return `<w:tbl><w:tblPr><w:tblStyle w:val="TableGrid"/><w:tblW w:w="0" w:type="auto"/>`
    + `<w:tblBorders>`
    + `<w:top w:val="single" w:sz="4" w:space="0" w:color="999999"/>`
    + `<w:left w:val="single" w:sz="4" w:space="0" w:color="999999"/>`
    + `<w:bottom w:val="single" w:sz="4" w:space="0" w:color="999999"/>`
    + `<w:right w:val="single" w:sz="4" w:space="0" w:color="999999"/>`
    + `<w:insideH w:val="single" w:sz="4" w:space="0" w:color="999999"/>`
    + `<w:insideV w:val="single" w:sz="4" w:space="0" w:color="999999"/>`
    + `</w:tblBorders></w:tblPr>`
    + `<w:tblGrid>${grid}</w:tblGrid>`
    + headerTr + bodyTrs + `</w:tbl>`;
}

// ---------------------------------------------------------------------------
// 报告内容（纯文本/表格块）渲染为 document.xml body
// ---------------------------------------------------------------------------
function buildBody(m) {
  const body = [];
  const app = m.appName;
  body.push(heading(`${app} · 外部攻击面（EASM）测绘报告`, 0));
  body.push(para(`版本 ${m.version}　|　生成时间 ${m.generatedAt}　|　目标：${m.input.rootDomain || m.input.ipRange || '—'}`));

  // 一、概览
  body.push(heading('一、概览', 1));
  const s = m.summary;
  body.push(tableXml(
    ['指标', '数量'],
    [
      ['子域名', s.subdomains || 0], ['IP资产', s.ips || 0], ['邮箱', s.emails || 0],
      ['敏感信息', s.leaks || 0], ['端口', s.ports || 0], ['指纹', s.fingerprints || 0],
      ['漏洞/配置', s.vulns || 0], ['确认资产', s.confirmedAssets || 0], ['高危项', s.riskHigh || 0],
    ].map(([k, v]) => [k, String(v)])
  ));

  // 二、人工审计结论
  const a = m.audit;
  body.push(heading('二、人工审计结论', 1));
  body.push(para(`共 ${a.total || 0} 项待审计资产 · 确认为真实资产 ${a.real || 0} · 判定为误报 ${a.falsePositive || 0} · 未判定 ${a.pending || 0}`));
  if (m.confirmedTargets.length) {
    body.push(para('已对以下确认资产执行安全扫描：'));
    for (const t of m.confirmedTargets) body.push(bullet(`${t.target}（${t.type}）`));
  }

  // 三、安全扫描结果
  body.push(heading('三、安全扫描结果', 1));
  if (!m.security.length) {
    body.push(para('未执行安全扫描（请先在「人工审计」中确认资产并启动扫描）。'));
  } else {
    let h = 0, mid = 0, low = 0;
    for (const r of m.security) {
      if (r.riskLevel === '高') h++;
      else if (r.riskLevel === '中') mid++;
      else if (r.riskLevel === '低') low++;
    }
    body.push(para(`风险分布：高危 ${h} · 中危 ${mid} · 低危 ${low}`));
    body.push(tableXml(
      ['目标', '类型', '可达', '延迟', '地理位置', '开放端口', '风险'],
      m.security.map((r) => [r.target, r.type, r.alive, r.latency, r.geo, r.openPorts, r.riskLevel])
    ));
    for (const r of m.security) {
      if (r.detail && r.detail !== '未发现高危指纹') {
        body.push(para(`${r.target} 详情：`));
        for (const line of String(r.detail).split('|')) {
          const t = line.trim();
          if (t) body.push(bullet(t));
        }
      }
    }
  }

  // 四、漏洞 / 配置明细
  body.push(heading('四、漏洞 / 配置明细', 1));
  if (!m.vulns.length) {
    body.push(para('未发现漏洞/配置风险。'));
  } else {
    body.push(para('分类统计：' + VULN_CATEGORIES.map((c) => `${c} ${m.catCount[c] || 0}`).join('，')));
    body.push(tableXml(
      ['目标', '严重度', '分类', '标题', '说明'],
      m.vulns.map((v) => [v.host, sevLabel(v.severity), v.category, v.title, v.detail])
    ));
  }

  // 五、资产发现清单
  body.push(heading('五、资产发现清单', 1));
  for (const [key, cfg] of Object.entries(m.categoryColumns)) {
    const rows = m.assets[key] || [];
    if (!rows.length) continue;
    body.push(heading(`${cfg.label}（${rows.length}）`, 2));
    body.push(tableXml(
      cfg.cols.map(([, label]) => label),
      rows.map((r) => cfg.cols.map(([field]) => {
        let val = r[field];
        if (Array.isArray(val)) val = val.join(', ');
        return val == null ? '' : String(val).replace(/\r?\n/g, ' ');
      }))
    ));
  }

  // 免责声明
  body.push(para([
    { text: '合规与免责声明：', bold: true },
    { text: `本报告由 ${app} 自动生成，仅用于已授权资产的安全评估与攻击面管理。所有探测均为被动/只读式，不含任何破坏性操作。请确保对扫描目标拥有合法授权，遵守《网络安全法》等相关法律法规，不得将本报告用于未授权目标。报告中的风险判定为初步筛查结果，最终以人工复核为准。` },
  ]));

  return body.join('');
}

// ---------------------------------------------------------------------------
// 包内 XML 常量
// ---------------------------------------------------------------------------
const CONTENT_TYPES = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>
</Types>`;

const ROOT_RELS = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>`;

const DOC_RELS = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
</Relationships>`;

const STYLES = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles xmlns:w="${W}">
<w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" w:eastAsia="宋体"/><w:sz w:val="21"/></w:rPr></w:rPrDefault></w:docDefaults>
<w:style w:type="paragraph" w:styleId="Normal"><w:name w:val="Normal"/><w:qFormat/></w:style>
<w:style w:type="paragraph" w:styleId="Title"><w:name w:val="Title"/><w:basedOn w:val="Normal"/><w:pPr><w:spacing w:before="120" w:after="120"/></w:pPr><w:rPr><w:b/><w:sz w:val="40"/><w:color w:val="1F3864"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:pPr><w:keepNext/><w:spacing w:before="200" w:after="80"/><w:outlineLvl w:val="0"/></w:pPr><w:rPr><w:b/><w:sz w:val="30"/><w:color w:val="1F3864"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:pPr><w:keepNext/><w:spacing w:before="160" w:after="60"/><w:outlineLvl w:val="1"/></w:pPr><w:rPr><w:b/><w:sz w:val="26"/><w:color w:val="2E5496"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading3"><w:name w:val="heading 3"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:pPr><w:keepNext/><w:spacing w:before="120" w:after="40"/><w:outlineLvl w:val="2"/></w:pPr><w:rPr><w:b/><w:sz w:val="23"/><w:color w:val="2E5496"/></w:rPr></w:style>
<w:style w:type="table" w:styleId="TableGrid"><w:name w:val="Table Grid"/><w:tblPr><w:tblBorders><w:top w:val="single" w:sz="4" w:space="0" w:color="999999"/><w:left w:val="single" w:sz="4" w:space="0" w:color="999999"/><w:bottom w:val="single" w:sz="4" w:space="0" w:color="999999"/><w:right w:val="single" w:sz="4" w:space="0" w:color="999999"/><w:insideH w:val="single" w:sz="4" w:space="0" w:color="999999"/><w:insideV w:val="single" w:sz="4" w:space="0" w:color="999999"/></w:tblBorders></w:tblPr></w:style>
</w:styles>`;

function buildEasmReportDocxBuffer(data) {
  const m = buildReportModel(data);
  const body = buildBody(m);
  const documentXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="${W}" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
<w:body>
${body}
<w:sectPr><w:pgSz w:w="11906" w:h="16838"/><w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440" w:header="720" w:footer="720" w:gutter="0"/></w:sectPr>
</w:body>
</w:document>`;

  const files = [
    { name: '[Content_Types].xml', data: Buffer.from(CONTENT_TYPES, 'utf8') },
    { name: '_rels/.rels', data: Buffer.from(ROOT_RELS, 'utf8') },
    { name: 'word/document.xml', data: Buffer.from(documentXml, 'utf8') },
    { name: 'word/styles.xml', data: Buffer.from(STYLES, 'utf8') },
    { name: 'word/_rels/document.xml.rels', data: Buffer.from(DOC_RELS, 'utf8') },
  ];
  return zipSync(files);
}

module.exports = { buildEasmReportDocxBuffer };
