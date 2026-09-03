'use strict';
/*
 * security.js — 高危指纹安全扫描
 * 输入：IPv4 或域名（每行一个）
 * 检测维度：
 *   1) 敏感端口开放（数据库/缓存/远程管理/明文服务等）
 *   2) 已知漏洞特征 / 危险组件标识（基于 high_risk_fingerprint_db.json 结构化规则匹配）
 *   3) 未授权访问（Redis / Elasticsearch / Memcached / Docker / etcd / Hadoop 等）
 * 输出：结构化结果，含 目标信息、命中指纹类型、风险等级。
 *
 * 资源控制：
 *   - 端口探测超时、指纹探测超时均显式限制
 *   - 目标级并发、单目标内端口并发均受限，避免资源滥用
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const dns = require('dns').promises;
const net = require('net');
const geo = require('./geo');
const { fetchWithTimeout, runPool } = require('./util');
const { tcpConnect } = require('./port');
const { EXT_FINGERPRINTS } = require('./ext_fingerprints');
const { mapVulnCategory } = require('../core/vuln-categories');

// 敏感端口指纹库：开放即作为一条基础发现
const SENSITIVE_PORTS = [
  { port: 21, service: 'FTP', severity: '中', category: '敏感端口', desc: 'FTP 明文文件传输，凭证存在泄露风险' },
  { port: 22, service: 'SSH', severity: '低', category: '敏感端口', desc: 'SSH 远程登录，可能遭遇暴力破解' },
  { port: 23, service: 'Telnet', severity: '高', category: '敏感端口', desc: 'Telnet 明文远程登录，极不安全' },
  { port: 25, service: 'SMTP', severity: '低', category: '敏感端口', desc: 'SMTP 邮件服务' },
  { port: 53, service: 'DNS', severity: '低', category: '敏感端口', desc: 'DNS 服务' },
  { port: 80, service: 'HTTP', severity: '低', category: '敏感端口', desc: 'HTTP Web 服务' },
  { port: 110, service: 'POP3', severity: '低', category: '敏感端口', desc: 'POP3 邮件收取' },
  { port: 111, service: 'RPCBind', severity: '中', category: '敏感端口', desc: 'RPCBind 服务' },
  { port: 135, service: 'MS-RPC', severity: '中', category: '敏感端口', desc: 'MS RPC 服务' },
  { port: 139, service: 'NetBIOS', severity: '中', category: '敏感端口', desc: 'NetBIOS 会话服务' },
  { port: 161, service: 'SNMP', severity: '中', category: '敏感端口', desc: 'SNMP 明文团体字风险' },
  { port: 443, service: 'HTTPS', severity: '低', category: '敏感端口', desc: 'HTTPS Web 服务' },
  { port: 445, service: 'SMB', severity: '高', category: '敏感端口', desc: 'SMB 文件共享，警惕永恒之蓝类漏洞' },
  { port: 512, service: 'rexec', severity: '高', category: '敏感端口', desc: 'rexec 远程执行' },
  { port: 513, service: 'rlogin', severity: '高', category: '敏感端口', desc: 'rlogin 明文远程登录' },
  { port: 514, service: 'rsh', severity: '高', category: '敏感端口', desc: 'rsh 远程 shell' },
  { port: 873, service: 'Rsync', severity: '中', category: '敏感端口', desc: 'Rsync 未授权访问风险' },
  { port: 1433, service: 'MSSQL', severity: '高', category: '数据库端口', desc: 'SQL Server 数据库暴露' },
  { port: 1521, service: 'Oracle', severity: '高', category: '数据库端口', desc: 'Oracle 数据库暴露' },
  { port: 2049, service: 'NFS', severity: '中', category: '敏感端口', desc: 'NFS 文件共享' },
  { port: 2375, service: 'Docker', severity: '高', category: '未授权访问', desc: 'Docker API 未授权访问（可接管宿主机）' },
  { port: 2379, service: 'etcd', severity: '高', category: '未授权访问', desc: 'etcd 未授权访问（可读取集群配置）' },
  { port: 3306, service: 'MySQL', severity: '高', category: '数据库端口', desc: 'MySQL 数据库暴露' },
  { port: 3389, service: 'RDP', severity: '中', category: '敏感端口', desc: 'RDP 远程桌面暴露' },
  { port: 5432, service: 'PostgreSQL', severity: '高', category: '数据库端口', desc: 'PostgreSQL 数据库暴露' },
  { port: 5900, service: 'VNC', severity: '中', category: '敏感端口', desc: 'VNC 远程桌面' },
  { port: 5984, service: 'CouchDB', severity: '中', category: '未授权访问', desc: 'CouchDB 未授权访问风险' },
  { port: 6379, service: 'Redis', severity: '高', category: '未授权访问', desc: 'Redis 未授权访问（可写入文件/执行命令）' },
  { port: 7001, service: 'WebLogic', severity: '中', category: '漏洞组件', desc: 'WebLogic 中间件，存在多个历史 RCE 漏洞' },
  { port: 8080, service: 'HTTP-Alt', severity: '中', category: '管理后台', desc: 'HTTP 备用端口/管理后台' },
  { port: 8161, service: 'ActiveMQ', severity: '中', category: '漏洞组件', desc: 'ActiveMQ 消息队列，存在历史漏洞' },
  { port: 9200, service: 'Elasticsearch', severity: '高', category: '未授权访问', desc: 'Elasticsearch 未授权访问（可读取全部数据）' },
  { port: 11211, service: 'Memcached', severity: '高', category: '未授权访问', desc: 'Memcached 未授权访问（可反射放大/数据泄露）' },
  { port: 27017, service: 'MongoDB', severity: '高', category: '数据库端口', desc: 'MongoDB 数据库暴露' },
  { port: 50070, service: 'Hadoop', severity: '高', category: '未授权访问', desc: 'Hadoop NameNode 未授权访问' },
  // —— 扩展端口（参照 FingerprintHub / wscan-Fingerprint 高频高危面）——
  { port: 389, service: 'LDAP', severity: '中', category: '敏感端口', desc: 'LDAP 目录服务，明文认证存在凭据泄露风险' },
  { port: 636, service: 'LDAPS', severity: '低', category: '敏感端口', desc: 'LDAPS 加密目录服务' },
  { port: 3690, service: 'SVN', severity: '低', category: '敏感端口', desc: 'SVN 版本控制服务暴露' },
  { port: 4848, service: 'GlassFish', severity: '中', category: '漏洞组件', desc: 'GlassFish 管理控制台，存在历史 RCE 漏洞' },
  { port: 5601, service: 'Kibana', severity: '中', category: '漏洞组件', desc: 'Kibana 存在历史 RCE / 未授权漏洞' },
  { port: 9000, service: 'SonarQube', severity: '中', category: '敏感端口', desc: 'SonarQube 代码审计平台，默认匿名可读 API' },
  { port: 9092, service: 'Kafka', severity: '中', category: '未授权访问', desc: 'Kafka 消息队列暴露' },
  { port: 2181, service: 'Zookeeper', severity: '中', category: '未授权访问', desc: 'Zookeeper 未授权访问（可读取节点配置）' },
  { port: 2376, service: 'DockerTLS', severity: '低', category: '未授权访问', desc: 'Docker TLS API' },
  { port: 8088, service: 'Hadoop-YARN', severity: '高', category: '未授权访问', desc: 'Hadoop YARN ResourceManager 未授权（可提交恶意任务）' },
  { port: 6443, service: 'Kubernetes-API', severity: '高', category: '未授权访问', desc: 'Kubernetes API Server 暴露，认证不当易未授权' },
  { port: 10000, service: 'Webmin', severity: '中', category: '漏洞组件', desc: 'Webmin 管理面板，存在历史 RCE 漏洞' },
];

// HTTP 类端口（用于抓取页面/响应头做组件识别）
const HTTP_PORTS = new Set([
  80, 443, 8080, 8000, 8443, 8888, 7001, 8161, 9200, 5984,
  808, 3000, 5000, 8001, 8002, 9000, 9090, 5601, 4848, 10000, 8088, 6443,
]);
// 显式使用 HTTPS 的端口（grabHttp 据此选择协议）
const HTTPS_PORTS = new Set([443, 8443, 6443, 9443, 8442]);
// 明文传输检测时的候选端口（提供 HTTP 服务的常见端口）
const PLAINTEXT_PORTS = new Set([80, 8080, 8000, 808, 8888, 3000, 5000, 8001, 8002, 9000, 9090, 7001, 8161, 9200, 5984, 8088, 10000]);

const SEVERITY_RANK = { '高': 3, '中': 2, '低': 1, '安全': 0 };

// ---- 命中维度强度分级（抑制过度匹配 / 问题数量异常偏多的根因）----
// 强维度：误报率极低（响应头 / 路径 / 图标哈希 / 正则 / banner），任一命中即可认定。
// 弱维度：body_keywords / title_keywords / cookie_keywords 为子串匹配，
//   极易被通用词（admin / login / api / manage / console）误触发（实测通用页可触发 30+ 误报）。
// 抑制规则：含 ≥1 强维度，或 ≥2 弱维度，才判定为有效命中；单弱维度一律忽略。
const STRONG_DIMS = new Set([
  'header_server', 'header_custom', 'header_keywords', 'path_keywords',
  'favicon_mmh3', 'favicon_md5', 'body_regex', 'banner_keywords', 'banner_regex',
]);
const WEAK_DIMS = new Set(['body_keywords', 'title_keywords', 'cookie_keywords']);

function isReportedHit(matched) {
  let strong = 0, weak = 0;
  for (const m of matched) {
    if (STRONG_DIMS.has(m)) strong++;
    else if (WEAK_DIMS.has(m)) weak++;
  }
  return strong > 0 || weak >= 2;
}

// ---- 高危指纹库加载 ----
//  high_risk_fingerprint_db.json：tolerant 解析（其 asset_queries 使用单引号，非严格 JSON）
//  fingerprint_db.json：由 wscan.json + finger.json 转换生成，结构兼容、严格 JSON
//  fingerprint_db_fh.json：由 FingerprintHub 的 web_fingerprint_v4.json + service_fingerprint_v4.json
//                          转换生成，结构兼容、严格 JSON（web→http 维度，service→banner 维度）
//  ext_fingerprints.js：内置 CVE 支撑的高危组件指纹
// 四者共用同一 match_rules 匹配引擎，合并后为完整指纹特征库。
let _fpDb = null;
function readFpFile(p, tolerant) {
  try {
    let raw = fs.readFileSync(p, 'utf8');
    if (tolerant) {
      // 仅将单引号字符串字面量（asset_queries 的 fofa/hunter/quake 查询）转为合法 JSON
      raw = raw.replace(/'([^']*)'/g, (m, inner) => '"' + inner.replace(/"/g, '\\"') + '"');
    }
    const obj = JSON.parse(raw);
    if (Array.isArray(obj)) return obj;
    if (obj && Array.isArray(obj.fingerprints)) return obj.fingerprints;
  } catch (e) {
    // 解析失败时静默跳过该来源，保证其它来源仍可用
  }
  return null;
}

// 判断指纹是否包含「HTTP 相关」匹配维度（用于 matchDbFindings 提速）
function hasHttpRule(rules) {
  return !!(rules && (
    (rules.header_server && rules.header_server.length) ||
    (rules.header_custom && rules.header_custom.length) ||
    (rules.header_keywords && rules.header_keywords.length) ||
    (rules.body_keywords && rules.body_keywords.length) ||
    (rules.cookie_keywords && rules.cookie_keywords.length) ||
    (rules.title_keywords && rules.title_keywords.length) ||
    (rules.body_regex && rules.body_regex.length) ||
    (rules.path_keywords && rules.path_keywords.length) ||
    (rules.favicon_mmh3 && rules.favicon_mmh3.length) ||
    (rules.favicon_md5 && rules.favicon_md5.length)
  ));
}
// 判断指纹是否包含「banner 相关」匹配维度（用于 matchBannerFindings 提速）
function hasBannerRule(rules) {
  return !!(rules && (
    (rules.banner_keywords && rules.banner_keywords.length) ||
    (rules.banner_regex && rules.banner_regex.length)
  ));
}

function loadFpDb() {
  if (_fpDb) return _fpDb;
  const fps = [];
  const sources = [
    [path.join(__dirname, 'data', 'high_risk_fingerprint_db.json'), true],
    [path.join(__dirname, 'data', 'fingerprint_db.json'), false],
    [path.join(__dirname, 'data', 'fingerprint_db_fh.json'), false],
  ];
  for (const [p, tol] of sources) {
    const arr = readFpFile(p, tol);
    if (arr) fps.push(...arr);
  }
  // 内置扩展指纹（CVE 支撑的高危项）始终并入
  fps.push(...EXT_FINGERPRINTS);
  // 按维度预拆分，避免每次匹配遍历全量指纹
  const fpsHttp = fps.filter((f) => hasHttpRule(f.match_rules));
  const fpsBanner = fps.filter((f) => hasBannerRule(f.match_rules));
  _fpDb = { fingerprints: fps, fpsHttp, fpsBanner };
  return _fpDb;
}

// ---- 工具函数 ----

function versionLt(a, b) {
  const pa = String(a).split('.').map(Number);
  const pb = String(b).split('.').map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i] || 0;
    const y = pb[i] || 0;
    if (x < y) return true;
    if (x > y) return false;
  }
  return false;
}

async function resolveIp(target) {
  if (target.kind === 'ip') return target.value;
  try {
    const r = await dns.lookup(target.value);
    if (r && r.address) return r.address;
    if (typeof r === 'string') return r; // 部分环境下返回字符串
    return null;
  } catch (e) {
    return null;
  }
}

// 通用 TCP banner 抓取
function grabTcp(host, port, probe, timeoutMs, maxBytes = 2048) {
  return new Promise((resolve) => {
    const sock = net.Socket();
    let settled = false;
    const chunks = [];
    let received = 0;
    const finish = (val) => {
      if (settled) return;
      settled = true;
      try { sock.destroy(); } catch (e) {}
      resolve(val);
    };
    sock.setTimeout(timeoutMs);
    sock.once('timeout', () => finish(chunks.length ? concat(chunks, maxBytes) : null));
    sock.once('error', () => finish(null));
    sock.on('data', (d) => {
      chunks.push(d);
      received += d.length;
      if (received >= maxBytes) finish(concat(chunks, maxBytes));
    });
    sock.once('close', () => finish(chunks.length ? concat(chunks, maxBytes) : null));
    sock.connect(port, host, () => {
      if (probe) { try { sock.write(probe); } catch (e) {} }
    });
  });
}

function concat(chunks, maxBytes) {
  const buf = Buffer.concat(chunks);
  return buf.toString('utf8', 0, Math.min(buf.length, maxBytes));
}

// HTTP 抓取（用于组件识别）
async function grabHttp(host, port, timeoutMs, reqPath = '/', forceProto = null) {
  const proto = forceProto || (HTTPS_PORTS.has(port) ? 'https' : 'http');
  try {
    const res = await fetchWithTimeout(`${proto}://${host}:${port}${reqPath}`, {
      method: 'GET',
      redirect: 'follow',
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; WanpingQiuzhen/1.0)' },
    }, timeoutMs);
    const body = await res.text();
    return {
      status: res.status,
      headers: res.headers ? Object.fromEntries(res.headers.entries()) : {},
      body: body.slice(0, 20000),
      proto,
    };
  } catch (e) {
    return null;
  }
}

// ---- 指纹库匹配 ----

function mapRisk(level) {
  if (level === 'Critical' || level === 'High') return '高';
  if (level === 'Medium') return '中';
  return '低';
}

// 编译后的正则缓存（指纹库含大量正则，避免每次匹配重复编译）
const _regexCache = new Map();
function safeRegexTest(pattern, text) {
  if (pattern == null) return false;
  let re = _regexCache.get(pattern);
  if (!re) {
    try {
      re = new RegExp(pattern, 'i');
    } catch (e) {
      re = null; // 非法正则：标记为不可匹配，避免重复编译报错
    }
    _regexCache.set(pattern, re);
  }
  if (!re) return false;
  try {
    return re.test(text);
  } catch (e) {
    return false;
  }
}

// 评估单条指纹规则的命中情况（match_type 为 or：任一维度命中即算命中）
function evaluateRules(fp, rules, httpData) {
  const d = httpData || {};
  const server = (d.server || '').toLowerCase();
  const headerLines = d.headerLines || '';
  const body = (d.body || '').toLowerCase();
  const cookieStr = (d.cookieStr || '').toLowerCase();
  const title = (d.title || '').toLowerCase();
  const banner = (d.banner || '').toLowerCase();

  const matched = [];
  if ((rules.header_server || []).some((v) => server.includes(String(v).toLowerCase()))) {
    matched.push('header_server');
  }
  if ((rules.header_custom || []).some((v) => safeRegexTest(v, headerLines))) {
    matched.push('header_custom');
  }
  // header_keywords：与 header_custom 同作用于响应头，但按字面量子串匹配（FingerprintHub word 匹配器）
  if ((rules.header_keywords || []).some((v) => headerLines.includes(String(v).toLowerCase()))) {
    matched.push('header_keywords');
  }
  if ((rules.body_keywords || []).some((v) => body.includes(String(v).toLowerCase()))) {
    matched.push('body_keywords');
  }
  if ((rules.cookie_keywords || []).some((v) => cookieStr.includes(String(v).toLowerCase()))) {
    matched.push('cookie_keywords');
  }
  if ((rules.title_keywords || []).some((v) => title.includes(String(v).toLowerCase()))) {
    matched.push('title_keywords');
  }
  // body_regex：FingerprintHub http regex 匹配器（按正则匹配响应体）
  if ((rules.body_regex || []).some((v) => safeRegexTest(v, body))) {
    matched.push('body_regex');
  }
  // banner_keywords：TCP 协议响应（SSH/FTP/Telnet/SNMP/设备等）特征，由 matchBannerFindings 注入
  if ((rules.banner_keywords || []).some((v) => banner.includes(String(v).toLowerCase()))) {
    matched.push('banner_keywords');
  }
  // banner_regex：FingerprintHub tcp extractor 正则（按正则匹配 banner；二进制正则通常不匹配，被动兜底）
  if ((rules.banner_regex || []).some((v) => safeRegexTest(v, banner))) {
    matched.push('banner_regex');
  }
  // path_keywords：必须实际探测到对应路径存在（非 404）才算命中，避免仅凭请求路径字符串误判
  if ((rules.path_keywords || []).length && d.pathHits && d.pathHits.length) {
    const hit = rules.path_keywords.some((kw) =>
      d.pathHits.some((h) => {
        const exists = (typeof h.status === 'number') && h.status !== 404;
        return exists && (h.path || '').includes(kw);
      }));
    if (hit) matched.push('path_keywords');
  }
  // favicon 哈希
  if ((rules.favicon_mmh3 || []).some((h) => Number(h) === d.faviconHash)) {
    matched.push('favicon_mmh3');
  }
  if ((rules.favicon_md5 || []).some((h) => h === d.faviconMd5)) {
    matched.push('favicon_md5');
  }
  return matched;
}

function buildFpNote(fp, matched) {
  const cves = (fp.critical_vulnerabilities || []).slice(0, 3).map((v) => `${v.cve_id}`).join('、');
  const parts = [
    `组件：${fp.product_cn}（${fp.category}）`,
    `风险：${fp.risk_level} / CVSS ${fp.cvss_base}`,
  ];
  if (cves) parts.push(`关联漏洞：${cves}`);
  parts.push(`命中规则：${matched.join('+')}`);
  return parts.join('；');
}

// 对一批指纹做匹配，返回命中列表
function matchHighRisk(fps, httpData) {
  const hits = [];
  for (const fp of fps) {
    const rules = (fp.match_rules || {});
    const matched = evaluateRules(fp, rules, httpData);
    // 抑制过度匹配：弱维度单点命中（通用词误触发）直接忽略
    if (matched.length && isReportedHit(matched)) {
      hits.push({
        id: fp.id,
        product: fp.product_cn,
        severity: mapRisk(fp.risk_level),
        riskLevel: fp.risk_level,
        cvss: fp.cvss_base,
        matched,
        note: buildFpNote(fp, matched),
      });
    }
  }
  return hits;
}

// 提取 favicon 的 mmh3（Shodan/fofa 风格）与 md5 哈希
async function grabFaviconHash(host, port, timeoutMs) {
  const proto = (port === 443 || port === 8443) ? 'https' : 'http';
  try {
    const res = await fetchWithTimeout(`${proto}://${host}:${port}/favicon.ico`, {
      method: 'GET', redirect: 'follow',
    }, timeoutMs);
    if (!res.ok) return null;
    const buf = Buffer.from(await res.arrayBuffer());
    if (!buf.length) return null;
    return { mmh3: mmh3Hash32(buf), md5: crypto.createHash('md5').update(buf).digest('hex') };
  } catch (e) {
    return null;
  }
}

// murmur3 32-bit (x86)，seed=0，返回有符号整型
function murmur3_32(data, seed) {
  let h = seed >>> 0;
  const c1 = 0xcc9e2d51, c2 = 0x1b873593;
  const len = data.length;
  const nblocks = len >> 2;
  for (let i = 0; i < nblocks; i++) {
    const j = i * 4;
    let k = (data[j] & 0xff) | ((data[j + 1] & 0xff) << 8) | ((data[j + 2] & 0xff) << 16) | ((data[j + 3] & 0xff) << 24);
    k = Math.imul(k, c1);
    k = (k << 15) | (k >>> 17);
    k = Math.imul(k, c2);
    h ^= k;
    h = (h << 13) | (h >>> 19);
    h = (Math.imul(h, 5) + 0xe6546b64) | 0;
  }
  let k1 = 0;
  const tail = len & 3;
  const base = nblocks * 4;
  if (tail === 3) k1 ^= (data[base + 2] & 0xff) << 16;
  if (tail >= 2) k1 ^= (data[base + 1] & 0xff) << 8;
  if (tail >= 1) {
    k1 ^= (data[base] & 0xff);
    k1 = Math.imul(k1, c1);
    k1 = (k1 << 15) | (k1 >>> 17);
    k1 = Math.imul(k1, c2);
    h ^= k1;
  }
  h ^= len;
  h ^= h >>> 16;
  h = Math.imul(h, 0x85ebca6b);
  h ^= h >>> 13;
  h = Math.imul(h, 0xc2b2ae35);
  h ^= h >>> 16;
  return h >>> 0;
}

function mmh3Hash32(buf) {
  const b64 = buf.toString('base64');
  const h = murmur3_32(new Uint8Array(Buffer.from(b64, 'utf8')), 0);
  return (h & 0x80000000) ? h - 0x100000000 : h;
}

// ---- 指纹识别 ----

// 针对开放端口做协议级指纹探测（含指纹库匹配）
// forceHttp：当端口为用户显式指定时，即便不在 HTTP_PORTS 集合也尝试 HTTP 组件识别
async function probeFingerprint(host, p, timeoutMs, db, forceHttp) {
  const findings = [];
  const port = p.port;
  try {
    if (port === 6379) {
      const b = await grabTcp(host, port, 'PING\r\n', timeoutMs);
      if (b && /\+PONG/.test(b)) {
        findings.push({ label: 'Redis 未授权访问', severity: '高', category: '未授权访问', note: 'Redis 无需认证即可读写/写入文件' });
      }
      return { findings };
    }
    if (port === 11211) {
      const b = await grabTcp(host, port, 'stats\r\n', timeoutMs);
      if (b && /STAT (pid|version)/i.test(b)) {
        findings.push({ label: 'Memcached 未授权访问', severity: '高', category: '未授权访问', note: 'Memcached 无需认证即可读取数据' });
      }
      return { findings };
    }
    if (port === 9200) {
      const info = await grabHttp(host, port, timeoutMs);
      if (info) {
        if (/cluster_name|"lucene"|"tagline"/i.test(info.body)) {
          findings.push({ label: 'Elasticsearch 未授权访问', severity: '高', category: '未授权访问', note: 'Elasticsearch 无需认证即可读取全部索引数据' });
        }
        analyzeHttpComponents(info, findings);
        matchDbFindings(host, port, info, timeoutMs, db, findings);
      }
      return { findings };
    }
    if (port === 5984) {
      const info = await grabHttp(host, port, timeoutMs);
      if (info) {
        if (/couchdb|"db_name"|welcome/i.test(info.body)) {
          findings.push({ label: 'CouchDB 未授权访问', severity: '中', category: '未授权访问', note: 'CouchDB 无需认证即可读写数据库' });
        }
        analyzeHttpComponents(info, findings);
        matchDbFindings(host, port, info, timeoutMs, db, findings);
      }
      return { findings };
    }
    if (port === 2181) {
      const b = await grabTcp(host, port, 'stat\r\n', timeoutMs);
      if (b && /Zookeeper version|Environment:/i.test(b)) {
        findings.push({ label: 'Zookeeper 未授权访问', severity: '中', category: '未授权访问', note: 'Zookeeper 无需认证即可读取节点配置/枚举' });
      }
      return { findings };
    }
    if (HTTP_PORTS.has(port) || forceHttp) {
      const info = await grabHttp(host, port, timeoutMs);
      if (info) {
        analyzeHttpComponents(info, findings);
        matchDbFindings(host, port, info, timeoutMs, db, findings);
        return { findings };
      }
      if (HTTP_PORTS.has(port)) return { findings }; // HTTP 专属端口且无响应 → 视为关闭/无 Web 服务
      // forceHttp 但非 HTTP 服务：继续走下方 banner 分支
    }
    // 通用 banner（SSH / FTP / SMTP / MySQL / 设备 / 物联网等）
    const b = await grabTcp(host, port, '', timeoutMs);
    if (b) {
      analyzeBanner(port, b, findings);
      await matchBannerFindings(host, port, b, db, findings);
    }
    return { findings };
  } catch (e) {
    return { findings };
  }
}

// 基于指纹库做匹配（含 verify_paths 探测与 favicon 哈希），将命中转为 findings
async function matchDbFindings(host, port, info, timeoutMs, db, findings) {
  const fps = (db && db.fpsHttp) || (db && db.fingerprints) || [];
  if (!fps.length) return;
  const server = (info.headers && (info.headers['server'] || info.headers['Server'])) || '';
  const headerLines = Object.entries(info.headers || {}).map(([k, v]) => `${k}: ${v}`).join('\n').toLowerCase();
  const title = (info.body.match(/<title>([^<]*)<\/title>/i) || [])[1] || '';
  const cookieStr = Object.entries(info.headers || {})
    .filter(([k]) => k.toLowerCase() === 'set-cookie').map(([, v]) => v).join('; ');

  const httpData = {
    server, headerLines, body: info.body || '', title, cookieStr: cookieStr.toLowerCase(),
    pathHits: [], faviconHash: null, faviconMd5: null,
  };

  let hits = matchHighRisk(fps, httpData);

  // 对含 path_keywords 且尚未命中的指纹，探测其 verify_paths 以提升准确性
  const needPath = fps.filter((fp) => (fp.match_rules.path_keywords || []).length && !hits.find((h) => h.id === fp.id));
  if (needPath.length) {
    const probes = [];
    for (const fp of needPath) {
      for (const p of (fp.verify_paths || []).slice(0, 3)) probes.push({ fp, p });
    }
    const results = await runPool(probes, async (pr) => {
      const r = await grabHttp(host, port, Math.min(timeoutMs, 2000), pr.p);
      return { fp: pr.fp, path: pr.p, status: r && r.status, body: r && r.body };
    }, 12);
    for (const r of results) {
      if (r) httpData.pathHits.push({ path: r.path, body: r.body, status: r.status });
    }
    hits = hits.concat(matchHighRisk(needPath, httpData));
  }

  // favicon 哈希匹配（仅当指纹库含 favicon 规则时抓取）
  const favFps = fps.filter((fp) => (fp.match_rules.favicon_mmh3 || []).length || (fp.match_rules.favicon_md5 || []).length);
  if (favFps.length) {
    const hash = await grabFaviconHash(host, port, Math.min(timeoutMs, 2000));
    if (hash) {
      httpData.faviconHash = hash.mmh3;
      httpData.faviconMd5 = hash.md5;
      hits = hits.concat(matchHighRisk(favFps, httpData));
    }
  }

  for (const h of hits) {
    findings.push({
      label: h.product, severity: h.severity, category: '高危组件',
      note: h.note, fpId: h.id,
    });
  }
}

// HTTP 响应中的危险组件 / 漏洞组件识别（覆盖指纹库未收录的常见组件）
function analyzeHttpComponents(info, findings) {
  const server = (info.headers && (info.headers['server'] || info.headers['Server'])) || '';
  const body = info.body || '';
  const title = (body.match(/<title>([^<]*)<\/title>/i) || [])[1] || '';
  const haystack = body + ' ' + title + ' ' + server;

  const COMPONENT_CHECKS = [
    { re: /phpMyAdmin/i, label: 'phpMyAdmin 管理面板暴露', severity: '中', category: '危险组件', note: '数据库管理面板暴露，存在弱口令/历史漏洞风险' },
    { re: /jenkins/i, label: 'Jenkins 暴露', severity: '中', category: '危险组件', note: 'CI 系统暴露，存在未授权访问/历史 RCE 漏洞' },
    { re: /apache\s*struts|struts2?/i, label: 'Apache Struts 组件', severity: '高', category: '漏洞组件', note: 'Struts2 存在远程命令执行历史漏洞' },
    { re: /weblogic/i, label: 'WebLogic 中间件', severity: '中', category: '漏洞组件', note: 'WebLogic 存在多个历史 RCE 漏洞' },
    { re: /apache\s*tomcat/i, label: 'Apache Tomcat', severity: '中', category: '危险组件', note: 'Tomcat 管理后台/示例可能暴露' },
    { re: /<title>[^<]*solr/i, label: 'Apache Solr', severity: '中', category: '漏洞组件', note: 'Solr 存在历史 RCE 漏洞' },
    { re: /grafana/i, label: 'Grafana', severity: '中', category: '危险组件', note: 'Grafana 存在未授权访问/CVE 漏洞' },
    { re: /kibana/i, label: 'Kibana', severity: '中', category: '危险组件', note: 'Kibana 存在历史漏洞' },
    { re: /activemq/i, label: 'ActiveMQ', severity: '中', category: '漏洞组件', note: 'ActiveMQ 存在历史漏洞' },
    { re: /phpinfo\(\)/i, label: 'phpinfo 信息泄露', severity: '中', category: '信息泄露', note: 'PHP 环境信息暴露' },
    { re: /thinkphp|think\s*php/i, label: 'ThinkPHP 框架', severity: '中', category: '漏洞组件', note: 'ThinkPHP 存在历史 RCE 漏洞' },
    // —— 扩展组件（参照 FingerprintHub / wscan-Fingerprint 高频高危面）——
    { re: /sonarqube|sonar\s?qube/i, label: 'SonarQube 代码平台', severity: '中', category: '危险组件', note: 'SonarQube 默认匿名可读 API，存在源码/配置泄露风险' },
    { re: /kubernetes|<title>[^<]*kubernetes/i, label: 'Kubernetes 组件', severity: '高', category: '漏洞组件', note: 'Kubernetes 相关组件暴露，认证不当易未授权' },
    { re: /hadoop|yarn|resourcemanager|applicationmaster/i, label: 'Hadoop / YARN 组件', severity: '高', category: '未授权访问', note: 'Hadoop YARN 默认无认证，可提交恶意 Container' },
    { re: /webmin/i, label: 'Webmin 管理面板', severity: '中', category: '漏洞组件', note: 'Webmin 管理面板暴露，存在历史 RCE 漏洞' },
    { re: /glassfish/i, label: 'GlassFish 中间件', severity: '中', category: '漏洞组件', note: 'GlassFish 管理控制台存在历史 RCE 漏洞' },
    { re: /swagger[- ]?ui|swagger\.json|swagger-config|swagger\.yaml/i, label: 'Swagger/OpenAPI 文档暴露', severity: '中', category: '信息泄露', note: 'API 文档未鉴权暴露，泄露接口与参数' },
    { re: /repositoryformatversion|\[core\]\n\s*repositoryformatversion|\.git\/|\.svn\//i, label: '源码仓库元数据泄露(.git/.svn)', severity: '高', category: '信息泄露', note: '站点根目录遗留 .git/.svn，可还原完整源码' },
  ];
  for (const c of COMPONENT_CHECKS) {
    if (c.re.test(haystack)) {
      findings.push({ label: c.label, severity: c.severity, category: c.category, note: c.note });
    }
  }
  // 过时的服务版本（EOL）：仅标记明确停止维护的版本，避免对仍在广泛使用的版本误报
  if (/Apache\/2\.[0-2]\b|OpenSSL\/1\.0|Microsoft-IIS\/[56]\b/i.test(server)) {
    const name = (server.split('/')[0] || 'server').trim();
    findings.push({ label: `过时服务版本(${name})`, severity: '中', category: '过时组件', note: `Server: ${server} 可能为已停止维护版本` });
  }
}

// 通用 banner 中的漏洞/过时特征
function analyzeBanner(port, banner, findings) {
  if (port === 22 && /SSH-/.test(banner)) {
    const m = banner.match(/SSH-[\d.]+-OpenSSH_([\d.]+)/);
    if (m && versionLt(m[1], '7.0')) {
      findings.push({ label: 'OpenSSH 旧版本', severity: '中', category: '过时组件', note: `OpenSSH ${m[1]} 存在历史漏洞` });
    }
  }
  if (port === 21 && /220.*FTP/i.test(banner)) {
    findings.push({ label: 'FTP 明文传输', severity: '中', category: '敏感端口', note: 'FTP 以明文传输凭证' });
  }
  if (port === 25 && /220.*(ESMTP|SMTP)/i.test(banner)) {
    findings.push({ label: 'SMTP 服务暴露', severity: '低', category: '敏感端口', note: 'SMTP 服务暴露' });
  }
  if (port === 3306 && /mysql/i.test(banner)) {
    const v = (banner.match(/(\d+\.\d+\.\d+)/) || [])[1];
    if (v && versionLt(v, '5.7')) {
      findings.push({ label: 'MySQL 旧版本', severity: '中', category: '过时组件', note: `MySQL ${v} 存在历史漏洞` });
    }
  }
}

// 基于指纹库做 banner（TCP 协议响应）匹配，将命中转为 findings
// 仅使用 banner_keywords / banner_regex 维度，被动匹配，不触发额外网络请求
async function matchBannerFindings(host, port, banner, db, findings) {
  const fps = (db && db.fpsBanner) || (db && db.fingerprints) || [];
  if (!banner || !fps.length) return;
  const httpData = {
    banner, server: '', headerLines: '', body: '', cookieStr: '', title: '',
    pathHits: [], faviconHash: null, faviconMd5: null,
  };
  const hits = matchHighRisk(fps, httpData);
  for (const h of hits) {
    findings.push({ label: h.product, severity: h.severity, category: '高危组件', note: h.note, fpId: h.id });
  }
}

/*
 * 明文传输检测（参照"网安企业实战脚本 明文传输.py"的判定逻辑）
 * 判定：
 *   1) HTTP 明文可访问（任意 HTTP 状态码均视为服务在跑）→ 确认明文风险
 *   2) 同时探测同端口 HTTPS：若 HTTPS 也可访问 → 降级为"中"（已具备加密能力，
 *      但明文 HTTP 仍可被 SSL Stripping / 中间人利用）；若 HTTPS 不可访问 → "高"（纯明文）
 *   3) HTTP 与 HTTPS 均不可达 → 不计入（端口关闭 / 服务下线）
 * 仅对开放且属于 PLAINTEXT_PORTS 的端口做检测。
 */
async function detectPlaintext(host, openPorts, timeoutMs, forcePorts) {
  const findings = [];
  const forceSet = new Set(forcePorts || []);
  // 候选端口：默认明文端口 + 用户显式指定的端口（即便不在默认集合，也应检测明文风险）
  const candidates = openPorts.filter((p) => PLAINTEXT_PORTS.has(p.port) || forceSet.has(p.port));
  if (!candidates.length) return findings;

  await runPool(candidates, async (p) => {
    const port = p.port;
    const httpRes = await grabHttp(host, port, timeoutMs, '/');
    if (!httpRes) return; // HTTP 不通，不报明文风险
    // 确认明文可达：进一步探测同端口 HTTPS 是否存在
    const httpsRes = await grabHttp(host, port, Math.min(timeoutMs, 2500), '/', 'https');
    if (httpsRes) {
      findings.push({
        label: `HTTP明文传输(:${port})`,
        severity: '中',
        category: '明文传输',
        note: `端口 ${port} 同时提供明文 HTTP 与 HTTPS；明文 HTTP 仍可被降级劫持，建议强制 301 跳转 HTTPS 并禁用 HTTP`,
      });
    } else {
      findings.push({
        label: `HTTP明文传输(:${port})`,
        severity: '高',
        category: '明文传输',
        note: `端口 ${port} 仅以明文 HTTP 提供服务且无 TLS 加密，登录凭据/敏感数据面临窃听与中间人攻击风险`,
      });
    }
  }, 8);

  return findings;
}

// ---- 主扫描流程 ----

async function scanTarget(target, opts = {}) {
 try {
  const portTimeout = opts.portTimeout || 1200;
  const bannerTimeout = opts.bannerTimeout || 2500;
  const portConcurrency = opts.portConcurrency || 16;

  const host = target.value;
  const kind = target.kind;
  const specificPort = (typeof target.port === 'number') ? target.port : null; // 用户显式指定端口
  const resolvedIp = await resolveIp(target);
  const geoStr = resolvedIp ? geo.lookup(resolvedIp) : '未知';
  const db = loadFpDb();

  // 1) 端口探测
  let openPorts;
  if (specificPort != null) {
    // —— 单端口精准扫描：仅探测用户指定的端口，跳过默认端口范围 ——
    const r = await tcpConnect(host, specificPort, portTimeout);
    if (r.open) {
      const sp = SENSITIVE_PORTS.find((p) => p.port === specificPort); // 命中内置敏感端口则沿用其严重度/分类
      openPorts = [sp || {
        port: specificPort, service: '指定端口', severity: '低',
        category: '指定端口', desc: `端口 ${specificPort} 开放（用户指定）`,
      }];
    } else {
      openPorts = []; // 指定端口未开放
    }
  } else {
    // —— 默认扫描：探测内置敏感端口范围 ——
    const openResults = await runPool(SENSITIVE_PORTS, (p) => tcpConnect(host, p.port, portTimeout)
      .then((r) => (r.open ? p : null)), portConcurrency);
    openPorts = openResults.filter(Boolean);
  }

  // 2) 对每个开放端口做指纹探测（仅对开放端口，控制并发）
  const findings = [];
  const seen = new Set();
  const addFinding = (f) => {
    const key = f.label + '#' + f.severity;
    if (!seen.has(key)) { seen.add(key); findings.push(f); }
  };

  // 基于端口的基础发现
  for (const p of openPorts) {
    addFinding({ label: `${p.service} (${p.port})`, severity: p.severity, category: p.category, note: p.desc });
  }

  // 协议级指纹探测（含指纹库匹配）；指定端口额外尝试 HTTP 组件识别
  const probeResults = await Promise.all(openPorts.map((p) => probeFingerprint(host, p, bannerTimeout, db, specificPort != null)));
  for (const r of probeResults) {
    if (r && r.findings) for (const f of r.findings) addFinding(f);
  }

  // 明文传输检测（参照 明文传输.py：HTTP 可达即风险，HTTPS 并存则降级）
  // 指定端口时将其纳入明文检测候选（即便不在默认明文端口集合）
  const ptFindings = await detectPlaintext(host, openPorts, bannerTimeout, specificPort != null ? [specificPort] : []);
  for (const f of ptFindings) addFinding(f);

  // 3) 风险等级聚合（取最高严重度）
  let riskLevel = '安全';
  for (const f of findings) {
    if (SEVERITY_RANK[f.severity] > SEVERITY_RANK[riskLevel]) riskLevel = f.severity;
  }

  const openPortStr = openPorts.length ? openPorts.map((p) => p.port).join(', ') : '无';
  const fpStr = findings.length ? findings.map((f) => f.label).join('; ') : '无';
  const detailStr = findings.length
    ? findings.map((f) => `${f.label}[${f.severity}]：${f.note}`).join(' | ')
    : '未发现高危指纹';

  // 4) 由高危指纹关联的 CVE 派生漏洞项（统一归类到 12 类标准标签）
  const vulns = [];
  const seenVuln = new Set();
  for (const f of findings) {
    if (!f.fpId) continue;
    const fp = db.fingerprints.find((x) => x.id === f.fpId);
    if (!fp || !Array.isArray(fp.critical_vulnerabilities)) continue;
    for (const cv of fp.critical_vulnerabilities) {
      const key = `${f.label}#${cv.cve_id || cv.vuln_name}`;
      if (seenVuln.has(key)) continue;
      seenVuln.add(key);
      vulns.push({
        host: target.raw,
        type: cv.cve_id || 'CVE',
        severity: mapRisk(fp.risk_level),
        title: `${f.label} · ${cv.vuln_name || cv.cve_id}`,
        detail: `关联漏洞 ${cv.cve_id || '-'}（${cv.type || '未知类型'}）：影响版本 ${cv.affected_versions || '未知'}`,
        evidence: `指纹命中：${f.label}（${f.category}）`,
        category: mapVulnCategory(cv.type),
      });
    }
  }

  return {
    target: target.raw,
    type: kind === 'domain' ? '域名' : 'IPv4',
    resolvedIp: resolvedIp || '-',
    geo: geoStr,
    openPorts: openPortStr,
    fingerprints: fpStr,
    riskLevel,
    detail: detailStr,
    vulns,
  };
 } catch (e) {
   // 单资产扫描异常时不整体中断：返回安全占位结果，由上层记录
   const message = String((e && e.message) ? e.message : e);
   return {
     target: target.raw,
     type: target.kind === 'domain' ? '域名' : 'IPv4',
     resolvedIp: '-',
     geo: '未知',
     openPorts: '无',
     fingerprints: '无',
     riskLevel: '未知',
     detail: `扫描异常（已跳过）：${message}`,
     vulns: [],
   };
 }
}

module.exports = {
  scanTarget,
  SENSITIVE_PORTS,
  SEVERITY_RANK,
  loadFpDb,
  matchHighRisk,
  evaluateRules,
  detectPlaintext,
};
