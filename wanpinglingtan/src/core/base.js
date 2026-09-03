'use strict';

const { normalizeCategory } = require('./vuln-categories');

/**
 * Provider 基类与结果归一化工厂。
 *
 * 统一调用接口约定：
 *   - 每个 provider 是一个继承 BaseProvider 的类，声明静态元信息
 *     (id / category / label / description / requiresKey / keyEnv / priority / defaultEnabled)
 *   - 构造函数接收 ctx：{ http, log, signals, isPublicIPv4, config, resolveDns }
 *   - 实现 async run(job) -> { items: [...], stats?: {...}, notes?: [...] }
 *   - job 包含：input(归一化输入) / config(运行配置) / context(流水线共享状态)
 *   - run 内发生错误应当抛出，引擎会捕获并隔离，不影响其它 provider（宁缺毋滥）
 */

const CATEGORIES = [
  'subdomain',
  'dns',
  'ip',
  'port',
  'fingerprint',
  'vuln',
  'enterprise',
  'search',
  'leak',
  'email',
  'whois',
];

class ProviderError extends Error {
  constructor(message, opts = {}) {
    super(message);
    this.name = 'ProviderError';
    this.transient = opts.transient !== false;
  }
}

class BaseProvider {
  static id = 'base';
  static category = 'subdomain';
  static label = 'Base';
  static description = '';
  static requiresKey = false;
  static keyEnv = null;
  static priority = 50;
  static defaultEnabled = true;

  constructor(ctx) {
    this.ctx = ctx || {};
  }

  log(level, msg) {
    if (this.ctx && typeof this.ctx.log === 'function') {
      this.ctx.log(level, `[${this.constructor.label || this.constructor.id}] ${msg}`);
    }
  }

  /** 子类实现 */
  async run(/* job */) {
    return { items: [] };
  }
}

// ---------------------------------------------------------------------------
// 结果归一化工厂：保证各 provider 产出结构一致，便于引擎去重与渲染
// ---------------------------------------------------------------------------

function subdomain(host, source, ips = []) {
  return { host: String(host).toLowerCase(), source, ips: ips || [] };
}

function dnsRecord(type, host, value, source = 'DNS') {
  return { type, host, value, source };
}

function ipAsset(ip, { scope = 'public', hosts = [], reverseHosts = [], confidence = 'medium', source = '' } = {}) {
  return { ip, scope, hosts, reverseHosts, confidence, source };
}

function portFinding(target, port, opts = {}) {
  return {
    target,
    port,
    protocol: opts.protocol || 'tcp',
    service: opts.service || '',
    state: opts.state || 'open',
    status: opts.status || null,
    title: opts.title || '',
    server: opts.server || '',
    banner: opts.banner || '',
    location: opts.location || '',
    tech: opts.tech || [],
    waf: opts.waf || [],
    source: opts.source || 'probe',
  };
}

function fingerprint(host, tech) {
  return { host, tech: tech || [] };
}

function vuln(host, type, severity, title, detail = '', evidence = '', category = '其他', source = 'scanner') {
  return {
    host, type, severity: severity || 'info', title, detail, evidence,
    category: normalizeCategory(category),
    source,
  };
}

function enterpriseInfo(data = {}) {
  return Object.assign({ source: 'unknown' }, data);
}

function searchResult(asset, source, raw = '', extra = {}) {
  return { asset, source, raw, ...extra };
}

function leakResult(item = {}) {
  return {
    title: item.title || '',
    url: item.url || '',
    source: item.source || 'web',
    confidence: item.confidence || 'medium',
    matchedKeyword: item.matchedKeyword || '',
    snippet: item.snippet || '',
    type: item.type || 'web',
  };
}

function emailResult(email, opts = {}) {
  return {
    email,
    source: opts.source || '',
    confidence: opts.confidence || 'medium',
    verified: opts.verified || false,
    mx: opts.mx || false,
    spf: opts.spf || false,
    dmarc: opts.dmarc || false,
    matchedSuffix: opts.matchedSuffix || null,
  };
}

function whoisResult(domain, fields = {}, source = '', raw = '') {
  return { domain, fields, source, raw };
}

module.exports = {
  CATEGORIES,
  BaseProvider,
  ProviderError,
  subdomain,
  dnsRecord,
  ipAsset,
  portFinding,
  fingerprint,
  vuln,
  enterpriseInfo,
  searchResult,
  leakResult,
  emailResult,
  whoisResult,
};
