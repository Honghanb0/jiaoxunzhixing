'use strict';

/**
 * 子域名 — 字典爆破（ksubdomain / subDomainsBrute 思路）。
 * 仅做「DNS 解析存在性」判断（被动式探测），不做端口/路径爆破；
 * 并发受控，仅保留真实解析到的主机（宁缺毋滥）。
 *
 * 注意：这是唯一带「主动解析」性质的子域来源，默认开启但规模收敛，
 * 词表为常见子域，不会做海量爆破。
 */

const { BaseProvider, subdomain } = require('../../core/base');
const { Pool } = require('../../core/semaphore');
const coreDns = require('../../core/dns');

// 常见子域词表（按出现频率筛选，约 150 个，覆盖大多数资产）
const WORDLIST = [
  'www', 'mail', 'ftp', 'webmail', 'smtp', 'pop', 'pop3', 'imap', 'ns', 'ns1', 'ns2', 'dns',
  'dns1', 'dns2', 'mx', 'mx1', 'mx2', 'autodiscover', 'autoconfig', 'm', 'mobile', 'wap', 'api',
  'api1', 'api2', 'app', 'admin', 'adm', 'manage', 'management', 'console', 'cp', 'cpanel',
  'panel', 'dashboard', 'root', 'test', 'dev', 'development', 'stage', 'staging', 'uat', 'demo',
  'pre', 'beta', 'alpha', 'prod', 'production', 'old', 'new', 'bbs', 'forum', 'blog', 'news',
  'shop', 'store', 'mall', 'pay', 'payment', 'paycenter', 'billing', 'bank', 'card', 'static',
  'img', 'image', 'images', 'cdn', 'cdn1', 'cdn2', 'assets', 'media', 'video', 'v', 'download',
  'dl', 'file', 'files', 'doc', 'docs', 'wiki', 'kb', 'help', 'support', 'service', 'services',
  'hr', 'oa', 'crm', 'erp', 'bi', 'data', 'db', 'database', 'sql', 'redis', 'cache', 'memcache',
  'search', 's', 'ss', 'sso', 'login', 'logon', 'auth', 'oauth', 'passport', 'vpn', 'gw', 'gateway',
  'firewall', 'fw', 'lb', 'load', 'balancer', 'proxy', 'nas', 'san', 'backup', 'bak', 'git', 'svn',
  'ci', 'jenkins', 'jira', 'confluence', 'wiki', 'monitor', 'zabbix', 'nagios', 'grafana', 'kibana',
  'es', 'elasticsearch', 'log', 'logs', 'mq', 'kafka', 'rabbit', 'docker', 'k8s', 'kubernetes',
  'cloud', 'oss', 'oss-cn', 'oss', 'minio', 'web', 'web1', 'web2', 'portal', 'agent', 'agents',
  'server', 'host', 'node', 'node1', 'node2', 'edge', 'edge1', 'g', 'go', 'internal', 'intranet',
  'vpn', 'remote', 'desk', 'rdp', 'term', 'meeting', 'live', 'stream', 'rtc', 'push', 'msg',
  'message', 'im', 'chat', 'open', 'openapi', 'gw', 'api-gateway', 'inner', 'corp', 'company',
];

class BruteProvider extends BaseProvider {
  static id = 'subdomain.brute';
  static category = 'subdomain';
  static label = '字典爆破 (DNS)';
  static description = '基于内置词表对根域名做 DNS 解析型子域枚举（被动检测）';
  static priority = 90;
  static defaultEnabled = true;

  async run(job) {
    const domains = job.input && job.input.rootDomains && job.input.rootDomains.length
      ? job.input.rootDomains
      : (job.domain ? [job.domain] : []);
    if (!domains.length) return { items: [] };
    const pool = new Pool(this.ctx.config.concurrency || 24);
    const candidates = [];
    for (const d of domains) {
      for (const w of WORDLIST) candidates.push(`${w}.${d}`);
    }
    this.log('info', `字典爆破：待解析 ${candidates.length} 个候选（词表 ${WORDLIST.length} × 域名 ${domains.length}）`);

    const items = [];
    const results = await pool.map(candidates, async (host) => {
      const ips = await coreDns.resolveA(host);
      return { host, ips };
    });

    for (const r of results) {
      if (r && r.ips && r.ips.length) {
        items.push(subdomain(r.host, 'brute-dns'));
      }
    }
    this.log('info', `字典爆破命中 ${items.length} 个可解析子域`);
    return { items };
  }
}

module.exports = BruteProvider;
