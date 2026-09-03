'use strict';

/**
 * DNS 解析 provider：
 *  - 对流水线发现的所有主机批量解析 A/AAAA（并发受控）
 *  - 仅保留公网 IP 作为暴露面资产，写入 context.discoveredIps
 *  - 收集根域名的 NS / MX / TXT / SOA 记录
 *  - 解析结果（host -> 公网 IP）写入 context.hostIps 供子域名回填
 */

const { BaseProvider, dnsRecord } = require('../../core/base');
const { Pool } = require('../../core/semaphore');
const coreDns = require('../../core/dns');
const { isPublicIPv4, uniq } = require('../../core/utils');

class DnsResolverProvider extends BaseProvider {
  static id = 'dns.resolver';
  static category = 'dns';
  static label = 'DNS 解析';
  static description = '批量解析主机 A/AAAA 并收集根域名 NS/MX/TXT/SOA 记录';
  static priority = 10;

  async run(job) {
    const ctx = job.context || {};
    const hosts = Array.from(ctx.hostSet || []).filter(Boolean);
    if (!hosts.length) return { items: [] };

    const pool = new Pool(this.ctx.config.concurrency || 24);
    const hostIps = ctx.hostIps || (ctx.hostIps = {});
    const discovered = ctx.discoveredIps || (ctx.discoveredIps = new Set());
    const records = [];

    const resolveOne = async (host) => {
      const a = await coreDns.resolveA(host);
      const aaaa = await coreDns.resolveAaaa(host);
      const allIps = uniq([...a, ...aaaa]);
      const publicIps = allIps.filter(isPublicIPv4);
      hostIps[host] = publicIps;
      publicIps.forEach((ip) => discovered.add(ip));
      for (const ip of publicIps) records.push(dnsRecord('A', host, ip, 'resolver'));
      for (const ip of aaaa) records.push(dnsRecord('AAAA', host, ip, 'resolver'));
      return { host, publicIps };
    };

    await pool.map(hosts, resolveOne);

    // 根域名记录
    const rootDomains = (job.input && job.input.rootDomains) || [];
    const recPool = new Pool(8);
    await recPool.map(rootDomains, async (domain) => {
      try {
        const ns = await coreDns.resolveNs(domain);
        ns.forEach((n) => records.push(dnsRecord('NS', domain, n, 'resolver')));
      } catch (_) {}
      try {
        const mx = await coreDns.resolveMx(domain);
        mx.forEach((m) => records.push(dnsRecord('MX', domain, `${m.priority || ''} ${m.exchange}`, 'resolver')));
      } catch (_) {}
      try {
        const txt = await coreDns.resolveTxt(domain);
        txt.forEach((t) => records.push(dnsRecord('TXT', domain, t, 'resolver')));
      } catch (_) {}
    });

    return { items: records, stats: { hosts: hosts.length, records: records.length } };
  }
}

module.exports = DnsResolverProvider;
