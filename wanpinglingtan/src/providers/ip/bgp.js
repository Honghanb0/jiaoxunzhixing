'use strict';

/**
 * IP / 网络信息 provider（bgp.he.net 思路）。
 * 对每个公网 IP 查询 BGP/ASN 归属（网络段、自治域号），用于归属与暴露面刻画。
 * 仅做被动情报查询，不探测。
 */

const { BaseProvider, ipAsset } = require('../../core/base');
const { Pool } = require('../../core/semaphore');
const { getText } = require('../../core/http');
const { isPublicIPv4, ipScope } = require('../../core/utils');

function parseAsnAndPrefix(html) {
  const asnMatch = html.match(/AS\d+/gi);
  const asns = asnMatch ? Array.from(new Set(asnMatch.map((s) => s.toUpperCase()))).slice(0, 5) : [];
  const prefixMatch = html.match(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}\b/g);
  const prefixes = prefixMatch ? Array.from(new Set(prefixMatch)).slice(0, 5) : [];
  const nameMatch = html.match(/>([^<]*?(?:Communications|Telecom|Hosting|Cloud|Networks|Limited|Inc|Corp|LLC)[^<]*?)</i);
  const org = nameMatch ? nameMatch[1].trim() : '';
  return { asns, prefixes, org };
}

class BgpProvider extends BaseProvider {
  static id = 'ip.bgp';
  static category = 'ip';
  static label = 'BGP / ASN (he.net)';
  static description = '通过 bgp.he.net 查询 IP 的 ASN 归属与网络段（国外在线资产归属）';
  static priority = 30;

  async run(job) {
    const ctx = job.context || {};
    const discovered = Array.from(ctx.discoveredIps || []);
    const inputs = (ctx.ipInputs || []).filter(isPublicIPv4);
    const ips = Array.from(new Set([...discovered, ...inputs])).filter(isPublicIPv4);
    if (!ips.length) return { items: [] };

    const pool = new Pool(10);
    const items = [];
    await pool.map(ips, async (ip) => {
      let asns = [];
      let prefixes = [];
      let org = '';
      try {
        const res = await getText(`https://bgp.he.net/ip/${encodeURIComponent(ip)}`, {
          timeout: this.ctx.config.timeout,
        });
        const parsed = parseAsnAndPrefix(res.body);
        asns = parsed.asns;
        prefixes = parsed.prefixes;
        org = parsed.org;
      } catch (_) {}
      const base = ipAsset(ip, {
        scope: ipScope(ip),
        confidence: 'medium',
        source: 'bgp.he.net',
      });
      base.asn = asns;
      base.prefix = prefixes;
      base.org = org;
      items.push(base);
    });
    return { items, stats: { ips: ips.length, withAsn: items.filter((i) => i.asn && i.asn.length).length } };
  }
}

module.exports = BgpProvider;
