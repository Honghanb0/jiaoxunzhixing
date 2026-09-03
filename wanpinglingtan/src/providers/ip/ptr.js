'use strict';

/**
 * IP 反查 provider（同 IP 查询 / 反查托管域名）。
 * 对发现的公网 IP 做 PTR 反向 DNS，得到共宿主域名。
 * 仅保留公网 IP；反查得到的共宿主域名交由引擎并入子域名（相关性在引擎侧过滤）。
 */

const { BaseProvider, ipAsset } = require('../../core/base');
const { Pool } = require('../../core/semaphore');
const coreDns = require('../../core/dns');
const { isPublicIPv4, ipScope } = require('../../core/utils');

class PtrProvider extends BaseProvider {
  static id = 'ip.ptr';
  static category = 'ip';
  static label = 'IP 反查 (PTR)';
  static description = '对公网 IP 做反向 DNS 解析，识别共宿主域名（同 IP 查询）';
  static priority = 10;

  async run(job) {
    const ctx = job.context || {};
    const discovered = Array.from(ctx.discoveredIps || []);
    const inputs = (ctx.ipInputs || []).filter(isPublicIPv4);
    const ips = Array.from(new Set([...discovered, ...inputs])).filter(isPublicIPv4);
    if (!ips.length) return { items: [] };

    const pool = new Pool(this.ctx.config.concurrency || 24);
    const items = [];
    await pool.map(ips, async (ip) => {
      let hosts = [];
      try {
        hosts = await coreDns.resolvePtr(ip);
      } catch (_) {}
      items.push(
        ipAsset(ip, {
          scope: ipScope(ip),
          reverseHosts: hosts,
          confidence: hosts.length ? 'high' : 'medium',
          source: 'ptr',
        })
      );
    });
    return { items, stats: { ips: ips.length, withPtr: items.filter((i) => i.reverseHosts.length).length } };
  }
}

module.exports = PtrProvider;
