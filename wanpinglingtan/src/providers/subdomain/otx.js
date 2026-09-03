'use strict';

/** 子域名 — AlienVault OTX 被动 DNS（Subfinder 数据源之一） */
const { BaseProvider, subdomain } = require('../../core/base');
const { getJson } = require('../../core/http');

class OtxProvider extends BaseProvider {
  static id = 'subdomain.otx';
  static category = 'subdomain';
  static label = 'AlienVault OTX';
  static description = '通过 AlienVault OTX 被动 DNS 接口发现子域名';
  static priority = 30;

  async run(job) {
    const domain = job.domain || (job.input && job.input.rootDomains && job.input.rootDomains[0]);
    if (!domain) return { items: [] };
    const url = `https://otx.alienvault.com/api/v1/indicators/domain/${encodeURIComponent(domain)}/passive_dns`;
    try {
      const res = await getJson(url, { timeout: this.ctx.config.timeout });
      const items = [];
      if (res.json && Array.isArray(res.json.passive_dns_entries)) {
        for (const e of res.json.passive_dns_entries) {
          const host = String(e.hostname || '').toLowerCase();
          if (host && (host.endsWith('.' + domain) || host === domain)) {
            items.push(subdomain(host, 'otx'));
          }
        }
      }
      return { items };
    } catch (e) {
      this.log('warn', `OTX 查询失败：${e.message}`);
      return { items: [] };
    }
  }
}

module.exports = OtxProvider;
