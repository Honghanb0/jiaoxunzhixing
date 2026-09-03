'use strict';

/** 子域名 — URLScan.io（Amass/Subfinder 数据源之一） */
const { BaseProvider, subdomain } = require('../../core/base');
const { getJson } = require('../../core/http');

class UrlscanProvider extends BaseProvider {
  static id = 'subdomain.urlscan';
  static category = 'subdomain';
  static label = 'URLScan.io';
  static description = '通过 URLScan 扫描索引发现子域名';
  static priority = 35;

  async run(job) {
    const domain = job.domain || (job.input && job.input.rootDomains && job.input.rootDomains[0]);
    if (!domain) return { items: [] };
    const url = `https://urlscan.io/api/v1/search/?q=domain:${encodeURIComponent(domain)}&size=100`;
    try {
      const res = await getJson(url, { timeout: this.ctx.config.timeout });
      const items = [];
      if (res.json && Array.isArray(res.json.results)) {
        for (const r of res.json.results) {
          const page = r.page || {};
          const hosts = [page.domain, page.domainWithoutWww].filter(Boolean);
          for (const h of hosts) {
            const host = String(h).toLowerCase();
            if (host && (host.endsWith('.' + domain) || host === domain)) {
              items.push(subdomain(host, 'urlscan'));
            }
          }
        }
      }
      return { items };
    } catch (e) {
      this.log('warn', `URLScan 查询失败：${e.message}`);
      return { items: [] };
    }
  }
}

module.exports = UrlscanProvider;
