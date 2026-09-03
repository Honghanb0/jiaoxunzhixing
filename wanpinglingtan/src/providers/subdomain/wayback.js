'use strict';

/** 子域名 — Wayback Machine CDX（历史快照被动收集，Subfinder/Amass 同类） */
const { BaseProvider, subdomain } = require('../../core/base');
const { getJson } = require('../../core/http');

class WaybackProvider extends BaseProvider {
  static id = 'subdomain.wayback';
  static category = 'subdomain';
  static label = 'Wayback CDX';
  static description = '通过 Wayback Machine 历史快照 URL 提取曾出现的子域名';
  static priority = 40;

  async run(job) {
    const domain = job.domain || (job.input && job.input.rootDomains && job.input.rootDomains[0]);
    if (!domain) return { items: [] };
    const url =
      `http://web.archive.org/cdx/search/cdx?url=*.${encodeURIComponent(domain)}` +
      `&output=json&collapse=urlkey&fl=original&limit=3000`;
    try {
      const res = await getJson(url, { timeout: this.ctx.config.timeout });
      const items = [];
      if (Array.isArray(res.json)) {
        for (const row of res.json) {
          const orig = Array.isArray(row) ? row[0] : row;
          if (!orig || typeof orig !== 'string') continue;
          try {
            const u = new URL(orig);
            const host = u.hostname.toLowerCase();
            if (host && host.includes('.') && (host.endsWith('.' + domain) || host === domain)) {
              items.push(subdomain(host, 'wayback'));
            }
          } catch (_) {
            /* 非合法 URL 跳过 */
          }
        }
      }
      return { items };
    } catch (e) {
      this.log('warn', `Wayback 查询失败：${e.message}`);
      return { items: [] };
    }
  }
}

module.exports = WaybackProvider;
