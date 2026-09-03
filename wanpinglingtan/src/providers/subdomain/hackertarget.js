'use strict';

/** 子域名 — HackerTarget hostsearch（被动 DNS，OneForAll 数据源之一） */
const { BaseProvider, subdomain } = require('../../core/base');
const { getText } = require('../../core/http');

class HackerTargetProvider extends BaseProvider {
  static id = 'subdomain.hackertarget';
  static category = 'subdomain';
  static label = 'HackerTarget';
  static description = '通过 HackerTarget 被动 DNS 接口发现子域名与关联 IP';
  static priority = 20;

  async run(job) {
    const domain = job.domain || (job.input && job.input.rootDomains && job.input.rootDomains[0]);
    if (!domain) return { items: [] };
    const url = `https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(domain)}`;
    try {
      const res = await getText(url, { timeout: this.ctx.config.timeout });
      const items = [];
      for (const line of res.body.split('\n')) {
        const [host] = line.split(',');
        if (host && host.includes(domain)) {
          items.push(subdomain(host.trim().toLowerCase(), 'hackertarget'));
        }
      }
      return { items };
    } catch (e) {
      this.log('warn', `HackerTarget 查询失败：${e.message}`);
      return { items: [] };
    }
  }
}

module.exports = HackerTargetProvider;
