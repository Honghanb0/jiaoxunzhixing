'use strict';

/** 子域名 — crt.sh（证书透明度被动收集，OneForAll/Subfinder 同类数据源） */
const { BaseProvider, subdomain } = require('../../core/base');
const { getJson } = require('../../core/http');

class CrtShProvider extends BaseProvider {
  static id = 'subdomain.crtsh';
  static category = 'subdomain';
  static label = 'crt.sh (证书透明度)';
  static description = '通过证书透明度(CT)日志被动发现子域名';
  static priority = 10;

  async run(job) {
    const domain = job.domain || (job.input && job.input.rootDomains && job.input.rootDomains[0]);
    if (!domain) return { items: [] };
    const url = `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`;
    try {
      const res = await getJson(url, { timeout: this.ctx.config.timeout });
      const items = [];
      if (res.json && Array.isArray(res.json)) {
        for (const e of res.json) {
          const names = [e.common_name, e.name_value].filter(Boolean);
        for (const raw of names) {
          for (const line of String(raw).split(/\n/)) {
            let host = line.trim().toLowerCase();
            host = host.replace(/^\*\./, '').replace(/^https?:\/\//, '').replace(/:.*$/, '').replace(/\/.*$/, '');
            if (host && host.includes('.') && (host.endsWith('.' + domain) || host === domain)) {
              items.push(subdomain(host, 'crt.sh'));
            }
          }
        }
        }
      }
      return { items };
    } catch (e) {
      this.log('warn', `crt.sh 查询失败：${e.message}`);
      return { items: [] };
    }
  }
}

module.exports = CrtShProvider;
