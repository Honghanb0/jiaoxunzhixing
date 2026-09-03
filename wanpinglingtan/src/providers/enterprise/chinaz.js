'use strict';

/**
 * 企业信息 provider（站长之家 whois.chinaz.com 备案查询）。
 * 提取域名的 ICP 备案号与主办单位，用于企业身份关联。
 */

const { BaseProvider, enterpriseInfo } = require('../../core/base');
const { getText } = require('../../core/http');

class ChinazProvider extends BaseProvider {
  static id = 'enterprise.chinaz';
  static category = 'enterprise';
  static label = '站长之家 (备案)';
  static description = '查询域名 ICP 备案号与主办单位（企业身份关联）';
  static priority = 10;

  async run(job) {
    const domains = (job.input && job.input.rootDomains) || [];
    if (!domains.length) return { items: [] };
    const timeout = this.ctx.config.timeout;
    const items = [];

    for (const domain of domains) {
      try {
        const res = await getText(`https://whois.chinaz.com/${encodeURIComponent(domain)}`, { timeout });
        const body = res.body || '';
        const icp = (body.match(/ICP备[\w-]*\d+号[^\s<]*/i) || [])[0] || '';
        const orgMatch = body.match(/(?:主办单位名称|单位名称)[^<]*?([^\s<]{2,40})/i)
          || body.match(/name="[\w]*UnitName[^>]*value="([^"]+)"/i);
        const org = orgMatch ? orgMatch[1].trim() : '';
        if (icp || org) {
          items.push(enterpriseInfo({ domain, icp: icp.trim(), org, source: 'chinaz' }));
        }
      } catch (e) {
        this.log('warn', `站长之家查询 ${domain} 失败：${e.message}`);
      }
    }
    return { items };
  }
}

module.exports = ChinazProvider;
