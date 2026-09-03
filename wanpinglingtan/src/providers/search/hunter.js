'use strict';

/**
 * 资产搜索引擎 — Hunter (奇安信) 适配器（密钥门控）。
 * 按域名检索 Hunter 资产数据。
 */

const { BaseProvider, searchResult } = require('../../core/base');
const { getJson } = require('../../core/http');

class HunterProvider extends BaseProvider {
  static id = 'search.hunter';
  static category = 'search';
  static label = 'Hunter (奇安信)';
  static description = 'Hunter 网络空间搜索引擎（需 hunter_key）';
  static priority = 50;
  static requiresKey = true;
  static keyEnv = 'hunter_key';

  async run(job) {
    const key = (this.ctx.config.keys || {}).hunter_key;
    if (!key) {
      this.log('info', '未配置 Hunter key，跳过');
      return { items: [] };
    }
    const domains = (job.input && job.input.rootDomains) || [];
    if (!domains.length) return { items: [] };
    const query = domains.map((d) => `domain="${d}"`).join(' OR ');
    const url = `https://hunter.qianxin.com/openapi/v3/banner/search?api-key=${encodeURIComponent(key)}&q=${encodeURIComponent(query)}&size=50&page=1`;
    try {
      const res = await getJson(url, { timeout: this.ctx.config.timeout });
      const items = [];
      const arr = res.json && res.json.data && res.json.data.list;
      if (Array.isArray(arr)) {
        for (const r of arr) {
          items.push(searchResult(String(r.ip || ''), 'hunter', JSON.stringify(r).slice(0, 1500), { port: r.port, domain: r.domain }));
        }
      }
      return { items };
    } catch (e) {
      this.log('warn', `Hunter 查询失败：${e.message}`);
      return { items: [] };
    }
  }
}

module.exports = HunterProvider;
