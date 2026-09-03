'use strict';

/**
 * 资产搜索引擎 — Quake (360) 适配器（密钥门控）。
 * 按域名检索 Quake 主机数据。
 */

const { BaseProvider, searchResult } = require('../../core/base');
const { getJson } = require('../../core/http');

class QuakeProvider extends BaseProvider {
  static id = 'search.quake';
  static category = 'search';
  static label = 'Quake (360)';
  static description = '360 Quake 网络空间搜索引擎（需 quake_key）';
  static priority = 40;
  static requiresKey = true;
  static keyEnv = 'quake_key';

  async run(job) {
    const key = (this.ctx.config.keys || {}).quake_key;
    if (!key) {
      this.log('info', '未配置 Quake key，跳过');
      return { items: [] };
    }
    const domains = (job.input && job.input.rootDomains) || [];
    if (!domains.length) return { items: [] };
    const query = domains.map((d) => `domain:"${d}"`).join(' OR ');
    try {
      const res = await getJson('https://quake.360.net/api/v3/search/quake', {
        method: 'POST',
        timeout: this.ctx.config.timeout,
        headers: { 'X-QuakeToken': key, 'Content-Type': 'application/json' },
        body: JSON.stringify({ query, start: 0, size: 50 }),
      });
      const items = [];
      const data = (res.json && res.json.data) || [];
      for (const r of data) {
        items.push(searchResult(String(r.ip || r.host || ''), 'quake', JSON.stringify(r).slice(0, 1500)));
      }
      return { items };
    } catch (e) {
      this.log('warn', `Quake 查询失败：${e.message}`);
      return { items: [] };
    }
  }
}

module.exports = QuakeProvider;
