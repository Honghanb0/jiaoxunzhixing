'use strict';

/**
 * 资产搜索引擎 — FOFA 适配器（密钥门控）。
 * 当配置 fofa_email + fofa_key 时，按域名/ IP 检索暴露资产。
 * 未配置自动停用。参考 Hunter/FOFA/ZoomEye 等网络空间搜索引擎能力。
 */

const { BaseProvider, searchResult } = require('../../core/base');
const { getJson } = require('../../core/http');

class FofaProvider extends BaseProvider {
  static id = 'search.fofa';
  static category = 'search';
  static label = 'FOFA';
  static description = 'FOFA 网络空间搜索引擎（需 fofa_email + fofa_key）';
  static priority = 10;
  static requiresKey = true;
  static keyEnv = 'fofa_key';

  async run(job) {
    const keys = this.ctx.config.keys || {};
    const email = keys.fofa_email;
    const apiKey = keys.fofa_key;
    if (!email || !apiKey) {
      this.log('info', '未配置 FOFA 凭据，跳过');
      return { items: [] };
    }
    const domains = (job.input && job.input.rootDomains) || [];
    if (!domains.length) return { items: [] };
    const query = domains.map((d) => `domain="${d}"`).join(' || ');
    const qbase64 = Buffer.from(query).toString('base64');
    const url = `https://fofa.info/api/v1/search/all?email=${encodeURIComponent(email)}&key=${encodeURIComponent(apiKey)}&qbase64=${encodeURIComponent(qbase64)}&size=100`;
    try {
      const res = await getJson(url, { timeout: this.ctx.config.timeout });
      const items = [];
      if (res.json && Array.isArray(res.json.results)) {
        for (const row of res.json.results) {
          const asset = Array.isArray(row) ? row[0] : row;
          items.push(searchResult(String(asset), 'fofa', JSON.stringify(row)));
        }
      }
      return { items, stats: { total: items.length } };
    } catch (e) {
      this.log('warn', `FOFA 查询失败：${e.message}`);
      return { items: [] };
    }
  }
}

module.exports = FofaProvider;
