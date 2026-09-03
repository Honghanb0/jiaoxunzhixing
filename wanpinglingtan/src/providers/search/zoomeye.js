'use strict';

/**
 * 资产搜索引擎 — ZoomEye 适配器（密钥门控）。
 * 按域名/ IP 检索 ZoomEye 主机数据。
 */

const { BaseProvider, searchResult } = require('../../core/base');
const { getJson } = require('../../core/http');

class ZoomEyeProvider extends BaseProvider {
  static id = 'search.zoomeye';
  static category = 'search';
  static label = 'ZoomEye';
  static description = 'ZoomEye 网络空间搜索引擎（需 zoomeye_key）';
  static priority = 30;
  static requiresKey = true;
  static keyEnv = 'zoomeye_key';

  async run(job) {
    const key = (this.ctx.config.keys || {}).zoomeye_key;
    if (!key) {
      this.log('info', '未配置 ZoomEye key，跳过');
      return { items: [] };
    }
    const domains = (job.input && job.input.rootDomains) || [];
    if (!domains.length) return { items: [] };
    const query = domains.map((d) => `site:"${d}"`).join(' || ');
    const url = `https://api.zoomeye.org/host/search?query=${encodeURIComponent(query)}&page=1`;
    try {
      const res = await getJson(url, { timeout: this.ctx.config.timeout, headers: { 'API-KEY': key } });
      const items = [];
      const list = (res.json && res.json.list) || [];
      for (const r of list) {
        const ip = r.ip || '';
        items.push(searchResult(ip, 'zoomeye', JSON.stringify(r).slice(0, 1500), { port: r.portinfo }));
      }
      return { items };
    } catch (e) {
      this.log('warn', `ZoomEye 查询失败：${e.message}`);
      return { items: [] };
    }
  }
}

module.exports = ZoomEyeProvider;
