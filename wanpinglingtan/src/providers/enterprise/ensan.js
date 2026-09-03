'use strict';

/**
 * 企业信息 provider — ENScan 适配器（密钥门控）。
 * ENScan（便捷的企查/信息收集工具）通常本地运行并暴露 HTTP API。
 * 本 provider 为适配器：当用户在「密钥/配置」中提供 ENScan 的
 *   - ensan_endpoint（如 http://127.0.0.1:8080）
 *   - ensan_key（若有鉴权）
 * 时，按企业关键字查询并归一化结果；未配置则自动停用（宁缺毋滥）。
 */

const { BaseProvider, enterpriseInfo } = require('../../core/base');
const { getJson } = require('../../core/http');

class EnsanProvider extends BaseProvider {
  static id = 'enterprise.ensan';
  static category = 'enterprise';
  static label = 'ENScan (企查)';
  static description = 'ENScan 企业信息适配器（需本地服务 endpoint + key）';
  static priority = 20;
  static requiresKey = true;
  static keyEnv = 'ensan_key';

  async run(job) {
    const keys = this.ctx.config.keys || {};
    const endpoint = keys.ensan_endpoint;
    const key = keys.ensan_key;
    if (!endpoint) {
      this.log('info', '未配置 ENScan endpoint，跳过');
      return { items: [] };
    }
    const keywords = Array.from(
      new Set([...(job.input.shortNames || []), ...(job.input.fullNames || []), ...(job.input.rootDomains || [])])
    ).filter(Boolean);
    if (!keywords.length) return { items: [] };
    const timeout = this.ctx.config.timeout;
    const items = [];

    for (const kw of keywords.slice(0, 10)) {
      try {
        const url = `${endpoint.replace(/\/$/, '')}/api/enterprise?keyword=${encodeURIComponent(kw)}`;
        const headers = key ? { Authorization: `Bearer ${key}` } : {};
        const res = await getJson(url, { timeout, headers });
        const data = res.json;
        if (Array.isArray(data)) {
          for (const d of data) items.push(enterpriseInfo({ ...d, source: 'ensan', keyword: kw }));
        } else if (data && typeof data === 'object') {
          items.push(enterpriseInfo({ ...data, source: 'ensan', keyword: kw }));
        }
      } catch (e) {
        this.log('warn', `ENScan 查询(${kw}) 失败：${e.message}`);
      }
    }
    return { items };
  }
}

module.exports = EnsanProvider;
