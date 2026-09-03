'use strict';

/**
 * 资产搜索引擎 — Shodan 适配器（密钥门控）。
 * 对发现的 IP 资产查询 Shodan 主机情报（开放端口、组织、服务指纹）。
 */

const { BaseProvider, searchResult } = require('../../core/base');
const { getJson } = require('../../core/http');
const { uniq, isPublicIPv4 } = require('../../core/utils');

class ShodanProvider extends BaseProvider {
  static id = 'search.shodan';
  static category = 'search';
  static label = 'Shodan';
  static description = 'Shodan 主机情报（需 shodan_key）';
  static priority = 20;
  static requiresKey = true;
  static keyEnv = 'shodan_key';

  async run(job) {
    const key = (this.ctx.config.keys || {}).shodan_key;
    if (!key) {
      this.log('info', '未配置 Shodan key，跳过');
      return { items: [] };
    }
    const ctx = job.context || {};
    const ips = uniq([...Array.from(ctx.discoveredIps || []), ...(ctx.ipInputs || [])]).filter(isPublicIPv4).slice(0, 100);
    if (!ips.length) return { items: [] };
    const items = [];
    for (const ip of ips) {
      try {
        const res = await getJson(`https://api.shodan.io/shodan/host/${encodeURIComponent(ip)}?key=${encodeURIComponent(key)}`, {
          timeout: this.ctx.config.timeout,
        });
        if (res.json && !res.json.error) {
          items.push(
            searchResult(ip, 'shodan', JSON.stringify(res.json).slice(0, 2000), {
              org: res.json.org,
              os: res.json.os,
              ports: res.json.ports,
              hostnames: res.json.hostnames,
            })
          );
        }
      } catch (e) {
        /* 单 IP 失败忽略 */
      }
    }
    return { items };
  }
}

module.exports = ShodanProvider;
