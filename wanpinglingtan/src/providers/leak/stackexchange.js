'use strict';

/**
 * 技术论坛泄露监测 provider（StackExchange 网络：StackOverflow / Security / ServerFault 等）。
 * 参考「技术论坛排查敏感信息」需求，检索与目标关键字相关的讨论 / 代码片段。
 */

const { BaseProvider, leakResult } = require('../../core/base');
const { getJson } = require('../../core/http');

const SITES = ['stackoverflow', 'security.stackexchange', 'serverfault', 'superuser', 'askubuntu'];

class StackExchangeProvider extends BaseProvider {
  static id = 'leak.stackexchange';
  static category = 'leak';
  static label = '技术论坛 (StackExchange)';
  static description = '检索 StackExchange 技术论坛中与目标相关的讨论与代码片段';
  static priority = 20;

  async run(job) {
    const inp = job.input || {};
    const keywords = Array.from(
      new Set([...(inp.githubKeywords || []), ...(inp.shortNames || []), ...(inp.rootDomains || [])])
    ).filter(Boolean);
    if (!keywords.length) return { items: [] };
    const timeout = this.ctx.config.timeout;
    const items = [];
    const seen = new Set();

    for (const kw of keywords.slice(0, 10)) {
      for (const site of SITES) {
        try {
          const url =
            `https://api.stackexchange.com/2.3/search/advanced?order=desc&sort=relevance` +
            `&q=${encodeURIComponent(kw)}&site=${site}&pagesize=8&filter=withbody`;
          const res = await getJson(url, { timeout });
          if (res.json && Array.isArray(res.json.items)) {
            for (const it of res.json.items) {
              const link = it.link || '';
              if (!link || seen.has(link)) continue;
              seen.add(link);
              items.push(
                leakResult({
                  title: it.title || '',
                  url: link,
                  source: 'stackexchange',
                  confidence: 'medium',
                  matchedKeyword: kw,
                  snippet: (it.body || '').replace(/<[^>]+>/g, ' ').slice(0, 200),
                  type: 'forum',
                })
              );
            }
          }
        } catch (e) {
          /* 单站点失败不影响其它 */
        }
      }
    }
    return { items, stats: { keywords: keywords.length, items: items.length } };
  }
}

module.exports = StackExchangeProvider;
