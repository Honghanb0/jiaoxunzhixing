'use strict';

/**
 * 社区 / 账号平台泄露监测 provider（Reddit 思路，覆盖账号平台与社区讨论）。
 * 通过 Reddit 公开搜索 JSON 接口检索与目标相关的帖子 / 评论。
 */

const { BaseProvider, leakResult } = require('../../core/base');
const { getJson } = require('../../core/http');

class RedditProvider extends BaseProvider {
  static id = 'leak.reddit';
  static category = 'leak';
  static label = '社区 (Reddit)';
  static description = '检索 Reddit 社区中与目标相关的公开讨论（账号/泄露线索）';
  static priority = 30;

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
      try {
        const url = `https://www.reddit.com/search.json?q=${encodeURIComponent(kw)}&limit=15`;
        const res = await getJson(url, { timeout, headers: { 'User-Agent': 'AssetCollector/2.0' } });
        const children = res.json && res.json.data && res.json.data.children;
        if (Array.isArray(children)) {
          for (const c of children) {
            const d = c.data || {};
            const permalink = d.permalink ? `https://www.reddit.com${d.permalink}` : '';
            if (!permalink || seen.has(permalink)) continue;
            seen.add(permalink);
            items.push(
              leakResult({
                title: d.title || '',
                url: permalink,
                source: 'reddit',
                confidence: 'medium',
                matchedKeyword: kw,
                snippet: (d.selftext || '').slice(0, 200),
                type: 'community',
              })
            );
          }
        }
      } catch (e) {
        this.log('warn', `Reddit 检索(${kw}) 失败：${e.message}`);
      }
    }
    return { items, stats: { keywords: keywords.length, items: items.length } };
  }
}

module.exports = RedditProvider;
