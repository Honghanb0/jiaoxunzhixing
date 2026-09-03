'use strict';

/**
 * GitHub 泄露监测 provider（GitHub 监测 / 代码敏感关键字思路）。
 *  - 仓库检索：按企业关键字 / 域名 / 简称检索相关仓库
 *  - 代码检索：按「关键字 × 敏感词」检索代码（需 Token，无 Token 时优雅降级）
 *  - 仅保留与目标相关、且尽量高置信的结果
 */

const { BaseProvider, leakResult } = require('../../core/base');
const { getJson } = require('../../core/http');

const CODE_SENSITIVE_DEFAULT = ['password', 'pass', 'secret', 'token', 'api_key', 'credential', 'private_key'];

function headers(token) {
  const h = { Accept: 'application/vnd.github+json' };
  if (token) h.Authorization = `Bearer ${token}`;
  return h;
}

class GithubProvider extends BaseProvider {
  static id = 'leak.github';
  static category = 'leak';
  static label = 'GitHub 监测';
  static description = '检索相关仓库与可能泄露敏感信息的代码（代码检索需 Token）';
  static priority = 10;

  async run(job) {
    const inp = job.input || {};
    const keywords = Array.from(
      new Set([...(inp.githubKeywords || []), ...(inp.shortNames || []), ...(inp.fullNames || []), ...(inp.rootDomains || [])])
    ).filter(Boolean);
    if (!keywords.length) return { items: [] };
    const sensitive = (inp.sensitiveKeywords && inp.sensitiveKeywords.length)
      ? inp.sensitiveKeywords
      : CODE_SENSITIVE_DEFAULT;
    const token = this.ctx.config.githubToken;
    const timeout = this.ctx.config.timeout;
    const items = [];
    const seen = new Set();

    const push = (it) => {
      const key = it.url || it.title;
      if (!key || seen.has(key)) return;
      seen.add(key);
      items.push(leakResult(it));
    };

    // 仓库检索
    for (const kw of keywords.slice(0, 12)) {
      try {
        const res = await getJson(
          `https://api.github.com/search/repositories?q=${encodeURIComponent(kw)}&per_page=15`,
          { headers: headers(token), timeout }
        );
        if (res.json && Array.isArray(res.json.items)) {
          for (const r of res.json.items) {
            push({
              title: r.full_name,
              url: r.html_url,
              source: 'github',
              confidence: 'medium',
              matchedKeyword: kw,
              snippet: r.description || '',
              type: 'repo',
            });
          }
        }
      } catch (e) {
        this.log('warn', `GitHub 仓库检索(${kw}) 失败：${e.message}`);
      }
    }

    // 代码检索（需 Token）
    if (token) {
      for (const kw of keywords.slice(0, 8)) {
        for (const s of sensitive.slice(0, 5)) {
          try {
            const q = `${kw} ${s} in:file`;
            const res = await getJson(
              `https://api.github.com/search/code?q=${encodeURIComponent(q)}&per_page=10`,
              { headers: headers(token), timeout }
            );
            if (res.json && Array.isArray(res.json.items)) {
              for (const r of res.json.items) {
                push({
                  title: `${r.repository ? r.repository.full_name : ''} / ${r.path}`,
                  url: r.html_url || (r.repository && r.repository.html_url),
                  source: 'github',
                  confidence: 'high',
                  matchedKeyword: `${kw} + ${s}`,
                  snippet: `代码命中敏感关键字：${s}`,
                  type: 'code',
                });
              }
            }
          } catch (e) {
            /* 代码检索限流常见，忽略 */
          }
        }
      }
    } else {
      this.log('info', '未提供 GitHub Token，跳过代码级敏感检索（仅仓库检索）');
    }

    return { items, stats: { keywords: keywords.length, repos: items.filter((i) => i.type === 'repo').length, code: items.filter((i) => i.type === 'code').length } };
  }
}

module.exports = GithubProvider;
