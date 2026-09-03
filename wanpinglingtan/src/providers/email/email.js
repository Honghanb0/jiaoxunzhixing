'use strict';

/**
 * 邮箱资产 provider（多后缀批量匹配 + 严格可靠性校验）。
 *  - 从 WHOIS / 泄露文本中提取真实出现的邮箱
 *  - 仅保留命中任一目标后缀者
 *  - 对每个域名做 MX/SPF/DMARC 校验：无任何邮件基础设施的域名视为虚假直接丢弃
 *  - DNS 不可达时（如受限环境）保留来源可靠的邮箱并标记为未验证，绝不误判「全部虚假」
 *  - 默认不含纯猜测角色邮箱（避免不可靠数据）
 */

const { BaseProvider, emailResult } = require('../../core/base');
const coreDns = require('../../core/dns');
const { uniq } = require('../../core/utils');

const EMAIL_REGEX = /[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}/gi;
const FAKE_LOCALPART = /^(test|example|sample|placeholder|user\d*|admin123|root123|foobar|qwerty)$/i;
const FAKE_DOMAINS = new Set(['example.com', 'test.com', 'sample.com', 'localhost', 'invalid', 'domain.com', 'email.com']);

const mailCache = new Map();

async function checkMailDomain(domain) {
  if (mailCache.has(domain)) return mailCache.get(domain);
  let mx = false, spf = false, dmarc = false, error = null;
  try {
    const mxRecs = await coreDns.resolveMx(domain);
    mx = Array.isArray(mxRecs) && mxRecs.length > 0;
  } catch (e) {
    error = e.code || e.message;
  }
  try {
    const txt = await coreDns.resolveTxt(domain);
    const flat = txt.map((r) => (Array.isArray(r) ? r.join('') : r)).join(' ');
    spf = /v=spf1/i.test(flat);
  } catch (_) {}
  try {
    const dtxt = await coreDns.resolveTxt('_dmarc.' + domain);
    dmarc = dtxt.map((r) => (Array.isArray(r) ? r.join('') : r)).join(' ').includes('v=DMARC1');
  } catch (_) {}

  // 区分「域名不存在」与「网络不可达」：仅前者判定为无邮件基础设施
  const mailInfra = mx || spf || dmarc;
  const res = { mx, spf, dmarc, mailInfra, error, unknown: !!error && error !== 'ENOTFOUND' };
  mailCache.set(domain, res);
  return res;
}

function extractRawEmails(text) {
  const out = new Set();
  const matches = String(text || '').match(EMAIL_REGEX) || [];
  for (const m of matches) {
    const e = m.toLowerCase();
    const [local, domain] = e.split('@');
    if (/\.(png|jpg|jpeg|gif|svg|webp|css|js|ico)$/i.test(e)) continue;
    if (FAKE_LOCALPART.test(local)) continue;
    if (FAKE_DOMAINS.has(domain)) continue;
    if (domain.length < 4) continue;
    out.add(e);
  }
  return out;
}

class EmailProvider extends BaseProvider {
  static id = 'email.collector';
  static category = 'email';
  static label = '邮箱资产';
  static description = '多后缀批量匹配 + DNS 可靠性校验，仅保留可信邮箱';
  static priority = 10;

  async run(job) {
    const inp = job.input || {};
    const suffixes = (inp.emailSuffixes || []).map((s) => s.toLowerCase()).filter(Boolean);
    const ctx = job.context || {};
    const texts = [...(ctx.whoisTexts || []), ...(ctx.leakTexts || [])];
    const dnsValidate = true;
    const stats = { generated: 0, extracted: 0, kept: 0, droppedFake: 0, droppedSuffix: 0, droppedNoMail: 0, droppedDup: 0, validated: 0, dnsUnavailable: false };

    if (!suffixes.length) return { items: [] };
    if (suffixes.length) this.log('info', `多后缀批量匹配：${suffixes.join('、')}`);

    const extracted = new Set();
    for (const t of texts) for (const e of extractRawEmails(t)) extracted.add(e);
    stats.extracted = extracted.size;

    const emailSet = uniq([...extracted]);
    const map = new Map();
    for (const email of emailSet) {
      const domain = email.split('@')[1];
      // 后缀匹配（批量）
      const matched = suffixes.find((s) => domain === s || domain.endsWith('.' + s));
      if (!matched) { stats.droppedSuffix++; continue; }
      if (map.has(email)) { stats.droppedDup++; continue; }
      map.set(email, { email, source: '提取', confidence: 'high', matchedSuffix: matched });
    }

    // DNS 可靠性校验
    if (dnsValidate) {
      for (const [email, c] of map) {
        const domain = email.split('@')[1];
        const info = await checkMailDomain(domain);
        if (info.unknown) {
          stats.dnsUnavailable = true;
          c.verified = false; // 不可验证，保留但标记未验证
        } else if (!info.mailInfra) {
          map.delete(email); stats.droppedNoMail++; continue;
        } else {
          c.verified = true; c.mx = info.mx; c.spf = info.spf; c.dmarc = info.dmarc; stats.validated++;
        }
      }
    }

    if (stats.dnsUnavailable) {
      this.log('warn', 'DNS 校验不可用（网络受限）：来源邮箱已保留但标记为「未验证」');
    }

    const items = Array.from(map.values()).map((c) => emailResult(c.email, c));
    stats.kept = items.length;
    return { items, stats };
  }
}

module.exports = EmailProvider;
