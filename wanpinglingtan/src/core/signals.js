'use strict';

/**
 * 技术指纹 / WAF 识别特征库与匹配器。
 * 参考 Wappalyzer / ObserverWard / WhatWaf 思路，使用内置正则签名，
 * 在不依赖外部二进制的情况下对 HTTP 响应做轻量识别。
 *
 * 签名结构：
 *   { name, category, where, pattern, confidence }
 *   where ∈ server | header | cookie | body | title
 *   header 签名的 pattern 同时匹配「头名:值」
 */

const TECH_SIGNATURES = [
  // Web 服务器 / 中间件
  { name: 'Nginx', category: 'web-server', where: 'server', pattern: /nginx/i, confidence: 0.9 },
  { name: 'Apache', category: 'web-server', where: 'server', pattern: /apache/i, confidence: 0.9 },
  { name: 'Microsoft-IIS', category: 'web-server', where: 'server', pattern: /iis/i, confidence: 0.9 },
  { name: 'LiteSpeed', category: 'web-server', where: 'server', pattern: /litespeed/i, confidence: 0.85 },
  { name: 'OpenResty', category: 'web-server', where: 'server', pattern: /openresty/i, confidence: 0.9 },
  { name: 'Tomcat', category: 'web-server', where: 'server', pattern: /tomcat/i, confidence: 0.85 },
  { name: 'Caddy', category: 'web-server', where: 'server', pattern: /caddy/i, confidence: 0.85 },

  // 语言 / 运行时
  { name: 'PHP', category: 'language', where: 'header', pattern: /x-powered-by:\s*php/i, confidence: 0.85 },
  { name: 'PHP', category: 'language', where: 'body', pattern: /\.php(\?|$)/i, confidence: 0.5 },
  { name: 'ASP.NET', category: 'language', where: 'header', pattern: /x-aspnet-version|x-aspnetmvc-version/i, confidence: 0.9 },
  { name: 'ASP.NET', category: 'language', where: 'cookie', pattern: /asp\.net|__viewstate|aspnet/i, confidence: 0.7 },
  { name: 'Java/JSP', category: 'language', where: 'cookie', pattern: /jsessionid|jserv/i, confidence: 0.8 },
  { name: 'Java/Spring', category: 'language', where: 'body', pattern: /spring|springboot|whitelabel error/i, confidence: 0.7 },
  { name: 'Python', category: 'language', where: 'header', pattern: /(django|flask|werkzeug|python)/i, confidence: 0.7 },
  { name: 'Node.js', category: 'language', where: 'header', pattern: /express|x-powered-by:\s*node/i, confidence: 0.7 },
  { name: 'Go', category: 'language', where: 'server', pattern: /\bgo-http-server\b/i, confidence: 0.8 },

  // CMS / 框架
  { name: 'WordPress', category: 'cms', where: 'body', pattern: /wp-content|wp-includes|wordpress/i, confidence: 0.85 },
  { name: 'Drupal', category: 'cms', where: 'body', pattern: /drupal|sites\/default\/files/i, confidence: 0.8 },
  { name: 'Joomla', category: 'cms', where: 'body', pattern: /\/media\/jui\/|joomla/i, confidence: 0.8 },
  { name: 'Discuz!', category: 'cms', where: 'body', pattern: /discuz|forum\.php/i, confidence: 0.8 },
  { name: 'ThinkPHP', category: 'framework', where: 'body', pattern: /thinkphp/i, confidence: 0.75 },
  { name: 'Vue.js', category: 'frontend', where: 'body', pattern: /vue(\.min)?\.js|__nuxt/i, confidence: 0.75 },
  { name: 'React', category: 'frontend', where: 'body', pattern: /react(\.production)?\.min\.js|reactjs/i, confidence: 0.7 },
  { name: 'jQuery', category: 'frontend', where: 'body', pattern: /jquery(\.min)?\.js/i, confidence: 0.6 },
  { name: 'Bootstrap', category: 'frontend', where: 'body', pattern: /bootstrap(\.min)?\.(css|js)/i, confidence: 0.6 },
  { name: 'Angular', category: 'frontend', where: 'body', pattern: /angular(\.min)?\.js|ng-app/i, confidence: 0.7 },

  // 云服务 / CDN
  { name: 'Cloudflare', category: 'cdn', where: 'header', pattern: /(cf-ray|server:\s*cloudflare|__cfduid)/i, confidence: 0.9 },
  { name: 'Akamai', category: 'cdn', where: 'header', pattern: /akamai|x-akamai/i, confidence: 0.85 },
  { name: 'Amazon-S3', category: 'cloud', where: 'server', pattern: /amazons3|s3\.amazonaws/i, confidence: 0.85 },
  { name: 'Amazon-CloudFront', category: 'cdn', where: 'server', pattern: /cloudfront/i, confidence: 0.85 },
  { name: 'Google-Cloud', category: 'cloud', where: 'server', pattern: /gse|google frontend/i, confidence: 0.8 },
  { name: 'Tencent-CDN', category: 'cdn', where: 'header', pattern: /(x-nws|tencent|qcloud)/i, confidence: 0.8 },
  { name: 'Baidu-CDN', category: 'cdn', where: 'server', pattern: /bws|baidu/i, confidence: 0.7 },
  { name: 'Alibaba-CDN', category: 'cdn', where: 'server', pattern: /tengine|aliyun/i, confidence: 0.8 },

  // 安全 / 分析
  { name: 'Google-Analytics', category: 'analytics', where: 'body', pattern: /google-analytics|gtag|ga\.js|ga\('/i, confidence: 0.7 },
  { name: 'Baidu-Tongji', category: 'analytics', where: 'body', pattern: /hm\.baidu\.com|百度统计/i, confidence: 0.7 },
  { name: 'reCAPTCHA', category: 'security', where: 'body', pattern: /recaptcha|gstatic\.com\/recaptcha/i, confidence: 0.7 },
];

const WAF_SIGNATURES = [
  { name: 'Cloudflare', where: 'header', pattern: /(cf-ray|cf-cache-status|server:\s*cloudflare)/i, confidence: 0.95 },
  { name: 'AWS-WAF / CloudFront', where: 'header', pattern: /x-amz-cf-id|x-amzn-requestid/i, confidence: 0.8 },
  { name: 'Akamai', where: 'header', pattern: /akamaighost|x-akamai/i, confidence: 0.9 },
  { name: 'F5-BIG-IP', where: 'header', pattern: /bigipserver|ts01=|x-waf/i, confidence: 0.85 },
  { name: 'ModSecurity', where: 'header', pattern: /mod_security|this error was generated by mod_security/i, confidence: 0.8 },
  { name: 'Sucuri', where: 'header', pattern: /x-sucuri-id|sucuri/i, confidence: 0.85 },
  { name: 'Wordfence', where: 'body', pattern: /generated by wordfence/i, confidence: 0.85 },
  { name: 'FortiWeb', where: 'header', pattern: /fortiwaf|fortiweb/i, confidence: 0.85 },
  { name: 'DenyAll', where: 'header', pattern: /sessioncookie|denyall/i, confidence: 0.7 },
  { name: 'Imperva-Incapsula', where: 'header', pattern: /incap_ses|x-iinfo|visid_incap/i, confidence: 0.85 },
  { name: 'Nginx-WAF', where: 'server', pattern: /nginx\+waf|wangzhan\.360/i, confidence: 0.6 },
  { name: 'Yundun', where: 'header', pattern: /yundun|cloudwaf/i, confidence: 0.7 },
];

function buildMatchContext(headers, body, server, title) {
  const flatHeaders = Object.entries(headers || {})
    .map(([k, v]) => `${k.toLowerCase()}:${Array.isArray(v) ? v.join(',') : v}`)
    .join('\n');
  const cookies = Array.isArray(headers && headers['set-cookie'])
    ? headers['set-cookie'].join('\n')
    : String((headers && headers['set-cookie']) || '');
  return {
    server: server || (headers && (headers.server || '')) || '',
    flatHeaders: flatHeaders.toLowerCase(),
    cookies: cookies.toLowerCase(),
    body: body || '',
    title: title || '',
  };
}

function matchOne(sig, ctx) {
  const re = sig.pattern instanceof RegExp ? sig.pattern : new RegExp(sig.pattern, 'i');
  switch (sig.where) {
    case 'server':
      return re.test(ctx.server);
    case 'header':
      return re.test(ctx.flatHeaders);
    case 'cookie':
      return re.test(ctx.cookies);
    case 'title':
      return re.test(ctx.title);
    case 'body':
    default:
      return re.test(ctx.body);
  }
}

/** 返回识别到的技术列表：[{name, category, confidence}]（去重取最高置信度） */
function detectTech(headers, body, server, title) {
  const ctx = buildMatchContext(headers, body, server, title);
  const byName = new Map();
  for (const sig of TECH_SIGNATURES) {
    if (matchOne(sig, ctx)) {
      const prev = byName.get(sig.name);
      if (!prev || sig.confidence > prev.confidence) {
        byName.set(sig.name, {
          name: sig.name,
          category: sig.category,
          confidence: sig.confidence,
        });
      }
    }
  }
  return Array.from(byName.values());
}

/** 返回识别到的 WAF 列表：[{name, confidence}] */
function detectWaf(headers, body, server, title) {
  const ctx = buildMatchContext(headers, body, server, title);
  const out = [];
  for (const sig of WAF_SIGNATURES) {
    if (matchOne(sig, ctx)) {
      out.push({ name: sig.name, confidence: sig.confidence });
    }
  }
  return out;
}

module.exports = { detectTech, detectWaf, TECH_SIGNATURES, WAF_SIGNATURES };
