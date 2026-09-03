'use strict';

/**
 * 漏洞 / 暴露面检测 provider（Nuclei / Xray / Goby 思路的轻量只读实现）。
 * 仅检测「明确的高危暴露」与「缺失安全响应头」，不做漏洞利用、不爆破、不登录。
 * 原则：疑似即提示，不确定即忽略（宁缺毋滥）。
 * 每个漏洞均打上 12 类标准标签之一（见 src/core/vuln-categories.js）。
 */

const { BaseProvider, vuln } = require('../../core/base');
const { Pool } = require('../../core/semaphore');
const { request } = require('../../core/http');

// 高危敏感文件：status 200 且命中特征即报高危
const SENSITIVE_FILES = [
  { path: '/.env', severity: 'high', category: '其他', match: /\b(?:DB_PASSWORD|APP_KEY|SECRET|API_KEY)\b/i },
  { path: '/.git/HEAD', severity: 'high', category: '其他', match: /ref:\s*refs\/heads/i },
  { path: '/.aws/credentials', severity: 'high', category: '其他', match: /\[default\]|aws_access_key_id/i },
  { path: '/.ssh/id_rsa', severity: 'high', category: '其他', match: /BEGIN (RSA|OPENSSH) PRIVATE KEY/i },
  { path: '/phpinfo.php', severity: 'medium', category: '其他', match: /phpinfo\(/i },
  { path: '/actuator/env', severity: 'high', category: '未授权访问', match: /"spring\.|"systemProperties"/i },
  { path: '/config.php.bak', severity: 'medium', category: '其他', match: /<\?php/i },
  { path: '/backup.zip', severity: 'medium', category: '其他', match: /PK\x03\x04/ },
  { path: '/.npmrc', severity: 'medium', category: '其他', match: /_authToken|\/\/registry\.npmjs/ },
  { path: '/.docker/config.json', severity: 'medium', category: '其他', match: /"auths"/ },
];

// 缺失安全响应头 → 对应防护类别（用于漏洞分类标签）
const REQUIRED_HEADERS = [
  { name: 'Strict-Transport-Security', label: 'HSTS', category: '其他', note: '未启用 HSTS，存在 SSL 剥离 / 明文降级风险' },
  { name: 'Content-Security-Policy', label: 'CSP', category: 'XSS', note: '缺失 CSP，缺乏 XSS 缓解与资源加载限制' },
  { name: 'X-Frame-Options', label: 'X-Frame-Options', category: 'CSRF', note: '缺失 X-Frame-Options，存在点击劫持（CSRF 衍生）风险' },
  { name: 'X-Content-Type-Options', label: 'X-Content-Type-Options', category: '其他', note: '缺失 X-Content-Type-Options，存在 MIME 嗅探风险' },
];

// 疑似未授权访问 / 信息泄露的管理端点（只读 GET，按响应特征判定）
const UNAUTH_PATHS = [
  { path: '/actuator/env', category: '未授权访问', severity: 'high', title: 'Spring Actuator 未授权访问', match: /"spring\.|"systemProperties"|"environment"/i },
  { path: '/actuator', category: '未授权访问', severity: 'medium', title: 'Spring Actuator 端点暴露', match: /"contexts"|"beans"|"_links"|"environment"/i },
  { path: '/swagger-ui.html', category: '信息泄露', severity: 'medium', title: 'Swagger 文档未授权暴露', match: /swagger/i },
  { path: '/v2/api-docs', category: '信息泄露', severity: 'medium', title: 'Swagger API 文档暴露', match: /"swagger"|"paths"|"definitions"/i },
  { path: '/druid/index.html', category: '未授权访问', severity: 'medium', title: 'Druid 监控未授权访问', match: /Druid|druid/i },
  { path: '/phpmyadmin/', category: '未授权访问', severity: 'medium', title: 'phpMyAdmin 管理面板暴露', match: /phpmyadmin|pma/i },
  { path: '/solr/', category: '未授权访问', severity: 'medium', title: 'Solr 管理后台暴露', match: /solr|lucene/i },
  { path: '/api/health', category: '信息泄露', severity: 'low', title: 'API 健康端点暴露', match: /"status"|"uptime"|"health"/i },
];

// 疑似文件上传入口（只读探测，405/403/200 均提示存在上传处理器）
const UPLOAD_PATHS = ['/upload', '/file/upload', '/attachment/upload', '/api/upload', '/upload/file', '/admin/upload'];

function baseOf(probe) {
  if (probe.https && probe.https.status > 0) return { scheme: 'https', resp: probe.https };
  if (probe.http && probe.http.status > 0) return { scheme: 'http', resp: probe.http };
  return null;
}

class MisconfigProvider extends BaseProvider {
  static id = 'vuln.misconfig';
  static category = 'vuln';
  static label = '暴露面 / 配置检测';
  static description = '检测敏感文件暴露、未授权管理端点、可疑上传入口与缺失安全响应头等明确风险（只读）';
  static priority = 10;

  async run(job) {
    const probes = (job.context && job.context.probes) || {};
    const hosts = Object.keys(probes);
    if (!hosts.length) return { items: [] };
    const items = [];
    const timeout = Math.min(this.ctx.config.timeout, 12000);

    for (const host of hosts) {
      const b = baseOf(probes[host]);
      if (!b) continue;
      const base = `${b.scheme}://${host}`;

      // 1) 缺失安全头
      for (const h of REQUIRED_HEADERS) {
        const present = Object.keys(b.resp.headers || {}).some(
          (k) => k.toLowerCase() === h.name.toLowerCase()
        );
        if (!present) {
          items.push(
            vuln(host, 'missing-header:' + h.label, 'low',
              `缺失响应头 ${h.label}`,
              h.note,
              `期望头 ${h.name} 未出现`, h.category)
          );
        }
      }

      // 2) 高危敏感文件暴露
      const pool = new Pool(8);
      await pool.map(SENSITIVE_FILES, async (f) => {
        try {
          const res = await request(base + f.path, { method: 'GET', timeout, maxRedirects: 1 });
          if (res.status >= 200 && res.status < 300) {
            const body = (res.body || '').slice(0, 64 * 1024);
            if (f.match.test(body)) {
              items.push(
                vuln(host, 'exposed-file:' + f.path, f.severity,
                  `暴露敏感文件 ${f.path}`,
                  `HTTP ${res.status}，命中特征内容（疑似凭据/源码/配置泄露）`,
                  `路径 ${f.path}`, f.category)
              );
            }
          }
        } catch (_) {}
      });

      // 3) 疑似未授权访问 / 信息泄露的管理端点
      await pool.map(UNAUTH_PATHS, async (u) => {
        try {
          const res = await request(base + u.path, { method: 'GET', timeout, maxRedirects: 1 });
          if ((res.status >= 200 && res.status < 300) || res.status === 403) {
            const body = (res.body || '').slice(0, 32 * 1024);
            if (u.match.test(body) || res.status === 403) {
              items.push(
                vuln(host, 'unauth:' + u.path, u.severity,
                  u.title,
                  `端点 ${u.path} 公开可访问（HTTP ${res.status}），存在未授权访问 / 信息泄露风险`,
                  `路径 ${u.path}`, u.category)
              );
            }
          }
        } catch (_) {}
      });

      // 4) 疑似文件上传入口（只读探测，不实际上传）
      await pool.map(UPLOAD_PATHS, async (p) => {
        try {
          const res = await request(base + p, { method: 'GET', timeout, maxRedirects: 0 });
          if ([200, 301, 302, 403, 405].includes(res.status)) {
            items.push(
              vuln(host, 'upload-ep:' + p, 'low',
                `疑似文件上传入口 ${p}`,
                `路径 ${p} 返回 HTTP ${res.status}，疑似存在上传处理器，建议核查是否限制类型/鉴权（文件上传类风险）`,
                `路径 ${p}`, '文件上传')
            );
          }
        } catch (_) {}
      });
    }

    return { items, stats: { hosts: hosts.length, findings: items.length } };
  }
}

module.exports = MisconfigProvider;
