'use strict';

/**
 * HTTP 探测 provider（HTTPX / WebBatchRequest 思路）。
 * 对发现资产做 HTTP/HTTPS 连通性探测，提取：状态码、标题、Server、跳转、响应头。
 * 同时把原始响应当作指纹/漏洞/WAF 阶段的数据源写入 context.probes。
 * 仅做只读 GET，不提交、不爆破。
 */

const { BaseProvider, portFinding } = require('../../core/base');
const { Pool } = require('../../core/semaphore');
const { request } = require('../../core/http');
const { isPublicIPv4 } = require('../../core/utils');

function extractTitle(body) {
  const m = body && body.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  return m ? m[1].replace(/\s+/g, ' ').trim().slice(0, 200) : '';
}

async function probeOne(scheme, target, timeout) {
  const url = `${scheme}://${target}/`;
  try {
    const res = await request(url, { method: 'GET', timeout, maxRedirects: 2 });
    const body = (res.body || '').slice(0, 256 * 1024);
    return {
      url,
      status: res.status,
      title: extractTitle(body),
      server: (res.headers && (res.headers.server || res.headers['server'])) || '',
      location: (res.headers && res.headers.location) || '',
      headers: res.headers || {},
      body,
    };
  } catch (e) {
    return { url, status: 0, error: e.message };
  }
}

class HttpxProvider extends BaseProvider {
  static id = 'port.httpx';
  static category = 'port';
  static label = 'HTTP 探测 (httpx)';
  static description = '对资产进行 HTTP/HTTPS 连通性探测，提取状态码/标题/Server/跳转';
  static priority = 10;

  async run(job) {
    const targets = (job.context && job.context.probeTargets) || [];
    if (!targets.length) return { items: [] };
    const timeout = Math.min(this.ctx.config.timeout, 15000);
    const pool = new Pool(this.ctx.config.concurrency || 24);
    const probes = job.context.probes || (job.context.probes = {});
    const items = [];

    await pool.map(targets, async (target) => {
      const httpProbe = await probeOne('http', target, timeout);
      const httpsProbe = await probeOne('https', target, timeout);
      probes[target] = { host: target, http: null, https: null };
      if (httpProbe.status > 0) probes[target].http = httpProbe;
      if (httpsProbe.status > 0) probes[target].https = httpsProbe;

      if (httpProbe.status > 0) {
        items.push(
          portFinding(target, 80, {
            protocol: 'http',
            service: 'http',
            status: httpProbe.status,
            title: httpProbe.title,
            server: httpProbe.server,
            location: httpProbe.location,
            source: 'httpx',
          })
        );
      }
      if (httpsProbe.status > 0) {
        items.push(
          portFinding(target, 443, {
            protocol: 'https',
            service: 'https',
            status: httpsProbe.status,
            title: httpsProbe.title,
            server: httpsProbe.server,
            location: httpsProbe.location,
            source: 'httpx',
          })
        );
      }
    });

    const responsive = Object.values(probes).filter((p) => p.http || p.https).length;
    return { items, stats: { targets: targets.length, responsive } };
  }
}

module.exports = HttpxProvider;
