'use strict';

/**
 * WAF 识别 provider（WhatWaf / wafw00f 思路）。
 * 基于响应特征识别网站防护（Cloudflare / Akamai / WAF 等），
 * 结果以「security」类技术形式并入指纹，统一在指纹 Tab 展示。
 */

const { BaseProvider, fingerprint } = require('../../core/base');

function pickResponse(probe) {
  if (probe.https && probe.https.status > 0) return probe.https;
  if (probe.http && probe.http.status > 0) return probe.http;
  return null;
}

class WafProvider extends BaseProvider {
  static id = 'port.waf';
  static category = 'fingerprint';
  static label = 'WAF 识别 (WhatWaf)';
  static description = '基于响应特征识别 WAF / 网站防护产品';
  static priority = 20;

  async run(job) {
    const probes = (job.context && job.context.probes) || {};
    const hosts = Object.keys(probes);
    if (!hosts.length) return { items: [] };
    const detect = this.ctx.signals.detectWaf;

    const items = [];
    for (const host of hosts) {
      const resp = pickResponse(probes[host]);
      if (!resp) continue;
      const wafs = detect(resp.headers, resp.body, resp.server, resp.title);
      if (wafs && wafs.length) {
        items.push(
          fingerprint(
            host,
            wafs.map((w) => ({ name: w.name, category: 'security', confidence: w.confidence }))
          )
        );
      }
    }
    return { items };
  }
}

module.exports = WafProvider;
