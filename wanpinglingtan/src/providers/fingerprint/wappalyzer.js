'use strict';

/**
 * 技术指纹识别 provider（Wappalyzer / ObserverWard / EHole 思路）。
 * 基于 HTTP 响应头 / 体 / 标题内置签名匹配技术栈。
 */

const { BaseProvider, fingerprint } = require('../../core/base');

function pickResponse(probe) {
  if (probe.https && probe.https.status > 0) return probe.https;
  if (probe.http && probe.http.status > 0) return probe.http;
  return null;
}

class WappalyzerProvider extends BaseProvider {
  static id = 'fingerprint.wappalyzer';
  static category = 'fingerprint';
  static label = '技术指纹 (Wappalyzer)';
  static description = '基于响应特征识别 Web 技术栈（服务器/语言/框架/CDN/CMS 等）';
  static priority = 10;

  async run(job) {
    const probes = (job.context && job.context.probes) || {};
    const hosts = Object.keys(probes);
    if (!hosts.length) return { items: [] };
    const detect = this.ctx.signals.detectTech;

    const items = [];
    for (const host of hosts) {
      const resp = pickResponse(probes[host]);
      if (!resp) continue;
      const tech = detect(resp.headers, resp.body, resp.server, resp.title);
      if (tech && tech.length) {
        items.push(fingerprint(host, tech));
      }
    }
    return { items };
  }
}

module.exports = WappalyzerProvider;
