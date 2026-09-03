'use strict';

/**
 * WHOIS provider（站长之家 / RDAP / TCP:43 思路）。
 * 优先使用 RDAP（现代 JSON 接口），失败时回退到传统 WHOIS TCP:43 查询。
 * 提取注册信息用于企业关联与邮箱提取（供邮箱阶段复用）。
 */

const net = require('net');
const { BaseProvider, whoisResult } = require('../../core/base');
const { getJson } = require('../../core/http');

function tcpWhois(server, query, timeout) {
  return new Promise((resolve) => {
    const sock = net.connect(43, server);
    let buf = '';
    let done = false;
    const finish = (data) => {
      if (done) return;
      done = true;
      try { sock.destroy(); } catch (_) {}
      resolve(data);
    };
    sock.setTimeout(timeout);
    sock.once('connect', () => sock.write(query + '\r\n'));
    sock.on('data', (d) => (buf += d.toString('utf8')));
    sock.once('timeout', () => finish(buf));
    sock.once('close', () => finish(buf));
    sock.once('error', () => finish(buf));
  });
}

function parseRdap(json) {
  const fields = {};
  if (Array.isArray(json.nameservers)) {
    fields.nameservers = json.nameservers.map((n) => n.ldhName).filter(Boolean);
  }
  if (Array.isArray(json.events)) {
    for (const ev of json.events) {
      if (ev.eventAction === 'registration' || ev.eventAction === 'created') fields.created = ev.eventDate;
      if (ev.eventAction === 'expiration' || ev.eventAction === 'expires') fields.expires = ev.eventDate;
      if (ev.eventAction === 'last changed' || ev.eventAction === 'last update of RDAP database') fields.updated = ev.eventDate;
    }
  }
  if (Array.isArray(json.entities)) {
    for (const e of json.entities) {
      if ((e.roles || []).includes('registrar')) fields.registrar = (e.vcardArray && e.vcardArray[1]) ? vcardToText(e.vcardArray) : (e.handle || '');
      if ((e.roles || []).includes('registrant')) fields.registrant = vcardToText(e.vcardArray);
    }
  }
  if (Array.isArray(json.status)) fields.status = json.status;
  return fields;
}

function vcardToText(vcard) {
  if (!Array.isArray(vcard) || !Array.isArray(vcard[1])) return '';
  const out = [];
  for (const prop of vcard[1]) {
    if (Array.isArray(prop) && (prop[0] === 'fn' || prop[0] === 'org' || prop[0] === 'email')) {
      out.push(prop[prop.length - 1]);
    }
  }
  return out.filter(Boolean).join(', ');
}

class WhoisProvider extends BaseProvider {
  static id = 'whois.collector';
  static category = 'whois';
  static label = 'WHOIS / RDAP';
  static description = '查询域名注册信息（RDAP 优先，TCP:43 回退）';
  static priority = 10;

  async run(job) {
    const domains = (job.input && job.input.rootDomains) || [];
    if (!domains.length) return { items: [] };
    const timeout = Math.min(this.ctx.config.timeout, 15000);
    const items = [];

    for (const domain of domains) {
      let fields = {};
      let raw = '';
      let source = '';
      try {
        const res = await getJson(`https://rdap.org/domain/${encodeURIComponent(domain)}`, { timeout });
        if (res.json && !res.json.errorCode) {
          fields = parseRdap(res.json);
          raw = JSON.stringify(res.json);
          source = 'rdap';
        }
      } catch (_) {}

      if (!source) {
        try {
          const txt = await tcpWhois('whois.verisign-grs.com', domain, timeout);
          if (txt && txt.length > 20) {
            raw = txt;
            source = 'whois:43';
            fields = parseClassicWhois(txt);
          }
        } catch (e) {
          this.log('warn', `WHOIS ${domain} 失败：${e.message}`);
        }
      }

      items.push(whoisResult(domain, fields, source, raw));
    }
    return { items };
  }
}

function parseClassicWhois(txt) {
  const fields = {};
  const get = (re) => {
    const m = txt.match(re);
    return m ? m[1].trim() : '';
  };
  const ns = txt.match(/Name Server:\s*([^\n]+)/gi);
  if (ns) fields.nameservers = ns.map((s) => s.replace(/Name Server:\s*/i, '').trim());
  fields.registrar = get(/Registrar:\s*([^\n]+)/i);
  fields.created = get(/Creation Date:\s*([^\n]+)/i) || get(/Created:\s*([^\n]+)/i);
  fields.expires = get(/Expir(?:y|ation) Date:\s*([^\n]+)/i);
  fields.registrant = get(/Registrant Organization:\s*([^\n]+)/i) || get(/Registrant:\s*([^\n]+)/i);
  const email = txt.match(/Registrant Email:\s*([^\n]+)/i);
  if (email) fields.email = email[1].trim();
  return fields;
}

module.exports = WhoisProvider;
