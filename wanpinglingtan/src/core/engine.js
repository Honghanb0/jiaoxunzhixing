'use strict';

/**
 * 调度引擎：将各分类 provider 编排为一条「资产发现流水线」。
 *
 * 设计要点：
 *  - 阶段化：subdomain → dns → ip → port → fingerprint → vuln → email → leak → enterprise → search
 *  - 并发受控：DNS 解析 / HTTP 探测 / 端口扫描均经信号量限制
 *  - 错误隔离：单个 provider 抛错只告警，不影响其它 provider 与阶段
 *  - 去重与过滤：每个分类按 key 去重；IP 仅留公网；邮箱/泄露严格相关性过滤
 *  - 结构化输出：meta 含 scope / rules / dedup / availableProviders，便于审计
 *
 * 容错原则：宁可返回空，也不纳入不可靠或疑似虚假资产。
 */

const path = require('path');
const { getRegistry } = require('./registry');
const { Pool } = require('./semaphore');
const httpClient = require('./http');
const signals = require('./signals');
const coreDns = require('./dns');
const {
  isPublicIPv4,
  ipScope,
  cleanDomain,
  splitList,
  splitKeywords,
  dedupByKey,
  uniq,
} = require('./utils');
const { expandCidr } = require('../utils/cidr');

// 分类 -> 前端 partial 通道名
const PARTIAL_CHANNEL = {
  subdomain: 'subdomains',
  dns: 'records',
  ip: 'ips',
  port: 'ports',
  fingerprint: 'fingerprints',
  vuln: 'vulns',
  enterprise: 'enterprise',
  search: 'search',
  leak: 'leaks',
  email: 'emails',
  whois: 'whois',
};

// 分类 -> 结果数组字段
const RESULT_FIELD = {
  subdomain: 'subdomains',
  dns: 'records',
  ip: 'ips',
  port: 'ports',
  fingerprint: 'fingerprints',
  vuln: 'vulns',
  enterprise: 'enterprise',
  search: 'search',
  leak: 'leaks',
  email: 'emails',
  whois: 'whois',
};

// 去重 key 函数（按分类）
const DEDUP_KEY = {
  subdomain: (i) => i.host,
  dns: (i) => `${i.type}|${i.host}|${i.value}`,
  ip: (i) => i.ip,
  port: (i) => `${i.target}|${i.port}|${i.protocol}|${i.service || ''}`,
  fingerprint: (i) => i.host, // 按 host 分组合并 tech
  vuln: (i) => `${i.host}|${i.type}`,
  enterprise: (i) => i.name || i.domain || i.icp,
  search: (i) => `${i.source}|${i.asset}`,
  leak: (i) => i.url || i.title,
  email: (i) => i.email,
  whois: (i) => i.domain,
};

const COMMON_PORTS = [
  21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445, 465,
  512, 513, 514, 587, 636, 873, 993, 995, 1080, 1433, 1521, 2049, 2121, 3128,
  3306, 3389, 3690, 4444, 4848, 5000, 5432, 5601, 5900, 5984, 6379, 7001,
  7002, 8080, 8081, 8443, 8888, 9000, 9043, 9090, 9200, 10000, 11211, 27017,
  28017, 50070, 50075,
];

class Engine {
  constructor(registry) {
    this.registry = registry || getRegistry();
  }

  /** 运行完整流水线 */
  async run(form, emitter) {
    const log = (lv, m) => emitter.log(lv, m);
    const startedAt = Date.now();
    const reg = this.registry;

    // ---------------- 归一化输入 ----------------
    const rootDomains = uniq(splitList(form.rootDomain).map(cleanDomain).filter((d) => d.includes('.')));
    const ipTargetsRaw = splitList(form.ipRange);
    const shortNames = splitKeywords(form.companyShort);
    const fullNames = form.companyFull ? [String(form.companyFull).trim()].filter(Boolean) : [];
    const emailSuffixes = uniq(splitList(form.emailSuffix).map(cleanDomain).filter(Boolean));
    const githubKeywords = splitKeywords(form.githubKeywords);
    const sensitiveKeywords = splitKeywords(form.sensitiveKeywords);
    const companyKeywords = uniq([...shortNames, ...fullNames, ...githubKeywords]);

    const config = {
      maxPerCidr: Number(form.maxPerCidr) || 64,
      concurrency: Number(form.concurrency) || 24,
      timeout: Number(form.timeout) || 20000,
      doReverseIp: form.doReverseIp !== false,
      doSubdomain: form.doSubdomain !== false,
      doWhois: form.doWhois !== false,
      doGithub: form.doGithub !== false,
      doPort: form.doPort !== false,
      doFingerprint: form.doFingerprint !== false,
      doVuln: form.doVuln !== false,
      doEnterprise: form.doEnterprise !== false,
      doSearch: form.doSearch !== false,
      includeGuesses: form.includeGuesses === true,
      githubToken: (form.githubToken || '').trim(),
      resolvers: splitList(form.resolvers),
      keys: form.keys || {},
    };
    reg.setConfig({
      keys: config.keys,
      concurrency: config.concurrency,
      timeout: config.timeout,
    });
    if (config.resolvers.length) coreDns.setResolvers(config.resolvers);

    const job = {
      input: {
        rootDomains,
        shortNames,
        fullNames,
        emailSuffixes,
        githubKeywords,
        sensitiveKeywords,
        companyKeywords,
      },
      config,
      context: {
        hostSet: new Set(rootDomains),
        discoveredIps: new Set(),
        probes: {}, // host -> { host, http, https }
        whoisTexts: [],
        leakTexts: [],
        stats: {},
        notes: [],
      },
    };

    const result = {
      meta: {
        startedAt: new Date(startedAt).toISOString(),
        input: { rootDomains, ipTargets: ipTargetsRaw, emailSuffixes, githubKeywords, sensitiveKeywords },
        scope: {},
        rules: {},
        dedup: {},
        availableProviders: reg.availableList().map((m) => ({ ...m })),
      },
      domains: rootDomains.map((d) => ({ host: d, source: '输入' })),
      subdomains: [],
      records: [],
      ips: [],
      ports: [],
      fingerprints: [],
      vulns: [],
      emails: [],
      leaks: [],
      whois: [],
      enterprise: [],
      search: [],
      notes: [],
    };

    if (
      rootDomains.length === 0 &&
      ipTargetsRaw.length === 0 &&
      githubKeywords.length === 0 &&
      emailSuffixes.length === 0
    ) {
      throw new Error('请至少填写「根域名」「IP/网段」「邮箱后缀」或「GitHub 关键字」中的一项');
    }

    result.meta.scope = {
      rootDomains,
      ipTargets: ipTargetsRaw,
      emailSuffixes,
      githubKeywords,
      description:
        '基于公开被动情报与受限主动探测（仅对发现资产做连通性/指纹检查）。' +
        '子域名为被动收集；端口/指纹/漏洞仅对命中资产做只读探测，不做爆破。',
    };
    result.meta.rules = {
      email: '仅保留命中目标后缀且域名具备邮件基础设施(MX/SPF/DMARC)的邮箱；占位/虚假域名丢弃；默认不含纯猜测角色邮箱。',
      ip: '仅保留公网可路由 IP（排除私有/环回/保留/组播）；反查共宿主域名仅保留与目标根域名相关者。',
      port: '仅对发现的公网主机/IP 做 TCP 连通与 HTTP 探测，按常见端口收敛；超时/不可达即标记为关闭，不臆测。',
      fingerprint: '基于 HTTP 响应头/体/标题特征匹配技术栈与 WAF，低置信度签名不计入。',
      vuln: '仅检测明确的高危暴露（敏感文件、缺失安全头），不做漏洞利用；疑似即提示，不确定即忽略。',
      leak: '仅保留与任一目标关键字/域名/后缀相关的结果；无关或重复一律丢弃。',
      dedup: '各分类按关键字段去重；邮箱按地址、IP 按地址、泄露按 URL、指纹按主机。',
    };

    // 运行上下文（注入给各 provider）
    const ctx = {
      http: httpClient,
      signals,
      coreDns,
      log,
      isPublicIPv4,
      ipScope,
      config,
      Pool,
    };
    job.ctx = ctx;

    log('info', '========== 资产收集任务启动（v3 · Provider 架构 · 宁缺毋滥）==========');
    log('info', `目标根域名：${rootDomains.join(', ') || '（无）'}`);
    log('info', `目标 IP/网段：${ipTargetsRaw.join(', ') || '（无）'}`);
    if (emailSuffixes.length) log('info', `邮箱后缀（批量匹配）：${emailSuffixes.join('、')}`);
    if (companyKeywords.length) log('info', `企业关键字：${companyKeywords.join('、')}`);
    log('info', `可用数据源：${reg.availableList().filter((m) => m.available).length}/${reg.availableList().length}`);

    const emit = (category, items) => {
      const field = RESULT_FIELD[category];
      if (!field) return;
      result[field] = items;
      emitter.partial(PARTIAL_CHANNEL[category], items);
    };

    const runCategory = async (category) => {
      const classes = reg.getProviders(category);
      const collected = [];
      for (const Cls of classes) {
        const inst = new Cls(ctx);
        try {
          const res = await inst.run(job);
          if (res && Array.isArray(res.items)) collected.push(...res.items);
          if (res && res.stats) job.context.stats[Cls.id] = res.stats;
          if (res && Array.isArray(res.notes)) {
            job.context.notes.push(...res.notes.map((n) => ({ provider: Cls.id, note: n })));
          }
        } catch (e) {
          log('warn', `${inst.constructor.label || Cls.id} 执行失败：${e.message}`);
        }
      }
      return collected;
    };

    // ===================== S1 子域名发现 =====================
    if (config.doSubdomain && rootDomains.length) {
      emitter.stage('subdomain', 'running');
      const before = job.context.hostSet.size;
      for (const domain of rootDomains) {
        const items = await this.runCategoryForDomain('subdomain', domain, ctx, log);
        for (const it of items) {
          if (it.host) job.context.hostSet.add(it.host);
        }
      }
      result.subdomains = Array.from(job.context.hostSet)
        .filter((h) => h !== '' )
        .map((h) => ({ host: h, ips: [] }));
      emitter.partial('subdomains', result.subdomains);
      log('success', `子域名发现：累计 ${job.context.hostSet.size} 个主机（本轮新增 ${job.context.hostSet.size - before}）`);
      emitter.stage('subdomain', 'done');
    } else {
      result.subdomains = rootDomains.map((d) => ({ host: d, ips: [] }));
      emitter.partial('subdomains', result.subdomains);
    }

    // ===================== S2 DNS 解析 =====================
    const hostList = Array.from(job.context.hostSet).filter(Boolean);
    if (hostList.length) {
      emitter.stage('dns', 'running');
      const dnsItems = await runCategory('dns');
      result.records = dedupByKey(dnsItems, DEDUP_KEY.dns);
      // 回填子域名 IP（dns provider 写入 context.hostIps）
      const ipByHost = job.context.hostIps || {};
      result.subdomains = hostList.map((h) => ({
        host: h,
        ips: uniq([...(ipByHost[h] || [])]),
      }));
      emitter.partial('records', result.records);
      emitter.partial('subdomains', result.subdomains);
      log('success', `DNS 解析完成，发现 ${job.context.discoveredIps.size} 个公网关联 IP，DNS 记录 ${result.records.length} 条`);
      emitter.stage('dns', 'done');
    }

    // ===================== S3 IP 资产 =====================
    const allIpInputs = this._expandIpTargets(ipTargetsRaw, config.maxPerCidr);
    job.context.ipInputs = allIpInputs.filter(isPublicIPv4);
    if (allIpInputs.length || job.context.discoveredIps.size) {
      emitter.stage('ip', 'running');
      const ipItems = await runCategory('ip');
      result.ips = this._mergeIps(ipItems);
      // 反查发现的相关新主机并入子域名
      const newHosts = [];
      for (const it of result.ips) {
        for (const h of it.reverseHosts || []) {
          for (const rd of rootDomains) {
            if ((h === rd || h.endsWith('.' + rd)) && !job.context.hostSet.has(h)) {
              job.context.hostSet.add(h);
              newHosts.push(h);
            }
          }
        }
      }
      if (newHosts.length) {
        for (const h of newHosts) result.subdomains.push({ host: h, ips: [] });
        emitter.partial('subdomains', dedupByKey(result.subdomains, (i) => i.host));
      }
      emit('ip', result.ips);
      log('success', `IP 资产：${result.ips.length} 个（公网 ${result.ips.filter((i) => i.scope === 'public').length}）`);
      emitter.stage('ip', 'done');
    }

    // ===================== S4 端口 / 服务探测 =====================
    const probeTargets = this._buildProbeTargets(job, allIpInputs, rootDomains, config);
    job.context.probeTargets = probeTargets;
    if (config.doPort && probeTargets.length) {
      emitter.stage('port', 'running');
      const portItems = await runCategory('port');
      result.ports = dedupByKey(portItems, DEDUP_KEY.port);
      emit('port', result.ports);
      const probedHosts = Object.keys(job.context.probes).length;
      log('success', `端口/服务探测：扫描目标 ${probeTargets.length} 个，产生探针 ${probedHosts} 个，端口结果 ${result.ports.length} 条`);
      emitter.stage('port', 'done');
    }

    // ===================== S5 指纹识别 =====================
    if (config.doFingerprint && Object.keys(job.context.probes).length) {
      emitter.stage('fingerprint', 'running');
      const fpItems = await runCategory('fingerprint');
      result.fingerprints = this._mergeFingerprints(fpItems);
      emit('fingerprint', result.fingerprints);
      log('success', `指纹识别：覆盖 ${result.fingerprints.length} 个主机`);
      emitter.stage('fingerprint', 'done');
    }

    // ===================== S6 漏洞/暴露检测 =====================
    if (config.doVuln && Object.keys(job.context.probes).length) {
      emitter.stage('vuln', 'running');
      const vulnItems = await runCategory('vuln');
      result.vulns = dedupByKey(vulnItems, DEDUP_KEY.vuln);
      emit('vuln', result.vulns);
      const high = result.vulns.filter((v) => v.severity === 'high' || v.severity === 'medium').length;
      log('success', `漏洞/暴露检测：发现 ${result.vulns.length} 项（中高危 ${high}）`);
      emitter.stage('vuln', 'done');
    }

    // ===================== S7 WHOIS =====================
    if (config.doWhois && rootDomains.length) {
      emitter.stage('whois', 'running');
      const whoisItems = await runCategory('whois');
      result.whois = whoisItems;
      for (const w of whoisItems) {
        if (w.raw) job.context.whoisTexts.push(w.raw);
        if (w.fields && w.fields.email) job.context.whoisTexts.push(String(w.fields.email));
      }
      emit('whois', result.whois);
      log('success', `WHOIS：${result.whois.length} 条`);
      emitter.stage('whois', 'done');
    }

    // ===================== S8 邮箱资产 =====================
    emitter.stage('email', 'running');
    const leakTexts = (result.leaks || []).map((l) => `${l.title} ${l.snippet} ${l.url}`);
    job.context.leakTexts = leakTexts;
    const emailItems = await runCategory('email');
    result.emails = dedupByKey(emailItems, DEDUP_KEY.email);
    emit('email', result.emails);
    log('success', `邮箱资产：${result.emails.length} 个（已验证 ${result.emails.filter((e) => e.verified).length}）`);
    emitter.stage('email', 'done');

    // ===================== S9 泄露监测 =====================
    if (config.doGithub) {
      emitter.stage('github', 'running');
      const leakItems = await runCategory('leak');
      result.leaks = dedupByKey(leakItems, DEDUP_KEY.leak);
      emit('leak', result.leaks);
      log('success', `泄露监测：${result.leaks.length} 条（高危 ${result.leaks.filter((l) => l.confidence === 'high').length}）`);
      emitter.stage('github', 'done');
    }

    // ===================== S10 企业信息 =====================
    if (config.doEnterprise && (rootDomains.length || companyKeywords.length)) {
      emitter.stage('enterprise', 'running');
      const entItems = await runCategory('enterprise');
      result.enterprise = entItems;
      emit('enterprise', result.enterprise);
      log('success', `企业信息：${result.enterprise.length} 条`);
      emitter.stage('enterprise', 'done');
    }

    // ===================== S11 资产搜索引擎（密钥门控） =====================
    if (config.doSearch && (rootDomains.length || allIpInputs.length)) {
      emitter.stage('search', 'running');
      const searchItems = await runCategory('search');
      result.search = dedupByKey(searchItems, DEDUP_KEY.search);
      emit('search', result.search);
      log('success', `资产搜索引擎：${result.search.length} 条`);
      emitter.stage('search', 'done');
    }

    // ===================== 汇总 =====================
    result.notes = job.context.notes;
    result.meta.dedup = job.context.stats;
    const elapsed = ((Date.now() - startedAt) / 1000).toFixed(1);
    result.meta.finishedAt = new Date().toISOString();
    result.meta.elapsedSeconds = Number(elapsed);
    result.meta.summary = {
      domains: result.domains.length,
      subdomains: result.subdomains.length,
      ips: result.ips.length,
      ports: result.ports.length,
      fingerprints: result.fingerprints.length,
      vulns: result.vulns.length,
      emails: result.emails.length,
      emailsVerified: result.emails.filter((e) => e.verified).length,
      leaks: result.leaks.length,
      leaksHigh: result.leaks.filter((l) => l.confidence === 'high').length,
      records: result.records.length,
      enterprise: result.enterprise.length,
      search: result.search.length,
    };

    log('success', '========== 任务完成 ==========');
    log('success',
      `汇总：域名 ${result.domains.length} | 子域名 ${result.subdomains.length} | ` +
      `IP ${result.ips.length} | 端口 ${result.ports.length} | 指纹 ${result.fingerprints.length} | ` +
      `漏洞 ${result.vulns.length} | 邮箱 ${result.emails.length}(已验证 ${result.meta.summary.emailsVerified}) | ` +
      `泄露 ${result.leaks.length}(高危 ${result.meta.summary.leaksHigh}) | 企业 ${result.enterprise.length} | 搜索 ${result.search.length}，` +
      `耗时 ${elapsed}s`
    );

    return result;
  }

  // 子域名阶段：对单个 domain 运行全部 subdomain provider
  async runCategoryForDomain(category, domain, ctx, log) {
    const classes = this.registry.getProviders(category);
    const collected = [];
    for (const Cls of classes) {
      const inst = new Cls(ctx);
      try {
        const res = await inst.run({ ...this._emptyJob(), input: { rootDomains: [domain] }, config: ctx.config, context: {} , domain });
        if (res && Array.isArray(res.items)) collected.push(...res.items);
      } catch (e) {
        log('warn', `${inst.constructor.label || Cls.id} (${domain}) 失败：${e.message}`);
      }
    }
    return collected;
  }

  _emptyJob() {
    return { input: {}, config: {}, context: {} };
  }

  _expandIpTargets(ipTargetsRaw, maxPerCidr) {
    const out = [];
    for (const t of ipTargetsRaw) {
      if (t.includes('/')) {
        const { ips } = expandCidr(t, maxPerCidr);
        out.push(...ips);
      } else {
        out.push(t);
      }
    }
    return uniq(out);
  }

  _buildProbeTargets(job, allIpInputs, rootDomains, config) {
    const targets = new Set();
    // 已发现的公网 IP
    for (const ip of job.context.discoveredIps) if (isPublicIPv4(ip)) targets.add(ip);
    // 显式 IP / 网段展开后的公网 IP
    for (const ip of allIpInputs) if (isPublicIPv4(ip)) targets.add(ip);
    // 子域名主机（仅公网解析到的才探测；这里直接取主机名，httpx 会自行处理不可达）
    for (const h of job.context.hostSet) if (h) targets.add(h);
    return Array.from(targets).filter(Boolean).slice(0, 4000);
  }

  _mergeIps(items) {
    const byIp = new Map();
    for (const it of items) {
      if (!it || !it.ip) continue;
      if (!byIp.has(it.ip)) {
        byIp.set(it.ip, {
          ip: it.ip,
          scope: it.scope || 'public',
          hosts: [],
          reverseHosts: [],
          confidence: it.confidence || 'medium',
          source: it.source || '',
          asn: [],
          prefix: [],
          org: '',
        });
      }
      const cur = byIp.get(it.ip);
      if (it.hosts) cur.hosts.push(...it.hosts);
      if (it.reverseHosts) cur.reverseHosts.push(...it.reverseHosts);
      if (it.asn) cur.asn.push(...it.asn);
      if (it.prefix) cur.prefix.push(...it.prefix);
      if (it.org) cur.org = it.org;
      if (it.source) cur.source = [cur.source, it.source].filter(Boolean).join(',');
      // 置信度取最高
      const rank = { low: 1, medium: 2, high: 3 };
      if ((rank[it.confidence] || 2) > (rank[cur.confidence] || 2)) cur.confidence = it.confidence;
    }
    const out = Array.from(byIp.values());
    for (const o of out) {
      o.hosts = uniq(o.hosts);
      o.reverseHosts = uniq(o.reverseHosts);
      o.asn = uniq(o.asn);
      o.prefix = uniq(o.prefix);
    }
    return out;
  }

  _mergeFingerprints(items) {    const byHost = new Map();
    for (const it of items) {
      if (!it || !it.host) continue;
      const tech = Array.isArray(it.tech) ? it.tech : [];
      if (!byHost.has(it.host)) byHost.set(it.host, { host: it.host, tech: [] });
      byHost.get(it.host).tech.push(...tech);
    }
    const out = [];
    for (const [host, v] of byHost) {
      // 按技术名去重，保留最高置信度
      const byName = new Map();
      for (const t of v.tech) {
        if (!t || !t.name) continue;
        const prev = byName.get(t.name);
        if (!prev || (t.confidence || 0) > (prev.confidence || 0)) byName.set(t.name, t);
      }
      out.push({ host, tech: Array.from(byName.values()).sort((a, b) => (b.confidence || 0) - (a.confidence || 0)) });
    }
    return out;
  }
}

function createEngine() {
  return new Engine(getRegistry());
}

module.exports = { Engine, createEngine, COMMON_PORTS, PARTIAL_CHANNEL, RESULT_FIELD };
