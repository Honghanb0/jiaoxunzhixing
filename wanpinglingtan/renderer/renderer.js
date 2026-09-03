'use strict';

/**
 * 渲染进程交互逻辑
 * 负责：表单采集、任务启动、流式事件渲染、结果 Tab 展示、过滤、导出。
 */

(function () {
  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => Array.from(document.querySelectorAll(sel));

  // 各分类的累计数据
  const store = {
    domains: [],
    subdomains: [],
    ips: [],
    ports: [],
    fingerprints: [],
    vulns: [],
    emails: [],
    leaks: [],
    records: [],
    whois: [],
    enterprise: [],
    search: [],
    // ---- 人工审计 & 安全扫描 ----
    auditItems: [],   // 待审计资产清单 [{id,target,kind,source}]
    audit: {},        // verdict 映射：id -> 'real' | 'false'
    secscan: [],      // 安全扫描结果
    secscanRunning: false,
  };

  const STAGES = {
    subdomain: '子域名枚举',
    dns: 'DNS 解析',
    ip: 'IP 资产',
    port: '端口/服务探测',
    fingerprint: '指纹识别',
    vuln: '漏洞/暴露检测',
    whois: 'WHOIS',
    email: '邮箱资产',
    github: '泄露监测',
    enterprise: '企业信息',
    search: '资产搜索引擎',
  };

  let running = false;

  // ----------------------------------------------------------------------
  // 工具函数
  // ----------------------------------------------------------------------
  function escapeHtml(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  // 严重度 → 标签文案 / 颜色类（与 CSS 的 tag-* / sev-* 对应）
  function sevLabel(sev) {
    return { high: '高危', medium: '中危', low: '低危', info: '提示' }[sev] || '提示';
  }
  function sevTagClass(sev) {
    return { high: 'tag-danger', medium: 'tag-warn', low: 'tag-ok', info: 'tag' }[sev] || 'tag';
  }
  // 漏洞分类标签（12 类统一规范）
  function catTag(cat) {
    if (!cat) return '';
    return `<span class="cat-tag cat-${escapeHtml(cat)}">${escapeHtml(cat)}</span>`;
  }

  function updateStat(id, n) {
    const el = document.getElementById(id);
    if (el) el.textContent = n;
  }

  function updateAllStats() {
    updateStat('statDomains', store.domains.length + store.subdomains.length);
    updateStat('statIps', store.ips.length);
    updateStat('statPorts', store.ports.length);
    updateStat('statFps', store.fingerprints.length);
    updateStat('statVulns', store.vulns.length);
    updateStat('statEmails', store.emails.length);
    updateStat('statLeaks', store.leaks.length);
  }

  function updateBadges() {
    document.getElementById('badgeSub').textContent = store.subdomains.length;
    document.getElementById('badgeIp').textContent = store.ips.length;
    document.getElementById('badgePort').textContent = store.ports.length;
    document.getElementById('badgeFp').textContent = store.fingerprints.length;
    document.getElementById('badgeVuln').textContent = store.vulns.length;
    document.getElementById('badgeEmail').textContent = store.emails.length;
    document.getElementById('badgeLeak').textContent = store.leaks.length;
    document.getElementById('badgeRec').textContent = store.records.length;
    document.getElementById('badgeWhois').textContent = store.whois.length;
    document.getElementById('badgeEnt').textContent = store.enterprise.length;
    document.getElementById('badgeSearch').textContent = store.search.length;
    const bAudit = document.getElementById('badgeAudit');
    if (bAudit) bAudit.textContent = store.auditItems.length;
    const bSec = document.getElementById('badgeSecscan');
    if (bSec) bSec.textContent = store.secscan.length;
  }

  // ----------------------------------------------------------------------
  // 日志 & 阶段
  // ----------------------------------------------------------------------
  function logLine(level, message) {
    const body = document.getElementById('consoleBody');
    const line = document.createElement('div');
    line.className = 'line lv-' + level;
    const t = new Date().toLocaleTimeString('zh-CN', { hour12: false });
    line.textContent = `[${t}] ${message}`;
    body.appendChild(line);
    body.scrollTop = body.scrollHeight;
  }

  function setStage(name, status) {
    const track = document.getElementById('stageTrack');
    let chip = track.querySelector(`[data-stage="${name}"]`);
    if (!chip) {
      chip = document.createElement('span');
      chip.className = 'stage-chip';
      chip.dataset.stage = name;
      chip.textContent = STAGES[name] || name;
      track.appendChild(chip);
    }
    chip.className = 'stage-chip' + (status ? ' ' + status : '');
  }

  function setProgress(p) {
    document.getElementById('progressFill').style.width = Math.max(0, Math.min(100, p)) + '%';
  }

  // ----------------------------------------------------------------------
  // 结果渲染
  // ----------------------------------------------------------------------
  function renderSubdomains() {
    const pane = document.getElementById('pane-subdomains');
    const items = filter(store.subdomains);
    let html = '';
    if (items.length === 0) {
      html = '<div class="empty">尚无数据</div>';
    } else {
      for (const s of items) {
        const ips = (s.ips || []).map((i) => `<span class="tag">${escapeHtml(i)}</span>`).join(' ');
        html += `<div class="row"><span class="grow mono">${escapeHtml(s.host)}</span><span class="meta">${ips}</span></div>`;
      }
    }
    pane.innerHTML = html;
  }

  function renderIps() {
    const pane = document.getElementById('pane-ips');
    const items = filter(store.ips);
    let html = '';
    if (items.length === 0) {
      html = '<div class="empty">尚无数据</div>';
    } else {
      for (const it of items) {
        const conf = it.confidence === 'high'
          ? '<span class="tag tag-ok">高</span>'
          : '<span class="tag tag-warn">中</span>';
        const scopeTag = `<span class="meta">${escapeHtml(it.scope || 'public')}</span>`;
        const hosts = (it.hosts || []).map((h) => escapeHtml(h)).join(', ');
        const rev = (it.reverseHosts && it.reverseHosts.length)
          ? `<div class="meta">相关共宿主：${it.reverseHosts.map(escapeHtml).join(', ')}</div>` : '';
        html += `<div class="row leak-row"><div class="grow"><span class="mono">${escapeHtml(it.ip)}</span> ${scopeTag}${conf}<div class="meta">${hosts || '（无 PTR 主机）'}</div>${rev}</div></div>`;
      }
    }
    pane.innerHTML = html;
  }

  function renderEmails() {
    const pane = document.getElementById('pane-emails');
    const items = filter(store.emails);
    let html = '';
    if (items.length === 0) {
      html = '<div class="empty">尚无数据</div>';
    } else {
      for (const e of items) {
        const conf = e.confidence === 'high'
          ? '<span class="tag tag-ok">高置信</span>'
          : e.confidence === 'guess'
            ? '<span class="tag tag-warn">推测</span>'
            : '<span class="tag">中</span>';
        const mail = [];
        if (e.mx) mail.push('MX');
        if (e.spf) mail.push('SPF');
        if (e.dmarc) mail.push('DMARC');
        const mailTag = mail.length ? `<span class="meta">${mail.join('/')}</span>` : '';
        html += `<div class="row"><span class="mono grow">${escapeHtml(e.email)}</span>${conf}<span class="meta">${escapeHtml(e.source || '')}</span>${mailTag}</div>`;
      }
    }
    pane.innerHTML = html;
  }

  function renderLeaks() {
    const pane = document.getElementById('pane-leaks');
    const items = filter(store.leaks);
    let html = '';
    if (items.length === 0) {
      html = '<div class="empty">尚无数据</div>';
    } else {
      for (const g of items) {
        const srcMap = { github: 'GitHub', stackexchange: '技术论坛', reddit: '社区', external: '外部' };
        const src = `<span class="tag">${srcMap[g.source] || g.source || 'web'}</span>`;
        const conf = g.confidence === 'high'
          ? '<span class="tag tag-ok">高危</span>'
          : '<span class="tag tag-warn">相关</span>';
        const url = escapeHtml(g.url || '');
        const open = url ? `<a class="tag" href="${url}" target="_blank" rel="noopener">打开</a>` : '';
        const snippet = g.snippet ? `<div class="meta">${escapeHtml(g.snippet.slice(0, 200))}</div>` : '';
        html += `<div class="row leak-row"><div class="grow"><div class="mono">${escapeHtml(g.title || '')}</div>${snippet}<div class="meta">命中：${escapeHtml(g.matchedKeyword || '')}</div></div>${src}${conf}${open}</div>`;
      }
    }
    pane.innerHTML = html;
  }

  function renderRecords() {
    const pane = document.getElementById('pane-records');
    const items = filter(store.records);
    let html = '';
    if (items.length === 0) {
      html = '<div class="empty">尚无数据</div>';
    } else {
      for (const r of items) {
        html += `<div class="row"><span class="tag">${escapeHtml(r.type)}</span><span class="mono grow">${escapeHtml(r.host)}</span><span class="meta">${escapeHtml(r.value)}</span></div>`;
      }
    }
    pane.innerHTML = html;
  }

  function renderWhois() {
    const pane = document.getElementById('pane-whois');
    const items = store.whois;
    let html = '';
    if (items.length === 0) {
      html = '<div class="empty">尚无数据</div>';
    } else {
      for (const w of items) {
        const f = w.fields || {};
        const kv = Object.entries(f)
          .map(([k, v]) => `<dt>${escapeHtml(k)}</dt><dd>${escapeHtml(Array.isArray(v) ? v.join(', ') : v)}</dd>`)
          .join('');
        html += `<div style="margin-bottom:14px"><div class="row"><span class="mono grow">${escapeHtml(w.domain)}</span><span class="tag">${escapeHtml(w.source || '')}</span></div><dl class="kv">${kv || '<dt>状态</dt><dd>无可用信息</dd>'}</dl></div>`;
      }
    }
    pane.innerHTML = html;
  }

  function renderPorts() {
    const pane = document.getElementById('pane-ports');
    const items = filter(store.ports);
    let html = '';
    if (items.length === 0) {
      html = '<div class="empty">尚无数据</div>';
    } else {
      for (const p of items) {
        const proto = p.protocol === 'https' ? '<span class="tag tag-ok">HTTPS</span>' : p.protocol === 'http' ? '<span class="tag">HTTP</span>' : '<span class="tag tag-warn">TCP</span>';
        const st = p.state === 'open' ? '<span class="tag tag-ok">开放</span>' : '<span class="tag tag-warn">关闭</span>';
        const svc = p.service ? `<span class="meta">${escapeHtml(p.service)}</span>` : '';
        const extra = [];
        if (p.status) extra.push('状态码 ' + p.status);
        if (p.server) extra.push('Server: ' + p.server);
        if (p.title) extra.push('标题: ' + p.title);
        const extraHtml = extra.length ? `<div class="meta">${escapeHtml(extra.join(' · '))}</div>` : '';
        html += `<div class="row"><span class="mono grow">${escapeHtml(p.target)}:${p.port}</span>${proto}${st}${svc}${extraHtml}</div>`;
      }
    }
    pane.innerHTML = html;
  }

  function renderFingerprints() {
    const pane = document.getElementById('pane-fingerprints');
    const items = filter(store.fingerprints);
    let html = '';
    if (items.length === 0) {
      html = '<div class="empty">尚无数据</div>';
    } else {
      for (const f of items) {
        const tech = (f.tech || []).map((t) => {
          const tag = t.category === 'security' ? 'tag-warn' : 'tag';
          const conf = t.confidence >= 0.85 ? '★' : t.confidence >= 0.7 ? '✦' : '·';
          return `<span class="tag ${tag}" title="置信度 ${t.confidence}">${escapeHtml(t.name)}<em style="opacity:.6">${conf}</em></span>`;
        }).join(' ');
        html += `<div class="row"><span class="mono grow">${escapeHtml(f.host)}</span><span class="meta">${tech || '（无识别）'}</span></div>`;
      }
    }
    pane.innerHTML = html;
  }

  function renderVulns() {
    const pane = document.getElementById('pane-vulns');
    const items = filter(store.vulns);
    let html = '';
    if (items.length === 0) {
      html = '<div class="empty">尚无数据</div>';
    } else {
      const order = { high: 0, medium: 1, low: 2, info: 3 };
      items.sort((a, b) => (order[a.severity] ?? 9) - (order[b.severity] ?? 9));
      for (const v of items) {
        const sevCls = { high: 'sev-high', medium: 'sev-medium', low: 'sev-low', info: 'sev-info' }[v.severity] || 'sev-info';
        const cardMeta = `<span class="tag ${sevTagClass(v.severity)}">${sevLabel(v.severity)}</span>`
          + catTag(v.category)
          + (v.type ? `<span class="meta">${escapeHtml(v.type)}</span>` : '')
          + (v.source ? `<span class="meta">来源：${escapeHtml(v.source)}</span>` : '');
        const detail = v.detail ? `<div class="vuln-detail">${escapeHtml(v.detail)}</div>` : '';
        const ev = v.evidence ? `<div class="vuln-evidence">证据：${escapeHtml(v.evidence)}</div>` : '';
        html += `<div class="vuln-card ${sevCls}">
          <div class="vuln-title"><span class="mono">${escapeHtml(v.host)}</span> · ${escapeHtml(v.title || '')}</div>
          <div class="vuln-meta">${cardMeta}</div>
          ${detail}${ev}
        </div>`;
      }
    }
    pane.innerHTML = html;
  }

  function renderEnterprise() {
    const pane = document.getElementById('pane-enterprise');
    const items = filter(store.enterprise);
    let html = '';
    if (items.length === 0) {
      html = '<div class="empty">尚无数据</div>';
    } else {
      for (const e of items) {
        const kv = Object.entries(e)
          .filter(([k]) => k !== 'source')
          .map(([k, v]) => `<dt>${escapeHtml(k)}</dt><dd>${escapeHtml(Array.isArray(v) ? v.join(', ') : (v == null ? '' : v))}</dd>`)
          .join('');
        html += `<div style="margin-bottom:14px"><div class="row"><span class="mono grow">${escapeHtml(e.domain || e.name || e.icp || '企业信息')}</span><span class="tag">${escapeHtml(e.source || '')}</span></div><dl class="kv">${kv || '<dt>状态</dt><dd>无可用信息</dd>'}</dl></div>`;
      }
    }
    pane.innerHTML = html;
  }

  function renderSearch() {
    const pane = document.getElementById('pane-search');
    const items = filter(store.search);
    let html = '';
    if (items.length === 0) {
      html = '<div class="empty">尚无数据（需配置对应引擎密钥）</div>';
    } else {
      for (const s of items) {
        const raw = s.raw ? `<div class="meta">${escapeHtml(String(s.raw).slice(0, 160))}</div>` : '';
        html += `<div class="row leak-row"><div class="grow"><span class="mono">${escapeHtml(String(s.asset))}</span> <span class="tag">${escapeHtml(s.source)}</span>${raw}</div></div>`;
      }
    }
    pane.innerHTML = html;
  }

  // 过滤（按当前搜索框）
  let currentFilter = '';
  function filter(arr) {
    if (!currentFilter) return arr;
    const q = currentFilter.toLowerCase();
    return arr.filter((item) => {
      const hay = JSON.stringify(item).toLowerCase();
      return hay.includes(q);
    });
  }

  // 重新渲染当前激活 Tab
  function rerenderActive() {
    const active = document.querySelector('.tab.active');
    const tab = active ? active.dataset.tab : 'subdomains';
    switch (tab) {
      case 'subdomains': renderSubdomains(); break;
      case 'ips': renderIps(); break;
      case 'ports': renderPorts(); break;
      case 'fingerprints': renderFingerprints(); break;
      case 'vulns': renderVulns(); break;
      case 'emails': renderEmails(); break;
      case 'leaks': renderLeaks(); break;
      case 'records': renderRecords(); break;
      case 'whois': renderWhois(); break;
      case 'enterprise': renderEnterprise(); break;
      case 'search': renderSearch(); break;
      case 'audit': renderAudit(); break;
      case 'secscan': renderSecscan(); break;
      case 'report': /* 报告面板无需重渲染 */ break;
    }
  }

  // ----------------------------------------------------------------------
  // Tab 切换
  // ----------------------------------------------------------------------
  $$('.tab').forEach((btn) => {
    btn.addEventListener('click', () => {
      $$('.tab').forEach((b) => b.classList.remove('active'));
      btn.classList.add('active');
      const tab = btn.dataset.tab;
      $$('.tab-pane').forEach((p) => p.classList.remove('active'));
      document.getElementById('pane-' + tab).classList.add('active');
      rerenderActive();
    });
  });

  // 过滤输入
  document.getElementById('filterInput').addEventListener('input', (e) => {
    currentFilter = e.target.value.trim();
    rerenderActive();
  });

  // ----------------------------------------------------------------------
  // 收集任务
  // ----------------------------------------------------------------------
  function collectForm() {
    const v = (id) => document.getElementById(id).value;
    const c = (id) => document.getElementById(id).checked;
    return {
      // ---- 检索维度 ----
      rootDomain: v('rootDomain'),
      ipRange: v('ipRange'),
      companyShort: v('companyShort'),
      companyFull: v('companyFull'),
      emailSuffix: v('emailSuffix'),
      githubKeywords: v('githubKeywords'),
      sensitiveKeywords: v('sensitiveKeywords'),
      githubToken: v('githubToken'),
      // ---- 通用配置 ----
      maxPerCidr: parseInt(v('maxPerCidr'), 10) || 64,
      concurrency: parseInt(v('concurrency'), 10) || 24,
      resolvers: v('resolvers'),
      includeGuesses: c('includeGuesses'),
      // ---- 采集模块开关 ----
      doSubdomain: c('doSubdomain'),
      doWhois: c('doWhois'),
      doReverseIp: c('doReverseIp'),
      doGithub: c('doGithub'),
      doPort: c('doPort'),
      doFingerprint: c('doFingerprint'),
      doVuln: c('doVuln'),
      doEnterprise: c('doEnterprise'),
      doSearch: c('doSearch'),
      // ---- 数据源密钥（按需，留空则对应模块自动停用）----
      keys: {
        fofa_email: v('keyFofaEmail'),
        fofa_key: v('keyFofa'),
        shodan_key: v('keyShodan'),
        zoomeye_key: v('keyZoomeye'),
        quake_key: v('keyQuake'),
        hunter_key: v('keyHunter'),
        ensan_endpoint: v('keyEnsanEndpoint'),
        ensan_key: v('keyEnsan'),
      },
    };
  }

  function resetStore() {
    store.domains = []; store.subdomains = []; store.ips = [];
    store.ports = []; store.fingerprints = []; store.vulns = [];
    store.emails = []; store.leaks = []; store.records = []; store.whois = [];
    store.enterprise = []; store.search = [];
    store.auditItems = []; store.audit = {}; store.secscan = []; store.secscanRunning = false;
    updateBadges(); updateAllStats();
    document.getElementById('stageTrack').innerHTML = '';
    setProgress(0);
  }

  document.getElementById('collectForm').addEventListener('submit', (e) => {
    e.preventDefault();
    if (running) return;
    running = true;
    document.getElementById('btnStart').disabled = true;
    document.getElementById('consoleBody').innerHTML = '';
    resetStore();
    logLine('info', '正在初始化采集任务…');
    window.assetAPI.startCollection(collectForm());
  });

  document.getElementById('btnClear').addEventListener('click', () => {
    document.getElementById('collectForm').reset();
    logLine('info', '表单已清空');
  });

  // 流式事件订阅
  window.assetAPI.onLog(({ level, message }) => logLine(level, message));
  window.assetAPI.onStage(({ name, status }) => {
    setStage(name, status);
    if (status === 'running') setProgress(Math.min(90, progressEst()));
  });
  window.assetAPI.onPartial(({ category, items }) => {
    if (category === 'subdomains') {
      mergeByHost(store.subdomains, items, 'host');
      renderSubdomains(); updateBadges(); updateAllStats();
    } else if (category === 'domains') {
      store.domains = items; updateBadges(); updateAllStats();
    } else if (category === 'ips') {
      store.ips = items; renderIps(); updateBadges(); updateAllStats();
    } else if (category === 'ports') {
      store.ports = items; renderPorts(); updateBadges(); updateAllStats();
    } else if (category === 'fingerprints') {
      store.fingerprints = items; renderFingerprints(); updateBadges(); updateAllStats();
    } else if (category === 'vulns') {
      store.vulns = items; renderVulns(); updateBadges(); updateAllStats();
    } else if (category === 'emails') {
      store.emails = items; renderEmails(); updateBadges(); updateAllStats();
    } else if (category === 'leaks') {
      store.leaks = items; renderLeaks(); updateBadges(); updateAllStats();
    } else if (category === 'records') {
      store.records = items; renderRecords(); updateBadges();
    } else if (category === 'whois') {
      store.whois = items; renderWhois(); updateBadges();
    } else if (category === 'enterprise') {
      store.enterprise = items; renderEnterprise(); updateBadges();
    } else if (category === 'search') {
      store.search = items; renderSearch(); updateBadges();
    }
  });

  window.assetAPI.onDone(({ ok, result, error }) => {
    running = false;
    document.getElementById('btnStart').disabled = false;
    setProgress(100);
    if (ok) {
      logLine('success', '全部结果已就绪，可导出 JSON / CSV。');
      buildAuditList();
      logLine('info', `已生成人工审计清单（${store.auditItems.length} 项），请切换至「人工审计」研判真实/误报资产。`);
    } else {
      logLine('error', '任务失败：' + error);
    }
  });

  // 进度粗估：根据阶段数
  const stageOrder = ['subdomain', 'dns', 'ip', 'port', 'fingerprint', 'vuln', 'whois', 'email', 'github', 'enterprise', 'search'];
  function progressEst() {
    const done = stageOrder.filter((s) => document.querySelector(`.stage-chip[data-stage="${s}"].done`)).length;
    return Math.round((done / stageOrder.length) * 90);
  }

  function mergeByHost(list, items, key) {
    const map = new Map();
    for (const it of list) map.set(it[key], it);
    for (const it of items) {
      const k = it[key];
      if (map.has(k)) {
        const ex = map.get(k);
        ex.ips = Array.from(new Set([...(ex.ips || []), ...(it.ips || [])]));
      } else {
        map.set(k, it);
      }
    }
    list.length = 0;
    for (const v of map.values()) list.push(v);
  }

  // ----------------------------------------------------------------------
  // 人工审计
  // ----------------------------------------------------------------------
  const auditSelected = new Set();

  // 从已收集资产中构建审计清单（去重，域名/IP 同视为一项）
  // 涵盖：子域名 / IP / 端口（可进入安全扫描）+ 邮箱 / 泄露 / 企业信息（仅人工研判，不触发扫描）
  function buildAuditList() {
    const map = new Map();
    const add = (id, target, kind, source, opts = {}) => {
      if (!target) return;
      if (!map.has(id)) map.set(id, Object.assign({
        id, target, value: target, kind, source,
        scannable: kind === 'domain' || kind === 'ip',
        resolvedIp: '-', geo: '—', alive: '—',
        meta: {},
      }, opts));
    };
    (store.subdomains || []).forEach((s) => add(s.host, s.host, 'domain', '子域名'));
    (store.ips || []).forEach((i) => add(i.ip, i.ip, 'ip', 'IP资产'));
    (store.ports || []).forEach((p) => {
      const t = p.target;
      if (!t) return;
      const kind = /^\d{1,3}(\.\d{1,3}){3}$/.test(t) ? 'ip' : 'domain';
      add(t, t, kind, '端口/服务');
    });
    (store.emails || []).forEach((e) => add('email:' + e.email, e.email, 'email', '邮箱', { meta: { email: e.email, source: e.source || '' } }));
    (store.leaks || []).forEach((g) => add('leak:' + (g.title || g.url), g.title || g.url, 'leak', '泄露', { meta: { title: g.title || '', url: g.url || '', snippet: (g.snippet || '').slice(0, 160) } }));
    (store.enterprise || []).forEach((e) => add('ent:' + (e.domain || e.name || e.icp), e.domain || e.name || e.icp, 'enterprise', '企业信息', { meta: { name: e.name || '', icp: e.icp || '', domain: e.domain || '' } }));

    store.auditItems = Array.from(map.values());
    // 仅保留仍存在资产的判定
    const valid = new Set(store.auditItems.map((x) => x.id));
    for (const k of Object.keys(store.audit)) if (!valid.has(k)) delete store.audit[k];
    auditSelected.clear();
    if (document.getElementById('pane-audit').classList.contains('active')) renderAudit();
    updateBadgeAudit();
    // 异步 enrichment：解析 IP / 地理位置 / 连通性（仅 IP / 域名类，辅助研判真实/误报）
    enrichAuditItems();
  }

  // 调用主进程对 IP / 域名类资产做轻量 enrichment（DNS 解析 + 地理库 + 连通性探测）
  async function enrichAuditItems() {
    const targets = store.auditItems
      .filter((i) => i.scannable)
      .map((i) => ({ id: i.id, kind: i.kind, value: i.value }));
    if (!targets.length) return;
    try {
      const res = await window.assetAPI.enrichAudit(targets);
      if (res && res.items) {
        const byId = new Map(res.items.map((x) => [x.id, x]));
        for (const it of store.auditItems) {
          const e = byId.get(it.id);
          if (e) { it.resolvedIp = e.resolvedIp || '-'; it.geo = e.geo || '—'; it.alive = e.alive || '—'; }
        }
        if (document.getElementById('pane-audit').classList.contains('active')) renderAudit();
      }
    } catch (e) { /* enrichment 失败不影响人工审计 */ }
  }

  function updateBadgeAudit() {
    const b = document.getElementById('badgeAudit');
    if (b) b.textContent = store.auditItems.length;
    const c = document.getElementById('auditCount');
    if (c) {
      const real = store.auditItems.filter((i) => store.audit[i.id] === 'real').length;
      const fp = store.auditItems.filter((i) => store.audit[i.id] === 'false').length;
      c.textContent = `待审计 ${store.auditItems.length} 项 · 真实 ${real} · 误报 ${fp}`;
    }
  }

  function renderAudit() {
    const wrap = document.getElementById('auditTable');
    if (!store.auditItems.length) {
      wrap.innerHTML = '<div class="empty">资产收集完成后，此处列出待审计资产清单。</div>';
      updateBadgeAudit();
      return;
    }
    let html = '<table class="audit-table"><thead><tr>'
      + '<th class="col-sel"><input type="checkbox" id="auditCheckAll" /></th>'
      + '<th>资产目标</th><th>类型</th><th>来源</th><th>解析IP</th><th>地理位置</th><th>连通性</th><th>研判（真实资产 / 误报）</th></tr></thead><tbody>';
    for (const it of store.auditItems) {
      const verdict = store.audit[it.id] || '';
      const sel = auditSelected.has(it.id) ? 'checked' : '';
      const typeLabel = it.kind === 'ip' ? 'IPv4' : it.kind === 'domain' ? '域名' : it.kind === 'email' ? '邮箱' : it.kind === 'leak' ? '泄露' : '企业';
      let extraCols;
      if (it.scannable) {
        const aliveCls = it.alive === '可达' ? 'ok' : 'bad';
        extraCols = `<td class="audit-ip">${escapeHtml(it.resolvedIp)}</td>`
          + `<td class="audit-geo">${escapeHtml(it.geo)}</td>`
          + `<td class="audit-alive ${aliveCls}">${escapeHtml(it.alive)}</td>`;
      } else {
        const m = it.meta || {};
        const desc = it.kind === 'email' ? `邮箱：${escapeHtml(m.email || '')}`
          : it.kind === 'leak' ? `泄露：${escapeHtml((m.title || '').slice(0, 40))}`
          : `企业：${escapeHtml(m.name || m.icp || m.domain || '')}`;
        extraCols = `<td colspan="3" class="audit-noscan">非扫描对象 · ${desc}</td>`;
      }
      html += `<tr data-id="${escapeHtml(it.id)}">
        <td class="col-sel"><input type="checkbox" class="audit-sel" data-id="${escapeHtml(it.id)}" ${sel}/></td>
        <td class="mono">${escapeHtml(it.target)}</td>
        <td>${typeLabel}</td>
        <td>${escapeHtml(it.source)}</td>
        ${extraCols}
        <td><select class="audit-verdict" data-id="${escapeHtml(it.id)}">
          <option value="" ${verdict === '' ? 'selected' : ''}>未判定</option>
          <option value="real" ${verdict === 'real' ? 'selected' : ''}>真实资产</option>
          <option value="false" ${verdict === 'false' ? 'selected' : ''}>误报</option>
        </select></td></tr>`;
    }
    html += '</tbody></table>';
    wrap.innerHTML = html;
    const ca = document.getElementById('auditCheckAll');
    if (ca) ca.checked = auditSelected.size > 0 && auditSelected.size === store.auditItems.length;
    updateBadgeAudit();
  }

  // 审计表事件委托（容器上一次性绑定，渲染重建不丢监听）
  const auditTableEl = document.getElementById('auditTable');
  if (auditTableEl) {
    auditTableEl.addEventListener('change', (e) => {
      const t = e.target;
      if (t.id === 'auditCheckAll') {
        auditSelected.clear();
        if (t.checked) store.auditItems.forEach((it) => auditSelected.add(it.id));
        renderAudit();
      } else if (t.classList.contains('audit-sel')) {
        const id = t.dataset.id;
        if (t.checked) auditSelected.add(id); else auditSelected.delete(id);
        const ca = document.getElementById('auditCheckAll');
        if (ca) ca.checked = auditSelected.size > 0 && auditSelected.size === store.auditItems.length;
      } else if (t.classList.contains('audit-verdict')) {
        const id = t.dataset.id;
        if (t.value) store.audit[id] = t.value; else delete store.audit[id];
        updateBadgeAudit();
      }
    });
  }

  // 对「选中项」批量操作，未选中则作用于全部
  function auditApplyToSelectionOrAll(fn) {
    const ids = auditSelected.size ? Array.from(auditSelected) : store.auditItems.map((i) => i.id);
    ids.forEach(fn);
    renderAudit();
  }
  document.getElementById('btnAuditSelectAll').addEventListener('click', () => {
    store.auditItems.forEach((it) => auditSelected.add(it.id)); renderAudit();
  });
  document.getElementById('btnAuditInvert').addEventListener('click', () => {
    store.auditItems.forEach((it) => {
      if (auditSelected.has(it.id)) auditSelected.delete(it.id); else auditSelected.add(it.id);
    });
    renderAudit();
  });
  document.getElementById('btnAuditClear').addEventListener('click', () => { auditSelected.clear(); renderAudit(); });
  document.getElementById('btnAuditAllReal').addEventListener('click', () => auditApplyToSelectionOrAll((id) => { store.audit[id] = 'real'; }));
  document.getElementById('btnAuditAllFalse').addEventListener('click', () => auditApplyToSelectionOrAll((id) => { store.audit[id] = 'false'; }));
  document.getElementById('btnAuditReset').addEventListener('click', () => auditApplyToSelectionOrAll((id) => { delete store.audit[id]; }));

  // 启动安全扫描（基于确认资产）
  document.getElementById('btnStartSecscan').addEventListener('click', () => {
    if (store.secscanRunning) return;
    const confirmed = store.auditItems.filter((i) => store.audit[i.id] === 'real');
    const targets = confirmed.length
      ? confirmed
      : store.auditItems.filter((i) => store.audit[i.id] !== 'false');
    if (!targets.length) { logLine('warn', '无可用审计资产，请先完成资产收集。'); return; }
    if (!confirmed.length) logLine('warn', '未标记「真实资产」，将对全部未判定资产执行安全扫描。');
    store.secscan = [];
    store.secscanRunning = true;
    document.getElementById('secscanProgress').style.display = 'block';
    document.getElementById('secscanFill').style.width = '0%';
    document.getElementById('secscanStatus').textContent = `安全扫描进行中（0/${targets.length}）…`;
    renderSecscan();
    logLine('info', `安全扫描启动：${targets.length} 个确认资产`);
    window.assetAPI.startSecscan(
      targets.map((i) => ({ kind: i.kind, value: i.value || i.target, raw: i.target, port: null })),
      { loginCheck: true, concurrency: 8, portTimeout: 1200, bannerTimeout: 2500 }
    );
  });

  // ----------------------------------------------------------------------
  // 安全扫描结果渲染
  // ----------------------------------------------------------------------
  function updateBadgeSecscan() {
    const el = document.getElementById('badgeSecscan');
    if (el) el.textContent = store.secscan.length;
  }
  function renderSecscan() {
    const el = document.getElementById('secscanTable');
    if (!store.secscan.length) {
      el.innerHTML = '<div class="empty">确认资产并启动扫描后，此处展示连通性与高危指纹扫描结果。</div>';
      return;
    }
    let html = '<table class="secscan-table"><thead><tr>'
      + '<th>目标</th><th>类型</th><th>可达</th><th>延迟</th><th>地理位置</th><th>开放端口</th><th>高危指纹/发现</th><th>风险</th></tr></thead><tbody>';
    for (const r of store.secscan) {
      const riskCls = r.riskLevel === '高' ? 'tag-danger' : r.riskLevel === '中' ? 'tag-warn' : r.riskLevel === '低' ? 'tag-ok' : 'tag';
      html += `<tr>
        <td class="mono">${escapeHtml(r.target)}</td>
        <td>${escapeHtml(r.type)}</td>
        <td>${escapeHtml(r.alive)}</td>
        <td>${escapeHtml(r.latency)}</td>
        <td>${escapeHtml(r.geo)}</td>
        <td>${escapeHtml(r.openPorts)}</td>
        <td>${escapeHtml(r.fingerprints)}</td>
        <td><span class="tag ${riskCls}">${escapeHtml(r.riskLevel)}</span></td>
      </tr>`;
      if (r.detail && r.detail !== '未发现高危指纹') {
        html += `<tr class="detail-row"><td colspan="8"><div class="detail">${escapeHtml(r.detail)}</div></td></tr>`;
      }
      // 展示该目标关联出的漏洞（带分类标签 + 严重度）
      if (r.vulns && r.vulns.length) {
        const vhtml = r.vulns.map((v) => {
          const sev = `<span class="tag ${sevTagClass(v.severity)}">${sevLabel(v.severity)}</span>`;
          return `<div class="vuln-row">${sev}${catTag(v.category)}<span class="mono">${escapeHtml(v.title || v.type || '')}</span></div>`;
        }).join('');
        html += `<tr class="detail-row"><td colspan="8"><div class="detail"><b>关联漏洞（${r.vulns.length}）：</b>${vhtml}</div></td></tr>`;
      }
    }
    html += '</tbody></table>';
    el.innerHTML = html;
  }
  window.assetAPI.onSecscanStart(({ total }) => { store.secscanTotal = total; });
  window.assetAPI.onSecscanProgress(({ done, total }) => {
    const pct = total ? Math.round((done / total) * 100) : 0;
    document.getElementById('secscanFill').style.width = pct + '%';
    document.getElementById('secscanStatus').textContent = `安全扫描进行中（${done}/${total}）…`;
  });
  window.assetAPI.onSecscanResult((row) => { store.secscan.push(row); renderSecscan(); updateBadgeSecscan(); });
  window.assetAPI.onSecscanDone(({ rows }) => {
    store.secscan = rows || store.secscan;
    store.secscanRunning = false;
    document.getElementById('secscanProgress').style.display = 'none';
    renderSecscan(); updateBadgeSecscan();
    logLine('success', `安全扫描完成：共 ${store.secscan.length} 项`);
  });
  window.assetAPI.onSecscanError(({ target, message }) => {
    logLine('error', `安全扫描异常 ${target}：${message}`);
  });

  // ----------------------------------------------------------------------
  // EASM 报告生成（支持 HTML / Markdown / DOCX 三种格式）
  // ----------------------------------------------------------------------
  async function buildReportData() {
    const form = collectForm();
    const summary = {
      subdomains: store.subdomains.length,
      ips: store.ips.length,
      emails: store.emails.length,
      leaks: store.leaks.length,
      ports: store.ports.length,
      fingerprints: store.fingerprints.length,
      vulns: store.vulns.length,
      confirmedAssets: store.auditItems.filter((i) => store.audit[i.id] === 'real').length,
      riskHigh: store.secscan.filter((r) => r.riskLevel === '高').length,
      riskMid: store.secscan.filter((r) => r.riskLevel === '中').length,
      riskLow: store.secscan.filter((r) => r.riskLevel === '低').length,
    };
    const real = store.auditItems.filter((i) => store.audit[i.id] === 'real').length;
    const fp = store.auditItems.filter((i) => store.audit[i.id] === 'false').length;
    const pend = store.auditItems.length - real - fp;
    const confirmedTargets = store.auditItems
      .filter((i) => store.audit[i.id] === 'real')
      .map((i) => ({ target: i.target, type: i.kind === 'ip' ? 'IPv4' : '域名' }));
    return {
      meta: { appName: '万平灵探', version: '1.0.0' },
      generatedAt: new Date().toISOString(),
      input: {
        rootDomain: form.rootDomain,
        ipRange: form.ipRange,
        companyShort: form.companyShort,
        emailSuffix: form.emailSuffix,
      },
      summary,
      assets: {
        subdomains: store.subdomains, domains: store.domains, ips: store.ips,
        emails: store.emails, leaks: store.leaks, records: store.records,
        whois: store.whois, ports: store.ports, fingerprints: store.fingerprints,
        vulns: store.vulns, enterprise: store.enterprise, search: store.search,
      },
      audit: { total: store.auditItems.length, real, falsePositive: fp, pending: pend },
      confirmedTargets,
      security: store.secscan,
    };
  }

  async function generateReport(format) {
    const reportStatus = document.getElementById('reportStatus');
    const fmtLabel = { html: 'HTML', markdown: 'Markdown', docx: 'DOCX' }[format] || 'HTML';
    reportStatus.textContent = `正在生成${fmtLabel}报告…`;
    const reportData = await buildReportData();
    let res;
    try {
      if (format === 'markdown') res = await window.assetAPI.generateReportMd(reportData);
      else if (format === 'docx') res = await window.assetAPI.generateReportDocx(reportData);
      else res = await window.assetAPI.generateReport(reportData);
    } catch (e) {
      res = { ok: false, error: String(e && e.message ? e.message : e) };
    }
    if (res && res.ok) {
      reportStatus.textContent = `报告已生成（${fmtLabel}）：${res.filePath}`;
      logLine('success', `${fmtLabel} 报告已生成：${res.filePath}`);
    } else if (res && !res.canceled) {
      reportStatus.textContent = `生成失败：${res.error}`;
      logLine('error', `报告生成失败：${res.error}`);
    } else {
      reportStatus.textContent = '已取消';
    }
  }
  document.getElementById('btnGenReport').addEventListener('click', () => generateReport('html'));
  document.getElementById('btnGenReportMd').addEventListener('click', () => generateReport('markdown'));
  document.getElementById('btnGenReportDocx').addEventListener('click', () => generateReport('docx'));

  // ----------------------------------------------------------------------
  // 导出
  // ----------------------------------------------------------------------
  async function exportAs(format) {
    const payload = {
      meta: { exportedAt: new Date().toISOString(), version: '3.0' },
      domains: store.domains,
      subdomains: store.subdomains,
      ips: store.ips,
      ports: store.ports,
      fingerprints: store.fingerprints,
      vulns: store.vulns,
      emails: store.emails,
      leaks: store.leaks,
      records: store.records,
      whois: store.whois,
      enterprise: store.enterprise,
      search: store.search,
      secscan: store.secscan,
      audit: store.audit,
    };
    const res = await window.assetAPI.exportResults(format, payload);
    if (res.ok) {
      logLine('success', `已导出：${res.filePath}`);
    } else if (!res.canceled) {
      logLine('error', '导出失败：' + res.error);
    }
  }
  document.getElementById('btnExportJson').addEventListener('click', () => exportAs('json'));
  document.getElementById('btnExportCsv').addEventListener('click', () => exportAs('csv'));

  logLine('info', '就绪。请填写检索维度后点击「开始收集」。');
})();
