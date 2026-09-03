'use strict';

/**
 * 企业万平灵探 - Electron 主进程
 * 负责创建窗口、桥接渲染进程与后端采集模块、处理导出等系统级操作。
 */

const electron = require('electron');
const { app, BrowserWindow, ipcMain, dialog } = electron;
const path = require('path');
const fs = require('fs');

const { runCollection } = require('./src/orchestrator');
const { runSecScan } = require('./src/secscan/run');
const { enrichTargets } = require('./src/secscan/enrich');
const { buildEasmReportHtml } = require('./src/report/easm');
const { buildEasmReportMarkdown } = require('./src/report/markdown');
const { buildEasmReportDocxBuffer } = require('./src/report/docx');

// 防御性检查：若环境把 electron 当普通 Node 运行（ELECTRON_RUN_AS_NODE 等），
// require('electron') 会退化成字符串，此处给出明确提示而非崩溃。
if (!app || typeof app.whenReady !== 'function') {
  console.error(
    '\n[万平灵探] 未能加载 Electron 运行时 API。\n' +
      '请确认以 Electron 模式启动（例如 npm run launch / npm start），\n' +
      '且环境变量 ELECTRON_RUN_AS_NODE 未被设置为 1。\n'
  );
  process.exit(1);
}

let mainWindow = null;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1280,
    height: 860,
    minWidth: 1024,
    minHeight: 680,
    backgroundColor: '#0e1420',
    title: '万平灵探',
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
    },
  });

  mainWindow.loadFile(path.join(__dirname, 'renderer', 'index.html'));

  mainWindow.webContents.on('did-finish-load', () => {
    console.log('[万平灵探] 渲染页面加载完成');
    if (process.argv.includes('--self-test')) runSelfTest(mainWindow);
  });
  mainWindow.webContents.on('crashed', (e, killed) => {
    console.error('[万平灵探] 渲染进程崩溃：', killed);
  });

  if (process.argv.includes('--dev')) {
    mainWindow.webContents.openDevTools({ mode: 'detach' });
  }

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

app.whenReady().then(() => {
  console.log('[万平灵探] app ready，正在创建窗口…');
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  console.log('[万平灵探] 所有窗口已关闭');
  if (process.platform !== 'darwin') app.quit();
});

// ---------------------------------------------------------------------------
// 自检模式：在无显示环境下验证前端是否正确加载、preload 桥接是否生效
// ---------------------------------------------------------------------------
async function runSelfTest(win) {
  const expr = `JSON.stringify({
    assetAPI: typeof window.assetAPI,
    apiMethods: window.assetAPI ? Object.keys(window.assetAPI).filter(k => typeof window.assetAPI[k] === 'function') : [],
    fields: ['rootDomain','ipRange','companyShort','companyFull','emailSuffix','githubKeywords','sensitiveKeywords','githubToken','doSubdomain','doWhois','doReverseIp','doGithub','doPort','doFingerprint','doVuln','doEnterprise','doSearch','includeGuesses','concurrency','resolvers','keyFofaEmail','keyFofa','keyShodan','keyZoomeye','keyQuake','keyHunter','keyEnsanEndpoint','keyEnsan','btnAuditSelectAll','btnAuditInvert','btnAuditClear',      'btnAuditAllReal','btnAuditAllFalse','btnAuditReset','btnStartSecscan','btnGenReport','btnGenReportMd','btnGenReportDocx'].map(id => ({id, ok: !!document.getElementById(id)})),
    tabs: document.querySelectorAll('.tab').length,
    panes: document.querySelectorAll('.tab-pane').length,
    copyright: (document.querySelector('.copyright') || {}).textContent,
    formSubmit: typeof document.getElementById('collectForm').requestSubmit
  })`;

  try {
    const result = await win.webContents.executeJavaScript(expr);
    const parsed = JSON.parse(result);
    const missing = parsed.fields.filter((f) => !f.ok).map((f) => f.id);
    const copyrightOk = /洪声越Jeff/.test(parsed.copyright) && /HongshengyueJeff@163\.com/.test(parsed.copyright);
    console.log('[自检] assetAPI:', parsed.assetAPI, '| 方法:', parsed.apiMethods.join(','));
    console.log('[自检] 表单字段缺失:', missing.length ? missing.join(',') : '无');
    console.log('[自检] Tab 数量:', parsed.tabs, '| 面板数量:', parsed.panes, '| 版权信息正确:', copyrightOk);
    console.log('[自检] 版权文本:', parsed.copyright);
    const pass = parsed.assetAPI === 'object' && missing.length === 0 && parsed.tabs === 14 && parsed.panes === 14 && copyrightOk;
    console.log(pass ? '[自检] 全部通过 ✅' : '[自检] 存在问题 ❌');
  } catch (e) {
    console.error('[自检] 执行失败:', e.message);
  }
  setTimeout(() => app.quit(), 500);
}

// ---------------------------------------------------------------------------
// IPC：启动一次资产收集任务（流式返回进度与结果）
// ---------------------------------------------------------------------------
ipcMain.on('collection:start', async (event, formData) => {
  const send = (channel, payload) => {
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send(channel, payload);
    }
  };

  const emitter = {
    log: (level, message) => send('collection:log', { level, message, time: Date.now() }),
    partial: (category, items) => send('collection:partial', { category, items }),
    stage: (name, status) => send('collection:stage', { name, status }),
  };

  try {
    const result = await runCollection(formData, emitter);
    send('collection:done', { ok: true, result });
  } catch (err) {
    emitter.log('error', `任务异常终止：${err && err.message ? err.message : String(err)}`);
    send('collection:done', { ok: false, error: String(err && err.message ? err.message : err) });
  }
});

// ---------------------------------------------------------------------------
// IPC：安全扫描（人工审计确认后的资产）
// ---------------------------------------------------------------------------
ipcMain.on('secscan:start', async (event, { targets, options }) => {
  const send = (channel, payload) => {
    if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send(channel, payload);
  };
  const hooks = {
    log: (level, message) => send('collection:log', { level, message, time: Date.now() }),
    onStart: ({ total }) => send('secscan:start', { total }),
    onProgress: ({ done, total, row }) => send('secscan:progress', { done, total, row }),
    onResult: (row) => send('secscan:result', row),
    onDone: ({ rows }) => send('secscan:done', { rows }),
    onError: ({ target, message }) => send('secscan:error', { target, message }),
  };
  try {
    await runSecScan(targets || [], options || {}, hooks);
  } catch (err) {
    hooks.log('error', `安全扫描异常：${err && err.message ? err.message : String(err)}`);
    send('secscan:done', { rows: [] });
  }
});

// ---------------------------------------------------------------------------
// IPC：生成格式化 EASM 报告（自包含 HTML）
// ---------------------------------------------------------------------------
ipcMain.handle('report:generate', async (_event, reportData) => {
  try {
    const html = buildEasmReportHtml(reportData || {});
    const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    const defaultName = `easm-report-${stamp}.html`;
    const { canceled, filePath } = await dialog.showSaveDialog(mainWindow, {
      title: '导出 EASM 报告',
      defaultPath: defaultName,
      filters: [{ name: 'HTML 报告', extensions: ['html'] }],
    });
    if (canceled || !filePath) return { ok: false, canceled: true };
    fs.writeFileSync(filePath, html, 'utf8');
    return { ok: true, filePath };
  } catch (err) {
    return { ok: false, error: String(err && err.message ? err.message : err) };
  }
});

// ---------------------------------------------------------------------------
// IPC：人工审计资产轻量 enrichment（DNS 解析 + 地理库 + 连通性）
// ---------------------------------------------------------------------------
ipcMain.handle('audit:enrich', async (_event, targets) => {
  try {
    return await enrichTargets(targets || []);
  } catch (err) {
    return { items: [] };
  }
});

// ---------------------------------------------------------------------------
// IPC：生成 Markdown 格式 EASM 报告
// ---------------------------------------------------------------------------
ipcMain.handle('report:generate-md', async (_event, reportData) => {
  try {
    const md = buildEasmReportMarkdown(reportData || {});
    const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    const { canceled, filePath } = await dialog.showSaveDialog(mainWindow, {
      title: '导出 EASM 报告（Markdown）',
      defaultPath: `easm-report-${stamp}.md`,
      filters: [{ name: 'Markdown 文档', extensions: ['md'] }],
    });
    if (canceled || !filePath) return { ok: false, canceled: true };
    fs.writeFileSync(filePath, md, 'utf8');
    return { ok: true, filePath };
  } catch (err) {
    return { ok: false, error: String(err && err.message ? err.message : err) };
  }
});

// ---------------------------------------------------------------------------
// IPC：生成 DOCX 格式 EASM 报告（自包含 OOXML，无需第三方库）
// ---------------------------------------------------------------------------
ipcMain.handle('report:generate-docx', async (_event, reportData) => {
  try {
    const buf = buildEasmReportDocxBuffer(reportData || {});
    const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    const { canceled, filePath } = await dialog.showSaveDialog(mainWindow, {
      title: '导出 EASM 报告（DOCX）',
      defaultPath: `easm-report-${stamp}.docx`,
      filters: [{ name: 'Word 文档', extensions: ['docx'] }],
    });
    if (canceled || !filePath) return { ok: false, canceled: true };
    fs.writeFileSync(filePath, buf);
    return { ok: true, filePath };
  } catch (err) {
    return { ok: false, error: String(err && err.message ? err.message : err) };
  }
});

// ---------------------------------------------------------------------------
// IPC：导出结果为 JSON / CSV
// ---------------------------------------------------------------------------
ipcMain.handle('results:export', async (_event, { format, data }) => {
  const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  const defaultName = `asset-report-${stamp}.${format === 'csv' ? 'csv' : 'json'}`;

  const { canceled, filePath } = await dialog.showSaveDialog(mainWindow, {
    title: '导出资产报告',
    defaultPath: defaultName,
    filters:
      format === 'csv'
        ? [{ name: 'CSV 文件', extensions: ['csv'] }]
        : [{ name: 'JSON 文件', extensions: ['json'] }],
  });

  if (canceled || !filePath) return { ok: false, canceled: true };

  try {
    let content;
    if (format === 'csv') {
      content = toCsv(data);
    } else {
      content = JSON.stringify(data, null, 2);
    }
    fs.writeFileSync(filePath, content, 'utf8');
    return { ok: true, filePath };
  } catch (err) {
    return { ok: false, error: String(err && err.message ? err.message : err) };
  }
});

/**
 * 将聚合结果扁平化为 CSV
 */
function toCsv(data) {
  const rows = [['类别', '资产', '详情', '置信度/来源']];
  const push = (cat, value, detail = '', extra = '') => rows.push([cat, value, detail, extra]);

  const r = data || {};
  (r.domains || []).forEach((d) => push('域名', d.host || d, '', d.source || ''));
  (r.subdomains || []).forEach((s) => push('子域名', s.host || s, (s.ips || []).join('|'), ''));
  (r.ips || []).forEach((i) =>
    push('IP资产', i.ip || i, (i.hosts || []).join('|'), `${i.scope || 'public'}/${i.confidence || ''}`)
  );
  (r.ports || []).forEach((p) => {
    const detail = [p.service || '', p.state || '', p.status ? `码${p.status}` : ''].filter(Boolean).join(' ');
    const extra = [p.protocol || '', p.server || '', p.title || ''].filter(Boolean).join(' · ');
    push('端口', `${p.target}:${p.port}`, detail, extra);
  });
  (r.fingerprints || []).forEach((f) => {
    const techs = (f.tech || []).map((t) => `${t.name}(${Math.round((t.confidence || 0) * 100)}%)`).join(' ');
    push('指纹', f.host || f, techs, '');
  });
  (r.vulns || []).forEach((v) => {
    const detail = [v.type || '', v.detail || ''].filter(Boolean).join(' · ');
    push('漏洞', `${v.severity || 'info'} ${v.host || ''}`, v.title || '', detail);
  });
  (r.emails || []).forEach((e) =>
    push('邮箱', e.email || e, e.source || '', `${e.confidence || ''}${e.mx ? '·MX' : ''}`)
  );
  (r.leaks || []).forEach((g) =>
    push('泄露', g.title || g.url || '', g.snippet || '', `${g.source || ''}/${g.confidence || ''}`)
  );
  (r.records || []).forEach((rec) => push('DNS记录', `${rec.type} ${rec.host}`, rec.value, ''));
  (r.enterprise || []).forEach((e) => {
    const kv = Object.entries(e)
      .filter(([k]) => k !== 'source')
      .map(([k, val]) => `${k}:${Array.isArray(val) ? val.join('/') : val}`)
      .join(' | ');
    push('企业信息', e.domain || e.name || e.icp || '企业信息', kv, e.source || '');
  });
  (r.search || []).forEach((s) => push('资产搜索', String(s.asset || ''), String(s.raw || '').slice(0, 200), s.source || ''));
  (r.secscan || []).forEach((sc) => {
    const detail = [`风险:${sc.riskLevel || '-'}`, `端口:${sc.openPorts || '-'}`, `指纹:${sc.fingerprints || '-'}`].join(' | ');
    const extra = [`连通:${sc.alive || '-'}/${sc.latency || '-'}`, `地理:${sc.geo || '-'}`, `登录页:${sc.hasLogin || '-'}`].join(' · ');
    push('安全扫描', sc.target || '', detail, extra);
  });

  return rows
    .map((cols) =>
      cols
        .map((c) => {
          const s = String(c == null ? '' : c).replace(/"/g, '""');
          return /[",\n]/.test(s) ? `"${s}"` : s;
        })
        .join(',')
    )
    .join('\r\n');
}
