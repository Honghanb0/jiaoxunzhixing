'use strict';

/**
 * 预加载脚本：在隔离上下文中向渲染进程安全暴露有限的 API。
 */

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('assetAPI', {
  // 启动收集任务
  startCollection: (formData) => ipcRenderer.send('collection:start', formData),

  // 订阅流式事件
  onLog: (cb) => ipcRenderer.on('collection:log', (_e, payload) => cb(payload)),
  onPartial: (cb) => ipcRenderer.on('collection:partial', (_e, payload) => cb(payload)),
  onStage: (cb) => ipcRenderer.on('collection:stage', (_e, payload) => cb(payload)),
  onDone: (cb) => ipcRenderer.on('collection:done', (_e, payload) => cb(payload)),

  // 导出结果
  exportResults: (format, data) => ipcRenderer.invoke('results:export', { format, data }),

  // ---- 安全扫描（针对人工审计确认后的资产）----
  startSecscan: (targets, options) => ipcRenderer.send('secscan:start', { targets, options }),
  onSecscanStart: (cb) => ipcRenderer.on('secscan:start', (_e, p) => cb(p)),
  onSecscanProgress: (cb) => ipcRenderer.on('secscan:progress', (_e, p) => cb(p)),
  onSecscanResult: (cb) => ipcRenderer.on('secscan:result', (_e, p) => cb(p)),
  onSecscanDone: (cb) => ipcRenderer.on('secscan:done', (_e, p) => cb(p)),
  onSecscanError: (cb) => ipcRenderer.on('secscan:error', (_e, p) => cb(p)),

  // ---- 人工审计增强：IP 解析 / 地理位置 / 连通性（仅 IP 与域名类资产）----
  enrichAudit: (targets) => ipcRenderer.invoke('audit:enrich', targets),

  // ---- EASM 报告生成（HTML / Markdown / DOCX）----
  generateReport: (reportData) => ipcRenderer.invoke('report:generate', reportData),
  generateReportMd: (reportData) => ipcRenderer.invoke('report:generate-md', reportData),
  generateReportDocx: (reportData) => ipcRenderer.invoke('report:generate-docx', reportData),
});
