'use strict';
/*
 * vuln-categories.js — 漏洞分类标签统一规范
 * 所有漏洞/暴露检测产出均须映射到下列 12 个标准分类之一，便于前端打标签与报告归类。
 */

// 标准漏洞分类（顺序用于报告/前端展示）
const VULN_CATEGORIES = [
  '文件上传',
  '反序列化',
  'SSRF',
  'CSRF',
  '未授权访问',
  'SQL注入',
  'XSS',
  '整数溢出',
  '代码注入',
  '路径遍历',
  '缓冲区溢出',
  '其他',
];

// CVE/漏洞类型（中文或英文）→ 标准分类 的映射
// 用于把指纹库关联漏洞的 type 字段归一化到 12 类
const CVE_TYPE_MAP = [
  [/远程代码执行|代码执行|rce|命令执行|命令注入/i, '代码注入'],
  [/反序列化|deserializ/i, '反序列化'],
  [/任意文件上传|文件上传|upload/i, '文件上传'],
  [/路径穿越|任意文件读取|目录遍历|path\s*traversal|directory\s*traversal|lfi|任意文件下载/i, '路径遍历'],
  [/服务端请求伪造|ssrf/i, 'SSRF'],
  [/未授权访问|鉴权绕过|权限绕过|认证绕过|unauthorized|未授权|无需认证/i, '未授权访问'],
  [/sql\s*注入|sql\s*injection/i, 'SQL注入'],
  [/跨站脚本|xss/i, 'XSS'],
  [/跨站请求伪造|csrf/i, 'CSRF'],
  [/整数溢出|integer\s*overflow/i, '整数溢出'],
  [/缓冲区溢出|buffer\s*overflow|栈溢出|堆溢出/i, '缓冲区溢出'],
  [/信息泄露|信息泄漏|泄露|disclosure|源码泄露/i, '其他'],
  [/拒绝服务|dos/i, '其他'],
];

// 将任意类型描述归一化为标准分类；无法识别 → '其他'
function mapVulnCategory(type) {
  if (!type) return '其他';
  const s = String(type);
  for (const [re, cat] of CVE_TYPE_MAP) {
    if (re.test(s)) return cat;
  }
  return '其他';
}

// 校验/修正一个分类是否为合法标准分类，否则归为 '其他'
function normalizeCategory(cat) {
  return VULN_CATEGORIES.includes(cat) ? cat : '其他';
}

module.exports = { VULN_CATEGORIES, CVE_TYPE_MAP, mapVulnCategory, normalizeCategory };
