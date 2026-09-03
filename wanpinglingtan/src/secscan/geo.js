'use strict';
/*
 * geo.js — IP 地理位置查询（离线，基于 ip2region）
 * 规则：
 *   - 中国大陆：精确到地级市，格式 国家-省-市（如 中国-浙江-杭州）
 *   - 其余：精确到一级行政区划，格式 国家-一级行政区（如 美国-阿拉斯加）
 */

const path = require('path');
let _searcher = undefined; // undefined=未初始化; null=加载失败; object=可用

function getSearcher() {
  if (_searcher !== undefined) return _searcher;
  try {
    const IP2Region = require('ip2region').default;
    // 仅 IPv4 地理库即可，禁用 ipv6 以避免额外加载 ipv6wry.db 及其失败风险
    _searcher = new IP2Region({ disableIpv6: true });
  } catch (e) {
    _searcher = null;
  }
  return _searcher;
}

// 去除省级行政区常见后缀，使输出贴近 中国-浙江-杭州 的简写风格
function cleanProvince(p) {
  if (!p) return '';
  return p
    .replace(/维吾尔自治区$/, '')
    .replace(/壮族自治区$/, '')
    .replace(/回族自治区$/, '')
    .replace(/自治区$/, '')
    .replace(/特别行政区$/, '')
    .replace(/省$/, '')
    .replace(/市$/, '');
}

function cleanCity(c) {
  if (!c) return '';
  return c.replace(/市$/, '').replace(/区$/, '').replace(/县$/, '');
}

/*
 * 将原始查询结果格式化为展示字符串
 * raw: { country, province, city, isp } | null
 */
function formatGeo(raw) {
  if (!raw || !raw.country) {
    if (raw && raw.city && /内网|保留|私有/.test(raw.city)) return '内网/保留IP';
    return '未知';
  }
  const country = raw.country;
  const isChina = country === '中国';
  if (isChina) {
    const prov = cleanProvince(raw.province);
    const city = cleanCity(raw.city);
    if (prov && city) return `中国-${prov}-${city}`;
    if (prov) return `中国-${prov}`;
    return '中国';
  }
  // 境外：精确到一级行政区划（省/州）
  const prov = cleanProvince(raw.province);
  if (prov) return `${country}-${prov}`;
  return country;
}

/*
 * 查询单条 IP 的地理位置（返回格式化字符串）
 */
function lookup(ip) {
  const searcher = getSearcher();
  if (!searcher) return '（地理库不可用）';
  try {
    const raw = searcher.search(ip);
    return formatGeo(raw);
  } catch (e) {
    return '未知';
  }
}

/*
 * 批量查询（供测试/渲染使用）
 */
function lookupBatch(ips) {
  return ips.map((ip) => lookup(ip));
}

module.exports = { lookup, lookupBatch, formatGeo, getSearcher };
