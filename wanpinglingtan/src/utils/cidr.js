'use strict';

/**
 * IPv4 / CIDR 工具：校验、展开、格式化。
 */

function isValidIPv4(ip) {
  if (typeof ip !== 'string') return false;
  const parts = ip.trim().split('.');
  if (parts.length !== 4) return false;
  return parts.every((p) => {
    if (!/^\d{1,3}$/.test(p)) return false;
    const n = Number(p);
    return n >= 0 && n <= 255;
  });
}

function isValidCidr(cidr) {
  if (typeof cidr !== 'string' || !cidr.includes('/')) return false;
  const [ip, bitsStr] = cidr.trim().split('/');
  if (!isValidIPv4(ip)) return false;
  if (!/^\d{1,2}$/.test(bitsStr)) return false;
  const bits = Number(bitsStr);
  return bits >= 0 && bits <= 32;
}

function ipToLong(ip) {
  return (
    ip.split('.').reduce((acc, o) => (acc << 8) + Number(o), 0) >>> 0
  );
}

function longToIp(long) {
  return [
    (long >>> 24) & 255,
    (long >>> 16) & 255,
    (long >>> 8) & 255,
    long & 255,
  ].join('.');
}

/**
 * 展开 CIDR 为 IP 列表。为避免超大范围导致卡死，默认最多返回 max 个地址。
 */
function expandCidr(cidr, max = 512) {
  if (!isValidCidr(cidr)) {
    return { ips: [], total: 0, truncated: false, error: `无效的 CIDR: ${cidr}` };
  }
  const [base, bitsStr] = cidr.trim().split('/');
  const bits = Number(bitsStr);
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  const start = (ipToLong(base) & mask) >>> 0;
  const total = 2 ** (32 - bits);

  const ips = [];
  const limit = Math.min(total, max);
  for (let i = 0; i < limit; i++) {
    ips.push(longToIp((start + i) >>> 0));
  }
  return { ips, total, truncated: total > max };
}

/**
 * 判定是否为「公网可路由」IPv4 地址。
 * 排除：环回、私有、链路本地、CGNAT、组播、保留、基准网络、广播、文档/基准段等。
 * 仅保留真实暴露面资产，过滤任何非公网/疑似虚假地址（宁可返回空）。
 */
function isPublicIPv4(ip) {
  if (!isValidIPv4(ip)) return false;
  const [a, b] = ip.split('.').map(Number);

  if (a === 0) return false;            // 0.0.0.0/8 保留
  if (a === 10) return false;           // 10.0.0.0/8 私有
  if (a === 127) return false;          // 127.0.0.0/8 环回
  if (a === 169 && b === 254) return false; // 169.254.0.0/16 链路本地
  if (a === 172 && b >= 16 && b <= 31) return false; // 172.16.0.0/12 私有
  if (a === 192 && b === 168) return false; // 192.168.0.0/16 私有
  if (a === 100 && b >= 64 && b <= 127) return false; // 100.64.0.0/10 CGNAT
  if (a === 192 && b === 0 && ip.startsWith('192.0.0.')) return false; // 192.0.0.0/24 保留
  if (a === 198 && (b === 18 || b === 19)) return false; // 198.18.0.0/15 基准网络
  if (a >= 224 && a <= 239) return false; // 224.0.0.0/4 组播
  if (a === 255) return false;           // 255.255.255.255 广播
  if (a >= 240) return false;            // 240.0.0.0/4 保留(E类)
  return true;
}

/** 返回 IP 的归属范围描述，用于结果标注 */
function ipScope(ip) {
  if (!isValidIPv4(ip)) return 'invalid';
  if (isPublicIPv4(ip)) return 'public';
  const [a, b] = ip.split('.').map(Number);
  if (a === 127) return 'loopback';
  if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) return 'private';
  if (a === 169 && b === 254) return 'link-local';
  if (a >= 224) return 'multicast/reserved';
  return 'reserved';
}

module.exports = { isValidIPv4, isValidCidr, expandCidr, ipToLong, longToIp, isPublicIPv4, ipScope };
