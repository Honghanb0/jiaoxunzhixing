'use strict';

/**
 * TCP 端口扫描 provider（Masscan / Nmap connect 思路）。
 * 仅对「IP 资产」（发现的公网 IP + 显式输入 IP）做 TCP 连通性扫描，
 * 不扫描域名主机（域名已由 HTTP 探测覆盖）。规模收敛，超时即关闭。
 * 仅探测、不识别服务版本（不主动发指纹探测包）。
 */

const net = require('net');
const { BaseProvider, portFinding } = require('../../core/base');
const { Pool } = require('../../core/semaphore');
const { isPublicIPv4, uniq } = require('../../core/utils');

const SCAN_PORTS = [
  21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 465, 587, 993, 995,
  1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9000, 9200, 27017,
];

const SERVICE_MAP = {
  21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns', 80: 'http',
  110: 'pop3', 135: 'msrpc', 139: 'netbios', 143: 'imap', 443: 'https',
  445: 'smb', 465: 'smtps', 587: 'submission', 993: 'imaps', 995: 'pop3s',
  1433: 'mssql', 1521: 'oracle', 3306: 'mysql', 3389: 'rdp', 5432: 'postgresql',
  5900: 'vnc', 6379: 'redis', 8080: 'http-alt', 8443: 'https-alt', 9000: 'sonarqube',
  9200: 'elasticsearch', 27017: 'mongodb',
};

function tcpConnect(ip, port, timeoutMs) {
  return new Promise((resolve) => {
    const sock = new net.Socket();
    let done = false;
    const finish = (open) => {
      if (done) return;
      done = true;
      try { sock.destroy(); } catch (_) {}
      resolve(open);
    };
    sock.setTimeout(timeoutMs);
    sock.once('connect', () => finish(true));
    sock.once('timeout', () => finish(false));
    sock.once('error', () => finish(false));
    try {
      sock.connect(port, ip);
    } catch (_) {
      finish(false);
    }
  });
}

class TcpProbeProvider extends BaseProvider {
  static id = 'port.tcpprobe';
  static category = 'port';
  static label = 'TCP 端口扫描';
  static description = '对 IP 资产做 TCP 连通性扫描（常见端口），识别开放服务';
  static priority = 30;

  async run(job) {
    const ctx = job.context || {};
    const discovered = Array.from(ctx.discoveredIps || []).filter(isPublicIPv4);
    const inputs = (ctx.ipInputs || []).filter(isPublicIPv4);
    const ips = uniq([...discovered, ...inputs]).slice(0, 500); // 收敛规模
    if (!ips.length) return { items: [] };

    const timeout = Math.min(this.ctx.config.timeout, 1200);
    const pool = new Pool(150);
    const items = [];
    let openCount = 0;

    await pool.map(ips, async (ip) => {
      const results = await Promise.all(
        SCAN_PORTS.map((p) => tcpConnect(ip, p, timeout).then((open) => ({ p, open })))
      );
      for (const { p, open } of results) {
        if (open) {
          openCount++;
          items.push(
            portFinding(ip, p, {
              protocol: 'tcp',
              service: SERVICE_MAP[p] || 'unknown',
              state: 'open',
              source: 'tcpprobe',
            })
          );
        }
      }
    });

    return { items, stats: { ips: ips.length, openPorts: openCount } };
  }
}

module.exports = TcpProbeProvider;
