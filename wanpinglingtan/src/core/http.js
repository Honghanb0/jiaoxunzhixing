'use strict';

/**
 * 轻量 HTTP(S) 客户端，纯 Node 内置模块实现。
 * 能力：自动重定向、gzip/deflate/brotli 自动解压、超时、失败重试、
 *      统一 UA、JSON / 文本两种读取方式。供所有 provider 复用。
 */

const https = require('https');
const http = require('http');
const { URL } = require('url');
const zlib = require('zlib');

const DEFAULT_UA =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' +
  '(KHTML, like Gecko) Chrome/124.0 Safari/537.36 AssetCollector/2.0';

function decodeBody(buffer, encoding) {
  try {
    if (encoding === 'gzip') return zlib.gunzipSync(buffer);
    if (encoding === 'deflate') return zlib.inflateSync(buffer);
    if (encoding === 'br') return zlib.brotliDecompressSync(buffer);
  } catch (_) {
    /* 解压失败时退回原始数据 */
  }
  return buffer;
}

function doRequest(urlString, options) {
  return new Promise((resolve, reject) => {
    let url;
    try {
      url = new URL(urlString);
    } catch (e) {
      return reject(new Error('无效的 URL: ' + urlString));
    }

    const lib = url.protocol === 'http:' ? http : https;
    const timeout = options.timeout || 20000;
    const bodyBuf = options.body ? Buffer.from(options.body) : null;

    const headers = Object.assign(
      {
        'User-Agent': DEFAULT_UA,
        Accept: 'application/json, text/html, text/plain, */*',
        'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
      },
      options.headers || {}
    );
    if (bodyBuf && !headers['Content-Type'] && !headers['content-type']) {
      headers['Content-Type'] = 'application/json';
    }
    if (!headers['Accept-Encoding'] && !headers['accept-encoding']) {
      headers['Accept-Encoding'] = 'gzip, deflate, br';
    }

    const req = lib.request(
      url,
      {
        method: (options.method || 'GET').toUpperCase(),
        headers,
        timeout,
        rejectUnauthorized: false, // 接受自签名证书（资产探测常见）
      },
      (res) => {
        const status = res.statusCode || 0;
        const enc = (res.headers['content-encoding'] || '').toLowerCase();

        if (
          status >= 300 &&
          status < 400 &&
          res.headers.location &&
          (options.maxRedirects || 0) > 0
        ) {
          res.resume();
          const nextUrl = new URL(res.headers.location, url).toString();
          const retryOpts = Object.assign({}, options, {
            maxRedirects: (options.maxRedirects || 0) - 1,
          });
          delete retryOpts.body;
          return resolve(doRequest(nextUrl, retryOpts));
        }

        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const raw = Buffer.concat(chunks);
          const body = decodeBody(raw, enc).toString('utf8');
          resolve({
            status,
            headers: res.headers,
            body,
            url: url.toString(),
          });
        });
      }
    );

    req.setTimeout(timeout, () => {
      req.destroy(new Error('请求超时 (' + timeout + 'ms)'));
    });
    req.on('error', (err) => reject(err));

    if (bodyBuf) req.write(bodyBuf);
    req.end();
  });
}

/**
 * 发起一次请求，带重试。网络层错误 / 5xx 才重试，4xx 不重试。
 */
async function request(url, options = {}) {
  const {
    retries = 1,
    retryDelay = 600,
    timeout = 20000,
    maxRedirects = 5,
    ...rest
  } = options;

  let lastErr = null;
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const res = await doRequest(url, { ...rest, timeout, maxRedirects });
      if (res.status >= 500 && attempt < retries) {
        lastErr = new Error('服务端错误 ' + res.status);
        await new Promise((r) => setTimeout(r, retryDelay));
        continue;
      }
      return res;
    } catch (e) {
      lastErr = e;
      if (attempt < retries) {
        await new Promise((r) => setTimeout(r, retryDelay));
      }
    }
  }
  throw lastErr || new Error('未知请求错误');
}

/** GET 并解析 JSON（失败返回 null） */
async function getJson(url, options = {}) {
  const res = await request(url, options);
  const json = (() => {
    try {
      return JSON.parse(res.body);
    } catch (_) {
      return null;
    }
  })();
  return { ...res, json };
}

/** GET 文本 */
async function getText(url, options = {}) {
  return request(url, options);
}

/** HEAD/GET 仅取状态码（轻量连通性探测） */
async function getStatus(url, options = {}) {
  try {
    const res = await request(url, { method: 'GET', ...options, maxRedirects: 3 });
    return res.status;
  } catch (e) {
    return 0;
  }
}

module.exports = { request, getJson, getText, getStatus, DEFAULT_UA };
