/**
 * 极简 HTTP 客户端
 *
 * 只用 Node 内置 https 模块，因此没有任何第三方依赖。
 * 内置：超时、有限重试、重定向跟随（有上限）、响应体大小上限、请求间隔。
 *
 * @module lib/http
 */

import https from 'node:https';
import http from 'node:http';
import { setTimeout as sleep } from 'node:timers/promises';

const DEFAULT_UA =
  'surface-watch/0.1 (+authorized-security-monitoring; contact: see scope.json)';

/** 响应体最大读取量，防止被超大响应拖死 */
const MAX_BODY_BYTES = 256 * 1024;
const MAX_REDIRECTS = 5;

/**
 * 发起一次请求
 * @param {string} url
 * @param {object} options
 * @returns {Promise<object>} 观测结果（永不 reject，网络错误变成 error 字段）
 */
export async function request(url, options = {}) {
  const {
    method = 'GET',
    timeoutMs = 10000,
    retries = 2,
    headers = {},
    followRedirects = true,
  } = options;

  let lastError = null;

  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      return await once(url, { method, timeoutMs, headers, followRedirects });
    } catch (err) {
      lastError = err;
      /* 只在网络类错误上重试；明显是逻辑错误就直接冒泡 */
      if (err.code === 'PROTOCOL_ERROR' || err.code === 'TOO_MANY_REDIRECTS') break;
      if (attempt < retries) await sleep(400 * (attempt + 1));
    }
  }

  return {
    ok: false,
    error: lastError ? lastError.code || lastError.message : 'UNKNOWN',
    status: null,
    headers: {},
    body: '',
    finalUrl: url,
    ms: 0,
  };
}

function once(url, { method, timeoutMs, headers, followRedirects }, redirectCount = 0) {
  return new Promise((resolve, reject) => {
    const started = Date.now();
    const parsed = new URL(url);
    const client = parsed.protocol === 'http:' ? http : https;

    const req = client.request(
      {
        protocol: parsed.protocol,
        hostname: parsed.hostname,
        port: parsed.port || (parsed.protocol === 'http:' ? 80 : 443),
        path: parsed.pathname + parsed.search,
        method,
        headers: {
          'User-Agent': DEFAULT_UA,
          Accept: '*/*',
          /* 明确不压缩：避免引入解压逻辑，也让"原始响应"更可解释 */
          'Accept-Encoding': 'identity',
          ...headers,
        },
        /* 自签证书也要能观测到（我们要的是"报告它"，不是"信任它"） */
        rejectUnauthorized: false,
        timeout: timeoutMs,
      },
      (res) => {
        /* 重定向处理 */
        if (
          followRedirects &&
          res.statusCode >= 300 &&
          res.statusCode < 400 &&
          res.headers.location
        ) {
          res.resume();
          if (redirectCount >= MAX_REDIRECTS) {
            const err = new Error('重定向次数过多');
            err.code = 'TOO_MANY_REDIRECTS';
            return reject(err);
          }
          const next = new URL(res.headers.location, url).toString();
          return resolve(once(next, { method, timeoutMs, headers, followRedirects }, redirectCount + 1));
        }

        const chunks = [];
        let received = 0;
        let sawEnd = false;
        let settled = false;

        res.on('data', (chunk) => {
          received += chunk.length;
          if (received <= MAX_BODY_BYTES) chunks.push(chunk);
          else res.destroy(); // 超出上限就断开，已读部分仍可用（并标记 truncated）
        });

        const finish = () => {
          if (settled) return;
          settled = true;
          resolve({
            ok: true,
            status: res.statusCode,
            headers: res.headers,
            body: Buffer.concat(chunks).toString('utf8'),
            truncated: received > MAX_BODY_BYTES,
            finalUrl: url,
            ms: Date.now() - started,
            tls: res.socket && res.socket.getPeerCertificate ? describeSocket(res.socket) : null,
          });
        };

        res.on('end', () => {
          sawEnd = true;
          finish();
        });

        /* 关键：连接可能被对端中断，此时 close 会先于 end 触发。
           静默返回残缺数据对安全工具是致命的 —— 靠响应内容判断暴露的检查
           （如 paths 的 .git/config 特征匹配）会因截断而漏报。
           因此这里必须区分「完整结束」与「提前断开」，后者一律当网络错误重试。 */
        res.on('close', () => {
          if (settled) return;
          if (sawEnd) return finish();

          const expected = Number(res.headers['content-length'] || 0);
          const incomplete = !expected || received < expected;

          if (incomplete && received <= MAX_BODY_BYTES) {
            settled = true;
            reject(
              Object.assign(new Error(`响应被提前中断（收到 ${received} 字节，期望 ${expected || '未知'}）`), {
                code: 'INCOMPLETE_RESPONSE',
              })
            );
            return;
          }
          finish();
        });
      }
    );

    req.on('timeout', () => {
      req.destroy(Object.assign(new Error('请求超时'), { code: 'TIMEOUT' }));
    });
    req.on('error', reject);
    req.end();
  });
}

function describeSocket(socket) {
  try {
    const cert = socket.getPeerCertificate();
    return {
      protocol: socket.getProtocol(),
      cipher: socket.getCipher() ? socket.getCipher().name : null,
      authorized: socket.authorized,
      authorizationError: socket.authorizationError || null,
      cert: cert && cert.valid_from ? cert : null,
    };
  } catch {
    return null;
  }
}

/**
 * 按给定间隔依次执行任务（简单节流，避免把目标打成压力测试）
 * @template T
 * @param {Array<() => Promise<T>>} tasks
 * @param {number} delayMs
 * @returns {Promise<T[]>}
 */
export async function runThrottled(tasks, delayMs = 0) {
  const results = [];
  for (const task of tasks) {
    results.push(await task());
    if (delayMs > 0) await sleep(delayMs);
  }
  return results;
}
