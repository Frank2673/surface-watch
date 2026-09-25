#!/usr/bin/env node
/**
 * 本机假 Webhook 接收服务（零依赖，仅 `node:http` / `node:crypto`）
 *
 * 用途：在没有真实告警通道（Slack / 飞书 / 企业微信）的情况下，端到端验证
 * surface-watch 的 Webhook 投递行为，并能**故意制造故障**来验证失败语义。
 *
 * 它做三件事：
 *   1. 把每个请求的方法 / 路径 / 头 / 原始 body / 时间 / 响应，逐行写入 JSONL
 *      （appendFileSync，进程被杀也不丢已收记录）
 *   2. 可选地用共享密钥独立复算 HMAC-SHA256，校验 `X-Surface-Watch-Signature`
 *   3. 故障注入：`--fail-status 500` / `--delay <ms>` / `--redirect`
 *
 * 安全边界：默认只绑定回环地址 127.0.0.1；要绑非回环地址必须显式加
 * `--allow-remote`（防止"为了测个告警"把监听面暴露到局域网）。
 *
 * 用法：
 *   node scripts/fake-webhook.mjs --port 8787 --log tmp/webhook-e2e/received.jsonl
 *   node scripts/fake-webhook.mjs --port 0                 # 随机端口，启动行会打印实际端口
 *   node scripts/fake-webhook.mjs --fail-status 500 --fail-times 2   # 前 2 次 500，第 3 次成功
 *   node scripts/fake-webhook.mjs --delay 8000 --secret s3cr3t       # 触发客户端超时
 *   node scripts/fake-webhook.mjs --redirect https://example.com/x   # 3xx 故障注入
 */

import http from 'node:http';
import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import { appendFileSync, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';

const SIGNATURE_HEADER = 'x-surface-watch-signature';
const MAX_BODY_BYTES = 1024 * 1024;

function parseArgs(argv) {
  const args = { _: [] };
  const takesValue = new Set([
    '--port',
    '--host',
    '--log',
    '--path',
    '--fail-status',
    '--fail-times',
    '--delay',
    '--redirect',
    '--redirect-status',
    '--secret',
  ]);
  const flags = new Set(['--allow-remote', '--quiet', '--help']);

  for (let i = 0; i < argv.length; i++) {
    const token = argv[i];
    if (takesValue.has(token)) {
      const value = argv[i + 1];
      if (value === undefined) throw new Error(`${token} 需要一个值`);
      args[token.slice(2)] = value;
      i++;
    } else if (flags.has(token)) {
      args[token.slice(2)] = true;
    } else {
      throw new Error(`未知参数：${token}（--help 查看用法）`);
    }
  }
  return args;
}

function usage() {
  return `
假 Webhook 接收服务（surface-watch 端到端验证用）

用法：node scripts/fake-webhook.mjs [选项]

选项：
  --port <n>            监听端口，默认 8787；传 0 表示随机可用端口
  --host <h>            监听地址，默认 127.0.0.1（非回环地址需配合 --allow-remote）
  --allow-remote        允许绑定非回环地址（默认拒绝）
  --log <路径>          请求记录（JSONL），默认 tmp/fake-webhook/received.jsonl
  --path <路径>         视为"正常接收"的路径，默认 /hook；其它路径返回 404（仍会记录）
  --secret <密钥>       用共享密钥复算 HMAC-SHA256 并校验签名头
                        （也可用环境变量 SURFACE_WATCH_WEBHOOK_SECRET）
  --fail-status <code>  故障注入：返回该状态码（如 500）
  --fail-times <n>      故障注入只对前 n 个请求生效，之后恢复正常（默认一直失败）
  --delay <ms>          响应前延迟，用于触发客户端超时
  --redirect [目标]     故障注入：返回 302（可指定 Location，默认 /moved）
  --redirect-status <code>  配合 --redirect 使用的状态码，默认 302
  --quiet               不打印逐请求日志
  --help                显示本帮助

退出：Ctrl+C 停止；停止时会打印收到的请求总数。
`.trim();
}

const args = parseArgs(process.argv.slice(2));
if (args.help) {
  console.log(usage());
  process.exit(0);
}

const host = args.host || '127.0.0.1';
const isLoopback = /^(127\.|::1$|localhost$)/.test(host);
if (!isLoopback && !args['allow-remote']) {
  console.error(
    `🛑 拒绝绑定非回环地址 ${host}：本服务仅用于本机验证。` +
      `确实需要时请显式加 --allow-remote。`
  );
  process.exit(2);
}

const port = args.port === undefined ? 8787 : Number(args.port);
const hookPath = args.path || '/hook';
const logPath = resolve(args.log || 'tmp/fake-webhook/received.jsonl');
const secret = args.secret || process.env.SURFACE_WATCH_WEBHOOK_SECRET || null;
const failStatus = args['fail-status'] ? Number(args['fail-status']) : null;
const failTimes = args['fail-times'] !== undefined ? Number(args['fail-times']) : Infinity;
const delayMs = args.delay ? Number(args.delay) : 0;
const redirectStatus = args['redirect-status'] ? Number(args['redirect-status']) : 302;
const redirectTarget = args.redirect !== undefined ? args.redirect : null;
const quiet = Boolean(args.quiet);

if (!Number.isInteger(port) || port < 0 || port > 65535) {
  console.error(`🛑 --port 非法：${args.port}`);
  process.exit(2);
}

mkdirSync(dirname(logPath), { recursive: true });

let received = 0;

function record(entry) {
  appendFileSync(logPath, `${JSON.stringify(entry)}\n`, 'utf8');
}

function verifySignature(headerValue, rawBody) {
  if (!headerValue) {
    return { header: null, valid: false, reason: secret ? 'missing-header' : 'no-secret-configured' };
  }
  if (!secret) {
    return { header: headerValue, valid: null, reason: 'no-secret-configured' };
  }
  const expected = `sha256=${createHmac('sha256', secret).update(rawBody).digest('hex')}`;
  const a = Buffer.from(String(headerValue));
  const b = Buffer.from(expected);
  const valid = a.length === b.length && timingSafeEqual(a, b);
  return {
    header: headerValue,
    algorithm: 'HMAC-SHA256(body)',
    expected,
    valid,
    reason: valid ? 'match' : 'mismatch',
  };
}

const server = http.createServer((req, res) => {
  const chunks = [];
  let receivedBytes = 0;
  let overflow = false;

  req.on('data', (chunk) => {
    receivedBytes += chunk.length;
    if (receivedBytes <= MAX_BODY_BYTES) chunks.push(chunk);
    else overflow = true;
  });

  req.on('end', async () => {
    received++;
    const index = received;
    const rawBody = Buffer.concat(chunks);
    const bodyText = rawBody.toString('utf8');

    let bodyJson = null;
    let bodyJsonError = null;
    try {
      bodyJson = JSON.parse(bodyText);
    } catch (err) {
      bodyJsonError = err.message;
    }

    const url = new URL(req.url, `http://${host}`);
    const matched = url.pathname === hookPath;
    const signature = verifySignature(req.headers[SIGNATURE_HEADER], rawBody);

    let statusCode = matched ? 200 : 404;
    const headers = { 'Content-Type': 'application/json' };

    if (failStatus !== null && index <= failTimes) {
      statusCode = failStatus;
    } else if (redirectTarget !== null) {
      statusCode = redirectStatus;
      headers.Location = redirectTarget;
    }

    if (delayMs > 0) await new Promise((r) => setTimeout(r, delayMs));

    record({
      index,
      receivedAt: new Date().toISOString(),
      method: req.method,
      path: url.pathname,
      query: url.search,
      httpVersion: req.httpVersion,
      remoteAddress: req.socket.remoteAddress,
      userAgent: req.headers['user-agent'] || null,
      headers: req.headers,
      bodyBytes: receivedBytes,
      bodyText,
      bodyJson,
      bodyJsonError,
      bodyOverflow: overflow,
      bodySha256: createHash('sha256').update(rawBody).digest('hex'),
      route: matched ? 'hook' : 'other',
      signature,
      response: { statusCode, delayMs, location: headers.Location || null },
    });

    if (!quiet) {
      console.log(
        `#${index} ${req.method} ${url.pathname} → ${statusCode}` +
          ` · ${receivedBytes}B` +
          ` · sig=${signature.valid === null ? 'n/a' : signature.valid ? 'valid' : 'invalid'}` +
          ` · bodyKeys=${bodyJson && typeof bodyJson === 'object' ? Object.keys(bodyJson).join(',') : 'n/a'}`
      );
    }

    res.writeHead(statusCode, headers);
    res.end(JSON.stringify({ ok: statusCode < 400, index, receivedBytes }));
  });
});

server.on('error', (err) => {
  console.error(`🛑 假接收服务启动失败：${err.message}`);
  process.exit(2);
});

server.listen(port, host, () => {
  const actualPort = server.address().port;
  const url = `http://${host}:${actualPort}${hookPath}`;
  console.log(`[fake-webhook] listening on ${url}`);
  console.log(`[fake-webhook] log → ${logPath}`);
  console.log(
    `[fake-webhook] faults: failStatus=${failStatus ?? 'none'} failTimes=${failTimes === Infinity ? '∞' : failTimes}` +
      ` delay=${delayMs}ms redirect=${redirectTarget ?? 'none'} secret=${secret ? 'set' : 'unset'}`
  );
  console.log(`[fake-webhook] port=${actualPort}`);
});

function shutdown() {
  console.log(`\n[fake-webhook] 收到 ${received} 个请求，记录已写入 ${logPath}`);
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 500).unref();
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
