/**
 * HTTP 客户端测试（真实起本地服务器，不是 mock）
 *
 * 重点覆盖一个曾经真实出现过的严重 bug：
 * 对端在响应中途断开时，客户端把残缺内容当作成功返回，
 * 导致靠响应内容判断的检查（如 .git/config 特征匹配）静默漏报。
 * 现在必须把「提前断开」识别为网络错误并重试。
 */

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { request } from '../src/lib/http.mjs';

let server;
let base;

before(async () => {
  server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://localhost');

    switch (url.pathname) {
      case '/ok':
        res.writeHead(200, { 'content-type': 'text/plain', 'content-length': '5' });
        res.end('hello');
        return;

      case '/truncated':
        /* 声明 1000 字节，实际只发 100 字节然后强行断开 —— 模拟连接被中断 */
        res.writeHead(200, { 'content-type': 'text/plain', 'content-length': '1000' });
        res.write('x'.repeat(100));
        res.socket.destroy();
        return;

      case '/short-body':
        /* 声明 1000 字节，但正常结束（只有 100 字节）—— 声明与实际不符 */
        res.writeHead(200, { 'content-type': 'text/plain', 'content-length': '1000' });
        res.end('x'.repeat(100));
        return;

      case '/redirect':
        res.writeHead(302, { location: '/ok' });
        res.end();
        return;

      case '/redirect-loop':
        res.writeHead(302, { location: '/redirect-loop' });
        res.end();
        return;

      case '/slow':
        /* 永不响应，用于验证超时 */
        return;

      case '/server-error':
        res.writeHead(503, { 'content-type': 'text/plain' });
        res.end('unavailable');
        return;

      case '/headers':
        res.writeHead(200, {
          'content-type': 'text/html',
          'strict-transport-security': 'max-age=31536000',
          'x-test': 'yes',
        });
        res.end('<html></html>');
        return;

      default:
        res.writeHead(404);
        res.end('not found');
    }
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  base = `http://127.0.0.1:${server.address().port}`;
});

after(() => {
  server.close();
});

test('正常响应返回完整内容', async () => {
  const r = await request(`${base}/ok`);
  assert.equal(r.ok, true);
  assert.equal(r.status, 200);
  assert.equal(r.body, 'hello');
  assert.equal(r.truncated, false);
});

test('响应头被完整保留', async () => {
  const r = await request(`${base}/headers`);
  assert.equal(r.headers['strict-transport-security'], 'max-age=31536000');
  assert.equal(r.headers['x-test'], 'yes');
});

test('提前断开的响应必须判为失败，不能静默返回残缺内容', async () => {
  const r = await request(`${base}/truncated`, { retries: 1, timeoutMs: 5000 });
  assert.equal(r.ok, false, '残缺响应不能算成功');
  assert.ok(
    ['INCOMPLETE_RESPONSE', 'ECONNRESET', 'ECONNABORTED'].includes(r.error),
    `错误应属网络中断类，实际为 ${r.error}`
  );
  assert.equal(r.status, null);
});

test('声明长度与实际不符（正常结束）同样判为失败', async () => {
  const r = await request(`${base}/short-body`, { retries: 1, timeoutMs: 5000 });
  assert.equal(r.ok, false, '内容长度不符不能算成功');
});

test('残缺响应会被重试，最终返回失败而不是半截数据', async () => {
  /* 这批路由永远残缺，验证重试后不会把最后一次的残缺内容当成功 */
  const r = await request(`${base}/truncated`, { retries: 2, timeoutMs: 5000 });
  assert.equal(r.ok, false);
  assert.equal(r.body, '');
});

test('重定向会被跟随', async () => {
  const r = await request(`${base}/redirect`);
  assert.equal(r.ok, true);
  assert.equal(r.status, 200);
  assert.equal(r.body, 'hello');
  assert.equal(r.finalUrl, `${base}/ok`);
});

test('重定向循环会被截断并报错', async () => {
  const r = await request(`${base}/redirect-loop`, { retries: 0 });
  assert.equal(r.ok, false);
  assert.equal(r.error, 'TOO_MANY_REDIRECTS');
});

test('超时会被识别并重试', async () => {
  const r = await request(`${base}/slow`, { timeoutMs: 300, retries: 1 });
  assert.equal(r.ok, false);
  assert.equal(r.error, 'TIMEOUT');
});

test('5xx 属于有效响应（由检查逻辑判定严重度，而不是客户端报错）', async () => {
  const r = await request(`${base}/server-error`);
  assert.equal(r.ok, true);
  assert.equal(r.status, 503);
});

test('连接被拒绝时返回错误而不是抛异常', async () => {
  const r = await request('http://127.0.0.1:1/', { timeoutMs: 1000, retries: 0 });
  assert.equal(r.ok, false);
  assert.ok(r.error);
});
