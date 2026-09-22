/**
 * 敏感路径探测测试
 *
 * 重点验证"宁可漏报不可误报"的两道闸：
 *   1. 软 404 排除（自定义错误页返回 200 不算暴露）
 *   2. 内容特征确认（.git/config 必须真的像 git 配置）
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { evaluate } from '../src/checks/paths.mjs';

const asset = { domain: 'example.com' };

const baseline = { status: 404, length: 153, contentType: 'text/html' };

function obs(results) {
  return { baseline, results };
}

const keys = (findings) => findings.map((f) => f.key);

test('软 404（自定义错误页返回 200 且长度接近基线）不报', () => {
  const findings = evaluate(
    asset,
    obs({
      '/.env': {
        ok: true,
        status: 200,
        length: 160,
        headers: { 'content-type': 'text/html' },
        body: '<html><body>页面不存在</body></html>',
      },
    })
  );
  assert.deepEqual(findings, []);
});

test('.env 含真实键值对 → 严重', () => {
  const findings = evaluate(
    asset,
    obs({
      '/.env': {
        ok: true,
        status: 200,
        length: 96,
        headers: { 'content-type': 'text/plain' },
        body: 'APP_ENV=production\nDB_PASSWORD=REDACTED\n',
      },
    })
  );
  const f = findings.find((x) => x.key === 'exposed-path:/.env');
  assert.ok(f);
  assert.equal(f.severity, 'critical');
});

test('.env 返回 HTML 内容时不报（避免把错误页误判）', () => {
  const findings = evaluate(
    asset,
    obs({
      '/.env': {
        ok: true,
        status: 200,
        length: 900,
        headers: { 'content-type': 'text/html' },
        body: '<html><body><h1>Welcome</h1></body></html>',
      },
    })
  );
  assert.deepEqual(findings, []);
});

test('.git/config 内容命中特征 → 高危', () => {
  const findings = evaluate(
    asset,
    obs({
      '/.git/config': {
        ok: true,
        status: 200,
        length: 132,
        headers: { 'content-type': 'text/plain' },
        body: '[core]\n\trepositoryformatversion = 0\n\tbare = false\n',
      },
    })
  );
  const f = findings.find((x) => x.key === 'exposed-path:/.git/config');
  assert.ok(f);
  assert.equal(f.severity, 'high');
});

test('.git/config 只返回普通文本但无特征 → 不报', () => {
  const findings = evaluate(
    asset,
    obs({
      '/.git/config': {
        ok: true,
        status: 200,
        length: 500,
        headers: { 'content-type': 'text/plain' },
        body: 'this is just a plain text file, nothing to see here',
      },
    })
  );
  assert.deepEqual(findings, []);
});

test('404 与 403 一律不报', () => {
  const findings = evaluate(
    asset,
    obs({
      '/.env': { ok: true, status: 404, length: 153, headers: {}, body: 'Not Found' },
      '/server-status': { ok: true, status: 403, length: 289, headers: {}, body: 'Forbidden' },
    })
  );
  assert.deepEqual(findings, []);
});

test('特征库之外的路径若明显偏离基线，会被标为可疑路径', () => {
  const findings = evaluate(
    asset,
    obs({
      '/db-dump.sql': {
        ok: true,
        status: 200,
        length: 8000,
        headers: { 'content-type': 'application/octet-stream' },
        body: 'INSERT INTO users VALUES (...);',
      },
    })
  );
  const f = findings.find((x) => x.key === 'exposed-path:/db-dump.sql');
  assert.ok(f, '应报为可疑路径');
  assert.equal(f.severity, 'medium');
  assert.match(f.title, /可疑路径/);
});

test('特征库中的路径若内容不符特征 → 按"宁可漏报"原则不报', () => {
  /* /phpinfo.php 在特征库中，要求内容必须出现 phpinfo() 才算确认。
     这是刻意的假阳性防护：站点对任何路径都返回 200 时，不应刷出一堆误报。 */
  const findings = evaluate(
    asset,
    obs({
      '/phpinfo.php': {
        ok: true,
        status: 200,
        length: 8000,
        headers: { 'content-type': 'text/html' },
        body: '<html><body>some large but unrelated page</body></html>',
      },
    })
  );
  assert.deepEqual(findings, []);
});

test('请求失败时跳过而不是崩溃', () => {
  const findings = evaluate(
    asset,
    obs({ '/.env': { ok: false, error: 'TIMEOUT', status: null } })
  );
  assert.deepEqual(findings, []);
});

test('缺少观测数据时安全返回', () => {
  assert.deepEqual(evaluate(asset, null), []);
  assert.deepEqual(evaluate(asset, {}), []);
});
