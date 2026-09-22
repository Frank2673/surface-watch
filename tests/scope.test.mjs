/**
 * Scope Gate 测试 —— 这是本工具最该被测死的部分
 * 因为一旦范围校验失效，工具就从"自查工具"变成了"越权扫描器"
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, mkdtempSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { checkHost, assertHostInScope, loadScope, ScopeError } from '../src/lib/scope.mjs';

const scope = {
  owner: 'tester',
  authorization: { statement: '我拥有这些资产' },
  assets: [{ domain: 'example.com', tags: [] }],
  rate_limit: { concurrency: 4, delayMs: 0, timeoutMs: 5000 },
  checks: { dns: true, tls: true, headers: true, ct_logs: false, paths: { enabled: false, list: [] } },
};

test('允许范围内的域名', () => {
  assert.equal(checkHost('example.com', scope).allowed, true);
});

test('允许范围内的子域', () => {
  assert.equal(checkHost('api.example.com', scope).allowed, true);
  assert.equal(checkHost('a.b.example.com', scope).allowed, true);
});

test('允许大小写与末尾点号差异', () => {
  assert.equal(checkHost('EXAMPLE.COM', scope).allowed, true);
  assert.equal(checkHost('example.com.', scope).allowed, true);
});

test('拒绝范围外的域名', () => {
  const r = checkHost('evil.com', scope);
  assert.equal(r.allowed, false);
  assert.match(r.reason, /不在授权范围内/);
});

test('拒绝形似域名（防止后缀混淆）', () => {
  /* notexample.com 以 example.com 结尾，但不能被当作子域放行 */
  assert.equal(checkHost('notexample.com', scope).allowed, false);
  assert.equal(checkHost('example.com.evil.net', scope).allowed, false);
});

test('拒绝内网与回环地址', () => {
  const forbidden = [
    'localhost',
    '127.0.0.1',
    '10.0.0.5',
    '192.168.1.1',
    '172.16.0.1',
    '169.254.169.254', // 云元数据
    '100.64.0.1',
    '::1',
    'fd00::1',
    'fe80::1',
    'metadata.google.internal',
  ];
  for (const host of forbidden) {
    const r = checkHost(host, scope);
    assert.equal(r.allowed, false, `${host} 应被拒绝`);
    assert.match(r.reason, /禁止规则/, `${host} 的拒绝原因应指出禁止规则`);
  }
});

test('即使把内网地址写进范围本身也要被拒绝', () => {
  const r = checkHost('10.0.0.5', { assets: [{ domain: '10.0.0.5' }] });
  assert.equal(r.allowed, false);
});

test('assertHostInScope 越界时抛 ScopeError', () => {
  assert.throws(() => assertHostInScope('evil.com', scope), ScopeError);
  assert.doesNotThrow(() => assertHostInScope('example.com', scope));
});

test('loadScope 缺少授权声明时拒绝加载', () => {
  const dir = mkdtempSync(join(tmpdir(), 'sw-'));
  const file = join(dir, 'scope.json');
  writeFileSync(
    file,
    JSON.stringify({ assets: [{ domain: 'example.com' }], authorization: { statement: '' } })
  );
  assert.throws(() => loadScope(file), ScopeError);
});

test('loadScope 拒绝空 assets', () => {
  const dir = mkdtempSync(join(tmpdir(), 'sw-'));
  const file = join(dir, 'scope.json');
  writeFileSync(file, JSON.stringify({ assets: [], authorization: { statement: '我拥有或已获授权测试这些资产' } }));
  assert.throws(() => loadScope(file), /assets/);
});

test('loadScope 拒绝把内网地址写进范围', () => {
  const dir = mkdtempSync(join(tmpdir(), 'sw-'));
  const file = join(dir, 'scope.json');
  writeFileSync(
    file,
    JSON.stringify({
      assets: [{ domain: '169.254.169.254' }],
      authorization: { statement: '我拥有或已获授权测试这些资产' },
    })
  );
  assert.throws(() => loadScope(file), ScopeError);
});

test('默认配置下主动路径探测是关闭的', () => {
  const dir = mkdtempSync(join(tmpdir(), 'sw-'));
  const file = join(dir, 'scope.json');
  writeFileSync(
    file,
    JSON.stringify({
      assets: [{ domain: 'example.com' }],
      authorization: { statement: '我拥有或已获授权测试这些资产' },
    })
  );
  const loaded = loadScope(file);
  assert.equal(loaded.checks.paths.enabled, false);
  assert.equal(loaded.checks.ct_logs, false);
  assert.equal(loaded.checks.dns, true);
});

test('并发与超时参数被限制在安全区间', () => {
  const dir = mkdtempSync(join(tmpdir(), 'sw-'));
  const file = join(dir, 'scope.json');
  writeFileSync(
    file,
    JSON.stringify({
      assets: [{ domain: 'example.com' }],
      authorization: { statement: '我拥有或已获授权测试这些资产' },
      rate_limit: { concurrency: 9999, delay_ms: -5, timeout_ms: 999999 },
    })
  );
  const loaded = loadScope(file);
  assert.equal(loaded.rate_limit.concurrency, 8);
  assert.equal(loaded.rate_limit.delayMs, 0);
  assert.equal(loaded.rate_limit.timeoutMs, 30000);
});
