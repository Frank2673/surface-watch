/**
 * 安全响应头评分测试
 * 用「全部缺失」与「全部到位」两个极端，加上若干边界值，把评分规则钉死。
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { evaluate } from '../src/checks/headers.mjs';

const asset = { domain: 'example.com' };

function obs(headers, extra = {}) {
  return {
    url: 'https://example.com/',
    ok: true,
    error: null,
    status: 200,
    finalUrl: 'https://example.com/',
    headers,
    ms: 100,
    ...extra,
  };
}

const keys = (findings) => findings.map((f) => f.key);

test('安全头齐全时不产生任何发现', () => {
  const findings = evaluate(
    asset,
    obs({
      'strict-transport-security': 'max-age=31536000; includeSubDomains',
      'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
      'x-content-type-options': 'nosniff',
      'x-frame-options': 'DENY',
      'referrer-policy': 'strict-origin-when-cross-origin',
      'permissions-policy': 'geolocation=(), camera=()',
    })
  );
  assert.deepEqual(findings, []);
});

test('全部缺失时逐项报出', () => {
  const findings = evaluate(asset, obs({ 'content-type': 'text/html' }));
  const k = keys(findings);
  for (const expected of [
    'missing-hsts',
    'missing-csp',
    'missing-frame-protection',
    'missing-nosniff',
    'missing-referrer-policy',
    'missing-permissions-policy',
  ]) {
    assert.ok(k.includes(expected), `应包含 ${expected}`);
  }
});

test('每条发现都必须带证据、影响与修复建议', () => {
  const findings = evaluate(asset, obs({}));
  assert.ok(findings.length > 0);
  for (const f of findings) {
    assert.ok(f.title && f.title.length > 4, '标题不为空');
    assert.ok(f.evidence && f.evidence.length > 2, `${f.key} 缺证据`);
    assert.ok(f.impact && f.impact.length > 8, `${f.key} 缺影响说明`);
    assert.ok(f.remediation && f.remediation.length > 8, `${f.key} 缺修复建议`);
    assert.ok(f.id.includes(f.check) && f.id.includes(f.asset), '指纹包含检查项与资产');
  }
});

test('HSTS max-age 过短单独报出', () => {
  const findings = evaluate(asset, obs({ 'strict-transport-security': 'max-age=600' }));
  const k = keys(findings);
  assert.ok(k.includes('hsts-short-max-age'));
  assert.ok(!k.includes('missing-hsts'), '有 HSTS 就不该报缺失');
});

test('HSTS 缺少 includeSubDomains 会被提示', () => {
  const findings = evaluate(asset, obs({ 'strict-transport-security': 'max-age=31536000' }));
  assert.ok(keys(findings).includes('hsts-no-subdomains'));
});

test('CSP 中含 frame-ancestors 时不再报点击劫持', () => {
  const findings = evaluate(
    asset,
    obs({ 'content-security-policy': "default-src 'self'; frame-ancestors 'none'" })
  );
  assert.ok(!keys(findings).includes('missing-frame-protection'));
});

test('Server 头带版本号判为信息泄露，不带版本号则不报', () => {
  assert.ok(keys(evaluate(asset, obs({ server: 'nginx/1.18.0' }))).includes('server-version-disclosure'));
  assert.ok(!keys(evaluate(asset, obs({ server: 'cloudflare' }))).includes('server-version-disclosure'));
});

test('首页 5xx 报服务端错误', () => {
  const findings = evaluate(asset, obs({}, { status: 503 }));
  assert.ok(keys(findings).includes('server-error'));
});

test('最终跳转到明文 HTTP 时判为高危', () => {
  const findings = evaluate(asset, obs({}, { finalUrl: 'http://example.com/' }));
  const f = findings.find((x) => x.key === 'no-https-redirect');
  assert.ok(f);
  assert.equal(f.severity, 'high');
});

test('请求失败时给出信息级提示而不是崩溃', () => {
  const findings = evaluate(asset, { ok: false, error: 'TIMEOUT' });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, 'info');
  assert.match(findings[0].evidence, /TIMEOUT/);
});

test('未采集到数据时不产生任何断言（区别于"请求失败"）', () => {
  assert.deepEqual(evaluate(asset, null), []);
  assert.deepEqual(evaluate(asset, undefined), []);
});
