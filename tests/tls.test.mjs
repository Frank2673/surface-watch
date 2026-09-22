/**
 * TLS 证书检查测试：到期阈值、协议版本、证书可信性
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { evaluate } from '../src/checks/tls.mjs';

const asset = { domain: 'example.com' };

function obs(partial = {}) {
  return {
    reachable: true,
    protocol: 'TLSv1.3',
    cipher: 'TLS_AES_256_GCM_SHA384',
    authorized: true,
    authorizationError: null,
    subject: 'example.com',
    issuer: "Let's Encrypt",
    validFrom: 'Sep  1 00:00:00 2026 GMT',
    validTo: 'Dec  1 00:00:00 2026 GMT',
    daysRemaining: 70,
    altNames: 'DNS:example.com',
    ...partial,
  };
}

const keys = (findings) => findings.map((f) => f.key);

test('健康证书不产生发现', () => {
  assert.deepEqual(evaluate(asset, obs()), []);
});

test('无法建立连接 → 信息级提示', () => {
  const findings = evaluate(asset, { reachable: false, error: 'ECONNREFUSED' });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, 'info');
  assert.match(findings[0].evidence, /ECONNREFUSED/);
});

test('证书已过期 → 严重', () => {
  const findings = evaluate(asset, obs({ daysRemaining: -3 }));
  const f = findings.find((x) => x.key === 'cert-expired');
  assert.ok(f);
  assert.equal(f.severity, 'critical');
});

test('14 天内到期 → 高危', () => {
  assert.equal(evaluate(asset, obs({ daysRemaining: 9 }))[0].severity, 'high');
  assert.equal(evaluate(asset, obs({ daysRemaining: 9 }))[0].key, 'cert-expiring-urgent');
});

test('30 天内到期 → 中危', () => {
  const findings = evaluate(asset, obs({ daysRemaining: 21 }));
  const f = findings.find((x) => x.key === 'cert-expiring');
  assert.ok(f);
  assert.equal(f.severity, 'medium');
});

test('阈值边界：14 天与 30 天', () => {
  assert.ok(keys(evaluate(asset, obs({ daysRemaining: 14 }))).includes('cert-expiring-urgent'));
  assert.ok(keys(evaluate(asset, obs({ daysRemaining: 15 }))).includes('cert-expiring'));
  assert.ok(keys(evaluate(asset, obs({ daysRemaining: 30 }))).includes('cert-expiring'));
  assert.deepEqual(evaluate(asset, obs({ daysRemaining: 31 })), []);
});

test('TLS 1.0 / 1.1 判为过时协议（高危）', () => {
  for (const protocol of ['TLSv1', 'TLSv1.1']) {
    const f = evaluate(asset, obs({ protocol })).find((x) => x.key === 'weak-protocol');
    assert.ok(f, `${protocol} 应被标记`);
    assert.equal(f.severity, 'high');
  }
  assert.ok(!keys(evaluate(asset, obs({ protocol: 'TLSv1.2' }))).includes('weak-protocol'));
});

test('证书不受信任 → 高危，并在证据中给出原因', () => {
  const findings = evaluate(
    asset,
    obs({ authorized: false, authorizationError: 'CERT_HAS_EXPIRED' })
  );
  const f = findings.find((x) => x.key === 'cert-untrusted');
  assert.ok(f);
  assert.equal(f.severity, 'high');
  assert.match(f.evidence, /CERT_HAS_EXPIRED/);
});

test('未采集到数据时不崩溃', () => {
  assert.deepEqual(evaluate(asset, null), []);
  assert.deepEqual(evaluate(asset, undefined), []);
});
