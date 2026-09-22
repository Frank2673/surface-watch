/**
 * DNS 检查测试：邮件伪造面（SPF/DMARC）与证书签发面（CAA）
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { evaluate } from '../src/checks/dns.mjs';

const asset = { domain: 'example.com' };

function obs(partial = {}) {
  return {
    domain: 'example.com',
    a: ['203.0.113.10'],
    aaaa: [],
    cname: [],
    ns: ['ns1.example.net'],
    mx: [],
    txt: [],
    dmarcTxt: [],
    caa: [],
    ...partial,
  };
}

const keys = (findings) => findings.map((f) => f.key);

test('无法解析时判为高危并短路返回', () => {
  const findings = evaluate(asset, obs({ a: [], aaaa: [], cname: [], ns: [] }));
  assert.equal(findings.length, 1);
  assert.equal(findings[0].key, 'unresolvable');
  assert.equal(findings[0].severity, 'high');
});

test('有 MX 但无 SPF → 中危', () => {
  const findings = evaluate(asset, obs({ mx: [{ priority: 10, exchange: 'mail.example.com' }] }));
  const f = findings.find((x) => x.key === 'missing-spf');
  assert.ok(f);
  assert.equal(f.severity, 'medium');
});

test('无 MX 时不报缺少 SPF（避免噪音）', () => {
  const findings = evaluate(asset, obs({ mx: [], txt: [] }));
  assert.ok(!keys(findings).includes('missing-spf'));
});

test('SPF 使用 +all → 高危', () => {
  const findings = evaluate(asset, obs({ txt: ['v=spf1 +all'] }));
  const f = findings.find((x) => x.key === 'spf-permissive');
  assert.ok(f);
  assert.equal(f.severity, 'high');
});

test('SPF 使用 ?all 同样判为宽松', () => {
  assert.ok(keys(evaluate(asset, obs({ txt: ['v=spf1 ?all'] }))).includes('spf-permissive'));
});

test('SPF 使用 -all 时不报', () => {
  const findings = evaluate(asset, obs({ txt: ['v=spf1 include:_spf.example.com -all'] }));
  assert.ok(!keys(findings).includes('spf-permissive'));
});

test('TXT 记录被拆成多段时能正确拼接识别', () => {
  /* node:dns 的 resolveTxt 返回字符串数组，collect 阶段已拍平，这里模拟拍平后的结果 */
  const findings = evaluate(asset, obs({ txt: ['v=spf1 include:_spf.google.com -all'] }));
  assert.ok(!keys(findings).includes('missing-spf'));
  assert.ok(!keys(findings).includes('spf-permissive'));
});

test('缺少 DMARC：有 MX 时中危，无 MX 时低危', () => {
  const withMx = evaluate(asset, obs({ mx: [{ priority: 10, exchange: 'm.example.com' }] }));
  assert.equal(withMx.find((x) => x.key === 'missing-dmarc').severity, 'medium');

  const noMx = evaluate(asset, obs({ mx: [] }));
  assert.equal(noMx.find((x) => x.key === 'missing-dmarc').severity, 'low');
});

test('DMARC 处于 p=none → 低危提示', () => {
  const findings = evaluate(asset, obs({ dmarcTxt: ['v=DMARC1; p=none; rua=mailto:a@example.com'] }));
  const f = findings.find((x) => x.key === 'dmarc-monitor-only');
  assert.ok(f);
  assert.equal(f.severity, 'low');
  assert.ok(!keys(findings).includes('missing-dmarc'));
});

test('DMARC 为 p=reject 时不报', () => {
  const findings = evaluate(asset, obs({ dmarcTxt: ['v=DMARC1; p=reject;'] }));
  assert.ok(!keys(findings).includes('missing-dmarc'));
  assert.ok(!keys(findings).includes('dmarc-monitor-only'));
});

test('缺少 CAA → 低危', () => {
  const findings = evaluate(asset, obs({ caa: [] }));
  const f = findings.find((x) => x.key === 'missing-caa');
  assert.ok(f);
  assert.equal(f.severity, 'low');
});

test('有 CAA 时不报', () => {
  const findings = evaluate(asset, obs({ caa: [{ critical: 0, issue: 'letsencrypt.org' }] }));
  assert.ok(!keys(findings).includes('missing-caa'));
});

test('未采集到数据时不产生任何断言（"未采集"≠"有问题"）', () => {
  assert.deepEqual(evaluate(asset, null), []);
  assert.deepEqual(evaluate(asset, undefined), []);
});
