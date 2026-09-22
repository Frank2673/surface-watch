/**
 * 基线差异测试
 *
 * 差异是本工具的核心价值，因此这里重点验证两件事：
 *   1. 指纹稳定性：证据文本变化不能产生"假新增"
 *   2. 首次运行不刷屏：没有基线时不应把所有发现当作告警
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createFinding, fingerprint, summarize, sortFindings } from '../src/lib/findings.mjs';
import {
  diffFindings,
  hasAddedAtOrAbove,
  isBaselineEstablishment,
} from '../src/lib/diff.mjs';

function makeFinding(overrides = {}) {
  return createFinding({
    asset: 'example.com',
    check: 'headers',
    key: 'missing-hsts',
    severity: 'medium',
    title: '缺少 HSTS 响应头',
    evidence: '原始证据',
    impact: '影响说明足够长',
    remediation: '修复建议足够长',
    ...overrides,
  });
}

test('指纹只由 资产+检查项+键 决定，不含证据', () => {
  const a = makeFinding({ evidence: '第一次的证据 长度 100' });
  const b = makeFinding({ evidence: '第二次的证据完全变了 长度 9000' });
  assert.equal(fingerprint(a), fingerprint(b));
  assert.equal(a.id, b.id);
});

test('不同资产/检查项/键产生不同指纹', () => {
  assert.notEqual(makeFinding().id, makeFinding({ asset: 'other.com' }).id);
  assert.notEqual(makeFinding().id, makeFinding({ check: 'tls' }).id);
  assert.notEqual(makeFinding().id, makeFinding({ key: 'missing-csp' }).id);
});

test('首次运行：无基线时所有发现都是"新增"但会被识别为建立基线', () => {
  const current = [makeFinding(), makeFinding({ key: 'missing-csp' })];
  const diff = diffFindings(current, []);
  assert.equal(diff.added.length, 2);
  assert.equal(diff.resolved.length, 0);
  assert.equal(isBaselineEstablishment([]), true);
  assert.equal(isBaselineEstablishment([makeFinding()]), false);
});

test('识别新增 / 已修复 / 持续存在', () => {
  const hsts = makeFinding({ firstSeen: '2026-09-01T00:00:00.000Z' });
  const csp = makeFinding({ key: 'missing-csp' });
  const tlsIssue = createFinding({
    asset: 'example.com',
    check: 'tls',
    key: 'cert-expiring',
    severity: 'medium',
    title: '证书即将过期',
    evidence: 'ev',
    impact: 'impact',
    remediation: 'fix',
  });

  const diff = diffFindings([hsts, csp], [hsts, tlsIssue]);

  assert.deepEqual(diff.added.map((f) => f.key), ['missing-csp']);
  assert.deepEqual(diff.resolved.map((f) => f.key), ['cert-expiring']);
  assert.deepEqual(diff.persistent.map((f) => f.key), ['missing-hsts']);
});

test('持续存在的项会继承首次发现时间（用于显示"挂了多久"）', () => {
  const baselineFinding = makeFinding({ firstSeen: '2026-08-01T00:00:00.000Z' });
  const currentFinding = makeFinding(); // 本次运行没有 firstSeen
  const diff = diffFindings([currentFinding], [baselineFinding]);
  assert.equal(diff.persistent[0].firstSeen, '2026-08-01T00:00:00.000Z');
});

test('证据变化不会造成假新增', () => {
  const baseline = [makeFinding({ evidence: '旧证据' })];
  const current = [makeFinding({ evidence: '新证据（响应头顺序变了）' })];
  const diff = diffFindings(current, baseline);
  assert.equal(diff.added.length, 0);
  assert.equal(diff.persistent.length, 1);
});

test('门禁判定：按严重度阈值触发', () => {
  const high = createFinding({
    asset: 'example.com',
    check: 'tls',
    key: 'cert-expired',
    severity: 'critical',
    title: '证书过期',
    evidence: 'e',
    impact: 'i',
    remediation: 'r',
  });
  const low = createFinding({
    asset: 'example.com',
    check: 'dns',
    key: 'missing-caa',
    severity: 'low',
    title: '缺少 CAA',
    evidence: 'e',
    impact: 'i',
    remediation: 'r',
  });

  const diffHigh = diffFindings([high], []);
  assert.equal(hasAddedAtOrAbove(diffHigh, 'high'), true);
  assert.equal(hasAddedAtOrAbove(diffHigh, 'critical'), true);
  assert.equal(hasAddedAtOrAbove(diffHigh, 'low'), true);

  const diffLow = diffFindings([low], []);
  assert.equal(hasAddedAtOrAbove(diffLow, 'high'), false);
  assert.equal(hasAddedAtOrAbove(diffLow, 'low'), true);
});

test('已修复的项不参与门禁（修复不该被拦）', () => {
  const fixed = createFinding({
    asset: 'example.com',
    check: 'tls',
    key: 'cert-expired',
    severity: 'critical',
    title: '证书过期',
    evidence: 'e',
    impact: 'i',
    remediation: 'r',
  });
  const diff = diffFindings([], [fixed]);
  assert.equal(diff.resolved.length, 1);
  assert.equal(hasAddedAtOrAbove(diff, 'high'), false);
});

test('严重度统计与最高级别', () => {
  const list = [
    makeFinding({ severity: 'low' }),
    makeFinding({ key: 'a', severity: 'high' }),
    makeFinding({ key: 'b', severity: 'high' }),
  ];
  const s = summarize(list);
  assert.equal(s.total, 3);
  assert.equal(s.counts.high, 2);
  assert.equal(s.counts.low, 1);
  assert.equal(s.counts.critical, 0);
  assert.equal(s.highest, 'high');
});

test('排序：严重度降序优先，同级按指纹稳定排序', () => {
  const list = sortFindings([
    makeFinding({ key: 'z-low', severity: 'low' }),
    makeFinding({ key: 'a-high', severity: 'high' }),
    makeFinding({ key: 'b-info', severity: 'info' }),
  ]);
  assert.deepEqual(list.map((f) => f.severity), ['high', 'low', 'info']);
});

test('部分扫描时，未扫描资产的基线发现不会被误判为「已修复」', () => {
  /* 真实场景：范围里有 3 个域名，本次只用 --asset 扫了其中之一。
     若不做资产过滤，其余两个域名的历史发现会全部变成"已修复"，刷一屏假警报。 */
  const scannedFinding = makeFinding({ asset: 'a.example.com' });
  const otherFinding = makeFinding({ asset: 'b.example.com' });
  const baseline = [{ ...scannedFinding, firstSeen: '2026-09-01T00:00:00.000Z' }, otherFinding];

  const diff = diffFindings([scannedFinding], baseline, { assets: ['a.example.com'] });

  assert.equal(diff.resolved.length, 0, '未扫描资产的发现不应算已修复');
  assert.equal(diff.persistent.length, 1);
  assert.equal(diff.ignoredCount, 1, '被忽略的基线条目数应透明可见');
});

test('未传 assets 时保持向后兼容（全量比对）', () => {
  const a = makeFinding({ asset: 'a.example.com' });
  const b = makeFinding({ asset: 'b.example.com' });
  const diff = diffFindings([a], [a, b]);
  assert.equal(diff.resolved.length, 1);
  assert.equal(diff.ignoredCount, 0);
});
