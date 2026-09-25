/**
 * 单一变化源测试
 *
 * 为什么单独一个测试文件：`changeset.mjs` 是"什么算变化"的**唯一判据**，
 * CLI 门禁 / Webhook 触发 / CI 的 Issue 判定都消费它。因此这里逐条锁死语义：
 *   1. 三种集合（新增 / 已修复 / 持续）与 diff.mjs 的结果**同一份**，不是各自实现
 *   2. `changed`（指纹未变但 severity/evidence 变了）是信息项，**绝不参与触发**
 *   3. `ignored` 只在限定扫描资产时出现，计数可用、条目摘要与集合差一致
 *   4. 标量摘要（供 findings.json / CI 读）的值与集合长度一致
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createFinding } from '../src/lib/findings.mjs';
import { diffFindings } from '../src/lib/diff.mjs';
import {
  TRIGGER_FIELD,
  buildChangeset,
  changesetFromDiff,
  detectChangedFindings,
  hasAddedAtOrAbove,
  summarizeChangeset,
  triggerFindings,
} from '../src/lib/changeset.mjs';

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

/* ---------------- 1. 集合语义与 diff.mjs 一致 ---------------- */

test('三种集合与 diff.mjs 的结果逐条一致（同一份判据，不是第二次实现）', () => {
  const hsts = makeFinding({ firstSeen: '2026-09-01T00:00:00.000Z' });
  const csp = makeFinding({ key: 'missing-csp' });
  const fixed = makeFinding({ key: 'missing-nosniff' });
  const brandNew = makeFinding({ key: 'server-header', severity: 'low' });

  const raw = diffFindings([hsts, csp, brandNew], [hsts, csp, fixed], { assets: ['example.com'] });
  const cs = buildChangeset({ findings: [hsts, csp, brandNew], baseline: [hsts, csp, fixed], assets: ['example.com'] });

  assert.deepEqual(cs.added.map((f) => f.id), raw.added.map((f) => f.id));
  assert.deepEqual(cs.resolved.map((f) => f.id), raw.resolved.map((f) => f.id));
  assert.deepEqual(cs.persistent.map((f) => f.id), raw.persistent.map((f) => f.id));
  assert.equal(cs.added.length, 1);
  assert.equal(cs.resolved.length, 1);
  assert.equal(cs.persistent.length, 2);
});

test('触发集合只有一个：changeset.added', () => {
  const f = makeFinding({ severity: 'high' });
  const cs = buildChangeset({ findings: [f], baseline: [] });
  assert.equal(TRIGGER_FIELD, 'added');
  assert.deepEqual(triggerFindings(cs), cs.added);
  assert.equal(triggerFindings({}).length, 0, '空变化集不能抛错，只能返回空集合');
});

/* ---------------- 2. changed 是信息项，不参与触发 ---------------- */

test('指纹未变但严重度升级 → 记为 changed，且不进入 added', () => {
  const before = makeFinding({ severity: 'low' });
  const after = makeFinding({ severity: 'high' });
  assert.equal(before.id, after.id, '指纹应保持稳定');

  const cs = buildChangeset({ findings: [after], baseline: [before], assets: ['example.com'] });
  assert.equal(cs.added.length, 0, '内容变化不是"新增"');
  assert.equal(cs.changed.length, 1);
  assert.deepEqual(cs.changed[0].changedFields, ['severity']);
  assert.equal(cs.changed[0].previousSeverity, 'low');
});

test('指纹未变但证据变化 → 记为 changed(evidence)，且不进入 added', () => {
  const before = makeFinding({ evidence: '证书 30 天后过期' });
  const after = makeFinding({ evidence: '证书 7 天后过期' });

  const cs = buildChangeset({ findings: [after], baseline: [before], assets: ['example.com'] });
  assert.equal(cs.added.length, 0);
  assert.deepEqual(cs.changed[0].changedFields, ['evidence']);
});

test('detectChangedFindings 对裸 diff 仍然可用（公开面不变）', () => {
  const before = makeFinding({ severity: 'info' });
  const after = makeFinding({ severity: 'medium' });
  const changed = detectChangedFindings({ persistent: [after] }, [before]);
  assert.equal(changed.length, 1);
  assert.deepEqual(changed[0].changedFields, ['severity']);
  assert.equal(detectChangedFindings({ persistent: [after] }, []).length, 0);
});

/* ---------------- 3. ignored：只在限定扫描资产时出现 ---------------- */

test('限定扫描资产时：未扫描资产的基线条目进 ignored（计数 + 摘要）', () => {
  const scanned = makeFinding({ asset: 'a.example.com' });
  const other = makeFinding({ asset: 'b.example.com' });
  const baseline = [scanned, other];

  const limited = buildChangeset({ findings: [scanned], baseline, assets: ['a.example.com'] });
  assert.equal(limited.ignored.count, 1);
  assert.equal(limited.ignored.entries.length, 1);
  assert.equal(limited.ignored.entries[0].fingerprint, other.id);
  assert.equal(limited.ignored.entries[0].asset, 'b.example.com');
  /* 被忽略的条目绝不能同时被算成"已修复" */
  assert.equal(limited.resolved.length, 0);

  const full = buildChangeset({ findings: [scanned], baseline, assets: ['a.example.com', 'b.example.com'] });
  assert.equal(full.ignored.count, 0);
  assert.deepEqual(full.ignored.entries, []);
  assert.equal(full.resolved.length, 1, '全量扫描时 b 的基线条目才是真的"已修复"');
});

test('未传 assets 时不做过滤，ignored 为 0', () => {
  const cs = buildChangeset({ findings: [], baseline: [makeFinding()] });
  assert.equal(cs.ignored.count, 0);
  assert.equal(cs.resolved.length, 1);
});

/* ---------------- 4. 基线建立与标量摘要 ---------------- */

test('基线缺失（空数组 / 非数组）→ baselineEstablished=true', () => {
  assert.equal(buildChangeset({ findings: [makeFinding()], baseline: [] }).baselineEstablished, true);
  assert.equal(buildChangeset({ findings: [], baseline: null }).baselineEstablished, true);
  assert.equal(buildChangeset({ findings: [], baseline: [makeFinding()] }).baselineEstablished, false);
});

test('标量摘要与集合长度一致，且给出下游该读哪个字段', () => {
  const added = makeFinding({ key: 'new-one', severity: 'high' });
  const cs = buildChangeset({ findings: [added], baseline: [makeFinding()], assets: ['example.com'] });
  const s = summarizeChangeset(cs);

  assert.equal(s.triggerField, 'added');
  assert.equal(s.addedCount, cs.added.length);
  assert.equal(s.resolvedCount, cs.resolved.length);
  assert.equal(s.persistentCount, cs.persistent.length);
  assert.equal(s.changedCount, cs.changed.length);
  assert.equal(s.ignoredCount, cs.ignored.count);
  assert.equal(s.hasAdded, true);
  assert.equal(s.baselineEstablished, false);
});

test('changesetFromDiff 规范化裸 diff：added 决定 hasAdded，缺失字段按 0 处理', () => {
  const f = makeFinding({ severity: 'critical' });
  const cs = changesetFromDiff({ added: [f] });
  assert.equal(cs.added.length, 1);
  assert.deepEqual(cs.resolved, []);
  assert.deepEqual(cs.persistent, []);
  assert.equal(cs.ignored.count, 0);
  assert.equal(summarizeChangeset(cs).hasAdded, true);
  assert.equal(summarizeChangeset(changesetFromDiff({})).hasAdded, false);
});

/* ---------------- 5. 门禁判定 ---------------- */

test('门禁判定只看 added，且严重度比较与 diff.mjs 同源', () => {
  const high = createFinding({
    asset: 'example.com',
    check: 'paths',
    key: 'exposed-path:/.env',
    severity: 'high',
    title: '.env 可下载',
    evidence: 'e',
    impact: 'i',
    remediation: 'r',
  });

  assert.equal(hasAddedAtOrAbove(changesetFromDiff({ added: [high] }), 'high'), true);
  assert.equal(hasAddedAtOrAbove(changesetFromDiff({ added: [high] }), 'critical'), false);
  assert.equal(hasAddedAtOrAbove(changesetFromDiff({ added: [] }), 'info'), false);
  /* persistent 里有 high 不算"新增达标" */
  assert.equal(hasAddedAtOrAbove(changesetFromDiff({ persistent: [high] }), 'high'), false);
});
