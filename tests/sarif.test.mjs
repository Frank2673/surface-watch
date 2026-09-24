/**
 * SARIF 输出测试
 *
 * SARIF 是给机器消费的格式：结构错一个字段，GitHub 会直接拒绝上传。
 * 所以这里把「GitHub 的最低要求」逐条钉死，避免在 CI 里才发现问题。
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { toSarif, validateSarif } from '../src/lib/sarif.mjs';
import { createFinding } from '../src/lib/findings.mjs';

function finding(overrides = {}) {
  return createFinding({
    asset: 'example.com',
    check: 'headers',
    key: 'missing-hsts',
    severity: 'medium',
    title: '缺少 HSTS 响应头',
    evidence: '响应头中未发现 strict-transport-security',
    impact: '存在被降级劫持的窗口',
    remediation: '添加 Strict-Transport-Security 响应头',
    ...overrides,
  });
}

const meta = { version: '0.1.0', startedAt: '2026-09-24T00:00:00.000Z', durationMs: 1234 };

test('生成的 SARIF 通过自校验', () => {
  const sarif = toSarif({ findings: [finding()], scannedAssets: ['example.com'], meta });
  const check = validateSarif(sarif);
  assert.equal(check.ok, true, `校验问题：${check.problems.join('; ')}`);
});

test('顶层版本与 schema 正确', () => {
  const sarif = toSarif({ findings: [], scannedAssets: [], meta });
  assert.equal(sarif.version, '2.1.0');
  assert.match(sarif.$schema, /sarif-2\.1\.0/);
  assert.equal(sarif.runs.length, 1);
});

test('工具信息包含名称与版本（GitHub 依赖它们归类告警）', () => {
  const sarif = toSarif({ findings: [finding()], meta });
  const driver = sarif.runs[0].tool.driver;
  assert.equal(driver.name, 'surface-watch');
  assert.equal(driver.version, '0.1.0');
  assert.ok(driver.informationUri.startsWith('https://'));
});

test('严重度映射到 SARIF level 与 security-severity', () => {
  const cases = [
    ['critical', 'error', '9.5'],
    ['high', 'error', '8.0'],
    ['medium', 'warning', '5.5'],
    ['low', 'note', '3.0'],
    ['info', 'note', '1.0'],
  ];

  for (const [severity, level, score] of cases) {
    const sarif = toSarif({ findings: [finding({ severity })], meta });
    const result = sarif.runs[0].results[0];
    const rule = sarif.runs[0].tool.driver.rules[0];
    assert.equal(result.level, level, `${severity} 应映射为 ${level}`);
    assert.equal(rule.properties['security-severity'], score, `${severity} 的 security-severity 应为 ${score}`);
  }
});

test('同一规则的多个发现只声明一条 rule（避免体积膨胀）', () => {
  const sarif = toSarif({
    findings: [
      finding({ asset: 'a.com' }),
      finding({ asset: 'b.com' }),
      finding({ asset: 'c.com' }),
    ],
    meta,
  });
  assert.equal(sarif.runs[0].tool.driver.rules.length, 1);
  assert.equal(sarif.runs[0].results.length, 3);
});

test('不同检查项的发现各自成规则', () => {
  const sarif = toSarif({
    findings: [
      finding({ check: 'headers', key: 'missing-hsts' }),
      finding({ check: 'tls', key: 'cert-expiring' }),
      finding({ check: 'dns', key: 'missing-dmarc' }),
    ],
    meta,
  });
  const ids = sarif.runs[0].tool.driver.rules.map((r) => r.id).sort();
  assert.deepEqual(ids, ['dns:missing-dmarc', 'headers:missing-hsts', 'tls:cert-expiring']);
});

test('每条 result 的 ruleId 都能在 rules 中找到（GitHub 的硬性要求）', () => {
  const sarif = toSarif({
    findings: [finding(), finding({ check: 'tls', key: 'cert-expired', severity: 'critical' })],
    meta,
  });
  const check = validateSarif(sarif);
  assert.equal(check.ok, true);
});

test('partialFingerprints 使用与内部差异比对相同的指纹（保证告警稳定）', () => {
  const f = finding();
  const sarif = toSarif({ findings: [f], meta });
  assert.equal(sarif.runs[0].results[0].partialFingerprints.surfaceWatchFingerprint, f.id);

  /* 证据文本变化不应改变指纹 —— 否则 GitHub 侧会反复新增告警 */
  const changed = finding({ evidence: '完全不同的证据文本' });
  const sarif2 = toSarif({ findings: [changed], meta });
  assert.equal(sarif2.runs[0].results[0].partialFingerprints.surfaceWatchFingerprint, f.id);
});

test('locations 落在仓库内的声明文件上（保证 Code Scanning 能展示）', () => {
  const sarif = toSarif({ findings: [finding({ asset: 'example.com' })], meta });
  const loc = sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation;
  /* 默认落在 scope.json —— 资产正是在那里声明的，且该文件在仓库中真实存在 */
  assert.equal(loc.uri, 'scope.json');
  assert.match(loc.description.text, /example\.com/);
});

test('资产 URL 完整保留在 properties 与 message 中（位置取舍不丢信息）', () => {
  const sarif = toSarif({ findings: [finding({ asset: 'example.com' })], meta });
  const result = sarif.runs[0].results[0];
  assert.equal(result.properties.asset, 'example.com');
  assert.equal(result.properties.assetUrl, 'https://example.com/');
  assert.match(result.message.text, /\[example\.com\]/);
});

test('已是 URL 形式的资产在 assetUrl 中不会被重复加协议头', () => {
  const sarif = toSarif({ findings: [finding({ asset: 'https://example.com' })], meta });
  assert.equal(sarif.runs[0].results[0].properties.assetUrl, 'https://example.com');
});

test('可指定告警落脚的文件', () => {
  const sarif = toSarif({ findings: [finding()], meta, sourceFile: 'headers.policy.json' });
  assert.equal(
    sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri,
    'headers.policy.json'
  );
});

test('message 里同时包含标题、影响与修复建议（告警要能直接指导修复）', () => {
  const sarif = toSarif({ findings: [finding()], meta });
  const text = sarif.runs[0].results[0].message.text;
  assert.match(text, /缺少 HSTS 响应头/);
  assert.match(text, /影响：/);
  assert.match(text, /修复建议：/);
});

test('运行属性声明扫描范围与授权纪律', () => {
  const sarif = toSarif({ findings: [finding()], scannedAssets: ['a.com', 'b.com'], meta });
  const props = sarif.runs[0].properties;
  assert.deepEqual(props.scannedAssets, ['a.com', 'b.com']);
  assert.match(props.scopeDiscipline, /授权范围强制/);
});

test('无发现时也产出合法的 SARIF（空结果不等于坏结果）', () => {
  const sarif = toSarif({ findings: [], scannedAssets: ['example.com'], meta });
  const check = validateSarif(sarif);
  assert.equal(check.ok, true);
  assert.deepEqual(sarif.runs[0].results, []);
  assert.deepEqual(sarif.runs[0].tool.driver.rules, []);
});

test('自校验能识别结构错误（负向验证）', () => {
  const sarif = toSarif({ findings: [finding()], meta });

  /* 1. 版本错误 */
  const badVersion = structuredClone(sarif);
  badVersion.version = '2.0.0';
  assert.equal(validateSarif(badVersion).ok, false);

  /* 2. result 引用了未声明的规则 */
  const badRule = structuredClone(sarif);
  badRule.runs[0].results[0].ruleId = 'not:declared';
  const r2 = validateSarif(badRule);
  assert.equal(r2.ok, false);
  assert.ok(r2.problems.some((p) => /不在 rules 中声明/.test(p)));

  /* 3. level 非法 */
  const badLevel = structuredClone(sarif);
  badLevel.runs[0].results[0].level = 'fatal';
  assert.equal(validateSarif(badLevel).ok, false);

  /* 4. 缺少 message */
  const noMessage = structuredClone(sarif);
  delete noMessage.runs[0].results[0].message;
  assert.equal(validateSarif(noMessage).ok, false);

  /* 5. 缺少 locations */
  const noLoc = structuredClone(sarif);
  delete noLoc.runs[0].results[0].locations;
  assert.equal(validateSarif(noLoc).ok, false);
});

test('规则名只含 SARIF 允许的字符', () => {
  const sarif = toSarif({
    findings: [finding({ key: 'exposed-path:/.env' })],
    meta,
  });
  for (const rule of sarif.runs[0].tool.driver.rules) {
    assert.match(rule.name, /^[A-Za-z0-9-]+$/, `规则名不合法：${rule.name}`);
  }
});
