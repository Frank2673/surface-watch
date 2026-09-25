/**
 * 报告生成
 *
 * 产出三种形态，覆盖三种消费场景：
 *   - Markdown：给人看（也可以直接贴进 Issue / PR）
 *   - JSON：给机器看（归档、二次分析、接入其它系统）
 *   - 控制台摘要：给 CI 日志看（一眼看出结论）
 *
 * @module lib/report
 */

import { SEVERITY, severityIcon, severityLabel, summarize } from './findings.mjs';
import { changesetFromDiff, summarizeChangeset } from './changeset.mjs';

const TOOL = 'surface-watch';

/**
 * 统一入参形状：优先用单一变化源（lib/changeset.mjs），
 * 仍传裸 diff 的调用方会被规范化成变化集（规范化只在 changeset 里做一次）。
 */
function asChangeset({ changeset, diff, baseline = [] }) {
  return changeset || changesetFromDiff(diff || {}, baseline);
}

/**
 * Markdown 报告
 * @param {object} input
 * @returns {string}
 */
export function renderMarkdown({ scope, findings, changeset, diff, meta }) {
  const cs = asChangeset({ changeset, diff });
  const stats = summarize(findings);
  const lines = [];

  lines.push(`# 攻击面监控报告`);
  lines.push('');
  lines.push(`> 由 \`${TOOL} v${meta.version}\` 于 ${meta.startedAt} 生成 · 耗时 ${(meta.durationMs / 1000).toFixed(1)}s`);
  lines.push('');

  /* ---- 概览 ---- */
  lines.push('## 概览');
  lines.push('');
  lines.push(`| 指标 | 数值 |`);
  lines.push(`| :--- | :--- |`);
  lines.push(`| 监控资产 | ${meta.assetsScanned} 个 |`);
  lines.push(`| 发现总数 | ${stats.total} |`);
  lines.push(`| 最高严重度 | ${stats.highest ? `${severityIcon(stats.highest)} ${severityLabel(stats.highest)}` : '无'} |`);
  lines.push(`| 本次新增 | ${cs.added.length} |`);
  lines.push(`| 本次已修复 | ${cs.resolved.length} |`);
  lines.push(`| 持续存在 | ${cs.persistent.length} |`);
  /* 透明度：部分扫描时"莫名少了"的基线条目（判据与计数来自单一变化源） */
  lines.push(`| 因未扫描而被忽略的基线项 | ${cs.ignored.count} |`);
  lines.push('');

  /* ---- 严重度分布 ---- */
  const dist = SEVERITY.filter((s) => stats.counts[s] > 0)
    .reverse()
    .map((s) => `${severityIcon(s)} ${severityLabel(s)}：${stats.counts[s]}`)
    .join(' · ');
  if (dist) {
    lines.push(`**严重度分布**：${dist}`);
    lines.push('');
  }

  /* ---- 本次新增（最重要的部分放最前）---- */
  lines.push('## 🔔 本次新增');
  lines.push('');
  if (cs.added.length === 0) {
    lines.push(meta.baselineEstablished ? '_首次运行，已建立基线；下次运行将显示变化。_' : '_无新增发现。_');
  } else {
    for (const f of cs.added) lines.push(...findingBlock(f, { showAsset: true }));
  }
  lines.push('');

  /* ---- 已修复 ---- */
  if (cs.resolved.length > 0) {
    lines.push('## ✅ 本次已修复');
    lines.push('');
    for (const f of cs.resolved) {
      lines.push(`- ${severityIcon(f.severity)} **${f.title}**（\`${f.asset}\` · ${f.check}）`);
    }
    lines.push('');
  }

  /* ---- 持续存在 ---- */
  lines.push('## 📌 持续存在');
  lines.push('');
  if (cs.persistent.length === 0) {
    lines.push('_无。_');
  } else {
    const byAsset = groupBy(cs.persistent, (f) => f.asset);
    for (const [asset, items] of Object.entries(byAsset)) {
      lines.push(`<details><summary><code>${asset}</code> — ${items.length} 项</summary>`);
      lines.push('');
      for (const f of items) lines.push(...findingBlock(f, { showAsset: false }));
      lines.push('</details>');
      lines.push('');
    }
  }

  /* ---- 检查覆盖情况（透明度：说明哪些没跑）---- */
  if (meta.skipped && meta.skipped.length) {
    lines.push('## ⏭️ 跳过的检查');
    lines.push('');
    for (const s of meta.skipped) lines.push(`- \`${s.asset}\` / ${s.check}：${s.reason}`);
    lines.push('');
  }

  /* ---- 范围声明（授权纪律，必须留在报告里）---- */
  lines.push('## 📋 授权范围');
  lines.push('');
  lines.push(`- 所有者：\`${scope.owner}\``);
  lines.push(`- 授权声明：${scope.authorization.statement}`);
  if (scope.authorization.contact) lines.push(`- 联系方式：${scope.authorization.contact}`);
  lines.push(`- 在范围资产：${scope.assets.map((a) => `\`${a.domain}\``).join(', ')}`);
  lines.push('');
  lines.push(
    '_本工具仅对上述已声明资产执行被动检查；主动路径探测默认关闭，需在 `scope.json` 中显式开启。_'
  );
  lines.push('');
  lines.push('---');
  lines.push('');
  lines.push(
    `<sub>${TOOL} v${meta.version} · 零依赖（仅使用 Node 内置模块） · 报告格式为确定性输出，便于跨版本比对</sub>`
  );

  return lines.join('\n');
}

function findingBlock(f, { showAsset }) {
  const out = [];
  const where = showAsset ? `\`${f.asset}\` · ` : '';
  out.push(`### ${severityIcon(f.severity)} ${f.title}`);
  out.push('');
  out.push(`- ${where}检查项 \`${f.check}\` · 严重度 **${severityLabel(f.severity)}**`);
  if (f.firstSeen) out.push(`- 首次发现：${f.firstSeen}`);
  out.push(`- **证据**：${inline(f.evidence)}`);
  out.push(`- **影响**：${f.impact}`);
  out.push(`- **修复建议**：${f.remediation}`);
  out.push('');
  return out;
}

function inline(text) {
  return String(text || '').replace(/\n/g, ' ').trim();
}

function groupBy(list, keyFn) {
  const out = {};
  for (const item of list) {
    const key = keyFn(item);
    (out[key] = out[key] || []).push(item);
  }
  return out;
}

/**
 * JSON 报告
 *
 * 产物契约（只**新增**字段，不改既有字段名与语义）：
 *   - `baselineEstablished`：本次是否为首次建立基线（既有 helper `isBaselineEstablishment` 的口径）
 *   - `diff.ignoredCount`  ：因本次未扫描该资产而被过滤掉的基线条目数（既有 diff 已算出、原先没落盘）
 *   - `changeset`          ：单一变化源的**标量摘要**，供 CI 直接读（`addedCount` 即"有没有新变化"的判据）
 */
export function renderJson({ scope, findings, changeset, diff, meta }) {
  const cs = asChangeset({ changeset, diff });
  const summary = summarizeChangeset(cs);

  return {
    tool: TOOL,
    version: meta.version,
    startedAt: meta.startedAt,
    durationMs: meta.durationMs,
    baselineEstablished: cs.baselineEstablished,
    scope: {
      owner: scope.owner,
      assets: scope.assets.map((a) => a.domain),
      statement: scope.authorization.statement,
    },
    summary: summarize(findings),
    diff: {
      added: cs.added.map(toPlain),
      resolved: cs.resolved.map(toPlain),
      persistent: cs.persistent.map(toPlain),
      ignoredCount: summary.ignoredCount,
    },
    changeset: summary,
    findings: findings.map(toPlain),
    skipped: meta.skipped || [],
  };
}

function toPlain(f) {
  const { id, asset, check, key, severity, title, evidence, impact, remediation, firstSeen } = f;
  return { id, asset, check, key, severity, title, evidence, impact, remediation, firstSeen };
}

/**
 * 控制台摘要（供 CI 日志阅读）
 *
 * 输出格式与改造前逐字一致：只把取值来源换成单一变化源。
 */
export function renderSummary({ findings, changeset, diff, meta }) {
  const cs = asChangeset({ changeset, diff });
  const stats = summarize(findings);
  const lines = [];
  const status = cs.added.some((f) => f.severity === 'high' || f.severity === 'critical')
    ? '🔴 有高危新增'
    : cs.added.length > 0
      ? '⚠️ 有新增发现'
      : '✅ 无新增';

  lines.push(`${status} | 资产 ${meta.assetsScanned} | 发现 ${stats.total} | 新增 ${cs.added.length} | 已修复 ${cs.resolved.length} | 持续 ${cs.persistent.length}`);

  for (const f of cs.added.slice(0, 10)) {
    lines.push(`  + [${severityLabel(f.severity)}] ${f.asset} · ${f.title}`);
  }
  if (cs.added.length > 10) lines.push(`  … 其余 ${cs.added.length - 10} 条见报告`);

  for (const f of cs.resolved.slice(0, 5)) {
    lines.push(`  - [已修复] ${f.asset} · ${f.title}`);
  }

  return lines.join('\n');
}

/**
 * GitHub Actions Job Summary（在 Actions 页面直接渲染，无需下载 artifact）
 */
export function renderJobSummary({ scope, findings, changeset, diff, meta }) {
  return renderMarkdown({ scope, findings, changeset, diff, meta });
}
