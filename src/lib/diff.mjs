/**
 * 基线差异计算
 *
 * 这是本工具的核心价值所在：安全监控的意义在于「变化」。
 * 一份全量清单看十遍也看不出问题，但"昨天没有、今天多了一条高危"一眼就能看见。
 *
 * 比对基于发现指纹（资产 + 检查项 + 键），因此同一问题在多次运行之间是稳定的，
 * 不会因为证据文本或响应长度的变化而被误判为新增。
 *
 * @module lib/diff
 */

import { compareSeverity } from './findings.mjs';

/**
 * 与基线比对
 *
 * @param {Array} current 本次的发现
 * @param {Array} baseline 上次的发现（无历史时传空数组）
 * @param {object} [options]
 * @param {string[]} [options.assets] 本次实际扫描的资产列表。
 *   务必传入！否则只扫描部分资产时，其它资产的基线发现会被误判为「已修复」，
 *   刷出一整屏假警报 —— 那正是差异报告最该避免的事。
 * @returns {{added: Array, resolved: Array, persistent: Array, unchangedCount: number, ignoredCount: number}}
 */
export function diffFindings(current, baseline = [], options = {}) {
  const scanned = options.assets
    ? new Set(options.assets.map((a) => String(a).toLowerCase()))
    : null;

  /* 只保留「本次确实扫过」的资产的基线记录 */
  const relevantBaseline = scanned
    ? baseline.filter((f) => scanned.has(String(f.asset).toLowerCase()))
    : baseline;
  const ignoredCount = baseline.length - relevantBaseline.length;

  const baseMap = new Map(relevantBaseline.map((f) => [f.id, f]));
  const currMap = new Map(current.map((f) => [f.id, f]));

  const added = [];
  const persistent = [];

  for (const [id, finding] of currMap) {
    const previous = baseMap.get(id);
    if (previous) {
      /* 保留首次发现时间：这样报告能说明"这个问题已经挂了多少天" */
      persistent.push({
        ...finding,
        firstSeen: previous.firstSeen || finding.firstSeen || null,
      });
    } else {
      added.push(finding);
    }
  }

  const resolved = [];
  for (const [id, finding] of baseMap) {
    if (!currMap.has(id)) resolved.push(finding);
  }

  return {
    added: sortBySeverity(added),
    resolved: sortBySeverity(resolved),
    persistent: sortBySeverity(persistent),
    unchangedCount: persistent.length,
    /* 因不在本次扫描范围而被忽略的基线条目数（透明化，避免"莫名少了"） */
    ignoredCount,
  };
}

function sortBySeverity(list) {
  return [...list].sort((a, b) => {
    const s = compareSeverity(b.severity, a.severity);
    return s !== 0 ? s : a.id.localeCompare(b.id);
  });
}

/**
 * 判断差异中是否出现达到指定严重度的新增项（用于 CI 门禁）
 */
export function hasAddedAtOrAbove(diff, severity) {
  return diff.added.some((f) => compareSeverity(f.severity, severity) >= 0);
}

/**
 * 首次运行时没有基线，此时所有发现都算"首次建立基线"，
 * 不应该被当作"新增问题"来告警 —— 这个区分很重要，否则第一次跑就会刷屏。
 */
export function isBaselineEstablishment(baseline) {
  return !Array.isArray(baseline) || baseline.length === 0;
}
