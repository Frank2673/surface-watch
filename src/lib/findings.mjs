/**
 * 发现（Finding）模型
 *
 * 设计要点：每条发现都带「证据 + 影响 + 修复建议」三件套。
 * 只报"缺了什么"的扫描器是半成品；能说清"为什么危险、怎么改"才是可交付的报告。
 *
 * @module lib/findings
 */

/** 严重度分级（由低到高） */
export const SEVERITY = ['info', 'low', 'medium', 'high', 'critical'];

const SEVERITY_LABEL = {
  info: '信息',
  low: '低',
  medium: '中',
  high: '高',
  critical: '严重',
};

const SEVERITY_ICON = {
  info: 'ℹ️',
  low: '🔹',
  medium: '⚠️',
  high: '🔴',
  critical: '🚨',
};

/**
 * 比较两个严重度
 * @returns {number} 正数表示 a 更严重
 */
export function compareSeverity(a, b) {
  return SEVERITY.indexOf(a) - SEVERITY.indexOf(b);
}

export function severityLabel(s) {
  return SEVERITY_LABEL[s] || s;
}

export function severityIcon(s) {
  return SEVERITY_ICON[s] || '';
}

/**
 * 生成稳定的指纹
 *
 * 关键设计：指纹**只由「资产 + 检查项 + 键」构成，不含证据文本**。
 * 否则证据里一个字节的变化（比如响应长度不同）都会被误判为"新增发现"，
 * 让差异报告彻底失去意义。
 */
export function fingerprint(finding) {
  return `${finding.check}:${finding.key}:${finding.asset}`;
}

/**
 * 创建一条发现
 * @param {object} input
 * @returns {object}
 */
export function createFinding({
  asset,
  check,
  key,
  severity = 'info',
  title,
  evidence = '',
  impact = '',
  remediation = '',
  firstSeen = null,
}) {
  if (!SEVERITY.includes(severity)) {
    throw new Error(`未知严重度：${severity}`);
  }
  const finding = {
    id: '',
    asset,
    check,
    key,
    severity,
    title,
    evidence,
    impact,
    remediation,
    firstSeen,
  };
  finding.id = fingerprint(finding);
  return finding;
}

/**
 * 排序：严重度优先，其次按资产与检查项，保证报告顺序稳定（便于人眼比对）
 */
export function sortFindings(findings) {
  return [...findings].sort((a, b) => {
    const bySeverity = compareSeverity(b.severity, a.severity);
    if (bySeverity !== 0) return bySeverity;
    if (a.asset !== b.asset) return a.asset.localeCompare(b.asset);
    return a.id.localeCompare(b.id);
  });
}

/**
 * 统计各严重度数量
 */
export function summarize(findings) {
  const counts = Object.fromEntries(SEVERITY.map((s) => [s, 0]));
  for (const f of findings) counts[f.severity]++;
  return {
    total: findings.length,
    counts,
    highest: [...SEVERITY].reverse().find((s) => counts[s] > 0) || null,
  };
}
