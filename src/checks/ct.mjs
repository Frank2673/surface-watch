/**
 * 证书透明度日志（CT Logs）子域发现 —— **可选项，默认关闭**
 *
 * 原理：任何公共 CA 签发证书都会记入 CT 日志，因此查 CT 日志能捞到
 * "曾经存在过的子域"，这是被动侦察里最经典的一步（且不触碰目标本身）。
 *
 * 设计原则：网络失败一律降级为"跳过"，绝不让整个扫描崩掉。
 *
 * @module checks/ct
 */

import { createFinding } from '../lib/findings.mjs';

export const name = 'ct';

/** 采集：查询 crt.sh */
export async function collect(asset, ctx = {}) {
  const domain = asset.domain;
  const url = `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`;

  const res = await ctx.request(url, { method: 'GET', timeoutMs: 20000, retries: 1 });

  if (!res.ok || res.status !== 200) {
    return { available: false, error: res.error || `HTTP ${res.status}`, subdomains: [] };
  }

  let rows;
  try {
    rows = JSON.parse(res.body);
  } catch {
    return { available: false, error: '返回内容不是合法 JSON（可能被限流）', subdomains: [] };
  }

  if (!Array.isArray(rows)) {
    return { available: false, error: '返回结构异常', subdomains: [] };
  }

  /* name_value 里可能塞了多行、带通配符，需要清洗去重 */
  const names = new Set();
  for (const row of rows) {
    const raw = String(row.name_value || row.common_name || '');
    for (const line of raw.split(/\n+/)) {
      const cleaned = line.trim().toLowerCase().replace(/^\*\./, '');
      if (!cleaned || cleaned.includes(' ')) continue;
      if (cleaned === domain || cleaned.endsWith('.' + domain)) names.add(cleaned);
    }
  }

  return {
    available: true,
    entries: rows.length,
    subdomains: [...names].sort(),
  };
}

/** 评估：把发现的子域作为情报项列出（差异报告会自动高亮"新增子域"） */
export function evaluate(asset, obs) {
  const findings = [];
  const domain = asset.domain;

  if (!obs || obs.available !== true) return findings;

  const subs = (obs.subdomains || []).filter((s) => s !== domain);
  if (subs.length === 0) return findings;

  findings.push(
    createFinding({
      asset: domain,
      check: name,
      key: 'ct-subdomains',
      severity: 'info',
      title: `CT 日志中发现 ${subs.length} 个子域`,
      evidence: `共 ${obs.entries} 条日志记录；子域：${subs.slice(0, 15).join(', ')}${subs.length > 15 ? ` 等 ${subs.length} 个` : ''}`,
      impact: '每个子域都是一块额外攻击面；其中可能存在已被遗忘、无人维护的资产（影子资产）。',
      remediation:
        '逐一确认这些子域是否仍在使用：在用的纳入监控，废弃的应及时下线并从 DNS 中移除（差异报告会在子域变化时提示）。',
    })
  );

  return findings;
}
