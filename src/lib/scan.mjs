/**
 * 扫描编排：采集 → 评估 → 汇总
 *
 * 分层的关键收益：evaluate 全是纯函数，因此可以用固定夹具做离线单元测试；
 * collect 才碰网络。测试跑得快、结果确定，CI 里不需要真的去打目标。
 *
 * @module lib/scan
 */

import * as dnsCheck from '../checks/dns.mjs';
import * as tlsCheck from '../checks/tls.mjs';
import * as headersCheck from '../checks/headers.mjs';
import * as pathsCheck from '../checks/paths.mjs';
import * as ctCheck from '../checks/ct.mjs';
import { assertHostInScope } from './scope.mjs';
import { sortFindings } from './findings.mjs';

export const CHECKS = {
  dns: dnsCheck,
  tls: tlsCheck,
  headers: headersCheck,
  paths: pathsCheck,
  ct: ctCheck,
};

/**
 * 判断某个检查在当前配置下是否启用
 */
export function isCheckEnabled(checkName, scope) {
  const cfg = scope.checks;
  switch (checkName) {
    case 'dns':
      return cfg.dns;
    case 'tls':
      return cfg.tls;
    case 'headers':
      return cfg.headers;
    case 'paths':
      return cfg.paths.enabled;
    case 'ct':
      return cfg.ct_logs;
    default:
      return false;
  }
}

/**
 * 执行一次完整扫描
 *
 * @param {object} scope 已归一化的范围
 * @param {object} options
 * @param {Function} options.request HTTP 客户端
 * @param {object|null} options.fixture 离线夹具（有则不联网）
 * @param {string[]|null} options.only 只跑指定检查
 * @param {Function} options.log 日志回调
 * @returns {Promise<{findings: Array, skipped: Array, observations: object}>}
 */
export async function runScan(scope, options = {}) {
  const { request, fixture = null, only = null, log = () => {} } = options;

  const findings = [];
  const skipped = [];
  const observations = {};

  for (const asset of scope.assets) {
    /* 双重保险：范围校验不仅在收集阶段做，扫描入口也做一次 */
    try {
      assertHostInScope(asset.domain, scope);
    } catch (err) {
      skipped.push({ asset: asset.domain, check: '*', reason: err.message });
      continue;
    }

    observations[asset.domain] = {};

    for (const [checkName, check] of Object.entries(CHECKS)) {
      if (only && !only.includes(checkName)) continue;

      if (!isCheckEnabled(checkName, scope)) {
        skipped.push({ asset: asset.domain, check: checkName, reason: '未在 scope.json 中启用' });
        continue;
      }

      const ctx = {
        request,
        timeoutMs: scope.rate_limit.timeoutMs,
        delayMs: scope.rate_limit.delayMs,
        paths: scope.checks.paths.list,
      };

      let obs;
      try {
        if (fixture) {
          obs = fixture.assets && fixture.assets[asset.domain]
            ? fixture.assets[asset.domain][checkName]
            : undefined;
          if (obs === undefined) {
            skipped.push({
              asset: asset.domain,
              check: checkName,
              reason: '离线夹具中无该检查数据',
            });
            continue;
          }
        } else {
          log(`  → ${asset.domain} · ${checkName}`);
          obs = await check.collect(asset, ctx);
        }
      } catch (err) {
        skipped.push({
          asset: asset.domain,
          check: checkName,
          reason: `采集失败：${err.message}`,
        });
        continue;
      }

      observations[asset.domain][checkName] = obs;

      try {
        const found = check.evaluate(asset, obs) || [];
        findings.push(...found.map((f) => (f.firstSeen ? f : { ...f, firstSeen: null })));
      } catch (err) {
        skipped.push({
          asset: asset.domain,
          check: checkName,
          reason: `评估失败：${err.message}`,
        });
      }
    }
  }

  return { findings: sortFindings(findings), skipped, observations };
}
