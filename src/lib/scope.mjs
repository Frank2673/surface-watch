/**
 * 授权范围模型与强制校验（Scope Gate）
 *
 * 这是本工具与"随便写个扫描脚本"最本质的区别：
 * 它拒绝做任何未被显式声明为「自有或已获授权」的事情。
 *
 * 强制规则：
 *   1. 目标域名必须在 scope.json 的 assets 列表中，且逐字匹配（含子域规则）
 *   2. 禁止扫描内网 / 回环 / 链路本地 / 云元数据地址（防止被当成 SSRF 跳板）
 *   3. 必须存在授权声明（authorization.statement 非空）
 *
 * @module lib/scope
 */

import { readFileSync } from 'node:fs';

/** 被禁止的目标：内网段、回环、链路本地、云元数据服务 */
const FORBIDDEN_HOST_PATTERNS = [
  { re: /^localhost$/i, why: '本机回环地址' },
  { re: /^127\./, why: 'IPv4 回环段' },
  { re: /^10\./, why: 'RFC1918 内网段' },
  { re: /^192\.168\./, why: 'RFC1918 内网段' },
  { re: /^172\.(1[6-9]|2\d|3[01])\./, why: 'RFC1918 内网段' },
  { re: /^169\.254\./, why: '链路本地段（含云元数据 169.254.169.254）' },
  { re: /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./, why: '运营商级 NAT 段' },
  { re: /^0\./, why: '保留段' },
  { re: /^\[?::1\]?$/, why: 'IPv6 回环' },
  { re: /^\[?f[cd][0-9a-f]{2}:/i, why: 'IPv6 唯一本地地址' },
  { re: /^\[?fe80:/i, why: 'IPv6 链路本地地址' },
  { re: /metadata\.(google|azure)\./i, why: '云元数据服务' },
];

export class ScopeError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ScopeError';
  }
}

/**
 * 校验主机名是否允许被检查
 * @param {string} host
 * @param {object} scope
 * @returns {{allowed: true, asset: object} | {allowed: false, reason: string}}
 */
export function checkHost(host, scope) {
  if (!host || typeof host !== 'string') {
    return { allowed: false, reason: '主机名为空' };
  }

  const normalized = host.trim().toLowerCase().replace(/\.$/, '');

  for (const { re, why } of FORBIDDEN_HOST_PATTERNS) {
    if (re.test(normalized)) {
      return { allowed: false, reason: `目标命中禁止规则：${why}` };
    }
  }

  const asset = (scope.assets || []).find((a) => {
    const target = String(a.domain || '').toLowerCase().replace(/\.$/, '');
    /* 只有完全相同，或是它的子域，才算在范围内 */
    return normalized === target || normalized.endsWith('.' + target);
  });

  if (!asset) {
    return {
      allowed: false,
      reason: '目标不在授权范围内（scope.json 的 assets 未声明该域名）',
    };
  }

  return { allowed: true, asset };
}

/**
 * 断言主机在授权范围内，否则抛错
 * @param {string} host
 * @param {object} scope
 */
export function assertHostInScope(host, scope) {
  const result = checkHost(host, scope);
  if (!result.allowed) {
    throw new ScopeError(`[Scope Gate] 拒绝检查 ${host}：${result.reason}`);
  }
  return result.asset;
}

/**
 * 读取并校验范围文件
 * @param {string} filePath
 * @returns {object} 归一化后的 scope
 */
export function loadScope(filePath) {
  let raw;
  try {
    raw = readFileSync(filePath, 'utf8');
  } catch (err) {
    throw new ScopeError(`无法读取范围文件 ${filePath}：${err.message}`);
  }

  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new ScopeError(`范围文件不是合法 JSON：${err.message}（本项目刻意不用 YAML，以保持零依赖）`);
  }

  if (!Array.isArray(parsed.assets) || parsed.assets.length === 0) {
    throw new ScopeError('范围文件必须包含非空的 assets 数组');
  }

  const statement = parsed.authorization && parsed.authorization.statement;
  if (!statement || String(statement).trim().length < 8) {
    throw new ScopeError(
      '缺少授权声明：请在 authorization.statement 中写明「你拥有该资产或已获得书面授权」'
    );
  }

  /* 逐条校验目标本身是否合法（防止把内网地址写进范围） */
  for (const asset of parsed.assets) {
    const probe = checkHost(asset.domain, { assets: [{ domain: asset.domain }] });
    if (!probe.allowed && /禁止规则/.test(probe.reason)) {
      throw new ScopeError(`范围中的 ${asset.domain} 不允许被检查：${probe.reason}`);
    }
  }

  const limits = parsed.rate_limit || {};
  return {
    owner: parsed.owner || 'unknown',
    authorization: {
      statement: String(statement).trim(),
      contact: parsed.authorization.contact || null,
    },
    assets: parsed.assets.map((a) => ({
      domain: String(a.domain).toLowerCase(),
      tags: Array.isArray(a.tags) ? a.tags : [],
      note: a.note || null,
    })),
    rate_limit: {
      /* 并发与间隔都设上限，避免把目标打成 DoS —— 这也是授权测试的基本纪律 */
      concurrency: clamp(Number(limits.concurrency) || 4, 1, 8),
      delayMs: clamp(Number(limits.delay_ms) || 300, 0, 5000),
      timeoutMs: clamp(Number(limits.timeout_ms) || 10000, 1000, 30000),
    },
    checks: normalizeChecks(parsed.checks),
  };
}

function clamp(value, min, max) {
  return Math.min(Math.max(value, min), max);
}

function normalizeChecks(checks = {}) {
  const paths = checks.paths || {};
  return {
    dns: checks.dns !== false,
    tls: checks.tls !== false,
    headers: checks.headers !== false,
    ct_logs: checks.ct_logs === true,
    paths: {
      /* 主动路径探测默认关闭：只有显式开启才会发包 */
      enabled: paths.enabled === true,
      list: Array.isArray(paths.list) && paths.list.length ? paths.list : DEFAULT_PATHS,
    },
  };
}

/** 默认探测的敏感路径（仅在显式开启 paths 时使用） */
export const DEFAULT_PATHS = [
  '/.git/config',
  '/.env',
  '/.DS_Store',
  '/backup.zip',
  '/server-status',
  '/phpinfo.php',
];
