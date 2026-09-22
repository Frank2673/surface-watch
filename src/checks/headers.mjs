/**
 * HTTP 安全响应头检查
 *
 * 响应头是最"便宜"的一层防护：不用改代码、不用改架构，改一行配置就能挡住
 * 点击劫持、MIME 嗅探、降级攻击等一整类问题。因此它也是监控性价比最高的一项。
 *
 * @module checks/headers
 */

import { createFinding } from '../lib/findings.mjs';

export const name = 'headers';

const HSTS_MIN_MAX_AGE = 15552000; // 180 天（HSTS 预加载列表的建议下限）

/** 采集：请求首页，记录状态码、响应头、最终地址 */
export async function collect(asset, ctx = {}) {
  const url = `https://${asset.domain}/`;
  const res = await ctx.request(url, { method: 'GET', timeoutMs: ctx.timeoutMs || 10000 });

  return {
    url,
    ok: res.ok,
    error: res.error || null,
    status: res.status,
    headers: res.headers || {},
    finalUrl: res.finalUrl || url,
    ms: res.ms || 0,
    truncated: res.truncated || false,
  };
}

/** 评估 */
export function evaluate(asset, obs) {
  const findings = [];
  const host = asset.domain;
  const add = (key, severity, title, evidence, impact, remediation) =>
    findings.push(
      createFinding({ asset: host, check: name, key, severity, title, evidence, impact, remediation })
    );

  /* 没有任何观测数据 → 不下任何结论（"未采集"不等于"有问题"） */
  if (!obs) return findings;

  if (obs.ok !== true) {
    add(
      'http-unreachable',
      'info',
      '无法通过 HTTPS 获取首页',
      `错误：${obs.error || '未知'}`,
      '可能与 TLS 检查结果相同（不提供 HTTPS 或网络受阻）。',
      '确认该资产是否需要提供 Web 服务；若需要，检查部署与网络策略。'
    );
    return findings;
  }

  const h = lowerHeaders(obs.headers);

  /* ---- 服务端错误 ---- */
  if (obs.status >= 500) {
    add(
      'server-error',
      'medium',
      `首页返回服务端错误 ${obs.status}`,
      `GET ${obs.url} → ${obs.status}`,
      '用户无法正常访问，可能是服务异常或部署失败。',
      '检查服务日志与最近一次部署；为首页增加可用性监控与告警。'
    );
  }

  /* ---- 强制 HTTPS ---- */
  if (String(obs.finalUrl).startsWith('http://')) {
    add(
      'no-https-redirect',
      'high',
      'HTTPS 未生效（最终跳转到明文 HTTP）',
      `请求 ${obs.url} 最终到达 ${obs.finalUrl}`,
      '流量可被窃听与篡改，登录态与敏感数据面临中间人风险。',
      '配置 301 跳转到 HTTPS，并开启 HSTS。'
    );
  }

  /* ---- HSTS ---- */
  const hsts = h['strict-transport-security'];
  if (!hsts) {
    add(
      'missing-hsts',
      'medium',
      '缺少 HSTS 响应头',
      '响应头中未发现 strict-transport-security',
      '首次访问或用户手动输入 http:// 时，存在被降级劫持的窗口，SSL 剥离攻击可生效。',
      `添加响应头 Strict-Transport-Security: max-age=${HSTS_MIN_MAX_AGE}; includeSubDomains，确认稳定后再考虑 preload。`
    );
  } else {
    const maxAge = Number((hsts.match(/max-age\s*=\s*(\d+)/i) || [])[1] || 0);
    if (maxAge > 0 && maxAge < HSTS_MIN_MAX_AGE) {
      add(
        'hsts-short-max-age',
        'low',
        `HSTS 有效期偏短（${maxAge} 秒）`,
        `strict-transport-security: ${hsts}`,
        '有效期过短会让强制 HTTPS 的保护频繁失效。',
        `提升 max-age 至 ${HSTS_MIN_MAX_AGE} 以上（建议 1 年）。`
      );
    }
    if (!/includeSubDomains/i.test(hsts)) {
      add(
        'hsts-no-subdomains',
        'low',
        'HSTS 未覆盖子域（缺少 includeSubDomains）',
        `strict-transport-security: ${hsts}`,
        '子域仍可能被降级，攻击者可从子域下手绕过保护。',
        '在响应头中加入 includeSubDomains（确认所有子域均支持 HTTPS 后再启用）。'
      );
    }
  }

  /* ---- 内容安全策略 ---- */
  const csp = h['content-security-policy'];
  if (!csp) {
    add(
      'missing-csp',
      'medium',
      '缺少内容安全策略（CSP）',
      '响应头中未发现 content-security-policy',
      '一旦出现 XSS 或第三方脚本注入，浏览器没有第二道防线来限制脚本执行与数据外发。',
      "从最小可用策略起步：default-src 'self'；逐步按实际资源收紧，先以 Content-Security-Policy-Report-Only 观察误报。"
    );
  }

  /* ---- 点击劫持 ---- */
  const xfo = h['x-frame-options'];
  const cspFrames = csp && /frame-ancestors/i.test(csp);
  if (!xfo && !cspFrames) {
    add(
      'missing-frame-protection',
      'medium',
      '缺少点击劫持防护（X-Frame-Options 与 frame-ancestors 均未设置）',
      `x-frame-options=${xfo || '(无)'}, CSP 含 frame-ancestors=${Boolean(cspFrames)}`,
      '页面可被第三方站点用 iframe 嵌套，诱导用户点击（点击劫持）或用于钓鱼伪装。',
      "设置 X-Frame-Options: DENY，或在 CSP 中声明 frame-ancestors 'none'。"
    );
  }

  /* ---- MIME 嗅探 ---- */
  if (!h['x-content-type-options']) {
    add(
      'missing-nosniff',
      'low',
      '缺少 X-Content-Type-Options: nosniff',
      '响应头中未发现 x-content-type-options',
      '浏览器可能按内容猜测类型，把本应下载的文件当脚本执行（MIME 混淆攻击）。',
      '添加响应头 X-Content-Type-Options: nosniff。'
    );
  }

  /* ---- Referrer 泄露 ---- */
  if (!h['referrer-policy']) {
    add(
      'missing-referrer-policy',
      'low',
      '缺少 Referrer-Policy',
      '响应头中未发现 referrer-policy',
      '跳转到第三方时可能把完整来源 URL（含路径甚至参数里的敏感信息）泄露出去。',
      '添加响应头 Referrer-Policy: strict-origin-when-cross-origin。'
    );
  }

  /* ---- 功能权限 ---- */
  if (!h['permissions-policy']) {
    add(
      'missing-permissions-policy',
      'info',
      '缺少 Permissions-Policy',
      '响应头中未发现 permissions-policy',
      '未显式关闭用不到的浏览器能力（摄像头、麦克风、定位等），被注入脚本时可被滥用。',
      '按需添加，例如 Permissions-Policy: geolocation=(), camera=(), microphone=()。'
    );
  }

  /* ---- 版本信息泄露 ---- */
  const server = h['server'];
  if (server && /\d/.test(server)) {
    add(
      'server-version-disclosure',
      'low',
      'Server 响应头暴露版本信息',
      `server: ${server}`,
      '攻击者可据此定位已知漏洞版本，减少探测成本。',
      '隐藏或泛化该响应头（如仅返回 "nginx" 或移除 Server 头）。'
    );
  }

  const poweredBy = h['x-powered-by'];
  if (poweredBy) {
    add(
      'x-powered-by-disclosure',
      'low',
      'X-Powered-By 暴露技术栈',
      `x-powered-by: ${poweredBy}`,
      '泄露后端框架与版本，便于攻击者选择针对性利用手段。',
      '关闭该响应头（多数框架有开关，如 Express 的 app.disable("x-powered-by")）。'
    );
  }

  return findings;
}

function lowerHeaders(headers) {
  const out = {};
  for (const [k, v] of Object.entries(headers || {})) {
    out[k.toLowerCase()] = Array.isArray(v) ? v.join(', ') : String(v);
  }
  return out;
}
