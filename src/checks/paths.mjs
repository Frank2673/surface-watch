/**
 * 敏感路径暴露检查（**主动探测，默认关闭**）
 *
 * 只有在 scope.json 里显式打开 checks.paths.enabled 才会发包。
 * 判据设计上刻意"宁可漏报、不可误报"：
 *   1. 先请求一个随机不存在的路径，建立「软 404 基线」
 *   2. 命中后必须再匹配内容特征（如 .git/config 必须含 [core]）才判定为暴露
 * 这样避免把"网站对任何路径都返回 200 的自定义 404 页"报成漏洞。
 *
 * @module checks/paths
 */

import { randomBytes } from 'node:crypto';
import { createFinding } from '../lib/findings.mjs';

export const name = 'paths';

/** 各路径的确认特征：只有内容对得上才算真暴露 */
const SIGNATURES = {
  '/.git/config': {
    test: (body) => /\[core\]/i.test(body) && /repositoryformatversion/i.test(body),
    severity: 'high',
    title: 'Git 配置目录可被公开访问',
    impact: '攻击者可下载 .git 目录并完整还原源码与提交历史，常从中翻出密钥、内网地址与历史漏洞。',
    remediation: '在 Web 服务器层拒绝访问 .git 等点号开头的路径，并立即轮换可能已泄露的凭据。',
  },
  '/.env': {
    test: (body) => /^[A-Z0-9_]{2,}=/m.test(body) && !/<html/i.test(body),
    severity: 'critical',
    title: '环境变量文件 .env 可被公开访问',
    impact: '数据库口令、API Key、第三方凭据直接暴露，通常意味着可进一步接管后端系统。',
    remediation: '立刻下线该文件、轮换其中所有凭据，并在部署流程中排除敏感配置文件。',
  },
  '/.DS_Store': {
    test: (body) => body.includes('Bud1'),
    severity: 'low',
    title: '.DS_Store 文件泄露目录结构',
    impact: 'macOS 打包残留文件，可泄露服务器上的文件名列表，辅助攻击者摸清结构。',
    remediation: '删除该文件并在部署/打包流程中排除 .DS_Store。',
  },
  '/backup.zip': {
    test: (body, headers) =>
      /zip|octet-stream/i.test(headers['content-type'] || '') || body.startsWith('PK'),
    severity: 'high',
    title: '备份压缩包可被公开下载',
    impact: '备份通常包含完整源码、配置甚至数据库导出，等同于把系统交付给攻击者。',
    remediation: '移除该文件；备份应存放在不可公开访问的位置（对象存储私有桶或内网）。',
  },
  '/server-status': {
    test: (body) => /Apache Server Status/i.test(body),
    severity: 'medium',
    title: 'Apache 服务器状态页对外暴露',
    impact: '泄露当前请求、客户端 IP、正在访问的 URL，可用于情报收集与流量分析。',
    remediation: '限制 /server-status 仅本地可访问（Require local），或直接关闭该模块。',
  },
  '/phpinfo.php': {
    test: (body) => /phpinfo\(\)/i.test(body),
    severity: 'high',
    title: 'phpinfo() 调试页对外暴露',
    impact: '泄露 PHP 版本、编译参数、环境变量、扩展与路径，为针对性利用提供完整指纹。',
    remediation: '删除该调试文件；生产环境禁止部署任何 phpinfo 页面。',
  },
};

/** 采集：软 404 基线 + 逐路径探测 */
export async function collect(asset, ctx = {}) {
  const host = asset.domain;
  const paths = ctx.paths || [];
  const request = ctx.request;
  const timeoutMs = ctx.timeoutMs || 10000;

  /* 软 404 基线：随机路径的响应特征 */
  const probePath = `/__surface_watch_probe_${randomBytes(6).toString('hex')}`;
  const baselineRes = await request(`https://${host}${probePath}`, {
    method: 'GET',
    timeoutMs,
    retries: 1,
  });

  const baseline = {
    status: baselineRes.status,
    length: (baselineRes.body || '').length,
    contentType: baselineRes.headers ? baselineRes.headers['content-type'] || '' : '',
  };

  const results = {};
  for (const path of paths) {
    const res = await request(`https://${host}${path}`, { method: 'GET', timeoutMs, retries: 1 });
    results[path] = {
      ok: res.ok,
      error: res.error || null,
      status: res.status,
      headers: res.headers || {},
      body: (res.body || '').slice(0, 4096),
      length: (res.body || '').length,
    };
    if (ctx.delayMs) await new Promise((r) => setTimeout(r, ctx.delayMs));
  }

  return { baseline, results };
}

/** 评估：必须先通过"软 404 排除"，再通过内容特征确认 */
export function evaluate(asset, obs) {
  const findings = [];
  const host = asset.domain;

  if (!obs || !obs.results) return findings;

  for (const [path, res] of Object.entries(obs.results)) {
    if (!res.ok || res.status !== 200) continue;

    /* 排除软 404：状态码与长度都与基线一致 → 判定为自定义错误页，不报 */
    const looksLikeSoft404 =
      res.status === obs.baseline.status && Math.abs(res.length - obs.baseline.length) < 64;
    if (looksLikeSoft404) continue;

    const sig = SIGNATURES[path];
    if (sig && !sig.test(res.body, res.headers)) continue; // 内容特征不符 → 不报

    const isKnown = Boolean(sig);
    findings.push(
      createFinding({
        asset: host,
        check: name,
        key: `exposed-path:${path}`,
        severity: isKnown ? sig.severity : 'medium',
        title: isKnown ? sig.title : `可疑路径可访问：${path}`,
        evidence: `GET ${path} → 200（${res.length} 字节，基线 ${obs.baseline.length} 字节）`,
        impact: isKnown
          ? sig.impact
          : '该路径在正常站点中不应存在，返回 200 说明可能有文件被误部署。',
        remediation: isKnown
          ? sig.remediation
          : '人工确认该路径内容；若为误部署文件请删除，并检查部署流程的排除规则。',
      })
    );
  }

  return findings;
}
