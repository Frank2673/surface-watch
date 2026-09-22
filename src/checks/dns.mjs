/**
 * DNS 检查
 *
 * 除了解析结果本身，还检查两个常被忽略但危害明确的问题：
 *   - 邮件伪造面：有 MX 却没有 SPF / DMARC，或 SPF 用了 +all
 *   - 证书签发面：缺少 CAA 记录，任何 CA 都能为该域名签发证书
 *
 * @module checks/dns
 */

import { Resolver } from 'node:dns/promises';
import { createFinding } from '../lib/findings.mjs';

export const name = 'dns';

/** 采集：把所有记录一次性取回（单项失败不影响其它项） */
export async function collect(asset, ctx = {}) {
  const resolver = new Resolver({ timeout: ctx.timeoutMs || 8000, tries: 2 });
  const domain = asset.domain;

  const safe = async (fn) => {
    try {
      return await fn();
    } catch {
      return null;
    }
  };

  const [a, aaaa, cname, ns, mx, txt, dmarcTxt, caa] = await Promise.all([
    safe(() => resolver.resolve4(domain)),
    safe(() => resolver.resolve6(domain)),
    safe(() => resolver.resolveCname(domain)),
    safe(() => resolver.resolveNs(domain)),
    safe(() => resolver.resolveMx(domain)),
    safe(() => resolver.resolveTxt(domain)),
    safe(() => resolver.resolveTxt(`_dmarc.${domain}`)),
    safe(() => resolver.resolveCaa(domain)),
  ]);

  return {
    domain,
    a: a || [],
    aaaa: aaaa || [],
    cname: cname || [],
    ns: ns || [],
    mx: mx || [],
    /* resolveTxt 返回的是「每条记录一个字符串数组」，这里拍平成整串便于匹配 */
    txt: (txt || []).map((parts) => parts.join('')),
    dmarcTxt: (dmarcTxt || []).map((parts) => parts.join('')),
    caa: caa || [],
  };
}

/** 评估：纯函数，输入观测结果，输出发现列表 */
export function evaluate(asset, obs) {
  const findings = [];
  const domain = asset.domain;

  /* 没有任何观测数据 → 不下任何结论（"未采集"不等于"有问题"） */
  if (!obs) return findings;

  const hasAddress = obs.a.length > 0 || obs.aaaa.length > 0 || obs.cname.length > 0;

  if (!hasAddress) {
    findings.push(
      createFinding({
        asset: domain,
        check: name,
        key: 'unresolvable',
        severity: 'high',
        title: '域名无法解析',
        evidence: `A=${obs.a.length} AAAA=${obs.aaaa.length} CNAME=${obs.cname.length}`,
        impact: '资产可能已下线或配置错误；若仍对外提供服务，说明存在解析异常。',
        remediation: '确认该资产是否仍在使用；若已废弃，请从监控范围中移除。',
      })
    );
    return findings;
  }

  /* ---- SPF：邮件伪造面 ---- */
  const spf = obs.txt.find((t) => /^v=spf1\b/i.test(t));
  const hasMx = obs.mx.length > 0;

  if (hasMx && !spf) {
    findings.push(
      createFinding({
        asset: domain,
        check: name,
        key: 'missing-spf',
        severity: 'medium',
        title: '存在邮件服务但缺少 SPF 记录',
        evidence: `MX 记录 ${obs.mx.length} 条；TXT 中未发现 v=spf1`,
        impact: '攻击者可伪造该域名的发件人地址投递钓鱼邮件，收件方难以识别。',
        remediation:
          '添加 TXT 记录声明合法发信源，例如 `v=spf1 include:<你的邮件服务商> -all`，并用硬失败（-all）收尾。',
      })
    );
  }

  if (spf && /[+?]all\b/i.test(spf)) {
    findings.push(
      createFinding({
        asset: domain,
        check: name,
        key: 'spf-permissive',
        severity: 'high',
        title: 'SPF 策略过于宽松（+all / ?all）',
        evidence: spf,
        impact: '等于声明"任何主机都可以代表本域发信"，SPF 形同虚设，钓鱼邮件可顺利通过校验。',
        remediation: '把 `+all` / `?all` 改为 `~all`（软失败）或 `-all`（硬失败）。',
      })
    );
  }

  /* ---- DMARC ---- */
  const dmarc = obs.dmarcTxt.find((t) => /^v=DMARC1\b/i.test(t));
  if (!dmarc) {
    findings.push(
      createFinding({
        asset: domain,
        check: name,
        key: 'missing-dmarc',
        severity: hasMx ? 'medium' : 'low',
        title: '缺少 DMARC 记录',
        evidence: `_dmarc.${domain} 未返回 v=DMARC1 记录`,
        impact: '收件方无法依据域名所有者意图处置伪造邮件，SPF/DKIM 校验失败时也不会被拦。',
        remediation: `添加 TXT 记录：\`_dmarc.${domain}\` = \`v=DMARC1; p=none; rua=mailto:<你的邮箱>\`，观察一段时间后再收紧为 quarantine/reject。`,
      })
    );
  } else if (/p\s*=\s*none/i.test(dmarc)) {
    findings.push(
      createFinding({
        asset: domain,
        check: name,
        key: 'dmarc-monitor-only',
        severity: 'low',
        title: 'DMARC 处于仅监控模式（p=none）',
        evidence: dmarc,
        impact: '策略只收集报告、不拦截伪造邮件，防护效果有限。',
        remediation: '确认报告显示合法邮件均通过校验后，将策略提升为 `p=quarantine` 或 `p=reject`。',
      })
    );
  }

  /* ---- CAA：证书签发面 ---- */
  if (obs.caa.length === 0) {
    findings.push(
      createFinding({
        asset: domain,
        check: name,
        key: 'missing-caa',
        severity: 'low',
        title: '缺少 CAA 记录',
        evidence: '未查询到 CAA 资源记录',
        impact: '任何公共 CA 都可以为该域名签发证书；若 CA 被滥用或错误签发，你不会被提前阻止。',
        remediation:
          '按实际使用的 CA 添加 CAA 记录，例如 `0 issue "letsencrypt.org"`，并补一条 `0 iodef "mailto:security@<域名>"` 用于接收违规签发报告。',
      })
    );
  }

  return findings;
}
