/**
 * TLS / 证书检查
 *
 * 关注三件事：证书还有多久过期、用的什么协议、证书本身是否可信。
 * 证书过期是运维事故里最常见的"可预防事故"，也是监控最该覆盖的一项。
 *
 * @module checks/tls
 */

import tls from 'node:tls';
import { createFinding } from '../lib/findings.mjs';

export const name = 'tls';

const WARN_DAYS = 30;
const URGENT_DAYS = 14;

/** 采集：直接握手，拿证书与协议信息 */
export function collect(asset, ctx = {}) {
  const host = asset.domain;
  const timeoutMs = ctx.timeoutMs || 10000;

  return new Promise((resolve) => {
    let settled = false;
    const done = (value) => {
      if (settled) return;
      settled = true;
      try {
        socket.destroy();
      } catch {
        /* ignore */
      }
      resolve(value);
    };

    const socket = tls.connect(
      {
        host,
        port: 443,
        servername: host,
        /* 不因为自签/过期就中断握手 —— 我们要把问题报告出来，而不是被它挡住 */
        rejectUnauthorized: false,
        timeout: timeoutMs,
      },
      () => {
        const cert = socket.getPeerCertificate() || {};
        const validTo = cert.valid_to ? new Date(cert.valid_to) : null;

        done({
          reachable: true,
          protocol: socket.getProtocol(),
          cipher: socket.getCipher() ? socket.getCipher().name : null,
          authorized: socket.authorized,
          authorizationError: socket.authorizationError
            ? String(socket.authorizationError)
            : null,
          subject: cert.subject ? cert.subject.CN || null : null,
          issuer: cert.issuer ? cert.issuer.O || cert.issuer.CN || null : null,
          validFrom: cert.valid_from || null,
          validTo: cert.valid_to || null,
          daysRemaining: validTo ? Math.floor((validTo - Date.now()) / 86400000) : null,
          altNames: cert.subjectaltname || null,
        });
      }
    );

    socket.on('timeout', () => done({ reachable: false, error: 'TIMEOUT' }));
    socket.on('error', (err) => done({ reachable: false, error: err.code || err.message }));
  });
}

/** 评估 */
export function evaluate(asset, obs) {
  const findings = [];
  const host = asset.domain;

  /* 没有任何观测数据 → 不下任何结论（"未采集"不等于"有问题"） */
  if (!obs) return findings;

  if (!obs.reachable) {
    findings.push(
      createFinding({
        asset: host,
        check: name,
        key: 'tls-unreachable',
        severity: 'info',
        title: '无法建立 TLS 连接',
        evidence: `错误：${obs.error || '未知'}`,
        impact: '可能是该资产不提供 HTTPS，或端口 443 被阻断；需人工确认。',
        remediation: '若该资产对外提供 HTTPS，请检查证书部署与网络策略；若本就无 HTTPS，可忽略此项。',
      })
    );
    return findings;
  }

  const days = obs.daysRemaining;

  if (days !== null && days < 0) {
    findings.push(
      createFinding({
        asset: host,
        check: name,
        key: 'cert-expired',
        severity: 'critical',
        title: '证书已过期',
        evidence: `有效期至 ${obs.validTo}（已过期 ${Math.abs(days)} 天）`,
        impact: '浏览器会直接拦截并显示安全警告，用户无法正常访问，等同服务中断。',
        remediation: '立即续期并部署证书；建议同时启用自动续期（如 ACME）与到期前 30 天的监控告警。',
      })
    );
  } else if (days !== null && days <= URGENT_DAYS) {
    findings.push(
      createFinding({
        asset: host,
        check: name,
        key: 'cert-expiring-urgent',
        severity: 'high',
        title: `证书将在 ${days} 天内过期`,
        evidence: `有效期至 ${obs.validTo}`,
        impact: '若不及时续期将导致全站不可访问。',
        remediation: '本周内完成续期，并确认自动续期流程可用。',
      })
    );
  } else if (days !== null && days <= WARN_DAYS) {
    findings.push(
      createFinding({
        asset: host,
        check: name,
        key: 'cert-expiring',
        severity: 'medium',
        title: `证书将在 ${days} 天内过期`,
        evidence: `有效期至 ${obs.validTo}`,
        impact: '进入续期窗口期，需安排处理。',
        remediation: '确认续期渠道与责任人，避免临近到期才发现问题。',
      })
    );
  }

  if (obs.protocol && /^TLSv1(\.[01])?$/.test(obs.protocol)) {
    findings.push(
      createFinding({
        asset: host,
        check: name,
        key: 'weak-protocol',
        severity: 'high',
        title: `使用了过时的 TLS 协议：${obs.protocol}`,
        evidence: `协议 ${obs.protocol}，套件 ${obs.cipher}`,
        impact: 'TLS 1.0/1.1 已被主流浏览器与合规标准弃用，存在已知攻击面（如降级、填充类攻击）。',
        remediation: '服务端仅保留 TLS 1.2 与 TLS 1.3，并禁用弱套件。',
      })
    );
  }

  if (obs.authorized === false && obs.authorizationError) {
    findings.push(
      createFinding({
        asset: host,
        check: name,
        key: 'cert-untrusted',
        severity: 'high',
        title: '证书不受信任',
        evidence: `校验错误：${obs.authorizationError}（颁发者：${obs.issuer || '未知'}）`,
        impact: '中间人可被替换证书而不被察觉，或用户会看到安全警告。',
        remediation: '换用受信任 CA 签发的证书，并确认中间证书链已完整部署。',
      })
    );
  }

  return findings;
}
