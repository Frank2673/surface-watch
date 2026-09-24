/**
 * SARIF 输出
 *
 * SARIF（Static Analysis Results Interchange Format，OASIS 标准）是让扫描结果
 * 进入 GitHub Code Scanning 告警面板的通用格式 —— Trivy、Semgrep、CodeQL 都用它。
 *
 * 接入后的价值：
 *   - 发现直接出现在仓库 Security 标签页，可指派、可标记误报、可跟踪修复
 *   - 告警按规则聚合，而不是每次都刷一堆新条目
 *   - 团队不必再打开 Markdown 报告才知道出了问题
 *
 * 关键设计：partialFingerprints 用与内部差异比对相同的稳定指纹，
 * 这样同一条发现在多次运行之间会被 GitHub 识别为「同一个告警」，而不是反复新增。
 *
 * @module lib/sarif
 */

const SARIF_VERSION = '2.1.0';
const SARIF_SCHEMA = 'https://json.schemastore.org/sarif-2.1.0.json';

/** 内部严重度 → SARIF level */
const LEVEL_MAP = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
  info: 'note',
};

/**
 * 内部严重度 → GitHub 的 security-severity 分值（0.0–10.0）
 * GitHub 用这个分值在 Security 面板里分级排序。
 */
const SECURITY_SEVERITY_MAP = {
  critical: '9.5',
  high: '8.0',
  medium: '5.5',
  low: '3.0',
  info: '1.0',
};

/**
 * 把发现转换为 SARIF
 *
 * 关于「位置」的设计取舍：
 *   本工具的发现针对**远端资产**（域名/URL），而 GitHub Code Scanning 的告警
 *   需要落在一个仓库内的文件上才能正常展示与指派。所以这里把位置指向
 *   `scope.json`（资产正是在该文件里声明的，也是你会去改动它的地方），
 *   同时把资产 URL 保留在 message 与 properties 中，信息不丢失。
 *
 * @param {object} input
 * @param {Array} input.findings 发现列表
 * @param {Array} input.scannedAssets 本次扫描的资产（用于声明扫描范围）
 * @param {object} input.meta 运行元信息
 * @param {string} [input.toolUri] 工具主页
 * @param {string} [input.sourceFile] 告警落脚的文件（默认 scope.json）
 * @returns {object} SARIF 文档
 */
export function toSarif({ findings, scannedAssets = [], meta = {}, toolUri, sourceFile = 'scope.json' }) {
  const rules = buildRules(findings);

  const results = findings.map((finding) => {
    const ruleId = ruleIdOf(finding);
    const result = {
      ruleId,
      ruleIndex: rules.findIndex((r) => r.id === ruleId),
      level: LEVEL_MAP[finding.severity] || 'note',
      message: {
        text: `[${finding.asset}] ${finding.title}\n影响：${finding.impact}\n修复建议：${finding.remediation}`,
      },
      locations: [
        {
          physicalLocation: {
            /* 落在仓库内的声明文件上（详见上方注释的取舍说明） */
            artifactLocation: {
              uri: sourceFile,
              description: { text: `资产声明于 ${sourceFile}：${finding.asset}` },
            },
          },
        },
      ],
      /* 与内部差异比对使用同一套指纹 —— 保证 GitHub 侧告警稳定不漂移 */
      partialFingerprints: {
        surfaceWatchFingerprint: finding.id,
      },
      properties: {
        asset: finding.asset,
        assetUrl: normalizeUri(finding.asset),
        check: finding.check,
        key: finding.key,
        severity: finding.severity,
        evidence: finding.evidence,
        ...(finding.firstSeen ? { firstSeen: finding.firstSeen } : {}),
      },
    };
    return result;
  });

  return {
    $schema: SARIF_SCHEMA,
    version: SARIF_VERSION,
    runs: [
      {
        tool: {
          driver: {
            name: 'surface-watch',
            version: meta.version || '0.0.0',
            informationUri: toolUri || 'https://github.com/Frank2673/surface-watch',
            rules,
          },
        },
        /* 声明扫描的资产范围：让 GitHub 侧也能看到"边界在哪" */
        invocation: undefined,
        properties: {
          scannedAssets: scannedAssets.length ? scannedAssets : undefined,
          startedAt: meta.startedAt,
          durationMs: meta.durationMs,
          scopeDiscipline: '仅扫描 scope.json 中声明的资产（授权范围强制）',
        },
        results,
      },
    ],
  };
}

/** 规则 id：检查项 + 键（不含资产，便于同类问题归并到一条规则） */
function ruleIdOf(finding) {
  return `${finding.check}:${finding.key}`;
}

/**
 * 按规则聚合：同一条规则只声明一次，避免 SARIF 体积膨胀
 */
function buildRules(findings) {
  const byId = new Map();

  for (const finding of findings) {
    const id = ruleIdOf(finding);
    if (byId.has(id)) continue;

    byId.set(id, {
      id,
      name: toRuleName(id),
      shortDescription: { text: finding.title },
      fullDescription: { text: finding.impact || finding.title },
      help: {
        text: `检查项：${finding.check}\n严重度：${finding.severity}\n\n影响：${finding.impact}\n\n修复建议：${finding.remediation}`,
        markdown: [
          `**检查项**：\`${finding.check}\``,
          '',
          `**严重度**：${finding.severity}`,
          '',
          `**影响**：${finding.impact}`,
          '',
          `**修复建议**：${finding.remediation}`,
        ].join('\n'),
      },
      defaultConfiguration: {
        level: LEVEL_MAP[finding.severity] || 'note',
      },
      properties: {
        tags: ['security', 'attack-surface', finding.check],
        'security-severity': SECURITY_SEVERITY_MAP[finding.severity] || '1.0',
      },
    });
  }

  return [...byId.values()].sort((a, b) => a.id.localeCompare(b.id));
}

/** 把规则 id 转成可读的规则名（SARIF 只能含字母数字与连字符） */
function toRuleName(id) {
  return id
    .split(':')
    .join('-')
    .replace(/[^A-Za-z0-9-]/g, '-')
    .replace(/-+/g, '-');
}

/** 资产 → URI（GitHub 需要一个可引用的位置） */
function normalizeUri(asset) {
  if (/^https?:\/\//i.test(asset)) return asset;
  return `https://${asset}/`;
}

/**
 * 校验生成的 SARIF 是否满足 GitHub 的最低要求（供 CI 自检使用）
 * @returns {{ok: boolean, problems: string[]}}
 */
export function validateSarif(sarif) {
  const problems = [];

  if (sarif.version !== SARIF_VERSION) problems.push(`version 应为 ${SARIF_VERSION}`);
  if (!sarif.$schema) problems.push('缺少 $schema');
  if (!Array.isArray(sarif.runs) || sarif.runs.length === 0) problems.push('runs 不能为空');

  const run = sarif.runs && sarif.runs[0];
  if (run) {
    const driver = run.tool && run.tool.driver;
    if (!driver) problems.push('缺少 tool.driver');
    else {
      if (!driver.name) problems.push('缺少 tool.driver.name');
      if (!driver.version) problems.push('缺少 tool.driver.version');
      if (!Array.isArray(driver.rules)) problems.push('缺少 tool.driver.rules 数组');
    }

    if (!Array.isArray(run.results)) problems.push('缺少 results 数组');

    for (const [i, result] of (run.results || []).entries()) {
      if (!result.ruleId) problems.push(`results[${i}] 缺少 ruleId`);
      if (!result.message || !result.message.text) problems.push(`results[${i}] 缺少 message.text`);
      if (!['error', 'warning', 'note', 'none'].includes(result.level)) {
        problems.push(`results[${i}] 的 level 非法：${result.level}`);
      }
      const loc = result.locations && result.locations[0];
      if (!loc || !loc.physicalLocation || !loc.physicalLocation.artifactLocation) {
        problems.push(`results[${i}] 缺少 locations[0].physicalLocation.artifactLocation`);
      }
    }

    /* 每条 result 的 ruleId 必须能在 rules 中找到 —— GitHub 会因此报错 */
    const ruleIds = new Set((driver && driver.rules ? driver.rules : []).map((r) => r.id));
    for (const [i, result] of (run.results || []).entries()) {
      if (result.ruleId && !ruleIds.has(result.ruleId)) {
        problems.push(`results[${i}] 的 ruleId「${result.ruleId}」不在 rules 中声明`);
      }
    }
  }

  return { ok: problems.length === 0, problems };
}
