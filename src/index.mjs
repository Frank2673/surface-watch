#!/usr/bin/env node
/**
 * surface-watch 命令行入口
 *
 * 用法示例：
 *   node src/index.mjs --scope scope.json --out out --update-baseline
 *   node src/index.mjs --fixture fixtures/demo-observations.json --out out   # 离线演示，不联网
 *   node src/index.mjs --fail-on high                                        # CI 门禁：出现高危新增则退出码 1
 *
 * 退出码约定：
 *   0 = 正常完成（无达到门禁阈值的新增发现）
 *   1 = 有新发现达到 --fail-on 阈值
 *   2 = 运行错误（范围非法、文件不可读等）
 *
 * @module index
 */

import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { request } from './lib/http.mjs';
import { loadScope, assertHostInScope, ScopeError } from './lib/scope.mjs';
import { runScan } from './lib/scan.mjs';
import { diffFindings, hasAddedAtOrAbove, isBaselineEstablishment } from './lib/diff.mjs';
import { renderMarkdown, renderJson, renderSummary } from './lib/report.mjs';
import { SEVERITY, compareSeverity } from './lib/findings.mjs';

const VERSION = '0.1.0';

const HELP = `
surface-watch v${VERSION} —— 攻击面监控与基线差异（零依赖）

用法：
  node src/index.mjs [选项]

选项：
  --scope <路径>        范围文件（默认 scope.json）
  --out <目录>          输出目录（默认 out）
  --baseline <路径>     基线文件（默认 state/baseline.json）
  --update-baseline     本次运行后把结果写入基线
  --fixture <路径>      使用离线夹具代替真实网络（不发起任何请求）
  --only <检查项>       只运行指定检查，逗号分隔：dns,tls,headers,paths,ct
  --asset <域名>        只扫描指定资产（逗号分隔可多个）；不在范围内的域名会被拒绝
  --fail-on <严重度>    有该级别及以上的「新增」发现时退出码为 1（info|low|medium|high|critical）
  --no-color            关闭彩色输出
  --quiet               精简输出
  --help                显示本帮助

说明：
  本工具只检查 scope.json 中声明的资产，并拒绝内网/回环/云元数据地址。
  主动路径探测默认关闭，需在 scope.json 中显式开启 checks.paths.enabled。
`.trim();

function parseArgs(argv) {
  const args = { _: [] };
  const takesValue = new Set([
    '--scope',
    '--out',
    '--baseline',
    '--fixture',
    '--only',
    '--fail-on',
    '--asset',
  ]);

  for (let i = 0; i < argv.length; i++) {
    const token = argv[i];
    if (takesValue.has(token)) {
      const value = argv[i + 1];
      if (!value || value.startsWith('--')) {
        throw new Error(`${token} 需要一个值`);
      }
      args[token.slice(2)] = value;
      i++;
    } else if (token.startsWith('--')) {
      args[token.slice(2)] = true;
    } else {
      args._.push(token);
    }
  }
  return args;
}

function readJsonIfExists(path) {
  if (!existsSync(path)) return null;
  try {
    return JSON.parse(readFileSync(path, 'utf8'));
  } catch (err) {
    throw new Error(`基线/夹具文件解析失败 ${path}：${err.message}`);
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));

  if (args.help) {
    console.log(HELP);
    return 0;
  }

  const scopePath = args.scope || 'scope.json';
  const outDir = args.out || 'out';
  const baselinePath = args.baseline || 'state/baseline.json';
  const only = args.only ? String(args.only).split(',').map((s) => s.trim()).filter(Boolean) : null;
  const failOn = args['fail-on'] || null;

  if (failOn && !SEVERITY.includes(failOn)) {
    throw new Error(`--fail-on 取值非法：${failOn}（可选：${SEVERITY.join('|')}）`);
  }
  if (only) {
    const unknown = only.filter((c) => !['dns', 'tls', 'headers', 'paths', 'ct'].includes(c));
    if (unknown.length) throw new Error(`未知检查项：${unknown.join(', ')}`);
  }

  const startedAt = new Date().toISOString();
  const t0 = Date.now();
  const log = args.quiet ? () => {} : (m) => console.log(m);

  /* ---- 1. 加载范围（Scope Gate 的第一道关）---- */
  const scope = loadScope(scopePath);
  log(`📋 范围：${scope.assets.length} 个资产（所有者 ${scope.owner}）`);

  /* 可选：只扫描指定资产。
     注意这里同样要过 Scope Gate —— 范围外的域名一律拒绝，
     不允许通过命令行参数绕过授权范围。 */
  if (args.asset) {
    const requested = String(args.asset)
      .split(',')
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean);

    for (const domain of requested) {
      assertHostInScope(domain, scope); // 越权目标在此抛 ScopeError（退出码 2）
    }

    const matched = scope.assets.filter((a) =>
      requested.some((d) => d === a.domain.toLowerCase())
    );
    if (matched.length === 0) {
      throw new Error(`指定的资产不在范围列表中：${requested.join(', ')}`);
    }
    scope.assets = matched;
    log(`🎯 已限定资产：${matched.map((a) => a.domain).join(', ')}`);
  }

  /* ---- 2. 执行扫描 ---- */
  let fixture = null;
  if (args.fixture) {
    fixture = readJsonIfExists(args.fixture);
    if (!fixture) throw new Error(`夹具文件不存在：${args.fixture}`);
    log(`🧪 离线模式：使用夹具 ${args.fixture}（不会发起任何网络请求）`);
  }

  log(fixture ? '🔍 开始评估…' : '🔍 开始采集…');
  const { findings, skipped, observations } = await runScan(scope, {
    request,
    fixture,
    only,
    log,
  });

  /* ---- 3. 与基线比对 ---- */
  const baselineData = readJsonIfExists(baselinePath);
  const baseline = baselineData && Array.isArray(baselineData.findings) ? baselineData.findings : [];
  const baselineEstablished = isBaselineEstablishment(baseline);
  const diff = diffFindings(findings, baseline, {
    /* 只在本次扫描的资产范围内比对，避免部分扫描时产生"已修复"假警报 */
    assets: scope.assets.map((a) => a.domain),
  });

  const meta = {
    version: VERSION,
    startedAt,
    durationMs: Date.now() - t0,
    assetsScanned: scope.assets.length,
    skipCount: skipped.length,
    skipped,
    baselineEstablished,
    observations,
  };

  /* ---- 4. 写输出 ---- */
  mkdirSync(outDir, { recursive: true });

  const markdown = renderMarkdown({ scope, findings, diff, meta });
  const json = renderJson({ scope, findings, diff, meta });
  json.observations = observations;

  const reportPath = join(outDir, 'report.md');
  const jsonPath = join(outDir, 'findings.json');
  writeFileSync(reportPath, markdown, 'utf8');
  writeFileSync(jsonPath, JSON.stringify(json, null, 2), 'utf8');

  /* ---- 5. 打印摘要 ---- */
  console.log('');
  console.log(renderSummary({ findings, diff, meta }));
  console.log('');
  log(`📄 报告：${reportPath}`);
  log(`🧾 数据：${jsonPath}`);

  /* ---- 6. 更新基线 ---- */
  if (args['update-baseline']) {
    mkdirSync(dirname(baselinePath), { recursive: true });
    writeFileSync(
      baselinePath,
      JSON.stringify(
        {
          updatedAt: new Date().toISOString(),
          scope: scope.assets.map((a) => a.domain),
          findings,
        },
        null,
        2
      ),
      'utf8'
    );
    log(`💾 基线已更新：${baselinePath}（${findings.length} 条）`);
  }

  /* ---- 7. 门禁判定 ---- */
  if (failOn && hasAddedAtOrAbove(diff, failOn)) {
    const top = diff.added
      .filter((f) => compareSeverity(f.severity, failOn) >= 0)
      .map((f) => `  • [${f.severity}] ${f.asset} · ${f.title}`)
      .join('\n');
    console.error(`\n❌ 出现 ${failOn} 及以上级别的新增发现：\n${top}`);
    return 1;
  }

  return 0;
}

main()
  .then((code) => process.exit(code))
  .catch((err) => {
    if (err instanceof ScopeError) {
      console.error(`\n🛑 范围校验失败：${err.message}`);
      console.error('   —— 本工具拒绝检查任何未在 scope.json 中声明的资产。');
    } else {
      console.error(`\n🛑 运行失败：${err.message}`);
    }
    process.exit(2);
  });
