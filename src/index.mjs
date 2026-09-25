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
import { buildChangeset, hasAddedAtOrAbove, triggerFindings } from './lib/changeset.mjs';
import { renderMarkdown, renderJson, renderSummary } from './lib/report.mjs';
import { toSarif, validateSarif } from './lib/sarif.mjs';
import { SEVERITY, compareSeverity } from './lib/findings.mjs';
import {
  resolveWebhookConfig,
  planDelivery,
  buildPayload,
  deliverWebhook,
  buildDeliveryRecord,
  buildNoDeliveryRecord,
  writeDeliveryRecord,
  redactUrl,
  DEFAULT_MIN_SEVERITY,
  DEFAULT_WEBHOOK_TIMEOUT_MS,
  defaultWebhookDeadlineMs,
  ENV_WEBHOOK_URL,
  ENV_WEBHOOK_SECRET,
} from './lib/notify.mjs';

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
  --sarif [路径]        额外输出 SARIF 报告（默认 out/results.sarif），
                        可上传至 GitHub Code Scanning，让告警出现在仓库 Security 面板
  --webhook <url>       Webhook 告警地址；仅当本次出现「新增指纹」时投递（详见下方说明），
                        可用环境变量 ${ENV_WEBHOOK_URL} 回退（CI 里用 secret 注入）
  --webhook-secret <s>  可选：对请求体做 HMAC-SHA256，请求头
                        ${'X-Surface-Watch-Signature'}: sha256=<hex>
                        可用环境变量 ${ENV_WEBHOOK_SECRET} 回退
  --webhook-min-severity <级别>
                        告警阈值（默认 ${DEFAULT_MIN_SEVERITY}）：仅投递该级别及以上的「新增指纹」
                        （info|low|medium|high|critical）
  --webhook-timeout <ms> 单次投递的 socket 空闲超时（默认 ${DEFAULT_WEBHOOK_TIMEOUT_MS}ms）：
                        只覆盖"一次尝试里 socket 无数据"，不是投递总时长
  --webhook-deadline <ms>
                        投递整体截止时间（默认 max(10000, 3 × --webhook-timeout)，
                        即 --webhook-timeout ${DEFAULT_WEBHOOK_TIMEOUT_MS} 时为 ${defaultWebhookDeadlineMs(DEFAULT_WEBHOOK_TIMEOUT_MS)}ms）：
                        覆盖 connect + 响应头 + 响应体 + 退避 + 全部重试的总时长。
                        慢接收端（200 + chunked 后每 200ms 一字节、永不结束）下
                        socket 一直有数据，只有它能保证投递阶段有界结束
  --webhook-include-initial
                        基线缺失（首次运行）时也投递首轮全量；默认跳过（基线缺失时
                        "全部都是新增"是假象，不是真的变化）
  --no-color            关闭彩色输出
  --quiet               精简输出
  --help                显示本帮助

说明：
  本工具只检查 scope.json 中声明的资产，并拒绝内网/回环/云元数据地址。
  主动路径探测默认关闭，需在 scope.json 中显式开启 checks.paths.enabled。

  Webhook 触发集合严格等于「本次新增的指纹」（diff.added）：
    - 无新增 → 不投递（no-op，仅日志一行）；
    - 指纹未变但内容变化（严重度升级/证据变化）只作为载荷里的信息项，不触发投递；
    - 基线不存在或为空 → 默认跳过（stderr 一行说明），加 --webhook-include-initial 才推送。
  两个阈值相互独立，别混用：
    --fail-on             控制**退出码**（严格阈值：无变化=0；新增 high 且 --fail-on high → 1）
    --webhook-min-severity 控制**推不推、推哪些**（默认 medium）
  投递失败不会改变扫描退出码与既有产物：错误写 stderr，
  投递结果写 <--out>/webhook-delivery.json。
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
    '--webhook',
    '--webhook-secret',
    '--webhook-min-severity',
    '--webhook-timeout',
    '--webhook-deadline',
  ]);
  /* 值可省略的选项：单独出现时按 true 处理（使用默认路径） */
  const optionalValue = new Set(['--sarif']);

  for (let i = 0; i < argv.length; i++) {
    const token = argv[i];
    if (takesValue.has(token)) {
      const value = argv[i + 1];
      if (!value || value.startsWith('--')) {
        throw new Error(`${token} 需要一个值`);
      }
      args[token.slice(2)] = value;
      i++;
    } else if (optionalValue.has(token)) {
      const value = argv[i + 1];
      if (value && !value.startsWith('--')) {
        args[token.slice(2)] = value;
        i++;
      } else {
        args[token.slice(2)] = true;
      }
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

  /* ---- 0. Webhook 配置（提前解析：配置类错误要在扫描前暴露，而不是扫完一轮才报）----
     注意：投递地址由使用者显式配置，因此不受 Scope Gate 约束（它指的是"把告警发去哪"，
     不是"扫什么"）；扫描目标本身仍然一律经过 Scope Gate。 */
  const webhook = resolveWebhookConfig({ args, env: process.env });
  if (!webhook && (args['webhook-secret'] || process.env[ENV_WEBHOOK_SECRET])) {
    console.error(
      `⚠️ 配置了 Webhook 密钥但没有投递地址（--webhook / ${ENV_WEBHOOK_URL}），本次不会投递告警。`
    );
  }
  if (webhook) {
    log(
      `🔔 Webhook：${redactUrl(webhook.url)}` +
        `${webhook.secret ? '（已启用 HMAC-SHA256 签名）' : '（未签名）'}` +
        ` · 阈值 ${webhook.minSeverity}` +
        ` · 单次空闲超时 ${webhook.timeoutMs}ms · 整体截止 ${webhook.deadlineMs}ms`
    );
  }

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

  /* ---- 3. 与基线比对 ----
     「什么算变化」的判据只有一处：lib/changeset.mjs（CLI 门禁 / Webhook / CI 都消费它）。
     本文件不再自己挑 diff 的子集来判定。 */
  const baselineData = readJsonIfExists(baselinePath);
  const baseline = baselineData && Array.isArray(baselineData.findings) ? baselineData.findings : [];
  const changeset = buildChangeset({
    findings,
    baseline,
    /* 只在本次扫描的资产范围内比对，避免部分扫描时产生"已修复"假警报 */
    assets: scope.assets.map((a) => a.domain),
  });
  const baselineEstablished = changeset.baselineEstablished;

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

  const markdown = renderMarkdown({ scope, findings, changeset, meta });
  const json = renderJson({ scope, findings, changeset, meta });
  json.observations = observations;

  const reportPath = join(outDir, 'report.md');
  const jsonPath = join(outDir, 'findings.json');
  writeFileSync(reportPath, markdown, 'utf8');
  writeFileSync(jsonPath, JSON.stringify(json, null, 2), 'utf8');

  /* ---- SARIF 输出（供 GitHub Code Scanning 消费）---- */
  let sarifPath = null;
  if (args.sarif) {
    sarifPath = typeof args.sarif === 'string' ? args.sarif : join(outDir, 'results.sarif');
    const sarif = toSarif({
      findings,
      scannedAssets: scope.assets.map((a) => a.domain),
      meta,
      changeset,
    });

    /* 自校验：SARIF 结构错误会让 GitHub 直接拒绝上传，与其在 CI 里报错，不如在这里拦住 */
    const check = validateSarif(sarif);
    if (!check.ok) {
      console.error('\n🛑 生成的 SARIF 未通过结构校验：');
      for (const p of check.problems) console.error(`   - ${p}`);
      return 2;
    }

    mkdirSync(dirname(sarifPath), { recursive: true });
    writeFileSync(sarifPath, JSON.stringify(sarif, null, 2), 'utf8');
  }

  /* ---- 5. 打印摘要 ---- */
  console.log('');
  console.log(renderSummary({ findings, changeset, meta }));
  console.log('');
  log(`📄 报告：${reportPath}`);
  log(`🧾 数据：${jsonPath}`);
  if (sarifPath) log(`🔒 SARIF：${sarifPath}（可上传至 GitHub Code Scanning）`);

  /* ---- 6. Webhook 告警投递（仅"新增指纹"时投递；失败不影响扫描结果与退出码）---- */
  if (webhook) {
    const includeInitial = Boolean(args['webhook-include-initial']);
    const plan = planDelivery({
      /* 触发集合从单一变化源来：changeset.added（不再由本文件自己挑 diff 的子集） */
      changeset,
      minSeverity: webhook.minSeverity,
      includeInitial,
    });
    const recordPath = join(outDir, 'webhook-delivery.json');

    if (!plan.triggered) {
      /* no-op：一次网络请求都不发。记录文件同步刷新，
         避免上一次运行留下的失败记录被误读成本次结果。 */
      if (plan.reason === 'baseline-establishment') {
        /* 首次运行必须静默：基线缺失时"全部发现都是新增"是假象。
           这一行写 stderr，因为它是"为什么没收到告警"的答案，CI 日志里不该被 quiet 吞掉。 */
        console.error(
          `⏭️ 基线不存在或为空（${existsSync(baselinePath) ? baselinePath : `${baselinePath} 不存在`}），` +
            `跳过 Webhook 投递（首次运行不告警；确需推送首轮全量请加 --webhook-include-initial）`
        );
      } else {
        const detail =
          plan.reason === 'below-threshold'
            ? `有新增指纹但均低于阈值 ${webhook.minSeverity}（新增 ${plan.summary.new + plan.summary.ignored.new} 条）`
            : '本次无新增指纹（diff.added 为空）';
        log(`⏭️ Webhook 未投递（no-op）：${detail}`);
      }

      writeDeliveryRecord(
        outDir,
        buildNoDeliveryRecord({
          url: webhook.url,
          secret: webhook.secret,
          minSeverity: webhook.minSeverity,
          reason: plan.reason,
          summary: plan.summary,
          deadlineMs: webhook.deadlineMs,
        })
      );
    } else {
      const payload = buildPayload({
        version: VERSION,
        scope,
        plan,
        minSeverity: webhook.minSeverity,
        signed: Boolean(webhook.secret),
        initial: baselineEstablished,
      });

      log(
        `🔔 投递 Webhook 告警：新增 ${plan.summary.new}` +
          `${baselineEstablished ? '（首轮全量，--webhook-include-initial）' : ''}`
      );

      const result = await deliverWebhook({
        url: webhook.url,
        secret: webhook.secret,
        body: JSON.stringify(payload),
        timeoutMs: webhook.timeoutMs,
        deadlineMs: webhook.deadlineMs,
        log,
      });

      writeDeliveryRecord(
        outDir,
        buildDeliveryRecord({
          url: webhook.url,
          secret: webhook.secret,
          minSeverity: webhook.minSeverity,
          summary: plan.summary,
          result,
          initial: baselineEstablished,
        })
      );

      if (result.ok) {
        log(
          `✅ Webhook 已投递：HTTP ${result.statusCode}（尝试 ${result.attempts} 次，${result.durationMs}ms）`
        );
      } else {
        /* 明确报错，但**不改变**退出码：告警通道坏掉不该让监控本身也失败 */
        console.error(`⚠️ Webhook 投递失败（不影响本次扫描结果）：${result.error}（尝试 ${result.attempts} 次）`);
        if (result.deadlineExceeded) {
          console.error(
            `   原因：投递整体截止时间 ${result.deadlineMs}ms 已到（可用 --webhook-deadline 调整）；` +
              `扫描产物与退出码不受影响。`
          );
        }
        console.error(`   投递记录：${recordPath}`);
      }
    }
  }

  /* ---- 7. 更新基线 ---- */
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

  /* ---- 8. 门禁判定（只看单一变化源的 added，语义与改造前逐字相同）---- */
  if (failOn && hasAddedAtOrAbove(changeset, failOn)) {
    const top = triggerFindings(changeset)
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
