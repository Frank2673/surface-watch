/**
 * Webhook 告警投递测试
 *
 * 重点验证四件事（都是"看上去能跑、实际会坏"的地方）：
 *   1. 触发语义：触发集合严格等于 diff.added（新增指纹）；
 *      无新增不投递、低于阈值不投递、基线缺失默认静默；
 *      指纹未变但内容变化只作信息项，不触发
 *   2. 载荷契约：必备字段齐全、带指纹、不含任何凭据
 *   3. 失败语义：网络错误与 5xx 重试、4xx 与 3xx 不重试、任何失败都不 reject，
 *      以及**两层超时**互不混淆（单次空闲 TIMEOUT vs 整体 DEADLINE_EXCEEDED）
 *   4. 签名：与独立复算的 HMAC-SHA256 完全一致（接收端可自行验签）
 *
 * 全部离线：测试里自己起一个 127.0.0.1 上的临时 HTTP 服务，不访问外部网络。
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createHash, createHmac } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { createFinding } from '../src/lib/findings.mjs';
import {
  DEFAULT_MIN_SEVERITY,
  DEFAULT_WEBHOOK_DEADLINE_FLOOR_MS,
  DEFAULT_WEBHOOK_TIMEOUT_MS,
  DEADLINE_EXCEEDED,
  SIGNATURE_HEADER,
  buildDeliveryRecord,
  buildNoDeliveryRecord,
  buildPayload,
  defaultWebhookDeadlineMs,
  deliverWebhook,
  detectChangedFindings,
  hashUrl,
  planDelivery,
  redactUrl,
  resolveWebhookConfig,
  signBody,
  writeDeliveryRecord,
} from '../src/lib/notify.mjs';

const silent = () => {};

/* ---------------- 工具 ---------------- */

function makeFinding(overrides = {}) {
  return createFinding({
    asset: 'example.com',
    check: 'headers',
    key: 'missing-hsts',
    severity: 'medium',
    title: '缺少 HSTS 响应头',
    evidence: 'strict-transport-security 未出现',
    impact: '影响说明',
    remediation: '修复建议',
    ...overrides,
  });
}

function makeScope() {
  return {
    owner: 'example-owner',
    assets: [{ domain: 'example.com' }, { domain: 'www.example.com' }],
    authorization: { statement: '仅对已声明资产做被动检查' },
  };
}

/** 在 127.0.0.1 上起一个临时服务，跑完自动关闭 */
async function withServer(handler, fn) {
  const server = http.createServer(handler);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  try {
    return await fn({ port, url: `http://127.0.0.1:${port}/hook` });
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

/** 收集请求体与请求头，并按要求的状态码应答 */
function collector({ statusCode = 200, delayMs = 0, headers = {} } = {}) {
  const seen = [];
  const handler = (req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const raw = Buffer.concat(chunks);
      seen.push({ headers: req.headers, raw, text: raw.toString('utf8') });
      const respond = () => {
        res.writeHead(statusCode, { 'Content-Type': 'application/json', ...headers });
        res.end(JSON.stringify({ ok: statusCode < 400 }));
      };
      if (delayMs > 0) setTimeout(respond, delayMs);
      else respond();
    });
  };
  return { seen, handler };
}

/**
 * 慢速接收端（slow-loris）：收到请求后回 `200 OK` + chunked，
 * 之后每 `intervalMs` 只发 1 字节且**永不结束**。
 *
 * 关键性质：socket 一直"有数据"，所以挂在 socket 上的**空闲超时永不触发** ——
 * 只有覆盖总时长的整体截止时间能把它掐断（这正是缺陷 1 的复现条件）。
 */
function slowLorisCollector({ intervalMs = 100 } = {}) {
  return (req, res) => {
    req.resume();
    req.on('error', () => {});
    res.on('error', () => {});
    req.on('end', () => {
      res.writeHead(200, { 'Content-Type': 'text/plain', 'Transfer-Encoding': 'chunked' });
      res.write('x');
      const timer = setInterval(() => res.write('y'), intervalMs);
      timer.unref?.();
      res.on('close', () => clearInterval(timer));
    });
  };
}

/** 指定状态码 + 固定字节数的响应体（用于 errorBody 截断验证） */
function fixedBodyCollector({ statusCode = 502, body }) {
  return (req, res) => {
    req.resume();
    req.on('error', () => {});
    res.on('error', () => {});
    req.on('end', () => {
      res.writeHead(statusCode, {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
      });
      res.end(body);
    });
  };
}

/* ---------------- 1. 配置解析 ---------------- */

test('未配置 Webhook 时返回 null（完全跳过投递）', () => {
  assert.equal(resolveWebhookConfig({ args: {}, env: {} }), null);
});

test('CLI 参数优先，环境变量回退', () => {
  const fromArgs = resolveWebhookConfig({
    args: { webhook: 'http://127.0.0.1:8787/hook' },
    env: { SURFACE_WATCH_WEBHOOK_URL: 'http://127.0.0.1:9999/other' },
  });
  assert.equal(fromArgs.url, 'http://127.0.0.1:8787/hook');
  assert.equal(fromArgs.minSeverity, DEFAULT_MIN_SEVERITY);
  assert.equal(fromArgs.timeoutMs, DEFAULT_WEBHOOK_TIMEOUT_MS);
  assert.equal(
    fromArgs.deadlineMs,
    defaultWebhookDeadlineMs(DEFAULT_WEBHOOK_TIMEOUT_MS),
    '缺省整体截止时间由单次超时推导'
  );

  const fromEnv = resolveWebhookConfig({
    args: {},
    env: {
      SURFACE_WATCH_WEBHOOK_URL: 'https://hooks.example.invalid/x',
      SURFACE_WATCH_WEBHOOK_SECRET: 'env-secret',
    },
  });
  assert.equal(fromEnv.url, 'https://hooks.example.invalid/x');
  assert.equal(fromEnv.secret, 'env-secret');
});

test('整体截止时间默认 = max(10s, 3 × 单次空闲超时)', () => {
  assert.equal(defaultWebhookDeadlineMs(1500), DEFAULT_WEBHOOK_DEADLINE_FLOOR_MS);
  assert.equal(defaultWebhookDeadlineMs(1500), 10000, '1.5s × 3 低于下限，取下限');
  assert.equal(defaultWebhookDeadlineMs(5000), 15000, '5s × 3 高于下限');
  assert.equal(defaultWebhookDeadlineMs(100000), 300000);
});

test('显式 --webhook-deadline 覆盖默认值，且允许小于单次超时', () => {
  const cfg = resolveWebhookConfig({
    args: {
      webhook: 'http://127.0.0.1:8787/hook',
      'webhook-timeout': '1500',
      'webhook-deadline': '2500',
    },
    env: {},
  });
  assert.equal(cfg.timeoutMs, 1500);
  assert.equal(cfg.deadlineMs, 2500);

  /* 显式把总预算压到比单次空闲超时还小：允许，运行时按剩余预算夹住单次超时 */
  const tight = resolveWebhookConfig({
    args: {
      webhook: 'http://127.0.0.1:8787/hook',
      'webhook-timeout': '9000',
      'webhook-deadline': '300',
    },
    env: {},
  });
  assert.equal(tight.deadlineMs, 300);
});

test('非 http/https 协议被拒绝', () => {
  assert.throws(() => resolveWebhookConfig({ args: { webhook: 'file:///etc/passwd' }, env: {} }), /只支持 http\/https/);
  assert.throws(() => resolveWebhookConfig({ args: { webhook: 'not a url' }, env: {} }), /不是合法 URL/);
});

test('阈值与超时参数非法时报错', () => {
  const base = { webhook: 'http://127.0.0.1:8787/hook' };
  assert.throws(
    () => resolveWebhookConfig({ args: { ...base, 'webhook-min-severity': 'blocker' }, env: {} }),
    /webhook-min-severity 取值非法/
  );
  assert.throws(
    () => resolveWebhookConfig({ args: { ...base, 'webhook-timeout': '0' }, env: {} }),
    /webhook-timeout 需要正整数/
  );
  assert.throws(
    () => resolveWebhookConfig({ args: { ...base, 'webhook-deadline': '0' }, env: {} }),
    /webhook-deadline 需要正整数/
  );
  assert.throws(
    () => resolveWebhookConfig({ args: { ...base, 'webhook-deadline': 'soon' }, env: {} }),
    /webhook-deadline 需要正整数/
  );
});

/* ---------------- 2. 触发语义 ---------------- */

test('无新增指纹 → 不投递（no-op）', () => {
  const f = makeFinding();
  const diff = { added: [], resolved: [], persistent: [{ ...f, firstSeen: '2026-01-01T00:00:00.000Z' }] };
  const plan = planDelivery({ diff, baseline: [f], minSeverity: 'medium' });
  assert.equal(plan.triggered, false);
  assert.equal(plan.reason, 'no-change');
  assert.equal(plan.findings.length, 0);
});

test('持续存在的条数变化不触发投递（禁止用"数量变化"做触发）', () => {
  const a = makeFinding({ key: 'k1' });
  const b = makeFinding({ key: 'k2', severity: 'critical' });
  const plan = planDelivery({
    diff: { added: [], resolved: [], persistent: [a, b] },
    baseline: [a, b],
    minSeverity: 'info',
  });
  assert.equal(plan.triggered, false);
  assert.equal(plan.reason, 'no-change');
});

test('有达到阈值的新增 → 投递，findings 标记 change=new 并带指纹', () => {
  const f = makeFinding({ severity: 'high' });
  const plan = planDelivery({ diff: { added: [f], resolved: [], persistent: [] }, minSeverity: 'medium' });
  assert.equal(plan.triggered, true);
  assert.equal(plan.summary.new, 1);
  assert.equal(plan.summary.bySeverity.high, 1);
  assert.equal(plan.findings[0].change, 'new');
  assert.equal(plan.findings[0].id, f.id);
  assert.equal(plan.findings[0].fingerprint, f.id, '载荷必须带指纹供下游去重');
  assert.equal(plan.findings[0].fingerprint, 'headers:missing-hsts:example.com');
});

test('有变化但均低于阈值 → 不投递，并记录被忽略的数量', () => {
  const info = makeFinding({ severity: 'info', key: 'server-header' });
  const plan = planDelivery({ diff: { added: [info], resolved: [], persistent: [] }, minSeverity: 'medium' });
  assert.equal(plan.triggered, false);
  assert.equal(plan.reason, 'below-threshold');
  assert.equal(plan.summary.ignored.new, 1);
});

test('阈值放宽到 info 时，信息级新增也会投递', () => {
  const info = makeFinding({ severity: 'info', key: 'server-header' });
  const plan = planDelivery({ diff: { added: [info], resolved: [], persistent: [] }, minSeverity: 'info' });
  assert.equal(plan.triggered, true);
  assert.equal(plan.summary.new, 1);
});

test('指纹未变但严重度升级 → 记为信息项 changed，但**不触发投递**', () => {
  const before = makeFinding({ severity: 'low' });
  const after = makeFinding({ severity: 'high' });
  assert.equal(before.id, after.id, '指纹应保持稳定');

  const changed = detectChangedFindings({ persistent: [after] }, [before]);
  assert.equal(changed.length, 1);
  assert.deepEqual(changed[0].changedFields, ['severity']);

  const plan = planDelivery({
    diff: { added: [], resolved: [], persistent: [after] },
    baseline: [before],
    minSeverity: 'medium',
  });
  assert.equal(plan.triggered, false, '触发集合严格等于 diff.added，persistent 内容变化不触发');
  assert.equal(plan.reason, 'no-change');
  assert.equal(plan.summary.changed, 1);
  assert.equal(plan.informationalChanged[0].previousSeverity, 'low');
  assert.deepEqual(plan.informationalChanged[0].changedFields, ['severity']);
  assert.equal(plan.informationalChanged[0].fingerprint, after.id);
});

test('指纹未变但证据变化 → 只记信息项，不触发投递', () => {
  const before = makeFinding({ evidence: '证书 30 天后过期' });
  const after = makeFinding({ evidence: '证书 7 天后过期' });
  const plan = planDelivery({
    diff: { added: [], resolved: [], persistent: [after] },
    baseline: [before],
    minSeverity: 'medium',
  });
  assert.equal(plan.triggered, false);
  assert.equal(plan.summary.changed, 1);
  assert.deepEqual(plan.informationalChanged[0].changedFields, ['evidence']);
});

test('基线缺失（首次运行）→ 默认 no-op，理由为 baseline-establishment', () => {
  const f = makeFinding({ severity: 'critical' });
  const plan = planDelivery({
    diff: { added: [f, makeFinding({ key: 'other', severity: 'high' })], resolved: [], persistent: [] },
    baseline: [],
    minSeverity: 'medium',
    baselineEstablished: true,
  });
  assert.equal(plan.triggered, false, '基线缺失时全量"新增"是假象，不能告警');
  assert.equal(plan.reason, 'baseline-establishment');
  assert.equal(plan.findings.length, 0);
});

test('基线缺失 + --webhook-include-initial → 允许推送首轮全量', () => {
  const f = makeFinding({ severity: 'critical' });
  const plan = planDelivery({
    diff: { added: [f], resolved: [], persistent: [] },
    baseline: [],
    minSeverity: 'medium',
    baselineEstablished: true,
    includeInitial: true,
  });
  assert.equal(plan.triggered, true);
  assert.equal(plan.summary.new, 1);
});

/* ---------------- 3. 载荷契约 ---------------- */

test('载荷包含契约要求的字段，且不含密钥', () => {
  const f = makeFinding({ severity: 'high' });
  const plan = planDelivery({ diff: { added: [f], resolved: [], persistent: [] }, minSeverity: 'medium' });
  const payload = buildPayload({
    version: '0.1.0',
    scope: makeScope(),
    plan,
    minSeverity: 'medium',
    signed: true,
  });

  assert.equal(payload.tool, 'surface-watch');
  assert.equal(payload.version, '0.1.0');
  assert.ok(typeof payload.generatedAt === 'string' && payload.generatedAt.length > 0);
  assert.deepEqual(payload.scope.assets, ['example.com', 'www.example.com']);
  assert.deepEqual(Object.keys(payload.summary).sort(), [
    'bySeverity',
    'changed',
    'ignored',
    'new',
    'removed',
  ]);
  assert.deepEqual(Object.keys(payload.summary.bySeverity).sort(), [
    'critical',
    'high',
    'info',
    'low',
    'medium',
  ]);
  assert.equal(payload.findings.length, 1);
  assert.equal(payload.delivery.threshold, 'medium');
  assert.equal(payload.delivery.triggerSet, 'diff.added');
  assert.equal(payload.delivery.changedIsInformational, true);
  assert.deepEqual(payload.delivery.triggeredBy, ['new']);

  const serialized = JSON.stringify(payload);
  assert.equal(serialized.includes('super-secret-value'), false, '载荷不得包含密钥明文');
});

test('首轮全量载荷标记 initial=true，且每条 finding 都带指纹', () => {
  const f = makeFinding({ severity: 'critical' });
  const plan = planDelivery({
    diff: { added: [f], resolved: [], persistent: [] },
    baselineEstablished: true,
    includeInitial: true,
  });
  const payload = buildPayload({ version: '0.1.0', scope: makeScope(), plan, initial: true });
  assert.equal(payload.delivery.initial, true);
  assert.equal(payload.findings[0].fingerprint, f.id);
});

test('超长证据在载荷中被截断（避免撑爆接收端）', () => {
  const f = makeFinding({ evidence: 'x'.repeat(5000) });
  const plan = planDelivery({ diff: { added: [f], resolved: [], persistent: [] }, minSeverity: 'medium' });
  const payload = buildPayload({ version: '0.1.0', scope: makeScope(), plan });
  assert.ok(payload.findings[0].evidence.length < 1100);
  assert.match(payload.findings[0].evidence, /已截断/);
});

/* ---------------- 4. 签名 ---------------- */

test('签名与独立复算的 HMAC-SHA256 一致', () => {
  const body = JSON.stringify({ hello: '世界' });
  const secret = 'super-secret-value';
  const signature = signBody(body, secret);

  const independent = `sha256=${createHmac('sha256', secret).update(Buffer.from(body, 'utf8')).digest('hex')}`;
  assert.equal(signature, independent);
  assert.match(signature, /^sha256=[0-9a-f]{64}$/);
});

test('投递时带签名头，接收端可独立复算通过', async () => {
  const secret = 'shared-secret-123';
  const { seen, handler } = collector();
  await withServer(handler, async ({ url }) => {
    const body = JSON.stringify({ tool: 'surface-watch' });
    const result = await deliverWebhook({ url, secret, body, log: silent });
    assert.equal(result.ok, true);
    assert.equal(result.signed, true);

    assert.equal(seen.length, 1);
    /* Node 收到的请求头名一律小写 */
    const header = seen[0].headers[SIGNATURE_HEADER.toLowerCase()];
    assert.ok(header, `应带 ${SIGNATURE_HEADER} 请求头`);
    const recomputed = `sha256=${createHmac('sha256', secret).update(seen[0].raw).digest('hex')}`;
    assert.equal(header, recomputed, '接收端独立复算应一致');
    assert.deepEqual(seen[0].raw, Buffer.from(body, 'utf8'), '发出的字节应与签名覆盖的字节完全相同');
  });
});

test('未配置密钥时不发送签名头', async () => {
  const { seen, handler } = collector();
  await withServer(handler, async ({ url }) => {
    const result = await deliverWebhook({ url, body: '{}', secret: null, log: silent });
    assert.equal(result.ok, true);
    assert.equal(seen[0].headers[SIGNATURE_HEADER.toLowerCase()], undefined);
    assert.equal(result.signed, false);
  });
});

/* ---------------- 5. 失败语义与重试 ---------------- */

test('2xx：一次成功，attempts=1，Content-Type 为 application/json', async () => {
  const { seen, handler } = collector({ statusCode: 202 });
  await withServer(handler, async ({ url }) => {
    const result = await deliverWebhook({ url, body: '{"a":1}', log: silent, backoffMs: 1 });
    assert.equal(result.ok, true);
    assert.equal(result.statusCode, 202);
    assert.equal(result.attempts, 1);
    assert.equal(result.error, null);
    assert.equal(seen[0].headers['content-type'], 'application/json');
    assert.equal(seen[0].headers['content-length'], '7');
  });
});

test('持续 5xx：重试到上限（1+2=3 次）后失败，但不抛异常', async () => {
  const { seen, handler } = collector({ statusCode: 500 });
  await withServer(handler, async ({ url }) => {
    const result = await deliverWebhook({ url, body: '{}', log: silent, backoffMs: 1 });
    assert.equal(result.ok, false);
    assert.equal(result.statusCode, 500);
    assert.equal(result.attempts, 3);
    assert.match(result.error, /HTTP 500/);
    assert.equal(result.attemptLog.length, 3);
    assert.equal(result.attemptLog.every((a) => a.retryable), true);
    assert.equal(seen.length, 3);
  });
});

test('一次 5xx 后恢复：第 2 次投递成功', async () => {
  let count = 0;
  const handler = (req, res) => {
    req.resume();
    req.on('end', () => {
      count++;
      const statusCode = count === 1 ? 500 : 200;
      res.writeHead(statusCode, { 'Content-Type': 'application/json' });
      res.end('{}');
    });
  };
  await withServer(handler, async ({ url }) => {
    const result = await deliverWebhook({ url, body: '{}', log: silent, backoffMs: 1 });
    assert.equal(result.ok, true);
    assert.equal(result.attempts, 2);
    assert.equal(count, 2);
  });
});

test('4xx：不重试', async () => {
  const { seen, handler } = collector({ statusCode: 400 });
  await withServer(handler, async ({ url }) => {
    const result = await deliverWebhook({ url, body: '{}', log: silent, backoffMs: 1 });
    assert.equal(result.ok, false);
    assert.equal(result.statusCode, 400);
    assert.equal(result.attempts, 1);
    assert.equal(result.attemptLog[0].retryable, false);
    assert.equal(seen.length, 1);
  });
});

test('3xx：不跟随重定向，按失败处理且不重试', async () => {
  const { seen, handler } = collector({ statusCode: 302, headers: { Location: 'http://127.0.0.1:1/evil' } });
  await withServer(handler, async ({ url }) => {
    const result = await deliverWebhook({ url, body: '{}', log: silent, backoffMs: 1 });
    assert.equal(result.ok, false);
    assert.equal(result.statusCode, 302);
    assert.equal(result.attempts, 1);
    assert.match(result.error, /重定向/);
    assert.equal(seen.length, 1, '不应把载荷转发到 Location 指向的地址');
  });
});

test('连接被拒：网络错误重试到上限，错误码可见', async () => {
  /* 先占一个端口再关掉，确保该端口必然拒绝连接 */
  const server = http.createServer(() => {});
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  await new Promise((resolve) => server.close(resolve));

  const result = await deliverWebhook({
    url: `http://127.0.0.1:${port}/hook`,
    body: '{}',
    log: silent,
    backoffMs: 1,
    timeoutMs: 500,
  });
  assert.equal(result.ok, false);
  assert.equal(result.statusCode, null);
  assert.equal(result.attempts, 3);
  assert.match(result.error, /ECONNREFUSED/);
});

test('超时：按网络错误重试到上限', async () => {
  const { handler } = collector({ delayMs: 300 });
  await withServer(handler, async ({ url }) => {
    const result = await deliverWebhook({
      url,
      body: '{}',
      log: silent,
      backoffMs: 1,
      timeoutMs: 60,
    });
    assert.equal(result.ok, false);
    assert.equal(result.attempts, 3);
    assert.match(result.error, /TIMEOUT/);
    /* 两层不混淆：这是一次真实的空闲超时，不是整体截止时间 */
    assert.equal(result.deadlineExceeded, false);
    assert.equal(result.error.includes(DEADLINE_EXCEEDED), false, '单次空闲超时不得报成 DEADLINE_EXCEEDED');
    assert.equal(result.attemptLog[0].error.startsWith('DEADLINE_EXCEEDED'), false);
  });
});

/* ---------------- 5b. 整体截止时间（两层超时里的第二层） ---------------- */

test('slow-loris 接收端：整体截止时间到点即有界失败，不再无限挂死', async () => {
  await withServer(slowLorisCollector({ intervalMs: 100 }), async ({ url }) => {
    const t0 = Date.now();
    const result = await deliverWebhook({
      url,
      body: '{}',
      log: silent,
      backoffMs: 1,
      /* 单次空闲超时：slow-loris 下 socket 一直有数据 → 永远不会触发 */
      timeoutMs: 250,
      /* 整体截止时间：真正的上界 */
      deadlineMs: 1200,
    });
    const elapsed = Date.now() - t0;

    assert.equal(result.ok, false, '整体截止必须判失败');
    assert.equal(result.deadlineExceeded, true);
    assert.equal(result.deadlineMs, 1200);
    assert.match(result.error, /^DEADLINE_EXCEEDED/, '错误必须能与 per-attempt TIMEOUT 区分');
    assert.equal(result.attempts, 1, '预算耗尽后不再重试；attempts 只计真实发生的尝试');
    assert.equal(result.error.includes('实际尝试 1 次'), true);
    assert.equal(result.attemptLog[0].retryable, false, '截止时间不是可重试错误');
    assert.ok(elapsed < 4000, `必须在有界时间内返回，实测 ${elapsed}ms`);
  });
});

test('缺省整体截止时间同样能掐断 slow-loris（不传 deadlineMs 时不再挂死）', async () => {
  await withServer(slowLorisCollector({ intervalMs: 100 }), async ({ url }) => {
    const t0 = Date.now();
    const result = await deliverWebhook({
      url,
      body: '{}',
      log: silent,
      backoffMs: 1,
      timeoutMs: 150,
      /* 缺省 = max(10_000, 3 × 150) = 10_000ms —— 缺陷 1 里正是这个缺省缺失导致挂死 */
      deadlineMs: undefined,
    });
    const elapsed = Date.now() - t0;
    assert.equal(result.deadlineMs, defaultWebhookDeadlineMs(150));
    assert.equal(result.deadlineExceeded, true);
    assert.equal(result.ok, false);
    assert.match(result.error, /^DEADLINE_EXCEEDED/);
    /* 有界：10s 预算 + 少量调度余量，远低于"永不返回" */
    assert.ok(elapsed < 14000, `实测 ${elapsed}ms（缺省预算 ${result.deadlineMs}ms）`);
  });
});

test('整体预算小于单次空闲超时时，整体语义优先（不报成 TIMEOUT）', async () => {
  /* 接收端完全不响应：按"单次空闲超时"口径应当报 TIMEOUT，
     但本次尝试的剩余预算已被截止时间夹住，因此整体语义优先 */
  const { handler } = collector({ delayMs: 5000 });
  await withServer(handler, async ({ url }) => {
    const t0 = Date.now();
    const result = await deliverWebhook({
      url,
      body: '{}',
      log: silent,
      backoffMs: 1,
      timeoutMs: 5000,
      deadlineMs: 250,
    });
    const elapsed = Date.now() - t0;
    assert.equal(result.ok, false);
    assert.equal(result.deadlineExceeded, true);
    assert.match(result.error, /^DEADLINE_EXCEEDED/);
    assert.equal(result.attempts, 1);
    assert.ok(elapsed < 3000, `实测 ${elapsed}ms`);
  });
});

test('成功投递不受整体截止时间影响（deadlineExceeded 保持 false）', async () => {
  const { handler } = collector({ statusCode: 200 });
  await withServer(handler, async ({ url }) => {
    const result = await deliverWebhook({ url, body: '{}', log: silent, deadlineMs: 5000 });
    assert.equal(result.ok, true);
    assert.equal(result.deadlineExceeded, false);
    assert.equal(result.deadlineMs, 5000);
    assert.equal(result.attempts, 1);
  });
});

/* ---------------- 5c. errorBody 按字节截断 ---------------- */

test('460 字节的 502 响应体：errorBody 不再是空串，而是前 200 字节 + 截断标注', async () => {
  const prefix = '{"error":"upstream boom","pad":"';
  const suffix = '"}';
  const body460 = `${prefix}${'P'.repeat(
    460 - Buffer.byteLength(prefix) - Buffer.byteLength(suffix)
  )}${suffix}`;
  assert.equal(Buffer.byteLength(body460, 'utf8'), 460, '测试前置：响应体恰为 460 字节');

  await withServer(fixedBodyCollector({ statusCode: 502, body: body460 }), async ({ url }) => {
    const result = await deliverWebhook({ url, body: '{}', log: silent, backoffMs: 1 });

    assert.equal(result.ok, false);
    assert.equal(result.statusCode, 502);
    assert.equal(result.attempts, 3, '5xx 仍按既有语义重试到上限');

    for (const entry of result.attemptLog) {
      assert.ok(entry.errorBody, 'errorBody 不得为空串（缺陷 2 的原始症状）');
      assert.match(entry.errorBody, /已截断：响应体共 460 字节，仅保留前 200 字节/);
      const retained = entry.errorBody.split('…（已截断')[0];
      assert.equal(Buffer.byteLength(retained, 'utf8'), 200, '保留的必须是 200 字节');
      assert.equal(retained.startsWith('{"error":"upstream boom"'), true);
    }
  });
});

test('多字节响应体：按字节而非字符截断', async () => {
  const body = '中'.repeat(400); /* 3 字节/字符 → 共 1200 字节 */
  assert.equal(Buffer.byteLength(body, 'utf8'), 1200);

  await withServer(fixedBodyCollector({ statusCode: 500, body }), async ({ url }) => {
    const result = await deliverWebhook({ url, body: '{}', log: silent, backoffMs: 1 });
    const retained = result.attemptLog[0].errorBody.split('…（已截断')[0];
    /* 200 字节的截断点落在第 67 个字符（汉字 3 字节）中间：
       得到 66 个完整汉字（198 字节）+ 1 个替换符（U+FFFD）。
       关键判据：**字符数是 67，不是 200** —— 按字符截断会留下 200 个汉字（600 字节）。 */
    const completeChars = retained.replace(/\uFFFD$/u, '');
    assert.equal(completeChars.length, 66);
    assert.equal(Buffer.byteLength(completeChars, 'utf8'), 198);
    assert.equal(retained.length, 67, '字符数 67 ≠ 200：证明截断按字节生效');
    assert.equal(retained.endsWith('\uFFFD'), true, '切在多字节字符中间 → 末尾一个替换符');
    assert.match(result.attemptLog[0].errorBody, /共 1200 字节/);
  });
});

test('响应体小于上限时原样保留，不加截断标注', async () => {
  const body = JSON.stringify({ error: 'boom' });
  await withServer(fixedBodyCollector({ statusCode: 404, body }), async ({ url }) => {
    const result = await deliverWebhook({ url, body: '{}', log: silent, backoffMs: 1 });
    assert.equal(result.attempts, 1, '4xx 不重试（既有语义不变）');
    assert.equal(result.attemptLog[0].errorBody, body, '未超限时不得改写响应体');
    assert.equal(result.attemptLog[0].errorBody.includes('已截断'), false);
  });
});

/* ---------------- 6. 投递记录 ---------------- */

test('投递记录包含 ok/statusCode/attempts/error，且 URL 查询串已脱敏', async () => {
  const { handler } = collector({ statusCode: 503 });
  await withServer(handler, async ({ port }) => {
    const url = `http://127.0.0.1:${port}/hook?token=super-secret-value`;
    const result = await deliverWebhook({ url, body: '{}', log: silent, backoffMs: 1 });
    const record = buildDeliveryRecord({
      url,
      secret: 'super-secret-value',
      minSeverity: 'medium',
      summary: { new: 1, changed: 0, removed: 0, bySeverity: {}, ignored: { new: 0, changed: 0 } },
      result,
    });

    assert.equal(record.ok, false);
    assert.equal(record.triggered, true);
    assert.equal(record.delivered, false);
    assert.equal(record.statusCode, 503);
    assert.equal(record.attempts, 3);
    assert.match(record.error, /HTTP 503/);
    assert.match(record.url, /token=\*\*\*/);

    const serialized = JSON.stringify(record);
    assert.equal(serialized.includes('super-secret-value'), false, '投递记录不得泄露密钥或 URL 凭据');
  });
});

test('投递记录区分 DEADLINE_EXCEEDED 与 TIMEOUT，并带上两层超时预算', async () => {
  const summary = { new: 1, changed: 0, removed: 0, bySeverity: {}, ignored: { new: 0, changed: 0 } };

  /* (a) 整体截止时间：deadlineExceeded=true，错误前缀可 grep */
  await withServer(slowLorisCollector({ intervalMs: 100 }), async ({ url }) => {
    const result = await deliverWebhook({
      url,
      body: '{}',
      log: silent,
      backoffMs: 1,
      timeoutMs: 200,
      deadlineMs: 1000,
    });
    const record = buildDeliveryRecord({ url, secret: null, minSeverity: 'medium', summary, result });
    assert.equal(record.ok, false);
    assert.equal(record.delivered, false);
    assert.equal(record.reason, 'delivery-failed');
    assert.equal(record.deadlineExceeded, true);
    assert.equal(record.deadlineMs, 1000);
    assert.match(record.error, /^DEADLINE_EXCEEDED/);
    assert.equal(record.attempts, result.attempts);
  });

  /* (b) 单次空闲超时：deadlineExceeded=false，错误里不得出现 DEADLINE_EXCEEDED */
  const { handler } = collector({ delayMs: 400 });
  await withServer(handler, async ({ url }) => {
    const result = await deliverWebhook({
      url,
      body: '{}',
      log: silent,
      backoffMs: 1,
      timeoutMs: 80,
    });
    const record = buildDeliveryRecord({ url, secret: null, minSeverity: 'medium', summary, result });
    assert.equal(record.deadlineExceeded, false);
    assert.match(record.error, /TIMEOUT/);
    assert.equal(record.error.includes(DEADLINE_EXCEEDED), false);
    assert.equal(record.attempts, 3);
  });
});

test('no-op 记录明确说明未投递及原因', () => {
  const record = buildNoDeliveryRecord({
    url: 'http://127.0.0.1:8787/hook',
    secret: null,
    minSeverity: 'medium',
    reason: 'no-change',
    summary: { new: 0, changed: 0, removed: 0, bySeverity: {}, ignored: { new: 0, changed: 0 } },
  });
  assert.equal(record.triggered, false);
  assert.equal(record.delivered, false);
  assert.equal(record.attempts, 0);
  assert.equal(record.error, null);
  assert.equal(record.reason, 'no-change');
});

test('writeDeliveryRecord 落盘为合法 JSON', () => {
  const base = join(process.cwd(), 'tmp');
  mkdirSync(base, { recursive: true });
  const dir = mkdtempSync(join(base, 'notify-test-'));
  try {
    const path = writeDeliveryRecord(dir, { ok: true, attempts: 1 });
    assert.equal(path, join(dir, 'webhook-delivery.json'));
    assert.deepEqual(JSON.parse(readFileSync(path, 'utf8')), { ok: true, attempts: 1 });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

/* ---------------- 7. URL 脱敏 ---------------- */

test('redactUrl 打码 query、userinfo 与动态 path 段，保留主机与结构性路径', () => {
  assert.equal(
    redactUrl('http://127.0.0.1:8787/hook'),
    'http://127.0.0.1:8787/hook'
  );
  /* 结构性段（services）保留；workspace / bot ID 这类「动态段」一律打码 ——
     不能假定某个位置上的短串「永远不是秘密」，反例见下一条用例 */
  assert.equal(
    redactUrl('https://hooks.example.com/services/T00/B00/XXXX?token=abc&foo=bar'),
    'https://hooks.example.com/services/T0***/B0***/XX***?token=***&foo=***'
  );
  assert.match(redactUrl('https://user:pass@hooks.example.com/x'), /^https:\/\/\*\*\*@hooks\.example\.com/);
  assert.equal(redactUrl('not a url'), '<非法 URL>');
});

test('redactUrl 打码 path 段里的令牌（Slack / 飞书 的凭据就在 path 上）', () => {
  /* Slack 的真实凭据是最后一段（24+ 字符），打码；
     workspace / bot ID 也不再「按长度放行」：长度不是「是不是凭据」的判据 */
  const slack = redactUrl('https://hooks.slack.com/services/T00000000/B00000000/FAKE-SLACK-TOKEN-E2E');
  assert.equal(slack, 'https://hooks.slack.com/services/T0***/B0***/FA***');
  assert.equal(slack.includes('FAKE-SLACK-TOKEN-E2E'), false);

  const feishu = redactUrl('https://open.feishu.cn/open-apis/bot/v2/hook/12345678-90ab-cdef-1234-567890abcdef');
  assert.equal(feishu.includes('12345678-90ab-cdef-1234-567890abcdef'), false);
  assert.match(feishu, /\/hook\/12\*\*\*$/);

  /* 结构性段照旧可读：排查时还能看出打到了哪个端点 */
  assert.equal(redactUrl('https://example.com/hook'), 'https://example.com/hook');
});

test('redactUrl 打码「短 path 段令牌」与「无值 query 参数」（对抗验证发现的两处泄漏面）', () => {
  /* 1) 短 path 段令牌：≤11 字符的段过去按长度原样保留，实测会把凭据写进
        stdout 与 <out>/webhook-delivery.json（CI 产物常被打包归档） */
  const short = redactUrl('http://127.0.0.1:8801/hook/AbC123');
  assert.equal(short.includes('AbC123'), false, '短 path 段令牌不得原文出现');
  assert.equal(short, 'http://127.0.0.1:8801/hook/Ab***');

  const eleven = redactUrl('http://127.0.0.1:8801/hook/AbCdEf12345');
  assert.equal(eleven.includes('AbCdEf12345'), false, '11 字符令牌不得原文出现');
  assert.equal(eleven, 'http://127.0.0.1:8801/hook/Ab***');

  /* 2) 无值 query 参数：过去只用 searchParams.keys() 取键、只对值打码，
        于是 `?BareSecret123456` 被原样写进记录的 url 字段（参数名即凭据） */
  const bare = redactUrl('http://127.0.0.1:8801/hook?BareSecret123456');
  assert.equal(bare.includes('BareSecret123456'), false, '无值 query 参数不得原文出现');
  assert.equal(bare, 'http://127.0.0.1:8801/hook?***');

  /* 3) 非白名单参数名（可被当成凭据载体）打码；白名单标签保持可读 */
  assert.equal(
    redactUrl('http://x.example.com/hook?token=abc&rand1234KEY=zzz'),
    'http://x.example.com/hook?token=***&***'
  );

  /* 4) 高熵长令牌（真实生产场景）行为不变 */
  assert.equal(
    redactUrl('https://hooks.slack.com/services/T00000000/B00000000/FAKE-SLACK-TOKEN-E2E'),
    'https://hooks.slack.com/services/T0***/B0***/FA***'
  );
});

test('hashUrl 稳定且不泄露原文，可用于跨记录关联', () => {
  const url = 'https://hooks.slack.com/services/T00000000/B00000000/FAKE-SLACK-TOKEN-E2E';
  const h = hashUrl(url);
  assert.match(h, /^sha256:[0-9a-f]{12}$/);
  assert.equal(hashUrl(url), h, '同一 URL 必须得到同一标识');
  /* 换主机 / 换结构性路径段 → 标识随之变化（关联粒度仍有可用的部分）。
     注意：只换"被脱敏的那一段"标识不变，这是有意取舍，见下条用例。 */
  assert.notEqual(hashUrl(url.replace('hooks.slack.com', 'hooks.example.com')), h);
  assert.equal(h.includes('FAKE'), false);
});

test('urlHash 对脱敏后的 URL 取哈希：旧口径的候选枚举比对 0 命中（预言机消失）', () => {
  const real = 'http://127.0.0.1:8801/hook/AbC123';
  const h = hashUrl(real);
  assert.match(h, /^sha256:[0-9a-f]{12}$/);

  /* 负向复跑（intent-4 的枚举思路）：攻击者手里只有记录里的脱敏 url
     （http://127.0.0.1:8801/hook/Ab***）与 urlHash。旧实现里 urlHash 是
     **完整 URL** 的 sha256 前 12 位，于是可以逐个候选比对；
     现在哈希对象是脱敏结果 —— 用"候选完整 URL 的哈希"去比对，连真值都对不上。 */
  const oldStyleHash = (s) =>
    `sha256:${createHash('sha256').update(s).digest('hex').slice(0, 12)}`;

  assert.notEqual(oldStyleHash(real), h, '连真值的旧口径哈希都对不上');
  const candidates = [];
  for (let i = 0; i < 200; i++) candidates.push(`cand${i}`);
  candidates.push('AbC123', 'AbC456', 'abC123', 'ABC123');
  const hits = candidates.filter(
    (c) => oldStyleHash(`http://127.0.0.1:8801/hook/${c}`) === h
  );
  assert.deepEqual(hits, [], '旧口径枚举无法命中：猜测无法被验证');
});

test('同前缀不同令牌 → 相同 urlHash（消除预言机的有意代价，粒度变粗）', () => {
  /* 副作用必须写进文档与测试注释：/hook/AbC123 与 /hook/AbC456 都脱敏为 /hook/Ab***，
     因此哈希相同 —— 跨记录关联只能到"脱敏形态"这一级，不能再证明是同一次配置。
     这是为消除凭据枚举而付的代价，属有意取舍（见 notify.mjs 的 hashUrl 注释）。 */
  assert.equal(
    hashUrl('http://127.0.0.1:8801/hook/AbC123'),
    hashUrl('http://127.0.0.1:8801/hook/AbC456'),
    '同前缀、不同令牌：urlHash 相同（设计使然）'
  );
  assert.equal(
    hashUrl('http://127.0.0.1:8801/hook/AbC123'),
    hashUrl('http://127.0.0.1:8801/hook/Ab***'),
    '已脱敏形态与其原 URL 得到同一标识（脱敏幂等）'
  );
  /* 粒度变粗的另一面：主机 / 端口 / 结构性路径段不同仍能区分 */
  assert.notEqual(
    hashUrl('http://127.0.0.1:8801/hook/AbC123'),
    hashUrl('http://127.0.0.1:8802/hook/AbC123')
  );
  assert.notEqual(
    hashUrl('http://127.0.0.1:8801/hook/AbC123'),
    hashUrl('http://127.0.0.1:8801/notify/AbC123')
  );
});

test('投递记录里不得出现可被枚举验证的 urlHash（记录 url 与哈希都来自脱敏形态）', () => {
  const url = 'http://127.0.0.1:8801/hook/AbC123';
  const record = buildNoDeliveryRecord({
    url,
    secret: null,
    minSeverity: 'medium',
    reason: 'no-change',
    summary: {},
  });
  const serialized = JSON.stringify(record);
  assert.equal(serialized.includes('AbC123'), false, '记录里不得出现原始令牌');
  assert.equal(
    record.urlHash,
    hashUrl(`${record.url}`),
    'urlHash 与记录里那条脱敏 url 一一对应'
  );
});

test('投递记录同时给出脱敏 URL 与 URL 哈希，且不含密钥', () => {
  const url = 'https://hooks.slack.com/services/T00000000/B00000000/FAKE-SLACK-TOKEN-E2E?k=super-secret-value';
  const record = buildNoDeliveryRecord({
    url,
    secret: 'super-secret-value',
    minSeverity: 'medium',
    reason: 'no-change',
    summary: {},
  });
  assert.match(record.url, /^https:\/\/hooks\.slack\.com\/services\/T0\*\*\*\/B0\*\*\*\/FA\*\*\*/);
  assert.match(record.urlHash, /^sha256:[0-9a-f]{12}$/);
  const serialized = JSON.stringify(record);
  assert.equal(serialized.includes('FAKE-SLACK-TOKEN-E2E'), false);
  assert.equal(serialized.includes('super-secret-value'), false);
});
