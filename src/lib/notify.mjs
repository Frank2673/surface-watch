/**
 * Webhook 告警投递
 *
 * 零依赖：只用 `node:http` / `node:https` / `node:crypto`。
 *
 * 设计要点（每一条都对应一个真实会踩的坑）：
 *
 * 1. **只看变化，且只看"新增指纹"**：触发集合严格等于**单一变化源**
 *    （`lib/changeset.mjs`）的 `added` —— 即本次出现、基线里没有的指纹。
 *    这里不再自己从 diff 里挑子集，避免"判据散落多处、改一处漏一处"。
 *    不 用「发现总数变了」「持续存在的条数变了」做触发 ——
 *    那类判据会把证据文本抖动也算成告警。
 *    `changed`（指纹未变但内容变了：严重度升级 / 证据变化）只作为**信息项**
 *    出现在载荷的 `summary.changed` 中，**不触发投递**：真正该报警的是新指纹，
 *    内容变化用来看趋势。无新增时一次网络请求都不发（no-op）。
 * 2. **首次运行不告警**：基线文件不存在或为空时默认静默跳过投递（stderr 一行说明），
 *    因为此时"全部发现都是新增"是基线缺失的假象，不是真的变化。
 *    确需推送首轮全量时用显式开关 `--webhook-include-initial`。
 * 3. **投递失败不影响扫描**：报告照常生成、退出码语义照常；
 *    失败原因写 stderr，投递结果写 `<out>/webhook-delivery.json` 供事后排查。
 *    告警通道坏掉不应该让监控本身也坏掉。
 * 4. **默认阈值 `medium`**：依据本项目既有的严重度 → SARIF level 映射
 *    （见 `sarif.mjs`：critical/high → `error`，medium → `warning`，low/info → `note`）。
 *    `error` 与 `warning` 是「需要人处理」的两档，`note` 是信息档 ——
 *    默认只对前两档告警，避免把信息项刷成告警噪音；需要时可放宽到 `low`/`info`。
 *    阈值过滤的对象是 `diff.added`，与 `--fail-on` 是两条独立阈值（见 README）。
 * 5. **签名只覆盖请求体原字节**（HMAC-SHA256，不掺时间戳）：
 *    接收端只要手里有共享密钥和原始 body 就能独立复算，不需要理解本工具的任何状态。
 *    请求头 `X-Surface-Watch-Signature: sha256=<hex>`。
 * 6. **载荷不含任何凭据**：不写 secret、不写环境变量内容；
 *    落盘的投递记录里 URL 也会脱敏 —— Webhook URL 常把 token 放在 query 上
 *    （Slack / 飞书 / 企业微信都这么干），原样落盘等于把凭据写进文件。
 *    脱敏不按长度做启发式（长度不是「是不是凭据」的判据）：path 段与 query 参数名
 *    都走白名单，只保留结构性段与常见标签，其余一律打码，见 `redactUrl()`。
 * 7. **不跟随重定向**：3xx 一律按投递失败处理。告警载荷不应被转发到
 *    未经配置的第三方地址 —— 「URL 里换个 Location 就能把载荷导走」是真实的
 *    凭据泄露路径，宁可失败也不要它偷偷成功。
 * 8. **两层超时，缺一不可**（`--webhook-timeout` 与 `--webhook-deadline`）：
 *    - **单次空闲超时**（`--webhook-timeout`，默认 5000ms）挂在 socket 上，
 *      只覆盖「一次尝试里 socket 无数据」的情况；
 *    - **整体截止时间**（`--webhook-deadline`，默认 `max(10_000, 3 × timeout)`）
 *      覆盖 connect + 响应头 + 响应体 + 全部重试的**总时长**。
 *    为什么必须有第二层：慢速接收端（回 200 + `Transfer-Encoding: chunked` 后每 200ms
 *    发 1 字节、永不结束）让 socket 始终「有数据」，空闲超时永不触发 —— 实测在
 *    `--webhook-timeout 1500` 下进程 40s 硬上限内不退出、不写投递记录、不走基线更新与退出码。
 *    触达整体截止时间时的语义：`ok=false`、`error` 以 `DEADLINE_EXCEEDED` 开头
 *    （与 per-attempt 的 `TIMEOUT` 明确区分）、`attempts` 为**真实**尝试次数、
 *    `deadlineExceeded=true`；扫描产物与退出码原样不变。
 *
 * 一条必须写清的边界（不要对它做任何承诺）：
 *   指纹是 `check:key:asset`，**同一类问题在 key 变化时会产生新的"新增"**。
 *   例如证书到期按剩余天数分三档（`cert-expiring` → `cert-expiring-urgent` → `cert-expired`），
 *   同一张证书在生命周期内最多会触发 3 次"新增"告警，旧指纹同时被记为 resolved。
 *   所以载荷里每条 finding 都带 `fingerprint` 字段，供下游按指纹自行去重，
 *   本工具**不承诺**"同一问题只推一次"。
 *
 * @module lib/notify
 */

import http from 'node:http';
import https from 'node:https';
import { createHash, createHmac } from 'node:crypto';
import { setTimeout as sleep } from 'node:timers/promises';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { SEVERITY, compareSeverity } from './findings.mjs';
import { changesetFromDiff, detectChangedFindings, triggerFindings } from './changeset.mjs';

/* 变化语义（含"指纹未变但内容变了"的信息项）只在 lib/changeset.mjs 定义一处。
   这里重新导出是为了不破坏既有调用方（本模块的公开面保持不变）。 */
export { detectChangedFindings };

const TOOL = 'surface-watch';
const DEFAULT_UA =
  'surface-watch/0.1 (+authorized-security-monitoring; webhook-alert)';

/** 环境变量回退（CI 里用 secret 注入，不要写进仓库文件） */
export const ENV_WEBHOOK_URL = 'SURFACE_WATCH_WEBHOOK_URL';
export const ENV_WEBHOOK_SECRET = 'SURFACE_WATCH_WEBHOOK_SECRET';

/** 签名请求头 */
export const SIGNATURE_HEADER = 'X-Surface-Watch-Signature';

export const DEFAULT_WEBHOOK_TIMEOUT_MS = 5000;
/** 整体截止时间的下限（默认 deadline 不会低于它） */
export const DEFAULT_WEBHOOK_DEADLINE_FLOOR_MS = 10_000;
/** 最多重试 2 次（指数退避）→ 含首次共最多 3 次尝试 */
export const MAX_WEBHOOK_RETRIES = 2;
/** 退避基数：250ms → 500ms */
export const WEBHOOK_BACKOFF_MS = 250;
/** 整体截止时间触达时的错误码（与单次空闲超时的 TIMEOUT 区分开） */
export const DEADLINE_EXCEEDED = 'DEADLINE_EXCEEDED';
/** 默认告警阈值（依据见文件头第 4 条） */
export const DEFAULT_MIN_SEVERITY = 'medium';
/**
 * 触发集合：严格等于**新增指纹集合**，即单一变化源（`lib/changeset.mjs`）的 `added`
 * —— 见 `changeset.TRIGGER_FIELD`。
 *
 * 字符串值保持 `'diff.added'` 不变：它已写进既有 `webhook-delivery.json` 记录与 README 契约，
 * 属于对外行为的一部分。这里改的是**判据的来源**（不再由本模块自己从 diff 里挑子集，
 * 而是消费 `triggerFindings(changeset)`），不是这个标签本身。
 */
export const TRIGGER_SET = 'diff.added';
/** 投递记录文件名（写在 --out 目录下） */
export const DELIVERY_FILE = 'webhook-delivery.json';

const MAX_ERROR_BODY = 200;
const MAX_EVIDENCE_CHARS = 1000;

const THRESHOLD_RATIONALE =
  'critical/high→error、medium→warning 为需处理档（对齐 sarif.mjs 的 level 映射）；low/info→note 为信息档，默认不告警；过滤对象是 diff.added（新增指纹）';

/* ------------------------------------------------------------------ *
 * 配置解析
 * ------------------------------------------------------------------ */

/**
 * 整体截止时间默认值：`max(10_000ms, 3 × 单次空闲超时)`。
 *
 * 为什么是「3 倍」：含首次共最多 3 次尝试，慢接收端下用户预期仍是"重试完就放弃"，
 * 而不是让 3 次尝试被总时长掐死；「10s 下限」保证单次超时调得很小时
 * 整体仍有完成 1 次尝试 + 退避的余量。
 *
 * @param {number} timeoutMs 单次空闲超时
 * @returns {number} 整体截止时间（毫秒）
 */
export function defaultWebhookDeadlineMs(timeoutMs) {
  const per = Number(timeoutMs);
  const base = Number.isFinite(per) && per > 0 ? per : DEFAULT_WEBHOOK_TIMEOUT_MS;
  return Math.max(DEFAULT_WEBHOOK_DEADLINE_FLOOR_MS, base * 3);
}

/**
 * 解析 Webhook 配置（CLI 参数优先，环境变量回退）
 *
 * @param {object} input
 * @param {object} input.args 已解析的 CLI 参数
 * @param {object} input.env  环境变量（默认 process.env）
 * @returns {{url:string, secret:string|null, minSeverity:string, timeoutMs:number, deadlineMs:number}|null}
 *   未配置 Webhook 时返回 null（调用方据此完全跳过投递）
 * @throws {Error} 配置非法（URL 协议不支持、阈值非法、超时/截止时间非正数）
 */
export function resolveWebhookConfig({ args = {}, env = {} } = {}) {
  const url = args.webhook || env[ENV_WEBHOOK_URL] || null;
  if (!url) return null;

  const secret = args['webhook-secret'] || env[ENV_WEBHOOK_SECRET] || null;
  const minSeverity = args['webhook-min-severity'] || DEFAULT_MIN_SEVERITY;
  const timeoutMs =
    args['webhook-timeout'] === undefined
      ? DEFAULT_WEBHOOK_TIMEOUT_MS
      : Number(args['webhook-timeout']);
  /* 未显式给 --webhook-deadline 时按 timeout 推导（见 defaultWebhookDeadlineMs） */
  const deadlineMs =
    args['webhook-deadline'] === undefined
      ? defaultWebhookDeadlineMs(timeoutMs)
      : Number(args['webhook-deadline']);

  assertSupportedUrl(url);

  if (!SEVERITY.includes(minSeverity)) {
    throw new Error(
      `--webhook-min-severity 取值非法：${minSeverity}（可选：${SEVERITY.join('|')}）`
    );
  }
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new Error(`--webhook-timeout 需要正整数毫秒，收到：${args['webhook-timeout']}`);
  }
  if (!Number.isFinite(deadlineMs) || deadlineMs <= 0) {
    throw new Error(`--webhook-deadline 需要正整数毫秒，收到：${args['webhook-deadline']}`);
  }

  return {
    url: String(url),
    secret: secret ? String(secret) : null,
    minSeverity,
    timeoutMs,
    deadlineMs,
  };
}

/** 只允许 http/https；其它协议（file:、ftp: 等）直接拒绝 */
export function assertSupportedUrl(url) {
  let parsed;
  try {
    parsed = new URL(String(url));
  } catch {
    throw new Error(`--webhook 不是合法 URL：${redactUrl(url)}`);
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error(`--webhook 只支持 http/https，收到：${parsed.protocol}`);
  }
  return parsed;
}

/**
 * 允许原样保留的「结构性」路径段。
 *
 * 这些是 Webhook 端点路由的固定组成部分（`/hook`、Slack 的 `services`、飞书的
 * `open-apis/bot/v2/hook` 等），本身不含凭据。
 *
 * 为什么不再按**长度**判断（原实现：长度 ≥ 12 才打码、短段原样保留）：
 * 长度从来不是「是不是凭据」的判据。对抗验证给出的反例：
 *   - `/hook/AbC123`：`AbC123` 只有 6 个字符，但把它当令牌用的服务是真实的；
 *   - `/services/T00000000/B00000000/<token>`：不能假定 workspace / bot ID
 *     「永远不是秘密」—— 用户完全可能把自建凭据放在这些位置。
 * 长度阈值把这类短凭据原样写进 stdout 与 `<out>/webhook-delivery.json`
 * （CI 产物常被打包归档），属于凭据泄漏。改成白名单后：
 * **只有下列结构性段保留，其余任何段一律打码**（保留前 2 位只为定位端点）。
 */
const SAFE_PATH_SEGMENTS = new Set([
  '',
  'hook',
  'hooks',
  'webhook',
  'webhooks',
  'notify',
  'notification',
  'notifications',
  'alert',
  'alerts',
  'incoming',
  'services',
  'open-apis',
  'bot',
  'bots',
  'api',
  'v1',
  'v2',
  'v3',
]);

/**
 * 允许保留参数**名**的常见告警参数标签。
 *
 * query 的值一律打码，但「参数名」本身也可能是凭据的载体
 * （`?BareSecret123456` 这种无值参数、或把 token 直接当参数名写进 URL 的做法），
 * 因此参数名同样走白名单：只有约定俗成的标签保留可读，
 * 其余一律替换为 `***`，避免把凭据当参数名落盘。
 */
const SAFE_QUERY_KEYS = new Set([
  'token',
  'access_token',
  'api_key',
  'apikey',
  'key',
  'auth',
  'authorization',
  'secret',
  'signature',
  'sig',
  'hmac',
  'ts',
  'timestamp',
  'nonce',
  'id',
  'type',
  'event',
  'channel',
  'format',
  'foo',
  'bar',
]);

/**
 * URL 脱敏：保留协议 / 主机 / 端口 / 结构性路径段与常见参数名，其余一律打码。
 *
 * 为什么连 **path 段**也要打码：Webhook URL 的凭据不一定在 query 上。
 * Slack 的 incoming webhook 形如 `https://hooks.slack.com/services/T…/B…/<token>`，
 * 飞书是 `https://open.feishu.cn/open-apis/bot/v2/hook/<uuid>` —— **凭据就是 path 段**。
 * 只脱敏 query 等于没脱敏。
 *
 * 规则（白名单式，不用长度启发式，理由见 SAFE_PATH_SEGMENTS / SAFE_QUERY_KEYS）：
 *   1. userinfo 一律 `***`；fragment 整段丢弃；
 *   2. path 段：只有 SAFE_PATH_SEGMENTS 里的结构性段原样保留，其余保留前 2 位 + `***`；
 *   3. query：值一律 `***`；参数名只有 SAFE_QUERY_KEYS 里的标签保留，其余替换为 `***`。
 *
 * 注意：脱敏后的 URL 无法与配置逐字比对，因此另提供 `hashUrl()` 供跨记录关联。
 * `hashUrl()` 对**脱敏后**的 URL 取 sha256 前 12 位，不是完整 URL ——
 * 理由与副作用见 `hashUrl()` 的注释。
 */
export function redactUrl(url) {
  try {
    const parsed = new URL(String(url));
    if (parsed.username || parsed.password) {
      parsed.username = '***';
      parsed.password = '';
    }
    parsed.pathname = parsed.pathname
      .split('/')
      .map((segment) =>
        SAFE_PATH_SEGMENTS.has(segment.toLowerCase()) ? segment : `${segment.slice(0, 2)}***`
      )
      .join('/');
    if (parsed.search) {
      const params = [...parsed.searchParams.entries()];
      parsed.search = params.length
        ? `?${params
            .map(([key]) =>
              SAFE_QUERY_KEYS.has(key.toLowerCase()) ? `${key}=***` : '***'
            )
            .join('&')}`
        : '?***';
    }
    parsed.hash = '';
    return parsed.toString();
  } catch {
    return '<非法 URL>';
  }
}

/**
 * 脱敏后 URL 的短哈希（sha256 前 12 位十六进制）。
 *
 * 用途：记录文件里 URL 已脱敏，运维仍需要一个稳定标识把「同一次配置」的多条记录串起来。
 *
 * 为什么哈希对象是**脱敏后的 URL**（而不是完整 URL）—— 这是一次有意的取舍：
 * 对完整 URL 做 hash 等于在记录里留了一个**可校验的预言机**。`urlHash` 是
 * 完整 URL 的 sha256 前 12 位（48 bit、无盐），攻击者只要拿到同一条记录里
 * 已经脱敏的 url 前缀（`http://127.0.0.1:8801/hook/Ab***`）就能离线枚举候选、
 * 逐个比对哈希还原低熵凭据。实测：7,122,554 个候选 / 11.8s 即还原出
 * `http://127.0.0.1:8801/hook/AbC123`，脱敏形同虚设。
 * 改成对脱敏结果取哈希后，候选串算出的哈希与记录里的**不一致**，
 * 因此无法验证猜测 —— 预言机消失，且不需要引入盐或密钥存储（零依赖前提保持不变）。
 *
 * **必须写清的副作用**：牺牲的是跨记录关联的粒度。
 * 同一个 URL 前缀 + 不同令牌（`/hook/AbC123` 与 `/hook/AbC456` 都脱敏成 `/hook/Ab***`）
 * 会得到**相同的 urlHash**。也就是说「两条记录的 urlHash 相同」只说明
 * 脱敏后的形态相同，不再能证明是同一次配置。
 * 这是为消除凭据枚举而付的代价，属有意取舍；需要逐字比对配置时请用
 * `redactUrl()` 的形态 + 人工核对，而不是靠 urlHash。
 *
 * @param {string|URL} url 原始（未脱敏）URL
 * @returns {string} `sha256:<12 位十六进制>`
 */
export function hashUrl(url) {
  const redacted = redactUrl(url instanceof URL ? url.toString() : url);
  return `sha256:${createHash('sha256').update(redacted).digest('hex').slice(0, 12)}`;
}

/* ------------------------------------------------------------------ *
 * 触发语义：新增 / 变化
 *
 * 判定不在这里：`added`（触发集合）与 `changed`（信息项）都由 lib/changeset.mjs
 * 这个单一变化源给出，本模块只按阈值过滤并组织载荷。
 * ------------------------------------------------------------------ */

/**
 * 决策：这次要不要投递，投递什么
 *
 * 判定顺序（每一步都可能直接判定为 no-op）：
 *   1. 基线缺失（首次运行）→ 默认 no-op（`baseline-establishment`）：
 *      此时"全部发现都是新增"是基线缺失的假象。确需推送首轮全量时传 `includeInitial: true`。
 *   2. 取变化源的 `added`（新增指纹集合）并按阈值过滤 → 空则 no-op
 *      （`no-change` / `below-threshold`）。
 *
 * @param {object} input
 * @param {object} input.changeset 单一变化源（lib/changeset.mjs 的 buildChangeset 结果）
 * @param {object} [input.diff] 兼容入参：仍是裸 diff 对象的调用方（会被规范化成变化集）
 * @param {Array}  [input.baseline] 基线发现（仅兼容入参路径下用于计算信息项 changed）
 * @param {string} [input.minSeverity] 告警阈值（过滤对象是 added）
 * @param {boolean} [input.baselineEstablished] 基线是否缺失（仅兼容入参路径下使用）
 * @param {boolean} [input.includeInitial] 是否允许在基线缺失时也投递（显式开关）
 * @returns {{triggered:boolean, reason:string|null, findings:Array, summary:object}}
 *   reason：`baseline-establishment`（基线缺失跳过）｜`no-change`（无新增指纹）
 *   　　｜`below-threshold`（有新增但都低于阈值）
 */
export function planDelivery({
  changeset,
  diff,
  baseline = [],
  minSeverity = DEFAULT_MIN_SEVERITY,
  baselineEstablished = false,
  includeInitial = false,
}) {
  /* 兼容路径只做规范化，不重新判定语义；有变化集时以变化集为准 */
  const cs = changeset || changesetFromDiff(diff, baseline, { baselineEstablished });
  const established = changeset ? Boolean(cs.baselineEstablished) : Boolean(baselineEstablished);

  const added = triggerFindings(cs);
  const changed = cs.changed || [];
  const removed = cs.resolved || [];

  /* 信息项：指纹未变但内容变化（不触发投递） */
  const informationalChanged = changed.map((f) => ({
    fingerprint: f.id,
    asset: f.asset,
    title: f.title,
    severity: f.severity,
    changedFields: f.changedFields,
    previousSeverity: f.previousSeverity,
  }));

  const alertNew = added.filter((f) => compareSeverity(f.severity, minSeverity) >= 0);
  const findings = alertNew.map((f) => ({ ...toPayloadFinding(f), change: 'new' }));

  const summary = {
    new: alertNew.length,
    changed: informationalChanged.length,
    removed: removed.length,
    bySeverity: countBySeverity(findings),
    /* 透明度：因低于阈值而未投递的新增数量（与变化源的 ignoredCount 同一套思路） */
    ignored: {
      new: added.length - alertNew.length,
      changed: 0,
    },
  };

  if (established && !includeInitial) {
    return { triggered: false, reason: 'baseline-establishment', findings: [], summary, informationalChanged };
  }

  const triggered = findings.length > 0;

  return {
    triggered,
    reason: triggered ? null : added.length > 0 ? 'below-threshold' : 'no-change',
    findings,
    summary,
    informationalChanged,
  };
}

function toPayloadFinding(f) {
  return {
    /* 指纹 = check:key:asset，与 SARIF partialFingerprints 同源，供下游去重 */
    fingerprint: f.id,
    id: f.id,
    asset: f.asset,
    check: f.check,
    key: f.key,
    severity: f.severity,
    title: f.title,
    evidence: truncate(f.evidence, MAX_EVIDENCE_CHARS),
    impact: f.impact,
    remediation: f.remediation,
    firstSeen: f.firstSeen || null,
  };
}

function truncate(text, max) {
  const s = String(text ?? '');
  return s.length <= max ? s : `${s.slice(0, max)}…（已截断，原文 ${s.length} 字符）`;
}

function countBySeverity(findings) {
  const counts = Object.fromEntries(SEVERITY.map((s) => [s, 0]));
  for (const f of findings) if (counts[f.severity] !== undefined) counts[f.severity]++;
  return counts;
}

/* ------------------------------------------------------------------ *
 * 载荷
 * ------------------------------------------------------------------ */

/**
 * 构造投递载荷
 *
 * 载荷里**不含**密钥、环境变量或任何凭据。
 *
 * @param {object} input
 * @param {string} input.version 工具版本
 * @param {object} input.scope   范围对象（来自 loadScope）
 * @param {object} input.plan    planDelivery 的结果
 * @param {string} input.minSeverity
 * @param {boolean} input.signed 本次是否带签名
 * @param {boolean} [input.initial] 是否为首轮全量（基线缺失 + 显式开关）
 * @param {string} [input.generatedAt]
 * @returns {object}
 */
export function buildPayload({
  version,
  scope,
  plan,
  minSeverity = DEFAULT_MIN_SEVERITY,
  signed = false,
  initial = false,
  generatedAt = new Date().toISOString(),
}) {
  return {
    tool: TOOL,
    version,
    generatedAt,
    scope: {
      owner: scope.owner,
      assets: scope.assets.map((a) => a.domain),
      statement: scope.authorization.statement,
    },
    summary: {
      new: plan.summary.new,
      changed: plan.summary.changed,
      removed: plan.summary.removed,
      bySeverity: plan.summary.bySeverity,
      ignored: plan.summary.ignored,
    },
    delivery: {
      /* 触发集合：严格等于单一变化源的 added（新增指纹集合） */
      triggerSet: TRIGGER_SET,
      initial,
      threshold: minSeverity,
      thresholdRationale: THRESHOLD_RATIONALE,
      triggeredBy: plan.summary.new > 0 ? ['new'] : [],
      /* 声明语义：changed 是信息项，不参与触发 */
      changedIsInformational: true,
      signed: Boolean(signed),
    },
    findings: plan.findings,
  };
}

/** 对请求体原字节做 HMAC-SHA256，返回 `sha256=<hex>` */
export function signBody(body, secret) {
  const buf = Buffer.isBuffer(body) ? body : Buffer.from(String(body), 'utf8');
  return `sha256=${createHmac('sha256', String(secret)).update(buf).digest('hex')}`;
}

/* ------------------------------------------------------------------ *
 * 投递
 * ------------------------------------------------------------------ */

/**
 * 投递 Webhook（永不 reject —— 失败信息通过返回值表达，调用方无需 try/catch）
 *
 * 两层超时（都必须有，缺一个就存在挂死面）：
 *   - `timeoutMs`：**单次尝试**的 socket 空闲超时。只覆盖「这次尝试里 socket 无数据」；
 *   - `deadlineMs`：**整体截止时间**，覆盖 connect + 响应头 + 响应体 + 退避 + 全部重试。
 *     缺省由 `timeoutMs` 推导（`defaultWebhookDeadlineMs`），可用 `--webhook-deadline` 覆盖。
 *   慢接收端（200 + chunked，每 200ms 一字节、永不结束）会让 socket 一直「有数据」，
 *   空闲超时永不触发 —— 只有整体截止时间能把它掐断。
 *
 * 重试策略（不变）：
 *   - 网络错误（连接被拒 / 空闲超时 / DNS / reset）→ 重试
 *   - 5xx → 重试
 *   - 4xx、3xx → 不重试（重试不会让错误消失，只会重复打扰接收端）
 *   - 触达整体截止时间 → **不再重试**（再试只会继续超预算）
 *   退避：250ms → 500ms，最多 2 次重试（含首次共最多 3 次尝试）
 *
 * @returns {Promise<object>} 投递记录（含 ok/statusCode/attempts/error/deadlineMs/
 *   deadlineExceeded/attemptLog）；触达截止时间时 `error` 以 `DEADLINE_EXCEEDED` 开头，
 *   与单次空闲超时的 `TIMEOUT` 明确区分，`attempts` 只计**真实发生**的尝试
 */
export async function deliverWebhook({
  url,
  secret = null,
  body,
  timeoutMs = DEFAULT_WEBHOOK_TIMEOUT_MS,
  deadlineMs = null,
  maxRetries = MAX_WEBHOOK_RETRIES,
  backoffMs = WEBHOOK_BACKOFF_MS,
  log = () => {},
}) {
  const parsed = assertSupportedUrl(url);
  const payloadBuf = Buffer.from(String(body), 'utf8');
  const signature = secret ? signBody(payloadBuf, secret) : null;
  const startedAt = Date.now();
  const totalDeadlineMs =
    deadlineMs === null || deadlineMs === undefined
      ? defaultWebhookDeadlineMs(timeoutMs)
      : Number(deadlineMs);
  /* 绝对时刻而非剩余量：退避 sleep 也走同一个预算，任何分支都不能超时 */
  const deadlineAt = startedAt + totalDeadlineMs;
  const attemptLog = [];

  /** 触达整体截止时间的错误串（前缀即错误码，便于记录里 grep） */
  const deadlineError = () =>
    `${DEADLINE_EXCEEDED}: 整体截止时间 ${totalDeadlineMs}ms 已到` +
    `（覆盖 connect + 响应头 + 响应体 + 全部重试），已中止投递；` +
    `实际尝试 ${attemptLog.length} 次`;

  let last = { ok: false, statusCode: null, error: 'NOT_ATTEMPTED', errorBody: null };
  let deadlineExceeded = false;

  for (let attempt = 1; attempt <= maxRetries + 1; attempt++) {
    const t0 = Date.now();
    const remaining = deadlineAt - t0;

    /* 预算已耗尽（含被退避 sleep 吃光的情况）：不再发起新尝试，
       attempts 保持为真实尝试次数，不虚增 */
    if (remaining <= 0) {
      deadlineExceeded = true;
      last = { ok: false, statusCode: null, error: deadlineError(), errorBody: null };
      break;
    }

    let result;
    try {
      result = await postOnce({
        parsed,
        body: payloadBuf,
        signature,
        /* 单次空闲超时被剩余预算夹住：两者取小，谁先到谁生效 */
        timeoutMs: Math.min(timeoutMs, remaining),
        hardDeadlineMs: remaining,
        url,
      });
    } catch (err) {
      result = { ok: false, statusCode: null, error: describeError(err), errorBody: null };
    }

    /* 本次尝试期间预算已耗尽（或错误本身就是截止时间）：整体语义优先于单次语义 */
    const hitDeadline = isDeadlineError(result.error) || Date.now() >= deadlineAt;
    const retryable =
      !result.ok && (result.statusCode === null || result.statusCode >= 500) && !hitDeadline;

    attemptLog.push({
      attempt,
      ok: result.ok,
      statusCode: result.statusCode,
      error: result.error,
      ...(result.errorBody ? { errorBody: result.errorBody } : {}),
      ms: Date.now() - t0,
      retryable,
    });

    if (result.ok) {
      last = result;
      break;
    }

    if (hitDeadline) {
      deadlineExceeded = true;
      last = {
        ok: false,
        statusCode: result.statusCode ?? null,
        error: deadlineError(),
        errorBody: result.errorBody ?? null,
      };
      break;
    }

    last = result;
    if (!retryable) break;

    if (attempt <= maxRetries) {
      const delay = backoffMs * 2 ** (attempt - 1);
      log(
        `⚠️ Webhook 第 ${attempt} 次投递失败（${result.error || `HTTP ${result.statusCode}`}），` +
          `${delay}ms 后重试…`
      );
      /* 退避也要受总预算约束：最多睡到 deadlineAt */
      const wait = Math.max(0, Math.min(delay, deadlineAt - Date.now()));
      if (wait > 0) await sleep(wait);
    }
  }

  return {
    tool: TOOL,
    generatedAt: new Date().toISOString(),
    url: redactUrl(url),
    signed: Boolean(secret),
    ok: last.ok,
    statusCode: last.statusCode ?? null,
    attempts: attemptLog.length,
    error: last.ok ? null : last.error || null,
    deadlineMs: totalDeadlineMs,
    deadlineExceeded,
    durationMs: Date.now() - startedAt,
    attemptLog,
  };
}

/**
 * 单次投递尝试。
 *
 * 两个计时器，职责不同：
 *   - `timeoutMs`：socket **空闲**超时（挂在请求上），只覆盖"这次尝试里没有数据"；
 *   - `hardDeadlineMs`：本次尝试的**硬上限**（整体截止时间的剩余量），到点无条件中止。
 *     慢接收端每次只吐 1 字节时 socket 空闲超时永不触发，只有硬计时器能掐断；
 *     必须显式 reject 兜底：响应体接收阶段 `req.destroy()` 不保证回调到 req 的 error 事件。
 *
 * @param {object} input
 * @param {URL} input.parsed           已校验的 URL
 * @param {Buffer} input.body          请求体原字节
 * @param {string|null} input.signature 签名头值
 * @param {number} input.timeoutMs     单次空闲超时
 * @param {number|null} [input.hardDeadlineMs] 本次尝试的硬上限（null = 不设）
 */
function postOnce({ parsed, body, signature, timeoutMs, hardDeadlineMs = null }) {
  return new Promise((resolve, reject) => {
    const client = parsed.protocol === 'http:' ? http : https;
    let settled = false;
    let hardTimer = null;

    /** 只结算一次；无论走哪条路径都清掉硬计时器，避免残留定时器 */
    const settle = (fn, value) => {
      if (settled) return;
      settled = true;
      if (hardTimer) clearTimeout(hardTimer);
      fn(value);
    };

    const headers = {
      'Content-Type': 'application/json',
      'Content-Length': body.length,
      'User-Agent': DEFAULT_UA,
      Accept: 'application/json',
      /* 明确不压缩：Webhook 载荷不需要压缩，也少一层解析分歧 */
      'Accept-Encoding': 'identity',
      ...(signature ? { [SIGNATURE_HEADER]: signature } : {}),
    };

    const req = client.request(
      {
        protocol: parsed.protocol,
        hostname: parsed.hostname,
        port: parsed.port || (parsed.protocol === 'http:' ? 80 : 443),
        path: parsed.pathname + parsed.search,
        method: 'POST',
        headers,
        timeout: timeoutMs,
      },
      (res) => {
        const chunks = [];
        let received = 0;
        let captured = 0;

        res.on('data', (chunk) => {
          received += chunk.length;
          /* 按**字节**截断：只攒够诊断所需的前 MAX_ERROR_BODY 字节。
             原实现是"整块丢弃"式（首个 chunk 就让累计字节超过上限 → 该 chunk 不入列），
             于是 460 字节的 502 体得到空串 errorBody —— 有错误码、没有错误内容。
             现在无论 body 多大、怎么分块，都能留下前 N 字节。 */
          if (captured >= MAX_ERROR_BODY) return; /* 继续 drain 但不留内存 */
          const need = MAX_ERROR_BODY - captured;
          chunks.push(chunk.length <= need ? chunk : chunk.subarray(0, need));
          captured += Math.min(need, chunk.length);
        });

        res.on('end', () => {
          const statusCode = res.statusCode || 0;
          const ok = statusCode >= 200 && statusCode < 300;
          settle(resolve, {
            ok,
            statusCode,
            error: ok ? null : `HTTP ${statusCode}${statusCode >= 300 && statusCode < 400 ? '（重定向一律视为投递失败，不跟随）' : ''}`,
            errorBody: ok ? null : decodeErrorBody(Buffer.concat(chunks), received, captured),
          });
        });

        /* 连接提前断开也要当失败，不能把"对端没收全"当成功 */
        res.on('close', () => {
          if (!res.complete) {
            settle(reject, errWithCode('INCOMPLETE_RESPONSE', '响应被提前中断'));
          }
        });
      }
    );

    req.on('timeout', () => {
      req.destroy(errWithCode('TIMEOUT', `请求空闲超时（> ${timeoutMs}ms）`));
    });
    req.on('error', (err) => settle(reject, err));

    if (hardDeadlineMs !== null && Number.isFinite(hardDeadlineMs)) {
      hardTimer = setTimeout(() => {
        const err = errWithCode(
          DEADLINE_EXCEEDED,
          `整体截止时间已到（本次尝试上限 ${hardDeadlineMs}ms），强制中止`
        );
        req.destroy(err);
        /* 兜底：接收响应体期间 destroy 不保证在 req 上派发 error */
        settle(reject, err);
      }, Math.max(1, hardDeadlineMs));
    }

    req.end(body);
  });
}

/** 错误体解码：按字节截断并标注，任何大小的响应体都留得下可诊断片段 */
function decodeErrorBody(buf, receivedBytes, capturedBytes) {
  const text = buf.toString('utf8');
  if (receivedBytes <= capturedBytes) return text;
  /* 截断点可能落在多字节字符中间 → 末尾出现一个替换符（U+FFFD），可接受：
     目标是"留得下片段"，不是"保证 UTF-8 完整" */
  return `${text}…（已截断：响应体共 ${receivedBytes} 字节，仅保留前 ${capturedBytes} 字节）`;
}

function errWithCode(code, message) {
  return Object.assign(new Error(message), { code });
}

/** 错误串是否由整体截止时间触发（前缀即错误码） */
function isDeadlineError(error) {
  return typeof error === 'string' && error.startsWith(DEADLINE_EXCEEDED);
}

function describeError(err) {
  if (!err) return 'UNKNOWN';
  const code = err.code ? `${err.code}: ` : '';
  return `${code}${err.message || err}`;
}

/* ------------------------------------------------------------------ *
 * 投递记录
 * ------------------------------------------------------------------ */

/**
 * 写投递记录（<out>/webhook-delivery.json）
 *
 * 无论投递成功还是失败都写：排查"告警为什么没收到"时，
 * 唯一能定位问题的就是这份记录。
 *
 * @param {string} outDir 输出目录
 * @param {object} record 记录内容
 * @returns {string} 记录文件路径
 */
export function writeDeliveryRecord(outDir, record) {
  const path = join(outDir, DELIVERY_FILE);
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(record, null, 2)}\n`, 'utf8');
  return path;
}

/**
 * 「无变化 / 低于阈值」时的记录：明确写清楚没投递以及为什么，
 * 避免上一次运行留下的失败记录被误读成本次结果。
 */
export function buildNoDeliveryRecord({
  url,
  secret = null,
  minSeverity,
  reason,
  summary,
  deadlineMs = null,
}) {
  return {
    tool: TOOL,
    generatedAt: new Date().toISOString(),
    url: redactUrl(url),
    urlHash: hashUrl(url),
    signed: Boolean(secret),
    triggerSet: TRIGGER_SET,
    threshold: minSeverity,
    deadlineMs,
    triggered: false,
    ok: true,
    delivered: false,
    reason,
    statusCode: null,
    attempts: 0,
    error: null,
    deadlineExceeded: false,
    durationMs: 0,
    summary,
    attemptLog: [],
  };
}

/**
 * 投递记录 + 投递结果合并（供调用方一次写盘）
 *
 * `deadlineExceeded=true` 时 `error` 必以 `DEADLINE_EXCEEDED` 开头，
 * 与单次空闲超时的 `TIMEOUT` 分属两层，排查时不要混看。
 */
export function buildDeliveryRecord({ url, secret, minSeverity, summary, result, initial = false }) {
  return {
    tool: TOOL,
    generatedAt: new Date().toISOString(),
    url: redactUrl(url),
    urlHash: hashUrl(url),
    signed: Boolean(secret),
    triggerSet: TRIGGER_SET,
    initial,
    threshold: minSeverity,
    deadlineMs: result.deadlineMs ?? null,
    triggered: true,
    delivered: Boolean(result.ok),
    ok: Boolean(result.ok),
    reason: result.ok ? 'delivered' : 'delivery-failed',
    statusCode: result.statusCode ?? null,
    attempts: result.attempts,
    error: result.error ?? null,
    deadlineExceeded: Boolean(result.deadlineExceeded),
    durationMs: result.durationMs,
    summary,
    attemptLog: result.attemptLog,
  };
}
