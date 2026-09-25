/**
 * 单一变化源（Change Set）
 *
 * ## 为什么需要它
 *
 * 「什么算变化」在本项目里曾经有**三处各自独立的实现**：
 *   1. `src/lib/notify.mjs`          —— `TRIGGER_SET = 'diff.added'`，投递与否看这个集合；
 *   2. `.github/workflows/scan.yml`  —— 内联 `node -e` 读 `diff.added.length` 决定开不开 Issue；
 *   3. `src/index.mjs`（门禁）       —— `--fail-on` 只看 `diff.added` 决定退出码。
 *
 * 三处写的是同一套判据，但**没有一处是权威**。后果是任何一个方向要扩展
 * （「忽略的基线条目要不要参与告警」「严重度升级算不算变化」），都必须同时改三处；
 * 而三处中漏改任何一处，就会出现「CLI 说没变化、CI 却开了 Issue」这类自相矛盾的结论 ——
 * 对监控工具来说，这比漏报更难排查：使用者不知道该信哪个。
 *
 * 所以把判据收敛到本模块：**只此一处定义，下游（CLI 门禁 / Webhook / CI / 报告）只消费**。
 * 集合差的**本义**仍然由 `lib/diff.mjs` 定义（本模块在其上封装，不改它的判定语义）。
 *
 * ## 语义（与收敛前逐字对齐，不得放宽）
 *
 * | 字段 | 含义 |
 * |---|---|
 * | `added` | 本次出现、基线里没有的指纹（指纹 = `check:key:asset`，见 `findings.mjs`） |
 * | `resolved` | 基线里有、本次没有 |
 * | `persistent` | 两边都有（沿用基线的 `firstSeen`） |
 * | `changed` | **指纹未变但 severity / evidence 变了** —— 信息项，**不参与触发** |
 * | `ignored` | 因本次未扫描该资产而被过滤掉的基线条目（计数 + 条目摘要） |
 *
 * 触发判据只有一条：**`added` 非空**。`changed` 是趋势信息，`persistent` 的数量变化不是变化。
 *
 * ## 纯函数
 *
 * 本模块无 I/O、不读时钟、不含随机 —— 同样的入参永远得到同样的结果，
 * 因此可以用固定夹具离线单测（本项目所有 check 与判定都遵守这条）。
 *
 * @module lib/changeset
 */

import {
  diffFindings,
  hasAddedAtOrAbove as hasAddedAtOrAboveInDiff,
  isBaselineEstablishment,
} from './diff.mjs';

/**
 * 触发字段：`changeset.added`。
 *
 * 下游一律只读这一个集合来判定"要不要告警/要不要失败"，
 * 不要再各自去比对 `persistent` 数量或指纹内容。
 */
export const TRIGGER_FIELD = 'added';

/**
 * 从差异（或变化集）中找出「指纹未变但内容变了」的发现 —— **仅作信息项，不触发投递**
 *
 * 为什么需要它：`diff.mjs` 的指纹只由「资产 + 检查项 + 键」构成（这是对的，
 * 否则证据里一个字节的变化都会变成"假新增"）。但指纹稳定也意味着
 * **严重度升级**（如 medium → high）或**证据变化**（如证书剩余天数变少）
 * 在差异报告里是看不出来的。把它算出来放进载荷的 `summary.changed`，
 * 让下游能看见趋势；但它不参与"要不要投递"的判定 ——
 * 触发集合严格等于 `added`，否则证据文本抖动就会变成告警。
 *
 * @param {object} diffOrChangeset 变化集（或 diffFindings 的结果）
 * @param {Array} baseline 基线发现列表
 * @returns {Array} 变化项（附 changedFields / previousSeverity）
 */
export function detectChangedFindings(diffOrChangeset, baseline = []) {
  const baseMap = new Map((baseline || []).map((f) => [f.id, f]));
  const changed = [];

  for (const current of (diffOrChangeset && diffOrChangeset.persistent) || []) {
    const previous = baseMap.get(current.id);
    if (!previous) continue;

    const changedFields = [];
    if (previous.severity !== current.severity) changedFields.push('severity');
    if (String(previous.evidence ?? '') !== String(current.evidence ?? '')) {
      changedFields.push('evidence');
    }
    if (changedFields.length === 0) continue;

    changed.push({
      ...current,
      changedFields,
      previousSeverity: previous.severity ?? null,
    });
  }

  return changed;
}

/**
 * 把任意「差异结果」规范化为变化集。
 *
 * 用途有二：
 *   1. 兼容仍然持有**裸 diff 对象**的调用方（例如只做集合差、不关心 changed/ignored 的老代码）——
 *      规范化只在这一处做，不会散落到各个消费点；
 *   2. 让下游消费点的入参形状统一（`added`/`resolved`/`persistent`/`changed`/`ignored` 恒存在）。
 *
 * @param {object} diff 形如 `{added, resolved, persistent, ignoredCount?}` 的对象
 * @param {Array}  [baseline] 基线发现（用于计算信息项 changed）
 * @param {object} [extra]
 * @param {boolean} [extra.baselineEstablished]
 * @param {Array}   [extra.ignoredEntries] 被忽略的基线条目摘要
 * @returns {object} 变化集
 */
export function changesetFromDiff(diff = {}, baseline = [], extra = {}) {
  const added = diff.added || [];
  const resolved = diff.resolved || [];
  const persistent = diff.persistent || [];
  const changed = detectChangedFindings({ persistent }, baseline);
  const ignoredEntries = extra.ignoredEntries || [];
  const ignoredCount = Number.isFinite(extra.ignoredCount)
    ? extra.ignoredCount
    : Number.isFinite(diff.ignoredCount)
      ? diff.ignoredCount
      : ignoredEntries.length;

  return {
    added,
    resolved,
    persistent,
    changed,
    ignored: { count: ignoredCount, entries: ignoredEntries },
    baselineEstablished: Boolean(extra.baselineEstablished),
    triggerField: TRIGGER_FIELD,
  };
}

/**
 * 由「本次发现 + 基线 + 本次扫描的资产」算出变化集 —— 本项目唯一的判定入口。
 *
 * @param {object} input
 * @param {Array}  input.findings 本次的发现
 * @param {Array}  [input.baseline] 基线的发现（无历史时传空数组）
 * @param {string[]|null} [input.assets] 本次**实际扫描**的资产列表。
 *   务必传入！否则部分扫描时其它资产的基线条目会被误判为「已修复」——
 *   这正是 `ignored` 要透明化的那批条目。
 * @param {boolean} [input.baselineEstablished] 基线是否缺失（首次运行）；
 *   省略时按 `baseline` 是否为空推断（口径与 `diff.mjs` 的 `isBaselineEstablishment` 一致）
 * @returns {object} 变化集：`{added, resolved, persistent, changed, ignored, baselineEstablished, triggerField}`
 */
export function buildChangeset({
  findings = [],
  baseline = [],
  assets = null,
  baselineEstablished = null,
} = {}) {
  /* 非数组（null / undefined / 手写坏数据）一律按"没有基线"处理 —— 与
     `isBaselineEstablishment` 的口径一致，避免下游因为一个坏基线直接崩掉。 */
  const base = Array.isArray(baseline) ? baseline : [];
  const diff = diffFindings(findings, base, assets ? { assets } : {});

  return changesetFromDiff(diff, base, {
    baselineEstablished:
      baselineEstablished === null ? isBaselineEstablishment(base) : Boolean(baselineEstablished),
    /* 计数以 diffFindings 为准（它对基线里的重复 id 更稳）；
       条目摘要派生自集合差的结果：既不在 persistent、也不在 resolved 里的基线条目，
       就是没进入本次比对的那批 —— 不做第二次资产过滤，避免两处判据漂移。 */
    ignoredCount: diff.ignoredCount,
    ignoredEntries: ignoredEntriesOf(diff, base, assets),
  });
}

/**
 * 被忽略的基线条目摘要（`ignored.entries`）。
 *
 * 只在**本次限定了扫描资产**时才有意义：这时"基线里有、本次没进比对"才等价于
 * "因未扫描该资产而被过滤"。不做资产名过滤的第二次实现，只按集合差反推，
 * 保证与 `added/resolved/persistent` 用的是同一套判据。
 */
function ignoredEntriesOf(diff, baseline, assets) {
  if (!assets || assets.length === 0) return [];
  const seen = new Set([...diff.persistent, ...diff.resolved].map((f) => f.id));
  return (baseline || [])
    .filter((f) => !seen.has(f.id))
    .map((f) => ({
      fingerprint: f.id,
      asset: f.asset,
      check: f.check,
      key: f.key,
      severity: f.severity,
      title: f.title,
    }));
}

/**
 * 触发集合（唯一）：`added`。
 *
 * 任何"要不要告警 / 要不要让 CI 失败"的判定都从这里取，不要再各自取 diff 的子集。
 */
export function triggerFindings(changeset) {
  return (changeset && changeset.added) || [];
}

/**
 * 门禁判定：新增里是否有达到指定严重度的项。
 *
 * 严重度比较复用 `diff.mjs` 的同一实现（不重写比较逻辑），
 * 本模块只负责回答"新增集合是哪一个"。
 */
export function hasAddedAtOrAbove(changeset, severity) {
  return hasAddedAtOrAboveInDiff({ added: triggerFindings(changeset) }, severity);
}

/**
 * 变化集的**标量摘要** —— 供产物（`findings.json`、SARIF properties）与 CI 读取。
 *
 * 为什么要有标量形态：CI 脚本不该自己去数数组长度、更不该自己重新判断"什么算变化"。
 * 它只需要读一个已经算好的数字（`addedCount`），判据仍只有一处。
 */
export function summarizeChangeset(changeset) {
  const added = (changeset && changeset.added) || [];
  return {
    /* 下游读哪个字段判定"有新变化"：changeset.addedCount */
    triggerField: TRIGGER_FIELD,
    addedCount: added.length,
    resolvedCount: ((changeset && changeset.resolved) || []).length,
    persistentCount: ((changeset && changeset.persistent) || []).length,
    changedCount: ((changeset && changeset.changed) || []).length,
    ignoredCount: (changeset && changeset.ignored && changeset.ignored.count) || 0,
    hasAdded: added.length > 0,
    baselineEstablished: Boolean(changeset && changeset.baselineEstablished),
  };
}
