# surface-watch

[English](README.en.md) | 简体中文

[![CI](https://github.com/Frank2673/surface-watch/actions/workflows/ci.yml/badge.svg)](https://github.com/Frank2673/surface-watch/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**零依赖的攻击面监控与基线差异工具** —— 只对已授权的资产做被动侦察，每次运行产出报告，并告诉你**变化了什么**。

> 安全监控的价值在于「变化」。一份全量清单看十遍也看不出问题，但「昨天没有、今天多了一条高危」一眼就能看见。

---

## 为什么做这个

任何渗透测试或红队任务都从**侦察**开始。而工业界的真实痛点不是"扫一遍"，而是：

- 新上线的子域没人管 → 影子资产
- 证书快过期了没人知道 → 到期当天全站报警
- 安全响应头被某次发布改掉了 → 无人察觉的防护降级
- 遗漏配置的 `.env` 被部署上去 → 直到被人下载才发现

本工具解决的就是这一类问题：**持续监控 + 变化告警**，而不是一次性扫描。

## 核心特色：授权纪律内置（Scope Gate）

这是本工具与"随便写的扫描脚本"最本质的区别：

| 机制 | 说明 |
|---|---|
| **范围强制** | 只有写在 `scope.json` 里的域名（及其子域）才会被检查，其余一律拒绝 |
| **禁止越界目标** | 内网段、回环、链路本地、云元数据地址（`169.254.169.254` 等）**硬拒绝**，连写进配置也不允许 |
| **必须声明授权** | 缺少授权声明时直接拒绝启动 |
| **默认被动** | 主动路径探测默认**关闭**，需显式开启 |
| **限速** | 并发与请求间隔被限制在安全区间，避免把目标打成压力测试 |

```
$ node src/index.mjs --scope scope.json
🛑 范围校验失败：目标不在授权范围内（scope.json 的 assets 未声明该域名）
   —— 本工具拒绝检查任何未在 scope.json 中声明的资产。
```

## 快速开始

零依赖，不需要 `npm install`（Node ≥ 20）：

```bash
# 1. 声明你的资产与授权
cp scope.json.example scope.json   # 或直接编辑 scope.json

# 2. 真实扫描（会访问网络）
node src/index.mjs --scope scope.json --out out --update-baseline

# 3. 离线演示（用夹具数据，不发起任何网络请求）
node src/index.mjs --scope fixtures/demo-scope.json \
                   --fixture fixtures/demo-observations.json --out out-demo

# 4. 跑测试
node --test tests/          # Linux/macOS/CI
```

查看报告：`out/report.md`（人看）与 `out/findings.json`（机器看）。

## 检查项

| 检查 | 默认 | 检查内容 | 典型发现 |
|---|---|---|---|
| `dns` | ✅ | A/AAAA/CNAME/NS/MX/TXT/CAA | 无 SPF（可伪造发件人）、SPF 用 `+all`、无 DMARC、缺 CAA |
| `tls` | ✅ | 证书有效期、协议版本、可信性 | 证书 ≤14 天到期（高）、已过期（严重）、TLS 1.0/1.1（高）、自签/不受信 |
| `headers` | ✅ | 安全响应头的 8 项评分 | 无 HSTS、无 CSP、无点击劫持防护、`Server` 头暴露版本 |
| `paths` | ⛔ 需显式开启 | 敏感路径暴露（先建软 404 基线，再按内容特征确认） | `.env` 可下载（严重）、`.git/config` 可读（高） |
| `ct_logs` | ⛔ 需显式开启 | 证书透明度日志中的子域 | 已被遗忘的影子资产 |

### 误报控制

安全工具最怕的是「狼来了」。因此本项目在判据上刻意**宁可漏报，不可误报**：

- 路径探测先请求随机路径建立**软 404 基线**，长度接近基线的一律不报
- 已知敏感路径必须命中**内容特征**才算确认（如 `.git/config` 必须含 `[repositoryformatversion]`）
- 没有任何观测数据时**不下任何结论**（"未采集" ≠ "有问题"）

## 工作原理

```
collect（采集，碰网络）  →  evaluate（评估，纯函数）  →  report（报告）
     ↓                          ↓                         ↓
 DNS/TLS/HTTP/路径         规则判定 + 分级            Markdown / JSON / 摘要
```

- **纯函数化的 evaluate** 让全部规则都能用固定夹具离线单测（CI 中无需联网打真实目标）
- **指纹 = 资产 + 检查项 + 键**，不含证据文本 —— 否则响应长度变一个字节就会被误判为"新增发现"

## 单一变化源：`src/lib/changeset.mjs`

「什么算变化」只有**一处**实现，其余地方一律消费它：

| 通道 | 消费方式 |
|---|---|
| CLI 门禁（`--fail-on`，退出码） | `hasAddedAtOrAbove(changeset, 级别)` |
| Webhook 投递 | `triggerFindings(changeset)`（严格等于 `changeset.added`） |
| CI（`scan.yml` 的 Issue 步骤） | 读产物 `findings.json` 的 `changeset.addedCount` |

为什么收敛：这三处原先各自实现了一遍同一套判据，任何一处漏改都会造成
「CLI 说没变化、CI 却开了 Issue」这类自相矛盾的结论。语义（不得放宽）：

| 字段 | 含义 | 是否触发 |
|---|---|---|
| `added` | 本次出现、基线里没有的指纹 | ✅ 唯一触发集合 |
| `resolved` | 基线有、本次没有 | ❌ |
| `persistent` | 两边都有（沿用基线 `firstSeen`） | ❌ |
| `changed` | **指纹未变**但 severity/evidence 变了 | ❌ 仅信息项（`summary.changed`） |
| `ignored` | 因本次未扫描该资产而被过滤掉的基线条目 | ❌ 透明化计数 |

## 产物契约（`out/findings.json`）

既有字段名与语义**不变**，只新增三处（纯增量，既有消费者不受影响）：

```jsonc
{
  "baselineEstablished": false,          // 本次是否为首轮建立基线（原先只在内部使用）
  "diff": { "added": [], "resolved": [], "persistent": [], "ignoredCount": 0 },
  "changeset": {                         // 单一变化源的标量摘要，供 CI 直接读
    "triggerField": "added",
    "addedCount": 0, "resolvedCount": 0, "persistentCount": 0,
    "changedCount": 0, "ignoredCount": 0,
    "hasAdded": false, "baselineEstablished": false
  }
}
```

- `diff.ignoredCount`：部分扫描（`--asset`）时"莫名少了"的基线条目数 —— 之前内部已算出、只是没落盘
- CI 判定**只读 `changeset.addedCount`**；产物里没有这个字段时判定命令会显式报错退出，
  而不是把"判据未知"当成"没有变化"
- SARIF 的 `runs[0].properties` 同步带 `addedCount` / `ignoredCount` / `baselineEstablished` 等计数，
  `partialFingerprints` 与既有字段完全不变

## 命令行参数

| 参数 | 说明 |
|---|---|
| `--scope <路径>` | 范围文件（默认 `scope.json`） |
| `--out <目录>` | 输出目录（默认 `out`） |
| `--baseline <路径>` | 基线文件（默认 `state/baseline.json`） |
| `--update-baseline` | 本次运行后更新基线 |
| `--fixture <路径>` | 用夹具代替网络（不发起任何请求） |
| `--only <检查项>` | 只跑指定检查，逗号分隔 |
| `--fail-on <严重度>` | 出现该级别及以上的**新增**发现时退出码为 1（用于 CI 门禁） |
| `--sarif [路径]` | 额外输出 SARIF 报告（默认 `out/results.sarif`），可上传至 GitHub Code Scanning |
| `--webhook <url>` | Webhook 告警地址；**仅当本次出现新增指纹时**投递（见下节）。可用环境变量 `SURFACE_WATCH_WEBHOOK_URL` 回退 |
| `--webhook-secret <s>` | 可选：对请求体做 HMAC-SHA256 签名。可用环境变量 `SURFACE_WATCH_WEBHOOK_SECRET` 回退 |
| `--webhook-min-severity <级别>` | 告警阈值，默认 `medium`；只投递该级别及以上的新增 |
| `--webhook-timeout <ms>` | **单次投递的 socket 空闲超时**，默认 `5000`。只覆盖"一次尝试里 socket 无数据"，**不是**投递总时长 |
| `--webhook-deadline <ms>` | **投递整体截止时间**，默认 `max(10000, 3 × --webhook-timeout)`（`--webhook-timeout 5000` 时 = `15000`）。覆盖 connect + 响应头 + 响应体 + 退避 + 全部重试的总时长 |
| `--webhook-include-initial` | 基线缺失（首次运行）时也投递首轮全量；**默认跳过** |

**退出码**：`0` 正常 · `1` 触发门禁阈值 · `2` 运行错误（范围非法等）

## 接入 GitHub Code Scanning

用 `--sarif` 产出标准 SARIF 报告，即可让发现直接出现在仓库的 **Security 面板**：可指派、可标记误报、可跟踪修复状态，团队不必打开报告才知道出了问题。

```bash
node src/index.mjs --scope scope.json --out out --sarif
```

```yaml
# 工作流中上传（需 permissions: security-events: write）
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: out/results.sarif
    category: surface-watch
```

**两个设计细节**：

1. **告警指纹与内部差异比对共用同一套**（`partialFingerprints`）——
   因此同一条发现跨多次运行会被 GitHub 识别为同一个告警，不会反复新增。
2. **位置落在 `scope.json`**（而非资产 URL）—— Code Scanning 的告警需要落在仓库内真实存在的文件上；
   资产正是在那里声明的，也是你会去改动它的地方。资产 URL 完整保留在告警消息与属性中，信息不丢失。

严重度映射：`critical/high` → `error`，`medium` → `warning`，`low/info` → `note`；
同时写入 `security-severity` 分值（9.5 / 8.0 / 5.5 / 3.0 / 1.0），供 GitHub 侧分级排序。

## 定时监控（GitHub Actions）

仓库自带 `.github/workflows/scan.yml`：每周一自动扫描 `scope.json` 中的资产，
把报告写入 Actions 摘要、上传为 artifact、**并把 SARIF 上传到 Code Scanning**，
**有新发现时自动创建或更新 Issue**。

Issue 的判定**不在 workflow 里自己算**：它读 `out/findings.json` 的 `changeset.addedCount`
（由单一变化源 `src/lib/changeset.mjs` 算出），为 0 就保持安静 ——
这样判据扩展时不会出现"改了 CLI、漏改 CI"的偏差。

也可以在 Actions 页面手动触发（`workflow_dispatch`）。基线通过 Actions cache 跨运行保存。

## Webhook 告警（只推变化，不刷全量清单）

监控结果只有被送到人面前才有价值。Webhook 把「本次出现了什么新问题」推到 Slack / 飞书 / 企业微信 / 自建告警台（本版本提供**通用传输层**，平台适配留待后续）。

```bash
# 仅在出现新增发现时投递；地址与密钥都从环境变量读（不要写进仓库文件）
export SURFACE_WATCH_WEBHOOK_URL='https://hooks.example.com/services/XXX/YYY'
export SURFACE_WATCH_WEBHOOK_SECRET='…'        # 可选：启用 HMAC-SHA256 签名

node src/index.mjs --scope scope.json --out out --update-baseline
```

### 触发语义：严格等于「新增指纹」

| 情况 | 行为 |
|---|---|
| 本次出现基线里没有的指纹（`diff.added`） | **投递** |
| `diff.added` 为空（哪怕证据文本变了、发现总数变了） | **不投递**（no-op，一次网络请求都不发） |
| 指纹未变、但严重度或证据发生变化 | **不投递**；只作为载荷里的信息项 `summary.changed`（看趋势用） |
| 基线文件不存在或为空（首次运行） | **默认不投递**，stderr 一行说明；确需推送首轮全量时加 `--webhook-include-initial` |

首次运行必须静默，是因为这时「全部发现都是新增」只是基线缺失的假象，不是变化。

**不承诺「同一问题只推一次」**：指纹是 `check:key:asset`，同一类问题在 `key` 变化时会产生新的"新增"。典型例子是证书到期按剩余天数分三档（`cert-expiring` → `cert-expiring-urgent` → `cert-expired`），同一张证书最多会触发 3 次新增告警，旧指纹同时被记为「已修复」。因此载荷里**每条 finding 都带 `fingerprint` 字段**（与 SARIF `partialFingerprints` 同源），下游可按它自行去重。

### 两个阈值是两件事，别混用

| 参数 | 作用 | 语义 |
|---|---|---|
| `--fail-on <级别>` | 控制**退出码** | 严格阈值：无变化 = 0；新增 high 且 `--fail-on high` = 1；`--fail-on critical` = 0 |
| `--webhook-min-severity <级别>` | 控制**推不推、推哪些** | 过滤对象是 `diff.added`；默认 `medium` |

默认阈值取 `medium` 的依据是本项目既有的严重度 → SARIF level 映射（见「接入 GitHub Code Scanning」一节）：`critical/high` → `error`、`medium` → `warning` 是需要人处理的两档，`low/info` → `note` 属信息档。要连信息项一起推就显式放宽到 `low`/`info`。

### 载荷

`POST`，`Content-Type: application/json`：

```jsonc
{
  "tool": "surface-watch",
  "version": "0.1.0",
  "generatedAt": "2026-09-24T17:35:00.000Z",
  "scope": { "owner": "…", "assets": ["example.com"], "statement": "…" },
  "summary": {
    "new": 1, "changed": 0, "removed": 2,
    "bySeverity": { "critical": 0, "high": 0, "medium": 1, "low": 0, "info": 0 },
    "ignored": { "new": 0, "changed": 0 }      // 低于阈值、被忽略的新增
  },
  "delivery": { "triggerSet": "diff.added", "initial": false, "threshold": "medium",
                "changedIsInformational": true, "signed": true },
  "findings": [ { "fingerprint": "tls:cert-expiring:demo.example.com", "change": "new", "…": "…" } ]
}
```

载荷里**不含**密钥、环境变量或任何凭据。

### 签名（可选）

提供 `--webhook-secret` / `SURFACE_WATCH_WEBHOOK_SECRET` 时，对**请求体原字节**做 HMAC-SHA256，请求头：

```
X-Surface-Watch-Signature: sha256=<hex>
```

接收端只要手里有共享密钥与原始 body 就能独立复算，不需要理解本工具的任何状态：

```bash
node -e "const c=require('crypto');console.log('sha256='+c.createHmac('sha256',process.env.SECRET).update(require('fs').readFileSync('body.json')).digest('hex'))"
```

### 失败语义：告警通道坏掉，不能让监控本身也坏掉

- 投递失败**不改变**扫描退出码，`out/report.md` 与 `out/findings.json` 照常生成
- 错误写 **stderr**（明确写出状态码或错误码与尝试次数）
- 投递结果写 **`out/webhook-delivery.json`**（`ok` / `delivered` / `statusCode` / `attempts` / `error` / `attemptLog` / `deadlineMs` / `deadlineExceeded`）
- 记录里的 `errorBody` 是**按字节截断**的响应体片段（保留前 200 字节 + 标注"已截断：响应体共 N 字节"）：无论响应体多大、怎么分块，都能留下可诊断的内容；只有确实没超限时才原样保留
- 重试策略：**网络错误与 5xx** 重试（最多 2 次，退避 250ms → 500ms）；**4xx 不重试**
- **3xx 一律视为失败、不跟随重定向** —— 一个 `Location` 头就能把载荷转发到未配置的第三方地址，宁可失败也不要它偷偷成功
- 记录文件里的 URL 会脱敏 query、userinfo 与动态 path 段（Webhook URL 常把 token 放在 query 或 path 上，原样落盘等于把凭据写进文件）

#### 两层超时：`--webhook-timeout` 与 `--webhook-deadline` 是两件事

| 参数 | 层次 | 覆盖范围 | 触达时的错误 |
|---|---|---|---|
| `--webhook-timeout` | 单次尝试 | 一次尝试里 **socket 空闲**（完全没数据） | `TIMEOUT`（按网络错误重试） |
| `--webhook-deadline` | 整体投递 | connect + 响应头 + 响应体 + 退避 + **全部重试** | `DEADLINE_EXCEEDED`（不再重试） |

为什么缺一不可：**慢速接收端**（回 `200 OK` + `Transfer-Encoding: chunked`，之后每 200ms 只发 1 字节且永不结束）会让 socket 始终"有数据"，**空闲超时永远不会触发** —— 实测在 `--webhook-timeout 1500` 下，进程 40s 硬上限内不退出、不写投递记录、不走基线更新与退出码，等于告警通道可以永久挂死监控进程。只有覆盖总时长的整体截止时间能把它掐断。

触达整体截止时间时的语义（与"重试完还是失败"区分开）：

- `ok=false`、`delivered=false`、`reason="delivery-failed"`；
- `error` 以 `DEADLINE_EXCEEDED` 开头（**不要**与 per-attempt 的 `TIMEOUT` 混看），并写明实际尝试次数；
- `attempts` 只计**真实发生**的尝试（预算耗尽后不再发起新尝试，不虚增）；
- `deadlineExceeded=true`、`deadlineMs` 为本次生效的整体预算；
- 扫描产物（`report.md` / `findings.json`）与退出码**原样不变** —— 提前结束投递不等于改变扫描结论。

调参建议：接收端已知很慢（如跨区域链路）就调大 `--webhook-timeout`，整体预算会跟着变成 `3 ×`；只想要一个硬上界就单独给 `--webhook-deadline`（可以比 `--webhook-timeout` 小，此时单次空闲超时会被剩余预算夹住，报的都是 `DEADLINE_EXCEEDED`）。

#### 记录里的 `urlHash`：对**脱敏后**的 URL 取哈希

`webhook-delivery.json` 的 `urlHash` 用于跨记录关联，但它算的是**脱敏后** URL 的 sha256 前 12 位，不是完整 URL。

原因：对完整 URL 取哈希等于在记录里留一个**可校验的预言机**。`urlHash` 是完整 URL 的 sha256 前 12 位（48 bit、无盐），攻击者拿同一条记录里已脱敏的 url 前缀（`http://127.0.0.1:8801/hook/Ab***`）即可离线枚举候选并逐个比对哈希，还原低熵凭据 —— 实测 7,122,554 个候选 / 11.8s 就还原出 `http://127.0.0.1:8801/hook/AbC123`，脱敏形同虚设。改为对脱敏结果取哈希后，候选串算出的哈希与记录里的**不一致**，猜测无法被验证，且不需要引入盐或密钥存储（零依赖前提不变）。

**副作用（有意取舍，必须知情）**：跨记录关联的粒度变粗。同一前缀、不同令牌的 URL（`/hook/AbC123` 与 `/hook/AbC456` 都脱敏成 `/hook/Ab***`）会得到**相同的 `urlHash`** —— `urlHash` 相同只说明"脱敏后的形态相同"，不再能证明是同一次配置。这是为消除凭据枚举付的代价；主机 / 端口 / 结构性路径段不同仍可区分。

### 本地端到端验证（不用真实告警通道）

仓库自带一个零依赖假接收服务，把每个请求的方法/路径/头/原始 body 逐行写入 JSONL，并可注入故障：

```bash
# 起假接收端（默认只绑回环 127.0.0.1；绑非回环地址需 --allow-remote）
node scripts/fake-webhook.mjs --port 8787 --log tmp/webhook-e2e/received.jsonl --secret s3cr3t

# 另开一个终端：跑一次真实 CLI（首次运行会建立基线，不投递）
node src/index.mjs --scope fixtures/demo-scope.json --fixture fixtures/demo-observations.json \
  --out tmp/webhook-e2e/out --baseline tmp/webhook-e2e/baseline.json --update-baseline \
  --webhook http://127.0.0.1:8787/hook --webhook-secret s3cr3t

# 故障注入：持续 500（验证重试与失败不破坏扫描）
node scripts/fake-webhook.mjs --fail-status 500
node scripts/fake-webhook.mjs --fail-status 500 --fail-times 2   # 前两次失败，第三次成功
node scripts/fake-webhook.mjs --delay 8000                        # 配合 --webhook-timeout 触发超时
node scripts/fake-webhook.mjs --redirect https://evil.invalid/x    # 验证不跟随重定向
```
## 项目结构

```
src/
├── index.mjs             CLI 入口（参数解析、退出码语义）
├── lib/
│   ├── scope.mjs         🔒 Scope Gate：授权范围模型与强制校验
│   ├── http.mjs          HTTP 客户端（超时/重试/重定向/截断检测）
│   ├── findings.mjs      发现模型（证据 + 影响 + 修复建议）
│   ├── diff.mjs          基线差异（新增 / 已修复 / 持续存在）
│   ├── changeset.mjs     🔔 单一变化源：什么算变化只在这里定义（CLI/Webhook/CI 都消费它）
│   ├── notify.mjs        Webhook 告警投递（触发语义 / 签名 / 失败不破坏扫描）
│   ├── report.mjs        Markdown / JSON / 控制台摘要
│   └── scan.mjs          编排：采集 → 评估 → 汇总
└── checks/               dns / tls / headers / paths / ct
tests/                    全部离线可跑（node --test tests/）
fixtures/                 虚构演示数据（RFC 2606 保留域名）
scripts/
├── check-zero-deps.mjs   零依赖自检（CI 强制）
└── fake-webhook.mjs      本机假 Webhook 接收服务（端到端验证 + 故障注入）
```

## 局限与边界

- 只做**被动与轻量检查**，不包含任何漏洞利用能力
- 不做端口扫描、不做目录爆破（此类行为需明确的书面授权与专用工具）
- `paths` 检查是基于特征匹配的**启发式判断**，不能替代人工验证
- 证书透明度查询依赖第三方服务（crt.sh），不可用时自动降级为「跳过」，不会影响其它检查
- Webhook 投递地址由使用者显式配置，因此**不受 Scope Gate 约束**（它决定「告警发去哪」，不是「扫什么」）；扫描目标本身仍然一律经过 Scope Gate
- Webhook 无法保证「同一问题只推一次」（指纹随 `key` 换档位会变），去重请用载荷里的 `fingerprint`

## 使用须知

**只有在满足以下条件时才能对本工具配置的资产发起检查**：

1. 你是该资产的所有者，或
2. 你持有资产所有者签署的**书面授权**（且范围明确）

详见 [SECURITY.md](SECURITY.md)。作者不对任何未授权使用承担责任。

## 路线图

- [x] 输出 SARIF 格式，接入 GitHub Code Scanning 告警面板 ✅
- [x] Webhook 通知（通用传输层：触发语义 / HMAC 签名 / 失败不破坏扫描 / 本机假接收端可端到端验证）✅
- [ ] Webhook 平台适配卡片（Slack / 飞书 / 企业微信 的模板与验签头差异）
- [ ] 邮件通知
- [ ] 增加 `robots.txt` / `security.txt` 检查
- [ ] 支持多目标并发采集（当前为顺序执行，换取更好的可控性）
- [ ] 报告增加趋势图（近 N 次运行的严重度变化）

## 许可

[MIT](LICENSE) © 2026 Frank2673

---

<sub>零依赖：全部功能仅使用 Node.js 内置模块（`dns` / `tls` / `https` / `crypto` / `zlib` / `test`），不引入任何第三方包。</sub>
