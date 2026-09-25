# 更新日志

本项目的所有重要变更都记录在此文件。

格式遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

> **0.1.0 是本仓库的首个 tagged release。** 本条目按最终状态编写，
> 因此「新增」一节覆盖了从首个提交 `5c3455f` 到本版本的全部能力，
> 而不是某一次发布的增量。文中每一节末尾标注来源，便于逐条核对。

## [Unreleased]

## [0.1.0] - 2026-09-25

**首个 tagged release。** 零依赖的攻击面监控与基线差异 CLI：
对已授权资产做被动侦察，每次运行产出报告，并只告诉你**变化了什么**。

### 新增

- **Scope Gate —— 授权纪律内置（`src/lib/scope.mjs`）**
  - 范围强制：只有写在 `scope.json` 里的域名（及其子域）才会被检查，其余一律拒绝
  - 禁止越界目标：内网段、回环、链路本地、云元数据地址（`169.254.169.254` 等）**硬拒绝**，
    连写进配置也不允许
  - 必须声明授权：缺少授权声明时直接拒绝启动
  - 默认被动：主动路径探测默认**关闭**，需显式开启
  - 限速：并发与请求间隔被限制在安全区间
  - 〔来源：README「核心特色：授权纪律内置（Scope Gate）」五项机制表 + `src/lib/scope.mjs` + commit `5c3455f`〕

- **五项检查（`src/checks/*.mjs`）**
  - `dns`（默认开）：A/AAAA/CNAME/NS/MX/TXT/CAA —— 无 SPF、SPF `+all`、无 DMARC、缺 CAA
  - `tls`（默认开）：证书有效期、协议版本、可信性 —— ≤14 天到期（高）、已过期（严重）、
    TLS 1.0/1.1（高）、自签/不受信
  - `headers`（默认开）：安全响应头的 8 项评分 —— 无 HSTS、无 CSP、无点击劫持防护、
    `Server` 头暴露版本
  - `paths`（**需显式开启**）：敏感路径暴露 —— 先建软 404 基线，再按内容特征确认
  - `ct_logs`（**需显式开启**）：证书透明度日志中的子域
  - 〔来源：README「检查项」表 + `src/checks/{dns,tls,headers,paths,ct}.mjs` + `--help` 的 `--only` 取值〕

- **误报控制：宁可漏报，不可误报**
  - 路径探测先请求随机路径建立**软 404 基线**，长度接近基线的一律不报
  - 已知敏感路径必须命中**内容特征**才算确认（如 `.git/config` 必须含 `[repositoryformatversion]`）
  - 没有任何观测数据时**不下任何结论**（"未采集" ≠ "有问题"）
  - 〔来源：README「误报控制」+ commit `5c3455f` 的「指纹不含证据文本」说明〕

- **基线差异与指纹（`src/lib/diff.mjs`、`src/lib/findings.mjs`）**
  - 只报告变化：`added` / `resolved` / `persistent`
  - **指纹 = 资产 + 检查项 + 键**，不含证据文本 —— 否则响应长度变一个字节就会被误判为"新增发现"
  - 〔来源：README「工作原理」+ `src/lib/diff.mjs`〕

- **单一变化源（`src/lib/changeset.mjs`）**
  - 「什么算变化」收敛到**一处**实现，CLI 门禁 / Webhook / CI 三处一律消费它；
    此前三处各自实现同一套判据，任何一处漏改都会造成「CLI 说没变化、CI 却开了 Issue」
  - 触发集合严格等于 `added`；`resolved` / `persistent` / `changed` / `ignored` 均不触发
  - 落盘新增 `diff.ignoredCount`、`changeset` 标量摘要、`baselineEstablished`（纯增量，
    既有字段名与语义不变）
  - CI 判定**只读 `changeset.addedCount`**；产物里没有这个字段时判定命令显式报错退出，
    而不是把"判据未知"当成"没有变化"
  - 〔来源：commit `b1035b6` + README「单一变化源」「产物契约」两节 + `src/lib/changeset.mjs`〕

- **SARIF 输出，接入 GitHub Code Scanning（`src/lib/sarif.mjs` + `--sarif [路径]`）**
  - 严重度映射：`critical`/`high` → `error`，`medium` → `warning`，`low`/`info` → `note`，
    同时写入 `security-severity` 分值（9.5 / 8.0 / 5.5 / 3.0 / 1.0）
  - 规则按「检查项:键」聚合；`partialFingerprints` 复用内部差异比对的指纹 →
    GitHub 侧告警稳定不漂移
  - 告警位置落在 `scope.json`（Code Scanning 需要告警落在仓库内真实存在的文件上），
    资产 URL 完整保留在告警消息与 properties 中
  - 内置 `validateSarif()` 自校验，结构不合规时本地就拦住
  - CI 增加离线 SARIF 校验步骤，防止结构回归
  - 〔来源：commit `b8adf58` + README「接入 GitHub Code Scanning」+ `tests/sarif.test.mjs`〕

- **Webhook 告警投递：只推变化，不刷全量清单（`src/lib/notify.mjs`）**
  - 触发语义严格等于「新增指纹」（`diff.added`）；无新增则一次网络请求都不发
  - **首次运行默认静默**（基线缺失时"全部发现都是新增"是假象而非变化），
    确需推送首轮全量时加 `--webhook-include-initial`
  - 指纹未变但严重度/证据变化只作为载荷信息项 `summary.changed`，不触发投递
  - **不承诺「同一问题只推一次」**并在文档里写明：指纹是 `check:key:asset`，
    证书到期按剩余天数分三档，同一张证书最多触发 3 次新增；载荷里每条 finding 都带
    `fingerprint`，去重交给下游
  - 两个阈值分离：`--fail-on` 管退出码、`--webhook-min-severity` 管推不推（默认 `medium`）
  - **两层超时**：`--webhook-timeout` 是单次尝试的 socket 空闲超时；
    `--webhook-deadline`（默认 `max(10000, 3 × timeout)`）覆盖 connect + 响应头 +
    响应体 + 退避 + 全部重试的总时长
  - **失败不破坏扫描**：投递失败只写 stderr 与 `out/webhook-delivery.json`，
    不改变扫描退出码与既有产物
  - 重试策略：网络错误与 5xx 重试（最多 2 次，退避 250ms → 500ms）；4xx 不重试
  - 可选 HMAC-SHA256 签名：对**请求体原字节**计算，请求头
    `X-Surface-Watch-Signature: sha256=<hex>`
  - 载荷**不含**密钥、环境变量或任何凭据
  - 〔来源：commit `a2c7276` + README「Webhook 告警」全节 + `src/lib/notify.mjs`〕

- **本机端到端验证与故障注入（`scripts/fake-webhook.mjs`）**
  - 零依赖假接收服务，把每个请求的方法/路径/头/原始 body 逐行写入 JSONL
  - 默认只绑回环 `127.0.0.1`；绑非回环地址需 `--allow-remote`
  - 故障注入：`--fail-status`、`--fail-times`、`--delay`、`--redirect`
  - 〔来源：README「本地端到端验证」+ `scripts/fake-webhook.mjs`〕

- **定时监控与门禁（`.github/workflows/scan.yml`、`ci.yml`）**
  - 每周一自动扫描 `scope.json` 中的资产，写 Actions 摘要、上传 artifact、
    上传 SARIF 到 Code Scanning，**有新发现时自动创建/更新 Issue**
  - Issue 判定**不在 workflow 里自己算**，读 `findings.json` 的 `changeset.addedCount`
  - CI 端到端验证 Scope Gate 的拒绝行为与门禁退出码语义
  - 〔来源：README「定时监控（GitHub Actions）」+ `.github/workflows/*.yml`〕

- **工程**
  - **零运行时依赖**：只用 Node 内置模块（`dns` / `tls` / `https` / `crypto` / `zlib` / `test`），
    CI 强制校验（`scripts/check-zero-deps.mjs`，当前 27 个源文件）
  - **Node.js >= 20**（`package.json` 的 `engines`）
  - **MIT 许可**（`LICENSE`）
  - **153 项单元测试**，全部离线可跑（`node --test tests/`），
    覆盖 Scope Gate / 差异 / 变化集 / DNS / TLS / 响应头 / 路径 / HTTP 截断 / SARIF / Webhook
  - 〔来源：`package.json` + `scripts/check-zero-deps.mjs` 实跑输出 + `tests/` 10 个测试文件实跑：
    153 pass / 0 fail〕

### 修复

> 以下均在本版本**发布之前**的开发期发现并修正，未进入任何已发布版本。
> 按 Keep a Changelog 的惯例保留记录，因为它们各自对应一个真实缺陷。

- **`urlHash` 曾是凭据枚举的预言机**：`webhook-delivery.json` 的 `urlHash` 原是对完整 URL
  取 sha256 前 12 位（48 bit、无盐），攻击者用同一条记录里已脱敏的 URL 前缀即可离线枚举
  候选逐个比对 —— 实测 7,122,554 个候选 / 11.8 s 还原出 `http://127.0.0.1:8801/hook/AbC123`，
  脱敏形同虚设。改为对**脱敏后**的 URL 取哈希：候选串算出的哈希与记录不一致，猜测无法被验证。
  副作用（有意取舍）：同一前缀、不同令牌的 URL 会得到相同的 `urlHash`，跨记录关联粒度变粗
  - 〔来源：README「记录里的 `urlHash`：对**脱敏后**的 URL 取哈希」〕

- **慢速接收端可以永久挂死监控进程**：`--webhook-timeout` 只覆盖单次尝试的 socket 空闲超时，
  而慢速接收端（回 `200 OK` + `Transfer-Encoding: chunked` 后每 200 ms 只发 1 字节且永不结束）
  会让 socket 始终"有数据" —— 实测在 `--webhook-timeout 1500` 下进程 40 s 硬上限内不退出、
  不写投递记录、不走基线更新与退出码。新增覆盖总时长的 `--webhook-deadline` 把它掐断
  - 〔来源：README「两层超时」小节〕

- **三处判据分叉**：`notify.mjs` 的 `TRIGGER_SET`、`scan.yml` 内联 `node -e` 读
  `diff.added.length`、`index.mjs` 门禁各有一份实现，没有一处是权威，后果是
  「CLI 说没变化、CI 却开了 Issue」这类自相矛盾。收敛为单一变化源 `src/lib/changeset.mjs`
  - 〔来源：commit `b1035b6`〕

- **CI artifact 曾包含投递记录**：`out/webhook-delivery.json` 含投递 URL（已脱敏），
  但 artifact 是对外可下载的长期产物，不该依赖「脱敏逻辑以后不会退化」这个假设 ——
  改为在打包阶段排除该文件，投递结果仍可在运行日志与 Actions 摘要中查看
  - 〔来源：commit `3ee8c18`（改 `.github/workflows/scan.yml`，未改 README）〕

### 安全

- **Scope Gate 是硬约束，不是提示**：未声明资产、内网 / 回环 / 链路本地 /
  云元数据地址一律拒绝，缺少授权声明即拒绝启动
- **Webhook 3xx 一律视为失败、不跟随重定向** —— 一个 `Location` 头就能把载荷转发到
  未配置的第三方地址，宁可失败也不要它偷偷成功
- **地址与密钥从环境变量读**（`SURFACE_WATCH_WEBHOOK_URL` / `SURFACE_WATCH_WEBHOOK_SECRET`），
  不写进仓库文件；记录里只留脱敏形态
- **投递记录里的 URL 会脱敏** query、userinfo 与动态 path 段
- **`errorBody` 按字节截断**（前 200 字节 + 标注总长度），既有可诊断内容又不会把大响应体落盘
- **HMAC-SHA256 签名**对请求体原字节计算，接收端凭共享密钥与原始 body 即可独立复算
- **Webhook 目标不受 Scope Gate 约束**（它决定「告警发去哪」，不是「扫什么」），
  扫描目标本身仍然一律经过 Scope Gate —— 这条边界在 README 里明确写出，避免被误读为漏洞
- 〔来源：README「核心特色」「Webhook 告警」「失败语义」各节 + SECURITY.md〕

### 已知局限

> 以下直接引自 README「局限与边界」一节，非本 CHANGELOG 自行发明。

- 只做**被动与轻量检查**，不包含任何漏洞利用能力
- 不做端口扫描、不做目录爆破（此类行为需明确的书面授权与专用工具）
- `paths` 检查是基于特征匹配的**启发式判断**，不能替代人工验证
- 证书透明度查询依赖第三方服务（crt.sh），不可用时自动降级为「跳过」，不会影响其它检查

补充两条由 README 其他章节明确写出的边界：

- Webhook 投递地址由使用者显式配置，因此**不受 Scope Gate 约束**
- Webhook **无法保证「同一问题只推一次」**（指纹随 `key` 换档位会变），去重请用载荷里的 `fingerprint`

### 使用须知

只有在以下条件之一成立时，才能对本工具配置的资产发起检查：① 你是该资产的所有者；
② 你持有资产所有者签署的**书面授权**（且范围明确）。详见 [SECURITY.md](SECURITY.md)。

[Unreleased]: https://github.com/Frank2673/surface-watch/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Frank2673/surface-watch/releases/tag/v0.1.0
