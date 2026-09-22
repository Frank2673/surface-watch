# surface-watch

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

- **纯函数化的 evaluate** 让全部规则都能用固定夹具离线单测（76 个断言，CI 中无需联网打真实目标）
- **指纹 = 资产 + 检查项 + 键**，不含证据文本 —— 否则响应长度变一个字节就会被误判为"新增发现"

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

**退出码**：`0` 正常 · `1` 触发门禁阈值 · `2` 运行错误（范围非法等）

## 定时监控（GitHub Actions）

仓库自带 `.github/workflows/scan.yml`：每周一自动扫描 `scope.json` 中的资产，
把报告写入 Actions 摘要并上传为 artifact，**有新发现时自动创建或更新 Issue**。

也可以在 Actions 页面手动触发（`workflow_dispatch`）。基线通过 Actions cache 跨运行保存。

## 项目结构

```
src/
├── index.mjs             CLI 入口（参数解析、退出码语义）
├── lib/
│   ├── scope.mjs         🔒 Scope Gate：授权范围模型与强制校验
│   ├── http.mjs          HTTP 客户端（超时/重试/重定向/截断检测）
│   ├── findings.mjs      发现模型（证据 + 影响 + 修复建议）
│   ├── diff.mjs          基线差异（新增 / 已修复 / 持续存在）
│   ├── report.mjs        Markdown / JSON / 控制台摘要
│   └── scan.mjs          编排：采集 → 评估 → 汇总
└── checks/               dns / tls / headers / paths / ct
tests/                    76 个断言，全部离线可跑
fixtures/                 虚构演示数据（RFC 2606 保留域名）
```

## 局限与边界

- 只做**被动与轻量检查**，不包含任何漏洞利用能力
- 不做端口扫描、不做目录爆破（此类行为需明确的书面授权与专用工具）
- `paths` 检查是基于特征匹配的**启发式判断**，不能替代人工验证
- 证书透明度查询依赖第三方服务（crt.sh），不可用时自动降级为「跳过」，不会影响其它检查

## 使用须知

**只有在满足以下条件时才能对本工具配置的资产发起检查**：

1. 你是该资产的所有者，或
2. 你持有资产所有者签署的**书面授权**（且范围明确）

详见 [SECURITY.md](SECURITY.md)。作者不对任何未授权使用承担责任。

## 路线图

- [ ] 输出 SARIF 格式，接入 GitHub Code Scanning 告警面板
- [ ] 支持邮件/Webhook 通知（Slack、飞书、企业微信）
- [ ] 增加 `robots.txt` / `security.txt` 检查
- [ ] 支持多目标并发采集（当前为顺序执行，换取更好的可控性）
- [ ] 报告增加趋势图（近 N 次运行的严重度变化）

## 许可

[MIT](LICENSE) © 2026 Frank2673

---

<sub>零依赖：全部功能仅使用 Node.js 内置模块（`dns` / `tls` / `https` / `crypto` / `zlib` / `test`），不引入任何第三方包。</sub>
