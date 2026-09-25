# surface-watch

English | [简体中文](README.md)

[![CI](https://github.com/Frank2673/surface-watch/actions/workflows/ci.yml/badge.svg)](https://github.com/Frank2673/surface-watch/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Zero-dependency attack-surface monitoring and baseline diffing** — it runs passive recon against authorized assets, emits a report every time, and tells you **what changed**.

> A security monitor is only worth anything if it tracks *change*. Reading a full inventory ten times reveals nothing; "this did not exist yesterday and it is high severity today" is visible at a glance.

---

## TL;DR (30 seconds)

| | |
|---|---|
| **What** | A CLI that checks a small set of domains you own — DNS, TLS, security headers, sensitive paths — and diffs each run against the previous one. |
| **Who it is for** | Security engineers, pentesters and small teams who already run reconnaissance and need *recurring* recon with change alerts, instead of a one-shot scan. |
| **Requires** | Node ≥ 20. No `npm install`, no third-party packages. |
| **Scope** | Only domains written in `scope.json`. Everything else is refused, by design. |
| **Does not do** | No exploitation, no port scanning, no directory brute-forcing. |

One command, offline (no network requests at all — it runs on bundled fixture data):

```bash
git clone https://github.com/Frank2673/surface-watch.git && cd surface-watch
node src/index.mjs --scope fixtures/demo-scope.json \
                   --fixture fixtures/demo-observations.json --out out-demo
```

Real output of that command (captured from this repository, verbatim):

```
📋 范围：1 个资产（所有者 demo）
🧪 离线模式：使用夹具 fixtures/demo-observations.json（不会发起任何网络请求）
🔍 开始评估…

🔴 有高危新增 | 资产 1 | 发现 16 | 新增 16 | 已修复 0 | 持续 0
  + [严重] demo.example.com · 环境变量文件 .env 可被公开访问
  + [严重] demo.example.com · 证书已过期
  + [高] demo.example.com · SPF 策略过于宽松（+all / ?all）
  + [高] demo.example.com · Git 配置目录可被公开访问
  + [高] demo.example.com · 证书不受信任
  + [高] demo.example.com · 使用了过时的 TLS 协议：TLSv1.1
  + [中] demo.example.com · 缺少 DMARC 记录
  + [中] demo.example.com · 缺少内容安全策略（CSP）
  + [中] demo.example.com · 缺少点击劫持防护（X-Frame-Options 与 frame-ancestors 均未设置）
  + [中] demo.example.com · 缺少 HSTS 响应头
  … 其余 6 条见报告

📄 报告：out-demo\report.md
🧾 数据：out-demo\findings.json
```

> **Translator's note (factual, not part of the Chinese README):** the tabular data
> above reads `scope: 1 asset (owner demo)` / `offline mode: using fixture ...` /
> `high-severity additions present | assets 1 | findings 16 | added 16 | resolved 0 | persistent 0`,
> and the numbered lines are `[critical] .env publicly accessible`, `[critical] certificate expired`,
> `[high] SPF too permissive`, `[high] .git/config publicly readable`, `[high] certificate untrusted`,
> `[high] obsolete TLS 1.1`, `[medium] no DMARC`, `[medium] no CSP`, `[medium] no clickjacking
> protection`, `[medium] no HSTS`, then `… 6 more in the report`. **The CLI's console output is
> currently Chinese-only** — that is a real limitation of the tool, not a documentation choice.

---

## Why this exists

Every penetration test or red-team engagement starts with **reconnaissance**. But the real-world pain point is not "scan once" — it is:

- a newly published subdomain nobody owns → shadow asset
- a certificate about to expire and nobody knows → the whole site alarms on the day it expires
- a security header silently dropped by some release → protection degraded with no one noticing
- a misconfigured `.env` deployed → discovered only when someone downloads it

This tool addresses exactly that class of problem: **continuous monitoring + change alerts**, not one-shot scanning.

## Core feature: authorization discipline built in (Scope Gate)

This is the essential difference between this tool and "some scanning script someone wrote":

| Mechanism | Behaviour |
|---|---|
| **Scope enforcement** | Only the domains declared in `scope.json` (and their subdomains) are ever checked; everything else is refused |
| **Forbidden targets** | Private ranges, loopback, link-local and cloud metadata addresses (`169.254.169.254` and friends) are **hard-refused** — you cannot even put them in the config |
| **Authorization must be declared** | If the authorization statement is missing, startup is refused |
| **Passive by default** | Active path probing is **off** by default and must be enabled explicitly |
| **Rate limiting** | Concurrency and request spacing are capped, so the target is never turned into a load test |

```
$ node src/index.mjs --scope scope.json
🛑 范围校验失败：目标不在授权范围内（scope.json 的 assets 未声明该域名）
   —— 本工具拒绝检查任何未在 scope.json 中声明的资产。
```

> Output: `scope validation failed: target is not within the authorized scope (the domain is not
> declared in scope.json's assets) — this tool refuses to check any asset not declared in
> scope.json.` Exit code `2`.

## Quick start

Zero dependencies, no `npm install` needed (Node ≥ 20):

```bash
# 1. Declare your assets and your authorization
cp scope.json.example scope.json   # or edit scope.json directly

# 2. Real scan (this one does touch the network)
node src/index.mjs --scope scope.json --out out --update-baseline

# 3. Offline demo (uses fixture data, makes no network requests)
node src/index.mjs --scope fixtures/demo-scope.json \
                   --fixture fixtures/demo-observations.json --out out-demo

# 4. Run the tests
node --test tests/          # Linux/macOS/CI
```

Read the reports: `out/report.md` (for humans) and `out/findings.json` (for machines).

## Checks

| Check | Default | What it inspects | Typical findings |
|---|---|---|---|
| `dns` | ✅ | A/AAAA/CNAME/NS/MX/TXT/CAA | no SPF (sender can be forged), SPF `+all`, no DMARC, no CAA |
| `tls` | ✅ | Certificate validity, protocol version, trust | certificate expiring within ≤14 days (high), already expired (critical), TLS 1.0/1.1 (high), self-signed / untrusted |
| `headers` | ✅ | 8-point scoring of security response headers | no HSTS, no CSP, no clickjacking protection, `Server` header leaking a version |
| `paths` | ⛔ opt-in | Sensitive path exposure (builds a soft-404 baseline first, then confirms by content signature) | `.env` downloadable (critical), `.git/config` readable (high) |
| `ct_logs` | ⛔ opt-in | Subdomains found in Certificate Transparency logs | forgotten shadow assets |

### False-positive control

The thing security tools are most feared for is crying wolf. So this project deliberately chooses **report nothing rather than report something wrong**:

- Path probing first requests a random path to establish a **soft-404 baseline**; anything whose length is close to that baseline is never reported
- A known sensitive path is only confirmed when its **content signature** matches (e.g. `.git/config` must contain `[repositoryformatversion]`)
- With no observation data at all, **no conclusion is drawn** ("not collected" ≠ "broken")

## How it works

```
collect (touches the network)  →  evaluate (pure functions)  →  report
     ↓                                ↓                           ↓
  DNS/TLS/HTTP/paths            rule evaluation + severity      Markdown / JSON / summary
```

- **A pure-function `evaluate`** means every rule can be unit-tested offline against fixed fixtures (CI never has to hit a real target)
- **A fingerprint = asset + check + key**, and excludes the evidence text — otherwise a single byte of change in a response length would be misread as a "new finding"

## Single source of change: `src/lib/changeset.mjs`

"What counts as a change" is implemented in exactly **one** place; everywhere else consumes it:

| Channel | How it consumes the changeset |
|---|---|
| CLI gate (`--fail-on`, exit code) | `hasAddedAtOrAbove(changeset, level)` |
| Webhook delivery | `triggerFindings(changeset)` (strictly equal to `changeset.added`) |
| CI (the Issue step in `scan.yml`) | reads `changeset.addedCount` from the `findings.json` artifact |

Why it was consolidated: these three places each used to re-implement the same criteria, so any one of them left un-updated produced self-contradictory outcomes such as "the CLI says nothing changed, but CI opened an issue". The semantics (which may not be relaxed):

| Field | Meaning | Triggers? |
|---|---|---|
| `added` | fingerprints present now that were not in the baseline | ✅ the only triggering set |
| `resolved` | present in the baseline, absent now | ❌ |
| `persistent` | present in both (keeps the baseline `firstSeen`) | ❌ |
| `changed` | **fingerprint unchanged** but severity/evidence changed | ❌ informational only (`summary.changed`) |
| `ignored` | baseline entries filtered out because that asset was not scanned this run | ❌ transparency counter |

## Output contract (`out/findings.json`)

Existing field names and semantics are **unchanged**; three things were added (purely additive, so existing consumers are unaffected):

```jsonc
{
  "baselineEstablished": false,          // whether this run established the baseline for the first time (previously internal only)
  "diff": { "added": [], "resolved": [], "persistent": [], "ignoredCount": 0 },
  "changeset": {                         // scalar summary of the single source of change, for CI to read directly
    "triggerField": "added",
    "addedCount": 0, "resolvedCount": 0, "persistentCount": 0,
    "changedCount": 0, "ignoredCount": 0,
    "hasAdded": false, "baselineEstablished": false
  }
}
```

- `diff.ignoredCount`: the number of baseline entries that "mysteriously went missing" during a partial scan (`--asset`) — it was already computed internally, just never written to disk
- CI decision-making reads **only `changeset.addedCount`**; if that field is absent from the artifact, the decision command exits with an explicit error instead of treating "criteria unknown" as "nothing changed"
- SARIF's `runs[0].properties` carries `addedCount` / `ignoredCount` / `baselineEstablished` and friends in step, while `partialFingerprints` and all existing fields stay exactly as they were

## Command-line reference

| Option | Description |
|---|---|
| `--scope <path>` | Scope file (default `scope.json`) |
| `--out <dir>` | Output directory (default `out`) |
| `--baseline <path>` | Baseline file (default `state/baseline.json`) |
| `--update-baseline` | Update the baseline after this run |
| `--fixture <path>` | Use fixtures instead of the network (makes no requests at all) |
| `--only <checks>` | Run only the named checks, comma-separated |
| `--fail-on <severity>` | Exit code 1 when an **added** finding at or above this severity appears (for CI gating) |
| `--sarif [path]` | Also write a SARIF report (default `out/results.sarif`), which can be uploaded to GitHub Code Scanning |
| `--webhook <url>` | Webhook alert URL; delivered **only when new fingerprints appear this run** (see below). Falls back to the `SURFACE_WATCH_WEBHOOK_URL` environment variable |
| `--webhook-secret <s>` | Optional: HMAC-SHA256 signature over the request body. Falls back to `SURFACE_WATCH_WEBHOOK_SECRET` |
| `--webhook-min-severity <level>` | Alert threshold, default `medium`; only additions at or above it are delivered |
| `--webhook-timeout <ms>` | **Socket idle timeout for a single delivery attempt**, default `5000`. It only covers "no data on the socket during one attempt" — it is **not** the total delivery duration |
| `--webhook-deadline <ms>` | **Overall delivery deadline**, default `max(10000, 3 × --webhook-timeout)` (= `15000` when `--webhook-timeout` is `5000`). Covers connect + response headers + response body + backoff + all retries |
| `--webhook-include-initial` | Also deliver the full first round when the baseline is missing (first run); **skipped by default** |

**Exit codes**: `0` normal · `1` gating threshold triggered · `2` runtime error (invalid scope, etc.)

## Integrating with GitHub Code Scanning

Produce a standard SARIF report with `--sarif` and your findings show up directly in the repository's **Security** panel: assignable, markable as false positive, and trackable through to fix — the team no longer has to open a report to learn something is wrong.

```bash
node src/index.mjs --scope scope.json --out out --sarif
```

```yaml
# Upload inside a workflow (requires permissions: security-events: write)
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: out/results.sarif
    category: surface-watch
```

**Two design details**:

1. **Alert fingerprints are shared with the internal diff comparison** (`partialFingerprints`) —
   so the same finding is recognised by GitHub as one alert across runs instead of being re-added each time.
2. **The location points at `scope.json`**, not at the asset URL — Code Scanning alerts must be anchored to a
   file that really exists in the repository; the asset is declared there, and that is where you will go to change
   it. The full asset URL is preserved in the alert message and properties, so nothing is lost.

Severity mapping: `critical/high` → `error`, `medium` → `warning`, `low/info` → `note`; a `security-severity` score (9.5 / 8.0 / 5.5 / 3.0 / 1.0) is written at the same time so GitHub can rank by severity.

## Scheduled monitoring (GitHub Actions)

The repository ships `.github/workflows/scan.yml`: every Monday it scans the assets in `scope.json`, writes the report into the Actions summary, uploads it as an artifact, **uploads the SARIF to Code Scanning**, and **automatically creates or updates an Issue when there are new findings**.

The Issue decision **is not computed inside the workflow**: it reads `changeset.addedCount` from `out/findings.json` (produced by the single source of change, `src/lib/changeset.mjs`) and stays quiet when that is 0 — so extending the criteria can never produce a "changed the CLI but forgot the CI" drift.

It can also be triggered manually from the Actions page (`workflow_dispatch`). The baseline is carried across runs via the Actions cache.

## Webhook alerts (push changes, not full inventories)

A monitoring result is only worth something once it reaches a human. The webhook pushes "what new problems appeared this run" into Slack / Feishu / WeCom / your own alerting console (this version provides the **generic transport layer**; per-platform adapters are left for later).

```bash
# Delivered only when there are new findings; URL and secret both come from the environment (never write them into repository files)
export SURFACE_WATCH_WEBHOOK_URL='https://hooks.example.com/services/XXX/YYY'
export SURFACE_WATCH_WEBHOOK_SECRET='…'        # optional: enables HMAC-SHA256 signing

node src/index.mjs --scope scope.json --out out --update-baseline
```

### Trigger semantics: strictly equal to "newly added fingerprints"

| Situation | Behaviour |
|---|---|
| A fingerprint appears that was not in the baseline (`diff.added`) | **delivered** |
| `diff.added` is empty (even if evidence text changed or the finding count changed) | **not delivered** (no-op, not a single network request) |
| Fingerprint unchanged but severity or evidence changed | **not delivered**; only carried as the informational item `summary.changed` in the payload (useful for trends) |
| Baseline file missing or empty (first run) | **not delivered by default**, with a one-line explanation on stderr; add `--webhook-include-initial` if you really want the full first round pushed |

The first run has to stay silent because at that point "every finding is new" is an artefact of the missing baseline, not a change.

**There is no promise that "the same problem is pushed only once"**: a fingerprint is `check:key:asset`, so the same class of problem yields a new "addition" whenever the `key` changes. The classic example is certificate expiry being split into three bands (`cert-expiring` → `cert-expiring-urgent` → `cert-expired`): one certificate can trigger up to 3 addition alerts, while the previous fingerprint is simultaneously recorded as "resolved". That is why **every finding in the payload carries a `fingerprint` field** (same origin as SARIF `partialFingerprints`), so downstream can deduplicate on its own.

### The two thresholds are two different things — do not mix them up

| Option | Controls | Semantics |
|---|---|---|
| `--fail-on <severity>` | the **exit code** | strict threshold: no change = 0; an added high with `--fail-on high` = 1; `--fail-on critical` = 0 |
| `--webhook-min-severity <level>` | **whether/what is pushed** | filters `diff.added`; default `medium` |

The default threshold of `medium` follows this project's existing severity → SARIF level mapping (see the "Integrating with GitHub Code Scanning" section): `critical/high` → `error` and `medium` → `warning` are the two bands that need a human, while `low/info` → `note` is informational. Widen it explicitly to `low`/`info` if you want informational items pushed too.

### Payload

`POST`, `Content-Type: application/json`:

```jsonc
{
  "tool": "surface-watch",
  "version": "0.1.0",
  "generatedAt": "2026-09-24T17:35:00.000Z",
  "scope": { "owner": "…", "assets": ["example.com"], "statement": "…" },
  "summary": {
    "new": 1, "changed": 0, "removed": 2,
    "bySeverity": { "critical": 0, "high": 0, "medium": 1, "low": 0, "info": 0 },
    "ignored": { "new": 0, "changed": 0 }      // additions below the threshold that were ignored
  },
  "delivery": { "triggerSet": "diff.added", "initial": false, "threshold": "medium",
                "changedIsInformational": true, "signed": true },
  "findings": [ { "fingerprint": "tls:cert-expiring:demo.example.com", "change": "new", "…": "…" } ]
}
```

The payload contains **no** secrets, environment variables or credentials of any kind.

### Signature (optional)

When `--webhook-secret` / `SURFACE_WATCH_WEBHOOK_SECRET` is provided, HMAC-SHA256 is computed over the **raw request body bytes** and sent as:

```
X-Surface-Watch-Signature: sha256=<hex>
```

A receiver only needs the shared secret and the raw body to recompute it independently, without understanding any of this tool's state:

```bash
node -e "const c=require('crypto');console.log('sha256='+c.createHmac('sha256',process.env.SECRET).update(require('fs').readFileSync('body.json')).digest('hex'))"
```

### Failure semantics: a broken alert channel must not break monitoring itself

- A failed delivery **does not change** the scan's exit code; `out/report.md` and `out/findings.json` are still produced
- Errors go to **stderr** (with the status code or error code and the attempt count spelled out)
- The delivery outcome is written to **`out/webhook-delivery.json`** (`ok` / `delivered` / `statusCode` / `attempts` / `error` / `attemptLog` / `deadlineMs` / `deadlineExceeded`)
- The `errorBody` in that record is a **byte-truncated** fragment of the response body (first 200 bytes kept, plus a note "truncated: response body was N bytes in total"): diagnostic content survives no matter how large the body is or how it is chunked; it is only kept verbatim when it genuinely did not exceed the limit
- Retry policy: **network errors and 5xx** are retried (at most 2 more times, backoff 250 ms → 500 ms); **4xx is never retried**
- **Any 3xx counts as a failure and redirects are not followed** — a single `Location` header would be enough to forward the payload to a third-party address you never configured; better to fail than to silently succeed
- The URL in the record file is redacted: query, userinfo and dynamic path segments (webhook URLs habitually carry tokens in the query or path, and writing them to disk verbatim amounts to writing credentials into a file)

#### Two layers of timeout: `--webhook-timeout` and `--webhook-deadline` are two different things

| Option | Layer | Coverage | Error when reached |
|---|---|---|---|
| `--webhook-timeout` | a single attempt | **socket idle** during one attempt (no data at all) | `TIMEOUT` (retried as a network error) |
| `--webhook-deadline` | the whole delivery | connect + response headers + response body + backoff + **all retries** | `DEADLINE_EXCEEDED` (no further retries) |

Why both are needed: a **slow receiver** (answers `200 OK` with `Transfer-Encoding: chunked`, then sends one byte every 200 ms and never finishes) keeps the socket permanently "active", so the **idle timeout never fires** — measured under `--webhook-timeout 1500`, the process did not exit within its 40 s hard cap, wrote no delivery record, and skipped both the baseline update and the exit code. In other words, a single alert channel can hang the monitoring process forever. Only an overall deadline covering total duration can cut it off.

Semantics when the overall deadline is hit (distinct from "retried and still failed"):

- `ok=false`, `delivered=false`, `reason="delivery-failed"`;
- `error` begins with `DEADLINE_EXCEEDED` (**do not** confuse it with the per-attempt `TIMEOUT`) and states the actual number of attempts;
- `attempts` counts only attempts that **actually happened** (no new attempt is started once the budget is exhausted, so it is never inflated);
- `deadlineExceeded=true`, and `deadlineMs` is the overall budget in effect for this run;
- The scan artifacts (`report.md` / `findings.json`) and the exit code are **unchanged** — ending a delivery early is not the same as changing the scan's conclusion.

Tuning advice: if the receiver is known to be slow (a cross-region link, say), raise `--webhook-timeout` and the overall budget follows as `3 ×`. If you only want a hard upper bound, give `--webhook-deadline` on its own (it may be smaller than `--webhook-timeout`, in which case the per-attempt idle timeout is clamped by the remaining budget and everything reported is `DEADLINE_EXCEEDED`).

#### `urlHash` in the record: the hash is taken over the **redacted** URL

`urlHash` in `webhook-delivery.json` exists to correlate records across runs, but it is the first 12 characters of the sha256 of the **redacted** URL — not of the full URL.

Why: hashing the full URL would leave a **verifiable oracle** in the record. `urlHash` would be the first 12 hex characters of the sha256 of the full URL (48 bit, unsalted), so an attacker holding the already-redacted URL prefix from the same record (`http://127.0.0.1:8801/hook/Ab***`) could enumerate candidates offline and compare hashes one by one to recover a low-entropy credential — measured: 7,122,554 candidates in 11.8 s recovered `http://127.0.0.1:8801/hook/AbC123`, making the redaction worthless. Once the hash is taken over the redacted form instead, the hash computed from a guessed candidate no longer matches the one in the record, so a guess cannot be verified — and no salt or key store is needed (the zero-dependency premise stands).

**Side effect (a deliberate trade-off you should know about)**: cross-record correlation becomes coarser. URLs sharing a prefix but differing in token (`/hook/AbC123` and `/hook/AbC456` both redact to `/hook/Ab***`) now produce the **same `urlHash`** — an equal `urlHash` only means "the redacted form is identical" and no longer proves it is the same configuration. That is the price paid to remove credential enumeration; host, port and structural path segments remain distinguishable.

### Local end-to-end verification (no real alert channel required)

The repository ships a zero-dependency fake receiver that writes each request's method, path, headers and raw body into a JSONL file line by line, and can inject faults:

```bash
# Start the fake receiver (binds loopback 127.0.0.1 by default; --allow-remote is needed for a non-loopback address)
node scripts/fake-webhook.mjs --port 8787 --log tmp/webhook-e2e/received.jsonl --secret s3cr3t

# In another terminal: run the real CLI (the first run establishes the baseline, so it does not deliver)
node src/index.mjs --scope fixtures/demo-scope.json --fixture fixtures/demo-observations.json \
  --out tmp/webhook-e2e/out --baseline tmp/webhook-e2e/baseline.json --update-baseline \
  --webhook http://127.0.0.1:8787/hook --webhook-secret s3cr3t

# Fault injection: persistent 500 (verifies retry, and that failure does not break the scan)
node scripts/fake-webhook.mjs --fail-status 500
node scripts/fake-webhook.mjs --fail-status 500 --fail-times 2   # first two fail, third succeeds
node scripts/fake-webhook.mjs --delay 8000                        # pair with --webhook-timeout to trigger a timeout
node scripts/fake-webhook.mjs --redirect https://evil.invalid/x    # verify that redirects are not followed
```

## Project structure

```
src/
├── index.mjs             CLI entry point (argument parsing, exit-code semantics)
├── lib/
│   ├── scope.mjs         🔒 Scope Gate: authorization-scope model and enforcement
│   ├── http.mjs          HTTP client (timeout/retry/redirect/truncation detection)
│   ├── findings.mjs      Finding model (evidence + impact + remediation advice)
│   ├── diff.mjs          Baseline diffing (added / resolved / persistent)
│   ├── changeset.mjs     🔔 Single source of change: what counts as a change is defined only here (consumed by CLI/Webhook/CI)
│   ├── notify.mjs        Webhook alert delivery (trigger semantics / signing / failure does not break the scan)
│   ├── report.mjs        Markdown / JSON / console summary
│   └── scan.mjs          Orchestration: collect → evaluate → summarise
└── checks/               dns / tls / headers / paths / ct
tests/                    all runnable offline (node --test tests/)
fixtures/                 fabricated demo data (RFC 2606 reserved domains)
scripts/
├── check-zero-deps.mjs   zero-dependency self-check (enforced by CI)
└── fake-webhook.mjs      local fake webhook receiver (end-to-end verification + fault injection)
```

## Limitations and boundaries

- It performs **passive and lightweight checks only**; it contains no exploitation capability of any kind
- No port scanning and no directory brute-forcing (those behaviours require explicit written authorization and dedicated tooling)
- The `paths` check is **heuristic** signature matching and cannot substitute for human verification
- Certificate Transparency queries depend on a third-party service (crt.sh); when it is unavailable the check degrades to "skipped" and does not affect the other checks
- The webhook destination is configured explicitly by the user and is therefore **not constrained by the Scope Gate** (it decides "where alerts go", not "what gets scanned"); the scan targets themselves always pass through the Scope Gate
- The webhook cannot guarantee "the same problem is pushed only once" (the fingerprint changes when its `key` moves band); deduplicate using the `fingerprint` in the payload

## Notice before use

**You may only run checks against the assets configured in this tool when one of the following holds**:

1. You own the asset, or
2. You hold **written authorization** signed by the asset owner (with an explicit scope)

See [SECURITY.md](SECURITY.md). The author accepts no responsibility for any unauthorized use.

## Roadmap

- [x] SARIF output, integrated with the GitHub Code Scanning alert panel ✅
- [x] Webhook notifications (generic transport layer: trigger semantics / HMAC signing / failure does not break the scan / locally verifiable end to end with a fake receiver) ✅
- [ ] Per-platform webhook adapter cards (templates and signature-header differences for Slack / Feishu / WeCom)
- [ ] Email notifications
- [ ] Add `robots.txt` / `security.txt` checks
- [ ] Concurrent collection across multiple targets (currently sequential, trading speed for better control)
- [ ] Trend charts in the report (severity changes over the last N runs)

## License

[MIT](LICENSE) © 2026 Frank2673

---

<sub>Zero dependencies: every feature uses only Node.js built-in modules (`dns` / `tls` / `https` / `crypto` / `zlib` / `test`) and pulls in no third-party package.</sub>
