# 贡献指南

## 环境

- Node.js ≥ 18（本仓零运行时依赖，不执行 `npm install` 也能跑）
- Windows 用 PowerShell 7，macOS / Linux 用 bash

## 本地流程

```bash
git clone <repo>
cd <repo>
npm test          # 全部测试
```

提交前请确保：

1. `npm test` 全绿
2. 改动有对应测试（修 bug 先写复现，加功能先写断言）
3. 没有把本地绝对路径、内网地址、真实域名写进代码或样例

## 提交信息

采用 Conventional Commits：

```
feat: 新增 xxx
fix: 修复 xxx
docs: 更新 xxx
test: 补充 xxx
chore: 杂项
```

格式不符会被 `.githooks/commit-msg` 拦截。

## PR 要求

- 一个 PR 只做一件事
- 描述里写清：改了什么、为什么、怎么验证
- 涉及输出格式变更的，必须同步更新文档与测试

## 评审

维护者通常在 7 天内给出第一次反馈。超过 14 天没回应，欢迎在 PR 里 @ 提醒。
