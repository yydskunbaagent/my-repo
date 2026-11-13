# PROJECT STATE

> 一页接手文件：任何人/任何智能体读完即可继续工作。最后更新：2026-11-14 04:30 (+8)

## 项目是什么

基于 NousResearch/hermes-agent（开源 Agent 框架）二次开发**白帽安全智能体**：
白盒审计 + 黑盒渗透 + 授权门禁，且授权不可被模型自我批准。

## 当前阶段

方案 v0.3 已定稿（`plan/白帽智能体-技术方案.md`），门禁插件进入可测状态。

- ✅ `plugins/scope_gate/`：授权门禁插件（pre_tool_call hook），约 2,100 行
  - 判定链：engagement 可用性 → forbidden → 时间窗 → 动作白名单 → 目标解析 →
    云元数据/排除项/范围/端口 → 私网阻断 → 限速 → exploit 升级人工
  - 66/66 测试全绿（`make test`）
- ✅ 事实基线：Hermes 核心仓 + 官方插件 monorepo 均已克隆核实（见 refs/README.md）
- ⏳ 下一步 **P0**：装官方三件套（hermes-security / advanced-delegation / snyk）+
  验证 `subagent_*` hook 在 profile 路由下是否静默失效
- ⏳ 仓库远端未建（GitHub token 曾暴露于对话，必须先吊销换 Fine-grained 新 token）

## 关键结论（防重查）

- 门禁正确落点 = `pre_tool_call` **plugin hook**（`register(ctx)`），不是 `~/.hermes/hooks/`（那是 gateway hook）
- 返回契约：`{"action":"block"|"approve"|"modify"}`，block > approve，超时/异常 **fail closed**
- 子 Agent 与父共用同进程同一 hook 注册表（`tools/delegate_tool.py:313`），门禁全域生效
- 进程内无安全边界（官方 SECURITY.md §2.2）；OS 层才是唯一边界
- 官方 egress（squid 白名单）只承载 HTTP CONNECT，**nmap/masscan 裸 TCP 过不去** → 扫描节点须 nftables
- hermes-security 是官方插件（monorepo 子目录），SARIF/可达性/排除项透明已内置，白盒不自研

## 已验证的环境坑

- WorkBuddy 注入 `http_proxy=127.0.0.1:59527` 拦 Google 系 → 绕道本地 Clash 7897
- ZCode 无头调用见 `AGENTS.md`；429 是套餐 5 小时窗口（`account:bigmodel-start-plan`），回退走 API Key 通道
- Git Bash `/tmp` 与 Windows Python 路径不一致 → 一律用绝对路径

## 未决问题

见方案 §9：6 条待验证（execute_code 限速计数共享、跨 profile hooks 目录等）
