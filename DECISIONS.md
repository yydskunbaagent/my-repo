# DECISIONS

> ADR 精简版：一行结论 + 理由 + 反对意见。新增往下追加，不删除不改写历史。

## 001 白盒审计不自研，装官方 hermes-security 插件
- 理由：官方插件（monorepo 子目录，v0.1.3，2,973 行）已覆盖威胁建模/可达性追踪/排除项透明/SARIF 导出
- 反对记录：曾主张自研，因误判该仓为社区 4 star 项目；2026-11-14 克隆源码核实后推翻
- 备注：官方插件无 pre_tool_call，与自研门禁职责不重叠

## 002 授权模型对齐官方 Grant 五原则
- 理由：agent 可提议不可自铸授权；grant 绑 origin+动作+有效期+预算；两套授权语义会让审计学两遍
- 不收口进官方 `mint_grant`（工程上做不到，fork 官方插件与"白盒不自研"冲突）；统一信封形状、物理存储分离

## 003 推理节点 / 扫描节点物理分离，nftables 而非 squid
- 理由：官方 egress 用 squid CONNECT 只承载 HTTP(S)，裸 TCP（nmap SYN/masscan/UDP）直接失败且报错有误导性
- 附加：扫描节点不持有模型凭据；CDN 场景用 DNS 感知动态集合（受控解析器 + TTL nft set），静态五元组会静默丢包

## 004 门禁落点 = pre_tool_call plugin hook，三层纵深
- 理由：SKILL.md 是提示词级约束可被注入说服；hook 层 fail closed 可硬拒；OS 层是唯一真边界
- 顺序：OS 网络 > hook > SKILL 提示词，三层都要，不能互相替代

## 005 代码仓 / 作业仓分离
- 理由：grants、authorization.md、evidence 是法律证据，泄露即事故；外部智能体会读全仓
- 本仓 .gitignore 已落实；作业数据永不入库

## 006 服务端锁 Linux，Windows 只作终端入口
- 理由：nftables、nmap -sS 原始套接字、unshare 全依赖 Linux 内核
- 反对记录：曾把 Windows 兼容列为待验证项，2026-11-14 定为决策（伪需求）

## 007 代码以直写为主，ZCode 无头用于后台并行与交叉评审
- 理由：实测派活 8min+验证 vs 直写 3min；ZCode 适合独立任务后台跑
- 调用方式见 AGENTS.md；禁止在对话里裸传任务，一律写任务书（docs/tasks/）

## 008 正负对照只约束主动 PoC 通道
- 理由：被动观察没有"清理动作"，硬套正负对照会卡死状态机（只读探测永远 NOT_RUN）
- 拆两条通道：被动（两路独立特征交叉印证，上限 observed）/ 主动 PoC（正负对照+清理，才可 confirmed）
