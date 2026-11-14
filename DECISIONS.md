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

## 009 域名目标网络层放行 = 精确"IP×端口"二元组；内联执行类别性拦截（TASK-007）
- 理由：allow_domains4/6 与 allow_ports 两个独立集合的实际放行面是笛卡尔积——授权 a.com:80 + b.com:8080 会放行 a.com:8080；改 allow_pairs4/6（ipv4_addr . inet_service）后域名目标只放行授权组合
- 代价：allow_domains4/6 集合及其喂入随之删除；scope_feed 不带 --feed-pairs/--feed-ports 时不喂任何集合（喂集动作显式化，防误跑出半套放行条目）
- netrange 目标（IP/CIDR）无域名语义，保留 ranges×ports 组合宽放行
- 内联代码（-c/-e/--eval/-m 任一参数或解释器交互模式）同理类别性拦截（inline_code_execution）：目标校验对"可见合法目标 + 隐藏 sink"无能为力

## 010 不可信数据层（T001/T002）接入点 = transform_tool_result，而非 post_tool_call（TASK-015）
- 结论：post_tool_call 是记录型钩子，Hermes 不消费其返回值（hermes-agent 源码核实：tool_executor 先 emit_post，替换发生在其后的 transform_tool_result），无法替换回传文本；任务书备选路径二（pre_tool_call 注入 system/context）同样不可行——Python 插件回调只认 block/approve/modify（modify 是浅合并进工具 args，会污染工具输入），没有注入通道
- 落点：Hermes 既有的 transform_tool_result（model_tools.py："plugins may replace the final result string. Runs after post_tool_call and before the result enters context. first string return wins"，fail-open）——正是任务书所指"工具结果回传模型前的钩子点"；出网工具结果先 mask_text（T002）再 wrap_untrusted（T001），本地工具（is_local_tool）只脱敏不包域，首个包域结果携带一次性不可信数据条款
- 代价：gate.py 对外新增 transform_tool_result（接口新增，pre/post 旧签名不变，本条即 AGENTS.md 要求的事前备案）；Hermes 对该钩子 fail-open——内部异常返回 None 保留原结果，损失纵深但不产生放行口子（出网动作仍由 pre_tool_call 硬判）

## 011 untrusted.py 允许内嵌 mask_text 兜底副本：插件独立加载优先于"不复制代码"（2026-11-14 第四轮评审修复）
- 结论：gate.py 顶层 `from .untrusted import ...` 且无兜底——untrusted 在导入阶段挂掉 = 整个门禁插件加载失败（等于门禁消失）。拷贝安装形态（hermes plugins install 复制目录）下 secops_report 不可达会让原实现必然挂掉，故 mask_text 改三级解析：常规导入 → 环境变量 SCOPE_GATE_REPO_ROOT / 父目录扫描 → 内嵌兜底副本
- 理由：门禁消失比脱敏降级严重得多（脱敏只是纵深一层，出网动作仍由 pre_tool_call 硬判）；"不复制代码"原则在此让位于插件独立加载
- 代价：masking 逻辑双份，漂移风险由 test_untrusted::test_fallback_mask_text_parity 守住（仓内形态逐条比对，改一边不改另一边即爆红）；域边界去活同步改为大小写不敏感（评审修复 2）
- 反对记录：曾考虑"拷贝安装形态属假设、暂不修"——被 A2 实测的 GitHub 子目录安装形态直接反驳，该形态真实在用
