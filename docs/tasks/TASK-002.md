# TASK-002：扫描节点网络隔离套件（deploy/）

## 背景

推理节点/扫描节点分离是方案 §5 的核心决策。官方 egress 用 squid CONNECT 只承载
HTTP(S)，nmap SYN/masscan 等裸 TCP 过不去，所以扫描节点用 nftables 五元组 + DNS
感知动态集合（方案 §5.2）。**本任务全部是配置与脚本，不改 plugins/ 下任何代码。**

## 任务

### 1. `deploy/nftables/scan-node.nft`

nftables 规则集（`inet hermes_scan` 表），要求：

- `allow_domains` 命名 set：IPv4/IPv6 各一个，带 `timeout`（动态集合，运行时由脚本喂 IP）
- `allow_ranges` 命名 set：静态 CIDR（netrange 授权直接放行）
- forward/input 链规则，语义：
  1. UDP/TCP 53 出站只允许到 `10.10.0.53`（受控解析器），其余 DNS 全部丢弃
  2. TCP 80/443 出站只允许到 `allow_domains` 或 `allow_ranges` 中的地址
  3. 其余出站全部丢弃；入站只放行 lo 和已建立连接
- 文件头注释写清：这是默认拒绝（default-deny）策略，新增放行必须走 scope 授权流程

### 2. `deploy/dns/unbound.conf`

受控解析器配置：

- 监听 10.10.0.53，仅服务扫描网段
- 转发模式：上游写 `1.1.1.1`、`8.8.8.8` 占位（部署时替换）
- **只允许解析 scope 内域名**：用 `local-zone` + `refuse`（对 `.` 默认 refuse，
  scope 域名 `transparent`/`domain-transparent` 放行）。文件里放示例域名
  `yyds520.online`，加注释说明部署时由脚本从 scope.yaml 生成

### 3. `deploy/dns/scope_feed.py`

把 scope.yaml 的授权域名喂进 nftables 动态集合的脚本：

- 参数：`--scope <scope.yaml 路径>` `--table hermes_scan` `--set allow_domains4/allow_domains6`
  `--ttl <秒，默认 300>` `--resolver <默认 10.10.0.53>`
- 复用 `plugins/scope_gate/scope.py` 的 `parse_scope`（import 方式：把仓库根加进
  `sys.path`，不要复制代码）
- 对每个授权域名向受控解析器发起 DNS 查询（只用标准库 socket，不用 dnspython），
  解析成功的 IP 分 IPv4/IPv6 执行：
  `nft add element inet hermes_scan allow_domains4 { <ip> timeout <ttl>s }`
  （通过 subprocess 调 nft，命令列表参数化，不要拼 shell 字符串）
- 解析失败打印警告并继续（fail-closed 语义：解析不出的域名自然没有放行条目）
- 私网/保留段 IP 跳过并警告（复用 `plugins/scope_gate/engine.py` 的
  `is_blocked_network`，同样 sys.path 引入）

### 4. `deploy/docker-compose.scan.yml`

两个服务定义（不用真跑，声明拓扑）：

- `reasoning`：推理节点，`network_mode: none`（完全无出网），挂载只读的
  `~/.hermes`，不含任何扫描工具
- `scanner`：扫描节点，接 `scannet` 内部网络（`internal: true`），安装
  nmap/nuclei/httpx（用注释写明镜像内安装方式即可，镜像本身 `image: scratch` 占位 +
  注释说明按 P0-B 验收时替换）
- 显式注释：scanner 容器内不得挂载任何含模型凭据的路径

## 约束

- 全部文件 LF 行尾
- `scope_feed.py` 纯标准库，Python 3.11+，风格对齐 plugins/scope_gate（类型注解+docstring）
- **不要动** plugins/、tests/ 下的现有文件
- nft/unbound 语法无法在 Windows 验证，写成结构正确即可；我会在 Linux 节点做 B1–B5 验收

## 验收（调用方执行）

1. `python deploy/dns/scope_feed.py --help` 正常输出
2. 用 `engagement-demo/scope.yaml` 试运行 `--dry-run`（脚本必须支持该参数：只打印将执行的 nft 命令，不真执行）——输出应包含 yyds520.online 的 nft add element 命令
3. 我人工审查 nft/unbound 语义与方案 §5.2 一致
