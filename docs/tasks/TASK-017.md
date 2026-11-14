# TASK-017：扫描任务投递/回收桥接（deploy/protocol/dispatch.py）

## 背景

RUNBOOK §6 的投递/回收目前是人工零散命令拼的（今天两次实扫全是临时手搓
paramiko 脚本）。本任务给推理端一条命令的闭环：本地预检 → 投递 task.json →
触发扫描容器 → 拉回 result.json + raw/ → 回程自动过 T002 脱敏 + T001 包域标注。

## 硬约束

- **纯标准库**，远端操作走 `subprocess` 调系统 `ssh/scp`（不引 paramiko）
- **只允许密钥认证**：ssh 必带 `-o BatchMode=yes`（无密钥当场失败，杜绝挂等
  密码输入）；密码不出现在任何命令/参数/日志里
- **固定模板**：远端只执行预定义命令（mkdir / 固定 docker run 模板），远端
  路径由已校验常量拼装（task_id 走 run_scan.ID_PATTERN，--remote-dir/--image/
  --network 各有字符白名单），任何用户数据不进远端 shell 拼接
- **fail closed**：validate_task 不过 → 退出码 2，一个 ssh 都不发；远端传输
  环节任何失败 → 退出码 3，本地不留半套残缺归档（回程文件先落临时目录，
  全部成功才进归档目录）
- 不改 run_scan.py 既有行为；validate_task 经 sys.path 复用（同 scope_feed
  复用 engine 的先例），不复制代码

## 任务

### 1. `deploy/protocol/dispatch.py`

CLI（argparse，风格对齐 run_scan.py）：

```
python deploy/protocol/dispatch.py --task task.json \
    --host root@47.108.111.56 --port 53142 \
    [--identity ~/.ssh/id_ed25519] \
    [--remote-dir /jobs] [--image secops-scanner] [--network scannet] \
    [--timeout 600] [--ssh-timeout 120] \
    --out-dir <本地归档目录>
```

步骤序列（每步一次 subprocess，argv 列表，禁止 shell=True）：

1. 本地 `validate_task()` 预检（时钟可注入）；不过即 2
2. ssh：`mkdir -p <remote_job>/out`
3. scp 推 task.json
4. ssh：固定 docker run 模板（`--network <net> -v <dir>/task.json:/tmp/task.json:ro
   -v <dir>/out:/tmp/out <image> python3 /opt/protocol/run_scan.py ... --timeout N`），
   模板尾部 `; echo RC=$?` 回传远端退出码并解析
5. scp 拉 result.json + raw/（raw 存在性以 result.json 里 raw_output_ref 为准：
   有引用而 raw 没拉到 = 证据残缺，3）
6. 本地脱敏/包域后进归档：`<out-dir>/<task_id>/result.json`（T002 递归掩码，
   复用 tools/trajectory_mask.mask_value）、`raw/*.log`（逐文件 mask_text）、
   `result.untrusted.txt`（T001 wrap_untrusted 包域全文）、`dispatch.json`
   （本次投递元数据：远端 RC、步骤耗时、掩码字段数、注入命中数；不含凭据）

退出码：0 全链路成功且远端 RC=0；1 远端 run_scan 有动作失败（RC=1，结果已
拉回）；2 本地输入/校验错误（fail closed，未投递）；3 投递/传输/拉回环节失败。
2/3 对应 run_scan 的 fail-closed 家族语义，1 对齐"有动作失败但结果可用"。

### 2. `tests/test_dispatch.py`

自包含（同 test_protocol 风格）：run_fn 注入 fake runner 记录全部命令；
时钟注入。必须覆盖：

- 校验失败 → 2 且零条 ssh/scp 命令发出
- happy path：命令序列与模板逐字核对（ssh 选项含 BatchMode=yes；scp 用 -P，
  ssh 用 -p；镜像/网络/路径按参数拼装）；result.json 掩码生效；raw 逐文件
  掩码；untrusted 包域头带 source 与 injection 计数；dispatch.json 无凭据
- 远端 RC=1 → 退出码 1（结果仍归档）；远端 RC=2（校验失败结果）→ 0（投递
  环节本身成功，错误由 result.json 承载）
- ssh/scp 任一步非零 → 3；`RC=` 解析不出 → 3
- 有 raw_output_ref 但 raw 拉取失败 → 3
- task.json 读取失败 / --port 越界 / --identity 文件不存在 → 2

### 3. `deploy/protocol/README.md` 补 dispatch 一节

时序图占位、与手工流程的替换关系、密钥前置条件（ssh-copy-id）。

## 验收标准

- `make test` 全绿（现有 314 条不回归）
- dispatch.py 不出现 paramiko / 密码字面量 / shell=True（测试断言命令 argv）
- 换行 LF；类型注解 + docstring + f-string，风格与 run_scan.py 一致
