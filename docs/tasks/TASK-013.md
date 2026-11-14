# TASK-013：终端命令逃逸三漏洞修复 + masking Base64 补全（plugins/scope_gate/ 与 secops_report/）

## 上下文预置（先读这些）

- `plugins/scope_gate/extract.py`：`_segments(cmd)`（只按 `&&`/`||`/`;`/`|`/`&` 切分）、
  `_LOCAL_SHELL_COMMANDS`（TASK-012）、`_SCRIPT_INTERPRETERS`、
  `analyze_terminal()`（`is_local_shell` 早退在首词命中时返回）、`script_path` 判定
- `plugins/scope_gate/gate.py`：`is_local_shell` 消费点
- `secops_report/masking.py`：`_BEARER_RE`（当前字符类 `[A-Za-z0-9._-]{8,}`）

## 实测复现的三条逃逸（2026-11-14，均已在当前代码复现）

```
A: analyze_terminal("ls -la\ncurl https://evil.com")
   → is_local_shell=True, targets=[]           ← 门禁放行（应拦）
B: analyze_terminal("curl https://yyds520.online && bash /tmp/evil.sh")
   → script_path=''                            ← 门禁放行（应拦）
C: analyze_terminal("bash /tmp/no_ext_script https://yyds520.online")
   → script_path=''                            ← 门禁放行（应拦）
```

## 修复要求

### 漏洞 1：换行符多行绕过（高危）

- `_segments(cmd)` 增加 `\r?\n` 切分
- `is_local_shell` 语义修正：**命令的每一段**（按完整分隔符切分后）首词都必须
  命中 `_LOCAL_SHELL_COMMANDS` 才为真；任一段不是本地命令 → `is_local_shell=False`
- 段级目标提取照常（`extract_targets` 已经遍历各段，保持），`A` 里的 `curl evil.com`
  必须被提取为目标

### 漏洞 2：多段脚本执行（高危）

- `script_path` 判定改为**逐段遍历**：每段首词命中 `_SCRIPT_INTERPRETERS` 时，
  检查该段参数；
- 参数判定**不再限定扩展名**：解释器后的第一个**非选项参数**（不以 `-` 开头、
  且不是 `-c`/`-e`/`--eval`/`-m` 内联执行开关）一律视为脚本文件 → `script_path`
  记录该段（含段序号注释，如 `seg#2:/tmp/evil.sh`）；
- `-c`/`-e`/`--eval`/`-m` 开关仍走 TASK-007 的 `inline_eval` 拦截，不记 script_path

### 漏洞 3：无后缀脚本（中危）

- 与漏洞 2 合并修复：取消扩展名过滤（`.sh/.py/.ps1/.pl/.rb/.js` 后缀条件删除）
- 注意豁免常见非脚本参数：解释器常见 flag 组合（`python3 --version`、`python3 -m pip`）
  里 `-m` 后是模块名——`-m` 已被 inline 拦截覆盖，不需要特殊豁免

### masking 补全

- `_BEARER_RE` 字符类扩展为 `[A-Za-z0-9._+/=-]{8,}`（Base64 形态的 `+`/`/`/`=`），
  注意保留 `\b` 边界；散落 `bearer YWJjZGVmZ2hpamtsMTIzNDU=` 必须掩码

### 测试（新增 `tests/test_task013.py`，不改现有用例）

必含（用例标注逃逸字母编号 A/B/C）：

1. `A`：`ls -la\ncurl https://evil.com` → `is_local_shell=False`，
   `evil.com` 在 targets 里
2. `A'`：`echo ok\r\ncurl http://10.20.30.40` → 同样语义（CRLF）
3. `A''`：`pwd\nls -la`（全本地）→ `is_local_shell=True`（不误伤纯本地多行）
4. `B`：`curl https://yyds520.online && bash /tmp/evil.sh` → `script_path` 非空
   且指向段 2
5. `B'`：`echo x; python3 /tmp/run.py && curl https://yyds520.online` → `script_path`
   非空
6. `C`：`bash /tmp/no_ext_script https://yyds520.online` → `script_path` 非空
7. 回归：`bash /tmp/a.sh` 仍拦（既有行为）；`python3 -c "x"` 仍 inline_eval
8. masking：`bearer YWJjZGVmZ2hpamtsMTIzNDU=`（含 `=` 的 Base64）→ 掩码
9. `git status` / `grep x f.log` → is_local_shell=True（白名单行为不变）

## 约束

- 只改 extract.py / masking.py + tests 新增；gate.py 如需消费字段变化才动
- LOCAL_TOOLS / GateConfig 公开接口不许变
- `make test` 全绿（266 + 新增）

## 验收

```bash
python -m pytest tests/ -q
```
外加我用三条逃逸命令实测复现确认修复。
