# AvEngine

基于 **YARA + ClamAV + Sysmon** 的 Windows 多引擎杀毒引擎：静态规则检测、特征库扫描与实时行为监控三者结合，检出威胁后可自动隔离，并支持接入 OpenAI 兼容大模型做事件分析。

- **内核**：C++（`avengine_core.dll`）——YARA 扫描、ClamAV 客户端、实时监控、AI 会话
- **外壳**：Python（Nuitka `--standalone` 打包为 `avengine.exe`）——参数解析、配置、菜单、展示
- **发布形态**：`build.bat` 一键产出 `releases\AvEngine-<版本>\`，整目录拷到目标机器即可运行，**目标机无需安装 Python**
- **许可证**：**LGPL-3.0-or-later** —— 全文见 [LICENSE](LICENSE)；LGPL 按 §3/§4 要求随附 GPL-3.0 全文 [COPYING](COPYING)。第三方组件（libyara、ClamAV、Sysmon、规则库等）各自遵循其上游许可证，见**第 17 节**。

> 本文档默认你拿到的是 `build.bat` 构建出的发布目录 `AvEngine-0.1.0\`。

---

## 1. 快速开始（发布版）

1. 把整个 `AvEngine-0.1.0\` 目录复制到目标机器（Win10/11，或 Win7 SP1）。
2. 打开 CMD / PowerShell，`cd` 进该目录，执行：

```bat
avengine.exe --version
avengine.exe status
avengine.exe scan C:\path\to\sample.exe
avengine.exe                     :: 不带参数进入交互菜单
```

3. 首次运行会自动生成 `config.yaml`（由 `config.example.yaml` 复制）和 `logs\`，无需手工准备。
   配置是否可用随时可查：`avengine.exe config --validate`；被写坏时 `avengine.exe config --regenerate --force` 从模板重建（原文件自动备份）。
4. 部署自检：双击 `deploy_win7.bat`（检查运行时、UCRT、数据目录并打印状态）。
5. 想启用 AI：`copy config.ini.example config.ini`，填 `base_url` / `model` / `api_key`。

> 普通用户即可运行 `scan` / `status` / `ai`；`monitor`（实时监控）与 Sysmon 安装需要**管理员权限**。

---

## 2. 发布包结构

```text
AvEngine-0.1.0\
├─ avengine.exe                   主程序（Nuitka standalone，内置 Python 3.8 运行时）
├─ avengine\_native\
│  └─ avengine_core.dll           C++ 内核（YARA / ClamAV 客户端 / 监控 / AI）
├─ python38.dll
├─ vcruntime140.dll               MSVC / Python 运行时，勿删
├─ *.pyd                          Nuitka 拆出的扩展模块，勿删
├─ rules\                         YARA 规则库（递归加载 .yar / .yara，共 735 个文件）
├─ bina\                          本地二进制与安装包
│  ├─ Sysmon\                     现代版 Sysmon 15.x（Win8.1+），按架构选文件：
│  │  ├─ Sysmon.exe                  x86
│  │  ├─ Sysmon64.exe                x64
│  │  ├─ Sysmon64a.exe               ARM64
│  │  └─ sysmonwin7\              旧版 Sysmon 13.x（Win7 SP1 / 2008 R2 专用）
│  │     ├─ Sysmon.exe               x86
│  │     └─ Sysmon64.exe             x64
│  ├─ packs\Sysmon.zip
│  ├─ clamav.msi                  现代版 ClamAV 1.x（Win8.1+ 本机安装用）
│  └─ clamwin7\                   最后支持 Win7 SP1 的 ClamAV（任意 *.msi 命名都可）
│     └─ clamavwin7.msi
├─ scripts\                       运维脚本（详见第 8 节）
│  ├─ sysmon_config.xml
│  ├─ lib_sysmon.ps1              按系统版本/架构选 Sysmon（唯一选择逻辑）
│  ├─ install.bat
│  ├─ config_sysmon.bat
│  ├─ sysmon_which.bat            只读诊断：本机该用哪个 Sysmon
│  ├─ setup_clamav.bat            本机装/配 ClamAV（纯 bat，进度与诊断齐全）
│  ├─ set_clamav.bat              指向局域网 clamd / 禁用 ClamAV（普通权限即可）
│  ├─ lib_avengine.bat            上面两个脚本共用的"找 CLI"库（avengine.exe / venv / PATH）
│  └─ start_clamav.bat
├─ config.example.yaml            主配置模板（首次运行自动生成 config.yaml）
├─ config.ini.example             AI 配置模板（复制为 config.ini 启用 AI）
├─ deploy_win7.bat                Win7 部署自检
└─ README.md
```

运行期还会自动产生（不属于发布内容，可随时删除）：

- `config.yaml`：主配置，首次运行生成
- `logs\`：`avengine.log`、`ai_state.json`、`ai_dumps\`
- `quarantine\`：隔离区

> 发布包**不含** `config.yaml` / `config.ini` / `logs\` / `quarantine\`（避免夹带本机密钥与状态），它们在首次运行时自动创建。

---

## 3. 运行要求

| 平台 | 支持情况 |
| ---- | -------- |
| Windows 10 / 11 | 全功能：YARA + 本机 ClamAV（现代版 1.x）+ Sysmon + AI |
| Windows 7 SP1 | 全功能：YARA + 本机 ClamAV（`bina\clamwin7` 下的 Win7 兼容版）+ Sysmon 13.x + AI |

**ClamAV 版本按系统自动选择**：Windows 8.1+ 用 `bina\clamav.msi`（现代版 1.x），
Windows 7 SP1 / Server 2008 R2 及更早用 `bina\clamwin7\*.msi`（最后支持 Win7 的版本）。
任何系统都可以在「本机 ClamAV / 局域网 clamd / 纯 YARA」之间选择，见第 6 节。

**Sysmon 版本按系统自动选择**：Sysmon 15.x 需要 Windows 8.1 / Server 2012 R2 及以上，
Win7 SP1 / Server 2008 R2 只能用 13.x。选择逻辑集中在 `scripts\lib_sysmon.ps1`
（`avengine\paths.py` 与 `installer\install.c` 用同一套规则）：

| 系统版本 | 使用的目录 | 架构 → 文件 |
| -------- | ---------- | ----------- |
| 6.0 / 6.1（Vista / 2008 / 7 / 2008 R2） | `bina\Sysmon\sysmonwin7\`（13.x） | x64 → `Sysmon64.exe`，x86 → `Sysmon.exe` |
| 6.2 及以上（8 / 8.1 / 10 / 11 / Server 2012+） | `bina\Sysmon\`（15.x） | x64 → `Sysmon64.exe`，ARM64 → `Sysmon64a.exe`，x86 → `Sysmon.exe` |

- 期望目录里没有对应文件时会自动回退到另一个目录（例如只有 13.x 时，新系统也能装上），
  再回退到项目根下的 `Sysmon.exe`（历史布局）。
- `install.bat` 启动时会打印 `[install] Windows 6.1 (AMD64)` 与实际选中的二进制；
  随时可用 `scripts\sysmon_which.bat` 只读查看本机选择结果。
- 版本探测走注册表 `CurrentMajorVersionNumber` / `CurrentVersion`，不用 `GetVersionEx`
  （后者在 Win10 上受清单影响会谎报 6.2）。

- **Win7 SP1 需安装 UCRT**（KB2999226 / Universal C Runtime）；`deploy_win7.bat` 会检测并提示。
- 64 位系统。发布版自带 Python 运行时，**目标机无需安装 Python**。
- 只读运行不需要管理员；`monitor` 与 Sysmon/ClamAV 安装需要管理员。

---

## 4. 命令总览

```bat
avengine.exe [全局参数] <命令> [命令参数]
```

> 不带任何参数运行 `avengine.exe` 时，**有桌面会话就直接打开图形界面**（见第 16 节）；
> 纯命令行/无桌面环境会自动退回控制台菜单（也可用 `avengine.exe menu` 强制进入）。

| 命令 | 作用 | 权限 |
| ---- | ---- | ---- |
| （无参数） | 进入交互菜单 | 实时监控需管理员 |
| `scan <path>` | 扫描文件或目录（YARA + ClamAV） | 普通用户 |
| `status` | 查看各引擎与环境状态 | 普通用户 |
| `monitor` | 实时监控（Sysmon 事件触发按访问扫描） | 管理员 |
| `update-db` | 通知 clamd 重载病毒库 | clamd 运行中 |
| `config` | 校验 `config.yaml`（`--regenerate` 从模板重建，原文件自动备份） | 普通用户 |
| `ai` | AI 分析：批次分析 / `ask` 提问 / `--test` 连通 | 普通用户 |
| `service status\|ping\|install\|uninstall` | 特权服务（LocalSystem）的状态 / 探活 / 安装 / 卸载 | 安装与探活需管理员 |
| `run-system -- <参数>` | 请特权服务以 SYSTEM 身份运行 `avengine.exe <参数>` | 管理员 |
| `gui [--tab <页>]` | 打开图形界面（Tkinter，见第 16 节） | 普通用户（部分功能需管理员） |
| `menu` | 旧的控制台交互菜单 | 实时监控需管理员 |
| `-v` / `--version` | 打印版本 | — |
| `-c, --config <文件>` | 指定配置文件（写在子命令**前面**） | — |

全局参数示例：

```bat
avengine.exe -c D:\other-config.yaml status
```

退出码：`scan` 返回 `0`（未检出）、`1`（检出威胁 / 路径不存在）或 `2`（**没有任何引擎生效**，结论无效，不能当成「干净」）。

### 4.1 扫描：scan

```bat
avengine.exe scan C:\Users\Public\sample.exe    :: 单文件（先打印 SHA256）
avengine.exe scan C:\Temp                        :: 递归目录
```

- 双引擎：YARA 匹配 `rules\`，ClamAV 交给 clamd；任一引擎不可用时**自动降级**，另一个继续工作。
- 降级不再静默：扫描前会打印 `[警告]`（哪个引擎不可用、为什么），结束时打印 `引擎: YARA + ClamAV`；
  两个引擎都不可用时不会输出「未发现威胁」，而是报错并以退出码 `2` 结束。
- 命中后逐条输出 `[YARA]` / `[ClamAV]` 明细。
- 发现威胁时**交互式询问**是否隔离到 `quarantine\`：

```bat
avengine.exe scan C:\dangerous
:: 发现 N 个受感染文件。
:: 是否将受感染文件隔离? (y/n):
```

非交互场景（计划任务、脚本）可管道传入回答，避免卡住：

```bat
echo n | avengine.exe scan C:\dangerous   :: 仅报告
echo y | avengine.exe scan C:\dangerous   :: 自动隔离
```

脚本判断检出：

```bat
avengine.exe scan C:\dangerous
if errorlevel 1 echo 发现威胁！
```

### 4.2 状态：status

```bat
avengine.exe status
```

输出示例：

```text
--- 引擎状态 ---
配置文件: <根目录>\config.yaml (已加载)
C++ 内核: 已加载 (v0.1.0)
YARA 规则: 已加载 (720 个规则文件, 跳过 15 个不兼容文件)
ClamAV 连接: 不可用 (127.0.0.1:3310)
Sysmon: 未安装
隔离目录: <根目录>\quarantine (未创建)
监控路径: C:\Users\Public, C:\Temp
AI 分析: 未配置（缺少 config.ini，参考 config.ini.example）
-----------------
```

| 字段 | 正常值 | 异常处理 |
| ---- | ------ | -------- |
| `配置文件` | 已加载 | 未生效（使用内置默认值）→ `avengine.exe config --validate` 看原因，`config --regenerate --force` 重建 |
| `C++ 内核` | 已加载 | 未加载 → 确认 `avengine\_native\avengine_core.dll` 存在且未被杀软拦截 |
| `YARA 规则` | 已加载（N 个规则文件） | 未加载 → 检查 `yara.rules_path` 与 `rules\`；「跳过 N 个」见 FAQ |
| `ClamAV 连接` | 可用 + 版本号 | Win10/11 → 管理员 `scripts\install.bat`（或 `net start clamd`）；Win7 → 见第 6 节 |
| `Sysmon` | 已安装 | 执行一次 `monitor`（管理员）会自动安装 |
| `AI 分析` | 已启用 | 缺 `config.ini` → 由 `config.ini.example` 复制并填写 |

### 4.3 实时监控：monitor

```bat
:: 需要管理员身份运行 CMD / PowerShell
avengine.exe monitor
```

- Sysmon 未安装时自动用 `bina\Sysmon\Sysmon.exe` 安装并应用 `scripts\sysmon_config.xml`。
- 订阅 Sysmon 文件事件，`scan.monitor_paths` 中的文件被创建/修改时触发按访问扫描。
- 检出时打印红色威胁告警（路径 / 明细 / 处理动作），`Ctrl+C` 停止。
- 非管理员运行会提示并退出。

### 4.4 病毒库：update-db

```bat
avengine.exe update-db
```

`freshclam` 更新病毒库后，用本命令通知 clamd **重载**；clamd 不可达时返回 1。

### 4.5 AI 分析：ai

```bat
copy config.ini.example config.ini          :: 1. 生成配置并填写 base_url / model / api_key
avengine.exe ai --test                       :: 2. 测试端点连通
avengine.exe ai                              :: 3. 手动跑一批事件分析
avengine.exe ai --minutes 10                 ::    指定窗口 10 分钟
avengine.exe ai ask "当前有可疑外联吗？"       :: 4. 自由提问（可调用工具查证）
avengine.exe ai ask "..." --no-stream        ::    关闭流式，改回整体输出
```

| 参数 | 说明 |
| ---- | ---- |
| （无参数） | 采集窗口内事件 → 多轮分析 → 输出中文结论 |
| `--minutes N` | 覆盖批次窗口分钟数（默认取 `config.ini` 的 `interval/60`） |
| `--prompt "..."` | 等价于 `ai ask "..."` |
| `ask <问题>` | 自由问答，可调用工具查证 |
| `--test` | 仅测试端点连通性 |
| `--no-stream` | 关闭流式显示（默认开启；也可用环境变量 `AVENGINE_AI_STREAM=0`） |

**流式显示（默认开启）**：AI 会话过程中实时打印「思考过程 / 工具调用 / 工具结果 / 正文」，
不再是等整段回复结束才一起出来：

```text
提问: 当前有可疑外联吗？
[AI 分析] 自由提问
  模型: deepseek-reasoner | 最大轮数: 12
── 第 1/12 轮 ──────────────────────────────────
[思考] 用户想知道有没有可疑外联。先看当前 TCP 连接再判断。
[AI →] list_connections {"state":"ESTABLISHED"}
[AI ←] list_connections: [{"pid":4820,"remote":"…"}] 7ms
── 第 2/12 轮 ──────────────────────────────────
[思考] 只有一个到内网网关的连接，没有异常目标。
[AI] 结论：未发现可疑外联。
理由：仅存在内网网关连接，无境外/陌生远端地址。
──── 会话结束: end_tag | 2 轮 | 1 次工具调用
```

- 「思考过程」来自模型返回的 `reasoning_content`（DeepSeek 推理模型等）；普通模型不返回该字段时，
  会提示一行「模型未提供思考过程」，此时只显示正文与工具调用。
- 模型的 `CALL xxx {...}` 协议行和结尾 `END` 标记不会原样刷屏：CALL 行会以 `[AI →]` 事件呈现，END 被隐藏。
- 交互菜单的「AI 分析」子菜单多了第 4 项，可临时开关流式显示；`scan` 命中的「AI 检出分析」
  与 `ai` 批次分析同样走流式。
- 事件接口在 C++ 内核里：`avc_ai_ask_stream` / `avc_ai_run_batch_stream` /
  `avc_ai_analyze_detection_stream`（C 回调 `avc_ai_event_cb`），事件 kind 见 `cpp/src/ai/ai_session.h`。
  内核较旧（没有 `*_stream` 符号）时程序会提示重新 `cpp\build.bat`，并自动退回整体输出。

#### 4.5.1 AI 工具清单（80 个，模型可自我发现）

AI 可调用的工具从 20 个扩到 **77 个**（对应 `todolist.txt` 的 36 项能力缺口），按类别：

| 类别 | 数量 | 代表工具 |
| ---- | ---- | ---- |
| 进程 | 12 | `get_process_tree` / `get_parent_chain` / `get_process_commandline`（读 PEB，含 WOW64）/ `get_process_env` / `list_threads`（线程起始地址是否在非映像内存）/ `list_handles`（句柄表）/ `scan_memory_regions`（私有可执行内存 + 熵 + YARA）/ `suspend_process` / `resume_process` / `kill_process_tree` |
| 文件 | 11 | `list_files` / `get_file_metadata`（硬链接/所有者/熵/魔数）/ `get_ads`（Zone.Identifier 来源判定）/ `get_recent_files`（USN 时间线）/ `scan_with_rule` / `verify_signature`（Authenticode） |
| 网络 | 10 | `get_dns_cache` / `list_udp_endpoints` / `list_listeners` / `resolve_ip_domains`（IP 反查 DNS 缓存域名）/ `get_route_table` / `get_arp_cache` / `list_firewall_rules` / `get_proxy_config` / `block_ip` / `block_domain` |
| 系统 | 5 | `enumerate_registry_tree`（递归键树）/ `delete_registry_value` / `stop_service` / `delete_service` / `delete_scheduled_task` |
| 事件 | 3 | `get_script_block_log`（4104 脚本块还原）/ `get_security_log`（4624/4625/4672/4688）/ `subscribe_events`+`tail_events`+`unsubscribe_events`（实时订阅） |
| 处置 | 15 | `remove_persistence`（registry/service/task/wmi 四类）/ `kill_process` / `quarantine_file` 等 |
| 情报 | 21 | `check_persistence`（Run/IFEO/COM 劫持/LSA 等聚合分级）/ `list_wmi_subscriptions` / `list_startup_folders` / `list_drivers_loaded` / `decode_script`（base64/UTF-16LE/hex/XOR 解混淆）/ `get_etw` / `get_amsi_events` / `reputation_lookup` / `build_static_report` / `write_yara_rule` / `save_baseline`+`compare_baseline` / `set_safety` / `list_tools` |
| 窗口 | 3 | `list_windows`（含 `class_module`/`class_wndproc` 模块归属）/ `get_window_detail`（父属主链、窗口线程、签名抽样）/ `close_window`（WM_CLOSE / EndTask，处置类） |

**窗口为什么要单列一类**：弹窗的"所属进程"经常是红鲱鱼——恶意代码可能在**注入到别的进程的 DLL** 里注册窗口类、处理消息（宿主进程只是受害者）。
窗口对象自带两个直接指向模块的指针，一次就能定位到真正干活的 DLL，不必逐个翻模块：

| 指针 | 取法 | 跨进程可读 | 含义 |
| ---- | ---- | ---------- | ---- |
| 类模块 | `GetClassLongPtr(hwnd, GCLP_HMODULE)` | ✅ | 注册该窗口类的模块（恶意 DLL 自己注册时就是它） |
| 类 WndProc | `GetClassLongPtr(hwnd, GCLP_WNDPROC)` | ✅ | 该类真正处理消息的代码地址 |
| 实例 WndProc | `GetWindowLongPtr(hwnd, GWLP_WNDPROC)` | ❌ 错误 5 | 被子类化时指向子类过程；跨进程被系统拒绝，结果里会说明 |

判读要点：两个地址**都不在目标 loader 模块列表**里 → 手工映射/被 rootkit 隐藏的强信号（`class_module_not_in_loader_list`）；
`wndproc_in_private_executable` 表示消息处理代码跑在私有可执行内存里。模块列表读不到时**不会**下"被隐藏"的结论，
而是标记 `module_list_unavailable` 并给出原因（`diagnostics`/`module_list_error`），避免误报。
`close_window` 只支持跨进程可用的两种方式（`wm_close`、`end_task`）；直接投递 `WM_DESTROY` 会被拒绝并说明原因。

安全设计：

- **处置分级**：17 个会改系统状态的工具全部支持 `dry_run`（只返回将执行的动作，不改系统）；
  `set_safety {"dry_run": true}` 可开会话级开关；`list_tools` 对每个工具标注 `readonly`。
- **操作审计**：处置类动作（含 dry-run）统一追加写入 `logs\ai_audit.log`，带哈希链
  （`hash = sha256(prev_hash + payload)`），可校验是否被篡改。
- **输出上限**：所有 list 类工具有 `limit` + 硬上限；结果按 `max_tool_result_chars` 截断且不劈开汉字。
- **需要管理员的操作**（错误信息会明确提示）：`list_handles`、`get_recent_files`(USN)、
  `get_security_log`、`block_ip/block_domain`、服务启停删除、驱动完整信息；其余全部用户态可用。

- 未创建 `config.ini` 时 AI 保持关闭，不影响引擎其他功能。
- `scan` 发现威胁且 `scan_analysis = true` 时，会把首个检出交给 AI 分析。
- `monitor` 启动时若 AI 已启用，会按 `interval` 秒后台自动跑批次。

### 4.6 交互菜单

不带任何参数运行即进入菜单：

```text
==================================================
 主菜单
==================================================
1. 启动实时监控 (Sysmon + 按访问扫描)
2. 手动扫描文件/目录
3. 更新病毒库 (ClamAV)
4. 查看引擎状态
5. AI 分析 (批次/提问)
6. 退出
```

---

## 5. 配置文件

### 5.1 `config.yaml`（引擎主配置）

首次运行由 `config.example.yaml` 自动生成。**相对路径一律基于程序根目录解析，与当前工作目录无关**。

| 配置段 | 字段 | 说明 |
| ------ | ---- | ---- |
| `yara` | `rules_path` | YARA 规则目录，递归加载 `.yar` / `.yara` |
| `clamav` | `host` / `port` / `timeout` | clamd 连接，默认 `127.0.0.1:3310`；可指向局域网 clamd，`host` 置空则禁用 ClamAV（纯 YARA） |
| `sysmon` | `channel` | Sysmon 事件通道 |
| `quarantine` | `path` | 检出后的隔离目录 |
| `scan` | `on_access` | 实时监控开关（由 Sysmon 文件事件触发） |
| `scan` | `timer_enabled` / `timer_interval` | 定时批量扫描开关与间隔（秒） |
| `scan` | `monitor_paths` | 实时监控 / 定时扫描关注的目录列表 |

用命令行参数 `-c <文件>` 可指定别的配置文件。

`config.yaml` 必须用 UTF-8（带不带 BOM 都行）保存。如果它解析失败，程序会打印 `[警告] 配置文件解析失败` 并退化为内置默认值
（此时 `status` 的「配置文件」一行会显示「未生效，使用内置默认值」，`scan` 会警告引擎缺失而不是假装扫干净）。
手动编辑请用 VS Code / Notepad++ 等 UTF-8 编辑器；不要用 Windows PowerShell 5.1 的 `Set-Content -Encoding UTF8` 改写它（见第 7 节说明）。

### 5.2 `config.ini`（AI，可选）

模板 `config.ini.example`，两段：

- `[ai]`：`enabled`、`base_url`、`api_key`、`model`、`timeout`、`interval`、`max_rounds`、`max_events_per_batch`、`max_event_chars`、`max_tool_result_chars`、`scan_analysis`
- `[sources]`：`sysmon` / `process` / `network` / `dns` / `powershell` / `system` / `application` / `fileio` 事件源开关

`base_url` 兼容任意 OpenAI 风格端点（OpenAI / DeepSeek / 本地 Ollama 等）。`fileio` 事件量大，恒不进批次，AI 需要时用 `grep_events` 按需检索。

---

## 6. Windows 7 部署

AvEngine 的 ClamAV 是一个 **clamd TCP 客户端**（读 `config.yaml` 的 `clamav.host` / `port`），
而 clamd 可以是本机的、也可以是局域网里另一台机器的 —— **任何系统都能在这两种之间选**，
Win7 也有本机安装方案。

### 6.1 ClamAV 安装包按系统版本自动选择

| 系统 | 使用的安装包 | 说明 |
| ---- | ------------ | ---- |
| Windows 8.1 / Server 2012 R2 及以上 | `bina\clamav.msi` | 现代版 ClamAV 1.x |
| Windows 7 SP1 / Server 2008 R2 及更早 | `bina\clamwin7\*.msi` | 最后支持 Win7 的版本（仓库里已带 `clamavwin7.msi`） |

- 判定规则与 Sysmon 完全一致（`6.0`/`6.1` → 旧版），三处实现保持同步：
  `avengine/paths.py` 的 `clamav_msi()`、`scripts\setup_clamav.bat` 的自动选择、
  `scripts\install.bat` 与 `installer\install.c`。
- `bina\clamwin7\` 里放**任意文件名**的 `*.msi` 都会被认出来，方便你替换成别的 Win7 版本。
- 期望目录里没有包时会自动用另一套（只放了一套包的机器也能装）。
- 想强制指定用哪一套：`scripts\setup_clamav.bat --msi bina\clamwin7\clamavwin7.msi`，
  或在 GUI 的 ClamAV 页选「现代版 / Win7 兼容版」。
- 只想看会自动选哪个包（不安装、不需要管理员）：`scripts\setup_clamav.bat --print-package`。

> **这条路径不用 PowerShell（重要）**：ClamAV 的安装/配置全部是 **bat + CLI**。
> Windows 7 SP1 自带的是 **PowerShell 2.0**，而旧版 `setup_clamav.ps1` 用了 3.0+ 语法
> （`-notin`、`Get-ChildItem -File`、`Get-Content -Tail`、`Get-NetTCPConnection`），
> 在 Win7 上是**解析期**失败 —— 整个安装一步都不执行，却只留一行难懂的报错。
> 现在 bat 负责机械动作（msiexec / conf / freshclam / sc），`config.yaml` 由
> `avengine config --clamav-host …` 写，也就是 `avengine/configwrite.py`（保注释、
> UTF-8 无 BOM、自动备份、损坏自愈）—— 与 GUI 设置页写回配置用的是同一套代码。

### 6.2 三种模式（所有系统都可选）

| 方案 | 操作 | 结果 |
| ---- | ---- | ---- |
| **本机 ClamAV** | 管理员跑 `scripts\setup_clamav.bat`（或 GUI 的「安装 / 配置」）；任何系统都行，按上面规则选包 | `status` 显示 ClamAV 可用 + 版本号 |
| **局域网 clamd** | 在另一台主机（Win10/11、Linux，或 `clamav/clamav` Docker 镜像）启动 clamd 并放开 3310；本机跑 `scripts\set_clamav.bat -ClamdHost <IP>` | 同上（连接远程 clamd） |
| **纯 YARA** | `scripts\set_clamav.bat -ClamdHost none`（等价于把 `clamav.host` 置空） | `status` 显示 ClamAV 不可用，`scan` 仍用 YARA 正常工作 |

管理员执行 `scripts\install.bat` 时会在**任何系统**上询问这三种模式（默认第一种，见第 7 节）。

部署步骤建议：

1. 复制整个发布目录到 Win7（如 `C:\AvEngine-0.1.0\`）。
2. 确认 UCRT 已安装（缺则装 KB2999226）。
3. 双击 `deploy_win7.bat` 自检，看 `status` 是否正常。
4. 用 `scripts\set_clamav.bat` 选择 ClamAV 方案（或直接纯 YARA）。
5. 需要实时监控则管理员运行 `scripts\install.bat` 装上 Sysmon（会自动选用 13.x），再 `avengine.exe monitor`。
   不确定会用哪个版本时先跑 `scripts\sysmon_which.bat`。

> 局域网 clamd 默认无认证，请用防火墙限制 3310 端口仅对可信网段开放。

---

## 7. Sysmon / ClamAV 安装（管理员）

```bat
:: 管理员 CMD / PowerShell，在发布目录下
scripts\install.bat
```

`install.bat` 行为：

- **先选 Sysmon 版本**：打印 `[install] Windows 6.1 (AMD64)`，由 `lib_sysmon.ps1` 按系统版本与架构
  选出 `bina\Sysmon\sysmonwin7\`（Win7/2008 R2，13.x）或 `bina\Sysmon\`（8.1+，15.x）里的对应文件，
  并把路径交给 `config_sysmon.bat`；`config_sysmon.bat` 在 Sysmon 未安装时用 `-i` 安装、已安装则 `-c` 只改配置。
  找不到二进制时只提示并继续 ClamAV 部分（不中断一键安装）。
- **ClamAV 三选一（任何系统都一样）**：打印 `1 = 本机安装`（默认）/ `2 = 局域网 clamd` / `3 = 纯 YARA`。
  - 选 1 调 `setup_clamav.bat`：按系统版本选包（8.1+ 用 `bina\clamav.msi`，Win7 SP1 用
    `bina\clamwin7\*.msi`）、写 `clamd.conf` / `freshclam.conf`、`freshclam` 更新病毒库、
    注册并启动 `clamd` 服务（`127.0.0.1:3310`），最后改写并**校验** `config.yaml`。
  - 选 2 调 `set_clamav.bat -ClamdHost <IP>`，选 3 调 `-ClamdHost none`（都不安装 MSI）。

`clamd` 服务注册方式（很容易踩的坑）：

- 服务 ImagePath 必须是
  `"C:\Program Files\ClamAV\clamd.exe" --daemon --service-mode`
  （`setup_clamav.bat` 直接用 ClamAV 官方的 `clamd.exe --install-service`，失败时才手工注册等价命令行）。
- `--daemon` 让 clamd 向 SCM 注册控制处理程序，`--service-mode` 在病毒库加载完成后上报 `SERVICE_RUNNING`。
  **少了这两个参数**，`net start clamd` 会以 1053「服务没有及时响应启动或控制请求」失败，
  而同一个 exe 在命令行前台运行却一切正常 —— 典型的「服务起不来、前台能用」。
- 反过来，**不要**手工执行带 `--daemon --service-mode` 的命令行：那是服务专用入口，脱离 SCM 时
  clamd 会只监听 3310 而不应答任何请求（看起来「起来了但没用」）。
- 服务起不来时先看 `C:\Program Files\ClamAV\clamd.log`：病毒库缺失、3310 被前台 clamd 占用是最常见的两个原因。

单独脚本：

| 脚本 | 作用 |
| ---- | ---- |
| `scripts\config_sysmon.bat` | 用 `sysmon_config.xml` 配置 Sysmon（需管理员）；未安装时自动以 `-i` 安装；自动选用本机匹配的 Sysmon 版本；退出码 2 = 没找到 Sysmon 二进制（供 `install.bat` 跳过而不是报错） |
| `scripts\sysmon_which.bat` | 只读诊断：打印系统版本/架构与本机将使用的 Sysmon 路径（不安装、不改动系统） |
| `scripts\lib_sysmon.ps1` | Sysmon 版本/架构选择实现（被 `install.bat`/`config_sysmon.bat` 调用，也可 `-Print`/`-Explain` 单独运行） |
| `scripts\setup_clamav.bat` | 本机安装/配置 ClamAV（需管理员，**纯 bat 不依赖 PowerShell**）。**安装包按系统版本自动选择**（8.1+ 现代版 / Win7 SP1 旧版），也可 `--msi <路径>` 指定；`--port N` 指定端口；`--print-package` 只打印会用的安装包后退出 |
| `scripts\set_clamav.bat` | 指向局域网 clamd（`-ClamdHost <ip>`）或禁用 ClamAV（`-ClamdHost none`）；普通权限即可 |
| `scripts\lib_avengine.bat` | 上面两个脚本共用的 CLI 定位库（`avengine.exe` → `venv\Scripts\python.exe` → PATH 上的 python），被 `call` 后设置 `AVENGINE` |
| `scripts\start_clamav.bat` | 启动本机 clamd：有服务就启服务，否则前台运行 |
| `avengine\configwrite.py` | `config.yaml` / `config.ini` 的保注释写回器（CLI 与 GUI 共用，由 `avengine config --clamav-host` 调用） |

> `config.yaml` 一律用 **UTF-8 无 BOM** 读写与按行改写（`avengine\configwrite.py`）。
> 不要改回 `Get-Content -Raw` / `Set-Content -Encoding UTF8`：中文系统上 PowerShell 5.1 会按 ANSI 解码，
> 中文注释变乱码并吞掉 CR，相邻行合并后顶层键被并进注释，`config.yaml` 直接解析失败。
> 带非 ASCII 文本的 `.ps1` 必须保存为 **UTF-8 带 BOM**，否则 PowerShell 5.1 同样会按 ANSI 读、脚本语法直接报错。

### 7.1 路径编码约定（非 ASCII 路径支持）

内核（C++）与 Python / JSON / `config.yaml` 之间**一律用 UTF-8**；而 Win32 与
`std::filesystem` 在 Windows 上处理文件必须用**宽字符**。所以：

| 方向 | 用 | 不要用 |
| ---- | -- | ------ |
| UTF-8 字符串 → 宽字符路径 | `utf8_to_wide_path()`（`cpp/src/util.h`，`aiutil::to_wide_path()` 转发同一实现） | `fs::path(narrow)`、`std::fopen(narrow)`、窄 `std::ifstream` |
| 宽字符路径 → 输出 / JSON | `wide_to_utf8()` / `aiutil::to_utf8()` | `path.string()`（返回 ANSI 字节，中文名变乱码） |
| libyara 扫描目标 | `CreateFileW` 打开后用 `yr_rules_scan_fd` | `yr_rules_scan_file`（libyara 内部窄 `fopen`） |

为什么写死这条：这些位置曾各自按系统 ANSI 代码页（中文系统 CP936）解码 UTF-8 路径，
于是 `C:\用户\文件.txt` 全是乱码 —— 文件类 AI 工具直接回「文件不存在」、`sha256` 为空、
熵采样 0 字节、YARA 规则目录判「不存在」、实时监控的中文目录整棵被跳过、隔离出来的中文文件名也变乱码。
回归测试见 `tests/test_non_ascii_paths.py`（中文 / 日文 / 西里尔文目录与文件名）。

---

## 8. `scripts\` 目录说明（哪些是程序必需的）

| 文件 | 谁使用 | 是否必需 |
| ---- | ------ | -------- |
| `sysmon_config.xml` | 程序：`monitor` 自动安装 Sysmon 时读取（`cli.py`） | **用 `monitor` 时必需** |
| `bina\Sysmon\`（15.x）与 `bina\Sysmon\sysmonwin7\`（13.x） | 程序：同上，按系统版本自动选 | **用 `monitor` 时必需**（至少一侧有对应架构的文件） |
| `install.bat` | 仅操作员手动执行 | 可选 |
| `config_sysmon.bat` | 仅操作员手动执行 | 可选 |
| `sysmon_which.bat` | 仅操作员手动执行（只读诊断） | 可选 |
| `lib_sysmon.ps1` | 被 `install.bat` / `config_sysmon.bat` 调用 | 与它们同进退 |
| `setup_clamav.bat` | 仅操作员手动执行 | 可选 |
| `set_clamav.bat` | 仅操作员手动执行 | 可选 |
| `start_clamav.bat` | 仅操作员手动执行 | 可选 |
| `lib_avengine.bat` | 被上面两个脚本 `call` | 与它们同进退 |

**结论**：`scan` / `status` / `ai` 完全不依赖 `scripts\` 里的任何文件；程序自身只会在 `monitor` 自动装 Sysmon 时读取 `scripts\sysmon_config.xml`（配合 `bina\Sysmon\`）。其余脚本都是给运维人员的便利工具，可删。

---

## 9. 构建（维护者）

### 9.0 先自备第三方二进制（不在仓库里）

仓库只含**自己的代码**；下面这些第三方产物因为体积/许可证原因**不入库**，需要自己放进 `bina\`：

| 路径 | 内容 | 从哪里来 |
| ---- | ---- | -------- |
| `bina\clamav.msi` | 现代版 ClamAV 1.x（Win8.1+） | <https://www.clamav.net/downloads> |
| `bina\clamwin7\*.msi` | 最后支持 Win7 SP1 的 ClamAV | 同上（旧版本），文件名任意 `*.msi` |
| `bina\Sysmon\Sysmon64.exe` | Sysmon 15.x（Win8.1+） | <https://learn.microsoft.com/sysinternals/downloads/sysmon> |
| `bina\Sysmon\sysmonwin7\Sysmon64.exe` | Sysmon 13.x（Win7/2008 R2） | 同上（旧版本） |

缺 `bina\` 也能构建出 `avengine.exe` 与 `avengine_core.dll`（内核 + 外壳自包含），只是发布包里
没有 Sysmon/ClamAV 安装包，`install.bat` 的第 3 步会退化为「局域网 clamd / 纯 YARA」。
`third_party\`（libyara 源码与预编译库）同样不入库，首次构建前按 `cpp\CMakeLists.txt` 的说明准备。

> 密钥类文件**永远不会入库**：`service\passwd.txt`、`service\signing.json`、`service\generated\`、
> `bina\signing\`、`config.ini`（含 API key）、`config.yaml.bak-*` 均已在 `.gitignore` 中。

### 9.1 环境

- Windows 10/11
- **MSYS2**（默认 `D:\msys64`，可用环境变量 `MSYS2_ROOT` 覆盖）内的 MinGW-w64 g++、`cmake`、`ninja`
- **Visual Studio 2022**（Nuitka 用 MSVC 编译 C 后端）
- 项目 `venv`（Python 3.8），已装 `nuitka`、`psutil`、`PyYAML`、`colorama` 等

### 9.2 一键构建

```bat
:: 在项目根目录
build.bat
```

可选：切换 Nuitka 编译器（默认 msvc）：

```bat
set NUITKA_COMPILER=clang
build.bat
```

`build.bat` 共 5 步：

| 步骤 | 内容 | 产物 |
| ---- | ---- | ---- |
| `[1/5]` | 检查 `libyara.a`，缺失时经 MSYS2 调 `cpp\scripts\build_libyara.sh` 重建 | `third_party\dist\lib\libyara.a` |
| `[2/5]` | 调 `cpp\build.bat`（CMake + Ninja + MinGW） | `third_party\dist\bin\avengine_core.dll` |
| `[3/5]` | 调 `scripts\build_nuitka.bat`（`--standalone --msvc=latest`） | `dist\avengine_main.dist\avengine.exe` |
| `[4/5]` | 组装发布目录：拷贝 dist + `rules\` + `bina\` + `scripts\` + `README.md`，并清理本机密钥/状态 | `releases\AvEngine-<版本>\` |
| `[5/5]` | 在发布目录内冒烟：`avengine.exe --version`、`avengine.exe status` | 构建成功判定 |
| `[extra]` | 编译特权服务（需 MSVC，失败只警告）+ 签名（无证书时跳过并提示） | `service\AvEnginePrivSvc.exe` |

版本号取自 `pyproject.toml` 的 `version = "..."`，产物目录为 `releases\AvEngine-<版本>\`。

> `build.bat` 会把 `config.ini` / `config.yaml` / `logs\` / `quarantine\` 从发布目录中剔除（含冒烟复检一次），确保发布包不夹带本机 API 密钥与运行状态。

### 9.3 单独构建各部件

```bat
cpp\build.bat                 :: 只重建 C++ 内核
scripts\build_nuitka.bat      :: 只重打包 Python 外壳
scripts\build_installer.bat   :: 只重编 installer\AvInstaller.exe
bash cpp\scripts\build_libyara.sh   :: 只重建 libyara.a（MSYS2 内，环境变量可覆盖 YARA_SRC / OUT）
```

> C++ 产物的链接参数带 **`-s`**（剥离调试符号）：`avengine_core.dll` 从 5.95 MB 降到 3.35 MB（−44%），
> `AvInstaller.exe` 从 470 KB 降到 104 KB（MSVC 分支等价于 `/DEBUG:NONE /OPT:REF /OPT:ICF`）。
> 导出表不受影响（`avc_*` 仍可用 `GetProcAddress` / ctypes 取到）。需要看调用栈符号时，把
> `cpp\CMakeLists.txt` 里 `target_link_options` 的 `-s` 去掉重新构建即可。

---

## 10. 从源码运行（开发）

```powershell
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
pip install -r requirements-dev.txt
pip install -e .

python -m avengine status
python -m avengine scan C:\path\to\file
python -m avengine
```

从源码运行需自行构建 `third_party\dist\bin\avengine_core.dll`（见 9.3）。

---

## 11. 测试

```powershell
pytest
python tests\manual\sysmon_watch.py    # 手动查看 Sysmon 事件流
```

`tests\manual\av_watchdog_sample.cpp` 是**行为测试样本**（不是程序的一部分，也不会进发布包）：
自我复制到 `%TEMP%`（随机名）→ 两个副本互守 → 杀一个会被另一个拉起，同时杀两个才会停；
退出开关是 `C:\exit.exit`。它**只做这些**：无持久化、无网络、无注入提权、无免杀混淆，
且有硬上限（稳定 2 进程 / 每副本重启上限 / 活动累计进程上限 / 运行时长上限），
收工一条命令：`av_watchdog_sample.exe --cleanup --purge`。
构建与用法见该文件头部注释，或 `tests\manual\build_av_watchdog_sample.bat`；
想让它被 YARA 引擎命中，把 `tests\manual\av_watchdog_sample.yar` 拷进 `rules\yara\` 即可。

测试不依赖本机 clamd / Sysmon：ClamAV 用例用不可达端口验证降级，YARA 用例用临时规则目录，并校验 `rules\` 真实规则库可编译。
`tests\test_ps_scripts.py` 会在 Windows 上用 Windows PowerShell 直接跑 `scripts\set_clamav.bat` / `setup_clamav.bat -ConfigOnly`，
断言改写后的 `config.yaml` 仍可解析、中文注释未被写坏、坏文件能自愈重建（即上面 FAQ 里那两个坑的回归测试）。

---

## 12. 日志与隔离区

- 引擎日志：`logs\avengine.log`
- AI 状态：`logs\ai_state.json`；AI 内存转储：`logs\ai_dumps\`
- 隔离区：`quarantine\`，命名 `原名_时间戳.扩展名`（重名自动追加序号）

---

## 13. 常见问题（FAQ）

**`status` 显示「跳过 N 个不兼容文件」**
`rules\` 中有少量规则使用 `pe.signatures` / `pe.number_of_signatures`。本项目为免 OpenSSL 采用 WinCrypt 版 libyara，这些标识符不可用，对应文件被**安全跳过**（约 15 个 / 735 个），其余规则不受影响。

**`scan` 卡死 / CPU 占满**
已在提交 `e19769c` 修复：当规则文件编译失败时不再从「带错误的编译器」生成规则集（否则会得到损坏规则集并死循环）。请使用最新构建。

**`ClamAV 连接: 不可用`**
管理员执行 `scripts\install.bat`（选 1 本机安装；或 `net start clamd` 只启服务）。
Win7 SP1 也能本机安装 —— 会自动用 `bina\clamwin7\*.msi`；想改用局域网 clamd 或纯 YARA 见第 6 节。

**`clamd` 服务启动失败，但 `clamd.exe` 前台运行正常（错误 1053 / 1067）**
服务 ImagePath 少了 `--daemon --service-mode`：进程不会向 SCM 报到，SCM 等 30 秒后杀掉它。用官方方式重注册一次：

```bat
:: 管理员 CMD
sc stop clamd & sc delete clamd
"C:\Program Files\ClamAV\clamd.exe" --install-service
net start clamd
```

`scripts\install.bat` 已经按这种方式注册；再不行就看 `C:\Program Files\ClamAV\clamd.log`（病毒库缺失 / 3310 被前台 clamd 占用）。

**AI 报 `WinHttpOpen 失败`（Windows 7，AI 完全不可用）**
旧内核用 `WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY` 打开 WinHTTP 会话，这个取值 **Windows 8.1 才支持**；Win7/2008 R2 上 `WinHttpOpen` 直接失败（错误 87）。已修复：先试自动代理，失败自动回退默认代理；同时显式允许 TLS 1.2（Win7 需要 **KB3140245** 才能用 TLS 1.2，否则现代 API 网关会拒绝握手，错误 12175）。若仍失败，错误信息里的错误码可直接定位：`12175` → 装 KB3140245 或改用 http 网关；`12029` → 网络/代理；`12007` → DNS/base_url。

**日志类工具报 `EvtQuery 失败（错误 87）`**
`get_script_block_log` / `get_etw` / `get_security_log` / `get_amsi_events` 曾把 `EvtQueryReverseDirection` 写成 `0x2000`（非法标志）。正确值是 **0x200**，已修复。

**`list_wmi_subscriptions` 报 `CoCreateInstance(WbemLocator) 失败 0x80004002`**
`IID_IWbemLocator` 写成了 `4590F812-…`（正确值 `DC12A687-737F-11CF-884D-00AA004B2E24`）→ `E_NOINTERFACE`；另外本地连接的用户名/密码必须传 `NULL`，传空串会得到 `WBEM_E_LOCAL_CREDENTIALS (0x80041064)`。两者都已修复。注意 `root\subscription` 命名空间查询需要管理员。

**`list_handles` 报「句柄表过大，枚举失败」或遇到看门狗样本时卡住**
曾用错信息类 62（扩展句柄表是 **64**），内核返回的 `needed` 是垃圾值，代码便一路扩容到上限。已修复，
并且按「大数据工具」约定改造：**必须给出 `type` / `name` / `handle` 之一**才会返回条目，否则只回错误说明；
`type="any"` 返回按类型的计数概览。

针对"宿主内有看门狗线程反复创建/销毁句柄、进程被杀即重启"这类卡死场景，现在的设计是**任何情况下都在预算内返回**：

- `budget_ms`（默认 5000，可调 1000–30000）总预算；快照阶段最多 3 次尝试且不超过预算一半，类型映射超过 2/3 预算即停，
  名字解析每 8 次检查一次时钟并有 `name_limit`（默认 200）次数上限；
- **`DuplicateHandle` 只在"每种类型取一个样本"时发生**（按 `ObjectTypeIndex` 归类是纯内存操作）：
  复制次数从"句柄数量级"降到"类型数量级"，避开了句柄表剧烈变化时卡在表锁上的问题；
- 名字解析改用**单个常驻 worker 线程 + 队列**（绝不一句柄一线程），超时就放弃该项；
  worker 长时间无进展时本轮不再提交，等它从驱动返回后自动恢复。**默认不做名字解析**，只有显式 `name=` 才做；
- 目标进程带**身份指纹**（创建时间 + 路径 + 存活）：进程中途退出或 PID 被复用时会返回**半成品结果**
  （`partial: true`）并说明原因，而不是假装完整；PID 不存在时直接快速失败，不做任何昂贵操作；
- 所有结果都带 `diagnostics`：`elapsed_ms` / `churn_bytes`（表抖动幅度）/ `dup_attempted` / `name_timeouts` /
  `unresolved_type_indexes` / `target_alive_at_end` / `pid_reuse_detected` / `stopped_reason`
  （`budget_exceeded(...)`、`name_limit_reached`、`name_worker_stalled`、`target_died`、`pid_reused` 等）。

排查"卡在哪一层"最快的方式：先用 `type="any"`（只做快照 + 类型计数，不快照句柄、不解析名字），
看 `elapsed_ms` 与 `churn_bytes`；如果概览正常而带 `name=` 卡，就是名字解析（FS 过滤驱动）那一层。
遇到看门狗样本时，更稳的取证顺序是：`suspend_process` → 再枚举/扫描 → `resume_process`；
或者干脆避开句柄表，用 `list_threads`（起始地址是否在非映像内存）、`list_process_modules`（`filter=unsigned`）、
`scan_memory_regions`（私有可执行内存 + YARA）与事件流（`query_events`/`get_etw`/`subscribe_events`）取证。

**`get_recent_files` 报「打开卷失败（错误 2）」**
卷参数带了冒号时（如 `C:`）会拼成 `\\.\C::`，`CreateFileW` 返回错误 2。现在 `C` / `C:` / `C:\` / `\\.\C:` 都会被规范化，非法写法（如 `C:\Windows`）直接给出「只接受盘符」的提示。USN 枚举需要管理员。

**`enumerate_registry_tree` 报「键不存在（错误 2）」**
子路径里的正斜杠以前不会被替换成反斜杠（`HKLM/SOFTWARE/Microsoft` 打不开）。现在 `/` 与 `\` 等价，两种写法都可用。

**`query_events source=process/network/fileio` 报「通道未找到」**
Win7 没有 `Microsoft-Windows-Kernel-Process/Network/File` 这些内核通道（Win8+ 才有）。现在按回退链自动尝试：`process` → Sysmon EID 1 → 安全日志 4688；`network` → Sysmon EID 3；`fileio` → Sysmon EID 11；`dns` → Sysmon EID 22。全部不可用时，错误里会列出尝试过的候选通道与启用命令（`wevtutil sl "<通道>" /e:true`）。

**`list_scheduled_tasks` 返回 0 条却不报错**
旧实现用 `_popen` 且把 stderr 重定向到 nul，`schtasks` 一旦失败（工作目录失效、任务库被策略限制等）就被静默吞掉。现在改用带超时与错误上报的捕获方式，失败时明确报错；`schtasks` 不可用时还会回退为直接枚举 `%SystemRoot%\System32\Tasks`（每个 XML 文件就是一个任务）。

**弹窗是谁弹的？——用 `list_windows` / `get_window_detail`，不要只看所属进程**
如果恶意逻辑在注入到 explorer 或某个常驻程序里的 DLL 中，`GetWindowThreadProcessId` 给的"所属进程"是受害者宿主，
会把人带偏。窗口工具改为给出**代码来源**：`class_module`（注册该窗口类的模块，`GCLP_HMODULE`）与
`class_wndproc`（类 WndProc，`GCLP_WNDPROC`）——这两个指针跨进程可读，直接指向真正干活的 DLL；
实例 WndProc（`GWLP_WNDPROC`）跨进程会被系统拒绝（错误 5），输出里会说明并用类 WndProc 代替。
两个地址都不在目标 loader 列表里，或 WndProc 落在私有可执行内存里（`wndproc_in_private_executable`），
就是手工映射/注入的强信号。注意：窗口只在当前桌面/会话可见，message-only 窗口不在枚举结果里；
若在我们自己的进程里被 user32 挂钩，取到的信息也可能不实，可交叉用 `scan_memory_regions` 复核。

**AI 工具里哪些需要管理员**
`list_handles`、`get_recent_files`(USN)、`get_security_log`、`list_wmi_subscriptions`、`list_drivers_loaded`、`block_ip` / `block_domain`、`stop_service` / `delete_service`、`remove_persistence`（service/task/wmi 部分）、`kill_process_tree`（其他用户的进程）。其余全部普通权限可用；失败时都会给出带错误码的说明，不会静默空结果。

**`config.yaml` 解析失败：`expected '<document start>', but found '<block mapping start>'`**
历史版本的 `setup_clamav.bat` 用 PowerShell 5.1 的 `Get-Content -Raw` + `Set-Content -Encoding UTF8` 改写配置：中文系统上按 ANSI 解码 UTF-8 文件，中文注释变乱码并吞掉 CR，相邻行合并后 `yara:` / `quarantine:` / `monitor_paths:` 被并进注释，于是第 N 行出现「孤立缩进映射」。
修复（原文件会自动备份）：

```bat
avengine.exe config --validate                  :: 只看原因
avengine.exe config --regenerate --force        :: 从 config.example.yaml 重建
scripts\set_clamav.bat -ClamdHost 127.0.0.1   :: 或让安装脚本重建并写回 clamav 段（无需管理员）
```

**扫描报「未发现威胁」，但其实引擎没在跑 / EICAR 没被检出**
配置坏掉或 clamd 没起时，旧版会静默跳过引擎并照样打印「未发现威胁」（假阴性）。现在：

- 扫描前会打印 `[警告]`，说明哪个引擎不可用；结尾打印 `引擎: YARA + ClamAV`；
- 两个引擎都不可用时以退出码 `2` 结束，不会输出「未发现威胁」。

自查顺序：`avengine.exe status`（三个字段看 YARA / ClamAV）→ `avengine.exe config --validate` → `avengine.exe scan <EICAR 文件>`（应同时出现 `[YARA]` 与 `[ClamAV]`）。EICAR 样本本身也可能被主机上的其他杀软删掉，换隔离环境再测。

**AI 会话最后抛 `[json.exception.type_error.316] invalid UTF-8 byte at index 200: 0x2E`**
内核序列化 JSON 时校验 UTF-8 失败：工具结果/事件在写进 trace 与事件流时按**字节**截断到 200，
正好把一个汉字（3 字节）劈成半个，于是 `dump()` 拒绝输出，整份会话结果都拿不回来（屏幕上会缺最后一条
工具结果和「会话结束」行）。已修：截断改为按 UTF-8 字符边界（`aiutil::utf8_truncate`），
所有事件/结果/请求体统一走容错 dump（`aiutil::dump_json`，非法字节替换为 U+FFFD 而不是抛异常）；
CLI 侧即使结果取不回来也会保留已流式输出的内容并明确打印失败原因。
旧构建请重新 `cpp\build.bat` 并重新打包。

**命令行扫描命中后一直等输入**
命中会询问是否隔离。脚本中用 `echo n | avengine.exe scan <path>` 提供回答。

**PowerShell 脚本被策略拦截**
各 `.bat` 已用 `-ExecutionPolicy Bypass` 调用 `.ps1`；手工执行时可用
`powershell -NoProfile -ExecutionPolicy Bypass -File scripts\set_clamav.bat -ClamdHost none`。

**想彻底不带 ClamAV**
删除 `bina\clamav.msi` 与 `bina\clamwin7\`（合计约 250 MB），并 `scripts\set_clamav.bat -ClamdHost none`。

---

## 14. YARA 规则库
`rules\` 为 [Neo23x0/signature-base](https://github.com/Neo23x0/signature-base) 的本地快照（普通目录，非 submodule），遵守其上游 LICENSE。更新方式：重新下载上游仓库并覆盖该目录，然后重新 `build.bat`（或直接把该目录拷进发布目录）。

---

## 15. 特权服务（SYSTEM 助手，可选）

AvEngine 有一部分取证/处置必须 SYSTEM 权限（读 Security 日志、枚举系统句柄表、驱动与防火墙信息……）。
这些活交给一个**独立的 LocalSystem 服务** `AvEnginePrivSvc.exe` 代做，AvEngine 自己仍然是普通进程。

### 15.1 它到底做了什么（以及刻意不做什么）

服务收到请求后，**用它自己的 SYSTEM 令牌启动一个 `avengine.exe` 子进程**，把子进程 pid、退出码和输出日志路径回给调用者。

- **做**：`CreateProcessAsUser`（SYSTEM 令牌 + SYSTEM 环境块），子进程 stdout/stderr 重定向到
  `%ProgramData%\AvEngine\privsvc\child-<pid>.log`（ACL 只给 SYSTEM/Administrators）。
- **不做**：不把 SYSTEM 令牌交给任何进程，也**不替换运行中进程的令牌**。
  `NtSetInformationProcess(ProcessAccessToken)` 那种换令牌的写法很脆——进程已有的线程、句柄、窗口站、桌面都和旧令牌绑定，
  换掉容易崩或行为异常，而且要服务启用 `SeTcbPrivilege`。需要强制处置就用子进程 + `kill_process_tree`。

### 15.2 授权门槛（五步，全过才执行）

| 步骤 | 检查 | 失败错误码 |
| ---- | ---- | ---------- |
| 1 | 命名管道 ACL 只允许 SYSTEM / Administrators 连接 | （连接被拒，错误 5） |
| 2 | 管道客户端 PID + **创建时间指纹**（防 PID 复用；授权前再复核一次） | `CALLER_OPEN_FAIL` |
| 3 | 调用者令牌必须属于 **Administrators** | `CALLER_NOT_ADMIN` |
| 4 | 调用者映像的**规范化路径**必须等于安装目录下的 `avengine.exe`（拒绝"把签名二进制复制到别处"） | `CALLER_WRONG_PATH` |
| 5 | Authenticode 验签 + 证书 **SHA-256 指纹与编译期钉住值**精确比对 | `CALLER_NOT_SIGNED` / `CALLER_WRONG_CERT` |

设计要点：

- **钉指纹而不是信任根存储**：服务只认"签发我们二进制的那张证书"，不依赖把自签名根装进 `LocalMachine\Root`。
  自签名证书不在根存储时 `WinVerifyTrust` 返回 `CERT_E_UNTRUSTEDROOT`（签名本身已校验通过），
  服务接受这一种结果但**必须**指纹匹配；其它错误码（摘要不符、证书损坏等）一律拒绝。
- **fail-closed**：没跑过证书初始化（没有编译进指纹）时，服务启动会在审计日志里写明并**拒绝一切请求**；
  `AvEnginePrivSvc.exe --check-pin` 以退出码 `2` 表示"未配置"。
- **参数校验**：命令行参数拒绝控制字符、限制长度（防拼出额外命令行）。
- **审计**：每次允许/拒绝都写 `%ProgramData%\AvEngine\privsvc\privsvc.log`（时间、调用者 PID/用户 SID、结论、参数）。

### 15.3 一次性初始化（管理员）

```bat
:: 1) 生成 256 位随机密码（Python），写入 service\passwd.txt
python scripts\gen_signing_password.py

:: 2) 生成自签名代码签名证书 + 导出 PFX/CER + 写 service\generated\cert_pin.h
powershell -ExecutionPolicy Bypass -File scripts\gen_signing_cert.ps1

:: 3) 重新编译服务（指纹是编译进去的！）+ 给它和发布包签名
service\build_service.bat
powershell -ExecutionPolicy Bypass -File scripts\sign_binaries.ps1 -Files releases\AvEngine-0.1.0\avengine.exe,releases\AvEngine-0.1.0\service\AvEnginePrivSvc.exe

:: 4) 安装并启动服务（管理员）
scripts\install_privsvc.bat
```

之后 `build.bat` 会自动带上"编译服务 + 签名"两步：**没有证书/没有 signtool 时只警告不阻断**（`sign_binaries.ps1 -Require` 可强制要求签名）。
注意：**一旦生成了证书指纹**（存在 `service\generated\cert_pin.h`），`build.bat` 就会给签名步骤加 `-Require`——
签名失败即视为**构建失败**。这是刻意的：服务会拒绝未签名的调用者，产出"BUILD OK 但没签名"的发布包只会在目标机上全线失败。

`-Files` 两种写法都支持，因为 `.bat` 与 PowerShell 的逗号语义不同：

```bat
:: 在 .bat / cmd 里（cmd 不按逗号拆分，脚本会自己展开）
powershell -File scripts\sign_binaries.ps1 -Files "a.exe,b.dll" -Require
:: 在 PowerShell 里（逗号由 PowerShell 解析成数组）
scripts\sign_binaries.ps1 -Files "a.exe","b.dll" -Require
```

脚本还会在 `signtool` 返回成功后**复核签名是否真的落地**（签名者指纹必须等于我们钉住的证书的 SHA-1）；
只有全部文件都通过才打印"完成：N 个文件已签名并校验通过"。想让构建强行要求这一步，用 `-Require`（`build.bat` 在已配指纹时会自动加）。

**如果签名报 `读不到签名材料` / `Access to the path ... is denied.`**

原因：证书脚本把 `bina\signing\` 与 `service\passwd.txt` 的 ACL 收紧成"只 SYSTEM + Administrators"，
而**未提权**的 shell 里令牌中的 Administrators 是 deny-only，所以读不到密码/PFX。二选一：

```bat
:: A) 以管理员身份重跑构建（或只重跑签名脚本）
:: B) 给当前账户补只读权限（不必重生成证书、不必重编服务）
powershell -ExecutionPolicy Bypass -File scripts\grant_signing_access.ps1
```

`grant_signing_access.ps1` 只改 ACL：默认额外给当前账户只读；`-Strict` 则反过来收紧成仅 SYSTEM/管理员。
（新生成的证书也会默认把当前账户加进只读名单，见 `gen_signing_cert.ps1` 的 `-NoUserAccess` 说明。）

`gen_signing_cert.ps1` 默认**不**动机器根存储；确实想装（例如给别的工具做链校验）再加 `-TrustRoot`。

### 15.4 使用

```bat
avengine.exe service status                                :: 服务状态 + 钉住的指纹 + 安装目录白名单
avengine.exe service ping                                  :: 探活：能通说明本进程已通过五步门槛
avengine.exe run-system -- status                           :: 让服务以 SYSTEM 跑 avengine.exe status
avengine.exe run-system --no-wait -- monitor                :: 只启动不等
avengine.exe run-system --timeout 900 -- ai --minutes 30    :: 等 15 分钟
```

服务端还可以单独用（排错很方便，不需要 SCM）：

```bat
service\bin\AvEnginePrivSvc.exe --check-pin          :: 打印指纹/安装目录，未配置指纹时退出码 2
service\bin\AvEnginePrivSvc.exe --selftest <pid>     :: 只跑验证链、逐项打印结论，不授权也不创建进程
service\bin\AvEnginePrivSvc.exe --console            :: 前台运行管道服务（Ctrl+C 退出）
service\bin\AvEnginePrivSvc.exe --install [--auto]   :: 安装（默认按需启动）/ --uninstall / --status
```

### 15.5 已知限制与风险（务必读）

- **必须用签名后的部署目录**：从源码树跑 `python -m avengine` 时调用者是 `python.exe`，
  第 4/5 步必然失败并返回 `CALLER_WRONG_PATH`。这是设计使然，不是 bug。
- **调用者必须已经是管理员**：这条门槛意味着本服务**不**提供"普通用户 → SYSTEM"的提权路径。
  这是刻意的：Windows 的权限模型本来就不允许普通用户拿到 SYSTEM，任何"仅凭签名就给 SYSTEM"的方案，
  都会因为**攻击者可以复制我们已签名的二进制到别处运行**而变成一台本机提权后门。
  管理员判定以**令牌组**为准（Administrators 存在且已启用、不是 `SE_GROUP_USE_FOR_DENY_ONLY`），
  再用复制出来的模拟令牌做一次 `CheckTokenMembership` 交叉验证；失败时错误消息里会带上诊断
  （`Administrators=…; TokenIsElevated=…; 完整性=…; CheckTokenMembership=…`），一眼能看出是不是"其实没提权"。
  注意：`CheckTokenMembership` 的文档要求传入**模拟令牌**，传主令牌在 Windows 7 上会误判。
- **Windows 7 的签名验证前提**：SHA-2 代码签名校验需要 **KB3033929**（Win7 SP1）。
  缺这个补丁时 `WinVerifyTrust` 会返回 `0x800b0100 TRUST_E_NOSIGNATURE`，服务会报 `CALLER_NOT_SIGNED`
  （错误消息里会提示补丁号）。要么装补丁，要么改用 SHA-1 签名（`signtool sign /fd sha1`，已不推荐）。
- **私钥即信任根**：`bina\signing\avengine-signing.pfx` + `service\passwd.txt` 泄漏 = 别人可以签出能让本服务授权的二进制。
  两者都在 `.gitignore` 里，ACL 只留 SYSTEM/Administrators，**不要**放进发布包。
- **自签名证书的后果**：别的工具做链校验时会报"不受信任的根"（本服务按指纹判定，不受影响）；
  想让 SmartScreen/第三方也认，得换受信任 CA 签发的证书。
- **服务是 SYSTEM 的攻击面**：默认**按需启动**（`--auto` 才自启），管道仅本机、仅管理员可连，
  参数与路径都做白名单校验，并有审计日志。EDR 会关注这类"SYSTEM 服务 + 管道"的组合，这是正常的。
- **子进程会话**：默认留在服务会话（session 0）。需要它出现在当前登录会话时加 `--caller-session`
  （会 `SetTokenInformation(TokenSessionId)`；子进程界面依然不可见，仅影响会话相关行为）。
- **轮换证书**：重新跑 `gen_signing_cert.ps1 -Force` → 重新编译服务（指纹变了）→ 重新签名发布包 → 重装服务。

---

## 16. 图形界面（Tkinter）

双击 `avengine.exe`（等价于不带参数运行）在有桌面会话时**直接打开图形界面**；也可以显式：

```bat
avengine.exe gui                 :: 打开界面
avengine.exe gui --tab 设置       :: 直接落到某个标签页
avengine.exe menu                :: 回到旧的控制台菜单
```

九个标签页覆盖全部功能与配置：

| 标签页 | 能做什么 |
| ------ | -------- |
| 概览 | 一眼看全：C++ 内核 / YARA / ClamAV / Sysmon / 实时监控 / AI / config.yaml 是否可解析 / 隔离区文件数；常用动作与快速跳转 |
| 扫描 | 选文件或目录扫描（YARA + ClamAV），结果表格 + 过程输出，检出后一键隔离（可勾选"检出后自动隔离"） |
| 实时监控 | 启停 C++ 常驻监控（Sysmon 事件驱动 + 定时扫描）；实时列出检出、按需隔离、把某条检出直接交给 AI 分析 |
| AI 分析 | 自由提问（Ctrl+Enter）/ 批次事件分析 / 常驻后台分析；**流式显示**思考、工具调用、工具结果与正文；一键测试连通性 |
| Sysmon | 安装或应用本项目配置（自动判断 `-i`/`-c`）、卸载、把事件通道写入 `config.yaml`、状态查看（含 Windows 7 legacy 13.x 判定） |
| ClamAV | 三种模式（本机安装 / 局域网 clamd / 纯 YARA）——**任何系统都可选**；本机安装带安装包选择（自动按系统 / 现代版 / Win7 兼容版）、两套包的可见性、服务状态与可达性、安装/卸载/启停/更新病毒库 |
| 特权服务 | 安装/卸载 `AvEnginePrivSvc`、查看钉住的证书指纹与安装目录白名单、探活（`service ping`）、以 SYSTEM 运行子进程 |
| 设置 | `config.yaml` 全部字段 + `config.ini` 全部字段（含 API 密钥、8 个事件源开关）；保存自动备份且**保留注释** |
| 日志 | 查看 `logs\avengine.log`（可自动刷新）、打开日志目录 |

设计要点（都是为了"不假死、不误操作、不丢注释"）：

- **页面只做 UI，系统操作全在 `avengine/gui/ops.py`**（无 Tk 依赖、可单测）：
  装了/卸了哪条命令、点了按钮会跑什么，都有测试固定住，不靠人肉检查。
- **所有耗时操作走后台线程 + 队列回主线程**（Tk 不是线程安全的，`ops` 在工作线程里绝不碰控件），
  扫描/安装/签名校验这类慢操作不会把界面卡住。
- **权限友好**：需要管理员的功能（实时监控、Sysmon/ClamAV 安装、特权服务）在普通用户下自动置灰并说明原因，
  右上角提供"以管理员身份重启"。
- **改配置不丢注释**：走 `avengine/configwrite.py`，按行定位只改目标键（YAML 与 INI 都是），
  写盘前备份为 `config.yaml.bak-<时间戳>` / `config.ini.bak-<时间戳>`。
- **AI 流式**：事件在 DLL 的工作线程里产生，先入队再由 Tk 的 `after` 循环渲染，
  所以"思考/工具调用"是实时滚出来的，而不是等整段结论。

### 16.1 GUI 为什么不卡（AI 长会话的性能约定）

用户报过"AI 执行工具（尤其阻塞型工具）时 GUI 卡死"。实测根因**不是**"GUI 和任务在同一线程"
（AI 会话本来就在后台线程，事件也是先入队再渲染），而是**回调/渲染的量**：

| 环节 | 曾经的写法 | 后果（实测） | 现在 |
| ---- | ---------- | ------------ | ---- |
| DLL → Python 的事件回调 | 每个 content/thinking 分片都回调一次 | 3000 chunk → Tk 主线程约一半时间在**等 GIL**，最长卡 14.7s | `ai_session.cpp` 合并：攒够 320 字节 / 40ms / 遇换行才发（回调数 3009 → **164**） |
| 一次 `after` tick 的渲染 | 把队列里**全部**事件渲染完 | 单次 tick 最长 3.3s | `_drain_now(budget_ms=25)`：**每条事件都检查**预算，超时就把剩余留给下一个 tick |
| 流式文本累积 | `self._pending_text += chunk` | 上万分片时是 **O(n²)** 的内存复制 | 用 `list` + `join`，遇换行才落行 |
| 单次写入量 | 一次 flush 掉整个缓冲 | 单条事件就能打穿 tick 预算 | `MAX_FLUSH_CHARS = 8192` 分片写 |
| 面板内容量 | 只增不减 | Tk Text 插入成本随内容增长（长会话单次 insert 到 0.25s） | 超过 `MAX_LINES=6000` 丢掉最旧部分并留一行提示 |
| 自动滚动 | 每次写都 `see("end")` | 流式输出时明显的重排开销 | 时间节流，最多每 100ms 一次 |

同一台机器、同一段真实 DLL 会话（3000 个 content 分片）实测：

| | 旧实现 | 现在 |
| --- | ------ | ---- |
| Tk 主线程渲染调用次数 | 3009 | **164** |
| 会话期间总耗时 | 15.75s | **3.17s** |
| 最长主线程停顿（含 mock 服务器噪声） | 14.68s | **1.20s** |
| 300 分片时的最长停顿 | — | **0.06s** |
| 真实阻塞工具（`list_firewall_rules` 60s，16 个事件） | — | **0.25s** |


维护者注意（打包）：`scripts\build_nuitka.bat` 里有 **`--enable-plugin=tk-inter`**，
少了它打包出来的 `avengine.exe` 一跑 `gui` 就会报
`Nuitka: Need to use '--enable-plugin=tk-inter' option during compilation for tk-inter to work!`。
（Nuitka 会顺带带上 `_tkinter.pyd` / `tcl86t.dll` / `tk86t.dll` / `tcl\` 数据目录。）



---

## 17. 许可证

本项目（`avengine_core.dll`、`avengine.exe` 外壳、`scripts\`、`installer\`、`service\` 等自有代码）
以 **GNU Lesser General Public License v3.0 or later（LGPL-3.0-or-later）** 发布：

- 许可证全文：[LICENSE](LICENSE)（GNU Lesser General Public License v3.0）
- 随附的 GPL-3.0 全文：[COPYING](COPYING) —— LGPL-3.0 第 3(b)、4(b) 条要求随附 GPL 文本
- 你也可以选择任何更新的 LGPL 版本（自选）。

**第三方组件各自遵循其上游许可证，本项目不改变、也不代表它们：**

| 组件 | 用途 | 许可证 | 说明 |
| ---- | ---- | ------ | ---- |
| [libyara](https://github.com/VirusTotal/yara) | YARA 规则编译/扫描 | BSD-3-Clause | 静态链接进 `avengine_core.dll` |
| [Neo23x0/signature-base](https://github.com/Neo23x0/signature-base) | `rules\` 下的本地规则快照 | 见上游 `LICENSE` | 随发布包分发时保留其许可证与出处 |
| [ClamAV](https://www.clamav.net/) | 特征库扫描（clamd） | GPL-2.0 | **独立进程**，通过 TCP（`clamd`）调用，不与本项目代码链接；`bina\` 里的安装包是第三方产物 |
| [Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon) | 实时文件/进程事件源 | Sysinternals EULA | 独立可执行文件，仅作为事件源调用 |
| Tcl/Tk、Python、Nuitka/PyYAML 等 | 运行时与打包工具链 | BSD 类 / PSF / Apache-2.0 等 | 随 `avengine.exe` 分发，遵循各自许可证 |

> 因为 ClamAV 是以**独立进程 + TCP** 方式使用（不是链接其代码），本项目自身可以按 LGPL-3.0 发布；
> 若你修改并分发 ClamAV 本体，需要单独遵守 GPL-2.0。
