# AvEngine

基于 **YARA + ClamAV + Sysmon** 的 Windows 多引擎杀毒引擎：静态规则检测、特征库扫描与实时行为监控三者结合，检出威胁后自动隔离。

## 目录结构

```
AntierX/
├── avengine/               # Python 包（主代码）
│   ├── cli.py              # 命令行入口：子命令 + 交互菜单
│   ├── paths.py            # 统一路径常量（相对路径均基于项目根目录）
│   ├── config.py           # 配置加载与默认配置生成
│   ├── utils.py            # 日志、隔离、哈希、权限检测
│   ├── yara_scanner.py     # YARA 规则编译与扫描
│   ├── clamav_scanner.py   # ClamAV (clamd) 封装
│   ├── sysmon_monitor.py   # Sysmon 安装/服务与事件订阅（win32 惰性导入）
│   ├── scheduler.py        # 扫描调度：实时事件 / 定时批量 / 手动任务
│   └── ai/                 # AI 分析子包（config.ini 驱动）
│       ├── client.py       # OpenAI 兼容客户端（Function Calling + CALL 兜底）
│       ├── collectors.py   # ETW/事件日志按需采集（EvtQuery 时间窗口）
│       ├── tools.py        # 工具库：进程/文件/网络/系统/事件/处置/情报
│       ├── session.py      # 多轮工具调用会话（END 协议）
│       ├── service.py      # 批次/问答/检出联动 + 后台定时
│       ├── prompts.py      # 系统提示与消息构建
│       └── config.py       # config.ini 解析
├── tests/                  # pytest 单元测试
│   ├── data/               # 测试样本（含 EICAR 测试串）
│   └── manual/             # 手动诊断脚本（不参与 pytest 收集）
├── scripts/                # 安装与运维脚本
├── installer/              # 一键安装程序（install.c + AvInstaller.exe）
├── rules/                  # YARA 规则库（Neo23x0/signature-base 快照）
├── bina/                   # 二进制与安装包（不入库）
├── logs/                   # 运行日志（不入库）
├── quarantine/             # 隔离区（不入库）
├── config.yaml             # 主配置
├── config.example.yaml     # 配置示例（缺失 config.yaml 时据此生成）
├── config.ini              # AI 配置（可选，复制 config.ini.example 生成）
├── config.ini.example      # AI 配置模板
└── pyproject.toml          # 包元数据与 pytest 配置
```

## 环境要求

- **Windows 10/11**：全功能（YARA + 本机 ClamAV + Sysmon）
- **Windows 7 SP1**：YARA + Sysmon；ClamAV 1.x 不支持 Win7，请改用「局域网 clamd」或「纯 YARA」（见下）
- Python 3.8+（源码方式运行需要）
- 管理员权限（实时监控、Sysmon 安装需要）
- 可选：ClamAV for Windows（`bina/clamav.msi`，仅 Win10/11）

## 安装

### 方式一：一键安装程序（推荐）

`installer\AvInstaller.exe`（C + Win32 编写）自动完成全部环境配置。以管理员身份运行：

```powershell
.\installer\AvInstaller.exe
```

程序依次执行：

1. 定位项目根目录，创建 `logs/`、`quarantine/`
2. 检查管理员权限
3. 创建 `venv`，安装 `requirements.txt` / `requirements-dev.txt`（yara-python、pyclamd、pywin32、pytest 等）
4. 安装 `bina\clamav.msi` → 写入 `clamd.conf` / `freshclam.conf` → 更新病毒库 → 注册并启动 `clamd` 服务（127.0.0.1:3310）
5. 安装 Sysmon 并应用 `scripts\sysmon_config.xml`
6. 生成 `config.yaml`，验证依赖导入、YARA 规则编译与 clamd 连通性

| 参数 | 说明 |
| ---- | ---- |
| `--dry-run` | 只打印将要执行的命令，不做任何修改 |
| `--no-python` / `--no-clamav` / `--no-sysmon` / `--no-verify` | 跳过对应步骤 |
| `--help` | 查看帮助 |

日志写入 `logs\install.log`。安装包缺失时请从官方地址下载后放入 `bina\`：

- ClamAV → `bina\clamav.msi`（https://www.clamav.net/downloads）
- Sysmon → `bina\Sysmon\Sysmon.exe`（https://learn.microsoft.com/sysinternals/downloads/sysmon）

重新编译安装器：

```bat
scripts\build_installer.bat
```

### 方式二：手动安装

```powershell
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt        # 运行依赖
pip install -r requirements-dev.txt    # 额外安装 pytest
pip install -e .                       # 可选：安装为包，提供 avengine 命令
```

仅安装 Sysmon 配置与 ClamAV（管理员 PowerShell / CMD）：

```powershell
.\scripts\install.bat
```

### Windows 7 部署（ClamAV 可选）

ClamAV 1.x 的官方 Windows 安装包面向 Windows 10+，在 Win7 上无法正常运行。AvEngine 的 ClamAV 只是一个 **clamd TCP 客户端**（读取 `config.yaml` 的 `clamav.host` / `port`），因此 Win7 上有两种选择：

| 方案 | 操作 | 结果 |
| ---- | ---- | ---- |
| **局域网 clamd** | 在另一台受支持主机（Win10/11、Linux，或 `clamav/clamav` Docker 镜像）安装并启动 clamd，放开 3310 端口；在 Win7 运行 `.\scripts\set_clamav.ps1 -ClamdHost <clamd的IP>` | `status` 显示 ClamAV 可用 + 版本号 |
| **纯 YARA** | 运行 `.\scripts\set_clamav.ps1 -ClamdHost none`（等价于把 `clamav.host` 置空） | `status` 显示 ClamAV 不可用，`scan` 仍用 YARA + Sysmon 正常工作 |

`.\scripts\install.bat` 会自动识别 Win7 并询问选择哪种方式，本机不安装 ClamAV。局域网 clamd 无认证，请用防火墙限制 3310 端口仅对可信网段开放。

## 使用指南

以下命令均在项目根目录执行（激活 venv 后可省略 `.\venv\Scripts\` 前缀；若执行过 `pip install -e .`，也可用 `avengine` 代替 `python -m avengine`）。

### 快速开始

```powershell
.\venv\Scripts\python.exe -m avengine status                # 1. 检查引擎状态
.\venv\Scripts\python.exe -m avengine scan C:\path\to\file  # 2. 扫描文件或目录
.\venv\Scripts\python.exe -m avengine                       # 3. 或进入交互菜单
```

### 命令总览

| 命令 | 作用 | 权限 |
| ---- | ---- | ---- |
| `scan <path>` | 扫描文件或目录（YARA + ClamAV 双引擎） | 普通用户 |
| `monitor` | 实时监控（Sysmon 事件触发按访问扫描） | 管理员 |
| `status` | 查看各引擎与环境状态 | 普通用户 |
| `update-db` | 通知 clamd 重载病毒库 | clamd 服务运行中 |
| `ai` | AI 分析：批次事件分析 / `ask` 自由提问 / `--test` 连通测试 | 普通用户 |
| （无参数） | 交互式菜单 | 实时监控需管理员 |
| `--help` / `-v` | 全部参数 / 版本号 | — |

全局参数写在子命令**前面**：`-c, --config <文件>` 指定配置（默认 `config.yaml`），例如 `python -m avengine -c D:\other.yaml status`。

### 扫描：scan

```powershell
.\venv\Scripts\python.exe -m avengine scan C:\Users\Public\sample.exe   # 单文件
.\venv\Scripts\python.exe -m avengine scan C:\Temp                      # 递归目录
```

- **双引擎并行**：YARA 匹配 `rules/` 规则，ClamAV 交给 clamd 特征扫描；任一引擎不可用时自动降级，另一个继续工作
- 单文件会先打印 SHA256；命中后逐条输出 `[YARA]` / `[ClamAV]` 明细
- 发现威胁时**交互式询问**是否隔离到 `quarantine/`（`y` 移入隔离区，`n` 保留原文件）
- 返回码：`0` = 未检出，`1` = 检出威胁或路径不存在，可直接用于脚本判断

```powershell
.\venv\Scripts\python.exe -m avengine scan C:\dangerous
if ($LASTEXITCODE -eq 1) { Write-Host "发现威胁！" }
```

脚本中无人应答交互时，可用管道直接传入：

```powershell
echo y | .\venv\Scripts\python.exe -m avengine scan C:\dangerous   # 自动隔离
echo n | .\venv\Scripts\python.exe -m avengine scan C:\dangerous   # 仅报告
```

验证引擎是否工作（项目自带 EICAR 测试样本，应报检出并返回 1）：

```powershell
.\venv\Scripts\python.exe -m avengine scan tests\data\malicious.txt
```

> 注意：EICAR 是标准测试串，主机上若装有其他杀软，可能在扫描前就把该样本删除。

### 实时监控：monitor

```powershell
# 需要管理员身份运行 PowerShell / CMD
.\venv\Scripts\python.exe -m avengine monitor
```

- 检测到 Sysmon 缺失时自动安装并启动，同时尝试拉起 `clamd` 服务
- 订阅 Sysmon 文件事件，`scan.monitor_paths` 目录中的文件被创建/修改时触发按访问扫描
- 检出时打印红色「威胁告警」（路径 / 细节 / 处理动作），`Ctrl+C` 停止
- 非管理员运行会直接提示并退出

### 查看状态：status

```powershell
.\venv\Scripts\python.exe -m avengine status
```

| 字段 | 正常值 | 异常处理 |
| ---- | ------ | -------- |
| ClamAV 连接 | 可用 + 版本号 | 服务未启动 → 运行 `scripts\start_clamav.bat`；Win7 请改用局域网 clamd 或纯 YARA（见「Windows 7 部署」） |
| YARA 规则 | 已加载（N 个规则文件） | 未加载 → 检查 `yara.rules_path` 与 `rules/` 目录 |
| Sysmon | 可用（已安装） | 执行一次 `monitor` 会自动安装 |
| 隔离目录 / 监控路径 | 与配置一致 | 见下方配置说明 |

### 病毒库：update-db

```powershell
.\venv\Scripts\python.exe -m avengine update-db
```

`freshclam` 下载新特征库后执行本命令，通知 clamd **重载**已加载的病毒库；clamd 不可达时返回 1。

### AI 分析：ai

把 ETW / Sysmon 事件交给大模型（OpenAI 兼容接口）自动分析，AI 可在会话中调用引擎工具取证，结论以 `END` 结束。

```powershell
copy config.ini.example config.ini     # 1. 生成配置并填写 base_url / model / api_key
.\venv\Scripts\python.exe -m avengine ai --test   # 2. 测试端点连通
.\venv\Scripts\python.exe -m avengine ai          # 3. 手动跑一批（窗口 = interval/60 分钟）
.\venv\Scripts\python.exe -m avengine ai --minutes 10      # 指定 10 分钟窗口
.\venv\Scripts\python.exe -m avengine ai ask "当前有可疑外联吗？"   # 自由提问
```

| 参数 | 说明 |
| ---- | ---- |
| （无参数） | 采集窗口内事件 → 多轮分析（调用工具取证）→ 输出中文结论 |
| `--minutes N` | 覆盖批次窗口分钟数（默认取 `config.ini` 的 `interval/60`） |
| `--prompt "..."` | 等价于 `ai ask "..."` |
| `ask <问题>` | 自由问答，可调用工具查证 |
| `--test` | 仅测试端点连通性（GET `/models`） |

工作机制：

- **批次会话**：每 `interval`（默认 300 秒）把 `sysmon / process / network / dns / powershell / system / application` 事件汇总为一批，作为一次独立会话发给 AI；AI 多轮调用工具直到输出 `END`、给出无工具结论或达到 `max_rounds`，下一批开新会话
- **Function Calling + 文本兜底**：优先走 `tools` / `tool_calls`；不支持 FC 的模型可用独占行 `CALL 工具名 参数=值` 发起调用，结果以 `TOOL ...` 回传
- **工具库（24 个）**：进程（含 `DUMP_MEMORY` 内存转储到 `logs\ai_dumps\`）、文件（哈希/读取/双引擎扫描/PE 解析/提字符串）、网络、系统（服务/注册表/计划任务/已安装程序）、事件（`query_events` / `grep_events` 按需检索，含不进批次的 `fileio`）、处置（隔离/恢复/杀进程，全自动执行）、情报（引擎日志/隔离区/引擎状态）
- **检出联动**：`scan` 发现威胁时把首个检出交给 AI 分析（`config.ini` 的 `scan_analysis=false` 关闭）
- **监控联动**：`monitor` 启动时若 AI 已启用，后台每 `interval` 秒自动跑一批（进程结束自动停止）
- **状态展示**：`status` 输出 AI 配置、端点连通性与最近一次分析记录（`logs\ai_state.json`）

> `fileio` 事件量大不进批次，AI 需要文件访问证据时用 `grep_events(source="fileio", keyword=...)` 按需检索。通道未启用时用管理员执行 `wevtutil sl "<通道名>" /e:true`。

### 交互菜单

不带子命令运行进入菜单（`python -m avengine`）：

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

输入 `1-6` 选择功能；扫描时按提示粘贴路径即可，`Ctrl+C` 取消当前操作。

### 配置

配置文件为 `config.yaml`（缺失时按 `config.example.yaml` 自动重建），结构如下：

| 配置段 | 字段 | 说明 |
| ------ | ---- | ---- |
| `yara` | `rules_path` | YARA 规则目录，递归加载 `.yar` / `.yara` |
| `clamav` | `host` / `port` / `timeout` | clamd 连接，默认 `127.0.0.1:3310`；可指向局域网 clamd（如 `192.168.1.50`），`host` 置空则禁用 ClamAV（纯 YARA） |
| `sysmon` | `channel` | Sysmon 事件通道 |
| `quarantine` | `path` | 检出后的隔离目录 |
| `scan` | `on_access` | 实时监控开关（由 Sysmon 文件事件触发） |
| `scan` | `timer_enabled` / `timer_interval` | 定时批量扫描开关与间隔（秒） |
| `scan` | `monitor_paths` | 定时扫描 / 实时监控关注的目录列表 |

- 所有相对路径一律基于**项目根目录**解析，与调用时的工作目录无关
- 修改 `monitor_paths` 后实时监控与定时扫描立即生效，无需改其他代码

AI 功能使用独立的 `config.ini`（模板 `config.ini.example`），分为 `[ai]`（端点、模型、`interval` 批次间隔、`max_rounds`、`scan_analysis` 等）与 `[sources]`（八个事件源开关）两段；未创建 `config.ini` 时 AI 保持关闭，不影响引擎其他功能。

### 日志与隔离区

- 引擎日志：`logs\avengine.log`（扫描、告警、错误全量记录）
- 安装日志：`logs\install.log`（一键安装器输出）
- AI 状态：`logs\ai_state.json`（最近分析记录，`status` 会展示）；AI 内存转储：`logs\ai_dumps\`
- 隔离区：`quarantine\`，被隔离文件以 `原名_时间戳.扩展名` 移入此处（重名自动追加序号）；恢复时改回原文件名并移回原路径

## 测试

```powershell
pytest                 # 运行单元测试（tests/）
python tests\manual\sysmon_watch.py   # 手动查看 Sysmon 事件流
```

测试不依赖本机 clamd / Sysmon 服务：ClamAV 用例使用不可达端口验证降级行为，YARA 用例使用临时规则目录，并额外校验 `rules/` 真实规则库可编译。

## YARA 规则库

`rules/` 为 [Neo23x0/signature-base](https://github.com/Neo23x0/signature-base) 的本地快照（普通目录，非 submodule），遵守其上游 LICENSE。更新方式：重新下载上游仓库并覆盖该目录。
