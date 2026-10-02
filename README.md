# AvEngine

基于 **YARA + ClamAV + Sysmon** 的 Windows 多引擎杀毒引擎：静态规则检测、特征库扫描与实时行为监控三者结合，检出威胁后可自动隔离，并支持接入 OpenAI 兼容大模型做事件分析。

- **内核**：C++（`avengine_core.dll`）——YARA 扫描、ClamAV 客户端、实时监控、AI 会话
- **外壳**：Python（Nuitka `--standalone` 打包为 `avengine.exe`）——参数解析、配置、菜单、展示
- **发布形态**：`build.bat` 一键产出 `releases\AvEngine-<版本>\`，整目录拷到目标机器即可运行，**目标机无需安装 Python**

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
│  ├─ Sysmon\Sysmon.exe(.64/.64a) monitor 自动安装 Sysmon 时使用
│  ├─ packs\Sysmon.zip
│  └─ clamav.msi                  Win10/11 本机安装 ClamAV 用（Win7 用不到）
├─ scripts\                       运维脚本（详见第 8 节）
│  ├─ sysmon_config.xml
│  ├─ install.bat
│  ├─ config_sysmon.bat
│  ├─ setup_clamav.ps1
│  ├─ set_clamav.ps1
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
| Windows 10 / 11 | 全功能：YARA + 本机 ClamAV + Sysmon + AI |
| Windows 7 SP1 | YARA + Sysmon + AI；**ClamAV 1.x 不支持 Win7**，需改用「局域网 clamd」或「纯 YARA」（见第 6 节） |

- **Win7 SP1 需安装 UCRT**（KB2999226 / Universal C Runtime）；`deploy_win7.bat` 会检测并提示。
- 64 位系统。发布版自带 Python 运行时，**目标机无需安装 Python**。
- 只读运行不需要管理员；`monitor` 与 Sysmon/ClamAV 安装需要管理员。

---

## 4. 命令总览

```bat
avengine.exe [全局参数] <命令> [命令参数]
```

| 命令 | 作用 | 权限 |
| ---- | ---- | ---- |
| （无参数） | 进入交互菜单 | 实时监控需管理员 |
| `scan <path>` | 扫描文件或目录（YARA + ClamAV） | 普通用户 |
| `status` | 查看各引擎与环境状态 | 普通用户 |
| `monitor` | 实时监控（Sysmon 事件触发按访问扫描） | 管理员 |
| `update-db` | 通知 clamd 重载病毒库 | clamd 运行中 |
| `ai` | AI 分析：批次分析 / `ask` 提问 / `--test` 连通 | 普通用户 |
| `-v` / `--version` | 打印版本 | — |
| `-c, --config <文件>` | 指定配置文件（写在子命令**前面**） | — |

全局参数示例：

```bat
avengine.exe -c D:\other-config.yaml status
```

退出码：`scan` 返回 `0`（未检出）或 `1`（检出威胁 / 路径不存在），可直接用于脚本判断。

### 4.1 扫描：scan

```bat
avengine.exe scan C:\Users\Public\sample.exe    :: 单文件（先打印 SHA256）
avengine.exe scan C:\Temp                        :: 递归目录
```

- 双引擎：YARA 匹配 `rules\`，ClamAV 交给 clamd；任一引擎不可用时**自动降级**，另一个继续工作。
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
C++ 内核: 已加载 (v0.1.0)
YARA 规则: 已加载 (720 个规则文件, 跳过 15 个不兼容文件)
ClamAV 连接: 不可用
Sysmon: 未安装
隔离目录: <根目录>\quarantine (未创建)
监控路径: C:\Users\Public, C:\Temp
AI 分析: 未配置（缺少 config.ini，参考 config.ini.example）
-----------------
```

| 字段 | 正常值 | 异常处理 |
| ---- | ------ | -------- |
| `C++ 内核` | 已加载 | 未加载 → 确认 `avengine\_native\avengine_core.dll` 存在且未被杀软拦截 |
| `YARA 规则` | 已加载（N 个规则文件） | 未加载 → 检查 `yara.rules_path` 与 `rules\`；「跳过 N 个」见 FAQ |
| `ClamAV 连接` | 可用 + 版本号 | Win10/11 → `scripts\start_clamav.bat`；Win7 → 见第 6 节 |
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
```

| 参数 | 说明 |
| ---- | ---- |
| （无参数） | 采集窗口内事件 → 多轮分析 → 输出中文结论 |
| `--minutes N` | 覆盖批次窗口分钟数（默认取 `config.ini` 的 `interval/60`） |
| `--prompt "..."` | 等价于 `ai ask "..."` |
| `ask <问题>` | 自由问答，可调用工具查证 |
| `--test` | 仅测试端点连通性 |

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

### 5.2 `config.ini`（AI，可选）

模板 `config.ini.example`，两段：

- `[ai]`：`enabled`、`base_url`、`api_key`、`model`、`timeout`、`interval`、`max_rounds`、`max_events_per_batch`、`max_event_chars`、`max_tool_result_chars`、`scan_analysis`
- `[sources]`：`sysmon` / `process` / `network` / `dns` / `powershell` / `system` / `application` / `fileio` 事件源开关

`base_url` 兼容任意 OpenAI 风格端点（OpenAI / DeepSeek / 本地 Ollama 等）。`fileio` 事件量大，恒不进批次，AI 需要时用 `grep_events` 按需检索。

---

## 6. Windows 7 部署

ClamAV 1.x 的官方 Windows 安装包面向 Windows 10+，在 Win7 上无法正常运行。AvEngine 的 ClamAV 只是一个 **clamd TCP 客户端**（读取 `config.yaml` 的 `clamav.host` / `port`），因此 Win7 上有两种选择，二选一即可，**不需要本机安装 ClamAV**：

| 方案 | 操作 | 结果 |
| ---- | ---- | ---- |
| **局域网 clamd** | 在另一台受支持主机（Win10/11、Linux，或 `clamav/clamav` Docker 镜像）安装并启动 clamd，放开 3310 端口；在 Win7 运行 `scripts\set_clamav.ps1 -ClamdHost <clamd的IP>` | `status` 显示 ClamAV 可用 + 版本号 |
| **纯 YARA** | 运行 `scripts\set_clamav.ps1 -ClamdHost none`（等价于把 `clamav.host` 置空） | `status` 显示 ClamAV 不可用，`scan` 仍用 YARA + Sysmon 正常工作 |

管理员执行 `scripts\install.bat` 时会自动识别 Win7 并询问选择哪一种（见第 7 节）。

部署步骤建议：

1. 复制整个发布目录到 Win7（如 `C:\AvEngine-0.1.0\`）。
2. 确认 UCRT 已安装（缺则装 KB2999226）。
3. 双击 `deploy_win7.bat` 自检，看 `status` 是否正常。
4. 用 `scripts\set_clamav.ps1` 选择 ClamAV 方案（或直接纯 YARA）。
5. 需要实时监控则管理员运行 `scripts\install.bat` 装上 Sysmon，再 `avengine.exe monitor`。

> 局域网 clamd 默认无认证，请用防火墙限制 3310 端口仅对可信网段开放。

---

## 7. Sysmon / ClamAV 安装（管理员）

```bat
:: 管理员 CMD / PowerShell，在发布目录下
scripts\install.bat
```

`install.bat` 行为：

- **Win10/11**：配置 Sysmon 后，调用 `setup_clamav.ps1` 安装 `bina\clamav.msi`、写 `clamd.conf` / `freshclam.conf`、`freshclam` 更新病毒库、注册并启动 `clamd` 服务（`127.0.0.1:3310`）。
- **Win7**：提示 ClamAV 1.x 不支持，并询问 `1 = 局域网 clamd` / `2 = 纯 YARA`，随后调用 `set_clamav.ps1` 更新 `config.yaml`，**不安装 MSI**。

单独脚本：

| 脚本 | 作用 |
| ---- | ---- |
| `scripts\config_sysmon.bat` | 仅用 `sysmon_config.xml` 配置 Sysmon（需管理员） |
| `scripts\setup_clamav.ps1` | Win10/11 本机安装/配置 ClamAV（需管理员） |
| `scripts\set_clamav.ps1` | 指向局域网 clamd 或禁用 ClamAV（普通权限即可） |
| `scripts\start_clamav.bat` | 前台启动本机 clamd |

---

## 8. `scripts\` 目录说明（哪些是程序必需的）

| 文件 | 谁使用 | 是否必需 |
| ---- | ------ | -------- |
| `sysmon_config.xml` | 程序：`monitor` 自动安装 Sysmon 时读取（`cli.py`） | **用 `monitor` 时必需** |
| `bina\Sysmon\Sysmon.exe` | 程序：同上 | **用 `monitor` 时必需** |
| `install.bat` | 仅操作员手动执行 | 可选 |
| `config_sysmon.bat` | 仅操作员手动执行 | 可选 |
| `setup_clamav.ps1` | 仅操作员手动执行 | 可选 |
| `set_clamav.ps1` | 仅操作员手动执行 | 可选 |
| `start_clamav.bat` | 仅操作员手动执行 | 可选 |

**结论**：`scan` / `status` / `ai` 完全不依赖 `scripts\` 里的任何文件；程序自身只会在 `monitor` 自动装 Sysmon 时读取 `scripts\sysmon_config.xml`（配合 `bina\Sysmon\`）。其余脚本都是给运维人员的便利工具，可删。

---

## 9. 构建（维护者）

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

版本号取自 `pyproject.toml` 的 `version = "..."`，产物目录为 `releases\AvEngine-<版本>\`。

> `build.bat` 会把 `config.ini` / `config.yaml` / `logs\` / `quarantine\` 从发布目录中剔除（含冒烟复检一次），确保发布包不夹带本机 API 密钥与运行状态。

### 9.3 单独构建各部件

```bat
cpp\build.bat                 :: 只重建 C++ 内核
scripts\build_nuitka.bat      :: 只重打包 Python 外壳
bash cpp\scripts\build_libyara.sh   :: 只重建 libyara.a（MSYS2 内，环境变量可覆盖 YARA_SRC / OUT）
```

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

测试不依赖本机 clamd / Sysmon：ClamAV 用例用不可达端口验证降级，YARA 用例用临时规则目录，并校验 `rules\` 真实规则库可编译。

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
Win10/11：启动本机服务 `scripts\start_clamav.bat`（或 `scripts\install.bat` 安装）。Win7：ClamAV 1.x 不支持，改用局域网 clamd 或纯 YARA（第 6 节）。

**命令行扫描命中后一直等输入**
命中会询问是否隔离。脚本中用 `echo n | avengine.exe scan <path>` 提供回答。

**EICAR 样本没被检出 / 找不到**
EICAR 是标准测试串，主机上其他杀软可能在扫描前就删除它；换一个隔离环境再测。

**PowerShell 脚本被策略拦截**
各 `.bat` 已用 `-ExecutionPolicy Bypass` 调用 `.ps1`；手工执行时可用
`powershell -NoProfile -ExecutionPolicy Bypass -File scripts\set_clamav.ps1 -ClamdHost none`。

**想彻底不带 ClamAV**
删除 `bina\clamav.msi`（省约 216 MB），并 `scripts\set_clamav.ps1 -ClamdHost none`。

---

## 14. YARA 规则库

`rules\` 为 [Neo23x0/signature-base](https://github.com/Neo23x0/signature-base) 的本地快照（普通目录，非 submodule），遵守其上游 LICENSE。更新方式：重新下载上游仓库并覆盖该目录，然后重新 `build.bat`（或直接把该目录拷进发布目录）。
