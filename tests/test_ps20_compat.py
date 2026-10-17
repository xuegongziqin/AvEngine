r"""
Windows PowerShell 2.0 兼容性回归测试。

为什么必须有这一组：**Windows 7 SP1 自带的是 PowerShell 2.0**，而下面这些构造是
PS 3.0/4.0/5.0 才有的 —— 用在脚本里在 Win7 上会直接**解析失败**（整个脚本一行都不执行）
或运行期报参数错误：

  * `-in` / `-notin`                      PS 3.0+   （实测：setup_clamav.ps1 在 Win7 上
                                                    报「必须在"-"运算符的右侧提供值表达式」，
                                                    整个安装一步都没跑）
  * `Get-ChildItem -File` / `-Directory`   PS 3.0+
  * `Get-Content -Tail` / `-Head`          PS 3.0+
  * `[pscustomobject]`                     PS 3.0+
  * `ConvertTo-Json`                       PS 3.0+  （整个 cmdlet 都是 3.0 新增）
  * `Get-CimInstance`                      PS 3.0+
  * `.Where{}` / `.ForEach{}` 方法语法      PS 4.0+
  * `::new()`                              PS 5.0+

签名工具链（gen_signing_cert / sign_binaries / grant_signing_access）**只在构建机上跑**，
构建机是 Win10 + PowerShell 5.1，所以允许它们使用 PS 3+ 构造（已列入白名单并有注释）。
"""

from __future__ import annotations

import pathlib
import re
import sys

import pytest

PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

SCRIPTS = PROJECT_ROOT / "scripts"

#: 只在构建机（Win10 + PS 5.1）运行，允许 PS 3+ 构造
BUILD_ONLY = {
    "gen_signing_cert.ps1",     # ConvertTo-Json / -Depth
    "sign_binaries.ps1",        # [pscustomobject]
    "grant_signing_access.ps1",  # 构建期 ACL 修复
}

FORBIDDEN = [
    (r"\s-(notin|in)\s", "-in/-notin 是 PS 3.0+（Win7 自带 PS 2.0，会解析失败）"),
    (r"Get-ChildItem[^|]*\s-(File|Directory)\b", "Get-ChildItem -File/-Directory 是 PS 3.0+"),
    (r"Get-ChildItem[^|]*\s-Recurse[^|]*\s-File\b", "Get-ChildItem -File 是 PS 3.0+"),
    (r"Get-Content[^|]*\s-(Tail|Head)\b", "Get-Content -Tail/-Head 是 PS 3.0+"),
    (r"\[pscustomobject\]", "[pscustomobject] 是 PS 3.0+"),
    (r"ConvertTo-Json", "ConvertTo-Json 是 PS 3.0+"),
    (r"Get-CimInstance", "Get-CimInstance 是 PS 3.0+"),
    (r"\.(Where|ForEach)\s*\{", ".Where{}/.ForEach{} 是 PS 4.0+"),
    (r"::new\(", "::new() 是 PS 5.0+"),
]


def _runtime_scripts():
    return sorted(p for p in SCRIPTS.glob("*.ps1") if p.name not in BUILD_ONLY)


def test_runtime_scripts_exist():
    """
    运行期（目标机上会跑）的 PS 脚本清单。

    ClamAV 的 setup_clamav / set_clamav / lib_config_yaml 曾经也在这份清单里，
    但因为 Win7 SP1 只有 PowerShell 2.0，它们已经**整体改成 bat + CLI**（config.yaml
    交给 avengine/configwrite.py 写），所以现在只剩 Sysmon 与配置相关的脚本。
    """
    names = {p.name for p in _runtime_scripts()}
    assert "lib_sysmon.ps1" in names, names
    # 已被 bat 取代的脚本不应再出现
    for gone in ("setup_clamav.ps1", "set_clamav.ps1", "lib_config_yaml.ps1"):
        assert gone not in names, "{} 应已删除（改用 bat + CLI）".format(gone)


@pytest.mark.parametrize("script", [p.name for p in _runtime_scripts()])
def test_runtime_script_is_powershell_2_compatible(script):
    text = (SCRIPTS / script).read_text(encoding="utf-8-sig", errors="replace")
    problems = []
    for lineno, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue          # 注释里提到这些关键字是允许的（本文件就在讲它们）
        for pattern, why in FORBIDDEN:
            if re.search(pattern, line):
                problems.append("{}:{}: {} -> {}".format(script, lineno, stripped[:80], why))
    assert not problems, "PowerShell 2.0 不兼容：\n" + "\n".join(problems)


def test_build_only_scripts_are_documented():
    """白名单必须真的存在且带说明，避免以后有人偷偷加一个进去。"""
    for name in BUILD_ONLY:
        assert (SCRIPTS / name).is_file(), name
    test_source = pathlib.Path(__file__).read_text(encoding="utf-8")
    assert "只在构建机" in test_source


def test_clamav_path_no_longer_depends_on_powershell():
    """
    具体守住那次 Win7 现场报错：PowerShell 版脚本里用了 PS 3.0+ 的 `-notin`，
    在 Win7 SP1（PS 2.0）上是**解析期**失败，整个 ClamAV 安装一步都没跑。

    修法不是把 `-notin` 换成 `-notcontains`，而是把这条路径整体从 PowerShell 上摘下来：
    scripts\\setup_clamav.bat + scripts\\set_clamav.bat（纯 bat）调用
    `avengine config --clamav-host ...` 来写 config.yaml。
    """
    for name in ("setup_clamav.bat", "set_clamav.bat", "lib_avengine.bat"):
        assert (SCRIPTS / name).is_file(), name
    setup = (SCRIPTS / "setup_clamav.bat").read_text(encoding="ascii", errors="replace")
    # 选包规则仍然按版本走（6.0/6.1 → legacy）
    assert 'if "%OSVER%"=="6.1" set "WANTS_LEGACY=1"' in setup
    assert "clamwin7" in setup
    # 配置改写交给 CLI
    assert "config --clamav-host" in setup
    # 曾经的 PS 陷阱在 bat 里同样存在：shift 会把 %0 一起移位（实测 %~dp0 因此失效）
    assert 'set "SCRIPT_DIR=%~dp0"' in setup
    for name in ("setup_clamav.ps1", "set_clamav.ps1", "lib_config_yaml.ps1"):
        assert not (SCRIPTS / name).is_file(), "{} 应已删除".format(name)


def test_config_sysmon_detects_a_broken_install():
    """
    回归守卫（现场实测两次）：判断 Sysmon 是否可用不能靠"服务项/注册表键在不在"。

    坏掉的状态是：`Sysmon64` 服务项还在、`SysmonDrv` 注册表键还在，但驱动没跑。
    此时 Sysmon 会打印

        Error: Sysmon is not installed.

    **却仍然返回 0**，于是脚本一路打印 "Configuration applied"，而机器上其实
    一点遥测都没有（安全工具里这种"假成功"最危险）。

    现在的判定：解析 Sysmon 自己的输出 + 要求驱动 SysmonDrv 处于 RUNNING；
    不满足就 `-u` 之后 `-i` 干净重装，最后再复核，失败如实报错退出。
    """
    raw = (SCRIPTS / "config_sysmon.bat").read_bytes()
    assert all(b < 128 for b in raw), "config_sysmon.bat 必须保持纯 ASCII"
    text = raw.decode("ascii", errors="replace")

    assert 'findstr /i /c:"Error:"' in text, "必须解析 Sysmon 输出里的 Error:"
    assert "sc query SysmonDrv" in text, "必须检查驱动是否真的在跑"
    assert "NEEDS_CLEAN_INSTALL" in text
    assert "-accepteula -u" in text and "-accepteula -i" in text
    assert "EnableDelayedExpansion" in text, "块内用 !NEEDS_CLEAN_INSTALL!，必须开延迟展开"
    # 装完要复核服务和驱动，不能让"没有遥测"静默通过
    assert "still missing after install" in text
    assert "driver is not RUNNING" in text
    # 不能再拿注册表键当"已安装"的证据
    assert 'reg query "HKLM\\SYSTEM\\CurrentControlSet\\Services\\SysmonDrv"' not in text
