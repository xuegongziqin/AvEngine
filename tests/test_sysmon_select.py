"""
Sysmon 二进制选择测试。

Windows 7 SP1 / Server 2008 R2 只支持 Sysmon 13.x（bina\\Sysmon\\sysmonwin7\\），
Windows 8.1+ 用 15.x（bina\\Sysmon\\）。选择规则有三处实现，必须一致：

  * scripts/lib_sysmon.ps1        （install.bat / config_sysmon.bat 调用，单一事实来源）
  * avengine/paths.py sysmon_exe()（Python 侧，monitor 自动安装用）
  * installer/install.c           （一键安装器；此处只做静态检查，见文件末尾）

本文件还验证批处理脚本能在这台机器上真正解析出正确路径（用临时副本 + 插桩，
不会真的调用 Sysmon，也不会改动系统）。
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from avengine.paths import (  # noqa: E402
    native_arch,
    sysmon_candidates,
    sysmon_exe,
    windows_version,
)

SCRIPTS = PROJECT_ROOT / "scripts"
LIB_PS1 = SCRIPTS / "lib_sysmon.ps1"
CONFIG_BAT = SCRIPTS / "config_sysmon.bat"
INSTALL_BAT = SCRIPTS / "install.bat"
IS_WINDOWS = os.name == "nt"

POWERSHELL = "powershell"
HAS_PS = IS_WINDOWS and LIB_PS1.is_file()
HAS_CMD = IS_WINDOWS and CONFIG_BAT.is_file()


def _ps_choose(
    version: str | None = None,
    arch: str | None = None,
    root: Path | None = None,
    timeout: int = 90,
) -> tuple[int, str, str]:
    """调用 lib_sysmon.ps1 -Print，返回 (退出码, stdout, stderr)。"""
    cmd = [POWERSHELL, "-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass",
           "-File", str(LIB_PS1)]
    if root is not None:
        cmd += ["-Root", str(root)]
    if version:
        cmd += ["-ForceVersion", version]
    if arch:
        cmd += ["-ForceArch", arch]
    cmd.append("-Print")
    proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                          errors="replace", timeout=timeout)
    return proc.returncode, (proc.stdout or "").strip(), (proc.stderr or "").strip()


# ----------------------------------------------------------------- 版本/架构探测


def test_windows_version_and_arch_detect_something():
    major, minor = windows_version()
    if IS_WINDOWS:
        assert major >= 6, "Windows 主版本号至少是 6"
        assert minor >= 0
    assert native_arch() in ("x64", "ARM64", "x86")


# ------------------------------------------------- Python 选择（注入版本/架构）

@pytest.mark.parametrize("version,arch,expected", [
    ((6, 1), "x64", "bina/Sysmon/sysmonwin7/Sysmon64.exe"),   # Win7 SP1 x64
    ((6, 1), "x86", "bina/Sysmon/sysmonwin7/Sysmon.exe"),     # Win7 SP1 x86
    ((6, 0), "x64", "bina/Sysmon/sysmonwin7/Sysmon64.exe"),   # 2008/Vista
    ((6, 2), "x64", "bina/Sysmon/Sysmon64.exe"),              # Win8
    ((6, 3), "x64", "bina/Sysmon/Sysmon64.exe"),              # Win8.1
    ((10, 0), "x64", "bina/Sysmon/Sysmon64.exe"),             # Win10/11
    ((10, 0), "ARM64", "bina/Sysmon/Sysmon64a.exe"),          # ARM64
    ((10, 0), "x86", "bina/Sysmon/Sysmon.exe"),               # 32 位系统
])
def test_python_picks_expected_binary(version, arch, expected):
    """真实 bina 目录下，各版本/架构选出的二进制应与约定一致。"""
    chosen = sysmon_exe(root=PROJECT_ROOT, version=version, arch=arch)
    assert chosen == PROJECT_ROOT / expected
    assert chosen.is_file(), f"{chosen} 应存在（bina/Sysmon 已就绪）"


def test_python_falls_back_to_other_folder(tmp_path):
    """期望目录缺文件时，应回退到另一个目录（与 lib_sysmon.ps1 的候选顺序一致）。"""
    modern = tmp_path / "bina" / "Sysmon"
    legacy = modern / "sysmonwin7"
    legacy.mkdir(parents=True)
    (legacy / "Sysmon.exe").write_bytes(b"x")

    # 现代系统但只有 13.x：回退到 sysmonwin7
    chosen = sysmon_exe(root=tmp_path, version=(10, 0), arch="x64")
    assert chosen == legacy / "Sysmon.exe"

    # Win7 但只有 15.x：回退到 bina\Sysmon
    (legacy / "Sysmon.exe").unlink()
    (modern / "Sysmon64.exe").write_bytes(b"x")
    chosen = sysmon_exe(root=tmp_path, version=(6, 1), arch="x64")
    assert chosen == modern / "Sysmon64.exe"


def test_python_accepts_legacy_root_layout(tmp_path):
    """历史上 Sysmon.exe 直接放在项目根，仍应可用。"""
    (tmp_path / "Sysmon.exe").write_bytes(b"x")
    assert sysmon_exe(root=tmp_path, version=(10, 0), arch="x64") == tmp_path / "Sysmon.exe"


def test_python_missing_returns_preferred_path(tmp_path):
    """都找不到时返回首选路径，便于错误信息指向期望位置。"""
    chosen = sysmon_exe(root=tmp_path, version=(6, 1), arch="x64")
    assert chosen == tmp_path / "bina" / "Sysmon" / "sysmonwin7" / "Sysmon64.exe"
    assert not chosen.is_file()


def test_candidate_order_is_documented_order(tmp_path):
    names = [p.as_posix().replace(tmp_path.as_posix() + "/", "")
             for p in sysmon_candidates(root=tmp_path, version=(6, 1), arch="x64")]
    assert names == [
        "bina/Sysmon/sysmonwin7/Sysmon64.exe",
        "bina/Sysmon/sysmonwin7/Sysmon.exe",
        "bina/Sysmon/Sysmon64.exe",
        "bina/Sysmon/Sysmon.exe",
        "Sysmon.exe",
    ]


# --------------------------------------------------------- PowerShell 同一套规则

@pytest.mark.skipif(not HAS_PS, reason="需要 Windows PowerShell 与 scripts/lib_sysmon.ps1")
@pytest.mark.parametrize("version,arch,expected", [
    ("6.1", "x64", "bina/Sysmon/sysmonwin7/Sysmon64.exe"),
    ("6.1", "x86", "bina/Sysmon/sysmonwin7/Sysmon.exe"),
    ("6.0", "x64", "bina/Sysmon/sysmonwin7/Sysmon64.exe"),
    ("10.0", "x64", "bina/Sysmon/Sysmon64.exe"),
    ("10.0", "ARM64", "bina/Sysmon/Sysmon64a.exe"),
    ("10.0", "x86", "bina/Sysmon/Sysmon.exe"),
])
def test_powershell_picks_expected_binary(version, arch, expected):
    code, out, err = _ps_choose(version=version, arch=arch)
    assert code == 0, f"stderr: {err}"
    assert Path(out) == PROJECT_ROOT / expected


@pytest.mark.skipif(not HAS_PS, reason="需要 Windows PowerShell")
def test_powershell_not_found_exits_nonzero(tmp_path):
    code, out, err = _ps_choose(version="6.1", arch="x64", root=tmp_path)
    assert code == 1
    assert out == ""
    assert "Sysmon not found" in err


@pytest.mark.skipif(not HAS_PS, reason="需要 Windows PowerShell")
def test_powershell_and_python_agree():
    """两处实现必须选出同一个文件——这就是"单一事实来源"的守卫测试。"""
    for version, arch in [((6, 1), "x64"), ((6, 1), "x86"), ((10, 0), "x64"),
                          ((10, 0), "ARM64"), ((10, 0), "x86")]:
        code, out, err = _ps_choose(version="%d.%d" % version, arch=arch)
        assert code == 0, f"stderr: {err}"
        py_choice = sysmon_exe(root=PROJECT_ROOT, version=version, arch=arch)
        assert Path(out) == py_choice, f"{version}/{arch}: PS={out} Python={py_choice}"


# --------------------------------------------- 真实批处理脚本的选择链（临时副本）

def _instrumented_config_bat(work: Path, with_helper: bool = True) -> Path:
    """
    把真实的 config_sysmon.bat 复制到临时目录并插桩：在读取 sysmon_config.xml
    之前打印解析结果。这样可以在不安装/不运行 Sysmon 的前提下检验选择逻辑。
    """
    script_dir = work / "scripts"
    script_dir.mkdir(parents=True, exist_ok=True)
    if with_helper:
        (script_dir / "lib_sysmon.ps1").write_bytes(LIB_PS1.read_bytes())

    raw = CONFIG_BAT.read_bytes()
    marker = b'set "CFG=%~dp0sysmon_config.xml"'
    assert marker in raw, "config_sysmon.bat 结构变了，请同步更新本测试"
    raw = raw.replace(marker, b"echo RESOLVED=[%SYSMON%]\r\n" + marker, 1)
    target = script_dir / "config_sysmon_instr.bat"
    target.write_bytes(raw)
    return target


def _layout(work: Path, files: list[str]) -> None:
    bina = work / "bina"
    if bina.exists():
        for child in sorted(bina.rglob("*"), reverse=True):
            child.unlink() if child.is_file() else child.rmdir()
        bina.rmdir()
    root_sysmon = work / "Sysmon.exe"
    if root_sysmon.exists():
        root_sysmon.unlink()
    for rel in files:
        path = work / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"x")


def _resolved(bat: Path, work: Path) -> str:
    proc = subprocess.run(["cmd", "/c", str(bat)], capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=120,
                          cwd=str(work))
    match = re.search(r"RESOLVED=\[(.*)\]", proc.stdout or "")
    assert match, f"没有拿到解析结果，输出：{proc.stdout!r} 错误：{proc.stderr!r}"
    return match.group(1)


@pytest.mark.skipif(not (HAS_CMD and HAS_PS), reason="需要 cmd 与 Windows PowerShell")
@pytest.mark.parametrize("files,expected_rel", [
    (["bina/Sysmon/Sysmon.exe", "bina/Sysmon/Sysmon64.exe", "bina/Sysmon/Sysmon64a.exe"],
     "bina/Sysmon/Sysmon64.exe"),
    (["bina/Sysmon/Sysmon.exe"], "bina/Sysmon/Sysmon.exe"),
    (["bina/Sysmon/sysmonwin7/Sysmon.exe"], "bina/Sysmon/sysmonwin7/Sysmon.exe"),
    (["Sysmon.exe"], "Sysmon.exe"),
])
def test_batch_resolution_chain(tmp_path, files, expected_rel):
    """config_sysmon.bat 在本机（现代 x64）应解析出预期路径。"""
    bat = _instrumented_config_bat(tmp_path)
    _layout(tmp_path, files)
    resolved = _resolved(bat, tmp_path)
    assert Path(resolved) == (tmp_path / expected_rel)


@pytest.mark.skipif(not (HAS_CMD and HAS_PS), reason="需要 cmd 与 Windows PowerShell")
@pytest.mark.parametrize("files,expected_rel", [
    (["bina/Sysmon/Sysmon.exe", "bina/Sysmon/Sysmon64.exe"], "bina/Sysmon/Sysmon64.exe"),
    (["bina/Sysmon/sysmonwin7/Sysmon.exe"], "bina/Sysmon/sysmonwin7/Sysmon.exe"),
])
def test_batch_fallback_without_powershell(tmp_path, files, expected_rel):
    """
    PowerShell 不可用时（helper 缺失），批处理自身的回退选择也必须正确——
    这里覆盖过 %VAR% 在括号块里被提前展开、以及缺少跨目录兜底两个坑。
    """
    bat = _instrumented_config_bat(tmp_path, with_helper=False)
    _layout(tmp_path, files)
    resolved = _resolved(bat, tmp_path)
    assert Path(resolved).resolve() == (tmp_path / expected_rel).resolve()


@pytest.mark.skipif(not (HAS_CMD and HAS_PS), reason="需要 cmd 与 Windows PowerShell")
def test_batch_reports_no_binary(tmp_path):
    """一个都没有时不能把垃圾值（例如 "\\"）当成路径。"""
    bat = _instrumented_config_bat(tmp_path, with_helper=False)
    _layout(tmp_path, [])
    resolved = _resolved(bat, tmp_path)
    assert resolved == ""


@pytest.mark.skipif(not (HAS_CMD and HAS_PS), reason="需要 cmd 与 Windows PowerShell")
def test_install_bat_selects_and_reports(tmp_path):
    """
    install.bat 自身的版本/架构探测 + 选择：在调用 config_sysmon.bat 之前插桩退出，
    这样只验证选择逻辑，不会真的去装 Sysmon / ClamAV。
    """
    script_dir = tmp_path / "scripts"
    script_dir.mkdir(parents=True)
    (script_dir / "lib_sysmon.ps1").write_bytes(LIB_PS1.read_bytes())

    raw = INSTALL_BAT.read_bytes()
    marker = b'call "%~dp0config_sysmon.bat"'
    assert marker in raw, "install.bat 结构变了，请同步更新本测试"
    raw = raw.replace(marker,
                      b"echo SELECTED=[%SYSMON_BIN%]\r\nexit /b 0\r\n" + marker, 1)
    bat = script_dir / "install_instr.bat"
    bat.write_bytes(raw)

    modern = tmp_path / "bina" / "Sysmon"
    modern.mkdir(parents=True)
    (modern / "Sysmon.exe").write_bytes(b"x")
    (modern / "Sysmon64.exe").write_bytes(b"x")

    proc = subprocess.run(["cmd", "/c", str(bat)], capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=120,
                          cwd=str(tmp_path))
    out = proc.stdout or ""
    assert re.search(r"\[install\] Windows \d+\.\d+ \(\w+\)", out), out
    match = re.search(r"SELECTED=\[(.*)\]", out)
    assert match, out
    assert Path(match.group(1)) == modern / "Sysmon64.exe"


@pytest.mark.skipif(not (HAS_CMD and HAS_PS), reason="需要 cmd 与 Windows PowerShell")
def test_install_bat_reports_missing_sysmon(tmp_path):
    script_dir = tmp_path / "scripts"
    script_dir.mkdir(parents=True)
    (script_dir / "lib_sysmon.ps1").write_bytes(LIB_PS1.read_bytes())
    raw = INSTALL_BAT.read_bytes().replace(
        b'call "%~dp0config_sysmon.bat"',
        b"echo SELECTED=[%SYSMON_BIN%]\r\nexit /b 0\r\ncall \"%~dp0config_sysmon.bat\"", 1)
    bat = script_dir / "install_instr.bat"
    bat.write_bytes(raw)

    proc = subprocess.run(["cmd", "/c", str(bat)], capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=120,
                          cwd=str(tmp_path))
    out = proc.stdout or ""
    assert "SELECTED=[]" in out, out
    assert "Sysmon binary not found" in out, out


# --------------------------------------------------------- 脚本约定与安装器接线

def test_bat_files_are_crlf_and_ascii():
    """
    Windows 批处理要求 CRLF（LF 在 goto/多行块上会出现诡异行为），
    且 .bat 里混入非 ASCII 会在中文系统上造成乱码/解析错误
    （cmd 按 ANSI 代码页读，UTF-8 中文会被拆成乱码并当成命令执行）。
    覆盖 scripts\\、service\\ 与根目录的构建脚本。
    """
    targets = sorted(SCRIPTS.glob("*.bat"))
    targets += sorted((PROJECT_ROOT / "service").glob("*.bat"))
    root_build = PROJECT_ROOT / "build.bat"
    if root_build.is_file():
        targets.append(root_build)
    assert targets, "没有找到任何 .bat"

    offenders = []
    for bat in targets:
        raw = bat.read_bytes()
        if b"\r\n" not in raw and raw:
            offenders.append(f"{bat.name}: 没有 CRLF 换行")
            continue
        bare_lf = len(re.findall(rb"(?<!\r)\n", raw))
        if bare_lf:
            offenders.append(f"{bat.name}: 有 {bare_lf} 个裸 LF")
        try:
            raw.decode("ascii")
        except UnicodeDecodeError:
            offenders.append(f"{bat.name}: 含非 ASCII 字节")
    assert not offenders, "批处理文件约定被破坏: " + "; ".join(offenders)


def test_install_scripts_use_shared_selector():
    """install.bat / config_sysmon.bat 都必须通过 lib_sysmon.ps1 选择 Sysmon。"""
    for bat in (INSTALL_BAT, CONFIG_BAT):
        text = bat.read_text(encoding="utf-8", errors="replace")
        assert "lib_sysmon.ps1" in text, f"{bat.name} 应调用 lib_sysmon.ps1"
        assert "sysmonwin7" in text, f"{bat.name} 应提到 Win7 的旧版目录"
    install_text = INSTALL_BAT.read_text(encoding="utf-8", errors="replace")
    # 版本/架构探测必须在 install.bat 里可见
    assert "PROCESSOR_ARCHITEW6432" in install_text
    assert "ver | findstr" in install_text


def test_installer_c_matches_the_same_rule():
    """安装器（C）必须实现同一套规则：6.0/6.1 → sysmonwin7，其余 → 现代目录。"""
    src = (PROJECT_ROOT / "installer" / "install.c").read_text(encoding="utf-8",
                                                              errors="replace")
    assert "pick_sysmon_exe" in src
    assert "sysmonwin7" in src
    assert "CurrentMajorVersionNumber" in src, "版本探测应走注册表（避免清单谎言）"
    assert "GetNativeSystemInfo" in src, "架构探测应是本机架构"
    # 规则本身：6.0/6.1 判定
    assert re.search(r"legacy\s*=\s*\(major\s*==\s*6\s*&&\s*\(minor\s*==\s*0\s*\|\|\s*minor\s*==\s*1\)\)", src)
