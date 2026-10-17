"""
paths.py - 项目统一路径常量
所有模块都应从这里取路径，避免各处硬编码相对路径（相对路径一律基于项目根目录解析）。
"""

from __future__ import annotations

import os
import platform
from pathlib import Path
from typing import List, Optional, Tuple, Union

PACKAGE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = PACKAGE_DIR.parent

# ---- 配置与日志 ----
CONFIG_FILE = PROJECT_ROOT / "config.yaml"
CONFIG_EXAMPLE_FILE = PROJECT_ROOT / "config.example.yaml"
AI_CONFIG_FILE = PROJECT_ROOT / "config.ini"
AI_CONFIG_EXAMPLE_FILE = PROJECT_ROOT / "config.ini.example"
LOG_DIR = PROJECT_ROOT / "logs"
LOG_FILE = LOG_DIR / "avengine.log"
AI_STATE_FILE = LOG_DIR / "ai_state.json"
AI_DUMP_DIR = LOG_DIR / "ai_dumps"

# ---- 数据目录 ----
RULES_DIR = PROJECT_ROOT / "rules"
QUARANTINE_DIR = PROJECT_ROOT / "quarantine"
TEST_DATA_DIR = PROJECT_ROOT / "tests" / "data"

# ---- 脚本与二进制 ----
SCRIPTS_DIR = PROJECT_ROOT / "scripts"
BINARIES_DIR = PROJECT_ROOT / "bina"
SYSMON_DIR = BINARIES_DIR / "Sysmon"
SYSMON_LEGACY_DIR = SYSMON_DIR / "sysmonwin7"
SYSMON_EXE = SYSMON_DIR / "Sysmon.exe"  # 现代版 32 位；实际选择见 sysmon_exe()
SYSMON_CONFIG = SCRIPTS_DIR / "sysmon_config.xml"
# ClamAV 安装包：现代版（1.x，需要 Win8.1+）与最后支持 Win7 SP1 的旧版。
# 选哪一套由 clamav_msi() 按系统版本决定，与 Sysmon 的判定规则保持一致。
CLAMAV_MSI = BINARIES_DIR / "clamav.msi"
CLAMAV_LEGACY_DIR = BINARIES_DIR / "clamwin7"

# Sysmon 15.x 需要 Windows 8.1 / Server 2012 R2 及以上；最后支持
# Windows 7 SP1 / Server 2008 R2 的是 13.x，放在 bina\Sysmon\sysmonwin7\。
# 这套规则与 scripts/lib_sysmon.ps1、scripts/install.bat、installer/install.c 保持一致。
SYSMON_LEGACY_VERSIONS = frozenset({(6, 0), (6, 1)})  # Vista/2008、7/2008 R2
#: ClamAV 用同一套版本边界（Win7 SP1 及更早 → 旧安装包）
CLAMAV_LEGACY_VERSIONS = SYSMON_LEGACY_VERSIONS

PathLike = Union[str, Path]


def windows_version() -> Tuple[int, int]:
    """
    返回当前系统版本 (major, minor)。

    优先读注册表：CurrentMajorVersionNumber 只在 Windows 10+ 存在，老系统用
    CurrentVersion（6.1 / 6.3）。这样可避开 GetVersionEx 受清单影响而谎报 6.2 的问题。
    非 Windows 平台返回 (0, 0)。
    """
    if os.name != "nt":
        return (0, 0)
    try:
        import winreg

        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        ) as key:
            try:
                major = int(winreg.QueryValueEx(key, "CurrentMajorVersionNumber")[0])
                try:
                    minor = int(winreg.QueryValueEx(key, "CurrentMinorVersionNumber")[0])
                except OSError:
                    minor = 0
                return (major, minor)
            except OSError:
                current = str(winreg.QueryValueEx(key, "CurrentVersion")[0])
                parts = current.split(".")
                if len(parts) >= 2:
                    return (int(parts[0]), int(parts[1]))
    except (ImportError, OSError, ValueError):
        pass
    try:
        parts = platform.version().split(".")
        if len(parts) >= 2:
            return (int(parts[0]), int(parts[1]))
    except (ValueError, IndexError):
        pass
    return (0, 0)


def native_arch() -> str:
    """
    返回本机架构：'x64' / 'ARM64' / 'x86'。

    32 位进程跑在 64 位系统上时 PROCESSOR_ARCHITECTURE 是 x86，
    所以先看 PROCESSOR_ARCHITEW6432（与 lib_sysmon.ps1 一致）。
    """
    arch = os.environ.get("PROCESSOR_ARCHITEW6432") or os.environ.get("PROCESSOR_ARCHITECTURE")
    if not arch:
        arch = platform.machine()
    arch = (arch or "").upper()
    if arch in ("AMD64", "IA64", "X86_64"):
        return "x64"
    if arch in ("ARM64", "AARCH64"):
        return "ARM64"
    return "x86"


def sysmon_candidates(
    root: Optional[PathLike] = None,
    version: Optional[Tuple[int, int]] = None,
    arch: Optional[str] = None,
) -> List[Path]:
    """
    按优先级列出候选 Sysmon 可执行文件（顺序与 lib_sysmon.ps1 相同）：
    期望目录的架构对应文件名 → 期望目录的其它名字 → 另一个目录 → 项目根下的旧布局。
    """
    base = Path(root) if root is not None else BINARIES_DIR.parent
    ver = version if version is not None else windows_version()
    architecture = arch if arch is not None else native_arch()

    legacy = (ver[0], ver[1]) in SYSMON_LEGACY_VERSIONS
    modern_dir = base / "bina" / "Sysmon"
    legacy_dir = modern_dir / "sysmonwin7"
    primary_dir = legacy_dir if legacy else modern_dir
    other_dir = modern_dir if legacy else legacy_dir

    if architecture == "ARM64" and not legacy:
        names = ["Sysmon64a.exe", "Sysmon64.exe", "Sysmon.exe"]
    elif architecture == "x64":
        names = ["Sysmon64.exe", "Sysmon.exe"]
    else:
        names = ["Sysmon.exe"]

    candidates: List[Path] = []
    candidates += [primary_dir / name for name in names]
    candidates += [other_dir / name for name in names]
    candidates.append(base / "Sysmon.exe")  # 旧布局：直接放在项目根
    return candidates


def sysmon_exe(
    root: Optional[PathLike] = None,
    version: Optional[Tuple[int, int]] = None,
    arch: Optional[str] = None,
) -> Path:
    """
    返回本机应当使用的 Sysmon 可执行文件。

    候选全部不存在时返回首选路径（调用方据此报错，提示期望位置）。
    """
    candidates = sysmon_candidates(root=root, version=version, arch=arch)
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return candidates[0]


# ---------------- ClamAV 安装包选择（与 Sysmon 同一套版本规则） ----------------


def clamav_is_legacy(version: Optional[Tuple[int, int]] = None) -> bool:
    """本机是否该用「最后支持 Win7」的 ClamAV 安装包。"""
    ver = version if version is not None else windows_version()
    return (ver[0], ver[1]) in CLAMAV_LEGACY_VERSIONS


def clamav_candidates(
    root: Optional[PathLike] = None,
    version: Optional[Tuple[int, int]] = None,
) -> List[Path]:
    """
    按优先级列出候选 ClamAV 安装包：

      1. 与本机版本匹配的目录里的任意 *.msi（按文件名排序，兼容 clamavwin7.msi /
         clamav.msi / 带版本号的各种命名）
      2. 另一个目录里的 *.msi（expected 目录为空时兜底）
      3. bina\\clamav.msi（旧布局：直接放在 bina 下）

    这样用户往 bina\\clamwin7\\ 里丢任意命名的 MSI 都能被认出来。
    """

    def msis_in(directory: Path) -> List[Path]:
        if not directory.is_dir():
            return []
        try:
            return sorted(p for p in directory.glob("*.msi") if p.is_file())
        except OSError:
            return []

    base = Path(root) if root is not None else BINARIES_DIR.parent
    modern_dir = base / "bina"
    legacy_dir = modern_dir / "clamwin7"
    expected, other = ((legacy_dir, modern_dir) if clamav_is_legacy(version)
                       else (modern_dir, legacy_dir))

    candidates: List[Path] = []
    # 现代版目录里可能有 signing\ 之类的子目录，glob 只扫一层 ✓
    for directory in (expected, other):
        for msi in msis_in(directory):
            if msi not in candidates:
                candidates.append(msi)
    fallback = modern_dir / "clamav.msi"
    if fallback not in candidates:
        candidates.append(fallback)
    return candidates


def clamav_msi(
    root: Optional[PathLike] = None,
    version: Optional[Tuple[int, int]] = None,
) -> Path:
    """
    返回本机应当使用的 ClamAV 安装包；都找不到时返回首选路径（调用方据此报错）。
    """
    candidates = clamav_candidates(root=root, version=version)
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return candidates[0]


def resolve_path(path: PathLike) -> Path:
    """
    解析路径：相对路径基于项目根目录，绝对路径原样返回。

    Args:
        path: 路径字符串或 Path 对象。

    Returns:
        解析后的绝对路径。
    """
    p = Path(path).expanduser()
    if p.is_absolute():
        return p
    return (PROJECT_ROOT / p).resolve()
