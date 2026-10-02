"""
paths.py - 项目统一路径常量
所有模块都应从这里取路径，避免各处硬编码相对路径（相对路径一律基于项目根目录解析）。
"""

from __future__ import annotations

from pathlib import Path
from typing import Union

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
SYSMON_EXE = BINARIES_DIR / "Sysmon" / "Sysmon.exe"
SYSMON_CONFIG = SCRIPTS_DIR / "sysmon_config.xml"
CLAMAV_MSI = BINARIES_DIR / "clamav.msi"

PathLike = Union[str, Path]


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
