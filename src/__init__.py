"""
AvEngine - 基于 YARA、ClamAV 和 Sysmon 的杀毒引擎核心包
"""

__version__ = "0.1.0"
__author__ = "Your Name"
__all__ = [
    "YaraScanner",
    "ClamavScanner",
    "SysmonMonitor",
    "Scheduler",
    "setup_logging",
    "quarantine_file",
    "load_config",
]

import logging
import sys

from .yara_scanner import YaraScanner
from .clamav_scanner import ClamavScanner
from .scheduler import Scheduler
from .utils import setup_logging, quarantine_file, load_config

# Sysmon 监控模块仅在 Windows 平台导入
if sys.platform == "win32":
    from .sysmon_monitor import SysmonMonitor
else:
    SysmonMonitor = None  # 非 Windows 下不可用


# 设置一个默认的 NullHandler，避免未配置日志时出现警告
logging.getLogger(__name__).addHandler(logging.NullHandler())

# 可选的包级别初始化日志
def _init_logger():
    """当包被导入时，可自动配置基础日志（仅在未配置时生效）"""
    if not logging.getLogger().handlers:
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

# 取消下面注释即可在导入时自动启用基础日志
# _init_logger()