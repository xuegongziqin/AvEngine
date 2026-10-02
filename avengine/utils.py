"""
utils.py - 公共工具函数
提供日志设置、文件隔离、哈希计算、权限与平台检测等通用能力。
"""

from __future__ import annotations

import hashlib
import logging
import platform
import shutil
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional

from .paths import resolve_path


# -------------------- 日志设置 --------------------

def setup_logging(
    log_level: int = logging.INFO,
    log_file: Optional[Path] = None,
    log_format: str = "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    date_format: str = "%Y-%m-%d %H:%M:%S",
) -> None:
    """
    配置全局日志记录器（控制台 + 可选文件），重复调用会替换已有 handler。

    Args:
        log_level: 日志级别。
        log_file: 日志文件路径，提供时同时写入文件。
        log_format: 日志格式。
        date_format: 时间格式。
    """
    formatter = logging.Formatter(log_format, datefmt=date_format)
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stdout)]

    if log_file:
        path = resolve_path(log_file)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            handlers.append(logging.FileHandler(path, encoding="utf-8"))
        except OSError as e:
            logging.error("无法创建日志文件 %s: %s", path, e)

    for handler in handlers:
        handler.setLevel(log_level)
        handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
        handler.close()
    for handler in handlers:
        root_logger.addHandler(handler)

    logging.info("日志系统已初始化 (级别=%s)", logging.getLevelName(log_level))
    if log_file:
        logging.info("日志文件: %s", resolve_path(log_file))


# -------------------- 文件隔离 --------------------

def quarantine_file(
    src_path: str,
    quarantine_dir: str,
    add_timestamp: bool = True,
) -> Optional[str]:
    """
    把可疑文件移动到隔离目录；目标重名时自动追加时间戳或序号。

    Args:
        src_path: 源文件路径。
        quarantine_dir: 隔离目录（相对路径基于项目根目录，目录会自动创建）。
        add_timestamp: 是否在文件名中追加时间戳。

    Returns:
        隔离后的新路径，失败返回 None。
    """
    src = Path(src_path)
    if not src.is_file():
        logging.error("隔离失败: 源文件不存在 %s", src_path)
        return None

    dest_dir = resolve_path(quarantine_dir)
    try:
        dest_dir.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        logging.error("无法创建隔离目录 %s: %s", dest_dir, e)
        return None

    name, ext = src.stem, src.suffix
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    dest = dest_dir / (f"{name}_{timestamp}{ext}" if add_timestamp else src.name)
    counter = 1
    while dest.exists():
        base = f"{name}_{timestamp}_({counter})" if add_timestamp else f"{name}_({counter})"
        dest = dest_dir / f"{base}{ext}"
        counter += 1

    try:
        shutil.move(str(src), str(dest))
        logging.info("文件已隔离: %s -> %s", src, dest)
        return str(dest)
    except OSError as e:
        logging.error("移动文件失败 %s -> %s: %s", src, dest, e)
        return None


# -------------------- 文件哈希 --------------------

def compute_file_hash(filepath: str, algorithm: str = "sha256") -> Optional[str]:
    """
    分块计算文件哈希。

    Args:
        filepath: 文件路径。
        algorithm: md5 / sha1 / sha256 / sha512 等 hashlib 支持的算法。

    Returns:
        十六进制哈希字符串；文件不存在或读取失败返回 None。
    """
    path = Path(filepath)
    if not path.is_file():
        logging.error("计算哈希失败: 文件不存在 %s", filepath)
        return None

    try:
        hasher = hashlib.new(algorithm)
    except ValueError:
        logging.error("不支持的哈希算法: %s", algorithm)
        return None

    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    except OSError as e:
        logging.error("读取文件 %s 失败: %s", filepath, e)
        return None


# -------------------- 权限与平台 --------------------

def is_admin() -> bool:
    """检查当前进程是否以管理员权限运行（仅 Windows，其余平台返回 False）。"""
    if platform.system() != "Windows":
        return False
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def get_platform_info() -> Dict[str, str]:
    """返回当前运行平台的简要信息。"""
    return {
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "python_version": sys.version.split()[0],
    }
