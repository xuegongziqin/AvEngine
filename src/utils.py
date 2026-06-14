"""
utils.py - 公共工具函数模块
提供日志设置、文件隔离、配置读取、哈希计算等通用功能。
"""

import os
import sys
import shutil
import hashlib
import logging
import platform
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

import yaml  # 需要 PyYAML: pip install pyyaml


# -------------------- 配置加载 --------------------

def load_config(config_path: str = "config.yaml") -> Dict[str, Any]:
    """
    加载 YAML 配置文件并返回字典。

    Args:
        config_path: 配置文件路径，默认为项目根目录下的 config.yaml。

    Returns:
        配置字典。若文件不存在或解析失败，返回空字典并记录警告。
    """
    if not os.path.isfile(config_path):
        logging.warning("配置文件不存在: %s，使用默认空配置", config_path)
        return {}
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f)
            if not isinstance(config, dict):
                logging.warning("配置文件 %s 内容不是字典类型", config_path)
                return {}
            logging.info("成功加载配置文件: %s", config_path)
            return config
    except yaml.YAMLError as e:
        logging.error("解析 YAML 配置失败 (%s): %s", config_path, e)
        return {}
    except Exception as e:
        logging.error("读取配置文件 %s 时出错: %s", config_path, e)
        return {}


# -------------------- 日志设置 --------------------

def setup_logging(
    log_level: int = logging.INFO,
    log_file: Optional[str] = None,
    log_format: Optional[str] = None,
) -> None:
    """
    配置全局日志记录器。

    Args:
        log_level: 日志级别（如 logging.DEBUG, logging.INFO）。
        log_file: 日志文件路径，如果提供则同时写入文件。
        log_format: 自定义日志格式，若为 None 则使用默认格式。
    """
    if log_format is None:
        log_format = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
        date_format = "%Y-%m-%d %H:%M:%S"
    else:
        date_format = None

    handlers = []

    # 控制台输出
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    console_handler.setFormatter(logging.Formatter(log_format, datefmt=date_format))
    handlers.append(console_handler)

    # 文件输出
    if log_file:
        try:
            # 确保日志目录存在
            log_dir = os.path.dirname(log_file)
            if log_dir:
                os.makedirs(log_dir, exist_ok=True)
            file_handler = logging.FileHandler(log_file, encoding="utf-8")
            file_handler.setLevel(log_level)
            file_handler.setFormatter(logging.Formatter(log_format, datefmt=date_format))
            handlers.append(file_handler)
        except Exception as e:
            logging.error("无法创建日志文件 %s: %s", log_file, e)

    # 配置根日志器
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    # 移除已有处理器，避免重复
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    for handler in handlers:
        root_logger.addHandler(handler)

    logging.info("日志系统已初始化 (级别=%s)", logging.getLevelName(log_level))
    if log_file:
        logging.info("日志文件: %s", log_file)


# -------------------- 文件隔离 --------------------

def quarantine_file(
    src_path: str,
    quarantine_dir: str,
    add_timestamp: bool = True,
) -> Optional[str]:
    """
    将可疑文件移动到隔离目录。

    若目标文件名已存在，会自动添加时间戳或序号以避免覆盖。
    移动成功后返回新路径，失败返回 None。

    Args:
        src_path: 源文件路径。
        quarantine_dir: 隔离目录路径（会自动创建）。
        add_timestamp: 是否在文件名中添加时间戳以区分重名文件。

    Returns:
        隔离后的新文件路径，或 None（移动失败）。
    """
    if not os.path.isfile(src_path):
        logging.error("隔离失败: 源文件不存在 %s", src_path)
        return None

    # 创建隔离目录
    try:
        os.makedirs(quarantine_dir, exist_ok=True)
    except OSError as e:
        logging.error("无法创建隔离目录 %s: %s", quarantine_dir, e)
        return None

    # 构造目标文件名
    original_name = os.path.basename(src_path)
    name, ext = os.path.splitext(original_name)

    if add_timestamp:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        new_name = f"{name}_{timestamp}{ext}"
    else:
        new_name = original_name

    dest_path = os.path.join(quarantine_dir, new_name)

    # 处理极端情况：目标文件已存在（即使在加时间戳的情况下也可能发生）
    counter = 1
    while os.path.exists(dest_path):
        new_name = f"{name}_{timestamp}_({counter}){ext}" if add_timestamp else f"{name}_({counter}){ext}"
        dest_path = os.path.join(quarantine_dir, new_name)
        counter += 1

    try:
        # 移动文件（跨卷移动用 shutil.move）
        shutil.move(src_path, dest_path)
        logging.info("文件已隔离: %s -> %s", src_path, dest_path)
        return dest_path
    except OSError as e:
        logging.error("移动文件失败 %s -> %s: %s", src_path, dest_path, e)
        return None


# -------------------- 文件哈希计算 --------------------

def compute_file_hash(filepath: str, algorithm: str = "sha256") -> Optional[str]:
    """
    计算文件的哈希值。

    Args:
        filepath: 文件路径。
        algorithm: 哈希算法，支持 md5, sha1, sha256, sha512。

    Returns:
        十六进制哈希字符串，或 None（如果文件不存在或读取错误）。
    """
    if not os.path.isfile(filepath):
        logging.error("计算哈希失败: 文件不存在 %s", filepath)
        return None

    try:
        hasher = hashlib.new(algorithm)
    except ValueError:
        logging.error("不支持的哈希算法: %s", algorithm)
        return None

    try:
        with open(filepath, "rb") as f:
            # 分块读取，避免大文件内存溢出
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        digest = hasher.hexdigest()
        logging.debug("文件 %s 的 %s 哈希: %s", filepath, algorithm, digest)
        return digest
    except OSError as e:
        logging.error("读取文件 %s 时出错: %s", filepath, e)
        return None


# -------------------- 权限检测 --------------------

def is_admin() -> bool:
    """
    检查当前进程是否以管理员权限运行。

    仅对 Windows 有效，非 Windows 平台总是返回 False。
    对于 Windows，通过尝试写入系统目录来判断（更简单可靠）。
    """
    if platform.system() != "Windows":
        return False
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        # 备用方案：检查是否可以写入系统目录
        test_path = os.path.join(os.environ.get("SYSTEMROOT", "C:\\Windows"), "Temp", "admin_test.tmp")
        try:
            with open(test_path, "w") as f:
                f.write("test")
            os.remove(test_path)
            return True
        except OSError:
            return False


# -------------------- 平台信息 --------------------

def get_platform_info() -> Dict[str, str]:
    """
    返回当前运行平台的简要信息。

    Returns:
        包含系统、版本、架构等字段的字典。
    """
    return {
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "python_version": sys.version,
    }


# -------------------- 通用路径处理 --------------------

def normalize_path(path: str) -> str:
    """
    将路径规范化，转换为绝对路径并统一分隔符。

    Args:
        path: 输入路径。

    Returns:
        规范化后的路径字符串。
    """
    try:
        return os.path.abspath(path)
    except Exception:
        return path


# -------------------- 模块独立测试 --------------------
if __name__ == "__main__":
    # 简单功能演示
    setup_logging(log_level=logging.DEBUG, log_file="./logs/test_utils.log")

    # 加载配置示例
    config = load_config("config.yaml")
    print("配置内容:", config)

    # 测试文件哈希
    test_file = __file__  # 自身文件
    h = compute_file_hash(test_file)
    print(f"{test_file} 的 SHA256: {h}")

    # 测试权限检测
    if platform.system() == "Windows":
        print("是否以管理员身份运行:", is_admin())

    # 测试隔离功能（请谨慎使用，此处仅打印路径）
    test_src = "./test_malware.txt"
    if os.path.exists(test_src):
        new_path = quarantine_file(test_src, "./quarantine")
        print(f"隔离后路径: {new_path}")
    else:
        print(f"测试隔离源文件 {test_src} 不存在，跳过")

    print("平台信息:", get_platform_info())