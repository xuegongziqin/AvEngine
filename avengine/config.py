"""
config.py - 配置加载与默认配置生成
负责读取 config.yaml、校验结构，并把其中的相对路径统一解析为项目根目录下的绝对路径。
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, Optional

import yaml

from .paths import CONFIG_EXAMPLE_FILE, CONFIG_FILE, resolve_path

logger = logging.getLogger(__name__)

DEFAULT_CONFIG: Dict[str, Any] = {
    "yara": {"rules_path": "./rules"},
    "clamav": {"host": "127.0.0.1", "port": 3310, "timeout": 30},
    "sysmon": {"channel": "Microsoft-Windows-Sysmon/Operational"},
    "quarantine": {"path": "./quarantine"},
    "scan": {
        "on_access": False,
        "timer_enabled": False,
        "timer_interval": 3600,
        "monitor_paths": ["C:\\Users\\Public", "C:\\Temp"],
    },
}


def _normalize(config: Dict[str, Any]) -> Dict[str, Any]:
    """把配置中的相对路径解析为基于项目根目录的绝对路径。"""
    yara_cfg = config.get("yara")
    if isinstance(yara_cfg, dict) and yara_cfg.get("rules_path"):
        yara_cfg["rules_path"] = str(resolve_path(yara_cfg["rules_path"]))

    q_cfg = config.get("quarantine")
    if isinstance(q_cfg, dict) and q_cfg.get("path"):
        q_cfg["path"] = str(resolve_path(q_cfg["path"]))

    scan_cfg = config.get("scan")
    if isinstance(scan_cfg, dict) and isinstance(scan_cfg.get("monitor_paths"), list):
        scan_cfg["monitor_paths"] = [str(resolve_path(p)) for p in scan_cfg["monitor_paths"]]

    return config


def load_config(config_path: Optional[Path] = None) -> Dict[str, Any]:
    """
    加载 YAML 配置文件。

    Args:
        config_path: 配置文件路径，默认为项目根目录下的 config.yaml。

    Returns:
        配置字典；文件不存在或解析失败时返回 {} 并记录日志。
    """
    path = Path(config_path) if config_path else CONFIG_FILE
    if not path.is_file():
        logger.warning("配置文件不存在: %s，使用空配置", path)
        return {}

    try:
        with open(path, "r", encoding="utf-8-sig") as f:
            config = yaml.safe_load(f)
    except yaml.YAMLError as e:
        logger.error("解析 YAML 配置失败 (%s): %s", path, e)
        return {}
    except OSError as e:
        logger.error("读取配置文件 %s 失败: %s", path, e)
        return {}

    if not isinstance(config, dict):
        logger.warning("配置文件 %s 顶层不是映射结构", path)
        return {}

    logger.info("已加载配置文件: %s", path)
    return _normalize(config)


def generate_default_config(config_path: Optional[Path] = None) -> Path:
    """
    生成默认配置文件。优先复制 config.example.yaml，否则内置模板写入。

    Args:
        config_path: 目标路径，默认为 config.yaml。

    Returns:
        生成的配置文件路径。
    """
    path = Path(config_path) if config_path else CONFIG_FILE
    if path.exists():
        return path

    try:
        if CONFIG_EXAMPLE_FILE.is_file():
            path.write_text(
                CONFIG_EXAMPLE_FILE.read_text(encoding="utf-8"), encoding="utf-8"
            )
        else:
            path.write_text(
                yaml.safe_dump(DEFAULT_CONFIG, allow_unicode=True, sort_keys=False),
                encoding="utf-8",
            )
        logger.info("已生成默认配置文件: %s", path)
    except OSError as e:
        logger.error("无法创建配置文件 %s: %s", path, e)
    return path
