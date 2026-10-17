"""
config.py - 配置加载与默认配置生成
负责读取 config.yaml、校验结构，并把其中的相对路径统一解析为项目根目录下的绝对路径。

注意：config.yaml 一旦解析失败，引擎会退化为「空配置 + 内置默认值」，
因此除 load_config 外还提供 validate_config，供 CLI 与安装脚本判断配置是否真的可用。
"""

from __future__ import annotations

import logging
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

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


def _read_yaml(path: Path) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """
    读取并解析 YAML 文件。

    Returns:
        (配置字典, 错误描述)；成功时错误描述为 None，失败时配置字典为 None。
    """
    if not path.is_file():
        return None, "配置文件不存在: {}".format(path)
    try:
        # utf-8-sig：同时兼容带 BOM（PowerShell 5.1 的 Set-Content -Encoding UTF8）与不带 BOM 的 UTF-8
        with open(path, "r", encoding="utf-8-sig") as f:
            config = yaml.safe_load(f)
    except yaml.YAMLError as e:
        return None, str(e)
    except OSError as e:
        return None, "读取失败: {}".format(e)
    except UnicodeDecodeError as e:
        return None, "编码不是 UTF-8: {}".format(e)

    if not isinstance(config, dict):
        return None, "顶层不是映射结构（应形如 `yara:` / `clamav:` 的键值对）"
    return config, None


def load_config(config_path: Optional[Path] = None) -> Dict[str, Any]:
    """
    加载 YAML 配置文件。

    Args:
        config_path: 配置文件路径，默认为项目根目录下的 config.yaml。

    Returns:
        配置字典；文件不存在或解析失败时返回 {} 并记录日志
        （此时引擎会用各自的默认值，属于「降级运行」，调用方应提示用户）。
    """
    path = Path(config_path) if config_path else CONFIG_FILE
    config, err = _read_yaml(path)
    if err is not None:
        logger.error("解析 YAML 配置失败 (%s): %s", path, err)
        return {}

    logger.info("已加载配置文件: %s", path)
    return _normalize(config)  # type: ignore[arg-type]


def validate_config(config_path: Optional[Path] = None) -> Optional[str]:
    """
    校验配置文件是否可解析（不落盘、不修改）。

    Returns:
        None 表示正常；否则返回人类可读的错误描述。
    """
    path = Path(config_path) if config_path else CONFIG_FILE
    _config, err = _read_yaml(path)
    return err


def generate_default_config(config_path: Optional[Path] = None, force: bool = False) -> Path:
    """
    生成默认配置文件。优先复制 config.example.yaml，否则内置模板写入。

    Args:
        config_path: 目标路径，默认为 config.yaml。
        force: 为 True 时覆盖已存在的文件（先把原文件备份为 config.yaml.bak-<时间戳>）。

    Returns:
        生成的配置文件路径。
    """
    path = Path(config_path) if config_path else CONFIG_FILE
    if path.exists():
        if not force:
            return path
        backup = path.with_name("{}.bak-{}".format(path.name, datetime.now().strftime("%Y%m%d_%H%M%S")))
        try:
            shutil.copy2(str(path), str(backup))
            logger.warning("原配置已备份: %s", backup)
        except OSError as e:
            logger.error("备份原配置 %s 失败: %s", path, e)
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
