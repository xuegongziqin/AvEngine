"""
aiconfig.py - AI 配置读取（config.ini）

原 avengine/ai/config.py 的 shell 层精简版：只负责读取 config.ini 供 CLI 构造
传给 C++ 内核的配置 JSON。AI 引擎本体已迁移到 C++。
"""

from __future__ import annotations

import configparser
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional

from .paths import AI_CONFIG_FILE

# 进入批次的事件源（fileio 恒不进批次，仅按需检索）
BATCH_SOURCES = ("sysmon", "process", "network", "dns", "powershell", "system", "application")

DEFAULT_SOURCES: Dict[str, bool] = {
    "sysmon": True,
    "process": True,
    "network": True,
    "dns": True,
    "powershell": True,
    "system": True,
    "application": True,
    "fileio": True,
}


@dataclass
class AIConfig:
    path: Path = AI_CONFIG_FILE
    enabled: bool = False
    base_url: str = ""
    api_key: str = ""
    model: str = ""
    timeout: int = 60
    interval: int = 300
    max_rounds: int = 12
    max_events_per_batch: int = 200
    max_event_chars: int = 600
    max_tool_result_chars: int = 12000
    scan_analysis: bool = True
    sources: Dict[str, bool] = field(default_factory=lambda: dict(DEFAULT_SOURCES))

    @property
    def exists(self) -> bool:
        return self.path.is_file()

    @property
    def configured(self) -> bool:
        return bool(self.base_url.strip() and self.model.strip())

    @property
    def active(self) -> bool:
        return self.enabled and self.configured

    def batch_sources(self):
        return [s for s in BATCH_SOURCES if self.sources.get(s)]


def _getbool(parser: configparser.ConfigParser, section: str, key: str, default: bool) -> bool:
    if not parser.has_option(section, key):
        return default
    try:
        return parser.getboolean(section, key)
    except ValueError:
        return default


def _getint(parser: configparser.ConfigParser, section: str, key: str, default: int) -> int:
    if not parser.has_option(section, key):
        return default
    try:
        return parser.getint(section, key)
    except ValueError:
        return default


def load_ai_config(path: Optional[Path] = None) -> AIConfig:
    """读取 config.ini；缺失或字段错误时使用默认值（不抛异常）。"""
    cfg_path = Path(path) if path else AI_CONFIG_FILE
    cfg = AIConfig(path=cfg_path)

    parser = configparser.ConfigParser(interpolation=None)
    try:
        parser.read(cfg_path, encoding="utf-8-sig")
    except configparser.Error:
        return cfg

    if parser.has_section("ai"):
        cfg.enabled = _getbool(parser, "ai", "enabled", False)
        cfg.base_url = parser.get("ai", "base_url", fallback="").strip()
        cfg.api_key = parser.get("ai", "api_key", fallback="").strip()
        cfg.model = parser.get("ai", "model", fallback="").strip()
        cfg.timeout = max(5, _getint(parser, "ai", "timeout", 60))
        cfg.interval = max(60, _getint(parser, "ai", "interval", 300))
        cfg.max_rounds = max(1, min(50, _getint(parser, "ai", "max_rounds", 12)))
        cfg.max_events_per_batch = max(10, _getint(parser, "ai", "max_events_per_batch", 200))
        cfg.max_event_chars = max(120, _getint(parser, "ai", "max_event_chars", 600))
        cfg.max_tool_result_chars = max(1000, _getint(parser, "ai", "max_tool_result_chars", 12000))
        cfg.scan_analysis = _getbool(parser, "ai", "scan_analysis", True)

    if parser.has_section("sources"):
        for name in DEFAULT_SOURCES:
            cfg.sources[name] = _getbool(parser, "sources", name, DEFAULT_SOURCES[name])

    return cfg
