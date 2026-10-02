"""
ai/config.py - AI 分析模块配置（独立 config.ini）

配置文件: 项目根目录 config.ini（模板见 config.ini.example）
分为 [ai]（端点与会话参数）与 [sources]（事件采集源开关）两段。
"""

from __future__ import annotations

import configparser
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional

from ..paths import AI_CONFIG_EXAMPLE_FILE, AI_CONFIG_FILE

# 进入每 5 分钟批次的事件源（fileio 恒不进批次，仅按需 grep/query）
BATCH_SOURCES = ("sysmon", "process", "network", "dns", "powershell", "system", "application")
# 允许 query_events / grep_events 使用的全部源
ALL_SOURCES = BATCH_SOURCES + ("fileio",)

DEFAULT_SOURCES: Dict[str, bool] = {
    "sysmon": True,
    "process": True,
    "network": True,
    "dns": True,
    "powershell": True,
    "system": True,
    "application": True,
    "fileio": True,  # 仅按需查询，不随批次发送
}


@dataclass
class AIConfig:
    """config.ini 的内存表示。"""

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
        """端点与模型是否齐全（api_key 允许为空，本地 Ollama 无密钥）。"""
        return bool(self.base_url.strip() and self.model.strip())

    @property
    def active(self) -> bool:
        return self.enabled and self.configured

    def batch_sources(self):
        return [s for s in BATCH_SOURCES if self.sources.get(s)]

    def source_enabled(self, name: str) -> bool:
        return bool(self.sources.get(name))


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
    """
    读取 config.ini；文件不存在或字段缺失时使用默认值（不抛异常）。

    Args:
        path: 配置文件路径，默认项目根目录的 config.ini。

    Returns:
        AIConfig 实例（configured/active 属性可判断可用性）。
    """
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
    else:
        cfg.sources = dict(DEFAULT_SOURCES)

    return cfg


def example_path() -> Path:
    """配置模板路径（config.ini.example）。"""
    return AI_CONFIG_EXAMPLE_FILE
