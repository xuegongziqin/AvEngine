"""
AvEngine - 基于 YARA、ClamAV 与 Sysmon 的多引擎杀毒引擎。

Python 外壳通过 ctypes 调用 C++ 内核 avengine_core.dll；被取代的 Python 引擎
模块（YARA/ClamAV/Sysmon/调度器/AI）已归档到项目根目录 legacy/。
"""

from __future__ import annotations

import importlib
from typing import Any

__version__ = "0.1.0"
__author__ = "AntierX"

__all__ = [
    "core_bridge",
    "load_config",
    "generate_default_config",
    "load_ai_config",
    "setup_logging",
    "quarantine_file",
    "compute_file_hash",
]

_LAZY_ATTRS = {
    "core_bridge": ".core_bridge",
    "load_config": ".config",
    "generate_default_config": ".config",
    "load_ai_config": ".aiconfig",
    "setup_logging": ".utils",
    "quarantine_file": ".utils",
    "compute_file_hash": ".utils",
}


def __getattr__(name: str) -> Any:
    module_name = _LAZY_ATTRS.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(importlib.import_module(module_name, __name__), name)
    globals()[name] = value
    return value


def __dir__() -> list:
    return sorted(set(globals()) | set(__all__))
