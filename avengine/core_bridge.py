"""
core_bridge.py - C++ 内核 avengine_core.dll 的 ctypes 绑定

DLL 位置查找顺序:
  1. 环境变量 AVENGINE_CORE_DLL
  2. third_party/dist/bin/avengine_core.dll   (CMake 构建产物)
  3. cpp/build/avengine_core.dll
  4. avengine/_native/avengine_core.dll

所有函数返回 Python dict（内核返回 UTF-8 JSON）；DLL 缺失时 is_available() 为 False，
load_error() 给出原因。内核报错抛 CoreError。
"""

from __future__ import annotations

import ctypes
import json
import os
from pathlib import Path
from typing import Any, Dict, Iterator, Optional

from .paths import PROJECT_ROOT

_DLL_ENV = "AVENGINE_CORE_DLL"

_lib: Optional[ctypes.CDLL] = None
_load_error: Optional[str] = None
_load_attempted = False


class CoreError(RuntimeError):
    """C++ 内核返回错误或无 DLL 时抛出。"""


def _candidate_paths() -> Iterator[Path]:
    env = os.environ.get(_DLL_ENV)
    if env:
        yield Path(env)
    yield PROJECT_ROOT / "third_party" / "dist" / "bin" / "avengine_core.dll"
    yield PROJECT_ROOT / "cpp" / "build" / "avengine_core.dll"
    yield Path(__file__).resolve().parent / "_native" / "avengine_core.dll"


def _setup(lib: ctypes.CDLL) -> None:
    lib.avc_version.restype = ctypes.c_char_p
    lib.avc_version.argtypes = []
    lib.avc_last_error.restype = ctypes.c_char_p
    lib.avc_last_error.argtypes = []
    lib.avc_free.argtypes = [ctypes.c_void_p]
    lib.avc_free.restype = None

    for name in ("avc_sha256",):
        fn = getattr(lib, name)
        fn.argtypes = [ctypes.c_char_p]
        fn.restype = ctypes.c_void_p

    for name in ("avc_scan_path", "avc_scan_dir"):
        fn = getattr(lib, name)
        fn.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
                       ctypes.c_int, ctypes.c_int]
        fn.restype = ctypes.c_void_p

    for name in ("avc_clam_version", "avc_clam_reload"):
        fn = getattr(lib, name)
        fn.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int]
        fn.restype = ctypes.c_void_p

    lib.avc_engine_status.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int, ctypes.c_int]
    lib.avc_engine_status.restype = ctypes.c_void_p

    lib.avc_monitor_start.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
                                      ctypes.c_int, ctypes.c_int, ctypes.c_char_p,
                                      ctypes.c_char_p, ctypes.c_int, ctypes.c_int]
    lib.avc_monitor_start.restype = ctypes.c_int
    lib.avc_monitor_stop.argtypes = []
    lib.avc_monitor_stop.restype = None
    lib.avc_monitor_running.argtypes = []
    lib.avc_monitor_running.restype = ctypes.c_int
    lib.avc_monitor_poll.argtypes = [ctypes.c_int]
    lib.avc_monitor_poll.restype = ctypes.c_void_p
    lib.avc_monitor_status.argtypes = []
    lib.avc_monitor_status.restype = ctypes.c_void_p

    lib.avc_ai_test.argtypes = [ctypes.c_char_p]
    lib.avc_ai_test.restype = ctypes.c_void_p
    lib.avc_ai_run_batch.argtypes = [ctypes.c_char_p, ctypes.c_int]
    lib.avc_ai_run_batch.restype = ctypes.c_void_p
    lib.avc_ai_ask.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    lib.avc_ai_ask.restype = ctypes.c_void_p
    lib.avc_ai_analyze_detection.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    lib.avc_ai_analyze_detection.restype = ctypes.c_void_p
    lib.avc_ai_start_background.argtypes = [ctypes.c_char_p]
    lib.avc_ai_start_background.restype = ctypes.c_int
    lib.avc_ai_stop_background.argtypes = []
    lib.avc_ai_stop_background.restype = None
    lib.avc_ai_background_running.argtypes = []
    lib.avc_ai_background_running.restype = ctypes.c_int
    lib.avc_ai_poll.argtypes = [ctypes.c_int]
    lib.avc_ai_poll.restype = ctypes.c_void_p


def _load() -> Optional[ctypes.CDLL]:
    global _lib, _load_error, _load_attempted
    if _load_attempted:
        return _lib
    _load_attempted = True
    for cand in _candidate_paths():
        if cand.is_file():
            try:
                lib = ctypes.CDLL(str(cand))
                _setup(lib)
                _lib = lib
                return _lib
            except OSError as e:
                _load_error = "加载 DLL 失败 {}: {}".format(cand, e)
                return None
    tried = ", ".join(str(p) for p in _candidate_paths())
    _load_error = "未找到 avengine_core.dll（先运行 cpp\\build.bat 构建，或用 AVENGINE_CORE_DLL 指定）。已尝试: " + tried
    return None


def is_available() -> bool:
    return _load() is not None


def load_error() -> Optional[str]:
    return _load_error


def _b(text: Optional[str]) -> bytes:
    return ("" if text is None else str(text)).encode("utf-8")


def _consume(ptr: Optional[int]) -> Dict[str, Any]:
    lib = _lib
    assert lib is not None
    if not ptr:
        err = lib.avc_last_error() or b"unknown error"
        raise CoreError(err.decode("utf-8", errors="replace"))
    try:
        raw = ctypes.string_at(ptr)
    finally:
        lib.avc_free(ctypes.c_void_p(ptr))
    return json.loads(raw.decode("utf-8"))


def version() -> str:
    lib = _load()
    if lib is None:
        raise CoreError(_load_error or "核心库不可用")
    v = lib.avc_version()
    return v.decode("utf-8") if v else ""


def _clam_params(clamav: Optional[Dict[str, Any]]):
    if not clamav:
        return b"", 0, 0
    host = _b(clamav.get("host", "127.0.0.1"))
    port = int(clamav.get("port", 0) or 0)
    timeout = int(clamav.get("timeout", 30) or 30)
    return host, port, timeout


def sha256(path) -> Dict[str, Any]:
    lib = _load()
    if lib is None:
        raise CoreError(_load_error or "核心库不可用")
    return _consume(lib.avc_sha256(_b(str(path))))


def scan_path(path, rules_path=None, clamav: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    lib = _load()
    if lib is None:
        raise CoreError(_load_error or "核心库不可用")
    host, port, timeout = _clam_params(clamav)
    ptr = lib.avc_scan_path(_b(str(path)), _b(rules_path), host, port, timeout)
    return _consume(ptr)


def scan_dir(path, rules_path=None, clamav: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    lib = _load()
    if lib is None:
        raise CoreError(_load_error or "核心库不可用")
    host, port, timeout = _clam_params(clamav)
    ptr = lib.avc_scan_dir(_b(str(path)), _b(rules_path), host, port, timeout)
    return _consume(ptr)


def clam_version(host: str, port: int, timeout: int = 5) -> Dict[str, Any]:
    lib = _load()
    if lib is None:
        raise CoreError(_load_error or "核心库不可用")
    return _consume(lib.avc_clam_version(_b(host), int(port), int(timeout)))


def clam_reload(host: str, port: int, timeout: int = 30) -> Dict[str, Any]:
    lib = _load()
    if lib is None:
        raise CoreError(_load_error or "核心库不可用")
    return _consume(lib.avc_clam_reload(_b(host), int(port), int(timeout)))


def engine_status(rules_path, clam_host: str, clam_port: int, clam_timeout: int = 30) -> Dict[str, Any]:
    lib = _load()
    if lib is None:
        raise CoreError(_load_error or "核心库不可用")
    return _consume(lib.avc_engine_status(_b(rules_path), _b(clam_host), int(clam_port), int(clam_timeout)))


# -------------------- 常驻实时监控 --------------------

DEFAULT_SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"


def monitor_start(rules_path=None, quarantine_dir="", clamav: Optional[Dict[str, Any]] = None,
                  channel: str = DEFAULT_SYSMON_CHANNEL, monitor_paths=(),
                  timer_interval: int = 0, on_access: bool = True) -> None:
    """启动 C++ 常驻监控；失败抛 CoreError。"""
    lib = _load()
    if lib is None:
        raise CoreError(_load_error or "核心库不可用")
    host, port, timeout = _clam_params(clamav)
    paths = ";".join(str(p) for p in monitor_paths)
    rc = lib.avc_monitor_start(
        _b(rules_path), _b(quarantine_dir), host, port, timeout,
        _b(channel), _b(paths), int(timer_interval), 1 if on_access else 0,
    )
    if rc != 0:
        err = lib.avc_last_error() or b"unknown error"
        raise CoreError(err.decode("utf-8", errors="replace"))


def monitor_stop() -> None:
    lib = _load()
    if lib is None:
        return
    lib.avc_monitor_stop()


def monitor_running() -> bool:
    lib = _load()
    if lib is None:
        return False
    return bool(lib.avc_monitor_running())


def monitor_poll(max_items: int = 100) -> list:
    """取出待处理的威胁事件列表（dict）。"""
    lib = _load()
    if lib is None:
        return []
    return _consume(lib.avc_monitor_poll(int(max_items)))


def monitor_status() -> Dict[str, Any]:
    lib = _load()
    if lib is None:
        raise CoreError(_load_error or "核心库不可用")
    return _consume(lib.avc_monitor_status())


# -------------------- AI --------------------

def _cfg_json(config: Dict[str, Any]) -> bytes:
    return json.dumps(config, ensure_ascii=False).encode("utf-8")


def ai_test(config: Dict[str, Any]) -> Dict[str, Any]:
    lib = _load()
    if lib is None:
        raise CoreError(_load_error or "核心库不可用")
    return _consume(lib.avc_ai_test(_cfg_json(config)))


def ai_run_batch(config: Dict[str, Any], minutes: int = 0) -> Dict[str, Any]:
    lib = _load()
    if lib is None:
        raise CoreError(_load_error or "核心库不可用")
    return _consume(lib.avc_ai_run_batch(_cfg_json(config), int(minutes)))


def ai_ask(config: Dict[str, Any], question: str) -> Dict[str, Any]:
    lib = _load()
    if lib is None:
        raise CoreError(_load_error or "核心库不可用")
    return _consume(lib.avc_ai_ask(_cfg_json(config), _b(question)))


def ai_analyze_detection(config: Dict[str, Any], detection: Dict[str, Any]) -> Dict[str, Any]:
    lib = _load()
    if lib is None:
        raise CoreError(_load_error or "核心库不可用")
    return _consume(lib.avc_ai_analyze_detection(_cfg_json(config), _cfg_json(detection)))


def ai_start_background(config: Dict[str, Any]) -> None:
    lib = _load()
    if lib is None:
        raise CoreError(_load_error or "核心库不可用")
    rc = lib.avc_ai_start_background(_cfg_json(config))
    if rc != 0:
        err = lib.avc_last_error() or b"unknown error"
        raise CoreError(err.decode("utf-8", errors="replace"))


def ai_stop_background() -> None:
    lib = _load()
    if lib is not None:
        lib.avc_ai_stop_background()


def ai_background_running() -> bool:
    lib = _load()
    return bool(lib and lib.avc_ai_background_running())


def ai_poll(max_items: int = 100) -> list:
    lib = _load()
    if lib is None:
        return []
    return _consume(lib.avc_ai_poll(int(max_items)))
