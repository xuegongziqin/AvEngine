"""
ai/tools.py - AI 可调用的工具库（AvEngine 能力集合）

七类工具：进程 / 文件 / 网络 / 系统 / 事件 / 处置 / 情报。
每个工具由 ToolSpec 描述（JSON Schema + 执行函数），execute() 统一分发、
参数类型转换、异常捕获与结果截断，保证回传给 AI 的永远是可读文本。

危险操作（隔离/杀进程等）按用户策略全自动执行；仅对系统进程（PID<=4）保留护栏。
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import logging
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, List

from ..paths import AI_DUMP_DIR, LOG_FILE, PROJECT_ROOT, resolve_path
from .collectors import get_event_xml, query_for_tools, supported as events_supported
from .config import AIConfig

logger = logging.getLogger(__name__)

_JSON_KW = dict(ensure_ascii=False, separators=(",", ":"))


# -------------------- 上下文与注册表 --------------------

@dataclass
class ToolContext:
    """工具执行上下文（引擎配置 + AI 配置 + 引擎实例缓存）。"""

    engine_config: Dict
    ai_config: AIConfig
    _yara: object = field(default=None, repr=False)
    _clam: object = field(default=None, repr=False)


@dataclass
class ToolSpec:
    name: str
    category: str
    description: str
    properties: Dict[str, Dict]
    func: Callable[[Dict, ToolContext], str]
    required: List[str] = field(default_factory=list)

    def schema(self) -> Dict:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": self.properties,
                    "required": self.required,
                },
            },
        }


TOOLS: Dict[str, ToolSpec] = {}


def register(spec: ToolSpec) -> None:
    TOOLS[spec.name] = spec


def schemas_for_api() -> List[Dict]:
    return [spec.schema() for spec in TOOLS.values()]


def coerce_args(spec: ToolSpec, raw: Dict) -> Dict:
    """按 schema 把参数转换为正确类型；缺 required 抛 ValueError。"""
    args: Dict = {}
    for key, value in (raw or {}).items():
        if key.startswith("_"):
            continue
        prop = spec.properties.get(key)
        if prop is None:
            continue
        ptype = prop.get("type", "string")
        try:
            if ptype == "integer":
                args[key] = int(float(value))
            elif ptype == "number":
                args[key] = float(value)
            elif ptype == "boolean":
                if isinstance(value, bool):
                    args[key] = value
                else:
                    args[key] = str(value).strip().lower() in ("true", "1", "yes", "y", "on")
            else:
                args[key] = str(value)
        except (TypeError, ValueError):
            raise ValueError(f"参数 {key}={value!r} 不是有效的 {ptype}")
    missing = [k for k in spec.required if k not in args]
    if missing:
        raise ValueError(f"缺少必需参数: {', '.join(missing)}")
    return args


def execute(name: str, raw_args: Dict, ctx: ToolContext) -> str:
    """
    执行一个工具调用；任何异常都转换为 ERROR 文本回传给 AI。
    """
    spec = TOOLS.get(name)
    if not spec:
        available = ", ".join(sorted(TOOLS))
        return f"ERROR: 未知工具 {name!r}。可用工具: {available}"
    try:
        args = coerce_args(spec, raw_args)
        logger.info("AI 工具调用: %s(%s)", name, json.dumps(args, **_JSON_KW))
        result = spec.func(args, ctx)
    except ValueError as e:
        return f"ERROR: {e}"
    except Exception as e:
        logger.exception("工具 %s 执行失败", name)
        return f"ERROR: {type(e).__name__}: {e}"

    limit = ctx.ai_config.max_tool_result_chars
    if len(result) > limit:
        result = (
            result[:limit]
            + f"\n...[结果被截断: 原长 {len(result)} 字符。请收窄参数（更小的 limit/范围）后重试]"
        )
    return result


# -------------------- 通用助手 --------------------

def _psutil():
    try:
        import psutil

        return psutil
    except ImportError:
        return None


def _ok_json(data) -> str:
    return json.dumps(data, **_JSON_KW)


def _err(msg: str) -> str:
    return f"ERROR: {msg}"


def _norm_path(path: str) -> Path:
    return Path(str(path)).expanduser()


# -------------------- 进程类 --------------------

def _list_processes(args: Dict, ctx: ToolContext) -> str:
    psutil = _psutil()
    if not psutil:
        return _err("psutil 未安装（pip install psutil）")
    keyword = str(args.get("keyword", "")).lower()
    limit = min(int(args.get("limit", 50)), 500)

    rows = []
    for proc in psutil.process_iter(["pid", "name", "exe", "username", "memory_info", "create_time"]):
        try:
            info = proc.info
            name = info.get("name") or ""
            exe = info.get("exe") or ""
            if keyword and keyword not in name.lower() and keyword not in exe.lower():
                continue
            mem = info.get("memory_info")
            rows.append(
                {
                    "pid": info.get("pid"),
                    "name": name,
                    "user": (info.get("username") or "").split("\\")[-1],
                    "exe": exe,
                    "rss_mb": round(mem.rss / 1048576, 1) if mem else None,
                    "started": datetime.fromtimestamp(info["create_time"]).strftime("%m-%d %H:%M:%S")
                    if info.get("create_time")
                    else None,
                }
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    total = len(rows)
    rows.sort(key=lambda r: (r["rss_mb"] or 0), reverse=True)
    rows = rows[:limit]
    return _ok_json({"total": total, "returned": len(rows), "processes": rows})


def _get_process_info(args: Dict, ctx: ToolContext) -> str:
    psutil = _psutil()
    if not psutil:
        return _err("psutil 未安装（pip install psutil）")
    pid = int(args["pid"])
    try:
        proc = psutil.Process(pid)
        info = proc.as_dict(
            attrs=[
                "pid", "name", "exe", "cmdline", "username", "create_time",
                "ppid", "num_threads", "memory_info", "cpu_percent", "cwd", "status",
            ]
        )
    except psutil.NoSuchProcess:
        return _err(f"进程 PID={pid} 不存在")
    except psutil.AccessDenied:
        return _err(f"拒绝访问 PID={pid}（可能需要管理员权限）")

    parent_name = ""
    try:
        parent_name = proc.parent().name()
    except Exception:
        pass

    exe = info.get("exe") or ""
    exe_hash = None
    if exe and Path(exe).is_file():
        try:
            size = Path(exe).stat().st_size
            if size <= 256 * 1048576:
                exe_hash = _file_hashes(exe, ["sha256"])["sha256"]
        except OSError:
            pass

    data = {
        "pid": info.get("pid"),
        "name": info.get("name"),
        "status": info.get("status"),
        "exe": exe,
        "exe_sha256": exe_hash,
        "cmdline": " ".join(info.get("cmdline") or []),
        "user": info.get("username"),
        "cwd": info.get("cwd") or "",
        "parent": {"pid": info.get("ppid"), "name": parent_name},
        "started": datetime.fromtimestamp(info["create_time"]).isoformat(sep=" ", timespec="seconds")
        if info.get("create_time")
        else None,
        "threads": info.get("num_threads"),
        "rss_mb": round(info["memory_info"].rss / 1048576, 1) if info.get("memory_info") else None,
    }
    return _ok_json(data)


def _list_process_modules(args: Dict, ctx: ToolContext) -> str:
    psutil = _psutil()
    if not psutil:
        return _err("psutil 未安装（pip install psutil）")
    pid = int(args["pid"])
    limit = min(int(args.get("limit", 200)), 1000)
    try:
        maps = psutil.Process(pid).memory_maps()
    except psutil.NoSuchProcess:
        return _err(f"进程 PID={pid} 不存在")
    except psutil.AccessDenied:
        return _err(f"拒绝访问 PID={pid}（可能需要管理员权限）")

    seen = []
    paths_seen = set()
    for entry in maps:
        path = getattr(entry, "path", "") or ""
        if not path or path in paths_seen:
            continue
        paths_seen.add(path)
        seen.append(path)
        if len(seen) >= limit:
            break
    return _ok_json({"pid": pid, "modules_returned": len(seen), "modules": seen})


def _dump_memory(args: Dict, ctx: ToolContext) -> str:
    """DUMP_MEMORY: 把进程可读内存区域写入 logs/ai_dumps/。"""
    import ctypes
    from ctypes import wintypes

    pid = int(args["pid"])
    max_mb = max(1, min(int(args.get("max_mb", 64)), 512))

    if pid <= 4:
        return _err(f"PID={pid} 是系统保护进程，禁止转储")

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.VirtualQueryEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
    kernel32.VirtualQueryEx.restype = ctypes.c_size_t
    kernel32.ReadProcessMemory.argtypes = [
        wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t),
    ]
    kernel32.ReadProcessMemory.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

    PROCESS_VM_READ = 0x0010
    PROCESS_QUERY_INFORMATION = 0x0400
    MEM_COMMIT = 0x1000

    handle = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    if not handle:
        err = ctypes.get_last_error()
        if err == 5:
            return _err(f"拒绝访问 PID={pid}（需要管理员权限，或目标为受保护进程）")
        return _err(f"OpenProcess 失败 (错误 {err})：进程可能已退出")

    class MBI(ctypes.Structure):
        _fields_ = [
            ("BaseAddress", ctypes.c_void_p),
            ("AllocationBase", ctypes.c_void_p),
            ("AllocationProtect", ctypes.c_uint32),
            ("RegionSize", ctypes.c_size_t),
            ("State", ctypes.c_uint32),
            ("Protect", ctypes.c_uint32),
            ("Type", ctypes.c_uint32),
        ]

    readable_protects = {0x02, 0x04, 0x08, 0x20, 0x40, 0x80}  # READONLY/READWRITE/WRITECOPY + EXECUTE 组合
    max_bytes = max_mb * 1048576
    AI_DUMP_DIR.mkdir(parents=True, exist_ok=True)
    out_path = AI_DUMP_DIR / f"pid{pid}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.bin"

    written = 0
    regions_read = 0
    regions_skipped = 0
    addr = 0
    buffer = ctypes.create_string_buffer(1048576)

    try:
        with open(out_path, "wb") as out:
            while addr < 0x00007FFFFFF00000 and written < max_bytes:
                mbi = MBI()
                got = kernel32.VirtualQueryEx(handle, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi))
                if not got:
                    break
                if mbi.State == MEM_COMMIT and (mbi.Protect & 0xFF) in readable_protects and not (
                    mbi.Protect & 0x100
                ):
                    region_base = mbi.BaseAddress or 0
                    region_size = int(mbi.RegionSize)
                    offset = 0
                    while offset < region_size and written < max_bytes:
                        chunk = min(1048576, region_size - offset)
                        read = ctypes.c_size_t(0)
                        ok = kernel32.ReadProcessMemory(
                            handle,
                            ctypes.c_void_p(region_base + offset),
                            buffer,
                            chunk,
                            ctypes.byref(read),
                        )
                        if ok and read.value:
                            out.write(buffer.raw[: read.value])
                            written += read.value
                        offset += chunk
                    regions_read += 1
                else:
                    regions_skipped += 1
                next_addr = (mbi.BaseAddress or 0) + int(mbi.RegionSize)
                if next_addr <= addr:
                    break
                addr = next_addr
    finally:
        kernel32.CloseHandle(handle)

    if written == 0:
        try:
            out_path.unlink()
        except OSError:
            pass
        return _err("没有读取到任何内存区域（进程可能已退出或全部区域不可读）")

    return _ok_json(
        {
            "path": str(out_path),
            "bytes_written": written,
            "size_mb": round(written / 1048576, 2),
            "truncated": written >= max_bytes,
            "regions_read": regions_read,
            "regions_skipped": regions_skipped,
            "next_hint": "用 extract_strings 工具从该文件提取可打印字符串进一步分析",
        }
    )


# -------------------- 文件类 --------------------

def _file_hashes(path: str, algos: List[str]) -> Dict[str, str]:
    result: Dict[str, str] = {}
    hashers = []
    for name in algos:
        name = name.strip().lower()
        if not name:
            continue
        try:
            hashers.append((name, hashlib.new(name)))
        except ValueError:
            continue
    if not hashers:
        hashers = [("sha256", hashlib.new("sha256"))]
    with open(path, "rb") as f:
        while True:
            chunk = f.read(1048576)
            if not chunk:
                break
            for _, h in hashers:
                h.update(chunk)
    for name, h in hashers:
        result[name] = h.hexdigest()
    return result


def _file_hash(args: Dict, ctx: ToolContext) -> str:
    path = _norm_path(args["path"])
    if not path.is_file():
        return _err(f"文件不存在: {path}")
    algos = [a for a in str(args.get("algos", "sha256")).split(",") if a.strip()]
    data = _file_hashes(str(path), algos)
    data["path"] = str(path)
    data["size"] = path.stat().st_size
    return _ok_json(data)


def _read_file_text(args: Dict, ctx: ToolContext) -> str:
    path = _norm_path(args["path"])
    if not path.is_file():
        return _err(f"文件不存在: {path}")
    offset = max(0, int(args.get("offset", 0)))
    length = max(1, min(int(args.get("length", 4096)), 65536))
    try:
        with open(path, "rb") as f:
            f.seek(offset)
            chunk = f.read(length)
    except OSError as e:
        return _err(f"读取失败: {e}")
    try:
        text = chunk.decode("utf-8")
        encoding = "utf-8"
    except UnicodeDecodeError:
        text = chunk.decode("gbk", errors="replace")
        encoding = "gbk/replaced"
    truncated = "..." if len(chunk) == length else ""
    return f"[path={path} offset={offset} encoding={encoding}]\n{text}{truncated}"


def _scan_file(args: Dict, ctx: ToolContext) -> str:
    path = _norm_path(args["path"])
    if not path.is_file():
        return _err(f"文件不存在: {path}")

    engine = ctx.engine_config
    if ctx._yara is None:
        try:
            from ..yara_scanner import YaraScanner

            ctx._yara = YaraScanner(rules_path=engine.get("yara", {}).get("rules_path"))
        except Exception as e:
            ctx._yara = False
            logger.warning("YARA 初始化失败: %s", e)
    if ctx._clam is None:
        try:
            from ..clamav_scanner import ClamavScanner

            clam_cfg = engine.get("clamav", {})
            ctx._clam = ClamavScanner(
                host=clam_cfg.get("host", "127.0.0.1"),
                port=clam_cfg.get("port", 3310),
                timeout=clam_cfg.get("timeout", 30),
            )
        except Exception as e:
            ctx._clam = False
            logger.warning("ClamAV 初始化失败: %s", e)

    yara_hits: List[str] = []
    yara_state = "unavailable"
    if ctx._yara and ctx._yara.is_available:
        yara_state = "ok"
        try:
            yara_hits = ctx._yara.scan_file(path) or []
        except Exception as e:
            yara_state = f"error: {e}"

    clam_result = None
    clam_state = "unavailable"
    if ctx._clam and ctx._clam.is_available:
        clam_state = "ok"
        try:
            clam_result = ctx._clam.scan_file(path)
        except Exception as e:
            clam_state = f"error: {e}"

    return _ok_json(
        {
            "path": str(path),
            "yara": {"state": yara_state, "matches": yara_hits},
            "clamav": {"state": clam_state, "virus": clam_result},
            "verdict": "infected" if (yara_hits or clam_result) else "clean",
        }
    )


def _get_pe_info(args: Dict, ctx: ToolContext) -> str:
    path = _norm_path(args["path"])
    if not path.is_file():
        return _err(f"文件不存在: {path}")
    try:
        import pefile
    except ImportError:
        return _err("pefile 未安装（pip install pefile）")
    try:
        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
        )
    except pefile.PEFormatError as e:
        return _err(f"不是有效的 PE 文件: {e}")
    except OSError as e:
        return _err(f"读取失败: {e}")

    try:
        header = pe.FILE_HEADER
        optional = pe.OPTIONAL_HEADER
        imports = []
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT[:40]:
                dll = entry.dll.decode(errors="replace") if entry.dll else "?"
                funcs = [
                    (imp.name.decode(errors="replace") if imp.name else f"#{imp.ordinal}")
                    for imp in entry.imports[:15]
                ]
                imports.append({"dll": dll, "functions": funcs})
        data = {
            "path": str(path),
            "machine": hex(header.Machine),
            "is_64bit": optional.Magic == 0x20B,
            "entry_point": hex(optional.AddressOfEntryPoint),
            "image_base": hex(optional.ImageBase),
            "compile_time": datetime.fromtimestamp(header.TimeDateStamp).isoformat(sep=" ", timespec="seconds"),
            "subsystem": optional.Subsystem,
            "sections": [
                {
                    "name": s.Name.decode(errors="replace").strip("\x00"),
                    "virtual_size": s.Misc_VirtualSize,
                    "raw_size": s.SizeOfRawData,
                }
                for s in pe.sections[:20]
            ],
            "imports": imports,
        }
        return _ok_json(data)
    finally:
        pe.close()


def _extract_strings(args: Dict, ctx: ToolContext) -> str:
    path = _norm_path(args["path"])
    if not path.is_file():
        return _err(f"文件不存在: {path}")
    min_length = max(3, min(int(args.get("min_length", 5)), 32))
    max_bytes = max(1024, min(int(args.get("max_bytes", 1048576)), 64 * 1048576))
    limit = min(int(args.get("limit", 200)), 1000)

    try:
        with open(path, "rb") as f:
            blob = f.read(max_bytes)
    except OSError as e:
        return _err(f"读取失败: {e}")

    ascii_re = re.compile(rb"[\x20-\x7e]{%d,}" % min_length)
    utf16_re = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_length)

    ascii_hits = [m.group().decode("ascii") for m in ascii_re.finditer(blob)]
    utf16_hits = [m.group().decode("utf-16-le", errors="ignore") for m in utf16_re.finditer(blob)]
    merged: List[str] = []
    seen = set()
    for item in ascii_hits + utf16_hits:
        if item not in seen:
            seen.add(item)
            merged.append(item)

    return _ok_json(
        {
            "path": str(path),
            "scanned_bytes": len(blob),
            "total_strings": len(merged),
            "strings": merged[:limit],
        }
    )


# -------------------- 网络类 --------------------

def _list_connections(args: Dict, ctx: ToolContext) -> str:
    psutil = _psutil()
    if not psutil:
        return _err("psutil 未安装（pip install psutil）")
    pid = args.get("pid")
    state = str(args.get("state", "")).upper()
    limit = min(int(args.get("limit", 100)), 500)

    try:
        conns = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        return _err("拒绝访问连接表（需要管理员权限）")

    name_cache: Dict[int, str] = {}
    rows = []
    for c in conns:
        if pid is not None and c.pid != int(pid):
            continue
        if state and (c.status or "").upper() != state:
            continue
        if c.pid is not None and c.pid not in name_cache:
            try:
                name_cache[c.pid] = psutil.Process(c.pid).name()
            except Exception:
                name_cache[c.pid] = ""
        row = {
            "pid": c.pid,
            "process": name_cache.get(c.pid, ""),
            "laddr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
            "raddr": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "",
            "status": c.status,
        }
        rows.append(row)
        if len(rows) >= limit:
            break
    return _ok_json({"returned": len(rows), "connections": rows})


def _network_stats(args: Dict, ctx: ToolContext) -> str:
    psutil = _psutil()
    if not psutil:
        return _err("psutil 未安装（pip install psutil）")
    counters = psutil.net_io_counters(pernic=True)
    data = {
        name: {"sent_mb": round(c.bytes_sent / 1048576, 2), "recv_mb": round(c.bytes_recv / 1048576, 2)}
        for name, c in list(counters.items())[:30]
    }
    total = psutil.net_io_counters()
    data["_total"] = {
        "sent_mb": round(total.bytes_sent / 1048576, 2),
        "recv_mb": round(total.bytes_recv / 1048576, 2),
        "errin": total.errin,
        "errout": total.errout,
    }
    return _ok_json(data)


# -------------------- 系统类 --------------------

def _list_services(args: Dict, ctx: ToolContext) -> str:
    state_filter = str(args.get("state", "all")).lower()
    limit = min(int(args.get("limit", 200)), 1000)
    try:
        proc = subprocess.run(
            ["sc", "query", "type=", "service", "state=", "all"],
            capture_output=True, timeout=30,
        )
    except Exception as e:
        return _err(f"sc 查询失败: {e}")
    text = proc.stdout.decode("gbk", errors="replace")

    state_names = {
        "1": "STOPPED", "2": "START_PENDING", "3": "STOP_PENDING",
        "4": "RUNNING", "5": "CONTINUE_PENDING", "6": "PAUSE_PENDING", "7": "PAUSED",
    }
    services: List[Dict] = []
    current: Dict = {}
    for line in text.splitlines():
        line = line.strip()
        if line.upper().startswith("SERVICE_NAME:"):
            if current.get("name"):
                services.append(current)
            current = {"name": line.split(":", 1)[1].strip(), "display": "", "state": ""}
        elif line.upper().startswith("DISPLAY_NAME:") and current is not None:
            current["display"] = line.split(":", 1)[1].strip()
        elif line.upper().startswith("STATE") and current is not None:
            raw = line.split(":", 1)[1].strip()
            code = raw.split()[0] if raw else ""
            current["state"] = state_names.get(code, raw)
    if current.get("name"):
        services.append(current)

    if state_filter in ("running", "stopped"):
        services = [s for s in services if s.get("state", "").startswith(state_filter.upper()[:4])]
    total = len(services)
    return _ok_json({"total": total, "returned": len(services[:limit]), "services": services[:limit]})


def _read_registry(args: Dict, ctx: ToolContext) -> str:
    try:
        import winreg
    except ImportError:
        return _err("仅 Windows 支持注册表读取")

    roots = {
        "HKLM": winreg.HKEY_LOCAL_MACHINE, "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE,
        "HKCU": winreg.HKEY_CURRENT_USER, "HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER,
        "HKCR": winreg.HKEY_CLASSES_ROOT, "HKEY_CLASSES_ROOT": winreg.HKEY_CLASSES_ROOT,
        "HKU": winreg.HKEY_USERS, "HKEY_USERS": winreg.HKEY_USERS,
    }
    key_path = str(args["key"]).replace("/", "\\")
    parts = key_path.split("\\")
    root = roots.get(parts[0].upper())
    if root is None:
        return _err(f"无效的根键 {parts[0]!r}，可用: HKLM/HKCU/HKCR/HKU")
    subkey = "\\".join(parts[1:])
    value_name = args.get("value_name")

    try:
        key = winreg.OpenKey(root, subkey, 0, winreg.KEY_READ)
    except OSError as e:
        return _err(f"打开注册表键失败: {e}")

    try:
        if value_name:
            value, vtype = winreg.QueryValueEx(key, str(value_name))
            text = str(value)
            if len(text) > 5000:
                text = text[:5000] + "..."
            return _ok_json({"key": key_path, "value_name": value_name, "type": vtype, "data": text})
        values = []
        for i in range(200):
            try:
                name, value, vtype = winreg.EnumValue(key, i)
            except OSError:
                break
            text = str(value)
            if len(text) > 300:
                text = text[:300] + "..."
            values.append({"name": name, "type": vtype, "data": text})
        return _ok_json({"key": key_path, "count": len(values), "values": values})
    finally:
        winreg.CloseKey(key)


def _list_scheduled_tasks(args: Dict, ctx: ToolContext) -> str:
    keyword = str(args.get("keyword", "")).lower()
    limit = min(int(args.get("limit", 200)), 1000)
    try:
        proc = subprocess.run(
            ["schtasks", "/query", "/fo", "CSV", "/nh"],
            capture_output=True, timeout=30,
        )
    except Exception as e:
        return _err(f"schtasks 查询失败: {e}")
    text = proc.stdout.decode("gbk", errors="replace")

    tasks = []
    reader = csv.reader(io.StringIO(text))
    for row in reader:
        if not row:
            continue
        name = row[0].strip().lstrip("\\")
        if not name or name.upper().startswith("INFO"):
            continue
        if keyword and keyword not in name.lower():
            continue
        tasks.append(name)
        if len(tasks) >= limit:
            break
    return _ok_json({"returned": len(tasks), "tasks": tasks})


def _list_installed_programs(args: Dict, ctx: ToolContext) -> str:
    try:
        import winreg
    except ImportError:
        return _err("仅 Windows 支持读取已安装程序")
    keyword = str(args.get("keyword", "")).lower()
    limit = min(int(args.get("limit", 200)), 1000)

    locations = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]
    programs: List[Dict] = []
    for root, subkey in locations:
        try:
            parent = winreg.OpenKey(root, subkey, 0, winreg.KEY_READ)
        except OSError:
            continue
        try:
            for i in range(1000):
                try:
                    sub = winreg.EnumKey(parent, i)
                except OSError:
                    break
                try:
                    key = winreg.OpenKey(parent, sub, 0, winreg.KEY_READ)
                    display, _ = winreg.QueryValueEx(key, "DisplayName")
                    version, _ = winreg.QueryValueEx(key, "DisplayVersion")
                    publisher, _ = winreg.QueryValueEx(key, "Publisher")
                    winreg.CloseKey(key)
                except OSError:
                    continue
                if keyword and keyword not in str(display).lower():
                    continue
                programs.append(
                    {"name": str(display), "version": str(version), "publisher": str(publisher)}
                )
                if len(programs) >= limit:
                    break
        finally:
            winreg.CloseKey(parent)
        if len(programs) >= limit:
            break
    return _ok_json({"returned": len(programs), "programs": programs})


# -------------------- 事件类 --------------------

def _query_events(args: Dict, ctx: ToolContext) -> str:
    if not events_supported():
        return _err("事件查询不可用：需要 Windows + pywin32")
    source = str(args["source"]).lower()
    hours = float(args.get("hours", 1))
    keyword = args.get("keyword")
    limit = min(int(args.get("limit", 50)), 500)
    text, err = query_for_tools(source, hours=hours, limit=limit, keyword=keyword)
    out = text
    if err:
        out = f"{err}\n---\n{text}"
    return out


def _grep_events(args: Dict, ctx: ToolContext) -> str:
    if not events_supported():
        return _err("事件查询不可用：需要 Windows + pywin32")
    source = str(args["source"]).lower()
    keyword = str(args["keyword"])
    hours = float(args.get("hours", 24))
    limit = min(int(args.get("limit", 100)), 500)
    if source == "fileio":
        hint = (
            "提示: fileio 为按需检索源（不随批次发送）。"
            "若通道未启用请用管理员执行: wevtutil sl \"Microsoft-Windows-Kernel-File/Operational\" /e:true"
        )
    else:
        hint = ""
    text, err = query_for_tools(source, hours=hours, limit=limit, keyword=keyword)
    out = text
    if err:
        out = f"{err}\n---\n{text}"
    if hint:
        out = f"{hint}\n---\n{out}"
    return out


def _get_event_xml(args: Dict, ctx: ToolContext) -> str:
    source = str(args["source"]).lower()
    record_id = int(args["record_id"])
    xml_str, err = get_event_xml(source, record_id)
    if err:
        return _err(err)
    if len(xml_str) > 20000:
        xml_str = xml_str[:20000] + "\n...[XML 被截断]"
    return xml_str


# -------------------- 处置类 --------------------

def _sidecar_path(quarantined: Path) -> Path:
    return Path(str(quarantined) + ".ai.json")


def _quarantine_file(args: Dict, ctx: ToolContext) -> str:
    from ..utils import quarantine_file

    path = _norm_path(args["path"])
    if not path.is_file():
        return _err(f"文件不存在: {path}")
    q_dir = ctx.engine_config.get("quarantine", {}).get("path", "./quarantine")
    reason = str(args.get("reason", ""))
    new_path = quarantine_file(str(path), q_dir)
    if not new_path:
        return _err("隔离失败（详见日志）")
    new_file = Path(new_path)
    try:
        import json as _json

        _sidecar_path(new_file).write_text(
            _json.dumps(
                {
                    "original": str(path),
                    "quarantined_at": datetime.now().isoformat(timespec="seconds"),
                    "source": "ai",
                    "reason": reason,
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
    except OSError:
        pass
    return _ok_json({"quarantined_to": str(new_file), "original": str(path), "reason": reason})


def _restore_file(args: Dict, ctx: ToolContext) -> str:
    import shutil

    quarantined = _norm_path(args["quarantined_path"])
    if not quarantined.is_file():
        return _err(f"隔离文件不存在: {quarantined}")

    original = args.get("original_path")
    meta_file = _sidecar_path(quarantined)
    if not original and meta_file.is_file():
        try:
            import json as _json

            original = _json.loads(meta_file.read_text(encoding="utf-8")).get("original")
        except Exception:
            original = None
    if not original:
        return _err("缺少 original_path（该文件也没有隔离元数据）")

    dest = Path(str(original))
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        stem, suffix, parent = dest.stem, dest.suffix, dest.parent
        counter = 1
        while dest.exists():
            dest = parent / f"{stem}_({counter}){suffix}"
            counter += 1
    try:
        shutil.move(str(quarantined), str(dest))
        if meta_file.is_file():
            meta_file.unlink()
    except OSError as e:
        return _err(f"恢复失败: {e}")
    return _ok_json({"restored_to": str(dest)})


def _kill_process(args: Dict, ctx: ToolContext) -> str:
    psutil = _psutil()
    if not psutil:
        return _err("psutil 未安装（pip install psutil）")
    pid = int(args["pid"])
    force = bool(args.get("force", True))
    if pid <= 4:
        return _err(f"PID={pid} 是系统保护进程，禁止终止")
    try:
        proc = psutil.Process(pid)
        name = proc.name()
        if force:
            proc.kill()
        else:
            proc.terminate()
        try:
            proc.wait(timeout=5)
            outcome = "killed" if force else "terminated"
        except psutil.TimeoutExpired:
            outcome = "signal_sent_but_still_running"
    except psutil.NoSuchProcess:
        return _ok_json({"pid": pid, "outcome": "already_exited"})
    except psutil.AccessDenied:
        return _err(f"拒绝操作 PID={pid}（需要管理员权限）")
    return _ok_json({"pid": pid, "name": name, "outcome": outcome, "force": force})


# -------------------- 情报类 --------------------

def _read_engine_log(args: Dict, ctx: ToolContext) -> str:
    tail = max(1, min(int(args.get("tail", 100)), 1000))
    keyword = str(args.get("keyword", "")).lower()
    if not LOG_FILE.is_file():
        return _err(f"日志文件不存在: {LOG_FILE}")
    try:
        from collections import deque

        with open(LOG_FILE, "r", encoding="utf-8", errors="replace") as f:
            lines = deque(f, maxlen=tail * 4 if keyword else tail)
    except OSError as e:
        return _err(f"读取日志失败: {e}")
    selected = list(lines)
    if keyword:
        selected = [ln for ln in lines if keyword in ln.lower()][-tail:]
    else:
        selected = selected[-tail:]
    if not selected:
        return f"（日志中没有匹配的行，log={LOG_FILE}）"
    return f"[{LOG_FILE} 尾部 {len(selected)} 行]\n" + "".join(selected)


def _list_quarantine(args: Dict, ctx: ToolContext) -> str:
    q_dir = resolve_path(ctx.engine_config.get("quarantine", {}).get("path", "./quarantine"))
    if not q_dir.is_dir():
        return _ok_json({"path": str(q_dir), "exists": False, "files": []})
    import json as _json

    files = []
    for item in sorted(q_dir.iterdir()):
        if item.name.endswith(".ai.json"):
            continue
        entry = {
            "name": item.name,
            "size": item.stat().st_size if item.is_file() else None,
            "original": None,
        }
        meta = _sidecar_path(item)
        if meta.is_file():
            try:
                entry["original"] = _json.loads(meta.read_text(encoding="utf-8")).get("original")
            except Exception:
                pass
        files.append(entry)
        if len(files) >= 200:
            break
    return _ok_json({"path": str(q_dir), "exists": True, "count": len(files), "files": files})


def _get_engine_status(args: Dict, ctx: ToolContext) -> str:
    data: Dict = {"time": datetime.now().isoformat(timespec="seconds")}

    if ctx._yara is None:
        try:
            from ..yara_scanner import YaraScanner

            ctx._yara = YaraScanner(rules_path=ctx.engine_config.get("yara", {}).get("rules_path"))
        except Exception as e:
            ctx._yara = False
            data["yara"] = f"init error: {e}"
    if ctx._yara and not isinstance(data.get("yara"), str):
        data["yara"] = {
            "available": ctx._yara.is_available,
            "rules_count": ctx._yara.rules_count,
            "skipped": ctx._yara.skipped_count,
        }

    if ctx._clam is None:
        try:
            from ..clamav_scanner import ClamavScanner

            clam_cfg = ctx.engine_config.get("clamav", {})
            ctx._clam = ClamavScanner(
                host=clam_cfg.get("host", "127.0.0.1"),
                port=clam_cfg.get("port", 3310),
                timeout=clam_cfg.get("timeout", 30),
            )
        except Exception as e:
            ctx._clam = False
            data["clamav"] = f"init error: {e}"
    if ctx._clam and not isinstance(data.get("clamav"), str):
        data["clamav"] = {
            "available": ctx._clam.is_available,
            "version": ctx._clam.get_version() if ctx._clam.is_available else None,
        }

    try:
        from .. import sysmon_monitor

        data["sysmon"] = {
            "supported": sysmon_monitor.is_supported(),
            "installed": sysmon_monitor.is_installed(),
        }
    except Exception as e:
        data["sysmon"] = f"error: {e}"

    data["events_supported"] = events_supported()
    data["ai"] = {
        "enabled": ctx.ai_config.enabled,
        "model": ctx.ai_config.model,
        "base_url": ctx.ai_config.base_url,
        "interval_seconds": ctx.ai_config.interval,
        "batch_sources": ctx.ai_config.batch_sources(),
    }
    q_dir = resolve_path(ctx.engine_config.get("quarantine", {}).get("path", "./quarantine"))
    data["quarantine"] = {"path": str(q_dir), "exists": q_dir.is_dir()}
    data["project_root"] = str(PROJECT_ROOT)
    return _ok_json(data)


# -------------------- 注册表 --------------------

_P = lambda t, d: {"type": t, "description": d}  # noqa: E731

register(ToolSpec(
    name="list_processes", category="进程",
    description="列出当前运行的进程。可按名称/路径关键字过滤，按内存占用降序返回。",
    properties={"keyword": _P("string", "过滤关键字（匹配进程名或路径，忽略大小写）"),
                "limit": _P("integer", "最多返回条数，默认 50，最大 500")},
    func=_list_processes,
))
register(ToolSpec(
    name="get_process_info", category="进程",
    description="获取单个进程的详细信息：路径、命令行、父进程、用户、启动时间、内存、可执行文件 SHA256。调查可疑进程时优先调用。",
    properties={"pid": _P("integer", "进程 PID")},
    required=["pid"], func=_get_process_info,
))
register(ToolSpec(
    name="list_process_modules", category="进程",
    description="列出进程已加载的模块（DLL/映像文件路径），用于发现注入或异常加载。",
    properties={"pid": _P("integer", "进程 PID"),
                "limit": _P("integer", "最多返回条数，默认 200")},
    required=["pid"], func=_list_process_modules,
))
register(ToolSpec(
    name="dump_memory", category="进程",
    description="DUMP_MEMORY: 把进程可读内存转储到 logs/ai_dumps/ 下的 bin 文件（默认上限 64MB）。"
                "返回文件路径与统计，随后用 extract_strings 提取字符串分析。需要管理员权限；系统进程(PID<=4)被拒绝。",
    properties={"pid": _P("integer", "要转储的进程 PID"),
                "max_mb": _P("integer", "转储上限 MB，默认 64，最大 512")},
    required=["pid"], func=_dump_memory,
))

register(ToolSpec(
    name="file_hash", category="文件",
    description="计算文件哈希（默认 sha256，可指定 md5/sha1/sha256/sha512 逗号分隔）。",
    properties={"path": _P("string", "文件绝对路径"),
                "algos": _P("string", "算法列表，逗号分隔，默认 sha256")},
    required=["path"], func=_file_hash,
))
register(ToolSpec(
    name="read_file_text", category="文件",
    description="读取文件的文本片段（自动识别 UTF-8/GBK）。用于查看脚本、配置、日志内容。",
    properties={"path": _P("string", "文件绝对路径"),
                "offset": _P("integer", "起始字节偏移，默认 0"),
                "length": _P("integer", "读取字节数，默认 4096，最大 65536")},
    required=["path"], func=_read_file_text,
))
register(ToolSpec(
    name="scan_file", category="文件",
    description="用双引擎扫描文件：YARA 规则匹配 + ClamAV 特征扫描，返回 verdict(clean/infected)。引擎不可用时如实返回状态。",
    properties={"path": _P("string", "文件绝对路径")},
    required=["path"], func=_scan_file,
))
register(ToolSpec(
    name="get_pe_info", category="文件",
    description="解析 PE（exe/dll）结构：32/64 位、入口点、编译时间、节区表、导入 DLL 与函数。判断可疑可执行文件时使用。",
    properties={"path": _P("string", "PE 文件绝对路径")},
    required=["path"], func=_get_pe_info,
))
register(ToolSpec(
    name="extract_strings", category="文件",
    description="从任意文件（含内存转储）提取可打印字符串（ASCII 与 UTF-16），用于 IOC 搜索、shellcode/配置分析。",
    properties={"path": _P("string", "文件绝对路径"),
                "min_length": _P("integer", "最小字符串长度，默认 5"),
                "max_bytes": _P("integer", "最多读取字节数，默认 1MB，最大 64MB"),
                "limit": _P("integer", "返回条数上限，默认 200")},
    required=["path"], func=_extract_strings,
))

register(ToolSpec(
    name="list_connections", category="网络",
    description="列出网络连接表（本端/远端地址、状态、对应进程）。state 可选 ESTABLISHED/LISTEN/TIME_WAIT 等；可按 PID 过滤。发现外联时使用。",
    properties={"pid": _P("integer", "只看该 PID 的连接"),
                "state": _P("string", "过滤状态，如 ESTABLISHED / LISTEN"),
                "limit": _P("integer", "最多返回条数，默认 100")},
    func=_list_connections,
))
register(ToolSpec(
    name="network_stats", category="网络",
    description="查看各网卡累计收发流量与错误计数。",
    properties={}, func=_network_stats,
))

register(ToolSpec(
    name="list_services", category="系统",
    description="列出 Windows 服务及状态（state 可选 running/stopped/all）。",
    properties={"state": _P("string", "running / stopped / all，默认 all"),
                "limit": _P("integer", "最多返回条数，默认 200")},
    func=_list_services,
))
register(ToolSpec(
    name="read_registry", category="系统",
    description="读取注册表：不带 value_name 列出键下的值（前 200 个）；带 value_name 读取单个值。key 形如 HKLM\\SOFTWARE\\...。",
    properties={"key": _P("string", "注册表键路径，如 HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),
                "value_name": _P("string", "要读取的值名称（省略则列出全部值）")},
    required=["key"], func=_read_registry,
))
register(ToolSpec(
    name="list_scheduled_tasks", category="系统",
    description="列出 Windows 计划任务名称，可按关键字过滤。排查持久化时使用。",
    properties={"keyword": _P("string", "过滤关键字（忽略大小写）"),
                "limit": _P("integer", "最多返回条数，默认 200")},
    func=_list_scheduled_tasks,
))
register(ToolSpec(
    name="list_installed_programs", category="系统",
    description="列出已安装程序（名称/版本/厂商），可按关键字过滤。",
    properties={"keyword": _P("string", "过滤关键字（忽略大小写）"),
                "limit": _P("integer", "最多返回条数，默认 200")},
    func=_list_installed_programs,
))

register(ToolSpec(
    name="query_events", category="事件",
    description="查询指定事件源最近若干小时的事件（最新优先）。source: sysmon/process/network/dns/powershell/system/application/fileio。"
                "批次未包含或需要更多历史时使用。",
    properties={"source": _P("string", "事件源名称"),
                "hours": _P("number", "回溯小时数，默认 1"),
                "keyword": _P("string", "关键字过滤（忽略大小写）"),
                "limit": _P("integer", "最多返回条数，默认 50")},
    required=["source"], func=_query_events,
))
register(ToolSpec(
    name="grep_events", category="事件",
    description="在指定事件源的历史事件中按关键字检索（类似 grep），默认回溯 24 小时。"
                "文件/磁盘事件(fileio)量大不随批次发送，需要时必须用本工具检索。",
    properties={"source": _P("string", "事件源: sysmon/process/network/dns/powershell/system/application/fileio"),
                "keyword": _P("string", "要匹配的关键字（如文件名、IP、域名、进程名），忽略大小写"),
                "hours": _P("number", "回溯小时数，默认 24"),
                "limit": _P("integer", "最多返回条数，默认 100")},
    required=["source", "keyword"], func=_grep_events,
))
register(ToolSpec(
    name="get_event_xml", category="事件",
    description="按 EventRecordID 获取某源单条事件的原始 XML（完整字段）。query_events/grep_events 结果中 rid= 后即 RecordID。",
    properties={"source": _P("string", "事件源名称"),
                "record_id": _P("integer", "EventRecordID")},
    required=["source", "record_id"], func=_get_event_xml,
))

register(ToolSpec(
    name="quarantine_file", category="处置",
    description="把文件隔离到 quarantine/ 目录（移动并记录原路径元数据）。确认恶意文件时调用；会附带 reason。",
    properties={"path": _P("string", "要隔离的文件绝对路径"),
                "reason": _P("string", "处置理由（写入元数据与日志）")},
    required=["path"], func=_quarantine_file,
))
register(ToolSpec(
    name="restore_file", category="处置",
    description="从隔离区恢复文件。带 quarantined_path 即可（元数据含原路径），元数据缺失时需提供 original_path。",
    properties={"quarantined_path": _P("string", "隔离区中的文件路径"),
                "original_path": _P("string", "恢复目标路径（无元数据时必填）")},
    required=["quarantined_path"], func=_restore_file,
))
register(ToolSpec(
    name="kill_process", category="处置",
    description="终止进程。force=true 直接 kill，false 先温和终止。系统进程(PID<=4)被拒绝。仅在判定为恶意且需要立即阻断时使用。",
    properties={"pid": _P("integer", "进程 PID"),
                "force": _P("boolean", "true=kill(默认)，false=terminate")},
    required=["pid"], func=_kill_process,
))

register(ToolSpec(
    name="read_engine_log", category="情报",
    description="读取引擎日志 logs/avengine.log 的尾部行，可按关键字过滤。了解引擎自身近期行为时使用。",
    properties={"tail": _P("integer", "返回行数，默认 100，最大 1000"),
                "keyword": _P("string", "过滤关键字（忽略大小写）")},
    func=_read_engine_log,
))
register(ToolSpec(
    name="list_quarantine", category="情报",
    description="列出隔离区文件（名称、大小、原路径）。",
    properties={}, func=_list_quarantine,
))
register(ToolSpec(
    name="get_engine_status", category="情报",
    description="获取引擎整体状态：YARA/ClamAV/Sysmon 可用性、AI 配置摘要、隔离区与项目路径。会话开始时通常已自动携带，需要刷新时调用。",
    properties={}, func=_get_engine_status,
))
