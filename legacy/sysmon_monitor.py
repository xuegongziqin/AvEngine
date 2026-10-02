"""
sysmon_monitor.py - Sysmon 事件监控与安装辅助
负责 Sysmon 服务检测/安装/启动，以及通过 Windows 事件日志轮询订阅 Sysmon 事件。
win32 依赖做惰性导入，非 Windows 平台导入本模块不会报错。
"""

from __future__ import annotations

import logging
import subprocess
import sys
import threading
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Callable, Dict, Optional, Set

from .paths import SYSMON_CONFIG, SYSMON_EXE

logger = logging.getLogger(__name__)

try:
    import win32api
    import win32evtlog

    HAS_WIN32 = True
except ImportError:  # 非 Windows 或未安装 pywin32
    win32api = None
    win32evtlog = None
    HAS_WIN32 = False

SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
SYSMON_SERVICE = "Sysmon"
SYSMON_DRIVER_KEY = r"SYSTEM\CurrentControlSet\Services\SysmonDrv"

EVENT_MEANING = {
    1: "ProcessCreate", 2: "FileCreateTime", 3: "NetworkConnect",
    4: "SysmonServiceStateChange", 5: "ProcessTerminate", 6: "DriverLoad",
    7: "ImageLoad", 8: "CreateRemoteThread", 9: "RawAccessRead",
    10: "ProcessAccess", 11: "FileCreate", 12: "RegistryCreateDelete",
    13: "RegistryValueSet", 14: "RegistryRename", 15: "FileCreateStreamHash",
    16: "SysmonConfigChange", 17: "PipeCreate", 18: "PipeConnect",
    19: "WmiFilter", 20: "WmiConsumer", 21: "WmiConsumerToFilter",
    22: "DNSEvent", 23: "FileDelete", 24: "ClipboardChange",
    25: "ProcessTampering", 26: "FileDeleteDetected", 255: "Error",
}

_EVENT_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


# -------------------- 安装与服务管理 --------------------

def is_supported() -> bool:
    """当前平台是否具备 Sysmon 监控能力（Windows + pywin32）。"""
    return sys.platform == "win32" and HAS_WIN32


def is_installed() -> bool:
    """通过注册表判断 Sysmon 驱动是否已安装。"""
    if not is_supported():
        return False
    import winreg

    try:
        winreg.CloseKey(winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, SYSMON_DRIVER_KEY))
        return True
    except FileNotFoundError:
        return False


def install(
    sysmon_exe: Optional[Path] = None,
    config: Optional[Path] = None,
) -> bool:
    """
    安装 Sysmon（需要管理员权限）。

    Args:
        sysmon_exe: Sysmon 可执行文件路径，默认使用 bina/Sysmon/Sysmon.exe。
        config: Sysmon 配置文件，存在时随安装一并应用。

    Returns:
        是否安装成功。
    """
    exe = Path(sysmon_exe or SYSMON_EXE)
    if not exe.is_file():
        logger.error("找不到 Sysmon 可执行文件: %s", exe)
        return False

    cmd = [str(exe), "-accepteula", "-i"]
    cfg = Path(config or SYSMON_CONFIG)
    if cfg.is_file():
        cmd.append(str(cfg))

    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True)
        logger.info("Sysmon 安装成功: %s", exe)
        return True
    except subprocess.CalledProcessError as e:
        logger.error("Sysmon 安装失败: %s", (e.stderr or e.stdout or "").strip())
        return False
    except OSError as e:
        logger.error("无法执行 Sysmon: %s", e)
        return False


def start_service() -> bool:
    """启动 Sysmon 服务（已安装但未运行时）。"""
    try:
        subprocess.run(
            ["sc", "start", SYSMON_SERVICE], check=True, capture_output=True
        )
        return True
    except (subprocess.CalledProcessError, OSError):
        return False


# -------------------- 事件监控 --------------------

class SysmonMonitor:
    """轮询订阅 Sysmon 事件日志，把解析后的事件交给回调函数。"""

    def __init__(self, channel: str = SYSMON_CHANNEL, query: Optional[str] = None):
        self.channel = channel
        self.query = query
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._callback: Optional[Callable[[Dict], None]] = None

    @property
    def is_running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def start(
        self,
        callback: Callable[[Dict], None],
        event_ids: Optional[Set[int]] = None,
        poll_interval: float = 0.5,
    ) -> None:
        """启动监控线程。"""
        if not is_supported():
            raise RuntimeError("Sysmon 监控不可用：需要 Windows 平台且已安装 pywin32")
        if self.is_running:
            raise RuntimeError("监控器已在运行中")

        self._callback = callback
        self._stop_event.clear()

        if self.query:
            query_str = self.query
        elif event_ids:
            conditions = " or ".join(f"EventID={eid}" for eid in sorted(event_ids))
            query_str = f"*[System[{conditions}]]"
        else:
            query_str = "*"

        logger.info("Sysmon 监控启动 (通道: %s, 查询: %s)", self.channel, query_str)
        self._thread = threading.Thread(
            target=self._polling_loop, args=(query_str, poll_interval), daemon=True
        )
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        """停止监控线程。"""
        if not self.is_running:
            return
        logger.info("正在停止 Sysmon 监控...")
        self._stop_event.set()
        assert self._thread is not None
        self._thread.join(timeout)
        if self._thread.is_alive():
            logger.warning("Sysmon 监控线程未在 %.1f 秒内退出", timeout)
        else:
            logger.info("Sysmon 监控已停止")

    def _polling_loop(self, query_str: str, poll_interval: float) -> None:
        """反向查询最新事件，按 EventRecordID 去重后分发。"""
        last_record_id = 0
        while not self._stop_event.is_set():
            try:
                handle = win32evtlog.EvtQuery(
                    Path=self.channel,
                    Query=query_str,
                    Flags=win32evtlog.EvtQueryChannelPath
                    | win32evtlog.EvtQueryReverseDirection,
                )
            except Exception as e:
                logger.error("创建事件查询失败: %s", e)
                self._stop_event.wait(1.0)
                continue

            try:
                events = win32evtlog.EvtNext(handle, 1, 100, 0)
                if events:
                    evt = events[0]
                    record_id = self._get_record_id(evt)
                    if record_id is not None and record_id > last_record_id:
                        last_record_id = record_id
                        parsed = self._parse_event(evt)
                        if parsed and self._callback:
                            logger.debug(
                                "Sysmon 新事件: EventID=%s, RecordID=%d",
                                parsed.get("EventID"),
                                record_id,
                            )
                            self._callback(parsed)
                    win32api.CloseHandle(evt)
            except Exception as e:
                logger.error("读取事件失败: %s", e)
            finally:
                win32api.CloseHandle(handle)

            self._stop_event.wait(poll_interval)

    def _render_xml(self, event_handle) -> Optional[str]:
        try:
            return win32evtlog.EvtRender(event_handle, win32evtlog.EvtRenderEventXml)
        except Exception as e:
            logger.error("渲染事件 XML 失败: %s", e)
            return None

    def _get_record_id(self, event_handle) -> Optional[int]:
        xml_str = self._render_xml(event_handle)
        if not xml_str:
            return None
        try:
            system = ET.fromstring(xml_str).find(f"{_EVENT_NS}System")
            if system is None:
                return None
            rid = system.find(f"{_EVENT_NS}EventRecordID")
            return int(rid.text) if rid is not None and rid.text else None
        except (ET.ParseError, ValueError, TypeError):
            return None

    def _parse_event(self, event_handle) -> Optional[Dict]:
        xml_str = self._render_xml(event_handle)
        if not xml_str:
            return None
        try:
            root = ET.fromstring(xml_str)
            system = root.find(f"{_EVENT_NS}System")
            if system is None:
                return None

            eid_el = system.find(f"{_EVENT_NS}EventID")
            event_id = int(eid_el.text) if eid_el is not None and eid_el.text else -1

            time_el = system.find(f"{_EVENT_NS}TimeCreated")
            time_created = time_el.attrib.get("SystemTime", "") if time_el is not None else ""

            computer_el = system.find(f"{_EVENT_NS}Computer")
            computer = computer_el.text or "" if computer_el is not None else ""

            data: Dict[str, Optional[str]] = {}
            event_data = root.find(f"{_EVENT_NS}EventData")
            if event_data is not None:
                for item in event_data.findall(f"{_EVENT_NS}Data"):
                    name = item.attrib.get("Name")
                    if name:
                        data[name] = item.text

            return {
                "EventID": event_id,
                "TimeCreated": time_created,
                "Computer": computer,
                "Meaning": EVENT_MEANING.get(event_id, "Unknown"),
                "EventData": data,
            }
        except (ET.ParseError, ValueError, TypeError) as e:
            logger.error("解析事件失败: %s", e)
            return None
