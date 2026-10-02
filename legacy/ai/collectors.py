"""
ai/collectors.py - 事件采集（Sysmon / ETW 通道 / Windows 事件日志）

不做常驻订阅：所有事件按需通过 EvtQuery 时间窗口查询（反向取最新 N 条），
批次分析、query_events、grep_events 共用同一套查询函数。

- fileio（文件创建/修改）量大，不进批次，仅在 AI 调用 grep_events 时按需检索
- 通道未启用/无权限时返回可读的错误提示（可引导用 wevtutil 启用）
"""

from __future__ import annotations

import logging
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Sequence, Tuple

from .config import AIConfig

logger = logging.getLogger(__name__)

try:
    import win32api
    import win32evtlog

    HAS_WIN32 = True
except ImportError:
    win32api = None
    win32evtlog = None
    HAS_WIN32 = False

# 事件源名 -> Windows 事件通道
SOURCES: Dict[str, str] = {
    "sysmon": "Microsoft-Windows-Sysmon/Operational",
    "process": "Microsoft-Windows-Kernel-Process/Operational",
    "network": "Microsoft-Windows-Kernel-Network/Operational",
    "dns": "Microsoft-Windows-DNS-Client/Operational",
    "powershell": "Microsoft-Windows-PowerShell/Operational",
    "system": "System",
    "application": "Application",
    "fileio": "Microsoft-Windows-Kernel-File/Operational",
}

_EVENT_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

_MEANING_HINT = {
    "sysmon": "Sysmon 事件（1=进程创建 3=网络连接 11=文件创建 ...）",
}


def supported() -> bool:
    """当前平台是否具备事件查询能力。"""
    import sys

    return sys.platform == "win32" and HAS_WIN32


@dataclass
class Event:
    """一条已解析的事件。"""

    source: str
    channel: str
    event_id: int
    record_id: int
    time: Optional[datetime]  # UTC
    provider: str
    computer: str
    data: Dict[str, str] = field(default_factory=dict)

    def text(self, max_chars: int = 600) -> str:
        """格式化为一行紧凑文本（供批次消息与工具输出）。"""
        t = self.time.astimezone().strftime("%H:%M:%S") if self.time else "--:--:--"
        parts: List[str] = []
        total = 0
        for key, value in self.data.items():
            if value is None:
                continue
            value = str(value).replace("\r", " ").replace("\n", " ").strip()
            if len(value) > 220:
                value = value[:220] + "..."
            piece = f"{key}={value}"
            total += len(piece) + 3
            if total > max_chars:
                parts.append("...")
                break
            parts.append(piece)
        meaning = _meaning(self.source, self.event_id)
        head = f"[{t}] {self.source} rid={self.record_id} id={self.event_id} {meaning}"
        if parts:
            return f"{head} | " + " | ".join(parts)
        return head


def _meaning(source: str, event_id: int) -> str:
    if source == "sysmon":
        try:
            from ..sysmon_monitor import EVENT_MEANING

            return EVENT_MEANING.get(event_id, "Unknown")
        except Exception:
            return "Sysmon"
    return f"evt{event_id}"


def parse_event_xml(source: str, channel: str, xml_str: str) -> Optional[Event]:
    """把事件 XML 解析为 Event。"""
    try:
        root = ET.fromstring(xml_str)
        system = root.find(f"{_EVENT_NS}System")
        if system is None:
            return None

        eid_el = system.find(f"{_EVENT_NS}EventID")
        event_id = int(eid_el.text) if eid_el is not None and eid_el.text else -1

        rid_el = system.find(f"{_EVENT_NS}EventRecordID")
        record_id = int(rid_el.text) if rid_el is not None and rid_el.text else 0

        time_el = system.find(f"{_EVENT_NS}TimeCreated")
        event_time: Optional[datetime] = None
        if time_el is not None:
            raw = time_el.attrib.get("SystemTime", "")
            try:
                event_time = datetime.fromisoformat(raw.replace("Z", "+00:00"))
                if event_time.tzinfo is None:
                    event_time = event_time.replace(tzinfo=timezone.utc)
            except ValueError:
                event_time = None

        provider_el = system.find(f"{_EVENT_NS}Provider")
        provider = provider_el.attrib.get("Name", "") if provider_el is not None else ""

        computer_el = system.find(f"{_EVENT_NS}Computer")
        computer = computer_el.text or "" if computer_el is not None else ""

        data: Dict[str, str] = {}
        event_data = root.find(f"{_EVENT_NS}EventData")
        if event_data is not None:
            unnamed_index = 0
            for item in event_data.findall(f"{_EVENT_NS}Data"):
                name = item.attrib.get("Name")
                if not name:
                    unnamed_index += 1
                    name = f"Data{unnamed_index}"
                data[name] = item.text or ""

        return Event(
            source=source,
            channel=channel,
            event_id=event_id,
            record_id=record_id,
            time=event_time,
            provider=provider,
            computer=computer,
            data=data,
        )
    except (ET.ParseError, ValueError, TypeError) as e:
        logger.debug("解析事件 XML 失败: %s", e)
        return None


def _iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _translate_error(source: str, channel: str, exc: Exception) -> str:
    text = str(exc)
    lowered = text.lower()
    hints = []
    if "denied" in lowered or "5" in text or "privilege" in lowered:
        hints.append("权限不足（尝试以管理员运行）")
    if "disabled" in lowered or "enabled" in lowered or "15001" in text or "15002" in text:
        hints.append(
            f"通道未启用，管理员执行: wevtutil sl \"{channel}\" /e:true 后重试"
        )
    if "not found" in lowered or "15007" in text or "15008" in text:
        hints.append("通道不存在（该 Windows 版本可能未提供）")
    suffix = ("；" + "；".join(hints)) if hints else ""
    return f"[{source}] 查询失败: {text}{suffix}"


def query_channel(
    source: str,
    since: datetime,
    until: Optional[datetime] = None,
    limit: int = 100,
    keyword: Optional[str] = None,
    scan_limit: Optional[int] = None,
) -> Tuple[List[Event], Optional[str]]:
    """
    查询某事件源在时间窗口内的事件。

    Args:
        source: SOURCES 中的事件源名。
        since: 起始时间（UTC 或带时区；裸 datetime 视为本地时间）。
        until: 截止时间，默认当前。
        limit: 最多返回条数（反向取最新）。
        keyword: 关键字（忽略大小写，匹配事件文本），None 表示不过滤。
        scan_limit: 关键字过滤时最多扫描的条数，默认 max(limit*20, 500)。

    Returns:
        (事件列表, 错误信息)；错误时事件列表为空。
    """
    if not supported():
        return [], f"[{source}] 事件查询不可用：需要 Windows 平台且已安装 pywin32"

    channel = SOURCES.get(source)
    if not channel:
        return [], f"[{source}] 未知事件源，可用: {', '.join(SOURCES)}"

    if since.tzinfo is None:
        since = since.astimezone()
    if until is None:
        until = datetime.now(timezone.utc)
    elif until.tzinfo is None:
        until = until.astimezone()

    xpath = f"*[System[TimeCreated[@SystemTime>='{_iso(since)}']]]"
    if keyword:
        scan = scan_limit or max(limit * 20, 500)
    else:
        scan = limit

    try:
        handle = win32evtlog.EvtQuery(
            Path=channel,
            Query=xpath,
            Flags=win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection,
        )
    except Exception as e:
        return [], _translate_error(source, channel, e)

    events: List[Event] = []
    error: Optional[str] = None
    scanned = 0
    try:
        while scanned < scan:
            batch_size = min(64, scan - scanned)
            try:
                handles = win32evtlog.EvtNext(handle, batch_size, 100, 0)
            except Exception:
                break  # 没有更多事件
            if not handles:
                break
            for event_handle in handles:
                scanned += 1
                try:
                    xml_str = win32evtlog.EvtRender(event_handle, win32evtlog.EvtRenderEventXml)
                except Exception as e:
                    error = error or f"[{source}] 渲染事件失败: {e}"
                    continue
                finally:
                    try:
                        win32api.CloseHandle(event_handle)
                    except Exception:
                        pass
                parsed = parse_event_xml(source, channel, xml_str or "")
                if not parsed:
                    continue
                if parsed.time and parsed.time > until:
                    continue
                if keyword:
                    haystack = " ".join([xml_str or "", *[str(v) for v in parsed.data.values()]]).lower()
                    if keyword.lower() not in haystack:
                        continue
                events.append(parsed)
                if len(events) >= limit:
                    break
    finally:
        try:
            win32api.CloseHandle(handle)
        except Exception:
            pass

    # 时间正序输出（反向查询拿到的是最新优先）
    events.sort(key=lambda e: (e.time or datetime.min.replace(tzinfo=timezone.utc)))
    return events, error


def query_batch(config: AIConfig, minutes: int) -> Tuple[str, Dict[str, int], int, List[str]]:
    """
    组装一个批次的事件文本（只含 [sources] 启用且属于批次集合的源）。

    Returns:
        (事件文本块, 各源统计, 截断条数, 错误列表)。
    """
    since = datetime.now(timezone.utc) - timedelta(minutes=max(1, minutes))
    stats: Dict[str, int] = {}
    errors: List[str] = []
    all_events: List[Event] = []
    truncated = 0
    max_total = config.max_events_per_batch
    sources = config.batch_sources()

    per_source = max(5, max_total // max(1, len(sources)))
    for source in sources:
        events, err = query_channel(source, since=since, limit=per_source)
        if err:
            errors.append(err)
        stats[source] = len(events)
        all_events.extend(events)

    all_events.sort(key=lambda e: (e.time or datetime.min.replace(tzinfo=timezone.utc)))
    if len(all_events) > max_total:
        truncated = len(all_events) - max_total
        all_events = all_events[-max_total:]

    lines = [ev.text(config.max_event_chars) for ev in all_events]
    text = "\n".join(lines) if lines else "（窗口内没有采集到事件）"
    return text, stats, truncated, errors


def query_for_tools(
    source: str,
    hours: float,
    limit: int,
    keyword: Optional[str] = None,
) -> Tuple[str, Optional[str]]:
    """工具层入口：返回格式化事件文本与错误文本。"""
    since = datetime.now(timezone.utc) - timedelta(hours=max(0.01, hours))
    events, err = query_channel(source, since=since, limit=limit, keyword=keyword)
    if not events:
        text = "（无匹配事件）"
    else:
        text = "\n".join(ev.text(600) for ev in events)
    return text, err


def get_event_xml(source: str, record_id: int) -> Tuple[str, Optional[str]]:
    """按 EventRecordID 取单条事件的原始 XML。"""
    if not supported():
        return "", "事件查询不可用：需要 Windows 平台且已安装 pywin32"
    channel = SOURCES.get(source)
    if not channel:
        return "", f"未知事件源: {source}，可用: {', '.join(SOURCES)}"
    xpath = f"*[System[EventRecordID={int(record_id)}]]"
    try:
        handle = win32evtlog.EvtQuery(
            Path=channel, Query=xpath, Flags=win32evtlog.EvtQueryChannelPath
        )
    except Exception as e:
        return "", _translate_error(source, channel, e)
    try:
        handles = win32evtlog.EvtNext(handle, 1, 200, 0)
        if not handles:
            return "", f"{source} 通道中不存在 EventRecordID={record_id}"
        try:
            xml_str = win32evtlog.EvtRender(handles[0], win32evtlog.EvtRenderEventXml)
            return xml_str or "", None
        finally:
            try:
                win32api.CloseHandle(handles[0])
            except Exception:
                pass
    except Exception as e:
        return "", f"读取事件失败: {e}"
    finally:
        try:
            win32api.CloseHandle(handle)
        except Exception:
            pass


def ensure_channels(config: AIConfig) -> List[str]:
    """
    尝试启用批次所需的 ETW 事件通道（需要管理员，失败仅记录）。

    Returns:
        失败的通道列表（成功启用或已启用的不返回）。
    """
    if not supported():
        return []
    import subprocess

    failed: List[str] = []
    seen = set()
    for source in config.batch_sources():
        channel = SOURCES.get(source)
        if not channel or channel in seen or channel in ("System", "Application"):
            continue
        seen.add(channel)
        try:
            result = subprocess.run(
                ["wevtutil", "sl", channel, "/e:true"],
                capture_output=True,
                timeout=10,
            )
            if result.returncode != 0:
                failed.append(channel)
        except Exception:
            failed.append(channel)
    return failed
