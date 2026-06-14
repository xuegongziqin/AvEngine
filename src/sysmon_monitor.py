import sys
import threading
import logging
import xml.etree.ElementTree as ET
from typing import Optional, Callable, Set, Dict
import time
import win32evtlog
import win32api

logger = logging.getLogger(__name__)

SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"

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

class SysmonMonitor:
    def __init__(self, channel=SYSMON_CHANNEL, query=None):
        self.channel = channel
        self.query = query
        self._stop_event = threading.Event()
        self._thread = None
        self._callback = None

    def start(self, callback, event_ids=None):
        if self._thread and self._thread.is_alive():
            raise RuntimeError("监控器已在运行中")
        self._callback = callback
        self._stop_event.clear()

        if self.query:
            query_str = self.query
        elif event_ids:
            conditions = " or ".join([f"EventID={eid}" for eid in sorted(event_ids)])
            query_str = f"*[System[{conditions}]]"
        else:
            query_str = "*"

        print(f"[SysmonMonitor] 启动查询: {query_str}", flush=True)
        logger.info("查询: %s", query_str)
        self._thread = threading.Thread(target=self._polling_loop, args=(query_str,), daemon=True)
        self._thread.start()
        logger.info("Sysmon 监控已启动 (通道: %s)", self.channel)

    def stop(self, timeout=5.0):
        if not self._thread or not self._thread.is_alive():
            return
        logger.info("正在停止 Sysmon 监控...")
        self._stop_event.set()
        self._thread.join(timeout)
        if self._thread.is_alive():
            logger.warning("监控线程未在规定时间内退出")
        else:
            logger.info("Sysmon 监控已停止")

    def _polling_loop(self, query_str):
        print("[SysmonMonitor] 轮询循环启动 (反向查询模式)", flush=True)
        last_record_id = 0
        loop_count = 0
        while not self._stop_event.is_set():
            loop_count += 1
            if loop_count % 10 == 0:
                print(f"[SysmonMonitor] 心跳 (循环 #{loop_count}, last_record_id={last_record_id})", flush=True)
                logger.info("心跳 (循环 %d, last_record_id=%d)", loop_count, last_record_id)

            try:
                reverse_handle = win32evtlog.EvtQuery(
                    Path=self.channel,
                    Query=query_str,
                    Flags=win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection,
                )
            except Exception as e:
                logger.error("无法创建反向查询: %s", e)
                time.sleep(0.5)
                continue

            try:
                events = win32evtlog.EvtNext(reverse_handle, 1, 100, 0)
                if events:
                    evt = events[0]
                    rid = self._get_record_id(evt)
                    if rid is not None and rid > last_record_id:
                        last_record_id = rid
                        parsed = self._parse_event(evt)
                        if parsed and self._callback:
                            print(f"[SysmonMonitor] 新事件: EventID={parsed.get('EventID')}, RecordID={rid}", flush=True)
                            self._callback(parsed)
                    win32api.CloseHandle(evt)
            except Exception as e:
                logger.error("EvtNext 错误: %s", e, exc_info=True)
            finally:
                win32api.CloseHandle(reverse_handle)

            time.sleep(0.5)

    def _get_record_id(self, event_handle):
        try:
            xml_str = win32evtlog.EvtRender(event_handle, win32evtlog.EvtRenderEventXml)
            root = ET.fromstring(xml_str)
            ns = "{http://schemas.microsoft.com/win/2004/08/events/event}"
            sys_node = root.find(f"{ns}System")
            if sys_node is not None:
                rid_el = sys_node.find(f"{ns}EventRecordID")
                if rid_el is not None:
                    return int(rid_el.text)
        except:
            pass
        return None

    def _parse_event(self, event_handle):
        try:
            xml_str = win32evtlog.EvtRender(event_handle, win32evtlog.EvtRenderEventXml)
            root = ET.fromstring(xml_str)
            ns = "{http://schemas.microsoft.com/win/2004/08/events/event}"
            sys_node = root.find(f"{ns}System")
            if sys_node is None:
                return None
            eid_el = sys_node.find(f"{ns}EventID")
            event_id = int(eid_el.text) if eid_el is not None else -1
            time_el = sys_node.find(f"{ns}TimeCreated")
            time_created = time_el.attrib.get("SystemTime", "") if time_el is not None else ""
            computer_el = sys_node.find(f"{ns}Computer")
            computer = computer_el.text if computer_el is not None else ""
            data_dict = {}
            event_data = root.find(f"{ns}EventData")
            if event_data is not None:
                for d in event_data.findall(f"{ns}Data"):
                    name = d.attrib.get("Name")
                    value = d.text
                    if name:
                        data_dict[name] = value
            return {
                "EventID": event_id,
                "TimeCreated": time_created,
                "Computer": computer,
                "Meaning": EVENT_MEANING.get(event_id, "Unknown"),
                "EventData": data_dict,
            }
        except Exception as e:
            logger.error("解析事件失败: %s", e)
            return None