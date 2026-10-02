"""
scheduler.py - 调度器
协调 Sysmon 实时事件、按需扫描与定时批量扫描，整合 YARA / ClamAV 引擎并自动响应威胁。
"""

from __future__ import annotations

import logging
import queue
import threading
import time
from pathlib import Path
from typing import Callable, Dict, List, Optional

from .clamav_scanner import ClamavScanner
from .config import load_config
from .sysmon_monitor import SysmonMonitor
from .utils import compute_file_hash, quarantine_file
from .yara_scanner import YaraScanner

logger = logging.getLogger(__name__)

ThreatCallback = Callable[[str, str, str], None]


class ScanJob:
    """一个待扫描任务（文件或目录）。"""

    def __init__(self, target: str, job_type: str = "file", source: str = "manual"):
        self.target = target
        self.job_type = job_type
        self.source = source
        self.timestamp = time.time()

    def __repr__(self) -> str:
        return f"<ScanJob {self.job_type} {self.target} ({self.source})>"


class Scheduler:
    """按配置把扫描任务分派给工作线程，并对威胁执行隔离与回调。"""

    def __init__(self, config: Optional[Dict] = None):
        self.config = config if config is not None else load_config()
        self._stop_event = threading.Event()
        self._scan_queue: "queue.Queue[ScanJob]" = queue.Queue()

        yara_rules = self.config.get("yara", {}).get("rules_path")
        self.yara_scanner = YaraScanner(rules_path=yara_rules)

        clamav_cfg = self.config.get("clamav", {})
        self.clamav_scanner = ClamavScanner(
            host=clamav_cfg.get("host", "127.0.0.1"),
            port=clamav_cfg.get("port", 3310),
            timeout=clamav_cfg.get("timeout", 30),
        )

        self.sysmon_monitor: Optional[SysmonMonitor] = None
        sysmon_cfg = self.config.get("sysmon", {})
        self.sysmon_monitor = SysmonMonitor(
            channel=sysmon_cfg.get("channel", "Microsoft-Windows-Sysmon/Operational")
        )

        scan_cfg = self.config.get("scan", {})
        self.monitor_paths: List[str] = scan_cfg.get("monitor_paths", [])
        self.timer_interval: int = scan_cfg.get("timer_interval", 3600)
        self.timer_enabled: bool = scan_cfg.get("timer_enabled", False)
        self.on_access: bool = scan_cfg.get("on_access", False)

        self.quarantine_dir: str = self.config.get("quarantine", {}).get("path", "./quarantine")

        self._timer_thread: Optional[threading.Thread] = None
        self._worker_thread: Optional[threading.Thread] = None
        self._sysmon_thread: Optional[threading.Thread] = None

        self.on_threat: Optional[ThreatCallback] = None

        logger.info(
            "调度器初始化完成 | YARA: %s | ClamAV: %s | Sysmon: %s | 定时扫描: %s",
            "可用" if self.yara_scanner.is_available else "不可用",
            "可用" if self.clamav_scanner.is_available else "不可用",
            "可用" if self.sysmon_monitor else "不可用",
            "启用" if self.timer_enabled else "未启用",
        )

    # -------------------- 生命周期 --------------------

    def start(self, enable_sysmon: bool = True, enable_timer: bool = True) -> None:
        """启动工作线程，以及可选的 Sysmon 订阅与定时扫描。"""
        self._stop_event.clear()

        self._worker_thread = threading.Thread(target=self._worker_loop, daemon=True)
        self._worker_thread.start()
        logger.info("扫描工作线程已启动")

        if self.sysmon_monitor and enable_sysmon and self.on_access:
            self._sysmon_thread = threading.Thread(
                target=self._sysmon_subscribe, daemon=True
            )
            self._sysmon_thread.start()
            logger.info("Sysmon 实时监控线程已启动")
        elif not self.sysmon_monitor:
            logger.info("Sysmon 不可用，跳过实时监控")
        elif not self.on_access:
            logger.info("scan.on_access 关闭，跳过实时监控")

        if enable_timer and self.timer_enabled:
            self._timer_thread = threading.Thread(target=self._timer_loop, daemon=True)
            self._timer_thread.start()
            logger.info("定时扫描线程已启动 (间隔 %d 秒)", self.timer_interval)

    def stop(self, timeout: float = 10.0) -> None:
        """停止调度器及所有子线程。"""
        logger.info("正在停止调度器...")
        self._stop_event.set()

        if self.sysmon_monitor:
            self.sysmon_monitor.stop()

        for name, thread in [
            ("工作线程", self._worker_thread),
            ("Sysmon 线程", self._sysmon_thread),
            ("定时器线程", self._timer_thread),
        ]:
            if thread and thread.is_alive():
                thread.join(timeout)
                if thread.is_alive():
                    logger.warning("%s 未在 %.1f 秒内退出", name, timeout)

        logger.info("调度器已停止")

    # -------------------- 扫描 --------------------

    def scan_now(self, target: str, target_type: str = "file") -> Dict:
        """
        立即扫描目标。

        Args:
            target: 文件或目录路径。
            target_type: "file" 或 "directory"。

        Returns:
            扫描结果字典。
        """
        result: Dict = {
            "target": target,
            "yara_matches": [],
            "clamav_result": None,
            "hash": None,
        }

        if target_type == "file":
            hits = self.yara_scanner.scan_file(target) if self.yara_scanner.is_available else []
            virus = (
                self.clamav_scanner.scan_file(target)
                if self.clamav_scanner.is_available
                else None
            )
            result["yara_matches"] = hits
            result["clamav_result"] = virus
            result["hash"] = compute_file_hash(target)
            if hits or virus:
                self._handle_threat(target, hits, virus)

        elif target_type == "directory":
            yara_results = (
                self.yara_scanner.scan_directory(target)
                if self.yara_scanner.is_available
                else {}
            )
            clam_results = (
                self.clamav_scanner.scan_directory(target)
                if self.clamav_scanner.is_available
                else {}
            )
            scanned = set()
            for path, hits in yara_results.items():
                scanned.add(path)
                self._handle_threat(path, hits, clam_results.get(path))
            for path, virus in clam_results.items():
                if path not in scanned:
                    self._handle_threat(path, [], virus)
            result["yara_matches"] = yara_results
            result["clamav_result"] = clam_results
        else:
            logger.error("不支持的扫描类型: %s", target_type)

        return result

    def enqueue(self, target: str, job_type: str = "file", source: str = "manual") -> None:
        """把任务加入扫描队列。"""
        self._scan_queue.put(ScanJob(target, job_type=job_type, source=source))

    # -------------------- 内部线程 --------------------

    def _worker_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                job = self._scan_queue.get(timeout=1)
            except queue.Empty:
                continue

            try:
                if job.job_type == "file":
                    self._process_file_scan(job.target, job.source)
                elif job.job_type == "directory":
                    self.scan_now(job.target, "directory")
                else:
                    logger.warning("未知任务类型: %s", job.job_type)
            except Exception as e:
                logger.error("处理扫描任务 %r 出错: %s", job, e)
            finally:
                self._scan_queue.task_done()

    def _sysmon_subscribe(self) -> None:
        """把 Sysmon 文件创建事件转换为扫描任务。"""

        def callback(event: Dict) -> None:
            event_id = event.get("EventID")
            if event_id not in (2, 11):
                logger.debug("忽略 Sysmon 事件 EventID=%s", event_id)
                return
            target = event.get("EventData", {}).get("TargetFilename")
            if target and Path(target).is_file():
                logger.info("Sysmon 文件事件触发扫描: %s", target)
                self.enqueue(target, job_type="file", source="sysmon")
            else:
                logger.debug("事件未携带有效文件路径: %s", target)

        if not self.sysmon_monitor:
            return
        try:
            self.sysmon_monitor.start(callback=callback, event_ids={2, 11})
        except Exception as e:
            logger.error("启动 Sysmon 监控失败: %s", e)

    def _timer_loop(self) -> None:
        while not self._stop_event.is_set():
            if self._stop_event.wait(timeout=self.timer_interval):
                return
            for path in self.monitor_paths:
                if self._stop_event.is_set():
                    return
                if Path(path).is_dir():
                    logger.info("定时扫描启动: %s", path)
                    self.enqueue(path, job_type="directory", source="timer")
                else:
                    logger.warning("定时扫描路径不存在: %s", path)

    def _process_file_scan(self, filepath: str, source: str) -> None:
        if not Path(filepath).is_file():
            logger.info("文件 %s 已不存在，跳过扫描", filepath)
            return
        logger.info("正在扫描文件: %s (来源: %s)", filepath, source)
        result = self.scan_now(filepath, "file")
        if not result["yara_matches"] and not result["clamav_result"]:
            logger.info("扫描完成，未发现威胁: %s", filepath)

    def _handle_threat(
        self, filepath: str, yara_hits: List[str], clam_virus: Optional[str]
    ) -> None:
        if not yara_hits and not clam_virus:
            return

        parts = []
        if yara_hits:
            parts.append(f"YARA: {', '.join(yara_hits)}")
        if clam_virus:
            parts.append(f"ClamAV: {clam_virus}")
        threat_desc = " | ".join(parts)

        logger.warning("检测到威胁: %s -> %s", filepath, threat_desc)

        action = "detected"
        if self.quarantine_dir:
            if quarantine_file(filepath, self.quarantine_dir):
                action = "quarantined"

        if self.on_threat:
            try:
                self.on_threat(filepath, threat_desc, action)
            except Exception as e:
                logger.error("威胁回调执行失败: %s", e)
