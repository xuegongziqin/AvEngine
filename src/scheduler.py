"""
scheduler.py - 调度器模块
负责协调实时 Sysmon 监控、按需扫描和定时批量扫描任务。
整合 YARA、ClamAV 引擎，根据配置自动响应威胁。
"""

import os
import time
import queue
import logging
import threading
from typing import Dict, Optional, Set, List, Callable

from .yara_scanner import YaraScanner
from .clamav_scanner import ClamavScanner
from .sysmon_monitor import SysmonMonitor
from .utils import quarantine_file, compute_file_hash, load_config

logger = logging.getLogger(__name__)


class ScanJob:
    """表示一个扫描任务，可以是文件、目录或数据流。"""
    def __init__(self, target: str, job_type: str = "file", source: str = "manual"):
        self.target = target
        self.job_type = job_type
        self.source = source
        self.timestamp = time.time()


class Scheduler:
    def __init__(self, config: Optional[Dict] = None):
        self.config = config if config else load_config()
        self._stop_event = threading.Event()
        self._scan_queue = queue.Queue()
        self._active_scans = 0
        self._active_scans_lock = threading.Lock()

        yara_rules = self.config.get("yara", {}).get("rules_path", "./rules")
        self.yara_scanner = YaraScanner(rules_path=yara_rules)

        clamav_cfg = self.config.get("clamav", {})
        self.clamav_scanner = ClamavScanner(
            host=clamav_cfg.get("host", "127.0.0.1"),
            port=clamav_cfg.get("port", 3310),
            timeout=clamav_cfg.get("timeout", 30),
        )

        self.sysmon_monitor: Optional[SysmonMonitor] = None
        if os.name == "nt":
            sysmon_channel = self.config.get("sysmon", {}).get(
                "channel", "Microsoft-Windows-Sysmon/Operational"
            )
            self.sysmon_monitor = SysmonMonitor(channel=sysmon_channel)

        scan_cfg = self.config.get("scan", {})
        self.monitor_paths: List[str] = scan_cfg.get("monitor_paths", [])
        self.timer_interval = scan_cfg.get("timer_interval", 3600)
        self.timer_enabled = scan_cfg.get("timer_enabled", False)
        self.on_access = scan_cfg.get("on_access", False)

        self.quarantine_dir = self.config.get("quarantine", {}).get("path", "./quarantine")

        self._timer_thread: Optional[threading.Thread] = None
        self._worker_thread: Optional[threading.Thread] = None
        self._sysmon_thread: Optional[threading.Thread] = None

        self.on_threat: Optional[Callable[[str, str, str], None]] = None

        logger.info(
            "调度器初始化完成 | YARA: %s | ClamAV: %s | Sysmon: %s | 定时扫描: %s",
            "可用" if self.yara_scanner.is_available else "不可用",
            "可用" if self.clamav_scanner.is_available else "不可用",
            "可用" if self.sysmon_monitor else "不可用",
            "启用" if self.timer_enabled else "未启用",
        )

    def start(self, enable_sysmon: bool = True, enable_timer: bool = True) -> None:
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
        else:
            if not self.sysmon_monitor:
                logger.info("Sysmon 不可用，跳过实时监控")
            elif not self.on_access:
                logger.info("on_access 关闭，跳过实时监控")

        if enable_timer and self.timer_enabled:
            self._timer_thread = threading.Thread(target=self._timer_loop, daemon=True)
            self._timer_thread.start()
            logger.info("定时扫描线程已启动 (间隔 %d 秒)", self.timer_interval)

    def stop(self, timeout: float = 10.0) -> None:
        logger.info("正在停止调度器...")
        self._stop_event.set()

        if self.sysmon_monitor:
            self.sysmon_monitor.stop()

        for t_name, t in [
            ("工作线程", self._worker_thread),
            ("Sysmon 线程", self._sysmon_thread),
            ("定时器线程", self._timer_thread),
        ]:
            if t and t.is_alive():
                t.join(timeout)
                if t.is_alive():
                    logger.warning("%s 未在规定时间内退出", t_name)

        logger.info("调度器已停止")

    def scan_now(self, target: str, target_type: str = "file") -> Dict:
        result = {
            "target": target,
            "yara_matches": [],
            "clamav_result": None,
            "hash": None,
        }

        if target_type == "file":
            yara_hits = self.yara_scanner.scan_file(target) if self.yara_scanner.is_available else []
            result["yara_matches"] = yara_hits

            clam_result = self.clamav_scanner.scan_file(target) if self.clamav_scanner.is_available else None
            result["clamav_result"] = clam_result

            result["hash"] = compute_file_hash(target)

            if yara_hits or clam_result:
                self._handle_threat(target, yara_hits, clam_result)

        elif target_type == "directory":
            yara_dir_results = self.yara_scanner.scan_directory(target) if self.yara_scanner.is_available else {}
            clam_dir_results = self.clamav_scanner.scan_directory(target) if self.clamav_scanner.is_available else {}
            all_infected = set()
            for fpath, hits in yara_dir_results.items():
                all_infected.add(fpath)
                clam_virus = clam_dir_results.get(fpath)
                self._handle_threat(fpath, hits, clam_virus)
            for fpath, virus in clam_dir_results.items():
                if fpath not in all_infected:
                    self._handle_threat(fpath, [], virus)
            result["yara_matches"] = yara_dir_results
            result["clamav_result"] = clam_dir_results
        else:
            logger.error("不支持的扫描类型: %s", target_type)

        return result

    def _worker_loop(self):
        while not self._stop_event.is_set():
            try:
                job = self._scan_queue.get(timeout=1)
            except queue.Empty:
                continue

            try:
                with self._active_scans_lock:
                    self._active_scans += 1

                if job.job_type == "file":
                    self._process_file_scan(job.target, job.source)
                elif job.job_type == "directory":
                    self.scan_now(job.target, "directory")
                else:
                    logger.warning("未知任务类型: %s", job.job_type)
            except Exception as e:
                logger.error("处理扫描任务时出错: %s", e)
            finally:
                with self._active_scans_lock:
                    self._active_scans -= 1
                self._scan_queue.task_done()

    def _sysmon_subscribe(self):
        """Sysmon 事件订阅回调，将文件创建/修改事件转换为扫描任务。"""
        def sysmon_callback(event: Dict):
            # 直接 print 到标准输出，确保无论 logger 如何配置都能看到
            print(f"[DEBUG] Sysmon 回调触发: EventID={event.get('EventID')}, Meaning={event.get('Meaning')}", flush=True)
            event_id = event.get("EventID")
            if event_id in (2, 11):
                target_file = event.get("EventData", {}).get("TargetFilename")
                print(f"[DEBUG] 文件事件: {target_file}", flush=True)
                if target_file and os.path.isfile(target_file):
                    job = ScanJob(target_file, job_type="file", source="sysmon")
                    self._scan_queue.put(job)
                    print(f"[DEBUG] 已加入扫描队列: {target_file}", flush=True)
                else:
                    print(f"[DEBUG] 文件不存在或未获取到路径", flush=True)
            else:
                print(f"[DEBUG] 忽略 EventID {event_id}", flush=True)

        if self.sysmon_monitor:
            try:
                self.sysmon_monitor.start(callback=sysmon_callback, event_ids={2, 11})
            except Exception as e:
                logger.error("启动 Sysmon 监控失败: %s", e)

    def _timer_loop(self):
        while not self._stop_event.is_set():
            if self._stop_event.wait(timeout=self.timer_interval):
                return
            for path in self.monitor_paths:
                if self._stop_event.is_set():
                    return
                if os.path.isdir(path):
                    logger.info("定时扫描启动: %s", path)
                    job = ScanJob(path, job_type="directory", source="timer")
                    self._scan_queue.put(job)
                else:
                    logger.warning("定时扫描路径不存在: %s", path)

    def _process_file_scan(self, filepath: str, source: str):
        if not os.path.isfile(filepath):
            logger.info("文件 %s 已不存在，跳过扫描", filepath)
            return
        logger.info("正在扫描文件: %s (来源: %s)", filepath, source)
        result = self.scan_now(filepath, "file")
        yara_hits = result.get("yara_matches", [])
        clam_result = result.get("clamav_result")
        if yara_hits or clam_result:
            # 威胁已在 _handle_threat 中输出告警
            pass
        else:
            logger.info("扫描完成，未发现威胁: %s", filepath)

    def _handle_threat(self, filepath: str, yara_hits: List[str], clam_virus: Optional[str]):
        if not yara_hits and not clam_virus:
            return

        threat_desc = ""
        if yara_hits:
            threat_desc += f"YARA: {', '.join(yara_hits)}"
        if clam_virus:
            threat_desc += f"{' ' if threat_desc else ''}ClamAV: {clam_virus}"

        logger.warning("检测到威胁: %s -> %s", filepath, threat_desc)

        if self.quarantine_dir:
            quarantine_file(filepath, self.quarantine_dir)

        if self.on_threat:
            try:
                self.on_threat(filepath, threat_desc, "quarantined")
            except Exception as e:
                logger.error("威胁回调执行失败: %s", e)


def run_scheduler_from_config(config_path: str = "config.yaml") -> None:
    config = load_config(config_path)
    scheduler = Scheduler(config)

    def threat_notify(path, desc, action):
        print(f"\n[!!!] 威胁告警: {path}\n  细节: {desc}\n  处理: {action}\n")

    scheduler.on_threat = threat_notify
    scheduler.start()

    print("调度器已启动，按 Ctrl+C 停止...")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n正在停止...")
    finally:
        scheduler.stop()


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    run_scheduler_from_config()