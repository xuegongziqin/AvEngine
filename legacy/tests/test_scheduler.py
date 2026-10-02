"""scheduler 模块单元测试。"""

from __future__ import annotations

import time
from pathlib import Path

from avengine.scheduler import ScanJob, Scheduler


def test_init_reads_config(base_config: dict):
    scheduler = Scheduler(base_config)
    assert scheduler.yara_scanner.is_available
    assert scheduler.quarantine_dir == base_config["quarantine"]["path"]
    assert scheduler.monitor_paths == []
    assert not scheduler.timer_enabled
    assert scheduler.on_threat is None


def test_scan_now_quarantines_threat(base_config: dict, malicious_file: Path):
    scheduler = Scheduler(base_config)
    alerts = []
    scheduler.on_threat = lambda path, desc, action: alerts.append((path, desc, action))

    result = scheduler.scan_now(str(malicious_file), "file")

    assert result["yara_matches"] == ["AntierX_Test"]
    assert result["hash"]
    assert not malicious_file.exists()
    assert Path(scheduler.quarantine_dir).is_dir()
    assert alerts and alerts[0][2] == "quarantined"
    assert "AntierX_Test" in alerts[0][1]


def test_scan_now_clean_file(base_config: dict, clean_file: Path):
    scheduler = Scheduler(base_config)
    alerts = []
    scheduler.on_threat = lambda *args: alerts.append(args)

    result = scheduler.scan_now(str(clean_file), "file")

    assert result["yara_matches"] == []
    assert clean_file.exists()
    assert alerts == []


def test_scan_now_directory(base_config: dict, malicious_file: Path, clean_file: Path):
    scheduler = Scheduler(base_config)
    result = scheduler.scan_now(str(malicious_file.parent), "directory")

    hits = result["yara_matches"]
    assert list(hits) == [str(malicious_file)]
    assert not malicious_file.exists()
    assert clean_file.exists()


def test_scan_now_unknown_type(base_config: dict):
    scheduler = Scheduler(base_config)
    result = scheduler.scan_now("whatever", "stream")
    assert result["yara_matches"] == []


def test_worker_loop_processes_enqueued_jobs(
    base_config: dict, malicious_file: Path
):
    scheduler = Scheduler(base_config)
    scheduler.start(enable_sysmon=False, enable_timer=False)
    try:
        scheduler.enqueue(str(malicious_file), job_type="file", source="test")
        deadline = time.time() + 10
        while malicious_file.exists() and time.time() < deadline:
            time.sleep(0.05)
        assert not malicious_file.exists(), "入队任务未被工作线程处理"
    finally:
        scheduler.stop(timeout=5)


def test_scan_job_repr():
    job = ScanJob("/tmp/a", job_type="directory", source="timer")
    assert "directory" in repr(job)
    assert "timer" in repr(job)
