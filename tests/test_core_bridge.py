"""C++ 内核 (avengine_core.dll) 绑定测试；DLL 未构建时整体跳过。"""

from __future__ import annotations

import hashlib
import time
from pathlib import Path

import pytest

from avengine import core_bridge

pytestmark = pytest.mark.skipif(
    not core_bridge.is_available(),
    reason="avengine_core.dll 未构建（先运行 cpp/build.bat）",
)

EICAR = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

RULE = (
    "rule EicarTest\n"
    "{\n"
    "    strings:\n"
    '        $a = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" ascii\n'
    "    condition:\n"
    "        $a\n"
    "}\n"
)


def _make_rules(root: Path) -> Path:
    rules = root / "rules"
    rules.mkdir()
    (rules / "eicar.yar").write_text(RULE, encoding="utf-8")
    return rules


def test_version_nonempty():
    assert core_bridge.version()


def test_sha256_matches_hashlib(tmp_path: Path):
    p = tmp_path / "a.txt"
    p.write_bytes(b"hello world")
    result = core_bridge.sha256(p)
    assert result["sha256"] == hashlib.sha256(b"hello world").hexdigest()


def test_scan_path_detects_eicar(tmp_path: Path):
    rules = _make_rules(tmp_path)
    sample = tmp_path / "eicar.txt"
    sample.write_text(EICAR + "\n", encoding="utf-8")

    result = core_bridge.scan_path(sample, rules_path=str(rules))
    assert result["verdict"] == "infected"
    assert "EicarTest" in result["yara"]["matches"]
    assert result["yara"]["available"] is True


def test_scan_path_clean_file(tmp_path: Path):
    rules = _make_rules(tmp_path)
    sample = tmp_path / "clean.txt"
    sample.write_text("harmless content\n", encoding="utf-8")

    result = core_bridge.scan_path(sample, rules_path=str(rules))
    assert result["verdict"] == "clean"
    assert result["yara"]["matches"] == []


def test_scan_dir(tmp_path: Path):
    rules = _make_rules(tmp_path)
    samples = tmp_path / "samples"
    samples.mkdir()
    (samples / "bad.txt").write_text(EICAR + "\n", encoding="utf-8")
    (samples / "good.txt").write_text("clean\n", encoding="utf-8")

    result = core_bridge.scan_dir(samples, rules_path=str(rules))
    assert result["scanned"] == 2
    assert len(result["infected"]) == 1
    assert result["infected"][0].endswith("bad.txt")


def test_scan_missing_file_raises(tmp_path: Path):
    with pytest.raises(core_bridge.CoreError):
        core_bridge.scan_path(tmp_path / "nope.txt", rules_path=None)


def test_monitor_timer_scan_and_quarantine(tmp_path: Path):
    rules = _make_rules(tmp_path)
    samples = tmp_path / "samples"
    samples.mkdir()
    bad = samples / "bad.txt"
    bad.write_text(EICAR + "\n", encoding="utf-8")
    quarantine = tmp_path / "quarantine"

    core_bridge.monitor_start(
        rules_path=str(rules),
        quarantine_dir=str(quarantine),
        clamav=None,
        monitor_paths=[str(samples)],
        timer_interval=1,
        on_access=False,  # 不依赖 Sysmon，用定时扫描验证常驻逻辑
    )
    try:
        assert core_bridge.monitor_running() is True

        events = []
        deadline = time.time() + 10
        while time.time() < deadline and not events:
            events = core_bridge.monitor_poll(50)
            time.sleep(0.3)

        assert events, "监控未在超时内上报威胁"
        event = events[0]
        assert event["path"].endswith("bad.txt")
        assert "EicarTest" in event["yara"]
        assert event["action"] == "quarantined"
        assert not bad.exists(), "命中文件应已被隔离移动"
        assert core_bridge.monitor_status()["threats"] >= 1
    finally:
        core_bridge.monitor_stop()

    assert core_bridge.monitor_running() is False
