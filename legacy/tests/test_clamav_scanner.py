"""clamav_scanner 模块单元测试（不依赖本机 clamd，使用不可达端口）。"""

from __future__ import annotations

from pathlib import Path

from avengine.clamav_scanner import ClamavScanner

UNREACHABLE = {"host": "127.0.0.1", "port": 65099, "timeout": 1}


def test_scanner_degrades_when_clamd_unavailable():
    scanner = ClamavScanner(**UNREACHABLE)
    assert not scanner.is_available
    assert "不可用" in repr(scanner)


def test_unavailable_scanner_is_a_noop(tmp_path: Path):
    scanner = ClamavScanner(**UNREACHABLE)
    sample = tmp_path / "sample.txt"
    sample.write_text("data", encoding="utf-8")
    directory = tmp_path / "dir"
    directory.mkdir()

    assert scanner.scan_file(sample) is None
    assert scanner.scan_directory(directory) == {}
    assert scanner.scan_stream(b"stream") is None
    assert scanner.get_version() is None
    assert scanner.get_database_info() is None
    assert scanner.reload() is False


def test_scan_skips_missing_paths(tmp_path: Path):
    scanner = ClamavScanner(**UNREACHABLE)
    # 即使扫描器不可用，也应先校验路径而不会抛异常
    assert scanner.scan_file(tmp_path / "missing.bin") is None
    assert scanner.scan_directory(tmp_path / "missing_dir") == {}


def test_context_manager_and_close():
    scanner = ClamavScanner(**UNREACHABLE)
    with scanner as inner:
        assert inner is scanner
    assert not scanner.is_available
