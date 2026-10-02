"""yara_scanner 模块单元测试。"""

from __future__ import annotations

from pathlib import Path

from avengine.paths import RULES_DIR
from avengine.yara_scanner import YaraScanner


def test_unavailable_when_rules_dir_missing(tmp_path: Path):
    scanner = YaraScanner(rules_path=tmp_path / "missing")
    assert not scanner.is_available
    assert scanner.rules_count == 0
    assert scanner.scan_file(tmp_path / "x.txt") == []
    assert scanner.scan_directory(tmp_path) == {}


def test_compile_and_counts(rules_dir: Path):
    scanner = YaraScanner(rules_path=rules_dir)
    assert scanner.is_available
    assert scanner.rules_count == 1
    assert scanner.skipped_count == 0
    assert "已加载" in repr(scanner)


def test_incompatible_rule_is_skipped_not_fatal(rules_dir: Path, malicious_file: Path):
    """单条坏规则只应被跳过，不能让整个规则库失效。"""
    (rules_dir / "broken.yar").write_text(
        'import "pe"\n'
        "rule Broken { condition: pe.number_of_signatures == 0 }\n",
        encoding="utf-8",
    )

    scanner = YaraScanner(rules_path=rules_dir)
    assert scanner.is_available
    assert scanner.rules_count == 1
    assert scanner.skipped_count == 1
    assert any("broken.yar" in f for f in scanner.skipped_files)
    assert scanner.scan_file(malicious_file) == ["AntierX_Test"]


def test_scan_file_hit_and_miss(rules_dir: Path, malicious_file: Path, clean_file: Path):
    scanner = YaraScanner(rules_path=rules_dir)
    assert scanner.scan_file(malicious_file) == ["AntierX_Test"]
    assert scanner.scan_file(clean_file) == []


def test_scan_file_skips_non_existing_and_oversized(rules_dir: Path, tmp_path: Path):
    scanner = YaraScanner(rules_path=rules_dir, max_file_size=4)
    big = tmp_path / "big.txt"
    big.write_text("TEST_MALWARE_STRING", encoding="utf-8")
    assert scanner.scan_file(big) == []
    assert scanner.scan_file(tmp_path / "missing.txt") == []


def test_scan_directory_reports_only_hits(
    rules_dir: Path, malicious_file: Path, clean_file: Path
):
    scanner = YaraScanner(rules_path=rules_dir)
    results = scanner.scan_directory(malicious_file.parent)
    assert list(results) == [str(malicious_file)]
    assert results[str(malicious_file)] == ["AntierX_Test"]

    # 非递归模式同样只报告命中文件
    results = scanner.scan_directory(malicious_file.parent, recursive=False)
    assert str(malicious_file) in results


def test_scan_data_and_string(rules_dir: Path):
    scanner = YaraScanner(rules_path=rules_dir)
    assert scanner.scan_data(b"prefix TEST_MALWARE_STRING suffix") == ["AntierX_Test"]
    assert scanner.scan_data(b"nothing here") == []
    assert scanner.scan_string("TEST_MALWARE_STRING") == ["AntierX_Test"]
    assert scanner.scan_data("not bytes") == []  # type: ignore[arg-type]


def test_reload_rules(rules_dir: Path, tmp_path: Path):
    scanner = YaraScanner(rules_path=rules_dir)
    empty = tmp_path / "empty_rules"
    empty.mkdir()

    assert not scanner.reload_rules(empty)
    assert not scanner.is_available
    assert scanner.reload_rules(rules_dir)
    assert scanner.is_available


def test_context_manager(rules_dir: Path):
    with YaraScanner(rules_path=rules_dir) as scanner:
        assert scanner.is_available
    assert not scanner.is_available


def test_project_rules_compile():
    """真实规则库必须能够编译并可用于扫描。"""
    scanner = YaraScanner(rules_path=RULES_DIR)
    assert scanner.is_available, "项目 rules/ 目录编译失败"
    assert scanner.rules_count > 100

    total = len(
        [p for p in RULES_DIR.rglob("*") if p.suffix in (".yar", ".yara") and p.is_file()]
    )
    assert scanner.rules_count + scanner.skipped_count == total
