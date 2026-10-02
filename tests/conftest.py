"""pytest 公共夹具：保证项目根目录可导入，并提供临时规则/样本/配置。"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

TEST_RULE = """
rule AntierX_Test
{
    strings:
        $a = "TEST_MALWARE_STRING" ascii
        $b = { 58 35 4F 21 50 25 40 41 50 }  // EICAR prefix "X5O!P%@AP"
    condition:
        any of them
}
"""


@pytest.fixture
def rules_dir(tmp_path: Path) -> Path:
    """包含一条测试规则的临时规则目录（与样本目录分离）。"""
    directory = tmp_path / "rules"
    directory.mkdir()
    (directory / "test_rule.yar").write_text(TEST_RULE, encoding="utf-8")
    return directory


@pytest.fixture
def samples_dir(tmp_path: Path) -> Path:
    """存放待扫描样本的目录（位于规则目录之外）。"""
    directory = tmp_path / "samples"
    directory.mkdir()
    return directory


@pytest.fixture
def malicious_file(samples_dir: Path) -> Path:
    """命中测试规则的样本文件。"""
    path = samples_dir / "malicious.txt"
    path.write_text(
        "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*\n"
        "TEST_MALWARE_STRING\n",
        encoding="utf-8",
    )
    return path


@pytest.fixture
def clean_file(samples_dir: Path) -> Path:
    """不命中任何规则的正常文件。"""
    path = samples_dir / "clean.txt"
    path.write_text("hello, this is a harmless file.\n", encoding="utf-8")
    return path


@pytest.fixture
def base_config(rules_dir: Path, tmp_path: Path) -> dict:
    """隔离的最小可用配置（clamd 不可达，避免依赖本机服务）。"""
    return {
        "yara": {"rules_path": str(rules_dir)},
        "clamav": {"host": "127.0.0.1", "port": 65099, "timeout": 1},
        "sysmon": {"channel": "Microsoft-Windows-Sysmon/Operational"},
        "quarantine": {"path": str(tmp_path / "quarantine")},
        "scan": {
            "on_access": False,
            "timer_enabled": False,
            "timer_interval": 3600,
            "monitor_paths": [],
        },
    }
