"""pytest 公共夹具：保证项目根目录可导入，并提供临时规则/样本/配置。"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


@pytest.fixture(autouse=True)
def _never_call_the_real_ai(monkeypatch):
    """
    测试绝不真的调用 AI。

    为什么必须这样：项目根下的 `config.ini` 是**操作员真实的配置**（带 API key 与
    base_url），而 CLI 的 `scan` 在检出威胁后会调用 `_ai_detection_analysis()` 把检测结果
    交给模型。后果有两个，都是真事：

      * 又慢又花钱，还会随网络/模型行为抖动 —— 一次全量跑里
        `test_cmd_scan_detects_threat` 就偶发失败过：模型真的调用了 `quarantine_file` 工具，
        在测试的隔离目录里留下文件，于是"用户选择不隔离"的断言失败。
      * 测试结果取决于操作员的私有配置，别人机器上跑不出同样结论。

    需要 AI 的测试自己准备假数据（见 test_ai_core.py / test_ai_stream.py 的假 DLL 与 fixture）。
    """
    try:
        import avengine.cli as cli
    except Exception:  # noqa: BLE001 - 环境缺依赖时不影响其它测试
        return
    monkeypatch.setattr(cli, "_ai_detection_analysis", lambda *a, **k: None, raising=False)

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
