"""cli 模块单元测试（命令级测试需要 C++ 内核）。"""

from __future__ import annotations

from pathlib import Path

import pytest

from avengine import core_bridge
from avengine.cli import build_parser, cmd_scan, cmd_status, cmd_update_db

requires_core = pytest.mark.skipif(
    not core_bridge.is_available(), reason="avengine_core.dll 未构建（先运行 cpp/build.bat）"
)


def _write_config(path: Path, rules_dir: Path, quarantine: Path) -> Path:
    path.write_text(
        "yara:\n"
        f"  rules_path: {rules_dir}\n"
        "clamav:\n"
        "  host: 127.0.0.1\n"
        "  port: 65099\n"
        "  timeout: 1\n"
        "quarantine:\n"
        f"  path: {quarantine}\n"
        "scan:\n"
        "  monitor_paths: []\n",
        encoding="utf-8",
    )
    return path


@pytest.fixture
def cli_config(tmp_path: Path, rules_dir: Path) -> Path:
    return _write_config(tmp_path / "config.yaml", rules_dir, tmp_path / "quarantine")


def test_parser_subcommands():
    parser = build_parser()

    args = parser.parse_args(["scan", "some/path"])
    assert args.command == "scan" and args.path == "some/path"

    for command in ("monitor", "status", "update-db"):
        assert parser.parse_args([command]).command == command

    assert parser.parse_args([]).command is None


def test_parser_version(capsys):
    with pytest.raises(SystemExit) as exc:
        build_parser().parse_args(["--version"])
    assert exc.value.code == 0
    assert "AvEngine" in capsys.readouterr().out


@requires_core
def test_cmd_status_returns_zero(cli_config: Path):
    assert cmd_status(_Args(config=str(cli_config))) == 0


@requires_core
def test_cmd_scan_clean_file(cli_config: Path, clean_file: Path):
    assert cmd_scan(_Args(config=str(cli_config), path=str(clean_file))) == 0


@requires_core
def test_cmd_scan_detects_threat(cli_config: Path, malicious_file: Path, monkeypatch):
    monkeypatch.setattr("builtins.input", lambda *_: "n")
    assert cmd_scan(_Args(config=str(cli_config), path=str(malicious_file))) == 1
    assert malicious_file.exists(), "用户选择不隔离时文件应保留"


@requires_core
def test_cmd_scan_missing_path(cli_config: Path, tmp_path: Path):
    assert cmd_scan(_Args(config=str(cli_config), path=str(tmp_path / "nope"))) == 1


@requires_core
def test_cmd_update_db_unavailable(cli_config: Path):
    assert cmd_update_db(_Args(config=str(cli_config))) == 1


class _Args:
    """模拟 argparse.Namespace。"""

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)
