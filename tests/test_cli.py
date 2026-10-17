"""cli 模块单元测试（命令级测试需要 C++ 内核）。"""

from __future__ import annotations

from pathlib import Path

import pytest

from avengine import core_bridge
from avengine.cli import (
    _Namespace,
    _prepare_config,
    build_parser,
    cmd_config,
    cmd_scan,
    cmd_status,
    cmd_update_db,
)
from avengine.config import validate_config

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
def test_cmd_scan_detects_threat(cli_config: Path, malicious_file: Path, monkeypatch,
                                 tmp_path: Path):
    monkeypatch.setattr("builtins.input", lambda *_: "n")
    assert cmd_scan(_Args(config=str(cli_config), path=str(malicious_file))) == 1
    # 断言"没有产生隔离文件"，而不是"样本文件还在"：
    # EICAR 样本会被本机杀软的实时保护删掉（环境行为，与我们的隔离逻辑无关），
    # 早期那种断言会因此在全量运行时偶发失败（单跑通过、连跑失败）。
    quarantine = tmp_path / "quarantine"
    assert (not quarantine.is_dir()) or not any(quarantine.iterdir()), \
        "用户选择不隔离时不应产生任何隔离文件"


@requires_core
def test_cmd_scan_missing_path(cli_config: Path, tmp_path: Path):
    assert cmd_scan(_Args(config=str(cli_config), path=str(tmp_path / "nope"))) == 1


@requires_core
def test_cmd_update_db_unavailable(cli_config: Path):
    assert cmd_update_db(_Args(config=str(cli_config))) == 1


# -------------------- 配置降级 / 菜单崩溃回归 --------------------

def test_prepare_config_accepts_already_loaded_dict():
    """
    回归：交互菜单把已加载的配置字典放进 args.config，
    旧版 _prepare_config 会 Path(dict) 抛 TypeError（菜单第 3、4 项直接崩）。
    """
    config = {"yara": {"rules_path": "rules"}, "clamav": {"host": "127.0.0.1", "port": 3310}}
    assert _prepare_config(_Namespace(config)) == config


@requires_core
def test_cmd_scan_without_any_engine_is_not_reported_clean(tmp_path: Path, capsys):
    """两个引擎都不可用时必须报错退出（2），而不是「未发现威胁」的假阴性。"""
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        "yara:\n"
        f"  rules_path: {tmp_path / 'missing-rules'}\n"
        "clamav:\n"
        "  host: 127.0.0.1\n"
        "  port: 65099\n"
        "  timeout: 1\n"
        "quarantine:\n"
        f"  path: {tmp_path / 'quarantine'}\n",
        encoding="utf-8",
    )
    sample = tmp_path / "sample.txt"
    sample.write_text("harmless\n", encoding="utf-8")

    assert cmd_scan(_Args(config=str(cfg), path=str(sample))) == 2
    out = capsys.readouterr().out
    assert "都不可用" in out and "未发现威胁" not in out


@requires_core
def test_cmd_scan_warns_when_clamav_is_down(cli_config: Path, clean_file: Path, capsys):
    """ClamAV 连不上时照样用 YARA 扫，但必须明确提示引擎缺失。"""
    assert cmd_scan(_Args(config=str(cli_config), path=str(clean_file))) == 0
    out = capsys.readouterr().out
    assert "ClamAV 不可用" in out
    assert "引擎: YARA" in out


# -------------------- config 子命令 --------------------

def test_cmd_config_validate_ok(tmp_path: Path, capsys):
    cfg = tmp_path / "config.yaml"
    cfg.write_text('yara:\n  rules_path: "./rules"\nclamav:\n  port: 3310\n', encoding="utf-8")

    assert cmd_config(_Args(config=str(cfg))) == 0
    assert "CONFIG_OK" in capsys.readouterr().out


def test_cmd_config_validate_invalid(tmp_path: Path, capsys):
    cfg = tmp_path / "config.yaml"
    cfg.write_text("yara:\n  rules_path: [oops\n", encoding="utf-8")

    assert cmd_config(_Args(config=str(cfg))) == 1
    assert "CONFIG_INVALID" in capsys.readouterr().out


def test_cmd_config_regenerate_recovers(tmp_path: Path, capsys):
    cfg = tmp_path / "config.yaml"
    cfg.write_text("yara:\n  rules_path: [oops\n", encoding="utf-8")

    assert cmd_config(_Args(config=str(cfg), regenerate=True, force=True)) == 0
    assert validate_config(cfg) is None
    assert list(tmp_path.glob("config.yaml.bak-*"))


def test_parser_config_subcommand():
    args = build_parser().parse_args(["config", "--regenerate"])
    assert args.command == "config" and args.regenerate is True


class _Args:
    """模拟 argparse.Namespace。"""

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)
