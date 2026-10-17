"""config 模块单元测试。"""

from __future__ import annotations

from pathlib import Path

from avengine.config import (
    DEFAULT_CONFIG,
    generate_default_config,
    load_config,
    validate_config,
)
from avengine.paths import CONFIG_EXAMPLE_FILE, PROJECT_ROOT


def test_load_config_missing_file(tmp_path: Path):
    assert load_config(tmp_path / "nope.yaml") == {}


def test_load_config_invalid_yaml(tmp_path: Path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("clamav: [unterminated", encoding="utf-8")
    assert load_config(bad) == {}


# 真实事故样本：PowerShell 5.1 用 Get-Content -Raw 按 ANSI 解码再写回后，
# 中文注释乱码、CR 被吞、相邻行合并，顶层键被并进注释 —— PyYAML 报的正是这个错。
CORRUPTED_BY_POWERSHELL = (
    "# AvEngine 閰嶇疆绀轰緥锛堢己澶?config.yaml 鏃朵細鎹鐢熸垚锛?# 鎵€鏈夌浉瀵硅矾寰勫潎鍩轰簬椤圭洰鏍圭洰褰曡В鏋愶紝涓庡綋鍓嶅伐浣滅洰褰曟棤鍏炽€?\n"
    "# YARA 瑙勫垯鐩綍锛堥€掑綊鍔犺浇 .yar / .yara 鏂囦欢锛?yara:\n"
    '  rules_path: "./rules"\n'
    "\n"
    "# clamd 瀹堟姢杩涚▼杩炴帴淇℃伅\n"
    "clamav:\n"
    '  host: "127.0.0.1"\n'
    "  port: 3310\n"
    "  timeout: 30\n"
    "# Sysmon 浜嬩欢閫氶亾\n"
    "sysmon:\n"
    '  channel: "Microsoft-Windows-Sysmon/Operational"\n'
)


def test_validate_config_reports_merged_line_corruption(tmp_path: Path):
    """被写坏的 config.yaml 必须报错（安装脚本据此触发重建）。"""
    broken = tmp_path / "config.yaml"
    broken.write_text(CORRUPTED_BY_POWERSHELL, encoding="utf-8")

    reason = validate_config(broken)
    assert reason and "line 6" in reason
    assert load_config(broken) == {}


def test_validate_config_ok(tmp_path: Path):
    assert validate_config(CONFIG_EXAMPLE_FILE) is None
    assert validate_config(tmp_path / "missing.yaml")


def test_load_config_non_mapping(tmp_path: Path):
    not_dict = tmp_path / "list.yaml"
    not_dict.write_text("- a\n- b\n", encoding="utf-8")
    assert load_config(not_dict) == {}


def test_load_config_resolves_relative_paths(tmp_path: Path):
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        'yara:\n  rules_path: "./rules"\n'
        'quarantine:\n  path: "./quarantine"\n'
        "scan:\n  monitor_paths:\n    - './data'\n",
        encoding="utf-8",
    )
    loaded = load_config(cfg)

    for key in (loaded["yara"]["rules_path"], loaded["quarantine"]["path"]):
        assert Path(key).is_absolute()
        assert PROJECT_ROOT in Path(key).parents or Path(key).parent == PROJECT_ROOT
    assert Path(loaded["scan"]["monitor_paths"][0]).is_absolute()


def test_example_config_is_valid_and_matches_defaults():
    example = load_config(CONFIG_EXAMPLE_FILE)
    assert set(example) == set(DEFAULT_CONFIG)
    assert example["clamav"]["port"] == 3310


def test_generate_default_config(tmp_path: Path):
    target = tmp_path / "config.yaml"
    generate_default_config(target)
    assert target.is_file()
    assert load_config(target)["yara"]["rules_path"]

    # 已存在时不应覆盖
    target.write_text("yara:\n  rules_path: custom\n", encoding="utf-8")
    generate_default_config(target)
    assert "custom" in target.read_text(encoding="utf-8")


def test_generate_default_config_force_backs_up(tmp_path: Path):
    """--force 重建前必须先备份坏文件（avengine config --regenerate 用它自愈）。"""
    target = tmp_path / "config.yaml"
    target.write_text(CORRUPTED_BY_POWERSHELL, encoding="utf-8")

    generate_default_config(target, force=True)

    assert validate_config(target) is None
    assert load_config(target)["clamav"]["port"] == 3310
    backups = list(tmp_path.glob("config.yaml.bak-*"))
    assert len(backups) == 1
    assert "yara:" in backups[0].read_text(encoding="utf-8") or backups[0].stat().st_size > 0
