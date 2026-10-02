"""config 模块单元测试。"""

from __future__ import annotations

from pathlib import Path

from avengine.config import DEFAULT_CONFIG, generate_default_config, load_config
from avengine.paths import CONFIG_EXAMPLE_FILE, PROJECT_ROOT


def test_load_config_missing_file(tmp_path: Path):
    assert load_config(tmp_path / "nope.yaml") == {}


def test_load_config_invalid_yaml(tmp_path: Path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("clamav: [unterminated", encoding="utf-8")
    assert load_config(bad) == {}


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
