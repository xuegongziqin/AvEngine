"""
ClamAV 安装包选择回归测试。

规则（三处实现必须一致）：avengine/paths.py `clamav_msi()`、
scripts/setup_clamav.bat 的自动选择、scripts/install.bat、
installer/install.c 的 pick_clamav_msi()：

    Windows 8.1+                    → bina\\clamav.msi       （现代版 1.x）
    Windows 7 SP1 / Server 2008 R2  → bina\\clamwin7\\*.msi   （最后支持 Win7 的版本）
    期望目录为空时用另一套兜底；显式指定则用指定的那套。

另外：**任何系统**都要能选「本机 ClamAV / 远程 clamd / 纯 YARA」，
不再像早期那样只在 Win7 上才给远程选项。
"""

from __future__ import annotations

import pathlib
import subprocess
import sys

import pytest

PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from avengine.paths import (  # noqa: E402
    CLAMAV_LEGACY_VERSIONS,
    clamav_candidates,
    clamav_is_legacy,
    clamav_msi,
)

SCRIPTS = PROJECT_ROOT / "scripts"
SETUP_BAT = SCRIPTS / "setup_clamav.bat"
INSTALL_BAT = SCRIPTS / "install.bat"
INSTALL_C = PROJECT_ROOT / "installer" / "install.c"


def _layout(tmp_path: pathlib.Path, modern: bool = True, legacy: bool = True) -> pathlib.Path:
    (tmp_path / "bina").mkdir(parents=True, exist_ok=True)
    if modern:
        (tmp_path / "bina" / "clamav.msi").write_bytes(b"MSI")
    if legacy:
        (tmp_path / "bina" / "clamwin7").mkdir(parents=True, exist_ok=True)
        (tmp_path / "bina" / "clamwin7" / "clamavwin7.msi").write_bytes(b"MSI")
    return tmp_path


def test_legacy_versions_match_sysmon_rule():
    """ClamAV 与 Sysmon 用同一套版本边界（6.0/6.1 = Vista/2008、7/2008 R2）。"""
    assert CLAMAV_LEGACY_VERSIONS == frozenset({(6, 0), (6, 1)})
    assert clamav_is_legacy((6, 1)) is True
    assert clamav_is_legacy((6, 0)) is True
    assert clamav_is_legacy((6, 3)) is False      # Win8.1
    assert clamav_is_legacy((10, 0)) is False


@pytest.mark.parametrize("version,expect_legacy", [
    ((6, 1), True), ((6, 0), True), ((6, 3), False), ((10, 0), False),
])
def test_clamav_msi_picks_package_by_version(tmp_path, version, expect_legacy):
    root = _layout(tmp_path)
    chosen = clamav_msi(root=root, version=version)
    assert chosen.is_file()
    if expect_legacy:
        assert chosen.parent.name == "clamwin7", chosen
    else:
        assert chosen.parent.name == "bina", chosen


def test_clamav_msi_falls_back_to_the_other_package(tmp_path):
    """只放了一套包时也要能用（Win7 机器上只有现代包，或反之）。"""
    root = _layout(tmp_path, modern=False, legacy=True)
    assert clamav_msi(root=root, version=(10, 0)).parent.name == "clamwin7"
    root2 = _layout(tmp_path / "second", modern=True, legacy=False)
    assert clamav_msi(root=root2, version=(6, 1)).parent.name == "bina"


def test_clamav_candidates_order_prefers_expected_dir(tmp_path):
    root = _layout(tmp_path)
    legacy_first = clamav_candidates(root=root, version=(6, 1))
    assert legacy_first[0].parent.name == "clamwin7"
    modern_first = clamav_candidates(root=root, version=(10, 0))
    assert modern_first[0].parent.name == "bina"


def test_clamav_msi_accepts_any_msi_name(tmp_path):
    """用户丢进 clamwin7\\ 的包可能不叫 clamavwin7.msi —— 任意 *.msi 都要认。"""
    root = tmp_path
    (root / "bina" / "clamwin7").mkdir(parents=True)
    (root / "bina" / "clamwin7" / "clamav-0.103.12-win64.msi").write_bytes(b"MSI")
    chosen = clamav_msi(root=root, version=(6, 1))
    assert chosen.name == "clamav-0.103.12-win64.msi"


def test_setup_clamav_bat_auto_selects_and_honours_explicit_msi(tmp_path):
    """
    --print-package 只打印选择结果（不安装、不需要管理员），便于验证选包逻辑。

    这个入口属于 bat 版脚本（不再有 PowerShell 版）：ClamAV 安装路径刻意不依赖 PowerShell，
    因为 Win7 SP1 自带 PS 2.0，而旧脚本用了 3.0+ 语法 → 解析期失败、整个安装被跳过。
    """
    if not SETUP_BAT.is_file():
        pytest.skip("缺少 scripts/setup_clamav.bat")

    def run(*extra: str) -> str:
        proc = subprocess.run(
            ["cmd", "/c", str(SETUP_BAT), "--print-package", *extra],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            cwd=str(PROJECT_ROOT), timeout=180)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        return (proc.stdout or "").strip().splitlines()[-1].strip()

    auto = run()
    assert auto.lower().endswith(".msi"), auto
    assert pathlib.Path(auto).is_absolute(), auto
    explicit = run("--msi", str(PROJECT_ROOT / "bina" / "clamwin7" / "clamavwin7.msi"))
    assert explicit.endswith("clamavwin7.msi"), explicit


def test_setup_clamav_bat_knows_the_legacy_directory_and_the_version_rule():
    source = SETUP_BAT.read_text(encoding="ascii", errors="replace")
    assert "clamwin7" in source
    assert "--print-package" in source
    assert 'if "%OSVER%"=="6.1" set "WANTS_LEGACY=1"' in source
    assert 'if "%OSVER%"=="6.0" set "WANTS_LEGACY=1"' in source
    # 老陷阱：shift 会把 %0 一起移位，导致后面的 %~dp0 失效（实测过）
    assert 'set "SCRIPT_DIR=%~dp0"' in source
    assert "shift" in source


def test_install_bat_offers_all_three_choices_on_every_os():
    """
    早期 install.bat 在 Win7 上直接拒绝本机安装（只给 LAN / YARA 两个选项）。
    现在三选一在**任何**系统上都给，默认是"本机安装"。
    """
    raw = INSTALL_BAT.read_bytes()
    assert b"\r\n" in raw and len(raw) > 0
    assert all(b < 128 for b in raw), ".bat 必须保持纯 ASCII"
    text = raw.decode("ascii", errors="replace")

    assert "1 = install ClamAV on this machine" in text
    assert "2 = connect to a clamd on another machine" in text
    assert "3 = YARA only" in text
    assert "default 1" in text
    assert "clamwin7" in text
    assert "is not supported here" not in text, "不应再在 Win7 上拒绝本机安装"


def test_installer_c_picks_msi_by_version():
    """一键安装器（install.c）必须用同一套选择规则，而不是写死 bina\\clamav.msi。"""
    source = INSTALL_C.read_text(encoding="utf-8", errors="replace")
    assert "pick_clamav_msi" in source
    assert "clamwin7" in source
    assert "major == 6 && minor <= 1" in source
    assert 'L"\\\\bina\\\\clamav.msi", NULL, NULL, NULL))\n        return STATUS_FAIL;\n\n    /* 1) install MSI */' \
        not in source, "不应再用写死的 MSI 路径作为安装包来源"


def test_gui_reports_both_packages():
    """GUI 的 ClamAV 状态要同时报出两套包是否存在，以及本机默认用哪套。"""
    from avengine.config import load_config
    from avengine.gui import ops

    state = ops.clamav_state(load_config())
    for key in ("modern_msi", "modern_exists", "legacy_msi", "legacy_exists",
                "legacy_expected", "os_version", "package_note", "msi", "msi_exists"):
        assert key in state, key
    assert state["os_version"], state
    assert isinstance(state["legacy_expected"], bool)


def test_gui_install_accepts_package_choice(monkeypatch):
    """ops.clamav_install 支持 auto/modern/legacy，并把选择传给 setup_clamav.bat。"""
    from avengine.gui import ops

    seen = {}

    def fake_bat(script, args=(), timeout=900):
        seen["script"] = str(script)
        seen["args"] = [str(a) for a in args]
        return 0, "ok"

    monkeypatch.setattr(ops, "admin_state", lambda: True)
    monkeypatch.setattr(ops, "run_bat", fake_bat)

    assert ops.clamav_install(3310, "auto").ok
    assert seen["script"].endswith("setup_clamav.bat"), seen["script"]
    assert "--msi" not in seen["args"], "auto 应交给脚本按版本决定"

    assert ops.clamav_install(3310, "legacy").ok
    assert "clamwin7" in " ".join(seen["args"])

    if (PROJECT_ROOT / "bina" / "clamav.msi").is_file():
        assert ops.clamav_install(3310, "modern").ok
        assert "clamwin7" not in " ".join(seen["args"])
