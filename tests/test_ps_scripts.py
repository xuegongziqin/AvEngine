r"""
config.yaml 改写回归测试（安装脚本走的那条路径）。

历史背景（为什么这组测试必须存在）：

  * `scripts\setup_clamav.ps1` 曾用 PowerShell 5.1 的
    `Get-Content -Raw` + `Set-Content -Encoding UTF8` 读写配置。中文系统上 `Get-Content -Raw`
    按 ANSI 解码，把 UTF-8 的中文注释读成乱码、吞掉 CR，于是 `yara:` / `quarantine:` 等
    顶层键被并进注释，config.yaml 解析失败 —— 而配置一坏，扫描会静默降级。
  * 之后改用 `lib_config_yaml.ps1`（.NET UTF-8 按行改写）修好了编码问题，
    但 **Windows 7 SP1 自带 PowerShell 2.0**，脚本里用了 3.0+ 语法（`-notin` 等），
    在 Win7 上是**解析期**失败，整个安装一步都不执行。
  * 现在统一由 CLI 负责：`avengine config --clamav-host <ip|none> [-clamav-port N]`，
    实现是 `avengine/configwrite.py`（保注释、UTF-8 无 BOM、自动备份、损坏自愈）——
    与 GUI 设置页写回配置用的是同一套代码，安装脚本（scripts\\*.bat）只是调用它。
"""

from __future__ import annotations

import pathlib
import subprocess
import sys

import pytest

PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

SCRIPTS = PROJECT_ROOT / "scripts"
EXAMPLE = PROJECT_ROOT / "config.example.yaml"
SET_CLAMAV_BAT = SCRIPTS / "set_clamav.bat"
SETUP_CLAMAV_BAT = SCRIPTS / "setup_clamav.bat"
LIB_BAT = SCRIPTS / "lib_avengine.bat"


def _run(*args) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-m", "avengine", *args],
                          capture_output=True, text=True, encoding="utf-8",
                          errors="replace", cwd=str(PROJECT_ROOT), timeout=180)


def _make_config(tmp_path: pathlib.Path) -> pathlib.Path:
    cfg = tmp_path / "config.yaml"
    cfg.write_text(EXAMPLE.read_text(encoding="utf-8"), encoding="utf-8")
    return cfg


def test_config_clamav_host_writes_and_validates(tmp_path):
    cfg = _make_config(tmp_path)
    proc = _run("--config", str(cfg), "config", "--clamav-host", "192.168.1.50",
                "--clamav-port", "3311")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "UPDATED: " + str(cfg) in proc.stdout
    assert "CONFIG_OK: " + str(cfg) in proc.stdout

    from avengine.config import load_config, validate_config
    assert validate_config(cfg) is None, validate_config(cfg)
    clam = load_config(cfg)["clamav"]
    assert clam["host"] == "192.168.1.50"
    assert int(clam["port"]) == 3311


def test_config_clamav_none_disables_clamav(tmp_path):
    cfg = _make_config(tmp_path)
    proc = _run("--config", str(cfg), "config", "--clamav-host", "none")
    assert proc.returncode == 0, proc.stdout

    from avengine.config import load_config
    host = load_config(cfg)["clamav"]["host"]
    assert host in ("", None), host


def test_config_rewrite_keeps_comments_and_other_sections(tmp_path):
    """保注释、不动其它段 —— 这是"配置写坏"那个事故的核心断言。"""
    cfg = tmp_path / "config.yaml"
    original = (
        "# 顶层注释：不许丢\n"
        "yara:\n"
        "  rules_path: \"./rules\"   # 行尾注释也不许丢\n"
        "\n"
        "clamav:\n"
        "  host: \"127.0.0.1\"\n"
        "  port: 3310\n"
        "  timeout: 30\n"
        "\n"
        "quarantine:\n"
        "  path: \"./quarantine\"\n"
        "\n"
        "scan:\n"
        "  on_access: true\n"
        "  monitor_paths:\n"
        "    - \"C:\\\\Users\\\\Public\"\n"
        "    - \"C:\\\\Temp\"\n"
    )
    cfg.write_text(original, encoding="utf-8")
    proc = _run("--config", str(cfg), "config", "--clamav-host", "10.0.0.9")
    assert proc.returncode == 0, proc.stdout

    text = cfg.read_text(encoding="utf-8")
    assert "# 顶层注释：不许丢" in text
    assert "# 行尾注释也不许丢" in text
    assert "host: 10.0.0.9" in text or "host: \"10.0.0.9\"" in text
    assert "quarantine:" in text
    # 关键：只改 clamav 时必须**原样保留**监控路径（早期实现传空列表，把条目整段清空了）
    assert "monitor_paths:" in text
    assert "C:\\\\Users\\\\Public" in text, text
    assert "C:\\\\Temp" in text, text
    # 编码：必须是无 BOM 的 UTF-8（BOM 会让 yaml 解析器把第一个键读成 '\ufeffyara'）
    assert not cfg.read_bytes().startswith(b"\xef\xbb\xbf")

    from avengine.config import load_config, validate_config
    assert validate_config(cfg) is None, validate_config(cfg)
    loaded = load_config(cfg)
    assert loaded["yara"]["rules_path"].endswith("rules")
    assert loaded["clamav"]["host"] == "10.0.0.9"
    assert len(loaded["scan"]["monitor_paths"]) == 2, loaded["scan"]["monitor_paths"]


def test_config_clamav_recovers_from_a_corrupted_file(tmp_path):
    """
    历史事故的现场：config.yaml 被写坏（中文注释乱码、顶层键被并进注释）。
    写 clamav 段时必须自愈：备份坏文件 → 从 config.example.yaml 重建 → 再写入。
    """
    cfg = tmp_path / "config.yaml"
    cfg.write_text("yara:\n  rules_path: \"./rules\"\n# ���乱码\nclamav:\n host: x\n",
                   encoding="utf-8")
    proc = _run("--config", str(cfg), "config", "--clamav-host", "127.0.0.1")
    assert proc.returncode == 0, proc.stdout + proc.stderr

    from avengine.config import load_config, validate_config
    assert validate_config(cfg) is None, validate_config(cfg)
    assert load_config(cfg)["clamav"]["host"] == "127.0.0.1"


def test_set_clamav_bat_calls_the_cli_and_needs_no_powershell(tmp_path):
    """安装脚本必须是纯 bat：不调 PowerShell，配置交给 CLI。"""
    for script in (SET_CLAMAV_BAT, SETUP_CLAMAV_BAT, LIB_BAT):
        raw = script.read_bytes()
        assert raw, script
        assert all(b < 128 for b in raw), "{} 必须保持纯 ASCII".format(script.name)
        assert b"\r\n" in raw, "{} 必须是 CRLF".format(script.name)
        for lineno, line in enumerate(raw.decode("ascii", errors="replace").splitlines(), 1):
            if line.strip().lower().startswith("rem"):
                continue      # 注释里解释"为什么不用 PowerShell"是允许的
            assert "powershell" not in line.lower(), \
                "{}:{} 不应调用 PowerShell（Win7 SP1 只有 PS 2.0）: {}".format(
                    script.name, lineno, line.strip())


def test_setup_clamav_bat_prints_the_version_appropriate_package():
    """--print-package 是选包逻辑的测试入口（不安装、不需要管理员）。"""
    if not SETUP_CLAMAV_BAT.is_file():
        pytest.skip("缺少 scripts/setup_clamav.bat")
    proc = subprocess.run(["cmd", "/c", str(SETUP_CLAMAV_BAT), "--print-package"],
                          capture_output=True, text=True, encoding="utf-8",
                          errors="replace", cwd=str(PROJECT_ROOT), timeout=120)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    printed = (proc.stdout or "").strip().splitlines()[-1].strip()
    assert printed.lower().endswith(".msi"), printed
    assert pathlib.Path(printed).is_absolute(), printed

    from avengine.paths import clamav_msi
    assert pathlib.Path(printed) == clamav_msi(), (printed, clamav_msi())

    forced = subprocess.run(
        ["cmd", "/c", str(SETUP_CLAMAV_BAT), "--print-package",
         "--msi", str(PROJECT_ROOT / "bina" / "clamwin7" / "clamavwin7.msi")],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        cwd=str(PROJECT_ROOT), timeout=120)
    assert forced.returncode == 0, forced.stdout
    assert forced.stdout.strip().splitlines()[-1].strip().endswith("clamavwin7.msi")


def test_set_clamav_bat_updates_a_config_file(tmp_path):
    """端到端：bat → CLI → config.yaml（含位置参数形式）。"""
    if not SET_CLAMAV_BAT.is_file():
        pytest.skip("缺少 scripts/set_clamav.bat")
    cfg = _make_config(tmp_path)
    proc = subprocess.run(
        ["cmd", "/c", str(SET_CLAMAV_BAT), "-ClamdHost", "192.168.1.77",
         "-Port", "3312", "-ConfigYaml", str(cfg)],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        cwd=str(PROJECT_ROOT), timeout=180)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    from avengine.config import load_config
    clam = load_config(cfg)["clamav"]
    assert clam["host"] == "192.168.1.77" and int(clam["port"]) == 3312


def test_no_clamav_powershell_scripts_left():
    """PS 版的 ClamAV 安装脚本应当已经移除，避免两套实现漂移。"""
    for name in ("setup_clamav.ps1", "set_clamav.ps1", "lib_config_yaml.ps1"):
        assert not (SCRIPTS / name).is_file(), \
            "{} 已被 bat+CLI 取代，留着会有两套实现".format(name)
    # 新脚本必须存在且被 install.bat 引用
    assert SETUP_CLAMAV_BAT.is_file() and SET_CLAMAV_BAT.is_file() and LIB_BAT.is_file()
    install = (PROJECT_ROOT / "scripts" / "install.bat").read_text(
        encoding="ascii", errors="replace")
    assert "setup_clamav.bat" in install
    assert "set_clamav.bat" in install
    assert "setup_clamav.ps1" not in install


def test_setup_clamav_bat_avoids_parenthesised_programfiles():
    """
    回归守卫：`%ProgramFiles(x86)%` 里**带括号**，在 `if (...)` 块里展开会把 cmd 的
    解析器搞崩。真实现场（Win7）：

        [clamav] Windows 6.1
        此时不应有 \\ClamAV。

    块还没执行就语法报错、整个安装中断。所以两个目录必须先各自解析成变量，
    块里一律用延迟展开 !PF_DIR! / !PF86_DIR!。
    """
    text = SETUP_CLAMAV_BAT.read_text(encoding="ascii", errors="replace")
    assert 'set "PF86_DIR=%ProgramFiles(x86)%"' in text, "必须有一处单行预展开"
    offenders = []
    for lineno, line in enumerate(text.splitlines(), 1):
        if line.strip().lower().startswith("rem"):
            continue
        if "%ProgramFiles(x86)%" in line and 'set "PF86_DIR=' not in line:
            offenders.append("{}: {}".format(lineno, line.strip()))
    assert not offenders, "块里不能展开 %ProgramFiles(x86)%：\n" + "\n".join(offenders)
    assert "!PF86_DIR!\\ClamAV" in text
    assert "!PF_DIR!\\ClamAV" in text
