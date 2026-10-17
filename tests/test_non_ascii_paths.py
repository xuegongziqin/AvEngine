r"""
非 ASCII 路径（中文/日文/西里尔文…）回归测试。

现场故障（AI 反馈）："中文路径无法被文件工具打开（引擎对非 ASCII 路径的兼容缺陷）"。
根因是**编码用错了代码页**：进入内核的路径都是 UTF-8（AI 工具的 JSON 参数、config.yaml、
Python 端 ctypes 都按 UTF-8 传），但 C++ 侧一律按系统 ANSI（中文系统是 CP936）转宽字符，
于是 `C:\用户\文件.txt` 变乱码、CreateFileW 报"找不到文件"。同一类错误散落在多处：

  * ai_util.h: to_wide_sys() 用 CP_ACP           -> 所有 AI 文件工具
  * yara_engine.cpp: fopen() + yr_rules_scan_file()（libyara 内部也是窄 fopen）
  * sha256.cpp: fopen()                          -> 中文文件名哈希为空
  * clamd_client.cpp: 窄 ifstream                -> 中文文件名"ClamAV 扫不了"
  * core.cpp / monitor.cpp: fs::path(窄字符串)    -> 扫描/实时监控/隔离静默漏掉
  * 输出方向：path.string() 返回 ANSI 字节        -> 列表里文件名变乱码

现在统一走 util.h 的 utf8_to_wide_path() / wide_to_utf8()（ai_util.h 转发到同一实现）。
"""

from __future__ import annotations

import json
import pathlib
import sys

import pytest

PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "tests"))

from avengine import core_bridge  # noqa: E402
from test_ai_tools_ext import _run  # noqa: E402

pytestmark = pytest.mark.skipif(
    not core_bridge.is_available(),
    reason="avengine_core.dll 不可用（先跑 cpp/build.bat）",
)

MARKER = "TEST_MALWARE_STRING"
# 注意用拼接而不是 .format()：规则文本里有 YARA 的 $a，花括号也会被 format 当成占位符
RULE_TEXT = ('rule NonAsciiPathTest { strings: $a = "' + MARKER
             + '" condition: $a }')

#: (目录名, 文件名)：中文 / 日文 / 西里尔文
NON_ASCII_NAMES = [
    ("中文目录", "测试文件.txt"),
    ("テスト日本語", "テスト.txt"),
    ("Русский-каталог", "тест-файл.txt"),
]


def _make_sample(tmp_path: pathlib.Path, dirname: str, filename: str,
                 rules_dir: pathlib.Path):
    """建一个含恶意标记的非 ASCII 路径样本；规则目录也支持非 ASCII。"""
    d = tmp_path / dirname
    d.mkdir(parents=True, exist_ok=True)
    f = d / filename
    f.write_text("hello\n" + MARKER + "\n", encoding="utf-8")
    rules_dir.mkdir(parents=True, exist_ok=True)
    (rules_dir / "规则文件.yar").write_text(RULE_TEXT, encoding="utf-8")
    return f


@pytest.mark.parametrize("dirname,filename", NON_ASCII_NAMES)
def test_sha256_and_entropy_on_non_ascii_path(tmp_path, dirname, filename):
    """哈希与熵采样：修好之前是"无法打开文件"/sampled_bytes=0。"""
    rules = tmp_path / "规则"
    f = _make_sample(tmp_path, dirname, filename, rules)

    info = core_bridge.sha256(str(f))
    assert info.get("sha256"), info
    assert len(info["sha256"]) == 64, info

    res = core_bridge.scan_path(str(f), str(rules))
    # 用实际文件大小：Windows 上 write_text 会把 \n 写成 \r\n
    assert res.get("size") == f.stat().st_size
    assert (res.get("entropy") or {}).get("sampled_bytes") > 0, res.get("entropy")


@pytest.mark.parametrize("dirname,filename", NON_ASCII_NAMES)
def test_yara_scan_finds_the_rule_in_a_non_ascii_path(tmp_path, dirname, filename):
    """
    规则目录与目标文件都是非 ASCII 时也必须命中。

    这里同时守着两个修复点：YaraEngine 的规则目录枚举（fs::path 需宽字符），
    以及扫描目标不再走 libyara 的 yr_rules_scan_file（内部窄 fopen）。
    """
    rules = tmp_path / "规则目录"
    f = _make_sample(tmp_path, dirname, filename, rules)

    res = core_bridge.scan_path(str(f), str(rules))
    yara = res.get("yara") or {}
    assert yara.get("rules_count") == 1, yara
    assert yara.get("matches"), res
    assert res.get("verdict") == "infected", res


@pytest.mark.parametrize("dirname,filename", NON_ASCII_NAMES)
def test_read_file_text_opens_non_ascii_path(tmp_path, dirname, filename):
    """AI 现场报的就是这个工具：以前直接回"文件不存在"。"""
    rules = tmp_path / "规则"
    f = _make_sample(tmp_path, dirname, filename, rules)

    _, ev = _run(tmp_path, "read_file_text", {"path": str(f), "length": 200})
    detail = str(ev["detail"])
    assert not detail.startswith("ERROR"), detail
    assert MARKER in detail, detail


def test_file_hash_tool_reports_the_path_as_utf8(tmp_path):
    """输出方向：JSON 里的路径/文件名必须是 UTF-8，不能是 ANSI 乱码。"""
    rules = tmp_path / "规则"
    f = _make_sample(tmp_path, "中文目录", "测试文件.txt", rules)

    _, ev = _run(tmp_path, "file_hash", {"path": str(f)})
    data = json.loads(ev["detail"])
    assert "中文目录" in data["path"], data
    assert len(data["sha256"]) == 64, data


def test_list_files_shows_non_ascii_names(tmp_path):
    """列目录：文件名要能读（path.string() 会给 ANSI 乱码）。"""
    rules = tmp_path / "规则"
    _make_sample(tmp_path, "中文目录", "测试文件.txt", rules)
    _, ev = _run(tmp_path, "list_files", {"dir": str(tmp_path / "中文目录")})
    detail = str(ev["detail"])
    assert not detail.startswith("ERROR"), detail
    assert "测试文件.txt" in detail, detail


def test_quarantine_tool_keeps_non_ascii_name_readable(tmp_path):
    """AI 的隔离工具：中文文件名要能搬进隔离目录，且返回的路径可读。"""
    rules = tmp_path / "规则"
    f = _make_sample(tmp_path, "中文目录", "测试文件.txt", rules)
    quarantine = tmp_path / "隔离目录"

    _, ev = _run(tmp_path, "quarantine_file",
                 {"path": str(f), "reason": "test", "quarantine_dir": str(quarantine)})
    detail = str(ev["detail"])
    assert not detail.startswith("ERROR"), detail
    data = json.loads(detail)
    assert "测试文件" in data["quarantined_to"], data
    assert not f.exists(), "原文件应已移动"
    moved = pathlib.Path(data["quarantined_to"])
    assert moved.is_file(), data
    assert moved.read_text(encoding="utf-8").count(MARKER) == 1


def test_scan_dir_walks_non_ascii_tree(tmp_path):
    """目录递归扫描：中文目录树以前会被整棵跳过（is_directory 判否）。"""
    # 规则目录放在被扫描树之外：规则文件本身含标记串，否则会被自己命中
    rules = tmp_path / "规则"
    tree = tmp_path / "样本树"
    tree.mkdir()
    for dirname, filename in NON_ASCII_NAMES:
        _make_sample(tree, dirname, filename, rules)

    res = core_bridge.scan_dir(str(tree), str(rules))
    infected = res.get("infected") or []
    assert len(infected) == len(NON_ASCII_NAMES), res
    # 命中的路径本身也要是可读的 UTF-8
    for item in infected:
        path = item if isinstance(item, str) else (item.get("path") or "")
        assert any(name in path for _, name in NON_ASCII_NAMES), path

def test_cli_scan_non_ascii_path_without_stdin(tmp_path):
    """
    非交互环境下扫描中文路径：既要有结论，也不能因为读不到 y/n 而崩出 traceback。

    现场：管道/服务里跑 vengine scan <中文目录> 时 input() 抛 EOFError，
    命令以 traceback 结束（结论其实已经打印，但看起来像失败）。
    """
    import subprocess

    rules = tmp_path / "规则"
    f = _make_sample(tmp_path, "中文目录", "测试文件.txt", rules)
    cfg = tmp_path / "config.yaml"
    # as_posix()：YAML 双引号标量里反斜杠是转义字符，直接用正斜杠最省事
    cfg.write_text(
        "yara:\n  rules_path: \"" + rules.as_posix() + "\"\n\n"
        "clamav:\n  host: \"\"\n  port: 3310\n  timeout: 5\n\n"
        "quarantine:\n  path: \"" + (tmp_path / "隔离").as_posix() + "\"\n\n"
        "scan:\n  monitor_paths: []\n",
        encoding="utf-8")

    proc = subprocess.run(
        [sys.executable, "-m", "avengine", "-c", str(cfg), "scan", str(tmp_path / "中文目录")],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        stdin=subprocess.DEVNULL, cwd=str(PROJECT_ROOT), timeout=300)
    out = (proc.stdout or "") + (proc.stderr or "")
    assert "Traceback" not in out, out
    assert "EOFError" not in out, out
    assert proc.returncode == 1, out          # 1 = 发现威胁
    assert "NonAsciiPathTest" in out or "测试文件.txt" in out, out
    assert f.exists(), "没有明确同意时不能动用户的文件"
