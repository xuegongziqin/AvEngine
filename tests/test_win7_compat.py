"""
Windows 7 兼容性回归测试。

项目宣称支持 Win7 SP1，但 Win8/8.1/10 才有的 API 一旦被无条件调用，在 Win7 上
往往表现为「功能直接不可用」而不是编译错误（例如 WinHttpOpen 用了
WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY → Win7 返回错误 87，AI 整个用不了）。
这里用静态检查把已知的坑钉住，避免回归。
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CPP_SRC = PROJECT_ROOT / "cpp" / "src"

# Win8 / 8.1 / 10 才有的 API（出现即为 Win7 潜在故障；确需使用必须带版本回退）
WIN8_ONLY_APIS = [
    "GetSystemTimePreciseAsFileTime",   # Win8
    "GetTempPath2W",                    # Win10 1803+
    "PathCchAppend",                    # Win8
    "PathCchCombine",
    "SetDefaultDllDirectories",         # Win7 需 KB2533623
    "AddDllDirectory",
    "GetThreadInformation",             # Win8
    "GetProcessMitigationPolicy",       # Win8
    "GetPackageFullName",               # Win8
    "InitializeProcThreadAttributeList",  # Vista+ 但常与 Win8 特性混用
    "GetDpiForWindow",                  # Win10
    "WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL",  # HTTP/2，Win10
    "WINHTTP_OPTION_HTTP_PROTOCOL_REQUIRED",
]


def _cpp_files() -> list[Path]:
    return sorted(CPP_SRC.rglob("*.cpp")) + sorted(CPP_SRC.rglob("*.h"))


@pytest.mark.skipif(not CPP_SRC.is_dir(), reason="cpp/src 不存在")
def test_no_win8_only_apis():
    hits = []
    for path in _cpp_files():
        text = path.read_text(encoding="utf-8", errors="replace")
        for api in WIN8_ONLY_APIS:
            if re.search(r"\b" + re.escape(api) + r"\b", text):
                hits.append(f"{path.relative_to(PROJECT_ROOT)}: {api}")
    assert not hits, "发现 Win8+ 专有 API（Win7 上会失败）: " + "; ".join(hits)


@pytest.mark.skipif(not CPP_SRC.is_dir(), reason="cpp/src 不存在")
def test_winhttp_access_type_has_win7_fallback():
    """
    WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY 仅 Win8.1+ 支持：Win7 上 WinHttpOpen
    直接返回 NULL（错误 87）。必须带 DEFAULT_PROXY 回退。
    """
    text = (CPP_SRC / "ai" / "http_client.cpp").read_text(encoding="utf-8", errors="replace")

    calls = re.findall(r"WinHttpOpen\s*\((?:[^;]|\n)*?\)\s*;", text, re.S)
    assert len(calls) >= 2, f"应有多次 WinHttpOpen 调用（先自动代理、失败再回退），实际 {len(calls)}"

    auto_calls = [c for c in calls if "WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY" in c]
    default_calls = [c for c in calls if "WINHTTP_ACCESS_TYPE_DEFAULT_PROXY" in c]
    assert auto_calls, "没有使用 AUTOMATIC_PROXY 的调用"
    assert default_calls, "缺少 Win7 回退用的 DEFAULT_PROXY 调用"

    # 回退必须在自动代理调用之后（同一函数内先试后回退）
    auto_at = text.index(auto_calls[0])
    default_at = text.index(default_calls[0])
    assert default_at > auto_at, "DEFAULT_PROXY 回退应在 AUTOMATIC_PROXY 之后"
    assert default_at - auto_at < 1200, "回退应紧跟自动代理调用"


@pytest.mark.skipif(not CPP_SRC.is_dir(), reason="cpp/src 不存在")
def test_winhttp_sets_tls12_and_reports_error_codes():
    """Win7 默认可能只协商 TLS 1.0；显式允许 TLS 1.2，并且失败信息要带错误码。"""
    text = (CPP_SRC / "ai" / "http_client.cpp").read_text(encoding="utf-8", errors="replace")
    assert "WINHTTP_OPTION_SECURE_PROTOCOLS" in text
    assert "WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2" in text
    assert "ERROR_WINHTTP_SECURE_FAILURE" in text, "应给出 TLS 失败的针对性提示"
    assert "GetLastError()" in text, "错误信息应包含 Win32 错误码"
