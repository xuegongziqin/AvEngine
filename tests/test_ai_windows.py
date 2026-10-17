"""
窗口工具回归测试（list_windows / get_window_detail / close_window）。

核心价值：弹窗的"所属进程"经常是红鲱鱼——恶意代码可能在注入到别的进程的 DLL 里
注册窗口类、处理消息。所以断言必须覆盖"能定位到具体模块"这件事：

  * class_module  注册窗口类的模块（GCLP_HMODULE，跨进程可读）
  * class_wndproc 类 WndProc（GCLP_WNDPROC，跨进程可读）——真正处理消息的代码
  * wndproc       实例 WndProc（GWLP_WNDPROC）跨进程会被系统拒绝（错误 5），
                  此时必须给出解释而不是静默为 null

另外覆盖：签名误报防护（系统目录内文件不因 catalog 校验不可用被判"未签名"）、
close_window 的护栏（dry-run 不投递、拒绝 WM_DESTROY、非法参数）。
注意：测试绝不真正关闭任何窗口。
"""

from __future__ import annotations

import json
import os
import pathlib
import sys

import pytest

PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "tests"))

from avengine import core_bridge  # noqa: E402
from test_ai_tools_ext import MY_PID, _run  # noqa: E402

pytestmark = pytest.mark.skipif(
    not core_bridge.is_available(), reason="avengine_core.dll 未构建（先运行 cpp/build.bat）"
)


def _json_or_error(text):
    if text.startswith("ERROR"):
        return None
    return json.loads(text)


def _live_windows(tmp_path, limit=6):
    """
    返回当前桌面仍然存活的窗口：[(list_item, detail), ...]。
    桌面是活的，窗口随时会被销毁（tooltip/弹出层尤其短命），所以必须先验证再使用。
    """
    _, ev = _run(tmp_path, "list_windows",
                 {"scope": "desktop", "visible_only": True, "limit": limit})
    data = _json_or_error(ev["detail"])
    if data is None:
        pytest.skip("list_windows 返回错误: " + ev["detail"][:120])
    live = []
    for w in data.get("windows", []):
        _, ev2 = _run(tmp_path, "get_window_detail", {"hwnd": w["hwnd"]})
        if ev2["detail"].startswith("ERROR"):
            continue   # 调用间隙里被销毁了，换下一个
        live.append((w, json.loads(ev2["detail"])))
    if not live:
        pytest.skip("当前桌面没有稳定存在的可见窗口（无交互会话）")
    return live


def _first_window(tmp_path, **extra):
    """取一个仍然存活的窗口条目，供过滤/关闭类用例复用。"""
    return _live_windows(tmp_path)[0][0]


# ------------------------------------------------------------------ list_windows


def test_list_windows_basic_shape(tmp_path):
    _, ev = _run(tmp_path, "list_windows", {"scope": "desktop", "limit": 5})
    data = _json_or_error(ev["detail"])
    assert data is not None, ev["detail"][:200]
    for key in ("count", "matched", "scope", "windows", "diagnostics"):
        assert key in data, key
    assert data["scope"] == "desktop"
    if not data["windows"]:
        pytest.skip("当前桌面没有窗口（无交互会话）")
    w = data["windows"][0]
    for key in ("hwnd", "class", "pid", "tid", "visible", "style", "ex_style"):
        assert key in w, key
    assert w["hwnd"].startswith("0x")
    # 定位模块用的两个指针必须存在（值可以为 null，但要解释）
    assert "class_module" in w and "class_wndproc" in w and "wndproc" in w


def test_list_windows_auto_scope_is_version_aware(tmp_path):
    """auto：Win10+ 走窗口站/桌面全枚举，Win7/8 只枚举当前桌面。"""
    _, ev = _run(tmp_path, "list_windows", {"limit": 1})
    data = _json_or_error(ev["detail"])
    assert data is not None, ev["detail"][:200]
    major = data["diagnostics"]["windows_os_major"]
    expected = "all" if major >= 10 else "desktop"
    assert data["scope"] == expected, data["diagnostics"]


def test_list_windows_class_and_title_filters(tmp_path):
    first = _first_window(tmp_path)
    cls = first["class"]
    _, ev = _run(tmp_path, "list_windows",
                 {"scope": "desktop", "class_contains": cls, "limit": 20})
    data = json.loads(ev["detail"])
    assert data["count"] >= 1
    for w in data["windows"]:
        assert cls.lower() in w["class"].lower()

    _, ev = _run(tmp_path, "list_windows",
                 {"scope": "desktop", "title_contains": "绝不存在的标题zzz", "limit": 5})
    data = json.loads(ev["detail"])
    assert data["count"] == 0
    assert "note" in data


def test_list_windows_pid_filter_excludes_our_process(tmp_path):
    """测试进程自己没有窗口：按自己的 pid 过滤应当返回 0 条。"""
    _, ev = _run(tmp_path, "list_windows", {"pid": MY_PID, "limit": 10})
    data = _json_or_error(ev["detail"])
    if data is None:
        pytest.skip("list_windows 不可用")
    assert data["count"] == 0
    for w in data["windows"]:
        assert w["pid"] == MY_PID


def test_list_windows_rejects_bad_scope(tmp_path):
    _, ev = _run(tmp_path, "list_windows", {"scope": "bogus"})
    text = ev["detail"]
    assert text.startswith("ERROR") and "scope" in text


def test_list_windows_module_attribution(tmp_path):
    """
    类模块/类 WndProc 至少要有一个能归到具体模块上——这正是"弹窗是谁弹的"的答案。
    """
    first = _first_window(tmp_path)
    cm = first.get("class_module") or {}
    cwp = first.get("class_wndproc") or {}
    assert "base" in cm
    if cm.get("base"):
        assert "in_module_list" in cm
        if cm["in_module_list"]:
            assert cm.get("module"), cm
            assert cm.get("path"), cm
            # 系统目录内文件若报无签名，必须带 catalog 说明，不能直接当可疑
            if cm.get("signature") == "no_signature":
                assert "signature_note" in cm, cm
    if cwp.get("addr"):
        assert "in_module_list" in cwp


def test_list_windows_wndproc_cross_process_is_explained(tmp_path):
    """
    跨进程读实例 WNDPROC 会被系统拒绝（错误 5）——必须解释清楚，不能静默 null。
    """
    first = _first_window(tmp_path)
    wp = first.get("wndproc") or {}
    if wp.get("addr"):
        pytest.skip("该窗口属于本进程，实例 WNDPROC 可读")
    assert "error" in wp, wp
    assert ("错误 5" in wp["error"]) or ("class_wndproc" in wp["error"])


# ------------------------------------------------------------- get_window_detail


def test_get_window_detail_full_picture(tmp_path):
    first, data = _live_windows(tmp_path)[0]
    for key in ("hwnd", "class", "pid", "thread", "owner_chain", "parent_chain",
                "class_module", "class_wndproc", "wndproc", "hung", "diagnostics",
                "next_steps", "process_module_count", "process_unsigned_modules_sample"):
        assert key in data, key
    assert data["hwnd"] == first["hwnd"]
    assert isinstance(data["owner_chain"], list)
    assert isinstance(data["parent_chain"], list)
    # 线程信息：起始地址要么给出，要么说明权限不足
    th = data["thread"]
    assert "tid" in th
    assert ("start_address" in th) or ("error" in th)
    # 有模块被归因时才应该有签名校验
    cm = data.get("class_module") or {}
    cwp = data.get("class_wndproc") or {}
    if cm.get("in_module_list") or cwp.get("in_module_list"):
        assert data["diagnostics"]["signature_checks"] >= 1


def test_module_list_never_silently_empty(tmp_path):
    """
    模块列表读不到时必须给出原因，绝不能静默返回空表——否则每个窗口都会被误判成
    "模块不在 loader 列表里"（安全工具最忌讳的误报）。这条同时覆盖 Toolhelp 失败时
    回退 PSAPI 的路径。
    """
    _, data = _live_windows(tmp_path)[0]
    count = data["process_module_count"]
    if count:
        assert data.get("module_list_source") in ("toolhelp", "psapi"), data.get("module_list_source")
        assert not data.get("module_list_error")
    else:
        assert data.get("module_list_error"), "列表为空却没有错误说明"
        assert "module_list_unavailable" in (data.get("findings") or []), data.get("findings")
        # 读不到列表时不能断言"模块被隐藏"
        for node in (data.get("class_module") or {}, data.get("class_wndproc") or {}):
            assert "not_in_loader_list" not in json.dumps(node), node


def test_get_window_detail_decimal_hwnd_accepted(tmp_path):
    first = _first_window(tmp_path)
    dec = str(int(first["hwnd"], 16))
    _, ev = _run(tmp_path, "get_window_detail", {"hwnd": dec})
    data = _json_or_error(ev["detail"])
    assert data is not None, ev["detail"][:200]
    assert data["hwnd"] == first["hwnd"]


@pytest.mark.parametrize("args", [{}, {"hwnd": "0x7fffff"}, {"hwnd": "not-a-handle"}])
def test_get_window_detail_bad_args(tmp_path, args):
    _, ev = _run(tmp_path, "get_window_detail", args)
    text = ev["detail"]
    assert text.startswith("ERROR"), text
    assert ("hwnd" in text) or ("窗口不存在" in text)


# ------------------------------------------------------------------ close_window


def test_close_window_dry_run_does_not_close(tmp_path):
    first = _first_window(tmp_path)
    hwnd = first["hwnd"]
    _, ev = _run(tmp_path, "close_window",
                 {"hwnd": hwnd, "method": "wm_close", "dry_run": True})
    data = _json_or_error(ev["detail"])
    assert data is not None, ev["detail"][:200]
    assert data["dry_run"] is True
    assert data["planned_message"] == "PostMessage(WM_CLOSE)"
    assert data["hwnd"] == hwnd
    # 窗口必须还在
    _, ev2 = _run(tmp_path, "get_window_detail", {"hwnd": hwnd})
    assert not ev2["detail"].startswith("ERROR"), "dry-run 不应影响窗口"


def test_close_window_rejects_wm_destroy(tmp_path):
    first = _first_window(tmp_path)
    _, ev = _run(tmp_path, "close_window", {"hwnd": first["hwnd"], "method": "wm_destroy"})
    text = ev["detail"]
    assert text.startswith("ERROR"), text
    assert "WM_DESTROY" in text and ("end_task" in text or "wm_close" in text)
    # 并确认窗口没事
    _, ev2 = _run(tmp_path, "get_window_detail", {"hwnd": first["hwnd"]})
    assert not ev2["detail"].startswith("ERROR")


def test_close_window_bad_args(tmp_path):
    _, ev = _run(tmp_path, "close_window", {})
    assert ev["detail"].startswith("ERROR") and "hwnd" in ev["detail"]
    _, ev = _run(tmp_path, "close_window", {"hwnd": "0x0"})
    assert ev["detail"].startswith("ERROR")


def test_close_window_invalid_method(tmp_path):
    first = _first_window(tmp_path)
    _, ev = _run(tmp_path, "close_window", {"hwnd": first["hwnd"], "method": "bogus"})
    assert ev["detail"].startswith("ERROR") and "method" in ev["detail"]


# ------------------------------------------------------------------ 注册表接线


def test_window_tools_registered_and_readonly_flags(tmp_path):
    _, ev = _run(tmp_path, "list_tools", {"category": "窗口"})
    data = json.loads(ev["detail"])
    names = {t["name"]: t["readonly"] for t in data["tools"]}
    assert set(names) == {"list_windows", "get_window_detail", "close_window"}, names
    assert names["list_windows"] is True
    assert names["get_window_detail"] is True
    assert names["close_window"] is False, "close_window 是处置类，必须标记为非只读"
