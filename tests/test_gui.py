"""
GUI 测试。

分三层：
  1. configwrite：保注释写回 config.yaml / config.ini，改完必须还能被正常解析
  2. ops：操作层的"命令拼装"与状态解析（用 monkeypatch 拦住真实系统调用）
  3. GUI 冒烟：真的建窗口、逐页切换、销毁（无桌面会话时自动跳过）

第 3 层很有价值：Tkinter 的错误大多在"构建控件 / 切页"时才暴露（拼错的参数、
错误的 pack 顺序、不存在的属性），只做语法检查是查不出来的。
"""

from __future__ import annotations

import json
import os
import pathlib
import sys

import pytest

PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from avengine import configwrite  # noqa: E402
from avengine.aiconfig import load_ai_config  # noqa: E402
from avengine.config import load_config, validate_config  # noqa: E402
from avengine.gui import ops  # noqa: E402
from avengine.paths import AI_CONFIG_EXAMPLE_FILE, CONFIG_EXAMPLE_FILE  # noqa: E402


# --------------------------------------------------------------- configwrite


def test_config_yaml_roundtrip_keeps_comments(tmp_path):
    target = tmp_path / "config.yaml"
    target.write_text(CONFIG_EXAMPLE_FILE.read_text(encoding="utf-8"), encoding="utf-8")
    before = target.read_text(encoding="utf-8")
    comments_before = sum(1 for line in before.splitlines() if line.strip().startswith("#"))

    scalars = {
        ("yara", "rules_path"): "./rules",
        ("clamav", "host"): "192.168.1.50",
        ("clamav", "port"): 3311,
        ("clamav", "timeout"): 45,
        ("sysmon", "channel"): "Microsoft-Windows-Sysmon/Operational",
        ("quarantine", "path"): "./quarantine",
        ("scan", "on_access"): True,
        ("scan", "timer_enabled"): True,
        ("scan", "timer_interval"): 1800,
    }
    backup = configwrite.write_config_yaml(target, scalars, ["D:\\watch", "C:\\Temp\\有 空格"])
    assert validate_config(target) is None
    config = load_config(target)
    assert config["clamav"]["host"] == "192.168.1.50"
    assert config["clamav"]["port"] == 3311
    assert config["clamav"]["timeout"] == 45
    assert config["scan"]["on_access"] is True
    assert config["scan"]["timer_enabled"] is True
    assert config["scan"]["timer_interval"] == 1800
    assert config["scan"]["monitor_paths"] == ["D:\\watch", "C:\\Temp\\有 空格"]

    after = target.read_text(encoding="utf-8")
    assert sum(1 for line in after.splitlines() if line.strip().startswith("#")) == comments_before
    assert backup is not None and backup.is_file(), "写盘前必须备份"


def test_ai_ini_roundtrip_keeps_comments_and_no_quotes(tmp_path):
    target = tmp_path / "config.ini"
    target.write_text(AI_CONFIG_EXAMPLE_FILE.read_text(encoding="utf-8"), encoding="utf-8")
    before = target.read_text(encoding="utf-8")
    comments_before = sum(1 for line in before.splitlines()
                          if line.strip().startswith(("#", ";")))

    configwrite.write_ai_config(
        target,
        {"enabled": True, "base_url": "https://api.deepseek.com/v1",
         "api_key": "sk-abc#123", "model": "deepseek-chat", "timeout": 45,
         "interval": 300, "max_rounds": 8, "max_events_per_batch": 150,
         "max_event_chars": 700, "max_tool_result_chars": 9000, "scan_analysis": False},
        {"sysmon": True, "process": False, "network": True, "dns": False,
         "powershell": True, "system": False, "application": True, "fileio": False})

    cfg = load_ai_config(target)
    assert cfg.enabled is True
    # configparser 不会去引号：URL 绝不能带引号，否则请求地址就错了
    assert cfg.base_url == "https://api.deepseek.com/v1"
    assert cfg.api_key == "sk-abc#123"
    assert cfg.model == "deepseek-chat"
    assert (cfg.timeout, cfg.interval, cfg.max_rounds) == (45, 300, 8)
    assert cfg.scan_analysis is False
    assert cfg.sources["process"] is False and cfg.sources["dns"] is False
    assert "process" not in cfg.batch_sources()

    after = target.read_text(encoding="utf-8")
    assert sum(1 for line in after.splitlines()
               if line.strip().startswith(("#", ";"))) >= comments_before - 1


def test_config_yaml_keeps_relative_paths_relative(tmp_path):
    """
    回归守卫：load_config() 会把路径归一化成绝对路径；写回时如果原样写进去，
    用户的 config.yaml 就从 ./rules 变成 E:\\...\\rules，发布目录一搬就失效。
    项目根内的绝对路径必须还原成相对写法，根外的保持绝对。
    """
    from avengine.paths import PROJECT_ROOT

    target = tmp_path / "config.yaml"
    target.write_text(CONFIG_EXAMPLE_FILE.read_text(encoding="utf-8"), encoding="utf-8")
    inside = str(PROJECT_ROOT / "rules")
    outside = r"D:\not\under\root"
    configwrite.write_config_yaml(
        target,
        {("yara", "rules_path"): inside, ("quarantine", "path"): str(PROJECT_ROOT / "quarantine")},
        [str(PROJECT_ROOT / "tests" / "tmpwatch"), outside])
    text = target.read_text(encoding="utf-8")
    assert "./rules" in text, text
    assert str(PROJECT_ROOT / "rules") not in text
    # 断言"解析后的值"，而不是字面文本（YAML 引号风格不该影响语义）
    parsed = load_config(target)
    assert parsed["yara"]["rules_path"] == str(PROJECT_ROOT / "rules")
    assert parsed["scan"]["monitor_paths"][1] == outside, "项目根外的绝对路径不能被改"
    assert configwrite.relativize(inside) == "./rules"
    assert configwrite.relativize(outside) == outside
    assert configwrite.relativize("./already/relative") == "./already/relative"


def test_apply_helpers_create_missing_sections():
    yaml_text = configwrite.apply_config_yaml("yara:\n  rules_path: ./rules\n",
                                              {("clamav", "host"): "10.0.0.9"}, [])
    assert "clamav:" in yaml_text and "10.0.0.9" in yaml_text
    ini_text = configwrite.apply_ai_ini("", {"enabled": True}, {"sysmon": False})
    assert "[ai]" in ini_text and "[sources]" in ini_text


def test_format_scalar_quotes_only_when_needed():
    assert configwrite.format_scalar(True) == "true"
    assert configwrite.format_scalar(3310) == "3310"
    assert configwrite.format_scalar("127.0.0.1") == "127.0.0.1"
    assert configwrite.format_scalar("a: b")[0] in "\"'"          # 需要引号
    assert configwrite.format_scalar(r"D:\watch")[0] in "\"'"     # 反斜杠走单引号，不转义
    assert "\\\\" not in configwrite.format_scalar(r"D:\watch")
    assert configwrite.format_ini_scalar("https://x/v1") == "https://x/v1"
    assert configwrite.format_ini_scalar("multi\nline") == "multi line"


# --------------------------------------------------------------- ops


def test_decode_output_prefers_utf8_then_locale():
    assert ops.decode_output("中文".encode("utf-8")) == "中文"
    assert "?" in ops.decode_output(b"\xff\xfe not utf8") or ops.decode_output(b"\xff\xfe")


def test_service_state_parses_sc_output(monkeypatch):
    sample = ("SERVICE_NAME: clamd\n"
              "        TYPE               : 10  WIN32_OWN_PROCESS\n"
              "        STATE              : 4  RUNNING\n")
    monkeypatch.setattr(ops, "run", lambda *a, **k: (0, sample))
    state = ops.service_state("clamd")
    assert state["exists"] is True and state["state"] == "RUNNING"

    monkeypatch.setattr(ops, "run", lambda *a, **k: (1060, "[SC] OpenService FAILED 1060"))
    assert ops.service_state("nope")["exists"] is False


def test_sysmon_install_picks_flag_by_driver_state(monkeypatch, tmp_path):
    calls = []

    def fake_run(cmd, timeout=120, cwd=None):
        calls.append([str(c) for c in cmd])
        return 0, "ok"

    monkeypatch.setattr(ops, "run", fake_run)
    monkeypatch.setattr(ops, "admin_state", lambda: True)
    monkeypatch.setattr(ops, "sysmon_driver_installed", lambda: False)
    monkeypatch.setattr(ops, "sysmon_exe", lambda: tmp_path / "Sysmon64.exe")
    (tmp_path / "Sysmon64.exe").write_bytes(b"MZ")
    import avengine.gui.ops as ops_module

    monkeypatch.setattr(ops_module, "SYSMON_CONFIG", tmp_path / "sysmon_config.xml")
    (tmp_path / "sysmon_config.xml").write_text("<Sysmon/>", encoding="utf-8")

    result = ops.sysmon_install()
    assert result.ok and "-i" in calls[0], calls

    calls.clear()
    monkeypatch.setattr(ops, "sysmon_driver_installed", lambda: True)
    ops.sysmon_install()
    assert "-c" in calls[0], "已安装时应改用 -c 应用配置"


def test_sysmon_install_requires_admin(monkeypatch):
    monkeypatch.setattr(ops, "admin_state", lambda: False)
    result = ops.sysmon_install()
    assert not result.ok and "管理员" in result.message


def test_clamav_configure_uses_repo_script(monkeypatch):
    """配置改写走 bat（bat 内部再找 CLI），不再经过 PowerShell。"""
    seen = {}

    def fake_bat(script, args=(), timeout=900):
        seen["script"] = str(script)
        seen["args"] = [str(a) for a in args]
        return 0, "ok"

    monkeypatch.setattr(ops, "run_bat", fake_bat)
    result = ops.clamav_configure("192.168.1.50", 3311)
    assert result.ok
    assert seen["script"].endswith("set_clamav.bat")
    assert "-ClamdHost" in seen["args"] and "192.168.1.50" in seen["args"]
    assert "3311" in seen["args"]


def test_clamav_install_requires_admin(monkeypatch):
    monkeypatch.setattr(ops, "admin_state", lambda: False)
    assert not ops.clamav_install().ok


def test_engine_readiness_reports_missing_rules(tmp_path):
    rules_path, clam_cfg, warnings, any_engine = ops.engine_readiness(
        {"yara": {"rules_path": str(tmp_path / "nope")},
         "clamav": {"host": "", "port": 3310, "timeout": 5}})
    assert rules_path.endswith("nope")
    assert clam_cfg == {}
    assert any("YARA" in w for w in warnings)
    assert any_engine is False


def test_scan_once_rejects_missing_path(tmp_path):
    outcome = ops.scan_once(tmp_path / "not-here", {})
    assert outcome.aborted and not outcome.ok


def test_recent_log_lines_handles_missing(monkeypatch, tmp_path):
    import avengine.gui.ops as ops_module

    monkeypatch.setattr(ops_module, "LOG_FILE", tmp_path / "nope.log")
    assert "还没有日志文件" in ops.recent_log_lines()


# --------------------------------------------------------------- GUI 冒烟


EXPECTED_TABS = ["概览", "扫描", "实时监控", "AI 分析", "Sysmon", "ClamAV",
                 "特权服务", "设置", "日志"]

# Tk 的 Variable.__del__ 在 root 销毁后仍可能被 GC 触发，CPython 会记一条
# "main thread is not in main loop" 的 unraisable 警告。这是解释器/Tk 的收尾特性，
# 不是被测代码的问题（变量在 root 之前创建、在其后回收），这里显式忽略以免噪音淹没真失败。
pytestmark = pytest.mark.filterwarnings(
    "ignore::pytest.PytestUnraisableExceptionWarning")


def _make_app():
    tkinter = pytest.importorskip("tkinter")
    from avengine.gui.app import AvEngineGUI

    try:
        app = AvEngineGUI(argv=[])
    except tkinter.TclError as exc:   # 没有桌面会话
        pytest.skip("没有可用桌面会话: {}".format(exc))
    app.withdraw()
    return app


def test_gui_builds_all_tabs():
    """所有标签页都能构建（控件参数写错、依赖了还没建的控件都会在这里炸）。"""
    app = _make_app()
    try:
        titles = [app.notebook.tab(i, "text") for i in range(app.notebook.index("end"))]
        assert titles == EXPECTED_TABS, titles
        for index, title in enumerate(titles):
            app.notebook.select(index)
            app.update_idletasks()
            page = app.tabs.get(title)
            assert page is not None
    finally:
        app.destroy()


def test_no_tab_falls_back_to_error_placeholder():
    """
    回归守卫：任何页面构造失败时，主窗口会把它替换成一个写着"XX 页加载失败: ..."的占位 Frame ——
    Tab 标题看起来还是对的，所以只比标题查不出问题。

    真实案例：标签页在 `_build_statusbar()` 之前构造，日志页在 __init__ 里调用
    app.set_status(...)，于是整页报 `'_tkinter.tkapp' object has no attribute 'status_var'`。
    """
    app = _make_app()
    try:
        broken = []
        for title, page in app.tabs.items():
            for child in page.winfo_children():
                try:
                    text = str(child.cget("text"))
                except Exception:  # noqa: BLE001 - 不是所有控件都有 text
                    continue
                if "页加载失败" in text:
                    broken.append(text)
        assert not broken, "有页面加载失败: {}".format(broken)
    finally:
        app.destroy()


def test_set_status_works_before_and_after_tabs_built():
    """set_status 依赖 status_var，必须在页面构造前后都能安全调用。"""
    app = _make_app()
    try:
        app.set_status("构造后设置状态")
        assert app.status_var.get() == "构造后设置状态"
        # 每个页面都要能在任意时刻调用（页面会在构造期、刷新期用它）
        for page in app.tabs.values():
            hook = getattr(page, "on_status", None)
            if callable(hook):
                hook({})
        app.update()
    finally:
        app.destroy()


def test_gui_switch_through_every_tab():
    """逐页切换并跑一轮事件循环：after 回调、状态分发里的错误都会暴露。"""
    app = _make_app()
    try:
        for index in range(app.notebook.index("end")):
            app.notebook.select(index)
            app.update()
        # 分发一份假状态，各页的 on_status 都要能吃下去
        fake = {"core_available": False, "core_error": "测试", "engines": {},
                "admin": False, "monitor_running": False, "ai_hint": "未配置",
                "ai_active": False, "quarantine_dir": "x", "quarantine_count": 0,
                "config_error": None, "paths": {}}
        app.status_data = fake
        for page in app.tabs.values():
            hook = getattr(page, "on_status", None)
            if callable(hook):
                hook(fake)
        app.update()
    finally:
        app.destroy()


def test_gui_hooks_are_callable():
    """配置重载钩子与 append_output 必须存在且不炸（主窗口会无条件调用）。"""
    app = _make_app()
    try:
        app.reload_config()
        for title, page in app.tabs.items():
            hook = getattr(page, "on_config_reloaded", None)
            if callable(hook):
                hook()
            append = getattr(page, "append_output", None)
            if callable(append):
                append("[测试] {} 输出".format(title))
        app.update()
    finally:
        app.destroy()


def test_gui_statusbar_is_not_squeezed():
    """
    回归守卫：早期用 pack 布局时，标签页的请求高度很高，把最后压入的状态栏挤成 1px，
    表现就是右下角"项目根: E:\\Python\\Antier"被截断。改成 grid + 权重后，
    状态栏与路径标签都必须拿到接近请求尺寸的宽度。
    """
    app = _make_app()
    try:
        app.geometry("1080x760+20+20")
        app.deiconify()
        app.update()
        app.update_idletasks()

        bars = [child for child in app.winfo_children()
                if child.winfo_class() == "TFrame" and child.grid_info().get("row") == 2]
        assert bars, "找不到状态栏（应位于 grid 第 2 行）"
        bar = bars[0]
        assert bar.winfo_height() > 10, "状态栏被压扁了: {}x{}".format(
            bar.winfo_width(), bar.winfo_height())

        labels = [w for w in bar.winfo_children() if w.winfo_class() == "TLabel"]
        path_labels = [w for w in labels if str(w.cget("text")).startswith("项目根")]
        assert path_labels, "状态栏里应有项目根标签"
        label = path_labels[0]
        assert label.winfo_width() >= min(label.winfo_reqwidth(), 100), \
            "路径标签被挤成 {}px（请求 {}px）".format(label.winfo_width(), label.winfo_reqwidth())
    finally:
        app.destroy()


def test_gui_ai_stream_accumulates_chunks_into_lines():
    """
    回归守卫：模型的 content 是**一大段话拆成很多小 chunk** 推过来的。
    早期实现把每个 chunk 当作独立行 append，界面上就变成"一个词一行"（用户截图实测）。
    现在按段落累积、遇换行才落行。
    """
    app = _make_app()
    try:
        tab = app.tabs["AI 分析"]
        for chunk in ["文件", " C:\\x.exe ", "被检出，", "建议立即", "隔离。", "\n第二段落", "继续。"]:
            tab._render_event({"kind": "content", "text": chunk})
        tab._flush_stream()
        text = tab.pane.get()
        assert "文件 C:\\x.exe 被检出，建议立即隔离。" in text, text
        assert "第二段落继续。" in text, text
        # 7 个 chunk 最多落成 3 行（两段 + 尾部），绝不能是 7 行
        assert text.count("\n") <= 3, repr(text)
    finally:
        app.destroy()


def test_gui_ai_drain_has_a_per_tick_budget():
    """
    回归守卫（GUI 卡死那件事）：DLL 在阻塞型工具执行期间仍会推事件，一秒可上千条。
    早期 `_drain_events` 一次 tick 渲染**整个**队列，实测主线程被卡 3.3 秒
    （20ms 的 tick 在 3.3 秒里只跑到 5 次），用户看到的就是"AI 一跑工具 GUI 就卡死"。

    现在 `_drain_now()` 有硬上限：单次调用最多处理 max_events 条，超时即返回 True。
    """
    app = _make_app()
    try:
        tab = app.tabs["AI 分析"]
        for i in range(50):
            tab._events.put({"kind": "content", "text": "第{}行\n".format(i)})

        more = tab._drain_now(budget_ms=0, max_events=10)   # 预算 0ms -> 至少处理 10 条后停
        assert more is True, "队列还有积压时必须返回 True，让调用方立刻再排一次"
        rendered = tab.pane.get().count("\n")
        assert rendered <= 10, "单次 tick 不得渲染超过 max_events 条: {}".format(rendered)

        tab._drain_all()          # 收尾负责把剩下的全部渲染完
        assert tab._events.empty(), "收尾必须排空队列"
        text = tab.pane.get()
        # 末行没有结尾换行（输入的最后一个 \n 是行分隔符）：50 行 -> 49 个 \n
        assert text.count("\n") == 49, text.count("\n")
        assert "第0行" in text and "第49行" in text, text[:120]
    finally:
        app.destroy()


def test_gui_ai_stream_scales_to_many_chunks():
    """
    回归守卫：流式累积不能用字符串 `+=`（O(n²)）。这里灌 5000 条，
    只验证"内容正确 + 全部渲染完"，以及对单次 drain 有上限。
    """
    app = _make_app()
    try:
        tab = app.tabs["AI 分析"]
        for i in range(5000):
            tab._events.put({"kind": "content", "text": "行{} abc\n".format(i)})
        tab._drain_all()
        tab._flush_stream()
        text = tab.pane.get()
        # 5000 行 -> 至少 4999 个换行（末行无结尾换行）
        assert text.count("\n") >= 4999, text.count("\n")
        assert "行0 abc" in text and "行4999 abc" in text, text[:200]
    finally:
        app.destroy()


def test_gui_ai_stream_flushes_before_tool_events():
    """工具调用事件到来前，缓冲的正文必须先落地，否则正文会串到工具行后面。"""
    app = _make_app()
    try:
        tab = app.tabs["AI 分析"]
        tab._render_event({"kind": "content", "text": "正在分析"})
        tab._render_event({"kind": "tool_call", "name": "list_handles", "args": {"pid": 4}})
        tab._render_event({"kind": "tool_result", "name": "list_handles", "detail": "ok", "ms": 5})
        text = tab.pane.get()
        assert text.index("正在分析") < text.index("list_handles"), text
    finally:
        app.destroy()


def test_gui_tab_option_selects_tab():
    tkinter = pytest.importorskip("tkinter")
    from avengine.gui.app import AvEngineGUI

    try:
        app = AvEngineGUI(argv=["--tab", "设置"])
    except tkinter.TclError as exc:
        pytest.skip("没有可用桌面会话: {}".format(exc))
    try:
        app.withdraw()
        app.update_idletasks()
        assert app.notebook.tab(app.notebook.select(), "text") == "设置"
    finally:
        app.destroy()
