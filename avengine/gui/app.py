"""
gui/app.py - 主窗口

职责（标签页只关心自己那点 UI）：
  * 建立 Notebook，加载所有标签页
  * **后台任务运行器**：外面所有耗时操作都通过 run_task() 丢到线程里执行，
    结果用 queue + after() 回到 Tk 主线程 —— Tk 不是线程安全的，绝不能在子线程里碰控件
  * 共享状态：当前 config、状态栏（提示 + 进度条）、管理员标识
  * 定时刷新：状态页 + 监控事件轮询由各页自己注册 after 回调
"""

from __future__ import annotations

import logging
import queue
import threading
import tkinter as tk
from tkinter import messagebox, ttk
from typing import Any, Callable, Dict, Optional

from ..config import load_config
from ..paths import PROJECT_ROOT
from . import theme
from .ops import OpResult, collect_status, relaunch_elevated


class AvEngineGUI(tk.Tk):
    """AvEngine 主窗口。"""

    def __init__(self, argv: Optional[list] = None):
        super().__init__()
        self.title("AvEngine 控制台")
        self.geometry("1080x760")
        self.minsize(940, 660)
        self.argv = argv or []
        theme.apply(self)
        self.configure(background=theme.BG)

        self.config_data: Dict[str, Any] = {}
        self.status_data: Dict[str, Any] = {}
        self._task_queue: "queue.Queue[tuple]" = queue.Queue()
        self._busy = False
        # 状态栏文本变量要在**任何页面构造之前**就存在：标签页在 __init__ 里就可能调用
        # app.set_status(...)，而状态栏控件是后建的 —— 顺序错了会让整页加载失败
        # （实测：日志页 '_tkinter.tkapp' object has no attribute 'status_var'）。
        self.status_var = tk.StringVar(value="就绪")

        # 用 grid + 权重安排三块区域。**不要用 pack**：标签页的请求高度很高，
        # pack 会把最后压入的状态栏挤成 1px（实测用户看到的"路径被截断"就是这个）。
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)
        self._build_header()
        self._build_notebook()
        self._build_statusbar()
        self._select_initial_tab()
        self.reload_config()
        self.after(100, self._drain_tasks)
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    def _select_initial_tab(self) -> None:
        """支持 `avengine gui --tab 设置` 直接落到指定页。"""
        if "--tab" not in self.argv:
            return
        index = self.argv.index("--tab")
        if index + 1 >= len(self.argv):
            return
        page = self.tabs.get(self.argv[index + 1])
        if page is not None:
            self.notebook.select(page)

    # ---------------- 布局 ----------------

    def _build_header(self) -> None:
        header = ttk.Frame(self, padding=(12, 10, 12, 4))
        header.grid(row=0, column=0, sticky="ew")
        ttk.Label(header, text="AvEngine", style="Header.TLabel").pack(side="left")
        ttk.Label(header, text="YARA + ClamAV + Sysmon 与 AI 分析",
                  style="Hint.TLabel").pack(side="left", padx=(8, 0))

        right = ttk.Frame(header)
        right.pack(side="right")
        self.admin_pill = ttk.Label(right, text="", style="Hint.TLabel")
        self.admin_pill.pack(side="left", padx=(0, 8))
        ttk.Button(right, text="刷新状态", width=10,
                   command=self.refresh_status).pack(side="left", padx=(0, 6))
        self.elevate_button = ttk.Button(right, text="以管理员身份重启", width=18,
                                         command=self.elevate)
        self.elevate_button.pack(side="left")

    def _build_notebook(self) -> None:
        self.notebook = ttk.Notebook(self)
        self.notebook.grid(row=1, column=0, sticky="nsew", padx=10, pady=(4, 6))
        self.notebook.bind("<<NotebookTabChanged>>", self._on_tab_changed)
        self.tabs: Dict[str, Any] = {}
        self._load_tabs()

    def _on_tab_changed(self, _event=None) -> None:
        # 切到较重的页面（设置/日志）时强制一次完整重绘：否则可能残留上一页的像素
        # （用户在截屏里能看到残影，但控件几何本身是对的）
        self.after_idle(self.update_idletasks)
        # 首次进入某页时自动刷新一次状态，免得看到的是"未知/查询中…"（用户实测困惑点）。
        # 页面自己决定怎么刷（都是走 run_task 的异步刷新，不会卡界面）。
        try:
            title = self.notebook.tab(self.notebook.select(), "text")
        except tk.TclError:
            return
        page = self.tabs.get(title)
        for hook_name in ("on_show", "refresh_state", "refresh"):
            hook = getattr(page, hook_name, None)
            if callable(hook):
                self.after(60, hook)
                break

    def _load_tabs(self) -> None:
        """按顺序注册标签页。任何一个页面导入失败都不该拖垮整个 GUI。"""
        from . import (tab_ai, tab_clamav, tab_logs, tab_monitor, tab_scan, tab_service,
                       tab_settings, tab_status, tab_sysmon)

        specs = (
            ("概览", tab_status.StatusTab),
            ("扫描", tab_scan.ScanTab),
            ("实时监控", tab_monitor.MonitorTab),
            ("AI 分析", tab_ai.AiTab),
            ("Sysmon", tab_sysmon.SysmonTab),
            ("ClamAV", tab_clamav.ClamavTab),
            ("特权服务", tab_service.ServiceTab),
            ("设置", tab_settings.SettingsTab),
            ("日志", tab_logs.LogsTab),
        )
        for title, factory in specs:
            try:
                page = factory(self.notebook, self)
            except Exception as exc:  # noqa: BLE001 - 单页失败也要能进 GUI 看原因
                # 页面构造失败会让整页不可用，必须留下可诊断的痕迹（GUI 里显示 + 写日志）
                logging.getLogger(__name__).exception("标签页 %s 加载失败", title)
                page = ttk.Frame(self.notebook)
                ttk.Label(page, text="{} 页加载失败: {}".format(title, exc),
                          foreground=theme.LEVEL_COLORS["error"],
                          wraplength=900, justify="left").pack(padx=12, pady=12)
            self.notebook.add(page, text=title)
            self.tabs[title] = page

    def _build_statusbar(self) -> None:
        bar = ttk.Frame(self, padding=(12, 2, 12, 8))
        bar.grid(row=2, column=0, sticky="ew")
        self.progress = ttk.Progressbar(bar, mode="indeterminate", length=140)
        self.progress.pack(side="left", padx=(0, 8))
        # 先把右侧路径放好再放左侧状态文本：反过来的话状态文本会独占空间，
        # 路径标签被挤成 1px，看起来就是"被截断"。
        ttk.Label(bar, text="项目根: {}".format(PROJECT_ROOT),
                  style="Hint.TLabel").pack(side="right")
        ttk.Label(bar, textvariable=self.status_var, style="Sub.TLabel").pack(
            side="left", fill="x", expand=True)

    # ---------------- 状态/配置 ----------------

    def reload_config(self) -> Dict[str, Any]:
        """重新读取 config.yaml（设置页保存、ClamAV 改 host 之后都要调用）。"""
        self.config_data = load_config()
        for page in self.tabs.values():
            hook = getattr(page, "on_config_reloaded", None)
            if callable(hook):
                try:
                    hook()
                except Exception:  # noqa: BLE001
                    pass
        return self.config_data

    def refresh_status(self) -> None:
        """后台收集状态，回来后分发给所有页面（页面自己决定显示哪些）。"""
        config = self.config_data or load_config()

        def work() -> OpResult:
            data = collect_status(config)
            return OpResult(True, "状态已刷新", "", data)

        def done(result: OpResult) -> None:
            if not result.ok:
                self.set_status("状态刷新失败: {}".format(result.message))
                return
            self.status_data = result.data
            admin = bool(result.data.get("admin"))
            self.admin_pill.configure(
                text="权限: 管理员" if admin else "权限: 普通用户（部分功能不可用）",
                foreground=theme.LEVEL_COLORS["ok" if admin else "warn"])
            for page in self.tabs.values():
                hook = getattr(page, "on_status", None)
                if callable(hook):
                    try:
                        hook(result.data)
                    except Exception:  # noqa: BLE001
                        pass
            self.set_status("状态已刷新")

        self.run_task("正在收集状态…", work, done, silent=True)

    def elevate(self) -> None:
        result = relaunch_elevated()
        if result.ok:
            messagebox.showinfo("提权", result.message)
        else:
            messagebox.showwarning("提权", result.message)

    # ---------------- 后台任务 ----------------

    def run_task(self, label: str, work: Callable[[], OpResult],
                 on_done: Optional[Callable[[OpResult], None]] = None,
                 silent: bool = False) -> None:
        """
        把 work() 放到后台线程执行；完成后在主线程调用 on_done(result)。

        work 里**不能**碰任何 Tk 控件；需要输出就返回在 OpResult 里。
        """
        if self._busy and not silent:
            self.set_status("有任务在执行中，请稍候…")
            return
        if not silent:
            self._busy = True
            self.progress.start(12)
        self.set_status(label)

        def runner() -> None:
            try:
                result = work()
            except Exception as exc:  # noqa: BLE001 - 后台异常必须转成结果
                result = OpResult(False, "任务异常: {}".format(exc))
            self._task_queue.put((result, on_done, silent))

        threading.Thread(target=runner, daemon=True, name="avengine-gui-task").start()

    def _drain_tasks(self) -> None:
        try:
            while True:
                result, on_done, silent = self._task_queue.get_nowait()
                if not silent:
                    self._busy = False
                    self.progress.stop()
                self.set_status(result.message.splitlines()[0] if result.message else "就绪")
                if on_done is not None:
                    try:
                        on_done(result)
                    except Exception as exc:  # noqa: BLE001
                        self.set_status("回调出错: {}".format(exc))
        except queue.Empty:
            pass
        self.after(120, self._drain_tasks)

    def set_status(self, text: str) -> None:
        self.status_var.set(text)

    def show_result(self, title: str, result: OpResult, pane=None) -> None:
        """统一的结果反馈：状态栏 +（可选）输出面板 + 关键失败弹窗。"""
        if pane is not None and result.output:
            pane.append("── {} ──".format(title))
            pane.append(result.output)
        if not result.ok:
            messagebox.showwarning(title, result.message)

    def append_to(self, page_title: str, text: str) -> None:
        """往某个页面的输出面板追加（若该页有 append_output）。"""
        page = self.tabs.get(page_title)
        hook = getattr(page, "append_output", None)
        if callable(hook):
            hook(text)

    # ---------------- 生命周期 ----------------

    def on_close(self) -> None:
        """退出前尽量收尾：停掉进程内的实时监控线程。"""
        try:
            from .. import core_bridge

            if core_bridge.is_available() and core_bridge.monitor_running():
                core_bridge.monitor_stop()
        except Exception:  # noqa: BLE001
            pass
        self.destroy()


def launch(argv: Optional[list] = None) -> int:
    """GUI 入口（CLI 的 gui 子命令与 python -m avengine.gui 都走这里）。"""
    try:
        import tkinter  # noqa: F401 - 先探一次，好给出比 ImportError 更能看懂的提示
    except ImportError as exc:
        print("当前环境没有 tkinter，无法启动图形界面: {}".format(exc))
        print("（打包版需要在 Nuitka 里加 --enable-plugin=tk-inter；"
              "命令行用法仍然可用：avengine status / scan / ai …）")
        return 1
    try:
        app = AvEngineGUI(argv=argv)
    except tkinter.TclError as exc:
        print("无法启动图形界面: {}".format(exc))
        print("（若无桌面会话，请改用命令行：avengine status / scan / ai …）")
        return 1
    app.refresh_status()
    app.mainloop()
    return 0
