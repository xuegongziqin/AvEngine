"""
gui/tab_logs.py - 日志页

一个大的只读输出面板 + 几个小控件：
  * 刷新：后台读 ops.recent_log_lines()（读文件也算"耗时"，统一走 run_task）
  * 自动刷新：勾选后每 2 秒 after 一次；取消勾选 / 页面关闭都会停掉定时器
  * 清空显示：只清屏，不动日志文件
  * 打开日志目录：os.startfile(LOG_DIR)，目录不存在先给出提示

自动刷新用的是 after 循环（只读文本，开销很小），并带 _refreshing / _pending 两个
标志位，避免用户手速太快点出一堆重入的读取。
"""

from __future__ import annotations

import os
import tkinter as tk
from tkinter import messagebox, ttk
from typing import Any, Dict

from ..paths import LOG_DIR, LOG_FILE, PROJECT_ROOT
from .ops import OpResult, recent_log_lines
from .widgets import OutputPane, button_row

# 自动刷新间隔（毫秒）
AUTO_INTERVAL_MS = 2000


class LogsTab(ttk.Frame):
    """日志尾部查看。"""

    def __init__(self, master, app):
        super().__init__(master, padding=10)
        self.app = app
        self.columnconfigure(0, weight=1)
        self.rowconfigure(2, weight=1)

        self._timer_id = None        # after 的 id，取消勾选/关闭时用它取消
        self._closed = False         # on_close 之后不再排新的定时器
        self._refreshing = False     # 正在读日志（防重入）
        self._pending = False        # 读日志期间又被要求刷新，读完再补一次

        self._build_header()
        self._build_toolbar()
        self._build_pane()

        # 首次载入
        self.refresh()

    # ---------------- 布局 ----------------

    def _build_header(self) -> None:
        header = ttk.Frame(self)
        header.grid(row=0, column=0, sticky="ew", pady=(0, 6))
        header.columnconfigure(0, weight=1)
        ttk.Label(header, text="日志", style="Header.TLabel").grid(row=0, column=0, sticky="w")
        self.path_label = ttk.Label(
            header,
            text="日志文件: {}｜目录: {}｜项目根: {}".format(LOG_FILE, LOG_DIR, PROJECT_ROOT),
            style="Hint.TLabel", wraplength=980, justify="left")
        self.path_label.grid(row=1, column=0, sticky="w", pady=(2, 0))

    def _build_toolbar(self) -> None:
        bar = ttk.Frame(self)
        bar.grid(row=1, column=0, sticky="ew", pady=(0, 6))

        row = button_row(bar, [("刷新", self.refresh, "立即重新读取日志尾部")])
        row.pack(side="left")
        for widget in row.winfo_children():
            if isinstance(widget, ttk.Button):
                self.refresh_button = widget

        self.auto_var = tk.BooleanVar(value=False)
        self.auto_check = ttk.Checkbutton(bar, text="自动刷新（每 {} 秒）".format(AUTO_INTERVAL_MS // 1000),
                                          variable=self.auto_var, command=self._on_auto_toggle)
        self.auto_check.pack(side="left", padx=(6, 6))
        self.auto_check.bind("<Destroy>", self._on_destroy, add="+")

        ttk.Button(bar, text="清空显示", command=self.clear,
                   width=10).pack(side="left", padx=(0, 6))
        ttk.Button(bar, text="打开日志目录", command=self.open_log_dir,
                   width=14).pack(side="left", padx=(0, 6))

        self.count_label = ttk.Label(bar, text="", style="Hint.TLabel")
        self.count_label.pack(side="left")

    def _build_pane(self) -> None:
        card = ttk.LabelFrame(self, text="日志尾部（最多 {} 行）".format(400), padding=10)
        card.grid(row=2, column=0, sticky="nsew")
        card.columnconfigure(0, weight=1)
        card.rowconfigure(0, weight=1)
        self.pane = OutputPane(card, height=22, with_clear=False)
        self.pane.grid(row=0, column=0, sticky="nsew")

    # ---------------- 钩子 ----------------

    def on_status(self, status: Dict[str, Any]) -> None:
        """状态钩子：顺手把配置文件名与项目根显示出来（可选信息，缺失就跳过）。"""
        if not isinstance(status, dict):
            return
        paths = status.get("paths") or {}
        self.path_label.configure(text="日志文件: {}｜目录: {}｜项目根: {}｜配置: {}".format(
            LOG_FILE, LOG_DIR, paths.get("project_root", PROJECT_ROOT),
            paths.get("config", "?")))

    def append_output(self, text: str) -> None:
        self.pane.append(text)

    def on_close(self) -> None:
        """主窗口退出前调用：停掉自动刷新定时器，避免 after 回调打在已销毁的控件上。"""
        self._closed = True
        self.stop_auto()

    # ---------------- 自动刷新 ----------------

    def _on_auto_toggle(self) -> None:
        if self.auto_var.get():
            self.start_auto()
        else:
            self.stop_auto()

    def start_auto(self) -> None:
        if self._closed or self._timer_id is not None:
            return
        self.refresh()
        self._timer_id = self.after(AUTO_INTERVAL_MS, self._auto_tick)

    def stop_auto(self) -> None:
        if self._timer_id is not None:
            try:
                self.after_cancel(self._timer_id)
            except (tk.TclError, ValueError):
                pass
            self._timer_id = None
        if self.auto_var.get():
            self.auto_var.set(False)

    def _auto_tick(self) -> None:
        self._timer_id = None
        if self._closed or not self.auto_var.get():
            return
        self.refresh()
        if not self._closed and self.auto_var.get():
            self._timer_id = self.after(AUTO_INTERVAL_MS, self._auto_tick)

    def _on_destroy(self, event) -> None:
        if event.widget is self and self._timer_id is not None:
            self.stop_auto()

    # ---------------- 动作 ----------------

    def refresh(self) -> None:
        """后台读取日志尾部（读文件不算快，别放在 UI 线程里）。"""
        if self._refreshing:
            self._pending = True
            return
        self._refreshing = True

        def work() -> OpResult:
            text = recent_log_lines(400)
            lines = [line for line in text.splitlines() if line.strip()]
            return OpResult(True, "日志已刷新（{} 行）".format(len(lines)), text,
                            {"lines": len(lines)})

        def done(result: OpResult) -> None:
            self._refreshing = False
            if not result.ok:
                self.pane.append("读取日志失败: {}".format(result.message))
            else:
                self.pane.clear()
                self.pane.append(result.output)
                self.count_label.configure(text="共 {} 行｜尾部读取时间 {}".format(
                    result.data.get("lines", 0), _now()))
                self.app.set_status("日志已刷新（{} 行）".format(result.data.get("lines", 0)))
            if self._pending:
                self._pending = False
                self.refresh()

        self.app.run_task("正在读取日志…", work, done, silent=True)

    def clear(self) -> None:
        """只清屏（不动日志文件）。"""
        self.pane.clear()
        self.count_label.configure(text="已清空显示（日志文件未改动）")

    def open_log_dir(self) -> None:
        """用资源管理器打开日志目录；目录不存在先提示、不硬开。"""
        if not LOG_DIR.is_dir():
            messagebox.showinfo("打开日志目录", "日志目录还不存在：\n{}\n\n"
                                                "产生日志后（跑一次扫描/监控或启动 AI 分析）再来看。".format(LOG_DIR))
            return
        try:
            if hasattr(os, "startfile"):
                os.startfile(str(LOG_DIR))  # noqa: S606 - Windows 专用
            else:
                messagebox.showinfo("打开日志目录", "当前平台不支持自动打开，请手动访问：\n{}".format(LOG_DIR))
        except OSError as exc:
            messagebox.showwarning("打开日志目录", "打开失败: {}".format(exc))
            self.app.set_status("打开日志目录失败: {}".format(exc))


def _now() -> str:
    from datetime import datetime

    return datetime.now().strftime("%H:%M:%S")
