"""
gui/tab_monitor.py - 实时监控页

实时监控 = C++ 内核的常驻线程（Sysmon 事件驱动 + 定时扫描）。它跑在本进程里，
所以：
  * 启动/停止都要管理员权限
  * 事件用 `core_bridge.monitor_poll()` 取，用 Tk 的 after 循环轮询（非阻塞，代价很小）
  * 检出可以当场隔离，隔离动作丢到后台线程（避免拷贝大文件时卡界面）
"""

from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, ttk
from typing import Any, Dict, List

from .. import core_bridge
from ..paths import resolve_path
from . import theme
from .ops import OpResult, admin_state, quarantine_paths
from .widgets import Card, OutputPane, StatusPill, ToolTip

POLL_MS = 800


class MonitorTab(ttk.Frame):
    """实时监控控制台。"""

    def __init__(self, master, app):
        super().__init__(master, padding=10)
        self.app = app
        self.columnconfigure(0, weight=1)
        self.rowconfigure(2, weight=1)
        self._polling = False
        self._detections: List[Dict[str, Any]] = []

        control = Card(self, "监控控制")
        control.grid(row=0, column=0, sticky="ew")
        self.pill = StatusPill(control, "监控: 未运行", "unknown")
        self.pill.grid(row=0, column=0, sticky="w")

        buttons = ttk.Frame(control)
        buttons.grid(row=0, column=1, sticky="e", padx=(12, 0))
        self.start_button = ttk.Button(buttons, text="启动监控", command=self.start_monitor)
        self.start_button.pack(side="left", padx=(0, 6))
        self.stop_button = ttk.Button(buttons, text="停止监控", command=self.stop_monitor)
        self.stop_button.pack(side="left", padx=(0, 6))
        ttk.Button(buttons, text="清空事件", command=self.clear_events).pack(side="left")
        control.columnconfigure(2, weight=1)

        self.auto_quarantine = tk.BooleanVar(value=False)
        ttk.Checkbutton(control, text="检出后自动隔离", variable=self.auto_quarantine).grid(
            row=1, column=0, columnspan=2, sticky="w", pady=(8, 0))

        self.env_label = ttk.Label(control, text="", style="Hint.TLabel",
                                   wraplength=940, justify="left")
        self.env_label.grid(row=2, column=0, columnspan=3, sticky="w", pady=(6, 0))

        # ---------- 事件表 ----------
        events = Card(self, "检出事件")
        events.grid(row=2, column=0, sticky="nsew", pady=(6, 0))
        events.columnconfigure(0, weight=1)
        events.rowconfigure(0, weight=1)
        self.tree = ttk.Treeview(events, columns=("time", "path", "detail", "action"),
                                 show="headings", height=10)
        for key, title, width in (("time", "时间", 90), ("path", "文件", 430),
                                  ("detail", "命中", 250), ("action", "处置", 160)):
            self.tree.heading(key, text=title)
            self.tree.column(key, width=width, anchor="w")
        self.tree.grid(row=0, column=0, sticky="nsew")
        scroll = ttk.Scrollbar(events, orient="vertical", command=self.tree.yview)
        scroll.grid(row=0, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=scroll.set)

        action_row = ttk.Frame(events)
        action_row.grid(row=1, column=0, sticky="ew", pady=(6, 0))
        ttk.Button(action_row, text="隔离选中", command=self.quarantine_selected).pack(side="left")
        ttk.Button(action_row, text="分析选中（AI）", command=self.analyze_selected).pack(
            side="left", padx=(6, 0))
        ToolTip(action_row.winfo_children()[-1], "把该检出交给 AI 做处置建议（需要 config.ini 已配置）")

        log = Card(self, "监控输出")
        log.grid(row=3, column=0, sticky="nsew", pady=(6, 0))
        self.pane = OutputPane(log, height=6)
        self.pane.pack(fill="both", expand=True)

    # ---------------- 钩子 ----------------

    def append_output(self, text: str) -> None:
        self.pane.append(text)

    def on_config_reloaded(self) -> None:
        self._update_env()

    def on_status(self, status: Dict[str, Any]) -> None:
        running = bool(status.get("monitor_running")) or core_bridge.monitor_running()
        self._set_running(running)
        self._update_env()

    def on_close(self) -> None:
        self._polling = False

    # ---------------- 内部 ----------------

    def _set_running(self, running: bool) -> None:
        self.pill.set("监控: {}".format("运行中" if running else "未运行"),
                      "ok" if running else "unknown")
        self.start_button.state(["disabled"] if running else ["!disabled"])
        self.stop_button.state(["!disabled"] if running else ["disabled"])

    def _update_env(self) -> None:
        config = self.app.config_data or {}
        scan = config.get("scan") or {}
        paths = scan.get("monitor_paths") or []
        channel = (config.get("sysmon") or {}).get("channel", core_bridge.DEFAULT_SYSMON_CHANNEL)
        pieces = [
            "Sysmon 通道: {}".format(channel),
            "按访问扫描: {}".format("开" if scan.get("on_access") else "关"),
            "定时扫描: {}".format("每 {} 秒".format(scan.get("timer_interval"))
                                 if scan.get("timer_enabled") else "关"),
            "监控目录: {}".format(", ".join(str(p) for p in paths) if paths else "（未配置）"),
        ]
        if not admin_state():
            pieces.append("⚠ 实时监控需要管理员权限")
        self.env_label.configure(text="\n".join(pieces))

    # ---------------- 启停 ----------------

    def start_monitor(self) -> None:
        if not admin_state():
            messagebox.showwarning("实时监控", "实时监控需要管理员权限：请点右上角「以管理员身份重启」。")
            return
        if not core_bridge.is_available():
            messagebox.showerror("实时监控", "C++ 内核未加载: {}".format(core_bridge.load_error()))
            return
        config = self.app.config_data or {}
        scan = config.get("scan") or {}
        rules = (config.get("yara") or {}).get("rules_path")
        quarantine = (config.get("quarantine") or {}).get("path", "./quarantine")
        channel = (config.get("sysmon") or {}).get("channel", core_bridge.DEFAULT_SYSMON_CHANNEL)
        paths = [str(resolve_path(p)) for p in (scan.get("monitor_paths") or [])]
        clam = config.get("clamav") or {}
        timer = int(scan.get("timer_interval", 0) or 0) if scan.get("timer_enabled") else 0
        on_access = bool(scan.get("on_access", True))

        def work() -> OpResult:
            try:
                core_bridge.monitor_start(rules, quarantine, clam, channel, paths, timer, on_access)
            except core_bridge.CoreError as exc:
                return OpResult(False, "启动监控失败: {}".format(exc))
            return OpResult(True, "监控已启动")

        def done(result: OpResult) -> None:
            self.pane.append(result.message)
            if not result.ok:
                messagebox.showwarning("实时监控", result.message)
                return
            self._set_running(True)
            self._start_polling()
            self.app.refresh_status()

        self.app.run_task("正在启动实时监控…", work, done)

    def stop_monitor(self) -> None:
        def work() -> OpResult:
            try:
                core_bridge.monitor_stop()
            except Exception as exc:  # noqa: BLE001
                return OpResult(False, "停止监控失败: {}".format(exc))
            return OpResult(True, "监控已停止")

        def done(result: OpResult) -> None:
            self._polling = False
            self._set_running(core_bridge.monitor_running())
            self.pane.append(result.message)
            self.app.refresh_status()

        self.app.run_task("正在停止实时监控…", work, done)

    # ---------------- 事件轮询 ----------------

    def _start_polling(self) -> None:
        if self._polling:
            return
        self._polling = True
        self.after(POLL_MS, self._poll_once)

    def _poll_once(self) -> None:
        if not self._polling:
            return
        try:
            events = core_bridge.monitor_poll(50)
        except Exception as exc:  # noqa: BLE001 - 轮询失败不该中断界面
            self.pane.append("轮询失败: {}".format(exc))
            events = []
        for event in events or []:
            self._add_event(event)
        if not core_bridge.monitor_running():
            self._polling = False
            self._set_running(False)
            self.pane.append("监控已停止。")
            return
        self.after(POLL_MS, self._poll_once)

    def _add_event(self, event: Dict[str, Any]) -> None:
        path = str(event.get("path", ""))
        details = ["YARA: {}".format(rule) for rule in (event.get("yara") or [])]
        if event.get("clamav"):
            details.append("ClamAV: {}".format(event["clamav"]))
        detail = " | ".join(details)
        action = event.get("quarantined_to") or ""
        item = self.tree.insert("", "end", values=(
            str(event.get("time", ""))[-8:], path, detail, "已隔离" if action else "待处置"))
        self._detections.append(dict(event, _item=item))
        self.pane.append("[检出] {} {}".format(path, detail))
        if self.auto_quarantine.get() and not action:
            self._quarantine([path])
        elif not self.auto_quarantine.get():
            self.app.set_status("实时监控检出: {}".format(path))

    def clear_events(self) -> None:
        for item in self.tree.get_children():
            self.tree.delete(item)
        self._detections.clear()

    # ---------------- 处置 ----------------

    def _selected_paths(self) -> List[str]:
        paths = []
        for item in self.tree.selection():
            values = self.tree.item(item, "values")
            if values and values[1]:
                paths.append(values[1])
        return paths

    def quarantine_selected(self) -> None:
        paths = self._selected_paths()
        if not paths:
            messagebox.showinfo("隔离", "请先在列表里选中要隔离的文件")
            return
        self._quarantine(paths)

    def _quarantine(self, paths: List[str]) -> None:
        config = self.app.config_data or {}

        def work() -> OpResult:
            moved = quarantine_paths(paths, config)
            result = OpResult(True, "已隔离 {} 个文件".format(len(moved)))
            result.output = "\n".join("{} -> {}".format(a, b) for a, b in moved)
            result.data["moved"] = moved
            return result

        def done(result: OpResult) -> None:
            self.pane.append("── 隔离 ──")
            self.pane.append(result.output or "（没有文件被移动）")
            for source, _dest in result.data.get("moved", []):
                for item in self.tree.get_children():
                    if self.tree.item(item, "values")[1] == source:
                        self.tree.set(item, "action", "已隔离")
            self.app.refresh_status()

        self.app.run_task("正在隔离…", work, done)

    def analyze_selected(self) -> None:
        paths = self._selected_paths()
        if not paths:
            messagebox.showinfo("AI 分析", "请先在列表里选中一条检出")
            return
        if not self.app.status_data.get("ai_active"):
            messagebox.showinfo("AI 分析", "AI 未启用：请到「设置」页填写 base_url / model / api_key 并启用。")
            return
        # 跳到 AI 页并预填问题
        ai_page = self.app.tabs.get("AI 分析")
        jump = getattr(ai_page, "ask_about_detection", None)
        if callable(jump):
            self.app.notebook.select(ai_page)
            jump(paths[0])
