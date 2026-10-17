"""
gui/tab_scan.py - 扫描页

支持单文件/目录扫描（YARA + ClamAV），结果按行展示，检出后可一键隔离。
扫描在后台线程执行（走 ops.scan_once），UI 只负责收集参数与展示。
"""

from __future__ import annotations

import os
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any, Dict, List

from ..paths import PROJECT_ROOT
from . import theme
from .ops import OpResult, ScanOutcome, quarantine_paths, scan_once
from .widgets import Card, FieldRow, OutputPane, ToolTip


class ScanTab(ttk.Frame):
    """手动扫描。"""

    def __init__(self, master, app):
        super().__init__(master, padding=10)
        self.app = app
        self.columnconfigure(0, weight=1)
        self.rowconfigure(2, weight=1)
        self._last: ScanOutcome = ScanOutcome()

        target = Card(self, "扫描目标")
        target.grid(row=0, column=0, sticky="ew")
        target.columnconfigure(0, weight=1)

        self.path_row = FieldRow(target, "路径", "", browse="浏览…", on_browse=self._browse_file)
        self.path_row.grid(row=0, column=0, sticky="ew")
        self.path_row.entry.bind("<Return>", lambda _e: self.start_scan())
        dir_row = ttk.Frame(target)
        dir_row.grid(row=1, column=0, sticky="ew", pady=(4, 0))
        ttk.Button(dir_row, text="选目录…", width=10, command=self._browse_dir).pack(side="left")
        ttk.Button(dir_row, text="扫项目根", width=10,
                   command=lambda: self._set_path(str(PROJECT_ROOT))).pack(side="left", padx=(6, 0))
        ttk.Button(dir_row, text="扫隔离区", width=10,
                   command=self._scan_quarantine_dir).pack(side="left", padx=(6, 0))
        ToolTip(dir_row.winfo_children()[-1], "扫描 config.yaml 里 quarantine.path 指向的目录")

        self.auto_quarantine = tk.BooleanVar(value=False)
        ttk.Checkbutton(dir_row, text="检出后自动隔离", variable=self.auto_quarantine).pack(
            side="left", padx=(12, 0))

        actions = ttk.Frame(target)
        actions.grid(row=2, column=0, sticky="ew", pady=(8, 0))
        self.scan_button = ttk.Button(actions, text="开始扫描", command=self.start_scan)
        self.scan_button.pack(side="left")
        ttk.Button(actions, text="隔离上次检出", command=self.quarantine_last).pack(side="left", padx=(6, 0))
        self.summary = ttk.Label(actions, text="就绪", style="Sub.TLabel")
        self.summary.pack(side="left", padx=(12, 0))
        self.engines_label = ttk.Label(target, text="", style="Hint.TLabel")
        self.engines_label.grid(row=3, column=0, sticky="w", pady=(4, 0))

        # ---------- 结果 ----------
        results = Card(self, "结果")
        results.grid(row=2, column=0, sticky="nsew", pady=(6, 0))
        results.columnconfigure(0, weight=1)
        results.rowconfigure(0, weight=1)
        columns = ("kind", "path", "detail")
        self.tree = ttk.Treeview(results, columns=columns, show="headings", height=9)
        self.tree.heading("kind", text="来源")
        self.tree.heading("path", text="文件")
        self.tree.heading("detail", text="命中 / 病毒名")
        self.tree.column("kind", width=80, anchor="w", stretch=False)
        self.tree.column("path", width=460, anchor="w")
        self.tree.column("detail", width=260, anchor="w")
        self.tree.grid(row=0, column=0, sticky="nsew")
        scroll = ttk.Scrollbar(results, orient="vertical", command=self.tree.yview)
        scroll.grid(row=0, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=scroll.set)

        log = Card(self, "过程输出")
        log.grid(row=3, column=0, sticky="nsew", pady=(6, 0))
        self.pane = OutputPane(log, height=7)
        self.pane.pack(fill="both", expand=True)

    # ---------------- 钩子 ----------------

    def append_output(self, text: str) -> None:
        self.pane.append(text)

    def on_status(self, status: Dict[str, Any]) -> None:
        engines = status.get("engines") or {}
        yara = engines.get("yara") or {}
        clam = engines.get("clamav") or {}
        self.engines_label.configure(text="引擎状态 — YARA: {} | ClamAV: {}".format(
            "可用" if yara.get("available") else "不可用",
            "可用" if clam.get("available") else "不可用"))

    def on_config_reloaded(self) -> None:
        pass

    # ---------------- 交互 ----------------

    def _set_path(self, value: str) -> None:
        self.path_row.value = value

    def _browse_file(self) -> None:
        path = filedialog.askopenfilename(title="选择要扫描的文件",
                                          initialdir=str(PROJECT_ROOT))
        if path:
            self._set_path(path)

    def _browse_dir(self) -> None:
        path = filedialog.askdirectory(title="选择要扫描的目录", initialdir=str(PROJECT_ROOT))
        if path:
            self._set_path(path)

    def _scan_quarantine_dir(self) -> None:
        target = (self.app.config_data.get("quarantine") or {}).get("path") or "./quarantine"
        self._set_path(str(target))

    # ---------------- 扫描 ----------------

    def start_scan(self) -> None:
        raw = self.path_row.value
        if not raw:
            messagebox.showinfo("扫描", "请先选择文件或目录")
            return
        target = Path(raw).expanduser()
        if not target.exists():
            messagebox.showwarning("扫描", "路径不存在: {}".format(target))
            return

        self.pane.clear()
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.pane.append("扫描目标: {}".format(target))
        self.summary.configure(text="扫描中…")
        self.scan_button.state(["disabled"])
        config = self.app.config_data
        self.app.run_task("正在扫描 {}…".format(target),
                          lambda: self._scan_worker(target, config),
                          self._scan_done)

    def _scan_worker(self, target: Path, config: Dict[str, Any]) -> "OpResult":
        """后台线程：只做扫描，绝不碰控件。"""
        outcome = scan_once(target, config)
        if outcome.aborted:
            summary = "扫描未执行"
        elif outcome.infected:
            summary = "发现 {} 个受感染文件".format(len(outcome.infected))
        else:
            summary = "未发现威胁"
        wrapper = OpResult(not outcome.aborted, summary)
        wrapper.data["outcome"] = outcome
        return wrapper

    def _scan_done(self, result: "OpResult") -> None:
        """主线程：渲染结果。"""
        self.scan_button.state(["!disabled"])
        outcome = result.data.get("outcome") or ScanOutcome(aborted=True)
        self._last = outcome
        for message in outcome.messages:
            self.pane.append(message)
        for warning in outcome.warnings:
            self.pane.append("[警告] {}".format(warning))
        for path, hits in outcome.yara_hits.items():
            self.tree.insert("", "end", values=("YARA", path, ", ".join(hits)))
            self.pane.append("[YARA] {}: {}".format(path, ", ".join(hits)))
        for path, virus in outcome.clam_hits.items():
            self.tree.insert("", "end", values=("ClamAV", path, virus))
            self.pane.append("[ClamAV] {}: {}".format(path, virus))

        engines = " + ".join(outcome.engines) if outcome.engines else "无"
        if outcome.aborted:
            self.summary.configure(text="未执行（见输出）")
            self.pane.append("扫描未执行。")
            return
        if not outcome.infected:
            self.summary.configure(text="未发现威胁 | 引擎: {}".format(engines))
            self.pane.append("未发现威胁。(引擎: {})".format(engines))
            return
        self.summary.configure(text="发现 {} 个受感染文件 | 引擎: {}".format(
            len(outcome.infected), engines))
        self.pane.append("发现 {} 个受感染文件。(引擎: {})".format(len(outcome.infected), engines))
        if self.auto_quarantine.get():
            self.quarantine_last()
        else:
            self.app.set_status("发现 {} 个威胁，可点「隔离上次检出」".format(len(outcome.infected)))

    def quarantine_last(self) -> None:
        infected = self._last.infected
        if not infected:
            messagebox.showinfo("隔离", "上一次扫描没有检出，无需隔离")
            return
        if not messagebox.askyesno("隔离", "将 {} 个文件移入隔离目录？\n{}".format(
                len(infected), "\n".join(infected[:8]) + ("\n…" if len(infected) > 8 else ""))):
            return
        paths: List[str] = list(infected)
        config = self.app.config_data

        def work() -> Any:
            from .ops import OpResult

            moved = quarantine_paths(paths, config)
            result = OpResult(True, "已隔离 {} 个文件".format(len(moved)))
            result.data["moved"] = moved
            result.output = "\n".join("{} -> {}".format(src, dst) for src, dst in moved)
            return result

        def done(result: Any) -> None:
            self.pane.append("── 隔离 ──")
            self.pane.append(result.output or "（没有文件被移动）")
            self.app.set_status(result.message)
            for item in self.tree.get_children():
                values = self.tree.item(item, "values")
                if values and values[1] in paths:
                    self.tree.set(item, "detail", "{}（已隔离）".format(values[2]))
            self.app.refresh_status()

        self.app.run_task("正在隔离…", work, done)
