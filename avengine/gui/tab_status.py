"""
gui/tab_status.py - 概览页

一眼看清"引擎/组件现在什么状态"，并提供最常用的三个动作（扫描、更新病毒库、提权）。
所有数据来自 ops.collect_status()（由主窗口在后台线程收集后分发进来）。
"""

from __future__ import annotations

import os
import tkinter as tk
from tkinter import ttk
from typing import Any, Dict

from ..paths import LOG_DIR
from . import theme
from .ops import admin_state, clamav_reload, clamav_test, clamav_config_values
from .widgets import Card, OutputPane, StatusPill, ToolTip


class StatusTab(ttk.Frame):
    """引擎与组件状态总览。"""

    def __init__(self, master, app):
        super().__init__(master, padding=10)
        self.app = app
        self.columnconfigure(0, weight=1)
        self.columnconfigure(1, weight=1)

        # ---------- 引擎 ----------
        engines = Card(self, "引擎")
        engines.grid(row=0, column=0, sticky="nsew", padx=(0, 6), pady=(0, 6))
        self.core_pill = StatusPill(engines, "C++ 内核: 检查中…")
        self.core_pill.pack(anchor="w", pady=2)
        self.yara_pill = StatusPill(engines, "YARA: 检查中…")
        self.yara_pill.pack(anchor="w", pady=2)
        self.clam_pill = StatusPill(engines, "ClamAV: 检查中…")
        self.clam_pill.pack(anchor="w", pady=2)
        self.sysmon_pill = StatusPill(engines, "Sysmon: 检查中…")
        self.sysmon_pill.pack(anchor="w", pady=2)
        self.monitor_pill = StatusPill(engines, "实时监控: 检查中…")
        self.monitor_pill.pack(anchor="w", pady=2)
        self.detail_label = ttk.Label(engines, text="", style="Hint.TLabel",
                                      wraplength=460, justify="left")
        self.detail_label.pack(anchor="w", pady=(6, 0), fill="x")

        # ---------- 环境 ----------
        env = Card(self, "环境与配置")
        env.grid(row=0, column=1, sticky="nsew", padx=(6, 0), pady=(0, 6))
        self.env_ai = ttk.Label(env, text="AI: 未知", wraplength=460, justify="left")
        self.env_ai.pack(anchor="w", pady=2)
        self.env_config = ttk.Label(env, text="config.yaml: 未知", wraplength=460, justify="left")
        self.env_config.pack(anchor="w", pady=2)
        self.env_quarantine = ttk.Label(env, text="隔离目录: 未知", wraplength=460, justify="left")
        self.env_quarantine.pack(anchor="w", pady=2)
        self.env_paths = ttk.Label(env, text="", style="Hint.TLabel", wraplength=460, justify="left")
        self.env_paths.pack(anchor="w", pady=(6, 0), fill="x")

        # ---------- 快速操作 ----------
        quick = Card(self, "快速操作")
        quick.grid(row=1, column=0, columnspan=2, sticky="nsew", pady=(6, 6))
        row = ttk.Frame(quick)
        row.pack(anchor="w")
        ttk.Button(row, text="开始扫描", command=lambda: self._goto("扫描")).pack(side="left", padx=(0, 6))
        ttk.Button(row, text="实时监控", command=lambda: self._goto("实时监控")).pack(side="left", padx=(0, 6))
        ttk.Button(row, text="AI 分析", command=lambda: self._goto("AI 分析")).pack(side="left", padx=(0, 6))
        ttk.Button(row, text="更新病毒库", command=self.update_db).pack(side="left", padx=(0, 6))
        ttk.Button(row, text="测试 ClamAV", command=self.test_clamav).pack(side="left", padx=(0, 6))
        ttk.Button(row, text="打开日志目录", command=self.open_logs).pack(side="left")
        ToolTip(row.winfo_children()[-1], "打开 {}（日志、AI 转储都在这里）".format(LOG_DIR))

        hint = ttk.Label(
            quick,
            text="提示：Sysmon/ClamAV 的安装、特权服务与全部配置都在对应标签页里（需要管理员权限的按钮会自动置灰）。",
            style="Hint.TLabel", wraplength=900, justify="left")
        hint.pack(anchor="w", pady=(8, 0))

        # ---------- 输出 ----------
        out = Card(self, "最近动作")
        out.grid(row=2, column=0, columnspan=2, sticky="nsew")
        self.rowconfigure(2, weight=1)
        self.pane = OutputPane(out, height=9)
        self.pane.pack(fill="both", expand=True)

    # ---------------- 钩子 ----------------

    def append_output(self, text: str) -> None:
        self.pane.append(text)

    def on_config_reloaded(self) -> None:
        if self.app.status_data:
            self.on_status(self.app.status_data)

    def on_status(self, status: Dict[str, Any]) -> None:
        engines = status.get("engines") or {}
        core_ok = bool(status.get("core_available"))
        self.core_pill.set(
            "C++ 内核: {}".format("已加载 ({})".format(status.get("core_version") or "?")
                                 if core_ok else "未加载"),
            "ok" if core_ok else "error")

        yara = engines.get("yara") or {}
        if yara.get("available"):
            extra = "（跳过 {} 个不兼容文件）".format(yara.get("skipped")) if yara.get("skipped") else ""
            self.yara_pill.set("YARA: 已加载{}".format(extra), "ok")
        elif "yara" in engines:
            self.yara_pill.set("YARA: 未加载（规则目录不可用或为空）", "warn")
        else:
            self.yara_pill.set("YARA: 未知", "unknown")

        clam = engines.get("clamav") or {}
        values = clamav_config_values(self.app.config_data or {})
        if not values["host"]:
            self.clam_pill.set("ClamAV: 已禁用（纯 YARA 模式）", "warn")
        elif clam.get("available"):
            version = clam.get("version")
            self.clam_pill.set("ClamAV: 可用{} ({})".format(
                " ({})".format(version) if version else "", "{}:{}".format(values["host"], values["port"])), "ok")
        elif "clamav" in engines:
            self.clam_pill.set("ClamAV: 不可用 ({}:{})".format(values["host"], values["port"]), "error")
        else:
            self.clam_pill.set("ClamAV: 未知", "unknown")

        # Sysmon 状态单独查（collect_status 里没有，避免它变慢）
        from .ops import sysmon_driver_installed

        if sysmon_driver_installed():
            self.sysmon_pill.set("Sysmon: 已安装（驱动服务 SysmonDrv 存在）", "ok")
        else:
            self.sysmon_pill.set("Sysmon: 未安装（实时监控不可用）", "warn")

        running = bool(status.get("monitor_running"))
        self.monitor_pill.set("实时监控: {}".format("运行中" if running else "未运行"),
                              "ok" if running else "unknown")

        self.env_ai.configure(text="AI: {}".format(status.get("ai_hint") or "未知"))
        config_error = status.get("config_error")
        self.env_config.configure(
            text="config.yaml: {}".format("正常" if not config_error else "解析失败 —— {}".format(config_error)))
        self.env_quarantine.configure(text="隔离目录: {}（{} 个文件）".format(
            status.get("quarantine_dir", "?"), status.get("quarantine_count", 0)))
        paths = status.get("paths") or {}
        self.env_paths.configure(text="项目根: {}\n日志: {}".format(
            paths.get("project_root", "?"), paths.get("log", "?")))

        detail = []
        if not status.get("admin"):
            detail.append("当前是普通用户权限：实时监控、Sysmon/ClamAV 安装、特权服务操作不可用。")
        if not core_ok and status.get("core_error"):
            detail.append("内核未加载原因: {}".format(status.get("core_error")))
        if config_error:
            detail.append("config.yaml 解析失败会让引擎退化为内置默认值，请到「设置」页修好。")
        self.detail_label.configure(text="\n".join(detail))

    # ---------------- 动作 ----------------

    def _goto(self, title: str) -> None:
        page = self.app.tabs.get(title)
        if page is not None:
            self.app.notebook.select(page)

    def update_db(self) -> None:
        values = clamav_config_values(self.app.config_data or {})
        if not values["host"]:
            self.pane.append("ClamAV 已禁用（纯 YARA 模式），无需更新病毒库。")
            return
        self.app.run_task("正在通知 clamd 重载病毒库…",
                          lambda: clamav_reload(values["host"], values["port"], values["timeout"]),
                          lambda result: self.app.show_result("更新病毒库", result, self.pane))

    def test_clamav(self) -> None:
        values = clamav_config_values(self.app.config_data or {})
        self.app.run_task("正在测试 ClamAV 连通…",
                          lambda: clamav_test(values["host"], values["port"], values["timeout"]),
                          lambda result: self.app.show_result("测试 ClamAV", result, self.pane))

    def open_logs(self) -> None:
        try:
            LOG_DIR.mkdir(parents=True, exist_ok=True)
            os.startfile(str(LOG_DIR))  # noqa: S606 - Windows 专用，打开资源管理器
        except OSError as exc:
            self.pane.append("打开日志目录失败: {}".format(exc))
