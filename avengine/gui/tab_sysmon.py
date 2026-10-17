"""
gui/tab_sysmon.py - Sysmon 标签页

职责：
  * 展示 ops.sysmon_state()：SysmonDrv 是否已安装、驱动/服务状态、本机该用哪个 exe、
    是否属于 Windows 7 兼容模式、scripts\\sysmon_config.xml 是否存在
  * 安装 / 应用配置（ops.sysmon_install 内部按已装与否选 -i / -c）、卸载（二次确认）
  * 把事件通道（sysmon.channel）写回 config.yaml，并可查看该通道最近 5 条事件
  * 非管理员时页面顶部给出醒目提示，并禁用安装 / 卸载

线程约定（与 app.run_task 一致）：所有外部命令都封在 ops 里，且都在 work() 子线程里跑；
work() 绝不能碰任何 Tk 控件，输出一律放进返回的 OpResult.output，由 on_done（主线程）显示。
"""

from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, ttk
from typing import Any, Callable, Dict, List, Tuple

from .. import configwrite
from ..paths import CONFIG_FILE
from . import ops, theme
from .widgets import Card, OutputPane, StatusPill, ToolTip, button_row

# 事件通道候选值。ttk.Combobox 不设 state="readonly"，所以也允许手工输入其它通道名。
CHANNEL_CHOICES = ("Microsoft-Windows-Sysmon/Operational",)

# 需要管理员权限的按钮文案（非管理员时置灰）
ADMIN_ONLY_BUTTONS = ("安装 / 应用配置", "卸载")


class SysmonTab(ttk.Frame):
    """Sysmon 页。"""

    def __init__(self, master, app):
        super().__init__(master, padding=10)
        self.app = app
        # admin_state() 只是 IsUserAnAdmin()，很轻，可以同步取
        self._admin = ops.admin_state()
        self._fields: Dict[str, ttk.Label] = {}
        self._buttons: Dict[str, ttk.Button] = {}
        self._refreshing = False

        self._build_notice()
        self._build_status()
        self._build_actions()
        self._build_output()
        self.on_config_reloaded()
        # 首屏状态：sysmon_state() 会跑 sc query，必须异步，不能阻塞 UI 线程
        self.after(200, self.refresh)

    # ---------------- 布局 ----------------

    def _build_notice(self) -> None:
        """非管理员时的置顶提示（管理员时 pack_forget）。"""
        self.notice = ttk.Label(
            self,
            text="注意：当前不是管理员权限，安装 / 卸载 Sysmon 不可用。"
                 "请点主窗口右上角「以管理员身份重启」后再操作。",
            foreground=theme.LEVEL_COLORS["warn"], wraplength=900, justify="left")
        if not self._admin:
            self.notice.pack(fill="x", pady=(0, 6))

    def _build_status(self) -> None:
        card = Card(self, title="状态")
        card.pack(fill="x")
        self.status_card = card
        body = ttk.Frame(card)
        body.grid(row=0, column=0, sticky="ew")
        body.columnconfigure(1, weight=1)

        head = ttk.Frame(body)
        head.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 4))
        ttk.Label(head, text="SysmonDrv:", style="Sub.TLabel").pack(side="left")
        self.install_pill = StatusPill(head, "查询中…", "unknown")
        self.install_pill.pack(side="left", padx=(6, 0))

        rows = (
            ("driver", "驱动服务 SysmonDrv:", "查询中…"),
            ("driver_state", "驱动当前状态:", "查询中…"),
            ("service_state", "Sysmon 服务状态:", "查询中…"),
            ("windows", "系统版本 / 架构:", "查询中…"),
            ("exe", "本机应使用的 exe:", "查询中…"),
            ("legacy", "Windows 7 兼容模式:", "查询中…"),
            ("config", "配置文件:", "查询中…"),
            ("channel", "config.yaml 事件通道:", "查询中…"),
        )
        row = 1
        for key, label, value in rows:
            row = self._add_field(body, row, key, label, value)
        ttk.Label(body,
                  text="数据来源: ops.sysmon_state()（刷新只查询状态，不改动系统）",
                  style="Hint.TLabel").grid(row=row, column=0, columnspan=2,
                                            sticky="w", pady=(4, 0))

    def _add_field(self, master, row: int, key: str, label: str, value: str = "") -> int:
        """一行"标签: 值"；值控件的引用存进 self._fields[key]，刷新时只改文本/颜色。"""
        ttk.Label(master, text=label, width=20, anchor="w", style="Sub.TLabel").grid(
            row=row, column=0, sticky="w", pady=1)
        widget = ttk.Label(master, text=value, anchor="w", wraplength=780, justify="left")
        widget.grid(row=row, column=1, sticky="w", pady=1)
        self._fields[key] = widget
        return row + 1

    def _build_actions(self) -> None:
        card = Card(self, title="操作")
        card.pack(fill="x", pady=(8, 0))

        row = ttk.Frame(card)
        row.grid(row=0, column=0, sticky="ew")
        # button_row 的按钮引用拿不到，这里需要按权限启停，所以自己建按钮 + ToolTip
        for label, command, tip, need_admin in (
            ("安装 / 应用配置", self._install,
             "未安装时用 -i 安装，已安装则用 -c 应用 scripts\\sysmon_config.xml（需管理员）", True),
            ("卸载", self._uninstall,
             "执行 Sysmon.exe -accepteula -u，卸载驱动与服务（需管理员，会二次确认）", True),
            ("刷新状态", self.refresh, "只读取状态，不改动系统", False),
        ):
            button = ttk.Button(row, text=label, command=command)
            if need_admin and not self._admin:
                button.state(["disabled"])
            button.pack(side="left", padx=(0, 6))
            ToolTip(button, tip)
            self._buttons[label] = button

        channel_row = ttk.Frame(card)
        channel_row.grid(row=1, column=0, sticky="ew", pady=(10, 0))
        ttk.Label(channel_row, text="事件通道:", style="Sub.TLabel").pack(side="left")
        self.channel_var = tk.StringVar(value=CHANNEL_CHOICES[0])
        self.channel_box = ttk.Combobox(channel_row, textvariable=self.channel_var,
                                        values=list(CHANNEL_CHOICES), width=42)
        self.channel_box.pack(side="left", padx=(6, 6))
        ToolTip(self.channel_box, "下拉是默认通道，也可以手工输入其它通道名（不需要管理员）")
        button_row(channel_row, [
            ("写入 config.yaml", self._write_channel,
             "把 sysmon.channel 写回 config.yaml（按行改写，保留注释与其它字段）"),
        ]).pack(side="left")
        button_row(channel_row, [
            ("查看最近 5 条事件", self._query_events,
             "用 wevtutil 查询该通道最近 5 条事件，结果追加到下方输出面板"),
        ]).pack(side="left", padx=(6, 0))

    def _build_output(self) -> None:
        self.pane = OutputPane(self, height=12, title="命令输出")
        self.pane.pack(fill="both", expand=True, pady=(8, 0))

    # ---------------- 状态刷新 ----------------

    def refresh(self) -> None:
        """
        后台读取 Sysmon 状态（内部会执行 sc query 等外部命令）。

        silent=True：不占用主窗口的"忙碌"标志，避免与其它页面的任务互相顶掉；
        状态栏仍会显示"正在读取 Sysmon 状态…"。
        """
        if self._refreshing:
            return
        self._refreshing = True

        def work() -> ops.OpResult:
            try:
                return ops.OpResult(True, "Sysmon 状态已刷新", "", ops.sysmon_state())
            except Exception as exc:  # noqa: BLE001 - 后台异常必须转成结果
                return ops.OpResult(False, "读取 Sysmon 状态失败: {}".format(exc))

        def done(result: ops.OpResult) -> None:
            self._refreshing = False
            if not result.ok:
                self.app.show_result("Sysmon 状态", result, self.pane)
                return
            self._apply_state(result.data)
            self.app.set_status(result.message)

        self.app.run_task("正在读取 Sysmon 状态…", work, done, silent=True)

    def _apply_state(self, state: Dict[str, Any]) -> None:
        installed = bool(state.get("driver_installed"))
        self.install_pill.set("已安装" if installed else "未安装",
                              "ok" if installed else "warn")
        self._set("driver", "已安装（服务 SysmonDrv 已注册）" if installed else "未安装",
                  "ok" if installed else "warn")

        driver_state = str(state.get("driver_state") or "")
        self._set("driver_state", driver_state or "未知（驱动未运行或服务不存在）",
                  "ok" if driver_state.upper() == "RUNNING" else "unknown")

        service_state = str(state.get("service_state") or "")
        self._set("service_state", service_state or "未知（服务不存在）",
                  "ok" if service_state.upper() == "RUNNING" else "unknown")

        windows = str(state.get("windows") or "?")
        arch = str(state.get("arch") or "")
        self._set("windows", "Windows {}{}".format(windows, " / {}".format(arch) if arch else ""),
                  "info")

        exe = str(state.get("exe") or "")
        exe_exists = bool(state.get("exe_exists"))
        self._set("exe", "{}（{}）".format(
            exe, "存在" if exe_exists else "不存在，请按系统版本放入 bina\\Sysmon\\ 或 bina\\Sysmon\\sysmonwin7\\"),
            "ok" if exe_exists else "error")

        legacy = bool(state.get("legacy_expected"))
        self._set("legacy", "是（Win7 / 2008 R2 需用 bina\\Sysmon\\sysmonwin7\\ 里的 13.x）"
                            if legacy else "否（使用现代版 Sysmon）", "info")

        config_exists = bool(state.get("config_exists"))
        self._set("config", "{}（{}）".format(state.get("config_xml") or "",
                                             "存在" if config_exists else "不存在"),
                  "ok" if config_exists else "error")

    def _set(self, key: str, text: str, level: str = "unknown") -> None:
        widget = self._fields.get(key)
        if widget is None:
            return
        widget.configure(text=text,
                         foreground=theme.LEVEL_COLORS.get(level, theme.LEVEL_COLORS["unknown"]))

    def _apply_admin(self, admin: bool) -> None:
        """权限变化时同步顶部提示与安装 / 卸载按钮。"""
        self._admin = bool(admin)
        if self._admin:
            self.notice.pack_forget()
        else:
            # 用 before= 放回原来的位置（否则会跑到输出面板下面）
            self.notice.pack(fill="x", pady=(0, 6), before=self.status_card)
        for label in ADMIN_ONLY_BUTTONS:
            button = self._buttons.get(label)
            if button is None:
                continue
            button.state(["!disabled"] if self._admin else ["disabled"])

    # ---------------- 主窗口钩子 ----------------

    def on_status(self, status: Dict[str, Any]) -> None:
        """主窗口收集完状态后回调：只关心权限，再顺手刷新本页自己的状态。"""
        self._apply_admin(status.get("admin", self._admin))
        self.refresh()

    def on_config_reloaded(self) -> None:
        """config.yaml 重新加载后：同步通道下拉框与状态卡里的通道值。"""
        config = self.app.config_data or {}
        channel = str((config.get("sysmon") or {}).get("channel") or "").strip()
        if not channel:
            channel = CHANNEL_CHOICES[0]
        self.channel_var.set(channel)
        self._set("channel", channel, "info")

    def append_output(self, text: str) -> None:
        """主窗口/其它页面转发过来的输出。"""
        self.pane.append(text)

    # ---------------- 操作 ----------------

    def _run_action(self, label: str, work: Callable[[], ops.OpResult],
                    refresh_after: bool = True) -> None:
        """统一入口：把 ops 里的操作丢到后台线程，回来后写输出面板并按需刷新状态。"""
        def done(result: ops.OpResult) -> None:
            self.app.show_result(label, result, self.pane)
            if refresh_after:
                self.refresh()

        self.app.run_task("{}…".format(label), work, done)

    def _install(self) -> None:
        """未安装 -> -i 安装；已安装 -> -c 应用配置（ops.sysmon_install 内部判断）。"""
        self._run_action("安装 / 应用 Sysmon 配置", ops.sysmon_install)

    def _uninstall(self) -> None:
        if not messagebox.askyesno(
                "确认卸载 Sysmon",
                "将执行：\n  Sysmon.exe -accepteula -u\n\n"
                "这会停止并卸载 Sysmon 驱动（SysmonDrv）与 Sysmon 服务，实时监控随之失效；\n"
                "已记录的事件日志不会被删除。\n\n确定继续？",
                parent=self):
            return
        self._run_action("卸载 Sysmon", ops.sysmon_uninstall)

    def _config_scalars(self, section: str, key: str, value: Any) -> Dict[Tuple[str, str], Any]:
        """
        组装 write_config_yaml 需要的 scalars 映射。

        configwrite 是逐行改写，没提供的键本来也不会丢；这里仍按 YAML_SCALAR_KEYS 把当前
        config.yaml 里已有的标量原样带上，只覆盖要改的那一个键，避免误以为会丢字段。
        """
        config = self.app.config_data or {}
        scalars: Dict[Tuple[str, str], Any] = {}
        for sec, name in configwrite.YAML_SCALAR_KEYS:
            node = config.get(sec)
            if isinstance(node, dict) and name in node:
                scalars[(sec, name)] = node[name]
        scalars[(section, key)] = value
        return scalars

    def _monitor_paths(self) -> List[str]:
        """monitor_paths 由 write_config_yaml 整块重写，必须原样带上，否则会被清空。"""
        scan = (self.app.config_data or {}).get("scan") or {}
        return [str(p) for p in (scan.get("monitor_paths") or [])]

    def _write_channel(self) -> None:
        """把下拉框里的通道写回 config.yaml，然后重新加载配置（普通权限即可）。"""
        channel = self.channel_var.get().strip()
        if not channel:
            messagebox.showwarning("事件通道", "通道名不能为空，例如 Microsoft-Windows-Sysmon/Operational")
            return
        scalars = self._config_scalars("sysmon", "channel", channel)
        monitor_paths = self._monitor_paths()

        def work() -> ops.OpResult:
            try:
                backup = configwrite.write_config_yaml(CONFIG_FILE, scalars, monitor_paths)
            except OSError as exc:
                return ops.OpResult(False, "写入 config.yaml 失败: {}".format(exc))
            detail = "已写入 {}：sysmon.channel = {}".format(CONFIG_FILE, channel)
            if backup:
                detail += "\n原文件已备份: {}".format(backup)
            return ops.OpResult(True, "事件通道已保存", detail)

        def done(result: ops.OpResult) -> None:
            self.app.show_result("写入事件通道", result, self.pane)
            if result.ok:
                self.app.reload_config()   # 触发各页 on_config_reloaded，通道立即生效
                self.app.set_status("已写入 sysmon.channel = {}".format(channel))

        self.app.run_task("正在写入 config.yaml…", work, done)

    def _query_events(self) -> None:
        """
        查询该通道最近 5 条事件。

        这里选 wevtutil 而不是 `eventvwr.msc`：eventvwr.msc 没有可靠的"直接定位到某个通道"
        命令行参数，而 wevtutil qe 的结果能直接显示在输出面板里。
        """
        channel = self.channel_var.get().strip() or CHANNEL_CHOICES[0]

        def work() -> ops.OpResult:
            code, out = ops.run(["wevtutil", "qe", channel, "/c:5", "/rd:true", "/f:text"],
                                timeout=60)
            ok = code == 0
            message = "{} 最近 5 条事件{}".format(
                channel, "已显示在输出面板" if ok else "查询失败（退出码 {}）".format(code))
            return ops.OpResult(ok, message,
                                out or "（没有返回内容：通道可能为空，或需要管理员权限）")

        self.app.run_task("正在查询 {} 最近事件…".format(channel), work,
                          lambda result: self.app.show_result("Sysmon 事件", result, self.pane))
