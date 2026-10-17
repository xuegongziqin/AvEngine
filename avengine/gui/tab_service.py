"""
gui/tab_service.py - 特权服务页（AvEnginePrivSvc）

干三件事：
  * 把 ops.privsvc_state() 的结果摊开显示 —— 是否已安装、SCM 状态、服务端 exe 是否存在、
    **钉住的证书指纹与安装目录白名单**（--check-pin 的原文）、管道探活结果
  * 装/卸服务、探活
  * "以 SYSTEM 运行"：请求服务以 SYSTEM 令牌启动 avengine.exe <参数>

关于限制（界面里也写了一遍，避免用户以为是 bug）：
调用者必须是**安装目录里被签名的 avengine.exe**，且当前进程已是管理员。从源码树跑
`python -m avengine` 一定会被服务拒绝（CALLER_WRONG_PATH / CALLER_NOT_ADMIN），
所以这里把 OpResult.message 原样显示 —— 里面已经有诊断与处置建议。

所有耗时操作都通过 self.app.run_task 走后台线程；work() 里只调 ops（不碰任何 Tk 控件）。
"""

from __future__ import annotations

import re
import tkinter as tk
from tkinter import messagebox, ttk
from typing import Any, Dict, Optional

from . import theme
from .ops import OpResult, admin_state, privsvc_install, privsvc_ping, privsvc_run_system, privsvc_state
from .widgets import OutputPane, StatusPill, ToolTip, button_row, grid_fields

# 参数里不允许出现的控制字符（服务端也会用 ARGS_REJECTED 再拒一次）
_CONTROL_CHARS = re.compile(r"[\x00-\x1f]")


def validate_int(text: Any, name: str, minimum: Optional[int] = None,
                 maximum: Optional[int] = None) -> "tuple[Optional[int], Optional[str]]":
    """
    校验"整数输入框"的值，返回 (值, 错误说明)；错误说明非 None 时值一定为 None。

    纯函数、不依赖 Tk，便于单测；设置页与特权服务页共用。
    """
    raw = "" if text is None else str(text).strip()
    if not raw:
        return None, "{}不能为空（请填整数）".format(name)
    try:
        value = int(raw, 10)
    except ValueError:
        return None, "{}必须是整数，当前是「{}」".format(name, raw)
    if minimum is not None and value < minimum:
        return None, "{}不能小于 {}".format(name, minimum)
    if maximum is not None and value > maximum:
        return None, "{}不能大于 {}".format(name, maximum)
    return value, None


def _safe_get(getter, key: str, default: Any = "") -> Any:
    """调用取值回调；回调抛异常时退回默认值（控件被销毁等场景）。"""
    try:
        return getter(key)
    except Exception:  # noqa: BLE001
        return default


class ServiceTab(ttk.Frame):
    """特权服务：状态 + 装/卸 + 以 SYSTEM 运行。"""

    def __init__(self, master, app):
        super().__init__(master, padding=10)
        self.app = app
        self.columnconfigure(0, weight=1)
        self.rowconfigure(5, weight=1)

        self._last_state: Dict[str, Any] = {}
        self._can_admin = False          # 由 on_status() / 首次刷新决定
        self._buttons: Dict[str, ttk.Button] = {}

        self._build_header()
        self._build_info()
        self._build_pin()
        self._build_actions()
        self._build_run_system()
        self._build_output()

        # 先按"当前进程权限"摆按钮；真正的状态等主窗口 refresh_status() 或点刷新按钮再拉
        self._apply_admin(admin_state())
        self._show_state(None)

    # ---------------- 布局 ----------------

    def _build_header(self) -> None:
        header = ttk.Frame(self)
        header.grid(row=0, column=0, sticky="ew", pady=(0, 6))
        header.columnconfigure(0, weight=1)
        ttk.Label(header, text="特权服务（AvEnginePrivSvc）", style="Header.TLabel").grid(
            row=0, column=0, sticky="w")
        row = button_row(header, [("刷新状态", self.refresh_state,
                                  "重新查询服务安装情况、SCM 状态、证书指纹与探活结果")])
        row.grid(row=0, column=1, sticky="e")
        self.state_pill = StatusPill(header, "服务: 未知", "unknown")
        self.state_pill.grid(row=1, column=0, sticky="w", pady=(4, 0))

        ttk.Label(header,
                  text="用途：需要 SYSTEM 权限的取证/处置（读 Security 日志、枚举句柄表、"
                       "驱动与防火墙信息等）。服务本身不把 SYSTEM 令牌交给别的进程。",
                  style="Hint.TLabel", wraplength=980, justify="left").grid(
            row=2, column=0, columnspan=2, sticky="w", pady=(4, 0))

        self.permission_label = ttk.Label(header, text="", wraplength=980, justify="left")
        self.permission_label.grid(row=3, column=0, columnspan=2, sticky="w", pady=(4, 0))

    def _build_info(self) -> None:
        info = ttk.LabelFrame(self, text="服务状态", padding=10)
        info.grid(row=1, column=0, sticky="ew", pady=(0, 6))
        info.columnconfigure(0, weight=1)
        rows = [
            ("服务是否已安装", "查询中…"),
            ("SCM 状态", "查询中…"),
            ("服务端 exe", "查询中…"),
            ("命名管道", "查询中…"),
        ]
        next_row = grid_fields(info, rows)
        # grid_fields 每行放了一个 Frame（标签 + 值标签），这里捞回值标签以便后续更新
        self._svc_labels: Dict[str, ttk.Label] = {}
        for index, (label_text, _value) in enumerate(rows):
            frames = info.grid_slaves(row=index)
            if not frames:
                continue
            value_labels = [w for w in frames[0].winfo_children() if isinstance(w, ttk.Label)]
            if len(value_labels) >= 2:
                self._svc_labels[label_text] = value_labels[1]

        ping_row = ttk.Frame(info)
        ping_row.grid(row=next_row, column=0, sticky="ew", pady=(6, 0))
        self.ping_pill = StatusPill(ping_row, "探活: 未知", "unknown")
        self.ping_pill.pack(side="left")
        self.ping_detail = ttk.Label(ping_row, text="", style="Hint.TLabel",
                                     wraplength=760, justify="left")
        self.ping_detail.pack(side="left", padx=(8, 0))

    def _build_pin(self) -> None:
        pin = ttk.LabelFrame(self, text="钉住的证书指纹与安装目录白名单（--check-pin 原文）", padding=10)
        pin.grid(row=2, column=0, sticky="ew", pady=(0, 6))
        pin.columnconfigure(0, weight=1)
        ttk.Label(pin,
                  text="服务只接受「由这条指纹签名的、且位于安装目录白名单内的 avengine.exe」"
                       "作为调用者；下面是服务端回显的钉住值。",
                  style="Hint.TLabel", wraplength=980, justify="left").grid(
            row=0, column=0, sticky="w", pady=(0, 4))
        frame = ttk.Frame(pin)
        frame.grid(row=1, column=0, sticky="ew")
        frame.columnconfigure(0, weight=1)
        self.check_pin_text = tk.Text(frame, height=5, wrap="word", relief="flat",
                                      background=theme.PANE_BG, foreground=theme.PANE_FG,
                                      insertbackground=theme.PANE_FG, font=theme.mono_font())
        self.check_pin_text.grid(row=0, column=0, sticky="ew")
        scroll = ttk.Scrollbar(frame, orient="vertical", command=self.check_pin_text.yview)
        scroll.grid(row=0, column=1, sticky="ns")
        self.check_pin_text.configure(yscrollcommand=scroll.set, state="disabled")
        self._set_text(self.check_pin_text, "查询中…")

    def _build_actions(self) -> None:
        actions = ttk.LabelFrame(self, text="服务管理", padding=10)
        actions.grid(row=3, column=0, sticky="ew", pady=(0, 6))

        row = button_row(actions, [
            ("安装服务", self.install_service,
             "运行 AvEnginePrivSvc.exe --install（注册为 LocalSystem 服务，需管理员）"),
            ("卸载服务", self.uninstall_service,
             "运行 AvEnginePrivSvc.exe --uninstall（会二次确认，需管理员）"),
            ("探活（service ping）", self.ping_service,
             "只做命名管道探活，顺带确认当前调用者是否满足授权门槛；不需要管理员"),
        ])
        row.pack(anchor="w")
        for name, widget in zip(("install", "uninstall", "ping"), row.winfo_children()):
            if isinstance(widget, ttk.Button):
                self._buttons[name] = widget

        self.auto_start_var = tk.BooleanVar(value=False)
        self.auto_check = ttk.Checkbutton(actions, text="自动启动（--auto）", variable=self.auto_start_var)
        self.auto_check.pack(anchor="w", pady=(6, 0))
        ToolTip(self.auto_check, "勾选后安装时加 --auto：服务设为自动启动（开机即随系统启动）")

    def _build_run_system(self) -> None:
        box = ttk.LabelFrame(self, text="以 SYSTEM 运行（请服务启动 avengine.exe 子进程）", padding=10)
        box.grid(row=4, column=0, sticky="ew", pady=(0, 6))
        box.columnconfigure(1, weight=1)

        ttk.Label(box, text="参数", width=14, anchor="w").grid(row=0, column=0, sticky="w")
        self.args_entry = ttk.Entry(box, width=60)
        self.args_entry.insert(0, "status")
        self.args_entry.grid(row=0, column=1, sticky="ew", padx=(4, 4))
        ToolTip(self.args_entry, "传给 avengine.exe 的命令行参数，例如：status / scan --path C:\\\\Temp。默认 status")

        self.wait_var = tk.BooleanVar(value=True)
        wait_check = ttk.Checkbutton(box, text="等待子进程", variable=self.wait_var)
        wait_check.grid(row=0, column=2, sticky="w", padx=(4, 0))
        ToolTip(wait_check, "等待：阻塞到子进程结束并回传退出码；不等待：立刻返回 pid，输出在服务端日志里")

        ttk.Label(box, text="超时（秒）", anchor="w").grid(row=1, column=0, sticky="w", pady=(6, 0))
        self.timeout_entry = ttk.Entry(box, width=10)
        self.timeout_entry.insert(0, "600")
        self.timeout_entry.grid(row=1, column=1, sticky="w", padx=(4, 4), pady=(6, 0))

        self.run_row = button_row(box, [
            ("运行", self.run_as_system, "请求服务以 SYSTEM 令牌启动 avengine.exe（需管理员 + 已签名安装版）"),
        ])
        self.run_row.grid(row=1, column=2, sticky="w", padx=(4, 0), pady=(6, 0))
        if self.run_row.winfo_children():
            self._buttons["run"] = self.run_row.winfo_children()[0]  # type: ignore[assignment]

        ttk.Label(box, text="参数不允许包含换行/制表等控制字符。", style="Hint.TLabel").grid(
            row=2, column=0, columnspan=3, sticky="w", pady=(6, 0))

        limit = ttk.Label(
            box,
            text="限制（这是设计，不是故障）：调用者必须同时满足 ① 已以管理员身份运行；"
                 "② 进程映像位于服务记录的安装目录白名单内；③ 映像是被内部证书签名的 avengine.exe。\n"
                 "因此从源码树运行本 GUI（python -m avengine）调用一定被拒：会收到 "
                 "CALLER_WRONG_PATH 或 CALLER_NOT_ADMIN。被拒时下方会原样显示服务返回的诊断与处置建议。",
            style="Hint.TLabel", wraplength=980, justify="left")
        limit.grid(row=3, column=0, columnspan=3, sticky="w", pady=(8, 0))

    def _build_output(self) -> None:
        out = ttk.LabelFrame(self, text="输出", padding=10)
        out.grid(row=5, column=0, sticky="nsew")
        out.columnconfigure(0, weight=1)
        out.rowconfigure(0, weight=1)
        self.pane = OutputPane(out, height=10)
        self.pane.grid(row=0, column=0, sticky="nsew")

    # ---------------- 小工具 ----------------

    def _set_text(self, widget: tk.Text, text: str) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", text or "")
        widget.configure(state="disabled")

    def _set_label(self, key: str, value: str) -> None:
        label = self._svc_labels.get(key)
        if label is not None:
            label.configure(text=value)

    # ---------------- 钩子 ----------------

    def on_status(self, status: Dict[str, Any]) -> None:
        """主窗口收集到状态后回调（这里只关心是否是管理员）。"""
        if not isinstance(status, dict) or "admin" not in status:
            return
        self._apply_admin(bool(status.get("admin")))

    def append_output(self, text: str) -> None:
        self.pane.append(text)

    # ---------------- 权限提示 ----------------

    def _apply_admin(self, admin: bool) -> None:
        self._can_admin = bool(admin)
        if admin:
            self.permission_label.configure(
                text="权限：管理员 —— 安装/卸载/以 SYSTEM 运行可用（仍需调用者位于安装目录且被签名）。",
                foreground=theme.LEVEL_COLORS["ok"])
        else:
            self.permission_label.configure(
                text="⚠ 当前是普通用户权限：安装服务 / 卸载服务 / 以 SYSTEM 运行都已被禁用。"
                     "请点右上角「以管理员身份重启」后再试。",
                foreground=theme.LEVEL_COLORS["error"])
        for name in ("install", "uninstall", "run"):
            button = self._buttons.get(name)
            if button is None:
                continue
            if self._can_admin:
                button.state(["!disabled"])
            else:
                button.state(["disabled"])

    # ---------------- 动作 ----------------

    def refresh_state(self) -> None:
        """后台查询 ops.privsvc_state()（会跑 sc query 与 --check-pin，不能在 UI 线程做）。"""
        def work() -> OpResult:
            state = privsvc_state()
            installed = bool(state.get("installed"))
            ping_ok = bool(state.get("ping_ok"))
            return OpResult(True, "特权服务状态已刷新", "", {"state": state,
                                                             "installed": installed,
                                                             "ping_ok": ping_ok})

        def done(result: OpResult) -> None:
            if not result.ok:
                self.app.set_status("特权服务状态查询失败: {}".format(result.message))
                self.pane.append("查询特权服务状态失败: {}".format(result.message))
                return
            self._show_state(result.data.get("state") or {})

        self.app.run_task("正在查询特权服务状态…", work, done, silent=True)

    def install_service(self) -> None:
        if not self._can_admin:
            messagebox.showwarning("安装服务", "需要管理员权限：请先点「以管理员身份重启」。")
            return
        auto_start = bool(self.auto_start_var.get())
        self.pane.append("── 安装特权服务（auto_start={}）──".format(auto_start))
        self.app.run_task(
            "正在安装特权服务…",
            lambda: privsvc_install(auto_start=auto_start),
            lambda result: self._after_action("安装特权服务", result))

    def uninstall_service(self) -> None:
        if not self._can_admin:
            messagebox.showwarning("卸载服务", "需要管理员权限：请先点「以管理员身份重启」。")
            return
        if not messagebox.askyesno(
                "卸载特权服务",
                "确定要卸载 AvEnginePrivSvc 吗？\n\n"
                "卸载后需要 SYSTEM 权限的取证/处置功能将不可用（直到重新安装）。"):
            self.app.set_status("已取消卸载特权服务")
            return
        self.pane.append("── 卸载特权服务 ──")
        self.app.run_task("正在卸载特权服务…", privsvc_uninstall,
                          lambda result: self._after_action("卸载特权服务", result))

    def ping_service(self) -> None:
        self.app.run_task("正在探活特权服务…", privsvc_ping,
                          lambda result: self._after_action("探活（service ping）", result))

    def run_as_system(self) -> None:
        if not self._can_admin:
            messagebox.showwarning("以 SYSTEM 运行", "需要管理员权限：请先点「以管理员身份重启」。")
            return
        args = self.args_entry.get().strip()
        if not args:
            messagebox.showwarning("以 SYSTEM 运行", "参数不能为空，例如填 status。")
            return
        if _CONTROL_CHARS.search(args):
            messagebox.showwarning("以 SYSTEM 运行",
                                   "参数里不能包含换行/制表等控制字符（服务会以 ARGS_REJECTED 拒绝）。")
            return
        timeout_s, error = validate_int(self.timeout_entry.get(), "超时秒数", minimum=1, maximum=86400)
        if error:
            messagebox.showwarning("以 SYSTEM 运行", error)
            return
        wait = bool(self.wait_var.get())
        timeout_value = int(timeout_s or 600)
        self.pane.append("── 以 SYSTEM 运行: avengine.exe {}（wait={}, timeout={}s）──".format(
            args, wait, timeout_value))
        self.app.run_task(
            "正在请求特权服务以 SYSTEM 运行…",
            lambda: privsvc_run_system(args, wait=wait, timeout_s=timeout_value),
            lambda result: self._after_action("以 SYSTEM 运行", result))

    # ---------------- 结果处理 ----------------

    def _after_action(self, title: str, result: OpResult) -> None:
        self.app.show_result(title, result, self.pane)
        if result.message:
            # 成功时 OpResult.output 常为空，但 message 里有 pid/退出码/日志路径与拒绝原因 —— 都要留下
            self.pane.append(result.message)
        # ping 的结果顺手更新"探活"指示（它本来就从 privsvc_state 里取）
        if title.startswith("探活"):
            self.ping_pill.set("探活: {}".format("成功" if result.ok else "失败"),
                               "ok" if result.ok else "error")
            self.ping_detail.configure(text=result.message)
        # 装/卸/运行之后状态都可能变了，刷新一次
        if not title.startswith("探活"):
            self.refresh_state()

    def _show_state(self, state: Optional[Dict[str, Any]]) -> None:
        if not state:
            self.state_pill.set("服务: 未知（点「刷新状态」查询）", "unknown")
            return
        self._last_state = dict(state)

        installed = bool(state.get("installed"))
        exe = str(state.get("exe") or "")
        exe_exists = bool(state.get("exe_exists"))
        svc_state = str(state.get("service_state") or "")
        check_pin = str(state.get("check_pin") or "")
        check_code = state.get("check_pin_code")
        ping_ok = bool(state.get("ping_ok"))
        ping_text = str(state.get("ping") or "")

        self._set_label("服务是否已安装", "已安装" if installed else "未安装")
        self._set_label("SCM 状态",
                        (svc_state or "未知（sc query 无输出，可能是服务未注册或权限不足）")
                        if installed else "—（服务未安装）")
        if exe_exists:
            self._set_label("服务端 exe", "存在: {}".format(exe))
        elif exe:
            self._set_label("服务端 exe", "路径已定位但文件不存在: {}".format(exe))
        else:
            self._set_label("服务端 exe",
                            "找不到 AvEnginePrivSvc.exe —— 先运行 service\\build_service.bat，"
                            "或查看预期位置 service\\AvEnginePrivSvc.exe / service\\bin\\AvEnginePrivSvc.exe")
        self._set_label("命名管道", str(state.get("pipe") or ""))

        if exe_exists and check_pin:
            hint = "（--check-pin 退出码 {}）".format(check_code)
            self._set_text(self.check_pin_text, check_pin + "\n" + hint)
        elif exe_exists:
            self._set_text(self.check_pin_text,
                           "（--check-pin 没有输出，退出码 {}）".format(check_code))
        else:
            self._set_text(self.check_pin_text,
                           "（服务端 exe 不存在，无法读取钉住的证书指纹 —— 先构建/放置 AvEnginePrivSvc.exe）")

        if not installed:
            self.state_pill.set("服务: 未安装（需要 SYSTEM 的取证功能不可用）", "warn")
        elif ping_ok:
            self.state_pill.set("服务: 已安装且探活正常", "ok")
        else:
            self.state_pill.set("服务: 已安装，但探活失败", "error")

        if ping_ok:
            self.ping_pill.set("探活: 成功", "ok")
        elif not installed:
            self.ping_pill.set("探活: 未测试（服务未安装）", "unknown")
        else:
            self.ping_pill.set("探活: 失败", "error")
        self.ping_detail.configure(text=ping_text)
