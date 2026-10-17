"""
gui/tab_clamav.py - ClamAV 标签页

职责：
  * 展示 ops.clamav_state()：本机 MSI / 安装目录 / clamd 服务状态、当前 host:port、
    当前模式（本地 / 纯 YARA / 局域网）、是否可达与版本
  * 局域网 clamd：改 host/port 写回 config.yaml（ops.clamav_configure）、测试连通、切纯 YARA
  * 本机 ClamAV：安装 / 配置、启动、停止、卸载（二次确认）
  * 病毒库：通知 clamd 重载病毒库（ops.clamav_reload）
  * 非管理员时页面顶部提示，并禁用安装 / 启动 / 停止 / 卸载（测试与保存仍可用）

线程约定（与 app.run_task 一致）：所有外部命令都封在 ops 里，且都在 work() 子线程里跑；
work() 绝不能碰任何 Tk 控件，输出一律放进返回的 OpResult.output，由 on_done（主线程）显示。
"""

from __future__ import annotations

from tkinter import messagebox, ttk
import tkinter as tk
from typing import Any, Callable, Dict, Optional, Tuple

from . import ops, theme
from .widgets import Card, FieldRow, OutputPane, StatusPill, ToolTip, button_row

# 这些 host 视为"本机 clamd"，其余非空 host 视为局域网
LOCAL_HOSTS = ("127.0.0.1", "localhost", "::1", "0.0.0.0")

# 需要管理员权限的按钮文案（非管理员时置灰；测试连通 / 保存配置不需要管理员）
ADMIN_ONLY_BUTTONS = ("安装 / 配置", "启动服务", "停止服务", "卸载")


class ClamavTab(ttk.Frame):
    """ClamAV 页。"""

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
        self._build_target_groups()
        self._build_db_group()
        self._build_output()
        self.on_config_reloaded()
        # 首屏状态：clamav_state() 会跑 sc query 并探测 clamd，必须异步
        self.after(200, self.refresh)

    # ---------------- 布局 ----------------

    def _build_notice(self) -> None:
        """非管理员时的置顶提示（管理员时 pack_forget）。"""
        self.notice = ttk.Label(
            self,
            text="注意：当前不是管理员权限，本机 ClamAV 的安装 / 启停 / 卸载不可用；"
                 "「测试连通」「保存到 config.yaml」「更新病毒库」仍然可用。"
                 "需要装本机 clamd 时请点主窗口右上角「以管理员身份重启」。",
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
        ttk.Label(head, text="clamd:", style="Sub.TLabel").pack(side="left")
        self.reach_pill = StatusPill(head, "查询中…", "unknown")
        self.reach_pill.pack(side="left", padx=(6, 12))
        refresh_button = ttk.Button(head, text="刷新状态", command=self.refresh)
        refresh_button.pack(side="left")
        ToolTip(refresh_button, "重新执行 ops.clamav_state()：查询服务状态并探测配置里的 clamd")

        rows = (
            ("packages", "安装包（两套）:", "查询中…"),
            ("msi", "本机将使用的安装包:", "查询中…"),
            ("install_dir", "安装目录（%ProgramFiles%\\ClamAV）:", "查询中…"),
            ("service", "clamd 服务:", "查询中…"),
            ("target", "当前配置的 host:port:", "查询中…"),
            ("mode", "当前模式:", "查询中…"),
            ("reachable", "是否可达 / 版本:", "查询中…"),
        )
        row = 1
        for key, label, value in rows:
            row = self._add_field(body, row, key, label, value)
        ttk.Label(body,
                  text="数据来源: ops.clamav_state()（可达性用内核的 clamd version 探测，只读不改动系统）",
                  style="Hint.TLabel").grid(row=row, column=0, columnspan=2,
                                            sticky="w", pady=(4, 0))

    def _add_field(self, master, row: int, key: str, label: str, value: str = "") -> int:
        """一行"标签: 值"；值控件的引用存进 self._fields[key]，刷新时只改文本/颜色。"""
        ttk.Label(master, text=label, width=26, anchor="w", style="Sub.TLabel").grid(
            row=row, column=0, sticky="w", pady=1)
        widget = ttk.Label(master, text=value, anchor="w", wraplength=740, justify="left")
        widget.grid(row=row, column=1, sticky="w", pady=1)
        self._fields[key] = widget
        return row + 1

    def _build_target_groups(self) -> None:
        groups = ttk.Frame(self)
        groups.pack(fill="x", pady=(8, 0))
        groups.columnconfigure(0, weight=1)
        groups.columnconfigure(1, weight=1)

        # ---- 局域网 clamd（普通权限即可）----
        lan = Card(groups, title="局域网 clamd")
        lan.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        self.host_field = FieldRow(lan, "clamd 主机", value="127.0.0.1", width=24)
        self.host_field.grid(row=0, column=0, sticky="ew", pady=2)
        self.port_field = FieldRow(lan, "clamd 端口", value="3310", width=24)
        self.port_field.grid(row=1, column=0, sticky="ew", pady=2)
        button_row(lan, [
            ("测试连通", self._test, "只探测 clamd version，不需要管理员，也不改配置"),
            ("保存到 config.yaml", self._save,
             "写 config.yaml 的 clamav.host/port，然后重新加载配置并刷新状态"),
            ("切换为纯 YARA 模式", self._use_yara_only,
             "把 clamav.host 置空：不再使用 ClamAV，扫描仍走 YARA + Sysmon"),
        ]).grid(row=2, column=0, sticky="w", pady=(8, 0))
        ttk.Label(lan,
                  text="ClamAV 1.x 不支持 Windows 7：Win7 请填局域网 clamd 的 IP 并放开 3310 端口，"
                       "或切到纯 YARA 模式。",
                  style="Hint.TLabel", wraplength=440, justify="left").grid(
            row=3, column=0, sticky="w", pady=(6, 0))

        # ---- 本机 ClamAV（需管理员）----
        local = Card(groups, title="本机 ClamAV（需管理员）")
        local.grid(row=0, column=1, sticky="nsew")
        local.columnconfigure(0, weight=1)

        # 安装包选择：任何系统都能选（默认按系统版本），Win7 可强制用兼容版
        picker = ttk.Frame(local)
        picker.grid(row=0, column=0, sticky="w")
        ttk.Label(picker, text="安装包:", style="Sub.TLabel").pack(side="left", padx=(0, 6))
        self.package_var = tk.StringVar(value="auto")
        for value, label, tip in (
            ("auto", "自动（按系统）", "Win8.1+ 用现代版 bina\\clamav.msi；Win7 SP1 用 bina\\clamwin7\\ 下的包"),
            ("modern", "现代版", "强制 bina\\clamav.msi（ClamAV 1.x，需要 Win8.1+）"),
            ("legacy", "Win7 兼容版", "强制 bina\\clamwin7\\*.msi（最后支持 Win7 SP1 的版本）"),
        ):
            radio = ttk.Radiobutton(picker, text=label, value=value, variable=self.package_var)
            radio.pack(side="left", padx=(0, 10))
            ToolTip(radio, tip)

        buttons = ttk.Frame(local)
        buttons.grid(row=1, column=0, sticky="w", pady=(6, 0))
        for label, command, tip in (
            ("安装 / 配置", self._install_local,
             "跑 scripts\\setup_clamav.bat：按上面的选择装对应安装包、写 clamd.conf、注册并启动 clamd（可能很久）"),
            ("启动服务", self._start, "sc start clamd（失败时退回 scripts\\start_clamav.bat）"),
            ("停止服务", self._stop, "sc stop clamd"),
            ("卸载", self._uninstall, "对两套安装包各执行 msiexec /x + sc delete clamd（会二次确认）"),
        ):
            button = ttk.Button(buttons, text=label, command=command)
            if not self._admin:
                button.state(["disabled"])
            button.pack(side="left", padx=(0, 6))
            ToolTip(button, tip)
            self._buttons[label] = button
        ttk.Label(local,
                  text="安装 / 配置会调用 scripts\\setup_clamav.bat（默认按系统版本选包；"
                       "Win7 SP1 → bina\\clamwin7\\*.msi），首次安装可能耗时 10 分钟以上；"
                       "卸载不会删除 %ProgramFiles%\\ClamAV 与病毒库。",
                  style="Hint.TLabel", wraplength=460, justify="left").grid(
            row=2, column=0, sticky="w", pady=(6, 0))

    def _build_db_group(self) -> None:
        card = Card(self, title="病毒库")
        card.pack(fill="x", pady=(8, 0))
        button_row(card, [
            ("更新病毒库", self._reload_db,
             "通过 TCP 让 clamd 重新加载病毒库（freshclam 更新完成后调用）；不需要管理员"),
        ]).grid(row=0, column=0, sticky="w")
        ttk.Label(card,
                  text="说明：这里只是让 clamd 重读磁盘上的病毒库，不下载新库；"
                       "下载请用 ClamAV 自带的 freshclam（setup_clamav.bat 安装时会跑一次）。",
                  style="Hint.TLabel", wraplength=880, justify="left").grid(
            row=1, column=0, sticky="w", pady=(6, 0))

    def _build_output(self) -> None:
        self.pane = OutputPane(self, height=10, title="命令输出")
        self.pane.pack(fill="both", expand=True, pady=(8, 0))

    # ---------------- 状态刷新 ----------------

    def refresh(self) -> None:
        """
        后台读取 ClamAV 状态（内部会执行 sc query 并探测 clamd）。

        silent=True：不占用主窗口的"忙碌"标志，避免与其它页面的任务互相顶掉；
        状态栏仍会显示"正在读取 ClamAV 状态…"。
        """
        if self._refreshing:
            return
        self._refreshing = True
        # 配置在子线程里只读，先拍个快照，避免和主线程的 reload_config 抢同一个 dict
        config = dict(self.app.config_data or {})

        def work() -> ops.OpResult:
            try:
                return ops.OpResult(True, "ClamAV 状态已刷新", "", ops.clamav_state(config))
            except Exception as exc:  # noqa: BLE001 - 后台异常必须转成结果
                return ops.OpResult(False, "读取 ClamAV 状态失败: {}".format(exc))

        def done(result: ops.OpResult) -> None:
            self._refreshing = False
            if not result.ok:
                self.app.show_result("ClamAV 状态", result, self.pane)
                return
            self._apply_state(result.data)
            self.app.set_status(result.message)

        self.app.run_task("正在读取 ClamAV 状态…", work, done, silent=True)

    def _apply_state(self, state: Dict[str, Any]) -> None:
        msi_exists = bool(state.get("msi_exists"))
        self._set("msi", "{}（{}）".format(state.get("msi") or "",
                                          "存在" if msi_exists else "不存在，缺它无法本机安装"),
                  "ok" if msi_exists else "warn")

        # 两套安装包的可见性：Win7 兼容版 / 现代版各在不在，以及本机默认会用哪套
        legacy_ok = bool(state.get("legacy_exists"))
        modern_ok = bool(state.get("modern_exists"))
        expected_legacy = bool(state.get("legacy_expected"))
        self._set("packages", "现代版 {} | Win7 兼容版 {}（本机默认：{}）".format(
            "有" if modern_ok else "缺", "有" if legacy_ok else "缺",
            "Win7 兼容版" if expected_legacy else "现代版"),
            "ok" if (legacy_ok if expected_legacy else modern_ok) else "warn")

        dir_exists = bool(state.get("install_dir_exists"))
        self._set("install_dir", "{}（{}）".format(state.get("install_dir") or "",
                                                  "存在" if dir_exists else "不存在"),
                  "ok" if dir_exists else "unknown")

        service_name = str(state.get("service_name") or "clamd")
        service_exists = bool(state.get("service_exists"))
        service_state = str(state.get("service_state") or "")
        if not service_exists:
            self._set("service", "{}：不存在（未安装服务）".format(service_name), "unknown")
        else:
            running = service_state.upper() == "RUNNING"
            self._set("service", "{}：存在（{}）".format(service_name, service_state or "状态未知"),
                      "ok" if running else "warn")

        host = str(state.get("configured_host") or "")
        port = state.get("configured_port") or 3310
        self._set("target", "{}:{}".format(host, port) if host else "未启用（clamav.host 为空）",
                  "info" if host else "unknown")
        self._set("mode", self._mode_text(host), "info")

        reachable = bool(state.get("reachable"))
        version = str(state.get("version") or "")
        if not host:
            self._set("reachable", "未启用（纯 YARA 模式）", "unknown")
        elif reachable:
            self._set("reachable", "可达（版本 {}）".format(version or "未知"), "ok")
        else:
            self._set("reachable", "不可达（确认 clamd 已启动、防火墙放通 TCP {}）".format(port),
                      "error")

        if not host:
            self.reach_pill.set("未启用", "unknown")
        elif reachable:
            self.reach_pill.set("可达 {}".format(version or "").strip(), "ok")
        else:
            self.reach_pill.set("不可达", "error")

    @staticmethod
    def _mode_text(host: str) -> str:
        if not host:
            return "纯 YARA 模式（ClamAV 已禁用）"
        if host.lower() in LOCAL_HOSTS:
            return "本地（连接本机 clamd {}）".format(host)
        return "局域网（连接远程 clamd {}）".format(host)

    def _set(self, key: str, text: str, level: str = "unknown") -> None:
        widget = self._fields.get(key)
        if widget is None:
            return
        widget.configure(text=text,
                         foreground=theme.LEVEL_COLORS.get(level, theme.LEVEL_COLORS["unknown"]))

    def _apply_admin(self, admin: bool) -> None:
        """权限变化时同步顶部提示与需要管理员的按钮。"""
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
        """config.yaml 重新加载后：把 host/port 输入框同步成配置里的值。"""
        values = ops.clamav_config_values(self.app.config_data or {})
        self.host_field.value = values["host"]
        self.port_field.value = str(values["port"])
        self._set("target", "{}:{}".format(values["host"], values["port"])
                  if values["host"] else "未启用（clamav.host 为空）",
                  "info" if values["host"] else "unknown")

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

    def _parse_port(self) -> Optional[int]:
        """读端口输入框；非法时提示并返回 None。"""
        text = self.port_field.value
        try:
            port = int(text)
        except ValueError:
            messagebox.showwarning("端口无效", "端口必须是数字，例如 3310（当前输入: {}）".format(text))
            return None
        if not 1 <= port <= 65535:
            messagebox.showwarning("端口无效", "端口范围应为 1-65535（当前输入: {}）".format(text))
            return None
        return port

    def _configured_target(self) -> Tuple[str, int]:
        """config.yaml 里当前的 clamd 目标（病毒库重载用它，而不是输入框里的草稿值）。"""
        values = ops.clamav_config_values(self.app.config_data or {})
        return values["host"], values["port"]

    # ---- 局域网 clamd ----

    def _test(self) -> None:
        """探测 host:port 上的 clamd（不改配置，不需要管理员）。"""
        host = self.host_field.value
        port = self._parse_port()
        if port is None:
            return
        if not host:
            messagebox.showinfo("测试连通", "主机为空表示纯 YARA 模式，没有可测试的 clamd。")
            return
        self._run_action("测试 clamd {}:{}".format(host, port),
                         lambda: ops.clamav_test(host, port), refresh_after=False)

    def _save(self) -> None:
        """把 host/port 写回 config.yaml（ops.clamav_configure -> scripts\\set_clamav.bat）。"""
        host = self.host_field.value
        port = self._parse_port()
        if port is None:
            return
        if not host:
            messagebox.showinfo("保存配置",
                                "主机为空会变成纯 YARA 模式；如需这样，请用「切换为纯 YARA 模式」按钮。")
            return

        def done(result: ops.OpResult) -> None:
            self.app.show_result("保存 ClamAV 配置", result, self.pane)
            if result.ok:
                self.app.reload_config()   # 触发各页 on_config_reloaded，再用新配置刷新状态
                self.refresh()

        self.app.run_task("正在写入 config.yaml（clamav {}:{}）…".format(host, port),
                          lambda: ops.clamav_configure(host, port), done)

    def _use_yara_only(self) -> None:
        """把 clamav.host 置空 = 纯 YARA 模式（Win7 常用；脚本会保留 timeout）。"""
        port = self._parse_port()
        if port is None:
            port = self._configured_target()[1]

        def done(result: ops.OpResult) -> None:
            self.app.show_result("切换为纯 YARA 模式", result, self.pane)
            if result.ok:
                self.app.reload_config()
                self.refresh()

        self.app.run_task("正在把 ClamAV 切换为纯 YARA 模式…",
                          lambda: ops.clamav_configure("none", port), done)

    # ---- 本机 ClamAV ----

    def _install_local(self) -> None:
        """本机安装 / 配置：跑 scripts\\setup_clamav.bat（装 MSI + 注册服务），可能很久。"""
        port = self._parse_port()
        if port is None:
            return
        package = self.package_var.get() if hasattr(self, "package_var") else "auto"
        label = {"auto": "自动（按系统）", "modern": "现代版",
                 "legacy": "Win7 兼容版"}.get(package, package)
        self._run_action("安装 / 配置本机 ClamAV（{}，可能耗时 10 分钟以上，请勿关闭窗口）".format(label),
                         lambda: ops.clamav_install(port, package))

    def _start(self) -> None:
        self._run_action("启动 clamd 服务", ops.clamav_start)

    def _stop(self) -> None:
        self._run_action("停止 clamd 服务", ops.clamav_stop)

    def _uninstall(self) -> None:
        if not messagebox.askyesno(
                "确认卸载 ClamAV",
                "将依次执行：\n"
                "  1) sc stop clamd\n"
                "  2) msiexec /x bina\\clamav.msi /qn /norestart\n"
                "  3) sc delete clamd\n\n"
                "安装目录 %ProgramFiles%\\ClamAV 与病毒库不会被删除；\n"
                "卸载后 config.yaml 里的 clamav.host 仍指向它，请记得改成局域网 clamd 或纯 YARA 模式。\n\n"
                "确定继续？",
                parent=self):
            return
        self._run_action("卸载本机 ClamAV", ops.clamav_uninstall)

    # ---- 病毒库 ----

    def _reload_db(self) -> None:
        """让当前配置的 clamd 重新加载病毒库（纯 YARA 模式下 ops 会直接返回错误）。"""
        host, port = self._configured_target()
        if not host:
            messagebox.showinfo("更新病毒库",
                                "当前为纯 YARA 模式（config.yaml 里 clamav.host 为空），没有 clamd 可重载。")
            return
        self._run_action("通知 {}:{} 重载病毒库".format(host, port),
                         lambda: ops.clamav_reload(host, port))
