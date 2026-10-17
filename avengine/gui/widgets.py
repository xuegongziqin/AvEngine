"""
gui/widgets.py - GUI 共用控件

只放"多个标签页都要用"的东西，避免每个页面各写一套：
  * Card：带标题的分组框
  * OutputPane：等宽只读文本区（滚到底、清空、追加），用于命令输出/AI 流
  * FieldRow：标签 + 输入框 + 浏览按钮
  * StatusPill：状态指示（绿/黄/红 + 文本）
  * make_button / ToolTip
"""

from __future__ import annotations

import time
import tkinter as tk
from tkinter import ttk
from typing import Callable, Iterable, Optional, Sequence

from . import theme


class Card(ttk.LabelFrame):
    """带标题的分组容器。"""

    def __init__(self, master, title: str, **kwargs):
        super().__init__(master, text=title, padding=10, **kwargs)
        self.columnconfigure(0, weight=1)


class OutputPane(ttk.Frame):
    """等宽只读文本区 + 清空按钮。append() 会自动滚到底，可带颜色标签。"""

    #: 自动滚动的最小间隔（秒）：流式输出时 see("end") 不能每条都调
    SCROLL_INTERVAL = 0.1
    #: 面板最多保留的行数；超过就丢掉最旧的（Tk Text 插入成本随内容增长）
    MAX_LINES = 6000
    #: 裁剪后保留的行数
    KEEP_LINES = 4000

    #: 可用标签（颜色见 theme.LEVEL_COLORS / 固定灰）
    TAGS = {
        "dim": {"foreground": "#8a8f98"},
        "info": {"foreground": "#6cb6ff"},
        "ok": {"foreground": "#7ee787"},
        "warn": {"foreground": "#e8a33d"},
        "error": {"foreground": "#ff7b72"},
        "tool": {"foreground": "#79c0ff"},
    }

    def __init__(self, master, height: int = 12, title: str = "", with_clear: bool = True):
        super().__init__(master)
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)
        if title:
            ttk.Label(self, text=title, style="Sub.TLabel").grid(row=0, column=0, sticky="w")
        if with_clear:
            ttk.Button(self, text="清空", width=6, command=self.clear).grid(
                row=0, column=1, sticky="e", padx=(6, 0))
        self.text = tk.Text(self, height=height, wrap="word", undo=False,
                            background=theme.PANE_BG, foreground=theme.PANE_FG,
                            insertbackground=theme.PANE_FG, relief="flat",
                            font=theme.mono_font())
        self.text.grid(row=1, column=0, columnspan=2, sticky="nsew", pady=(4, 0))
        scroll = ttk.Scrollbar(self, orient="vertical", command=self.text.yview)
        scroll.grid(row=1, column=2, sticky="ns", pady=(4, 0))
        self.text.configure(yscrollcommand=scroll.set, state="disabled")
        self._last_scroll = 0.0
        self._writes = 0
        for name, options in self.TAGS.items():
            self.text.tag_configure(name, **options)

    def write(self, text: str, tag: Optional[str] = None, scroll: bool = True) -> None:
        """
        写入**不追加换行**的片段（流式输出用：模型是一个词一个词吐的）。

        两个性能措施（长会话实测必需）：
          * 自动滚动做**时间节流**：`see("end")` 每次都要重排视图，流式输出时是明显开销，
            现在最多每 100ms 滚一次，用户看到的仍是"跟着走"。
          * 内容量**上限**：Tk Text 的插入成本随内容增长（实测长会话单次 insert 涨到 0.25s），
            超过 MAX_LINES 就丢掉最旧的部分并留一行提示。
        """
        if not text:
            return
        self.text.configure(state="normal")
        self.text.insert("end", text, tag if tag in self.TAGS else ())
        if scroll:
            now = time.monotonic()
            if now - self._last_scroll >= self.SCROLL_INTERVAL:
                self.text.see("end")
                self._last_scroll = now
        self.text.configure(state="disabled")

        # 每 64 次写检查一次行数（index() 很便宜，但没必要每次都查）
        self._writes += 1
        if self._writes % 64 == 0:
            self._trim_if_needed()

    def _trim_if_needed(self) -> None:
        """内容超过上限时丢掉最旧的行，保证控件不会越用越慢。"""
        try:
            lines = int(self.text.index("end-1c").split(".")[0])
        except (tk.TclError, ValueError):
            return
        if lines <= self.MAX_LINES:
            return
        self.text.configure(state="normal")
        self.text.delete("1.0", "end-{}lines".format(self.KEEP_LINES))
        self.text.insert("1.0", "…… 更早的输出已省略（面板只保留最近 {} 行）……\n".format(
            self.KEEP_LINES), "dim")
        self.text.configure(state="disabled")

    def append(self, text: str, tag: Optional[str] = None) -> None:
        if not text:
            return
        self.write(text if text.endswith("\n") else text + "\n", tag)

    def scroll_to_end(self) -> None:
        """立即滚到底（会话结束/清屏后用，绕过节流）。"""
        self.text.see("end")
        self._last_scroll = time.monotonic()

    def clear(self) -> None:
        self.text.configure(state="normal")
        self.text.delete("1.0", "end")
        self.text.configure(state="disabled")
        self._writes = 0

    def get(self) -> str:
        return self.text.get("1.0", "end").strip()


class FieldRow(ttk.Frame):
    """一行：标签 + 输入框 +（可选）浏览/按钮。value 属性读写字符串。"""

    def __init__(self, master, label: str, value: str = "", width: int = 34,
                 browse: Optional[str] = None, on_browse: Optional[Callable[[], None]] = None,
                 label_width: int = 14):
        super().__init__(master)
        self.columnconfigure(1, weight=1)
        ttk.Label(self, text=label, width=label_width, anchor="w").grid(row=0, column=0, sticky="w")
        self.var = tk.StringVar(value=value)
        self.entry = ttk.Entry(self, textvariable=self.var, width=width)
        self.entry.grid(row=0, column=1, sticky="ew", padx=(4, 4))
        self.button: Optional[ttk.Button] = None
        if browse and on_browse:
            self.button = ttk.Button(self, text=browse, width=8, command=on_browse)
            self.button.grid(row=0, column=2, sticky="e")

    @property
    def value(self) -> str:
        return self.var.get().strip()

    @value.setter
    def value(self, text: str) -> None:
        self.var.set(text)


class StatusPill(ttk.Frame):
    """一个彩色圆点 + 文本，用于状态指示。"""

    def __init__(self, master, text: str = "未知", level: str = "unknown"):
        super().__init__(master)
        self.dot = tk.Canvas(self, width=12, height=12, highlightthickness=0,
                             background=theme.BG)
        self.dot.grid(row=0, column=0, padx=(0, 6))
        self.label = ttk.Label(self, text=text)
        self.label.grid(row=0, column=1, sticky="w")
        self.set(text, level)

    def set(self, text: str, level: str = "unknown") -> None:
        color = theme.LEVEL_COLORS.get(level, theme.LEVEL_COLORS["unknown"])
        self.dot.delete("all")
        self.dot.create_oval(2, 2, 11, 11, fill=color, outline=color)
        self.label.configure(text=text)


def labeled_value(master, label: str, value: str = "", label_width: int = 14) -> ttk.Label:
    """只读的"标签: 值"行，返回可后续 .configure(text=...) 的 Label。"""
    frame = ttk.Frame(master)
    frame.pack(fill="x", pady=1)
    ttk.Label(frame, text=label, width=label_width, anchor="w",
              style="Sub.TLabel").pack(side="left")
    widget = ttk.Label(frame, text=value, anchor="w", wraplength=760, justify="left")
    widget.pack(side="left", fill="x", expand=True)
    return widget


class ToolTip:
    """极简 tooltip（悬停显示说明），避免用户看不懂按钮。"""

    def __init__(self, widget: tk.Widget, text: str):
        self.widget = widget
        self.text = text
        self.tip: Optional[tk.Toplevel] = None
        widget.bind("<Enter>", self._show, add="+")
        widget.bind("<Leave>", self._hide, add="+")

    def _show(self, _event=None) -> None:
        if self.tip or not self.text:
            return
        x = self.widget.winfo_rootx() + 12
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 4
        self.tip = tk.Toplevel(self.widget)
        self.tip.wm_overrideredirect(True)
        self.tip.wm_geometry("+{}+{}".format(x, y))
        tk.Label(self.tip, text=self.text, justify="left", background="#ffffe0",
                 relief="solid", borderwidth=1, padx=6, pady=3).pack()

    def _hide(self, _event=None) -> None:
        if self.tip:
            self.tip.destroy()
            self.tip = None


def button_row(master, buttons: Sequence[tuple]) -> ttk.Frame:
    """
    一行按钮：buttons = [(文本, 回调, tooltip), ...]；回调为 None 时禁用。
    返回容器（调用方可再 pack 额外控件）。
    """
    frame = ttk.Frame(master)
    for label, command, tip in buttons:
        btn = ttk.Button(frame, text=label, command=command)
        if command is None:
            btn.state(["disabled"])
        btn.pack(side="left", padx=(0, 6))
        if tip:
            ToolTip(btn, tip)
    return frame


def grid_fields(master, rows: Iterable[tuple], start_row: int = 0) -> int:
    """
    紧凑地摆放 (标签, 值) 只读行：rows = [(label, value), ...]。返回下一个可用行号。
    """
    row = start_row
    for label, value in rows:
        frame = ttk.Frame(master)
        frame.grid(row=row, column=0, sticky="ew", pady=1)
        frame.columnconfigure(1, weight=1)
        ttk.Label(frame, text=label, width=16, anchor="w", style="Sub.TLabel").grid(
            row=0, column=0, sticky="w")
        ttk.Label(frame, text=value, anchor="w", wraplength=780, justify="left").grid(
            row=0, column=1, sticky="w")
        row += 1
    return row
