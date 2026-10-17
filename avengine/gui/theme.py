"""
gui/theme.py - 外观常量与全局 ttk 样式

集中放在这里，标签页就不再各写颜色/字体（也方便以后整体换肤）。
字体优先用雅黑（中文清晰），等宽首选 Consolas（日志/输出对齐）。
"""

from __future__ import annotations

import tkinter as tk
from tkinter import font as tkfont
from tkinter import ttk

BG = "#f5f6f8"
PANE_BG = "#1e1f22"
PANE_FG = "#dcdcdc"
ACCENT = "#2b6cb0"

LEVEL_COLORS = {
    "ok": "#2f9e44",
    "warn": "#e8a33d",
    "error": "#d64545",
    "unknown": "#9aa0a6",
    "info": "#2b6cb0",
}

_UI_FAMILY = "Microsoft YaHei UI"
_MONO_FAMILY = "Consolas"


def ui_font(size: int = 10, bold: bool = False):
    family = _UI_FAMILY if _UI_FAMILY in tkfont.families() else "TkDefaultFont"
    return (family, size, "bold") if bold else (family, size)


def mono_font(size: int = 9):
    family = _MONO_FAMILY if _MONO_FAMILY in tkfont.families() else "Courier"
    return (family, size)


def apply(root: tk.Misc) -> ttk.Style:
    """应用全局样式，返回 Style 对象。"""
    style = ttk.Style(root)
    try:
        style.theme_use("vista")
    except tk.TclError:
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

    base = ui_font()
    root.option_add("*Font", base)
    style.configure(".", font=base)
    style.configure("TLabel", font=base)
    style.configure("TButton", font=base)
    style.configure("TNotebook.Tab", font=ui_font(10), padding=(14, 7))
    style.configure("Header.TLabel", font=ui_font(13, bold=True))
    style.configure("Sub.TLabel", font=ui_font(9), foreground="#5a5f66")
    style.configure("Hint.TLabel", font=ui_font(9), foreground="#7a7f86")
    style.configure("TLabelframe.Label", font=ui_font(10, bold=True))
    try:
        style.configure("Treeview", font=base, rowheight=22)
        style.configure("Treeview.Heading", font=ui_font(9, bold=True))
    except tk.TclError:
        pass
    return style
