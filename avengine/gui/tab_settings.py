"""
gui/tab_settings.py - 设置页

一个竖向滚动的表单，分两段：
  * config.yaml：YARA 规则目录、clamd 连接、Sysmon 通道、隔离目录、扫描行为与监控目录
  * config.ini（AI）：开关、端点、模型、各上限、以及 8 个事件源开关

写盘**必须**走 avengine/configwrite.py：它按行定位只改目标键的值，能保住
config.example.yaml / config.ini.example 里的说明性注释（yaml.safe_dump 会全部抹掉）。
保存前会做整数/端口范围校验，非法就提示并中止，绝不写坏配置。

为了让"读控件 → 写盘"这段逻辑可被单测，它被抽成不依赖 Tk 的函数：
    validate_int / collect_yaml_values / collect_ai_values / validate_yaml_values / validate_ai_values
它们只接收入参，不碰任何控件（getter 由调用方传入）。
"""

from __future__ import annotations

import re
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

import yaml

from ..aiconfig import load_ai_config
from ..config import generate_default_config, validate_config
from ..configwrite import AI_INI_KEYS, SOURCE_KEYS, write_ai_config, write_config_yaml
from ..paths import (
    AI_CONFIG_EXAMPLE_FILE,
    AI_CONFIG_FILE,
    CONFIG_EXAMPLE_FILE,
    CONFIG_FILE,
    PROJECT_ROOT,
)
from . import theme
from .ops import OpResult
from .tab_service import validate_int
from .widgets import Card, ToolTip, button_row

__all__ = [
    "SettingsTab",
    "validate_int",
    "collect_yaml_values",
    "collect_ai_values",
    "validate_yaml_values",
    "validate_ai_values",
]

# 整数键 -> (界面名, 最小值, 最大值)；上下限与 avengine/aiconfig.py 的钳制范围一致，
# 免得用户填了 3 却被静默改成 5。
_INT_RULES: Dict[str, Tuple[str, int, int]] = {
    "clamav.port": ("clamav.port（clamd 端口）", 1, 65535),
    "clamav.timeout": ("clamav.timeout（连接超时秒）", 1, 3600),
    "scan.timer_interval": ("scan.timer_interval（定时扫描间隔秒）", 10, 604800),
    "timeout": ("timeout（AI 请求超时秒）", 5, 3600),
    "interval": ("interval（批次间隔秒）", 60, 86400),
    "max_rounds": ("max_rounds（单批次最大轮数）", 1, 50),
    "max_events_per_batch": ("max_events_per_batch（单批次最多事件条数）", 10, 1000000),
    "max_event_chars": ("max_event_chars（单条事件最大字符数）", 120, 1000000),
    "max_tool_result_chars": ("max_tool_result_chars（工具结果最大字符数）", 1000, 100000000),
}

_YAML_DEFAULTS: Dict[Tuple[str, str], Any] = {
    ("yara", "rules_path"): "./rules",
    ("clamav", "host"): "127.0.0.1",
    ("clamav", "port"): 3310,
    ("clamav", "timeout"): 30,
    ("sysmon", "channel"): "Microsoft-Windows-Sysmon/Operational",
    ("quarantine", "path"): "./quarantine",
    ("scan", "on_access"): False,
    ("scan", "timer_enabled"): False,
    ("scan", "timer_interval"): 3600,
}

_YAML_TEXT_KEYS = (("yara", "rules_path"), ("clamav", "host"), ("sysmon", "channel"),
                   ("quarantine", "path"))
_YAML_BOOL_KEYS = (("scan", "on_access"), ("scan", "timer_enabled"))

# 控件键 -> configwrite 的 (section, key)，顺序即写入顺序
YAML_KEY_MAP: Tuple[Tuple[str, Tuple[str, str]], ...] = (
    ("yara.rules_path", ("yara", "rules_path")),
    ("clamav.host", ("clamav", "host")),
    ("clamav.port", ("clamav", "port")),
    ("clamav.timeout", ("clamav", "timeout")),
    ("sysmon.channel", ("sysmon", "channel")),
    ("quarantine.path", ("quarantine", "path")),
    ("scan.on_access", ("scan", "on_access")),
    ("scan.timer_enabled", ("scan", "timer_enabled")),
    ("scan.timer_interval", ("scan", "timer_interval")),
)


# -------------------- 纯函数：取值与校验（不依赖 Tk） --------------------


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def collect_yaml_values(getter: Callable[[str], Any]) -> Dict[Tuple[str, str], Any]:
    """
    从 getter(键) 收集 config.yaml 的标量值（键形如 "clamav.port"）。

    注意：要把**当前配置里所有需要保留的键**都带上（这里覆盖 configwrite.YAML_SCALAR_KEYS
    的全部 9 个），否则 configwrite 会按默认值补齐缺失的键。
    """
    return {section_key: getter(name) for name, section_key in YAML_KEY_MAP}


def collect_ai_values(getter: Callable[[str], Any]) -> Dict[str, Any]:
    """从 getter(键) 收集 config.ini 的字段与事件源开关。"""
    values: Dict[str, Any] = {}
    for key in AI_INI_KEYS:
        raw = getter(key)
        if key in ("enabled", "scan_analysis"):
            values[key] = _as_bool(raw)
        elif key in ("timeout", "interval", "max_rounds", "max_events_per_batch",
                     "max_event_chars", "max_tool_result_chars"):
            values[key] = int(raw)          # collect 前必须先通过 validate_ai_values
        else:
            values[key] = "" if raw is None else str(raw).strip()
    values["sources"] = {name: _as_bool(getter(name)) for name in SOURCE_KEYS}
    return values


def validate_yaml_values(values: Mapping[Tuple[str, str], Any],
                         monitor_paths: Sequence[str]) -> Tuple[bool, List[str], Dict[str, Any]]:
    """
    校验 config.yaml 的取值，返回 (是否通过, 错误列表, 规整后的值)。

    port / timeout / timer_interval 必须能转成整数并在范围内，否则整次保存中止。
    """
    errors: List[str] = []
    clean: Dict[str, Any] = {}

    for key, (label, minimum, maximum) in _INT_RULES.items():
        if not key.startswith(("clamav.", "scan.timer_interval")):
            continue
        value, error = validate_int(values.get((key.split(".")[0], key.split(".")[1])),
                                    label, minimum=minimum, maximum=maximum)
        if error:
            errors.append(error)
        else:
            clean[key] = value

    for section_key in _YAML_TEXT_KEYS:
        clean[".".join(section_key)] = str(values.get(section_key) or "").strip()

    for section_key in _YAML_BOOL_KEYS:
        clean[".".join(section_key)] = _as_bool(values.get(section_key))

    host = clean.get("clamav.host", "")
    if host and not re.fullmatch(r"[A-Za-z0-9_.\-:\[\]]+", host):
        errors.append("clamav.host 看起来不是合法的主机名/IP：{}".format(host))

    if not clean.get("yara.rules_path"):
        errors.append("yara.rules_path 不能为空（YARA 引擎会没有规则可用）")

    paths = [str(p).strip() for p in monitor_paths if str(p).strip()]
    clean["scan.monitor_paths"] = paths

    return (not errors), errors, clean


def validate_ai_values(values: Mapping[str, Any]) -> Tuple[bool, List[str], Dict[str, Any]]:
    """校验 config.ini 的取值，返回 (是否通过, 错误列表, 规整后的值)。"""
    errors: List[str] = []
    clean: Dict[str, Any] = {
        "enabled": _as_bool(values.get("enabled")),
        "base_url": str(values.get("base_url") or "").strip(),
        "api_key": str(values.get("api_key") or "").strip(),
        "model": str(values.get("model") or "").strip(),
        "scan_analysis": _as_bool(values.get("scan_analysis")),
    }

    for key, (label, minimum, maximum) in _INT_RULES.items():
        if "." in key:      # config.yaml 的键，这里不处理
            continue
        value, error = validate_int(values.get(key), label, minimum=minimum, maximum=maximum)
        if error:
            errors.append(error)
        else:
            clean[key] = value

    base_url = clean["base_url"]
    if base_url and not re.match(r"^(https?|file)://", base_url, re.IGNORECASE):
        errors.append("base_url 必须以 http:// 或 https:// 开头（当前：{}）".format(base_url))
    if clean["enabled"]:
        if not base_url:
            errors.append("启用 AI 时必须填 base_url（OpenAI 兼容端点）")
        if not clean["model"]:
            errors.append("启用 AI 时必须填 model（例如 deepseek-chat / gpt-4o-mini）")

    clean["sources"] = {name: _as_bool((values.get("sources") or {}).get(name))
                        for name in SOURCE_KEYS}
    return (not errors), errors, clean


def parse_number(text: Any, default: int) -> int:
    """把控件文本转成整数；不合法时退回 default（只用于"规整显示"）。"""
    try:
        return int(str(text).strip(), 10)
    except (TypeError, ValueError):
        return default


def _read_config_yaml_raw(path) -> Dict[str, Any]:
    """直接读 config.yaml（**不做路径归一化**），失败时返回 {}。"""
    try:
        with open(str(path), "r", encoding="utf-8-sig") as handle:
            data = yaml.safe_load(handle)
    except (OSError, yaml.YAMLError, UnicodeDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _raw_scalar(config: Mapping[str, Any], path: Tuple[str, str], default: Any) -> Any:
    section = config.get(path[0])
    if not isinstance(section, Mapping):
        return default
    value = section.get(path[1], default)
    return default if value is None else value


class SettingsTab(ttk.Frame):
    """config.yaml + config.ini（AI）的可视化编辑。"""

    def __init__(self, master, app):
        super().__init__(master, padding=10)
        self.app = app
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)

        self.rows: Dict[str, Any] = {}       # 控件键 -> FieldRow / Checkbutton / Text
        self.vars: Dict[str, tk.BooleanVar] = {}
        self.hint_var = tk.StringVar(value="点「重新载入」从磁盘读取当前生效的配置。")

        self._build_scroll_area()
        self._build_yaml_card()
        self._build_ai_card()
        self._build_actions()

        self.reload_from_disk()

    # ---------------- 滚动容器 ----------------

    def _build_scroll_area(self) -> None:
        outer = ttk.Frame(self)
        outer.grid(row=0, column=0, sticky="nsew")
        outer.columnconfigure(0, weight=1)
        outer.rowconfigure(0, weight=1)

        self.canvas = tk.Canvas(outer, highlightthickness=0, background=theme.BG)
        self.canvas.grid(row=0, column=0, sticky="nsew")
        scroll = ttk.Scrollbar(outer, orient="vertical", command=self.canvas.yview)
        scroll.grid(row=0, column=1, sticky="ns")
        self.canvas.configure(yscrollcommand=scroll.set)

        self.body = ttk.Frame(self.canvas)
        self.body.columnconfigure(0, weight=1)
        window = self.canvas.create_window((0, 0), window=self.body, anchor="nw")
        self.body.bind("<Configure>", lambda _e: self.canvas.configure(
            scrollregion=self.canvas.bbox("all")))
        self.canvas.bind("<Configure>", lambda e: self.canvas.itemconfigure(window, width=e.width))
        self.canvas.bind("<Enter>", self._bind_wheel)
        self.canvas.bind("<Leave>", self._unbind_wheel)

    def _bind_wheel(self, _event=None) -> None:
        self.canvas.bind_all("<MouseWheel>", self._on_wheel)

    def _unbind_wheel(self, _event=None) -> None:
        self.canvas.unbind_all("<MouseWheel>")

    def _on_wheel(self, event) -> None:
        try:
            self.canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
        except tk.TclError:
            pass

    # ---------------- 控件工厂 ----------------

    def _field(self, master, name: str, label: str, browse: Optional[str] = None,
               tip: str = "", show: str = "") -> ttk.Entry:
        row = ttk.Frame(master)
        row.pack(fill="x", pady=2)
        row.columnconfigure(1, weight=1)
        ttk.Label(row, text=label, width=22, anchor="w").grid(row=0, column=0, sticky="w")
        var = tk.StringVar()
        entry = ttk.Entry(row, textvariable=var, show=show)
        entry.grid(row=0, column=1, sticky="ew", padx=(4, 4))
        self.rows[name] = var
        if browse:
            button = ttk.Button(row, text=browse, width=8,
                                command=lambda n=name: self._browse_dir(n))
            button.grid(row=0, column=2, sticky="e")
        if tip:
            ToolTip(entry, tip)
        return entry

    def _check(self, master, name: str, label: str, tip: str = "") -> ttk.Checkbutton:
        var = tk.BooleanVar(value=False)
        self.vars[name] = var
        check = ttk.Checkbutton(master, text=label, variable=var)
        check.pack(anchor="w", pady=1)
        if tip:
            ToolTip(check, tip)
        return check

    def _browse_dir(self, name: str) -> None:
        """选目录：先按当前值定位，选完写回输入框。"""
        var = self.rows.get(name)
        if var is None:
            return
        current = str(var.get() or "").strip()
        if current:
            from ..paths import resolve_path

            try:
                current = str(resolve_path(current))
            except Exception:  # noqa: BLE001
                pass
        try:
            chosen = filedialog.askdirectory(title="选择目录", initialdir=current or str(PROJECT_ROOT))
        except Exception as exc:  # noqa: BLE001 - 无桌面会话时别把页面搞崩
            messagebox.showwarning("选择目录", "打开目录选择框失败: {}".format(exc))
            return
        if chosen:
            var.set(chosen)

    # ---------------- config.yaml ----------------

    def _build_yaml_card(self) -> None:
        card = Card(self.body, "config.yaml（引擎主配置）")
        card.pack(fill="x", expand=False, pady=(0, 8))
        ttk.Label(card, text="路径相对项目根目录解析（也可以直接填绝对路径）：{}".format(PROJECT_ROOT),
                  style="Hint.TLabel", wraplength=900, justify="left").pack(anchor="w", pady=(0, 4))

        self._field(card, "yara.rules_path", "YARA 规则目录", browse="浏览…",
                    tip="递归加载该目录下的 .yar / .yara 文件")
        self._field(card, "clamav.host", "clamav.host", tip="clamd 主机；留空 = 纯 YARA 模式（禁用 ClamAV）")
        self._field(card, "clamav.port", "clamav.port", tip="clamd 监听端口，默认 3310")
        self._field(card, "clamav.timeout", "clamav.timeout（秒）", tip="连接/扫描超时，需为整数")
        self._field(card, "sysmon.channel", "sysmon.channel", tip="Sysmon 事件通道名")
        self._field(card, "quarantine.path", "隔离目录", browse="浏览…",
                    tip="检出威胁后文件的存放目录")

        self._check(card, "scan.on_access", "scan.on_access：实时监控（Sysmon 文件事件触发扫描）")
        self._check(card, "scan.timer_enabled", "scan.timer_enabled：启用定时批量扫描")
        self._field(card, "scan.timer_interval", "scan.timer_interval（秒）",
                    tip="定时扫描间隔，整数秒（最小 10）")

        ttk.Label(card, text="scan.monitor_paths（一行一个目录）").pack(anchor="w", pady=(6, 2))
        text = tk.Text(card, height=5, wrap="none", relief="flat",
                       background=theme.PANE_BG, foreground=theme.PANE_FG,
                       insertbackground=theme.PANE_FG, font=theme.mono_font())
        text.pack(fill="x", expand=False)
        self.rows["scan.monitor_paths"] = text

    # ---------------- config.ini（AI） ----------------

    def _build_ai_card(self) -> None:
        card = Card(self.body, "config.ini（AI 分析）")
        card.pack(fill="x", expand=False, pady=(0, 8))
        ttk.Label(card, text="文件: {}（不存在时保存会先按 config.ini.example 初始化）".format(AI_CONFIG_FILE),
                  style="Hint.TLabel", wraplength=900, justify="left").pack(anchor="w", pady=(0, 4))

        self._check(card, "enabled", "enabled：启用 AI 批次分析 / 检出联动",
                    "打开后还会校验 base_url 与 model 是否填写")

        self._field(card, "base_url", "base_url", tip="OpenAI 兼容端点，例如 https://api.deepseek.com/v1")
        self.api_key_entry = self._field(card, "api_key", "api_key",
                                         tip="API 密钥；本地模型可留空。默认掩码显示", show="*")

        show_row = ttk.Frame(card)
        show_row.pack(fill="x")
        self.show_key_var = tk.BooleanVar(value=False)
        show_check = ttk.Checkbutton(show_row, text="显示 API 密钥", variable=self.show_key_var,
                                     command=self._toggle_api_key)
        show_check.pack(anchor="e")

        self._field(card, "model", "model", tip="模型名，例如 deepseek-chat / gpt-4o-mini / qwen2.5:14b")
        self._field(card, "timeout", "timeout（秒）", tip="单次 HTTP 请求超时，最小 5")
        self._field(card, "interval", "interval（秒）", tip="批次采集间隔，最小 60")
        self._field(card, "max_rounds", "max_rounds", tip="单批次会话最大轮数（1-50）")
        self._field(card, "max_events_per_batch", "max_events_per_batch", tip="单批次最多发送的事件条数")
        self._field(card, "max_event_chars", "max_event_chars", tip="单条事件文本最大字符数")
        self._field(card, "max_tool_result_chars", "max_tool_result_chars",
                    tip="单个工具结果回传上限，超出会截断")

        self._check(card, "scan_analysis", "scan_analysis：扫描检出后联动 AI 分析")

        ttk.Label(card, text="[sources] 事件源开关（进批次的事件源）").pack(anchor="w", pady=(8, 2))
        grid = ttk.Frame(card)
        grid.pack(fill="x")
        for index, name in enumerate(SOURCE_KEYS):
            var = tk.BooleanVar(value=True)
            self.vars[name] = var
            check = ttk.Checkbutton(grid, text=name, variable=var)
            check.grid(row=index // 4, column=index % 4, sticky="w", padx=(0, 12), pady=1)
            ToolTip(check, "事件源 {} 是否参与 AI 批次".format(name))
        ttk.Label(card,
                  text="提示：fileio（文件读写）事件量极大，恒不进入批次；AI 需要文件访问证据时会"
                       "用 grep_events 工具按需检索，该开关只控制这种按需检索是否允许。",
                  style="Hint.TLabel", wraplength=900, justify="left").pack(anchor="w", pady=(4, 0))

        self._toggle_api_key()

    def _toggle_api_key(self) -> None:
        """在掩码 / 明文之间切换 api_key 输入框（不改变值本身）。"""
        entry = getattr(self, "api_key_entry", None)
        if entry is None:
            return
        try:
            entry.configure(show="" if self.show_key_var.get() else "*")
        except tk.TclError:
            pass

    # ---------------- 底部按钮 ----------------

    def _build_actions(self) -> None:
        bar = ttk.Frame(self)
        bar.grid(row=1, column=0, sticky="ew", pady=(6, 0))
        row = button_row(bar, [
            ("保存全部", self.save_all, "先写 config.yaml 再写 config.ini，然后重新加载配置（写前自动备份）"),
            ("重新载入", self.reload_from_disk, "丢弃未保存的修改，从磁盘读回并刷新所有控件"),
            ("校验配置", self.check_config, "只读校验 config.yaml 能否被解析（不落盘）"),
            ("从模板重建 config.yaml", self.rebuild_config,
             "用 config.example.yaml 覆盖 config.yaml（原文件会备份，需二次确认）"),
        ])
        row.pack(side="left")
        ttk.Label(bar, textvariable=self.hint_var, style="Hint.TLabel",
                  wraplength=640, justify="left").pack(side="left", padx=(10, 0))
        # 路径信息单独一行：避免 on_status() 把"保存成功/失败"的提示覆盖掉
        self.paths_label = ttk.Label(bar, text="", style="Hint.TLabel",
                                     wraplength=980, justify="left")
        self.paths_label.pack(side="left", padx=(10, 0), fill="x", expand=True)

    # ---------------- 载入 / 刷新 ----------------

    def reload_from_disk(self) -> None:
        """从磁盘读回 config.yaml（保留原样，不做路径归一化）与 config.ini，刷新全部控件。"""
        raw = _read_config_yaml_raw(CONFIG_FILE)
        for name, section_key in YAML_KEY_MAP:
            var = self.rows.get(name)
            if var is None:
                continue
            value = _raw_scalar(raw, section_key, _YAML_DEFAULTS.get(section_key, ""))
            if isinstance(var, tk.BooleanVar):
                var.set(_as_bool(value))
            else:
                var.set("" if value is None else str(value))

        monitor = raw.get("scan") if isinstance(raw.get("scan"), Mapping) else {}
        paths = monitor.get("monitor_paths") if isinstance(monitor, Mapping) else None
        if not isinstance(paths, (list, tuple)):
            paths = []
        text = self.rows.get("scan.monitor_paths")
        if isinstance(text, tk.Text):
            text.delete("1.0", "end")
            text.insert("1.0", "\n".join(str(p) for p in paths))

        ai = load_ai_config()
        for key in AI_INI_KEYS:
            if key in ("enabled", "scan_analysis"):
                var = self.vars.get(key)
                if var is not None:
                    var.set(bool(getattr(ai, key)))
                continue
            value = getattr(ai, key)
            entry_var = self.rows.get(key)
            if entry_var is not None:
                entry_var.set("" if value is None else str(value))
        for name in SOURCE_KEYS:
            var = self.vars.get(name)
            if var is not None:
                var.set(bool(ai.sources.get(name, True)))

        self.hint_var.set("已从磁盘载入：{} / {}（{}）".format(
            CONFIG_FILE.name, AI_CONFIG_FILE.name,
            "AI 已启用" if ai.active else "AI 未启用"))

    def on_config_reloaded(self) -> None:
        """
        主窗口重新读取配置后会回调这里。

        **故意不刷新控件**：保存后 app.reload_config() 也会走到这里，如果顺手回填，
        用户还没保存的其它改动会被静默覆盖。控件只在「重新载入」按钮里刷新。
        """
        self.hint_var.set("配置已由主窗口重新加载（控件内容未变；如需回填请点「重新载入」）")

    def on_status(self, status: Dict[str, Any]) -> None:
        """状态钩子：这里只用来提示配置文件名与项目根（单独一行，不覆盖操作提示）。"""
        if not isinstance(status, dict):
            return
        paths = status.get("paths") or {}
        self.paths_label.configure(text="项目根: {}   config: {}   AI 配置: {}".format(
            paths.get("project_root", PROJECT_ROOT),
            paths.get("config", CONFIG_FILE),
            paths.get("ai_config", AI_CONFIG_FILE)))

    # ---------------- 收集控件值 ----------------

    def _gather(self) -> Tuple[Dict[Tuple[str, str], Any], List[str], Dict[str, Any]]:
        """把控件内容收集成纯数据（不写盘、不碰 ops）。"""
        getter = self._getter
        yaml_values = collect_yaml_values(getter)
        text = self.rows.get("scan.monitor_paths")
        monitor_paths = []
        if isinstance(text, tk.Text):
            monitor_paths = [line.strip() for line in text.get("1.0", "end").splitlines()
                             if line.strip()]
        ai_values = collect_ai_values(getter)
        return yaml_values, monitor_paths, ai_values

    def _getter(self, key: str) -> Any:
        if key in self.vars:
            return self.vars[key].get()
        if key in self.rows:
            var = self.rows[key]
            if isinstance(var, tk.Text):
                return var.get("1.0", "end")
            return var.get()
        return ""

    # ---------------- 动作 ----------------

    def save_all(self) -> None:
        try:
            yaml_values, monitor_paths, ai_values = self._gather()
        except (tk.TclError, ValueError) as exc:
            messagebox.showwarning("保存", "读取控件内容失败: {}".format(exc))
            return

        ok_yaml, yaml_errors, clean_yaml = validate_yaml_values(yaml_values, monitor_paths)
        ok_ai, ai_errors, clean_ai = validate_ai_values(ai_values)
        errors = yaml_errors + ai_errors
        if errors:
            messagebox.showwarning("保存中止", "配置未通过校验，未写入任何文件：\n\n• " +
                                   "\n• ".join(errors))
            self.hint_var.set("保存中止：{} 项校验未通过".format(len(errors)))
            return

        # 交给子线程的只有"纯数据"，控件一律在主线程读
        scalars = {section_key: clean_yaml[".".join(section_key)]
                   for _name, section_key in YAML_KEY_MAP}
        ini_fields = {key: clean_ai[key] for key in AI_INI_KEYS}
        sources = dict(clean_ai["sources"])
        monitor = list(clean_yaml["scan.monitor_paths"])

        def job() -> OpResult:
            """后台线程：写盘（configwrite 保注释；两份文件各自先备份）。"""
            yaml_backup = write_config_yaml(CONFIG_FILE, scalars, monitor,
                                            example=CONFIG_EXAMPLE_FILE)
            ini_backup = write_ai_config(AI_CONFIG_FILE, ini_fields, sources,
                                         example=AI_CONFIG_EXAMPLE_FILE)
            output = "config.yaml  备份: {}\nconfig.ini   备份: {}\nmonitor_paths: {}".format(
                yaml_backup or "（无，首次创建）", ini_backup or "（无，首次创建）",
                ", ".join(monitor) if monitor else "（空）")
            return OpResult(True, "配置已保存", output,
                            {"yaml_backup": str(yaml_backup) if yaml_backup else None,
                             "ini_backup": str(ini_backup) if ini_backup else None})

        def done(result: OpResult) -> None:
            if not result.ok:
                messagebox.showwarning("保存配置", result.message)
                self.hint_var.set("保存失败：{}".format(result.message))
                return
            # 先让主窗口重新加载配置（会回调各页的 on_config_reloaded）
            try:
                self.app.reload_config()
            except Exception as exc:  # noqa: BLE001
                self.pane_hint("配置已写入，但重新加载失败: {}".format(exc))
            self.app.set_status("配置已保存")
            self.hint_var.set(
                "已保存。config.yaml 备份: {} ｜ config.ini 备份: {}".format(
                    result.data.get("yaml_backup") or "（无）",
                    result.data.get("ini_backup") or "（无）"))
            messagebox.showinfo(
                "保存配置",
                "已写入：\n  {}\n  {}\n\n备份文件：\n  config.yaml: {}\n  config.ini : {}".format(
                    CONFIG_FILE, AI_CONFIG_FILE,
                    result.data.get("yaml_backup") or "（无，首次创建）",
                    result.data.get("ini_backup") or "（无，首次创建）"))

        self.app.run_task("正在保存配置…", job, done)

    def pane_hint(self, text: str) -> None:
        """没有输出面板，就在提示行里反馈（同时写状态栏）。"""
        self.hint_var.set(text)
        try:
            self.app.set_status(text)
        except Exception:  # noqa: BLE001
            pass

    def check_config(self) -> None:
        error = validate_config(CONFIG_FILE)
        if error is None:
            messagebox.showinfo("校验配置", "{} 解析正常。".format(CONFIG_FILE))
            self.pane_hint("config.yaml 解析正常")
        else:
            messagebox.showwarning("校验配置", "{} 解析失败：\n\n{}".format(CONFIG_FILE, error))
            self.pane_hint("config.yaml 解析失败：{}".format(error))

    def rebuild_config(self) -> None:
        if CONFIG_FILE.is_file() and not messagebox.askyesno(
                "从模板重建 config.yaml",
                "将用 config.example.yaml 覆盖：\n{}\n\n原文件会先备份为 {}.bak-<时间戳>。\n"
                "继续吗？".format(CONFIG_FILE, CONFIG_FILE.name)):
            self.pane_hint("已取消重建 config.yaml")
            return

        def job() -> OpResult:
            path = generate_default_config(CONFIG_FILE, force=True)
            backups = sorted(CONFIG_FILE.parent.glob("{}.bak-*".format(CONFIG_FILE.name)))
            latest = str(backups[-1]) if backups else None
            return OpResult(True, "已从模板重建 config.yaml", "写入: {}\n原文件备份: {}".format(
                path, latest or "（无）"), {"backup": latest})

        def done(result: OpResult) -> None:
            self.app.show_result("从模板重建 config.yaml", result)
            if not result.ok:
                return
            self.reload_from_disk()
            try:
                self.app.reload_config()
            except Exception:  # noqa: BLE001
                pass
            self.pane_hint("已重建 config.yaml；备份: {}".format(
                result.data.get("backup") or "（无）"))

        self.app.run_task("正在从模板重建 config.yaml…", job, done)
