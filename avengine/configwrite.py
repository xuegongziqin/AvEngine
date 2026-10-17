"""
configwrite.py - 保注释地写回 config.yaml / config.ini

CLI 与 GUI 都需要"改几个值但别把注释弄丢"。直接 yaml.safe_dump / configparser.write
会把 config.example.yaml、config.ini.example 里那些说明性注释全部抹掉，
用户下一次手工编辑就失去了上下文。这里用**按行定位**的方式只改目标键的值：

  * 标量键：保留行尾注释与缩进，只替换冒号后的值
  * 列表键（monitor_paths）：整块重写为 YAML 块序列
  * 段/键不存在：按缩进补齐，不重排其它内容
  * 写盘前自动备份为 <文件名>.bak-<时间戳>

对应的单元测试覆盖"改完还能被 load_config / load_ai_config 正确解析"与"注释仍在"。
"""

from __future__ import annotations

import re
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence

# -------------------- 通用小工具 --------------------


def _backup(path: Path) -> Optional[Path]:
    if not path.is_file():
        return None
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup = path.with_name("{}.bak-{}".format(path.name, stamp))
    try:
        shutil.copy2(str(path), str(backup))
        return backup
    except OSError:
        return None


def format_scalar(value: Any) -> str:
    """把 Python 值转成 YAML/INI 里的字面量。"""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    text = "" if value is None else str(value)
    if text == "":
        return '""'
    # 需要引号的情况：包含 YAML 特殊字符/首尾空白/看起来像数字或布尔
    needs_quote = (
        text != text.strip()
        or any(ch in text for ch in ':#{}[]&*!|>%@`"\'')
        or text.startswith("-")
        or re.fullmatch(r"(?i)(true|false|null|yes|no|on|off|~)", text) is not None
    )
    if needs_quote:
        # 单引号风格：反斜杠不需要转义，Windows 路径写出来最可读（用户还要手工编辑）
        if "'" not in text:
            return "'" + text + "'"
        return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return text


def _section_bounds(lines: Sequence[str], section: str) -> Optional[tuple]:
    """
    返回顶层段 section 的行范围 [start, end)：start 是 "section:" 那一行，
    end 是下一个顶层键（或文件末尾）。找不到返回 None。
    """
    pattern = re.compile(r"^{}\s*:\s*(#.*)?$".format(re.escape(section)))
    start = None
    for index, line in enumerate(lines):
        if pattern.match(line):
            start = index
            break
    if start is None:
        return None
    end = len(lines)
    for index in range(start + 1, len(lines)):
        line = lines[index]
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line[:1].isspace():   # 下一个顶层键
            end = index
            break
    return (start, end)


def _key_line_pattern(key: str) -> "re.Pattern[str]":
    return re.compile(r"^(?P<indent>\s+){}\s*:(?P<value>.*)$".format(re.escape(key)))


def _ini_section_bounds(lines: Sequence[str], section: str) -> Optional[tuple]:
    """INI 版的段范围：[section] 到下一个 [...] 或文件末尾。"""
    pattern = re.compile(r"^\[{}\]\s*$".format(re.escape(section)), re.IGNORECASE)
    start = None
    for index, line in enumerate(lines):
        if pattern.match(line.strip()):
            start = index
            break
    if start is None:
        return None
    end = len(lines)
    for index in range(start + 1, len(lines)):
        if lines[index].strip().startswith("["):
            end = index
            break
    return (start, end)


def set_scalar(lines: list, section: str, key: str, value: Any) -> list:
    """在（已存在的）段里设置标量键；保留原行的行尾注释。"""
    bounds = _section_bounds(lines, section)
    literal = format_scalar(value)
    if bounds is None:
        lines.append("{}:".format(section))
        lines.append("  {}: {}".format(key, literal))
        return lines

    start, end = bounds
    pattern = _key_line_pattern(key)
    for index in range(start + 1, end):
        match = pattern.match(lines[index])
        if not match:
            continue
        original = match.group("value")
        comment = ""
        hash_pos = original.find(" #")
        if hash_pos >= 0:
            comment = original[hash_pos:]
        elif original.strip().startswith("#"):
            comment = " " + original.strip()
        lines[index] = "{}{}: {}{}".format(match.group("indent"), key, literal, comment)
        return lines

    # 键不存在：按同级键的缩进插入到段末（跳过尾部空行）
    indent = "  "
    for index in range(start + 1, end):
        match = re.match(r"^(\s+)\S", lines[index])
        if match:
            indent = match.group(1)
            break
    insert_at = end
    while insert_at - 1 > start and not lines[insert_at - 1].strip():
        insert_at -= 1
    lines.insert(insert_at, "{}{}: {}".format(indent, key, literal))
    return lines


def set_sequence(lines: list, section: str, key: str, values: Iterable[str]) -> list:
    """设置 YAML 块序列（如 scan.monitor_paths），整块重写。"""
    values = [str(v) for v in values]
    bounds = _section_bounds(lines, section)
    if bounds is None:
        lines.append("{}:".format(section))
        lines.append("  {}:".format(key))
        for value in values:
            lines.append("    - {}".format(format_scalar(value)))
        return lines

    start, end = bounds
    pattern = _key_line_pattern(key)
    key_index = None
    for index in range(start + 1, end):
        if pattern.match(lines[index]):
            key_index = index
            break

    block = ["  {}:".format(key)] if values else ["  {}: []".format(key)]
    for value in values:
        block.append("    - {}".format(format_scalar(value)))

    if key_index is None:
        insert_at = end
        while insert_at - 1 > start and not lines[insert_at - 1].strip():
            insert_at -= 1
        lines[insert_at:insert_at] = block
        return lines

    # 覆盖 key 行以及其后的 "- item" 行
    remove_end = key_index + 1
    while remove_end < end:
        stripped = lines[remove_end].strip()
        if stripped.startswith("- ") or stripped == "-":
            remove_end += 1
        elif not stripped:
            break
        else:
            break
    lines[key_index:remove_end] = block
    return lines


# -------------------- config.yaml --------------------

YAML_SCALAR_KEYS = (
    ("yara", "rules_path"),
    ("clamav", "host"),
    ("clamav", "port"),
    ("clamav", "timeout"),
    ("sysmon", "channel"),
    ("quarantine", "path"),
    ("scan", "on_access"),
    ("scan", "timer_enabled"),
    ("scan", "timer_interval"),
)


def relativize(value: Any, root: Optional[Path] = None) -> Any:
    """
    把"位于项目根下的绝对路径"还原成相对写法。

    为什么需要：load_config() 会把 rules_path / quarantine.path / monitor_paths
    归一化成绝对路径，如果原样写回，用户的 config.yaml 会从 `./rules` 变成
    `E:\\Python\\AntierX\\rules` —— 一旦把发布目录搬到别的机器或别的盘就失效了。
    项目根之外的路径（例如 D:\\watch）保持绝对，别乱改用户的意思。
    """
    if not isinstance(value, str) or not value:
        return value
    base = Path(root) if root is not None else _project_root()
    try:
        candidate = Path(value)
    except (TypeError, ValueError):
        return value
    if not candidate.is_absolute():
        return value
    try:
        relative = candidate.resolve().relative_to(base.resolve())
    except (ValueError, OSError):
        return value            # 不在项目根下 → 保持绝对
    text = relative.as_posix()
    if text == ".":
        return "./"
    return "./" + text


def _project_root() -> Path:
    # 延迟导入，避免 configwrite 依赖 paths 的导入顺序
    from .paths import PROJECT_ROOT

    return PROJECT_ROOT


#: 需要做"绝对路径→相对路径"还原的键
PATH_KEYS = (("yara", "rules_path"), ("quarantine", "path"))


def apply_config_yaml(text: str, scalars: Mapping[tuple, Any],
                      monitor_paths: Optional[Sequence[str]] = None) -> str:
    """
    纯函数：把标量（以及可选的监控目录列表）写进 YAML 文本（保留注释）。

    `monitor_paths=None` 表示**不动** scan.monitor_paths ——
    只改 clamav 段的调用方（如 `avengine config --clamav-host`）必须传 None，
    否则会把用户已有的监控路径整段清空（这是真出过的事故：一条 --clamav-host
    把 monitor_paths 的条目全删了）。
    """
    lines = text.splitlines()
    for (section, key), value in scalars.items():
        if (section, key) in PATH_KEYS:
            value = relativize(value)
        lines = set_scalar(lines, section, key, value)
    if monitor_paths is not None:
        lines = set_sequence(lines, "scan", "monitor_paths",
                             [relativize(p) for p in monitor_paths])
    return "\n".join(lines).rstrip("\n") + "\n"


def write_config_yaml(path: Path, scalars: Mapping[tuple, Any],
                      monitor_paths: Optional[Sequence[str]] = None,
                      example: Optional[Path] = None) -> Optional[Path]:
    """
    写回 config.yaml（不存在时先用 example 初始化）。返回备份路径（无备份为 None）。

    monitor_paths 默认 None = 保持文件里已有的监控路径不变。
    """
    path = Path(path)
    if not path.is_file() and example is not None and Path(example).is_file():
        path.write_text(Path(example).read_text(encoding="utf-8"), encoding="utf-8")
    text = path.read_text(encoding="utf-8-sig") if path.is_file() else ""
    backup = _backup(path)
    path.write_text(apply_config_yaml(text, scalars, monitor_paths), encoding="utf-8")
    return backup


# -------------------- config.ini（AI） --------------------

AI_INI_KEYS = ("enabled", "base_url", "api_key", "model", "timeout", "interval",
               "max_rounds", "max_events_per_batch", "max_event_chars",
               "max_tool_result_chars", "scan_analysis")

SOURCE_KEYS = ("sysmon", "process", "network", "dns", "powershell", "system",
               "application", "fileio")


def format_ini_scalar(value: Any) -> str:
    """
    INI 字面量：**不加引号**。

    configparser 不会去引号，给 URL 加引号会变成值的一部分（'base_url' 就带上字面引号，
    直接让 AI 请求失败）。同时把换行压成空格，避免写出跨行的值。
    """
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    text = "" if value is None else str(value)
    return " ".join(text.split())


def set_ini_value(lines: list, section: str, key: str, value: Any) -> list:
    """INI 里设置键值；与 YAML 版同样的"按行定位 + 保留注释"策略。"""
    literal = format_ini_scalar(value)
    bounds = _ini_section_bounds(lines, section)
    if bounds is None:
        if lines and lines[-1].strip():
            lines.append("")
        lines.append("[{}]".format(section))
        lines.append("{} = {}".format(key, literal))
        return lines

    start, end = bounds
    pattern = re.compile(r"^(?P<indent>\s*){}\s*=(?P<value>.*)$".format(re.escape(key)),
                         re.IGNORECASE)
    for index in range(start + 1, end):
        match = pattern.match(lines[index])
        if not match:
            continue
        original = match.group("value")
        comment = ""
        hash_pos = original.find(" #")
        if hash_pos < 0:
            hash_pos = original.find(" ;")
        if hash_pos >= 0:
            comment = original[hash_pos:].strip()
        lines[index] = "{}{} = {}".format(match.group("indent"), key, literal)
        if comment:
            # configparser 默认不解析行尾注释，留着会并进值里 —— 挪到独立行
            lines.insert(index, "{}{}".format(match.group("indent"), comment))
        return lines

    insert_at = end
    while insert_at - 1 > start and not lines[insert_at - 1].strip():
        insert_at -= 1
    lines.insert(insert_at, "{} = {}".format(key, literal))
    return lines


def apply_ai_ini(text: str, fields: Mapping[str, Any], sources: Mapping[str, bool]) -> str:
    """纯函数：写 [ai] 段的字段与 [sources] 段的开关（保留注释）。"""
    lines = text.splitlines()
    for key in AI_INI_KEYS:
        if key in fields:
            lines = set_ini_value(lines, "ai", key, fields[key])
    for name in SOURCE_KEYS:
        if name in sources:
            lines = set_ini_value(lines, "sources", name, bool(sources[name]))
    return "\n".join(lines).rstrip("\n") + "\n"


def write_ai_config(path: Path, fields: Mapping[str, Any],
                    sources: Mapping[str, bool],
                    example: Optional[Path] = None) -> Optional[Path]:
    """写回 config.ini（不存在时先用 example 初始化）。返回备份路径。"""
    path = Path(path)
    if not path.is_file() and example is not None and Path(example).is_file():
        path.write_text(Path(example).read_text(encoding="utf-8-sig"), encoding="utf-8")
    text = path.read_text(encoding="utf-8-sig") if path.is_file() else ""
    backup = _backup(path)
    path.write_text(apply_ai_ini(text, fields, sources), encoding="utf-8")
    return backup
