"""
cli.py - 命令行入口

Python 外壳（参数解析 / 菜单 / 配置 / 展示）调用 C++ 内核 avengine_core.dll 完成
扫描、实时监控与 AI 分析。被取代的 Python 引擎模块已归档到 legacy/。

子命令：scan / monitor / status / update-db / ai
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, NamedTuple, Optional, Tuple

from colorama import Fore, Style, init as colorama_init

from . import __version__
from .config import generate_default_config, load_config, validate_config
from .paths import CONFIG_EXAMPLE_FILE, CONFIG_FILE, LOG_DIR, LOG_FILE, SYSMON_CONFIG, sysmon_exe
from .utils import compute_file_hash, is_admin, make_console_tolerant, quarantine_file, setup_logging

logger = logging.getLogger(__name__)


# -------------------- 扫描 --------------------

class ScanResult(NamedTuple):
    """一次扫描的结果：命中明细 + 实际参与扫描的引擎。"""

    yara_hits: Dict[str, List[str]]
    clam_hits: Dict[str, str]
    engines: List[str]
    aborted: bool = False


def _has_yara_rules(rules_path: Optional[str]) -> bool:
    """规则目录里至少有一个 .yar / .yara 文件才算 YARA 可用（避免静默降级）。"""
    if not rules_path:
        return False
    root = Path(rules_path)
    if not root.is_dir():
        return False
    checked = 0
    for item in root.rglob("*"):
        checked += 1
        if checked > 20000:
            break
        if item.is_file() and item.suffix.lower() in (".yar", ".yara"):
            return True
    return False


def _engine_readiness(config: Dict) -> Tuple[Optional[str], Dict, List[str], bool]:
    """
    扫描前先确认 YARA / ClamAV 能不能用，并把结论作为提示返回。

    背景：引擎不可用时旧版会直接打印「未发现威胁」，把「没扫」说成「干净」。
    这里改为显式提示，ClamAV 连不上时也不再把端口退化成 0（等价于关闭引擎）。

    Returns:
        (rules_path, 传给 C++ 内核的 clamav 段, 提示列表, 是否至少有一个引擎可用)
    """
    from . import core_bridge

    warnings: List[str] = []
    rules_path = (config.get("yara") or {}).get("rules_path")
    yara_ok = _has_yara_rules(rules_path)
    if not yara_ok:
        warnings.append(
            "YARA 引擎未启用：规则目录不可用或为空 (yara.rules_path={})，"
            "请检查 config.yaml 或 rules\\ 目录".format(rules_path or "未配置")
        )

    clam = config.get("clamav") or {}
    host = str(clam.get("host", "127.0.0.1") or "")
    port = int(clam.get("port", 3310) or 3310)
    timeout = int(clam.get("timeout", 30) or 30)
    clam_for_core: Dict = {}

    if not host:
        warnings.append("ClamAV 已按配置禁用 (clamav.host 为空)，配置为纯 YARA 模式")
    else:
        try:
            info = core_bridge.clam_version(host, port, max(1, min(timeout, 5)))
        except core_bridge.CoreError as e:
            info = {}
            warnings.append("ClamAV 探测失败: {}".format(e))
        if info.get("available"):
            clam_for_core = {"host": host, "port": port, "timeout": timeout}
        else:
            warnings.append(
                "ClamAV 不可用 ({}:{})：本次扫描不含 ClamAV 结论。".format(host, port)
                + "启动 clamd 后重试：管理员执行 scripts\\install.bat，或 net start clamd"
            )

    return rules_path, clam_for_core, warnings, (yara_ok or bool(clam_for_core))


def scan_target(config: Dict, target: Path) -> ScanResult:
    """
    用 C++ 内核（YARA + ClamAV）扫描目标。

    Returns:
        ScanResult（yara 命中 {路径: 规则}、clamav 命中 {路径: 病毒名}、生效引擎、是否未执行）
    """
    from . import core_bridge

    quarantine_path = config.get("quarantine", {}).get("path", "./quarantine")

    if target.is_file():
        print(f"正在扫描文件: {target}")
    elif target.is_dir():
        print(f"正在扫描目录: {target}")
    else:
        print(f"路径不存在: {target}")
        return ScanResult({}, {}, [], True)

    if not core_bridge.is_available():
        print(f"C++ 内核未加载，无法扫描: {core_bridge.load_error()}")
        return ScanResult({}, {}, [], True)

    rules_path, clam_cfg, warnings, any_engine = _engine_readiness(config)
    for message in warnings:
        print(f"{Fore.YELLOW}[警告]{Style.RESET_ALL} {message}")
    if not any_engine:
        print(f"{Fore.RED}[错误]{Style.RESET_ALL} YARA 与 ClamAV 都不可用，本次扫描未执行。")
        print("        排查: avengine status 看引擎状态；avengine config --validate 看 config.yaml。")
        return ScanResult({}, {}, [], True)

    yara_hits: Dict[str, List[str]] = {}
    clam_hits: Dict[str, str] = {}

    try:
        if target.is_file():
            result = core_bridge.scan_path(target, rules_path, clam_cfg)
            matches = (result.get("yara") or {}).get("matches") or []
            if matches:
                yara_hits[result["path"]] = matches
            virus = (result.get("clamav") or {}).get("virus")
            if virus:
                clam_hits[result["path"]] = virus
            if rules_path and not (result.get("yara") or {}).get("available"):
                print(f"{Fore.YELLOW}[警告]{Style.RESET_ALL} YARA 规则未能加载"
                      "（规则语法错误或版本不兼容，见 status 的「跳过 N 个」）")
            if clam_cfg and not (result.get("clamav") or {}).get("available"):
                print(f"{Fore.YELLOW}[警告]{Style.RESET_ALL} ClamAV 扫描失败"
                      "（clamd 中途断开或拒绝该文件），本次结果不含 ClamAV 结论")
        else:
            result = core_bridge.scan_dir(target, rules_path, clam_cfg)
            yara_hits = result.get("yara", {})
            clam_hits = result.get("clamav", {})
    except core_bridge.CoreError as e:
        print(f"扫描失败: {e}")
        return ScanResult({}, {}, [], True)

    for path, hits in yara_hits.items():
        print(f"{Fore.RED}[YARA]{Style.RESET_ALL} {path}: {', '.join(hits)}")
    for path, virus in clam_hits.items():
        print(f"{Fore.RED}[ClamAV]{Style.RESET_ALL} {path}: {virus}")

    engines = []
    if rules_path:
        engines.append("YARA")
    if clam_cfg:
        engines.append("ClamAV")
    engines_text = " + ".join(engines) if engines else "无"

    infected = sorted(set(yara_hits) | set(clam_hits))
    if not infected:
        print(f"未发现威胁。(引擎: {engines_text})")
        return ScanResult(yara_hits, clam_hits, engines)

    print(f"\n发现 {len(infected)} 个受感染文件。(引擎: {engines_text})")
    _ai_detection_analysis(config, infected, yara_hits, clam_hits)

    # 非交互环境（管道/服务/被其它程序调用）读不到输入时 input() 会抛 EOFError，
    # 以前直接崩在这里、还留一个 traceback。默认**不隔离**（不代替用户处置），
    # 只把结论和后续命令打出来 —— 安全工具不该在没有明确同意时动用户的文件。
    try:
        answer = input("是否将受感染文件隔离? (y/n): ").strip().lower()
    except EOFError:
        answer = ""
        print("（非交互环境：默认不隔离。需要隔离请手动运行本命令并输入 y，"
              "或对单个文件用 avengine quarantine）")
    if answer == "y":
        for path in infected:
            new_path = quarantine_file(path, quarantine_path)
            if new_path:
                print(f"  已隔离: {path} -> {new_path}")
    else:
        print("跳过隔离。")

    return ScanResult(yara_hits, clam_hits, engines)


def cmd_scan(args: argparse.Namespace) -> int:
    config = _prepare_config(args)
    target = Path(args.path).expanduser()
    if not target.exists():
        print(f"路径不存在: {target}")
        return 1
    if target.is_file():
        print(f"SHA256: {compute_file_hash(str(target))}")
    outcome = scan_target(config, target)
    if outcome.aborted:
        return 2
    return 1 if (outcome.yara_hits or outcome.clam_hits) else 0


# -------------------- 实时监控 --------------------

def _sysmon_installed() -> bool:
    try:
        import winreg
    except ImportError:
        return False
    try:
        winreg.CloseKey(
            winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\SysmonDrv")
        )
        return True
    except OSError:
        return False


def _ensure_sysmon() -> bool:
    if sys.platform != "win32":
        print("实时监控需要 Windows 平台。")
        return False
    if not _sysmon_installed():
        exe = sysmon_exe()
        if not exe.is_file():
            print(f"未检测到 Sysmon，且找不到安装程序: {exe}")
            print("请把 Sysmon 15.x 放到 bina/Sysmon/（Windows 7 用 13.x，放 bina/Sysmon/sysmonwin7/）后重试。")
            print("可运行 scripts\\sysmon_which.bat 查看本机应使用哪个版本。")
            return False
        print(f"未检测到 Sysmon，正在安装（使用 {exe.name}）...")
        cmd = [str(exe), "-accepteula", "-i"]
        cfg = Path(SYSMON_CONFIG)
        if cfg.is_file():
            cmd.append(str(cfg))
        try:
            subprocess.run(cmd, check=True, capture_output=True, text=True)
            print("Sysmon 安装完成。")
        except (subprocess.CalledProcessError, OSError) as e:
            print(f"Sysmon 安装失败: {e}")
            return False
    else:
        subprocess.run(["sc", "start", "Sysmon"], capture_output=True)

    # clamd 服务可选：安装了就尝试拉起
    try:
        subprocess.run(["sc", "start", "clamd"], capture_output=True)
    except OSError:
        pass
    return True


def _print_native_threat(event: Dict) -> None:
    """打印 C++ 监控内核上报的威胁事件。"""
    path = event.get("path", "")
    details = [f"YARA: {rule}" for rule in (event.get("yara") or [])]
    if event.get("clamav"):
        details.append(f"ClamAV: {event['clamav']}")
    print(
        f"\n{Fore.RED}[!!!] 威胁告警{Style.RESET_ALL}: {path}\n"
        f"  细节: {' | '.join(details) if details else '(未知引擎)'}\n"
        f"  处理: {event.get('action', '')}\n"
    )
    if event.get("quarantined_to"):
        print(f"  已隔离: {event['quarantined_to']}")


def _start_native_monitor(config: Dict) -> bool:
    """用 C++ 内核启动常驻监控；失败打印原因并返回 False。"""
    from . import core_bridge
    from .paths import resolve_path

    scan_cfg = config.get("scan", {}) or {}
    rules = (config.get("yara") or {}).get("rules_path")
    quar = (config.get("quarantine") or {}).get("path", "./quarantine")
    channel = (config.get("sysmon") or {}).get("channel", core_bridge.DEFAULT_SYSMON_CHANNEL)
    monitor_paths = [str(resolve_path(p)) for p in scan_cfg.get("monitor_paths", [])]
    try:
        core_bridge.monitor_start(rules, quar, config.get("clamav") or {}, channel, monitor_paths, 0, True)
        return True
    except core_bridge.CoreError as e:
        print(f"C++ 监控启动失败: {e}")
        return False


def _start_ai_background(config: Dict) -> bool:
    """启动 C++ AI 后台批次分析。"""
    from . import core_bridge

    ai_cfg, payload = _ai_config_payload(config)
    if not ai_cfg.active:
        return False
    try:
        core_bridge.ai_start_background(payload)
        print(f"[AI] 后台分析已启动: 每 {ai_cfg.interval} 秒一批")
        return True
    except core_bridge.CoreError as e:
        logger.warning("AI 后台启动失败: %s", e)
        return False


def run_monitor(config: Dict) -> None:
    """启动实时监控（Sysmon 事件 + 按访问扫描），Ctrl+C 返回。"""
    if sys.platform != "win32":
        print("实时监控仅在 Windows 上可用。")
        return
    if not is_admin():
        print("实时监控需要管理员权限，请以管理员身份重新运行。")
        return
    if not _ensure_sysmon():
        return

    from . import core_bridge

    if not core_bridge.is_available():
        print(f"C++ 内核未加载，无法启动实时监控: {core_bridge.load_error()}")
        return
    if not _start_native_monitor(config):
        print("实时监控启动失败，已退出。")
        return

    ai_on = _start_ai_background(config)

    print("实时监控已启动 (C++ 内核)，按 Ctrl+C 停止...")
    try:
        while True:
            try:
                for event in core_bridge.monitor_poll(100):
                    _print_native_threat(event)
            except core_bridge.CoreError:
                logger.debug("监控事件轮询失败", exc_info=True)
            if ai_on:
                for res in core_bridge.ai_poll(100):
                    _print_native_ai_result(res)
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n停止实时监控...")
    finally:
        core_bridge.monitor_stop()
        if ai_on:
            core_bridge.ai_stop_background()


def cmd_monitor(args: argparse.Namespace) -> int:
    config = _prepare_config(args)
    run_monitor(config)
    return 0


# -------------------- 状态与病毒库 --------------------

def cmd_status(args: argparse.Namespace) -> int:
    config = _prepare_config(args)
    from . import core_bridge

    print("\n--- 引擎状态 ---")
    config_path = _config_path_of(args)
    print(f"配置文件: {config_path} ({'已加载' if config else '未生效，使用内置默认值'})")
    if not core_bridge.is_available():
        print(f"C++ 内核: 未加载 ({core_bridge.load_error()})")
    else:
        print(f"C++ 内核: 已加载 (v{core_bridge.version()})")
        clam = config.get("clamav") or {}
        rules = (config.get("yara") or {}).get("rules_path")
        clam_host = str(clam.get("host", "127.0.0.1") or "")
        clam_port = int(clam.get("port", 3310) or 3310)
        clam_disabled = not clam_host
        try:
            st = core_bridge.engine_status(
                rules, clam_host or "127.0.0.1",
                clam_port, int(clam.get("timeout", 30) or 30),
            )
        except core_bridge.CoreError as e:
            st = {}
            print(f"  状态查询失败: {e}")
        if st:
            y = st.get("yara", {})
            if y.get("available"):
                skipped = f", 跳过 {y.get('skipped', 0)} 个不兼容文件" if y.get("skipped") else ""
                print(f"YARA 规则: 已加载 ({y.get('rules_count', 0)} 个规则文件{skipped})")
            else:
                print("YARA 规则: 未加载 (请检查规则目录与语法)")
            c = st.get("clamav", {})
            if clam_disabled:
                print("ClamAV 连接: 已禁用 (config.yaml 的 clamav.host 为空，纯 YARA 模式)")
            else:
                print(f"ClamAV 连接: {'可用' if c.get('available') else '不可用'}"
                      + (f" | 版本: {c.get('version')}" if c.get("version") else "")
                      + ("" if c.get("available") else f" ({clam_host}:{clam_port})"))

    print(f"Sysmon: {'已安装' if _sysmon_installed() else '未安装'}")

    q_path = Path(config.get("quarantine", {}).get("path", "./quarantine"))
    print(f"隔离目录: {q_path} {'(存在)' if q_path.is_dir() else '(未创建)'}")

    monitor_paths = config.get("scan", {}).get("monitor_paths", [])
    print(f"监控路径: {', '.join(monitor_paths) if monitor_paths else '无'}")

    ai_cfg, ai_payload = _ai_config_payload(config)
    print(f"AI 分析: {_ai_hint(ai_cfg)}")
    if ai_cfg.active and core_bridge.is_available():
        res = core_bridge.ai_test(ai_payload)
        print(f"  端点: {ai_cfg.base_url} | 模型: {ai_cfg.model}")
        print(f"  连通: {res.get('detail')} | 批次间隔: {ai_cfg.interval}s")
        print(f"  事件源: {', '.join(ai_cfg.batch_sources())}")
    print("-----------------\n")
    return 0


def cmd_update_db(args: argparse.Namespace) -> int:
    config = _prepare_config(args)
    from . import core_bridge

    if not core_bridge.is_available():
        print(f"C++ 内核未加载: {core_bridge.load_error()}")
        return 1
    clam = config.get("clamav") or {}
    host = str(clam.get("host", "127.0.0.1") or "")
    port = int(clam.get("port", 3310) or 3310)
    timeout = int(clam.get("timeout", 30) or 30)
    if not host:
        print("ClamAV 已按配置禁用 (clamav.host 为空)，无病毒库可重载。")
        return 1
    print(f"正在请求 ClamAV ({host}:{port}) 重载病毒库...")
    try:
        res = core_bridge.clam_reload(host, port, timeout)
    except core_bridge.CoreError as e:
        print(f"重载失败: {e}")
        return 1
    if res.get("ok"):
        print("重载指令已发送。")
        return 0
    print(f"重载失败：无法连接 clamd ({host}:{port})。")
    print("  本机 clamd 未启动 → 管理员执行: net start clamd（或 scripts\\install.bat 安装）")
    print("  病毒库本身需要用 freshclam 更新后再重载。")
    return 1


# -------------------- AI 分析 --------------------

def _ai_hint(ai_cfg) -> str:
    if not ai_cfg.exists:
        return "未配置（缺少 config.ini，参考 config.ini.example）"
    if not ai_cfg.enabled:
        return "已禁用（config.ini [ai] enabled=false）"
    if not ai_cfg.configured:
        return "配置不完整（config.ini 缺少 base_url 或 model）"
    return "已启用"


def _ai_config_payload(config: Dict):
    """构造传给 C++ 内核的 AI 配置 JSON（实现在 aiconfig.build_ai_payload，GUI 共用）。"""
    from .aiconfig import build_ai_payload, load_ai_config

    ai_cfg = load_ai_config()
    return ai_cfg, build_ai_payload(config, ai_cfg)


def _ai_stream_default() -> bool:
    """默认开启流式显示；可用环境变量 AVENGINE_AI_STREAM=0 关闭。"""
    value = os.environ.get("AVENGINE_AI_STREAM", "1").strip().lower()
    return value not in ("0", "off", "false", "no")


class _AiStreamRenderer:
    """
    把内核抛出的 AI 事件实时渲染到终端。

    事件（见 cpp/src/ai/ai_session.h）：
      session_info/session_start 会话开始     round_start 新一轮
      thinking  思考增量（灰）                content 正文增量
      tool_call 要调用工具                    tool_result 工具返回（含耗时/成败）
      note 提示                               error 出错
      final 最终结论                          done 会话结束
    """

    def __init__(self, title: str = "AI 分析") -> None:
        self.title = title
        self.mode: Optional[str] = None      # thinking | content | None
        self.line_open = False
        self.streamed = ""                   # 已流式输出的正文（用于避免重复打印结论）
        self.rounds = 0
        self.tool_calls = 0
        self._pending = ""                   # 未确认结尾的最后一行（可能是 END 标记/CALL 行）
        self._notes_seen = set()             # 同一提示只打印一次（如每轮都会来的「已连接」）

    # ---------- 底层输出 ----------
    def _write(self, text: str) -> None:
        sys.stdout.write(text)
        sys.stdout.flush()

    def _close_line(self) -> None:
        if self.line_open:
            self._write("\n")
            self.line_open = False

    # ---------- 正文行缓冲：隐藏协议行 + 流式打印 ----------
    _CALL_RE = re.compile(r"^\s*CALL\s+[A-Za-z_][A-Za-z0-9_]*\s*(.*)$")

    def _emit_content(self, text: str) -> None:
        if not text:
            return
        self.streamed += text
        self._write(text)
        # 正文自带换行时视为已换行，避免结束语前多出一个空行
        self.line_open = not text.endswith("\n")

    def _push_content(self, text: str) -> None:
        """正文增量先缓冲，按行确认后再打印：隐藏 CALL 协议行、吞掉结尾 END 标记。"""
        self._pending += text
        while True:
            idx = self._pending.find("\n")
            if idx < 0:
                break
            line = self._pending[:idx + 1]
            self._pending = self._pending[idx + 1:]
            self._emit_content(self._filter_line(line, final=False))

    def _filter_line(self, line: str, final: bool) -> str:
        if self._CALL_RE.match(line):
            return ""                                    # 工具调用行交给 [AI →] 事件显示
        if final:
            stripped = line.strip()
            if stripped.upper() == "END":
                return ""                                # 协议结束标记
            if stripped.upper().endswith(" END"):
                return line.rstrip()[:-3].rstrip() + ("\n" if line.endswith("\n") else "")
        return line

    def _flush_content(self, final: bool = True) -> None:
        if not self._pending:
            return
        tail = self._pending
        self._pending = ""
        self._emit_content(self._filter_line(tail, final=final))

    # ---------- 事件渲染 ----------
    def feed(self, event: Dict) -> None:
        kind = event.get("kind")
        if kind == "session_info":
            mode = {"ask": "自由提问", "batch": "批次事件分析", "detection": "检出分析"}.get(
                event.get("mode"), event.get("mode") or "")
            self._close_line()
            self._write(f"{Fore.CYAN}[{self.title}]{Style.RESET_ALL} {mode}\n")
        elif kind == "session_start":
            self._close_line()
            self._write(f"{Style.DIM}  模型: {event.get('model')} | 最大轮数: {event.get('max_rounds')}"
                        f"{Style.RESET_ALL}\n")
        elif kind == "round_start":
            self._close_line()
            try:
                self.rounds = max(self.rounds, int(event.get("round") or 0))
            except (TypeError, ValueError):
                pass
            total = event.get("max_rounds")
            suffix = f"/{total}" if total else ""
            self._write(f"{Style.DIM}── 第 {event.get('round')}{suffix} 轮 "
                        f"{'─' * 34}{Style.RESET_ALL}\n")
        elif kind == "thinking":
            if self.mode != "thinking":
                self._close_line()
                self._write(f"{Style.DIM}[思考] {Style.RESET_ALL}")
                self.mode = "thinking"
                self.line_open = True
            self._write(f"{Style.DIM}{event.get('text', '')}{Style.RESET_ALL}")
        elif kind == "content":
            text = event.get("text", "")
            if self.mode != "content":
                self._close_line()
                self._write(f"{Fore.GREEN}[AI]{Style.RESET_ALL} ")
                self.mode = "content"
                self.line_open = True
            self._push_content(text)
        elif kind == "tool_call":
            self._flush_content(final=False)   # 本轮正文先落地（CALL 行不打印）
            self._close_line()
            self.mode = None
            self.tool_calls += 1
            args = event.get("args")
            try:
                detail = json.dumps(args, ensure_ascii=False)
            except (TypeError, ValueError):
                detail = str(args)
            if len(detail) > 200:
                detail = detail[:200] + "…"
            self._write(f"{Fore.CYAN}[AI →]{Style.RESET_ALL} {event.get('name')} {detail}\n")
        elif kind == "tool_result":
            self._close_line()
            self.mode = None
            ok = event.get("ok", True)
            color = Fore.CYAN if ok else Fore.RED
            took = event.get("ms")
            took_text = f"{took}ms" if isinstance(took, int) else ""
            detail = str(event.get("detail", ""))
            if len(detail) > 160:
                detail = detail[:160] + "…"
            self._write(f"{color}[AI ←]{Style.RESET_ALL} {event.get('name')}: "
                        f"{detail} {Style.DIM}{took_text}{Style.RESET_ALL}\n")
        elif kind == "note":
            text = event.get("text", "")
            if text in self._notes_seen:
                return
            self._notes_seen.add(text)
            self._close_line()
            self.mode = None
            self._write(f"{Style.DIM}[提示] {text}{Style.RESET_ALL}\n")
        elif kind == "error":
            self._close_line()
            self.mode = None
            self._write(f"{Fore.RED}[错误]{Style.RESET_ALL} {event.get('message', '')}\n")
        elif kind == "final":
            self._flush_content(final=True)
            self._close_line()
            self.mode = None
            text = (event.get("text") or "").strip()
            if text and self._needs_final_block(text):
                self._write(f"\n{Fore.CYAN}--- 结论（已清理 CALL/END 标记）{Style.RESET_ALL} ---\n")
                self._write(text + "\n")
        elif kind == "done":
            self._flush_content(final=True)
            self.rounds = event.get("rounds", self.rounds)
            self.tool_calls = event.get("tool_calls", self.tool_calls)
        elif kind == "round_end":
            self._flush_content(final=True)
            self._close_line()
            self.mode = None

    def _needs_final_block(self, text: str) -> bool:
        """流式已经吐过同样的内容就不再重复打印结论。"""
        head = "".join(text.split())[:40]
        if not head:
            return False
        return head not in "".join(self.streamed.split())

    def finish(self, result: Dict) -> None:
        """会话结束：兜底补打印结论 + 状态行。"""
        self._flush_content(final=True)
        self._close_line()
        self.mode = None
        final_text = (result.get("final_text") or "").strip()
        if final_text and self._needs_final_block(final_text):
            print(f"\n{Fore.CYAN}--- AI 结论 ({result.get('ended_by')}){Style.RESET_ALL} ---")
            print(final_text)
            print("-" * 46)
        color = Fore.GREEN if result.get("ok") else Fore.YELLOW
        print(f"{Style.DIM}──── 会话结束: {result.get('ended_by')} | "
              f"{result.get('rounds')} 轮 | {result.get('tool_calls')} 次工具调用 "
              f"{Style.RESET_ALL}")
        if not result.get("ok") and result.get("error"):
            print(f"{color}（{result.get('error')}）{Style.RESET_ALL}")

    def close(self) -> None:
        self._flush_content(final=True)
        self._close_line()
        self.mode = None


def _print_native_ai_result(res: Dict) -> None:
    """非流式（或 --no-stream）时的整体输出。"""
    for item in res.get("trace") or []:
        kind = item.get("kind")
        if kind == "tool_call":
            print(f"  {Fore.CYAN}[AI ->]{Style.RESET_ALL} {item.get('name')} {item.get('detail', '')}")
        elif kind == "tool_result":
            print(f"  {Fore.CYAN}[AI <-]{Style.RESET_ALL} {item.get('name')}: {item.get('detail', '')}")
    print(
        f"  {Fore.CYAN}[AI]{Style.RESET_ALL} 会话结束: {res.get('ended_by')} "
        f"({res.get('rounds')} 轮, {res.get('tool_calls')} 次工具)"
    )
    print(f"\n{Fore.CYAN}--- AI 结论 ({res.get('ended_by')}){Style.RESET_ALL} ---")
    print(res.get("final_text") or "（无输出）")
    print("-" * 46)


def _run_ai_native(payload: Dict, question=None, minutes: int = 0, stream: bool = True) -> Dict:
    """
    执行一次 AI 会话。

    stream=True 且内核带流式接口时，会把「思考过程 / 工具调用 / 工具结果 / 正文」
    边生成边打印（走 core_bridge.*_stream 的事件回调），否则退回一次性输出。
    """
    from . import core_bridge

    renderer = _AiStreamRenderer() if (stream and core_bridge.supports_ai_stream()) else None
    if question:
        print(f"提问: {question}")
    else:
        print(f"开始批次分析（--minutes={minutes or '默认'}）...")
    if renderer is None and stream:
        print(f"{Fore.YELLOW}[提示]{Style.RESET_ALL} 当前内核不支持流式事件（请重新构建 cpp\\build.bat），改为整体输出")

    try:
        if renderer is not None:
            if question:
                res = core_bridge.ai_ask_stream(payload, question, on_event=renderer.feed)
            else:
                res = core_bridge.ai_run_batch_stream(payload, minutes, on_event=renderer.feed)
        else:
            if question:
                res = core_bridge.ai_ask(payload, question)
            else:
                res = core_bridge.ai_run_batch(payload, minutes)
    except core_bridge.CoreError as e:
        if renderer is None:
            raise
        # 会话本身已经流式显示过了：这里不能再把整段输出丢掉，
        # 用已有信息收尾并把失败原因明确打出来（结果序列化/内核错误等）。
        renderer.finish({
            "ended_by": "error",
            "error": str(e),
            "rounds": renderer.rounds,
            "tool_calls": renderer.tool_calls,
            "final_text": "",
            "ok": False,
        })
        return {
            "ended_by": "error", "error": str(e), "ok": False, "trace": [],
            "rounds": renderer.rounds, "tool_calls": renderer.tool_calls, "final_text": "",
        }

    if renderer is not None:
        renderer.finish(res)
    return res


def _ai_detection_analysis(config: Dict, infected: List[str], yara_hits: Dict, clam_hits: Dict) -> None:
    """扫描检出联动：把首个检出交给 AI 分析（config.ini 可关 scan_analysis）。"""
    if not infected:
        return
    from . import core_bridge

    ai_cfg, payload = _ai_config_payload(config)
    if not (ai_cfg.active and ai_cfg.scan_analysis) or not core_bridge.is_available():
        return

    path = infected[0]
    match = ", ".join(yara_hits.get(path) or []) or clam_hits.get(path) or ""
    engines = [name for name, hits in (("yara", yara_hits), ("clamav", clam_hits)) if path in hits]
    detection = {
        "path": path,
        "engine": "+".join(engines),
        "match": match,
        "action": "待隔离确认",
        "total": len(infected),
    }
    stream = _ai_stream_default() and core_bridge.supports_ai_stream()
    renderer = _AiStreamRenderer(title="AI 检出分析") if stream else None
    try:
        if renderer is not None:
            renderer.feed({"kind": "session_info", "mode": "detection"})
            res = core_bridge.ai_analyze_detection_stream(payload, detection, on_event=renderer.feed)
            renderer.finish(res)
        else:
            res = core_bridge.ai_analyze_detection(payload, detection)
            if res.get("final_text"):
                print(f"\n{Fore.CYAN}[AI 检出分析]{Style.RESET_ALL}")
                print(res["final_text"])
                print("-" * 46)
    except Exception:
        if renderer is not None:
            renderer.close()
        logger.exception("AI 检出联动失败（不影响扫描流程）")


def cmd_ai(args: argparse.Namespace) -> int:
    config = _prepare_config(args)
    from . import core_bridge

    ai_cfg, payload = _ai_config_payload(config)
    question = getattr(args, "question", None) or getattr(args, "prompt", None)
    minutes = getattr(args, "minutes", None) or 0
    stream = _ai_stream_default() and not getattr(args, "no_stream", False)

    print(f"AI: {_ai_hint(ai_cfg)}")
    if not core_bridge.is_available():
        print(f"C++ 内核未加载: {core_bridge.load_error()}")
        return 1

    if getattr(args, "test", False):
        res = core_bridge.ai_test(payload)
        print(f"连通性: {res.get('detail')}")
        return 0 if res.get("ok") else 1

    if not ai_cfg.active:
        print("提示: 复制 config.ini.example 为 config.ini，填写 base_url / model / api_key 后重试。")
        return 1

    try:
        res = _run_ai_native(payload, question=question, minutes=minutes, stream=stream)
    except core_bridge.CoreError as e:
        print(f"AI 调用失败: {e}")
        return 1
    if not stream:
        _print_native_ai_result(res)
    return 0 if res.get("ok") else 1


# -------------------- 交互菜单 --------------------

def interactive_menu(config: Dict) -> None:
    actions = {
        "1": ("启动实时监控 (Sysmon + 按访问扫描)", lambda: run_monitor(config)),
        "2": ("手动扫描文件/目录", lambda: _menu_scan(config)),
        "3": ("更新病毒库 (ClamAV)", lambda: cmd_update_db(_Namespace(config))),
        "4": ("查看引擎状态", lambda: cmd_status(_Namespace(config))),
        "5": ("AI 分析 (批次/提问)", lambda: _menu_ai(config)),
    }
    while True:
        print("\n" + "=" * 50)
        print(" 主菜单")
        print("=" * 50)
        for key, (label, _) in actions.items():
            print(f"{key}. {label}")
        print("6. 退出")

        choice = input("请输入选项 [1-6]: ").strip()
        if choice == "6":
            print("感谢使用 AvEngine，再见！")
            return
        action = actions.get(choice)
        if action is None:
            print("无效选项，请重新输入。")
            continue
        try:
            action[1]()
        except KeyboardInterrupt:
            print("\n已取消。")
        except EOFError:
            return


class _Namespace(argparse.Namespace):
    """把已加载的配置当作 Namespace 传给命令函数。"""

    def __init__(self, config: Dict):
        super().__init__(config=config)


def _menu_scan(config: Dict) -> None:
    target = input("请输入要扫描的文件或目录路径: ").strip().strip('"')
    if not target:
        print("路径不能为空。")
        return
    scan_target(config, Path(target))


def _menu_ai(config: Dict) -> None:
    """交互菜单的 AI 分析子菜单。"""
    from . import core_bridge

    stream = _ai_stream_default() and core_bridge.supports_ai_stream()
    while True:
        ai_cfg, payload = _ai_config_payload(config)
        print("\n--- AI 分析 ---")
        print(f"状态: {_ai_hint(ai_cfg)}")
        print("1. 执行本批事件分析")
        print("2. 自由提问")
        print("3. 测试端点连通")
        print(f"4. 流式显示思考/工具调用: {'开' if stream else '关'}")
        print("0. 返回主菜单")
        try:
            choice = input("请选择 [0-4]: ").strip()
        except EOFError:
            return
        try:
            if choice == "0":
                return
            if not core_bridge.is_available():
                print(f"C++ 内核未加载: {core_bridge.load_error()}")
                continue
            if choice == "4":
                if not core_bridge.supports_ai_stream():
                    print("当前内核不支持流式事件，请重新运行 cpp\\build.bat 构建。")
                    continue
                stream = not stream
                print(f"流式显示: {'开' if stream else '关'}")
                continue
            if choice in ("1", "2") and not ai_cfg.active:
                print(f"AI 不可用: {_ai_hint(ai_cfg)}")
                print("提示: 复制 config.ini.example 为 config.ini 并填写 base_url/model/api_key。")
                continue
            if choice == "1":
                res = _run_ai_native(payload, minutes=0, stream=stream)
                if not stream:
                    _print_native_ai_result(res)
            elif choice == "2":
                question = input("请输入问题: ").strip()
                if question:
                    res = _run_ai_native(payload, question=question, stream=stream)
                    if not stream:
                        _print_native_ai_result(res)
            elif choice == "3":
                res = core_bridge.ai_test(payload)
                print(f"连通性: {res.get('detail')}")
            else:
                print("无效选项。")
        except KeyboardInterrupt:
            print("\n已取消。")
        except EOFError:
            return


def print_banner() -> None:
    print(
        f"""
   █████╗ ██╗   ██╗███████╗███╗   ██╗ ██████╗ ██╗███╗   ██╗███████╗
  ██╔══██╗██║   ██║██╔════╝████╗  ██║██╔════╝ ██║████╗  ██║██╔════╝
  ███████║██║   ██║█████╗  ██╔██╗ ██║██║  ███╗██║██╔██╗ ██║█████╗
  ██╔══██║╚██╗ ██╔╝██╔══╝  ██║╚██╗██║██║   ██║██║██║╚██╗██║██╔══╝
  ██║  ██║ ╚████╔╝ ███████╗██║ ╚████║╚██████╔╝██║██║ ╚████║███████╗
  ╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝╚═╝  ╚═══╝╚══════╝
         基于 YARA + ClamAV + Sysmon 的多引擎杀毒引擎 v{__version__}
        """
    )


# -------------------- 参数解析与入口 --------------------

def _config_path_of(args: argparse.Namespace) -> Path:
    """
    取配置文件的**路径**。

    交互菜单会把已加载的配置字典塞进 args.config（见 _Namespace），
    这里统一把它归一成路径，避免 Path(dict) 抛 TypeError。
    """
    given = getattr(args, "config", None)
    if isinstance(given, (str, Path)) and str(given):
        return Path(given)
    return CONFIG_FILE


def _prepare_config(args: argparse.Namespace) -> Dict:
    """确保配置存在并加载；若命令未显式传入配置则使用默认值。"""
    given = getattr(args, "config", None)
    if isinstance(given, dict):
        # 交互菜单已经加载过配置，直接用，不再读盘
        return given

    path = Path(given) if given else CONFIG_FILE
    if not path.exists():
        generate_default_config(path)
    if given is None:
        args.config = str(path)

    config = load_config(path)
    if not config:
        reason = validate_config(path)
        if reason:
            print(f"{Fore.YELLOW}[警告]{Style.RESET_ALL} 配置文件解析失败: {path}")
            print(f"        {reason.strip().splitlines()[0] if reason.strip() else reason}")
            print("        本次按内置默认值运行（YARA/ClamAV 可能降级）；"
                  "修复: avengine config --regenerate （会先备份原文件）")
    return config


def _set_clamav_in_config(path: Path, host: str, port: Optional[int],
                          timeout: Optional[int]) -> int:
    """
    把 clamav.host / port / timeout 写回 config.yaml（保注释、UTF-8 无 BOM、自动备份）。

    这是 `scripts\\set_clamav.bat` 与 `scripts\\setup_clamav.bat` 的唯一实现 ——
    过去由 PowerShell 版的 lib_config_yaml.ps1 负责，但 Win7 SP1 自带的是 PS 2.0，
    语言版本差异反复出事；改成让安装脚本调用这个子命令，配置写法只剩 Python 一份。

    host 传 "none"（或空）表示关闭 ClamAV、走纯 YARA 模式。
    """
    from .configwrite import write_config_yaml  # 局部导入：只有改配置时才需要

    normalized = (host or "").strip()
    if normalized.lower() in ("none", "no", "disable", "disabled", "off", "-", "yara"):
        normalized = ""
    if path.is_file():
        current = (load_config(path).get("clamav") or {}) if validate_config(path) is None else {}
    else:
        current = {}
    if port is None or port <= 0:
        port = int(current.get("port") or 3310)
    if timeout is None or timeout <= 0:
        timeout = int(current.get("timeout") or 30)

    example = CONFIG_EXAMPLE_FILE if CONFIG_EXAMPLE_FILE.is_file() else None
    scalars = {
        ("clamav", "host"): normalized,
        ("clamav", "port"): port,
        ("clamav", "timeout"): timeout,
    }
    try:
        write_config_yaml(path, scalars, example=example)
    except OSError as exc:
        print(f"{Fore.RED}[失败]{Style.RESET_ALL} 无法写入 {path}: {exc}")
        return 1

    # 写坏了（历史乱码/并行文件）就按 PS 版的老办法从 config.example.yaml 重建再写一次
    if validate_config(path) is not None:
        print(f"{Fore.YELLOW}[警告]{Style.RESET_ALL} 写入后配置无法解析，从 config.example.yaml 重建…")
        generate_default_config(path, force=True)
        try:
            write_config_yaml(path, scalars, example=example)
        except OSError as exc:
            print(f"{Fore.RED}[失败]{Style.RESET_ALL} 重建后仍无法写入 {path}: {exc}")
            return 1

    print(f"UPDATED: {path}")
    if normalized:
        print(f"{Fore.GREEN}[正常]{Style.RESET_ALL} clamd 目标: {normalized}:{port}（超时 {timeout}s）")
        print(f"  确认 clamd 在该地址监听、防火墙放通 TCP {port}；验证: avengine status")
    else:
        print(f"{Fore.GREEN}[正常]{Style.RESET_ALL} ClamAV 已禁用（纯 YARA 模式）")
        print("  avengine status 会显示 ClamAV 不可用，扫描仍用 YARA + Sysmon 正常工作。")
    return 0


def cmd_config(args: argparse.Namespace) -> int:
    """
    校验 config.yaml；`--regenerate` 时从 config.example.yaml 重建；
    带 `--clamav-host` / `--clamav-port` / `--clamav-timeout` 时先写回再校验。

    输出首行固定为 `CONFIG_OK: <路径>` 或 `CONFIG_INVALID: <路径>`（写回成功时先输出
    `UPDATED: <路径>`），便于安装脚本（scripts\\*.bat）判断结果。
    """
    path = _config_path_of(args)

    if getattr(args, "regenerate", False):
        if path.exists() and not getattr(args, "force", False) and validate_config(path) is None:
            print(f"当前配置可正常解析，未重建: {path}")
            print("如需强制重建请加 --force（原文件会备份为 config.yaml.bak-<时间戳>）")
            return 0
        generate_default_config(path, force=True)
        if not path.is_file():
            print(f"CONFIG_INVALID: {path}")
            print(f"{Fore.RED}[失败]{Style.RESET_ALL} 无法写入 {path}")
            return 1
        print(f"已从 config.example.yaml 重建: {path}")

    host_arg = getattr(args, "clamav_host", None)
    port_arg = getattr(args, "clamav_port", None)
    timeout_arg = getattr(args, "clamav_timeout", None)
    if host_arg is not None or port_arg is not None or timeout_arg is not None:
        code = _set_clamav_in_config(path, host_arg if host_arg is not None else "",
                                     port_arg, timeout_arg)
        if code != 0:
            return code

    reason = validate_config(path)
    if reason:
        print(f"CONFIG_INVALID: {path}")
        print(f"{Fore.RED}[失败]{Style.RESET_ALL} {path}")
        print(reason)
        return 1

    config = load_config(path)
    clam = config.get("clamav") or {}
    print(f"CONFIG_OK: {path}")
    print(f"{Fore.GREEN}[正常]{Style.RESET_ALL} {path}")
    print(f"  YARA 规则目录: {(config.get('yara') or {}).get('rules_path')}")
    print(f"  ClamAV: {clam.get('host') or '(已禁用)'}:{clam.get('port')}")
    print(f"  隔离目录: {(config.get('quarantine') or {}).get('path')}")
    paths = (config.get("scan") or {}).get("monitor_paths") or []
    print(f"  监控路径: {', '.join(paths) if paths else '无'}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="avengine",
        description="AvEngine - 基于 YARA + ClamAV + Sysmon 的多引擎杀毒引擎",
    )
    parser.add_argument("-c", "--config", default=None, help="配置文件路径 (默认: config.yaml)")
    parser.add_argument("-v", "--version", action="version", version=f"AvEngine {__version__}")

    subparsers = parser.add_subparsers(dest="command", metavar="命令")

    p_scan = subparsers.add_parser("scan", help="扫描文件或目录")
    p_scan.add_argument("path", help="要扫描的文件或目录")
    p_scan.set_defaults(func=cmd_scan)

    p_monitor = subparsers.add_parser("monitor", help="启动实时监控 (需管理员权限)")
    p_monitor.set_defaults(func=cmd_monitor)

    p_status = subparsers.add_parser("status", help="查看引擎状态")
    p_status.set_defaults(func=cmd_status)

    p_update = subparsers.add_parser("update-db", help="重载 ClamAV 病毒库")
    p_update.set_defaults(func=cmd_update_db)

    p_config = subparsers.add_parser("config", help="校验 config.yaml（--regenerate 重建）")
    p_config.add_argument("--validate", action="store_true", help="仅校验语法（默认行为）")
    p_config.add_argument("--regenerate", action="store_true",
                          help="从 config.example.yaml 重建（原文件自动备份）")
    p_config.add_argument("--force", action="store_true",
                          help="配合 --regenerate：即使当前配置可解析也重建")
    p_config.add_argument("--clamav-host", default=None, metavar="HOST",
                          help="写回 clamav.host（安装脚本用；none/off 表示关闭 ClamAV）")
    p_config.add_argument("--clamav-port", type=int, default=None, metavar="N",
                          help="写回 clamav.port（默认沿用现有值或 3310）")
    p_config.add_argument("--clamav-timeout", type=int, default=None, metavar="SEC",
                          help="写回 clamav.timeout（默认沿用现有值或 30）")
    p_config.set_defaults(func=cmd_config)

    p_ai = subparsers.add_parser("ai", help="AI 分析（批次事件分析 / 自由提问）")
    p_ai.add_argument("--minutes", type=int, default=None, help="批次窗口分钟数 (默认: config.ini interval)")
    p_ai.add_argument("--prompt", default=None, help="直接提问（等价于 ai ask）")
    p_ai.add_argument("--test", action="store_true", help="仅测试 AI 端点连通性")
    p_ai.add_argument("--no-stream", action="store_true",
                      help="关闭流式显示（默认边生成边显示思考/工具调用/正文）")
    ai_sub = p_ai.add_subparsers(dest="ai_action", metavar="子命令")
    p_ask = ai_sub.add_parser("ask", help="自由问答（可调用工具查证）")
    p_ask.add_argument("question", help="要提问的内容")
    p_ask.set_defaults(func=cmd_ai)
    p_ai.set_defaults(func=cmd_ai)

    p_svc = subparsers.add_parser(
        "service", help="特权服务（LocalSystem）：状态/安装/卸载/探活")
    svc_sub = p_svc.add_subparsers(dest="service_action", metavar="子命令")
    svc_sub.add_parser("status", help="查看服务与钉住的证书指纹").set_defaults(func=cmd_service)
    svc_sub.add_parser("ping", help="探活并检查自己是否满足授权门槛").set_defaults(func=cmd_service)
    p_svc_install = svc_sub.add_parser("install", help="安装服务（需管理员）")
    p_svc_install.add_argument("--auto", action="store_true", help="改为自动启动（默认按需启动）")
    p_svc_install.set_defaults(func=cmd_service)
    svc_sub.add_parser("uninstall", help="停止并删除服务（需管理员）").set_defaults(
        func=cmd_service)
    p_svc.set_defaults(func=cmd_service)

    p_rs = subparsers.add_parser(
        "run-system", help="请特权服务以 SYSTEM 身份运行 avengine.exe（需管理员 + 已签名部署）")
    p_rs.add_argument("--timeout", type=int, default=600, help="等待子进程的秒数（默认 600）")
    p_rs.add_argument("--no-wait", action="store_true", help="只启动不等待")
    p_rs.add_argument("--caller-session", action="store_true",
                      help="让 SYSTEM 子进程跑在当前登录会话（默认留在服务会话）")
    p_rs.add_argument("args", nargs=argparse.REMAINDER,
                      help="传给子进程的参数，例如: run-system -- status")
    p_rs.set_defaults(func=cmd_run_system)

    p_gui = subparsers.add_parser("gui", help="图形界面（Tkinter，所有功能与配置都在里面）")
    p_gui.add_argument("--tab", default=None,
                       help="启动后直接切到某个标签页（概览/扫描/实时监控/AI 分析/Sysmon/"
                            "ClamAV/特权服务/设置/日志）")
    p_gui.set_defaults(func=cmd_gui)

    p_menu = subparsers.add_parser("menu", help="旧的控制台交互菜单")
    p_menu.set_defaults(func=cmd_menu)

    return parser


def cmd_gui(args) -> int:
    """启动 Tkinter 图形界面。"""
    from .gui import launch

    return launch(["--tab", args.tab] if getattr(args, "tab", None) else [])


def cmd_menu(args) -> int:
    """强制进入控制台交互菜单（无参数时的回退路径）。"""
    config = _prepare_config(args)
    print_banner()
    print(f"配置文件: {_config_path_of(args).resolve()}")
    print(f"日志文件: {LOG_FILE}")
    interactive_menu(config)
    return 0


def cmd_service(args) -> int:
    """特权服务管理：status / ping / install / uninstall。"""
    from . import privsvc

    action = getattr(args, "service_action", None) or "status"
    exe = privsvc.service_dir_hint()

    if action == "status":
        print(f"服务名        : AvEnginePrivSvc")
        print(f"是否已安装    : {'是' if privsvc.is_service_installed() else '否'}")
        print(f"服务端可执行  : {exe}（{'存在' if exe.is_file() else '缺失'}）")
        if exe.is_file():
            # 服务端 --check-pin 会打印钉住的指纹与安装目录白名单。
            # 服务把自己的输出统一成 UTF-8（见 wmain 里的 SetConsoleOutputCP），
            # 所以这里必须显式按 UTF-8 解码，否则本机 GBK 环境下会解码失败。
            try:
                out = subprocess.run([str(exe), "--check-pin"], capture_output=True, text=True,
                                     encoding="utf-8", errors="replace", timeout=15)
                for line in (out.stdout or "").splitlines():
                    print(f"  {line}")
                if out.returncode == 2:
                    print("  => 未配置证书指纹：服务会拒绝一切请求（先跑 gen_signing_cert.ps1）")
            except (OSError, subprocess.SubprocessError) as e:
                print(f"  调用 --check-pin 失败: {e}")
        print(f"管道          : {privsvc.PIPE_NAME}")
        return 0

    if action == "ping":
        try:
            pong = privsvc.ping()
            print(f"服务可用；响应: {pong}")
            print("（能 ping 通说明本进程已通过服务的授权门槛）")
            return 0
        except privsvc.PrivSvcError as e:
            print(f"不可用: {e}")
            if e.hint:
                print(f"提示: {e.hint}")
            return 1

    if action in ("install", "uninstall"):
        if not exe.is_file():
            print("找不到服务端可执行文件，检查过：")
            for cand in privsvc.service_candidates():
                print(f"    {cand}")
            print("请先构建：service\\build_service.bat")
            return 1
        cmd = [str(exe), "--uninstall"] if action == "uninstall" else \
            [str(exe), "--install"] + (["--auto"] if getattr(args, "auto", False) else [])
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.SubprocessError) as e:
            print(f"执行失败: {e}")
            return 1
        print((proc.stdout or "").strip() or (proc.stderr or "").strip())
        return proc.returncode

    print(f"未知的 service 子命令: {action}")
    return 2


def cmd_run_system(args) -> int:
    """请特权服务以 SYSTEM 身份运行 avengine.exe <args>。"""
    from . import privsvc

    child_args_list = list(getattr(args, "args", []) or [])
    if child_args_list and child_args_list[0] == "--":
        child_args_list = child_args_list[1:]   # REMAINDER 会把分隔符也带进来
    child_args = " ".join(child_args_list).strip()
    if not child_args:
        print("需要给出要执行的参数，例如: avengine.exe run-system -- status")
        return 2
    timeout_s = max(1, int(getattr(args, "timeout", 600)))
    wait = not getattr(args, "no_wait", False)

    if not privsvc.is_service_installed():
        print("特权服务未安装。先以管理员执行：")
        print("    scripts\\install_privsvc.bat        (推荐：编译好的发布包里直接跑)")
        print("    service\\build_service.bat && service\\bin\\AvEnginePrivSvc.exe --install")
        return 1
    privsvc.ensure_started()

    print(f"请求以 SYSTEM 运行: avengine.exe {child_args}")
    try:
        result = privsvc.run_system(child_args, wait=wait, timeout_ms=timeout_s * 1000,
                                    caller_session=getattr(args, "caller_session", False))
    except privsvc.PrivSvcError as e:
        print(f"被拒绝或失败: {e}")
        if e.hint:
            print(f"提示: {e.hint}")
        return 1

    print(f"已启动 SYSTEM 子进程 pid={result.pid}")
    if result.log_path:
        print(f"子进程输出: {result.log_path}")
    if result.note:
        print(f"说明: {result.note}")
    if wait:
        if result.timed_out:
            print(f"等待超时（{timeout_s}s）：子进程仍在运行，pid={result.pid}")
            return 124
        print(f"子进程退出码: {result.exit_code}")
        if result.log_path:
            try:
                text = Path(result.log_path).read_text(encoding="utf-8", errors="replace")
                if text.strip():
                    print("--- 子进程输出 ---")
                    print(text.rstrip())
            except OSError:
                pass
        return int(result.exit_code or 0)
    return 0


def _desktop_available() -> bool:
    """
    当前是否有可用的桌面会话（决定无参数启动时是开 GUI 还是走控制台菜单）。

    直接试着建一个 Tk 根窗口再销毁：无桌面/无权限时会抛 TclError。
    比查环境变量可靠（Windows 上没有 DISPLAY 这类标志）。
    """
    if sys.platform != "win32":
        return bool(os.environ.get("DISPLAY"))
    try:
        import tkinter

        root = tkinter.Tk()
        root.withdraw()
        root.destroy()
        return True
    except Exception:  # noqa: BLE001 - 任何失败都视为没有桌面
        return False


def main(argv: Optional[List[str]] = None) -> int:
    # 先让标准流对编码问题免疫（errors="replace"），再做 colorama 包装 ——
    # 否则中文 Windows 上遇到不可编码字符/代码页被改过时，logging 会吐出
    # "--- Logging error ---" + traceback 这种纯噪音。
    make_console_tolerant()
    colorama_init()
    parser = build_parser()
    args = parser.parse_args(argv)

    setup_logging(log_level=logging.INFO, log_file=LOG_FILE)

    if args.command:
        return args.func(args)

    # 无子命令：有桌面会话就直接开图形界面（普通用户的主入口），
    # 否则退回控制台菜单（纯命令行/服务环境）。想强制走菜单用 avengine menu。
    if _desktop_available():
        from .gui import launch

        return launch([])

    config = _prepare_config(args)
    print_banner()
    print(f"配置文件: {_config_path_of(args).resolve()}")
    print(f"日志文件: {LOG_FILE}")
    print(f"Python: {sys.version.split()[0]} | 平台: {sys.platform}")
    interactive_menu(config)
    return 0


if __name__ == "__main__":
    sys.exit(main())
