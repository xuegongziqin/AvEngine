"""
cli.py - 命令行入口

Python 外壳（参数解析 / 菜单 / 配置 / 展示）调用 C++ 内核 avengine_core.dll 完成
扫描、实时监控与 AI 分析。被取代的 Python 引擎模块已归档到 legacy/。

子命令：scan / monitor / status / update-db / ai
"""

from __future__ import annotations

import argparse
import logging
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from colorama import Fore, Style, init as colorama_init

from . import __version__
from .config import generate_default_config, load_config
from .paths import CONFIG_FILE, LOG_FILE, SYSMON_CONFIG, SYSMON_EXE
from .utils import compute_file_hash, is_admin, quarantine_file, setup_logging

logger = logging.getLogger(__name__)


# -------------------- 扫描 --------------------

def scan_target(config: Dict, target: Path) -> Tuple[Dict[str, List[str]], Dict[str, str]]:
    """
    用 C++ 内核（YARA + ClamAV）扫描目标。

    Returns:
        (yara 命中 {路径: 规则}, clamav 命中 {路径: 病毒名})
    """
    from . import core_bridge

    quarantine_path = config.get("quarantine", {}).get("path", "./quarantine")

    if target.is_file():
        print(f"正在扫描文件: {target}")
    elif target.is_dir():
        print(f"正在扫描目录: {target}")
    else:
        print(f"路径不存在: {target}")
        return {}, {}

    if not core_bridge.is_available():
        print(f"C++ 内核未加载，无法扫描: {core_bridge.load_error()}")
        return {}, {}

    rules_path = (config.get("yara") or {}).get("rules_path")
    clamav = config.get("clamav") or {}
    yara_hits: Dict[str, List[str]] = {}
    clam_hits: Dict[str, str] = {}

    try:
        if target.is_file():
            result = core_bridge.scan_path(target, rules_path, clamav)
            matches = (result.get("yara") or {}).get("matches") or []
            if matches:
                yara_hits[result["path"]] = matches
            virus = (result.get("clamav") or {}).get("virus")
            if virus:
                clam_hits[result["path"]] = virus
        else:
            result = core_bridge.scan_dir(target, rules_path, clamav)
            yara_hits = result.get("yara", {})
            clam_hits = result.get("clamav", {})
    except core_bridge.CoreError as e:
        print(f"扫描失败: {e}")
        return {}, {}

    for path, hits in yara_hits.items():
        print(f"{Fore.RED}[YARA]{Style.RESET_ALL} {path}: {', '.join(hits)}")
    for path, virus in clam_hits.items():
        print(f"{Fore.RED}[ClamAV]{Style.RESET_ALL} {path}: {virus}")

    infected = sorted(set(yara_hits) | set(clam_hits))
    if not infected:
        print("未发现威胁。")
        return yara_hits, clam_hits

    print(f"\n发现 {len(infected)} 个受感染文件。")
    _ai_detection_analysis(config, infected, yara_hits, clam_hits)

    answer = input("是否将受感染文件隔离? (y/n): ").strip().lower()
    if answer == "y":
        for path in infected:
            new_path = quarantine_file(path, quarantine_path)
            if new_path:
                print(f"  已隔离: {path} -> {new_path}")
    else:
        print("跳过隔离。")

    return yara_hits, clam_hits


def cmd_scan(args: argparse.Namespace) -> int:
    config = _prepare_config(args)
    target = Path(args.path).expanduser()
    if not target.exists():
        print(f"路径不存在: {target}")
        return 1
    if target.is_file():
        print(f"SHA256: {compute_file_hash(str(target))}")
    yara_hits, clam_hits = scan_target(config, target)
    return 1 if (yara_hits or clam_hits) else 0


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
        exe = Path(SYSMON_EXE)
        if not exe.is_file():
            print(f"未检测到 Sysmon，且找不到安装程序: {exe}")
            print("请将 Sysmon.exe 放到 bina/Sysmon/ 后重试（或先手动安装 Sysmon）。")
            return False
        print("未检测到 Sysmon，正在安装...")
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
    if not core_bridge.is_available():
        print(f"C++ 内核: 未加载 ({core_bridge.load_error()})")
    else:
        print(f"C++ 内核: 已加载 (v{core_bridge.version()})")
        clam = config.get("clamav") or {}
        rules = (config.get("yara") or {}).get("rules_path")
        try:
            st = core_bridge.engine_status(
                rules, clam.get("host", "127.0.0.1"),
                int(clam.get("port", 3310) or 3310), int(clam.get("timeout", 30) or 30),
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
            print(f"ClamAV 连接: {'可用' if c.get('available') else '不可用'}"
                  + (f" | 版本: {c.get('version')}" if c.get("version") else ""))

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
    host = clam.get("host", "127.0.0.1")
    port = int(clam.get("port", 3310) or 3310)
    timeout = int(clam.get("timeout", 30) or 30)
    print("正在请求 ClamAV 重载病毒库...")
    try:
        res = core_bridge.clam_reload(host, port, timeout)
    except core_bridge.CoreError as e:
        print(f"重载失败: {e}")
        return 1
    if res.get("ok"):
        print("重载指令已发送。")
        return 0
    print("重载失败，请检查 clamd 服务与 freshclam 是否已更新病毒库。")
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
    """构造传给 C++ 内核的 AI 配置 JSON。"""
    from .aiconfig import load_ai_config
    from .paths import AI_DUMP_DIR, PROJECT_ROOT, resolve_path

    ai_cfg = load_ai_config()
    clam = config.get("clamav") or {}
    payload = {
        "base_url": ai_cfg.base_url,
        "api_key": ai_cfg.api_key,
        "model": ai_cfg.model,
        "timeout": ai_cfg.timeout,
        "max_rounds": ai_cfg.max_rounds,
        "interval": ai_cfg.interval,
        "max_events_per_batch": ai_cfg.max_events_per_batch,
        "max_event_chars": ai_cfg.max_event_chars,
        "max_tool_result_chars": ai_cfg.max_tool_result_chars,
        "scan_analysis": ai_cfg.scan_analysis,
        "batch_sources": ai_cfg.batch_sources(),
        "rules_path": (config.get("yara") or {}).get("rules_path") or "",
        "quarantine_dir": str(
            resolve_path((config.get("quarantine") or {}).get("path", "./quarantine"))
        ),
        "clam_host": clam.get("host", "127.0.0.1"),
        "clam_port": int(clam.get("port", 3310) or 3310),
        "clam_timeout": int(clam.get("timeout", 30) or 30),
        "log_file": str(LOG_FILE),
        "dump_dir": str(AI_DUMP_DIR),
        "project_root": str(PROJECT_ROOT),
    }
    return ai_cfg, payload


def _print_native_ai_result(res: Dict) -> None:
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


def _run_ai_native(payload: Dict, question=None, minutes: int = 0) -> Dict:
    from . import core_bridge

    if question:
        print(f"提问: {question}")
        return core_bridge.ai_ask(payload, question)
    print(f"开始批次分析（--minutes={minutes or '默认'}）...")
    return core_bridge.ai_run_batch(payload, minutes)


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
    try:
        res = core_bridge.ai_analyze_detection(payload, detection)
        if res.get("final_text"):
            print(f"\n{Fore.CYAN}[AI 检出分析]{Style.RESET_ALL}")
            print(res["final_text"])
            print("-" * 46)
    except Exception:
        logger.exception("AI 检出联动失败（不影响扫描流程）")


def cmd_ai(args: argparse.Namespace) -> int:
    config = _prepare_config(args)
    from . import core_bridge

    ai_cfg, payload = _ai_config_payload(config)
    question = getattr(args, "question", None) or getattr(args, "prompt", None)
    minutes = getattr(args, "minutes", None) or 0

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
        res = _run_ai_native(payload, question=question, minutes=minutes)
    except core_bridge.CoreError as e:
        print(f"AI 调用失败: {e}")
        return 1
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

    while True:
        ai_cfg, payload = _ai_config_payload(config)
        print("\n--- AI 分析 ---")
        print(f"状态: {_ai_hint(ai_cfg)}")
        print("1. 执行本批事件分析")
        print("2. 自由提问")
        print("3. 测试端点连通")
        print("0. 返回主菜单")
        try:
            choice = input("请选择 [0-3]: ").strip()
        except EOFError:
            return
        try:
            if choice == "0":
                return
            if not core_bridge.is_available():
                print(f"C++ 内核未加载: {core_bridge.load_error()}")
                continue
            if choice in ("1", "2") and not ai_cfg.active:
                print(f"AI 不可用: {_ai_hint(ai_cfg)}")
                print("提示: 复制 config.ini.example 为 config.ini 并填写 base_url/model/api_key。")
                continue
            if choice == "1":
                _print_native_ai_result(_run_ai_native(payload, minutes=0))
            elif choice == "2":
                question = input("请输入问题: ").strip()
                if question:
                    _print_native_ai_result(_run_ai_native(payload, question=question))
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

def _prepare_config(args: argparse.Namespace) -> Dict:
    """确保配置存在并加载；若命令未显式传入配置则使用默认值。"""
    config_path = getattr(args, "config", None)
    path = Path(config_path) if config_path else CONFIG_FILE
    if not path.exists():
        generate_default_config(path)
    if getattr(args, "config", None) is None:
        args.config = str(path)
    return load_config(path)


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

    p_ai = subparsers.add_parser("ai", help="AI 分析（批次事件分析 / 自由提问）")
    p_ai.add_argument("--minutes", type=int, default=None, help="批次窗口分钟数 (默认: config.ini interval)")
    p_ai.add_argument("--prompt", default=None, help="直接提问（等价于 ai ask）")
    p_ai.add_argument("--test", action="store_true", help="仅测试 AI 端点连通性")
    ai_sub = p_ai.add_subparsers(dest="ai_action", metavar="子命令")
    p_ask = ai_sub.add_parser("ask", help="自由问答（可调用工具查证）")
    p_ask.add_argument("question", help="要提问的内容")
    p_ask.set_defaults(func=cmd_ai)
    p_ai.set_defaults(func=cmd_ai)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    colorama_init()
    parser = build_parser()
    args = parser.parse_args(argv)

    setup_logging(log_level=logging.INFO, log_file=LOG_FILE)

    if args.command:
        return args.func(args)

    # 无子命令：进入交互菜单
    config = _prepare_config(args)
    print_banner()
    print(f"配置文件: {Path(args.config).resolve()}")
    print(f"日志文件: {LOG_FILE}")
    print(f"Python: {sys.version.split()[0]} | 平台: {sys.platform}")
    interactive_menu(config)
    return 0


if __name__ == "__main__":
    sys.exit(main())
