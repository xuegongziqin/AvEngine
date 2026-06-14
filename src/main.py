"""
main.py - AvEngine 杀毒引擎主程序
提供命令行菜单，支持实时监控、手动扫描、病毒库更新等功能。
"""

import os
import sys
import time
import logging
import argparse
import subprocess
import shutil
from typing import Optional

# 确保项目根目录在 sys.path 中，便于导入 src 包
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.scheduler import Scheduler
from src.clamav_scanner import ClamavScanner
from src.yara_scanner import YaraScanner
from src.utils import setup_logging, load_config, is_admin, quarantine_file
from src.utils import compute_file_hash

# 全局配置
DEFAULT_CONFIG_PATH = "config.yaml"
DEFAULT_LOG_FILE = os.path.join("logs", "avengine.log")

def is_sysmon_installed() -> bool:
    """通过注册表检查 Sysmon 服务和驱动是否已安装。"""
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                             r"SYSTEM\CurrentControlSet\Services\SysmonDrv")
        winreg.CloseKey(key)
        return True
    except FileNotFoundError:
        return False

def install_sysmon(sysmon_exe_path: str = "Sysmon.exe") -> bool:
    """
    使用管理员权限安装 Sysmon（需以管理员身份运行本程序）。
    默认使用内置配置（不加载任何过滤，记录所有事件），可替换为自定义 xml。
    """
    if not os.path.exists(sysmon_exe_path):
        logging.error("找不到 Sysmon.exe，请将其放在项目根目录。")
        return False

    # 安装命令：接受最终用户许可协议，安装（-i），使用默认配置（不指定 -c）
    cmd = [sysmon_exe_path, "-accepteula", "-i"]
    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True)
        logging.info("Sysmon 安装成功，驱动已加载。")
        return True
    except subprocess.CalledProcessError as e:
        logging.error(f"Sysmon 安装失败: {e.stderr}")
        return False
    except FileNotFoundError:
        logging.error("无法执行 Sysmon.exe，请确认路径正确。")
        return False

def start_sysmon_service() -> bool:
    """启动 Sysmon 服务（若已安装但未运行）。"""
    try:
        subprocess.run(["sc", "start", "Sysmon"], check=True, capture_output=True)
        return True
    except subprocess.CalledProcessError:
        return False

def generate_default_config(path: str) -> None:
    """若配置文件不存在，生成默认配置。"""
    if os.path.exists(path):
        return
    default_config = """# AvEngine 配置文件
yara:
  rules_path: "./rules"
clamav:
  host: "127.0.0.1"
  port: 3310
  timeout: 30
sysmon:
  channel: "Microsoft-Windows-Sysmon/Operational"
quarantine:
  path: "./quarantine"
scan:
  on_access: false
  timer_enabled: false
  timer_interval: 3600
  monitor_paths:
    - "C:\\\\Users\\\\Public"
    - "C:\\\\Temp"
"""
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(default_config)
        logging.info("已生成默认配置文件: %s", path)
    except Exception as e:
        logging.error("无法创建配置文件 %s: %s", path, e)

def print_banner():
    banner = """
   █████╗ ██╗   ██╗███████╗███╗   ██╗ ██████╗ ██╗███╗   ██╗███████╗
  ██╔══██╗██║   ██║██╔════╝████╗  ██║██╔════╝ ██║████╗  ██║██╔════╝
  ███████║██║   ██║█████╗  ██╔██╗ ██║██║  ███╗██║██╔██╗ ██║█████╗
  ██╔══██║╚██╗ ██╔╝██╔══╝  ██║╚██╗██║██║   ██║██║██║╚██╗██║██╔══╝
  ██║  ██║ ╚████╔╝ ███████╗██║ ╚████║╚██████╔╝██║██║ ╚████║███████╗
  ╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝╚═╝  ╚═══╝╚══════╝
         基于 YARA + ClamAV + Sysmon 的多引擎杀毒引擎 v0.1
    """
    print(banner)

def show_status(config):
    """显示当前配置和引擎状态。"""
    print("\n--- 引擎状态 ---")
    clamav = ClamavScanner(
        host=config.get("clamav", {}).get("host", "127.0.0.1"),
        port=config.get("clamav", {}).get("port", 3310),
    )
    print(f"ClamAV 连接: {'可用' if clamav.is_available else '不可用'}")
    if clamav.is_available:
        ver = clamav.get_version()
        print(f"  版本: {ver}")

    yara_rules = config.get("yara", {}).get("rules_path", "./rules")
    yara = YaraScanner(rules_path=yara_rules)
    if yara.is_available:
        print(f"YARA 规则: 已加载 ({yara.rules_count} 条)")
    else:
        print("YARA 规则: 未加载 (请检查规则文件语法)")

    if sys.platform == "win32":
        print("Sysmon: 模块可用 (需确保服务运行)")
    else:
        print("Sysmon: 仅限 Windows")

    q_path = config.get("quarantine", {}).get("path", "./quarantine")
    print(f"隔离目录: {q_path} {'(存在)' if os.path.isdir(q_path) else '(未创建)'}")

    monitor_paths = config.get("scan", {}).get("monitor_paths", [])
    print(f"监控路径: {', '.join(monitor_paths) if monitor_paths else '无'}")
    print("-----------------\n")

def manual_scan(config):
    """交互式手动扫描。"""
    target = input("请输入要扫描的文件或目录路径: ").strip()
    if not target:
        print("路径不能为空。")
        return
    if not os.path.exists(target):
        print(f"路径不存在: {target}")
        return

    # 创建独立扫描器（不使用调度器）
    yara = YaraScanner(rules_path=config.get("yara", {}).get("rules_path", "./rules"))
    clamav = ClamavScanner(
        host=config.get("clamav", {}).get("host", "127.0.0.1"),
        port=config.get("clamav", {}).get("port", 3310),
    )
    quarantine_path = config.get("quarantine", {}).get("path", "./quarantine")

    if os.path.isfile(target):
        print(f"正在扫描文件: {target}")
        yara_hits = yara.scan_file(target) if yara.is_available else []
        clam_result = clamav.scan_file(target) if clamav.is_available else None
        file_hash = compute_file_hash(target)

        print(f"SHA256: {file_hash}")
        if yara_hits:
            print(f"YARA 命中: {', '.join(yara_hits)}")
        if clam_result:
            print(f"ClamAV 发现病毒: {clam_result}")

        if yara_hits or clam_result:
            action = input("是否隔离此文件? (y/n): ").lower()
            if action == 'y':
                new_path = quarantine_file(target, quarantine_path)
                if new_path:
                    print(f"文件已隔离到: {new_path}")
                else:
                    print("隔离失败。")
            else:
                print("跳过隔离。")
        else:
            print("未发现威胁。")

    elif os.path.isdir(target):
        print(f"正在扫描目录: {target}")
        yara_dir = yara.scan_directory(target) if yara.is_available else {}
        clam_dir = clamav.scan_directory(target) if clamav.is_available else {}
        infected = set()
        for f, rules in yara_dir.items():
            infected.add(f)
            print(f"[YARA] {f}: {', '.join(rules)}")
        for f, virus in clam_dir.items():
            infected.add(f)
            print(f"[ClamAV] {f}: {virus}")

        if infected:
            print(f"\n发现 {len(infected)} 个受感染文件。")
            action = input("是否将所有受感染文件隔离? (y/n): ").lower()
            if action == 'y':
                for f in infected:
                    quarantine_file(f, quarantine_path)
                print("隔离完成。")
        else:
            print("未发现威胁。")

def update_virus_db():
    """触发 ClamAV 病毒库更新（需要 freshclam 或 clamd 重载）。"""
    clamav = ClamavScanner()
    if clamav.is_available:
        print("正在请求 ClamAV 重载病毒库...")
        if clamav.reload():
            print("重载指令已发送，更新将在后台完成。")
        else:
            print("重载失败，请检查 clamd 服务。")
    else:
        print("ClamAV 不可用，无法更新。")
def run_realtime_monitor(config):
    """启动实时监控（Sysmon + 按访问扫描）。"""
    if sys.platform != "win32":
        print("实时监控功能仅在 Windows 上可用。")
        return

    # 1. 必须以管理员权限运行（Sysmon 安装和读取事件日志都需要）
    if not is_admin():
        print("实时监控需要管理员权限，请以管理员身份重新运行本程序。")
        input("按回车键返回主菜单...")
        return

    # 2. 检查/安装 Sysmon
    sysmon_exe = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Sysmon.exe")
    if not is_sysmon_installed():
        print("未检测到 Sysmon 服务，正在自动安装...")
        if not install_sysmon(sysmon_exe):
            print("Sysmon 安装失败，实时监控无法启动。")
            input("按回车键返回主菜单...")
            return
        print("Sysmon 安装完成，服务已启动。")
    else:
        # 确保服务处于运行状态
        print("Sysmon 已安装，检查服务状态...")
        start_sysmon_service()

    # 3. 启动 ClamAV 服务（如果安装了 msi，默认服务名可能是 clamd 或 ClamAVService）
    try:
        subprocess.run(["sc", "start", "clamd"], capture_output=True)
    except Exception:
        pass  # 非必需

    # 4. 强制开启 on_access 并启动调度器
    config.setdefault("scan", {})["on_access"] = True
    scheduler = Scheduler(config)
    scheduler.on_threat = lambda path, desc, action: print(
        f"\n[!!!] 威胁告警: {path}\n  细节: {desc}\n  处理: {action}\n"
    )
    scheduler.start(enable_sysmon=True, enable_timer=False)

    print("实时监控已启动，按 Ctrl+C 返回主菜单...")
    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n停止实时监控...")
    finally:
        scheduler.stop()

def main():
    # 解析命令行参数（可选，此处仅用于初始化）
    parser = argparse.ArgumentParser(description="AvEngine 杀毒引擎")
    parser.add_argument("-c", "--config", default=DEFAULT_CONFIG_PATH, help="配置文件路径")
    args = parser.parse_args()

    # 设置日志
    log_dir = os.path.dirname(DEFAULT_LOG_FILE)
    os.makedirs(log_dir, exist_ok=True)
    setup_logging(log_level=logging.INFO, log_file=DEFAULT_LOG_FILE)

    # 加载配置
    if not os.path.exists(args.config):
        generate_default_config(args.config)
    config = load_config(args.config)

    print_banner()
    print(f"配置文件: {os.path.abspath(args.config)}")
    print(f"日志文件: {os.path.abspath(DEFAULT_LOG_FILE)}")
    print(f"Python: {sys.version}")
    print(f"平台: {sys.platform}")

    # 主菜单循环
    while True:
        print("\n" + "="*50)
        print(" 主菜单")
        print("="*50)
        print("1. 启动实时监控 (Sysmon + 按访问扫描)")
        print("2. 手动扫描文件/目录")
        print("3. 更新病毒库 (ClamAV)")
        print("4. 查看引擎状态")
        print("5. 退出")
        choice = input("请输入选项 [1-5]: ").strip()

        if choice == "1":
            run_realtime_monitor(config)
        elif choice == "2":
            manual_scan(config)
        elif choice == "3":
            update_virus_db()
        elif choice == "4":
            show_status(config)
        elif choice == "5":
            print("感谢使用 AvEngine，再见！")
            break
        else:
            print("无效选项，请重新输入。")

if __name__ == "__main__":
    main()