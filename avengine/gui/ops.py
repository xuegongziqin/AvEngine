"""
gui/ops.py - GUI 背后的操作层（**不导入 Tk**，因此可以单元测试）

所有会改变系统状态的操作（装/卸 Sysmon、装/卸 ClamAV、启停服务、特权服务安装、
隔离文件、更新病毒库、扫描）都在这里，标签页只负责收集参数 + 显示结果。
这样 GUI 的"会不会下错命令"这件事可以被测试固定住。

约定：
  * 一切外部命令都用 run() 起，带 CREATE_NO_WINDOW（GUI 下不该闪黑框）
  * 输出解码顺序：UTF-8 严格 → 本机 ANSI（与内核 run_capture、CLI 的既有约定一致）
  * 返回 OpResult（ok / message / output / data），不抛异常给 UI
"""

from __future__ import annotations

import ctypes
import json
import locale
import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .. import core_bridge, privsvc
from ..aiconfig import AIConfig, load_ai_config
from ..config import validate_config
from ..paths import (
    AI_CONFIG_FILE,
    CLAMAV_MSI,
    CONFIG_FILE,
    LOG_FILE,
    PROJECT_ROOT,
    SCRIPTS_DIR,
    SYSMON_CONFIG,
    clamav_candidates,
    clamav_is_legacy,
    clamav_msi,
    native_arch,
    sysmon_exe,
    windows_version,
)
from ..utils import is_admin, quarantine_file

CREATE_NO_WINDOW = 0x08000000
CLAMD_SERVICE = "clamd"
PRIVSVC_SERVICE = "AvEnginePrivSvc"


# -------------------- 基础执行 --------------------


@dataclass
class OpResult:
    ok: bool
    message: str
    output: str = ""
    data: Dict[str, Any] = field(default_factory=dict)


def decode_output(raw: bytes) -> str:
    """
    解码子进程输出：UTF-8 严格 → 本机 ANSI。

    仓库里 C++ 的 run_capture 也是这个顺序：UTF-8 优先能保住中文（脚本会把控制台切到
    UTF-8），无 BOM 的 GBK 输出再退到 ANSI，避免整段变成乱码。
    """
    if not raw:
        return ""
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode(locale.getpreferredencoding(False) or "gbk", errors="replace")


def run(cmd: Sequence[Any], timeout: int = 120, cwd: Optional[Path] = None) -> Tuple[int, str]:
    """
    执行外部命令，返回 (returncode, 合并输出)。

    returncode = -1 表示**命令压根没跑起来**（找不到 / 起不来 / 超时），
    此时第二项是原因说明；调用方应把它带进面向用户的提示里 —— 只报"退出码 -1"
    等于什么都没说（用户实际踩过：服务安装失败，对话框只有 -1，原因藏在输出面板里）。
    """
    args = [str(c) for c in cmd]
    kwargs: Dict[str, Any] = {"capture_output": True, "cwd": str(cwd) if cwd else None}
    if os.name == "nt":
        kwargs["creationflags"] = CREATE_NO_WINDOW
    try:
        proc = subprocess.run(args, timeout=timeout, **kwargs)  # type: ignore[arg-type]
    except FileNotFoundError:
        return -1, "找不到可执行文件: {}".format(args[0])
    except subprocess.TimeoutExpired:
        return -1, "命令超时（{} 秒）: {}".format(timeout, " ".join(args))
    except OSError as exc:
        return -1, "无法执行 {}: {}".format(args[0], exc)
    text = decode_output(proc.stdout or b"") + decode_output(proc.stderr or b"")
    return proc.returncode, text.strip()


def first_line(text: str, limit: int = 300) -> str:
    """取输出的第一行非空内容（用于把失败原因塞进一句话提示里）。"""
    for line in (text or "").splitlines():
        line = line.strip()
        if line:
            return line[:limit]
    return ""


def summarize(code: int, output: str) -> str:
    """把 (退出码, 输出) 压成一句能直接给用户看的原因。"""
    reason = first_line(output)
    if code == -1:
        return reason or "命令没有执行成功（既没有退出码也没有输出）"
    if reason:
        return "退出码 {}：{}".format(code, reason)
    return "退出码 {}".format(code)


def run_powershell(script: Path, args: Sequence[Any] = (), timeout: int = 900) -> Tuple[int, str]:
    """执行仓库里的 .ps1（脚本自身用 $PSScriptRoot 定位资源，工作目录固定为项目根）。"""
    cmd = ["powershell", "-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass",
           "-File", str(script)] + [str(a) for a in args]
    return run(cmd, timeout=timeout, cwd=PROJECT_ROOT)


def run_bat(script: Path, args: Sequence[Any] = (), timeout: int = 900) -> Tuple[int, str]:
    """
    执行仓库里的 .bat（用 cmd /c，工作目录固定为项目根）。

    ClamAV 的安装/配置路径刻意走 bat + CLI 而不是 PowerShell：Win7 SP1 自带 PS 2.0，
    之前的 PS 脚本用了 3.0+ 语法（-notin / Get-ChildItem -File），在那边是**解析期**失败，
    整个安装一步都不执行。bat 内部通过 scripts\\lib_avengine.bat 找到 CLI 来写 config.yaml。
    """
    cmd = ["cmd", "/c", str(script)] + [str(a) for a in args]
    return run(cmd, timeout=timeout, cwd=PROJECT_ROOT)


# -------------------- 系统/权限 --------------------


def admin_state() -> bool:
    return bool(is_admin())


def relaunch_elevated(argv: Optional[Sequence[str]] = None) -> OpResult:
    """用 runas 重新以管理员身份启动当前程序（GUI 里的"以管理员身份重启"）。"""
    if os.name != "nt":
        return OpResult(False, "仅 Windows 支持提权重启")
    exe = sys.executable
    params = " ".join(['"{}"'.format(a) for a in (argv or sys.argv[1:])])
    try:
        rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, str(PROJECT_ROOT), 1)
    except Exception as exc:  # noqa: BLE001
        return OpResult(False, "提权启动失败: {}".format(exc))
    if rc <= 32:
        return OpResult(False, "提权被取消或失败（ShellExecuteW={}）".format(rc))
    return OpResult(True, "已请求以管理员身份重启（UAC 确认后新窗口会打开）")


# -------------------- Sysmon --------------------


def sysmon_driver_installed() -> bool:
    try:
        import winreg
    except ImportError:
        return False
    try:
        winreg.CloseKey(winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                       r"SYSTEM\CurrentControlSet\Services\SysmonDrv"))
        return True
    except OSError:
        return False


def service_state(name: str) -> Dict[str, Any]:
    """查询服务状态：{exists, state, pid}。用 sc query（英文输出好解析）。"""
    code, out = run(["sc", "query", name], timeout=20)
    if code != 0 or "SERVICE_NAME" not in out.upper():
        return {"exists": False, "state": "", "raw": out}
    state = ""
    for line in out.splitlines():
        if "STATE" in line.upper():
            parts = line.split(":", 1)
            if len(parts) == 2:
                # 形如 "4  RUNNING (STOPPABLE, NOT_PAUSABLE)"：状态名是数字后的那个 token
                tokens = parts[1].split()
                if len(tokens) > 1 and tokens[0].isdigit():
                    state = tokens[1]
                elif tokens:
                    state = tokens[0]
    return {"exists": True, "state": state, "raw": out}


def sysmon_state() -> Dict[str, Any]:
    version = windows_version()
    legacy = version in ((6, 0), (6, 1))
    exe = sysmon_exe()
    drv = service_state("SysmonDrv")
    svc = service_state("Sysmon")
    return {
        "windows": "{}.{}".format(version[0], version[1]),
        "arch": native_arch(),
        "legacy_expected": legacy,
        "exe": str(exe),
        "exe_exists": exe.is_file(),
        "config_xml": str(SYSMON_CONFIG),
        "config_exists": SYSMON_CONFIG.is_file(),
        "driver_installed": sysmon_driver_installed(),
        "driver_state": drv.get("state", ""),
        "service_state": svc.get("state", ""),
    }


def sysmon_install() -> OpResult:
    """未装则 -i 安装，已装则 -c 应用本项目的配置（与 scripts\\config_sysmon.bat 一致）。"""
    if os.name != "nt":
        return OpResult(False, "仅 Windows 支持")
    if not admin_state():
        return OpResult(False, "需要管理员权限：请以管理员身份重启本程序")
    exe = sysmon_exe()
    if not exe.is_file():
        return OpResult(False, "找不到 Sysmon 可执行文件: {}\n"
                               "现代版放 bina\\Sysmon\\（Win8.1+），Win7 用 bina\\Sysmon\\sysmonwin7\\".format(exe))
    if not SYSMON_CONFIG.is_file():
        return OpResult(False, "找不到配置文件: {}".format(SYSMON_CONFIG))
    installed = sysmon_driver_installed()
    flag = "-c" if installed else "-i"
    code, out = run([exe, "-accepteula", flag, str(SYSMON_CONFIG)], timeout=300)
    ok = code == 0
    action = "应用配置" if installed else "安装"
    return OpResult(ok, "Sysmon {} {}".format(action, "成功" if ok else "失败（退出码 {}）".format(code)),
                    out, {"installed": sysmon_driver_installed(), "flag": flag})


def sysmon_uninstall() -> OpResult:
    if not admin_state():
        return OpResult(False, "需要管理员权限：请以管理员身份重启本程序")
    exe = sysmon_exe()
    if not exe.is_file():
        return OpResult(False, "找不到 Sysmon 可执行文件: {}".format(exe))
    code, out = run([exe, "-accepteula", "-u"], timeout=300)
    ok = code == 0 and not sysmon_driver_installed()
    return OpResult(ok, "Sysmon 卸载{}".format("成功" if ok else "可能失败（退出码 {}）".format(code)),
                    out, {"installed": sysmon_driver_installed()})


# -------------------- ClamAV --------------------


def clamav_config_values(config: Dict[str, Any]) -> Dict[str, Any]:
    clam = config.get("clamav") or {}
    return {
        "host": str(clam.get("host", "127.0.0.1") or ""),
        "port": int(clam.get("port", 3310) or 3310),
        "timeout": int(clam.get("timeout", 30) or 30),
    }


def clamav_state(config: Dict[str, Any]) -> Dict[str, Any]:
    values = clamav_config_values(config)
    svc = service_state(CLAMD_SERVICE)
    local_files = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "ClamAV"
    reachable = False
    version = ""
    if values["host"]:
        try:
            info = core_bridge.clam_version(values["host"], values["port"], 3)
            reachable = bool(info.get("available"))
            version = str(info.get("version") or "")
        except core_bridge.CoreError:
            reachable = False

    version_pair = windows_version()
    legacy_expected = clamav_is_legacy(version_pair)
    candidates = clamav_candidates()
    selected = clamav_msi()
    modern = [p for p in candidates if p.parent.name.lower() != "clamwin7"]
    legacy = [p for p in candidates if p.parent.name.lower() == "clamwin7"]
    return {
        "msi": str(selected),
        "msi_exists": selected.is_file(),
        "modern_msi": str(modern[0]) if modern else "",
        "modern_exists": any(p.is_file() for p in modern),
        "legacy_msi": str(legacy[0]) if legacy else "",
        "legacy_exists": any(p.is_file() for p in legacy),
        "os_version": "{}.{}".format(version_pair[0], version_pair[1]),
        "legacy_expected": legacy_expected,
        "package_note": "本机 Windows {} → 默认{}安装包".format(
            "{}.{}".format(version_pair[0], version_pair[1]),
            "Win7 兼容" if legacy_expected else "现代"),
        "install_dir": str(local_files),
        "install_dir_exists": local_files.is_dir(),
        "service_name": CLAMD_SERVICE,
        "service_exists": svc.get("exists", False),
        "service_state": svc.get("state", ""),
        "configured_host": values["host"],
        "configured_port": values["port"],
        "configured_timeout": values["timeout"],
        "mode": "disabled" if not values["host"] else ("local" if values["host"] in
                                                       ("127.0.0.1", "localhost", "::1") else "lan"),
        "reachable": reachable,
        "version": version,
    }


def clamav_configure(host: str, port: int = 3310) -> OpResult:
    """
    写 config.yaml 的 clamav 段：调用 scripts\\set_clamav.bat（保持与安装脚本同一实现）。
    host 传 none/off/空 → 纯 YARA 模式。

    为什么走 bat 而不是在这里直接写：安装路径必须不依赖 PowerShell（Win7 SP1 只有 PS 2.0），
    而 bat 内部会找到 CLI（发布包 avengine.exe / venv / PATH 上的 python），
    最终仍由 avengine/configwrite.py 写文件 —— 与本页设置用的是同一套写入代码。
    """
    script = SCRIPTS_DIR / "set_clamav.bat"
    if not script.is_file():
        return OpResult(False, "找不到 {}".format(script))
    args = ["-ClamdHost", host or "none", "-Port", str(port or 3310),
            "-ConfigYaml", str(CONFIG_FILE)]
    code, out = run_bat(script, args, timeout=120)
    ok = code == 0
    return OpResult(ok, "已写入 config.yaml（clamd={}:{}）".format(host or "(禁用)", port) if ok
                    else "写入失败 —— {}".format(summarize(code, out)), out)


def clamav_test(host: str, port: int, timeout: int = 5) -> OpResult:
    if not host:
        return OpResult(False, "当前配置为纯 YARA 模式（未启用 ClamAV）")
    try:
        info = core_bridge.clam_version(host, port, max(1, min(timeout, 10)))
    except core_bridge.CoreError as exc:
        return OpResult(False, "探测失败: {}".format(exc))
    ok = bool(info.get("available"))
    detail = info.get("version") or info.get("error") or info.get("detail") or ""
    return OpResult(ok, "{}:{} {}".format(host, port, "可用" + ("（{}）".format(detail) if detail else "")
                                          if ok else "不可用" + ("（{}）".format(detail) if detail else "")),
                    json.dumps(info, ensure_ascii=False, indent=2), info)


def clamav_reload(host: str, port: int, timeout: int = 30) -> OpResult:
    if not host:
        return OpResult(False, "当前配置为纯 YARA 模式（未启用 ClamAV）")
    try:
        info = core_bridge.clam_reload(host, port, max(1, min(timeout, 120)))
    except core_bridge.CoreError as exc:
        return OpResult(False, "重载失败: {}".format(exc))
    ok = bool(info.get("ok", info.get("available", False)))
    return OpResult(ok, info.get("detail") or ("已通知 clamd 重载病毒库" if ok else "重载失败"),
                    json.dumps(info, ensure_ascii=False, indent=2), info)


def clamav_install(port: int = 3310, package: str = "auto") -> OpResult:
    """
    本机安装 ClamAV。

    package:
      auto（默认）  按系统版本自动选包（Win8.1+ 现代版；Win7 SP1 用 bina\\clamwin7 下的包）
      modern        强制现代版（bina\\clamav.msi 等）
      legacy        强制 Win7 兼容版（bina\\clamwin7\\*.msi）
    """
    if not admin_state():
        return OpResult(False, "需要管理员权限：请以管理员身份重启本程序")
    script = SCRIPTS_DIR / "setup_clamav.bat"
    if not script.is_file():
        return OpResult(False, "找不到 {}".format(script))
    args = ["--port", str(port or 3310)]
    if package in ("modern", "legacy"):
        candidates = clamav_candidates()
        wanted = [p for p in candidates
                  if (p.parent.name.lower() == "clamwin7") == (package == "legacy")]
        chosen = next((p for p in wanted if p.is_file()), None)
        if chosen is None:
            return OpResult(False, "没有{}安装包（{}）".format(
                "Win7 兼容" if package == "legacy" else "现代版",
                "、".join(str(p) for p in wanted) or "候选目录为空"))
        args += ["--msi", str(chosen)]
    code, out = run_bat(script, args, timeout=1800)
    ok = code == 0
    message = ("ClamAV 安装/配置完成（{}）".format(package) if ok
               else "ClamAV 安装失败 —— {}".format(summarize(code, out)))
    return OpResult(ok, message, out, {"package": package})


def clamav_start() -> OpResult:
    code, out = run(["sc", "start", CLAMD_SERVICE], timeout=180)
    if code != 0:
        # 服务名不对/未注册时退回仓库脚本（它会在必要时前台启动 clamd）
        script = SCRIPTS_DIR / "start_clamav.bat"
        if script.is_file():
            code2, out2 = run([str(script)], timeout=180)
            if code2 == 0:
                return OpResult(True, "已通过 scripts\\start_clamav.bat 启动 clamd", out + "\n" + out2)
            return OpResult(False, "启动 clamd 失败（sc={}, 脚本={}）".format(code, code2), out + "\n" + out2)
    ok = code == 0
    return OpResult(ok, "clamd {}".format("已启动" if ok else "启动失败（退出码 {}）".format(code)), out)


def clamav_stop() -> OpResult:
    code, out = run(["sc", "stop", CLAMD_SERVICE], timeout=180)
    ok = code == 0 or "1062" in out  # 1062 = 服务未启动
    return OpResult(ok, "clamd {}".format("已停止" if code == 0 else "停止返回 {}".format(code)), out)


def clamav_uninstall(purge_dir: bool = False) -> OpResult:
    if not admin_state():
        return OpResult(False, "需要管理员权限：请以管理员身份重启本程序")
    logs: List[str] = []
    code, out = run(["sc", "stop", CLAMD_SERVICE], timeout=180)
    logs.append("$ sc stop clamd -> {}\n{}".format(code, out))
    # 两套安装包都试一遍：用户可能装的是 Win7 兼容版或现代版（msiexec /x 对没装的包会返回
    # 1605「未知产品」并被忽略）
    tried = []
    for candidate in clamav_candidates():
        if not candidate.is_file() or candidate in tried:
            continue
        tried.append(candidate)
        code, out = run(["msiexec", "/x", str(candidate), "/qn", "/norestart"], timeout=1800)
        logs.append("$ msiexec /x {} -> {}\n{}".format(candidate.name, code, out))
    if not tried:
        logs.append("未找到任何 ClamAV 安装包，跳过 msiexec 卸载")
    code, out = run(["sc", "delete", CLAMD_SERVICE], timeout=60)
    logs.append("$ sc delete clamd -> {}\n{}".format(code, out))
    if purge_dir:
        target = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "ClamAV"
        logs.append("安装目录保留未删除: {}".format(target) if target.is_dir()
                    else "安装目录已不存在: {}".format(target))
    state = service_state(CLAMD_SERVICE)
    ok = not state.get("exists")
    return OpResult(ok, "ClamAV 卸载{}（服务残留={}）".format("完成" if ok else "可能未完全卸载",
                                                              state.get("exists")), "\n\n".join(logs))


# -------------------- 特权服务 --------------------


def privsvc_exe() -> Optional[Path]:
    for candidate in privsvc.service_candidates():
        if candidate.is_file():
            return candidate
    return None


def privsvc_state() -> Dict[str, Any]:
    exe = privsvc_exe()
    info: Dict[str, Any] = {
        "installed": privsvc.is_service_installed(),
        "exe": str(exe) if exe else "",
        "exe_exists": bool(exe),
        "service_state": service_state(PRIVSVC_SERVICE).get("state", ""),
        "pipe": privsvc.PIPE_NAME,
        "check_pin": "",
        "check_pin_code": None,
        "ping": "",
        "ping_ok": False,
    }
    if exe is not None:
        code, out = run([exe, "--check-pin"], timeout=30)
        info["check_pin"] = out
        info["check_pin_code"] = code
    if info["installed"]:
        try:
            info["ping"] = privsvc.ping()
            info["ping_ok"] = True
        except privsvc.PrivSvcError as exc:
            info["ping"] = "{}{}".format(exc, "（{}）".format(exc.hint) if exc.hint else "")
    return info


def privsvc_install(auto_start: bool = False) -> OpResult:
    exe = privsvc_exe()
    if exe is None:
        return OpResult(False, "找不到 AvEnginePrivSvc.exe：先运行 service\\build_service.bat")
    cmd = [exe, "--install"] + (["--auto"] if auto_start else [])
    code, out = run(cmd, timeout=180)
    ok = code == 0
    message = ("特权服务已安装（{}）".format("自动启动" if auto_start else "按需启动") if ok
               else "特权服务安装失败 —— {}".format(summarize(code, out)))
    return OpResult(ok, message, out, {"installed": privsvc.is_service_installed()})


def privsvc_uninstall() -> OpResult:
    exe = privsvc_exe()
    if exe is None:
        return OpResult(False, "找不到 AvEnginePrivSvc.exe")
    code, out = run([exe, "--uninstall"], timeout=180)
    ok = code == 0
    message = "特权服务已卸载" if ok else "特权服务卸载失败 —— {}".format(summarize(code, out))
    return OpResult(ok, message, out, {"installed": privsvc.is_service_installed()})


def privsvc_ping() -> OpResult:
    try:
        pong = privsvc.ping()
    except privsvc.PrivSvcError as exc:
        hint = "（{}）".format(exc.hint) if exc.hint else ""
        return OpResult(False, "探活失败: {}{}".format(exc, hint), "", {})
    return OpResult(True, "服务可用: {}".format(pong), "", {"reply": pong})


def privsvc_run_system(args: str, wait: bool = True, timeout_s: int = 600,
                       caller_session: bool = False) -> OpResult:
    """
    请特权服务以 SYSTEM 运行 avengine.exe <args>。

    注意：调用者必须是**安装目录里被签名的 avengine.exe**；从源码树运行会被
    路径白名单拒绝（CALLER_WRONG_PATH）——这是设计，不是 bug。
    """
    try:
        result = privsvc.run_system(args, wait=wait, timeout_ms=max(1, timeout_s) * 1000,
                                    caller_session=caller_session)
    except privsvc.PrivSvcError as exc:
        hint = "（{}）".format(exc.hint) if exc.hint else ""
        return OpResult(False, "被拒绝或失败: {}{}".format(exc, hint), "", {})
    detail = "已启动 SYSTEM 子进程 pid={}".format(result.pid)
    if result.log_path:
        detail += "\n输出: {}".format(result.log_path)
    if result.note:
        detail += "\n说明: {}".format(result.note)
    if wait:
        detail += "\n退出码: {}".format("timeout" if result.timed_out else result.exit_code)
    return OpResult(not result.timed_out, detail, "", {"pid": result.pid,
                                                       "exit_code": result.exit_code,
                                                       "log": result.log_path})


# -------------------- 状态汇总 / 扫描 --------------------


def collect_status(config: Dict[str, Any]) -> Dict[str, Any]:
    """给"概览"页用的状态快照。各字段都可能缺失，UI 要按"未知"处理。"""
    status: Dict[str, Any] = {
        "core_available": core_bridge.is_available(),
        "core_error": core_bridge.load_error(),
        "core_version": "",
        "config_error": validate_config(CONFIG_FILE),
        "admin": admin_state(),
        "monitor_running": False,
        "ai_hint": "",
        "ai_active": False,
        "quarantine_dir": "",
        "quarantine_count": 0,
        "engines": {},
        "paths": {
            "project_root": str(PROJECT_ROOT),
            "config": str(CONFIG_FILE),
            "ai_config": str(AI_CONFIG_FILE),
            "log": str(LOG_FILE),
            "sysmon_config": str(SYSMON_CONFIG),
        },
    }
    if status["core_available"]:
        try:
            status["core_version"] = core_bridge.version()
        except core_bridge.CoreError:
            pass

    try:
        status["monitor_running"] = core_bridge.monitor_running()
    except Exception:  # noqa: BLE001 - 状态页不该因内核异常炸掉
        status["monitor_running"] = False

    ai_cfg: AIConfig = load_ai_config()
    status["ai_active"] = ai_cfg.active
    if not ai_cfg.exists:
        status["ai_hint"] = "未配置（缺少 config.ini）"
    elif not ai_cfg.enabled:
        status["ai_hint"] = "已禁用（enabled=false）"
    elif not ai_cfg.configured:
        status["ai_hint"] = "配置不完整（缺 base_url 或 model）"
    else:
        status["ai_hint"] = "已启用（{} / {}）".format(ai_cfg.model, ai_cfg.base_url)

    quarantine = Path((config.get("quarantine") or {}).get("path") or "./quarantine")
    status["quarantine_dir"] = str(quarantine)
    try:
        status["quarantine_count"] = sum(1 for p in quarantine.iterdir() if p.is_file()) \
            if quarantine.is_dir() else 0
    except OSError:
        status["quarantine_count"] = 0

    if status["core_available"]:
        values = clamav_config_values(config)
        rules = (config.get("yara") or {}).get("rules_path")
        try:
            status["engines"] = core_bridge.engine_status(rules, values["host"], values["port"],
                                                          values["timeout"])
        except core_bridge.CoreError as exc:
            status["engines"] = {"error": str(exc)}
    return status


@dataclass
class ScanOutcome:
    ok: bool = True
    aborted: bool = False
    engines: List[str] = field(default_factory=list)
    yara_hits: Dict[str, List[str]] = field(default_factory=dict)
    clam_hits: Dict[str, str] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)
    messages: List[str] = field(default_factory=list)
    quarantined: List[Tuple[str, str]] = field(default_factory=list)

    @property
    def infected(self) -> List[str]:
        return sorted(set(self.yara_hits) | set(self.clam_hits))


def engine_readiness(config: Dict[str, Any]) -> Tuple[Optional[str], Dict[str, Any], List[str], bool]:
    """
    与 CLI 的 _engine_readiness 同一套判定（YARA 规则目录非空 + ClamAV 探测可用），
    返回 (rules_path, 传给内核的 clamav 段, 警告, 是否至少一个引擎可用)。
    """
    warnings: List[str] = []
    rules_path = (config.get("yara") or {}).get("rules_path")
    yara_dir = Path(rules_path) if rules_path else None
    yara_ok = bool(yara_dir and yara_dir.is_dir() and any(
        p.suffix.lower() in (".yar", ".yara") for p in yara_dir.rglob("*") if p.is_file()))
    if not yara_ok:
        warnings.append("YARA 引擎未启用：规则目录不可用或为空 ({})".format(rules_path or "未配置"))

    values = clamav_config_values(config)
    clam_for_core: Dict[str, Any] = {}
    if not values["host"]:
        warnings.append("ClamAV 已按配置禁用（clamav.host 为空），纯 YARA 模式")
    else:
        try:
            info = core_bridge.clam_version(values["host"], values["port"],
                                            max(1, min(values["timeout"], 5)))
        except core_bridge.CoreError as exc:
            info = {}
            warnings.append("ClamAV 探测失败: {}".format(exc))
        if info.get("available"):
            clam_for_core = values
        else:
            warnings.append("ClamAV 不可用 ({}:{})：本次扫描不含 ClamAV 结论".format(
                values["host"], values["port"]))
    return rules_path, clam_for_core, warnings, (yara_ok or bool(clam_for_core))


def scan_once(target: Path, config: Dict[str, Any]) -> ScanOutcome:
    """扫描文件或目录，返回结构化结果（隔离由调用方另行决定）。"""
    outcome = ScanOutcome()
    target = Path(target)
    if not target.exists():
        outcome.ok = False
        outcome.aborted = True
        outcome.messages.append("路径不存在: {}".format(target))
        return outcome
    if not core_bridge.is_available():
        outcome.ok = False
        outcome.aborted = True
        outcome.messages.append("C++ 内核未加载: {}".format(core_bridge.load_error()))
        return outcome

    rules_path, clam_cfg, warnings, any_engine = engine_readiness(config)
    outcome.warnings.extend(warnings)
    if not any_engine:
        outcome.ok = False
        outcome.aborted = True
        outcome.messages.append("YARA 与 ClamAV 都不可用，本次扫描未执行")
        return outcome

    outcome.messages.append("正在扫描{}: {}".format("目录" if target.is_dir() else "文件", target))
    try:
        if target.is_file():
            result = core_bridge.scan_path(target, rules_path, clam_cfg)
            matches = (result.get("yara") or {}).get("matches") or []
            if matches:
                outcome.yara_hits[result.get("path", str(target))] = matches
            virus = (result.get("clamav") or {}).get("virus")
            if virus:
                outcome.clam_hits[result.get("path", str(target))] = virus
        else:
            result = core_bridge.scan_dir(target, rules_path, clam_cfg)
            outcome.yara_hits = result.get("yara", {}) or {}
            outcome.clam_hits = result.get("clamav", {}) or {}
    except core_bridge.CoreError as exc:
        outcome.ok = False
        outcome.aborted = True
        outcome.messages.append("扫描失败: {}".format(exc))
        return outcome

    if rules_path:
        outcome.engines.append("YARA")
    if clam_cfg:
        outcome.engines.append("ClamAV")
    return outcome


def quarantine_paths(paths: Sequence[str], config: Dict[str, Any]) -> List[Tuple[str, str]]:
    """把文件隔离到配置的隔离目录，返回 [(原路径, 新路径)]。"""
    target_dir = (config.get("quarantine") or {}).get("path", "./quarantine")
    moved: List[Tuple[str, str]] = []
    for path in paths:
        new_path = quarantine_file(path, target_dir)
        if new_path:
            moved.append((path, str(new_path)))
    return moved


def recent_log_lines(limit: int = 400) -> str:
    """读取日志尾部（日志标签页用）。"""
    if not LOG_FILE.is_file():
        return "（还没有日志文件: {}）".format(LOG_FILE)
    try:
        text = LOG_FILE.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return "读取日志失败: {}".format(exc)
    lines = text.splitlines()
    return "\n".join(lines[-limit:])
