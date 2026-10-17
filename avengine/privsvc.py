"""
privsvc.py - AvEngine 特权服务（AvEnginePrivSvc，LocalSystem）的客户端。

用途：AvEngine 需要 SYSTEM 权限的取证/处置（读 Security 日志、枚举系统句柄表、
驱动/防火墙信息……）时，请求服务**以 SYSTEM 令牌启动一个 avengine.exe 子进程**，
服务把子进程 pid、退出码与输出日志路径回给我们。服务不会把 SYSTEM 令牌直接交给
任何进程，也不替换运行中进程的令牌。

服务端的授权门槛（全部满足才执行，任一失败都会拒绝并写审计日志）：
    1) 命名管道 ACL 只允许 SYSTEM/Administrators 连接
    2) 调用者进程创建时间指纹（防 PID 复用）
    3) 调用者令牌必须属于 Administrators
    4) 调用者映像的规范化路径必须等于安装目录下的 avengine.exe（拒绝副本）
    5) Authenticode 验签 + 证书 SHA-256 指纹与服务内钉住值精确比对

因此：**从源码目录跑 `python -m avengine` 无法使用本功能**（调用者不是安装目录里
被签名的 avengine.exe，第 4/5 步必然失败）。必须在已签名部署的发布目录中使用。
"""

from __future__ import annotations

import os
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

PIPE_NAME = r"\\.\pipe\AvEnginePrivSvc"
PROTOCOL_VERSION = "AVPRIV/1"
SERVICE_EXE = "AvEnginePrivSvc.exe"

# 与服务端 service/priv_protocol.h 的 ErrCode 一一对应
ERROR_HINTS = {
    "BAD_PROTOCOL": "服务与客户端协议版本不一致（升级服务或客户端）",
    "BAD_REQUEST": "请求格式不对",
    "NOT_CONFIGURED": "服务未配置证书指纹：先跑 scripts\\gen_signing_cert.ps1 并重新编译服务",
    "INSTALL_DIR_UNKNOWN": "服务无法确定安装目录白名单（找不到 avengine.exe）："
                           "用 service\\AvEnginePrivSvc.exe --install 重新安装，"
                           "或把服务放在 avengine.exe 同目录/其 service\\ 子目录下",
    "CALLER_OPEN_FAIL": "服务打不开调用者进程（可能已退出，或 PID 被复用）",
    "CALLER_NOT_ADMIN": "调用者不是管理员：请以管理员身份运行 avengine.exe",
    "CALLER_SESSION": "调用者会话不符合策略",
    "CALLER_NOT_SIGNED": "调用者没有有效 Authenticode 签名",
    "CALLER_WRONG_CERT": "调用者签名证书不是 AvEngine 内部证书（指纹不匹配）",
    "CALLER_WRONG_PATH": "调用者不是安装目录里的 avengine.exe（副本/源码运行都会被拒）",
    "ARGS_REJECTED": "参数被拒（含控制字符或过长）",
    "CHILD_FAIL": "以 SYSTEM 创建子进程失败",
    "INTERNAL": "服务内部错误",
}


class PrivSvcError(RuntimeError):
    """服务返回的错误（含错误码，便于上层判断该不该提示管理员）。"""

    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message

    @property
    def hint(self) -> str:
        return ERROR_HINTS.get(self.code, "")


@dataclass
class RunResult:
    pid: int
    log_path: Optional[str] = None
    exit_code: Optional[int] = None
    timed_out: bool = False
    note: str = ""


def _encode_value(raw: str) -> str:
    """与 service/priv_protocol.h 的 encode_value 对齐：%XX 转义空白/控制字符/%"""
    out = []
    for ch in raw:
        code = ord(ch)
        if ch == "%" or ch in " \t\r\n" or code < 0x20:
            out.append(f"%{code:02X}")
        else:
            out.append(ch)
    return "".join(out)


def _decode_value(enc: str) -> str:
    def unescape(m: "re.Match[str]") -> str:
        return chr(int(m.group(1), 16))

    return re.sub(r"%([0-9A-Fa-f]{2})", unescape, enc)


def _parse_kv(line: str) -> dict:
    out = {}
    for token in line.split():
        if "=" in token:
            k, v = token.split("=", 1)
            out[k] = v
        else:
            out[token] = ""
    return out


def build_request(args: str = "", wait: bool = False, timeout_ms: int = 600000,
                  caller_session: bool = False, verb: str = "RUN") -> bytes:
    """构造一行请求（供测试直接断言协议字节）。"""
    parts = [PROTOCOL_VERSION, verb]
    if verb == "RUN":
        parts.append("args=" + _encode_value(args))
        parts.append("wait=" + ("1" if wait else "0"))
        parts.append(f"timeout_ms={int(timeout_ms)}")
        if caller_session:
            parts.append("session=caller")
    return (" ".join(parts) + "\r\n").encode("utf-8")


def parse_response(text: str) -> RunResult:
    """解析一行响应；错误响应抛 PrivSvcError。"""
    text = text.strip("\r\n").strip()
    if not text:
        raise PrivSvcError("INTERNAL", "服务没有返回任何内容")
    if text.startswith("ERR "):
        rest = text[4:]
        code, _, msg = rest.partition(" ")
        raise PrivSvcError(code or "INTERNAL", msg or "(无说明)")
    if not text.startswith("OK"):
        raise PrivSvcError("BAD_PROTOCOL", f"无法识别的响应: {text[:120]}")
    kv = _parse_kv(text[2:].strip())
    result = RunResult(pid=int(kv.get("pid", "0") or 0))
    if "log" in kv:
        result.log_path = _decode_value(kv["log"])
    if "exit" in kv:
        if kv["exit"] == "timeout":
            result.timed_out = True
        else:
            try:
                result.exit_code = int(kv["exit"])
            except ValueError:
                pass
    if "note" in kv:
        result.note = _decode_value(kv["note"])
    return result


def _send(request: bytes, timeout_ms: int) -> str:
    """
    连接命名管道并收发一行。Windows 上用普通文件 IO 打开 \\\\.\\pipe\\... 即可；
    服务端是 MESSAGE 模式，单次 WriteFile 即一条消息。
    """
    if os.name != "nt":
        raise PrivSvcError("INTERNAL", "特权服务只在 Windows 上可用")
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    GENERIC_READ, GENERIC_WRITE = 0x80000000, 0x40000000
    OPEN_EXISTING = 3
    INVALID = wintypes.HANDLE(-1).value

    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                     wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD,
                                     wintypes.HANDLE]
    handle = kernel32.CreateFileW(PIPE_NAME, GENERIC_READ | GENERIC_WRITE, 0, None,
                                  OPEN_EXISTING, 0, None)
    if handle == INVALID:
        err = ctypes.get_last_error()
        if err in (2, 231):   # 文件不存在 / 管道忙
            raise PrivSvcError(
                "INTERNAL",
                "连不上特权服务（管道不存在）。请先以管理员安装并启动："
                "service\\bin\\AvEnginePrivSvc.exe --install")
        if err == 5:
            raise PrivSvcError("CALLER_NOT_ADMIN",
                               "连接被拒绝（错误 5）：管道只允许管理员，请以管理员身份运行")
        raise PrivSvcError("INTERNAL", f"CreateFileW 失败（错误 {err}）")

    try:
        written = wintypes.DWORD(0)
        if not kernel32.WriteFile(handle, request, len(request), ctypes.byref(written), None):
            raise PrivSvcError("INTERNAL", f"写入管道失败（错误 {ctypes.get_last_error()}）")
        # wait=true 时服务端会阻塞到子进程结束，所以读超时按请求超时给足
        kernel32.SetNamedPipeHandleState(handle, ctypes.byref(wintypes.DWORD(0)), None, None)
        buf = ctypes.create_string_buffer(8192)
        read = wintypes.DWORD(0)
        if not kernel32.ReadFile(handle, buf, 8191, ctypes.byref(read), None):
            raise PrivSvcError("INTERNAL", f"读取管道失败（错误 {ctypes.get_last_error()}）")
        return buf.raw[: read.value].decode("utf-8", errors="replace")
    finally:
        kernel32.CloseHandle(handle)


def ping(timeout_ms: int = 10000) -> str:
    """探活 + 顺带确认自己是否满足授权门槛（不满足会抛 PrivSvcError）。"""
    return _send(build_request(verb="PING"), timeout_ms)


def run_system(args: str, wait: bool = True, timeout_ms: int = 600000,
               caller_session: bool = False) -> RunResult:
    """
    请求服务以 SYSTEM 令牌运行 `avengine.exe <args>`。
    返回子进程 pid/退出码/输出日志路径；失败抛 PrivSvcError。
    """
    request = build_request(args=args, wait=wait, timeout_ms=timeout_ms,
                            caller_session=caller_session)
    return parse_response(_send(request, timeout_ms + 30000))


def is_service_installed() -> bool:
    """服务是否已注册（只读查询，不需要管理员）。"""
    if os.name != "nt":
        return False
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SYSTEM\CurrentControlSet\Services\AvEnginePrivSvc"):
            return True
    except OSError:
        return False


def service_dir_hint() -> Path:
    """
    服务可执行文件的预期位置。两种布局都要认：
      * 发布包：<root>\\service\\AvEnginePrivSvc.exe      （build.bat 的拷贝目标）
      * 源码树：<root>\\service\\bin\\AvEnginePrivSvc.exe  （build_service.bat 的输出）
    """
    root = Path(__file__).resolve().parent.parent
    release_layout = root / "service" / SERVICE_EXE
    source_layout = root / "service" / "bin" / SERVICE_EXE
    for cand in (release_layout, source_layout):
        if cand.is_file():
            return cand
    return release_layout


def service_candidates() -> list:
    """所有可能位置（找不到时用来提示用户）。"""
    root = Path(__file__).resolve().parent.parent
    return [root / "service" / SERVICE_EXE, root / "service" / "bin" / SERVICE_EXE]


def ensure_started(timeout_s: float = 10.0) -> bool:
    """
    服务按需启动：先探活，连不上就尝试 `net start`（需要管理员），再探活。
    返回是否可用；不抛异常（调用方自己决定怎么提示）。
    """
    try:
        ping()
        return True
    except PrivSvcError:
        pass
    if not is_service_installed():
        return False
    import subprocess
    try:
        subprocess.run(["sc", "start", "AvEnginePrivSvc"], capture_output=True, text=True)
    except OSError:
        return False
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            ping()
            return True
        except PrivSvcError:
            time.sleep(0.3)
    return False
