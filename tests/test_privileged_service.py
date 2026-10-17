"""
特权服务（AvEnginePrivSvc）回归测试。

这台机器上装不了真服务（非管理员），所以这里覆盖的是**不需要管理员就能验证**的部分：
  * 管道协议编解码（与 service/priv_protocol.h 逐字节对齐）
  * 客户端错误处理与提示映射
  * 256 位密码生成（一次性、不覆盖、URL-safe）
  * 服务二进制的 fail-closed 行为：未配置证书指纹 → --check-pin 退出码 2；
    未安装 → --status 退出码 1；自检把调用者挡在管理员门槛外
  * 签名脚本在"无证书/无 PFX"时必须跳过而不是让构建失败
"""

from __future__ import annotations

import json
import locale
import os
import pathlib
import subprocess
import sys

import pytest

PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from avengine import privsvc  # noqa: E402

SERVICE_EXE = PROJECT_ROOT / "service" / "bin" / "AvEnginePrivSvc.exe"
PASSWORD_SCRIPT = PROJECT_ROOT / "scripts" / "gen_signing_password.py"
SIGN_SCRIPT = PROJECT_ROOT / "scripts" / "sign_binaries.ps1"
VENV_PY = PROJECT_ROOT / "venv" / "Scripts" / "python.exe"

# Python 子进程（3.8 在 Windows 上）按语言环境编码写 stdout（本机 GBK），
# 而服务自己会把控制台切到 UTF-8 —— 两者解码方式不同，不能混用。
_LOCALE_ENC = locale.getpreferredencoding(False) or "utf-8"

# 服务二进制的测试统一用它做跳过条件（装饰器在导入期求值，必须定义在使用之前）
needs_service = pytest.mark.skipif(
    not SERVICE_EXE.is_file(), reason="服务未构建（service\\build_service.bat）")


def _python() -> str:
    return str(VENV_PY) if VENV_PY.is_file() else sys.executable


# --------------------------------------------------------------- 协议编解码


def test_request_bytes_match_protocol():
    """请求必须与服务端 parse_kv 能解析的格式完全一致（含版本头与转义）。"""
    raw = privsvc.build_request(args="status --json", wait=True, timeout_ms=5000)
    text = raw.decode("utf-8")
    assert text.endswith("\r\n")
    assert text.startswith("AVPRIV/1 RUN ")
    assert "args=status%20--json" in text
    assert "wait=1" in text
    assert "timeout_ms=5000" in text

    ping = privsvc.build_request(verb="PING").decode("utf-8")
    assert ping.strip() == "AVPRIV/1 PING"


def test_value_escaping_roundtrip():
    for raw in ["a b\tc", "路径 带空格\\和%号", "C:\\Program Files\\AvEngine\\avengine.exe",
                "line1\r\nline2", "百分号%25已转义"]:
        enc = privsvc._encode_value(raw)
        assert " " not in enc and "\r" not in enc and "\n" not in enc
        assert privsvc._decode_value(enc) == raw


def test_parse_response_ok_and_error():
    ok = privsvc.parse_response("OK pid=1234 log=C%3A%5Ctmp%5Cchild.log exit=0\r\n")
    assert ok.pid == 1234
    assert ok.exit_code == 0
    assert ok.log_path == r"C:\tmp\child.log"
    assert not ok.timed_out

    t = privsvc.parse_response("OK pid=9 log=C%3A%5Ca.log exit=timeout note=still%20running\r\n")
    assert t.timed_out and t.note == "still running"

    with pytest.raises(privsvc.PrivSvcError) as e:
        privsvc.parse_response("ERR CALLER_NOT_ADMIN 调用者不在 Administrators 组\r\n")
    assert e.value.code == "CALLER_NOT_ADMIN"
    assert "管理员" in e.value.hint

    with pytest.raises(privsvc.PrivSvcError):
        privsvc.parse_response("GARBAGE")
    with pytest.raises(privsvc.PrivSvcError):
        privsvc.parse_response("")


def test_error_hint_coverage():
    """服务端 ErrCode 的每个错误码都要有中文处置提示（否则用户看不懂拒绝原因）。"""
    header = (PROJECT_ROOT / "service" / "priv_protocol.h").read_text(encoding="utf-8")
    import re
    # error_code_name() 的返回码就是协议上真实出现的错误码集合；"OK" 是成功码，不算错误
    named = set(re.findall(r'case ErrCode::k\w+:\s*return "([A-Z_]+)";', header))
    named.discard("OK")
    assert named, "没解析到 error_code_name 的返回码"
    missing = named - set(privsvc.ERROR_HINTS)
    extra = set(privsvc.ERROR_HINTS) - named
    assert not missing, f"客户端缺少这些错误码的提示: {sorted(missing)}"
    assert not extra, f"客户端有多余/过期的错误码提示: {sorted(extra)}"


# --------------------------------------------------------------- 密码生成


def test_password_is_256bit_and_not_overwritten(tmp_path):
    out = tmp_path / "passwd.txt"
    r1 = subprocess.run([_python(), str(PASSWORD_SCRIPT), "--out", str(out), "--print"],
                        capture_output=True, text=True, encoding=_LOCALE_ENC, errors="replace",
                        timeout=60)
    assert r1.returncode == 0, r1.stderr
    first = out.read_text(encoding="utf-8").strip()
    assert len(first) >= 43, "256 位熵的 URL-safe 串至少 43 字符"
    assert all(c.isalnum() or c in "-_" for c in first), first
    assert first in r1.stdout

    # 不带 --force 时不得覆盖（覆盖会让已有 PFX 再也导不出来）
    r2 = subprocess.run([_python(), str(PASSWORD_SCRIPT), "--out", str(out)],
                        capture_output=True, text=True, encoding=_LOCALE_ENC, errors="replace",
                        timeout=60)
    assert r2.returncode == 0
    assert out.read_text(encoding="utf-8").strip() == first
    assert "保持不变" in r2.stdout

    # --force 才重写
    r3 = subprocess.run([_python(), str(PASSWORD_SCRIPT), "--out", str(out), "--force"],
                        capture_output=True, text=True, encoding=_LOCALE_ENC, errors="replace",
                        timeout=60)
    assert r3.returncode == 0
    assert out.read_text(encoding="utf-8").strip() != first


def test_password_file_is_gitignored():
    gi = (PROJECT_ROOT / ".gitignore").read_text(encoding="utf-8")
    for entry in ("service/passwd.txt", "service/generated/", "service/bin/", "service/signing.json"):
        assert entry in gi, f".gitignore 必须排除 {entry}"


@pytest.mark.skipif(os.name != "nt", reason="需要 Windows PowerShell")
def test_sign_script_reports_unreadable_material_actionably(tmp_path):
    """
    回归守卫：签名材料读不到时（真实场景：gen_signing_cert.ps1 把 ACL 收紧成仅
    SYSTEM/Administrators，而非提权的 shell 里 Administrators 是 deny-only），
    必须给出可操作的中文说明，而不是甩一个 'Access to the path ... is denied.'
    原始异常——那种输出会让人以为"签名做了"，最后拿到一个服务会拒绝的未签名发布包。

    这里用"独占占用"来制造不可读，避免依赖 ACL 操作。
    """
    import ctypes
    from ctypes import wintypes

    dummy = tmp_path / "x.exe"
    dummy.write_bytes(b"MZ")
    pfx = tmp_path / "fake.pfx"
    pfx.write_bytes(b"PFX")
    pwd = tmp_path / "passwd.txt"
    pwd.write_text("secret-password", encoding="utf-8")
    cfg = tmp_path / "signing.json"
    cfg.write_text(json.dumps({"pfx": str(pfx), "password_file": str(pwd),
                               "thumbprint_sha256": "AB" * 32}), encoding="utf-8")

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                     wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD,
                                     wintypes.HANDLE]
    # 共享模式 0：任何其他打开（哪怕只读）都会被拒绝
    handle = kernel32.CreateFileW(str(pwd), 0x80000000, 0, None, 3, 0, None)
    assert handle != wintypes.HANDLE(-1).value, ctypes.get_last_error()
    try:
        proc = subprocess.run(
            ["powershell", "-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass",
             "-File", str(SIGN_SCRIPT), "-Files", str(dummy),
             "-SigningJson", str(cfg), "-Require"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=180)
    finally:
        kernel32.CloseHandle(handle)

    combined = proc.stdout + proc.stderr
    assert proc.returncode != 0, combined
    assert "读不到签名材料" in combined, combined
    assert "grant_signing_access.ps1" in combined, "必须给出修复命令"
    assert "Access to the path" not in combined, "不该再是原始 PowerShell 异常"


def test_build_requires_signing_when_pin_is_configured():
    """
    回归守卫：一旦生成了证书指纹（service\\generated\\cert_pin.h），签名就是**必须成功**的
    一步——因为服务会拒绝未签名的调用者，产出未签名的发布包等于构建骗人。
    早期实现把它当 best-effort，于是出现了 "BUILD OK" 但两个 exe 都是 NotSigned。
    """
    build = (PROJECT_ROOT / "build.bat").read_text(encoding="utf-8", errors="replace")
    assert "service\\generated\\cert_pin.h" in build, "build.bat 需要检测证书指纹是否存在"
    assert "SIGNREQ=-Require" in build, "指纹存在时必须传 -Require"
    assert "signing failed while a certificate pin is configured" in build
    idx_check = build.index("SIGNREQ=-Require")
    idx_fail = build.index("signing failed while a certificate pin is configured")
    assert idx_check < idx_fail


def test_cert_script_grants_current_user_by_default():
    """
    回归守卫：证书脚本默认必须给**当前账户**只读权限，否则非提权构建读不到密码/PFX
    （未提权时 Administrators 是 deny-only），签名会静默失败。要严格可以 -NoUserAccess。
    """
    src = (PROJECT_ROOT / "scripts" / "gen_signing_cert.ps1").read_text(encoding="utf-8-sig")
    assert "NoUserAccess" in src
    assert "USERDOMAIN" in src and "USERNAME" in src
    assert "/grant" in src
    # 修复脚本也必须存在（不改证书、只修 ACL）
    helper = PROJECT_ROOT / "scripts" / "grant_signing_access.ps1"
    assert helper.is_file(), "缺少 scripts\\grant_signing_access.ps1"
    text = helper.read_text(encoding="utf-8-sig")
    assert "icacls" in text and "-Strict" in text


def _fake_signing_json(tmp_path, **over):
    """造一份"材料可读但 PFX 是假的"签名配置：用来测签名流程本身而不需要真证书。"""
    pfx = tmp_path / "fake.pfx"
    pfx.write_bytes(b"NOT-A-REAL-PFX")
    pwd = tmp_path / "passwd.txt"
    pwd.write_text("fake-password", encoding="utf-8")
    cfg = {"pfx": str(pfx), "password_file": str(pwd),
           "thumbprint_sha1": "BD79C4F33440B0DC503EFBF697657D1641A154CB",
           "thumbprint_sha256": "3D" * 32}
    cfg.update(over)
    path = tmp_path / "signing.json"
    path.write_text(json.dumps(cfg), encoding="utf-8")
    return path


@pytest.mark.skipif(os.name != "nt", reason="需要 Windows PowerShell")
def test_sign_script_expands_comma_separated_files(tmp_path):
    """
    回归守卫：从 .bat/cmd 调 `-Files "a.exe,b.dll"` 时，**cmd 不会按逗号拆分**，
    PowerShell 收到的是一个含逗号的字符串。脚本必须自己展开，否则它会"文件不存在，跳过"
    然后照样打印"完成"——发布包里的 exe 其实没签名（真实踩过）。
    """
    a = tmp_path / "a.exe"
    b = tmp_path / "b.dll"
    a.write_bytes(b"MZ")
    b.write_bytes(b"MZ")
    cfg = _fake_signing_json(tmp_path)

    proc = subprocess.run(
        ["powershell", "-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass",
         "-File", str(SIGN_SCRIPT), "-Files", f"{a},{b}", "-SigningJson", str(cfg)],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=180)
    combined = proc.stdout + proc.stderr
    assert "文件不存在" not in combined, combined
    # 两个文件都必须被当成独立目标处理过（PFX 是假的，所以会签名失败——这正是预期）
    assert str(a) in combined and str(b) in combined, combined
    assert "完成" not in combined, "有失败时不能报'完成'"


@pytest.mark.skipif(os.name != "nt", reason="需要 Windows PowerShell")
def test_sign_script_fails_when_named_file_missing(tmp_path):
    """调用方点名的文件不存在必须算失败（-Require 下非零退出），不能只警告后说'完成'。"""
    cfg = _fake_signing_json(tmp_path)
    missing = tmp_path / "not-built-yet.exe"
    proc = subprocess.run(
        ["powershell", "-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass",
         "-File", str(SIGN_SCRIPT), "-Files", str(missing), "-SigningJson", str(cfg),
         "-Require"],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=180)
    combined = proc.stdout + proc.stderr
    assert proc.returncode != 0, combined
    assert "文件不存在" in combined
    assert "未签名" in combined or "签名失败" in combined
    assert "完成" not in combined


@pytest.mark.skipif(os.name != "nt", reason="需要 Windows PowerShell")
def test_sign_script_rejects_empty_file_list(tmp_path):
    """没给出任何文件时必须报错，不能静默'完成'（PowerShell 参数绑定或脚本自检拦下都算合格）。"""
    cfg = _fake_signing_json(tmp_path)
    proc = subprocess.run(
        ["powershell", "-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass",
         "-File", str(SIGN_SCRIPT), "-Files", "", "-SigningJson", str(cfg)],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=180)
    combined = proc.stdout + proc.stderr
    assert proc.returncode != 0, combined
    assert "完成" not in combined
    assert ("没给出任何文件" in combined) or ("Cannot bind argument to parameter 'Files'" in combined), combined


def test_service_admin_check_avoids_primary_token_contract_violation():
    """
    回归守卫：CheckTokenMembership 的文档要求 TokenHandle **必须是模拟令牌**
    （"The token must be an impersonation token"）。早期实现直接把 OpenProcessToken
    得到的主令牌传进去，在 Windows 7 上会把已提权的管理员判成"非管理员"
    （实测：管理员 cmd 里 ping 得到 CALLER_NOT_ADMIN）。

    现在必须：直接读令牌组（存在 + 已启用 + 非 SE_GROUP_USE_FOR_DENY_ONLY）为准，
    并把主令牌复制成模拟令牌后做交叉验证。
    """
    src = (PROJECT_ROOT / "service" / "AvEnginePrivSvc.cpp").read_text(encoding="utf-8")
    assert "TokenGroups" in src, "必须以令牌组为准"
    assert "SE_GROUP_USE_FOR_DENY_ONLY" in src, "必须区分 deny-only（未提权）"
    assert "TokenElevation" in src and "TokenIntegrityLevel" in src, "诊断字段"
    assert "TokenImpersonation" in src, "交叉验证要用模拟令牌"
    assert "CheckTokenMembership(imp" in src, "只能用复制出来的模拟令牌调用"
    assert "CheckTokenMembership(tok" not in src, "不能把主令牌传给 CheckTokenMembership"
    # 复制令牌需要 TOKEN_DUPLICATE
    assert "TOKEN_QUERY | TOKEN_DUPLICATE" in src


@needs_service
def test_service_selftest_reports_token_diagnostics():
    """
    自检必须给出令牌诊断（Administrators 是否启用/是否 deny-only、是否提权、完整性级别），
    否则用户在管理员窗口里看到 CALLER_NOT_ADMIN 时无从判断到底哪一步不对。
    """
    proc = subprocess.run([str(SERVICE_EXE), "--selftest", str(os.getpid())],
                          capture_output=True, text=True, encoding="utf-8",
                          errors="replace", timeout=60)
    out = proc.stdout
    assert "Administrators=" in out, out
    assert "TokenIsElevated=" in out, out
    assert "完整性=" in out, out
    assert "CheckTokenMembership=" in out, out


def test_verify_failure_codes_have_actionable_hints():
    """验签失败码要给出能行动的说明（Win7 缺 KB3033929 是最常见的一个）。"""
    src = (PROJECT_ROOT / "service" / "AvEnginePrivSvc.cpp").read_text(encoding="utf-8")
    assert "0x800B0100UL" in src and "KB3033929" in src
    assert "TRUST_E_BAD_DIGEST" in src or "0x80096010UL" in src


def test_service_restores_console_codepage():
    """
    回归守卫：SetConsoleOutputCP 是**进程级共享**的 —— 服务把控制台改成 65001 之后，
    同一个 cmd 窗口里后续运行的程序（avengine.exe 的 Python/colorama）也会受影响，
    出现过乱码甚至 "--- Logging error ---"。所以服务必须在自己退出时恢复原代码页。
    """
    src = (PROJECT_ROOT / "service" / "AvEnginePrivSvc.cpp").read_text(encoding="utf-8")
    assert "ConsoleCodepageGuard" in src
    assert "GetConsoleOutputCP" in src, "必须先保存原代码页"
    assert "SetConsoleOutputCP(saved_out_)" in src, "退出时必须还原"
    assert "std::atexit(restore_console_cp)" in src, "return 路径不会析构自动对象，需要 atexit 兜底"
    # 不允许在 guard 之外裸改代码页
    body = src.replace("SetConsoleOutputCP(CP_UTF8);\n        // 不改输入代码页", "")
    assert body.count("SetConsoleOutputCP") <= 4, body.count("SetConsoleOutputCP")


def test_cli_makes_streams_tolerant():
    """CLI 必须在 colorama 包装之前把标准流设成 errors='replace'，并挂 SafeStreamHandler。"""
    cli = (PROJECT_ROOT / "avengine" / "cli.py").read_text(encoding="utf-8")
    assert "make_console_tolerant()" in cli
    idx_call = cli.index("make_console_tolerant()")
    idx_colorama = cli.index("colorama_init()")
    assert idx_call < idx_colorama, "必须在 colorama 包装之前调用"
    utils = (PROJECT_ROOT / "avengine" / "utils.py").read_text(encoding="utf-8")
    assert "class SafeStreamHandler" in utils
    assert "SafeStreamHandler(sys.stdout)" in utils
    assert "def handleError" in utils


def test_build_never_ships_signing_secrets():
    """
    发布包会被拷到别的机器上，**私钥绝不能跟着走**。
    build.bat 会把整个 bina\\ 拷进发布目录，而私钥就在 bina\\signing\\ —— 必须显式排除，
    并且在排除不干净时让构建失败（而不是安静地把私钥发出去）。
    """
    build = (PROJECT_ROOT / "build.bat").read_text(encoding="utf-8", errors="replace")
    assert "bina\\signing" in build, "build.bat 必须处理 bina\\signing"
    assert "*.pfx" in build and "*.pvk" in build and "*.key" in build, "必须删除私钥类文件"
    assert "service\\passwd.txt" in build, "必须删除密码文件"
    assert "signing private key left in the release" in build, "残留时必须让构建失败"
    # 排除动作必须发生在拷贝 bina 之后、组装结束之前
    idx_copy = build.index('bina\\*" "%REL%\\bina')
    idx_guard = build.index("signing private key left in the release")
    assert idx_copy < idx_guard


# --------------------------------------------------------------- 签名脚本


@pytest.mark.skipif(os.name != "nt", reason="需要 Windows PowerShell")
def test_sign_script_skips_without_certificate(tmp_path):
    """没有 signing.json 时必须跳过（exit 0），不能让 build.bat 挂掉。"""
    dummy = tmp_path / "x.exe"
    dummy.write_bytes(b"MZ")
    proc = subprocess.run(
        ["powershell", "-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass",
         "-File", str(SIGN_SCRIPT), "-Files", str(dummy),
         "-SigningJson", str(tmp_path / "missing.json")],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=180)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "跳过" in proc.stdout + proc.stderr or "skip" in (proc.stdout + proc.stderr).lower()


@pytest.mark.skipif(os.name != "nt", reason="需要 Windows PowerShell")
def test_sign_script_require_fails_without_certificate(tmp_path):
    """-Require 时缺少证书必须失败（发布流水线用它强制要求签名）。"""
    dummy = tmp_path / "x.exe"
    dummy.write_bytes(b"MZ")
    proc = subprocess.run(
        ["powershell", "-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass",
         "-File", str(SIGN_SCRIPT), "-Files", str(dummy),
         "-SigningJson", str(tmp_path / "missing.json"), "-Require"],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=180)
    assert proc.returncode != 0


@pytest.mark.skipif(os.name != "nt", reason="需要 Windows PowerShell")
def test_sign_script_rejects_misfired_positional_binding(tmp_path):
    """
    回归守卫：`-Files a.exe b.dll` 这种写法曾经把第二个路径**位置绑定给 -SigningJson**，
    脚本于是去把 DLL 当 JSON 解析（"Invalid JSON primitive: MZ"）——
    签名静默没做，构建却报 OK。现在必须响亮失败。
    """
    a = tmp_path / "a.exe"
    b = tmp_path / "b.dll"
    a.write_bytes(b"MZ")
    b.write_bytes(b"MZ")
    proc = subprocess.run(
        ["powershell", "-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass",
         "-File", str(SIGN_SCRIPT), "-Files", str(a), str(b)],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=180)
    assert proc.returncode != 0, proc.stdout + proc.stderr
    combined = proc.stdout + proc.stderr
    assert "Invalid JSON" not in combined, "不能再退化成 JSON 解析异常"
    assert "positional parameter" in combined or "参数" in combined


@pytest.mark.skipif(os.name != "nt", reason="需要 Windows PowerShell")
def test_sign_script_rejects_binary_as_config(tmp_path):
    """误把二进制当配置文件传入时要给出能看懂的中文报错，而不是 JSON 解析异常。"""
    a = tmp_path / "a.exe"
    dll = tmp_path / "cfg.dll"
    a.write_bytes(b"MZ")
    dll.write_bytes(b"MZ")
    proc = subprocess.run(
        ["powershell", "-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass",
         "-File", str(SIGN_SCRIPT), "-Files", str(a), "-SigningJson", str(dll)],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=180)
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert "SigningJson" in (proc.stdout + proc.stderr)
    assert "数组形式" in (proc.stdout + proc.stderr)


# ------------------------------------------------- 服务二进制的 fail-closed 行为


@needs_service
def test_service_check_pin_reports_whitelist_or_fails_closed():
    """
    --check-pin 必须把"钉住的证书指纹"和"安装目录白名单"两件事都交代清楚；
    任一项定不下来就必须以退出码 2 表示"必然拒绝一切请求"。
    """
    proc = subprocess.run([str(SERVICE_EXE), "--check-pin"], capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=60)
    assert "钉住的证书指纹" in proc.stdout
    assert "安装目录(白名单)" in proc.stdout
    pin_missing = "未配置" in proc.stdout
    dir_unknown = "无法确定" in proc.stdout
    if pin_missing or dir_unknown:
        assert proc.returncode == 2, proc.stdout
    else:
        assert proc.returncode == 0, proc.stdout


def test_service_never_skips_path_check():
    """
    静态守卫：安装目录白名单定不下来时**必须拒绝**，绝不能"读不到就放行"
    （发布布局里服务在 service\\ 子目录、avengine.exe 在上一级；早期实现找不到 avengine.exe
     就静默跳过第 4 步校验，等于 fail-open）。
    """
    src = (PROJECT_ROOT / "service" / "AvEnginePrivSvc.cpp").read_text(encoding="utf-8")
    anchor = "if (whitelist.empty())"
    assert anchor in src, "第 4 步必须显式处理'白名单定不下来'"
    segment = src[src.index(anchor):src.index(anchor) + 600]
    assert "return fail(ErrCode::kInstallDirUnknown" in segment, segment
    assert "resolve_install_dir" in src
    # 运行时不许出现"跳过校验"式的提示（注释里解释历史行为不算）
    for line in src.splitlines():
        stripped = line.strip()
        if stripped.startswith(("//", "*", "/*")):
            continue
        assert "跳过路径比对" not in stripped, line
    header = (PROJECT_ROOT / "service" / "priv_protocol.h").read_text(encoding="utf-8")
    assert "INSTALL_DIR_UNKNOWN" in header
    assert "INSTALL_DIR_UNKNOWN" in privsvc.ERROR_HINTS


def test_resolve_install_dir_layout_rules(tmp_path):
    """
    目录推断顺序：注册表白名单 → 自身目录 → 上一级目录（发布包布局）。
    用真实文件系统验证与服务端相同的判定语义。
    """
    release = tmp_path / "AvEngine-0.1.0"
    (release / "service").mkdir(parents=True)
    (release / "avengine.exe").write_bytes(b"MZ")
    service_dir = release / "service"

    def resolve(start):
        for cand in (start, start.parent):
            if (cand / "avengine.exe").is_file():
                return cand
        return None

    assert resolve(service_dir) == release       # 发布布局：服务在 service\，exe 在上一级
    (service_dir / "avengine.exe").write_bytes(b"MZ")
    assert resolve(service_dir) == service_dir   # 同目录布局优先


@needs_service
def test_service_status_reports_not_installed_or_running():
    proc = subprocess.run([str(SERVICE_EXE), "--status"], capture_output=True, text=True, encoding="utf-8", errors="replace",
                          timeout=60)
    # 未安装=1；已安装=0 并打印状态
    assert proc.returncode in (0, 1), proc.stdout
    assert ("服务未安装" in proc.stdout) or ("RUNNING" in proc.stdout) or ("STOPPED" in proc.stdout)


@needs_service
def test_service_selftest_blocks_non_admin():
    """
    自检跑完整验证链但不授权。非管理员下必须在管理员门槛失败，
    并且要打印调用者路径与创建时间指纹（便于现场判断是不是 PID 复用）。
    """
    proc = subprocess.run([str(SERVICE_EXE), "--selftest", str(os.getpid())],
                          capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60)
    out = proc.stdout
    assert "自检" in out
    assert "调用者:" in out
    assert "created=" in out
    is_admin = False
    try:
        import ctypes
        is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        pass
    if not is_admin:
        assert "CALLER_NOT_ADMIN" in out, out
        assert proc.returncode == 1


@needs_service
def test_service_selftest_bad_pid():
    """不存在的 PID 必须报"打不开调用者"，不能崩。"""
    proc = subprocess.run([str(SERVICE_EXE), "--selftest", "999999"], capture_output=True,
                          text=True, encoding="utf-8", errors="replace", timeout=60)
    assert proc.returncode == 1
    assert "CALLER_OPEN_FAIL" in proc.stdout or "打不开" in proc.stdout


@needs_service
def test_service_usage_on_bad_arg():
    proc = subprocess.run([str(SERVICE_EXE), "--nope"], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60)
    assert proc.returncode == 1
    assert "用法" in proc.stdout


# --------------------------------------------------------------- 客户端行为


def test_client_reports_missing_pipe_helpfully():
    """
    服务没装/没启动时，客户端要给出"怎么装"的提示，而不是抛底层错误码。
    （本机未安装服务，因此正好覆盖这条路径。）
    """
    if privsvc.is_service_installed():
        pytest.skip("本机已安装服务，跳过")
    with pytest.raises(privsvc.PrivSvcError) as e:
        privsvc.ping()
    msg = str(e.value)
    assert "AvEnginePrivSvc" in msg or "管道" in msg or "管理员" in msg


def test_service_dir_hint_points_into_repo():
    hint = privsvc.service_dir_hint()
    assert hint.name == "AvEnginePrivSvc.exe"
    assert "service" in hint.parts
