// AvEnginePrivSvc.cpp - AvEngine 特权服务（LocalSystem）
//
// 目的：AvEngine 需要 SYSTEM 权限才能做的取证/处置（读 Security 日志、枚举系统句柄表、
// 驱动信息、防火墙规则……）由本服务代为执行——服务**用 SYSTEM 令牌创建一个 avengine.exe
// 子进程**并把子进程 pid / 退出码 / 输出日志路径回给调用者。服务自身不把 SYSTEM 令牌交给
// 任何进程，也不替换运行中进程的令牌（那样会破坏目标进程状态）。
//
// 安全模型（fail-closed，五步全过才授权）：
//   1) 管道 ACL 只允许 SYSTEM/Administrators 连接（客户端必须已是管理员才是第一道门）
//   2) 取管道客户端 PID + 进程创建时间（身份指纹，防 PID 复用）
//   3) 调用者令牌必须属于 Administrators
//   4) 调用者映像的**规范化路径**必须等于安装目录下的 avengine.exe（拒绝"把签名二进制
//      复制到别处再申请"这种绕过）
//   5) Authenticode 验签 + 证书 SHA-256 指纹与编译期钉住值精确比对（不信任根存储）
// 任何一步失败都拒绝并写审计日志（%ProgramData%\AvEngine\privsvc\privsvc.log）。
//
// 子命令：
//   --install [--auto]   安装为 LocalSystem 服务（默认按需启动）；同时写 InstallDir
//   --uninstall          停止并删除服务
//   --console            前台运行管道服务（调试用，需管理员）
//   --selftest <pid>     只跑验证链并逐项打印结论，不授权、不创建进程（需管理员才有意义）
//   --check-pin          打印当前钉住的证书指纹/安装目录/服务状态（无需管理员）
//   --status             打印服务状态
#include "cert_pin.h"
#include "priv_protocol.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <sddl.h>
#include <softpub.h>
#include <userenv.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <wtsapi32.h>

#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using namespace avpriv;

namespace {

constexpr wchar_t kServiceName[] = L"AvEnginePrivSvc";
constexpr wchar_t kServiceDisplay[] = L"AvEngine Privileged Helper";
constexpr wchar_t kServiceDesc[] =
    L"AvEngine 特权助手：校验调用者签名后，以 SYSTEM 令牌启动 avengine.exe 子进程。";
constexpr wchar_t kInstallDirValue[] = L"InstallDir";
constexpr wchar_t kRegPath[] = L"SOFTWARE\\AvEngine";

SERVICE_STATUS_HANDLE g_status_handle = nullptr;
SERVICE_STATUS g_status{};
HANDLE g_stop_event = nullptr;
volatile LONG g_active_connections = 0;
constexpr LONG kMaxConnections = 4;

// ---------------- 小工具 ----------------

std::wstring utf8_to_wide(const std::string& s) {
    if (s.empty()) return std::wstring();
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring w(static_cast<size_t>(n) + 1, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), &w[0], n);
    w.resize(static_cast<size_t>(n));
    return w;
}

std::string wide_to_utf8(const std::wstring& w) {
    if (w.empty()) return std::string();
    const int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), nullptr, 0,
                                      nullptr, nullptr);
    std::string s(static_cast<size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), &s[0], n, nullptr,
                        nullptr);
    return s;
}

std::wstring to_lower(std::wstring s) {
    for (wchar_t& c : s) c = static_cast<wchar_t>(towlower(c));
    return s;
}

std::wstring exe_dir() {
    wchar_t buf[MAX_PATH * 2]{};
    const DWORD n = GetModuleFileNameW(nullptr, buf, MAX_PATH * 2);
    std::wstring p(buf, n);
    const size_t pos = p.find_last_of(L"\\/");
    return pos == std::wstring::npos ? p : p.substr(0, pos);
}

// 日志/子进程输出目录：%ProgramData%\AvEngine\privsvc
std::wstring log_dir() {
    wchar_t buf[MAX_PATH * 2]{};
    DWORD n = GetEnvironmentVariableW(L"ProgramData", buf, MAX_PATH * 2);
    std::wstring root = (n > 0 && n < MAX_PATH * 2) ? std::wstring(buf, n) : L"C:\\ProgramData";
    std::wstring dir = root + L"\\AvEngine\\privsvc";
    CreateDirectoryW((root + L"\\AvEngine").c_str(), nullptr);
    CreateDirectoryW(dir.c_str(), nullptr);
    return dir;
}

void audit(const char* fmt, ...) {
    // 审计必须尽量不失败：服务是 SYSTEM，目录由本服务创建
    std::string line;
    SYSTEMTIME st{};
    GetLocalTime(&st);
    char ts[40];
    std::snprintf(ts, sizeof(ts), "%04d-%02d-%02d %02d:%02d:%02d", st.wYear, st.wMonth, st.wDay,
                  st.wHour, st.wMinute, st.wSecond);
    line += ts;
    line += " | ";

    char body[2048];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(body, sizeof(body), fmt, ap);
    va_end(ap);
    line += body;
    line += "\r\n";

    const std::wstring path = log_dir() + L"\\privsvc.log";
    HANDLE h = CreateFileW(path.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ, nullptr, OPEN_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        WriteFile(h, line.data(), static_cast<DWORD>(line.size()), &written, nullptr);
        CloseHandle(h);
    }
    OutputDebugStringA(("[AvEnginePrivSvc] " + line).c_str());
}

// 规范化路径（解析符号链接/联接点），失败返回空串
std::wstring canonical_path(const std::wstring& path) {
    HANDLE h = CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                           OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (h == INVALID_HANDLE_VALUE) return std::wstring();
    wchar_t buf[32768]{};
    const DWORD n = GetFinalPathNameByHandleW(h, buf, 32768, FILE_NAME_NORMALIZED);
    CloseHandle(h);
    if (n == 0 || n >= 32768) return std::wstring();
    std::wstring out(buf, n);
    if (out.rfind(L"\\\\?\\", 0) == 0) out = out.substr(4);   // 去掉 \\?\ 前缀
    return out;
}

/*
 * 解析"安装目录白名单"：必须能找到 avengine.exe 的那一层。
 * 顺序：注册表 InstallDir → 服务自身目录 → 上一级目录（发布包布局里
 * AvEnginePrivSvc.exe 在 <release>\service\ 下，而 avengine.exe 在 <release>\ 下）。
 * 都找不到时返回空串 —— 调用方必须**拒绝一切请求**（不能"跳过路径比对"，那是 fail-open）。
 */
std::wstring resolve_install_dir() {
    wchar_t buf[MAX_PATH * 2]{};
    DWORD size = sizeof(buf);
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kRegPath, 0, KEY_READ | KEY_WOW64_64KEY, &key) ==
        ERROR_SUCCESS) {
        DWORD type = 0;
        if (RegQueryValueExW(key, kInstallDirValue, nullptr, &type, reinterpret_cast<LPBYTE>(buf),
                             &size) == ERROR_SUCCESS &&
            type == REG_SZ) {
            std::wstring dir(buf);
            while (!dir.empty() && (dir.back() == L'\\' || dir.back() == L'/')) dir.pop_back();
            if (!dir.empty() &&
                GetFileAttributesW((dir + L"\\avengine.exe").c_str()) != INVALID_FILE_ATTRIBUTES) {
                RegCloseKey(key);
                return dir;
            }
        }
        RegCloseKey(key);
    }

    const std::wstring self = exe_dir();
    if (GetFileAttributesW((self + L"\\avengine.exe").c_str()) != INVALID_FILE_ATTRIBUTES)
        return self;

    const size_t pos = self.find_last_of(L"\\/");
    if (pos != std::wstring::npos && pos > 0) {
        const std::wstring parent = self.substr(0, pos);
        if (GetFileAttributesW((parent + L"\\avengine.exe").c_str()) != INVALID_FILE_ATTRIBUTES)
            return parent;
    }
    return std::wstring();   // 无法确定 → fail-closed
}

std::wstring install_dir() {
    const std::wstring dir = resolve_install_dir();
    return dir.empty() ? exe_dir() : dir;   // 仅供显示；授权判定必须用 resolve_install_dir()
}

bool is_local_system() {
    HANDLE tok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return false;
    bool ok = false;
    DWORD size = 0;
    GetTokenInformation(tok, TokenUser, nullptr, 0, &size);
    if (size > 0) {
        std::vector<unsigned char> buf(size);
        if (GetTokenInformation(tok, TokenUser, buf.data(), size, &size)) {
            auto* user = reinterpret_cast<TOKEN_USER*>(buf.data());
            BYTE local_system[SECURITY_MAX_SID_SIZE]{};
            DWORD sid_size = sizeof(local_system);
            if (CreateWellKnownSid(WinLocalSystemSid, nullptr, local_system, &sid_size))
                ok = EqualSid(user->User.Sid, local_system) != FALSE;
        }
    }
    CloseHandle(tok);
    return ok;
}

bool enable_privilege(const wchar_t* name) {
    HANDLE tok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok))
        return false;
    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    if (!LookupPrivilegeValueW(nullptr, name, &tp.Privileges[0].Luid)) {
        CloseHandle(tok);
        return false;
    }
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    const BOOL ok = AdjustTokenPrivileges(tok, FALSE, &tp, 0, nullptr, nullptr);
    const DWORD err = GetLastError();
    CloseHandle(tok);
    return ok && err == ERROR_SUCCESS;   // AdjustTokenPrivileges 会"成功"但没改任何东西
}

// ---------------- 验证链 ----------------

struct CallerInfo {
    DWORD pid = 0;
    std::wstring path;
    std::wstring canonical;
    unsigned long long created = 0;   // FILETIME：身份指纹
    bool is_admin = false;
    DWORD session = 0xFFFFFFFF;
    std::string user;                 // SID 字符串（UTF-8），仅用于审计
    std::string admin_diag;           // 管理员判定诊断（审计/报错都用它）
};

// 证书指纹（去掉空格、转大写）比较
std::string normalize_thumbprint(const std::string& in) {
    std::string out;
    for (unsigned char c : in) {
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == ':') continue;
        out += static_cast<char>(toupper(c));
    }
    return out;
}

// ---------------- 管理员判定 ----------------
//
// 注意：CheckTokenMembership 的文档要求 TokenHandle **必须是模拟令牌**
// （"The token must be an impersonation token"）。直接传 OpenProcessToken 得到的
// 主令牌是违反契约的 —— 实测在 Windows 7 上会把已提权的管理员判成"非管理员"。
// 所以这里以**直接检查令牌组**为准（存在 + 已启用，且不是 SE_GROUP_USE_FOR_DENY_ONLY），
// 再把主令牌复制成模拟令牌做一次文档要求的交叉验证，并把两者都记进诊断。
struct AdminCheck {
    bool is_admin = false;
    bool sid_present = false;
    bool sid_deny_only = false;
    bool sid_enabled = false;
    bool elevated = false;
    std::string integrity = "unknown";
    bool api_checked = false;
    bool api_member = false;

    std::string summary() const {
        std::string group;
        if (sid_enabled) group = "已启用";
        else if (sid_deny_only) group = "存在但 deny-only（未提权）";
        else if (sid_present) group = "存在但未启用";
        else group = "不存在";
        return "Administrators=" + group + "; TokenIsElevated=" + (elevated ? "1" : "0") +
               "; 完整性=" + integrity + "; CheckTokenMembership=" +
               (api_checked ? (api_member ? "true" : "false") : "n/a");
    }

    // 给用户的处置建议
    std::string hint() const {
        if (!elevated && (integrity == "Medium" || integrity == "Low" || integrity == "unknown"))
            return "这是**未提权**的令牌：请右键 cmd → “以管理员身份运行”后再试";
        if (!sid_present)
            return "该账户不在本机 Administrators 组：需要管理员账户（或把账户加入该组）";
        return "令牌已提权但组属性异常：请把上面的诊断发给开发者";
    }
};

std::string integrity_name(DWORD rid) {
    switch (rid) {
    case 0x0000: return "Untrusted";
    case 0x1000: return "Low";
    case 0x2000: return "Medium";
    case 0x2100: return "MediumPlus";
    case 0x3000: return "High";
    case 0x4000: return "System";
    case 0x5000: return "ProtectedProcess";
    default: {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "0x%lx", static_cast<unsigned long>(rid));
        return buf;
    }
    }
}

AdminCheck check_administrator(HANDLE token, PSID admins_sid) {
    AdminCheck r;

    // 1) 直接读令牌组（不用 CheckTokenMembership 的契约限制）
    DWORD size = 0;
    GetTokenInformation(token, TokenGroups, nullptr, 0, &size);
    if (size > 0) {
        std::vector<unsigned char> buf(size);
        if (GetTokenInformation(token, TokenGroups, buf.data(), size, &size)) {
            auto* groups = reinterpret_cast<TOKEN_GROUPS*>(buf.data());
            for (DWORD i = 0; i < groups->GroupCount; ++i) {
                if (!EqualSid(groups->Groups[i].Sid, admins_sid)) continue;
                r.sid_present = true;
                const DWORD attr = groups->Groups[i].Attributes;
                if (attr & SE_GROUP_USE_FOR_DENY_ONLY)
                    r.sid_deny_only = true;
                else if (attr & SE_GROUP_ENABLED)
                    r.sid_enabled = true;
            }
        }
    }

    // 2) 提权状态与完整性级别（诊断用；Vista+ 都有）
    DWORD value = 0, ret = 0;
    if (GetTokenInformation(token, TokenElevation, &value, sizeof(value), &ret))
        r.elevated = value != 0;
    size = 0;
    GetTokenInformation(token, TokenIntegrityLevel, nullptr, 0, &size);
    if (size > 0) {
        std::vector<unsigned char> buf(size);
        if (GetTokenInformation(token, TokenIntegrityLevel, buf.data(), size, &size)) {
            auto* label = reinterpret_cast<TOKEN_MANDATORY_LABEL*>(buf.data());
            if (label->Label.Sid) {
                const UCHAR count = *GetSidSubAuthorityCount(label->Label.Sid);
                if (count > 0)
                    r.integrity = integrity_name(*GetSidSubAuthority(label->Label.Sid, count - 1));
            }
        }
    }

    // 3) 交叉验证：按文档要求，先复制成**模拟令牌**再调 CheckTokenMembership
    HANDLE imp = nullptr;
    if (DuplicateTokenEx(token, TOKEN_QUERY, nullptr, SecurityImpersonation, TokenImpersonation,
                         &imp)) {
        BOOL member = FALSE;
        if (CheckTokenMembership(imp, admins_sid, &member)) {
            r.api_checked = true;
            r.api_member = member != FALSE;
        }
        CloseHandle(imp);
    }

    // 组属性是事实依据；两者取并集，避免环境差异造成误拒
    r.is_admin = r.sid_enabled || (r.api_checked && r.api_member);
    return r;
}

// Authenticode 验签 + 指纹钉住。
// 自签名证书不在机器根存储里时 WinVerifyTrust 返回 CERT_E_UNTRUSTEDROOT —— 签名本身
// 已经校验通过，只是"根不受信任"。因为我们随后要用**精确指纹**比对，所以这两种结果都接受；
// 其它错误码（签名损坏、摘要不符、证书过期等）一律拒绝。
ErrCode verify_caller_signature(const std::wstring& path, std::string* detail) {
    const std::string pin = normalize_thumbprint(AVPRIV_PINNED_CERT_SHA256);
    if (pin.empty()) {
        *detail = "服务未配置证书指纹（service/generated/cert_pin.h 缺失）→ 拒绝一切请求";
        return ErrCode::kNotConfigured;
    }

    WINTRUST_FILE_INFO file_info{};
    file_info.cbStruct = sizeof(file_info);
    file_info.pcwszFilePath = path.c_str();
    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA data{};
    data.cbStruct = sizeof(data);
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_NONE;
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.dwStateAction = WTD_STATEACTION_VERIFY;
    data.pFile = &file_info;

    const LONG rc = WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &action, &data);
    std::string thumbprint;
    if (rc == 0 || static_cast<unsigned long>(rc) == 0x800B0109UL /*CERT_E_UNTRUSTEDROOT*/) {
        // 从状态数据里取签名证书（自签名场景下签名者就是根）
        CRYPT_PROVIDER_DATA* prov = WTHelperProvDataFromStateData(data.hWVTStateData);
        if (prov) {
            CRYPT_PROVIDER_SGNR* sgnr = WTHelperGetProvSignerFromChain(prov, 0, FALSE, 0);
            if (sgnr && sgnr->pasCertChain && sgnr->csCertChain > 0 &&
                sgnr->pasCertChain[0].pCert) {
                BYTE hash[64]{};
                DWORD hash_len = sizeof(hash);
                if (CertGetCertificateContextProperty(sgnr->pasCertChain[0].pCert,
                                                      CERT_SHA256_HASH_PROP_ID, hash, &hash_len)) {
                    char buf[8];
                    for (DWORD i = 0; i < hash_len; ++i) {
                        std::snprintf(buf, sizeof(buf), "%02X", hash[i]);
                        thumbprint += buf;
                    }
                }
            }
        }
    }
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &action, &data);

    char code[32];
    std::snprintf(code, sizeof(code), "0x%08lx", static_cast<unsigned long>(rc));
    // 常见失败码给一句能行动的说明（Win7 上最容易踩的是缺 SHA-2 支持）
    const char* why = "";
    switch (static_cast<unsigned long>(rc)) {
    case 0x800B0100UL: why = "（TRUST_E_NOSIGNATURE：文件没有签名，或系统不支持 SHA-2 代码签名 —— "
                              "Win7 SP1 需要 KB3033929）"; break;
    case 0x800B0101UL: why = "（CERT_E_EXPIRED：签名证书已过期）"; break;
    case 0x800B0110UL: why = "（CERT_E_WRONG_USAGE：证书用途不是代码签名）"; break;
    case 0x80096005UL: why = "（TRUST_E_TIME_STAMP：时间戳无效）"; break;
    case 0x80096010UL: why = "（TRUST_E_BAD_DIGEST：文件内容被改动过，摘要不符）"; break;
    case 0x800B010AUL: why = "（CERT_E_CHAINING：证书链不完整）"; break;
    default: break;
    }
    if (thumbprint.empty()) {
        *detail = std::string("验签失败（WinVerifyTrust=") + code + "，" +
                  "未取到签名证书）" + why;
        return ErrCode::kCallerNotSigned;
    }
    if (thumbprint != pin) {
        *detail = "签名证书指纹不匹配：调用者=" + thumbprint.substr(0, 16) + "… 期望=" +
                  pin.substr(0, 16) + "…";
        return ErrCode::kCallerWrongCert;
    }
    *detail = "验签通过（指纹 " + pin.substr(0, 16) + "…）";
    return ErrCode::kOk;
}

// 返回 true 表示通过；否则在 code/detail 里给出原因
bool validate_caller(DWORD pid, ErrCode* code, std::string* detail, CallerInfo* info,
                     bool verbose) {
    auto fail = [&](ErrCode c, const std::string& d) {
        *code = c;
        *detail = d;
        if (verbose) std::printf("  [失败] %s: %s\n", error_code_name(c), d.c_str());
        return false;
    };
    auto pass = [&](const std::string& d) {
        if (verbose) std::printf("  [通过] %s\n", d.c_str());
        return true;
    };
    *code = ErrCode::kOk;
    info->pid = pid;

    // 1) 打开调用者（只用 QUERY_LIMITED：够拿路径/时间/令牌，不需要更多权限）
    HANDLE hp = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hp) return fail(ErrCode::kCallerOpenFail,
                         "OpenProcess 失败（错误 " + std::to_string(GetLastError()) + "）");

    // 2) 身份指纹：创建时间 + 路径
    FILETIME c{}, e{}, k{}, u{};
    if (!GetProcessTimes(hp, &c, &e, &k, &u)) {
        CloseHandle(hp);
        return fail(ErrCode::kCallerOpenFail, "GetProcessTimes 失败");
    }
    info->created = (static_cast<unsigned long long>(c.dwHighDateTime) << 32) | c.dwLowDateTime;
    wchar_t path[MAX_PATH * 2]{};
    DWORD n = MAX_PATH * 2;
    if (!QueryFullProcessImageNameW(hp, 0, path, &n)) {
        CloseHandle(hp);
        return fail(ErrCode::kCallerOpenFail, "QueryFullProcessImageName 失败");
    }
    info->path.assign(path, n);
    if (verbose) std::printf("  [信息] 调用者: pid=%lu path=%ls created=%llu\n", pid,
                             info->path.c_str(), info->created);

    // 3) 调用者令牌：必须在 Administrators 组
    //    TOKEN_DUPLICATE 是为了下面"复制成模拟令牌"的交叉验证（服务是 SYSTEM，能拿到）；
    //    拿不到就退回只用 TOKEN_QUERY，组检查仍然照做。
    HANDLE tok = nullptr;
    if (!OpenProcessToken(hp, TOKEN_QUERY | TOKEN_DUPLICATE, &tok) &&
        !OpenProcessToken(hp, TOKEN_QUERY, &tok)) {
        CloseHandle(hp);
        return fail(ErrCode::kCallerOpenFail,
                    "OpenProcessToken 失败（错误 " + std::to_string(GetLastError()) + "）");
    }
    {
        DWORD size = 0;
        GetTokenInformation(tok, TokenUser, nullptr, 0, &size);
        if (size > 0) {
            std::vector<unsigned char> buf(size);
            if (GetTokenInformation(tok, TokenUser, buf.data(), size, &size)) {
                auto* tu = reinterpret_cast<TOKEN_USER*>(buf.data());
                LPWSTR sid_str = nullptr;
                if (ConvertSidToStringSidW(tu->User.Sid, &sid_str)) {
                    info->user = wide_to_utf8(sid_str);
                    LocalFree(sid_str);
                }
            }
        }
        DWORD session = 0, ret = 0;
        if (GetTokenInformation(tok, TokenSessionId, &session, sizeof(session), &ret))
            info->session = session;
        BYTE admins[SECURITY_MAX_SID_SIZE]{};
        DWORD admins_size = sizeof(admins);
        if (CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, admins, &admins_size)) {
            const AdminCheck adm = check_administrator(tok, admins);
            info->is_admin = adm.is_admin;
            info->admin_diag = adm.summary();
            if (!adm.is_admin) info->admin_diag += "；" + adm.hint();
            if (verbose) {
                std::printf("  [信息] 令牌: %s\n", adm.summary().c_str());
                if (adm.api_checked && adm.api_member != adm.sid_enabled) {
                    std::printf("  [注意] 组检查与 CheckTokenMembership 结论不一致"
                                "（组=%d api=%d），已按并集处理\n",
                                adm.sid_enabled ? 1 : 0, adm.api_member ? 1 : 0);
                }
            }
        } else {
            info->admin_diag = "CreateWellKnownSid(Administrators) 失败（错误 " +
                               std::to_string(GetLastError()) + "）";
        }
    }
    CloseHandle(tok);
    if (!info->is_admin) {
        CloseHandle(hp);
        return fail(ErrCode::kCallerNotAdmin,
                    "调用者不在 Administrators 组（用户 SID " + info->user + "；" +
                        info->admin_diag + "）");
    }

    // 4) 规范化路径必须等于安装目录下的 avengine.exe（拒绝复制到别处的副本）
    {
        const std::wstring whitelist = resolve_install_dir();
        if (whitelist.empty()) {
            CloseHandle(hp);
            // fail-closed：白名单都定不下来，绝不能"跳过路径比对"放行
            return fail(ErrCode::kInstallDirUnknown,
                        "无法确定安装目录白名单（在服务目录、上一级目录和 HKLM\\" +
                            std::string("SOFTWARE\\AvEngine\\InstallDir 都找不到 avengine.exe）"
                                        "→ 拒绝一切请求，请先运行 --install"));
        }
        const std::wstring expected = canonical_path(whitelist + L"\\avengine.exe");
        const std::wstring actual = canonical_path(info->path);
        info->canonical = actual;
        if (expected.empty() || actual.empty()) {
            CloseHandle(hp);
            return fail(ErrCode::kCallerWrongPath,
                        "无法规范化路径（调用者=" + wide_to_utf8(info->path) + " 白名单=" +
                            wide_to_utf8(whitelist) + "）");
        }
        if (to_lower(expected) != to_lower(actual)) {
            CloseHandle(hp);
            return fail(ErrCode::kCallerWrongPath,
                        "调用者不是安装目录中的 avengine.exe（调用者=" + wide_to_utf8(actual) +
                            " 期望=" + wide_to_utf8(expected) + "）");
        }
        if (verbose) std::printf("  [信息] 路径比对通过: %ls\n", actual.c_str());
    }

    // 5) 验签 + 钉指纹
    {
        std::string sig_detail;
        const ErrCode sc = verify_caller_signature(info->path, &sig_detail);
        CloseHandle(hp);
        if (sc != ErrCode::kOk) return fail(sc, sig_detail);
        if (verbose) std::printf("  [信息] %s\n", sig_detail.c_str());
        // PID 复用复核：按 pid 重新打开一次，创建时间必须一致
        HANDLE again = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (again) {
            FILETIME c2{}, e2{}, k2{}, u2{};
            if (GetProcessTimes(again, &c2, &e2, &k2, &u2)) {
                const unsigned long long created2 =
                    (static_cast<unsigned long long>(c2.dwHighDateTime) << 32) | c2.dwLowDateTime;
                CloseHandle(again);
                if (created2 != info->created)
                    return fail(ErrCode::kCallerOpenFail, "PID 已被复用（创建时间不一致）");
            } else {
                CloseHandle(again);
            }
        }
    }
    return pass("验证链全部通过");
}

// ---------------- 以 SYSTEM 令牌创建子进程 ----------------

bool launch_as_system(const std::wstring& args, bool wait, DWORD timeout_ms, DWORD caller_session,
                      bool adopt_caller_session, DWORD* child_pid, DWORD* exit_code,
                      std::wstring* log_path, ErrCode* code, std::string* detail) {
    const std::wstring dir = resolve_install_dir();
    if (dir.empty()) {
        *code = ErrCode::kInstallDirUnknown;
        *detail = "无法确定安装目录（找不到 avengine.exe）→ 拒绝启动子进程";
        return false;
    }
    const std::wstring exe = dir + L"\\avengine.exe";
    if (GetFileAttributesW(exe.c_str()) == INVALID_FILE_ATTRIBUTES) {
        *code = ErrCode::kCallerWrongPath;
        *detail = "安装目录里找不到 avengine.exe: " + wide_to_utf8(exe);
        return false;
    }
    // CreateProcessAsUser 需要这两个特权（SYSTEM 持有，但要显式启用）
    enable_privilege(SE_ASSIGNPRIMARYTOKEN_NAME);
    enable_privilege(SE_INCREASE_QUOTA_NAME);

    HANDLE tok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY,
                          &tok)) {
        *code = ErrCode::kChildFail;
        *detail = "OpenProcessToken 失败（错误 " + std::to_string(GetLastError()) + "）";
        return false;
    }
    HANDLE primary = nullptr;
    if (!DuplicateTokenEx(tok, MAXIMUM_ALLOWED, nullptr, SecurityImpersonation, TokenPrimary,
                          &primary)) {
        CloseHandle(tok);
        *code = ErrCode::kChildFail;
        *detail = "DuplicateTokenEx 失败（错误 " + std::to_string(GetLastError()) + "）";
        return false;
    }
    CloseHandle(tok);

    if (adopt_caller_session) {
        // 让子进程跑在调用者所在会话（默认保持服务会话 0）
        if (!SetTokenInformation(primary, TokenSessionId, &caller_session, sizeof(caller_session)))
            audit("WARN 设置 TokenSessionId=%lu 失败（错误 %lu），继续使用服务会话", caller_session,
                  GetLastError());
    }

    // 子进程输出重定向到日志文件：客户端（管理员）可读
    const std::wstring out_path = log_dir() + L"\\child-" + std::to_wstring(GetCurrentProcessId()) +
                                  L"-" + std::to_wstring(GetTickCount64()) + L".log";
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:P(A;;GA;;;SY)(A;;GA;;;BA)", SDDL_REVISION_1, &sd, nullptr)) {
        sa.lpSecurityDescriptor = sd;   // 只有 SYSTEM/管理员能读写子进程输出
    }
    HANDLE out = CreateFileW(out_path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, &sa, CREATE_ALWAYS,
                             FILE_ATTRIBUTE_NORMAL, nullptr);
    if (sd) LocalFree(sd);

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = (out != INVALID_HANDLE_VALUE) ? out : nullptr;
    si.hStdError = si.hStdOutput;
    si.hStdInput = nullptr;

    void* env = nullptr;
    CreateEnvironmentBlock(&env, primary, FALSE);

    std::wstring cmdline = L"\"" + exe + L"\" " + args;
    std::vector<wchar_t> cmd(cmdline.begin(), cmdline.end());
    cmd.push_back(L'\0');

    PROCESS_INFORMATION pi{};
    /*
     * DETACHED_PROCESS：子进程**完全不要控制台**。
     *
     * 为什么必须显式声明：avengine.exe 打包时用了 Nuitka 的
     * --windows-console-mode=attach，子进程启动时会尝试 AttachConsole(父进程)，
     * 若父进程（本服务，session 0）没有控制台，它可能转而新建/接管一个控制台，
     * 那样 stdout 会被重新指到 CONOUT$，绕过我们重定向到日志文件的句柄 ——
     * 表现就是 SYSTEM 子进程的输出去到了别的窗口、或半行文本混进用户的命令行。
     * DETACHED_PROCESS 让子进程根本没有控制台，输出只能走我们给的日志句柄。
     */
    const DWORD flags = CREATE_UNICODE_ENVIRONMENT | DETACHED_PROCESS;
    const BOOL ok = CreateProcessAsUserW(primary, exe.c_str(), cmd.data(), nullptr, nullptr, TRUE,
                                         flags, env, dir.c_str(), &si, &pi);
    const DWORD err = GetLastError();
    if (env) DestroyEnvironmentBlock(env);
    if (out != INVALID_HANDLE_VALUE) CloseHandle(out);
    CloseHandle(primary);

    if (!ok) {
        *code = ErrCode::kChildFail;
        *detail = "CreateProcessAsUser 失败（错误 " + std::to_string(err) + "）";
        return false;
    }
    *child_pid = pi.dwProcessId;
    *log_path = out_path;
    if (wait) {
        const DWORD to = timeout_ms ? timeout_ms : 600000;
        const DWORD w = WaitForSingleObject(pi.hProcess, to);
        DWORD code_val = 0;
        if (w == WAIT_TIMEOUT) {
            *exit_code = 0xFFFFFFFF;   // 超时：交给客户端决定是否终止
            *detail = "等待子进程超时（" + std::to_string(to) + " ms），子进程仍在运行";
        } else if (GetExitCodeProcess(pi.hProcess, &code_val)) {
            *exit_code = code_val;
        }
    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return true;
}

// ---------------- 请求处理 ----------------

std::string handle_request(const std::string& line, DWORD caller_pid) {
    char errbuf[32];
    // 版本头
    if (line.rfind(kProtocolVersion, 0) != 0)
        return std::string("ERR ") + error_code_name(ErrCode::kBadProtocol) +
               " 协议版本不匹配（需要 " + kProtocolVersion + "）\r\n";
    const std::string rest = line.substr(std::strlen(kProtocolVersion));
    const std::vector<Kv> kvs = parse_kv(rest);
    const std::string verb = kvs.empty() ? std::string() : kvs[0].key;

    CallerInfo info;
    ErrCode code = ErrCode::kOk;
    std::string detail;

    if (verb == "PING") {
        if (!validate_caller(caller_pid, &code, &detail, &info, false))
            return std::string("ERR ") + error_code_name(code) + " " + detail + "\r\n";
        audit("PING pid=%lu user=%s admin=yes", caller_pid, info.user.c_str());
        return std::string("OK pid=") + std::to_string(GetCurrentProcessId()) +
               " pin=" + normalize_thumbprint(AVPRIV_PINNED_CERT_SHA256).substr(0, 16) + "\r\n";
    }
    if (verb != "RUN")
        return std::string("ERR ") + error_code_name(ErrCode::kBadRequest) + " 未知请求: " + verb +
               "\r\n";

    // 先验证调用者，再碰参数
    if (!validate_caller(caller_pid, &code, &detail, &info, false)) {
        audit("DENY %s pid=%lu user=%s path=%s detail=%s", error_code_name(code), caller_pid,
              info.user.c_str(), wide_to_utf8(info.path).c_str(), detail.c_str());
        return std::string("ERR ") + error_code_name(code) + " " + detail + "\r\n";
    }

    const std::string args_enc = kv_get(kvs, "args");
    const std::wstring args = utf8_to_wide(decode_value(args_enc));
    // 参数与命令行安全：拒绝控制字符/换行（防注入额外命令行）、限制长度
    if (args.size() > 4096 || args.find_first_of(L"\r\n\0") != std::wstring::npos) {
        audit("DENY %s pid=%lu len=%zu", error_code_name(ErrCode::kArgsRejected), caller_pid,
              args.size());
        return std::string("ERR ") + error_code_name(ErrCode::kArgsRejected) +
               " 参数被拒（含控制字符或过长）\r\n";
    }
    const bool wait = kv_get(kvs, "wait") == "1";
    const bool adopt = kv_get(kvs, "session") == "caller";
    DWORD timeout_ms = 600000;
    {
        const std::string t = kv_get(kvs, "timeout_ms");
        if (!t.empty()) {
            try {
                timeout_ms = static_cast<DWORD>(std::stoul(t));
            } catch (...) {
                timeout_ms = 600000;
            }
            if (timeout_ms > 1800000) timeout_ms = 1800000;
        }
    }

    DWORD child = 0, exit_code = 0;
    std::wstring log_path;
    if (!launch_as_system(args, wait, timeout_ms, info.session, adopt, &child, &exit_code, &log_path,
                          &code, &detail)) {
        audit("FAIL %s pid=%lu args=%s detail=%s", error_code_name(code), caller_pid,
              wide_to_utf8(args).c_str(), detail.c_str());
        return std::string("ERR ") + error_code_name(code) + " " + detail + "\r\n";
    }
    audit("GRANT pid=%lu user=%s child=%lu wait=%d args=%s", caller_pid, info.user.c_str(), child,
          wait ? 1 : 0, wide_to_utf8(args).c_str());
    std::string resp = "OK pid=" + std::to_string(child);
    resp += " log=" + encode_value(wide_to_utf8(log_path));
    if (wait) {
        resp += " exit=";
        resp += (exit_code == 0xFFFFFFFF) ? std::string("timeout") : std::to_string(exit_code);
    }
    if (!detail.empty()) resp += " note=" + encode_value(detail);
    resp += "\r\n";
    (void)errbuf;
    return resp;
}

// ---------------- 管道服务端 ----------------

DWORD WINAPI pipe_thread(LPVOID param) {
    HANDLE pipe = reinterpret_cast<HANDLE>(param);
    std::string request;
    char buf[kMaxRequestBytes]{};
    DWORD read = 0;
    std::string response;
    DWORD caller_pid = 0;

    const BOOL connected = ConnectNamedPipe(pipe, nullptr) ? TRUE : (GetLastError() ==
                                                                    ERROR_PIPE_CONNECTED);
    if (!connected) {
        DisconnectNamedPipe(pipe);
        CloseHandle(pipe);
        InterlockedDecrement(&g_active_connections);
        return 0;
    }
    if (!GetNamedPipeClientProcessId(pipe, &caller_pid)) caller_pid = 0;

    // 只读一行（协议就是一行请求）
    if (ReadFile(pipe, buf, sizeof(buf) - 1, &read, nullptr) && read > 0) {
        request.assign(buf, read);
        while (!request.empty() && (request.back() == '\r' || request.back() == '\n'))
            request.pop_back();
    }
    if (caller_pid == 0) {
        response = std::string("ERR ") + error_code_name(ErrCode::kCallerOpenFail) +
                   " 无法获取客户端 PID\r\n";
    } else if (request.empty()) {
        response = std::string("ERR ") + error_code_name(ErrCode::kBadRequest) + " 空请求\r\n";
    } else {
        response = handle_request(request, caller_pid);
    }

    DWORD written = 0;
    WriteFile(pipe, response.data(), static_cast<DWORD>(response.size()), &written, nullptr);
    FlushFileBuffers(pipe);
    DisconnectNamedPipe(pipe);
    CloseHandle(pipe);
    InterlockedDecrement(&g_active_connections);
    return 0;
}

// 管道 ACL：只有 SYSTEM 与 Administrators 能连接（第一道门；服务内部还会再查令牌）
bool make_pipe_sa(SECURITY_ATTRIBUTES* sa, PSECURITY_DESCRIPTOR* sd) {
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)",
                                                              SDDL_REVISION_1, sd, nullptr))
        return false;
    sa->nLength = sizeof(*sa);
    sa->lpSecurityDescriptor = *sd;
    sa->bInheritHandle = FALSE;
    return true;
}

void pipe_server_loop() {
    SECURITY_ATTRIBUTES sa{};
    PSECURITY_DESCRIPTOR sd = nullptr;
    const bool have_sa = make_pipe_sa(&sa, &sd);
    if (!have_sa) audit("WARN 构造管道安全描述符失败（错误 %lu），使用默认 ACL", GetLastError());

    while (WaitForSingleObject(g_stop_event, 0) == WAIT_TIMEOUT) {
        if (InterlockedCompareExchange(&g_active_connections, 0, 0) >= kMaxConnections) {
            Sleep(200);
            continue;
        }
        HANDLE pipe = CreateNamedPipeW(
            kPipeNameW, PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, PIPE_UNLIMITED_INSTANCES,
            kMaxRequestBytes, kMaxRequestBytes, 0, have_sa ? &sa : nullptr);
        if (pipe == INVALID_HANDLE_VALUE) {
            audit("ERROR CreateNamedPipe 失败（错误 %lu）", GetLastError());
            Sleep(500);
            continue;
        }
        InterlockedIncrement(&g_active_connections);
        HANDLE th = CreateThread(nullptr, 0, pipe_thread, pipe, 0, nullptr);
        if (th)
            CloseHandle(th);
        else {
            CloseHandle(pipe);
            InterlockedDecrement(&g_active_connections);
        }
    }
    if (sd) LocalFree(sd);
}

// ---------------- SCM ----------------

void set_status(DWORD state, DWORD exit_code = NO_ERROR, DWORD wait_hint = 0) {
    g_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_status.dwCurrentState = state;
    g_status.dwWin32ExitCode = exit_code;
    g_status.dwWaitHint = wait_hint;
    g_status.dwControlsAccepted =
        (state == SERVICE_START_PENDING) ? 0 : (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN);
    static DWORD checkpoint = 1;
    g_status.dwCheckPoint = wait_hint ? checkpoint++ : 0;
    if (g_status_handle) SetServiceStatus(g_status_handle, &g_status);
}

DWORD WINAPI service_ctrl(DWORD ctrl, DWORD, LPVOID, LPVOID) {
    switch (ctrl) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        set_status(SERVICE_STOP_PENDING, NO_ERROR, 3000);
        if (g_stop_event) SetEvent(g_stop_event);
        return NO_ERROR;
    case SERVICE_CONTROL_INTERROGATE:
        set_status(g_status.dwCurrentState);
        return NO_ERROR;
    default:
        return ERROR_CALL_NOT_IMPLEMENTED;
    }
}

void WINAPI service_main(DWORD, LPWSTR*) {
    g_status_handle = RegisterServiceCtrlHandlerExW(kServiceName, service_ctrl, nullptr);
    if (!g_status_handle) return;
    set_status(SERVICE_START_PENDING, NO_ERROR, 5000);
    g_stop_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);

    if (!is_local_system())
        audit("ERROR 服务未以 LocalSystem 运行，将拒绝所有请求");
    {
        const std::wstring wl = resolve_install_dir();
        audit("INFO 服务启动：pin=%s install_dir=%s system=%d",
              normalize_thumbprint(AVPRIV_PINNED_CERT_SHA256).empty()
                  ? "(未配置)"
                  : normalize_thumbprint(AVPRIV_PINNED_CERT_SHA256).substr(0, 16).c_str(),
              wl.empty() ? "(无法确定→拒绝一切)" : wide_to_utf8(wl).c_str(),
              is_local_system() ? 1 : 0);
    }

    set_status(SERVICE_RUNNING);
    pipe_server_loop();
    set_status(SERVICE_STOP_PENDING, NO_ERROR, 3000);
    if (g_stop_event) CloseHandle(g_stop_event);
    audit("INFO 服务停止");
    set_status(SERVICE_STOPPED);
}

// ---------------- 安装 / 卸载 / 状态 ----------------

int cmd_install(bool autostart) {
    const std::wstring exe = exe_dir() + L"\\AvEnginePrivSvc.exe";
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!scm) {
        std::printf("打开 SCM 失败（错误 %lu）——请以管理员身份运行\n", GetLastError());
        return 1;
    }
    SC_HANDLE svc = CreateServiceW(
        scm, kServiceName, kServiceDisplay, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
        autostart ? SERVICE_AUTO_START : SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, exe.c_str(),
        nullptr, nullptr, nullptr, nullptr, nullptr);
    if (!svc && GetLastError() == ERROR_SERVICE_EXISTS) {
        svc = OpenServiceW(scm, kServiceName, SERVICE_ALL_ACCESS);
        if (svc) {
            ChangeServiceConfigW(svc, SERVICE_NO_CHANGE, autostart ? SERVICE_AUTO_START
                                                                   : SERVICE_DEMAND_START,
                                 SERVICE_NO_CHANGE, exe.c_str(), nullptr, nullptr, nullptr,
                                 nullptr, nullptr, kServiceDisplay);
            std::printf("服务已存在，已更新配置\n");
        }
    }
    if (!svc) {
        std::printf("创建服务失败（错误 %lu）\n", GetLastError());
        CloseServiceHandle(scm);
        return 1;
    }
    SERVICE_DESCRIPTIONW desc{};
    desc.lpDescription = const_cast<LPWSTR>(kServiceDesc);
    ChangeServiceConfig2W(svc, SERVICE_CONFIG_DESCRIPTION, &desc);
    // 失败动作：崩溃后自动重启两次（避免"服务死了就没特权"）
    SERVICE_FAILURE_ACTIONSW fa{};
    SC_ACTION actions[2]{};
    actions[0].Type = SC_ACTION_RESTART;
    actions[0].Delay = 5000;
    actions[1].Type = SC_ACTION_RESTART;
    actions[1].Delay = 15000;
    fa.dwResetPeriod = 86400;
    fa.cActions = 2;
    fa.lpsaActions = actions;
    ChangeServiceConfig2W(svc, SERVICE_CONFIG_FAILURE_ACTIONS, &fa);
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);

    // 记录安装目录（服务用它做路径白名单）——必须记"真正能找到 avengine.exe 的那一层"，
    // 否则发布包布局（<release>\service\AvEnginePrivSvc.exe + <release>\avengine.exe）会记错。
    const std::wstring wl = resolve_install_dir();
    if (wl.empty()) {
        std::printf("警告：在服务目录、上一级目录都找不到 avengine.exe，无法确定白名单。\n");
        std::printf("      服务会拒绝一切请求。请把服务放在 avengine.exe 同目录或其 service\\ 子目录下，\n");
        std::printf("      再重新执行 --install。\n");
    } else {
        HKEY key = nullptr;
        if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, kRegPath, 0, nullptr, 0,
                            KEY_WRITE | KEY_WOW64_64KEY, nullptr, &key,
                            nullptr) == ERROR_SUCCESS) {
            RegSetValueExW(key, kInstallDirValue, 0, REG_SZ,
                           reinterpret_cast<const BYTE*>(wl.c_str()),
                           static_cast<DWORD>((wl.size() + 1) * sizeof(wchar_t)));
            RegCloseKey(key);
            std::printf("安装目录白名单：%ls\n", wl.c_str());
        } else {
            std::printf("警告：写入 HKLM\\%ls\\%ls 失败（错误 %lu），服务将按目录位置自行推断\n",
                        kRegPath, kInstallDirValue, GetLastError());
        }
    }
    std::printf("服务已安装：%ls（启动类型 %ls）\n", kServiceName,
                autostart ? L"自动" : L"按需");
    if (normalize_thumbprint(AVPRIV_PINNED_CERT_SHA256).empty())
        std::printf("注意：当前未配置证书指纹（service/generated/cert_pin.h 缺失），"
                    "服务会拒绝所有请求。请先运行 scripts\\gen_signing_cert.ps1 再重新构建。\n");
    return 0;
}

int cmd_uninstall() {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) {
        std::printf("打开 SCM 失败（错误 %lu）——请以管理员身份运行\n", GetLastError());
        return 1;
    }
    SC_HANDLE svc = OpenServiceW(scm, kServiceName, SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS);
    if (!svc) {
        std::printf("服务不存在或无权访问（错误 %lu）\n", GetLastError());
        CloseServiceHandle(scm);
        return 1;
    }
    SERVICE_STATUS st{};
    ControlService(svc, SERVICE_CONTROL_STOP, &st);
    const BOOL ok = DeleteService(svc);
    std::printf(ok ? "服务已删除\n" : "删除服务失败（错误 %lu）\n", GetLastError());
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return ok ? 0 : 1;
}

int cmd_status() {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) {
        std::printf("打开 SCM 失败（错误 %lu）\n", GetLastError());
        return 1;
    }
    SC_HANDLE svc = OpenServiceW(scm, kServiceName, SERVICE_QUERY_STATUS);
    if (!svc) {
        std::printf("服务未安装（错误 %lu）\n", GetLastError());
        CloseServiceHandle(scm);
        return 1;
    }
    SERVICE_STATUS_PROCESS ssp{};
    DWORD needed = 0;
    if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&ssp),
                             sizeof(ssp), &needed)) {
        const char* state = "?";
        switch (ssp.dwCurrentState) {
        case SERVICE_RUNNING: state = "RUNNING"; break;
        case SERVICE_STOPPED: state = "STOPPED"; break;
        case SERVICE_START_PENDING: state = "START_PENDING"; break;
        case SERVICE_STOP_PENDING: state = "STOP_PENDING"; break;
        default: state = "OTHER"; break;
        }
        std::printf("服务 %ls：%s（pid=%lu）\n", kServiceName, state, ssp.dwProcessId);
    }
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return 0;
}

int cmd_check_pin() {
    const std::string pin = normalize_thumbprint(AVPRIV_PINNED_CERT_SHA256);
    const std::wstring wl = resolve_install_dir();
    std::printf("协议版本        : %s\n", kProtocolVersion);
    std::printf("钉住的证书指纹  : %s\n", pin.empty() ? "(未配置 → 拒绝一切请求)" : pin.c_str());
    std::printf("证书主体        : %s\n",
                AVPRIV_PINNED_CERT_SUBJECT[0] ? AVPRIV_PINNED_CERT_SUBJECT : "(未配置)");
    if (wl.empty())
        std::printf("安装目录(白名单): (无法确定 → 拒绝一切请求；请把服务放到 avengine.exe 同目录"
                    "或其 service\\ 子目录后执行 --install)\n");
    else
        std::printf("安装目录(白名单): %s\n", wide_to_utf8(wl).c_str());
    std::printf("当前进程是SYSTEM: %s\n", is_local_system() ? "是" : "否");
    std::printf("审计/输出目录   : %s\n", wide_to_utf8(log_dir()).c_str());
    return (pin.empty() || wl.empty()) ? 2 : 0;   // 2 = 未完整配置，必然拒绝一切请求
}

int cmd_selftest(DWORD pid) {
    std::printf("AvEngine 特权服务自检（只验证、不授权、不创建进程）\n");
    std::printf("目标 pid=%lu\n", pid);
    const std::string pin = normalize_thumbprint(AVPRIV_PINNED_CERT_SHA256);
    const std::wstring wl = resolve_install_dir();
    std::printf("[0] 证书指纹: %s\n", pin.empty() ? "未配置 → 所有请求都会被拒绝" : pin.c_str());
    std::printf("[0] 安装目录白名单: %s\n",
                wl.empty() ? "(无法确定 → 所有请求都会被拒绝)" : wide_to_utf8(wl).c_str());
    std::printf("[0] 本进程 SYSTEM: %s\n", is_local_system() ? "是" : "否（无法创建 SYSTEM 子进程）");
    CallerInfo info;
    ErrCode code = ErrCode::kOk;
    std::string detail;
    const bool ok = validate_caller(pid, &code, &detail, &info, true);
    std::printf("结论: %s（%s）\n", ok ? "通过" : error_code_name(code), detail.c_str());
    return ok ? 0 : 1;
}

bool run_as_service() {
    SERVICE_TABLE_ENTRYW table[] = {{const_cast<LPWSTR>(kServiceName), service_main},
                                    {nullptr, nullptr}};
    return StartServiceCtrlDispatcherW(table) != FALSE;
}

}  // namespace

namespace {

/*
 * 控制台代码页会被"进程级共享"：调用 SetConsoleOutputCP(CP_UTF8) 之后，
 * **同一个 cmd 窗口里后续运行的其他程序**（比如 avengine.exe 的 Python/colorama）
 * 也会看到 65001，从而出现乱码甚至写入异常。特权服务不该留下这种全局副作用，
 * 所以这里只在自己运行期间临时改，退出时无条件恢复（RAII + atexit 双保险，
 * 因为 return 路径不会析构自动对象）。
 */
class ConsoleCodepageGuard {
public:
    ConsoleCodepageGuard() {
        h_ = GetStdHandle(STD_OUTPUT_HANDLE);
        DWORD mode = 0;
        is_console_ = (h_ && h_ != INVALID_HANDLE_VALUE && GetConsoleMode(h_, &mode));
        if (!is_console_) return;
        saved_out_ = GetConsoleOutputCP();
        saved_in_ = GetConsoleCP();
        if (saved_out_ != CP_UTF8) SetConsoleOutputCP(CP_UTF8);
        // 不改输入代码页：服务从不读控制台输入
        (void)saved_in_;
    }
    ~ConsoleCodepageGuard() { restore(); }
    void restore() {
        if (!is_console_ || restored_) return;
        restored_ = true;
        if (saved_out_ != 0 && saved_out_ != CP_UTF8) SetConsoleOutputCP(saved_out_);
    }

private:
    HANDLE h_ = nullptr;
    bool is_console_ = false;
    bool restored_ = false;
    UINT saved_out_ = 0;
    UINT saved_in_ = 0;
};

ConsoleCodepageGuard* g_cp_guard = nullptr;

void restore_console_cp() {
    if (g_cp_guard) g_cp_guard->restore();
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    // 输出统一成 UTF-8：命令行模式下中文提示在 GBK 控制台上也不会变成乱码，
    // 而且调用方（Python）按 UTF-8 解码即可。**退出时必须把控制台代码页还原**，
    // 否则同一个 cmd 窗口里后续运行的程序（avengine.exe/colorama）会受牵连。
    static ConsoleCodepageGuard cp_guard;
    g_cp_guard = &cp_guard;
    std::atexit(restore_console_cp);
    if (argc >= 2) {
        const std::wstring cmd = argv[1];
        if (cmd == L"--install")
            return cmd_install(argc >= 3 && std::wstring(argv[2]) == L"--auto");
        if (cmd == L"--uninstall") return cmd_uninstall();
        if (cmd == L"--status") return cmd_status();
        if (cmd == L"--check-pin") return cmd_check_pin();
        if (cmd == L"--selftest") {
            const DWORD pid = (argc >= 3) ? static_cast<DWORD>(wcstoul(argv[2], nullptr, 10))
                                          : GetCurrentProcessId();
            return cmd_selftest(pid);
        }
        if (cmd == L"--console") {
            g_stop_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
            std::printf("前台运行（Ctrl+C 退出）... 管道 %s\n", kPipeName);
            if (!is_local_system())
                std::printf("警告：当前不是 SYSTEM，创建 SYSTEM 子进程会失败\n");
            if (normalize_thumbprint(AVPRIV_PINNED_CERT_SHA256).empty())
                std::printf("警告：未配置证书指纹，所有请求都会被拒绝\n");
            pipe_server_loop();
            return 0;
        }
        std::printf("未知参数: %ls\n", cmd.c_str());
        std::printf("用法: AvEnginePrivSvc.exe [--install [--auto] | --uninstall | --status |"
                    " --check-pin | --selftest <pid> | --console]\n"
                    "不带参数时由 SCM 启动。\n");
        return 1;
    }
    if (!run_as_service()) {
        std::printf("作为服务启动失败（错误 %lu）。\n"
                    "请用 --install 安装服务，或用 --console 前台调试。\n",
                    GetLastError());
        return 1;
    }
    return 0;
}
