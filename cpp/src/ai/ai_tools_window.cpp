// ai_tools_window.cpp - AI 工具扩展库：窗口组（枚举 / 深挖 / 关闭）
//
// 为什么需要窗口工具：弹窗的"所属进程"经常是红鲱鱼——恶意代码可能在注入到别的
// 进程（explorer、某常驻程序）的 DLL 里注册窗口类、处理消息。窗口对象本身带着两个
// 直接指向模块的指针，靠它们可以一次定位到真正干活的 DLL，而不是逐个模块翻：
//   GetClassLongPtr(hwnd, GCLP_HMODULE)  注册该窗口类的模块（在目标进程地址空间）
//   GetWindowLongPtr(hwnd, GWLP_WNDPROC) 真正处理窗口消息的 WndProc 地址
// 这两个地址都不落在目标进程的模块列表里时，就是"手工映射 / 被 rootkit 隐藏"的强信号。
//
// 枚举策略（按系统版本与 scope 参数）：
//   auto    Windows 10+ 多桌面：EnumWindowStations → OpenDesktop → EnumDesktopWindows
//           Windows 7/8 单桌面：只枚举当前桌面（EnumWindows 等价路径）
//   desktop 仅当前桌面
//   session 当前窗口站下的所有桌面（WinSta0 的 Default/Winlogon/...）
//   all     所有窗口站的所有桌面（其他 session 需要管理员，失败的逐条记录）
//
// 审计由 ai_execute_tool 统一完成，本文件不调用 aiext::audit_log。
#include "ai_tools_ext.h"

#include "ai_util.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <map>
#include <string>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <softpub.h>
#include <wintrust.h>

using nlohmann::json;

namespace {

std::string ERR(const std::string& m) { return "ERROR: " + m; }

std::string to_lower(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

long long arg_int(const json& a, const char* k, long long def) {
    auto it = a.find(k);
    if (it == a.end() || it->is_null()) return def;
    if (it->is_number_integer()) return it->get<long long>();
    if (it->is_number_float()) return static_cast<long long>(it->get<double>());
    if (it->is_boolean()) return it->get<bool>() ? 1 : 0;
    if (it->is_string()) {
        try {
            return std::stoll(it->get<std::string>());
        } catch (...) {
            return def;
        }
    }
    return def;
}
std::string arg_str(const json& a, const char* k, const std::string& def = "") {
    auto it = a.find(k);
    if (it == a.end() || it->is_null()) return def;
    if (it->is_string()) return it->get<std::string>();
    if (it->is_boolean()) return it->get<bool>() ? "true" : "false";
    if (it->is_number_integer()) return std::to_string(it->get<long long>());
    return def;
}
bool arg_bool(const json& a, const char* k, bool def) {
    auto it = a.find(k);
    if (it == a.end() || it->is_null()) return def;
    if (it->is_boolean()) return it->get<bool>();
    if (it->is_number_integer()) return it->get<long long>() != 0;
    if (it->is_string()) {
        std::string v = to_lower(it->get<std::string>());
        return v == "true" || v == "1" || v == "yes";
    }
    return def;
}

std::string hex_addr(unsigned long long a) {
    char buf[24];
    std::snprintf(buf, sizeof(buf), "0x%llx", a);
    return buf;
}

std::string hex32(unsigned long v) {
    char buf[16];
    std::snprintf(buf, sizeof(buf), "0x%08lx", static_cast<unsigned long>(v));
    return buf;
}

// hwnd 参数：接受 "0x00010A2C" / "68140" / 十进制数字
unsigned long long parse_hwnd(const json& args, const char* key, bool* ok) {
    *ok = false;
    auto it = args.find(key);
    if (it == args.end() || it->is_null()) return 0;
    if (it->is_number_integer()) {
        *ok = true;
        return static_cast<unsigned long long>(it->get<long long>());
    }
    if (!it->is_string()) return 0;
    const std::string s = it->get<std::string>();
    try {
        size_t idx = 0;
        const unsigned long long v = std::stoull(s, &idx, 0);   // 0 基数：自动识别 0x
        if (idx == s.size()) {
            *ok = true;
            return v;
        }
    } catch (...) {
    }
    return 0;
}

// ---------------- 系统版本（决定默认枚举范围） ----------------

int windows_major_version() {
    HKEY h = nullptr;
    int major = 0;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                      0, KEY_READ, &h) == ERROR_SUCCESS) {
        DWORD type = 0, value = 0, size = sizeof(value);
        if (RegQueryValueExW(h, L"CurrentMajorVersionNumber", nullptr, &type, (LPBYTE)&value,
                             &size) == ERROR_SUCCESS &&
            type == REG_DWORD) {
            major = static_cast<int>(value);
        } else {
            wchar_t text[64]{};
            size = sizeof(text);
            if (RegQueryValueExW(h, L"CurrentVersion", nullptr, &type, (LPBYTE)text, &size) ==
                ERROR_SUCCESS) {
                int a = 0;
                if (swscanf(text, L"%d", &a) == 1) major = a;
            }
        }
        RegCloseKey(h);
    }
    return major > 0 ? major : 6;
}

// ---------------- 进程 / 模块信息（各分组文件自带，避免跨文件耦合） ----------------

struct ModuleRange {
    std::string name;
    std::string path;
    unsigned long long base = 0;
    unsigned long long size = 0;
};

std::string process_image_path(DWORD pid) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return "";
    wchar_t buf[MAX_PATH * 2]{};
    DWORD n = MAX_PATH * 2;
    std::string out;
    if (QueryFullProcessImageNameW(h, 0, buf, &n)) out = aiutil::to_utf8(std::wstring(buf, n));
    CloseHandle(h);
    return out;
}

std::string file_name_of(const std::string& path) {
    const size_t pos = path.find_last_of("\\/");
    return pos == std::string::npos ? path : path.substr(pos + 1);
}

/*
 * 模块列表。**失败必须能被区分出来**：不能读列表时返回空表 + error，调用方绝不能把
 * "读不到"当成"模块不在 loader 列表里"（那是安全工具的经典误报）。
 * 两条路径：Toolhelp 优先（信息最全），失败回退 PSAPI（EnumProcessModulesEx）——
 * 有些受限环境/受保护进程只允许其中一条。
 */
struct ModuleList {
    std::vector<ModuleRange> mods;
    std::string error;   // 非空 = 列表不可用
    std::string source;  // toolhelp | psapi
};

ModuleList collect_modules(DWORD pid) {
    ModuleList out;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap != INVALID_HANDLE_VALUE) {
        MODULEENTRY32W me{};
        me.dwSize = sizeof(me);
        if (Module32FirstW(snap, &me)) {
            do {
                ModuleRange r;
                r.name = aiutil::to_utf8(me.szModule);
                r.path = aiutil::to_utf8(me.szExePath);
                r.base = reinterpret_cast<unsigned long long>(me.modBaseAddr);
                r.size = me.modBaseSize;
                out.mods.push_back(r);
            } while (Module32NextW(snap, &me));
        }
        CloseHandle(snap);
        if (!out.mods.empty()) {
            out.source = "toolhelp";
            return out;
        }
        out.error = "CreateToolhelp32Snapshot 未返回模块";
    } else {
        out.error = "CreateToolhelp32Snapshot 失败（错误 " + std::to_string(GetLastError()) + "）";
    }

    HANDLE hp = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hp) {
        out.error += "；OpenProcess 失败（错误 " + std::to_string(GetLastError()) + "）";
        return out;
    }
    std::vector<HMODULE> hmods(1024);
    DWORD needed = 0;
    BOOL ok = EnumProcessModulesEx(hp, hmods.data(),
                                   static_cast<DWORD>(hmods.size() * sizeof(HMODULE)), &needed,
                                   LIST_MODULES_ALL);
    if (ok && needed > hmods.size() * sizeof(HMODULE)) {
        hmods.resize(needed / sizeof(HMODULE) + 64);
        ok = EnumProcessModulesEx(hp, hmods.data(),
                                  static_cast<DWORD>(hmods.size() * sizeof(HMODULE)), &needed,
                                  LIST_MODULES_ALL);
    }
    if (!ok) {
        out.error += "；EnumProcessModulesEx 失败（错误 " + std::to_string(GetLastError()) + "）";
        CloseHandle(hp);
        return out;
    }
    const size_t count = needed / sizeof(HMODULE);
    for (size_t i = 0; i < count; ++i) {
        ModuleRange r;
        r.base = reinterpret_cast<unsigned long long>(hmods[i]);
        wchar_t path[MAX_PATH * 2]{};
        if (GetModuleFileNameExW(hp, hmods[i], path, MAX_PATH * 2))
            r.path = aiutil::to_utf8(path);
        wchar_t base_name[MAX_PATH]{};
        if (GetModuleBaseNameW(hp, hmods[i], base_name, MAX_PATH))
            r.name = aiutil::to_utf8(base_name);
        if (r.name.empty() && !r.path.empty()) r.name = file_name_of(r.path);
        MODULEINFO mi{};
        if (GetModuleInformation(hp, hmods[i], &mi, sizeof(mi))) r.size = mi.SizeOfImage;
        if (!r.name.empty() || r.base) out.mods.push_back(r);
    }
    CloseHandle(hp);
    if (!out.mods.empty()) {
        out.source = "psapi";
        out.error.clear();   // 回退成功：列表可用
    } else {
        out.error += "；PSAPI 也未返回模块";
    }
    return out;
}

const ModuleRange* module_containing(const std::vector<ModuleRange>& mods, unsigned long long addr) {
    for (const auto& m : mods)
        if (addr >= m.base && addr < m.base + m.size) return &m;
    return nullptr;
}

// 轻量 Authenticode 校验（无 UI、不查吊销）。返回 WinVerifyTrust 的结果码：
//   0            = 有效签名
//   0x800B0100   = TRUST_E_NOSIGNATURE（确实没有签名）
//   其它         = 校验本身失败（例如 catalog 数据库不可用、证书链问题）
// 必须区分后两者：把"校验失败"当成"无签名"会让安全工具满屏误报系统 DLL。
LONG quick_signed_rc(const std::string& path) {
    if (path.empty()) return static_cast<LONG>(0x800B0100);
    std::wstring wpath = aiutil::to_wide_sys(path);
    WINTRUST_FILE_INFO file_info{};
    file_info.cbStruct = sizeof(file_info);
    file_info.pcwszFilePath = wpath.c_str();
    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA data{};
    data.cbStruct = sizeof(data);
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_NONE;
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.dwStateAction = WTD_STATEACTION_VERIFY;
    data.pFile = &file_info;
    const LONG rc = WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &action, &data);
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &action, &data);
    return rc;
}

std::string signature_status_text(LONG rc) {
    if (rc == 0) return "signed";
    if (static_cast<unsigned long>(rc) == 0x800B0100UL) return "no_signature";
    char buf[48];
    std::snprintf(buf, sizeof(buf), "verify_failed(0x%08lx)", static_cast<unsigned long>(rc));
    return buf;
}

bool is_system_path(const std::string& path) {
    wchar_t win[MAX_PATH]{};
    if (!GetWindowsDirectoryW(win, MAX_PATH)) return false;
    const std::string root = to_lower(aiutil::to_utf8(win));
    return !root.empty() && to_lower(path).rfind(root, 0) == 0;
}

struct SignatureCache {
    std::map<std::string, std::string> cache;   // path -> status
    int checks = 0;
    int limit = 24;
    bool truncated = false;

    const std::string& status(const std::string& path) {
        static const std::string kUnknown = "not_checked";
        if (path.empty()) return kUnknown;
        auto it = cache.find(path);
        if (it != cache.end()) return it->second;
        if (checks >= limit) {
            truncated = true;
            return kUnknown;
        }
        ++checks;
        const LONG rc = quick_signed_rc(path);
        return cache.emplace(path, signature_status_text(rc)).first->second;
    }

    // 只有"确实没有签名"才算作未签名；校验失败不算
    bool clearly_unsigned(const std::string& path) { return status(path) == "no_signature"; }
};

// 一次调用内复用的模块列表缓存（按 pid）——绝不能做成函数内 static，那样会跨调用变脏
using ModuleCache = std::map<DWORD, ModuleList>;

const ModuleList& modules_for(ModuleCache& cache, DWORD pid) {
    auto it = cache.find(pid);
    if (it == cache.end()) it = cache.emplace(pid, collect_modules(pid)).first;
    return it->second;
}

// 窗口所属线程：起始地址 + 该地址的内存属性（是否落在非映像的可执行内存里）
json thread_start_info(DWORD tid, const std::vector<ModuleRange>& mods, HANDLE hproc) {
    json out = {{"tid", tid}};
    HANDLE ht = OpenThread(THREAD_QUERY_INFORMATION, FALSE, tid);
    if (!ht) ht = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, tid);
    if (!ht) {
        out["error"] = "OpenThread 失败（权限不足）";
        return out;
    }
    auto fn = reinterpret_cast<LONG(WINAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG)>(
        reinterpret_cast<void*>(
            GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationThread")));
    unsigned long long start = 0;
    if (fn && fn(ht, 9 /*ThreadQuerySetWin32StartAddress*/, &start, sizeof(start), nullptr) != 0)
        start = 0;
    CloseHandle(ht);

    if (!start) {
        out["start_address"] = nullptr;
        out["note"] = "读不到起始地址（权限不足）";
        return out;
    }
    out["start_address"] = hex_addr(start);
    const ModuleRange* mod = module_containing(mods, start);
    out["module"] = mod ? json(mod->name) : json(nullptr);
    out["in_image"] = mod != nullptr;

    if (hproc) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQueryEx(hproc, reinterpret_cast<LPCVOID>(start), &mbi, sizeof(mbi)) ==
            sizeof(mbi)) {
            out["protect"] = hex32(mbi.Protect);
            const bool exec = (mbi.Protect & 0xF0) != 0;
            if (mbi.Type & MEM_PRIVATE) {
                out["backed_by"] = "private";
                out["suspicious"] = exec && !mod;
            } else if (mbi.Type & MEM_IMAGE) {
                out["backed_by"] = "image";
                out["suspicious"] = false;
            } else if (mbi.Type & MEM_MAPPED) {
                out["backed_by"] = "mapped";
                out["suspicious"] = exec && !mod;
            }
        }
    }
    return out;
}

// ---------------- 桌面 / 窗口枚举 ----------------

struct WindowRow {
    HWND hwnd = nullptr;
    std::string station;
    std::string desktop;
};

struct DesktopFailure {
    std::string station;
    std::string desktop;
    std::string error;
};

struct EnumState {
    std::vector<WindowRow>* rows = nullptr;
    std::vector<DesktopFailure>* failures = nullptr;
    std::string station;
    std::string desktop;
    int collect_cap = 500;
    int skipped_by_limit = 0;
};

BOOL CALLBACK window_enum_proc(HWND hwnd, LPARAM param) {
    auto* st = reinterpret_cast<EnumState*>(param);
    if (static_cast<int>(st->rows->size()) >= st->collect_cap) {
        ++st->skipped_by_limit;
        return TRUE;
    }
    WindowRow row;
    row.hwnd = hwnd;
    row.station = st->station;
    row.desktop = st->desktop;
    st->rows->push_back(row);
    return TRUE;
}

struct StationCtx {
    EnumState* state = nullptr;
};

BOOL CALLBACK desktop_enum_proc(LPWSTR desk_name, LPARAM param) {
    auto* sc = reinterpret_cast<StationCtx*>(param);
    const std::string dn = aiutil::to_utf8(desk_name);
    HDESK desk = OpenDesktopW(desk_name, 0, FALSE, DESKTOP_ENUMERATE | DESKTOP_READOBJECTS);
    if (!desk) {
        sc->state->failures->push_back(
            {sc->state->station, dn, "OpenDesktop 失败（错误 " + std::to_string(GetLastError()) +
                                        "，其他 session 需要管理员）"});
        return TRUE;
    }
    sc->state->desktop = dn;
    EnumDesktopWindows(desk, window_enum_proc, reinterpret_cast<LPARAM>(sc->state));
    CloseDesktop(desk);
    return TRUE;
}

struct StationListCtx {
    HWINSTA* stations = nullptr;
    DWORD count = 0;
    DWORD cap = 0;
    std::vector<DesktopFailure>* failures = nullptr;
};

BOOL CALLBACK station_enum_proc(LPWSTR name, LPARAM param) {
    auto* sl = reinterpret_cast<StationListCtx*>(param);
    if (sl->count >= sl->cap) return TRUE;
    const std::string sn = aiutil::to_utf8(name);
    HWINSTA h = OpenWindowStationW(name, FALSE, WINSTA_ENUMDESKTOPS | WINSTA_READATTRIBUTES);
    if (!h) {
        sl->failures->push_back({sn, "",
                                 "OpenWindowStation 失败（错误 " +
                                     std::to_string(GetLastError()) + "，其他 session 需要管理员）"});
        return TRUE;
    }
    sl->stations[sl->count++] = h;
    return TRUE;
}

std::string current_station_name() {
    wchar_t buf[256]{};
    DWORD needed = 0;
    HWINSTA ws = GetProcessWindowStation();
    if (ws && GetUserObjectInformationW(ws, UOI_NAME, buf, sizeof(buf), &needed))
        return aiutil::to_utf8(buf);
    return "";
}

std::string current_desktop_name() {
    wchar_t buf[256]{};
    DWORD needed = 0;
    HDESK desk = GetThreadDesktop(GetCurrentThreadId());
    if (desk && GetUserObjectInformationW(desk, UOI_NAME, buf, sizeof(buf), &needed))
        return aiutil::to_utf8(buf);
    return "";
}

/*
 * 按 scope 枚举窗口：
 *   desktop  仅当前桌面（等价 EnumWindows；Win7/8 的默认路径）
 *   session  当前窗口站的所有桌面
 *   all      所有窗口站的所有桌面（其他 session 需要管理员；失败逐条记录）
 */
void enum_windows(const std::string& scope, int collect_cap, std::vector<WindowRow>* rows,
                  std::vector<DesktopFailure>* failures, int* skipped_by_limit) {
    EnumState state;
    state.rows = rows;
    state.failures = failures;
    state.collect_cap = collect_cap;
    state.station = current_station_name();
    state.desktop = current_desktop_name();

    if (scope == "desktop") {
        HDESK desk = GetThreadDesktop(GetCurrentThreadId());
        EnumDesktopWindows(desk, window_enum_proc, reinterpret_cast<LPARAM>(&state));
        *skipped_by_limit += state.skipped_by_limit;
        return;
    }

    const std::string cur_station = state.station;
    HWINSTA stations[32]{};
    StationListCtx sl;
    sl.stations = stations;
    sl.cap = 32;
    sl.failures = failures;
    if (!EnumWindowStationsW(station_enum_proc, reinterpret_cast<LPARAM>(&sl)) &&
        sl.count == 0) {
        // 枚举窗口站失败就退回当前桌面，至少给出结果
        failures->push_back({"", "", "EnumWindowStations 失败（错误 " +
                                          std::to_string(GetLastError()) +
                                          "），已退回当前桌面"});
        state.station = cur_station;
        state.desktop = current_desktop_name();
        HDESK desk = GetThreadDesktop(GetCurrentThreadId());
        EnumDesktopWindows(desk, window_enum_proc, reinterpret_cast<LPARAM>(&state));
        *skipped_by_limit += state.skipped_by_limit;
        return;
    }

    for (DWORD i = 0; i < sl.count; ++i) {
        wchar_t sname[256]{};
        DWORD needed = 0;
        std::string station_name;
        if (GetUserObjectInformationW(stations[i], UOI_NAME, sname, sizeof(sname), &needed))
            station_name = aiutil::to_utf8(sname);
        if (scope == "session" && !cur_station.empty() && station_name != cur_station) {
            CloseWindowStation(stations[i]);
            continue;
        }
        state.station = station_name;
        StationCtx sc;
        sc.state = &state;
        EnumDesktopsW(stations[i], desktop_enum_proc, reinterpret_cast<LPARAM>(&sc));
        CloseWindowStation(stations[i]);
    }
    *skipped_by_limit += state.skipped_by_limit;
}

// ---------------- 单窗口画像（list_windows 与 get_window_detail 共用） ----------------

json window_snapshot(HWND hwnd, const std::string& station, const std::string& desktop,
                     SignatureCache& sig, ModuleCache& mod_cache, bool detail) {
    json w = json::object();
    w["hwnd"] = hex_addr(reinterpret_cast<unsigned long long>(hwnd));

    wchar_t cls[256]{};
    if (GetClassNameW(hwnd, cls, 256)) w["class"] = aiutil::to_utf8(cls);
    const int tlen = GetWindowTextLengthW(hwnd);
    if (tlen > 0) {
        std::vector<wchar_t> buf(static_cast<size_t>(tlen) + 1, L'\0');
        if (GetWindowTextW(hwnd, buf.data(), tlen + 1))
            w["title"] = aiutil::to_utf8(std::wstring(buf.data()));
    } else {
        w["title"] = "";
    }
    if (!station.empty()) w["station"] = station;
    if (!desktop.empty()) w["desktop"] = desktop;

    DWORD pid = 0;
    const DWORD tid = GetWindowThreadProcessId(hwnd, &pid);
    w["pid"] = pid;
    w["tid"] = tid;
    const std::string path = process_image_path(pid);
    w["process"] = path.empty() ? json(nullptr) : json(file_name_of(path));
    w["process_path"] = path.empty() ? json(nullptr) : json(path);

    RECT r{};
    if (GetWindowRect(hwnd, &r))
        w["rect"] = {{"left", r.left},   {"top", r.top},
                     {"right", r.right}, {"bottom", r.bottom},
                     {"width", r.right - r.left},
                     {"height", r.bottom - r.top}};
    w["visible"] = IsWindowVisible(hwnd) != FALSE;
    if (detail) w["hung"] = IsHungAppWindow(hwnd) != FALSE;

    const LONG_PTR style = GetWindowLongPtrW(hwnd, GWL_STYLE);
    const LONG_PTR ex_style = GetWindowLongPtrW(hwnd, GWL_EXSTYLE);
    w["style"] = hex32(static_cast<unsigned long>(style));
    w["ex_style"] = hex32(static_cast<unsigned long>(ex_style));
    {
        json flags = json::array();
        if (ex_style & WS_EX_TOPMOST) flags.push_back("topmost");
        if (ex_style & WS_EX_TOOLWINDOW) flags.push_back("tool_window");   // 不进 Alt-Tab
        if (ex_style & WS_EX_LAYERED) flags.push_back("layered");
        if (ex_style & WS_EX_TRANSPARENT) flags.push_back("transparent");
        if (ex_style & WS_EX_NOACTIVATE) flags.push_back("no_activate");
        if (ex_style & WS_EX_APPWINDOW) flags.push_back("app_window");
        if (style & WS_POPUP) flags.push_back("popup");
        if (style & WS_CHILD) flags.push_back("child");
        if (style & WS_DISABLED) flags.push_back("disabled");
        if (!flags.empty()) w["style_flags"] = flags;
    }

    const ModuleList& ml = modules_for(mod_cache, pid);
    const std::vector<ModuleRange>& mods = ml.mods;
    const bool list_ok = ml.error.empty() && !ml.mods.empty();
    json findings = json::array();
    if (!list_ok) findings.push_back("module_list_unavailable");

    /*
     * 把模块的签名状态写进节点，并且只在"确实无签名、且不在系统目录"时才报可疑。
     * 系统目录里的文件多为 catalog 签名，WinVerifyTrust 在 catalog 校验不可用时
     * 也会返回 TRUST_E_NOSIGNATURE —— 安全工具不能据此给系统 DLL 挂"未签名"。
     */
    auto annotate_signature = [&](json& node, const std::string& path, const char* finding) {
        if (path.empty()) return;
        const std::string status = sig.status(path);
        node["signature"] = status;
        if (status != "no_signature") return;
        if (is_system_path(path)) {
            node["signature_note"] =
                "系统目录内文件多为 catalog 签名；catalog 校验不可用时 WinVerifyTrust 也会报无签名，"
                "不据此判定可疑（可用 verify_signature 复核）";
        } else if (finding) {
            findings.push_back(finding);
        }
    };

    // 1) 注册窗口类的模块：GCLP_HMODULE 是目标进程地址空间里的 HMODULE
    const unsigned long long class_mod =
        static_cast<unsigned long long>(GetClassLongPtrW(hwnd, GCLP_HMODULE));
    {
        json cm = {{"base", class_mod ? json(hex_addr(class_mod)) : json(nullptr)}};
        if (class_mod) {
            const ModuleRange* m = module_containing(mods, class_mod);
            if (m && m->base == class_mod) {
                cm["module"] = m->name;
                cm["path"] = m->path;
                cm["in_module_list"] = true;
                annotate_signature(cm, m->path, "class_module_unsigned");
            } else if (m) {
                cm["module"] = m->name;
                cm["path"] = m->path;
                cm["in_module_list"] = false;
                findings.push_back("class_module_base_inside_other_module");
            } else if (!list_ok) {
                // 列表读不到 → 不能判定"模块被隐藏"，只能说未知
                cm["in_module_list"] = nullptr;
                cm["module_list_error"] = ml.error;
            } else {
                cm["module"] = nullptr;
                cm["in_module_list"] = false;
                findings.push_back("class_module_not_in_loader_list");
            }
        }
        w["class_module"] = cm;
    }

    /*
     * 2) 处理消息的代码地址。跨进程读 GWLP_WNDPROC（实例 WndProc）会被系统拒绝
     *    （错误 5），所以主力是 GCLP_WNDPROC（类 WndProc，跨进程可读）——对
     *    "恶意 DLL 自己注册窗口类"的场景，这个指针就是它的代码。
     *    本进程内的窗口两者都能读，可以顺带看出是否被子类化。
     */
    auto clean_addr = [&](unsigned long long addr, const char* finding_prefix, json& node) {
        node["addr"] = addr ? json(hex_addr(addr)) : json(nullptr);
        if (!addr) return;
        const ModuleRange* m = module_containing(mods, addr);
        if (m) {
            node["module"] = m->name;
            node["in_module_list"] = true;
            node["path"] = m->path;
            annotate_signature(node, m->path, nullptr);
        } else if (!list_ok) {
            node["module"] = nullptr;
            node["in_module_list"] = nullptr;   // 未知，不是"被隐藏"
            node["module_list_error"] = ml.error;
        } else {
            node["module"] = nullptr;
            node["in_module_list"] = false;
        }
        HANDLE hp = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!hp) return;
        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQueryEx(hp, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) == sizeof(mbi)) {
            node["protect"] = hex32(mbi.Protect);
            const bool exec = (mbi.Protect & 0xF0) != 0;
            if (mbi.Type & MEM_PRIVATE) {
                node["backed_by"] = "private";
                if (exec && !m) {
                    node["private_executable"] = true;
                    findings.push_back(std::string(finding_prefix) + "_in_private_executable");
                }
            } else if (mbi.Type & MEM_IMAGE) {
                node["backed_by"] = "image";
                // 只有在模块列表可用时才敢说"映像不在模块列表里"
                if (!m && list_ok)
                    findings.push_back(std::string(finding_prefix) + "_image_not_in_module_list");
            } else if (mbi.Type & MEM_MAPPED) {
                node["backed_by"] = "mapped";
                if (exec && !m)
                    findings.push_back(std::string(finding_prefix) + "_in_mapped_executable");
            }
        }
        CloseHandle(hp);
    };

    const unsigned long long class_wndproc =
        static_cast<unsigned long long>(GetClassLongPtrW(hwnd, GCLP_WNDPROC));
    json cwp = json::object();
    clean_addr(class_wndproc, "class_wndproc", cwp);
    w["class_wndproc"] = cwp;

    SetLastError(0xDEADBEEF);
    const unsigned long long inst_wndproc =
        static_cast<unsigned long long>(GetWindowLongPtrW(hwnd, GWLP_WNDPROC));
    const DWORD inst_err = GetLastError();
    json iwp = json::object();
    if (inst_wndproc) {
        clean_addr(inst_wndproc, "wndproc", iwp);
        if (class_wndproc && inst_wndproc != class_wndproc)
            findings.push_back("window_subclassed");   // 实例 WndProc 与类 WndProc 不同
    } else {
        iwp["addr"] = nullptr;
        if (inst_err == ERROR_ACCESS_DENIED)
            iwp["error"] = "跨进程读取实例 WNDPROC 被系统拒绝（错误 5）；"
                           "已用 class_wndproc（类 WndProc）代替。"
                           "实例级子类化在本进程外无法观测";
        else
            iwp["error"] = "读取失败（错误 " + std::to_string(inst_err) + "）";
    }
    w["wndproc"] = iwp;

    if (detail) {
        // 属主链（GW_OWNER）与父链（GetParent）
        json owners = json::array();
        for (HWND cur = GetWindow(hwnd, GW_OWNER); cur && owners.size() < 8;
             cur = GetWindow(cur, GW_OWNER)) {
            wchar_t c2[256]{};
            std::string cn;
            if (GetClassNameW(cur, c2, 256)) cn = aiutil::to_utf8(c2);
            DWORD opid = 0;
            GetWindowThreadProcessId(cur, &opid);
            owners.push_back({{"hwnd", hex_addr(reinterpret_cast<unsigned long long>(cur))},
                              {"class", cn},
                              {"pid", opid},
                              {"process", file_name_of(process_image_path(opid))}});
        }
        w["owner_chain"] = owners;

        json parents = json::array();
        for (HWND cur = GetParent(hwnd); cur && parents.size() < 8; cur = GetParent(cur)) {
            wchar_t c2[256]{};
            std::string cn;
            if (GetClassNameW(cur, c2, 256)) cn = aiutil::to_utf8(c2);
            parents.push_back({{"hwnd", hex_addr(reinterpret_cast<unsigned long long>(cur))},
                               {"class", cn}});
        }
        w["parent_chain"] = parents;

        HANDLE hp = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!hp) hp = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        json th = thread_start_info(tid, mods, hp);
        if (th.value("suspicious", false)) findings.push_back("window_thread_start_suspicious");
        if (th.contains("start_address") && !th["start_address"].is_null() &&
            !th.value("in_image", true))
            findings.push_back("window_thread_start_outside_image");
        w["thread"] = th;
        if (hp) CloseHandle(hp);

        // 进程侧抽样：最多校验 8 个模块的签名（只把"非系统目录且确实无签名"的算进来）
        json unsigned_mods = json::array();
        int checked = 0;
        for (const auto& m : mods) {
            if (checked >= 8) break;
            if (m.path.empty()) continue;
            ++checked;
            if (sig.status(m.path) == "no_signature" && !is_system_path(m.path))
                unsigned_mods.push_back(m.name);
        }
        w["process_unsigned_modules_sample"] = unsigned_mods;
        w["process_module_count"] = static_cast<long long>(mods.size());
        w["module_list_source"] = ml.source.empty() ? json(nullptr) : json(ml.source);
        if (!list_ok) w["module_list_error"] = ml.error;
    }

    if (!findings.empty()) w["findings"] = findings;
    return w;
}

// 等窗口真的消失（关闭结果校验）
bool wait_window_gone(HWND hwnd, int timeout_ms) {
    for (int waited = 0; waited < timeout_ms; waited += 50) {
        if (!IsWindow(hwnd)) return true;
        Sleep(50);
    }
    return !IsWindow(hwnd);
}

}  // namespace

namespace aiext {

std::string t_list_windows(const json& args, AiContext&) {
    int limit = static_cast<int>(arg_int(args, "limit", 100));
    limit = std::min(std::max(limit, 1), 1000);
    std::string scope = to_lower(arg_str(args, "scope", "auto"));
    if (scope != "auto" && scope != "desktop" && scope != "session" && scope != "all")
        return ERR("scope 取值 desktop|session|all|auto，收到: " + scope);
    const int major = windows_major_version();
    if (scope == "auto") scope = (major >= 10) ? "all" : "desktop";   // Win10+ 多桌面；Win7 单桌面
    const std::string title_kw = to_lower(arg_str(args, "title_contains"));
    const std::string class_kw = to_lower(arg_str(args, "class_contains"));
    const long long pid_filter = arg_int(args, "pid", 0);
    const bool visible_only = arg_bool(args, "visible_only", false);

    // 收集上限：过滤在收集之后做，所以收集面要足够宽（有硬上限，避免超大桌面拖慢）
    const int collect_cap = 4000;
    std::vector<WindowRow> rows;
    std::vector<DesktopFailure> failures;
    int skipped_by_limit = 0;
    enum_windows(scope, collect_cap, &rows, &failures, &skipped_by_limit);

    SignatureCache sig;
    ModuleCache mod_cache;
    json windows = json::array();
    long long matched = 0;
    bool truncated = skipped_by_limit > 0;
    for (const auto& row : rows) {
        HWND hwnd = row.hwnd;
        if (!IsWindow(hwnd)) continue;
        if (pid_filter > 0) {
            DWORD pid = 0;
            GetWindowThreadProcessId(hwnd, &pid);
            if (pid != static_cast<DWORD>(pid_filter)) continue;
        }
        if (visible_only && !IsWindowVisible(hwnd)) continue;
        if (!title_kw.empty()) {
            wchar_t buf[512]{};
            GetWindowTextW(hwnd, buf, 512);
            if (to_lower(aiutil::to_utf8(buf)).find(title_kw) == std::string::npos) continue;
        }
        if (!class_kw.empty()) {
            wchar_t buf[256]{};
            GetClassNameW(hwnd, buf, 256);
            if (to_lower(aiutil::to_utf8(buf)).find(class_kw) == std::string::npos) continue;
        }
        ++matched;
        if (static_cast<int>(windows.size()) >= limit) {
            truncated = true;
            continue;
        }
        windows.push_back(window_snapshot(hwnd, row.station, row.desktop, sig, mod_cache, false));
    }

    json skipped = json::array();
    for (const auto& f : failures)
        skipped.push_back({{"station", f.station}, {"desktop", f.desktop}, {"error", f.error}});

    json out = {{"count", windows.size()},
                {"matched", matched},
                {"truncated", truncated},
                {"scope", scope},
                {"windows", windows},
                {"diagnostics",
                 {{"windows_os_major", major},
                  {"enumerated", static_cast<long long>(rows.size())},
                  {"collect_cap", collect_cap},
                  {"skipped_by_collect_cap", skipped_by_limit},
                  {"signature_checks", sig.checks},
                  {"signature_checks_truncated", sig.truncated},
                  {"skipped_desktops", skipped}}}};
    if (!skipped.empty())
        out["note"] = "部分窗口站/桌面打不开（多为其他 session，需要管理员）；"
                      "见 diagnostics.skipped_desktops";
    if (windows.empty())
        out["note"] = out.contains("note")
                          ? out["note"].get<std::string>() + "；当前范围没有匹配的窗口"
                          : "当前范围没有匹配的窗口（可用 scope=\"all\" 扩大范围）";
    return aiutil::dump_json(out);
}

std::string t_get_window_detail(const json& args, AiContext&) {
    bool ok = false;
    const unsigned long long raw = parse_hwnd(args, "hwnd", &ok);
    if (!ok) return ERR("hwnd 必填，格式如 \"0x00010A2C\" 或十进制 68140");
    HWND hwnd = reinterpret_cast<HWND>(static_cast<ULONG_PTR>(raw));
    if (!IsWindow(hwnd)) return ERR("窗口不存在或已销毁: " + hex_addr(raw));

    SignatureCache sig;
    ModuleCache mod_cache;
    json w = window_snapshot(hwnd, current_station_name(), current_desktop_name(), sig, mod_cache,
                             true);
    w["diagnostics"] = {{"signature_checks", sig.checks},
                        {"signature_checks_truncated", sig.truncated}};
    const long long pid = w.value("pid", 0LL);
    w["next_steps"] = json::array(
        {"list_process_modules {\"pid\": " + std::to_string(pid) + ", \"filter\": \"unsigned\"}",
         "scan_memory_regions {\"pid\": " + std::to_string(pid) + "}",
         "list_threads {\"pid\": " + std::to_string(pid) + "}",
         "verify_signature {\"path\": \"<class_module.path>\"}"});
    return aiutil::dump_json(w);
}

/*
 * {"hwnd":"0x...","method":"wm_close|end_task","dry_run":bool}
 *
 * 跨进程能用的关闭方式只有两类：
 *   - PostMessage(WM_CLOSE)：礼貌请求，程序可以弹"是否保存"并拒绝关闭；
 *   - EndTask：等价任务管理器的"结束任务"，对卡死窗口有效（user32 导出）。
 * 注意：**不能**跨进程 PostMessage(WM_DESTROY)。WM_DESTROY 是 DestroyWindow 内部发出的
 * 通知，直接投递给别人的窗口既不会销毁窗口，还可能让目标进程状态不一致；
 * DestroyWindow 本身也只能销毁本线程创建的窗口。要强制关就用 end_task，
 * 要结束整个进程用 kill_process / kill_process_tree。
 */
std::string t_close_window(const json& args, AiContext& ctx) {
    bool ok = false;
    const unsigned long long raw = parse_hwnd(args, "hwnd", &ok);
    if (!ok) return ERR("hwnd 必填，格式如 \"0x00010A2C\" 或十进制 68140");
    HWND hwnd = reinterpret_cast<HWND>(static_cast<ULONG_PTR>(raw));
    if (!IsWindow(hwnd)) return ERR("窗口不存在或已销毁: " + hex_addr(raw));

    const std::string method = to_lower(arg_str(args, "method", "wm_close"));
    if (method != "wm_close" && method != "end_task") {
        if (method == "wm_destroy" || method == "destroy")
            return ERR("不支持直接投递 WM_DESTROY：它是 DestroyWindow 内部发出的通知，"
                       "跨进程投递不会销毁窗口，还可能让目标进程状态不一致。"
                       "请用 method=\"wm_close\"（礼貌关闭）或 method=\"end_task\"（强制结束，"
                       "等价任务管理器）；要结束整个进程用 kill_process_tree。");
        return ERR("method 取值 wm_close|end_task，收到: " + method);
    }

    DWORD pid = 0;
    const DWORD tid = GetWindowThreadProcessId(hwnd, &pid);
    wchar_t cls[256]{};
    GetClassNameW(hwnd, cls, 256);
    wchar_t title[512]{};
    GetWindowTextW(hwnd, title, 512);
    const std::string path = process_image_path(pid);
    const std::string proc = file_name_of(path);

    // 关键进程护栏：动这些进程的窗口会直接影响登录/桌面/服务
    static const char* const kCritical[] = {"csrss.exe", "winlogon.exe", "lsass.exe", "smss.exe",
                                            "services.exe", "wininit.exe", "svchost.exe"};
    const std::string low_proc = to_lower(proc);
    for (const char* c : kCritical) {
        if (low_proc == c)
            return ERR(std::string("拒绝关闭关键进程的窗口: ") + proc +
                       "（可能造成登录/桌面异常）；如确需处置请用进程级工具并人工确认");
    }

    json info = {{"hwnd", hex_addr(raw)},
                 {"class", aiutil::to_utf8(cls)},
                 {"title", aiutil::to_utf8(title)},
                 {"pid", pid},
                 {"tid", tid},
                 {"process", proc.empty() ? json(nullptr) : json(proc)},
                 {"process_path", path.empty() ? json(nullptr) : json(path)},
                 {"method", method}};

    if (dry_run_requested(args, ctx)) {
        info["dry_run"] = true;
        info["planned_message"] = (method == "wm_close") ? "PostMessage(WM_CLOSE)" : "EndTask";
        info["note"] = "仅演练：没有向窗口投递任何消息";
        return aiutil::dump_json(info);
    }

    if (method == "wm_close") {
        info["sent"] = "WM_CLOSE";
        const BOOL posted = PostMessageW(hwnd, WM_CLOSE, 0, 0);
        info["post_ok"] = posted != FALSE;
        if (!posted) info["post_error"] = static_cast<long long>(GetLastError());
        info["closed"] = wait_window_gone(hwnd, 1500);
    } else {
        info["sent"] = "EndTask";
        using EndTaskFn = BOOL(WINAPI*)(HWND, BOOL, BOOL);
        auto fn = reinterpret_cast<EndTaskFn>(
            reinterpret_cast<void*>(GetProcAddress(GetModuleHandleW(L"user32.dll"), "EndTask")));
        if (!fn) return ERR("当前系统没有 EndTask 导出，请改用 method=\"wm_close\"");
        info["end_task_ok"] = fn(hwnd, FALSE, FALSE) != FALSE;
        info["closed"] = wait_window_gone(hwnd, 3000);
    }
    if (!info["closed"].get<bool>())
        info["note"] = "窗口仍在：程序可能弹了确认框或被别的代码阻止关闭。"
                       "可改用 method=\"end_task\" 强制结束，或终止其所属进程（kill_process_tree）。";
    return aiutil::dump_json(info);
}

}  // namespace aiext
