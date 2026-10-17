// ai_tools_reg.cpp - AI 工具扩展库：注册表/持久化组
// 契约见 ai_tools_ext.h 第三节；审计由 ai_execute_tool 统一完成。
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
#include <objbase.h>
#include <oleauto.h>
#include <psapi.h>
#include <winreg.h>
#include <winsvc.h>

#include <wbemcli.h>

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
    if (it->is_string()) { try { return std::stoll(it->get<std::string>()); } catch (...) { return def; } }
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

// ---------------- 注册表通用 ----------------

// 解析 "HKLM/SOFTWARE/xxx" 或 "HKEY_LOCAL_MACHINE\SOFTWARE\xxx" → 根键 + 子路径
// 子路径里的正斜杠一律换成反斜杠：RegOpenKeyExW 只认 "\"，"HKLM/SOFTWARE/Microsoft"
// 这种写法以前会被当成「键不存在（错误 2）」。
bool parse_reg_key(const std::string& key, HKEY* root, std::wstring* sub) {
    if (key.empty()) return false;
    size_t sep = key.find_first_of("/\\");
    std::string head = to_lower(sep == std::string::npos ? key : key.substr(0, sep));
    std::string rest = (sep == std::string::npos) ? std::string() : key.substr(sep + 1);
    for (char& c : rest)
        if (c == '/') c = '\\';
    while (!rest.empty() && rest.back() == '\\') rest.pop_back();

    HKEY r = nullptr;
    if (head == "hklm" || head == "hkey_local_machine") r = HKEY_LOCAL_MACHINE;
    else if (head == "hkcu" || head == "hkey_current_user") r = HKEY_CURRENT_USER;
    else if (head == "hkcr" || head == "hkey_classes_root") r = HKEY_CLASSES_ROOT;
    else if (head == "hku" || head == "hkey_users") r = HKEY_USERS;
    else if (head == "hkcc" || head == "hkey_current_config") r = HKEY_CURRENT_CONFIG;
    else return false;

    *root = r;
    *sub = aiutil::to_wide(rest);
    return true;
}

// 打开键（读或写），失败返回错误文本；sub 为空表示根键本身
HKEY open_reg(const std::string& key, REGSAM access, std::string& err) {
    HKEY root = nullptr;
    std::wstring sub;
    if (!parse_reg_key(key, &root, &sub)) {
        err = "键格式无效（应形如 HKLM/SOFTWARE/...）: " + key;
        return nullptr;
    }
    HKEY h = nullptr;
    LSTATUS rc = RegOpenKeyExW(root, sub.c_str(), 0, access, &h);
    if (rc != ERROR_SUCCESS) {
        err = "打开注册表失败（错误 " + std::to_string(rc) +
              (rc == 5 ? "，需要管理员" : rc == 2 ? "，键不存在" : "") + "）: " + key;
        return nullptr;
    }
    return h;
}

struct RegValueInfo {
    std::string name;
    std::string data;      // 已转成展示文本
    DWORD type = 0;
};

std::string reg_data_to_text(DWORD type, const std::vector<unsigned char>& raw) {
    if (type == REG_SZ || type == REG_EXPAND_SZ || type == REG_MULTI_SZ) {
        if (raw.empty()) return "";
        std::wstring w(reinterpret_cast<const wchar_t*>(raw.data()),
                       raw.size() / sizeof(wchar_t));
        if (type == REG_MULTI_SZ) {
            std::string out;
            size_t start = 0;
            while (start < w.size()) {
                size_t end = w.find(L'\0', start);
                if (end == std::wstring::npos) break;
                if (end > start) {
                    if (!out.empty()) out += "; ";
                    out += aiutil::to_utf8(w.substr(start, end - start));
                }
                start = end + 1;
                if (start + 1 < w.size() && w[start] == L'\0') break;  // 双 NUL 结束
            }
            return out;
        }
        while (!w.empty() && w.back() == L'\0') w.pop_back();
        return aiutil::to_utf8(w);
    }
    if (type == REG_DWORD && raw.size() >= 4) {
        DWORD v = *reinterpret_cast<const DWORD*>(raw.data());
        return std::to_string(v);
    }
    if (type == REG_QWORD && raw.size() >= 8) {
        unsigned long long v = *reinterpret_cast<const unsigned long long*>(raw.data());
        return std::to_string(v);
    }
    if (type == REG_BINARY) {
        static const char* hx = "0123456789abcdef";
        std::string out;
        size_t n = std::min<size_t>(raw.size(), 32);
        out.reserve(n * 2);
        for (size_t i = 0; i < n; ++i) {
            out += hx[raw[i] >> 4];
            out += hx[raw[i] & 0xF];
        }
        if (raw.size() > 32) out += "...";
        return out;
    }
    return "<类型 " + std::to_string(type) + ">";
}

// 枚举一个键下的全部值（不带子键）；上限 max_values
std::vector<RegValueInfo> enum_reg_values(HKEY h, int max_values) {
    std::vector<RegValueInfo> out;
    for (DWORD idx = 0; static_cast<int>(out.size()) < max_values; ++idx) {
        wchar_t name[512]{};
        DWORD name_len = 512;
        DWORD type = 0;
        std::vector<unsigned char> data(2048);
        DWORD data_len = static_cast<DWORD>(data.size());
        LSTATUS rc = RegEnumValueW(h, idx, name, &name_len, nullptr, &type, data.data(), &data_len);
        if (rc == ERROR_MORE_DATA) {
            data.resize(data_len + 16);
            data_len = static_cast<DWORD>(data.size());
            rc = RegEnumValueW(h, idx, name, &name_len, nullptr, &type, data.data(), &data_len);
        }
        if (rc == ERROR_NO_MORE_ITEMS) break;
        if (rc != ERROR_SUCCESS) break;
        RegValueInfo info;
        info.name = aiutil::to_utf8(std::wstring(name, name_len));
        info.type = type;
        data.resize(data_len);
        info.data = reg_data_to_text(type, data);
        out.push_back(info);
    }
    return out;
}

// 读一个值；不存在返回 false
bool read_reg_value(const std::string& key, const std::string& value_name, RegValueInfo* out) {
    std::string err;
    HKEY h = open_reg(key, KEY_READ, err);
    if (!h) return false;
    std::wstring vname = aiutil::to_wide(value_name);
    DWORD type = 0;
    std::vector<unsigned char> data(2048);
    DWORD len = static_cast<DWORD>(data.size());
    LSTATUS rc = RegQueryValueExW(h, vname.c_str(), nullptr, &type, data.data(), &len);
    if (rc == ERROR_MORE_DATA) {
        data.resize(len + 16);
        len = static_cast<DWORD>(data.size());
        rc = RegQueryValueExW(h, vname.c_str(), nullptr, &type, data.data(), &len);
    }
    RegCloseKey(h);
    if (rc != ERROR_SUCCESS) return false;
    data.resize(len);
    if (out) {
        out->name = value_name;
        out->type = type;
        out->data = reg_data_to_text(type, data);
    }
    return true;
}

std::vector<std::string> enum_reg_subkeys(HKEY h, int max_keys) {
    std::vector<std::string> out;
    for (DWORD idx = 0; static_cast<int>(out.size()) < max_keys; ++idx) {
        wchar_t name[512]{};
        DWORD name_len = 512;
        LSTATUS rc = RegEnumKeyExW(h, idx, name, &name_len, nullptr, nullptr, nullptr, nullptr);
        if (rc == ERROR_NO_MORE_ITEMS) break;
        if (rc != ERROR_SUCCESS) break;
        out.push_back(aiutil::to_utf8(std::wstring(name, name_len)));
    }
    return out;
}

// ---------------- WMI（root\subscription） ----------------

/*
 * GUID 必须手写：MinGW 没有 wbemuuid 库，wbemcli.h 里只有 extern 声明（链接会
 * undefined reference）。下面的值与 wbemcli.h 里的 DEFINE_GUID 逐字节一致：
 *   CLSID_WbemLocator = 4590F811-1D3A-11D0-891F-00AA004B2E24
 *   IID_IWbemLocator  = DC12A687-737F-11CF-884D-00AA004B2E24
 * 曾经把 IID 误写成 4590F812-... ，CoCreateInstance 返回 E_NOINTERFACE
 * (0x80004002)，表现为「WMI 不可用」，实际是这套 GUID 写错。
 */
const CLSID kCLSID_WbemLocator = {0x4590F811, 0x1D3A, 0x11D0,
                                  {0x89, 0x1F, 0x00, 0xAA, 0x00, 0x4B, 0x2E, 0x24}};
const IID kIID_IWbemLocator = {0xDC12A687, 0x737F, 0x11CF,
                               {0x88, 0x4D, 0x00, 0xAA, 0x00, 0x4B, 0x2E, 0x24}};

std::string hresult_hex(HRESULT hr) {
    char buf[16];
    std::snprintf(buf, sizeof(buf), "0x%08lx", static_cast<unsigned long>(hr));
    return buf;
}

// 把常见 HRESULT / WBEM 错误码翻译成人能看懂的处置建议
std::string hresult_hint(HRESULT hr) {
    switch (static_cast<unsigned long>(hr)) {
    case 0x80041003:  // WBEM_E_ACCESS_DENIED
        return "（拒绝访问：root\\subscription 命名空间受限，需以管理员身份运行）";
    case 0x8004100E:  // WBEM_E_INVALID_NAMESPACE
        return "（命名空间不存在：WMI 仓库可能损坏，可运行 winmgmt /verifyrepository 检查）";
    case 0x80041064:  // WBEM_E_LOCAL_CREDENTIALS
        return "（本地连接不能带用户名/密码，必须传 NULL）";
    case 0x80040154:  // REGDB_E_CLASSNOTREG
        return "（WMI 类未注册：Winmgmt 服务可能被禁用，可试 net start Winmgmt）";
    case 0x80004002:  // E_NOINTERFACE
        return "（接口不支持：WMI 注册异常）";
    case 0x800401F0:  // CO_E_NOTINITIALIZED
        return "（COM 未初始化）";
    default:
        return "";
    }
}

struct WmiSession {
    bool coinited = false;
    IWbemLocator* loc = nullptr;
    IWbemServices* svc = nullptr;

    ~WmiSession() {
        if (svc) svc->Release();
        if (loc) loc->Release();
        if (coinited) CoUninitialize();
    }

    bool connect(std::string& err) {
        HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
            err = "CoInitializeEx 失败 " + hresult_hex(hr) + hresult_hint(hr);
            return false;
        }
        if (SUCCEEDED(hr)) coinited = true;

        // 进程内 + 本地服务器都允许：个别系统只注册了其中之一
        hr = CoCreateInstance(kCLSID_WbemLocator, nullptr,
                              CLSCTX_INPROC_SERVER | CLSCTX_LOCAL_SERVER,
                              kIID_IWbemLocator, reinterpret_cast<void**>(&loc));
        if (FAILED(hr) || !loc) {
            loc = nullptr;
            err = "CoCreateInstance(WbemLocator) 失败 " + hresult_hex(hr) + hresult_hint(hr);
            return false;
        }

        // 本地连接：用户名/密码必须是 NULL，传空字符串会返回 WBEM_E_LOCAL_CREDENTIALS
        BSTR ns = SysAllocString(L"ROOT\\SUBSCRIPTION");
        hr = loc->ConnectServer(ns, nullptr, nullptr, nullptr, 0, nullptr, nullptr, &svc);
        SysFreeString(ns);
        if (FAILED(hr) || !svc) {
            svc = nullptr;
            err = "ConnectServer(ROOT\\SUBSCRIPTION) 失败 " + hresult_hex(hr) + hresult_hint(hr);
            return false;
        }
        CoSetProxyBlanket(svc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
                          RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);
        return true;
    }

    // 执行查询，逐对象回调；返回对象数量（失败返回 -1）
    int query(const wchar_t* wql, const std::function<void(IWbemClassObject*)>& cb) {
        if (!svc) return -1;
        BSTR lang = SysAllocString(L"WQL");
        BSTR q = SysAllocString(wql);
        IEnumWbemClassObject* en = nullptr;
        HRESULT hr = svc->ExecQuery(lang, q, WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                                    nullptr, &en);
        SysFreeString(lang); SysFreeString(q);
        if (FAILED(hr) || !en) return -1;
        int count = 0;
        for (;;) {
            IWbemClassObject* obj = nullptr;
            ULONG got = 0;
            hr = en->Next(WBEM_INFINITE, 1, &obj, &got);
            if (hr != WBEM_S_NO_ERROR || got == 0 || !obj) break;
            cb(obj);
            obj->Release();
            ++count;
            if (count > 200) break;
        }
        en->Release();
        return count;
    }

    static std::string get_str(IWbemClassObject* obj, const wchar_t* prop) {
        VARIANT v{};
        VariantInit(&v);
        std::string out;
        if (SUCCEEDED(obj->Get(prop, 0, &v, nullptr, nullptr))) {
            if (v.vt == VT_BSTR && v.bstrVal) out = aiutil::to_utf8(v.bstrVal);
            else if (v.vt == VT_I4) out = std::to_string(v.lVal);
        }
        VariantClear(&v);
        return out;
    }

    static std::wstring get_wstr(IWbemClassObject* obj, const wchar_t* prop) {
        VARIANT v{};
        VariantInit(&v);
        std::wstring out;
        if (SUCCEEDED(obj->Get(prop, 0, &v, nullptr, nullptr)) && v.vt == VT_BSTR && v.bstrVal)
            out = v.bstrVal;
        VariantClear(&v);
        return out;
    }

    // 删除对象（按 __RELPATH）
    bool delete_by_relpath(const std::wstring& relpath, std::string& err) {
        BSTR path = SysAllocString(relpath.c_str());
        HRESULT hr = svc->DeleteInstance(path, 0, nullptr, nullptr);
        SysFreeString(path);
        if (FAILED(hr)) {
            err = "DeleteInstance 失败: 0x" + std::to_string(hr);
            return false;
        }
        return true;
    }
};

// ---------------- 服务 ----------------

bool stop_service_internal(const std::string& name, int wait_seconds, std::string& err) {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!scm) {
        err = "OpenSCManager 失败（需要管理员，错误 " + std::to_string(GetLastError()) + "）";
        return false;
    }
    SC_HANDLE svc = OpenServiceW(scm, aiutil::to_wide_sys(name).c_str(),
                                 SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (!svc) {
        err = "服务不存在或无权限: " + name + "（错误 " + std::to_string(GetLastError()) + "）";
        CloseServiceHandle(scm);
        return false;
    }
    SERVICE_STATUS st{};
    bool ok = false;
    if (ControlService(svc, SERVICE_CONTROL_STOP, &st)) {
        for (int i = 0; i < wait_seconds; ++i) {
            if (!QueryServiceStatus(svc, &st)) break;
            if (st.dwCurrentState == SERVICE_STOPPED) { ok = true; break; }
            Sleep(1000);
        }
        if (!ok && st.dwCurrentState == SERVICE_STOPPED) ok = true;
    } else {
        DWORD e = GetLastError();
        if (QueryServiceStatus(svc, &st) && st.dwCurrentState == SERVICE_STOPPED) {
            ok = true;
        } else {
            err = "停止服务失败（错误 " + std::to_string(e) + "）";
        }
    }
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return ok;
}

bool delete_service_internal(const std::string& name, std::string& err) {
    // 先停（忽略停止失败：可能本来就是停止态）
    std::string stop_err;
    stop_service_internal(name, 10, stop_err);

    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!scm) {
        err = "OpenSCManager 失败（需要管理员，错误 " + std::to_string(GetLastError()) + "）";
        return false;
    }
    SC_HANDLE svc = OpenServiceW(scm, aiutil::to_wide_sys(name).c_str(), DELETE | SERVICE_QUERY_STATUS);
    if (!svc) {
        err = "服务不存在或无权限: " + name;
        CloseServiceHandle(scm);
        return false;
    }
    BOOL ok = DeleteService(svc);
    if (!ok) err = "DeleteService 失败（错误 " + std::to_string(GetLastError()) + "）";
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return ok != FALSE;
}

std::string delete_task_internal(const std::string& name) {
    std::string cmd = "schtasks /delete /tn \"" + name + "\" /f";
    return aiext::run_capture(cmd, 30000, 4000);
}

std::string hex(unsigned long long a) {
    char buf[24];
    std::snprintf(buf, sizeof(buf), "0x%llx", a);
    return buf;
}

// 检查路径是否可疑（TEMP/AppData/ProgramData/无引号含空格）
std::string path_suspicion(const std::string& p) {
    std::string low = to_lower(p);
    if (low.find("%temp%") != std::string::npos || low.find("\\appdata\\") != std::string::npos ||
        low.find("\\programdata\\") != std::string::npos)
        return "路径位于用户可写目录（TEMP/AppData/ProgramData）";
    if (!p.empty() && p[0] != '"' && p.find(" ") != std::string::npos &&
        low.find("system32") == std::string::npos && low.find("program files") == std::string::npos)
        return "路径含空格但未加引号（可被劫持）";
    return "";
}

}  // namespace

namespace aiext {

std::string t_enumerate_registry_tree(const json& args, AiContext&) {
    std::string key = arg_str(args, "key");
    int depth = static_cast<int>(arg_int(args, "depth", 2));
    bool want_values = arg_bool(args, "values", true);
    int limit = static_cast<int>(arg_int(args, "limit", 200));
    depth = std::min(std::max(depth, 0), 5);
    limit = std::min(std::max(limit, 1), 2000);

    std::string err;
    HKEY root_h = open_reg(key, KEY_READ, err);
    if (!root_h) return ERR(err);
    RegCloseKey(root_h);
    HKEY root = nullptr;
    std::wstring sub;
    parse_reg_key(key, &root, &sub);

    json items = json::array();
    int count = 0;
    bool truncated = false;

    std::function<void(HKEY, const std::string&, int)> walk =
        [&](HKEY h, const std::string& path, int d) {
            if (count >= limit) { truncated = true; return; }
            if (want_values) {
                for (const auto& v : enum_reg_values(h, 200)) {
                    if (count >= limit) { truncated = true; return; }
                    items.push_back({{"type", "value"}, {"path", path}, {"name", v.name},
                                     {"data", v.data}});
                    ++count;
                }
            }
            if (d >= depth) return;
            HKEY cur = nullptr;
            for (const auto& sub_name : enum_reg_subkeys(h, 500)) {
                if (count >= limit) { truncated = true; return; }
                if (RegOpenKeyExW(h, aiutil::to_wide(sub_name).c_str(), 0, KEY_READ, &cur) !=
                    ERROR_SUCCESS)
                    continue;
                std::string child = path + "\\" + sub_name;
                if (count >= limit) { truncated = true; RegCloseKey(cur); return; }
                items.push_back({{"type", "key"}, {"path", child}, {"name", sub_name},
                                 {"data", nullptr}});
                ++count;
                walk(cur, child, d + 1);
                RegCloseKey(cur);
            }
        };

    HKEY h = open_reg(key, KEY_READ, err);
    if (!h) return ERR(err);
    walk(h, key, 0);
    RegCloseKey(h);

    json out = {{"key", key}, {"count", count}, {"truncated", truncated}, {"items", items}};
    if (count == 0) {
        out["note"] = (depth <= 0 && !want_values)
                          ? "depth=0 且 values=false：没有任何可返回的内容；"
                            "把 depth 设为 >=1 看子键，或 values=true 看值"
                          : "该键下没有可返回的值/子键（键可能不存在或没有内容）";
    }
    return aiutil::dump_json(out);
}

std::string t_check_persistence(const json& /*args*/, AiContext&) {
    json findings = json::array();
    int count = 0;
    const int kLimit = 500;
    bool truncated = false;
    auto add = [&](const std::string& loc, const std::string& value, const std::string& data,
                   const std::string& suspicion, const std::string& note) {
        if (count >= kLimit) { truncated = true; return; }
        json f = {{"location", loc}, {"value", value}, {"data", data}, {"suspicion", suspicion}};
        if (!note.empty()) f["note"] = note;
        findings.push_back(f);
        ++count;
    };

    // 1. Run / RunOnce（HKLM + HKCU）
    for (const char* hive : {"HKLM", "HKCU"}) {
        for (const char* sub : {"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                                "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"}) {
            std::string key = std::string(hive) + "/" + sub;
            std::string err;
            HKEY h = open_reg(key, KEY_READ, err);
            if (!h) continue;
            for (const auto& v : enum_reg_values(h, 100)) {
                std::string s = path_suspicion(v.data);
                add(key, v.name, v.data, s.empty() ? "low" : "high", s);
            }
            RegCloseKey(h);
        }
    }

    // 2. Winlogon（Shell/Userinit/AppInit_DLLs + Wow6432Node）
    for (const char* base :
         {"HKLM/SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
          "HKLM/SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"}) {
        for (const char* val : {"Shell", "Userinit", "AppInit_DLLs"}) {
            RegValueInfo info;
            if (read_reg_value(base, val, &info)) {
                std::string s = path_suspicion(info.data);
                std::string suspicion = "medium";
                if (!s.empty()) suspicion = "high";
                if (std::string(val) == "AppInit_DLLs" && !info.data.empty() &&
                    to_lower(info.data) != "0")
                    suspicion = "high";
                add(base, val, info.data, suspicion, s);
            }
        }
    }

    // 3. IFEO Debugger（映像劫持）
    {
        std::string key = "HKLM/SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options";
        std::string err;
        HKEY h = open_reg(key, KEY_READ, err);
        if (h) {
            int scanned = 0;
            for (const auto& sub_name : enum_reg_subkeys(h, 400)) {
                if (++scanned > 400) { truncated = true; break; }
                RegValueInfo info;
                std::string child = key + "\\" + sub_name;
                if (read_reg_value(child, "Debugger", &info))
                    add(child, "Debugger", info.data, "high", "IFEO 映像劫持");
            }
            RegCloseKey(h);
        }
    }

    // 4. 服务 ImagePath 可疑模式
    {
        SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
        if (scm) {
            DWORD needed = 0, count_svcs = 0, resume = 0;
            std::vector<unsigned char> buf(64 * 1024);
            if (EnumServicesStatusW(scm, SERVICE_WIN32, SERVICE_STATE_ALL,
                                    reinterpret_cast<LPENUM_SERVICE_STATUSW>(buf.data()),
                                    static_cast<DWORD>(buf.size()), &needed, &count_svcs, &resume) ||
                GetLastError() == ERROR_MORE_DATA) {
                if (needed > buf.size()) buf.resize(needed + 1024);
                if (EnumServicesStatusW(scm, SERVICE_WIN32, SERVICE_STATE_ALL,
                                        reinterpret_cast<LPENUM_SERVICE_STATUSW>(buf.data()),
                                        static_cast<DWORD>(buf.size()), &needed, &count_svcs,
                                        &resume) ||
                    count_svcs > 0) {
                    auto* svcs = reinterpret_cast<LPENUM_SERVICE_STATUSW>(buf.data());
                    int scanned = 0;
                    for (DWORD i = 0; i < count_svcs && scanned < 300; ++i) {
                        ++scanned;
                        std::string name = aiutil::to_utf8(svcs[i].lpServiceName);
                        SC_HANDLE sh = OpenServiceW(scm, svcs[i].lpServiceName,
                                                     SERVICE_QUERY_CONFIG);
                        if (!sh) continue;
                        DWORD qneeded = 0;
                        QueryServiceConfigW(sh, nullptr, 0, &qneeded);
                        if (qneeded > 0 && qneeded < 65536) {
                            std::vector<unsigned char> qbuf(qneeded);
                            auto* cfg = reinterpret_cast<LPQUERY_SERVICE_CONFIGW>(qbuf.data());
                            if (QueryServiceConfigW(sh, cfg, qneeded, &qneeded) && cfg->lpBinaryPathName) {
                                std::string image = aiutil::to_utf8(cfg->lpBinaryPathName);
                                std::string s = path_suspicion(image);
                                if (!s.empty() || image.find("cmd") != std::string::npos ||
                                    to_lower(image).find("powershell") != std::string::npos) {
                                    add("HKLM/SYSTEM\\CurrentControlSet\\Services\\" + name,
                                        "ImagePath", image,
                                        s.empty() ? "medium" : "high", s);
                                }
                            }
                        }
                        CloseServiceHandle(sh);
                    }
                }
            }
            CloseServiceHandle(scm);
        }
    }

    // 5. COM 劫持（HKCU CLSID InprocServer32 指向用户可写目录）
    {
        std::string key = "HKCU/Software\\Classes\\CLSID";
        std::string err;
        HKEY h = open_reg(key, KEY_READ, err);
        if (h) {
            int scanned = 0;
            for (const auto& sub_name : enum_reg_subkeys(h, 100000)) {
                if (++scanned > 300) { truncated = true; break; }
                RegValueInfo info;
                std::string child = key + "\\" + sub_name + "\\InprocServer32";
                if (read_reg_value(child, "", &info)) {
                    std::string s = path_suspicion(info.data);
                    if (!s.empty()) add(child, "(默认)", info.data, "high", "COM 劫持: " + s);
                }
            }
            RegCloseKey(h);
        }
    }

    // 6. LSA（认证/安全/通知包）
    for (const char* val : {"Authentication Packages", "Security Packages", "Notification Packages"}) {
        RegValueInfo info;
        if (read_reg_value("HKLM/SYSTEM\\CurrentControlSet\\Control\\Lsa", val, &info)) {
            std::string data = to_lower(info.data);
            std::string suspicion = "low";
            if (data.find("msv1_0") == std::string::npos && !data.empty() &&
                std::string(val) != "Security Packages")
                suspicion = "high";
            add("HKLM/SYSTEM\\CurrentControlSet\\Control\\Lsa", val, info.data, suspicion,
                "LSA 包（改动需极高警惕）");
        }
    }

    // 7. Print Monitor 驱动
    {
        std::string key = "HKLM/SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors";
        std::string err;
        HKEY h = open_reg(key, KEY_READ, err);
        if (h) {
            for (const auto& sub_name : enum_reg_subkeys(h, 100)) {
                RegValueInfo info;
                std::string child = key + "\\" + sub_name;
                if (read_reg_value(child, "Driver", &info)) {
                    std::string s = path_suspicion(info.data);
                    add(child, "Driver", info.data, s.empty() ? "medium" : "high", s);
                }
            }
            RegCloseKey(h);
        }
    }

    json out = {{"count", count},
                {"truncated", truncated},
                {"findings", findings},
                {"note", "WMI 永久订阅不在此工具范围，请用 list_wmi_subscriptions 单独检查"}};
    return aiutil::dump_json(out);
}

std::string t_list_wmi_subscriptions(const json& args, AiContext&) {
    int limit = static_cast<int>(arg_int(args, "limit", 50));
    limit = std::min(std::max(limit, 1), 200);

    WmiSession w;
    std::string err;
    if (!w.connect(err)) return ERR("WMI 不可用: " + err);

    json filters = json::array();
    json consumers = json::array();
    json bindings = json::array();
    int fc = 0, cc = 0, bc = 0;

    w.query(L"SELECT * FROM __EventFilter", [&](IWbemClassObject* obj) {
        if (fc >= limit) return;
        filters.push_back({{"name", WmiSession::get_str(obj, L"Name")},
                           {"query", WmiSession::get_str(obj, L"Query")},
                           {"language", WmiSession::get_str(obj, L"QueryLanguage")}});
        ++fc;
    });
    w.query(L"SELECT * FROM __EventConsumer", [&](IWbemClassObject* obj) {
        if (cc >= limit) return;
        json item = {{"name", WmiSession::get_str(obj, L"Name")},
                     {"class", WmiSession::get_str(obj, L"__CLASS")},
                     {"command", WmiSession::get_str(obj, L"CommandLineTemplate")},
                     {"script", WmiSession::get_str(obj, L"ScriptText")}};
        consumers.push_back(item);
        ++cc;
    });
    w.query(L"SELECT * FROM __FilterToConsumerBinding", [&](IWbemClassObject* obj) {
        if (bc >= limit) return;
        bindings.push_back({{"filter", WmiSession::get_str(obj, L"Filter")},
                            {"consumer", WmiSession::get_str(obj, L"Consumer")}});
        ++bc;
    });

    json out = {{"count", fc + cc + bc},
                {"filters", filters}, {"consumers", consumers}, {"bindings", bindings}};
    return aiutil::dump_json(out);
}

std::string t_list_startup_folders(const json&, AiContext&) {
    json folders = json::array();
    int count = 0;
    for (const char* key : {"HKCU/Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders",
                            "HKLM/Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders"}) {
        RegValueInfo info;
        if (!read_reg_value(key, "Startup", &info)) continue;
        // REG_EXPAND_SZ 展开
        std::wstring raw = aiutil::to_wide(info.data);
        wchar_t expanded[MAX_PATH * 2]{};
        ExpandEnvironmentStringsW(raw.c_str(), expanded, MAX_PATH * 2);
        std::string dir = aiutil::to_utf8(expanded);
        if (dir.empty()) continue;

        json files = json::array();
        WIN32_FIND_DATAW fd{};
        std::wstring pattern = aiutil::to_wide_sys(dir) + L"\\*";
        HANDLE find = FindFirstFileW(pattern.c_str(), &fd);
        if (find != INVALID_HANDLE_VALUE) {
            do {
                std::wstring n = fd.cFileName;
                if (n == L"." || n == L"..") continue;
                std::string name = aiutil::to_utf8(n);
                unsigned long long size =
                    (static_cast<unsigned long long>(fd.nFileSizeHigh) << 32) | fd.nFileSizeLow;
                json f = {{"name", name}, {"size", size}};
                f["modified"] = iso_from_filetime(
                    (static_cast<long long>(fd.ftLastWriteTime.dwHighDateTime) << 32) |
                    fd.ftLastWriteTime.dwLowDateTime);
                files.push_back(f);
                ++count;
            } while (FindNextFileW(find, &fd));
            FindClose(find);
        }
        folders.push_back({{"path", dir}, {"files", files}});
    }
    json out = {{"folders", folders}, {"count", count}};
    return aiutil::dump_json(out);
}

std::string t_list_drivers_loaded(const json& args, AiContext&) {
    int limit = static_cast<int>(arg_int(args, "limit", 200));
    limit = std::min(std::max(limit, 1), 2000);

    LPVOID drivers[1024]{};
    DWORD needed = 0;
    if (!EnumDeviceDrivers(drivers, sizeof(drivers), &needed)) {
        DWORD e = GetLastError();
        if (e == ERROR_ACCESS_DENIED)
            return ERR("枚举驱动需要管理员权限（错误 5）");
        return ERR("EnumDeviceDrivers 失败（错误 " + std::to_string(e) + "）");
    }
    int total = static_cast<int>(needed / sizeof(LPVOID));
    int shown = 0;
    bool truncated = false;
    json drivers_out = json::array();
    for (int i = 0; i < total; ++i) {
        if (shown >= limit) { truncated = true; break; }
        wchar_t base[256]{};
        std::string name;
        if (GetDeviceDriverBaseNameW(drivers[i], base, 256)) name = aiutil::to_utf8(base);
        if (name.empty()) continue;
        json item = {{"name", name}, {"address", hex(reinterpret_cast<unsigned long long>(drivers[i]))}};
        wchar_t path[MAX_PATH * 2]{};
        if (GetDeviceDriverFileNameW(drivers[i], path, MAX_PATH * 2))
            item["file"] = aiutil::to_utf8(path);
        drivers_out.push_back(item);
        ++shown;
    }
    if (shown == 0) return ERR("没有枚举到驱动（可能需要管理员）");
    json out = {{"count", shown}, {"truncated", truncated}, {"drivers", drivers_out}};
    return aiutil::dump_json(out);
}

std::string t_delete_registry_value(const json& args, AiContext& ctx) {
    std::string key = arg_str(args, "key");
    std::string value_name = arg_str(args, "value_name");
    if (key.empty() || value_name.empty()) return ERR("key 与 value_name 必填");
    if (dry_run_requested(args, ctx))
        return aiutil::dump_json(json{{"key", key}, {"value_name", value_name},
                                      {"action", "delete_registry_value"}, {"dry_run", true},
                                      {"note", "将删除该注册表值（不执行）"}});

    std::string err;
    HKEY h = open_reg(key, KEY_SET_VALUE, err);
    if (!h) return ERR(err);
    LSTATUS rc = RegDeleteValueW(h, aiutil::to_wide(value_name).c_str());
    RegCloseKey(h);
    if (rc != ERROR_SUCCESS)
        return ERR("删除失败（错误 " + std::to_string(rc) +
                   (rc == 5 ? "，需要管理员" : rc == 2 ? "，值不存在" : "") + "）: " + key + " -> " +
                   value_name);
    return aiutil::dump_json(json{{"key", key}, {"value_name", value_name},
                                  {"deleted", true}, {"dry_run", false}});
}

std::string t_remove_persistence(const json& args, AiContext& ctx) {
    std::string type = to_lower(arg_str(args, "type"));
    std::string target = arg_str(args, "target");
    if (type.empty() || target.empty()) return ERR("type 与 target 必填");
    if (dry_run_requested(args, ctx))
        return aiutil::dump_json(json{{"type", type}, {"target", target}, {"dry_run", true},
                                      {"note", "将移除该持久化项（不执行）"}});

    if (type == "registry") {
        size_t colon = target.rfind(':');
        if (colon == std::string::npos) return ERR("target 应形如 HKCU\\...\\Run:值名");
        std::string key = target.substr(0, colon);
        std::string value = target.substr(colon + 1);
        json inner = {{"key", key}, {"value_name", value}, {"dry_run", false}};
        std::string res = t_delete_registry_value(inner, ctx);
        json out = {{"type", type}, {"target", target}, {"dry_run", false}};
        if (res.rfind("ERROR", 0) == 0) {
            out["removed"] = false;
            out["detail"] = res;
        } else {
            out["removed"] = true;
            out["detail"] = "已删除注册表值";
        }
        return aiutil::dump_json(out);
    }
    if (type == "service") {
        std::string err;
        bool ok = delete_service_internal(target, err);
        json out = {{"type", type}, {"target", target}, {"removed", ok}, {"dry_run", false}};
        if (!ok) out["detail"] = err;
        return aiutil::dump_json(out);
    }
    if (type == "task") {
        std::string output = delete_task_internal(target);
        bool ok = output.find("成功") != std::string::npos ||
                  output.find("SUCCESS") != std::string::npos;
        json out = {{"type", type}, {"target", target}, {"removed", ok}, {"dry_run", false},
                    {"output", output}};
        return aiutil::dump_json(out);
    }
    if (type == "wmi") {
        WmiSession w;
        std::string err;
        if (!w.connect(err)) return ERR("WMI 不可用: " + err);
        std::string kind, name;
        size_t sep = target.find(':');
        if (sep == std::string::npos) return ERR("target 应形如 filter:名称 / consumer:名称 / binding:关键字");
        kind = to_lower(target.substr(0, sep));
        name = target.substr(sep + 1);
        if (name.empty()) return ERR("名称为空");

        std::wstring wql;
        if (kind == "filter")
            wql = L"SELECT * FROM __EventFilter WHERE Name='" + aiutil::to_wide(name) + L"'";
        else if (kind == "consumer")
            wql = L"SELECT * FROM __EventConsumer WHERE Name='" + aiutil::to_wide(name) + L"'";
        else if (kind == "binding")
            wql = L"SELECT * FROM __FilterToConsumerBinding";
        else
            return ERR("未知 wmi 类型: " + kind + "（支持 filter/consumer/binding）");

        bool removed = false;
        std::string detail;
        w.query(wql.c_str(), [&](IWbemClassObject* obj) {
            if (removed) return;
            if (kind == "binding") {
                std::string f = WmiSession::get_str(obj, L"Filter");
                std::string c = WmiSession::get_str(obj, L"Consumer");
                if (to_lower(f).find(to_lower(name)) == std::string::npos &&
                    to_lower(c).find(to_lower(name)) == std::string::npos)
                    return;
            }
            std::wstring relpath = WmiSession::get_wstr(obj, L"__RELPATH");
            std::string del_err;
            if (w.delete_by_relpath(relpath, del_err)) {
                removed = true;
                detail = "已删除 " + aiutil::to_utf8(relpath);
            } else {
                detail = del_err;
            }
        });
        json out = {{"type", type}, {"target", target}, {"removed", removed}, {"dry_run", false}};
        if (!detail.empty()) out["detail"] = detail;
        else if (!removed) out["detail"] = "没有匹配的 WMI 对象";
        return aiutil::dump_json(out);
    }
    return ERR("未知 type: " + type + "（支持 registry/service/task/wmi）");
}

std::string t_stop_service(const json& args, AiContext& ctx) {
    std::string name = arg_str(args, "name");
    if (name.empty()) return ERR("服务名必填");
    if (dry_run_requested(args, ctx))
        return aiutil::dump_json(json{{"name", name}, {"action", "stop_service"},
                                      {"dry_run", true}, {"note", "将停止该服务（不执行）"}});

    std::string err;
    if (!stop_service_internal(name, 10, err)) return ERR(err);
    return aiutil::dump_json(json{{"name", name}, {"stopped", true},
                                  {"state", "STOPPED"}, {"dry_run", false}});
}

std::string t_delete_service(const json& args, AiContext& ctx) {
    std::string name = arg_str(args, "name");
    if (name.empty()) return ERR("服务名必填");
    if (dry_run_requested(args, ctx))
        return aiutil::dump_json(json{{"name", name}, {"action", "delete_service"},
                                      {"dry_run", true}, {"note", "将先停再删该服务（不执行）"}});

    std::string err;
    if (!delete_service_internal(name, err)) return ERR(err);
    return aiutil::dump_json(json{{"name", name}, {"deleted", true}, {"dry_run", false}});
}

std::string t_delete_scheduled_task(const json& args, AiContext& ctx) {
    std::string name = arg_str(args, "name");
    if (name.empty()) return ERR("任务名必填");
    if (name.find('"') != std::string::npos) return ERR("任务名不能包含引号");
    if (dry_run_requested(args, ctx))
        return aiutil::dump_json(json{{"name", name}, {"action", "delete_scheduled_task"},
                                      {"dry_run", true},
                                      {"note", "将执行 schtasks /delete /tn \"" + name + "\" /f"}});

    std::string output = delete_task_internal(name);
    bool ok = output.find("成功") != std::string::npos ||
              output.find("SUCCESS") != std::string::npos;
    if (!ok)
        return ERR("删除计划任务失败: " + output.substr(0, 300));
    return aiutil::dump_json(json{{"name", name}, {"deleted", true}, {"dry_run", false},
                                  {"output", output}});
}

}  // namespace aiext
