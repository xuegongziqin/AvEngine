// ai_tools_intel.cpp - AI 工具扩展库：情报与元工具组
// 契约见 ai_tools_ext.h 第七节；审计由 ai_execute_tool 统一完成。
#include "ai_tools_ext.h"

#include "ai_util.h"
#include "clamd_client.h"
#include "http_client.h"
#include "yara_engine.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <map>
#include <set>
#include <string>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <softpub.h>
#include <tlhelp32.h>
#include <winreg.h>
#include <winsvc.h>
#include <wintrust.h>

using nlohmann::json;

namespace fs = std::filesystem;

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

// ---------------- 流式哈希 ----------------
std::string hash_file_stream(const std::string& path_utf8, const wchar_t* algo, std::string& err) {
    BCRYPT_ALG_HANDLE ah = nullptr;
    if (BCryptOpenAlgorithmProvider(&ah, algo, nullptr, 0) != 0 || !ah) {
        err = "BCryptOpenAlgorithmProvider 失败";
        return "";
    }
    BCRYPT_HASH_HANDLE hh = nullptr;
    if (BCryptCreateHash(ah, &hh, nullptr, 0, nullptr, 0, 0) != 0) {
        BCryptCloseAlgorithmProvider(ah, 0);
        err = "BCryptCreateHash 失败";
        return "";
    }
    std::FILE* fp = _wfopen(aiutil::to_wide_sys(path_utf8).c_str(), L"rb");
    if (!fp) {
        BCryptDestroyHash(hh);
        BCryptCloseAlgorithmProvider(ah, 0);
        err = "无法打开文件: " + path_utf8;
        return "";
    }
    std::vector<unsigned char> buf(1 << 20);
    size_t n;
    while ((n = std::fread(buf.data(), 1, buf.size(), fp)) > 0)
        BCryptHashData(hh, buf.data(), static_cast<ULONG>(n), 0);
    std::fclose(fp);

    DWORD digest_len = 64;
    DWORD cb = 0;
    BCryptGetProperty(ah, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&digest_len),
                      sizeof(digest_len), &cb, 0);
    std::vector<unsigned char> digest(digest_len);
    std::string out;
    if (BCryptFinishHash(hh, digest.data(), digest_len, 0) == 0) {
        static const char* hx = "0123456789abcdef";
        out.reserve(digest_len * 2);
        for (unsigned char b : digest) {
            out += hx[b >> 4];
            out += hx[b & 0xF];
        }
    }
    BCryptDestroyHash(hh);
    BCryptCloseAlgorithmProvider(ah, 0);
    return out;
}

// ---------------- 快速签名检查（只要 signed 与否） ----------------

// 是否位于 %SystemRoot% 之下。系统目录里大量文件走 catalog 签名，而 catalog 校验
// 在某些环境（Win7、catalog 数据库不可读）下不可用，此时 WinVerifyTrust 会返回
// TRUST_E_NOSIGNATURE —— 那**不等于**"没有签名"。
bool intel_is_system_path(const std::string& path_utf8) {
    wchar_t win[MAX_PATH]{};
    if (!GetWindowsDirectoryW(win, MAX_PATH)) return false;
    std::string root = aiutil::to_utf8(win);
    std::string lower_path = path_utf8;
    std::string lower_root = root;
    for (char& c : lower_path) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    for (char& c : lower_root) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return !lower_root.empty() && lower_path.rfind(lower_root, 0) == 0;
}

bool quick_signed(const std::string& path_utf8) {
    std::wstring wpath = aiutil::to_wide_sys(path_utf8);
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
    LONG rc = WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &action, &data);
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &action, &data);
    if (rc == 0) return true;
    // 系统目录文件在 catalog 校验不可用时会被判成"无签名"：这里当作**未知**处理，
    // 不让 build_static_report 把 cmd.exe 这类系统文件误标成 suspicious。
    if (rc == static_cast<LONG>(TRUST_E_NOSIGNATURE) && intel_is_system_path(path_utf8))
        return true;
    return false;
}

// ---------------- 可打印字符串提取 ----------------
std::vector<std::string> extract_printable(const unsigned char* data, size_t len, int min_len,
                                           int limit) {
    std::vector<std::string> out;
    std::string cur;
    for (size_t i = 0; i < len && static_cast<int>(out.size()) < limit; ++i) {
        unsigned char c = data[i];
        if (c >= 0x20 && c < 0x7f) {
            cur += static_cast<char>(c);
        } else {
            if (static_cast<int>(cur.size()) >= min_len) out.push_back(cur);
            cur.clear();
        }
    }
    if (static_cast<int>(cur.size()) >= min_len && static_cast<int>(out.size()) < limit)
        out.push_back(cur);
    return out;
}

// ---------------- 临时目录 ----------------
std::string make_temp_rule_dir() {
    wchar_t temp[MAX_PATH]{};
    GetTempPathW(MAX_PATH, temp);
    char suffix[32];
    std::snprintf(suffix, sizeof(suffix), "avrule_%08x",
                  static_cast<unsigned>(GetTickCount() ^ GetCurrentProcessId()));
    std::string dir = aiutil::to_utf8(temp) + suffix;
    std::error_code ec;
    fs::create_directories(fs::path(aiutil::to_wide_sys(dir)), ec);
    if (ec && !fs::is_directory(fs::path(aiutil::to_wide_sys(dir)), ec)) return "";
    return dir;
}

// 收集 strings 参数：接受数组、单字符串、或 JSON 数组字符串
std::vector<std::string> collect_strings_arg(const json& args) {
    std::vector<std::string> out;
    auto it = args.find("strings");
    if (it == args.end()) return out;
    if (it->is_array()) {
        for (const auto& s : *it)
            if (s.is_string()) out.push_back(s.get<std::string>());
    } else if (it->is_string()) {
        std::string raw = it->get<std::string>();
        try {
            json parsed = json::parse(raw);
            if (parsed.is_array()) {
                for (const auto& s : parsed)
                    if (s.is_string()) out.push_back(s.get<std::string>());
                return out;
            }
        } catch (...) {
        }
        out.push_back(raw);
    }
    return out;
}

// YARA 字符串转义
std::string yara_escape(const std::string& s) {
    std::string out;
    for (char c : s) {
        if (c == '\\') out += "\\\\";
        else if (c == '"') out += "\\\"";
        else if (static_cast<unsigned char>(c) < 0x20) {
            char buf[8];
            std::snprintf(buf, sizeof(buf), "\\x%02x", static_cast<unsigned char>(c));
            out += buf;
        } else {
            out += c;
        }
    }
    return out;
}

std::string now_suffix() {
    SYSTEMTIME st{};
    GetLocalTime(&st);
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%04d%02d%02d_%02d%02d%02d", st.wYear, st.wMonth, st.wDay,
                  st.wHour, st.wMinute, st.wSecond);
    return buf;
}

// 简单 IPv4 点分串解析；非 IPv4 返回 0
unsigned long ip_to_u32(const std::string& s) {
    unsigned a = 0, b = 0, c = 0, d = 0;
    char extra = 0;
    if (std::sscanf(s.c_str(), "%u.%u.%u.%u%c", &a, &b, &c, &d, &extra) != 4) return 0;
    if (a > 255 || b > 255 || c > 255 || d > 255) return 0;
    return (a << 24) | (b << 16) | (c << 8) | d;
}

bool looks_like_ipv4(const std::string& s) { return ip_to_u32(s) != 0; }

// ---------------- 基线采集 ----------------
json capture_processes() {
    json items = json::array();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return items;
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            items.push_back({{"name", aiutil::to_utf8(pe.szExeFile)}});
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return items;
}

json capture_services() {
    json items = json::array();
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) return items;
    DWORD needed = 0, count = 0, resume = 0;
    std::vector<unsigned char> buf(64 * 1024);
    if (EnumServicesStatusW(scm, SERVICE_WIN32, SERVICE_STATE_ALL,
                            reinterpret_cast<LPENUM_SERVICE_STATUSW>(buf.data()),
                            static_cast<DWORD>(buf.size()), &needed, &count, &resume) ||
        GetLastError() == ERROR_MORE_DATA) {
        if (needed > buf.size()) buf.resize(needed + 1024);
        EnumServicesStatusW(scm, SERVICE_WIN32, SERVICE_STATE_ALL,
                            reinterpret_cast<LPENUM_SERVICE_STATUSW>(buf.data()),
                            static_cast<DWORD>(buf.size()), &needed, &count, &resume);
        auto* svcs = reinterpret_cast<LPENUM_SERVICE_STATUSW>(buf.data());
        for (DWORD i = 0; i < count; ++i)
            items.push_back({{"name", aiutil::to_utf8(svcs[i].lpServiceName)}});
    }
    CloseServiceHandle(scm);
    return items;
}

json capture_tasks() {
    std::string text = aiext::run_capture("schtasks /query /fo csv /nh", 60000, 30000);
    json items = json::array();
    size_t pos = 0;
    while (pos < text.size()) {
        size_t nl = text.find('\n', pos);
        std::string line = text.substr(pos, (nl == std::string::npos ? text.size() : nl) - pos);
        pos = (nl == std::string::npos) ? text.size() : nl + 1;
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty() || line.find("ERROR") == 0) continue;
        // CSV 首列是任务名（可能被引号包裹）
        std::string name = line;
        size_t comma = line.find(',');
        if (comma != std::string::npos) name = line.substr(0, comma);
        if (!name.empty() && name.front() == '"') name = name.substr(1);
        if (!name.empty() && name.back() == '"') name.pop_back();
        if (name.empty() || name == "TaskName" || name == "\ufffd") continue;
        items.push_back({{"name", name}});
    }
    return items;
}

json capture_startup() {
    json items = json::array();
    for (const char* key :
         {"HKCU/Software\\Microsoft\\Windows\\CurrentVersion\\Run",
          "HKLM/Software\\Microsoft\\Windows\\CurrentVersion\\Run"}) {
        HKEY root = nullptr;
        std::wstring sub;
        std::string k = key;
        if (to_lower(k.substr(0, 4)) == "hkcu") root = HKEY_CURRENT_USER;
        else root = HKEY_LOCAL_MACHINE;
        size_t sep = k.find_first_of("/\\");
        std::wstring rest = aiutil::to_wide(k.substr(sep + 1));
        HKEY h = nullptr;
        if (RegOpenKeyExW(root, rest.c_str(), 0, KEY_READ, &h) != ERROR_SUCCESS) continue;
        for (DWORD idx = 0;; ++idx) {
            wchar_t name[512]{};
            DWORD name_len = 512;
            std::vector<unsigned char> data(2048);
            DWORD data_len = static_cast<DWORD>(data.size());
            DWORD type = 0;
            LSTATUS rc = RegEnumValueW(h, idx, name, &name_len, nullptr, &type, data.data(),
                                       &data_len);
            if (rc == ERROR_NO_MORE_ITEMS) break;
            if (rc != ERROR_SUCCESS) break;
            items.push_back({{"name", aiutil::to_utf8(std::wstring(name, name_len))},
                             {"location", key}});
        }
        RegCloseKey(h);
    }
    return items;
}

json capture_kind(const std::string& kind) {
    if (kind == "process") return capture_processes();
    if (kind == "service") return capture_services();
    if (kind == "task") return capture_tasks();
    if (kind == "startup") return capture_startup();
    return json::array();
}

std::string item_key(const json& item) {
    // 基线比对键：进程用 name（+exe 可选），服务/任务/启动项用 name
    std::string key = item.value("name", "");
    if (item.contains("exe")) key += "|" + item.value("exe", "");
    return key;
}

}  // namespace

namespace aiext {

std::string t_reputation_lookup(const json& args, AiContext& ctx) {
    std::string value = arg_str(args, "value");
    std::string type = to_lower(arg_str(args, "type", "auto"));
    long long timeout = arg_int(args, "timeout", 5);
    if (value.empty()) return ERR("value 必填");
    timeout = std::min<long long>(std::max<long long>(timeout, 2), 30);

    // 类型自动判定
    if (type == "auto") {
        bool hex_only = value.size() == 32 || value.size() == 40 || value.size() == 64;
        if (hex_only)
            for (char c : value)
                if (!std::isxdigit(static_cast<unsigned char>(c))) { hex_only = false; break; }
        if (hex_only) type = "hash";
        else if (value.find("://") != std::string::npos) type = "url";
        else if (looks_like_ipv4(value)) type = "ip";
        else type = "domain";
    }

    // 本地启发式
    json local = json::object();
    json reasons = json::array();
    if (type == "ip") {
        unsigned long a = ip_to_u32(value);
        if (a != 0) {
            unsigned char b3 = (a >> 24) & 0xFF;
            unsigned char b2 = (a >> 16) & 0xFF;
            if (b3 == 10 || (b3 == 172 && b2 >= 16 && b2 <= 31) || (b3 == 192 && b2 == 168) ||
                b3 == 127 || (b3 == 169 && b2 == 254) || b3 == 0 || b3 >= 224) {
                local["verdict"] = "private/reserved";
                reasons.push_back("私网/保留地址，不构成外联威胁");
            } else {
                local["verdict"] = "public";
            }
        } else {
            local["verdict"] = "ipv6/unknown";
        }
    } else if (type == "domain") {
        std::string low = to_lower(value);
        local["verdict"] = "unknown";
        for (const char* tld : {".zip", ".mov", ".tk", ".top", ".xyz", ".click", ".gq", ".cf",
                                ".ml", ".work"}) {
            std::string t(tld);
            if (low.size() >= t.size() && low.compare(low.size() - t.size(), t.size(), t) == 0) {
                reasons.push_back("可疑 TLD: " + t);
                local["verdict"] = "suspicious";
            }
        }
        if (low.find("xn--") != std::string::npos) {
            reasons.push_back("包含 punycode 编码，可能伪装成知名域名");
            local["verdict"] = "suspicious";
        }
        size_t first_dot = low.find('.');
        if (first_dot != std::string::npos && low.find('.', first_dot + 1) != std::string::npos &&
            low.find(' ') == std::string::npos) {
            // 双标签域名（如 a.com）正常；三段式伪装检测省略
        }
        for (const char* pat : {".pdf.exe", ".doc.exe", ".jpg.exe", ".txt.exe"}) {
            if (low.find(pat) != std::string::npos) {
                reasons.push_back("双扩展名伪装: " + std::string(pat));
                local["verdict"] = "suspicious";
            }
        }
    } else if (type == "hash") {
        local["verdict"] = "unknown";
        reasons.push_back("本地无哈希情报，需配置在线端点查询");
    } else {
        local["verdict"] = "unknown";
        reasons.push_back("URL 信誉需在线端点支持");
    }
    local["reasons"] = reasons;

    // 本地黑名单文件
    json blocklist = json::object();
    std::string bl_path = ctx.project_root.empty() ? "blocklist.txt"
                                                   : ctx.project_root + "\\blocklist.txt";
    std::ifstream bl(fs::path(aiutil::to_wide_sys(bl_path)));
    if (!bl) {
        blocklist = {{"exists", false}, {"hit", false}};
    } else {
        blocklist = {{"exists", true}, {"hit", false}};
        std::string line, low_value = to_lower(value);
        while (std::getline(bl, line)) {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            if (line.empty() || line[0] == '#') continue;
            if (to_lower(line) == low_value) {
                blocklist["hit"] = true;
                blocklist["verdict"] = "blocked";
                break;
            }
        }
    }

    // 在线端点（可选）
    json provider = nullptr;
    std::string endpoint = arg_str(args, "endpoint");
    if (!endpoint.empty()) {
        size_t pos = endpoint.find("{value}");
        std::string url = (pos == std::string::npos)
                              ? endpoint + (endpoint.find('?') == std::string::npos ? "?" : "&") +
                                    "value=" + value
                              : endpoint.replace(pos, 7, value);
        HttpResponse resp = http_request("GET", url, arg_str(args, "api_key"), "",
                                         static_cast<int>(timeout));
        provider = {{"status", resp.status},
                    {"body", resp.body.size() > 2000 ? resp.body.substr(0, 2000) + "..." : resp.body}};
        if (!resp.ok) provider["error"] = resp.error;
    }

    json out = {{"value", value}, {"type", type}, {"local", local},
                {"blocklist", blocklist}, {"provider", provider}};
    if (endpoint.empty())
        out["note"] = "未配置查询端点，仅本地检查（可在参数 endpoint 提供 URL 模板，含 {value} 占位符）";
    return aiutil::dump_json(out);
}

std::string t_build_static_report(const json& args, AiContext& ctx) {
    std::string path = arg_str(args, "path");
    if (path.empty()) return ERR("path 必填");
    if (!fs::is_regular_file(fs::path(aiutil::to_wide_sys(path))))
        return ERR("文件不存在: " + path);

    // 头部 4MB：熵/魔数/字符串
    std::string read_err;
    std::vector<unsigned char> head = read_file_bytes(path, 4u * 1024 * 1024, read_err);
    if (head.empty()) return ERR("读取失败: " + read_err);
    double entropy = shannon_entropy(head.data(), head.size());

    std::string magic;
    if (head.size() >= 2) {
        if (head[0] == 'M' && head[1] == 'Z') magic = "PE";
        else if (head[0] == 'P' && head[1] == 'K') magic = "ZIP";
        else if (head[0] == '#' && head[1] == '!') magic = "script";
        else if (head[0] == 0xD0 && head[1] == 0xCF) magic = "OLE2";
    }

    // 哈希（流式，可处理大文件）
    std::string herr;
    std::string sha256 = hash_file_stream(path, BCRYPT_SHA256_ALGORITHM, herr);
    std::string md5 = hash_file_stream(path, BCRYPT_MD5_ALGORITHM, herr);
    unsigned long long fsize = fs::file_size(fs::path(aiutil::to_wide_sys(path)));

    // PE 简析
    json pe = nullptr;
    bool packed_suspicion = false;
    if (magic == "PE" && head.size() >= 0x40 + 4) {
        unsigned e_lfanew = *reinterpret_cast<unsigned*>(head.data() + 0x3C);
        if (e_lfanew + 24 < head.size() &&
            head[e_lfanew] == 'P' && head[e_lfanew + 1] == 'E') {
            unsigned machine = *reinterpret_cast<unsigned short*>(head.data() + e_lfanew + 4);
            unsigned ts = *reinterpret_cast<unsigned*>(head.data() + e_lfanew + 8);
            unsigned short nsec = *reinterpret_cast<unsigned short*>(head.data() + e_lfanew + 6);
            unsigned short opt_size = *reinterpret_cast<unsigned short*>(head.data() + e_lfanew + 20);
            json sections = json::array();
            size_t sec_off = e_lfanew + 24 + opt_size;
            for (unsigned s = 0; s < nsec && s < 96 && sec_off + 40 <= head.size(); ++s) {
                size_t base = sec_off + s * 40;
                std::string name(reinterpret_cast<const char*>(head.data() + base), 8);
                size_t nul = name.find('\0');
                if (nul != std::string::npos) name.resize(nul);
                unsigned vsize = *reinterpret_cast<unsigned*>(head.data() + base + 8);
                unsigned rawsize = *reinterpret_cast<unsigned*>(head.data() + base + 16);
                unsigned rawptr = *reinterpret_cast<unsigned*>(head.data() + base + 20);
                double sent = 0.0;
                if (rawsize > 1024 && rawsize <= head.size() && rawptr + rawsize <= head.size())
                    sent = shannon_entropy(head.data() + rawptr, rawsize);
                bool packed = sent > 7.2 && rawsize > 10240;
                if (packed) packed_suspicion = true;
                sections.push_back({{"name", name}, {"vsize", vsize}, {"rawsize", rawsize},
                                      {"entropy", sent}, {"packed", packed}});
            }
            std::string compiled;
            {
                // PE TimeDateStamp 是 Unix 纪元秒
                time_t t = static_cast<time_t>(ts);
                struct tm tmv{};
                if (localtime_s(&tmv, &t) == 0) {
                    char buf[40];
                    std::snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d",
                                  tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday, tmv.tm_hour,
                                  tmv.tm_min, tmv.tm_sec);
                    compiled = buf;
                }
            }
            pe = {{"machine", machine == 0x8664 ? "x64" : machine == 0x14C ? "x86" :
                          std::to_string(machine)},
                  {"compiled", compiled.empty() ? json(nullptr) : json(compiled)},
                  {"sections", sections},
                  {"packed_suspicion", packed_suspicion}};
        }
    }
    if (packed_suspicion || (entropy > 7.0 && fsize > 16 * 1024 && magic != "PE"))
        packed_suspicion = true;

    // 签名
    bool signed_ok = quick_signed(path);
    json signature = {{"signed", signed_ok}};

    // YARA
    json yara = nullptr;
    if (!ctx.rules_path.empty()) {
        YaraEngine engine(ctx.rules_path);
        json y = {{"available", engine.available()},
                  {"rules_count", engine.rules_count()}};
        if (engine.available()) y["matches"] = engine.scan_file(path);
        else y["matches"] = json::array();
        yara = y;
    }

    // ClamAV
    json clam = nullptr;
    if (!ctx.clam_host.empty() && ctx.clam_port > 0) {
        ClamdClient client(ctx.clam_host, static_cast<int>(ctx.clam_port), ctx.clam_timeout);
        ClamScanResult r = client.scan_file(path);
        clam = {{"available", r.available},
                {"infected", r.infected},
                {"virus", r.virus.empty() ? json(nullptr) : json(r.virus)}};
    }

    // 字符串样本
    json strings_sample = json::array();
    for (const auto& s : extract_printable(head.data(), head.size(), 6, 50)) {
        if (s.size() > 200) continue;
        strings_sample.push_back(s);
    }

    // 结论
    std::string verdict = "clean";
    if (yara.is_object() && yara.value("matches", json::array()).size() > 0) verdict = "infected";
    else if (clam.is_object() && !clam.value("virus", json(nullptr)).is_null()) verdict = "infected";
    else if (packed_suspicion || !signed_ok) verdict = "suspicious";

    json out = {{"path", path},
                {"size", fsize},
                {"sha256", sha256.empty() ? json(nullptr) : json(sha256)},
                {"md5", md5.empty() ? json(nullptr) : json(md5)},
                {"entropy", entropy},
                {"magic", magic.empty() ? json(nullptr) : json(magic)},
                {"pe", pe},
                {"signature", signature},
                {"yara", yara},
                {"clamav", clam},
                {"strings_sample", strings_sample},
                {"verdict", verdict}};
    return aiutil::dump_json(out);
}

std::string t_write_yara_rule(const json& args, AiContext& ctx) {
    std::string name = arg_str(args, "name");
    std::vector<std::string> strings = collect_strings_arg(args);
    std::string condition = arg_str(args, "condition", "any of them");
    std::string description = arg_str(args, "description", "AI 现场生成的特征规则");

    if (name.empty()) return ERR("name 必填");
    for (char c : name)
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '_')
            return ERR("name 只能包含字母数字下划线: " + name);
    if (strings.empty()) return ERR("strings 至少一条特征字符串");
    if (ctx.rules_path.empty()) return ERR("未配置规则目录（yara.rules_path）");
    if (condition.size() > 500) return ERR("condition 过长");

    // 生成规则文本
    std::string text = "rule " + name + " {\n";
    text += "    meta:\n        author = \"AvEngine AI\"\n        description = \"" +
            yara_escape(description) + "\"\n";
    text += "    strings:\n";
    for (size_t i = 0; i < strings.size(); ++i) {
        if (strings[i].size() > 512) return ERR("特征字符串过长（>512）: 第 " + std::to_string(i) + " 条");
        text += "        $s" + std::to_string(i) + " = \"" + yara_escape(strings[i]) + "\" ascii\n";
    }
    text += "    condition:\n        " + condition + "\n}\n";

    std::string target_path = ctx.rules_path + "\\yara\\" + name + ".yar";
    if (dry_run_requested(args, ctx))
        return aiutil::dump_json(json{{"name", name}, {"target_path", target_path},
                                      {"rule_text", text}, {"dry_run", true},
                                      {"note", "将写入规则文件（不执行）"}});

    // 先验证可编译
    std::string temp_dir = make_temp_rule_dir();
    if (temp_dir.empty()) return ERR("无法创建临时目录");
    std::string temp_rule = temp_dir + "\\" + name + ".yar";
    {
        std::ofstream out(fs::path(aiutil::to_wide_sys(temp_rule)), std::ios::binary);
        if (!out) return ERR("无法写入临时规则文件: " + temp_rule);
        out << text;
    }
    {
        YaraEngine check(temp_dir);
        if (!check.available()) {
            std::error_code ec;
            fs::remove_all(fs::path(aiutil::to_wide_sys(temp_dir)), ec);
            return ERR("规则编译失败: " + (check.error().empty() ? "语法错误" : check.error()));
        }
    }
    std::error_code ec;
    fs::remove_all(fs::path(aiutil::to_wide_sys(temp_dir)), ec);

    // 写入规则库
    fs::path ydir(aiutil::to_wide_sys(ctx.rules_path + "\\yara"));
    fs::create_directories(ydir, ec);
    std::ofstream out(fs::path(aiutil::to_wide_sys(target_path)), std::ios::binary);
    if (!out) return ERR("无法写入规则文件（需要写权限）: " + target_path);
    out << text;

    return aiutil::dump_json(json{{"name", name}, {"path", target_path},
                                  {"compiled", true}, {"dry_run", false}});
}

std::string t_scan_with_rule(const json& args, AiContext& ctx) {
    std::string rule = arg_str(args, "rule");
    std::string target = arg_str(args, "target");
    int limit = static_cast<int>(arg_int(args, "limit", 50));
    limit = std::min(std::max(limit, 1), 500);
    if (rule.empty() || target.empty()) return ERR("rule 与 target 必填");
    if (!fs::exists(fs::path(aiutil::to_wide_sys(target))))
        return ERR("目标不存在: " + target);

    // 规则来源：rules\yara 下的文件名，或 YARA 源文本
    std::string rule_text;
    if (rule.find('\n') == std::string::npos && rule.find("rule") == std::string::npos) {
        std::string candidate = (ctx.rules_path.empty() ? std::string() : ctx.rules_path) +
                                 "\\yara\\" + rule;
        if (!fs::is_regular_file(fs::path(aiutil::to_wide_sys(candidate + ".yar"))))
            candidate += ".yara";
        else
            candidate += ".yar";
        if (fs::is_regular_file(fs::path(aiutil::to_wide_sys(candidate)))) {
            std::ifstream in(fs::path(aiutil::to_wide_sys(candidate)), std::ios::binary);
            std::string content((std::istreambuf_iterator<char>(in)),
                                std::istreambuf_iterator<char>());
            rule_text = content;
        }
    }
    if (rule_text.empty()) rule_text = rule;   // 当作 YARA 源文本

    std::string temp_dir = make_temp_rule_dir();
    if (temp_dir.empty()) return ERR("无法创建临时目录");
    std::string temp_rule = temp_dir + "\\scan.yar";
    {
        std::ofstream out(fs::path(aiutil::to_wide_sys(temp_rule)), std::ios::binary);
        if (!out) return ERR("无法写入临时规则文件");
        out << rule_text;
    }
    YaraEngine engine(temp_dir);
    if (!engine.available()) {
        std::error_code ec;
        fs::remove_all(fs::path(aiutil::to_wide_sys(temp_dir)), ec);
        return ERR("规则编译失败: " + (engine.error().empty() ? "语法错误" : engine.error()));
    }

    json matches = json::array();
    long long scanned = 0;
    bool truncated = false;
    auto scan_one = [&](const std::string& p) {
        if (static_cast<int>(matches.size()) >= limit) { truncated = true; return; }
        ++scanned;
        std::vector<std::string> hits = engine.scan_file(p);
        if (!hits.empty())
            matches.push_back({{"path", p}, {"rules", hits}});
    };

    if (fs::is_regular_file(fs::path(aiutil::to_wide_sys(target)))) {
        scan_one(target);
    } else {
        std::error_code ec;
        int files = 0;
        for (auto it = fs::recursive_directory_iterator(
                 fs::path(aiutil::to_wide_sys(target)), ec);
             it != fs::recursive_directory_iterator(); it.increment(ec)) {
            if (ec) break;
            if (files >= 500) { truncated = true; break; }
            if (!it->is_regular_file(ec)) continue;
            ++files;
            scan_one(aiutil::to_utf8(it->path().wstring()));
        }
    }
    std::error_code ec;
    fs::remove_all(fs::path(aiutil::to_wide_sys(temp_dir)), ec);

    json out = {{"scanned", scanned}, {"count", matches.size()},
                {"truncated", truncated}, {"matches", matches}};
    return aiutil::dump_json(out);
}

std::string t_save_baseline(const json& args, AiContext& ctx) {
    std::string kind = to_lower(arg_str(args, "kind", "all"));
    if (kind != "process" && kind != "service" && kind != "task" && kind != "startup" &&
        kind != "all")
        return ERR("kind 取值 process|service|task|startup|all");

    std::vector<std::string> kinds;
    if (kind == "all") kinds = {"process", "service", "task", "startup"};
    else kinds = {kind};

    json plan = json::array();
    for (const auto& k : kinds) plan.push_back({{"kind", k}, {"items", capture_kind(k)}});
    if (dry_run_requested(args, ctx))
        return aiutil::dump_json(json{{"kind", kind}, {"would_save", plan}, {"dry_run", true}});

    if (ctx.project_root.empty()) return ERR("未配置 project_root");
    fs::path bdir(aiutil::to_wide_sys(ctx.project_root + "\\logs\\baselines"));
    std::error_code ec;
    fs::create_directories(bdir, ec);
    if (!fs::is_directory(bdir, ec)) return ERR("无法创建基线目录: " + aiutil::to_utf8(bdir.wstring()));

    json saved = json::array();
    for (const auto& item : plan) {
        std::string k = item["kind"];
        std::string fname = k + "_" + now_suffix() + ".json";
        fs::path fpath = bdir / aiutil::to_wide(fname);
        json content = {{"kind", k}, {"saved_at", now_iso()},
                        {"count", item["items"].size()}, {"items", item["items"]}};
        std::ofstream out(fpath, std::ios::binary);
        if (!out) return ERR("无法写入基线文件: " + aiutil::to_utf8(fpath.wstring()));
        out << aiutil::dump_json(content);
        saved.push_back({{"kind", k}, {"path", aiutil::to_utf8(fpath.wstring())},
                         {"count", item["items"].size()}});
    }
    json out;
    if (kinds.size() == 1) {
        // 单一 kind：契约要求 saved_to 为字符串
        out = {{"kind", kinds[0]},
               {"saved_to", saved.empty() ? json("") : saved[0]["path"]},
               {"count", saved.empty() ? json(0) : saved[0]["count"]},
               {"saved", saved}, {"dry_run", false}};
    } else {
        out = {{"kind", kind}, {"saved_to", saved}, {"count", saved.size()},
               {"saved", saved}, {"dry_run", false}};
    }
    return aiutil::dump_json(out);
}

std::string t_compare_baseline(const json& args, AiContext& ctx) {
    std::string kind = to_lower(arg_str(args, "kind", "process"));
    if (kind == "all") kind = "process";   // 比较时一次一种
    std::string baseline_path = arg_str(args, "baseline");
    if (ctx.project_root.empty()) return ERR("未配置 project_root");
    fs::path bdir(aiutil::to_wide_sys(ctx.project_root + "\\logs\\baselines"));

    // 找基线文件
    if (baseline_path.empty()) {
        std::error_code ec;
        fs::path newest;
        fs::file_time_type newest_time{};
        for (auto it = fs::directory_iterator(bdir, ec); it != fs::directory_iterator();
             it.increment(ec)) {
            if (ec) break;
            if (!it->is_regular_file(ec)) continue;
            std::string n = aiutil::to_utf8(it->path().filename().wstring());
            if (n.rfind(kind + "_", 0) != 0 || n.size() < 6 ||
                n.compare(n.size() - 5, 5, ".json") != 0)
                continue;
            auto tm = it->last_write_time(ec);
            if (ec) continue;
            if (newest.empty() || tm > newest_time) {
                newest = it->path();
                newest_time = tm;
            }
        }
        if (newest.empty())
            return ERR("没有 " + kind + " 的基线，先用 save_baseline 保存");
        baseline_path = aiutil::to_utf8(newest.wstring());
    }
    if (!fs::is_regular_file(fs::path(aiutil::to_wide_sys(baseline_path))))
        return ERR("基线文件不存在: " + baseline_path);

    // 读基线
    std::ifstream in(fs::path(aiutil::to_wide_sys(baseline_path)), std::ios::binary);
    if (!in) return ERR("无法读取基线文件: " + baseline_path);
    std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    json base;
    try {
        base = json::parse(content);
    } catch (const std::exception& e) {
        return ERR(std::string("基线 JSON 解析失败: ") + e.what());
    }
    json base_items = base.value("items", json::array());
    std::set<std::string> base_keys;
    for (const auto& it : base_items) base_keys.insert(item_key(it));

    // 当前
    json cur = capture_kind(kind);
    std::set<std::string> cur_keys;
    for (const auto& it : cur) cur_keys.insert(item_key(it));

    json added = json::array();
    json removed = json::array();
    long long unchanged = 0;
    for (const auto& it : cur) {
        std::string k = item_key(it);
        if (base_keys.count(k)) ++unchanged;
        else added.push_back(it);
    }
    for (const auto& it : base_items) {
        std::string k = item_key(it);
        if (!cur_keys.count(k)) removed.push_back(it);
    }

    json out = {{"kind", kind}, {"baseline", baseline_path},
                {"baseline_count", base_items.size()},
                {"current_count", cur.size()},
                {"added", added}, {"removed", removed}, {"unchanged", unchanged}};
    return aiutil::dump_json(out);
}

std::string t_set_safety(const json& args, AiContext& ctx) {
    bool changed = false;
    if (args.contains("dry_run") && args["dry_run"].is_boolean()) {
        ctx.dry_run = args["dry_run"].get<bool>();
        changed = true;
    }
    if (args.contains("max_tool_result_chars")) {
        long long v = arg_int(args, "max_tool_result_chars", ctx.max_tool_result_chars);
        ctx.max_tool_result_chars = static_cast<int>(std::min(std::max(v, 1000LL), 60000LL));
        changed = true;
    }
    json out = {{"dry_run", ctx.dry_run},
                {"max_tool_result_chars", ctx.max_tool_result_chars},
                {"note", "仅影响本会话" + std::string(changed ? "（已更新）" : "（仅查看）")}};
    return aiutil::dump_json(out);
}

}  // namespace aiext
