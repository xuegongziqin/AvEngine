// ai_tools.cpp - AI 工具库实现（Win32 原生）
// winsock2.h 必须先于任何会引入 windows.h 的头文件（ai_util.h 就会引入），
// 否则 MinGW 报 "#warning Please include winsock2.h before windows.h"。
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include "ai_tools.h"
#include "ai_tools_ext.h"

#include "ai_collectors.h"
#include "ai_util.h"
#include "clamd_client.h"
#include "util.h"
#include "yara_engine.h"

#include <bcrypt.h>
#include <iphlpapi.h>
#include <psapi.h>
#include <softpub.h>
#include <tlhelp32.h>
#include <winsvc.h>
#include <winreg.h>
#include <wintrust.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <map>
#include <sstream>
#include <vector>

using nlohmann::json;
namespace fs = std::filesystem;
using aiutil::to_utf8;
using aiutil::to_wide;
using aiutil::to_wide_sys;

namespace {

std::string ERR(const std::string& m) { return "ERROR: " + m; }

std::string base_name(const std::string& p) {
    // 路径是 UTF-8：先转宽字符再取文件名，最后转回 UTF-8，中文名不会变乱码
    return aiutil::to_utf8(fs::path(aiutil::to_wide_path(p)).filename().wstring());
}

std::string lower(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

// 安全取参：模型偶尔会把数字写成字符串、把字符串写成数字，value<T>() 会抛异常
long long safe_int(const json& a, const char* key, long long def) {
    auto it = a.find(key);
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

std::string safe_str(const json& a, const char* key, const std::string& def = "") {
    auto it = a.find(key);
    if (it == a.end() || it->is_null()) return def;
    if (it->is_string()) return it->get<std::string>();
    if (it->is_boolean()) return it->get<bool>() ? "true" : "false";
    if (it->is_number_integer()) return std::to_string(it->get<long long>());
    return def;
}

std::string now_iso() {
    char buf[32];
    std::time_t t = std::time(nullptr);
    std::tm tmv{};
    localtime_s(&tmv, &t);
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tmv);
    return buf;
}

std::string fmt_time(const FILETIME& ft) {
    SYSTEMTIME st{};
    if (!FileTimeToSystemTime(&ft, &st)) return "";
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d", st.wYear, st.wMonth,
                  st.wDay, st.wHour, st.wMinute, st.wSecond);
    return buf;
}

std::string read_whole(const std::string& path, size_t max_bytes) {
    std::ifstream in(fs::path(to_wide_sys(path)), std::ios::binary);
    if (!in) return "";
    std::string data;
    data.resize(max_bytes);
    in.read(&data[0], static_cast<std::streamsize>(max_bytes));
    data.resize(static_cast<size_t>(in.gcount()));
    return data;
}

std::string hash_file(const std::string& algo, const std::string& path, std::string& err) {
    LPCWSTR alg = nullptr;
    std::string a = lower(algo);
    if (a == "md5") alg = BCRYPT_MD5_ALGORITHM;
    else if (a == "sha1") alg = BCRYPT_SHA1_ALGORITHM;
    else if (a == "sha256") alg = BCRYPT_SHA256_ALGORITHM;
    else if (a == "sha512") alg = BCRYPT_SHA512_ALGORITHM;
    else { err = "不支持的算法: " + algo; return ""; }

    BCRYPT_ALG_HANDLE ah = nullptr;
    if (BCryptOpenAlgorithmProvider(&ah, alg, nullptr, 0) != 0 || !ah) {
        err = "BCryptOpenAlgorithmProvider 失败";
        return "";
    }
    DWORD obj_len = 0, cb = 0;
    BCryptGetProperty(ah, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&obj_len), sizeof(obj_len), &cb, 0);
    std::vector<unsigned char> obj(obj_len);
    BCRYPT_HASH_HANDLE hh = nullptr;
    if (BCryptCreateHash(ah, &hh, obj.data(), obj_len, nullptr, 0, 0) != 0) {
        BCryptCloseAlgorithmProvider(ah, 0);
        err = "BCryptCreateHash 失败";
        return "";
    }
    std::FILE* fp = _wfopen(to_wide_sys(path).c_str(), L"rb");
    if (!fp) {
        BCryptDestroyHash(hh);
        BCryptCloseAlgorithmProvider(ah, 0);
        err = "无法打开文件: " + path;
        return "";
    }
    std::vector<unsigned char> buf(1 << 20);
    size_t n;
    while ((n = std::fread(buf.data(), 1, buf.size(), fp)) > 0) {
        BCryptHashData(hh, buf.data(), static_cast<ULONG>(n), 0);
    }
    std::fclose(fp);

    DWORD digest_len = 64;
    BCryptGetProperty(ah, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&digest_len), sizeof(digest_len), &cb, 0);
    std::vector<unsigned char> digest(digest_len);
    std::string result;
    if (BCryptFinishHash(hh, digest.data(), digest_len, 0) == 0) {
        result = to_hex_lower(digest.data(), digest_len);
    } else {
        err = "BCryptFinishHash 失败";
    }
    BCryptDestroyHash(hh);
    BCryptCloseAlgorithmProvider(ah, 0);
    return result;
}

std::string process_path(DWORD pid) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return "";
    wchar_t buf[MAX_PATH * 2];
    DWORD n = static_cast<DWORD>(MAX_PATH * 2);
    std::string path;
    if (QueryFullProcessImageNameW(h, 0, buf, &n)) path = to_utf8(std::wstring(buf, n));
    CloseHandle(h);
    return path;
}

std::string process_name(DWORD pid) {
    std::string p = process_path(pid);
    return p.empty() ? "" : base_name(p);
}

unsigned long long process_rss(DWORD pid) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return 0;
    PROCESS_MEMORY_COUNTERS pmc{};
    unsigned long long rss = 0;
    if (GetProcessMemoryInfo(h, &pmc, sizeof(pmc))) rss = pmc.WorkingSetSize;
    CloseHandle(h);
    return rss;
}

// 轻量 Authenticode 校验（无 UI、不查吊销，够快），用于"只看无签名模块"过滤
bool quick_is_signed(const std::string& path_utf8) {
    std::wstring wpath = to_wide_sys(path_utf8);
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
    data.dwStateAction = WTD_STATEACTION_CLOSE;   // 释放状态数据
    WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &action, &data);
    return rc == 0;
}

// 说明：这里曾有一个基于 _popen 的 run_capture（无超时、无错误上报、ANSI 编码，
// 子命令失败还会被静默吞掉）。需要执行外部命令的工具统一改用
// aiext::run_capture()（CreateProcessW + 超时 + 错误回报 + 编码自适应）。

// ---------------- 进程 ----------------

std::string t_list_processes(const json& a, AiContext&) {
    std::string kw = lower(a.value("keyword", ""));
    int limit = std::min(a.value("limit", 50), 500);
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return ERR("CreateToolhelp32Snapshot 失败");
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    json rows = json::array();
    if (Process32FirstW(snap, &pe)) {
        do {
            DWORD pid = pe.th32ProcessID;
            std::string name = to_utf8(pe.szExeFile);
            std::string exe = process_path(pid);
            if (!kw.empty() && lower(name).find(kw) == std::string::npos &&
                lower(exe).find(kw) == std::string::npos)
                continue;
            unsigned long long rss = process_rss(pid);
            rows.push_back({{"pid", pid}, {"name", name}, {"exe", exe},
                            {"rss_mb", static_cast<double>(rss) / 1048576.0}});
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    std::sort(rows.begin(), rows.end(),
              [](const json& x, const json& y) { return x["rss_mb"].get<double>() > y["rss_mb"].get<double>(); });
    int total = static_cast<int>(rows.size());
    if (total > limit) rows.erase(rows.begin() + limit, rows.end());
    return json{{"total", total}, {"returned", rows.size()}, {"processes", rows}}.dump();
}

std::string t_get_process_info(const json& a, AiContext&) {
    DWORD pid = a.value("pid", 0);
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return ERR("进程不存在或拒绝访问 PID=" + std::to_string(pid));
    wchar_t buf[MAX_PATH * 2];
    DWORD n = static_cast<DWORD>(std::size(buf));
    std::string exe;
    if (QueryFullProcessImageNameW(h, 0, buf, &n)) exe = to_utf8(std::wstring(buf, n));
    FILETIME ct{}, et{}, kt{}, ut{};
    GetProcessTimes(h, &ct, &et, &kt, &ut);
    PROCESS_MEMORY_COUNTERS pmc{};
    GetProcessMemoryInfo(h, &pmc, sizeof(pmc));
    CloseHandle(h);

    std::string hash, herr;
    if (!exe.empty() && fs::is_regular_file(fs::path(to_wide_sys(exe)))) {
        hash = hash_file("sha256", exe, herr);
    }
    json j = {{"pid", pid},
              {"name", base_name(exe)},
              {"exe", exe},
              {"exe_sha256", hash.empty() ? json(nullptr) : json(hash)},
              {"started", fmt_time(ct)},
              {"threads", nullptr},
              {"rss_mb", static_cast<double>(pmc.WorkingSetSize) / 1048576.0}};
    return j.dump();
}

std::string t_list_process_modules(const json& a, AiContext&) {
    DWORD pid = a.value("pid", 0);
    int limit = std::min(std::max(a.value("limit", 200), 1), 1000);
    int offset = std::min(std::max(a.value("offset", 0), 0), 900);
    // filter: all | unsigned（只看无签名模块，识别注入/未签名 DLL）
    std::string filter = lower(a.value("filter", "all"));

    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!h) return ERR("拒绝访问 PID=" + std::to_string(pid));
    std::vector<HMODULE> mods(1024);
    DWORD needed = 0;
    json out = json::array();
    int total = 0;
    bool truncated = false;
    if (EnumProcessModulesEx(h, mods.data(), static_cast<DWORD>(mods.size() * sizeof(HMODULE)),
                             &needed, LIST_MODULES_ALL)) {
        total = static_cast<int>(needed / sizeof(HMODULE));
        if (total > static_cast<int>(mods.size())) {   // 缓冲不够，扩容重试
            mods.resize(static_cast<size_t>(total) + 64);
            if (EnumProcessModulesEx(h, mods.data(),
                                     static_cast<DWORD>(mods.size() * sizeof(HMODULE)),
                                     &needed, LIST_MODULES_ALL))
                total = static_cast<int>(needed / sizeof(HMODULE));
        }
        int sig_checked = 0;
        for (int i = offset; i < total; ++i) {
            wchar_t path[MAX_PATH];
            if (!GetModuleFileNameExW(h, mods[i], path, MAX_PATH)) continue;
            std::string mp = to_utf8(path);

            if (filter == "unsigned") {
                if (sig_checked >= 200) { truncated = true; break; }  // 签名校验预算
                ++sig_checked;
                if (quick_is_signed(mp)) continue;
            }
            out.push_back(mp);
            if (static_cast<int>(out.size()) >= limit) { truncated = (i + 1 < total); break; }
        }
    }
    CloseHandle(h);
    json result = {{"pid", pid}, {"total_modules", total}, {"offset", offset},
                   {"modules_returned", out.size()}, {"truncated", truncated},
                   {"modules", out}};
    return aiutil::dump_json(result);
}

std::string t_dump_memory(const json& a, AiContext& ctx) {
    DWORD pid = a.value("pid", 0);
    int max_mb = std::min(std::max(a.value("max_mb", 64), 1), 512);
    if (pid <= 4) return ERR("PID=" + std::to_string(pid) + " 是系统保护进程，禁止转储");

    HANDLE h = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!h) return ERR("OpenProcess 失败（需要管理员或进程已退出）");

    std::error_code ec;
    // ctx.dump_dir 是 UTF-8 字符串；fs::path 直接收 char* 会按 ANSI 解码（中文用户名下必失败）
    const fs::path dump_dir(aiutil::to_wide_path(ctx.dump_dir));
    fs::create_directories(dump_dir, ec);
    char ts[32];
    std::time_t t = std::time(nullptr);
    std::tm tmv{};
    localtime_s(&tmv, &t);
    std::strftime(ts, sizeof(ts), "%Y%m%d_%H%M%S", &tmv);
    fs::path out_path = dump_dir / aiutil::to_wide_path("pid" + std::to_string(pid) + "_" + ts + ".bin");

    unsigned long long written = 0, max_bytes = static_cast<unsigned long long>(max_mb) * 1048576ULL;
    std::ofstream out(out_path, std::ios::binary);
    if (!out) {
        CloseHandle(h);
        return ERR("无法创建转储文件: " + aiutil::to_utf8(out_path.wstring()));
    }

    MEMORY_BASIC_INFORMATION mbi{};
    unsigned long long addr = 0;
    std::vector<char> buf(1 << 20);
    int regions = 0;
    while (addr < 0x00007FFFFFF00000ULL && written < max_bytes) {
        if (!VirtualQueryEx(h, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi))) break;
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) == 0 &&
            (mbi.Protect & 0xFF) != 0) {
            unsigned long long base = reinterpret_cast<unsigned long long>(mbi.BaseAddress);
            unsigned long long size = mbi.RegionSize;
            unsigned long long off = 0;
            while (off < size && written < max_bytes) {
                SIZE_T chunk = static_cast<SIZE_T>(std::min<unsigned long long>(buf.size(), size - off));
                SIZE_T read = 0;
                if (ReadProcessMemory(h, reinterpret_cast<LPCVOID>(base + off), buf.data(), chunk, &read) && read) {
                    out.write(buf.data(), read);
                    written += read;
                }
                off += chunk;
            }
            ++regions;
        }
        unsigned long long next = reinterpret_cast<unsigned long long>(mbi.BaseAddress) + mbi.RegionSize;
        if (next <= addr) break;
        addr = next;
    }
    out.close();
    CloseHandle(h);
    if (written == 0) {
        std::error_code rec;
        fs::remove(out_path, rec);
        return ERR("没有读取到任何可读内存（进程可能已退出）");
    }
    return json{{"path", aiutil::to_utf8(out_path.wstring())},
                {"bytes_written", written},
                {"size_mb", static_cast<double>(written) / 1048576.0},
                {"regions_read", regions},
                {"next_hint", "用 extract_strings 从该文件提取可打印字符串"}}
        .dump();
}

// ---------------- 文件 ----------------

std::string t_file_hash(const json& a, AiContext&) {
    std::string path = a.value("path", "");
    if (!fs::is_regular_file(fs::path(to_wide_sys(path)))) return ERR("文件不存在: " + path);
    std::string algos = a.value("algos", "sha256");
    json out = json::object();
    std::istringstream ss(algos);
    std::string algo;
    while (std::getline(ss, algo, ',')) {
        algo = lower(algo);
        if (algo.empty()) continue;
        std::string err;
        std::string hex = hash_file(algo, path, err);
        if (hex.empty()) return ERR(err);
        out[algo] = hex;
    }
    out["path"] = path;
    std::error_code ec;
    out["size"] = static_cast<unsigned long long>(fs::file_size(fs::path(to_wide_sys(path)), ec));
    return out.dump();
}

std::string t_read_file_text(const json& a, AiContext&) {
    std::string path = a.value("path", "");
    if (!fs::is_regular_file(fs::path(to_wide_sys(path)))) return ERR("文件不存在: " + path);
    long long offset = std::max<long long>(a.value("offset", 0), 0);
    int length = std::min(std::max(a.value("length", 4096), 1), 65536);
    std::ifstream in(fs::path(to_wide_sys(path)), std::ios::binary);
    if (!in) return ERR("读取失败: " + path);
    in.seekg(offset);
    std::string data;
    data.resize(length);
    in.read(&data[0], length);
    data.resize(static_cast<size_t>(in.gcount()));
    return "[path=" + path + " offset=" + std::to_string(offset) + "]\n" + data;
}

std::string t_scan_file(const json& a, AiContext& ctx) {
    std::string path = a.value("path", "");
    if (!fs::is_regular_file(fs::path(to_wide_sys(path)))) return ERR("文件不存在: " + path);
    YaraEngine yara(ctx.rules_path);
    std::vector<std::string> matches;
    if (yara.available()) matches = yara.scan_file(path);
    bool clam_avail = false;
    std::string virus;
    if (!ctx.clam_host.empty() && ctx.clam_port > 0) {
        ClamdClient clam(ctx.clam_host, ctx.clam_port, ctx.clam_timeout);
        ClamScanResult cr = clam.scan_file(path);
        clam_avail = cr.error.empty();
        virus = cr.virus;
    }
    std::string verdict = (matches.empty() && virus.empty()) ? "clean" : "infected";
    return json{{"path", path},
                {"yara", {{"available", yara.available()}, {"matches", matches}}},
                {"clamav", {{"available", clam_avail}, {"virus", virus.empty() ? json(nullptr) : json(virus)}}},
                {"verdict", verdict}}
        .dump();
}

std::string t_get_pe_info(const json& a, AiContext&) {
    std::string path = a.value("path", "");
    if (!fs::is_regular_file(fs::path(to_wide_sys(path)))) return ERR("文件不存在: " + path);
    std::string d = read_whole(path, 4 * 1024 * 1024);
    if (d.size() < 64 || d[0] != 'M' || d[1] != 'Z') return ERR("不是有效的 PE 文件");
    uint32_t peoff = *reinterpret_cast<const uint32_t*>(d.data() + 0x3C);
    if (peoff + 24 > d.size() || std::memcmp(d.data() + peoff, "PE\0\0", 4) != 0)
        return ERR("不是有效的 PE 文件");
    const unsigned char* fh = reinterpret_cast<const unsigned char*>(d.data() + peoff + 4);
    uint16_t machine = *reinterpret_cast<const uint16_t*>(fh);
    uint16_t nsec = *reinterpret_cast<const uint16_t*>(fh + 2);
    uint32_t tds = *reinterpret_cast<const uint32_t*>(fh + 4);
    uint16_t optsize = *reinterpret_cast<const uint16_t*>(fh + 16);
    const unsigned char* oh = fh + 20;
    if (oh + 70 > reinterpret_cast<const unsigned char*>(d.data()) + d.size())
        return ERR("PE 头不完整");
    uint16_t magic = *reinterpret_cast<const uint16_t*>(oh);
    uint32_t entry = *reinterpret_cast<const uint32_t*>(oh + 16);
    uint16_t subsystem = *reinterpret_cast<const uint16_t*>(oh + 68);
    bool is64 = (magic == 0x20B);
    unsigned long long image_base;
    if (is64) image_base = *reinterpret_cast<const uint64_t*>(oh + 24);
    else image_base = *reinterpret_cast<const uint32_t*>(oh + 28);

    json sections = json::array();
    const unsigned char* sh = oh + optsize;
    for (int i = 0; i < nsec && sh + 40 <= reinterpret_cast<const unsigned char*>(d.data()) + d.size(); ++i, sh += 40) {
        char name[9] = {0};
        std::memcpy(name, sh, 8);
        sections.push_back({{"name", std::string(name)},
                            {"virtual_size", *reinterpret_cast<const uint32_t*>(sh + 8)},
                            {"raw_size", *reinterpret_cast<const uint32_t*>(sh + 16)}});
    }
    char machbuf[16];
    std::snprintf(machbuf, sizeof(machbuf), "0x%x", machine);
    time_t ct = static_cast<time_t>(tds);
    std::tm tmv{};
    gmtime_s(&tmv, &ct);
    char ctbuf[32];
    std::strftime(ctbuf, sizeof(ctbuf), "%Y-%m-%d %H:%M:%S", &tmv);

    return json{{"path", path},
                {"machine", machbuf},
                {"is_64bit", is64},
                {"entry_point", entry},
                {"image_base", image_base},
                {"compile_time", ctbuf},
                {"subsystem", subsystem},
                {"sections", sections}}
        .dump();
}

std::string t_extract_strings(const json& a, AiContext&) {
    std::string path = a.value("path", "");
    if (!fs::is_regular_file(fs::path(to_wide_sys(path)))) return ERR("文件不存在: " + path);
    int min_len = std::min(std::max(a.value("min_length", 5), 3), 32);
    size_t max_bytes = std::min<size_t>(std::max(a.value("max_bytes", 1048576), 1024), 64 * 1048576);
    int limit = std::min(a.value("limit", 200), 1000);
    std::string blob = read_whole(path, max_bytes);

    json out = json::array();
    std::string cur;
    for (unsigned char c : blob) {
        if (c >= 0x20 && c < 0x7f) {
            cur += static_cast<char>(c);
        } else {
            if (static_cast<int>(cur.size()) >= min_len && static_cast<int>(out.size()) < limit)
                out.push_back(cur);
            cur.clear();
            if (static_cast<int>(out.size()) >= limit) break;
        }
    }
    if (static_cast<int>(out.size()) < limit && static_cast<int>(cur.size()) >= min_len)
        out.push_back(cur);
    return json{{"path", path}, {"scanned_bytes", blob.size()}, {"strings", out}}.dump();
}

// ---------------- 网络 ----------------

std::string t_list_connections(const json& a, AiContext&) {
    json rows = json::array();
    int limit = std::min(a.value("limit", 100), 500);
    bool has_pid = a.contains("pid") && !a["pid"].is_null();
    DWORD want_pid = has_pid ? a.value("pid", 0) : 0;
    std::string state_filter = a.value("state", "");
    for (auto& c : state_filter) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));

    static const std::map<DWORD, std::string> states = {
        {1, "CLOSED"}, {2, "LISTEN"}, {3, "SYN_SENT"}, {4, "SYN_RCVD"}, {5, "ESTABLISHED"},
        {6, "FIN_WAIT1"}, {7, "FIN_WAIT2"}, {8, "CLOSE_WAIT"}, {9, "CLOSING"},
        {10, "LAST_ACK"}, {11, "TIME_WAIT"}, {12, "DELETE_TCB"}};

    DWORD size = 0;
    if (GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == ERROR_INSUFFICIENT_BUFFER) {
        std::vector<unsigned char> buf(size);
        if (GetExtendedTcpTable(buf.data(), &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
            auto* table = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(buf.data());
            for (DWORD i = 0; i < table->dwNumEntries && static_cast<int>(rows.size()) < limit; ++i) {
                const MIB_TCPROW_OWNER_PID& r = table->table[i];
                if (has_pid && r.dwOwningPid != want_pid) continue;
                std::string st = states.count(r.dwState) ? states.at(r.dwState) : std::to_string(r.dwState);
                if (!state_filter.empty() && st != state_filter) continue;
                char la[32], ra[32];
                std::snprintf(la, sizeof(la), "%lu.%lu.%lu.%lu:%u",
                              static_cast<unsigned long>(r.dwLocalAddr & 0xff),
                              static_cast<unsigned long>((r.dwLocalAddr >> 8) & 0xff),
                              static_cast<unsigned long>((r.dwLocalAddr >> 16) & 0xff),
                              static_cast<unsigned long>((r.dwLocalAddr >> 24) & 0xff),
                              ntohs(static_cast<u_short>(r.dwLocalPort)));
                std::snprintf(ra, sizeof(ra), "%lu.%lu.%lu.%lu:%u",
                              static_cast<unsigned long>(r.dwRemoteAddr & 0xff),
                              static_cast<unsigned long>((r.dwRemoteAddr >> 8) & 0xff),
                              static_cast<unsigned long>((r.dwRemoteAddr >> 16) & 0xff),
                              static_cast<unsigned long>((r.dwRemoteAddr >> 24) & 0xff),
                              ntohs(static_cast<u_short>(r.dwRemotePort)));
                rows.push_back({{"pid", r.dwOwningPid},
                                {"process", process_name(r.dwOwningPid)},
                                {"laddr", la},
                                {"raddr", ra},
                                {"status", st}});
            }
        }
    }
    return json{{"returned", rows.size()}, {"connections", rows}}.dump();
}

std::string t_network_stats(const json&, AiContext&) {
    DWORD size = 0;
    if (GetIfTable(nullptr, &size, FALSE) == ERROR_INSUFFICIENT_BUFFER) {
        std::vector<unsigned char> buf(size);
        if (GetIfTable(reinterpret_cast<MIB_IFTABLE*>(buf.data()), &size, FALSE) == NO_ERROR) {
            auto* table = reinterpret_cast<MIB_IFTABLE*>(buf.data());
            json out = json::object();
            unsigned long long total_in = 0, total_out = 0;
            for (DWORD i = 0; i < table->dwNumEntries && i < 40; ++i) {
                const MIB_IFROW& r = table->table[i];
                std::string name = to_utf8(std::wstring(r.wszName));
                if (name.empty()) name = "if" + std::to_string(r.dwIndex);
                out[name] = {{"sent_mb", static_cast<double>(r.dwOutOctets) / 1048576.0},
                             {"recv_mb", static_cast<double>(r.dwInOctets) / 1048576.0}};
                total_in += r.dwInOctets;
                total_out += r.dwOutOctets;
            }
            out["_total"] = {{"sent_mb", static_cast<double>(total_out) / 1048576.0},
                             {"recv_mb", static_cast<double>(total_in) / 1048576.0}};
            return out.dump();
        }
    }
    return ERR("GetIfTable 失败");
}

// ---------------- 系统 ----------------

std::string t_list_services(const json& a, AiContext&) {
    std::string filter = lower(a.value("state", "all"));
    int limit = std::min(a.value("limit", 200), 1000);
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) return ERR("打开服务控制管理器失败（需要管理员）");
    DWORD needed = 0, count = 0, resume = 0;
    EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, nullptr, 0,
                          &needed, &count, &resume, nullptr);
    std::vector<unsigned char> buf(needed);
    json rows = json::array();
    if (EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, buf.data(),
                              needed, &needed, &count, &resume, nullptr)) {
        auto* arr = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(buf.data());
        for (DWORD i = 0; i < count && static_cast<int>(rows.size()) < limit; ++i) {
            std::string state;
            switch (arr[i].ServiceStatusProcess.dwCurrentState) {
                case SERVICE_RUNNING: state = "RUNNING"; break;
                case SERVICE_STOPPED: state = "STOPPED"; break;
                case SERVICE_PAUSED: state = "PAUSED"; break;
                default: state = "OTHER"; break;
            }
            if (filter == "running" && state != "RUNNING") continue;
            if (filter == "stopped" && state != "STOPPED") continue;
            rows.push_back({{"name", to_utf8(arr[i].lpServiceName)},
                            {"display", to_utf8(arr[i].lpDisplayName)},
                            {"state", state}});
        }
    }
    CloseServiceHandle(scm);
    return json{{"total", count}, {"returned", rows.size()}, {"services", rows}}.dump();
}

HKEY reg_root(const std::string& name, bool& ok) {
    ok = true;
    if (name == "HKLM" || name == "HKEY_LOCAL_MACHINE") return HKEY_LOCAL_MACHINE;
    if (name == "HKCU" || name == "HKEY_CURRENT_USER") return HKEY_CURRENT_USER;
    if (name == "HKCR" || name == "HKEY_CLASSES_ROOT") return HKEY_CLASSES_ROOT;
    if (name == "HKU" || name == "HKEY_USERS") return HKEY_USERS;
    ok = false;
    return nullptr;
}

std::string t_read_registry(const json& a, AiContext&) {
    std::string key = a.value("key", "");
    for (auto& c : key) if (c == '/') c = '\\';
    size_t slash = key.find('\\');
    std::string rootname = slash == std::string::npos ? key : key.substr(0, slash);
    std::string subkey = slash == std::string::npos ? "" : key.substr(slash + 1);
    for (auto& c : rootname) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    bool ok = false;
    HKEY root = reg_root(rootname, ok);
    if (!ok) return ERR("无效的根键 " + rootname);

    HKEY hk = nullptr;
    if (RegOpenKeyExW(root, to_wide(subkey).c_str(), 0, KEY_READ, &hk) != ERROR_SUCCESS)
        return ERR("打开注册表键失败: " + key);

    json out;
    if (a.contains("value_name") && !a["value_name"].is_null()) {
        std::string vn = a["value_name"].get<std::string>();
        wchar_t buf[8192];
        DWORD size = sizeof(buf), type = 0;
        if (RegQueryValueExW(hk, to_wide(vn).c_str(), nullptr, &type,
                             reinterpret_cast<LPBYTE>(buf), &size) != ERROR_SUCCESS) {
            RegCloseKey(hk);
            return ERR("值不存在: " + vn);
        }
        out = {{"key", key}, {"value_name", vn}, {"type", type},
               {"data", to_utf8(std::wstring(buf, size / sizeof(wchar_t)))}};
    } else {
        json values = json::array();
        for (DWORD i = 0; i < 200; ++i) {
            wchar_t name[512];
            DWORD nsize = 512, type = 0;
            BYTE data[4096];
            DWORD dsize = sizeof(data);
            LONG rc = RegEnumValueW(hk, i, name, &nsize, nullptr, &type, data, &dsize);
            if (rc != ERROR_SUCCESS) break;
            std::string val;
            if (type == REG_SZ || type == REG_EXPAND_SZ)
                val = to_utf8(std::wstring(reinterpret_cast<wchar_t*>(data), dsize / sizeof(wchar_t)));
            else if (type == REG_DWORD && dsize >= 4)
                val = std::to_string(*reinterpret_cast<DWORD*>(data));
            else {
                char hex[8];
                std::snprintf(hex, sizeof(hex), "(%luB)", static_cast<unsigned long>(dsize));
                val = hex;
            }
            values.push_back({{"name", to_utf8(name)}, {"type", type}, {"data", val}});
        }
        out = {{"key", key}, {"count", values.size()}, {"values", values}};
    }
    RegCloseKey(hk);
    return out.dump();
}

// 回退：schtasks 被策略/权限挡住时，直接枚举任务库目录
// （%SystemRoot%\System32\Tasks 下每个 XML 文件就是一个任务，相对路径就是任务名）
json list_tasks_from_store(int limit, const std::string& kw) {
    json tasks = json::array();
    wchar_t win[MAX_PATH]{};
    if (!GetWindowsDirectoryW(win, MAX_PATH)) return tasks;
    fs::path dir = fs::path(win) / L"System32" / L"Tasks";
    std::error_code ec;
    if (!fs::is_directory(dir, ec)) return tasks;
    for (auto it = fs::recursive_directory_iterator(
             dir, fs::directory_options::skip_permission_denied, ec);
         it != fs::recursive_directory_iterator() && static_cast<int>(tasks.size()) < limit;
         it.increment(ec)) {
        if (ec) break;
        std::error_code fec;
        if (!it->is_regular_file(fec)) continue;
        std::string rel = aiutil::to_utf8(fs::relative(it->path(), dir, fec).wstring());
        if (fec || rel.empty()) continue;
        std::replace(rel.begin(), rel.end(), '/', '\\');
        if (!kw.empty() && lower(rel).find(kw) == std::string::npos) continue;
        tasks.push_back(rel);
    }
    return tasks;
}

std::string t_list_scheduled_tasks(const json& a, AiContext&) {
    std::string kw = lower(safe_str(a, "keyword"));
    int limit = static_cast<int>(std::min<long long>(std::max<long long>(safe_int(a, "limit", 200), 1), 1000));

    // 用 aiext::run_capture：有超时、失败会返回 ERROR（旧实现用 _popen，schtasks 一旦失败
    // 错误被 2>nul 吞掉，工具就静默返回 0 条），并按 OEM 代码页转成 UTF-8，
    // 中文系统上的任务名不会变乱码。
    //
    // 注意 /NH：部分系统（实测 Windows 7 中文版）会报
    // "错误: /NH 开关不能与 LIST 格式同时使用"，直接导致本工具完全拿不到数据。
    // 所以下面解析不到任务且错误行与 /NH 相关时，会**不带 /NH 重试一次**（首行是表头，跳过）。
    auto parse_csv = [&](const std::string& text, bool skip_header, json& tasks,
                         std::string& error_line) {
        std::istringstream ss(text);
        std::string line;
        bool first = true;
        while (std::getline(ss, line) && static_cast<int>(tasks.size()) < limit) {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            if (first && skip_header) {
                first = false;
                continue;   // 不带 /NH 时第一行是表头（TaskName, Next Run Time, ...）
            }
            first = false;
            // 本地化的错误/提示行（"错误: ..." / "ERROR: ..." / "信息: ..."）不是任务名
            std::string low_line = lower(line);
            if (low_line.rfind("错误", 0) == 0 || low_line.rfind("error", 0) == 0 ||
                low_line.rfind("info", 0) == 0 || low_line.rfind("信息", 0) == 0) {
                if (error_line.empty()) error_line = line;
                continue;
            }
            // CSV 第一列
            std::string name;
            if (!line.empty() && line[0] == '"') {
                size_t end = line.find('"', 1);
                name = line.substr(1, end == std::string::npos ? std::string::npos : end - 1);
            } else {
                size_t comma = line.find(',');
                name = line.substr(0, comma);
            }
            while (!name.empty() && name.front() == '\\') name.erase(name.begin());
            if (name.empty()) continue;
            // 兜底：若表头没被跳过，靠首列名字认出来
            if (lower(name) == "taskname" || name == "任务名") { tasks.clear(); continue; }
            if (!kw.empty() && lower(name).find(kw) == std::string::npos) continue;
            tasks.push_back(name);
        }
    };

    auto nh_related = [](const std::string& s) {
        std::string low = lower(s);
        return low.find("/nh") != std::string::npos || s.find("开关不能与") != std::string::npos;
    };

    std::string text = aiext::run_capture("schtasks /query /fo CSV /nh", 30000, 512 * 1024);
    json tasks = json::array();
    std::string error_line;
    if (text.rfind("ERROR: ", 0) != 0) parse_csv(text, false, tasks, error_line);

    // /NH 被系统拒绝 → 退回不带 /NH 的 CSV（表头跳过）
    if (tasks.empty() && (!error_line.empty() ? nh_related(error_line) : text.rfind("ERROR: ", 0) == 0)) {
        std::string retry = aiext::run_capture("schtasks /query /fo CSV", 30000, 512 * 1024);
        if (retry.rfind("ERROR: ", 0) != 0) {
            json retry_tasks = json::array();
            std::string retry_error;
            parse_csv(retry, true, retry_tasks, retry_error);
            if (!retry_tasks.empty()) {
                tasks = retry_tasks;
                error_line.clear();
                json out = {{"returned", tasks.size()}, {"tasks", tasks},
                            {"note", "本机 schtasks 不接受 /NH，已改用不带 /NH 的 CSV 输出"}};
                return aiutil::dump_json(out);
            }
            if (error_line.empty()) error_line = retry_error;
        }
    }

    if (text.rfind("ERROR: ", 0) == 0 && tasks.empty()) {
        json from_store = list_tasks_from_store(limit, kw);
        if (!from_store.empty())
            return aiutil::dump_json(json{{"returned", from_store.size()}, {"tasks", from_store},
                                          {"source", "tasks_dir"},
                                          {"note", "schtasks 执行失败（" + text +
                                                   "），已改为直接枚举任务库目录"}});
        return text;
    }

    if (tasks.empty() && !error_line.empty()) {
        // schtasks 自己报错时也退回任务库目录
        json from_store = list_tasks_from_store(limit, kw);
        if (!from_store.empty())
            return aiutil::dump_json(json{{"returned", from_store.size()}, {"tasks", from_store},
                                          {"source", "tasks_dir"},
                                          {"note", "schtasks 不可用（" + error_line +
                                                   "），已直接枚举任务库目录"}});
        return ERR("schtasks 返回错误: " + error_line +
                   "；任务库目录也读不到（通常需要管理员）");
    }
    json out = {{"returned", tasks.size()}, {"tasks", tasks}};
    if (tasks.empty()) {
        // 别静默返回空：把原文开头带上，失败原因一眼可见
        std::string preview = text.substr(0, 300);
        out["note"] = preview.empty() ? "schtasks 没有输出（可能被策略限制）"
                                      : ("schtasks 未返回可用任务，原文开头: " + preview);
    }
    return aiutil::dump_json(out);
}

void enum_uninstall(HKEY root, const wchar_t* subkey, const std::string& kw, int limit, json& out) {
    HKEY parent = nullptr;
    if (RegOpenKeyExW(root, subkey, 0, KEY_READ, &parent) != ERROR_SUCCESS) return;
    for (DWORD i = 0; i < 1000 && static_cast<int>(out.size()) < limit; ++i) {
        wchar_t sub[512];
        DWORD len = 512;
        if (RegEnumKeyExW(parent, i, sub, &len, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
            break;
        HKEY k = nullptr;
        if (RegOpenKeyExW(parent, sub, 0, KEY_READ, &k) != ERROR_SUCCESS) continue;
        auto get = [&](const wchar_t* name) -> std::string {
            wchar_t buf[1024];
            DWORD size = sizeof(buf), type = 0;
            if (RegQueryValueExW(k, name, nullptr, &type, reinterpret_cast<LPBYTE>(buf), &size) == ERROR_SUCCESS)
                return to_utf8(std::wstring(buf, size / sizeof(wchar_t) > 0 ? size / sizeof(wchar_t) - 1 : 0));
            return "";
        };
        std::string display = get(L"DisplayName");
        if (!display.empty()) {
            if (kw.empty() || lower(display).find(kw) != std::string::npos) {
                out.push_back({{"name", display},
                               {"version", get(L"DisplayVersion")},
                               {"publisher", get(L"Publisher")}});
            }
        }
        RegCloseKey(k);
    }
    RegCloseKey(parent);
}

std::string t_list_installed_programs(const json& a, AiContext&) {
    std::string kw = lower(a.value("keyword", ""));
    int limit = std::min(a.value("limit", 200), 1000);
    json out = json::array();
    enum_uninstall(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", kw, limit, out);
    enum_uninstall(HKEY_LOCAL_MACHINE, L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall", kw, limit, out);
    enum_uninstall(HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", kw, limit, out);
    return json{{"returned", out.size()}, {"programs", out}}.dump();
}

// ---------------- 事件 ----------------

std::string t_query_events(const json& a, AiContext&) {
    std::string source = lower(a.value("source", ""));
    if (!ai_is_known_source(source)) return ERR("未知事件源: " + source);
    double hours = a.value("hours", 1.0);
    int limit = std::min(a.value("limit", 50), 500);
    std::string kw = a.value("keyword", "");
    auto res = ai_query_tool(source, hours, limit, kw);
    std::string out = res.first;
    if (!res.second.empty()) out = "ERROR: " + res.second + "\n---\n" + out;
    return out;
}

std::string t_grep_events(const json& a, AiContext&) {
    std::string source = lower(a.value("source", ""));
    if (!ai_is_known_source(source)) return ERR("未知事件源: " + source);
    std::string kw = a.value("keyword", "");
    double hours = a.value("hours", 24.0);
    int limit = std::min(a.value("limit", 100), 500);
    std::string hint;
    if (source == "fileio") {
        hint = "提示: fileio 为按需检索源（不随批次发送）。通道未启用时用管理员执行 "
               "wevtutil sl \"Microsoft-Windows-Kernel-File/Operational\" /e:true\n---\n";
    }
    auto res = ai_query_tool(source, hours, limit, kw);
    std::string out = res.first;
    if (!res.second.empty()) out = "ERROR: " + res.second + "\n---\n" + out;
    return hint + out;
}

std::string t_get_event_xml(const json& a, AiContext&) {
    std::string source = lower(a.value("source", ""));
    long long rid = a.value("record_id", 0LL);
    std::string err;
    std::string xml = ai_get_event_xml(source, rid, err);
    if (!err.empty()) return ERR(err);
    if (xml.size() > 20000) xml = aiutil::utf8_truncate(xml, 20000) + "\n...[XML 被截断]";
    return xml;
}

// ---------------- 处置 ----------------

std::string sidecar_path(const std::string& quarantined) { return quarantined + ".ai.json"; }

std::string t_quarantine_file(const json& a, AiContext& ctx) {
    std::string path = a.value("path", "");
    if (!fs::is_regular_file(fs::path(to_wide_sys(path)))) return ERR("文件不存在: " + path);
    std::string reason = a.value("reason", "");
    std::error_code ec;
    // 全线 UTF-8 -> 宽字符：中文/日文文件名既要能隔离，也要保持文件名可读
    const fs::path quarantine_dir(to_wide_sys(ctx.quarantine_dir));
    fs::create_directories(quarantine_dir, ec);
    const fs::path src(to_wide_sys(path));
    std::string stem = aiutil::to_utf8(src.stem().wstring());
    std::string ext = aiutil::to_utf8(src.extension().wstring());
    char ts[32];
    std::time_t t = std::time(nullptr);
    std::tm tmv{};
    localtime_s(&tmv, &t);
    std::strftime(ts, sizeof(ts), "%Y%m%d_%H%M%S", &tmv);
    fs::path dest = quarantine_dir / to_wide_sys(stem + "_" + ts + ext);
    int counter = 1;
    while (fs::exists(dest, ec))
        dest = quarantine_dir / to_wide_sys(stem + "_" + ts + "_(" + std::to_string(counter++) + ")" + ext);
    fs::rename(src, dest, ec);
    if (ec) return ERR("隔离失败: " + ec.message());
    std::ofstream meta(sidecar_path(aiutil::to_utf8(dest.wstring())));
    if (meta) {
        meta << "{\"original\":" << aiutil::dump_json(json(path))
             << ",\"quarantined_at\":" << aiutil::dump_json(json(now_iso()))
             << ",\"source\":\"ai\",\"reason\":" << aiutil::dump_json(json(reason)) << "}";
    }
    // 路径统一转成 UTF-8（to_utf8）后再进 JSON，中文文件名不会变乱码
    return aiutil::dump_json(json{{"quarantined_to", aiutil::to_utf8(dest.wstring())},
                              {"original", path}, {"reason", reason}});
}

std::string t_restore_file(const json& a, AiContext&) {
    std::string quarantined = a.value("quarantined_path", "");
    if (!fs::is_regular_file(fs::path(to_wide_sys(quarantined)))) return ERR("隔离文件不存在: " + quarantined);
    std::string original = a.value("original_path", "");
    std::string meta = sidecar_path(quarantined);
    if (original.empty() && fs::is_regular_file(fs::path(to_wide_sys(meta)))) {
        try {
            json j = json::parse(read_whole(meta, 65536));
            original = j.value("original", "");
        } catch (...) {
        }
    }
    if (original.empty()) return ERR("缺少 original_path（也没有隔离元数据）");
    fs::path dest(to_wide_sys(original));
    std::error_code ec;
    fs::create_directories(dest.parent_path(), ec);
    fs::path final_dest = dest;
    int counter = 1;
    while (fs::exists(final_dest, ec)) {
        final_dest = dest.parent_path() /
                     aiutil::to_utf8(dest.stem().wstring() + L"_(" + std::to_wstring(counter++) + L")" + dest.extension().wstring());
    }
    fs::rename(fs::path(to_wide_sys(quarantined)), final_dest, ec);
    if (ec) return ERR("恢复失败: " + ec.message());
    std::error_code rec;
    fs::remove(fs::path(to_wide_sys(meta)), rec);
    return json{{"restored_to", aiutil::to_utf8(final_dest.wstring())}}.dump();
}

std::string t_kill_process(const json& a, AiContext&) {
    DWORD pid = a.value("pid", 0);
    bool force = a.value("force", true);
    if (pid <= 4) return ERR("PID=" + std::to_string(pid) + " 是系统保护进程，禁止终止");
    HANDLE h = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return ERR("拒绝操作 PID=" + std::to_string(pid));
    std::string name = base_name(process_path(pid));
    BOOL ok = TerminateProcess(h, force ? 1 : 0);
    CloseHandle(h);
    if (!ok) return ERR("终止进程失败 PID=" + std::to_string(pid));
    return json{{"pid", pid}, {"name", name}, {"outcome", "killed"}}.dump();
}

// ---------------- 情报 ----------------

std::string t_read_engine_log(const json& a, AiContext& ctx) {
    int tail = std::min(std::max(a.value("tail", 100), 1), 1000);
    std::string kw = lower(a.value("keyword", ""));
    if (!fs::is_regular_file(fs::path(to_wide_sys(ctx.log_file))))
        return ERR("日志文件不存在: " + ctx.log_file);
    std::ifstream in(fs::path(to_wide_sys(ctx.log_file)));
    std::vector<std::string> lines;
    std::string line;
    while (std::getline(in, line)) {
        if (!kw.empty() && lower(line).find(kw) == std::string::npos) continue;
        lines.push_back(line);
        if (lines.size() > static_cast<size_t>(tail) * 4) lines.erase(lines.begin(), lines.begin() + tail);
    }
    if (lines.empty()) return "（没有匹配的日志行）";
    int start = static_cast<int>(lines.size()) - tail;
    if (start < 0) start = 0;
    std::string out = "[" + ctx.log_file + "]\n";
    for (int i = start; i < static_cast<int>(lines.size()); ++i) out += lines[i] + "\n";
    return out;
}

std::string t_list_quarantine(const json&, AiContext& ctx) {
    std::error_code ec;
    if (!fs::is_directory(fs::path(to_wide_sys(ctx.quarantine_dir)), ec))
        return json{{"path", ctx.quarantine_dir}, {"exists", false}, {"files", json::array()}}.dump();
    json files = json::array();
    fs::path qdir(to_wide_sys(ctx.quarantine_dir));
    for (auto it = fs::directory_iterator(qdir, ec);
         it != fs::directory_iterator() && files.size() < 200; it.increment(ec)) {
        if (ec) break;
        if (!it->is_regular_file(ec)) continue;
        std::string name = aiutil::to_utf8(it->path().filename().wstring());
        if (name.size() > 8 && name.substr(name.size() - 8) == ".ai.json") continue;
        files.push_back({{"name", name}, {"size", static_cast<unsigned long long>(it->file_size(ec))}});
    }
    return json{{"path", ctx.quarantine_dir}, {"exists", true}, {"count", files.size()}, {"files", files}}.dump();
}

std::string t_get_engine_status(const json&, AiContext& ctx) {
    YaraEngine yara(ctx.rules_path);
    bool clam_avail = false;
    std::string clam_ver;
    if (!ctx.clam_host.empty() && ctx.clam_port > 0) {
        ClamdClient clam(ctx.clam_host, ctx.clam_port, ctx.clam_timeout);
        clam_ver = clam.version();
        clam_avail = !clam_ver.empty();
    }
    std::error_code ec;
    bool qexists = fs::is_directory(fs::path(to_wide_sys(ctx.quarantine_dir)), ec);
    return json{{"time", now_iso()},
                {"yara", {{"available", yara.available()}, {"rules_count", yara.rules_count()}, {"skipped", yara.skipped_count()}}},
                {"clamav", {{"available", clam_avail}, {"version", clam_ver.empty() ? json(nullptr) : json(clam_ver)}}},
                {"quarantine", {{"path", ctx.quarantine_dir}, {"exists", qexists}}},
                {"project_root", ctx.project_root}}
        .dump();
}

// ---------------- 注册表 ----------------

// 处置类工具（统一审计清单；审计由 ai_execute_tool 写入 ctx.audit_log_file）
const char* const kMutating[] = {
    "dump_memory", "quarantine_file", "restore_file", "kill_process",
    "suspend_process", "resume_process", "kill_process_tree",
    "delete_registry_value", "remove_persistence", "stop_service",
    "delete_service", "delete_scheduled_task", "block_ip", "block_domain",
    "write_yara_rule", "save_baseline", "set_safety", "close_window",
};

std::string t_list_tools(const json& args, AiContext& ctx);  // 定义在 tools() 之后

struct ToolDef {
    const char* name;
    const char* category;
    const char* description;
    json properties;
    std::vector<std::string> required;
    std::string (*func)(const json&, AiContext&);
};

std::string prop(const char* type, const char* desc) {
    // description 里可能出现反斜杠/引号，必须转义，否则整份 schema JSON 解析失败
    std::string d;
    for (const char* p = desc; *p; ++p) {
        if (*p == '\\' || *p == '"') d += '\\';
        d += *p;
    }
    return std::string("{\"type\":\"") + type + "\",\"description\":\"" + d + "\"}";
}

const std::vector<ToolDef>& tools() {
    static const std::vector<ToolDef> kTools = {
        {"list_processes", "进程", "列出当前运行的进程，可按名称/路径关键字过滤，按内存降序。",
         json::parse(R"({"keyword":)" + prop("string", "过滤关键字") + R"(,"limit":)" + prop("integer", "最多返回条数，默认 50") + "}"),
         {}, t_list_processes},
        {"get_process_info", "进程", "获取单个进程详情：路径、父进程、启动时间、内存、可执行文件 SHA256。",
         json::parse(R"({"pid":)" + prop("integer", "进程 PID") + "}"), {"pid"}, t_get_process_info},
        {"list_process_modules", "进程", "列出进程已加载的模块（可分页；filter=unsigned 只看无签名模块，识别注入/未签名 DLL）。",
         json::parse(R"({"pid":)" + prop("integer", "进程 PID") + R"(,"limit":)" + prop("integer", "默认 200") + R"(,"offset":)" + prop("integer", "分页偏移，默认 0") + R"(,"filter":)" + prop("string", "all|unsigned") + "}"),
         {"pid"}, t_list_process_modules},
        {"dump_memory", "进程", "DUMP_MEMORY: 把进程可读内存转储到 logs/ai_dumps/（默认上限 64MB）。",
         json::parse(R"({"pid":)" + prop("integer", "进程 PID") + R"(,"max_mb":)" + prop("integer", "上限 MB，默认 64") + "}"),
         {"pid"}, t_dump_memory},
        {"file_hash", "文件", "计算文件哈希（默认 sha256，可 md5/sha1/sha256/sha512 逗号分隔）。",
         json::parse(R"({"path":)" + prop("string", "文件绝对路径") + R"(,"algos":)" + prop("string", "默认 sha256") + "}"),
         {"path"}, t_file_hash},
        {"read_file_text", "文件", "读取文件文本片段（脚本/配置/日志）。",
         json::parse(R"({"path":)" + prop("string", "文件绝对路径") + R"(,"offset":)" + prop("integer", "偏移，默认 0") + R"(,"length":)" + prop("integer", "字节数，默认 4096") + "}"),
         {"path"}, t_read_file_text},
        {"scan_file", "文件", "用 YARA + ClamAV 扫描文件，返回 verdict(clean/infected)。",
         json::parse(R"({"path":)" + prop("string", "文件绝对路径") + "}"), {"path"}, t_scan_file},
        {"get_pe_info", "文件", "解析 PE：32/64 位、入口点、编译时间、节区表。",
         json::parse(R"({"path":)" + prop("string", "PE 文件路径") + "}"), {"path"}, t_get_pe_info},
        {"extract_strings", "文件", "从文件/内存转储提取可打印字符串（ASCII）。",
         json::parse(R"({"path":)" + prop("string", "文件路径") + R"(,"min_length":)" + prop("integer", "默认 5") + R"(,"max_bytes":)" + prop("integer", "默认 1MB") + R"(,"limit":)" + prop("integer", "默认 200") + "}"),
         {"path"}, t_extract_strings},
        {"list_connections", "网络", "列出 TCP 连接（本端/远端/状态/进程）。",
         json::parse(R"({"pid":)" + prop("integer", "只看该 PID") + R"(,"state":)" + prop("string", "如 ESTABLISHED") + R"(,"limit":)" + prop("integer", "默认 100") + "}"),
         {}, t_list_connections},
        {"network_stats", "网络", "查看各网卡累计收发流量。", json::parse("{}"), {}, t_network_stats},
        {"list_services", "系统", "列出 Windows 服务及状态（running/stopped/all）。",
         json::parse(R"({"state":)" + prop("string", "running/stopped/all") + R"(,"limit":)" + prop("integer", "默认 200") + "}"),
         {}, t_list_services},
        {"read_registry", "系统", "读取注册表键值。",
         json::parse(R"({"key":)" + prop("string", "如 HKLM/SOFTWARE/...（根键用斜杠分隔）") + R"(,"value_name":)" + prop("string", "省略则列出全部值") + "}"),
         {"key"}, t_read_registry},
        {"list_scheduled_tasks", "系统", "列出计划任务名称，可按关键字过滤。",
         json::parse(R"({"keyword":)" + prop("string", "过滤关键字") + R"(,"limit":)" + prop("integer", "默认 200") + "}"),
         {}, t_list_scheduled_tasks},
        {"list_installed_programs", "系统", "列出已安装程序（名称/版本/厂商）。",
         json::parse(R"({"keyword":)" + prop("string", "过滤关键字") + R"(,"limit":)" + prop("integer", "默认 200") + "}"),
         {}, t_list_installed_programs},
        {"query_events", "事件", "查询指定源最近若干小时事件。source: sysmon/process/network/dns/powershell/system/application/fileio。",
         json::parse(R"({"source":)" + prop("string", "事件源") + R"(,"hours":)" + prop("number", "回溯小时，默认 1") + R"(,"keyword":)" + prop("string", "关键字") + R"(,"limit":)" + prop("integer", "默认 50") + "}"),
         {"source"}, t_query_events},
        {"grep_events", "事件", "按关键字在事件源历史中检索（默认 24h）；fileio 需按需检索。",
         json::parse(R"({"source":)" + prop("string", "事件源") + R"(,"keyword":)" + prop("string", "关键字") + R"(,"hours":)" + prop("number", "默认 24") + R"(,"limit":)" + prop("integer", "默认 100") + "}"),
         {"source", "keyword"}, t_grep_events},
        {"get_event_xml", "事件", "按 EventRecordID 获取单条事件原始 XML。",
         json::parse(R"({"source":)" + prop("string", "事件源") + R"(,"record_id":)" + prop("integer", "EventRecordID") + "}"),
         {"source", "record_id"}, t_get_event_xml},
        {"quarantine_file", "处置", "隔离文件到 quarantine/ 并记录元数据。",
         json::parse(R"({"path":)" + prop("string", "文件路径") + R"(,"reason":)" + prop("string", "理由") + "}"),
         {"path"}, t_quarantine_file},
        {"restore_file", "处置", "从隔离区恢复文件。",
         json::parse(R"({"quarantined_path":)" + prop("string", "隔离区路径") + R"(,"original_path":)" + prop("string", "原路径（可选）") + "}"),
         {"quarantined_path"}, t_restore_file},
        {"kill_process", "处置", "终止进程（系统进程 PID<=4 被拒绝）。",
         json::parse(R"({"pid":)" + prop("integer", "进程 PID") + R"(,"force":)" + prop("boolean", "默认 true") + "}"),
         {"pid"}, t_kill_process},
        {"read_engine_log", "情报", "读取引擎日志尾部，可按关键字过滤。",
         json::parse(R"({"tail":)" + prop("integer", "默认 100") + R"(,"keyword":)" + prop("string", "关键字") + "}"),
         {}, t_read_engine_log},
        {"list_quarantine", "情报", "列出隔离区文件。", json::parse("{}"), {}, t_list_quarantine},
        {"get_engine_status", "情报", "获取引擎整体状态（YARA/ClamAV/路径）。", json::parse("{}"), {}, t_get_engine_status},

        // ---------- 扩展工具（todolist.txt，实现在 ai_tools_*.cpp） ----------
        // 进程 / 线程 / 内存 / 签名
        {"get_process_tree", "进程", "按 PID 列出完整后代进程树（父子关系 + 深度），判断谁拉起了谁。",
         json::parse(R"({"pid":)" + prop("integer", "进程 PID") + R"(,"depth":)" + prop("integer", "树深度，默认 3") + R"(,"limit":)" + prop("integer", "最多节点数，默认 200") + "}"),
         {"pid"}, t_get_process_tree},
        {"get_parent_chain", "进程", "按 PID 向上回溯完整父子链到根进程。",
         json::parse(R"({"pid":)" + prop("integer", "进程 PID") + R"(,"limit":)" + prop("integer", "最多层，默认 16") + "}"),
         {"pid"}, t_get_parent_chain},
        {"get_process_commandline", "进程", "读进程完整命令行/工作目录/启动用户/完整性级别（读 PEB，可识别 -enc、-w hidden 等伪装参数）。",
         json::parse(R"({"pid":)" + prop("integer", "进程 PID") + "}"), {"pid"}, t_get_process_commandline},
        {"get_process_env", "进程", "读进程环境变量块（TEMP/PATH/代理等，判断环境伪装）。",
         json::parse(R"({"pid":)" + prop("integer", "进程 PID") + R"(,"limit":)" + prop("integer", "最多条数，默认 200") + "}"),
         {"pid"}, t_get_process_env},
        {"list_threads", "进程", "列出进程线程与起始地址；起始地址落在非映像内存 = 注入/反射加载证据。",
         json::parse(R"({"pid":)" + prop("integer", "进程 PID") + R"(,"limit":)" + prop("integer", "默认 200") + "}"),
         {"pid"}, t_list_threads},
        {"get_thread_start_address", "进程", "取单个线程起始地址并判断是否在非映像内存。",
         json::parse(R"({"tid":)" + prop("integer", "线程 TID") + "}"), {"tid"}, t_get_thread_start_address},
        {"list_handles", "进程", "列出进程句柄表（互斥体/节区/文件/键），勒索与横向移动识别。"
                              "句柄表可能有上万条，必须给出 type/name/handle 之一作为过滤条件；"
                              "type=\"any\" 只返回按类型的计数概览。需要管理员权限。"
                              "有名额与时间预算（budget_ms），目标进程句柄表剧烈变化时会在预算内"
                              "返回部分结果并在 diagnostics.stopped_reason 说明原因；"
                              "若目标有看门狗行为，建议先 suspend_process 或改用 "
                              "list_threads/list_process_modules/事件流取证。",
         json::parse(R"({"pid":)" + prop("integer", "进程 PID") + R"(,"type":)" + prop("string", "对象类型名（子串），如 File/Mutant/Key/Section；any=只回类型计数") + R"(,"name":)" + prop("string", "名字子串，如 \\Device\\ 或 .dll") + R"(,"handle":)" + prop("string", "句柄值，如 0x1a4 或 420") + R"(,"limit":)" + prop("integer", "返回条目上限，默认 200，上限 1000") + R"(,"budget_ms":)" + prop("integer", "总时间预算毫秒，默认 5000，范围 1000-30000") + R"(,"name_limit":)" + prop("integer", "名字解析次数上限，默认 200") + "}"),
         {"pid"}, t_list_handles},
        {"scan_memory_regions", "进程", "枚举进程私有可执行内存区域（无文件注入证据）并做熵 + YARA 扫描。",
         json::parse(R"({"pid":)" + prop("integer", "进程 PID") + R"(,"max_mb":)" + prop("integer", "扫描预算 MB，默认 32") + R"(,"max_regions":)" + prop("integer", "最多区域数，默认 64") + R"(,"yara":)" + prop("boolean", "默认 true") + R"(,"rules_path":)" + prop("string", "规则目录，默认取引擎配置") + "}"),
         {"pid"}, t_scan_memory_regions},
        {"suspend_process", "处置", "挂起进程（取证前冻结，防样本自毁）。",
         json::parse(R"({"pid":)" + prop("integer", "进程 PID") + R"(,"dry_run":)" + prop("boolean", "默认 false") + "}"),
         {"pid"}, t_suspend_process},
        {"resume_process", "处置", "恢复被挂起的进程。",
         json::parse(R"({"pid":)" + prop("integer", "进程 PID") + R"(,"dry_run":)" + prop("boolean", "默认 false") + "}"),
         {"pid"}, t_resume_process},
        {"kill_process_tree", "处置", "连后代一起终止进程树（叶子优先，防互守复活）。",
         json::parse(R"({"pid":)" + prop("integer", "根进程 PID") + R"(,"include_self":)" + prop("boolean", "默认 true") + R"(,"dry_run":)" + prop("boolean", "默认 false") + "}"),
         {"pid"}, t_kill_process_tree},
        {"verify_signature", "文件", "校验 Authenticode 签名（签名者/颁发者/时间戳/吊销），区分微软签名与无签名。",
         json::parse(R"({"path":)" + prop("string", "文件绝对路径") + R"(,"check_revocation":)" + prop("boolean", "默认 false，开启会联网查吊销") + "}"),
         {"path"}, t_verify_signature},
        // 文件取证与时间线
        {"list_files", "文件", "目录枚举（大小/创建/修改/访问时间），用于 %TEMP%、%APPDATA%、Startup 巡检。",
         json::parse(R"({"dir":)" + prop("string", "目录绝对路径") + R"(,"recursive":)" + prop("boolean", "默认 false") + R"(,"filter":)" + prop("string", "通配符，默认 *") + R"(,"limit":)" + prop("integer", "默认 200") + R"(,"sort":)" + prop("string", "created|modified|size|name") + "}"),
         {"dir"}, t_list_files},
        {"get_file_metadata", "文件", "文件元数据：时间戳/属性/硬链接数/所有者/熵值/格式魔数。",
         json::parse(R"({"path":)" + prop("string", "文件绝对路径") + "}"), {"path"}, t_get_file_metadata},
        {"get_ads", "文件", "读 NTFS 备用数据流与 Zone.Identifier（判断文件来源是下载/邮件）。",
         json::parse(R"({"path":)" + prop("string", "文件绝对路径") + "}"), {"path"}, t_get_ads},
        {"get_recent_files", "文件", "按 USN 日志拉取近期创建/改名文件（还原落地动作，需要管理员）。",
         json::parse(R"({"hours":)" + prop("number", "回溯小时，默认 24") + R"(,"volumes":)" + prop("string", "卷，如 C: 或 C:,D:，默认 C:") + R"(,"limit":)" + prop("integer", "默认 100") + R"(,"event":)" + prop("string", "create|rename|all") + "}"),
         {}, t_get_recent_files},
        // 注册表与持久化
        {"enumerate_registry_tree", "系统", "递归枚举注册表键树与值（Run/Services 逐条查不再费劲）。",
         json::parse(R"({"key":)" + prop("string", "如 HKLM/SOFTWARE/...") + R"(,"depth":)" + prop("integer", "默认 2") + R"(,"values":)" + prop("boolean", "默认 true") + R"(,"limit":)" + prop("integer", "默认 200") + "}"),
         {"key"}, t_enumerate_registry_tree},
        {"check_persistence", "情报", "聚合检查常见持久化位置（Run/Winlogon/IFEO/服务/COM 劫持/LSA/打印监视器）。",
         json::parse("{}"), {}, t_check_persistence},
        {"list_wmi_subscriptions", "情报", "列出 WMI 永久订阅（__EventFilter/消费者/绑定），常见无文件持久化盲区。",
         json::parse(R"({"limit":)" + prop("integer", "默认 50") + "}"), {}, t_list_wmi_subscriptions},
        {"list_startup_folders", "情报", "列出用户与公共启动文件夹内容。",
         json::parse("{}"), {}, t_list_startup_folders},
        {"list_drivers_loaded", "情报", "列出已加载内核驱动（用户态枚举，rootkit 识别参考）。",
         json::parse(R"({"limit":)" + prop("integer", "默认 200") + "}"), {}, t_list_drivers_loaded},
        {"delete_registry_value", "处置", "删除注册表值（清持久化）。",
         json::parse(R"({"key":)" + prop("string", "如 HKCU/.../Run") + R"(,"value_name":)" + prop("string", "值名") + R"(,"dry_run":)" + prop("boolean", "默认 false") + "}"),
         {"key", "value_name"}, t_delete_registry_value},
        {"remove_persistence", "处置", "按类型移除持久化项（registry/service/task/wmi）。",
         json::parse(R"({"type":)" + prop("string", "registry|service|task|wmi") + R"(,"target":)" + prop("string", "定位：注册表用 HKCU/.../Run:值名，服务/任务用名称，wmi 用 filter:名") + R"(,"dry_run":)" + prop("boolean", "默认 false") + "}"),
         {"type", "target"}, t_remove_persistence},
        {"stop_service", "处置", "停止服务。",
         json::parse(R"({"name":)" + prop("string", "服务名") + R"(,"force":)" + prop("boolean", "默认 true") + R"(,"dry_run":)" + prop("boolean", "默认 false") + "}"),
         {"name"}, t_stop_service},
        {"delete_service", "处置", "删除服务（先停再删）。",
         json::parse(R"({"name":)" + prop("string", "服务名") + R"(,"dry_run":)" + prop("boolean", "默认 false") + "}"),
         {"name"}, t_delete_service},
        {"delete_scheduled_task", "处置", "删除计划任务。",
         json::parse(R"({"name":)" + prop("string", "任务名") + R"(,"dry_run":)" + prop("boolean", "默认 false") + "}"),
         {"name"}, t_delete_scheduled_task},
        // 网络侧
        {"get_dns_cache", "网络", "本机 DNS 解析缓存（补历史 C2 域名）。",
         json::parse(R"({"limit":)" + prop("integer", "默认 200") + "}"), {}, t_get_dns_cache},
        {"list_udp_endpoints", "网络", "列出 UDP 端点（进程/本地端口）。",
         json::parse(R"({"pid":)" + prop("integer", "只看该 PID") + R"(,"limit":)" + prop("integer", "默认 200") + "}"),
         {}, t_list_udp_endpoints},
        {"list_listeners", "网络", "列出监听端口（进程/创建时间/模块）。",
         json::parse(R"({"pid":)" + prop("integer", "只看该 PID") + R"(,"limit":)" + prop("integer", "默认 200") + "}"),
         {}, t_list_listeners},
        {"resolve_ip_domains", "网络", "把远端 IP 反查成 DNS 缓存里最近解析过的域名（识别 C2 域）。",
         json::parse(R"({"ip":)" + prop("string", "IP 地址") + "}"), {"ip"}, t_resolve_ip_domains},
        {"get_route_table", "网络", "本机路由表。",
         json::parse(R"({"limit":)" + prop("integer", "默认 100") + "}"), {}, t_get_route_table},
        {"get_arp_cache", "网络", "ARP 缓存（内网横向线索）。",
         json::parse(R"({"limit":)" + prop("integer", "默认 200") + "}"), {}, t_get_arp_cache},
        {"list_firewall_rules", "网络", "只读查询防火墙规则（netsh）。",
         json::parse(R"({"profile":)" + prop("string", "domain|private|public|all") + R"(,"limit":)" + prop("integer", "默认 100") + "}"),
         {}, t_list_firewall_rules},
        {"get_proxy_config", "网络", "查 WinHTTP/WinINet 代理设置（判断是否被改代理劫持流量）。",
         json::parse("{}"), {}, t_get_proxy_config},
        {"block_ip", "处置", "防火墙封禁 IP（掐断 C2；需要管理员）。",
         json::parse(R"({"ip":)" + prop("string", "IP 地址") + R"(,"name":)" + prop("string", "规则名，默认自动生成") + R"(,"direction":)" + prop("string", "out|in，默认 out") + R"(,"dry_run":)" + prop("boolean", "默认 false") + "}"),
         {"ip"}, t_block_ip},
        {"block_domain", "处置", "解析域名并封禁解析出的 IP（需要管理员）。",
         json::parse(R"({"domain":)" + prop("string", "域名") + R"(,"dry_run":)" + prop("boolean", "默认 false") + "}"),
         {"domain"}, t_block_domain},
        // 日志与脚本侧
        {"get_script_block_log", "情报", "读 PowerShell 4104 脚本块日志（还原混淆脚本的真实内容）。",
         json::parse(R"({"hours":)" + prop("number", "默认 24") + R"(,"limit":)" + prop("integer", "默认 50") + R"(,"channel":)" + prop("string", "默认 Microsoft-Windows-PowerShell/Operational") + "}"),
         {}, t_get_script_block_log},
        {"get_powershell_transcript", "情报", "查找 PowerShell 转录文件（完整会话记录）。",
         json::parse(R"({"limit":)" + prop("integer", "默认 20") + "}"), {}, t_get_powershell_transcript},
        {"decode_script", "情报", "还原混淆脚本：base64(-EncodedCommand)/hex/XOR/拼接，直接给出明文。",
         json::parse(R"({"text":)" + prop("string", "混淆文本") + R"(,"encodings":)" + prop("string", "auto|base64|base64_utf16|hex|xor") + R"(,"key":)" + prop("string", "XOR 密钥或单字节值") + R"(,"limit":)" + prop("integer", "默认 4000") + "}"),
         {"text"}, t_decode_script},
        {"subscribe_events", "情报", "开始实时订阅事件流（边跑边看，不再反复轮询）。",
         json::parse(R"({"source":)" + prop("string", "sysmon|powershell|security|system|application|wmi|dns 或通道名") + R"(,"keyword":)" + prop("string", "过滤关键字") + "}"),
         {"source"}, t_subscribe_events},
        {"tail_events", "情报", "取走实时订阅自上次以来的新事件。",
         json::parse(R"({"max":)" + prop("integer", "默认 50") + "}"), {}, t_tail_events},
        {"unsubscribe_events", "情报", "停止实时订阅。", json::parse("{}"), {}, t_unsubscribe_events},
        {"get_etw", "情报", "按显式通道名查事件（WMI-Activity/DNS-Client 等用户态可消费通道）。",
         json::parse(R"({"channel":)" + prop("string", "通道名或短名") + R"(,"hours":)" + prop("number", "默认 1") + R"(,"limit":)" + prop("integer", "默认 50") + R"(,"level":)" + prop("integer", "级别过滤") + "}"),
         {"channel"}, t_get_etw},
        {"get_amsi_events", "情报", "AMSI 相关事件（Threat-Intelligence 通道；读不到时回退 4104 脚本块日志）。",
         json::parse(R"({"limit":)" + prop("integer", "默认 50") + "}"), {}, t_get_amsi_events},
        {"get_security_log", "情报", "Security 日志 4624/4625/4672/4688（登录/提权/口令喷洒；需要管理员）。",
         json::parse(R"({"hours":)" + prop("number", "默认 24") + R"(,"limit":)" + prop("integer", "默认 50") + R"(,"event_id":)" + prop("integer", "只看某事件 ID") + "}"),
         {}, t_get_security_log},
        // 情报与元工具
        {"reputation_lookup", "情报", "信誉查询：本地启发式（私网/可疑TLD/黑名单）+ 可选配置端点在线查。",
         json::parse(R"({"value":)" + prop("string", "hash/ip/domain/url") + R"(,"type":)" + prop("string", "hash|ip|domain|url|auto") + R"(,"endpoint":)" + prop("string", "可选查询端点 URL 模板，含 {value} 占位符") + R"(,"api_key":)" + prop("string", "可选") + R"(,"timeout":)" + prop("integer", "默认 5") + "}"),
         {"value"}, t_reputation_lookup},
        {"build_static_report", "情报", "聚合静态报告：哈希/熵/PE/签名/字符串样本/YARA+ClamAV 结论。",
         json::parse(R"({"path":)" + prop("string", "文件绝对路径") + "}"), {"path"}, t_build_static_report},
        {"write_yara_rule", "处置", "把现场特征写成 YARA 规则（先验证可编译再入规则库）。",
         json::parse(R"({"name":)" + prop("string", "规则名 [A-Za-z0-9_]") +
                     R"(,"strings":{"type":"array","items":{"type":"string"},"description":"特征字符串数组"})" +
                     R"(,"condition":)" + prop("string", "默认 any of them") + R"(,"description":)" + prop("string", "可选") + R"(,"dry_run":)" + prop("boolean", "默认 false") + "}"),
         {"name", "strings"}, t_write_yara_rule},
        {"scan_with_rule", "文件", "用临时/库内规则立即扫描文件或目录。",
         json::parse(R"({"rule":)" + prop("string", "YARA 源文本或规则库 yara 子目录下的规则文件名") + R"(,"target":)" + prop("string", "文件或目录") + R"(,"limit":)" + prop("integer", "默认 50") + "}"),
         {"rule", "target"}, t_scan_with_rule},
        {"save_baseline", "处置", "保存当前进程/服务/任务/启动项基线快照。",
         json::parse(R"({"kind":)" + prop("string", "process|service|task|startup|all") + R"(,"dry_run":)" + prop("boolean", "默认 false") + "}"),
         {}, t_save_baseline},
        {"compare_baseline", "情报", "当前状态与基线 diff（识别新增进程/服务/任务）。",
         json::parse(R"({"kind":)" + prop("string", "process|service|task|startup|all") + R"(,"baseline":)" + prop("string", "可选基线文件，默认最新") + "}"),
         {}, t_compare_baseline},
        {"set_safety", "情报", "查看/设置本会话安全参数（dry-run 开关、结果上限）。",
         json::parse(R"({"dry_run":)" + prop("boolean", "省略则只查看") + R"(,"max_tool_result_chars":)" + prop("integer", "省略则只查看") + "}"),
         {}, t_set_safety},
        {"list_windows", "窗口",
         "枚举窗口并定位其代码来源：每个窗口都给出 class_module（注册该窗口类的模块）与 "
         "wndproc（真正处理消息的代码）及其归属模块——弹窗逻辑在注入的 DLL 里时能一次定位，"
         "不必逐个翻模块；两者不在目标 loader 列表里即为手工映射/被 rootkit 隐藏的强信号。"
         "scope: auto=Win10+ 枚举所有窗口站/桌面、Win7/8 只枚举当前桌面；all 会尝试其他 session"
         "（需要管理员，打不开的列在 diagnostics.skipped_desktops）。",
         json::parse(R"({"scope":)" + prop("string", "auto|desktop|session|all") + R"(,"title_contains":)" + prop("string", "标题子串") + R"(,"class_contains":)" + prop("string", "类名子串") + R"(,"pid":)" + prop("integer", "只看该进程的窗口") + R"(,"visible_only":)" + prop("boolean", "默认 false") + R"(,"limit":)" + prop("integer", "默认 100，上限 1000") + "}"),
         {}, t_list_windows},
        {"get_window_detail", "窗口",
         "单个窗口的完整画像：父/属主链、窗口线程起始地址与内存属性、class_module/wndproc 归属与"
         "签名、是否无响应(hung)、进程未签名模块抽样，并给出 next_steps。",
         json::parse(R"({"hwnd":)" + prop("string", "窗口句柄，如 0x00010A2C 或十进制") + "}"),
         {"hwnd"}, t_get_window_detail},
        {"close_window", "窗口",
         "关闭窗口（处置类）。method=wm_close 礼貌发送 WM_CLOSE（默认）；method=end_task 等价"
         "任务管理器的强制结束。WM_DESTROY 不能跨进程投递，会被明确拒绝并说明替代方式；"
         "关键进程（winlogon/lsass/csrss 等）的窗口一律拒绝。",
         json::parse(R"({"hwnd":)" + prop("string", "窗口句柄，如 0x00010A2C 或十进制") + R"(,"method":)" + prop("string", "wm_close|end_task") + R"(,"dry_run":)" + prop("boolean", "默认 false") + "}"),
         {"hwnd"}, t_close_window},
        {"list_tools", "情报", "列出本引擎全部 AI 工具（名称/类别/是否只读），供自我发现。",
         json::parse(R"({"category":)" + prop("string", "按类别过滤，如 进程") + "}"), {}, t_list_tools},
    };
    return kTools;
}

std::string t_list_tools(const json& args, AiContext& /*ctx*/) {
    std::string want = lower(args.value("category", ""));
    json items = json::array();
    int count = 0;
    for (const auto& t : tools()) {
        if (!want.empty() && lower(t.category) != want) continue;
        bool readonly = true;
        for (const char* m : kMutating) {
            if (std::string(m) == t.name) { readonly = false; break; }
        }
        items.push_back({{"name", t.name}, {"category", t.category}, {"readonly", readonly}});
        ++count;
    }
    json out = {{"count", count}, {"tools", items}};
    return aiutil::dump_json(out);
}

}  // namespace

json ai_tool_schemas() {
    json arr = json::array();
    for (const auto& t : tools()) {
        json schema = {{"type", "function"},
                       {"function", {{"name", t.name},
                                     {"description", t.description},
                                     {"parameters", {{"type", "object"},
                                                     {"properties", t.properties},
                                                     {"required", t.required}}}}}};
        arr.push_back(schema);
    }
    return arr;
}

std::string ai_execute_tool(const std::string& name, const json& args, AiContext& ctx) {
    for (const auto& t : tools()) {
        if (name == t.name) {
            std::string result;
            try {
                result = t.func(args, ctx);
            } catch (const std::exception& e) {
                result = ERR(std::string("工具执行异常: ") + e.what());
            }
            // 处置类动作统一写审计（追加式 + 哈希链）；审计失败不影响工具本身
            for (const char* m : kMutating) {
                if (std::string(m) == name) {
                    size_t nl = result.find('\n');
                    std::string summary = (nl == std::string::npos) ? result : result.substr(0, nl);
                    aiext::audit_log(ctx, name, args, summary);
                    break;
                }
            }
            if (static_cast<int>(result.size()) > ctx.max_tool_result_chars) {
                // 按字符边界截断，避免把汉字劈成半个（否则回传给模型的 JSON 会非法）
                result = aiutil::utf8_truncate(result, static_cast<size_t>(ctx.max_tool_result_chars)) +
                         "\n...[结果被截断，请收窄参数后重试]";
            }
            return result;
        }
    }
    return ERR("未知工具 " + name);
}
