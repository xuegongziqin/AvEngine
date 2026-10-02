// ai_tools.cpp - AI 工具库实现（Win32 原生）
#include "ai_tools.h"

#include "ai_collectors.h"
#include "ai_util.h"
#include "clamd_client.h"
#include "util.h"
#include "yara_engine.h"

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <bcrypt.h>
#include <iphlpapi.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <winsvc.h>
#include <winreg.h>

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

std::string base_name(const std::string& p) { return fs::path(p).filename().string(); }

std::string lower(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
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

std::string run_capture(const std::string& cmd) {
    std::FILE* p = _popen(cmd.c_str(), "r");
    if (!p) return "";
    std::string out;
    char buf[4096];
    size_t n;
    while ((n = std::fread(buf, 1, sizeof(buf), p)) > 0) out.append(buf, n);
    _pclose(p);
    return out;
}

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
    int limit = std::min(a.value("limit", 200), 1000);
    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!h) return ERR("拒绝访问 PID=" + std::to_string(pid));
    HMODULE mods[1024];
    DWORD needed = 0;
    json out = json::array();
    if (EnumProcessModulesEx(h, mods, sizeof(mods), &needed, LIST_MODULES_ALL)) {
        int count = static_cast<int>(needed / sizeof(HMODULE));
        for (int i = 0; i < count && static_cast<int>(out.size()) < limit; ++i) {
            wchar_t path[MAX_PATH];
            if (GetModuleFileNameExW(h, mods[i], path, MAX_PATH)) {
                out.push_back(to_utf8(path));
            }
        }
    }
    CloseHandle(h);
    return json{{"pid", pid}, {"modules_returned", out.size()}, {"modules", out}}.dump();
}

std::string t_dump_memory(const json& a, AiContext& ctx) {
    DWORD pid = a.value("pid", 0);
    int max_mb = std::min(std::max(a.value("max_mb", 64), 1), 512);
    if (pid <= 4) return ERR("PID=" + std::to_string(pid) + " 是系统保护进程，禁止转储");

    HANDLE h = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!h) return ERR("OpenProcess 失败（需要管理员或进程已退出）");

    std::error_code ec;
    fs::create_directories(ctx.dump_dir, ec);
    char ts[32];
    std::time_t t = std::time(nullptr);
    std::tm tmv{};
    localtime_s(&tmv, &t);
    std::strftime(ts, sizeof(ts), "%Y%m%d_%H%M%S", &tmv);
    fs::path out_path = fs::path(ctx.dump_dir) / ("pid" + std::to_string(pid) + "_" + ts + ".bin");

    unsigned long long written = 0, max_bytes = static_cast<unsigned long long>(max_mb) * 1048576ULL;
    std::ofstream out(out_path, std::ios::binary);
    if (!out) {
        CloseHandle(h);
        return ERR("无法创建转储文件: " + out_path.string());
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
    return json{{"path", out_path.string()},
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
                std::snprintf(la, sizeof(la), "%u.%u.%u.%u:%u",
                              r.dwLocalAddr & 0xff, (r.dwLocalAddr >> 8) & 0xff,
                              (r.dwLocalAddr >> 16) & 0xff, (r.dwLocalAddr >> 24) & 0xff,
                              ntohs(static_cast<u_short>(r.dwLocalPort)));
                std::snprintf(ra, sizeof(ra), "%u.%u.%u.%u:%u",
                              r.dwRemoteAddr & 0xff, (r.dwRemoteAddr >> 8) & 0xff,
                              (r.dwRemoteAddr >> 16) & 0xff, (r.dwRemoteAddr >> 24) & 0xff,
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

std::string t_list_scheduled_tasks(const json& a, AiContext&) {
    std::string kw = lower(a.value("keyword", ""));
    int limit = std::min(a.value("limit", 200), 1000);
    std::string text = run_capture("schtasks /query /fo CSV /nh 2>nul");
    json tasks = json::array();
    std::istringstream ss(text);
    std::string line;
    while (std::getline(ss, line) && static_cast<int>(tasks.size()) < limit) {
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
        if (name.empty() || lower(name).rfind("info", 0) == 0) continue;
        if (!kw.empty() && lower(name).find(kw) == std::string::npos) continue;
        tasks.push_back(name);
    }
    return json{{"returned", tasks.size()}, {"tasks", tasks}}.dump();
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
    if (xml.size() > 20000) xml = xml.substr(0, 20000) + "\n...[XML 被截断]";
    return xml;
}

// ---------------- 处置 ----------------

std::string sidecar_path(const std::string& quarantined) { return quarantined + ".ai.json"; }

std::string t_quarantine_file(const json& a, AiContext& ctx) {
    std::string path = a.value("path", "");
    if (!fs::is_regular_file(fs::path(to_wide_sys(path)))) return ERR("文件不存在: " + path);
    std::string reason = a.value("reason", "");
    std::error_code ec;
    fs::create_directories(ctx.quarantine_dir, ec);
    fs::path src(path);
    std::string stem = src.stem().string();
    std::string ext = src.extension().string();
    char ts[32];
    std::time_t t = std::time(nullptr);
    std::tm tmv{};
    localtime_s(&tmv, &t);
    std::strftime(ts, sizeof(ts), "%Y%m%d_%H%M%S", &tmv);
    fs::path dest = fs::path(ctx.quarantine_dir) / (stem + "_" + ts + ext);
    int counter = 1;
    while (fs::exists(dest, ec))
        dest = fs::path(ctx.quarantine_dir) / (stem + "_" + ts + "_(" + std::to_string(counter++) + ")" + ext);
    fs::rename(src, dest, ec);
    if (ec) return ERR("隔离失败: " + ec.message());
    std::ofstream meta(sidecar_path(dest.string()));
    if (meta) {
        meta << "{\"original\":" << json(path).dump() << ",\"quarantined_at\":" << json(now_iso()).dump()
             << ",\"source\":\"ai\",\"reason\":" << json(reason).dump() << "}";
    }
    return json{{"quarantined_to", dest.string()}, {"original", path}, {"reason", reason}}.dump();
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
                     (dest.stem().string() + "_(" + std::to_string(counter++) + ")" + dest.extension().string());
    }
    fs::rename(fs::path(to_wide_sys(quarantined)), final_dest, ec);
    if (ec) return ERR("恢复失败: " + ec.message());
    std::error_code rec;
    fs::remove(fs::path(to_wide_sys(meta)), rec);
    return json{{"restored_to", final_dest.string()}}.dump();
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
        std::string name = it->path().filename().string();
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

struct ToolDef {
    const char* name;
    const char* category;
    const char* description;
    json properties;
    std::vector<std::string> required;
    std::string (*func)(const json&, AiContext&);
};

std::string prop(const char* type, const char* desc) {
    return std::string("{\"type\":\"") + type + "\",\"description\":\"" + desc + "\"}";
}

const std::vector<ToolDef>& tools() {
    static const std::vector<ToolDef> kTools = {
        {"list_processes", "进程", "列出当前运行的进程，可按名称/路径关键字过滤，按内存降序。",
         json::parse(R"({"keyword":)" + prop("string", "过滤关键字") + R"(,"limit":)" + prop("integer", "最多返回条数，默认 50") + "}"),
         {}, t_list_processes},
        {"get_process_info", "进程", "获取单个进程详情：路径、父进程、启动时间、内存、可执行文件 SHA256。",
         json::parse(R"({"pid":)" + prop("integer", "进程 PID") + "}"), {"pid"}, t_get_process_info},
        {"list_process_modules", "进程", "列出进程已加载的模块（DLL/映像路径）。",
         json::parse(R"({"pid":)" + prop("integer", "进程 PID") + R"(,"limit":)" + prop("integer", "默认 200") + "}"),
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
    };
    return kTools;
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
            try {
                std::string result = t.func(args, ctx);
                if (static_cast<int>(result.size()) > ctx.max_tool_result_chars) {
                    result = result.substr(0, ctx.max_tool_result_chars) +
                             "\n...[结果被截断，请收窄参数后重试]";
                }
                return result;
            } catch (const std::exception& e) {
                return ERR(std::string("工具执行异常: ") + e.what());
            }
        }
    }
    return ERR("未知工具 " + name);
}
