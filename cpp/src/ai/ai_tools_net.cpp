// ai_tools_net.cpp - AI 工具扩展库：网络侧
//
// 实现 ai_tools_ext.h 第四节（网络侧）声明的 10 个工具：
//   t_get_dns_cache        本机 DNS 解析缓存（dnsapi DnsGetCacheDataTable，动态加载，导出名试 A/W）
//   t_list_udp_endpoints   UDP 端点（iphlpapi GetExtendedUdpTable，AF_INET + 可选 PID 过滤）
//   t_list_listeners       TCP 监听器（GetExtendedTcpTable OWNER_MODULE_LISTENER，含创建时间/模块）
//   t_resolve_ip_domains   用 DNS 缓存把远端 IP 反查成最近解析过的域名
//   t_get_route_table      IPv4 路由表（GetIpForwardTable）
//   t_get_arp_cache        ARP/邻居缓存（GetIpNetTable）
//   t_list_firewall_rules  防火墙规则原文（只读 netsh advfirewall，aiext::run_capture）
//   t_get_proxy_config     WinHTTP + WinINET（注册表）代理配置
//   t_block_ip             防火墙封禁 IP（netsh add rule，处置类，支持 dry_run）
//   t_block_domain         解析域名并封禁其解析出的 IP（处置类，支持 dry_run）
//
// 实现约定见 ai_tools_ext.h 头部「硬性约定」1-7 条：
//   - 成功返回 UTF-8 JSON（一律 aiutil::dump_json），失败返回 "ERROR: 中文原因"，绝不抛异常
//   - 处置类先 aiext::dry_run_requested 判断；审计由 ai_execute_tool 统一完成，这里不调用
//   - ws2_32/iphlpapi/winhttp 由 CMake 链接（不放 #pragma comment，MinGW 忽略并告警）
//   - include 顺序：winsock2.h 必须先于 windows.h

#include "ai_tools_ext.h"

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>      // 必须先于 windows.h，避免 winsock.h 冲突
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>      // MIB_* 结构（iprtrmib.h）/ GetExtended*Table / GetOwnerModuleFromTcpEntry
#include <winreg.h>
#include <winhttp.h>

#include "ai_util.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <sstream>
#include <string>
#include <vector>

using nlohmann::json;

namespace {

// ---------------- 通用小工具 ----------------

std::string ERR(const std::string& m) { return "ERROR: " + m; }

std::string to_lower(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

// IPv4：DWORD 按内存字节序（低字节为首八位组）转点分串
std::string ipv4_from_be(unsigned long a) {
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
                  static_cast<unsigned>(a & 0xFFUL), static_cast<unsigned>((a >> 8) & 0xFFUL),
                  static_cast<unsigned>((a >> 16) & 0xFFUL), static_cast<unsigned>((a >> 24) & 0xFFUL));
    return buf;
}

// IPv6：16 字节（网络序）转小写冒分十六进制，零段压缩（::）
std::string ipv6_from_bytes(const unsigned char* b) {
    unsigned short g[8];
    for (int i = 0; i < 8; ++i)
        g[i] = static_cast<unsigned short>((static_cast<unsigned>(b[2 * i]) << 8) | b[2 * i + 1]);
    int zs = -1, zl = 0;   // 最长零段起点/长度
    for (int i = 0; i < 8;) {
        if (g[i] == 0) {
            int j = i;
            while (j < 8 && g[j] == 0) ++j;
            if (j - i > zl) {
                zl = j - i;
                zs = i;
            }
            i = j;
        } else {
            ++i;
        }
    }
    std::string out;
    char tmp[8];
    if (zl < 2) {   // 无需压缩
        for (int i = 0; i < 8; ++i) {
            if (i) out += ':';
            std::snprintf(tmp, sizeof(tmp), "%x", static_cast<unsigned>(g[i]));
            out += tmp;
        }
        return out;
    }
    for (int i = 0; i < zs; ++i) {
        if (i) out += ':';
        std::snprintf(tmp, sizeof(tmp), "%x", static_cast<unsigned>(g[i]));
        out += tmp;
    }
    out += "::";
    for (int i = zs + zl; i < 8; ++i) {
        if (i > zs + zl) out += ':';
        std::snprintf(tmp, sizeof(tmp), "%x", static_cast<unsigned>(g[i]));
        out += tmp;
    }
    return out;
}

// DNS 记录类型名（未列出的映射为数字字符串）
std::string dns_type_name(unsigned int t) {
    switch (t) {
        case 1:  return "A";
        case 28: return "AAAA";
        case 5:  return "CNAME";
        case 12: return "PTR";
        case 16: return "TXT";
        case 33: return "SRV";
        default: return std::to_string(t);
    }
}

// MIB_IPFORWARDTYPE
std::string route_type_name(unsigned long t) {
    switch (t) {
        case 1:  return "other";
        case 2:  return "invalid";
        case 3:  return "direct";
        case 4:  return "indirect";
        default: return std::to_string(t);
    }
}

// MIB_IPFORWARD_PROTO（常用映射，其他为数字字符串）
std::string route_proto_name(unsigned long t) {
    switch (t) {
        case 1:  return "other";
        case 2:  return "local";
        case 3:  return "static";
        case 4:  return "icmp";
        case 8:  return "rip";
        case 9:  return "isis";
        case 10: return "esis";
        case 13: return "ospf";
        case 14: return "bgp";
        default: return std::to_string(t);
    }
}

// MIB_IPNETROW.dwType
std::string arp_type_name(unsigned long t) {
    switch (t) {
        case 1:  return "other";
        case 2:  return "invalid";
        case 3:  return "dynamic";
        case 4:  return "static";
        default: return std::to_string(t);
    }
}

// WINHTTP_ACCESS_TYPE（0=default,1=no_proxy/直连,3=named_proxy,4=auto_detect）
std::string proxy_access_name(unsigned long t) {
    switch (t) {
        case 0: return "default";
        case 1: return "direct";
        case 3: return "proxy";
        case 4: return "auto_detect";
        default: return std::to_string(t);
    }
}

// 净化进 netsh 命令行的字符串（去控制字符与双引号）
std::string sanitize_netsh_string(const std::string& s) {
    std::string out;
    for (char c : s) {
        unsigned char u = static_cast<unsigned char>(c);
        if (u < 0x20 || c == '"') continue;
        out += c;
    }
    return out;
}

// 进程名（OpenProcess + QueryFullProcessImageNameW，失败返回空串）
std::string process_name_by_pid(DWORD pid) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return "";
    wchar_t buf[1024];
    DWORD n = static_cast<DWORD>(sizeof(buf) / sizeof(wchar_t));
    std::string path;
    if (QueryFullProcessImageNameW(h, 0, buf, &n)) {
        path = aiutil::to_utf8(std::wstring(buf, n));
        size_t slash = path.find_last_of("\\/");
        if (slash != std::string::npos) path = path.substr(slash + 1);
    }
    CloseHandle(h);
    return path;
}

// 安全取整数参数（类型不符/越界回默认，绝不抛异常）
int parse_int_arg(const json& a, const char* key, int def) {
    if (!a.is_object() || !a.contains(key)) return def;
    const json& v = a.at(key);
    try {
        if (v.is_number_unsigned()) {
            unsigned long long u = v.get<unsigned long long>();
            return (u > 2147483647ULL) ? 2147483647 : static_cast<int>(u);
        }
        if (v.is_number_integer()) return v.get<int>();
        if (v.is_number_float()) return static_cast<int>(v.get<double>());
        if (v.is_string()) return std::stoi(v.get<std::string>());
    } catch (...) {
        return def;
    }
    return def;
}

// 安全取字符串参数（类型不符回默认）
std::string json_string_arg(const json& a, const char* key, const std::string& def = "") {
    if (!a.is_object() || !a.contains(key)) return def;
    const json& v = a.at(key);
    if (v.is_string()) return v.get<std::string>();
    return def;
}

// pid 过滤参数（可选）
void parse_pid_arg(const json& a, bool& has_pid, DWORD& pid) {
    has_pid = false;
    pid = 0;
    if (!a.is_object() || !a.contains("pid") || a.at("pid").is_null()) return;
    const json& v = a.at("pid");
    long long p = -1;
    try {
        if (v.is_number_unsigned()) p = static_cast<long long>(v.get<unsigned long long>());
        else if (v.is_number_integer()) p = v.get<long long>();
        else if (v.is_number_float()) p = static_cast<long long>(v.get<double>());
        else if (v.is_string()) p = std::stoll(v.get<std::string>());
    } catch (...) {
        return;
    }
    if (p > 0) {
        has_pid = true;
        pid = static_cast<DWORD>(p);
    }
}

// ---------------- WSAStartup（只做一次） ----------------

std::once_flag g_wsa_once;
bool g_wsa_ok = false;
std::string g_wsa_err;

// WSAStartup 成功与否记录；失败时调用方返回 ERROR
bool ensure_wsa() {
    std::call_once(g_wsa_once, [] {
        WSADATA data{};
        int rc = WSAStartup(MAKEWORD(2, 2), &data);
        if (rc == 0) {
            g_wsa_ok = true;
        } else {
            g_wsa_err = "WSAStartup 失败（错误 " + std::to_string(rc) + "）";
        }
    });
    return g_wsa_ok;
}

// ---------------- DNS 缓存（t_get_dns_cache / t_resolve_ip_domains 共用） ----------------

// DNS 缓存链表节点（未完全文档化，按常见布局；x64 上 24 字节，记录数据紧随结构之后）
struct DNS_CACHE_ENTRY {
    DNS_CACHE_ENTRY* pNext;
    PWSTR pszName;
    unsigned short wType;
    unsigned short wDataLength;
    unsigned long dwFlags;
};

struct DnsCacheItem {
    std::string name;
    unsigned int type = 0;
    std::string ip;   // 空 = 未提取到（尽力而为失败）
};

/*
 * 读取本机 DNS 缓存（dnsapi DnsGetCacheDataTable，动态加载，导出名试 A/W 两种）。
 * 防环：最多遍历 max_nodes 个节点；对每个节点先 IsBadReadPtr 预检再读，尽力而为不崩溃。
 * 返回遍历的节点数（>=0）；失败返回 -1 并填 err；guard_hit=true 表示因上限提前停止（可能还有更多）。
 */
long long collect_dns_cache(size_t max_nodes, std::vector<DnsCacheItem>& out,
                            std::string& err, bool& guard_hit) {
    guard_hit = false;
    HMODULE mod = GetModuleHandleW(L"dnsapi.dll");
    if (!mod) mod = LoadLibraryW(L"dnsapi.dll");
    if (!mod) {
        err = "无法加载 dnsapi.dll";
        return -1;
    }
    using DnsGetCacheDataTableFn = int (WINAPI*)(DNS_CACHE_ENTRY**);
    DnsGetCacheDataTableFn fn = nullptr;
    static const char* kNames[] = {"DnsGetCacheDataTable", "DnsGetCacheDataTableW",
                                   "DnsGetCacheDataTableA"};
    for (const char* n : kNames) {
        // 经 void* 双重转换，规避 -Wcast-function-type
        fn = reinterpret_cast<DnsGetCacheDataTableFn>(reinterpret_cast<void*>(GetProcAddress(mod, n)));
        if (fn) break;
    }
    if (!fn) {
        err = "dnsapi.dll 中找不到 DnsGetCacheDataTable 导出";
        return -1;
    }
    DNS_CACHE_ENTRY* head = nullptr;
    const int rc = fn(&head);
    if (rc == 0) {
        err = "DnsGetCacheDataTable 返回 0（缓存为空或读取失败）";
        return -1;
    }
    if (!head) return 0;   // 空缓存

    long long walked = 0;
    DNS_CACHE_ENTRY* p = head;
    while (p != nullptr && walked < static_cast<long long>(max_nodes)) {
        ++walked;
        if (IsBadReadPtr(p, sizeof(DNS_CACHE_ENTRY))) break;   // 节点内存不可读，停止
        DNS_CACHE_ENTRY* next = p->pNext;
        PWSTR wname = p->pszName;
        unsigned int type = p->wType;
        // 记录数据紧随结构之后（布局未完全文档化，best effort）
        const unsigned char* data = reinterpret_cast<const unsigned char*>(p) + sizeof(DNS_CACHE_ENTRY);
        std::string name;
        if (wname != nullptr && !IsBadReadPtr(wname, sizeof(wchar_t) * 2)) {
            // 每 64 字符整块预检可读性，避免跨页越界读取；遇 NUL 提前结束，上限 512 字符
            std::wstring w;
            for (int base = 0; base < 512; base += 64) {
                if (IsBadReadPtr(wname + base, sizeof(wchar_t) * 64)) break;
                for (int i = base; i < base + 64; ++i) {
                    wchar_t c = wname[i];
                    if (c == L'\0') break;
                    w += c;
                }
            }
            name = aiutil::to_utf8(w);
        }
        if (!name.empty()) {
            DnsCacheItem item;
            item.name = name;
            item.type = type;
            if (type == 1 && !IsBadReadPtr(data, 4)) {              // A 记录：4 字节 IPv4
                unsigned long v = 0;
                std::memcpy(&v, data, 4);
                item.ip = ipv4_from_be(v);
            } else if (type == 28 && !IsBadReadPtr(data, 16)) {     // AAAA 记录：16 字节 IPv6
                unsigned char b[16];
                std::memcpy(b, data, 16);
                item.ip = ipv6_from_bytes(b);
            }
            out.push_back(item);
        }
        p = next;
    }
    if (p != nullptr && walked >= static_cast<long long>(max_nodes)) guard_hit = true;
    return walked;
}

// ---------------- 注册表值读取（t_get_proxy_config 用） ----------------

std::string reg_sz(HKEY hk, const wchar_t* name) {
    wchar_t buf[4096];
    DWORD size = sizeof(buf), type = 0;
    if (RegQueryValueExW(hk, name, nullptr, &type, reinterpret_cast<LPBYTE>(buf), &size) != ERROR_SUCCESS)
        return "";
    if (type != REG_SZ && type != REG_EXPAND_SZ) return "";
    size_t chars = size / sizeof(wchar_t);
    if (chars > 0 && buf[chars - 1] == L'\0') --chars;
    return aiutil::to_utf8(std::wstring(buf, chars));
}

unsigned long reg_dword(HKEY hk, const wchar_t* name, unsigned long def = 0) {
    DWORD v = 0, size = sizeof(v), type = 0;
    if (RegQueryValueExW(hk, name, nullptr, &type, reinterpret_cast<LPBYTE>(&v), &size) != ERROR_SUCCESS)
        return def;
    if (type != REG_DWORD || size < 4) return def;
    return v;
}

// ---------------- 防火墙规则分隔线（t_list_firewall_rules 用） ----------------

// netsh 规则块之间是一串 '-' 的长行
bool is_dash_line(const std::string& line) {
    int dashes = 0;
    for (char c : line) {
        if (c == '-') {
            ++dashes;
        } else if (c != ' ' && c != '\r' && c != '\t') {
            return false;
        }
    }
    return dashes >= 8;
}

// ---------------- 封禁单个 IP（t_block_ip / t_block_domain 共用核心逻辑） ----------------

/*
 * 成功返回 true 并填 entry；失败返回 false 并填 err（含 "需要管理员" 的错误会以 ERROR 文本返回）。
 * dry_run 时只返回将执行的命令，不改系统。
 */
bool block_ip_core(const std::string& ip, const std::string& rule_name,
                   const std::string& direction, bool dry,
                   json& entry, std::string& err) {
    const std::string safe_name = sanitize_netsh_string(rule_name);
    const std::string cmd = "netsh advfirewall firewall add rule name=\"" + safe_name
                          + "\" dir=" + direction + " action=block remoteip=" + ip;
    if (dry) {
        entry = json{{"ip", ip}, {"command", cmd}, {"dry_run", true},
                     {"note", "将添加防火墙规则（不执行）"}};
        return true;
    }
    // 真执行（超时 20 秒）
    std::string out_text = aiext::run_capture(cmd, 20000, 8000);
    if (out_text.rfind("ERROR: ", 0) == 0) {   // CreateProcess/超时等失败
        err = out_text;
        return false;
    }
    // netsh 成功输出 "确定。" / "Ok."
    const bool ok = out_text.find("确定") != std::string::npos
                 || out_text.find("Ok.") != std::string::npos
                 || out_text.find("OK.") != std::string::npos;
    if (!ok) {
        const bool need_admin = out_text.find("需要管理员") != std::string::npos
                             || out_text.find("需要提升") != std::string::npos
                             || out_text.find("requires elevation") != std::string::npos;
        err = need_admin ? ("添加防火墙规则失败（需要管理员权限）: " + out_text)
                         : ("添加防火墙规则失败: " + out_text);
        return false;
    }
    entry = json{{"ip", ip}, {"blocked", true}, {"rule_name", rule_name},
                 {"command", cmd}, {"output", out_text}, {"dry_run", false}};
    return true;
}

}  // namespace

namespace aiext {

// ============================================================
// 1. t_get_dns_cache：本机 DNS 解析缓存
// ============================================================

// {"limit":200} -> {"count","truncated","entries":[{name,type,ip?}],"note"}
std::string t_get_dns_cache(const nlohmann::json& args, AiContext&) {
    try {
        int limit = parse_int_arg(args, "limit", 200);
        if (limit <= 0) limit = 200;
        if (limit > 1000) limit = 1000;
        std::vector<DnsCacheItem> items;
        std::string err;
        bool guard_hit = false;
        // 防环：最多遍历 limit*4 个节点
        const long long walked =
            collect_dns_cache(static_cast<size_t>(limit) * 4, items, err, guard_hit);
        if (walked < 0) return ERR(err);
        json entries = json::array();
        int count = 0;
        for (const auto& it : items) {
            if (count >= limit) break;
            json e = {{"name", it.name}, {"type", dns_type_name(it.type)}};
            if (!it.ip.empty()) e["ip"] = it.ip;   // 提取失败则省略 ip 字段
            entries.push_back(std::move(e));
            ++count;
        }
        const bool truncated = guard_hit || static_cast<int>(items.size()) > limit;
        const json out = {
            {"count", count}, {"truncated", truncated}, {"entries", entries},
            {"note", "DNS 缓存条目布局未完全文档化，IP 提取为 best effort"
                     "（A/AAAA 按结构体后数据读取，可能不准）；名称不可读的条目已跳过"}};
        return aiutil::dump_json(out);
    } catch (const std::exception& e) {
        return ERR(std::string("工具执行异常: ") + e.what());
    } catch (...) {
        return ERR("工具执行异常（未知）");
    }
}

// ============================================================
// 2. t_list_udp_endpoints：UDP 端点（AF_INET）
// ============================================================

// {"pid":可选,"limit":200} -> {"count","truncated","endpoints":[{local,port,pid,process}]}
std::string t_list_udp_endpoints(const nlohmann::json& args, AiContext&) {
    try {
        int limit = parse_int_arg(args, "limit", 200);
        if (limit <= 0) limit = 200;
        if (limit > 1000) limit = 1000;
        bool has_pid = false;
        DWORD want_pid = 0;
        parse_pid_arg(args, has_pid, want_pid);

        DWORD size = 0;
        DWORD rc = GetExtendedUdpTable(nullptr, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
        if (rc != ERROR_INSUFFICIENT_BUFFER)
            return ERR("GetExtendedUdpTable 失败（错误 " + std::to_string(rc) + "）");
        if (size == 0 || size > 16UL * 1024UL * 1024UL)
            return ERR("UDP 表大小异常: " + std::to_string(size));
        std::vector<unsigned char> buf(size);
        rc = GetExtendedUdpTable(buf.data(), &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
        if (rc != NO_ERROR)
            return ERR("GetExtendedUdpTable 失败（错误 " + std::to_string(rc) + "）");
        auto* table = reinterpret_cast<MIB_UDPTABLE_OWNER_PID*>(buf.data());

        json endpoints = json::array();
        int count = 0;
        bool truncated = false;
        for (DWORD i = 0; i < table->dwNumEntries; ++i) {
            const MIB_UDPROW_OWNER_PID& r = table->table[i];
            if (has_pid && r.dwOwningPid != want_pid) continue;
            if (count >= limit) {
                truncated = true;
                continue;
            }
            endpoints.push_back({{"local", ipv4_from_be(r.dwLocalAddr)},
                                 {"port", static_cast<int>(ntohs(static_cast<u_short>(r.dwLocalPort)))},
                                 {"pid", r.dwOwningPid},
                                 {"process", process_name_by_pid(r.dwOwningPid)}});
            ++count;
        }
        const json out = {{"count", count}, {"truncated", truncated}, {"endpoints", endpoints}};
        return aiutil::dump_json(out);
    } catch (const std::exception& e) {
        return ERR(std::string("工具执行异常: ") + e.what());
    } catch (...) {
        return ERR("工具执行异常（未知）");
    }
}

// ============================================================
// 3. t_list_listeners：TCP 监听器（含创建时间/模块）
// ============================================================

// {"pid":可选,"limit":200} -> {"count","truncated","listeners":[{local,port,pid,process,created,module?}]}
std::string t_list_listeners(const nlohmann::json& args, AiContext&) {
    try {
        int limit = parse_int_arg(args, "limit", 200);
        if (limit <= 0) limit = 200;
        if (limit > 1000) limit = 1000;
        bool has_pid = false;
        DWORD want_pid = 0;
        parse_pid_arg(args, has_pid, want_pid);

        DWORD size = 0;
        DWORD rc =
            GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_MODULE_LISTENER, 0);
        if (rc != ERROR_INSUFFICIENT_BUFFER)
            return ERR("GetExtendedTcpTable 失败（错误 " + std::to_string(rc) + "）");
        if (size == 0 || size > 16UL * 1024UL * 1024UL)
            return ERR("TCP 表大小异常: " + std::to_string(size));
        std::vector<unsigned char> buf(size);
        rc = GetExtendedTcpTable(buf.data(), &size, FALSE, AF_INET,
                                 TCP_TABLE_OWNER_MODULE_LISTENER, 0);
        if (rc != NO_ERROR)
            return ERR("GetExtendedTcpTable 失败（错误 " + std::to_string(rc) + "）");
        auto* table = reinterpret_cast<MIB_TCPTABLE_OWNER_MODULE*>(buf.data());

        json listeners = json::array();
        int count = 0;
        bool truncated = false;
        for (DWORD i = 0; i < table->dwNumEntries; ++i) {
            const MIB_TCPROW_OWNER_MODULE& r = table->table[i];
            if (has_pid && r.dwOwningPid != want_pid) continue;
            if (r.dwState != MIB_TCP_STATE_LISTEN) continue;   // 只保留 LISTEN(2)
            if (count >= limit) {
                truncated = true;
                continue;
            }
            json row = {{"local", ipv4_from_be(r.dwLocalAddr)},
                        {"port", static_cast<int>(ntohs(static_cast<u_short>(r.dwLocalPort)))},
                        {"pid", r.dwOwningPid},
                        {"process", process_name_by_pid(r.dwOwningPid)},
                        {"created", aiext::iso_from_filetime(r.liCreateTimestamp.QuadPart)}};
            // 模块路径尽力而为（需要完整 row 结构，失败省略）
            DWORD msize = 0;
            if (GetOwnerModuleFromTcpEntry(&table->table[i], TCPIP_OWNER_MODULE_INFO_BASIC,
                                           nullptr, &msize) == ERROR_INSUFFICIENT_BUFFER &&
                msize > 0 && msize <= 65536) {
                std::vector<unsigned char> mbuf(msize);
                if (GetOwnerModuleFromTcpEntry(&table->table[i], TCPIP_OWNER_MODULE_INFO_BASIC,
                                               mbuf.data(), &msize) == NO_ERROR) {
                    const auto* bi = reinterpret_cast<const TCPIP_OWNER_MODULE_BASIC_INFO*>(mbuf.data());
                    if (bi->pModulePath != nullptr) row["module"] = aiutil::to_utf8(bi->pModulePath);
                }
            }
            listeners.push_back(std::move(row));
            ++count;
        }
        const json out = {{"count", count}, {"truncated", truncated}, {"listeners", listeners}};
        return aiutil::dump_json(out);
    } catch (const std::exception& e) {
        return ERR(std::string("工具执行异常: ") + e.what());
    } catch (...) {
        return ERR("工具执行异常（未知）");
    }
}

// ============================================================
// 4. t_resolve_ip_domains：用 DNS 缓存反查 IP 的域名
// ============================================================

// {"ip":"1.2.3.4"} -> {"ip","domains":[...],"count","note"}
std::string t_resolve_ip_domains(const nlohmann::json& args, AiContext&) {
    try {
        const std::string ip = json_string_arg(args, "ip");
        if (ip.empty()) return ERR("缺少 ip 参数");
        if (!ensure_wsa()) return ERR(g_wsa_err);
        sockaddr_in sa4{};
        sockaddr_in6 sa6{};
        const bool v4 = inet_pton(AF_INET, ip.c_str(), &sa4.sin_addr) == 1;
        bool v6 = false;
        if (!v4) v6 = inet_pton(AF_INET6, ip.c_str(), &sa6.sin6_addr) == 1;
        if (!v4 && !v6) return ERR("无效的 IP 地址: " + ip);
        std::string target_norm;
        if (v4) {
            target_norm = ip;   // 点分串直接比对
        } else {
            unsigned char b[16];
            std::memcpy(b, &sa6.sin6_addr, 16);
            target_norm = to_lower(ipv6_from_bytes(b));   // 归一化为小写后比对
        }

        std::vector<DnsCacheItem> items;
        std::string err;
        bool guard_hit = false;
        // 与 t_get_dns_cache 同款缓存条目，上限 500 个节点
        const long long walked = collect_dns_cache(500, items, err, guard_hit);
        if (walked < 0) return ERR(err);
        constexpr size_t kMaxDomains = 500;
        std::vector<std::string> doms;
        for (const auto& it : items) {
            if (it.ip.empty()) continue;   // 提取失败的条目被跳过
            const std::string cmp = v4 ? it.ip : to_lower(it.ip);
            if (cmp == target_norm && doms.size() < kMaxDomains &&
                std::find(doms.begin(), doms.end(), it.name) == doms.end())
                doms.push_back(it.name);
        }
        json jdoms = json::array();
        for (const auto& d : doms) jdoms.push_back(d);
        const json out = {{"ip", ip}, {"domains", jdoms}, {"count", jdoms.size()},
                          {"note", "来自 DNS 缓存，只能反映近期解析；提取失败的条目被跳过"}};
        return aiutil::dump_json(out);
    } catch (const std::exception& e) {
        return ERR(std::string("工具执行异常: ") + e.what());
    } catch (...) {
        return ERR("工具执行异常（未知）");
    }
}

// ============================================================
// 5. t_get_route_table：IPv4 路由表
// ============================================================

// {"limit":100} -> {"count","truncated","routes":[{dest,mask,gateway,if_index,metric,type,proto}],"note"}
std::string t_get_route_table(const nlohmann::json& args, AiContext&) {
    try {
        int limit = parse_int_arg(args, "limit", 100);
        if (limit <= 0) limit = 100;
        if (limit > 1000) limit = 1000;
        unsigned long size = 0;
        DWORD rc = GetIpForwardTable(nullptr, &size, FALSE);
        if (rc != ERROR_INSUFFICIENT_BUFFER)
            return ERR("GetIpForwardTable 失败（错误 " + std::to_string(rc) + "）");
        if (size == 0 || size > 16UL * 1024UL * 1024UL)
            return ERR("路由表大小异常: " + std::to_string(size));
        std::vector<unsigned char> buf(size);
        rc = GetIpForwardTable(reinterpret_cast<MIB_IPFORWARDTABLE*>(buf.data()), &size, FALSE);
        if (rc != NO_ERROR && rc != ERROR_NO_DATA)
            return ERR("GetIpForwardTable 失败（错误 " + std::to_string(rc) + "）");
        auto* table = reinterpret_cast<MIB_IPFORWARDTABLE*>(buf.data());
        const DWORD total = (rc == NO_ERROR) ? table->dwNumEntries : 0;

        json routes = json::array();
        int count = 0;
        bool truncated = false;
        for (DWORD i = 0; i < total; ++i) {
            const MIB_IPFORWARDROW& r = table->table[i];
            if (count >= limit) {
                truncated = true;
                continue;
            }
            routes.push_back({{"dest", ipv4_from_be(r.dwForwardDest)},
                              {"mask", ipv4_from_be(r.dwForwardMask)},
                              {"gateway", ipv4_from_be(r.dwForwardNextHop)},
                              {"if_index", r.dwForwardIfIndex},
                              {"metric", r.dwForwardMetric1},
                              {"type", route_type_name(r.dwForwardType)},
                              {"proto", route_proto_name(r.dwForwardProto)}});
            ++count;
        }
        const json out = {
            {"count", count}, {"truncated", truncated}, {"routes", routes},
            {"note", "type: 1=other,2=invalid,3=direct,4=indirect；"
                     "proto: 2=local,3=static,4=icmp,8=rip,13=ospf,14=bgp（其他为数字）"}};
        return aiutil::dump_json(out);
    } catch (const std::exception& e) {
        return ERR(std::string("工具执行异常: ") + e.what());
    } catch (...) {
        return ERR("工具执行异常（未知）");
    }
}

// ============================================================
// 6. t_get_arp_cache：ARP/邻居缓存
// ============================================================

// {"limit":200} -> {"count","truncated","arp":[{ip,mac,if_index,type}]}
std::string t_get_arp_cache(const nlohmann::json& args, AiContext&) {
    try {
        int limit = parse_int_arg(args, "limit", 200);
        if (limit <= 0) limit = 200;
        if (limit > 1000) limit = 1000;
        unsigned long size = 0;
        DWORD rc = GetIpNetTable(nullptr, &size, FALSE);
        if (rc != ERROR_INSUFFICIENT_BUFFER)
            return ERR("GetIpNetTable 失败（错误 " + std::to_string(rc) + "）");
        if (size == 0 || size > 16UL * 1024UL * 1024UL)
            return ERR("ARP 表大小异常: " + std::to_string(size));
        std::vector<unsigned char> buf(size);
        rc = GetIpNetTable(reinterpret_cast<MIB_IPNETTABLE*>(buf.data()), &size, FALSE);
        if (rc != NO_ERROR && rc != ERROR_NO_DATA)
            return ERR("GetIpNetTable 失败（错误 " + std::to_string(rc) + "）");
        auto* table = reinterpret_cast<MIB_IPNETTABLE*>(buf.data());
        const DWORD total = (rc == NO_ERROR) ? table->dwNumEntries : 0;

        json arp = json::array();
        int count = 0;
        bool truncated = false;
        for (DWORD i = 0; i < total; ++i) {
            const MIB_IPNETROW& r = table->table[i];
            if (count >= limit) {
                truncated = true;
                continue;
            }
            std::string mac;
            char hex[4];
            for (DWORD j = 0; j < r.dwPhysAddrLen && j < static_cast<DWORD>(MAXLEN_PHYSADDR); ++j) {
                std::snprintf(hex, sizeof(hex), "%02x", static_cast<unsigned>(r.bPhysAddr[j]));
                if (!mac.empty()) mac += ':';
                mac += hex;
            }
            arp.push_back({{"ip", ipv4_from_be(r.dwAddr)},
                           {"mac", mac},
                           {"if_index", r.dwIndex},
                           {"type", arp_type_name(r.dwType)}});
            ++count;
        }
        const json out = {{"count", count}, {"truncated", truncated}, {"arp", arp}};
        return aiutil::dump_json(out);
    } catch (const std::exception& e) {
        return ERR(std::string("工具执行异常: ") + e.what());
    } catch (...) {
        return ERR("工具执行异常（未知）");
    }
}

// ============================================================
// 7. t_list_firewall_rules：防火墙规则原文（只读 netsh）
// ============================================================

// {"profile":"domain|private|public|all","limit":100} -> {"profile","count","rules_text","truncated"}
std::string t_list_firewall_rules(const nlohmann::json& args, AiContext&) {
    try {
        std::string profile = to_lower(json_string_arg(args, "profile", "all"));
        if (profile.empty()) profile = "all";
        if (profile != "all" && profile != "domain" && profile != "private" && profile != "public")
            return ERR("无效的 profile: " + profile + "（可选 all/domain/private/public）");
        int limit = parse_int_arg(args, "limit", 100);
        if (limit <= 0) limit = 100;
        if (limit > 1000) limit = 1000;
        // netsh 输出整份规则很慢：Win7 上几百条规则经常超过 30 秒，会直接报"命令超时"。
        // 实测在规则多的机器上 120 秒仍不够（AI 反馈过一次超时），默认给 300 秒（上限 15 分钟）。
        // 想快就带 profile 或调小 limit；超时时返回的 note 会提示这一点。
        int timeout_ms = parse_int_arg(args, "timeout_ms", 300000);
        if (timeout_ms < 5000) timeout_ms = 5000;
        if (timeout_ms > 900000) timeout_ms = 900000;
        const std::string cmd = (profile == "all")
            ? std::string("netsh advfirewall firewall show rule name=all")
            : std::string("netsh advfirewall firewall show rule name=all profile=") + profile;
        // 只读查询，原文交给 AI 自己解析（输出上限 512KB，避免规则多时被截太早）
        std::string text = aiext::run_capture(cmd, timeout_ms, 512 * 1024);
        if (text.rfind("ERROR: ", 0) == 0) {
            // 超时是"规则太多/机器慢"的典型症状，直接把可操作的下一步写进错误里
            if (text.find("超时") != std::string::npos)
                return ERR(text + "；本机规则可能特别多，建议加 profile=domain|private|public "
                                  "缩小范围，或用 timeout_ms 再放宽（上限 900000）");
            return text;   // run_capture 的其它失败
        }

        // 按分隔线（'-' 长行）切块：每块约一条规则
        std::vector<std::string> blocks;
        {
            std::istringstream ss(text);
            std::string line, cur;
            while (std::getline(ss, line)) {
                if (is_dash_line(line)) {
                    if (!cur.empty()) {
                        blocks.push_back(cur);
                        cur.clear();
                    }
                } else {
                    cur += line;
                    cur += '\n';
                }
            }
            if (!cur.empty()) blocks.push_back(cur);
        }
        blocks.erase(std::remove_if(blocks.begin(), blocks.end(),
                                    [](const std::string& b) {
                                        return b.find_first_not_of(" \t\r\n") == std::string::npos;
                                    }),
                     blocks.end());
        const int total = static_cast<int>(blocks.size());
        const bool truncated = total > limit;
        std::string rules_text;
        for (int i = 0; i < total && i < limit; ++i) {
            rules_text += blocks[static_cast<size_t>(i)];
            if (i + 1 < total && i + 1 < limit) rules_text += '\n';
        }
        if (rules_text.size() > 65536) rules_text = aiutil::utf8_truncate(rules_text, 65536);
        const json out = {{"profile", profile}, {"count", total},
                          {"rules_text", rules_text}, {"truncated", truncated}};
        return aiutil::dump_json(out);
    } catch (const std::exception& e) {
        return ERR(std::string("工具执行异常: ") + e.what());
    } catch (...) {
        return ERR("工具执行异常（未知）");
    }
}

// ============================================================
// 8. t_get_proxy_config：WinHTTP + WinINET 代理配置
// ============================================================

// {} -> {"winhttp":{...},"wininet":{...}}
std::string t_get_proxy_config(const nlohmann::json&, AiContext&) {
    try {
        json winhttp = json::object();
        {
            WINHTTP_PROXY_INFO info{};
            if (WinHttpGetDefaultProxyConfiguration(&info)) {
                winhttp["access_type"] = info.dwAccessType;
                winhttp["access_type_name"] = proxy_access_name(info.dwAccessType);
                winhttp["proxy"] =
                    (info.lpszProxy != nullptr) ? aiutil::to_utf8(info.lpszProxy) : "";
                winhttp["bypass"] =
                    (info.lpszProxyBypass != nullptr) ? aiutil::to_utf8(info.lpszProxyBypass) : "";
            } else {
                winhttp["access_type"] = 0;
                winhttp["access_type_name"] = "unknown";
                winhttp["proxy"] = "";
                winhttp["bypass"] = "";
                winhttp["error"] = "WinHttpGetDefaultProxyConfiguration 失败（错误 "
                                 + std::to_string(GetLastError()) + "）";
            }
            if (info.lpszProxy != nullptr) GlobalFree(info.lpszProxy);
            if (info.lpszProxyBypass != nullptr) GlobalFree(info.lpszProxyBypass);
        }
        json wininet = json::object();
        {
            HKEY hk = nullptr;
            if (RegOpenKeyExW(HKEY_CURRENT_USER,
                              L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
                              0, KEY_READ, &hk) == ERROR_SUCCESS) {
                wininet["proxy_enable"] = static_cast<int>(reg_dword(hk, L"ProxyEnable"));
                wininet["proxy_server"] = reg_sz(hk, L"ProxyServer");
                wininet["proxy_override"] = reg_sz(hk, L"ProxyOverride");
                wininet["autoconfig_url"] = reg_sz(hk, L"AutoConfigURL");
                RegCloseKey(hk);
            } else {
                wininet["proxy_enable"] = 0;
                wininet["proxy_server"] = "";
                wininet["proxy_override"] = "";
                wininet["autoconfig_url"] = "";
                wininet["error"] = "打开注册表 Internet Settings 失败（错误 "
                                 + std::to_string(GetLastError()) + "）";
            }
        }
        const json out = {
            {"winhttp", winhttp}, {"wininet", wininet},
            {"note", "winhttp access_type: 0=default(通常直连),1=direct(no_proxy),"
                     "3=proxy(named_proxy),4=auto_detect"}};
        return aiutil::dump_json(out);
    } catch (const std::exception& e) {
        return ERR(std::string("工具执行异常: ") + e.what());
    } catch (...) {
        return ERR("工具执行异常（未知）");
    }
}

// ============================================================
// 9. t_block_ip：防火墙封禁 IP（处置类，支持 dry_run）
// ============================================================

// {"ip":"1.2.3.4","name":可选,"direction":"out|in","dry_run":bool} -> 防火墙封禁
std::string t_block_ip(const nlohmann::json& args, AiContext& ctx) {
    try {
        const std::string ip = json_string_arg(args, "ip");
        if (ip.empty()) return ERR("缺少 ip 参数");
        if (!ensure_wsa()) return ERR(g_wsa_err);
        sockaddr_in sa4{};
        sockaddr_in6 sa6{};
        const bool v4 = inet_pton(AF_INET, ip.c_str(), &sa4.sin_addr) == 1;
        bool v6 = false;
        if (!v4) v6 = inet_pton(AF_INET6, ip.c_str(), &sa6.sin6_addr) == 1;
        if (!v4 && !v6) return ERR("无效的 IP 地址: " + ip);
        std::string name = json_string_arg(args, "name");
        if (name.empty()) name = "AvEngine block " + ip;
        const std::string direction = to_lower(json_string_arg(args, "direction", "out"));
        if (direction != "in" && direction != "out")
            return ERR("无效的 direction: " + direction + "（可选 in/out）");

        const bool dry = aiext::dry_run_requested(args, ctx);
        json entry;
        std::string err;
        if (!block_ip_core(ip, name, direction, dry, entry, err)) return err;
        return aiutil::dump_json(entry);
    } catch (const std::exception& e) {
        return ERR(std::string("工具执行异常: ") + e.what());
    } catch (...) {
        return ERR("工具执行异常（未知）");
    }
}

// ============================================================
// 10. t_block_domain：解析域名并封禁其 IP（处置类，支持 dry_run）
// ============================================================

// {"domain":"evil.com","dry_run":bool} -> {"domain","resolved":[...],"blocked":[...],"note","dry_run"}
std::string t_block_domain(const nlohmann::json& args, AiContext& ctx) {
    try {
        const std::string domain = json_string_arg(args, "domain");
        if (domain.empty()) return ERR("缺少 domain 参数");
        if (domain.size() > 253) return ERR("域名过长: " + domain);
        // 域名校验：仅 [A-Za-z0-9.-]
        for (char c : domain) {
            const bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                            (c >= '0' && c <= '9') || c == '.' || c == '-';
            if (!ok) return ERR("域名包含非法字符（仅允许字母/数字/./-）: " + domain);
        }

        const bool dry = aiext::dry_run_requested(args, ctx);
        if (!ensure_wsa()) return ERR(g_wsa_err);

        // getaddrinfo 解析（AF_INET 优先，失败回退 IPv6）
        constexpr size_t kMaxResolved = 500;
        std::vector<std::string> ips;
        {
            addrinfo hints{};
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_STREAM;
            addrinfo* res = nullptr;
            if (getaddrinfo(domain.c_str(), nullptr, &hints, &res) == 0 && res != nullptr) {
                for (const addrinfo* p = res; p != nullptr; p = p->ai_next) {
                    if (p->ai_family == AF_INET && p->ai_addr != nullptr &&
                        p->ai_addrlen >= sizeof(sockaddr_in)) {
                        unsigned long addr_be = 0;
                        std::memcpy(&addr_be,
                                    &reinterpret_cast<const sockaddr_in*>(p->ai_addr)->sin_addr, 4);
                        const std::string ip = ipv4_from_be(addr_be);
                        if (ips.size() < kMaxResolved &&
                            std::find(ips.begin(), ips.end(), ip) == ips.end())
                            ips.push_back(ip);
                    }
                }
                freeaddrinfo(res);
            }
        }
        if (ips.empty()) {
            addrinfo hints6{};
            hints6.ai_family = AF_INET6;
            hints6.ai_socktype = SOCK_STREAM;
            addrinfo* res6 = nullptr;
            if (getaddrinfo(domain.c_str(), nullptr, &hints6, &res6) == 0 && res6 != nullptr) {
                for (const addrinfo* p = res6; p != nullptr; p = p->ai_next) {
                    if (p->ai_family == AF_INET6 && p->ai_addr != nullptr &&
                        p->ai_addrlen >= sizeof(sockaddr_in6)) {
                        unsigned char b[16];
                        std::memcpy(b,
                                    &reinterpret_cast<const sockaddr_in6*>(p->ai_addr)->sin6_addr,
                                    16);
                        const std::string ip = ipv6_from_bytes(b);
                        if (ips.size() < kMaxResolved &&
                            std::find(ips.begin(), ips.end(), ip) == ips.end())
                            ips.push_back(ip);
                    }
                }
                freeaddrinfo(res6);
            }
        }
        if (ips.empty()) return ERR("无法解析域名: " + domain);

        json resolved = json::array();
        for (const auto& ip : ips) resolved.push_back(ip);
        json blocked = json::array();
        int fail_count = 0;
        std::string first_err;
        for (const auto& ip : ips) {
            json entry;
            std::string err;
            const std::string rule_name = "AvEngine block " + ip;
            if (block_ip_core(ip, rule_name, "out", dry, entry, err)) {
                blocked.push_back(std::move(entry));
            } else {
                ++fail_count;
                if (first_err.empty()) first_err = err;
                blocked.push_back(json{{"ip", ip}, {"blocked", false}, {"error", err}});
            }
        }
        if (fail_count > 0 && fail_count == static_cast<int>(ips.size()))
            return ERR(first_err);   // 全部封禁失败（常见原因：需要管理员）
        const json out = {{"domain", domain}, {"resolved", resolved}, {"blocked", blocked},
                          {"note", "域名解析会变化，建议同时封禁关键 IP 段"}, {"dry_run", dry}};
        return aiutil::dump_json(out);
    } catch (const std::exception& e) {
        return ERR(std::string("工具执行异常: ") + e.what());
    } catch (...) {
        return ERR("工具执行异常（未知）");
    }
}

}  // namespace aiext
