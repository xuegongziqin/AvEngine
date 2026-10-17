// ai_tools_logs.cpp - AI 工具扩展库：日志与脚本侧
// （PowerShell 4104 脚本块日志 / 转录文件 / 脚本解码 / 事件订阅与实时 tail /
//   任意通道事件查询 / AMSI 事件 / Security 登录与进程日志）
//
// 实现约定见 ai_tools_ext.h 头部：
//   - 成功返回 UTF-8 JSON 文本（一律 aiutil::dump_json），失败返回 "ERROR: 原因"，不抛异常；
//   - 审计由 ai_execute_tool 统一完成，工具内不做审计；
//   - 列表输出全部带 limit 与硬上限，防止撑爆模型上下文；
//   - CDATA 标记与 XML 实体名用字符常量拼接构造（源码里不出现会被写入管线破坏的字面量序列）。
#define WIN32_LEAN_AND_MEAN
#include "ai_tools_ext.h"

#include "ai_util.h"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include <windows.h>
#include <winevt.h>
#include <winreg.h>

namespace fs = std::filesystem;

using nlohmann::json;

namespace {

// ---------------- 小工具 ----------------

std::string make_err(const std::string& m) { return "ERROR: " + m; }

char lower_char(char c) {
    return static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
}

std::string to_lower(std::string s) {
    for (char& c : s) c = lower_char(c);
    return s;
}

std::string trim_copy(const std::string& s) {
    const size_t b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) return "";
    const size_t e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}

int clamp_int(int v, int lo, int hi) { return v < lo ? lo : (v > hi ? hi : v); }

// 数字参数（兼容数字字符串；解析失败用默认值）
double json_num(const json& args, const char* key, double def) {
    if (!args.contains(key)) return def;
    const json& v = args.at(key);
    if (v.is_number()) return v.get<double>();
    if (v.is_string()) {
        try {
            return std::stod(v.get<std::string>());
        } catch (...) {
            return def;
        }
    }
    return def;
}

int json_int(const json& args, const char* key, int def) {
    const double d = json_num(args, key, static_cast<double>(def));
    if (!(d > -2.0e9)) return -2000000000;  // NaN 或过小
    if (d > 2.0e9) return 2000000000;
    return static_cast<int>(d);
}

// 数字字符串 -> 整数，否则原样字符串（JSON 输出更紧凑）
json number_or_string(const std::string& s) {
    if (!s.empty()) {
        char* endp = nullptr;
        const long long v = std::strtoll(s.c_str(), &endp, 10);
        if (endp && endp != s.c_str() && *endp == '\0') return v;
    }
    return s;
}

// source -> 事件通道名（其他值直接当作通道名）
std::string map_source_to_channel(const std::string& source) {
    const std::string s = to_lower(trim_copy(source));
    if (s == "sysmon") return "Microsoft-Windows-Sysmon/Operational";
    if (s == "powershell") return "Windows PowerShell";
    if (s == "powershell_core") return "PowerShellCore/Operational";
    if (s == "security") return "Security";
    if (s == "system") return "System";
    if (s == "application") return "Application";
    if (s == "wmi") return "Microsoft-Windows-WMI-Activity/Operational";
    if (s == "dns") return "Microsoft-Windows-DNS-Client/Operational";
    if (s == "powershell_operational") return "Microsoft-Windows-PowerShell/Operational";
    return trim_copy(source);
}

// ---------------- 简易 XML 提取（不使用正则库） ----------------
// 注意：CDATA 标记与 XML 实体名都用字符常量拼接构造。

const std::string kCdataStart = std::string("<") + "![CDATA[";
const std::string kCdataEnd = std::string("]]") + ">";

std::string xml_attr(const std::string& xml, const std::string& tag, const std::string& attr) {
    const std::string needle = "<" + tag;
    size_t p = xml.find(needle);
    while (p != std::string::npos) {
        const size_t gt = xml.find('>', p);
        if (gt == std::string::npos) break;
        const std::string open = xml.substr(p, gt - p);
        // EvtRender 输出的事件 XML 属性用单引号（SystemTime='...'、Name='...'），
        // 只认双引号会把时间戳和所有 Data 名称都取成空。
        for (const char* q : {"\"", "'"}) {
            const size_t a = open.find(attr + "=" + q);
            if (a == std::string::npos) continue;
            const size_t vstart = a + attr.size() + 2;
            const size_t vend = open.find(q[0], vstart);
            if (vend != std::string::npos) return open.substr(vstart, vend - vstart);
        }
        p = xml.find(needle, gt);
    }
    return "";
}

std::string xml_inner(const std::string& xml, const std::string& tag) {
    const std::string open = "<" + tag;
    const size_t p = xml.find(open);
    if (p == std::string::npos) return "";
    const size_t gt = xml.find('>', p);
    if (gt == std::string::npos) return "";
    const size_t end = xml.find("</" + tag + ">", gt);
    if (end == std::string::npos) return "";
    return xml.substr(gt + 1, end - gt - 1);
}

// 从 EventData 内部按 Name 属性提取 Data 元素的值（值可能被 CDATA 包裹；引号单双兼容）
std::string xml_data_value(const std::string& data_xml, const std::string& name) {
    size_t p = std::string::npos;
    size_t name_end = 0;
    for (const char* q : {"\"", "'"}) {
        const std::string needle = "<Data Name=" + std::string(q) + name + q;
        const size_t hit = data_xml.find(needle);
        if (hit != std::string::npos) {
            p = hit;
            name_end = hit + needle.size();
            break;
        }
    }
    if (p == std::string::npos) return "";
    const size_t gt = data_xml.find('>', name_end);
    if (gt == std::string::npos) return "";
    if (gt > 0 && data_xml[gt - 1] == '/') return "";  // 自闭合（无值）
    const size_t vstart = gt + 1;
    const size_t close = data_xml.find("</Data>", vstart);
    if (close == std::string::npos) return "";
    // 值内部若含 CDATA 段：从 CDATA 结束之后找关闭标签，避免被值内容截断
    const size_t cstart = data_xml.find(kCdataStart, vstart);
    if (cstart != std::string::npos && cstart < close) {
        const size_t cend = data_xml.find(kCdataEnd, cstart);
        if (cend != std::string::npos && cend < close) {
            const size_t close2 = data_xml.find("</Data>", cend + kCdataEnd.size());
            if (close2 != std::string::npos) return data_xml.substr(vstart, close2 - vstart);
        }
    }
    return data_xml.substr(vstart, close - vstart);
}

// 提取 CDATA 内容（不转义）；无 CDATA 时返回空串
std::string xml_cdata_content(const std::string& s) {
    const size_t start = s.find(kCdataStart);
    if (start == std::string::npos) return "";
    const size_t vstart = start + kCdataStart.size();
    const size_t end = s.find(kCdataEnd, vstart);
    if (end == std::string::npos) return s.substr(vstart);
    return s.substr(vstart, end - vstart);
}

std::string xml_unescape(std::string s) {
    // 实体名用字符常量拼接（见文件头说明）；amp 最后替换避免二次解转义
    const std::string lt(1, '<'), gt(1, '>'), amp(1, '&');
    const std::pair<std::string, std::string> ents[] = {
        { std::string(1, '&') + "lt;",   lt  },
        { std::string(1, '&') + "gt;",   gt  },
        { std::string(1, '&') + "quot;", "\"" },
        { std::string(1, '&') + "amp;",  amp },
    };
    for (const auto& e : ents) {
        size_t p;
        while ((p = s.find(e.first)) != std::string::npos)
            s.replace(p, e.first.size(), e.second);
    }
    return s;
}

// 控制字符变空格、多空格合并、去首尾
std::string squeeze_ws(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (const char c : s) {
        char m = c;
        if (m == '\n' || m == '\r' || m == '\t') m = ' ';
        if (m == ' ' && !out.empty() && out.back() == ' ') continue;
        out += m;
    }
    const size_t b = out.find_first_not_of(' ');
    if (b == std::string::npos) return "";
    const size_t e = out.find_last_not_of(' ');
    return out.substr(b, e - b + 1);
}

// 在 squeeze_ws 基础上把标签字符也变空格（EventData 压缩成一行用）
std::string squeeze_line(const std::string& s) {
    std::string compact;
    compact.reserve(s.size());
    for (const char c : s) {
        if (c == '<' || c == '>') compact += ' ';
        else compact += c;
    }
    return squeeze_ws(compact);
}

// ---------------- wevtapi：EvtQuery / EvtNext / EvtRender ----------------

// 渲染单条事件为紧凑单行：time=.. eid=.. rid=.. level=.. | 数据区压缩文本
std::string render_compact_event(const std::string& xml, size_t data_max) {
    const std::string time = xml_attr(xml, "TimeCreated", "SystemTime");
    const std::string eid = xml_inner(xml, "EventID");
    const std::string rid = xml_inner(xml, "EventRecordID");
    const std::string level = xml_inner(xml, "Level");
    std::string line = "time=" + time + " eid=" + eid + " rid=" + rid + " level=" + level;
    std::string data = xml_inner(xml, "EventData");
    if (data.empty()) data = xml_inner(xml, "UserData");
    if (!data.empty()) {
        std::string text = xml_unescape(squeeze_line(data));
        if (text.size() > data_max) text = aiutil::utf8_truncate(text, data_max) + "...";
        if (!text.empty()) line += " | " + text;
    }
    return line;
}

// EvtRender 两次调用（先查大小 ERROR_INSUFFICIENT_BUFFER）取事件 XML（UTF-16 转 UTF-8）
std::string render_event_xml(EVT_HANDLE event) {
    DWORD used = 0, props = 0;
    if (!EvtRender(nullptr, event, EvtRenderEventXml, 0, nullptr, &used, &props) &&
        GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        return "";
    if (used == 0) return "";
    std::vector<wchar_t> buf(static_cast<size_t>(used) / sizeof(wchar_t) + 1, L'\0');
    if (!EvtRender(nullptr, event, EvtRenderEventXml, used, buf.data(), &used, &props))
        return "";
    return aiutil::to_utf8(std::wstring(buf.data()));
}

struct ChannelQuery {
    std::vector<std::string> xmls;  // 渲染好的事件 XML（新到旧）
    DWORD error_code = 0;           // 0 = 成功
    std::string error;              // 非空 = 出错
};

/*
 * EvtQuery 通道（可选 XPath）-> EvtNext 循环（每批 10 条，超时 5s）-> EvtRender。
 * reverse=true 时从新到旧。
 *
 * EvtQueryReverseDirection = 0x200（Windows SDK 与 MinGW winevt.h 都是这个值）。
 * 曾经误用 0x2000（那既不是 ReverseDirection 也不是 TolerateQueryErrors=0x1000），
 * 结果是每次 EvtQuery 都返回 ERROR_INVALID_PARAMETER(87)，所有日志类工具全废。
 */
ChannelQuery query_channel_xml(const std::wstring& channel_w, const wchar_t* query_w,
                               bool reverse, int max_events) {
    ChannelQuery res;
    DWORD flags = EvtQueryChannelPath;
    if (reverse) flags |= EvtQueryReverseDirection;
    EVT_HANDLE q = EvtQuery(nullptr, channel_w.c_str(), query_w, flags);
    if (!q) {
        res.error_code = GetLastError();
        res.error = "EvtQuery 失败（错误 " + std::to_string(res.error_code) + "）";
        return res;
    }
    std::vector<EVT_HANDLE> events(10, nullptr);
    int fetched = 0;
    const int want = max_events > 0 ? max_events : 1;
    for (;;) {
        DWORD returned = 0;
        if (!EvtNext(q, static_cast<DWORD>(events.size()), events.data(), 5000, 0, &returned)) {
            const DWORD e = GetLastError();
            if (e != ERROR_NO_MORE_ITEMS) {
                res.error_code = e;
                res.error = "EvtNext 失败（错误 " + std::to_string(e) + "）";
            }
            break;
        }
        if (returned == 0) break;
        for (DWORD i = 0; i < returned; ++i) {
            if (fetched < want) {
                std::string xml = render_event_xml(events[i]);
                if (!xml.empty()) res.xmls.push_back(std::move(xml));
                ++fetched;
            }
            EvtClose(events[i]);
            events[i] = nullptr;
        }
        if (fetched >= want) break;
    }
    EvtClose(q);
    return res;
}

// ---------------- 时间：ISO8601 -> FILETIME（UTC） ----------------

long long filetime_to_i64(const FILETIME& ft) {
    return (static_cast<long long>(ft.dwHighDateTime) << 32)
         | static_cast<long long>(ft.dwLowDateTime);
}

// 接受 "2026-10-03T14:49:13.123Z" / "2026-10-03 14:49:13" 两种分隔（%*c 跳过分隔符）
bool iso_to_filetime_utc(const std::string& iso, FILETIME& out_ft) {
    if (iso.size() < 14) return false;
    int y = 0, mo = 0, d = 0, h = 0, mi = 0, s = 0;
    if (std::sscanf(iso.c_str(), "%d-%d-%d%*c%d:%d:%d", &y, &mo, &d, &h, &mi, &s) != 6)
        return false;
    if (y < 1601 || y > 9999 || mo < 1 || mo > 12 || d < 1 || d > 31 ||
        h < 0 || h > 23 || mi < 0 || mi > 59 || s < 0 || s > 60)
        return false;
    SYSTEMTIME st{};
    st.wYear = static_cast<WORD>(y);
    st.wMonth = static_cast<WORD>(mo);
    st.wDay = static_cast<WORD>(d);
    st.wHour = static_cast<WORD>(h);
    st.wMinute = static_cast<WORD>(mi);
    st.wSecond = static_cast<WORD>(s);
    return SystemTimeToFileTime(&st, &out_ft) != 0;
}

// 是否落在最近 hours 小时内（解析失败视为在范围内避免丢数据；hours<=0 不过滤）
bool within_hours(const std::string& iso_time, double hours) {
    if (hours <= 0.0) return true;
    FILETIME ft{};
    if (!iso_to_filetime_utc(iso_time, ft)) return true;
    FILETIME now_ft{};
    GetSystemTimeAsFileTime(&now_ft);
    const double seconds = hours * 3600.0;
    if (seconds > 9.0e11) return true;  // 超大 hours：视为全部在范围内
    const long long cutoff = filetime_to_i64(now_ft)
                           - static_cast<long long>(seconds * 10000000.0);
    return filetime_to_i64(ft) >= cutoff;
}

// ---------------- 4104 脚本块日志查询核心（t_get_script_block_log / t_get_amsi_events 复用） ----------------

json query_script_block_json(double hours, int limit, const std::string& channel, std::string& err) {
    err.clear();
    json out;
    out["count"] = 0;
    out["truncated"] = false;
    out["channel"] = channel;
    json events = json::array();

    const std::wstring xpath = L"*[System[(EventID=4104)]]";
    int max_fetch = limit + 200;
    if (max_fetch > 1000) max_fetch = 1000;
    const ChannelQuery q = query_channel_xml(aiutil::to_wide(channel), xpath.c_str(), true, max_fetch);
    if (!q.error.empty()) {
        if (q.error_code == ERROR_EVT_CHANNEL_NOT_FOUND)
            err = "通道不存在或未启用: " + channel;
        else
            err = q.error + ": " + channel;
        return out;
    }

    size_t matched = 0;
    bool truncated = false;
    for (const std::string& xml : q.xmls) {
        const std::string time = xml_attr(xml, "TimeCreated", "SystemTime");
        if (!within_hours(time, hours)) continue;
        ++matched;
        if (matched > static_cast<size_t>(limit)) {
            truncated = true;
            break;
        }
        const std::string data = xml_inner(xml, "EventData");
        const std::string sbt_raw = xml_data_value(data, "ScriptBlockText");
        // ScriptBlockText 被 CDATA 包裹：提取后不转义
        std::string script_text = xml_cdata_content(sbt_raw);
        if (script_text.empty() && !sbt_raw.empty()) script_text = xml_unescape(sbt_raw);
        if (script_text.size() > 2000) script_text = aiutil::utf8_truncate(script_text, 2000) + "...";

        json ev;
        ev["time"] = time;
        ev["script_text"] = script_text;
        ev["path"] = xml_unescape(xml_data_value(data, "Path"));
        ev["message_number"] = number_or_string(xml_unescape(xml_data_value(data, "MessageNumber")));
        ev["message_total"] = number_or_string(xml_unescape(xml_data_value(data, "MessageTotal")));
        events.push_back(std::move(ev));
    }
    const size_t count = events.size();
    out["events"] = std::move(events);
    out["count"] = count;
    out["truncated"] = truncated;
    return out;
}

// ---------------- PowerShell 转录文件 ----------------

// 展开环境变量引用（REG_EXPAND_SZ / %VAR%）
std::wstring expand_env(const std::wstring& s) {
    const DWORD n = ExpandEnvironmentStringsW(s.c_str(), nullptr, 0);
    if (n == 0) return L"";
    std::vector<wchar_t> buf(n);
    if (ExpandEnvironmentStringsW(s.c_str(), buf.data(), n) == 0) return L"";
    return std::wstring(buf.data());
}

bool wide_ci_equal(const std::wstring& a, const std::wstring& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        wchar_t ca = a[i], cb = b[i];
        if (ca >= L'A' && ca <= L'Z') ca = static_cast<wchar_t>(ca - L'A' + L'a');
        if (cb >= L'A' && cb <= L'Z') cb = static_cast<wchar_t>(cb - L'A' + L'a');
        if (ca != cb) return false;
    }
    return true;
}

// Documents 目录：注册表 User Shell Folders 的 Personal（REG_EXPAND_SZ），
// 失败回退 %USERPROFILE%\Documents
std::wstring get_documents_dir() {
    HKEY hk = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER,
                      L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders",
                      0, KEY_READ, &hk) == ERROR_SUCCESS) {
        DWORD type = 0, cb = 0;
        if (RegQueryValueExW(hk, L"Personal", nullptr, &type, nullptr, &cb) == ERROR_SUCCESS &&
            cb > 0 && cb < 8192) {
            std::vector<BYTE> buf(static_cast<size_t>(cb) + 2 * sizeof(wchar_t), 0);
            DWORD cb2 = cb;
            if (RegQueryValueExW(hk, L"Personal", nullptr, &type, buf.data(), &cb2) == ERROR_SUCCESS) {
                std::wstring raw(reinterpret_cast<const wchar_t*>(buf.data()));
                while (!raw.empty() && raw.back() == L'\0') raw.pop_back();
                RegCloseKey(hk);
                const std::wstring exp = expand_env(raw);
                return exp.empty() ? raw : exp;
            }
        }
        RegCloseKey(hk);
    }
    wchar_t up[1024]{};
    const DWORD n = GetEnvironmentVariableW(L"USERPROFILE", up, 1024);
    if (n > 0 && n < 1024) return std::wstring(up) + L"\\Documents";
    return L"";
}

// 读文件前 max_bytes 字节转文本（处理 UTF-16LE / UTF-8 BOM）
std::string read_preview(const std::wstring& path_w, size_t max_bytes) {
    HANDLE h = CreateFileW(path_w.c_str(), GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return "";
    std::vector<char> buf(max_bytes);
    DWORD got = 0;
    ReadFile(h, buf.data(), static_cast<DWORD>(buf.size()), &got, nullptr);
    CloseHandle(h);
    const std::string raw(buf.data(), got);

    if (raw.size() >= 4 &&
        static_cast<unsigned char>(raw[0]) == 0xFF && static_cast<unsigned char>(raw[1]) == 0xFE) {
        std::wstring w((raw.size() - 2) / 2, L'\0');
        if (!w.empty()) std::memcpy(&w[0], raw.data() + 2, w.size() * sizeof(wchar_t));
        return aiutil::to_utf8(w);
    }
    if (raw.size() >= 3 &&
        static_cast<unsigned char>(raw[0]) == 0xEF &&
        static_cast<unsigned char>(raw[1]) == 0xBB &&
        static_cast<unsigned char>(raw[2]) == 0xBF) {
        return raw.substr(3);
    }
    return raw;
}

// 通配符匹配（* 与 ?），大小写不敏感（文件名匹配用）
bool wc_match_ci(const std::string& pat, const std::string& s) {
    size_t p = 0, i = 0;
    size_t star_p = std::string::npos, star_i = 0;
    while (i < s.size()) {
        if (p < pat.size() && (pat[p] == '?' || lower_char(pat[p]) == lower_char(s[i]))) {
            ++p;
            ++i;
        } else if (p < pat.size() && pat[p] == '*') {
            star_p = p++;
            star_i = i;
        } else if (star_p != std::string::npos) {
            p = star_p + 1;
            i = ++star_i;
        } else {
            return false;
        }
    }
    while (p < pat.size() && pat[p] == '*') ++p;
    return p == pat.size();
}

// 递归（深度 <=2，std::error_code 全程）收集文件名匹配通配符模式的文件
void collect_transcript_files(const std::wstring& dir_w, const std::string& pattern,
                              std::vector<std::wstring>& found, size_t hard_cap) {
    std::error_code ec;
    const fs::path base(dir_w);
    fs::recursive_directory_iterator it(base, fs::directory_options::skip_permission_denied, ec);
    if (ec) return;
    for (fs::recursive_directory_iterator end_it; it != end_it; it.increment(ec)) {
        if (ec) return;
        const fs::directory_entry entry = *it;
        std::error_code ec2;
        if (entry.is_directory(ec2) && !ec2) {
            if (it.depth() >= 2) it.disable_recursion_pending();  // 深度 <=2
            continue;
        }
        if (!entry.is_regular_file(ec2) || ec2) continue;
        if (wc_match_ci(pattern, aiutil::to_utf8(entry.path().filename().wstring()))) {
            found.push_back(entry.path().wstring());
            if (found.size() >= hard_cap) return;
        }
    }
}

// ---------------- 脚本解码 ----------------

struct DecodeState {
    std::string decoded;
    std::string encoding;
    double ratio = 0.0;
    bool ok = false;
};

std::string fmt_ratio(double r) {
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%.2f", r);
    return buf;
}

// 可打印率（0~1）：可打印 ASCII（0x20-0x7e）或换行/制表；UTF-8 多字节序列按可打印字符计
double printable_ratio_str(const std::string& s) {
    if (s.empty()) return 0.0;
    size_t total = 0, printable = 0;
    for (size_t i = 0; i < s.size();) {
        const unsigned char c = static_cast<unsigned char>(s[i]);
        if (c < 0x80) {
            ++total;
            if (c == 0x09 || c == 0x0a || c == 0x0d || (c >= 0x20 && c <= 0x7e)) ++printable;
            ++i;
        } else if (i + 1 < s.size() && (c & 0xE0) == 0xC0 &&
                   (static_cast<unsigned char>(s[i + 1]) & 0xC0) == 0x80) {
            ++total; ++printable; i += 2;
        } else if (i + 2 < s.size() && (c & 0xF0) == 0xE0 &&
                   (static_cast<unsigned char>(s[i + 1]) & 0xC0) == 0x80 &&
                   (static_cast<unsigned char>(s[i + 2]) & 0xC0) == 0x80) {
            ++total; ++printable; i += 3;
        } else if (i + 3 < s.size() && (c & 0xF8) == 0xF0 &&
                   (static_cast<unsigned char>(s[i + 1]) & 0xC0) == 0x80 &&
                   (static_cast<unsigned char>(s[i + 2]) & 0xC0) == 0x80 &&
                   (static_cast<unsigned char>(s[i + 3]) & 0xC0) == 0x80) {
            ++total; ++printable; i += 4;
        } else {
            ++total; ++i;  // 非法 UTF-8 字节：不可打印
        }
    }
    return total ? static_cast<double>(printable) / static_cast<double>(total) : 0.0;
}

// 字节级可打印率（XOR 穷举用）：0x20-0x7e 或 \n\r\t
double printable_ratio_bytes(const std::vector<unsigned char>& b) {
    if (b.empty()) return 0.0;
    size_t printable = 0;
    for (const unsigned char c : b)
        if (c == 0x09 || c == 0x0a || c == 0x0d || (c >= 0x20 && c <= 0x7e)) ++printable;
    return static_cast<double>(printable) / static_cast<double>(b.size());
}

// 是否像 UTF-16LE（偶数字节 + 大量 NUL 交错 + 可打印率高）：-EncodedCommand 的形态
bool looks_utf16le(const std::vector<unsigned char>& b) {
    if (b.size() < 4 || b.size() % 2 != 0) return false;
    const size_t chars = b.size() / 2;
    size_t nul_hi = 0, printable = 0;
    for (size_t i = 0; i + 1 < b.size(); i += 2) {
        if (b[i + 1] != 0) continue;
        ++nul_hi;
        const unsigned char lo = b[i];
        if (lo == 0x09 || lo == 0x0a || lo == 0x0d || (lo >= 0x20 && lo <= 0x7e)) ++printable;
    }
    return nul_hi * 4 >= chars * 3 && printable * 2 >= chars;
}

std::string utf16le_to_utf8(const std::vector<unsigned char>& b) {
    if (b.size() < 2 || b.size() % 2 != 0) return "";
    std::wstring w(b.size() / 2, L'\0');
    std::memcpy(&w[0], b.data(), b.size());
    return aiutil::to_utf8(w);
}

int b64_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

// 手工 base64 解码：字母表 A-Za-z0-9+/，= 结尾，忽略空白
bool b64_decode(const std::string& in, std::vector<unsigned char>& out) {
    out.clear();
    std::string clean;
    clean.reserve(in.size());
    for (const char c : in) {
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') continue;
        if (c == '=') break;  // padding
        clean += c;
    }
    if (clean.empty()) return false;
    int buf = 0, bits = 0;
    for (const char c : clean) {
        const int v = b64_val(c);
        if (v < 0) return false;
        buf = (buf << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<unsigned char>((buf >> bits) & 0xFF));
        }
    }
    return !out.empty();
}

int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// 手工 hex 解码：偶数长度十六进制字符，忽略空白
bool hex_decode(const std::string& in, std::vector<unsigned char>& out) {
    out.clear();
    std::string clean;
    clean.reserve(in.size());
    for (const char c : in) {
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') continue;
        clean += c;
    }
    if (clean.empty() || clean.size() % 2 != 0) return false;
    out.reserve(clean.size() / 2);
    for (size_t i = 0; i + 1 < clean.size(); i += 2) {
        const int hi = hex_val(clean[i]), lo = hex_val(clean[i + 1]);
        if (hi < 0 || lo < 0) return false;
        out.push_back(static_cast<unsigned char>((hi << 4) | lo));
    }
    return !out.empty();
}

// key 参数：整数（单字节循环）或字符串（循环 XOR）；缺失返回空 vector
std::vector<unsigned char> parse_xor_key(const json& args, bool& key_error, std::string& kerr) {
    key_error = false;
    if (!args.contains("key")) return {};
    const json& k = args.at("key");
    if (k.is_number_integer()) return { static_cast<unsigned char>(k.get<long long>() & 0xFF) };
    if (k.is_number())
        return { static_cast<unsigned char>(static_cast<long long>(k.get<double>()) & 0xFF) };
    if (k.is_string()) {
        const std::string s = k.get<std::string>();
        if (s.empty()) {
            key_error = true;
            kerr = "key 为空字符串";
            return {};
        }
        return std::vector<unsigned char>(s.begin(), s.end());
    }
    key_error = true;
    kerr = "key 类型不支持（应为整数或字符串）";
    return {};
}

// XOR：key_bytes 非空时用之；否则 0-255 单字节穷举，选可打印率最高的 key
DecodeState decode_xor(const std::string& text, const std::vector<unsigned char>& key_bytes,
                       int limit, json& notes) {
    DecodeState st;
    std::vector<unsigned char> key = key_bytes;
    std::vector<unsigned char> in(text.begin(), text.end());
    if (key.empty()) {
        const size_t eval_n = in.size() < 512 ? in.size() : 512;
        int best_key = 0;
        double best_r = -1.0;
        for (int k = 0; k < 256; ++k) {
            size_t printable = 0;
            for (size_t i = 0; i < eval_n; ++i) {
                const unsigned char c =
                    static_cast<unsigned char>(in[i] ^ static_cast<unsigned char>(k));
                if (c == 0x09 || c == 0x0a || c == 0x0d || (c >= 0x20 && c <= 0x7e)) ++printable;
            }
            const double r =
                eval_n ? static_cast<double>(printable) / static_cast<double>(eval_n) : 0.0;
            if (r > best_r) {
                best_r = r;
                best_key = k;
            }
        }
        key.assign(1, static_cast<unsigned char>(best_key));
        notes.push_back("xor 未提供 key，穷举选中 key=" + std::to_string(best_key)
                        + "（可打印率 " + fmt_ratio(best_r) + "）");
    }
    std::vector<unsigned char> out_b(in.size());
    for (size_t i = 0; i < in.size(); ++i)
        out_b[i] = static_cast<unsigned char>(in[i] ^ key[i % key.size()]);
    const double r = printable_ratio_bytes(out_b);
    notes.push_back("xor 解码可打印率 " + fmt_ratio(r));
    if (r >= 0.7) {
        st.decoded = aiutil::utf8_truncate(std::string(out_b.begin(), out_b.end()), limit);
        st.encoding = "xor";
        st.ratio = r;
        st.ok = true;
    } else {
        notes.push_back("xor 解码结果可打印率过低，视为失败");
    }
    return st;
}

// 解码后的字节 -> 先试 UTF-16LE（-EncodedCommand 形态）再试 UTF-8/ASCII
void accept_decoded_bytes(const std::vector<unsigned char>& b, const std::string& enc_name,
                          int limit, json& notes, DecodeState& st) {
    if (looks_utf16le(b)) {
        const std::string s16 = utf16le_to_utf8(b);
        const double r = printable_ratio_str(s16);
        notes.push_back(enc_name + " 解码检出 UTF-16LE（-EncodedCommand 格式），可打印率 "
                        + fmt_ratio(r));
        if (!s16.empty() && r >= 0.7) {
            st.decoded = aiutil::utf8_truncate(s16, limit);
            st.encoding = enc_name + "_utf16";
            st.ratio = r;
            st.ok = true;
            return;
        }
    }
    const std::string raw(reinterpret_cast<const char*>(b.data()), b.size());
    const double r2 = printable_ratio_str(raw);
    notes.push_back(enc_name + " -> 原始字节可打印率 " + fmt_ratio(r2));
    if (r2 >= 0.7) {
        st.decoded = aiutil::utf8_truncate(raw, limit);
        st.encoding = enc_name;
        st.ratio = r2;
        st.ok = true;
    }
}

// 显式 base64_utf16：base64 -> UTF-16LE，不做 UTF-8 回退
void accept_utf16_only(const std::vector<unsigned char>& b, int limit, json& notes, DecodeState& st) {
    if (!looks_utf16le(b)) {
        notes.push_back("base64 结果不像 UTF-16LE（-EncodedCommand 应为 base64 编码的 UTF-16LE）");
        return;
    }
    const std::string s16 = utf16le_to_utf8(b);
    const double r = printable_ratio_str(s16);
    notes.push_back("UTF-16LE 解读可打印率 " + fmt_ratio(r));
    if (s16.empty() || r < 0.7) {
        notes.push_back("UTF-16LE 解读结果可打印率过低");
        return;
    }
    st.decoded = aiutil::utf8_truncate(s16, limit);
    st.encoding = "base64_utf16";
    st.ratio = r;
    st.ok = true;
}

std::vector<std::string> split_lines(const std::string& s) {
    std::vector<std::string> out;
    std::string cur;
    for (const char c : s) {
        if (c == '\n') {
            out.push_back(cur);
            cur.clear();
        } else if (c != '\r') {
            cur += c;
        }
    }
    out.push_back(cur);
    return out;
}

std::string strip_all_ws(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (const char c : s) {
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') continue;
        out += c;
    }
    return out;
}

// 「连接还原」：解码结果为多行且行都很短时，把所有行拼接（去空白）成一行附在 notes
void append_concat_note(const std::string& decoded, json& notes) {
    const std::vector<std::string> lines = split_lines(decoded);
    if (lines.size() < 2) return;
    std::string joined;
    for (const std::string& l : lines) {
        const std::string stripped = strip_all_ws(l);
        if (stripped.size() > 72) return;  // 存在长行：不是分行内容
        joined += stripped;
    }
    if (joined.empty()) return;
    notes.push_back("concatenated: " + aiutil::utf8_truncate(joined, 500));
}

}  // namespace

namespace aiext {

// ============================================================
// 五、日志与脚本侧
// ============================================================

// {"hours":24,"limit":50,"channel":可选}
// -> {"count","truncated","channel","events":[{time,path,message_number,message_total,script_text}]}
std::string t_get_script_block_log(const nlohmann::json& args, AiContext& /*ctx*/) {
    const double hours = json_num(args, "hours", 24.0);
    const int limit = clamp_int(json_int(args, "limit", 50), 1, 500);
    std::string channel = "Microsoft-Windows-PowerShell/Operational";
    if (args.contains("channel") && args["channel"].is_string()) {
        const std::string c = trim_copy(args["channel"].get<std::string>());
        if (!c.empty()) channel = map_source_to_channel(c);  // 兼容短名（powershell 等）
    }
    std::string err;
    const json out = query_script_block_json(hours, limit, channel, err);
    if (!err.empty()) return make_err(err);
    return aiutil::dump_json(out);
}

// {"limit":20} -> {"count","truncated","transcripts":[{path,size,modified,preview}]}
std::string t_get_powershell_transcript(const nlohmann::json& args, AiContext& /*ctx*/) {
    const int limit = clamp_int(json_int(args, "limit", 20), 1, 200);

    // 候选目录：Documents（注册表 Personal）与 %APPDATA% 各自拼 WindowsPowerShell / PowerShell
    std::vector<std::wstring> dirs;
    std::wstring docs = get_documents_dir();
    if (!docs.empty()) {
        while (!docs.empty() && (docs.back() == L'\\' || docs.back() == L'/')) docs.pop_back();
        dirs.push_back(docs + L"\\WindowsPowerShell");
        dirs.push_back(docs + L"\\PowerShell");
    }
    std::wstring appdata = expand_env(L"%APPDATA%");
    if (!appdata.empty()) {
        while (!appdata.empty() && (appdata.back() == L'\\' || appdata.back() == L'/'))
            appdata.pop_back();
        dirs.push_back(appdata + L"\\WindowsPowerShell");
        dirs.push_back(appdata + L"\\PowerShell");
    }
    std::vector<std::wstring> uniq;
    for (const std::wstring& d : dirs) {
        bool dup = false;
        for (const std::wstring& u : uniq)
            if (wide_ci_equal(u, d)) { dup = true; break; }
        if (!dup) uniq.push_back(d);
    }

    // 递归收集（扫描硬上限防撑爆）
    std::vector<std::wstring> paths;
    const size_t scan_cap = 400;
    for (const std::wstring& d : uniq) {
        if (paths.size() >= scan_cap) break;
        collect_transcript_files(d, "PowerShell_transcript*.txt", paths, scan_cap);
    }
    if (paths.size() > scan_cap) paths.resize(scan_cap);

    // 大小 + 修改时间（GetFileAttributesExW），按修改时间从新到旧
    struct TransFile {
        std::wstring path;
        long long mtime = 0;
        unsigned long long size = 0;
    };
    std::vector<TransFile> files;
    files.reserve(paths.size());
    for (const std::wstring& p : paths) {
        TransFile tf;
        tf.path = p;
        WIN32_FILE_ATTRIBUTE_DATA fad{};
        if (GetFileAttributesExW(p.c_str(), GetFileExInfoStandard, &fad)) {
            tf.mtime = filetime_to_i64(fad.ftLastWriteTime);
            tf.size = (static_cast<unsigned long long>(fad.nFileSizeHigh) << 32)
                    | static_cast<unsigned long long>(fad.nFileSizeLow);
        }
        files.push_back(std::move(tf));
    }
    std::sort(files.begin(), files.end(),
              [](const TransFile& a, const TransFile& b) { return a.mtime > b.mtime; });

    json transcripts = json::array();
    size_t listed = 0;
    for (const TransFile& tf : files) {
        if (listed >= static_cast<size_t>(limit)) break;
        json t;
        t["path"] = aiutil::to_utf8(tf.path);
        t["size"] = tf.size;
        t["modified"] = aiext::iso_from_filetime(tf.mtime);
        t["preview"] = aiutil::utf8_truncate(squeeze_ws(read_preview(tf.path, 400)), 400);
        transcripts.push_back(std::move(t));
        ++listed;
    }
    json out;
    out["count"] = listed;
    out["truncated"] = files.size() > listed;
    out["transcripts"] = std::move(transcripts);
    return aiutil::dump_json(out);
}

/*
 * {"text":"...","encodings":"auto|base64|base64_utf16|hex|xor","key":可选,"limit":4000}
 * -> {"decoded","encoding","printable_ratio","notes":[...]}
 * 还原 -EncodedCommand（base64+UTF-16LE）、hex、单字节/密钥 XOR；gzip 只报告不尝试。
 */
std::string t_decode_script(const nlohmann::json& args, AiContext& /*ctx*/) {
    if (!args.contains("text") || !args["text"].is_string())
        return make_err("缺少 text 参数（要解码的脚本文本）");
    const std::string text = args["text"].get<std::string>();
    if (text.empty()) return make_err("text 为空");

    std::string encodings = "auto";
    if (args.contains("encodings") && args["encodings"].is_string())
        encodings = to_lower(trim_copy(args["encodings"].get<std::string>()));
    if (encodings.empty()) encodings = "auto";
    if (encodings != "auto" && encodings != "base64" && encodings != "base64_utf16" &&
        encodings != "hex" && encodings != "xor")
        return make_err("不支持的 encodings: " + encodings + "（auto|base64|base64_utf16|hex|xor）");

    bool key_error = false;
    std::string kerr;
    const std::vector<unsigned char> key_bytes = parse_xor_key(args, key_error, kerr);
    if (key_error) return make_err(kerr);

    const int limit = clamp_int(json_int(args, "limit", 4000), 1, 12000);

    json notes = json::array();
    DecodeState st;

    // gzip：检测 0x1f 0x8b 开头，只报告不尝试
    if (text.size() >= 2 &&
        static_cast<unsigned char>(text[0]) == 0x1f &&
        static_cast<unsigned char>(text[1]) == 0x8b) {
        notes.push_back("gzip 压缩内容暂不支持解码");
        json out;
        out["decoded"] = aiutil::utf8_truncate(text, limit);
        out["encoding"] = "gzip";
        out["printable_ratio"] = std::round(printable_ratio_str(text) * 100.0) / 100.0;
        out["notes"] = std::move(notes);
        return aiutil::dump_json(out);
    }

    std::vector<unsigned char> bytes;
    // (1)(2) base64 -> UTF-16LE / UTF-8
    if (encodings == "auto" || encodings == "base64" || encodings == "base64_utf16") {
        if (b64_decode(text, bytes)) {
            notes.push_back("base64 解码成功（" + std::to_string(bytes.size()) + " 字节）");
            if (encodings == "base64_utf16") accept_utf16_only(bytes, limit, notes, st);
            else accept_decoded_bytes(bytes, "base64", limit, notes, st);
        } else {
            notes.push_back("base64 解码失败（非法字符或长度不对）");
        }
    }
    // (3) hex -> 同样两步
    if (!st.ok && (encodings == "auto" || encodings == "hex")) {
        if (hex_decode(text, bytes)) {
            notes.push_back("hex 解码成功（" + std::to_string(bytes.size()) + " 字节）");
            accept_decoded_bytes(bytes, "hex", limit, notes, st);
        } else {
            notes.push_back("hex 解码失败（非偶数长度十六进制或非法字符）");
        }
    }
    // (4) xor：给定 key 用之，否则单字节穷举
    if (!st.ok && (encodings == "auto" || encodings == "xor"))
        st = decode_xor(text, key_bytes, limit, notes);

    if (!st.ok) {
        // (5) 都失败：返回原文 + 说明
        st.decoded = aiutil::utf8_truncate(text, limit);
        st.encoding = "none";
        st.ratio = printable_ratio_str(text);
        notes.push_back("未能解码，已返回原文（可尝试 encodings=base64/base64_utf16/hex/xor 或提供 key）");
    } else {
        append_concat_note(st.decoded, notes);
    }

    json out;
    out["decoded"] = st.decoded;
    out["encoding"] = st.encoding;
    out["printable_ratio"] = std::round(st.ratio * 100.0) / 100.0;
    out["notes"] = std::move(notes);
    return aiutil::dump_json(out);
}

// {"source":"sysmon|...","keyword":可选} -> {"subscription":1,"channel":..,"keyword"?,"active":true}
std::string t_subscribe_events(const nlohmann::json& args, AiContext& /*ctx*/) {
    std::string source;
    if (args.contains("source") && args["source"].is_string())
        source = trim_copy(args["source"].get<std::string>());
    if (source.empty())
        return make_err("缺少 source 参数（sysmon/powershell/powershell_core/security/system/"
                        "application/wmi/dns/powershell_operational 或通道名）");
    const std::string channel = map_source_to_channel(source);
    std::string keyword;
    if (args.contains("keyword") && args["keyword"].is_string())
        keyword = args["keyword"].get<std::string>();
    std::string err;
    if (aiext::event_sub_start(channel, keyword, err) != 0)
        return make_err("订阅失败: " + (err.empty() ? "未知原因" : err));
    json out;
    out["subscription"] = 1;
    out["channel"] = channel;
    if (!keyword.empty()) out["keyword"] = keyword;
    out["active"] = aiext::event_sub_active();
    return aiutil::dump_json(out);
}

// {"max":50} -> {"count","events":[...]}（自上次 tail 以来的新事件，紧凑单行文本）
std::string t_tail_events(const nlohmann::json& args, AiContext& /*ctx*/) {
    if (!aiext::event_sub_active())
        return make_err("没有活动订阅，先用 subscribe_events 订阅");
    const int max_n = clamp_int(json_int(args, "max", 50), 1, 100);
    const std::vector<std::string> events = aiext::event_sub_poll(max_n);
    json arr = json::array();
    for (const std::string& e : events) arr.push_back(e);
    json out;
    out["count"] = arr.size();
    out["events"] = std::move(arr);
    return aiutil::dump_json(out);
}

// {} -> {"stopped":bool}（没订阅时 stopped=false）
std::string t_unsubscribe_events(const nlohmann::json& args, AiContext& /*ctx*/) {
    (void)args;
    const bool stopped = aiext::event_sub_stop();
    json out;
    out["stopped"] = stopped;
    return aiutil::dump_json(out);
}

// {"channel":"...","hours":1,"limit":50,"level":可选} -> {"count","truncated","channel","events":[...]}
std::string t_get_etw(const nlohmann::json& args, AiContext& /*ctx*/) {
    std::string channel;
    if (args.contains("channel") && args["channel"].is_string())
        channel = trim_copy(args["channel"].get<std::string>());
    if (channel.empty())
        return make_err("缺少 channel 参数（通道名，或短名 sysmon/powershell/security/system/"
                        "application/wmi/dns）");
    channel = map_source_to_channel(channel);  // 也接受 source 映射表里的短名

    const double hours = json_num(args, "hours", 1.0);
    const int limit = clamp_int(json_int(args, "limit", 50), 1, 500);

    // 可选 XPath：level 给定时按级别过滤
    std::wstring xpath;
    bool has_xpath = false;
    if (args.contains("level")) {
        const int level = json_int(args, "level", 0);
        if (level > 0 && level <= 5) {
            xpath = L"*[System[Level=" + std::to_wstring(level) + L"]]";
            has_xpath = true;
        }
    }

    int max_fetch = limit + 200;
    if (max_fetch > 1000) max_fetch = 1000;
    const ChannelQuery q = query_channel_xml(aiutil::to_wide(channel),
                                             has_xpath ? xpath.c_str() : nullptr, true, max_fetch);
    if (!q.error.empty()) {
        if (q.error_code == ERROR_EVT_CHANNEL_NOT_FOUND)
            return make_err("通道不存在或未启用: " + channel);
        return make_err(q.error + ": " + channel);
    }

    json events = json::array();
    size_t matched = 0;
    bool truncated = false;
    for (const std::string& xml : q.xmls) {
        const std::string time = xml_attr(xml, "TimeCreated", "SystemTime");
        if (!within_hours(time, hours)) continue;
        ++matched;
        if (matched > static_cast<size_t>(limit)) {
            truncated = true;
            break;
        }
        events.push_back(render_compact_event(xml, 600));
    }
    json out;
    out["count"] = events.size();
    out["truncated"] = truncated;
    out["channel"] = channel;
    out["events"] = std::move(events);
    return aiutil::dump_json(out);
}

// {"limit":50} -> {"count","channel","events":[...],"note"?}
std::string t_get_amsi_events(const nlohmann::json& args, AiContext& /*ctx*/) {
    const int limit = clamp_int(json_int(args, "limit", 50), 1, 500);
    const std::string ti_channel = "Microsoft-Windows-Threat-Intelligence/Operational";
    const std::string ps_channel = "Microsoft-Windows-PowerShell/Operational";

    // 先尝试 Threat-Intelligence（AMSI 事件所在；通常需要 PPL/反恶意软件服务）
    const ChannelQuery q = query_channel_xml(aiutil::to_wide(ti_channel), nullptr, true, limit);
    if (q.error.empty() && !q.xmls.empty()) {
        json events = json::array();
        for (const std::string& xml : q.xmls) events.push_back(render_compact_event(xml, 600));
        json out;
        out["count"] = events.size();
        out["channel"] = ti_channel;
        out["events"] = std::move(events);
        return aiutil::dump_json(out);
    }

    // 回退：PowerShell 4104 脚本块日志（hours=24，复用 t_get_script_block_log 的核心）
    const std::string note =
        "AMSI 事件在 Threat-Intelligence 通道，通常需要 PPL/反恶意软件服务才能读，"
        "已回退 PowerShell 4104 脚本块日志";
    std::string err;
    json sb = query_script_block_json(24.0, limit, ps_channel, err);
    if (!err.empty()) {
        json out;
        out["count"] = 0;
        out["channel"] = ti_channel;
        out["events"] = json::array();
        out["note"] = note + "；但 4104 查询也失败: " + err;
        return aiutil::dump_json(out);
    }
    sb["note"] = note;
    return aiutil::dump_json(sb);
}

// {"hours":24,"limit":50,"event_id":可选}
// -> {"count","truncated","events":[{time,eid,user,domain,logon_type,ip,process,detail}]}
std::string t_get_security_log(const nlohmann::json& args, AiContext& /*ctx*/) {
    const double hours = json_num(args, "hours", 24.0);
    const int limit = clamp_int(json_int(args, "limit", 50), 1, 500);

    // 查询：event_id 给定按其过滤，否则默认登录/特权/进程相关事件
    std::wstring xpath;
    bool has_xpath = false;
    if (args.contains("event_id")) {
        long long eid = 0;
        const json& v = args.at("event_id");
        if (v.is_number_integer()) eid = v.get<long long>();
        else if (v.is_number()) eid = static_cast<long long>(v.get<double>());
        else if (v.is_string()) {
            const std::string s = trim_copy(v.get<std::string>());
            if (!s.empty()) {
                char* endp = nullptr;
                eid = std::strtoll(s.c_str(), &endp, 10);
                if (!endp || endp == s.c_str() || *endp != '\0') eid = 0;
            }
        }
        if (eid > 0 && eid <= 65535) {
            xpath = L"*[System[(EventID=" + std::to_wstring(eid) + L")]]";
            has_xpath = true;
        }
    }
    const std::wstring default_xpath =
        L"*[System[(EventID=4624) or (EventID=4625) or (EventID=4672) or (EventID=4688)]]";

    int max_fetch = limit + 200;
    if (max_fetch > 1000) max_fetch = 1000;
    const ChannelQuery q = query_channel_xml(std::wstring(L"Security"),
                                             has_xpath ? xpath.c_str() : default_xpath.c_str(),
                                             true, max_fetch);
    if (!q.error.empty()) {
        if (q.error_code == ERROR_ACCESS_DENIED)
            return make_err("读取 Security 日志需要管理员权限（错误 "
                            + std::to_string(q.error_code) + "）");
        if (q.error_code == ERROR_EVT_CHANNEL_NOT_FOUND)
            return make_err("Security 日志通道不存在或未启用（错误 "
                            + std::to_string(q.error_code) + "）");
        return make_err(q.error + ": Security");
    }

    json events = json::array();
    size_t matched = 0;
    bool truncated = false;
    for (const std::string& xml : q.xmls) {
        const std::string time = xml_attr(xml, "TimeCreated", "SystemTime");
        if (!within_hours(time, hours)) continue;
        ++matched;
        if (matched > static_cast<size_t>(limit)) {
            truncated = true;
            break;
        }

        const std::string eid = xml_inner(xml, "EventID");
        const std::string data = xml_inner(xml, "EventData");
        auto field = [&data](const char* name) -> std::string {
            return xml_unescape(xml_data_value(data, name));
        };

        // 按 EID 取相关字段：4624/4625 登录成功/失败，4672 特权分配，4688 进程创建
        std::string user, domain, logon_type, ip, process, detail;
        if (eid == "4624" || eid == "4625") {
            user = field("TargetUserName");
            domain = field("TargetDomainName");
            logon_type = field("LogonType");
            ip = field("IpAddress");
            process = field("ProcessName");
            const std::string subject_user = field("SubjectUserName");
            const std::string subject_domain = field("SubjectDomainName");
            detail = (eid == "4625") ? "登录失败" : "登录成功";
            if (!subject_user.empty()) {
                std::string who = subject_user;
                if (!subject_domain.empty()) who = subject_domain + "\\" + who;
                detail += "，发起者: " + who;
            }
        } else if (eid == "4672") {
            user = field("SubjectUserName");
            domain = field("SubjectDomainName");
            detail = field("EnabledPrivilegeList");
        } else if (eid == "4688") {
            user = field("SubjectUserName");
            domain = field("SubjectDomainName");
            process = field("NewProcessName");
            if (process.empty()) process = field("ProcessName");
            detail = field("CommandLine");
        } else {
            // 其他 EID（event_id 指定了别的）：尽力取常见字段 + 数据区压缩行
            user = field("TargetUserName");
            if (user.empty()) user = field("SubjectUserName");
            domain = field("TargetDomainName");
            if (domain.empty()) domain = field("SubjectDomainName");
            detail = xml_unescape(squeeze_line(data));
        }
        if (detail.size() > 300) detail = aiutil::utf8_truncate(detail, 300) + "...";

        json ev;
        ev["time"] = time;
        ev["eid"] = number_or_string(eid);
        ev["user"] = user;
        ev["domain"] = domain;
        ev["logon_type"] = number_or_string(logon_type);
        ev["ip"] = ip;
        ev["process"] = process;
        ev["detail"] = detail;
        events.push_back(std::move(ev));
    }
    json out;
    out["count"] = events.size();
    out["truncated"] = truncated;
    out["events"] = std::move(events);
    return aiutil::dump_json(out);
}

}  // namespace aiext
