// ai_tools_ext.cpp - AI 工具扩展库：共享基础设施
// （审计日志 / dry-run 判断 / 子进程输出捕获 / 熵 / 时间格式 / 事件订阅槽）
#include "ai_tools_ext.h"

#include "ai_util.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <deque>
#include <map>
#include <mutex>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winevt.h>

// advapi32 / bcrypt / wevtapi / winhttp 等由 CMake 链接（不放 #pragma comment，
// MinGW 会告警 unknown pragma）

namespace fs = std::filesystem;

using nlohmann::json;

namespace {

std::string to_lower(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

// 缓冲区 SHA256（BCrypt），用于审计哈希链
std::string sha256_hex_buffer(const unsigned char* data, size_t len) {
    BCRYPT_ALG_HANDLE ah = nullptr;
    if (BCryptOpenAlgorithmProvider(&ah, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0 || !ah)
        return "";
    BCRYPT_HASH_HANDLE hh = nullptr;
    if (BCryptCreateHash(ah, &hh, nullptr, 0, nullptr, 0, 0) != 0) {
        BCryptCloseAlgorithmProvider(ah, 0);
        return "";
    }
    BCryptHashData(hh, const_cast<PUCHAR>(data), static_cast<ULONG>(len), 0);
    unsigned char digest[32];
    std::string out;
    if (BCryptFinishHash(hh, digest, sizeof(digest), 0) == 0) {
        static const char* hexd = "0123456789abcdef";
        out.reserve(64);
        for (unsigned char b : digest) {
            out += hexd[b >> 4];
            out += hexd[b & 0xF];
        }
    }
    BCryptDestroyHash(hh);
    BCryptCloseAlgorithmProvider(ah, 0);
    return out;
}

std::string sha256_hex(const std::string& s) {
    return sha256_hex_buffer(reinterpret_cast<const unsigned char*>(s.data()), s.size());
}

// 读审计日志最后一条记录的 hash=（哈希链头）
std::string read_last_hash(const std::string& path) {
    HANDLE h = CreateFileW(aiutil::to_wide_sys(path).c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return "";
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(h, &size)) { CloseHandle(h); return ""; }
    const long long want = 64 * 1024;
    long long off = (size.QuadPart > want) ? size.QuadPart - want : 0;
    LARGE_INTEGER li{};
    li.QuadPart = off;
    SetFilePointerEx(h, li, nullptr, FILE_BEGIN);
    std::string tail;
    tail.resize(static_cast<size_t>(size.QuadPart - off));
    DWORD got = 0;
    if (ReadFile(h, &tail[0], static_cast<DWORD>(tail.size()), &got, nullptr)) tail.resize(got);
    else tail.clear();
    CloseHandle(h);

    size_t pos = tail.rfind("hash=");
    if (pos == std::string::npos) return "";
    size_t start = pos + 5;
    size_t end = start;
    while (end < tail.size() && std::isxdigit(static_cast<unsigned char>(tail[end]))) ++end;
    return tail.substr(start, end - start);
}

// ---------------- 简易 XML 字段提取（渲染订阅事件用） ----------------

std::string xml_attr(const std::string& xml, const std::string& tag, const std::string& attr) {
    std::string needle = "<" + tag;
    size_t p = xml.find(needle);
    while (p != std::string::npos) {
        size_t gt = xml.find('>', p);
        if (gt == std::string::npos) break;
        std::string open = xml.substr(p, gt - p);
        size_t a = open.find(attr + "=\"");
        if (a != std::string::npos) {
            size_t vstart = a + attr.size() + 2;
            size_t vend = open.find('"', vstart);
            if (vend != std::string::npos) return open.substr(vstart, vend - vstart);
        }
        p = xml.find(needle, gt);
    }
    return "";
}

std::string xml_inner(const std::string& xml, const std::string& tag) {
    std::string open = "<" + tag;
    size_t p = xml.find(open);
    if (p == std::string::npos) return "";
    size_t gt = xml.find('>', p);
    if (gt == std::string::npos) return "";
    size_t end = xml.find("</" + tag + ">", gt);
    if (end == std::string::npos) return "";
    return xml.substr(gt + 1, end - gt - 1);
}

std::string xml_unescape(std::string s) {
    // 注意：实体名用字符常量拼接，避免被写入管线里的 HTML 解码破坏
    const std::string lt(1, '<'), gt(1, '>'), amp(1, '&');
    const std::pair<std::string, std::string> ents[] = {
        { std::string(1, '&') + "lt;",   lt  },
        { std::string(1, '&') + "gt;",   gt  },
        { std::string(1, '&') + "quot;", "\"" },
        { std::string(1, '&') + "amp;",  amp },   // amp 最后替换，避免二次解转义
    };
    for (const auto& e : ents) {
        size_t p;
        while ((p = s.find(e.first)) != std::string::npos)
            s.replace(p, e.first.size(), e.second);
    }
    return s;
}

// ---------------- 事件订阅（单槽位） ----------------

struct SubState {
    std::mutex mtx;
    std::vector<std::string> lines;
    EVT_HANDLE handle = nullptr;
    std::string channel;
    std::string keyword;
    bool active = false;
};

SubState g_sub;

std::string render_sub_event(EVT_HANDLE event) {
    DWORD used = 0, props = 0;
    if (!EvtRender(nullptr, event, EvtRenderEventXml, 0, nullptr, &used, &props) &&
        GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        return "";
    std::vector<wchar_t> buf(used / sizeof(wchar_t) + 1);
    if (!EvtRender(nullptr, event, EvtRenderEventXml, used, buf.data(), &used, &props))
        return "";
    std::string xml = aiutil::to_utf8(std::wstring(buf.data()));
    std::string time = xml_attr(xml, "TimeCreated", "SystemTime");
    std::string eid = xml_inner(xml, "EventID");
    std::string rid = xml_inner(xml, "EventRecordID");
    std::string level = xml_inner(xml, "Level");
    // 数据区压缩成一行（去标签）
    std::string data = xml_inner(xml, "EventData");
    std::string compact;
    if (!data.empty()) {
        for (size_t i = 0; i < data.size(); ++i) {
            char c = data[i];
            if (c == '<' || c == '>' || c == '\n' || c == '\r' || c == '\t') compact += ' ';
            else compact += c;
        }
        std::string out;
        for (size_t i = 0; i < compact.size(); ++i) {
            if (compact[i] == ' ' && !out.empty() && out.back() == ' ') continue;
            out += compact[i];
        }
        compact = out;
        if (compact.size() > 600) compact = compact.substr(0, 600) + "...";
    }
    std::string line = "time=" + time + " eid=" + eid + " rid=" + rid + " level=" + level;
    if (!compact.empty()) line += " | " + compact;
    return line;
}

DWORD WINAPI sub_callback(EVT_SUBSCRIBE_NOTIFY_ACTION action, PVOID pctx, EVT_HANDLE event) {
    if (action != EvtSubscribeActionDeliver || !event) return ERROR_SUCCESS;
    auto* s = static_cast<SubState*>(pctx);
    if (!s) return ERROR_SUCCESS;
    std::string line = render_sub_event(event);
    if (line.empty()) return ERROR_SUCCESS;
    {
        // keyword 过滤（局部拷贝，避免持锁调函数）
        std::string kw;
        {
            std::lock_guard<std::mutex> lk(s->mtx);
            kw = s->keyword;
        }
        if (!kw.empty() && to_lower(line).find(to_lower(kw)) == std::string::npos)
            return ERROR_SUCCESS;
    }
    std::lock_guard<std::mutex> lk(s->mtx);
    s->lines.push_back(line);
    if (s->lines.size() > 2000) s->lines.erase(s->lines.begin(), s->lines.begin() + 500);
    return ERROR_SUCCESS;
}

}  // namespace

namespace aiext {

bool dry_run_requested(const nlohmann::json& args, AiContext& ctx) {
    if (args.contains("dry_run")) {
        if (args["dry_run"].is_boolean()) return args["dry_run"].get<bool>();
        if (args["dry_run"].is_string()) {
            std::string v = to_lower(args["dry_run"].get<std::string>());
            return v == "true" || v == "1" || v == "yes";
        }
        return false;
    }
    return ctx.dry_run;
}

void audit_log(AiContext& ctx, const std::string& tool, const nlohmann::json& args,
               const std::string& outcome) {
    std::string path = ctx.audit_log_file;
    if (path.empty()) {
        std::string lf = ctx.log_file;
        size_t slash = lf.find_last_of("\\/");
        if (lf.empty() || slash == std::string::npos) return;  // 无处可写，静默
        path = lf.substr(0, slash + 1) + "ai_audit.log";
    }

    std::string prev = read_last_hash(path);
    std::string args_json = aiutil::dump_json(args);
    std::string payload = tool + "|" + args_json + "|" + outcome;
    std::string hash = sha256_hex(prev + payload);

    std::string line = now_iso() + " | " + tool + " | " + args_json + " | " + outcome
                       + " | prev=" + (prev.empty() ? "GENESIS" : prev) + " hash=" + hash + "\n";

    HANDLE h = CreateFileW(aiutil::to_wide_sys(path).c_str(), FILE_APPEND_DATA,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    DWORD written = 0;
    WriteFile(h, line.data(), static_cast<DWORD>(line.size()), &written, nullptr);
    CloseHandle(h);
}

std::string run_capture(const std::string& cmd_utf8, int timeout_ms, size_t max_chars) {
    std::wstring cmd = aiutil::to_wide(cmd_utf8);
    if (cmd.empty()) return "ERROR: 命令为空";

    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    HANDLE out_r = nullptr, out_w = nullptr;
    if (!CreatePipe(&out_r, &out_w, &sa, 0)) return "ERROR: CreatePipe 失败";
    SetHandleInformation(out_r, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = out_w;
    si.hStdError = out_w;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

    // CreateProcessW 会改动命令行缓冲，传可写副本
    std::vector<wchar_t> cmdline(cmd.begin(), cmd.end());
    cmdline.push_back(L'\0');

    // 显式给一个一定存在的工作目录：继承父进程 CWD 时，如果父进程的当前目录已被
    // 删除（临时目录被清理等），schtasks/netsh 会报「系统找不到指定的路径」。
    wchar_t cwd[MAX_PATH]{};
    UINT cwd_len = GetSystemDirectoryW(cwd, MAX_PATH);

    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(nullptr, cmdline.data(), nullptr, nullptr, TRUE,
                        CREATE_NO_WINDOW, nullptr, cwd_len ? cwd : nullptr, &si, &pi)) {
        CloseHandle(out_r); CloseHandle(out_w);
        return "ERROR: CreateProcessW 失败（错误 " + std::to_string(GetLastError()) + "）";
    }
    CloseHandle(out_w);   // 写端必须关，否则读不到 EOF

    std::string raw;
    DWORD wait_result = WaitForSingleObject(pi.hProcess, timeout_ms > 0 ? timeout_ms : 30000);
    if (wait_result == WAIT_TIMEOUT) {
        TerminateProcess(pi.hProcess, 1);
        raw = "ERROR: 命令超时（已终止）";
    } else {
        // 把管道剩余数据读干净
        char buf[4096];
        DWORD got = 0;
        while (ReadFile(out_r, buf, sizeof(buf), &got, nullptr) && got > 0) raw.append(buf, got);
    }
    CloseHandle(out_r);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    // 子进程输出编码不固定：新版控制台程序（以及把控制台代码页设成 UTF-8 的系统）
    // 会直接写 UTF-8，老工具写 OEM 代码页。先按 UTF-8 严格校验，失败再按 OEM 转，
    // 最后兜底 ACP——统一假定 OEM 会把中文变成乱码。
    auto decode_with = [](const std::string& bytes, UINT cp) -> std::string {
        if (bytes.empty()) return std::string();
        int n = MultiByteToWideChar(cp, MB_ERR_INVALID_CHARS, bytes.data(),
                                    static_cast<int>(bytes.size()), nullptr, 0);
        if (n <= 0) return std::string();
        std::wstring w(static_cast<size_t>(n), L'\0');
        MultiByteToWideChar(cp, MB_ERR_INVALID_CHARS, bytes.data(),
                            static_cast<int>(bytes.size()), &w[0], n);
        return aiutil::to_utf8(w);
    };

    std::string text;
    bool ascii_only = true;
    for (unsigned char c : raw) {
        if (c >= 0x80) { ascii_only = false; break; }
    }
    if (ascii_only) {
        text = raw;
    } else {
        text = decode_with(raw, CP_UTF8);
        if (text.empty()) text = decode_with(raw, GetOEMCP());
        if (text.empty()) text = decode_with(raw, GetACP());
        if (text.empty()) text = raw;   // 实在无法解码就原样返回
    }
    if (text.size() > max_chars) text = aiutil::utf8_truncate(text, max_chars) + "\n...[输出被截断]";
    return text;
}

std::string now_iso() {
    SYSTEMTIME st{};
    GetLocalTime(&st);
    char buf[40];
    std::snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d", st.wYear, st.wMonth, st.wDay,
                  st.wHour, st.wMinute, st.wSecond);
    return buf;
}

std::string iso_from_filetime(long long ft64) {
    if (ft64 <= 0) return "";
    FILETIME ft{};
    ft.dwHighDateTime = static_cast<DWORD>((static_cast<unsigned long long>(ft64) >> 32) & 0xFFFFFFFFULL);
    ft.dwLowDateTime = static_cast<DWORD>(static_cast<unsigned long long>(ft64) & 0xFFFFFFFFULL);
    FILETIME local{};
    if (!FileTimeToLocalFileTime(&ft, &local)) return "";
    SYSTEMTIME st{};
    if (!FileTimeToSystemTime(&local, &st)) return "";
    char buf[40];
    std::snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d", st.wYear, st.wMonth, st.wDay,
                  st.wHour, st.wMinute, st.wSecond);
    return buf;
}

std::string sha256_buffer(const unsigned char* data, size_t len) {
    return sha256_hex_buffer(data, len);
}

double shannon_entropy(const unsigned char* data, size_t len) {
    if (!data || len == 0) return 0.0;
    unsigned bins[256] = {};
    for (size_t i = 0; i < len; ++i) bins[data[i]]++;
    double e = 0.0;
    for (int i = 0; i < 256; ++i) {
        if (bins[i] == 0) continue;
        double p = static_cast<double>(bins[i]) / static_cast<double>(len);
        e -= p * std::log2(p);
    }
    return e;
}

std::vector<unsigned char> read_file_bytes(const std::string& path_utf8, size_t max_bytes,
                                           std::string& err) {
    HANDLE h = CreateFileW(aiutil::to_wide_sys(path_utf8).c_str(), GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        err = "无法打开文件（错误 " + std::to_string(GetLastError()) + "）: " + path_utf8;
        return {};
    }
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(h, &size)) {
        err = "无法获取文件大小: " + path_utf8;
        CloseHandle(h);
        return {};
    }
    size_t want = static_cast<size_t>(size.QuadPart < 0 ? 0 : size.QuadPart);
    if (want > max_bytes) want = max_bytes;
    std::vector<unsigned char> data(want);
    DWORD got = 0, total = 0;
    while (total < want) {
        if (!ReadFile(h, data.data() + total, static_cast<DWORD>(want - total), &got, nullptr) || got == 0)
            break;
        total += got;
    }
    CloseHandle(h);
    data.resize(total);
    return data;
}

// ---------------- 事件订阅 ----------------

int event_sub_start(const std::string& channel_utf8, const std::string& keyword, std::string& err) {
    event_sub_stop();
    if (channel_utf8.empty()) {
        err = "channel 为空";
        return -1;
    }
    {
        std::lock_guard<std::mutex> lk(g_sub.mtx);
        g_sub.keyword = keyword;
    }
    std::wstring wch = aiutil::to_wide(channel_utf8);
    EVT_HANDLE handle = EvtSubscribe(nullptr, nullptr, wch.c_str(), nullptr, nullptr, &g_sub,
                                     sub_callback, EvtSubscribeToFutureEvents);
    if (!handle) {
        DWORD e = GetLastError();
        err = "EvtSubscribe 失败（错误 " + std::to_string(e) + "）：通道不存在或权限不足";
        return -1;
    }
    std::lock_guard<std::mutex> lk(g_sub.mtx);
    g_sub.handle = handle;
    g_sub.channel = channel_utf8;
    g_sub.active = true;
    return 0;
}

std::vector<std::string> event_sub_poll(int max_items) {
    std::lock_guard<std::mutex> lk(g_sub.mtx);
    int n = std::max(max_items, 1);
    size_t take = std::min(static_cast<size_t>(n), g_sub.lines.size());
    std::vector<std::string> out(g_sub.lines.begin(), g_sub.lines.begin() + static_cast<long>(take));
    g_sub.lines.erase(g_sub.lines.begin(), g_sub.lines.begin() + static_cast<long>(take));
    return out;
}

bool event_sub_stop() {
    EVT_HANDLE handle = nullptr;
    {
        std::lock_guard<std::mutex> lk(g_sub.mtx);
        handle = g_sub.handle;
        g_sub.handle = nullptr;
        g_sub.active = false;
        g_sub.lines.clear();
    }
    if (handle) {
        EvtClose(handle);   // 关闭订阅句柄即停止订阅
        return true;
    }
    return false;
}

bool event_sub_active() {
    std::lock_guard<std::mutex> lk(g_sub.mtx);
    return g_sub.active;
}

}  // namespace aiext
