// ai_collectors.cpp - 用 wevtapi 按需查询事件
#include "ai_collectors.h"

#include "ai_util.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winevt.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <ctime>
#include <map>
#include <sstream>

using aiutil::to_wide;
using aiutil::to_utf8;

namespace {

// 事件源表已由下面的 source_chain() 统一维护（含回退链）

std::string iso_utc(time_t t) {
    std::tm tmv{};
    gmtime_s(&tmv, &t);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tmv);
    return buf;
}

std::string xml_unescape(const std::string& in) {
    std::string out;
    out.reserve(in.size());
    for (size_t i = 0; i < in.size();) {
        if (in.compare(i, 5, "&amp;") == 0) { out += '&'; i += 5; }
        else if (in.compare(i, 4, "&lt;") == 0) { out += '<'; i += 4; }
        else if (in.compare(i, 4, "&gt;") == 0) { out += '>'; i += 4; }
        else if (in.compare(i, 6, "&quot;") == 0) { out += '"'; i += 6; }
        else if (in.compare(i, 6, "&apos;") == 0) { out += '\''; i += 6; }
        else { out += in[i++]; }
    }
    return out;
}

std::string attr(const std::string& xml, const char* tag, const char* attrib) {
    std::string open = std::string("<") + tag;
    auto a = xml.find(open);
    if (a == std::string::npos) return "";
    auto close = xml.find('>', a);
    if (close == std::string::npos) return "";
    std::string head = xml.substr(a, close - a);
    // 事件 XML 的属性可能是双引号，也可能是单引号（EvtRender 实际输出用单引号：
    // <TimeCreated SystemTime='2026-...'/>、<Data Name='Image'>），两种都要认，
    // 否则时间戳和 Sysmon 的字段名会全部丢成空。
    const char quotes[2] = {'"', '\''};
    for (char q : quotes) {
        std::string key = std::string(attrib) + "=" + q;
        auto k = head.find(key);
        if (k == std::string::npos) continue;
        k += key.size();
        auto e = head.find(q, k);
        if (e == std::string::npos) continue;
        return xml_unescape(head.substr(k, e - k));
    }
    return "";
}

std::string inner_tag(const std::string& xml, const char* tag) {
    std::string open = std::string("<") + tag + ">";
    auto a = xml.find(open);
    if (a == std::string::npos) return "";
    a += open.size();
    auto b = xml.find(std::string("</") + tag + ">", a);
    if (b == std::string::npos) return "";
    return xml_unescape(xml.substr(a, b - a));
}

// 收集所有 <Data Name="x">v</Data>（属性引号单双兼容；没有 Name 的按 Data1/Data2 编号）
void collect_data(const std::string& xml, std::vector<std::pair<std::string, std::string>>& out) {
    size_t pos = 0;
    int unnamed = 0;
    while (true) {
        auto p = xml.find("<Data", pos);
        if (p == std::string::npos) break;
        auto gt = xml.find('>', p);
        if (gt == std::string::npos) break;
        if (gt > p && xml[gt - 1] == '/') {   // <Data/> 自闭合，跳过
            pos = gt + 1;
            continue;
        }
        auto end = xml.find("</Data>", gt);
        if (end == std::string::npos) break;
        std::string head = xml.substr(p, gt - p + 1);
        std::string name = attr(head, "Data", "Name");
        std::string value = xml_unescape(xml.substr(gt + 1, end - gt - 1));
        if (name.empty()) {
            if (value.empty()) { pos = end + 7; continue; }
            name = "Data" + std::to_string(++unnamed);
        }
        out.emplace_back(name, value);
        pos = end + 7;
    }
}

std::string shorten(const std::string& s, size_t maxlen) {
    if (s.size() <= maxlen) return s;
    // 按字符边界截断：GBK/UTF-8 文本按字节切会劈开汉字，回传给模型的 JSON 会变成非法 UTF-8
    return aiutil::utf8_truncate(s, maxlen) + "...";
}

// 把一条事件 XML 渲染为紧凑单行
std::string render_event(const std::string& xml, int max_chars) {
    std::string time = attr(xml, "TimeCreated", "SystemTime");
    std::string eid = inner_tag(xml, "EventID");
    std::string rid = inner_tag(xml, "EventRecordID");
    // 时间取后半段 HH:MM:SS
    std::string clock = time;
    auto tpos = time.find('T');
    if (tpos != std::string::npos && time.size() >= tpos + 9) clock = time.substr(tpos + 1, 8);

    std::string line = "[" + clock + "] rid=" + rid + " EID=" + eid;
    std::vector<std::pair<std::string, std::string>> data;
    collect_data(xml, data);
    for (auto& kv : data) {
        if (kv.second.empty()) continue;
        line += " " + kv.first + "=" + shorten(kv.second, 200);
    }
    return shorten(line, static_cast<size_t>(max_chars > 40 ? max_chars : 40));
}

bool icontains(const std::string& hay, const std::string& needle) {
    if (needle.empty()) return true;
    std::string h = hay, n = needle;
    std::transform(h.begin(), h.end(), h.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    std::transform(n.begin(), n.end(), n.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return h.find(n) != std::string::npos;
}

struct QueryOutcome {
    std::vector<std::string> lines;  // 渲染后的事件行（按时间正序）
    std::string error;
};

QueryOutcome query_channel(const std::string& channel, const std::string& xpath, int limit,
                           bool reverse, const std::string& keyword) {
    QueryOutcome out;
    std::wstring wch = to_wide(channel);
    std::wstring wq = to_wide(xpath);
    DWORD flags = EvtQueryChannelPath | (reverse ? EvtQueryReverseDirection : 0);
    EVT_HANDLE h = EvtQuery(nullptr, wch.c_str(), wq.c_str(), flags);
    if (!h) {
        DWORD e = GetLastError();
        if (e == ERROR_EVT_CHANNEL_NOT_FOUND) {
            out.error = "通道未找到: " + channel;
        } else if (e == ERROR_ACCESS_DENIED) {
            out.error = "访问被拒绝（需管理员）: " + channel;
        } else {
            out.error = "EvtQuery 失败（错误 " + std::to_string(e) + "）: " + channel;
        }
        return out;
    }

    std::vector<wchar_t> buf(1 << 16);
    std::vector<EVT_HANDLE> events(64);
    while (static_cast<int>(out.lines.size()) < limit) {
        DWORD returned = 0;
        if (!EvtNext(h, static_cast<DWORD>(events.size()), events.data(), 100, 0, &returned) ||
            returned == 0) {
            break;
        }
        for (DWORD i = 0; i < returned; ++i) {
            DWORD used = 0, props = 0;
            BOOL ok = EvtRender(nullptr, events[i], EvtRenderEventXml,
                                static_cast<DWORD>(buf.size() * sizeof(wchar_t)), buf.data(),
                                &used, &props);
            if (!ok && GetLastError() == ERROR_INSUFFICIENT_BUFFER && used > 0) {
                buf.resize(used / sizeof(wchar_t) + 1);
                ok = EvtRender(nullptr, events[i], EvtRenderEventXml,
                               static_cast<DWORD>(buf.size() * sizeof(wchar_t)), buf.data(),
                               &used, &props);
            }
            if (ok) {
                std::string xml = to_utf8(std::wstring(buf.data()));
                std::string line = render_event(xml, 0);
                if (icontains(line, keyword)) out.lines.push_back(line);
            }
            EvtClose(events[i]);
        }
    }
    EvtClose(h);
    if (reverse) std::reverse(out.lines.begin(), out.lines.end());
    return out;
}

struct ChannelCandidate {
    const char* channel;
    int event_id;  // >0 时在 XPath 里加 EventID 过滤（回退到 Sysmon 时用）
};

/*
 * 事件源 -> 通道候选链（按顺序尝试）。
 *
 * Win7 上根本没有 Microsoft-Windows-Kernel-Process/Network/File 这些内核通道
 * （它们是 Win8+ 的），所以老系统上直接用主通道只会得到「通道未找到」。项目本身
 * 会安装 Sysmon，因此回退到 Sysmon 的对应事件 ID；process 还能再退到安全日志
 * 4688（需先开启审核策略）。
 */
const std::vector<ChannelCandidate>* source_chain(const std::string& source) {
    static const std::map<std::string, std::vector<ChannelCandidate>> kChains = {
        {"sysmon", {{"Microsoft-Windows-Sysmon/Operational", 0}}},
        {"process",
         {{"Microsoft-Windows-Kernel-Process/Operational", 0},
          {"Microsoft-Windows-Sysmon/Operational", 1},
          {"Security", 4688}}},
        {"network",
         {{"Microsoft-Windows-Kernel-Network/Operational", 0},
          {"Microsoft-Windows-Sysmon/Operational", 3}}},
        {"dns",
         {{"Microsoft-Windows-DNS-Client/Operational", 0},
          {"Microsoft-Windows-Sysmon/Operational", 22}}},
        {"fileio",
         {{"Microsoft-Windows-Kernel-File/Operational", 0},
          {"Microsoft-Windows-Sysmon/Operational", 11}}},
        {"powershell", {{"Microsoft-Windows-PowerShell/Operational", 0}}},
        {"system", {{"System", 0}}},
        {"application", {{"Application", 0}}},
    };
    auto it = kChains.find(source);
    return it == kChains.end() ? nullptr : &it->second;
}

std::string build_xpath(const std::string& since, int event_id) {
    if (event_id > 0)
        return "*[System[(EventID=" + std::to_string(event_id) +
               ") and TimeCreated[@SystemTime>='" + since + "']]]";
    return "*[System[TimeCreated[@SystemTime>='" + since + "']]]";
}

struct ChainOutcome {
    QueryOutcome outcome;
    std::string channel_used;
    bool fallback = false;
    std::vector<std::string> tried;  // 每个候选的结果摘要（诊断用）
};

ChainOutcome query_source(const std::string& source, const std::string& since, int limit,
                          bool reverse, const std::string& keyword) {
    ChainOutcome res;
    const std::vector<ChannelCandidate>* chain = source_chain(source);
    if (!chain || chain->empty()) {
        res.outcome.error = "未知事件源: " + source;
        return res;
    }
    for (size_t i = 0; i < chain->size(); ++i) {
        const ChannelCandidate& c = (*chain)[i];
        std::string label = c.channel;
        if (c.event_id > 0) label += " EventID=" + std::to_string(c.event_id);

        QueryOutcome q = query_channel(c.channel, build_xpath(since, c.event_id), limit, reverse,
                                       keyword);
        if (!q.error.empty()) {
            res.tried.push_back(label + " -> " + q.error);
            continue;
        }
        if (q.lines.empty() && i + 1 < chain->size()) {
            res.tried.push_back(label + " -> 窗口内无事件");
            continue;   // 主通道没数据时，也值得看一眼 Sysmon
        }
        res.outcome = q;
        res.channel_used = label;
        res.fallback = (i > 0);
        return res;
    }
    std::string joined;
    for (size_t i = 0; i < res.tried.size(); ++i) {
        if (i) joined += "；";
        joined += res.tried[i];
    }
    res.outcome.error = "候选通道都不可用: " + joined;
    return res;
}

std::string enable_hint(const std::string& source) {
    const std::vector<ChannelCandidate>* chain = source_chain(source);
    if (!chain || chain->empty()) return "";
    std::string primary = chain->front().channel;
    if (source == "process" || source == "network" || source == "fileio" || source == "dns")
        return "\n（Windows 7 没有该内核通道；可用管理员执行 wevtutil sl \"" + primary +
               "\" /e:true 尝试启用，或安装/启动 Sysmon 后重试——本工具会自动回退到 Sysmon 事件）";
    if (source == "sysmon")
        return "\n（Sysmon 通道不可用：确认 Sysmon 已安装并运行，sc query SysmonDrv）";
    return "";
}

}  // namespace

bool ai_is_known_source(const std::string& source) { return source_chain(source) != nullptr; }

std::string ai_event_channel(const std::string& source) {
    const std::vector<ChannelCandidate>* chain = source_chain(source);
    return (chain && !chain->empty()) ? std::string(chain->front().channel) : std::string();
}

bool ai_events_supported() { return true; }

AiBatch ai_query_batch(const std::vector<std::string>& srcs, int minutes, int max_events,
                       int max_chars) {
    AiBatch batch;
    time_t now = std::time(nullptr);
    std::string since = iso_utc(now - static_cast<time_t>(minutes) * 60);

    int per_source = std::max(5, max_events / std::max(1, static_cast<int>(srcs.size())));
    std::vector<std::string> all;
    for (const std::string& s : srcs) {
        if (!ai_is_known_source(s)) continue;
        ChainOutcome cr = query_source(s, since, per_source, true, "");
        if (!cr.outcome.error.empty()) {
            batch.errors.push_back(cr.outcome.error);
            batch.stats.emplace_back(s, 0);
            continue;
        }
        batch.stats.emplace_back(s + (cr.fallback ? "(" + cr.channel_used + ")" : ""),
                                 static_cast<int>(cr.outcome.lines.size()));
        for (auto& l : cr.outcome.lines) all.push_back(render_event(l, max_chars));
    }
    if (static_cast<int>(all.size()) > max_events) {
        batch.truncated = static_cast<int>(all.size()) - max_events;
        all.erase(all.begin(), all.begin() + batch.truncated);
    }
    if (all.empty()) {
        batch.text = "（窗口内没有采集到事件）";
    } else {
        std::string joined;
        for (size_t i = 0; i < all.size(); ++i) {
            if (i) joined += "\n";
            joined += all[i];
        }
        batch.text = joined;
    }
    return batch;
}

std::pair<std::string, std::string> ai_query_tool(const std::string& source, double hours,
                                                  int limit, const std::string& keyword) {
    if (!ai_is_known_source(source)) {
        return {"", "未知事件源: " + source};
    }
    if (hours <= 0) hours = 0.01;
    time_t now = std::time(nullptr);
    std::string since = iso_utc(now - static_cast<time_t>(hours * 3600));

    ChainOutcome cr = query_source(source, since, limit, true, keyword);
    if (!cr.outcome.error.empty()) {
        return {"", cr.outcome.error + enable_hint(source)};
    }

    std::string text;
    if (cr.fallback)
        text = "（主通道不可用，已回退到 " + cr.channel_used + "）\n";
    if (cr.outcome.lines.empty()) {
        text += "（无匹配事件）";
        if (!cr.tried.empty()) {
            text += "\n尝试过的通道: ";
            for (size_t i = 0; i < cr.tried.size(); ++i) {
                if (i) text += "；";
                text += cr.tried[i];
            }
        }
    } else {
        for (size_t i = 0; i < cr.outcome.lines.size(); ++i) {
            if (i) text += "\n";
            text += cr.outcome.lines[i];
        }
    }
    return {text, ""};
}

std::string ai_get_event_xml(const std::string& source, long long record_id, std::string& err) {
    err.clear();
    std::string channel = ai_event_channel(source);
    if (channel.empty()) {
        err = "未知事件源: " + source;
        return "";
    }
    std::wstring wch = to_wide(channel);
    std::wstring xpath = to_wide("*[System[EventRecordID=" + std::to_string(record_id) + "]]");
    EVT_HANDLE h = EvtQuery(nullptr, wch.c_str(), xpath.c_str(), EvtQueryChannelPath);
    if (!h) {
        err = "EvtQuery 失败: " + channel;
        return "";
    }
    EVT_HANDLE ev = nullptr;
    DWORD returned = 0;
    std::string result;
    if (EvtNext(h, 1, &ev, 200, 0, &returned) && returned == 1 && ev) {
        std::vector<wchar_t> buf(1 << 16);
        DWORD used = 0, props = 0;
        BOOL ok = EvtRender(nullptr, ev, EvtRenderEventXml,
                            static_cast<DWORD>(buf.size() * sizeof(wchar_t)), buf.data(), &used,
                            &props);
        if (!ok && GetLastError() == ERROR_INSUFFICIENT_BUFFER && used > 0) {
            buf.resize(used / sizeof(wchar_t) + 1);
            ok = EvtRender(nullptr, ev, EvtRenderEventXml,
                           static_cast<DWORD>(buf.size() * sizeof(wchar_t)), buf.data(), &used,
                           &props);
        }
        if (ok) result = to_utf8(std::wstring(buf.data()));
        EvtClose(ev);
    } else {
        err = "不存在 EventRecordID=" + std::to_string(record_id);
    }
    EvtClose(h);
    return result;
}
