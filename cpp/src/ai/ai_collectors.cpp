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

const std::map<std::string, std::string>& sources() {
    static const std::map<std::string, std::string> kSources = {
        {"sysmon", "Microsoft-Windows-Sysmon/Operational"},
        {"process", "Microsoft-Windows-Kernel-Process/Operational"},
        {"network", "Microsoft-Windows-Kernel-Network/Operational"},
        {"dns", "Microsoft-Windows-DNS-Client/Operational"},
        {"powershell", "Microsoft-Windows-PowerShell/Operational"},
        {"system", "System"},
        {"application", "Application"},
        {"fileio", "Microsoft-Windows-Kernel-File/Operational"},
    };
    return kSources;
}

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
    std::string key = std::string(attrib) + "=\"";
    auto k = head.find(key);
    if (k == std::string::npos) return "";
    k += key.size();
    auto e = head.find('"', k);
    if (e == std::string::npos) return "";
    return xml_unescape(head.substr(k, e - k));
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

// 收集所有 <Data Name="x">v</Data>
void collect_data(const std::string& xml, std::vector<std::pair<std::string, std::string>>& out) {
    size_t pos = 0;
    const std::string marker = "<Data Name=\"";
    while (true) {
        auto p = xml.find(marker, pos);
        if (p == std::string::npos) break;
        auto name_b = p + marker.size();
        auto name_e = xml.find('"', name_b);
        if (name_e == std::string::npos) break;
        auto gt = xml.find('>', name_e);
        if (gt == std::string::npos) break;
        auto end = xml.find("</Data>", gt);
        if (end == std::string::npos) break;
        std::string name = xml.substr(name_b, name_e - name_b);
        std::string value = xml_unescape(xml.substr(gt + 1, end - gt - 1));
        out.emplace_back(name, value);
        pos = end + 7;
    }
}

std::string shorten(const std::string& s, size_t maxlen) {
    if (s.size() <= maxlen) return s;
    return s.substr(0, maxlen) + "...";
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

}  // namespace

bool ai_is_known_source(const std::string& source) {
    return sources().count(source) > 0;
}

std::string ai_event_channel(const std::string& source) {
    auto it = sources().find(source);
    return it == sources().end() ? "" : it->second;
}

bool ai_events_supported() { return true; }

AiBatch ai_query_batch(const std::vector<std::string>& srcs, int minutes, int max_events,
                       int max_chars) {
    AiBatch batch;
    time_t now = std::time(nullptr);
    std::string since = iso_utc(now - static_cast<time_t>(minutes) * 60);
    std::string xpath = "*[System[TimeCreated[@SystemTime>='" + since + "']]]";

    int per_source = std::max(5, max_events / std::max(1, static_cast<int>(srcs.size())));
    std::vector<std::string> all;
    for (const std::string& s : srcs) {
        std::string channel = ai_event_channel(s);
        if (channel.empty()) continue;
        QueryOutcome q = query_channel(channel, xpath, per_source, true, "");
        if (!q.error.empty()) batch.errors.push_back(q.error);
        batch.stats.emplace_back(s, static_cast<int>(q.lines.size()));
        for (auto& l : q.lines) all.push_back(render_event(l, max_chars));
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
    std::string channel = ai_event_channel(source);
    if (channel.empty()) {
        return {"", "未知事件源: " + source};
    }
    if (hours <= 0) hours = 0.01;
    time_t now = std::time(nullptr);
    std::string since = iso_utc(now - static_cast<time_t>(hours * 3600));
    std::string xpath = "*[System[TimeCreated[@SystemTime>='" + since + "']]]";

    QueryOutcome q = query_channel(channel, xpath, limit, true, keyword);
    std::string text;
    if (q.lines.empty()) {
        text = "（无匹配事件）";
    } else {
        for (size_t i = 0; i < q.lines.size(); ++i) {
            if (i) text += "\n";
            text += q.lines[i];
        }
    }
    return {text, q.error};
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
