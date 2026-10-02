// monitor.cpp - 常驻实时监控：Sysmon 订阅 + 按访问/定时扫描 + 自动隔离
#include "monitor.h"

#include "clamd_client.h"
#include "util.h"
#include "yara_engine.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winevt.h>

#include <atomic>
#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <mutex>
#include <thread>
#include <vector>

namespace fs = std::filesystem;

namespace {

struct MonitorState {
    std::mutex mtx;
    std::condition_variable sleep_cv;
    std::mutex sleep_mtx;
    std::vector<std::string> events;
    std::atomic<bool> stop{false};
    std::atomic<bool> running{false};
    std::string error;
    std::atomic<unsigned long long> scanned{0};
    std::atomic<unsigned long long> threats{0};
    std::thread sysmon_thread;
    std::thread timer_thread;
    MonitorConfig cfg;
};

MonitorState g;

std::wstring to_wide(const std::string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), nullptr, 0);
    if (n <= 0) return L"";
    std::wstring w(static_cast<size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), &w[0], n);
    return w;
}

std::string to_utf8(const std::wstring& w) {
    if (w.empty()) return "";
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()),
                                nullptr, 0, nullptr, nullptr);
    if (n <= 0) return "";
    std::string s(static_cast<size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()),
                        &s[0], n, nullptr, nullptr);
    return s;
}

void interruptible_sleep(int ms) {
    std::unique_lock<std::mutex> lk(g.sleep_mtx);
    g.sleep_cv.wait_for(lk, std::chrono::milliseconds(ms), [] { return g.stop.load(); });
}

std::string now_str() {
    char buf[32];
    std::time_t t = std::time(nullptr);
    std::tm tmv{};
    localtime_s(&tmv, &t);
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tmv);
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

bool extract_tag(const std::string& xml, const char* tag, std::string& out) {
    std::string open = std::string("<") + tag + ">";
    auto a = xml.find(open);
    if (a == std::string::npos) return false;
    a += open.size();
    auto b = xml.find(std::string("</") + tag + ">", a);
    if (b == std::string::npos) return false;
    out = xml_unescape(xml.substr(a, b - a));
    return true;
}

bool extract_named_data(const std::string& xml, const char* name, std::string& out) {
    std::string key = std::string("Name=\"") + name + "\"";
    auto a = xml.find(key);
    if (a == std::string::npos) return false;
    auto gt = xml.find('>', a);
    if (gt == std::string::npos) return false;
    auto b = xml.find("</Data>", gt);
    if (b == std::string::npos) return false;
    out = xml_unescape(xml.substr(gt + 1, b - (gt + 1)));
    return true;
}

std::string join_raw_json(const std::vector<std::string>& items) {
    std::string out = "[";
    for (size_t i = 0; i < items.size(); ++i) {
        if (i) out += ",";
        out += items[i];
    }
    out += "]";
    return out;
}

void push_event(const std::string& json) {
    std::lock_guard<std::mutex> lk(g.mtx);
    g.events.push_back(json);
    if (g.events.size() > 1000) {
        g.events.erase(g.events.begin(), g.events.begin() + (g.events.size() - 1000));
    }
}

bool quarantine_move(const std::string& src, const std::string& dir, std::string& out,
                     std::string& err) {
    std::error_code ec;
    fs::create_directories(dir, ec);
    fs::path s(src);
    std::string stem = s.stem().string();
    std::string ext = s.extension().string();

    char ts[32];
    std::time_t t = std::time(nullptr);
    std::tm tmv{};
    localtime_s(&tmv, &t);
    std::strftime(ts, sizeof(ts), "%Y%m%d_%H%M%S", &tmv);

    fs::path dest = fs::path(dir) / (stem + "_" + ts + ext);
    int counter = 1;
    while (fs::exists(dest, ec)) {
        dest = fs::path(dir) / (stem + "_" + ts + "_(" + std::to_string(counter) + ")" + ext);
        ++counter;
    }

    fs::rename(s, dest, ec);
    if (ec) {
        ec.clear();
        fs::copy_file(s, dest, fs::copy_options::overwrite_existing, ec);
        if (ec) {
            err = "移动失败: " + ec.message();
            return false;
        }
        fs::remove(s, ec);
    }
    out = dest.string();
    return true;
}

// 扫描单个文件；命中则隔离并投递事件。返回是否命中。
bool scan_and_handle(const std::string& file, YaraEngine& yara, bool use_clam,
                     const ClamdClient& clam) {
    g.scanned.fetch_add(1);

    std::vector<std::string> matches;
    if (yara.available()) {
        matches = yara.scan_file(file);
    }
    std::string virus;
    if (use_clam) {
        ClamScanResult cr = clam.scan_file(file);
        if (cr.infected) virus = cr.virus;
    }
    if (matches.empty() && virus.empty()) return false;

    std::string action = "detected";
    std::string new_path;
    if (!g.cfg.quarantine_dir.empty()) {
        std::string qerr;
        if (quarantine_move(file, g.cfg.quarantine_dir, new_path, qerr)) {
            action = "quarantined";
        }
    }

    g.threats.fetch_add(1);
    std::string j = "{";
    j += "\"time\":" + json_str(now_str()) + ",";
    j += "\"path\":" + json_str(file) + ",";
    j += "\"yara\":" + join_json_array(matches) + ",";
    j += "\"clamav\":" + (virus.empty() ? std::string("null") : json_str(virus)) + ",";
    j += "\"action\":" + json_str(action);
    if (!new_path.empty()) j += ",\"quarantined_to\":" + json_str(new_path);
    j += "}";
    push_event(j);
    return true;
}

void sysmon_loop() {
    YaraEngine yara(g.cfg.rules_path);
    bool use_clam = !g.cfg.clam_host.empty() && g.cfg.clam_port > 0;
    ClamdClient clam(g.cfg.clam_host, g.cfg.clam_port, g.cfg.clam_timeout);
    std::wstring channel = to_wide(g.cfg.channel);
    const wchar_t* query = L"*[System[(EventID=2) or (EventID=11)]]";

    unsigned long long last_id = 0;
    std::vector<wchar_t> buf(1 << 16);

    while (!g.stop.load()) {
        EVT_HANDLE h = EvtQuery(nullptr, channel.c_str(), query,
                                EvtQueryChannelPath | EvtQueryReverseDirection);
        if (!h) {
            std::lock_guard<std::mutex> lk(g.mtx);
            g.error = "EvtQuery 失败（通道可能未启用或权限不足），错误码 " +
                      std::to_string(GetLastError());
            interruptible_sleep(1000);
            continue;
        }

        EVT_HANDLE ev = nullptr;
        DWORD returned = 0;
        if (EvtNext(h, 1, &ev, 100, 0, &returned) && returned == 1 && ev) {
            DWORD used = 0, props = 0;
            BOOL ok = EvtRender(nullptr, ev, EvtRenderEventXml,
                                static_cast<DWORD>(buf.size() * sizeof(wchar_t)),
                                buf.data(), &used, &props);
            if (!ok && GetLastError() == ERROR_INSUFFICIENT_BUFFER && used > 0) {
                buf.resize(used / sizeof(wchar_t) + 1);
                ok = EvtRender(nullptr, ev, EvtRenderEventXml,
                               static_cast<DWORD>(buf.size() * sizeof(wchar_t)),
                               buf.data(), &used, &props);
            }
            if (ok) {
                std::string xml = to_utf8(std::wstring(buf.data()));
                std::string rid_s, target;
                unsigned long long rid = 0;
                if (extract_tag(xml, "EventRecordID", rid_s)) {
                    rid = std::strtoull(rid_s.c_str(), nullptr, 10);
                }
                if (rid > last_id) {
                    last_id = rid;
                    if (extract_named_data(xml, "TargetFilename", target) && !target.empty()) {
                        std::error_code ec;
                        if (fs::is_regular_file(target, ec)) {
                            scan_and_handle(target, yara, use_clam, clam);
                        }
                    }
                }
            }
            EvtClose(ev);
        }
        EvtClose(h);
        interruptible_sleep(500);
    }
}

void timer_loop() {
    YaraEngine yara(g.cfg.rules_path);
    bool use_clam = !g.cfg.clam_host.empty() && g.cfg.clam_port > 0;
    ClamdClient clam(g.cfg.clam_host, g.cfg.clam_port, g.cfg.clam_timeout);
    int interval = g.cfg.timer_interval > 0 ? g.cfg.timer_interval : 3600;

    while (!g.stop.load()) {
        interruptible_sleep(interval * 1000);
        if (g.stop.load()) break;

        for (const std::string& dir : g.cfg.monitor_paths) {
            if (g.stop.load()) break;
            std::error_code ec;
            if (!fs::is_directory(dir, ec)) continue;
            for (auto it = fs::recursive_directory_iterator(dir, ec);
                 it != fs::recursive_directory_iterator(); it.increment(ec)) {
                if (ec || g.stop.load()) break;
                if (!it->is_regular_file(ec)) continue;
                scan_and_handle(it->path().string(), yara, use_clam, clam);
            }
        }
    }
}

}  // namespace

namespace monitor {

bool start(const MonitorConfig& cfg, std::string& err) {
    stop();

    {
        std::lock_guard<std::mutex> lk(g.mtx);
        g.cfg = cfg;
        g.events.clear();
        g.error.clear();
    }
    g.scanned.store(0);
    g.threats.store(0);
    g.stop.store(false);

    bool do_sysmon = cfg.on_access;
    bool do_timer = cfg.timer_interval > 0 && !cfg.monitor_paths.empty();
    if (!do_sysmon && !do_timer) {
        err = "未启用任何监控（on_access=false 且无定时扫描）";
        return false;
    }

    g.running.store(true);
    if (do_sysmon) g.sysmon_thread = std::thread(sysmon_loop);
    if (do_timer) g.timer_thread = std::thread(timer_loop);
    return true;
}

void stop() {
    g.stop.store(true);
    g.sleep_cv.notify_all();
    if (g.sysmon_thread.joinable()) g.sysmon_thread.join();
    if (g.timer_thread.joinable()) g.timer_thread.join();
    g.running.store(false);
}

bool running() {
    return g.running.load() &&
           ((g.sysmon_thread.joinable()) || (g.timer_thread.joinable()));
}

std::string poll(int max_items) {
    if (max_items < 1) max_items = 1;
    std::vector<std::string> items;
    {
        std::lock_guard<std::mutex> lk(g.mtx);
        size_t n = std::min(static_cast<size_t>(max_items), g.events.size());
        items.assign(g.events.begin(), g.events.begin() + n);
        g.events.erase(g.events.begin(), g.events.begin() + n);
    }
    return join_raw_json(items);
}

std::string status() {
    bool run;
    std::string err;
    {
        std::lock_guard<std::mutex> lk(g.mtx);
        err = g.error;
    }
    run = running();
    std::string j = "{";
    j += "\"running\":" + std::string(run ? "true" : "false") + ",";
    j += "\"error\":" + (err.empty() ? std::string("null") : json_str(err)) + ",";
    j += "\"scanned\":" + std::to_string(g.scanned.load()) + ",";
    j += "\"threats\":" + std::to_string(g.threats.load());
    j += "}";
    return j;
}

}  // namespace monitor
