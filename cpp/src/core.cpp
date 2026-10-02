// core.cpp - AvEngine C++ 内核：C ABI 导出实现
#include "avengine_core.h"

#include "clamd_client.h"
#include "monitor.h"
#include "sha256.h"
#include "util.h"
#include "yara_engine.h"

#include "ai_service.h"
#include <nlohmann/json.hpp>

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <string>
#include <utility>
#include <vector>

namespace fs = std::filesystem;

namespace {

const char* kVersion = "0.1.0";

thread_local std::string g_last_error;

void set_error(const std::string& msg) { g_last_error = msg; }
void clear_error() { g_last_error.clear(); }

char* dup_out(const std::string& s) {
    char* p = static_cast<char*>(std::malloc(s.size() + 1));
    if (!p) return nullptr;
    std::memcpy(p, s.data(), s.size());
    p[s.size()] = '\0';
    return p;
}

std::string safe(const char* s) { return s ? std::string(s) : std::string(); }

bool clam_enabled(const char* host, int port) {
    return host && host[0] != '\0' && port > 0;
}

std::vector<std::string> split_semicolon(const char* s) {
    std::vector<std::string> out;
    if (!s || !*s) return out;
    std::string cur;
    for (const char* p = s; ; ++p) {
        if (*p == ';' || *p == '\0') {
            if (!cur.empty()) out.push_back(cur);
            cur.clear();
            if (*p == '\0') break;
        } else {
            cur += *p;
        }
    }
    return out;
}

}  // namespace

extern "C" {

AVC_API const char* avc_version(void) { return kVersion; }

AVC_API const char* avc_last_error(void) { return g_last_error.c_str(); }

AVC_API void avc_free(char* p) { std::free(p); }

AVC_API char* avc_sha256(const char* path) {
    clear_error();
    if (!path || !*path) { set_error("path 为空"); return nullptr; }
    std::string err;
    std::string hash = sha256_file(path, err);
    if (hash.empty()) { set_error(err.empty() ? "计算哈希失败" : err); return nullptr; }
    std::string j = "{\"path\":" + json_str(path) + ",\"sha256\":" + json_str(hash) + "}";
    return dup_out(j);
}

AVC_API char* avc_scan_path(const char* path, const char* rules_path, const char* clam_host,
                            int clam_port, int clam_timeout) {
    clear_error();
    if (!path || !*path) { set_error("path 为空"); return nullptr; }

    std::error_code ec;
    fs::path p(path);
    if (!fs::is_regular_file(p, ec)) {
        set_error("文件不存在: " + std::string(path));
        return nullptr;
    }
    uintmax_t size = fs::file_size(p, ec);

    std::string hash_err;
    std::string hash = sha256_file(path, hash_err);

    // YARA
    YaraEngine yara(safe(rules_path));
    std::vector<std::string> matches;
    if (yara.available()) {
        matches = yara.scan_file(path);
    }

    // ClamAV
    bool clam_avail = false;
    std::string virus;
    if (clam_enabled(clam_host, clam_port)) {
        ClamdClient clam(clam_host, clam_port, clam_timeout);
        ClamScanResult cr = clam.scan_file(path);
        clam_avail = cr.error.empty();
        virus = cr.virus;
    }

    bool infected = !matches.empty() || !virus.empty();
    std::string j = "{";
    j += "\"path\":" + json_str(path) + ",";
    j += "\"size\":" + std::to_string(static_cast<unsigned long long>(size)) + ",";
    j += "\"sha256\":" + (hash.empty() ? std::string("null") : json_str(hash)) + ",";
    j += "\"yara\":{\"available\":" + std::string(yara.available() ? "true" : "false") +
         ",\"rules_count\":" + std::to_string(yara.rules_count()) +
         ",\"matches\":" + join_json_array(matches) + "},";
    j += "\"clamav\":{\"available\":" + std::string(clam_avail ? "true" : "false") +
         ",\"virus\":" + (virus.empty() ? std::string("null") : json_str(virus)) + "},";
    j += "\"verdict\":" + json_str(infected ? "infected" : "clean") + "}";
    return dup_out(j);
}

AVC_API char* avc_scan_dir(const char* dir, const char* rules_path, const char* clam_host,
                           int clam_port, int clam_timeout) {
    clear_error();
    if (!dir || !*dir) { set_error("dir 为空"); return nullptr; }

    std::error_code ec;
    fs::path root(dir);
    if (!fs::is_directory(root, ec)) {
        set_error("目录不存在: " + std::string(dir));
        return nullptr;
    }

    YaraEngine yara(safe(rules_path));
    bool use_clam = clam_enabled(clam_host, clam_port);

    unsigned long long scanned = 0;
    std::vector<std::pair<std::string, std::vector<std::string>>> yara_hits;
    std::vector<std::pair<std::string, std::string>> clam_hits;
    std::vector<std::string> infected;

    for (auto it = fs::recursive_directory_iterator(root, ec);
         it != fs::recursive_directory_iterator(); it.increment(ec)) {
        if (ec) break;
        if (!it->is_regular_file(ec)) continue;
        std::string file = it->path().string();
        ++scanned;

        bool hit = false;
        if (yara.available()) {
            std::vector<std::string> m = yara.scan_file(file);
            if (!m.empty()) {
                yara_hits.emplace_back(file, m);
                hit = true;
            }
        }
        if (use_clam) {
            ClamdClient clam(clam_host, clam_port, clam_timeout);
            ClamScanResult cr = clam.scan_file(file);
            if (cr.infected) {
                clam_hits.emplace_back(file, cr.virus);
                hit = true;
            }
        }
        if (hit) infected.push_back(file);
    }

    std::string j = "{\"scanned\":" + std::to_string(scanned) + ",";
    j += "\"infected\":" + join_json_array(infected) + ",";
    j += "\"yara\":{";
    for (size_t i = 0; i < yara_hits.size(); ++i) {
        if (i) j += ",";
        j += json_str(yara_hits[i].first) + ":" + join_json_array(yara_hits[i].second);
    }
    j += "},\"clamav\":{";
    for (size_t i = 0; i < clam_hits.size(); ++i) {
        if (i) j += ",";
        j += json_str(clam_hits[i].first) + ":" + json_str(clam_hits[i].second);
    }
    j += "}}";
    return dup_out(j);
}

AVC_API char* avc_clam_version(const char* host, int port, int timeout) {
    clear_error();
    if (!clam_enabled(host, port)) { set_error("ClamAV 未配置"); return nullptr; }
    ClamdClient clam(host, port, timeout);
    std::string v = clam.version();
    bool avail = !v.empty();
    std::string j = "{\"available\":" + std::string(avail ? "true" : "false") +
                    ",\"version\":" + (v.empty() ? std::string("null") : json_str(v)) +
                    ",\"error\":" + (avail ? std::string("null") : json_str("clamd 不可达")) + "}";
    return dup_out(j);
}

AVC_API char* avc_clam_reload(const char* host, int port, int timeout) {
    clear_error();
    if (!clam_enabled(host, port)) { set_error("ClamAV 未配置"); return nullptr; }
    ClamdClient clam(host, port, timeout);
    bool ok = clam.reload();
    std::string j = "{\"ok\":" + std::string(ok ? "true" : "false") +
                    ",\"error\":" + (ok ? std::string("null") : json_str("reload 失败")) + "}";
    return dup_out(j);
}

AVC_API char* avc_engine_status(const char* rules_path, const char* clam_host, int clam_port,
                                int clam_timeout) {
    clear_error();
    YaraEngine yara(safe(rules_path));
    bool clam_avail = false;
    std::string clam_ver;
    if (clam_enabled(clam_host, clam_port)) {
        ClamdClient clam(safe(clam_host), clam_port, clam_timeout);
        clam_ver = clam.version();
        clam_avail = !clam_ver.empty();
    }
    nlohmann::json j;
    j["yara"] = {{"available", yara.available()},
                 {"rules_count", yara.rules_count()},
                 {"skipped", yara.skipped_count()}};
    j["clamav"] = {{"available", clam_avail},
                   {"version", clam_ver.empty() ? nlohmann::json(nullptr) : nlohmann::json(clam_ver)}};
    return dup_out(j.dump());
}

AVC_API int avc_monitor_start(const char* rules_path, const char* quar_dir, const char* clam_host,
                              int clam_port, int clam_timeout, const char* channel,
                              const char* monitor_paths, int timer_interval, int on_access) {
    clear_error();
    MonitorConfig cfg;
    cfg.rules_path = safe(rules_path);
    cfg.quarantine_dir = safe(quar_dir);
    cfg.clam_host = safe(clam_host);
    cfg.clam_port = clam_port;
    cfg.clam_timeout = clam_timeout > 0 ? clam_timeout : 30;
    cfg.channel = (channel && *channel) ? std::string(channel)
                                        : std::string("Microsoft-Windows-Sysmon/Operational");
    cfg.monitor_paths = split_semicolon(monitor_paths);
    cfg.timer_interval = timer_interval;
    cfg.on_access = on_access != 0;

    std::string err;
    if (!monitor::start(cfg, err)) {
        set_error(err);
        return -1;
    }
    return 0;
}

AVC_API void avc_monitor_stop(void) { monitor::stop(); }

AVC_API int avc_monitor_running(void) { return monitor::running() ? 1 : 0; }

AVC_API char* avc_monitor_poll(int max_items) {
    clear_error();
    return dup_out(monitor::poll(max_items));
}

AVC_API char* avc_monitor_status(void) {
    clear_error();
    return dup_out(monitor::status());
}

// -------------------- AI --------------------

AVC_API char* avc_ai_test(const char* config_json) {
    clear_error();
    try {
        nlohmann::json j = nlohmann::json::parse(config_json ? config_json : "{}");
        return dup_out(ai_service_test(ai_parse_config(j)).dump());
    } catch (const std::exception& e) {
        set_error(e.what());
        return nullptr;
    }
}

AVC_API char* avc_ai_run_batch(const char* config_json, int minutes) {
    clear_error();
    try {
        nlohmann::json j = nlohmann::json::parse(config_json ? config_json : "{}");
        AiServiceConfig cfg = ai_parse_config(j);
        if (minutes <= 0) minutes = std::max(1, cfg.interval / 60);
        return dup_out(ai_service_run_batch(cfg, minutes).dump());
    } catch (const std::exception& e) {
        set_error(e.what());
        return nullptr;
    }
}

AVC_API char* avc_ai_ask(const char* config_json, const char* question) {
    clear_error();
    try {
        nlohmann::json j = nlohmann::json::parse(config_json ? config_json : "{}");
        return dup_out(ai_service_ask(ai_parse_config(j), safe(question)).dump());
    } catch (const std::exception& e) {
        set_error(e.what());
        return nullptr;
    }
}

AVC_API char* avc_ai_analyze_detection(const char* config_json, const char* detection_json) {
    clear_error();
    try {
        nlohmann::json cfgj = nlohmann::json::parse(config_json ? config_json : "{}");
        nlohmann::json det = nlohmann::json::parse(detection_json ? detection_json : "{}");
        return dup_out(ai_service_analyze_detection(ai_parse_config(cfgj), det).dump());
    } catch (const std::exception& e) {
        set_error(e.what());
        return nullptr;
    }
}

AVC_API int avc_ai_start_background(const char* config_json) {
    clear_error();
    try {
        nlohmann::json j = nlohmann::json::parse(config_json ? config_json : "{}");
        std::string err;
        if (!ai_bg_start(ai_parse_config(j), err)) {
            set_error(err);
            return -1;
        }
        return 0;
    } catch (const std::exception& e) {
        set_error(e.what());
        return -1;
    }
}

AVC_API void avc_ai_stop_background(void) { ai_bg_stop(); }

AVC_API int avc_ai_background_running(void) { return ai_bg_running() ? 1 : 0; }

AVC_API char* avc_ai_poll(int max_items) {
    clear_error();
    return dup_out(ai_bg_poll(max_items));
}

}  // extern "C"
