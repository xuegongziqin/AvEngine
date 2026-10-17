// ai_service.cpp
#include "ai_service.h"

#include "ai_client.h"
#include "ai_collectors.h"
#include "ai_prompts.h"
#include "ai_util.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <thread>

using nlohmann::json;

namespace {

json session_cfg(const AiServiceConfig& cfg) {
    return json{{"base_url", cfg.base_url},
                {"api_key", cfg.api_key},
                {"model", cfg.model},
                {"timeout", cfg.timeout},
                {"max_rounds", cfg.max_rounds},
                {"max_tool_result_chars", cfg.max_tool_result_chars}};
}

json run_with_message(const AiServiceConfig& cfg, const std::string& message,
                      const AiEventFn* on_event, const char* mode) {
    AiContext ctx = cfg.ctx;  // 每会话独立（拷贝）
    AiSessionHooks hooks;
    if (on_event) {
        hooks.on_event = *on_event;
        // 先告诉 UI 这次是什么任务，便于显示标题
        hooks.on_event({{"kind", "session_info"}, {"mode", mode ? mode : ""}});
    }
    AiSessionResult r = ai_run_session(session_cfg(cfg), message, ctx, on_event ? &hooks : nullptr);
    return ai_session_to_json(r);
}

// ---- 后台线程 ----
struct BgState {
    std::mutex mtx;
    std::condition_variable cv;
    std::mutex sleep_mtx;
    std::vector<std::string> results;  // JSON 字符串
    std::atomic<bool> stop{false};
    std::atomic<bool> running{false};
    std::string error;
    AiServiceConfig cfg;
    std::thread thread;
};

BgState g_bg;

void bg_loop() {
    while (!g_bg.stop.load()) {
        try {
            json result = ai_service_run_batch(g_bg.cfg, std::max(1, g_bg.cfg.interval / 60));
            std::lock_guard<std::mutex> lk(g_bg.mtx);
            g_bg.results.push_back(aiutil::dump_json(result));
            if (g_bg.results.size() > 100) g_bg.results.erase(g_bg.results.begin());
        } catch (const std::exception& e) {
            std::lock_guard<std::mutex> lk(g_bg.mtx);
            g_bg.error = e.what();
        }
        std::unique_lock<std::mutex> lk(g_bg.sleep_mtx);
        g_bg.cv.wait_for(lk, std::chrono::seconds(std::max(60, g_bg.cfg.interval)),
                         [] { return g_bg.stop.load(); });
    }
}

}  // namespace

AiServiceConfig ai_parse_config(const json& j) {
    AiServiceConfig cfg;
    cfg.base_url = j.value("base_url", "");
    cfg.api_key = j.value("api_key", "");
    cfg.model = j.value("model", "");
    cfg.timeout = j.value("timeout", 60);
    cfg.max_rounds = j.value("max_rounds", 12);
    cfg.interval = j.value("interval", 300);
    cfg.max_events_per_batch = j.value("max_events_per_batch", 200);
    cfg.max_event_chars = j.value("max_event_chars", 600);
    cfg.max_tool_result_chars = j.value("max_tool_result_chars", 12000);
    cfg.scan_analysis = j.value("scan_analysis", true);
    if (j.contains("batch_sources") && j["batch_sources"].is_array()) {
        for (const auto& s : j["batch_sources"]) cfg.batch_sources.push_back(s.get<std::string>());
    }
    cfg.ctx.rules_path = j.value("rules_path", "");
    cfg.ctx.quarantine_dir = j.value("quarantine_dir", "");
    cfg.ctx.clam_host = j.value("clam_host", "");
    cfg.ctx.clam_port = j.value("clam_port", 0);
    cfg.ctx.clam_timeout = j.value("clam_timeout", 30);
    cfg.ctx.log_file = j.value("log_file", "");
    cfg.ctx.dump_dir = j.value("dump_dir", "");
    cfg.ctx.project_root = j.value("project_root", "");
    cfg.ctx.max_tool_result_chars = cfg.max_tool_result_chars;
    cfg.ctx.dry_run = j.value("dry_run", false);
    cfg.ctx.audit_log_file = j.value("audit_log_file", "");
    if (cfg.ctx.audit_log_file.empty() && !cfg.ctx.log_file.empty()) {
        // 默认放在引擎日志同目录：logs\ai_audit.log
        size_t slash = cfg.ctx.log_file.find_last_of("\\/");
        if (slash != std::string::npos)
            cfg.ctx.audit_log_file = cfg.ctx.log_file.substr(0, slash + 1) + "ai_audit.log";
    }
    return cfg;
}

json ai_session_to_json(const AiSessionResult& r) {
    return json{{"ended_by", r.ended_by},
                {"final_text", r.final_text},
                {"error", r.error},
                {"rounds", r.rounds},
                {"tool_calls", r.tool_calls},
                {"ok", r.ended_by == "end_tag" || r.ended_by == "final_text"},
                {"trace", r.trace}};
}

json ai_service_run_batch(const AiServiceConfig& cfg, int minutes, const AiEventFn* on_event) {
    AiBatch batch = ai_query_batch(cfg.batch_sources, minutes, cfg.max_events_per_batch,
                                   cfg.max_event_chars);
    std::string message = aiprompts::build_batch_message(batch.text, batch.stats, batch.truncated,
                                                         batch.errors, minutes);
    json result = run_with_message(cfg, message, on_event, "batch");
    result["kind"] = "batch";
    result["minutes"] = minutes;
    return result;
}

json ai_service_ask(const AiServiceConfig& cfg, const std::string& question,
                    const AiEventFn* on_event) {
    std::string message = aiprompts::build_ask_context("Sysmon/事件采集可用") + "\n\n用户问题: " + question;
    json result = run_with_message(cfg, message, on_event, "ask");
    result["kind"] = "ask";
    return result;
}

json ai_service_analyze_detection(const AiServiceConfig& cfg, const json& detection,
                                  const AiEventFn* on_event) {
    std::string path = detection.value("path", "");
    std::string engine = detection.value("engine", "");
    std::string match = detection.value("match", "");
    std::string action = detection.value("action", "");
    int total = detection.value("total", 0);
    std::string message = aiprompts::build_detection_message(path, engine, match, action, total);
    json result = run_with_message(cfg, message, on_event, "detection");
    result["kind"] = "detection";
    return result;
}

json ai_service_test(const AiServiceConfig& cfg) {
    AIClient client(cfg.base_url, cfg.api_key, cfg.model, cfg.timeout);
    std::string detail;
    bool ok = client.test_connection(detail);
    return json{{"ok", ok}, {"detail", detail}};
}

bool ai_bg_start(const AiServiceConfig& cfg, std::string& err) {
    ai_bg_stop();
    if (cfg.base_url.empty() || cfg.model.empty()) {
        err = "AI 未配置（缺少 base_url 或 model）";
        return false;
    }
    g_bg.cfg = cfg;
    g_bg.stop.store(false);
    {
        std::lock_guard<std::mutex> lk(g_bg.mtx);
        g_bg.results.clear();
        g_bg.error.clear();
    }
    g_bg.running.store(true);
    g_bg.thread = std::thread(bg_loop);
    return true;
}

void ai_bg_stop() {
    g_bg.stop.store(true);
    g_bg.cv.notify_all();
    if (g_bg.thread.joinable()) g_bg.thread.join();
    g_bg.running.store(false);
}

bool ai_bg_running() { return g_bg.running.load(); }

std::string ai_bg_poll(int max_items) {
    if (max_items < 1) max_items = 1;
    std::vector<std::string> items;
    {
        std::lock_guard<std::mutex> lk(g_bg.mtx);
        size_t n = std::min(static_cast<size_t>(max_items), g_bg.results.size());
        items.assign(g_bg.results.begin(), g_bg.results.begin() + n);
        g_bg.results.erase(g_bg.results.begin(), g_bg.results.begin() + n);
    }
    std::string out = "[";
    for (size_t i = 0; i < items.size(); ++i) {
        if (i) out += ",";
        out += items[i];
    }
    out += "]";
    return out;
}
