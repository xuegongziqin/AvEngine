// ai_service.h - AI 服务层（批次/问答/检出联动/后台定时）
#pragma once

#include <nlohmann/json.hpp>

#include <functional>
#include <string>
#include <vector>

#include "ai_session.h"
#include "ai_tools.h"

struct AiServiceConfig {
    std::string base_url, api_key, model;
    int timeout = 60;
    int max_rounds = 12;
    int interval = 300;
    int max_events_per_batch = 200;
    int max_event_chars = 600;
    int max_tool_result_chars = 12000;
    bool scan_analysis = true;
    std::vector<std::string> batch_sources;
    AiContext ctx;
};

// 会话事件转发函数（见 AiSessionHooks 的事件说明）；传 nullptr 表示不要流式事件
using AiEventFn = std::function<void(const nlohmann::json&)>;

AiServiceConfig ai_parse_config(const nlohmann::json& j);
nlohmann::json ai_session_to_json(const AiSessionResult& r);

nlohmann::json ai_service_run_batch(const AiServiceConfig& cfg, int minutes,
                                    const AiEventFn* on_event = nullptr);
nlohmann::json ai_service_ask(const AiServiceConfig& cfg, const std::string& question,
                              const AiEventFn* on_event = nullptr);
nlohmann::json ai_service_analyze_detection(const AiServiceConfig& cfg,
                                            const nlohmann::json& detection,
                                            const AiEventFn* on_event = nullptr);
nlohmann::json ai_service_test(const AiServiceConfig& cfg);

bool ai_bg_start(const AiServiceConfig& cfg, std::string& err);
void ai_bg_stop();
bool ai_bg_running();
std::string ai_bg_poll(int max_items);
