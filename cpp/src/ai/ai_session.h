// ai_session.h - AI 多轮工具调用会话
#pragma once

#include <nlohmann/json.hpp>

#include <string>

struct AiContext;  // ai_tools.h

struct AiSessionResult {
    std::string ended_by = "error";  // end_tag | final_text | max_rounds | error
    std::string final_text;
    std::string error;
    int rounds = 0;
    int tool_calls = 0;
    nlohmann::json trace = nlohmann::json::array();
};

// ai_cfg: {"base_url","api_key","model","timeout","max_rounds"}
AiSessionResult ai_run_session(const nlohmann::json& ai_cfg, const std::string& user_message,
                               AiContext& ctx);
