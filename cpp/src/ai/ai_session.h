// ai_session.h - AI 多轮工具调用会话
#pragma once

#include <nlohmann/json.hpp>

#include <functional>
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

/*
 * 会话事件钩子：会话每推进一步就同步回调一次（与调用线程相同），
 * 供 CLI 做「思考过程 / 工具调用 / 工具结果 / 正文」的流式显示。
 *
 * 事件 kind 一览（都带 kind 字段，UTF-8 JSON 对象）：
 *   session_start {model,max_rounds}          round_start {round}
 *   thinking      {text,round}                 content {text,round}
 *   tool_call     {name,args,round}            tool_result {name,detail,ok,ms,round}
 *   round_end     {round,tool_calls,ms}        note {text,round}
 *   error         {message}                    final {text,ended_by}
 *   done          {ended_by,rounds,tool_calls,final_text,ok}
 */
struct AiSessionHooks {
    std::function<void(const nlohmann::json&)> on_event;
};

// ai_cfg: {"base_url","api_key","model","timeout","max_rounds"}
AiSessionResult ai_run_session(const nlohmann::json& ai_cfg, const std::string& user_message,
                               AiContext& ctx, const AiSessionHooks* hooks = nullptr);
