// ai_session.cpp
#include "ai_session.h"

#include "ai_client.h"
#include "ai_prompts.h"
#include "ai_tools.h"

#include <map>

using nlohmann::json;

namespace {

void add_trace(AiSessionResult& r, std::string kind, std::string name, const std::string& detail) {
    if (r.trace.size() >= 200) return;
    std::string d = detail.size() > 200 ? detail.substr(0, 200) + "..." : detail;
    r.trace.push_back({{"kind", kind}, {"name", name}, {"detail", d}});
}

}  // namespace

AiSessionResult ai_run_session(const json& ai_cfg, const std::string& user_message,
                               AiContext& ctx) {
    AiSessionResult result;
    AIClient client(ai_cfg.value("base_url", ""), ai_cfg.value("api_key", ""),
                    ai_cfg.value("model", ""), ai_cfg.value("timeout", 60));
    int max_rounds = std::max(1, ai_cfg.value("max_rounds", 12));
    ctx.max_tool_result_chars = std::max(1000, ai_cfg.value("max_tool_result_chars", 12000));

    json messages = json::array();
    messages.push_back({{"role", "system"}, {"content", aiprompts::kSystemPrompt}});
    messages.push_back({{"role", "user"}, {"content", user_message}});

    json tools = ai_tool_schemas();
    std::map<std::string, int> call_counts;

    for (int round = 1; round <= max_rounds; ++round) {
        result.rounds = round;
        AIReply reply;
        std::string err;
        if (!client.chat(messages, tools, reply, err)) {
            result.ended_by = "error";
            result.error = err;
            break;
        }

        std::vector<AIToolCall> text_calls;
        std::string stripped;
        parse_text_calls(reply.content, text_calls, stripped);
        bool has_fc = !reply.tool_calls.empty();

        if (reply.tool_calls.empty() && text_calls.empty()) {
            bool has_end = false;
            std::string body = split_end_tag(reply.content, has_end);
            if (has_end) {
                result.ended_by = "end_tag";
                result.final_text = body;
            } else if (!reply.content.empty()) {
                result.ended_by = "final_text";
                result.final_text = reply.content;
            } else {
                messages.push_back({{"role", "assistant"}, {"content", ""}});
                messages.push_back({{"role", "user"},
                                    {"content", "（无内容）请给出最终中文结论，最后一行单独写 END。"}});
                continue;
            }
            break;
        }

        // 落 assistant 消息
        if (has_fc) {
            json am = {{"role", "assistant"}, {"content", reply.content.empty() ? json(nullptr) : json(reply.content)}};
            json tcs = json::array();
            for (const auto& c : reply.tool_calls) {
                tcs.push_back({{"id", c.id},
                               {"type", "function"},
                               {"function", {{"name", c.name}, {"arguments", c.arguments.dump()}}}});
            }
            am["tool_calls"] = tcs;
            messages.push_back(am);
        } else {
            messages.push_back({{"role", "assistant"}, {"content", stripped.empty() ? "（发起工具调用）" : stripped}});
        }

        // 执行
        auto run_one = [&](const AIToolCall& c) {
            ++result.tool_calls;
            std::string sig = c.name + "|" + c.arguments.dump();
            int count = ++call_counts[sig];
            add_trace(result, "tool_call", c.name, c.arguments.dump());
            std::string out;
            if (count > 3) {
                out = "ERROR: 同一调用已重复 3 次均失败，请勿重试；请调整参数或直接给出结论。";
            } else {
                out = ai_execute_tool(c.name, c.arguments, ctx);
            }
            std::string first = out.substr(0, out.find('\n') == std::string::npos ? out.size() : out.find('\n'));
            add_trace(result, "tool_result", c.name, first);
            return out;
        };

        for (const auto& c : reply.tool_calls) {
            std::string out = run_one(c);
            messages.push_back({{"role", "tool"}, {"tool_call_id", c.id}, {"name", c.name}, {"content", out}});
        }
        for (const auto& c : text_calls) {
            std::string out = run_one(c);
            messages.push_back({{"role", "user"},
                                {"content", "TOOL " + c.name + " 结果:\n" + out +
                                                "\n\n（继续分析；证据充分则给出结论并以 END 结束，否则继续调用工具）"}});
        }
    }

    if (result.ended_by == "error" && result.final_text.empty()) {
        result.final_text = "（AI 请求失败: " + result.error + "）";
    }
    // for 循环正常结束且未 break → max_rounds
    if (result.ended_by == "error" && result.error.empty() && result.rounds >= max_rounds) {
        result.ended_by = "max_rounds";
        result.final_text = "（已达到最大轮数 " + std::to_string(max_rounds) + "，会话被截断。）";
    }
    return result;
}
