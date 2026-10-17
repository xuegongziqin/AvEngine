// ai_session.cpp
#include "ai_session.h"

#include "ai_client.h"
#include "ai_prompts.h"
#include "ai_tools.h"
#include "ai_util.h"

#include <chrono>
#include <map>

using nlohmann::json;

namespace {

void add_trace(AiSessionResult& r, std::string kind, std::string name, const std::string& detail) {
    if (r.trace.size() >= 200) return;
    // 按字符边界截断：按字节切会把汉字劈成半个，dump 成 JSON 时直接抛 type_error.316
    std::string d = detail.size() > 200 ? aiutil::utf8_truncate(detail, 200) + "..." : detail;
    r.trace.push_back({{"kind", kind}, {"name", name}, {"detail", d}});
}

long long now_ms() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

std::string first_line(const std::string& text, size_t limit = 200) {
    size_t nl = text.find('\n');
    std::string line = (nl == std::string::npos) ? text : text.substr(0, nl);
    if (line.size() > limit) line = aiutil::utf8_truncate(line, limit) + "...";
    return line;
}

}  // namespace

AiSessionResult ai_run_session(const json& ai_cfg, const std::string& user_message,
                               AiContext& ctx, const AiSessionHooks* hooks) {
    AiSessionResult result;
    AIClient client(ai_cfg.value("base_url", ""), ai_cfg.value("api_key", ""),
                    ai_cfg.value("model", ""), ai_cfg.value("timeout", 60));
    int max_rounds = std::max(1, ai_cfg.value("max_rounds", 12));
    ctx.max_tool_result_chars = std::max(1000, ai_cfg.value("max_tool_result_chars", 12000));

    // 事件回调：任何异常都不能影响会话本身
    //
    // 连续的小 delta 必须**合并后**再回调（见下面的 emit_delta）。
    // 原因：Python 侧每收到一次回调都要抢一次 GIL；真实长回答会产生几千个 chunk，
    // 不合并时 GUI 主线程有一半时间在等 GIL —— 实测 3000 个 chunk 下界面最长卡 5 秒，
    // 用户看到的正是"AI 一跑（阻塞型）工具 GUI 就卡死"。合并后回调次数降 1~2 个数量级，
    // 而 40ms 的刷新节奏让流式观感不变。
    const size_t kFlushChars = 320;
    const long long kFlushMs = 40;
    std::string sbuf_text;
    std::string sbuf_kind;
    int sbuf_round = 0;
    long long sbuf_since = 0;

    auto emit_raw = [&](json event) {
        if (!hooks || !hooks->on_event) return;
        try {
            hooks->on_event(event);
        } catch (...) {
        }
    };
    auto flush_stream = [&]() {
        if (sbuf_text.empty()) return;
        json ev = {{"kind", sbuf_kind}, {"text", sbuf_text}, {"round", sbuf_round}};
        sbuf_text.clear();
        sbuf_since = 0;
        emit_raw(std::move(ev));
    };
    // 非流式事件：先落地已缓冲的正文，保证事件顺序与内容完整
    auto emit = [&](json event) {
        flush_stream();
        emit_raw(std::move(event));
    };
    auto emit_delta = [&](const char* kind, const std::string& delta, int round) {
        if (delta.empty()) return;
        if (!sbuf_text.empty() && (sbuf_kind != kind || sbuf_round != round)) flush_stream();
        sbuf_kind = kind;
        sbuf_round = round;
        sbuf_text += delta;
        const long long now = now_ms();
        if (sbuf_since == 0) sbuf_since = now;
        // 攒够一定量、或到了一个刷新间隔、或出现换行（让"逐行出现"的观感保留）就发出
        if (sbuf_text.size() >= kFlushChars || now - sbuf_since >= kFlushMs ||
            sbuf_text.find('\n') != std::string::npos) {
            flush_stream();
        }
    };

    emit({{"kind", "session_start"},
          {"model", ai_cfg.value("model", "")},
          {"max_rounds", max_rounds}});

    json messages = json::array();
    messages.push_back({{"role", "system"}, {"content", aiprompts::kSystemPrompt}});
    messages.push_back({{"role", "user"}, {"content", user_message}});

    json tools = ai_tool_schemas();
    std::map<std::string, int> call_counts;
    bool reasoning_seen = false;

    for (int round = 1; round <= max_rounds; ++round) {
        result.rounds = round;
        long long round_started = now_ms();
        emit({{"kind", "round_start"}, {"round", round}, {"max_rounds", max_rounds}});

        AIReply reply;
        std::string err;
        AIStreamHooks stream_hooks;
        stream_hooks.on_reasoning = [&](const std::string& delta) {
            reasoning_seen = true;
            emit_delta("thinking", delta, round);
        };
        stream_hooks.on_content = [&](const std::string& delta) {
            emit_delta("content", delta, round);
        };
        stream_hooks.on_note = [&](const std::string& note) {
            emit({{"kind", "note"}, {"text", note}, {"round", round}});
        };

        if (!client.chat_stream(messages, tools, reply, err, stream_hooks)) {
            result.ended_by = "error";
            result.error = err;
            emit({{"kind", "error"}, {"message", err}, {"round", round}});
            break;
        }
        if (!reasoning_seen) {
            emit({{"kind", "note"},
                  {"text", "模型未提供思考过程（reasoning_content/reasoning），只显示正文与工具调用"},
                  {"round", round}});
            reasoning_seen = true;  // 只提示一次
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
                emit({{"kind", "round_end"},
                      {"round", round},
                      {"tool_calls", 0},
                      {"ms", now_ms() - round_started},
                      {"note", "本轮无内容"}});
                continue;
            }
            emit({{"kind", "round_end"},
                  {"round", round},
                  {"tool_calls", 0},
                  {"ms", now_ms() - round_started}});
            emit({{"kind", "final"}, {"text", result.final_text}, {"ended_by", result.ended_by}});
            break;
        }

        // 落 assistant 消息
        if (has_fc) {
            json am = {{"role", "assistant"}, {"content", reply.content.empty() ? json(nullptr) : json(reply.content)}};
            json tcs = json::array();
            for (const auto& c : reply.tool_calls) {
                tcs.push_back({{"id", c.id},
                               {"type", "function"},
                               {"function", {{"name", c.name}, {"arguments", aiutil::dump_json(c.arguments)}}}});
            }
            am["tool_calls"] = tcs;
            messages.push_back(am);
        } else {
            messages.push_back({{"role", "assistant"}, {"content", stripped.empty() ? "（发起工具调用）" : stripped}});
        }

        // 执行
        int round_tools = 0;
        auto run_one = [&](const AIToolCall& c) {
            ++result.tool_calls;
            ++round_tools;
            std::string sig = c.name + "|" + aiutil::dump_json(c.arguments);
            int count = ++call_counts[sig];
            add_trace(result, "tool_call", c.name, aiutil::dump_json(c.arguments));
            emit({{"kind", "tool_call"}, {"name", c.name}, {"args", c.arguments}, {"round", round}});

            long long tool_started = now_ms();
            std::string out;
            if (count > 3) {
                out = "ERROR: 同一调用已重复 3 次均失败，请勿重试；请调整参数或直接给出结论。";
            } else {
                out = ai_execute_tool(c.name, c.arguments, ctx);
            }
            long long took = now_ms() - tool_started;
            bool ok = out.rfind("ERROR", 0) != 0;
            std::string first = first_line(out);
            add_trace(result, "tool_result", c.name, first);
            emit({{"kind", "tool_result"},
                  {"name", c.name},
                  {"detail", first},
                  {"ok", ok},
                  {"ms", took},
                  {"round", round}});
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

        emit({{"kind", "round_end"},
              {"round", round},
              {"tool_calls", round_tools},
              {"ms", now_ms() - round_started}});
    }

    if (result.ended_by == "error" && result.final_text.empty()) {
        result.final_text = "（AI 请求失败: " + result.error + "）";
    }
    // for 循环正常结束且未 break → max_rounds
    if (result.ended_by == "error" && result.error.empty() && result.rounds >= max_rounds) {
        result.ended_by = "max_rounds";
        result.final_text = "（已达到最大轮数 " + std::to_string(max_rounds) + "，会话被截断。）";
    }

    emit({{"kind", "done"},
          {"ended_by", result.ended_by},
          {"rounds", result.rounds},
          {"tool_calls", result.tool_calls},
          {"final_text", result.final_text},
          {"ok", result.ended_by == "end_tag" || result.ended_by == "final_text"}});
    flush_stream();          // 保险：任何残留正文都要送出去（emit 之后不会再缓冲）
    return result;
}
