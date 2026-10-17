// ai_client.cpp
#include "ai_client.h"

#include "ai_util.h"
#include "http_client.h"

#include <algorithm>
#include <cctype>
#include <map>
#include <regex>
#include <sstream>

using nlohmann::json;

namespace {

const std::regex kCallLine(R"(^\s*CALL\s+([A-Za-z_][A-Za-z0-9_]*)\s*(.*)$)");
const std::regex kEndLine(R"(^(?:.*\s)?END$)", std::regex::icase);

std::string trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

// 流式工具调用按 index 累积分片（OpenAI 规范：name/arguments 都可能被拆成多片）
struct ToolCallAccum {
    std::string id;
    std::string name;
    std::string args;
};

// 把累积的分片转成最终 AIReply（arguments 尽力解析为 JSON）
void flush_tool_calls(std::map<int, ToolCallAccum>& acc, AIReply& out) {
    for (auto& kv : acc) {
        ToolCallAccum& a = kv.second;
        if (a.name.empty()) continue;
        AIToolCall call;
        call.id = a.id.empty() ? ("call_" + std::to_string(kv.first)) : a.id;
        call.name = a.name;
        std::string args = trim(a.args);
        if (args.empty()) {
            call.arguments = json::object();
        } else {
            try {
                json j = json::parse(args);
                call.arguments = j.is_object() ? j : json{{"_raw", args}};
            } catch (...) {
                call.arguments = json{{"_raw", args}};
            }
        }
        out.tool_calls.push_back(std::move(call));
    }
}

std::string to_lower(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

// 解析 CALL 行剩余部分为参数对象
json parse_call_args(const std::string& rest_in) {
    std::string rest = trim(rest_in);
    if (rest.empty()) return json::object();
    if (rest[0] == '{') {
        try {
            json j = json::parse(rest);
            if (j.is_object()) return j;
        } catch (...) {
        }
        return json{{"_raw", rest}};
    }
    // key=value，支持双引号包裹带空格的值
    json args = json::object();
    size_t i = 0;
    while (i < rest.size()) {
        while (i < rest.size() && std::isspace(static_cast<unsigned char>(rest[i]))) ++i;
        if (i >= rest.size()) break;
        size_t eq = rest.find('=', i);
        if (eq == std::string::npos) break;
        std::string key = trim(rest.substr(i, eq - i));
        size_t v = eq + 1;
        std::string value;
        if (v < rest.size() && rest[v] == '"') {
            ++v;
            size_t end = rest.find('"', v);
            if (end == std::string::npos) end = rest.size();
            value = rest.substr(v, end - v);
            i = (end < rest.size()) ? end + 1 : rest.size();
        } else {
            size_t space = rest.find(' ', v);
            if (space == std::string::npos) space = rest.size();
            value = rest.substr(v, space - v);
            i = space;
        }
        if (!key.empty()) args[key] = value;
    }
    return args;
}

}  // namespace

void parse_text_calls(const std::string& text, std::vector<AIToolCall>& calls,
                      std::string& stripped) {
    calls.clear();
    std::string kept;
    std::string line;
    std::istringstream stream(text);
    int seq = 0;
    bool first = true;
    while (std::getline(stream, line)) {
        std::smatch m;
        if (std::regex_match(line, m, kCallLine)) {
            AIToolCall call;
            ++seq;
            call.id = "text_" + std::to_string(seq);
            call.name = m[1].str();
            call.arguments = parse_call_args(m[2].str());
            calls.push_back(call);
        } else {
            if (!first) kept += "\n";
            kept += line;
            first = false;
        }
    }
    stripped = trim(kept);
}

std::string split_end_tag(const std::string& text, bool& has_end) {
    has_end = false;
    if (text.empty()) return "";

    // 去掉尾部空行
    std::string body = text;
    while (!body.empty() && std::isspace(static_cast<unsigned char>(body.back()))) body.pop_back();
    if (body.empty()) return "";

    size_t nl = body.find_last_of('\n');
    std::string last = (nl == std::string::npos) ? body : body.substr(nl + 1);
    std::string last_trim = trim(last);
    if (!last_trim.empty() && last_trim.size() <= 20 && std::regex_match(last_trim, kEndLine)) {
        has_end = true;
        // END 之前的文字保留
        std::string prefix = last_trim;
        size_t endpos = prefix.size() - 3;  // "END"
        prefix = trim(prefix.substr(0, endpos));
        std::string head = (nl == std::string::npos) ? "" : body.substr(0, nl);
        if (prefix.empty()) return trim(head);
        if (head.empty()) return prefix;
        return head + "\n" + prefix;
    }
    return body;
}

namespace {

// 把「整体 JSON 响应」解析成 AIReply（非流式路径，以及服务端忽略 stream 时的回退）
bool parse_completion_body(const std::string& body, AIReply& out, std::string& err) {
    json j;
    try {
        j = json::parse(body);
    } catch (const std::exception& e) {
        err = std::string("响应 JSON 解析失败: ") + e.what();
        return false;
    }
    try {
        const json& message = j.at("choices").at(0).at("message");
        out = AIReply{};
        if (message.contains("content") && !message["content"].is_null()) {
            out.content = message["content"].get<std::string>();
        }
        if (message.contains("tool_calls") && message["tool_calls"].is_array()) {
            for (const auto& item : message["tool_calls"]) {
                AIToolCall call;
                call.id = item.value("id", "call_0");
                const json& fn = item.value("function", json::object());
                call.name = fn.value("name", "");
                if (fn.contains("arguments")) {
                    if (fn["arguments"].is_string()) {
                        try {
                            call.arguments = json::parse(fn["arguments"].get<std::string>());
                        } catch (...) {
                            call.arguments = json{{"_raw", fn["arguments"].get<std::string>()}};
                        }
                    } else if (fn["arguments"].is_object()) {
                        call.arguments = fn["arguments"];
                    }
                }
                out.tool_calls.push_back(std::move(call));
            }
        }
    } catch (const std::exception& e) {
        err = std::string("响应格式异常: ") + e.what();
        return false;
    }
    return true;
}

std::string http_error_text(const HttpResponse& resp) {
    if (resp.status == 0) return resp.error.empty() ? "网络错误" : resp.error;
    std::string detail;
    try {
        json j = json::parse(resp.body);
        detail = j.value("error", json::object()).value("message", "");
        if (detail.empty()) detail = aiutil::utf8_truncate(resp.body, 300);
    } catch (...) {
        detail = aiutil::utf8_truncate(resp.body, 300);
    }
    return "HTTP " + std::to_string(resp.status) + ": " + detail;
}

}  // namespace

AIClient::AIClient(std::string base_url, std::string api_key, std::string model, int timeout)
    : base_url_(std::move(base_url)), api_key_(std::move(api_key)),
      model_(std::move(model)), timeout_(timeout) {}

std::string AIClient::endpoint_() const {
    std::string url = base_url_;
    while (!url.empty() && url.back() == '/') url.pop_back();
    if (url.size() >= 17 && url.substr(url.size() - 17) == "/chat/completions") return url;
    return url + "/chat/completions";
}

bool AIClient::chat(const json& messages, const json& tools, AIReply& out, std::string& err) {
    json payload;
    payload["model"] = model_;
    payload["messages"] = messages;
    payload["temperature"] = 0.2;
    payload["stream"] = false;
    if (tools.is_array() && !tools.empty()) {
        payload["tools"] = tools;
        payload["tool_choice"] = "auto";
    }

    HttpResponse resp = http_request("POST", endpoint_(), api_key_, aiutil::dump_json(payload), timeout_);
    if (!resp.ok) {
        err = http_error_text(resp);
        return false;
    }
    return parse_completion_body(resp.body, out, err);
}

bool AIClient::chat_stream(const json& messages, const json& tools, AIReply& out,
                           std::string& err, const AIStreamHooks& hooks) {
    json payload;
    payload["model"] = model_;
    payload["messages"] = messages;
    payload["temperature"] = 0.2;
    payload["stream"] = true;
    if (tools.is_array() && !tools.empty()) {
        payload["tools"] = tools;
        payload["tool_choice"] = "auto";
    }

    std::string buffer;   // 未成行的残余字节
    std::string content;  // 累积正文
    std::string reasoning;
    std::map<int, ToolCallAccum> acc;
    bool saw_event = false;
    bool saw_done = false;
    bool first_byte = false;

    auto handle_payload = [&](const std::string& data) {
        if (data == "[DONE]") {
            saw_done = true;
            return;
        }
        json j;
        try {
            j = json::parse(data);
        } catch (...) {
            return;  // 心跳/坏块，忽略
        }
        if (j.contains("error")) {
            std::string msg;
            if (j["error"].is_object()) msg = j["error"].value("message", "");
            else if (j["error"].is_string()) msg = j["error"].get<std::string>();
            if (!msg.empty()) err = msg;
        }
        if (!j.contains("choices") || !j["choices"].is_array() || j["choices"].empty()) return;

        const json& ch = j["choices"][0];
        const json& d = ch.contains("delta") ? ch["delta"] : ch.value("message", json::object());
        if (!d.is_object()) return;

        // 思考过程：DeepSeek 用 reasoning_content，部分服务用 reasoning / thinking
        for (const char* key : {"reasoning_content", "reasoning", "thinking"}) {
            if (d.contains(key) && d[key].is_string()) {
                std::string piece = d[key].get<std::string>();
                if (!piece.empty()) {
                    reasoning += piece;
                    if (hooks.on_reasoning) hooks.on_reasoning(piece);
                }
            }
        }
        if (d.contains("content") && d["content"].is_string()) {
            std::string piece = d["content"].get<std::string>();
            if (!piece.empty()) {
                content += piece;
                if (hooks.on_content) hooks.on_content(piece);
            }
        }
        if (d.contains("tool_calls") && d["tool_calls"].is_array()) {
            for (const auto& item : d["tool_calls"]) {
                int idx = item.value("index", 0);
                ToolCallAccum& a = acc[idx];
                if (item.contains("id") && item["id"].is_string())
                    a.id = item["id"].get<std::string>();
                const json& fn = item.value("function", json::object());
                if (fn.contains("name") && fn["name"].is_string())
                    a.name = fn["name"].get<std::string>();
                if (fn.contains("arguments")) {
                    if (fn["arguments"].is_string())
                        a.args += fn["arguments"].get<std::string>();
                    else if (fn["arguments"].is_object())
                        a.args += aiutil::dump_json(fn["arguments"]);
                }
            }
        }
    };

    auto feed = [&](const char* data, size_t len) {
        if (!first_byte && len > 0) {
            first_byte = true;
            if (hooks.on_note) hooks.on_note("已连接，开始接收流式响应");
        }
        buffer.append(data, len);
        size_t pos = 0;
        while ((pos = buffer.find('\n')) != std::string::npos) {
            std::string line = buffer.substr(0, pos);
            buffer.erase(0, pos + 1);
            if (!line.empty() && line.back() == '\r') line.pop_back();
            std::string t = trim(line);
            if (t.empty() || t[0] == ':') continue;  // 空行 / SSE 注释（心跳）
            if (t.rfind("data:", 0) == 0) {
                saw_event = true;
                handle_payload(trim(t.substr(5)));
            } else if (t.rfind("event:", 0) == 0) {
                // SSE 事件名，本项目不使用
            } else if (t[0] == '{') {
                saw_event = true;  // 少数服务不带 data: 前缀，直接吐 JSON 行
                handle_payload(t);
            }
        }
    };

    // 思考期间可能几十秒没有字节：单次读取超时给足（连接/发送仍用 timeout_）
    int recv_ms = std::max(180000, timeout_ * 1000 * 3);
    HttpResponse resp = http_request_stream(
        "POST", endpoint_(), api_key_, aiutil::dump_json(payload), timeout_, recv_ms,
        [&](const char* d, size_t n) { feed(d, n); return true; });

    if (!resp.ok) {
        err = http_error_text(resp);
        return false;
    }

    // 收尾：处理最后一段没有换行符的残留
    if (!trim(buffer).empty())
        feed("\n", 1);

    if (!saw_event) {
        // 服务端忽略了 stream，直接返回整体 JSON：回退成非流式解析，并把正文整体抛给 UI
        if (!parse_completion_body(resp.body, out, err)) return false;
        if (!out.content.empty() && hooks.on_content) hooks.on_content(out.content);
        if (hooks.on_note) hooks.on_note("服务端未返回 SSE 流，已按整体响应处理");
        return true;
    }

    out = AIReply{};
    out.content = content;
    flush_tool_calls(acc, out);

    if (hooks.on_note) {
        if (!saw_done) hooks.on_note("流已结束（未收到 [DONE] 标记）");
        if (reasoning.empty()) hooks.on_note("本轮未返回思考内容（部分模型/网关不暴露 reasoning）");
    }
    return true;
}

bool AIClient::test_connection(std::string& detail) {
    std::string url = base_url_;
    while (!url.empty() && url.back() == '/') url.pop_back();
    if (url.size() < 7 || url.substr(url.size() - 7) != "/models") url += "/models";

    HttpResponse resp = http_request("GET", url, api_key_, "", 5);
    if (resp.status == 200) {
        detail = "连通";
        return true;
    }
    if (resp.status == 401 || resp.status == 403) {
        detail = "HTTP " + std::to_string(resp.status) + "（密钥无效）";
        return false;
    }
    if (resp.status == 404) {
        detail = "端点可达（无 /models 接口）";
        return true;
    }
    if (resp.status == 0) {
        detail = "不可达（" + resp.error + "）";
        return false;
    }
    detail = "HTTP " + std::to_string(resp.status);
    return false;
}
