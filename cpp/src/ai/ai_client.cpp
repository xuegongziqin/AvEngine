// ai_client.cpp
#include "ai_client.h"

#include "http_client.h"

#include <cctype>
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

    HttpResponse resp = http_request("POST", endpoint_(), api_key_, payload.dump(), timeout_);
    if (!resp.ok) {
        if (resp.status == 0) {
            err = resp.error.empty() ? "网络错误" : resp.error;
        } else {
            std::string detail;
            try {
                json j = json::parse(resp.body);
                detail = j.value("error", json::object()).value("message", "");
            } catch (...) {
                detail = resp.body.substr(0, 300);
            }
            err = "HTTP " + std::to_string(resp.status) + ": " + detail;
        }
        return false;
    }

    json j;
    try {
        j = json::parse(resp.body);
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
