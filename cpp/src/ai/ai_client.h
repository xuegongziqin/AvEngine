// ai_client.h - OpenAI 兼容客户端（WinHTTP + nlohmann/json）
#pragma once

#include <nlohmann/json.hpp>

#include <string>
#include <vector>

struct AIToolCall {
    std::string id;
    std::string name;
    nlohmann::json arguments = nlohmann::json::object();
};

struct AIReply {
    std::string content;
    std::vector<AIToolCall> tool_calls;
};

// 从纯文本中提取 CALL 行；stripped 为移除 CALL 行后的文本
void parse_text_calls(const std::string& text, std::vector<AIToolCall>& calls,
                      std::string& stripped);

// 检测末尾 END 标记；返回去掉标记的正文，has_end 置位
std::string split_end_tag(const std::string& text, bool& has_end);

class AIClient {
public:
    AIClient(std::string base_url, std::string api_key, std::string model, int timeout);

    // 一轮对话。tools 为空数组表示不携带工具。
    bool chat(const nlohmann::json& messages, const nlohmann::json& tools, AIReply& out,
              std::string& err);

    // GET {base_url}/models 轻量连通测试
    bool test_connection(std::string& detail);

private:
    std::string base_url_;
    std::string api_key_;
    std::string model_;
    int timeout_;
    std::string endpoint_() const;
};
