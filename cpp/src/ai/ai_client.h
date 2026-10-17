// ai_client.h - OpenAI 兼容客户端（WinHTTP + nlohmann/json）
#pragma once

#include <nlohmann/json.hpp>

#include <functional>
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

// 流式增量回调：在收到 SSE 分片时被同步调用（同一线程），用于边生成边显示
struct AIStreamHooks {
    std::function<void(const std::string& delta)> on_content;    // 正文增量
    std::function<void(const std::string& delta)> on_reasoning;  // 思考增量（reasoning_content/reasoning/thinking）
    std::function<void(const std::string& note)> on_note;        // 状态提示（如「已收到首字节」）
};

// 从纯文本中提取 CALL 行；stripped 为移除 CALL 行后的文本
void parse_text_calls(const std::string& text, std::vector<AIToolCall>& calls,
                      std::string& stripped);

// 检测末尾 END 标记；返回去掉标记的正文，has_end 置位
std::string split_end_tag(const std::string& text, bool& has_end);

class AIClient {
public:
    AIClient(std::string base_url, std::string api_key, std::string model, int timeout);

    // 一轮对话（非流式）。tools 为空数组表示不携带工具。
    bool chat(const nlohmann::json& messages, const nlohmann::json& tools, AIReply& out,
              std::string& err);

    /*
     * 一轮对话（流式 SSE）。语义与 chat() 相同：返回同样的 AIReply（正文 + 工具调用），
     * 区别只在于过程中会通过 hooks 把正文/思考增量实时抛给调用方。
     * 若服务端忽略 stream 参数直接返回整体 JSON，会自动回退按非流式解析。
     */
    bool chat_stream(const nlohmann::json& messages, const nlohmann::json& tools, AIReply& out,
                     std::string& err, const AIStreamHooks& hooks);

    // GET {base_url}/models 轻量连通测试
    bool test_connection(std::string& detail);

private:
    std::string base_url_;
    std::string api_key_;
    std::string model_;
    int timeout_;
    std::string endpoint_() const;
};
