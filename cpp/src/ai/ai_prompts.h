// ai_prompts.h - 提示词与消息构建
#pragma once

#include <string>
#include <vector>

namespace aiprompts {

extern const char* kSystemPrompt;

std::string now_string();
std::string build_batch_message(const std::string& batch_text,
                                const std::vector<std::pair<std::string, int>>& stats,
                                int truncated, const std::vector<std::string>& errors,
                                int minutes);
std::string build_ask_context(const std::string& engine_status);
std::string build_detection_message(const std::string& path, const std::string& engine,
                                    const std::string& match, const std::string& action,
                                    int total);

}  // namespace aiprompts
