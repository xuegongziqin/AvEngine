// ai_tools.h - AI 工具库（七类：进程/文件/网络/系统/事件/处置/情报）
#pragma once

#include <nlohmann/json.hpp>

#include <string>
#include <vector>

struct AiContext {
    std::string rules_path;
    std::string quarantine_dir;
    std::string clam_host;
    int clam_port = 0;
    int clam_timeout = 30;
    std::string log_file;
    std::string dump_dir;
    std::string project_root;
    int max_tool_result_chars = 12000;
};

// tools 数组（OpenAI function calling 格式）
nlohmann::json ai_tool_schemas();

// 执行工具；未知工具或异常返回 "ERROR: ..." 文本
std::string ai_execute_tool(const std::string& name, const nlohmann::json& args, AiContext& ctx);
