// ai_collectors.h - ETW/事件日志按需采集（批次 + 工具查询）
#pragma once

#include <string>
#include <utility>
#include <vector>

struct AiBatch {
    std::string text;
    std::vector<std::pair<std::string, int>> stats;
    int truncated = 0;
    std::vector<std::string> errors;
};

bool ai_events_supported();
std::string ai_event_channel(const std::string& source);  // 未知源返回空
bool ai_is_known_source(const std::string& source);

// 按时间窗口汇总多个源的事件文本
AiBatch ai_query_batch(const std::vector<std::string>& sources, int minutes, int max_events,
                       int max_chars);

// 工具查询：返回 (事件文本, 错误)；keyword 为空则不过滤
std::pair<std::string, std::string> ai_query_tool(const std::string& source, double hours,
                                                  int limit, const std::string& keyword);

// 按 EventRecordID 取单条 XML；err 非空表示失败
std::string ai_get_event_xml(const std::string& source, long long record_id, std::string& err);
