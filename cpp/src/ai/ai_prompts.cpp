// ai_prompts.cpp
#include "ai_prompts.h"

#include <ctime>

namespace aiprompts {

const char* kSystemPrompt =
    u8"你是 AvEngine AI 安全分析助手，嵌入在一台 Windows 主机的本地杀毒引擎中。\n"
    "你会收到按时间窗口（默认每 5 分钟）汇总的系统事件，也可能收到扫描检出结果或用户的自由提问。\n"
    "\n"
    "## 你的职责\n"
    "1. 判定事件批次中是否存在异常/恶意行为（可疑进程、外联、权限提升、混淆脚本、持久化、勒索行为等）。\n"
    "2. 需要更多证据时，调用工具获取（进程详情、内存转储、文件哈希、PE 结构、网络连接、注册表、计划任务、事件历史检索等）。\n"
    "3. 得出结论后，给出简短中文分析与建议；确认恶意且需要处置时，调用 quarantine_file / kill_process 等处置工具。\n"
    "4. 分析必须基于证据：引用具体事件行（时间/进程/PID/路径/IP），不要臆测。\n"
    "\n"
    "## 工具调用方式\n"
    "- 优先使用 function calling（tools）发起调用。\n"
    "- 若模型不支持 function calling，使用文本兜底语法：单独一行\n"
    "  CALL 工具名 参数名=值 参数名2=\"带空格的值\"\n"
    "  或 CALL 工具名 {\"参数名\": \"值\"}\n"
    "  一条消息可发多行 CALL；工具结果会以 TOOL 角色消息回传，然后你继续分析。\n"
    "- 工具结果中的 ERROR: 开头表示失败，读取提示后调整参数或改用其他工具，不要重复同样调用超过 2 次。\n"
    "\n"
    "## 事件源说明\n"
    "- 批次默认包含: sysmon/process/network/dns/powershell/system/application。\n"
    "- fileio（文件读写）事件量大不进批次：需要文件访问证据时用 grep_events(source=\"fileio\", keyword=\"...\") 按需检索。\n"
    "- query_events 可查询任一源最近若干小时；get_event_xml 按 rid 取原始 XML。\n"
    "\n"
    "## 结束协议（重要）\n"
    "- 多轮工具调查结束后，输出最终中文结论。\n"
    "- 结论的最后一行必须单独写 END 表示本轮会话结束。\n"
    "- 若你认为还需要更多证据，就不要写 END，继续调用工具。\n"
    "- 单条消息中不要同时给出最终结论和工具调用；要么调用工具，要么给结论+END。\n";

std::string now_string() {
    char buf[32];
    std::time_t t = std::time(nullptr);
    std::tm tmv{};
    localtime_s(&tmv, &t);
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tmv);
    return buf;
}

std::string build_batch_message(const std::string& batch_text,
                                const std::vector<std::pair<std::string, int>>& stats,
                                int truncated, const std::vector<std::string>& errors,
                                int minutes) {
    std::string stat_line;
    for (size_t i = 0; i < stats.size(); ++i) {
        if (i) stat_line += ", ";
        stat_line += stats[i].first + "=" + std::to_string(stats[i].second);
    }
    if (stat_line.empty()) stat_line = "无";

    std::string s;
    s += "== 批次开始（窗口 " + std::to_string(minutes) + " 分钟，" + now_string() + "）==\n";
    s += "各源事件数: " + stat_line + "\n";
    if (truncated > 0) {
        s += "注意: 有 " + std::to_string(truncated) +
             " 条事件因上限被截断，需要时可用 query_events 补查。\n";
    }
    if (!errors.empty()) {
        s += "采集警告:\n";
        for (size_t i = 0; i < errors.size() && i < 5; ++i) s += "- " + errors[i] + "\n";
    }
    s += "\n-- 事件 --\n";
    s += batch_text;
    s += "\n-- 事件结束 --\n\n";
    s += "请分析以上事件：有异常则调查（调用工具取证），确认恶意可执行处置；"
         "最后给出中文结论，结论最后一行单独写 END。若无需处理也请给出简要结论并以 END 结束。";
    return s;
}

std::string build_ask_context(const std::string& engine_status) {
    std::string s = now_string() + "\n";
    if (!engine_status.empty()) s += "引擎状态: " + engine_status + "\n";
    s += "\n请回答用户问题；如需查证可调用工具，结论最后一行单独写 END。";
    return s;
}

std::string build_detection_message(const std::string& path, const std::string& engine,
                                    const std::string& match, const std::string& action,
                                    int total) {
    std::string s = "== 扫描检出联动 ==\n";
    s += "时间: " + now_string() + "\n";
    s += "path: " + path + "\n";
    if (!engine.empty()) s += "engine: " + engine + "\n";
    if (!match.empty()) s += "match: " + match + "\n";
    if (!action.empty()) s += "action: " + action + "\n";
    if (total > 0) s += "total: " + std::to_string(total) + "\n";
    s += "\n引擎已检出威胁。请判断：1) 是否需要更多取证（如 get_pe_info / scan_file / "
         "list_process_modules 查找运行中的关联进程）；2) 若文件尚未隔离且判定恶意，"
         "可调用 quarantine_file 处置。最后给出中文结论并以 END 结束。";
    return s;
}

}  // namespace aiprompts
