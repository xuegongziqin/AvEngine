// monitor.h - 常驻实时监控（Sysmon 订阅 + 按访问/定时扫描 + 隔离）
#pragma once

#include <string>
#include <vector>

struct MonitorConfig {
    std::string rules_path;
    std::string quarantine_dir;
    std::string clam_host;
    int clam_port = 0;
    int clam_timeout = 30;
    std::string channel = "Microsoft-Windows-Sysmon/Operational";
    std::vector<std::string> monitor_paths;  // 定时扫描目录
    int timer_interval = 0;                  // 秒；<=0 关闭定时
    bool on_access = true;                   // Sysmon 文件事件触发扫描
};

namespace monitor {

// 启动监控（Sysmon 线程 + 可选定时线程）。成功返回 true。
bool start(const MonitorConfig& cfg, std::string& err);

// 停止并等待线程退出。
void stop();

bool running();

// 取出最多 max_items 条威胁事件（JSON 数组字符串）。
std::string poll(int max_items);

// 监控状态 JSON。
std::string status();

}  // namespace monitor
