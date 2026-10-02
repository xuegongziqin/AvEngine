// yara_engine.h - libyara 扫描封装（编译规则目录 + 扫描文件）
#pragma once

#include <string>
#include <vector>

class YaraEngine {
public:
    explicit YaraEngine(const std::string& rules_path);
    ~YaraEngine();

    bool available() const { return available_; }
    int rules_count() const { return rules_count_; }
    int skipped_count() const { return skipped_count_; }
    const std::string& error() const { return error_; }

    // 返回命中的规则标识符列表
    std::vector<std::string> scan_file(const std::string& path) const;

private:
    void* rules_ = nullptr;
    bool available_ = false;
    int rules_count_ = 0;
    int skipped_count_ = 0;
    std::string error_;

    YaraEngine(const YaraEngine&) = delete;
    YaraEngine& operator=(const YaraEngine&) = delete;
};
