// yara_engine.cpp - libyara 扫描封装
#include "yara_engine.h"

#include <yara.h>

#include <cctype>
#include <cstdio>
#include <filesystem>
#include <mutex>

namespace fs = std::filesystem;

static bool ensure_yara_init(std::string& err) {
    static std::once_flag flag;
    static bool ok = false;
    static std::string init_err;
    std::call_once(flag, []() {
        int rc = yr_initialize();
        if (rc == ERROR_SUCCESS) {
            ok = true;
        } else {
            init_err = "yr_initialize 失败，错误码 " + std::to_string(rc);
        }
    });
    if (!ok) err = init_err;
    return ok;
}

static int scan_callback(YR_SCAN_CONTEXT* /*context*/, int message, void* message_data,
                         void* user_data) {
    if (message == CALLBACK_MSG_RULE_MATCHING) {
        auto* rule = static_cast<YR_RULE*>(message_data);
        auto* out = static_cast<std::vector<std::string>*>(user_data);
        if (rule && rule->identifier) {
            out->push_back(rule->identifier);
        }
    }
    return CALLBACK_CONTINUE;
}

YaraEngine::YaraEngine(const std::string& rules_path) {
    if (rules_path.empty()) {
        error_ = "未配置规则目录";
        return;
    }
    if (!fs::is_directory(rules_path)) {
        error_ = "规则目录不存在: " + rules_path;
        return;
    }
    if (!ensure_yara_init(error_)) {
        return;
    }

    YR_COMPILER* compiler = nullptr;
    if (yr_compiler_create(&compiler) != ERROR_SUCCESS || !compiler) {
        error_ = "yr_compiler_create 失败";
        return;
    }

    std::error_code ec;
    for (auto it = fs::recursive_directory_iterator(rules_path, ec);
         it != fs::recursive_directory_iterator(); it.increment(ec)) {
        if (ec) break;
        if (!it->is_regular_file(ec)) continue;
        std::string ext = it->path().extension().string();
        for (auto& ch : ext) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
        if (ext != ".yar" && ext != ".yara") continue;

        std::FILE* fp = std::fopen(it->path().string().c_str(), "rb");
        if (!fp) {
            ++skipped_count_;
            continue;
        }
        int rc = yr_compiler_add_file(compiler, fp, nullptr, it->path().string().c_str());
        std::fclose(fp);
        if (rc == 0) {
            ++rules_count_;
        } else {
            ++skipped_count_;
        }
    }

    YR_RULES* rules = nullptr;
    if (yr_compiler_get_rules(compiler, &rules) != ERROR_SUCCESS || !rules) {
        error_ = "yr_compiler_get_rules 失败（规则编译错误）";
        yr_compiler_destroy(compiler);
        return;
    }
    yr_compiler_destroy(compiler);

    rules_ = rules;
    available_ = true;
}

YaraEngine::~YaraEngine() {
    if (rules_) {
        yr_rules_destroy(static_cast<YR_RULES*>(rules_));
        rules_ = nullptr;
    }
}

std::vector<std::string> YaraEngine::scan_file(const std::string& path) const {
    std::vector<std::string> hits;
    if (!available_ || !rules_) return hits;
    int rc = yr_rules_scan_file(static_cast<YR_RULES*>(rules_), path.c_str(), 0,
                                scan_callback, &hits, 0);
    if (rc != ERROR_SUCCESS) {
        return hits;
    }
    return hits;
}
