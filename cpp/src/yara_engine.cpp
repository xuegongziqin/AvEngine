// yara_engine.cpp - libyara 扫描封装
#include "yara_engine.h"

#include <yara.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <filesystem>
#include <mutex>
#include <set>
#include <vector>

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

// 将一批规则文件加入一个新建的编译器。返回编译器（需调用方销毁），并把
// 无法读取或编译报错的文件记入 errored。
//
// 注意：libyara 要求编译器零错误时才可调用 yr_compiler_get_rules()。该约束
// 在源码中由 assert 保证，而本项目以 -DNDEBUG 构建，assert 被移除；若在存在
// 编译错误的编译器上强行 get_rules，会得到损坏的规则集，扫描时死循环。
static YR_COMPILER* compile_files(const std::vector<std::string>& files,
                                  std::vector<std::string>& errored) {
    errored.clear();
    YR_COMPILER* compiler = nullptr;
    if (yr_compiler_create(&compiler) != ERROR_SUCCESS || !compiler) {
        return nullptr;
    }
    for (const auto& path : files) {
        std::FILE* fp = std::fopen(path.c_str(), "rb");
        if (!fp) {
            errored.push_back(path);
            continue;
        }
        int rc = yr_compiler_add_file(compiler, fp, nullptr, path.c_str());
        std::fclose(fp);
        if (rc != 0) {
            errored.push_back(path);
        }
    }
    return compiler;
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

    std::vector<std::string> files;
    {
        std::error_code ec;
        for (auto it = fs::recursive_directory_iterator(rules_path, ec);
             it != fs::recursive_directory_iterator(); it.increment(ec)) {
            if (ec) break;
            if (!it->is_regular_file(ec)) continue;
            std::string ext = it->path().extension().string();
            for (auto& ch : ext) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
            if (ext != ".yar" && ext != ".yara") continue;
            files.push_back(it->path().string());
        }
    }
    std::sort(files.begin(), files.end());
    if (files.empty()) {
        error_ = "规则目录中没有 .yar/.yara 文件";
        return;
    }

    // 逐轮剔除编译失败的文件，直到剩余文件全部编译成功，保证 get_rules 安全。
    std::vector<std::string> remaining = files;
    YR_COMPILER* compiler = nullptr;
    for (;;) {
        std::vector<std::string> errored;
        compiler = compile_files(remaining, errored);
        if (!compiler) {
            error_ = "yr_compiler_create 失败";
            return;
        }
        if (errored.empty()) {
            break;
        }
        if (errored.size() >= remaining.size()) {
            // 没有可用的规则文件，避免无限重试。
            yr_compiler_destroy(compiler);
            error_ = "所有规则文件均编译失败";
            return;
        }
        std::set<std::string> bad(errored.begin(), errored.end());
        std::vector<std::string> next;
        next.reserve(remaining.size() - bad.size());
        for (const auto& f : remaining) {
            if (!bad.count(f)) next.push_back(f);
        }
        remaining.swap(next);
        yr_compiler_destroy(compiler);
        compiler = nullptr;
    }

    skipped_count_ = static_cast<int>(files.size() - remaining.size());
    rules_count_ = static_cast<int>(remaining.size());

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
