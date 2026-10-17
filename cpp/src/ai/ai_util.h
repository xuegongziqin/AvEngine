// ai_util.h - AI 模块公共小工具
#pragma once

#include <windows.h>

#include <nlohmann/json.hpp>

#include "util.h"   // utf8_to_wide_path / wide_to_utf8：内核公共的路径编码转换

#include <string>

namespace aiutil {

inline std::wstring to_wide(const std::string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), nullptr, 0);
    if (n <= 0) return L"";
    std::wstring w(static_cast<size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), &w[0], n);
    return w;
}

inline std::string to_utf8(const std::wstring& w) {
    return wide_to_utf8(w);
}

inline std::wstring to_wide_path(const std::string& s) {
    // 实现见 util.h（内核与 AI 共用一份，避免两处漂移）。
    return utf8_to_wide_path(s);
}

inline std::wstring to_wide_sys(const std::string& s) {
    // 历史名字，语义已改为"UTF-8 优先"：调用点很多（文件工具、fs::path、CreateFileW），
    // 保持名字不变可以让它们一次性全部修好。
    return utf8_to_wide_path(s);
}

/*
 * 安全 dump：遇到非法 UTF-8 字节用 U+FFFD 替换，绝不抛异常。
 *
 * 为什么必须用它：nlohmann 默认的 dump() 在序列化时校验 UTF-8，一旦某个字符串里
 * 混入非法字节（典型来源：按「字节」截断了中文，把汉字劈成半个；或 Windows API 返回的
 * GBK 字节被当成 UTF-8），就会抛 type_error.316 —— 整份会话结果直接拿不回来。
 * 事件/结果都要经过这里。
 */
inline std::string dump_json(const nlohmann::json& j) {
    return j.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
}

/*
 * 按 UTF-8 字符边界截断，最多 max_bytes 字节：宁可少几个字节，也不把汉字劈成半个。
 */
inline std::string utf8_truncate(const std::string& s, size_t max_bytes) {
    if (s.size() <= max_bytes) return s;
    size_t end = max_bytes;
    while (end > 0 && end < s.size() && (static_cast<unsigned char>(s[end]) & 0xC0) == 0x80) {
        --end;  // 回退到序列首字节（UTF-8 尾部字节形如 10xxxxxx）
    }
    if (end >= s.size()) return s.substr(0, max_bytes);
    unsigned char c = static_cast<unsigned char>(s[end]);
    size_t len = 1;
    if ((c & 0xE0) == 0xC0) len = 2;
    else if ((c & 0xF0) == 0xE0) len = 3;
    else if ((c & 0xF8) == 0xF0) len = 4;
    if (end + len > max_bytes) return s.substr(0, end);  // 该字符跨过边界 -> 丢掉
    return s.substr(0, end + len);
}

}  // namespace aiutil
