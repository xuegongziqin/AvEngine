// util.h - 小工具（JSON 转义 / 十六进制 / 路径编码转换）
#pragma once

#include <windows.h>

#include <string>
#include <vector>
#include <cstdio>

/*
 * -------------------- 路径编码：UTF-8 <-> 宽字符 --------------------
 *
 * 内核与 Python、JSON、config.yaml 之间**一律用 UTF-8**；而 Win32 / std::filesystem
 * 在 Windows 上处理文件必须用宽字符。两处转换放这里，是因为它们属于内核基础设施：
 * core / monitor / sha256 / clamd 与 AI 工具都要用（ai_util.h 直接转发到这两个函数）。
 *
 * 反面教材（曾经到处这么写，中文/日文路径全废）：
 *   std::fopen(path.c_str(), "rb")          // ANSI 代码页解码
 *   fs::path p(narrow_utf8_string)          // ANSI 代码页解码
 *   std::ifstream in(narrow_utf8_string)    // ANSI 代码页解码
 * 在中文系统（CP936）上，UTF-8 的中文路径被当 GBK 解出来就是乱码，于是
 * CreateFileW/fopen 报"找不到文件"，工具表现为"中文路径打不开"。
 */

/** UTF-8 -> 宽字符；非法 UTF-8 时退回系统 ANSI（兼容确实按 ANSI 传入的老调用点）。 */
inline std::wstring utf8_to_wide_path(const std::string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.c_str(),
                                static_cast<int>(s.size()), nullptr, 0);
    if (n > 0) {
        std::wstring w(static_cast<size_t>(n), L'\0');
        MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.c_str(),
                            static_cast<int>(s.size()), &w[0], n);
        return w;
    }
    n = MultiByteToWideChar(CP_ACP, 0, s.c_str(), static_cast<int>(s.size()), nullptr, 0);
    if (n <= 0) return L"";
    std::wstring w(static_cast<size_t>(n), L'\0');
    MultiByteToWideChar(CP_ACP, 0, s.c_str(), static_cast<int>(s.size()), &w[0], n);
    return w;
}

/** 宽字符 -> UTF-8。 */
inline std::string wide_to_utf8(const std::wstring& w) {
    if (w.empty()) return "";
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()),
                                nullptr, 0, nullptr, nullptr);
    if (n <= 0) return "";
    std::string s(static_cast<size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()),
                        &s[0], n, nullptr, nullptr);
    return s;
}

inline std::string json_escape(const std::string& in) {
    std::string out;
    out.reserve(in.size() + 8);
    for (unsigned char c : in) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out += static_cast<char>(c);
                }
        }
    }
    return out;
}

inline std::string to_hex_lower(const unsigned char* data, size_t len) {
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.resize(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out[i * 2] = kHex[data[i] >> 4];
        out[i * 2 + 1] = kHex[data[i] & 0x0F];
    }
    return out;
}

inline std::string json_str(const std::string& s) {
    return "\"" + json_escape(s) + "\"";
}

inline std::string join_json_array(const std::vector<std::string>& items) {
    std::string out = "[";
    for (size_t i = 0; i < items.size(); ++i) {
        if (i) out += ",";
        out += json_str(items[i]);
    }
    out += "]";
    return out;
}
