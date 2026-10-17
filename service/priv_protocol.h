// priv_protocol.h - AvEngine 特权服务与客户端之间的命名管道协议
//
// 只走本机命名管道（不走网络、不注册 RPC）。协议刻意做成"一行请求、一行响应"的
// 纯文本，方便 Python 客户端与 C++ 服务端实现，也方便人工用测试工具复现。
//
// 请求：  AVPRIV/1 <verb> [key=value ...]\r\n
// 响应：  OK [key=value ...]\r\n   或   ERR <code> <message>\r\n
//
// 为什么带版本号：服务与客户端会分别升级，版本不匹配必须直接拒绝，
// 而不是按老格式瞎猜（鉴权通道上"猜"等于给攻击面）。
#pragma once

#include <cstdio>
#include <string>
#include <vector>

namespace avpriv {

constexpr const char* kProtocolVersion = "AVPRIV/1";
constexpr const char* kPipeName = "\\\\.\\pipe\\AvEnginePrivSvc";
constexpr const wchar_t* kPipeNameW = L"\\\\.\\pipe\\AvEnginePrivSvc";

// 管道最大请求长度（一条命令行的量级）
constexpr int kMaxRequestBytes = 8192;

// 服务端返回给客户端、也写进审计日志的错误码
enum class ErrCode {
    kOk = 0,
    kBadProtocol,      // 协议头/版本不对
    kBadRequest,       // 参数不合法
    kNotConfigured,    // 服务未配置证书指纹（fail-closed：拒绝一切）
    kInstallDirUnknown,// 无法确定安装目录白名单（找不到 avengine.exe）→ 同样拒绝一切
    kCallerOpenFail,   // 打不开调用者进程
    kCallerNotAdmin,   // 调用者不在 Administrators 组
    kCallerSession,    // 调用者会话与服务所在的交互会话不一致（可配）
    kCallerNotSigned,  // 调用者没有有效签名
    kCallerWrongCert,  // 签名有效但不是我们钉住的那张证书
    kCallerWrongPath,  // 调用者不是安装目录里的那个可执行文件（拒绝副本）
    kArgsRejected,     // 命令行参数被拒（含控制字符/超长）
    kChildFail,        // 创建 SYSTEM 子进程失败
    kInternal,         // 其它内部错误
};

inline const char* error_code_name(ErrCode c) {
    switch (c) {
    case ErrCode::kOk: return "OK";
    case ErrCode::kBadProtocol: return "BAD_PROTOCOL";
    case ErrCode::kBadRequest: return "BAD_REQUEST";
    case ErrCode::kNotConfigured: return "NOT_CONFIGURED";
    case ErrCode::kInstallDirUnknown: return "INSTALL_DIR_UNKNOWN";
    case ErrCode::kCallerOpenFail: return "CALLER_OPEN_FAIL";
    case ErrCode::kCallerNotAdmin: return "CALLER_NOT_ADMIN";
    case ErrCode::kCallerSession: return "CALLER_SESSION";
    case ErrCode::kCallerNotSigned: return "CALLER_NOT_SIGNED";
    case ErrCode::kCallerWrongCert: return "CALLER_WRONG_CERT";
    case ErrCode::kCallerWrongPath: return "CALLER_WRONG_PATH";
    case ErrCode::kArgsRejected: return "ARGS_REJECTED";
    case ErrCode::kChildFail: return "CHILD_FAIL";
    case ErrCode::kInternal: return "INTERNAL";
    }
    return "UNKNOWN";
}

// ---------------- 极简 key=value 编解码（值里不允许空白，命令行单独编码） ----------------

struct Kv {
    std::string key;
    std::string value;
};

inline std::vector<Kv> parse_kv(const std::string& line) {
    std::vector<Kv> out;
    size_t i = 0;
    while (i < line.size()) {
        while (i < line.size() && (line[i] == ' ' || line[i] == '\t')) ++i;
        if (i >= line.size()) break;
        size_t start = i;
        while (i < line.size() && line[i] != ' ' && line[i] != '\t') ++i;
        std::string tok = line.substr(start, i - start);
        const size_t eq = tok.find('=');
        if (eq == std::string::npos) {
            out.push_back({tok, ""});
        } else {
            out.push_back({tok.substr(0, eq), tok.substr(eq + 1)});
        }
    }
    return out;
}

inline std::string kv_get(const std::vector<Kv>& kvs, const std::string& key,
                          const std::string& def = "") {
    for (const auto& kv : kvs)
        if (kv.key == key) return kv.value;
    return def;
}

/*
 * 命令行参数编码：整条命令行作为一个值传，所以必须可逆。
 * 用 %XX 转义空白与 '%'，其余字节原样（命令行本身是 UTF-8，不动它）。
 */
inline std::string encode_value(const std::string& raw) {
    std::string out;
    out.reserve(raw.size() + 8);
    for (unsigned char c : raw) {
        if (c == '%' || c == ' ' || c == '\t' || c == '\r' || c == '\n' || c < 0x20) {
            char buf[8];
            std::snprintf(buf, sizeof(buf), "%%%02X", c);
            out += buf;
        } else {
            out += static_cast<char>(c);
        }
    }
    return out;
}

inline std::string decode_value(const std::string& enc) {
    std::string out;
    out.reserve(enc.size());
    for (size_t i = 0; i < enc.size(); ++i) {
        if (enc[i] == '%' && i + 2 < enc.size()) {
            auto hex = [](char c) -> int {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                return -1;
            };
            const int hi = hex(enc[i + 1]), lo = hex(enc[i + 2]);
            if (hi >= 0 && lo >= 0) {
                out += static_cast<char>((hi << 4) | lo);
                i += 2;
                continue;
            }
        }
        out += enc[i];
    }
    return out;
}

}  // namespace avpriv
