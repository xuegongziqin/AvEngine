// http_client.cpp - WinHTTP 实现（含流式分块读取）
#include "http_client.h"

#include "ai_util.h"

#include <algorithm>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhttp.h>

// winhttp 由 CMake 链接（不放 #pragma comment，MinGW 会告警 unknown pragma）

using aiutil::to_wide;

namespace {

constexpr size_t kMaxBufferedBody = 4u * 1024 * 1024;  // 流式请求最多缓存 4MB 供回退解析

// Windows 8.1 才支持 WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY（值 4）；在 Windows 7 /
// Server 2008 R2 上用它会让 WinHttpOpen 直接失败（错误 87 参数错误）。
#ifndef WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY
#define WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY 4
#endif
#ifndef WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_1
#define WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_1 0x00000200
#endif
#ifndef WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2
#define WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 0x00000800
#endif

/*
 * 打开 WinHTTP 会话。
 * 新系统先用自动代理（会读 PAC/WPAD，行为与浏览器一致）；Windows 7 等不支持时
 * 回退到默认代理设置。随后显式允许 TLS 1.2 —— Win7 SP1 需要 KB3140245 才有
 * TLS 1.2，否则只能协商 TLS 1.0，现代 API 网关会拒绝握手（错误 12175）。
 */
HINTERNET open_session(std::string& err) {
    HINTERNET session = WinHttpOpen(L"AvEngine/0.1", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                                    WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) {
        session = WinHttpOpen(L"AvEngine/0.1", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                              WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    }
    if (!session) {
        err = "WinHttpOpen 失败（错误 " + std::to_string(GetLastError()) + "）";
        return nullptr;
    }
    DWORD protocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1 |
                      WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_1 |
                      WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2;
    WinHttpSetOption(session, WINHTTP_OPTION_SECURE_PROTOCOLS, &protocols, sizeof(protocols));
    return session;
}

/*
 * 公共实现：on_chunk 非空时为流式模式（边收边回调），同时最多缓存 kMaxBufferedBody 字节。
 */
HttpResponse request_impl(const std::string& method, const std::string& url,
                          const std::string& api_key, const std::string& body,
                          int timeout_sec, int recv_timeout_ms, const HttpChunkFn* on_chunk) {
    HttpResponse r;
    std::wstring wurl = to_wide(url);
    if (wurl.empty()) {
        r.error = "URL 为空";
        return r;
    }

    URL_COMPONENTS uc{};
    uc.dwStructSize = sizeof(uc);
    uc.dwSchemeLength = static_cast<DWORD>(-1);
    uc.dwHostNameLength = static_cast<DWORD>(-1);
    uc.dwUrlPathLength = static_cast<DWORD>(-1);
    uc.dwExtraInfoLength = static_cast<DWORD>(-1);
    if (!WinHttpCrackUrl(wurl.c_str(), static_cast<DWORD>(wurl.size()), 0, &uc)) {
        r.error = "URL 解析失败";
        return r;
    }

    std::wstring host(uc.lpszHostName, uc.dwHostNameLength);
    std::wstring path(uc.lpszUrlPath, uc.dwUrlPathLength);
    if (uc.dwExtraInfoLength > 0 && uc.lpszExtraInfo) {
        path.append(uc.lpszExtraInfo, uc.dwExtraInfoLength);
    }
    bool https = (uc.nScheme == INTERNET_SCHEME_HTTPS);
    int timeout_ms = (timeout_sec > 0 ? timeout_sec : 60) * 1000;

    std::string open_err;
    HINTERNET session = open_session(open_err);
    if (!session) {
        r.error = open_err;
        return r;
    }
    int recv_ms = recv_timeout_ms > 0 ? recv_timeout_ms : timeout_ms;
    WinHttpSetTimeouts(session, timeout_ms, timeout_ms, timeout_ms, recv_ms);

    HINTERNET connect = WinHttpConnect(session, host.c_str(), uc.nPort, 0);
    if (!connect) {
        r.error = "WinHttpConnect 失败（错误 " + std::to_string(GetLastError()) +
                  "，主机 " + aiutil::to_utf8(host) + "）";
        WinHttpCloseHandle(session);
        return r;
    }

    std::wstring verb = (method == "GET") ? L"GET" : L"POST";
    HINTERNET req = WinHttpOpenRequest(connect, verb.c_str(), path.c_str(), nullptr,
                                       WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                       https ? WINHTTP_FLAG_SECURE : 0);
    if (!req) {
        r.error = "WinHttpOpenRequest 失败（错误 " + std::to_string(GetLastError()) + "）";
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return r;
    }

    std::wstring headers = L"Content-Type: application/json\r\n";
    if (!api_key.empty()) {
        headers += L"Authorization: Bearer " + to_wide(api_key) + L"\r\n";
    }
    if (on_chunk) {
        headers += L"Accept: text/event-stream\r\n";  // 明确要 SSE
    }

    BOOL sent = WinHttpSendRequest(
        req, headers.c_str(), static_cast<DWORD>(-1),
        body.empty() ? WINHTTP_NO_REQUEST_DATA : const_cast<char*>(body.data()),
        static_cast<DWORD>(body.size()), static_cast<DWORD>(body.size()), 0);
    if (sent) {
        sent = WinHttpReceiveResponse(req, nullptr);
    }

    if (!sent) {
        DWORD err = GetLastError();
        if (err == ERROR_WINHTTP_TIMEOUT) {
            r.error = "请求超时（模型思考较久时可调大 config.ini 的 timeout）";
        } else if (err == ERROR_WINHTTP_SECURE_FAILURE) {
            r.error = "TLS 握手失败（错误 12175）：Windows 7 需安装 KB3140245 以启用 TLS 1.2，"
                      "或把 base_url 换成支持 TLS 1.0 的网关/局域网代理";
        } else if (err == ERROR_WINHTTP_CANNOT_CONNECT) {
            r.error = "无法连接（错误 12029）：检查网络、代理与 base_url";
        } else if (err == ERROR_WINHTTP_NAME_NOT_RESOLVED) {
            r.error = "域名解析失败（错误 12007）：检查 DNS 与 base_url 主机名";
        } else {
            r.error = "HTTP 请求失败（错误 " + std::to_string(err) + "）";
        }
    } else {
        DWORD status = 0, len = sizeof(status);
        WinHttpQueryHeaders(req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &status, &len, WINHTTP_NO_HEADER_INDEX);
        r.status = static_cast<int>(status);

        DWORD avail = 0;
        do {
            if (!WinHttpQueryDataAvailable(req, &avail)) break;
            if (avail == 0) break;
            std::string chunk;
            chunk.resize(avail);
            DWORD read = 0;
            if (!WinHttpReadData(req, &chunk[0], avail, &read)) break;
            if (read == 0) break;
            if (on_chunk) {
                if (!(*on_chunk)(chunk.data(), read)) {  // 回调要求中断
                    r.ok = (r.status >= 200 && r.status < 300);
                    WinHttpCloseHandle(req);
                    WinHttpCloseHandle(connect);
                    WinHttpCloseHandle(session);
                    return r;
                }
                if (r.body.size() < kMaxBufferedBody) {
                    size_t room = kMaxBufferedBody - r.body.size();
                    r.body.append(chunk.data(), std::min<size_t>(read, room));
                }
            } else {
                r.body.append(chunk.data(), read);
            }
        } while (avail > 0);

        r.ok = (r.status >= 200 && r.status < 300);
    }

    WinHttpCloseHandle(req);
    WinHttpCloseHandle(connect);
    WinHttpCloseHandle(session);
    return r;
}

}  // namespace

HttpResponse http_request(const std::string& method, const std::string& url,
                          const std::string& api_key, const std::string& body,
                          int timeout_sec) {
    return request_impl(method, url, api_key, body, timeout_sec, 0, nullptr);
}

HttpResponse http_request_stream(const std::string& method, const std::string& url,
                                 const std::string& api_key, const std::string& body,
                                 int timeout_sec, int recv_timeout_ms,
                                 const HttpChunkFn& on_chunk) {
    return request_impl(method, url, api_key, body, timeout_sec, recv_timeout_ms, &on_chunk);
}
