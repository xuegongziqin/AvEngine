// http_client.cpp - WinHTTP 实现
#include "http_client.h"

#include "ai_util.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhttp.h>

#pragma comment(lib, "winhttp.lib")

using aiutil::to_wide;

HttpResponse http_request(const std::string& method, const std::string& url,
                          const std::string& api_key, const std::string& body,
                          int timeout_sec) {
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

    HINTERNET session = WinHttpOpen(L"AvEngine/0.1", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                                    WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) {
        r.error = "WinHttpOpen 失败";
        return r;
    }
    WinHttpSetTimeouts(session, timeout_ms, timeout_ms, timeout_ms, timeout_ms);

    HINTERNET connect = WinHttpConnect(session, host.c_str(), uc.nPort, 0);
    if (!connect) {
        r.error = "WinHttpConnect 失败";
        WinHttpCloseHandle(session);
        return r;
    }

    std::wstring verb = (method == "GET") ? L"GET" : L"POST";
    HINTERNET req = WinHttpOpenRequest(connect, verb.c_str(), path.c_str(), nullptr,
                                       WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                       https ? WINHTTP_FLAG_SECURE : 0);
    if (!req) {
        r.error = "WinHttpOpenRequest 失败";
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return r;
    }

    std::wstring headers = L"Content-Type: application/json\r\n";
    if (!api_key.empty()) {
        headers += L"Authorization: Bearer " + to_wide(api_key) + L"\r\n";
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
        r.error = "HTTP 请求失败（错误 " + std::to_string(err) + "）";
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
            r.body.append(chunk.data(), read);
        } while (avail > 0);

        r.ok = (r.status >= 200 && r.status < 300);
    }

    WinHttpCloseHandle(req);
    WinHttpCloseHandle(connect);
    WinHttpCloseHandle(session);
    return r;
}
