// http_client.h - 基于 WinHTTP 的 HTTP 客户端
#pragma once

#include <string>

struct HttpResponse {
    bool ok = false;
    int status = 0;
    std::string body;
    std::string error;
};

// method: "GET" / "POST"；body 仅 POST 使用。
HttpResponse http_request(const std::string& method, const std::string& url,
                          const std::string& api_key, const std::string& body,
                          int timeout_sec);
