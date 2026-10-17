// http_client.h - 基于 WinHTTP 的 HTTP 客户端
#pragma once

#include <functional>
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

/*
 * 流式请求：每读到一段响应体就同步调用 on_chunk(data, len)，返回 false 可提前中断。
 *
 * recv_timeout_ms 是「单次读取」的超时：推理模型可能在思考期间几十秒不吐字节，
 * 这个值应给足（调用方通常取 max(3*timeout, 180s)）；连接/发送仍用 timeout_sec。
 * body 最多累积 4MB，供调用方在「服务端忽略 stream、直接返回整体 JSON」时回退解析。
 */
using HttpChunkFn = std::function<bool(const char* data, size_t len)>;

HttpResponse http_request_stream(const std::string& method, const std::string& url,
                                 const std::string& api_key, const std::string& body,
                                 int timeout_sec, int recv_timeout_ms,
                                 const HttpChunkFn& on_chunk);
