// clamd_client.h - clamd TCP(INSTREAM/VERSION/RELOAD) 客户端
#pragma once

#include <string>

struct ClamScanResult {
    bool available = false;  // clamd 是否可用（本次请求是否成功完成）
    bool infected = false;
    std::string virus;       // 命中时的病毒名
    std::string error;       // 失败原因
};

class ClamdClient {
public:
    ClamdClient(std::string host, int port, int timeout_sec);

    bool available();                 // 用 VERSION 探测
    std::string version();            // 失败返回空串
    bool reload();                    // 通知重载病毒库
    ClamScanResult scan_file(const std::string& path) const;

private:
    std::string host_;
    int port_;
    int timeout_sec_;
};
