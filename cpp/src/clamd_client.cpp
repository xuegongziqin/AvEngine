// clamd_client.cpp - clamd TCP 客户端（Windows Winsock）
#include "clamd_client.h"
#include "ai/ai_util.h"   // aiutil::to_wide_path：非 ASCII 路径支持

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>

#include <cstdint>
#include <cstring>
#include <fstream>
#include <mutex>
#include <vector>

#pragma comment(lib, "ws2_32.lib")

namespace {

bool ensure_winsock(std::string& err) {
    static std::once_flag flag;
    static bool ok = false;
    static std::string init_err;
    std::call_once(flag, []() {
        WSADATA data;
        if (WSAStartup(MAKEWORD(2, 2), &data) == 0) {
            ok = true;
        } else {
            init_err = "WSAStartup 失败";
        }
    });
    if (!ok) err = init_err;
    return ok;
}

bool send_all(SOCKET s, const void* data, size_t len, std::string& err) {
    const char* p = static_cast<const char*>(data);
    size_t sent = 0;
    while (sent < len) {
        int n = ::send(s, p + sent, static_cast<int>(len - sent), 0);
        if (n == SOCKET_ERROR) {
            err = "send 失败 (" + std::to_string(WSAGetLastError()) + ")";
            return false;
        }
        sent += static_cast<size_t>(n);
    }
    return true;
}

std::string recv_response(SOCKET s, std::string& err) {
    std::string out;
    char buf[4096];
    for (;;) {
        int n = ::recv(s, buf, sizeof(buf), 0);
        if (n == SOCKET_ERROR) {
            int code = WSAGetLastError();
            if (code == WSAETIMEDOUT) { err = "读取超时"; }
            else { err = "recv 失败 (" + std::to_string(code) + ")"; }
            return out;
        }
        if (n == 0) break;
        out.append(buf, buf + n);
        if (out.find('\0') != std::string::npos) break;
    }
    // 去掉结尾 NUL
    auto nul = out.find('\0');
    if (nul != std::string::npos) out.resize(nul);
    return out;
}

SOCKET connect_to(const std::string& host, int port, int timeout_sec, std::string& err) {
    if (!ensure_winsock(err)) return INVALID_SOCKET;

    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    addrinfo* res = nullptr;
    std::string port_str = std::to_string(port);
    if (getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res) != 0 || !res) {
        err = "无法解析地址: " + host;
        return INVALID_SOCKET;
    }

    SOCKET s = INVALID_SOCKET;
    for (addrinfo* ai = res; ai; ai = ai->ai_next) {
        s = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s == INVALID_SOCKET) continue;

        DWORD tv = static_cast<DWORD>(timeout_sec > 0 ? timeout_sec * 1000 : 5000);
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));

        if (::connect(s, ai->ai_addr, static_cast<int>(ai->ai_addrlen)) == 0) {
            break;
        }
        closesocket(s);
        s = INVALID_SOCKET;
    }
    freeaddrinfo(res);

    if (s == INVALID_SOCKET) {
        err = "连接 clamd " + host + ":" + port_str + " 失败";
    }
    return s;
}

ClamScanResult parse_scan_reply(const std::string& resp, bool connected) {
    ClamScanResult r;
    r.available = connected;
    if (!connected) return r;
    if (resp.empty()) {
        r.error = "clamd 无响应";
        r.available = false;
        return r;
    }
    auto found = resp.rfind("FOUND");
    if (found != std::string::npos) {
        r.infected = true;
        auto colon = resp.rfind(": ", found);
        size_t start = (colon == std::string::npos) ? 0 : colon + 2;
        size_t end = found;
        while (end > start && (resp[end - 1] == ' ')) --end;
        r.virus = resp.substr(start, end - start);
    }
    return r;
}

}  // namespace

ClamdClient::ClamdClient(std::string host, int port, int timeout_sec)
    : host_(std::move(host)), port_(port), timeout_sec_(timeout_sec) {}

bool ClamdClient::available() {
    std::string v = version();
    return !v.empty();
}

std::string ClamdClient::version() {
    std::string err;
    SOCKET s = connect_to(host_, port_, timeout_sec_, err);
    if (s == INVALID_SOCKET) return "";
    std::string cmd = "zVERSION";
    if (!send_all(s, cmd.c_str(), cmd.size() + 1, err)) {
        closesocket(s);
        return "";
    }
    std::string resp = recv_response(s, err);
    closesocket(s);
    if (resp.find("ERROR") != std::string::npos) return "";
    return resp;
}

bool ClamdClient::reload() {
    std::string err;
    SOCKET s = connect_to(host_, port_, timeout_sec_, err);
    if (s == INVALID_SOCKET) return false;
    std::string cmd = "zRELOAD";
    bool ok = send_all(s, cmd.c_str(), cmd.size() + 1, err);
    std::string resp;
    if (ok) resp = recv_response(s, err);
    closesocket(s);
    return ok && (resp.find("RELOADING") != std::string::npos ||
                  resp.find("OK") != std::string::npos);
}

ClamScanResult ClamdClient::scan_file(const std::string& path) const {
    ClamScanResult r;
    std::string err;

    // 窄 ifstream 在 Windows 上按 ANSI 代码页解释路径：中文文件名会打开失败，
    // 于是表现成"ClamAV 扫不了"而不是"文件有问题"。
    // 用 C++17 标准的 fs::path 重载（Windows 上 path 内部就是宽字符，走宽字符 open）。
    std::ifstream in(std::filesystem::path(aiutil::to_wide_path(path)), std::ios::binary);
    if (!in) {
        r.error = "无法打开文件: " + path;
        return r;
    }

    SOCKET s = connect_to(host_, port_, timeout_sec_, err);
    if (s == INVALID_SOCKET) {
        r.error = err;
        return r;
    }

    std::string cmd = "zINSTREAM";
    if (!send_all(s, cmd.c_str(), cmd.size() + 1, err)) {
        closesocket(s);
        r.error = err;
        return r;
    }

    std::vector<char> buf(1 << 16);
    bool send_ok = true;
    while (in) {
        in.read(buf.data(), static_cast<std::streamsize>(buf.size()));
        std::streamsize n = in.gcount();
        if (n <= 0) break;
        uint32_t be = htonl(static_cast<uint32_t>(n));
        if (!send_all(s, &be, 4, err) || !send_all(s, buf.data(), static_cast<size_t>(n), err)) {
            send_ok = false;
            break;
        }
    }
    if (send_ok) {
        uint32_t zero = 0;
        send_ok = send_all(s, &zero, 4, err);
    }

    if (!send_ok) {
        closesocket(s);
        r.error = err;
        return r;
    }

    std::string resp = recv_response(s, err);
    closesocket(s);

    ClamScanResult parsed = parse_scan_reply(resp, true);
    if (resp.find("ERROR") != std::string::npos && !parsed.infected) {
        parsed.available = false;
        parsed.error = resp;
    }
    return parsed;
}
