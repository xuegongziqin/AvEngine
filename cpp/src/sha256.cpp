// sha256.cpp - 基于 Windows CNG(BCrypt) 的文件哈希实现
#include "sha256.h"
#include "util.h"

#include <windows.h>
#include <bcrypt.h>

#include <cstdio>
#include <vector>

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

static std::string last_error_message(DWORD code) {
    char buf[256];
    std::snprintf(buf, sizeof(buf), "Windows error %lu", static_cast<unsigned long>(code));
    return buf;
}

std::string sha256_file(const std::string& path, std::string& err) {
    err.clear();

    BCRYPT_ALG_HANDLE alg = nullptr;
    NTSTATUS st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (st != STATUS_SUCCESS || !alg) {
        err = "BCryptOpenAlgorithmProvider 失败 (" + std::to_string(static_cast<long>(st)) + ")";
        return "";
    }

    DWORD obj_size = 0, cb = 0;
    BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH,
                      reinterpret_cast<PUCHAR>(&obj_size), sizeof(obj_size), &cb, 0);
    std::vector<unsigned char> hash_obj(obj_size);

    BCRYPT_HASH_HANDLE hash = nullptr;
    st = BCryptCreateHash(alg, &hash, hash_obj.data(), obj_size, nullptr, 0, 0);
    if (st != STATUS_SUCCESS || !hash) {
        BCryptCloseAlgorithmProvider(alg, 0);
        err = "BCryptCreateHash 失败";
        return "";
    }

    std::FILE* fp = std::fopen(path.c_str(), "rb");
    if (!fp) {
        BCryptDestroyHash(hash);
        BCryptCloseAlgorithmProvider(alg, 0);
        err = "无法打开文件: " + path;
        return "";
    }

    std::vector<unsigned char> buf(1 << 20);
    bool failed = false;
    for (;;) {
        size_t n = std::fread(buf.data(), 1, buf.size(), fp);
        if (n > 0) {
            st = BCryptHashData(hash, buf.data(), static_cast<ULONG>(n), 0);
            if (st != STATUS_SUCCESS) {
                failed = true;
                err = "BCryptHashData 失败";
                break;
            }
        }
        if (n < buf.size()) {
            if (std::ferror(fp)) {
                failed = true;
                err = last_error_message(GetLastError());
            }
            break;
        }
    }
    std::fclose(fp);

    std::string result;
    if (!failed) {
        unsigned char digest[32];
        st = BCryptFinishHash(hash, digest, sizeof(digest), 0);
        if (st == STATUS_SUCCESS) {
            result = to_hex_lower(digest, sizeof(digest));
        } else {
            err = "BCryptFinishHash 失败";
        }
    }

    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);
    return result;
}
