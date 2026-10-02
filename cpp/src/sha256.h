// sha256.h - 基于 Windows CNG(BCrypt) 的文件哈希
#pragma once

#include <string>

// 计算文件 SHA256；成功返回小写十六进制，失败返回空串并填充 err。
std::string sha256_file(const std::string& path, std::string& err);
