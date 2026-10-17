// cert_pin.h - 特权服务"钉住"的签名证书（SHA-256 指纹）
//
// 安全要点：服务**不依赖**系统根证书信任，而是把签发我们二进制的证书指纹编译进来做
// 精确比对。这样即使有人在机器根存储里塞了别的自签名根，也无法用它冒充我们的 AV。
//
// 指纹由 scripts/gen_signing_cert.ps1 生成到 service/generated/cert_pin.h。
// 生成文件不存在时（例如刚 clone 下来、还没做一次性证书初始化），指纹为空 ——
// 服务会 **fail-closed**：拒绝一切请求并在审计日志里写明原因。
#pragma once

#if __has_include("generated/cert_pin.h")
#include "generated/cert_pin.h"
#else
// 占位默认值：故意留空 → 未配置指纹 = 不授权任何进程
#define AVPRIV_PINNED_CERT_SHA256 ""
#define AVPRIV_PINNED_CERT_SUBJECT ""
#define AVPRIV_PIN_CONFIGURED 0
#endif

#ifndef AVPRIV_PIN_CONFIGURED
#define AVPRIV_PIN_CONFIGURED 1
#endif
