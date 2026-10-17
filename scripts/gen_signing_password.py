#!/usr/bin/env python3
"""生成 256 位随机密码，供自签名代码签名证书（PFX）使用。

密码写入 service/passwd.txt，默认已存在就不覆盖（避免把已用的证书密码弄丢 → PFX 再也导不出来）。
它属于机密：已在 .gitignore 里排除，并且脚本会尽量收紧 ACL（只留 SYSTEM/Administrators）。

用法：
    python scripts/gen_signing_password.py            # 不存在则生成
    python scripts/gen_signing_password.py --force     # 重新生成（会覆盖，需重新导出证书）
    python scripts/gen_signing_password.py --print     # 同时打印密码（默认只写文件）
"""
from __future__ import annotations

import argparse
import secrets
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUT = PROJECT_ROOT / "service" / "passwd.txt"

# 256 位熵：token_urlsafe(32) 用 32 字节随机 → 43 个 URL-safe 字符
ENTROPY_BYTES = 32


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="生成 256 位随机密码（PFX 用）")
    ap.add_argument("--out", default=str(DEFAULT_OUT), help="输出文件，默认 service/passwd.txt")
    ap.add_argument("--force", action="store_true", help="已存在也覆盖")
    ap.add_argument("--print", dest="show", action="store_true", help="同时在标准输出打印")
    args = ap.parse_args(argv)

    out = Path(args.out)
    if out.exists() and not args.force:
        print(f"[passwd] 已存在，保持不变: {out}")
        print("[passwd] 需要重新生成请加 --force（注意：旧 PFX 将无法再用该密码导出）")
        return 0

    password = secrets.token_urlsafe(ENTROPY_BYTES)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(password + "\n", encoding="utf-8")
    bits = ENTROPY_BYTES * 8
    print(f"[passwd] 已生成 {bits} 位随机密码 → {out}（{len(password)} 字符）")
    print("[passwd] 该文件是机密：勿提交代码库、勿放进发布包")
    if args.show:
        print(password)
    return 0


if __name__ == "__main__":
    sys.exit(main())
