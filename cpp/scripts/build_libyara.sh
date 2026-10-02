#!/usr/bin/env bash
# build_libyara.sh - 用 MinGW gcc 手工编译 YARA 4.5.4 为静态库 libyara.a
# 不依赖 Autotools/CMake/Jansson/OpenSSL：
#   - 词法/语法文件已在源码包中预生成（lexer.c/grammar.c/re_*.c）
#   - 哈希用 Windows CNG（-DHAVE_WINCRYPT_H），无需 OpenSSL
#   - 跳过需要 Jansson 的 cuckoo 模块
set -e

export PATH=/mingw64/bin:$PATH

YARA_SRC="${YARA_SRC:-/e/Python/AntierX/third_party/src/yara-4.5.4}"
OUT="${OUT:-/e/Python/AntierX/third_party/dist}"
OBJ="$OUT/obj"
LIB="$OUT/lib"
INC_OUT="$OUT/include"

rm -rf "$OBJ"
mkdir -p "$OBJ" "$LIB" "$INC_OUT"

cd "$YARA_SRC/libyara"

SRCS="
ahocorasick.c
arena.c
atoms.c
base64.c
bitmask.c
compiler.c
exec.c
exefiles.c
filemap.c
grammar.c
hash.c
hex_grammar.c
hex_lexer.c
lexer.c
libyara.c
mem.c
modules.c
modules/console/console.c
modules/dex/dex.c
modules/dotnet/dotnet.c
modules/elf/elf.c
modules/hash/hash.c
modules/math/math.c
modules/macho/macho.c
modules/pe/pe.c
modules/pe/authenticode-parser/authenticode.c
modules/pe/authenticode-parser/helper.c
modules/pe/authenticode-parser/countersignature.c
modules/pe/authenticode-parser/structs.c
modules/pe/authenticode-parser/certificate.c
modules/pe/pe_utils.c
modules/string/string.c
modules/tests/tests.c
modules/time/time.c
notebook.c
object.c
parser.c
proc.c
proc/windows.c
re.c
re_grammar.c
re_lexer.c
rules.c
scan.c
scanner.c
sizedstr.c
stack.c
stopwatch.c
stream.c
strutils.c
threading.c
simple_str.c
tlshc/tlsh_util.c
tlshc/tlsh_impl.c
tlshc/tlsh.c
"

DEFS="-DHAVE_WINCRYPT_H -DUSE_WINDOWS_PROC -DDOTNET_MODULE -DHASH_MODULE \
-DBUCKETS_128 -DCHECKSUM_1B -DNDEBUG -D_CRT_SECURE_NO_WARNINGS -DYR_BUILDING_STATIC_LIB"
INC="-I. -Iinclude -I.."
CFLAGS="-O2 -std=gnu11 -w $DEFS $INC"

OBJS=""
FAIL=0
for s in $SRCS; do
  if [ ! -f "$s" ]; then
    echo "MISSING SOURCE: $s"
    FAIL=1
    continue
  fi
  obj="$OBJ/$(echo "$s" | tr '/' '_').o"
  echo "CC $s"
  gcc $CFLAGS -c "$s" -o "$obj" || { echo "FAILED: $s"; exit 1; }
  OBJS="$OBJS $obj"
done
[ "$FAIL" -eq 0 ] || exit 1

ar rcs "$LIB/libyara.a" $OBJS

# 导出公共头文件
cp -r include/. "$INC_OUT/"

echo "=== libyara.a ==="
ls -l "$LIB/libyara.a"
echo "=== headers ==="
ls "$INC_OUT"
