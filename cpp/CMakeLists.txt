cmake_minimum_required(VERSION 3.15)
project(avengine_core LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# libyara 由 cpp/scripts/build_libyara.sh 构建，产物在 third_party/dist
set(YARA_DIST "${CMAKE_CURRENT_SOURCE_DIR}/../third_party/dist" CACHE PATH "libyara dist 目录")

add_library(avengine_core SHARED
    src/core.cpp
    src/sha256.cpp
    src/yara_engine.cpp
    src/clamd_client.cpp
    src/monitor.cpp
    src/ai/http_client.cpp
    src/ai/ai_client.cpp
    src/ai/ai_prompts.cpp
    src/ai/ai_collectors.cpp
    src/ai/ai_tools.cpp
    src/ai/ai_tools_ext.cpp
    src/ai/ai_tools_process.cpp
    src/ai/ai_tools_fs.cpp
    src/ai/ai_tools_reg.cpp
    src/ai/ai_tools_net.cpp
    src/ai/ai_tools_logs.cpp
    src/ai/ai_tools_intel.cpp
    src/ai/ai_tools_window.cpp
    src/ai/ai_session.cpp
    src/ai/ai_service.cpp
)

target_include_directories(avengine_core PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/ai"
    "${CMAKE_CURRENT_SOURCE_DIR}/../third_party"
    "${YARA_DIST}/include"
)

target_compile_definitions(avengine_core PRIVATE _WIN32_WINNT=0x0601)

target_link_libraries(avengine_core PRIVATE
    "${YARA_DIST}/lib/libyara.a"
    ws2_32
    bcrypt
    advapi32
    psapi
    wevtapi
    winhttp
    iphlpapi
    wintrust
    crypt32
    dnsapi
    ole32
    oleaut32
    shell32
    user32
)

# 静态链接 MinGW 运行时，避免依赖 libstdc++-6.dll / libgcc_s_*.dll
# -s：链接后剥离调试符号（导出表照旧可用，GetProcAddress 不受影响），
#     显著减小 DLL 体积；需要调试时把 -s 去掉重新构建即可。
target_link_options(avengine_core PRIVATE
    -static
    -static-libgcc
    -static-libstdc++
    -s
)

set_target_properties(avengine_core PROPERTIES
    PREFIX ""
    OUTPUT_NAME "avengine_core"
    RUNTIME_OUTPUT_DIRECTORY "${YARA_DIST}/bin"
    LIBRARY_OUTPUT_DIRECTORY "${YARA_DIST}/bin"
)
