// ai_tools_process.cpp - AI 工具扩展库：进程/线程/句柄/内存/签名组
// 契约见 ai_tools_ext.h 第一节；共享基础设施见 ai_tools_ext.cpp。
// 审计由 ai_execute_tool 统一完成，本文件不调用 aiext::audit_log。
#include "ai_tools_ext.h"

#include "ai_util.h"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <softpub.h>
#include <wintrust.h>

#include "yara_engine.h"

using nlohmann::json;

namespace {

std::string ERR(const std::string& m) { return "ERROR: " + m; }

std::string to_lower(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

std::string hex_addr(unsigned long long a) {
    char buf[24];
    std::snprintf(buf, sizeof(buf), "0x%llx", a);
    return buf;
}

// ---------------- 安全取参（模型传错类型也不抛异常） ----------------
long long arg_int(const json& a, const char* k, long long def) {
    auto it = a.find(k);
    if (it == a.end() || it->is_null()) return def;
    if (it->is_number_integer()) return it->get<long long>();
    if (it->is_number_unsigned()) return static_cast<long long>(it->get<unsigned long long>());
    if (it->is_number_float()) return static_cast<long long>(it->get<double>());
    if (it->is_boolean()) return it->get<bool>() ? 1 : 0;
    if (it->is_string()) { try { return std::stoll(it->get<std::string>()); } catch (...) { return def; } }
    return def;
}
std::string arg_str(const json& a, const char* k, const std::string& def = "") {
    auto it = a.find(k);
    if (it == a.end() || it->is_null()) return def;
    if (it->is_string()) return it->get<std::string>();
    if (it->is_boolean()) return it->get<bool>() ? "true" : "false";
    if (it->is_number_integer()) return std::to_string(it->get<long long>());
    return def;
}
bool arg_bool(const json& a, const char* k, bool def) {
    auto it = a.find(k);
    if (it == a.end() || it->is_null()) return def;
    if (it->is_boolean()) return it->get<bool>();
    if (it->is_number_integer()) return it->get<long long>() != 0;
    if (it->is_string()) {
        std::string v = to_lower(it->get<std::string>());
        return v == "true" || v == "1" || v == "yes";
    }
    return def;
}

// ---------------- ntdll 动态函数 ----------------
template <typename T>
T nt_fn(const char* name) {
    static HMODULE nt = GetModuleHandleW(L"ntdll.dll");
    if (!nt) return nullptr;
    return reinterpret_cast<T>(reinterpret_cast<void*>(GetProcAddress(nt, name)));
}

// 读内存/线程信息用的进程句柄：优先完整权限，受限环境回退 LIMITED
HANDLE open_process_read(DWORD pid) {
    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!h) h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    return h;
}

using NtQueryInformationProcessFn = LONG(WINAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
using NtQueryInformationThreadFn = LONG(WINAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
using NtQuerySystemInformationFn = LONG(WINAPI*)(ULONG, PVOID, ULONG, PULONG);
using NtQueryObjectFn = LONG(WINAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
using NtSuspendResumeFn = LONG(WINAPI*)(HANDLE);

// ---------------- 进程表 ----------------
struct ProcRow {
    DWORD pid = 0;
    DWORD ppid = 0;
    std::string name;
};

std::vector<ProcRow> snapshot_processes() {
    std::vector<ProcRow> rows;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return rows;
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            ProcRow r;
            r.pid = pe.th32ProcessID;
            r.ppid = pe.th32ParentProcessID;
            r.name = aiutil::to_utf8(pe.szExeFile);
            rows.push_back(r);
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return rows;
}

std::string process_image_path(DWORD pid) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return "";
    wchar_t buf[MAX_PATH * 2]{};
    DWORD n = MAX_PATH * 2;
    std::string out;
    if (QueryFullProcessImageNameW(h, 0, buf, &n)) out = aiutil::to_utf8(std::wstring(buf, n));
    CloseHandle(h);
    return out;
}

// ---------------- PEB / 命令行 / 环境变量 ----------------
bool read_mem(HANDLE h, unsigned long long addr, void* buf, size_t len) {
    if (!addr || !len) return false;
    SIZE_T got = 0;
    return ReadProcessMemory(h, reinterpret_cast<LPCVOID>(addr), buf, len, &got) && got == len;
}

// 读 UNICODE_STRING（is64 决定指针宽度），返回 UTF-8；失败返回空串
std::string read_unicode_string(HANDLE h, unsigned long long us_addr, bool is64, size_t max_chars) {
    if (!us_addr) return "";
    unsigned short len = 0;
    if (!read_mem(h, us_addr, &len, sizeof(len))) return "";
    if (!len || len > max_chars * 2) return "";
    unsigned long long buf_addr = 0;
    if (!read_mem(h, us_addr + (is64 ? 8 : 4), &buf_addr, is64 ? 8 : 4)) return "";
    std::vector<wchar_t> w(len / 2 + 1, L'\0');
    if (!read_mem(h, buf_addr, w.data(), len)) return "";
    return aiutil::to_utf8(std::wstring(w.data(), len / 2));
}

struct ProcParams {
    bool ok = false;
    std::string image_path;
    std::string command_line;
    std::string current_dir;
    unsigned long long env_addr = 0;
};

// 读取目标进程的 ProcessParameters；自动处理 x64 与 WOW64(32位) 两种布局
ProcParams read_proc_params(HANDLE h) {
    ProcParams out;
    auto ntqip = nt_fn<NtQueryInformationProcessFn>("NtQueryInformationProcess");
    if (!ntqip) return out;

    // 目标是否 32 位（WOW64）
    BOOL wow64 = FALSE;
    IsWow64Process(h, &wow64);
    bool is64 = !wow64;

    unsigned long long peb = 0;
    if (is64) {
        struct { unsigned long exit; unsigned long pad; void* peb; void* affinity; } pbi{};
        if (ntqip(h, 0 /*ProcessBasicInformation*/, &pbi, sizeof(pbi), nullptr) != 0) return out;
        peb = reinterpret_cast<unsigned long long>(pbi.peb);
    } else {
        if (ntqip(h, 26 /*ProcessWow64Information*/, &peb, sizeof(peb), nullptr) != 0) return out;
    }
    if (!peb) return out;

    unsigned long long params = 0;
    if (!read_mem(h, peb + (is64 ? 0x20 : 0x10), &params, is64 ? 8 : 4) || !params) return out;

    // x64 偏移: DosPath 0x38 ImagePathName 0x60 CommandLine 0x70 Environment 0x80
    // 32位偏移: DosPath 0x24 ImagePathName 0x38 CommandLine 0x40 Environment 0x48
    out.image_path = read_unicode_string(h, params + (is64 ? 0x60 : 0x38), is64, 4096);
    out.command_line = read_unicode_string(h, params + (is64 ? 0x70 : 0x40), is64, 16384);
    out.current_dir = read_unicode_string(h, params + (is64 ? 0x38 : 0x24), is64, 4096);
    if (!read_mem(h, params + (is64 ? 0x80 : 0x48), &out.env_addr, is64 ? 8 : 4)) out.env_addr = 0;
    out.ok = true;
    return out;
}

// ---------------- 令牌信息（用户/完整性级别/提权） ----------------
json token_details(HANDLE h) {
    json out;
    HANDLE tok = nullptr;
    if (!OpenProcessToken(h, TOKEN_QUERY, &tok) || !tok) return out;

    // 用户
    DWORD len = 0;
    GetTokenInformation(tok, TokenUser, nullptr, 0, &len);
    if (len && len < 65536) {
        std::vector<unsigned char> buf(len);
        if (GetTokenInformation(tok, TokenUser, buf.data(), len, &len)) {
            auto* tu = reinterpret_cast<TOKEN_USER*>(buf.data());
            wchar_t name[256]{}, domain[256]{};
            DWORD nl = 256, dl = 256;
            SID_NAME_USE use = SidTypeUnknown;
            if (LookupAccountSidW(nullptr, tu->User.Sid, name, &nl, domain, &dl, &use)) {
                out["user"] = aiutil::to_utf8(name);
                out["domain"] = aiutil::to_utf8(domain);
            }
        }
    }
    // 完整性级别（TokenIntegrityLevel = 25）
    len = 0;
    GetTokenInformation(tok, (TOKEN_INFORMATION_CLASS)25, nullptr, 0, &len);
    if (len && len < 65536) {
        std::vector<unsigned char> buf(len);
        if (GetTokenInformation(tok, (TOKEN_INFORMATION_CLASS)25, buf.data(), len, &len)) {
            auto* ml = reinterpret_cast<TOKEN_MANDATORY_LABEL*>(buf.data());
            UCHAR cnt = *GetSidSubAuthorityCount(ml->Label.Sid);
            if (cnt > 0) {
                DWORD rid = *GetSidSubAuthority(ml->Label.Sid, cnt - 1);
                out["integrity_rid"] = rid;
                std::string name;
                if (rid < 0x1000) name = "untrusted";
                else if (rid < 0x2000) name = "low";
                else if (rid < 0x3000) name = "medium";
                else if (rid < 0x4000) name = "high";
                else name = "system";
                out["integrity"] = "S-1-16-" + std::to_string(rid) + " (" + name + ")";
            }
        }
    }
    // 提权（TokenElevation = 20）
    TOKEN_ELEVATION elev{};
    DWORD el = 0;
    if (GetTokenInformation(tok, (TOKEN_INFORMATION_CLASS)20, &elev, sizeof(elev), &el) && el)
        out["is_elevated"] = elev.TokenIsElevated != 0;

    CloseHandle(tok);
    return out;
}

// ---------------- 线程起始地址 ----------------
struct ModuleRange {
    std::string name;
    unsigned long long base;
    unsigned long long size;
};

std::vector<ModuleRange> collect_modules(DWORD pid) {
    std::vector<ModuleRange> out;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return out;
    MODULEENTRY32W me{};
    me.dwSize = sizeof(me);
    if (Module32FirstW(snap, &me)) {
        do {
            ModuleRange r;
            r.name = aiutil::to_utf8(me.szModule);
            r.base = reinterpret_cast<unsigned long long>(me.modBaseAddr);
            r.size = me.modBaseSize;
            out.push_back(r);
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    return out;
}

std::string module_at(const std::vector<ModuleRange>& mods, unsigned long long addr) {
    for (const auto& m : mods) {
        if (addr >= m.base && addr < m.base + m.size) return m.name;
    }
    return "";
}

// 判断起始地址的内存属性：返回 {in_image, backed_by, protect}
json classify_address(HANDLE h, const std::vector<ModuleRange>& mods, unsigned long long addr) {
    json out;
    std::string mod = module_at(mods, addr);
    out["module"] = mod.empty() ? json(nullptr) : json(mod);
    out["in_image"] = !mod.empty();

    MEMORY_BASIC_INFORMATION mbi{};
    std::string backed = "unknown";
    if (VirtualQueryEx(h, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.Type & MEM_IMAGE) backed = "image";
        else if (mbi.Type & MEM_MAPPED) backed = "mapped";
        else if (mbi.Type & MEM_PRIVATE) backed = "private";
        out["protect"] = mbi.Protect;
    }
    if (!mod.empty()) backed = "image";
    out["backed_by"] = backed;
    unsigned long protect = out.value("protect", 0);
    bool exec = (protect & 0xF0) != 0;  // PAGE_EXECUTE_* 家族
    out["suspicious"] = (!out["in_image"].get<bool>()) && exec && backed != "unknown";
    return out;
}

unsigned long long thread_start_address(HANDLE h_thread) {
    auto fn = nt_fn<NtQueryInformationThreadFn>("NtQueryInformationThread");
    if (!fn) return 0;
    unsigned long long addr = 0;
    if (fn(h_thread, 9 /*ThreadQuerySetWin32StartAddress*/, &addr, sizeof(addr), nullptr) != 0)
        return 0;
    return addr;
}

// ---------------- 句柄枚举 ----------------
struct HandleEntryEx {
    void* object;
    unsigned long long pid;
    unsigned long long handle;
    unsigned long granted;
    unsigned short backtrace;
    unsigned short type_index;
    unsigned long attributes;
    unsigned long reserved;
};

std::string query_object_type(HANDLE obj) {
    auto fn = nt_fn<NtQueryObjectFn>("NtQueryObject");
    if (!fn) return "";
    std::vector<unsigned char> buf(1024);
    ULONG needed = 0;
    LONG rc = fn(obj, 2 /*ObjectTypeInformation*/, buf.data(), static_cast<ULONG>(buf.size()), &needed);
    if (rc == static_cast<LONG>(0xC0000004) /*STATUS_INFO_LENGTH_MISMATCH*/ && needed > buf.size()) {
        buf.resize(needed + 256);
        rc = fn(obj, 2, buf.data(), static_cast<ULONG>(buf.size()), &needed);
    }
    if (rc != 0 || buf.size() < 16) return "";
    unsigned short len = *reinterpret_cast<unsigned short*>(buf.data());
    void* ptr = *reinterpret_cast<void**>(buf.data() + 8);
    if (!len || !ptr) return "";
    char* base = reinterpret_cast<char*>(buf.data());
    char* p = reinterpret_cast<char*>(ptr);
    if (p < base || p + len > base + buf.size()) return "";
    return aiutil::to_utf8(std::wstring(reinterpret_cast<wchar_t*>(p), len / 2));
}

/*
 * ---------------- 句柄名字解析：单 worker + 队列（第 3 层） ----------------
 *
 * 名字解析可能卡在第三方文件系统过滤驱动里（共享目录 / UWF / 网络重定向器）。
 * 绝不能"一个句柄起一个线程"——那样被卡住的线程会在驱动里堆积，最终把进程拖死。
 * 这里全进程只有一个 worker 线程：
 *   - 句柄所有权交给 worker，由它负责关闭（调用方超时也不能关，否则 worker 会用野句柄）；
 *   - 调用方只等固定时长，超时就放弃该项（worker 会继续卡着，但只有一个线程）；
 *   - worker 长时间没有任何进展（last_progress 过旧）时拒绝再排队，避免任务堆积；
 *     一旦它从驱动里返回，进展时间刷新，解析能力自动恢复。
 */
struct NameJob {
    HANDLE handle = nullptr;   // worker 负责 CloseHandle
    std::atomic<bool> done{false};
    std::wstring name;         // 仅 worker 写；调用方在 done 之后读
};

struct NameWorkerState {
    std::mutex mu;
    std::condition_variable cv;
    std::deque<std::shared_ptr<NameJob>> queue;
    std::atomic<long long> last_progress_ms{0};
    std::atomic<long long> completed{0};
    std::atomic<long long> timeouts{0};
};

long long steady_ms() {
    return static_cast<long long>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                      std::chrono::steady_clock::now().time_since_epoch())
                                      .count());
}

std::shared_ptr<NameWorkerState>* name_worker_slot() {
    static std::shared_ptr<NameWorkerState> st;   // 为空表示 worker 还没启动过
    return &st;
}

std::shared_ptr<NameWorkerState> name_worker_state() {
    auto* slot = name_worker_slot();
    if (*slot) return *slot;
    static std::once_flag once;
    std::call_once(once, [slot] {
        auto st = std::make_shared<NameWorkerState>();
        st->last_progress_ms.store(steady_ms());
        std::thread([st] {
            for (;;) {
                std::shared_ptr<NameJob> job;
                {
                    std::unique_lock<std::mutex> lk(st->mu);
                    st->cv.wait(lk, [&] { return !st->queue.empty(); });
                    job = st->queue.front();
                    st->queue.pop_front();
                }
                wchar_t buf[2048];
                DWORD n = GetFinalPathNameByHandleW(job->handle, buf, 2048, 0);
                if (n > 0 && n < 2048) job->name.assign(buf, n);
                CloseHandle(job->handle);
                job->done.store(true);
                st->completed.fetch_add(1);
                st->last_progress_ms.store(steady_ms());
            }
        }).detach();
        *slot = st;
    });
    return *slot;
}

// 只读统计：不做名字解析时不要因为读诊断而把 worker 线程拉起来
long long name_worker_timeouts() {
    auto* slot = name_worker_slot();
    return *slot ? (*slot)->timeouts.load() : 0;
}

/*
 * 解析一个（已复制的）句柄的名字。句柄所有权移交给 worker：
 * 无论返回 true/false，调用方都**不要**再 CloseHandle(dup)。
 * 返回 true 表示拿到结果（out 可能为空串 = 该对象确实没有名字）。
 */
bool resolve_handle_name(HANDLE dup, long long wait_ms, std::string* out, bool* timed_out) {
    auto st = name_worker_state();
    if (timed_out) *timed_out = false;
    const long long staleness_limit = std::max<long long>(2000, wait_ms * 2);
    if (steady_ms() - st->last_progress_ms.load() > staleness_limit) {
        CloseHandle(dup);   // worker 卡住了：本次放弃，句柄自己关
        if (timed_out) *timed_out = true;
        return false;
    }

    auto job = std::make_shared<NameJob>();
    job->handle = dup;
    {
        std::lock_guard<std::mutex> lk(st->mu);
        if (st->queue.size() >= 4) {   // 排队堆积同样说明 worker 卡着
            CloseHandle(job->handle);
            if (timed_out) *timed_out = true;
            return false;
        }
        st->queue.push_back(job);
    }
    st->cv.notify_one();

    const long long deadline = steady_ms() + std::max<long long>(50, wait_ms);
    while (!job->done.load()) {
        if (steady_ms() > deadline) {
            st->timeouts.fetch_add(1);
            if (timed_out) *timed_out = true;
            return false;   // 句柄仍归 worker，等它从驱动返回后自行关闭
        }
        Sleep(5);
    }
    std::wstring w = job->name;
    if (w.rfind(L"\\\\?\\", 0) == 0) w = w.substr(4);
    *out = w.empty() ? std::string() : aiutil::to_utf8(w);
    return true;
}

/*
 * ---------------- 目标进程身份指纹（第 4 层） ----------------
 * 看门狗样本会在宿主被杀后立刻拉起新进程。仅凭 PID 会张冠李戴，所以记录
 * "创建时间"作为身份指纹，并在结束前重新按 PID 打开比对一次。
 */
struct TargetIdentity {
    unsigned long long created = 0;
    std::string name;
    bool alive = false;
    bool valid = false;
};

TargetIdentity target_identity(HANDLE h) {
    TargetIdentity id;
    FILETIME c{}, e{}, k{}, u{};
    if (GetProcessTimes(h, &c, &e, &k, &u)) {
        id.created = (static_cast<unsigned long long>(c.dwHighDateTime) << 32) | c.dwLowDateTime;
        id.valid = true;
    }
    wchar_t buf[MAX_PATH * 2]{};
    DWORD n = MAX_PATH * 2;
    if (QueryFullProcessImageNameW(h, 0, buf, &n))
        id.name = aiutil::to_utf8(std::wstring(buf, n));
    id.alive = (WaitForSingleObject(h, 0) == WAIT_TIMEOUT);
    return id;
}

// 按 PID 重新打开并比对创建时间：不同说明该 PID 已被复用（宿主被替换）
bool pid_now_belongs_to_other(DWORD pid, unsigned long long expect_created) {
    if (!expect_created) return false;
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return false;   // 打不开：多半是已退出，由 target_died 表达
    FILETIME c{}, e{}, k{}, u{};
    const bool ok = GetProcessTimes(h, &c, &e, &k, &u) != 0;
    CloseHandle(h);
    if (!ok) return false;
    const unsigned long long created =
        (static_cast<unsigned long long>(c.dwHighDateTime) << 32) | c.dwLowDateTime;
    return created != expect_created;
}

// 目标进程中途失效时给调用方的说明（半成品结果必须讲清楚为什么可能不完整）
std::string target_warning(bool alive, bool reused) {
    if (reused)
        return "目标 PID 已被复用（创建时间与开始取证时不一致）：原进程已不在，"
               "当前结果来自句柄表快照，可能不完整或不属于原进程。"
               "请用命令行/模块特征重新定位后再取证。";
    if (!alive)
        return "目标进程在取证期间已退出/被杀（看门狗场景常见）：这是退出前的快照，"
               "可能不完整；PID 可能已被复用，建议重新定位当前进程"
               "（get_process_tree / list_process_modules）后再取证。";
    return "";
}

}  // namespace

namespace aiext {

std::string t_get_process_tree(const json& args, AiContext&) {
    long long pid = arg_int(args, "pid", 0);
    int depth = static_cast<int>(arg_int(args, "depth", 3));
    int limit = static_cast<int>(arg_int(args, "limit", 200));
    depth = std::min(std::max(depth, 0), 8);
    limit = std::min(std::max(limit, 1), 2000);
    if (pid <= 0) return ERR("pid 无效");

    std::vector<ProcRow> rows = snapshot_processes();
    std::map<DWORD, std::vector<size_t>> children;
    bool found = false;
    for (size_t i = 0; i < rows.size(); ++i) {
        children[rows[i].ppid].push_back(i);
        if (rows[i].pid == static_cast<DWORD>(pid)) found = true;
    }
    if (!found) return ERR("进程不存在 PID=" + std::to_string(pid));

    int count = 0;
    bool truncated = false;
    std::function<json(size_t, int)> build = [&](size_t idx, int d) -> json {
        json node = {{"pid", rows[idx].pid},
                     {"ppid", rows[idx].ppid},
                     {"name", rows[idx].name},
                     {"depth", d}};
        node["children"] = json::array();
        if (d < depth) {
            auto it = children.find(rows[idx].pid);
            if (it != children.end()) {
                for (size_t ci : it->second) {
                    if (count >= limit) { truncated = true; break; }
                    ++count;
                    node["children"].push_back(build(ci, d + 1));
                }
            }
        }
        return node;
    };

    size_t root_idx = 0;
    for (size_t i = 0; i < rows.size(); ++i)
        if (rows[i].pid == static_cast<DWORD>(pid)) { root_idx = i; break; }
    ++count;
    json tree = build(root_idx, 0);

    json out = {{"root", pid}, {"count", count}, {"truncated", truncated}, {"tree", json::array()}};
    out["tree"].push_back(tree);
    return aiutil::dump_json(out);
}

std::string t_get_parent_chain(const json& args, AiContext&) {
    long long pid = arg_int(args, "pid", 0);
    int limit = static_cast<int>(arg_int(args, "limit", 16));
    limit = std::min(std::max(limit, 1), 64);
    if (pid <= 0) return ERR("pid 无效");

    std::vector<ProcRow> rows = snapshot_processes();
    std::map<DWORD, ProcRow> by_pid;
    for (const auto& r : rows) by_pid[r.pid] = r;

    json chain = json::array();
    DWORD cur = static_cast<DWORD>(pid);
    for (int i = 0; i < limit; ++i) {
        auto it = by_pid.find(cur);
        if (it == by_pid.end()) break;
        chain.push_back({{"pid", it->second.pid},
                         {"ppid", it->second.ppid},
                         {"name", it->second.name}});
        DWORD next = it->second.ppid;
        if (next == cur || next == 0) {
            if (next != 0) {
                auto nit = by_pid.find(next);
                if (nit != by_pid.end())
                    chain.push_back({{"pid", nit->second.pid}, {"ppid", nit->second.ppid},
                                     {"name", nit->second.name}});
            }
            break;
        }
        cur = next;
    }
    if (chain.empty()) return ERR("进程不存在 PID=" + std::to_string(pid));
    json out = {{"chain", chain}, {"depth", chain.size()}};
    return aiutil::dump_json(out);
}

std::string t_get_process_commandline(const json& args, AiContext&) {
    long long pid = arg_int(args, "pid", 0);
    if (pid <= 0) return ERR("pid 无效");

    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE,
                           static_cast<DWORD>(pid));
    if (!h)
        h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE,
                        static_cast<DWORD>(pid));  // 部分权限下回退
    if (!h) return ERR("无法打开进程 PID=" + std::to_string(pid) +
                       "（错误 " + std::to_string(GetLastError()) + "，可能需要管理员或进程已退出）");

    ProcParams pp = read_proc_params(h);
    BOOL wow64 = FALSE;
    IsWow64Process(h, &wow64);
    json tok = token_details(h);

    std::string exe = process_image_path(static_cast<DWORD>(pid));
    std::string layout = "unverified";
    if (pp.ok && !pp.image_path.empty() && !exe.empty()) {
        // 宽松自校验：文件名部分一致即认为 PEB 布局正确
        auto base_of = [](const std::string& p) {
            size_t pos = p.find_last_of("\\/");
            return pos == std::string::npos ? to_lower(p) : to_lower(p.substr(pos + 1));
        };
        if (base_of(pp.image_path) == base_of(exe)) layout = "verified";
    }

    json out = {{"pid", pid},
                {"exe", exe.empty() ? json(nullptr) : json(exe)},
                {"commandline", pp.command_line.empty() ? json(nullptr) : json(pp.command_line)},
                {"current_dir", pp.current_dir.empty() ? json(nullptr) : json(pp.current_dir)},
                {"wow64", wow64 != FALSE},
                {"peb_layout", layout}};
    for (auto& kv : tok.items()) out[kv.key()] = kv.value();
    CloseHandle(h);
    return aiutil::dump_json(out);
}

std::string t_get_process_env(const json& args, AiContext&) {
    long long pid = arg_int(args, "pid", 0);
    int limit = static_cast<int>(arg_int(args, "limit", 200));
    limit = std::min(std::max(limit, 1), 2000);
    if (pid <= 0) return ERR("pid 无效");

    HANDLE h = open_process_read(static_cast<DWORD>(pid));
    if (!h) return ERR("无法打开进程 PID=" + std::to_string(pid) +
                       "（错误 " + std::to_string(GetLastError()) + "）");
    ProcParams pp = read_proc_params(h);
    if (!pp.ok || !pp.env_addr) {
        CloseHandle(h);
        return ERR("读不到环境变量块（PEB 不可读，可能需要管理员或进程已退出）");
    }

    // 分块读环境块，直到双 NUL
    std::vector<wchar_t> block;
    block.reserve(4096);
    bool double_nul = false;
    const size_t kMax = 1024 * 1024;
    for (size_t off = 0; off < kMax; off += 4096) {
        std::vector<wchar_t> chunk(4096, L'\0');
        SIZE_T got = 0;
        if (!ReadProcessMemory(h, reinterpret_cast<LPCVOID>(pp.env_addr + off * 2),
                               chunk.data(), chunk.size() * 2, &got))
            break;
        size_t chars = got / 2;
        block.insert(block.end(), chunk.begin(), chunk.begin() + chars);
        for (size_t i = 1; i < block.size(); ++i) {
            if (block[i] == 0 && block[i - 1] == 0) { double_nul = true; break; }
        }
        if (double_nul || chars == 0) break;
    }
    // 解析 KEY=VALUE
    json env = json::object();
    int count = 0;
    bool truncated = false;
    size_t i = 0;
    while (i < block.size() && count < limit) {
        std::wstring key;
        while (i < block.size() && block[i] != L'=' && block[i] != 0) { key += block[i]; ++i; }
        if (i < block.size() && block[i] == L'=') {
            ++i;
            std::wstring val;
            while (i < block.size() && block[i] != 0) { val += block[i]; ++i; }
            std::string k = aiutil::to_utf8(key);
            if (!k.empty()) { env[k] = aiutil::to_utf8(val); ++count; }
        }
        while (i < block.size() && block[i] == 0) ++i;
    }
    if (count >= limit) truncated = true;
    CloseHandle(h);
    if (count == 0) return ERR("环境变量块为空或不可读（PID=" + std::to_string(pid) + "）");
    json out = {{"pid", pid}, {"count", count}, {"truncated", truncated}, {"env", env}};
    return aiutil::dump_json(out);
}

std::string t_list_threads(const json& args, AiContext&) {
    long long pid = arg_int(args, "pid", 0);
    int limit = static_cast<int>(arg_int(args, "limit", 200));
    limit = std::min(std::max(limit, 1), 1000);
    if (pid <= 0) return ERR("pid 无效");

    HANDLE h = open_process_read(static_cast<DWORD>(pid));
    if (!h) return ERR("无法打开进程 PID=" + std::to_string(pid) +
                       "（错误 " + std::to_string(GetLastError()) + "）");
    std::vector<ModuleRange> mods = collect_modules(static_cast<DWORD>(pid));

    json threads = json::array();
    int count = 0;
    bool truncated = false;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te{};
        te.dwSize = sizeof(te);
        if (Thread32First(snap, &te)) {
            do {
                if (te.th32OwnerProcessID != static_cast<DWORD>(pid)) continue;
                if (count >= limit) { truncated = true; break; }
                ++count;
                json item = {{"tid", te.th32ThreadID}};
                HANDLE ht = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
                if (!ht) ht = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, te.th32ThreadID);
                if (ht) {
                    unsigned long long addr = thread_start_address(ht);
                    if (addr) {
                        item["start_address"] = hex_addr(addr);
                        json cls = classify_address(h, mods, addr);
                        item["module"] = cls["module"];
                        item["in_image"] = cls["in_image"];
                        item["backed_by"] = cls["backed_by"];
                        item["protect"] = cls["protect"];
                        item["suspicious"] = cls["suspicious"];
                    } else {
                        item["start_address"] = nullptr;
                        item["note"] = "读不到起始地址（权限不足）";
                    }
                    CloseHandle(ht);
                } else {
                    item["start_address"] = nullptr;
                    item["note"] = "OpenThread 失败（权限不足）";
                }
                threads.push_back(item);
            } while (Thread32Next(snap, &te));
        }
        CloseHandle(snap);
    }
    CloseHandle(h);
    if (count == 0) return ERR("进程没有可枚举线程（可能已退出）PID=" + std::to_string(pid));
    json out = {{"pid", pid}, {"count", count}, {"truncated", truncated}, {"threads", threads}};
    return aiutil::dump_json(out);
}

std::string t_get_thread_start_address(const json& args, AiContext&) {
    long long tid = arg_int(args, "tid", 0);
    if (tid <= 0) return ERR("tid 无效");

    // 找到所属 PID
    DWORD owner = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return ERR("无法枚举线程");
    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32ThreadID == static_cast<DWORD>(tid)) { owner = te.th32OwnerProcessID; break; }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    if (!owner) return ERR("线程不存在 TID=" + std::to_string(tid));

    // ThreadQuerySetWin32StartAddress 需要 THREAD_QUERY_INFORMATION
    HANDLE ht = OpenThread(THREAD_QUERY_INFORMATION, FALSE, static_cast<DWORD>(tid));
    if (!ht) ht = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, static_cast<DWORD>(tid));
    if (!ht) return ERR("OpenThread 失败（权限不足）TID=" + std::to_string(tid));
    unsigned long long addr = thread_start_address(ht);
    CloseHandle(ht);
    if (!addr) return ERR("读不到起始地址（权限不足）TID=" + std::to_string(tid));

    HANDLE h = open_process_read(owner);
    std::vector<ModuleRange> mods = collect_modules(owner);
    json cls = classify_address(h, mods, addr);
    if (h) CloseHandle(h);

    json out = {{"tid", tid}, {"pid", owner}, {"start_address", hex_addr(addr)}};
    for (auto& kv : cls.items()) out[kv.key()] = kv.value();
    return aiutil::dump_json(out);
}

/*
 * 句柄枚举。
 *
 * 契约：
 *   1) 必须给出过滤条件（type / name / handle 之一），否则拒绝并说明用法；
 *   2) 只返回符合条件的条目 + 一份很小的按类型计数概览；
 *   3) type="any" 只返回计数概览。
 *
 * 抗"看门狗"设计（目标是：任何情况下都在预算内返回，绝不无限等待）：
 *   - 总预算 budget_ms（默认 5s，可调 1–30s），各阶段都检查预算，超了就带着
 *     已有结果返回并把原因写进 diagnostics.stopped_reason；
 *   - DuplicateHandle 只在"每种 type_index 取一个样本"时发生（几十次量级），
 *     不再对每个句柄复制一次——句柄表剧烈增删时，逐句柄复制会卡在句柄表锁上；
 *   - 名字解析（最可能卡在第三方文件系统过滤驱动里）有单项超时 + 次数上限 +
 *     受总预算约束，超时会统计进 name_timeouts；
 *   - 表大小抖动可通过两次廉价的大小探测量化（churn_bytes），抖动剧烈时提示
 *     调用方改用更稳的证据（list_threads / list_process_modules / 事件流）。
 *
 * 系统句柄表用 SystemExtendedHandleInformation = 64（需要管理员/SeDebugPrivilege）。
 * 曾经错用 62：那不是扩展句柄信息类，返回的 needed 是垃圾值，代码便一路扩容到上限，
 * 最终报「句柄表过大，枚举失败」。布局见 phnt：
 *   { ULONG_PTR NumberOfHandles; ULONG_PTR Reserved; entries[] }
 */
std::string t_list_handles(const json& args, AiContext&) {
    using Clock = std::chrono::steady_clock;
    const auto t_start = Clock::now();
    auto ms_since = [&t_start]() {
        return static_cast<long long>(
            std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - t_start).count());
    };

    long long pid = arg_int(args, "pid", 0);
    int limit = static_cast<int>(arg_int(args, "limit", 200));
    std::string type_filter = to_lower(arg_str(args, "type"));
    std::string name_filter = to_lower(arg_str(args, "name"));
    std::string handle_filter = to_lower(arg_str(args, "handle"));
    long long budget_ms = arg_int(args, "budget_ms", 5000);
    long long name_limit = arg_int(args, "name_limit", 200);
    limit = std::min(std::max(limit, 1), 1000);
    budget_ms = std::min(std::max(budget_ms, 1000LL), 30000LL);
    name_limit = std::min(std::max(name_limit, 1LL), 2000LL);
    if (pid <= 0) return ERR("pid 无效");

    const bool overview_only = (type_filter == "any" || type_filter == "*");
    if (!overview_only && type_filter.empty() && name_filter.empty() && handle_filter.empty())
        return ERR("必须给出过滤条件之一（句柄表可能有上万条，不能整表返回）："
                   "type（对象类型名，支持子串，如 File / Mutant / Key / Section / Event；"
                   "type=\"any\" 只返回按类型的计数概览）、"
                   "name（名字子串，如 \\Device\\ 或 .dll）、"
                   "handle（句柄值，如 0x1a4 或 420）。");

    unsigned long long want_handle = 0;
    bool handle_is_number = false;
    if (!handle_filter.empty()) {
        try {
            size_t idx = 0;
            want_handle = std::stoull(handle_filter, &idx, 0);  // 自动识别 0x 前缀
            handle_is_number = (idx == handle_filter.size());
        } catch (...) {
            handle_is_number = false;
        }
        if (!handle_is_number)
            return ERR("handle 需要是十六进制（0x1a4）或十进制数字，收到: " + handle_filter);
    }

    auto ntqsi = nt_fn<NtQuerySystemInformationFn>("NtQuerySystemInformation");
    if (!ntqsi) return ERR("无法定位 ntdll!NtQuerySystemInformation");

    // 早期存在性检查：PID 不存在就立刻说清楚（不需要管理员，也避免白跑一次全表查询）。
    // 看门狗场景里"宿主已被替换"是最常见的情况，早报比晚报有用。
    {
        HANDLE probe = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                                   static_cast<DWORD>(pid));
        if (!probe) {
            const DWORD e = GetLastError();
            if (e == ERROR_INVALID_PARAMETER)
                return ERR("进程不存在：PID " + std::to_string(pid) +
                           " 无效（可能已退出，或被看门狗替换）。"
                           "请先 get_process_tree / list_processes 重新定位。");
            // 其它错误（如 ACCESS_DENIED）继续往下走，由全表查询给出更准确的权限提示
        } else {
            CloseHandle(probe);
        }
    }

    // ---- 阶段 1：读系统句柄表（有界重试；按 needed 精确扩容）----
    const ULONG kExtendedHandleInfo = 64;
    const size_t kMaxTableBytes = 256u << 20;
    size_t size = 8u << 20;
    std::vector<unsigned char> buf;
    LONG rc = 0;
    ULONG needed = 0;
    bool size_known = false;
    long long snapshot_attempts = 0;
    unsigned long long bytes_first = 0;
    for (; snapshot_attempts < 3; ++snapshot_attempts) {
        buf.assign(size, 0);
        needed = 0;
        rc = ntqsi(kExtendedHandleInfo, buf.data(), static_cast<ULONG>(buf.size()), &needed);
        if (rc == 0) break;
        if (rc == static_cast<LONG>(0xC0000004)) {  // STATUS_INFO_LENGTH_MISMATCH
            if (bytes_first == 0) bytes_first = needed;
            if (needed > size) {
                if (needed > kMaxTableBytes) break;
                size = needed + (1u << 20);
                size_known = true;
            } else {
                // needed 为 0 或比自己还小：说明表在剧烈变化，按当前大小翻倍再试
                size *= 2;
                if (size > kMaxTableBytes) break;
            }
            if (ms_since() > budget_ms / 2) break;   // 表抖动时不把预算耗在重试上
            continue;
        }
        break;
    }
    const long long snapshot_ms = ms_since();

    if (rc != 0) {
        if (rc == static_cast<LONG>(0xC0000022)) {  // STATUS_ACCESS_DENIED
            DWORD handle_count = 0;
            HANDLE hp = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                                    static_cast<DWORD>(pid));
            if (hp) {
                GetProcessHandleCount(hp, &handle_count);
                CloseHandle(hp);
            }
            return ERR("枚举系统句柄表需要管理员权限（STATUS_ACCESS_DENIED）。"
                       "PID " + std::to_string(pid) + " 当前句柄数约 " +
                       std::to_string(handle_count) +
                       "（只取计数不需要管理员）；请以管理员身份运行后再按 type/name/handle 过滤。");
        }
        char code[32];
        std::snprintf(code, sizeof(code), "0x%08lx", static_cast<unsigned long>(rc));
        if (rc == static_cast<LONG>(0xC0000004))
            return ERR(std::string("句柄表在持续变化，") + std::to_string(snapshot_attempts) +
                       " 次尝试都没能取到稳定快照（" +
                       (size_known ? "最后一次内核报需要 " + std::to_string(needed) + " 字节"
                                   : "内核未返回准确大小") +
                       "）。目标进程可能正在被反复创建/销毁句柄；"
                       "建议改用 list_threads / list_process_modules / scan_memory_regions，"
                       "或先 suspend_process 再取证。");
        return ERR(std::string("NtQuerySystemInformation(class 64) 失败，错误码 ") + code);
    }

    // 布局自检：扩展句柄信息 = 8 字节计数 + 8 字节保留 + 条目数组
    size_t header = 2 * sizeof(void*);
    unsigned long long count = *reinterpret_cast<unsigned long long*>(buf.data());
    if (count == 0 || header + count * sizeof(HandleEntryEx) > buf.size()) {
        // 退化尝试：4 字节计数（老布局），仍然做边界检查
        unsigned int small = *reinterpret_cast<unsigned int*>(buf.data());
        if (small > 0 && sizeof(unsigned int) + static_cast<size_t>(small) * sizeof(HandleEntryEx) <=
                             buf.size()) {
            header = sizeof(unsigned int);
            count = small;
        } else {
            return ERR("句柄表解析失败（表头与内核返回的长度不匹配）");
        }
    }
    auto* entries = reinterpret_cast<HandleEntryEx*>(buf.data() + header);

    // ---- 阶段 1b：抖动观测（两次廉价的大小探测，不复制表）----
    unsigned long long churn_bytes = 0;
    bool churn_measured = false;
    if (ms_since() < budget_ms / 2) {
        unsigned char probe[8];
        ULONG n1 = 0, n2 = 0;
        ntqsi(kExtendedHandleInfo, probe, sizeof(probe), &n1);
        ntqsi(kExtendedHandleInfo, probe, sizeof(probe), &n2);
        if (n1 > 0 && n2 > 0) {
            churn_measured = true;
            churn_bytes = (n1 > n2) ? (n1 - n2) : (n2 - n1);
        }
    }
    const long long snapshot_ms2 = ms_since() - snapshot_ms;

    // ---- 阶段 2：按 pid 归类到 type_index（不复制任何句柄）----
    json handles = json::array();
    std::map<unsigned short, long long> index_counts;          // type_index -> 该进程句柄数
    std::map<unsigned short, std::vector<size_t>> index_samples;  // 每类型最多留 3 个样本下标
    long long total_handles = 0;
    for (unsigned long long i = 0; i < count; ++i) {
        if (entries[i].pid != static_cast<unsigned long long>(pid)) continue;
        ++total_handles;
        const unsigned short ti = entries[i].type_index;
        index_counts[ti] += 1;
        auto& samples = index_samples[ti];
        if (samples.size() < 3) samples.push_back(static_cast<size_t>(i));
    }

    HANDLE hproc = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                               static_cast<DWORD>(pid));
    if (!hproc) {
        const DWORD e = GetLastError();
        // PID 已经不存在（看门狗场景：宿主被替换）与权限不足要区分开
        if (e == ERROR_INVALID_PARAMETER) {
            json out = {{"pid", pid}, {"total_handles", total_handles},
                        {"handles", handles},
                        {"partial", true},
                        {"diagnostics",
                         {{"budget_ms", budget_ms},
                          {"elapsed_ms", ms_since()},
                          {"table_entries", static_cast<long long>(count)},
                          {"total_handles_of_pid", total_handles},
                          {"stopped_reason", "target_died"}}}};
            out["note"] = "目标进程已退出（错误 87：PID 已无效，可能已被看门狗替换）。"
                          "上面这些是句柄表里残留的条目；请用命令行/模块特征重新定位当前进程。";
            return aiutil::dump_json(out);
        }
        // 拿不到复制权限时，仍然给出按 type_index 的分布（无需复制句柄）
        json idx_counts = json::object();
        for (const auto& kv : index_counts) idx_counts[std::to_string(kv.first)] = kv.second;
        json out = {{"pid", pid}, {"total_handles", total_handles},
                    {"type_index_counts", idx_counts}, {"handles", handles},
                    {"partial", true},
                    {"diagnostics",
                     {{"budget_ms", budget_ms},
                      {"elapsed_ms", ms_since()},
                      {"snapshot_attempts", snapshot_attempts},
                      {"table_entries", static_cast<long long>(count)},
                      {"total_handles_of_pid", total_handles},
                      {"churn_bytes", churn_measured ? json(churn_bytes) : json(nullptr)},
                      {"stopped_reason", "open_process_failed: 无 PROCESS_DUP_HANDLE"}}}};
        out["note"] = "无法复制目标进程句柄（需要管理员），只能给出按类型索引的计数；"
                      "错误 " + std::to_string(e);
        return aiutil::dump_json(out);
    }

    // 身份指纹：创建时间 + 可执行路径 + 存活状态（看门狗替换宿主时靠它识别）
    const TargetIdentity ident = target_identity(hproc);
    auto alive_now = [&hproc]() { return WaitForSingleObject(hproc, 0) == WAIT_TIMEOUT; };

    // 每类型只复制一个样本解出类型名：复制次数从"每句柄"降到"每类型"
    const auto t_typemap = Clock::now();
    std::map<unsigned short, std::string> type_names;
    long long dup_attempted = 0, dup_failed = 0;
    std::string stopped_reason;
    bool target_died = false;
    for (const auto& kv : index_samples) {
        if (ms_since() > budget_ms * 2 / 3) {
            stopped_reason = "budget_exceeded(type_map)";
            break;
        }
        if (!alive_now()) { target_died = true; stopped_reason = "target_died"; break; }
        std::string resolved;
        for (size_t idx : kv.second) {
            ++dup_attempted;
            HANDLE dup = nullptr;
            if (!DuplicateHandle(hproc, reinterpret_cast<HANDLE>(entries[idx].handle),
                                 GetCurrentProcess(), &dup, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
                ++dup_failed;
                continue;
            }
            resolved = query_object_type(dup);
            CloseHandle(dup);
            if (!resolved.empty()) break;
        }
        type_names[kv.first] = resolved;   // 可能为空（该类型所有样本都打不开）
    }

    // 类型名救援：还有解不出来的类型时，再扫一遍表多取几个样本
    // （现场数据里 type_index 39 对应 169 个句柄，只试 3 个样本不够）
    long long type_rescue_attempts = 0;
    if (!type_names.empty() && ms_since() < budget_ms * 4 / 5) {
        std::map<unsigned short, int> extra_tried;
        for (unsigned long long i = 0; i < count; ++i) {
            if (entries[i].pid != static_cast<unsigned long long>(pid)) continue;
            const unsigned short ti = entries[i].type_index;
            auto it = type_names.find(ti);
            if (it != type_names.end() && !it->second.empty()) continue;   // 已解出
            if (extra_tried[ti] >= 6) continue;
            if (ms_since() > budget_ms * 9 / 10) {
                stopped_reason = "budget_exceeded(type_rescue)";
                break;
            }
            ++extra_tried[ti];
            ++type_rescue_attempts;
            ++dup_attempted;
            HANDLE dup = nullptr;
            if (!DuplicateHandle(hproc, reinterpret_cast<HANDLE>(entries[i].handle),
                                 GetCurrentProcess(), &dup, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
                ++dup_failed;
                continue;
            }
            const std::string nm = query_object_type(dup);
            CloseHandle(dup);
            if (!nm.empty()) type_names[ti] = nm;
        }
    }
    const long long type_map_ms =
        static_cast<long long>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                   Clock::now() - t_typemap).count());

    // 按名字汇总；解不出名字的类型归到 unknown，并把索引列出来
    json counts = json::object();
    json unresolved = json::array();
    {
        std::map<std::string, long long> by_name;
        for (const auto& kv : index_counts) {
            auto it = type_names.find(kv.first);
            const std::string nm = (it != type_names.end()) ? it->second : std::string();
            if (nm.empty()) {
                by_name["unknown"] += kv.second;
                unresolved.push_back(kv.first);
            } else {
                by_name[nm] += kv.second;
            }
        }
        for (const auto& kv : by_name) counts[kv.first] = kv.second;
    }

    // ---- 阶段 3：按过滤条件挑条目（只对需要的句柄做名字解析）----
    const auto t_filter = Clock::now();
    int shown = 0;
    long long matched = 0;
    bool truncated = false;
    long long name_attempts = 0, name_timeouts = 0;
    bool name_budget_hit = false;
    int budget_check_counter = 0;
    // 概览模式不挑条目，直接跳过整表扫描
    for (unsigned long long i = 0; !overview_only && i < count; ++i) {
        if (entries[i].pid != static_cast<unsigned long long>(pid)) continue;
        if (handle_is_number && entries[i].handle != want_handle) continue;

        const unsigned short ti = entries[i].type_index;
        auto tname_it = type_names.find(ti);
        const std::string type = (tname_it != type_names.end() && !tname_it->second.empty())
                                     ? tname_it->second
                                     : std::string("unknown");

        bool type_ok = type_filter.empty() || overview_only ||
                       to_lower(type).find(type_filter) != std::string::npos;
        if (!type_ok) continue;

        std::string name;
        bool name_ok = name_filter.empty();
        if ((!overview_only) && (!name_ok)) {
            if (name_attempts >= name_limit) {
                name_budget_hit = true;
                if (stopped_reason.empty()) stopped_reason = "name_limit_reached";
                break;
            }
            if (++budget_check_counter % 8 == 0) {
                if (!alive_now()) { target_died = true; stopped_reason = "target_died"; break; }
                if (ms_since() > budget_ms) {
                    name_budget_hit = true;
                    stopped_reason = "budget_exceeded(name_scan)";
                    break;
                }
            }
            ++name_attempts;
            HANDLE dup = nullptr;
            if (!DuplicateHandle(hproc, reinterpret_cast<HANDLE>(entries[i].handle),
                                 GetCurrentProcess(), &dup, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
                ++dup_failed;
                continue;
            }
            bool timed_out = false;
            // 句柄所有权交给 worker，这里不再 CloseHandle
            if (resolve_handle_name(dup, 500, &name, &timed_out)) {
                name_ok = to_lower(name).find(name_filter) != std::string::npos;
            } else {
                if (timed_out) ++name_timeouts;
                // worker 卡在驱动里：本轮不再做名字解析（等它恢复）
                if (name_timeouts > 0 && stopped_reason.empty())
                    stopped_reason = "name_worker_stalled";
                name_budget_hit = true;
                break;
            }
        }
        if (overview_only || !name_ok) continue;

        ++matched;
        if (shown >= limit) {
            truncated = true;
            continue;   // 继续统计 matched，但不再收条目
        }
        ++shown;
        json item = {{"handle", hex_addr(entries[i].handle)}, {"type", type}};
        if (!name.empty()) item["name"] = name;
        handles.push_back(item);
    }
    const long long filter_ms = static_cast<long long>(
        std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - t_filter).count());
    const bool alive_at_end = alive_now();
    const bool pid_reused = pid_now_belongs_to_other(static_cast<DWORD>(pid), ident.created);
    CloseHandle(hproc);
    if (!alive_at_end && stopped_reason.empty()) stopped_reason = "target_died";
    if (pid_reused && stopped_reason.empty()) stopped_reason = "pid_reused";
    const bool partial = target_died || !alive_at_end || pid_reused || !stopped_reason.empty();

    json target = {{"pid", pid},
                   {"name", ident.name.empty() ? json(nullptr) : json(ident.name)},
                   {"created", ident.valid ? json(iso_from_filetime(
                                                 static_cast<long long>(ident.created)))
                                           : json(nullptr)},
                   {"alive", alive_at_end},
                   {"pid_reused", pid_reused}};

    json diag = {
        {"budget_ms", budget_ms},
        {"elapsed_ms", ms_since()},
        {"snapshot_ms", snapshot_ms},
        {"churn_probe_ms", snapshot_ms2},
        {"type_map_ms", type_map_ms},
        {"filter_ms", filter_ms},
        {"snapshot_attempts", snapshot_attempts},
        {"table_bytes", static_cast<long long>(size)},
        {"table_bytes_first_report", static_cast<long long>(bytes_first)},
        {"table_entries", static_cast<long long>(count)},
        {"total_handles_of_pid", total_handles},
        {"type_indexes", static_cast<long long>(index_counts.size())},
        {"dup_attempted", dup_attempted},
        {"dup_failed", dup_failed},
        {"type_rescue_attempts", type_rescue_attempts},
        {"name_attempts", name_attempts},
        {"name_timeouts", name_timeouts},
        {"name_worker_total_timeouts", name_worker_timeouts()},
        {"name_limit", name_limit},
        {"unresolved_type_indexes", unresolved},
        {"churn_bytes", churn_measured ? json(churn_bytes) : json(nullptr)},
        {"target_alive_at_end", alive_at_end},
        {"pid_reuse_detected", pid_reused},
        {"stopped_reason", stopped_reason.empty() ? json(nullptr) : json(stopped_reason)}};

    if (overview_only) {
        json out = {{"pid", pid}, {"target", target}, {"total_handles", total_handles},
                    {"type_counts", counts},
                    {"type_indexes", static_cast<long long>(index_counts.size())},
                    {"partial", partial}, {"diagnostics", diag},
                    {"note", "只返回类型计数概览；要看条目请加 type/name/handle 过滤条件"}};
        if (!alive_at_end || pid_reused) out["note"] = target_warning(alive_at_end, pid_reused);
        return aiutil::dump_json(out);
    }

    json out = {{"pid", pid}, {"target", target}, {"total_handles", total_handles},
                {"matched", matched}, {"returned", shown}, {"truncated", truncated},
                {"type_counts", counts}, {"handles", handles}, {"partial", partial},
                {"diagnostics", diag}};
    if (!alive_at_end || pid_reused) {
        out["note"] = target_warning(alive_at_end, pid_reused);
    } else if (matched == 0) {
        out["note"] = name_budget_hit
                          ? "名字解析没跑完（见 diagnostics.stopped_reason）；"
                            "可先用 type=\"any\" 看类型分布，或调大 budget_ms"
                          : "没有符合条件的句柄；可先用 type=\"any\" 看类型分布";
    }
    if (!unresolved.empty()) {
        const std::string extra = "另有 " + std::to_string(unresolved.size()) +
                                  " 种类型名解不出来（样本句柄打不开，见 diagnostics）";
        out["note"] = out.contains("note") ? out["note"].get<std::string>() + "；" + extra : extra;
    }
    return aiutil::dump_json(out);
}

std::string t_scan_memory_regions(const json& args, AiContext& ctx) {
    long long pid = arg_int(args, "pid", 0);
    int max_mb = static_cast<int>(arg_int(args, "max_mb", 32));
    int max_regions = static_cast<int>(arg_int(args, "max_regions", 64));
    bool use_yara = arg_bool(args, "yara", true);
    std::string rules_path = arg_str(args, "rules_path");
    max_mb = std::min(std::max(max_mb, 1), 256);
    max_regions = std::min(std::max(max_regions, 1), 512);
    if (pid <= 0) return ERR("pid 无效");

    HANDLE h = open_process_read(static_cast<DWORD>(pid));
    if (!h) return ERR("无法打开进程 PID=" + std::to_string(pid) +
                       "（错误 " + std::to_string(GetLastError()) + "）");
    std::vector<ModuleRange> mods = collect_modules(static_cast<DWORD>(pid));

    // YARA 规则（可选）
    std::unique_ptr<YaraEngine> yara;
    if (use_yara) {
        std::string rp = rules_path.empty() ? ctx.rules_path : rules_path;
        if (!rp.empty()) yara.reset(new YaraEngine(rp));
    }

    json regions = json::array();
    json matches = json::array();
    int regions_total = 0;
    int exec_private = 0;
    int scanned_regions = 0;
    long long scanned_bytes = 0;
    int skipped = 0;
    bool truncated = false;
    const long long budget = static_cast<long long>(max_mb) * 1024 * 1024;
    const size_t kRegionCap = 8u * 1024 * 1024;

    MEMORY_BASIC_INFORMATION mbi{};
    unsigned long long addr = 0;
    while (VirtualQueryEx(h, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) == sizeof(mbi)) {
        unsigned long long base = reinterpret_cast<unsigned long long>(mbi.BaseAddress);
        unsigned long long next = base + mbi.RegionSize;
        if (next < base) break;  // 地址空间回绕
        addr = next;

        bool exec = (mbi.Protect & 0xF0) != 0 && (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) == 0;
        if (mbi.State != MEM_COMMIT || !exec) continue;
        ++regions_total;

        std::string mod = module_at(mods, base);
        bool in_image = !mod.empty();
        if (!in_image) ++exec_private;
        if (in_image) continue;                        // 只关心无映像支撑的可执行区域
        if (scanned_regions >= max_regions) { ++skipped; continue; }
        if (scanned_bytes + static_cast<long long>(std::min<size_t>(mbi.RegionSize, kRegionCap))
            > budget) {
            ++skipped;
            continue;
        }
        ++scanned_regions;

        size_t want = static_cast<size_t>(std::min<unsigned long long>(mbi.RegionSize, kRegionCap));
        std::vector<unsigned char> data(want);
        SIZE_T got = 0;
        if (!ReadProcessMemory(h, reinterpret_cast<LPCVOID>(base), data.data(), want, &got) ||
            got == 0) {
            --scanned_regions;
            ++skipped;
            continue;
        }
        data.resize(got);
        scanned_bytes += static_cast<long long>(got);

        double entropy = shannon_entropy(data.data(), got);
        std::string backed = (mbi.Type & MEM_MAPPED) ? "mapped" : "private";
        json r = {{"addr", hex_addr(base)}, {"size", got},
                  {"protect", mbi.Protect}, {"backed_by", backed}, {"entropy", entropy}};
        if (yara && yara->available()) {
            std::vector<std::string> hits = yara->scan_memory(data.data(), got);
            if (!hits.empty()) {
                json m = {{"addr", hex_addr(base)}, {"size", got}, {"rules", hits}};
                matches.push_back(m);
                r["yara"] = hits;
            }
        }
        regions.push_back(r);
    }
    CloseHandle(h);

    json out = {{"pid", pid},
                {"regions_total", regions_total},
                {"executable_private", exec_private},
                {"scanned", scanned_bytes},
                {"scanned_regions", scanned_regions},
                {"skipped", skipped},
                {"budget_mb", max_mb},
                {"truncated", truncated},
                {"matches", matches},
                {"regions", regions}};
    return aiutil::dump_json(out);
}

std::string t_suspend_process(const json& args, AiContext& ctx) {
    long long pid = arg_int(args, "pid", 0);
    if (pid <= 4) return ERR("PID=" + std::to_string(pid) + " 是系统保护进程，拒绝操作");
    if (dry_run_requested(args, ctx))
        return aiutil::dump_json(json{{"pid", pid}, {"action", "suspend"},
                                      {"dry_run", true}, {"note", "将挂起进程（不执行）"}});
    auto fn = nt_fn<NtSuspendResumeFn>("NtSuspendProcess");
    if (!fn) return ERR("无法定位 ntdll!NtSuspendProcess");
    HANDLE h = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, static_cast<DWORD>(pid));
    if (!h) return ERR("OpenProcess(PROCESS_SUSPEND_RESUME) 失败（错误 " +
                       std::to_string(GetLastError()) + "，可能需要管理员）");
    LONG rc = fn(h);
    CloseHandle(h);
    if (rc != 0) return ERR("NtSuspendProcess 失败，错误码 " + std::to_string(rc));
    return aiutil::dump_json(json{{"pid", pid}, {"suspended", true}, {"dry_run", false}});
}

std::string t_resume_process(const json& args, AiContext& ctx) {
    long long pid = arg_int(args, "pid", 0);
    if (pid <= 0) return ERR("pid 无效");
    if (dry_run_requested(args, ctx))
        return aiutil::dump_json(json{{"pid", pid}, {"action", "resume"},
                                      {"dry_run", true}, {"note", "将恢复进程（不执行）"}});
    auto fn = nt_fn<NtSuspendResumeFn>("NtResumeProcess");
    if (!fn) return ERR("无法定位 ntdll!NtResumeProcess");
    HANDLE h = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, static_cast<DWORD>(pid));
    if (!h) return ERR("OpenProcess(PROCESS_SUSPEND_RESUME) 失败（错误 " +
                       std::to_string(GetLastError()) + "）");
    LONG rc = fn(h);
    CloseHandle(h);
    if (rc != 0) return ERR("NtResumeProcess 失败，错误码 " + std::to_string(rc));
    return aiutil::dump_json(json{{"pid", pid}, {"resumed", true}, {"dry_run", false}});
}

std::string t_kill_process_tree(const json& args, AiContext& ctx) {
    long long pid = arg_int(args, "pid", 0);
    bool include_self = arg_bool(args, "include_self", true);
    if (pid <= 4) return ERR("PID=" + std::to_string(pid) + " 是系统保护进程，拒绝终止");
    if (pid <= 0) return ERR("pid 无效");

    // 收集全部后代（叶子优先杀，最后杀根，防互守复活）
    std::vector<ProcRow> rows = snapshot_processes();
    std::map<DWORD, std::vector<DWORD>> kids;
    for (const auto& r : rows)
        if (r.ppid != 0) kids[r.ppid].push_back(r.pid);
    std::map<DWORD, int> depth;
    std::vector<DWORD> order;
    std::vector<DWORD> stack{static_cast<DWORD>(pid)};
    depth[static_cast<DWORD>(pid)] = 0;
    while (!stack.empty()) {
        DWORD cur = stack.back();
        stack.pop_back();
        order.push_back(cur);
        auto it = kids.find(cur);
        if (it != kids.end()) {
            for (DWORD c : it->second) {
                if (depth.count(c)) continue;   // 防环
                depth[c] = depth[cur] + 1;
                if (static_cast<int>(depth.size()) > 200) break;  // 树过大截断
                stack.push_back(c);
            }
        }
    }

    if (dry_run_requested(args, ctx)) {
        json list = json::array();
        for (DWORD p : order)
            list.push_back(static_cast<long long>(p));
        return aiutil::dump_json(json{{"pid", pid}, {"count", order.size()},
                                      {"would_kill", list}, {"dry_run", true}});
    }

    json killed = json::array();
    int ok_count = 0;
    // 按深度降序（叶子先杀）
    std::sort(order.begin(), order.end(),
              [&](DWORD a, DWORD b) { return depth[a] > depth[b]; });
    for (DWORD p : order) {
        if (!include_self && p == static_cast<DWORD>(pid)) continue;
        HANDLE h = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, p);
        if (!h) {
            killed.push_back({{"pid", p}, {"ok", false},
                              {"error", "打开失败 " + std::to_string(GetLastError())}});
            continue;
        }
        BOOL ok = TerminateProcess(h, 1);
        WaitForSingleObject(h, 3000);
        CloseHandle(h);
        if (ok) ++ok_count;
        killed.push_back({{"pid", p}, {"ok", ok != FALSE}});
    }
    json out = {{"pid", pid}, {"count", ok_count}, {"killed", killed}, {"dry_run", false}};
    return aiutil::dump_json(out);
}

std::string t_verify_signature(const json& args, AiContext&) {
    std::string path = arg_str(args, "path");
    bool revocation = arg_bool(args, "check_revocation", false);
    if (path.empty()) return ERR("path 为空");
    if (GetFileAttributesW(aiutil::to_wide_sys(path).c_str()) == INVALID_FILE_ATTRIBUTES)
        return ERR("文件不存在: " + path);

    std::wstring wpath = aiutil::to_wide_sys(path);
    WINTRUST_FILE_INFO file_info{};
    file_info.cbStruct = sizeof(file_info);
    file_info.pcwszFilePath = wpath.c_str();

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA data{};
    data.cbStruct = sizeof(data);
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = revocation ? WTD_REVOKE_WHOLECHAIN : WTD_REVOKE_NONE;
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.dwStateAction = WTD_STATEACTION_VERIFY;
    data.pFile = &file_info;

    LONG rc = WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &action, &data);

    std::string status;
    if (rc == 0) status = "有效签名";
    else if (rc == TRUST_E_NOSIGNATURE) {
        // 系统目录里的文件大量使用 catalog 签名；catalog 校验不可用（Win7 常见）时
        // WinVerifyTrust 也会返回 TRUST_E_NOSIGNATURE —— 不等于"没有签名"。
        wchar_t win[MAX_PATH]{};
        std::string root;
        if (GetWindowsDirectoryW(win, MAX_PATH)) root = aiutil::to_utf8(win);
        std::string lower_path = path, lower_root = root;
        for (char& c : lower_path) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        for (char& c : lower_root) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        const bool system_file = !lower_root.empty() && lower_path.rfind(lower_root, 0) == 0;
        status = system_file
            ? "本机无法验证（系统目录文件通常是 catalog 签名，而本机 catalog 校验不可用）"
            : "无签名";
    }
    else if (rc == TRUST_E_PROVIDER_UNKNOWN) status = "签名提供者未知";
    else if (rc == TRUST_E_ACTION_UNKNOWN) status = "签名动作未知";
    else if (rc == TRUST_E_SUBJECT_FORM_UNKNOWN) status = "主体格式不受支持";
    else if (rc == TRUST_E_SUBJECT_NOT_TRUSTED) status = "主体不受信任";
    else if (rc == TRUST_E_EXPLICIT_DISTRUST) status = "签名被显式拒绝";
    else if (rc == CERT_E_EXPIRED) status = "证书已过期";
    else if (rc == CERT_E_VALIDITYPERIODNESTING) status = "证书有效期嵌套无效";
    else if (rc == CERT_E_ROLE) status = "证书角色无效";
    else if (rc == CERT_E_PATHLENCONST) status = "证书链长度超限";
    else if (rc == CERT_E_CRITICAL) status = "证书关键扩展无法处理";
    else if (rc == CERT_E_PURPOSE) status = "证书用途不符";
    else if (rc == static_cast<LONG>(0x800B0104)) status = "颁发者名无效";       // CERT_E_ISSUERNAME
    else if (rc == static_cast<LONG>(0x800B0105)) status = "主体名无效";        // CERT_E_SUBJECTNAME
    else if (rc == CERT_E_UNTRUSTEDROOT) status = "不受信任的根证书";
    else if (rc == CERT_E_CHAINING) status = "证书链构建失败";
    else if (rc == CERT_E_REVOKED) status = "证书已被吊销";
    else if (rc == CERT_E_UNTRUSTEDTESTROOT) status = "不受信任的测试根";
    else if (rc == CERT_E_REVOCATION_FAILURE) status = "吊销检查失败";
    else if (rc == CERT_E_WRONG_USAGE) status = "证书用法错误";
    else if (rc == CRYPT_E_REVOCATION_OFFLINE) status = "吊销检查离线失败（无法访问 CRL/OCSP）";
    else status = "校验失败（代码 " + std::to_string(rc) + "）";

    json out = {{"path", path},
                {"signed", rc == 0 ? json(true)
                                   : (rc == TRUST_E_NOSIGNATURE &&
                                      status.find("本机无法验证") != std::string::npos
                                          ? json(nullptr)   // 未知，不是"未签名"
                                          : json(false))},
                {"status", status},
                {"result_code", static_cast<long long>(rc)},
                {"revocation", revocation ? "wholechain" : "none"}};
    if (out["signed"].is_null()) {
        out["note"] = "判不了：系统目录文件通常是 catalog 签名，本机 catalog 校验不可用。"
                      "需要确认时用 Windows 的「属性 → 数字签名」页或 signtool verify /pa。";
    }

    if (rc == 0 && data.hWVTStateData) {
        CRYPT_PROVIDER_DATA* prov = WTHelperProvDataFromStateData(data.hWVTStateData);
        if (prov) {
            CRYPT_PROVIDER_SGNR* sgnr = WTHelperGetProvSignerFromChain(prov, 0, FALSE, 0);
            // 签名者证书在证书链第 0 项（MinGW 头里 psSigner 是 CMSG_SIGNER_INFO*，无 pSigningCert）
            if (sgnr && sgnr->pasCertChain && sgnr->csCertChain > 0 &&
                sgnr->pasCertChain[0].pCert) {
                PCCERT_CONTEXT cert = sgnr->pasCertChain[0].pCert;
                wchar_t buf[512]{};
                CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, buf, 512);
                if (buf[0]) out["signer"] = aiutil::to_utf8(buf);
                wchar_t ibuf[512]{};
                CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG,
                                   nullptr, ibuf, 512);
                if (ibuf[0]) out["issuer"] = aiutil::to_utf8(ibuf);
                FILETIME ts = sgnr->sftVerifyAsOf;
                out["timestamp"] = iso_from_filetime(
                    (static_cast<long long>(ts.dwHighDateTime) << 32) | ts.dwLowDateTime);
            }
        }
    }

    data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &action, &data);
    return aiutil::dump_json(out);
}

}  // namespace aiext
