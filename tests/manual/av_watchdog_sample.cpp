/*
 * av_watchdog_sample.cpp - AvEngine 行为测试样本（自复制到 %TEMP% + 双进程互守 + 退出开关）
 * =====================================================================================
 *
 * 【用途】
 *   给自研 AV/EDR 做「行为检出 + 清除能力」测试：
 *     1) 自我复制到 %TEMP%，用随机文件名；
 *     2) 启动两个副本，互相守护：一个被杀掉，另一个会把它拉起来；
 *     3) 退出开关：只要出现 C:\exit.exit（或 %TEMP%\<tag>.exit），所有副本自行退出。
 *   目的是验证你的引擎能不能：
 *     - 通过 Sysmon 文件事件 / 按访问扫描发现「写入 %TEMP% 并立即执行」的行为；
 *     - 把两个互守进程**同时**清掉（只杀一个会看到它被重新拉起）；
 *     - 把 %TEMP% 下的副本文件一起隔离/删除。
 *
 * 【安全边界（刻意为之，别加）】
 *   - 只在 %TEMP% 写文件；全盘唯一额外写入是退出开关 C:\exit.exit 与日志；
 *   - 无持久化：不写注册表 Run、不装服务、不加计划任务、不碰启动目录 —— 重启即消失；
 *   - 无网络：不联网、不下载、不回连；
 *   - 无注入/无提权/无进程镂空/不碰其他进程内存；
 *   - 不做任何免杀与混淆，字符串明文保留（AVB-WATCHDOG-SAMPLE），方便 YARA/ClamAV 命中；
 *   - 有硬上限：稳定在 2 个进程（只有「一个同类都不剩」时才补 1 个）、
 *     每副本重启上限（默认 20）、**整个活动累计创建进程上限**（默认 100）、
 *     每副本运行时长上限（默认 1800 秒）。
 *
 * 【用法】（管理员或普通用户都可；写 C:\ 根目录普通用户默认也可创建文件）
 *   av_watchdog_sample.exe                 复制自身到 %TEMP%，拉起互守副本（最终 2 个进程）
 *   av_watchdog_sample.exe --once          只留 1 个副本、不互守（便于分步测试）
 *   av_watchdog_sample.exe --tag test1     用自定义前缀区分不同测试活动（默认 avb）
 *   av_watchdog_sample.exe --show          子进程带可见窗口（默认 CREATE_NO_WINDOW）
 *   av_watchdog_sample.exe --stop          只放退出开关（等价于手工创建 C:\exit.exit）
 *   av_watchdog_sample.exe --cleanup       放开关 → 等 3 秒 → 兜底强杀 → 删副本文件
 *   av_watchdog_sample.exe --cleanup --purge   连日志一起删
 *
 *   环境变量：
 *     AVB_MAX_RESTARTS=20      每个副本最多重启对端多少次
 *     AVB_MAX_SECONDS=1800     每个副本最长活多久（0 = 不限；建议保留默认，防止忘记收工）
 *     AVB_MAX_TOTAL_SPAWNS=100 整个活动最多创建多少个进程，用完就不再重生
 *
 * 【观测点】
 *   - 进程：%TEMP%\<tag>_xxxxxxxx.exe，正常情况下始终 2 个；
 *   - 日志：%TEMP%\<tag>.log（UTF-16LE，含 BOM），记录 spawn / peer died / respawn / exit；
 *   - Sysmon：EventID 11（%TEMP% 下的新 .exe 文件）+ EventID 1（从 %TEMP% 启动的进程）。
 *     注意 AvEngine 的 scan.monitor_paths 默认只有 C:\Users\Public 与 C:\Temp，
 *     想让它实时抓到本样本，请把 %TEMP%（如 C:\Users\<你>\AppData\Local\Temp）加进 config.yaml。
 *
 * 【构建】
 *   scripts 同目录的 build_av_watchdog_sample.bat，或手工：
 *     g++ -O2 -municode -o av_watchdog_sample.exe av_watchdog_sample.cpp -static
 *     cl /nologo /O2 /EHsc /DUNICODE /D_UNICODE av_watchdog_sample.cpp /link /OUT:av_watchdog_sample.exe
 *
 * 【清理】
 *   av_watchdog_sample.exe --cleanup --purge
 *   或手工：任务管理器结束 %TEMP% 下的 avb_*.exe → 删除 %TEMP%\avb_*.exe、%TEMP%\avb.log、C:\exit.exit
 */

#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>

#include <string>
#include <vector>

namespace {

const wchar_t* kMarker       = L"AVB-WATCHDOG-SAMPLE";  // 明文标记：供 YARA / ClamAV / EDR 识别
const wchar_t* kDefaultTag   = L"avb";
const wchar_t* kExitFile     = L"C:\\exit.exit";        // 用户要求的退出开关
const DWORD    kPollMs       = 1000;                    // 轮询间隔（退出开关 / 对端存活）
const size_t   kMaxInstances = 2;                       // 互守只需要 2 个，多了不给起

// ---------------------------------------------------------------- 基础小工具

std::wstring ExePath()
{
    std::vector<wchar_t> buf(MAX_PATH * 4);
    DWORD n = GetModuleFileNameW(nullptr, buf.data(), (DWORD)buf.size());
    return std::wstring(buf.data(), n);
}

std::wstring TempDir()
{
    std::vector<wchar_t> buf(MAX_PATH * 4);
    DWORD n = GetTempPathW((DWORD)buf.size(), buf.data());
    std::wstring dir(buf.data(), n);
    if (!dir.empty() && dir.back() != L'\\' && dir.back() != L'/')
        dir += L'\\';
    return dir;
}

std::wstring Lower(std::wstring s)
{
    for (wchar_t& c : s)
        c = (wchar_t)towlower(c);
    return s;
}

bool StartsWithI(const std::wstring& s, const std::wstring& prefix)
{
    if (s.size() < prefix.size())
        return false;
    return Lower(s).compare(0, prefix.size(), Lower(prefix)) == 0;
}

bool EndsWithI(const std::wstring& s, const std::wstring& suffix)
{
    if (s.size() < suffix.size())
        return false;
    return Lower(s).compare(s.size() - suffix.size(), suffix.size(), Lower(suffix)) == 0;
}

bool FileExists(const std::wstring& path)
{
    return GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES;
}

std::wstring Pad2(WORD v)
{
    std::wstring s;
    s += (wchar_t)(L'0' + (v / 10) % 10);
    s += (wchar_t)(L'0' + v % 10);
    return s;
}

std::wstring Hex4(unsigned v)
{
    const wchar_t* digits = L"0123456789abcdef";
    std::wstring s;
    s += digits[(v >> 12) & 0xF];
    s += digits[(v >> 8) & 0xF];
    s += digits[(v >> 4) & 0xF];
    s += digits[v & 0xF];
    return s;
}

// 随机文件名：<tag>_<8 位十六进制>.exe
std::wstring RandomName(const std::wstring& tag)
{
    LARGE_INTEGER pc{};
    QueryPerformanceCounter(&pc);
    unsigned seed = (unsigned)(GetTickCount64() ^ (unsigned long long)pc.QuadPart
                               ^ ((unsigned long long)GetCurrentProcessId() << 17));
    return tag + L"_" + Hex4(seed >> 16) + Hex4(seed & 0xFFFF) + L".exe";
}

// 控制台直接写宽字符；被重定向/管道时按 UTF-8 输出，避免出现 UTF-16 乱码
void Echo(const std::wstring& text)
{
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (out && out != INVALID_HANDLE_VALUE && GetConsoleMode(out, &mode)) {
        DWORD written = 0;
        WriteConsoleW(out, text.c_str(), (DWORD)text.size(), &written, nullptr);
        WriteConsoleW(out, L"\n", 1, &written, nullptr);
        return;
    }
    if (!out || out == INVALID_HANDLE_VALUE)
        return;
    int need = WideCharToMultiByte(CP_UTF8, 0, text.c_str(), (int)text.size(),
                                   nullptr, 0, nullptr, nullptr);
    if (need <= 0)
        return;
    std::string utf8((size_t)need, '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.c_str(), (int)text.size(),
                        utf8.data(), need, nullptr, nullptr);
    utf8 += "\r\n";
    DWORD written = 0;
    WriteFile(out, utf8.data(), (DWORD)utf8.size(), &written, nullptr);
}

void Log(const std::wstring& tag, const std::wstring& message, bool echo)
{
    SYSTEMTIME st{};
    GetLocalTime(&st);
    std::wstring line = L"[" + Pad2(st.wHour) + L":" + Pad2(st.wMinute) + L":" + Pad2(st.wSecond) + L"]"
                        L" pid=" + std::to_wstring(GetCurrentProcessId()) + L" " + message;

    std::wstring path = TempDir() + tag + L".log";
    HANDLE h = CreateFileW(path.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        if (GetLastError() != ERROR_ALREADY_EXISTS) {   // 新建时写 UTF-16LE BOM，记事本可直读
            const unsigned char bom[2] = {0xFF, 0xFE};
            WriteFile(h, bom, sizeof(bom), &written, nullptr);
        }
        std::wstring withEol = line + L"\r\n";
        WriteFile(h, withEol.c_str(), (DWORD)(withEol.size() * sizeof(wchar_t)), &written, nullptr);
        CloseHandle(h);
    }
    if (echo)
        Echo(line);
}

// ---------------------------------------------------------------- 生成次数上限（防止进程雪崩）

int ReadCounter(const std::wstring& path)
{
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        return 0;
    char buf[32]{};
    DWORD got = 0;
    ReadFile(h, buf, sizeof(buf) - 1, &got, nullptr);
    CloseHandle(h);
    int value = 0;
    try {
        value = std::stoi(std::string(buf, got));
    } catch (...) {
        value = 0;
    }
    return value;
}

void WriteCounter(const std::wstring& path, int value)
{
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        return;
    std::string text = std::to_string(value);
    DWORD written = 0;
    WriteFile(h, text.c_str(), (DWORD)text.size(), &written, nullptr);
    CloseHandle(h);
}

// 整个活动（含后续重生）累计最多创建多少个进程；超过就不再生，活动自然收敛
bool ReserveSpawn(const std::wstring& tag, int limit)
{
    std::wstring path = TempDir() + tag + L".count";
    int n = ReadCounter(path);
    if (n >= limit)
        return false;
    WriteCounter(path, n + 1);
    return true;
}

// ---------------------------------------------------------------- 退出开关 / 进程发现

bool ExitRequested(const std::wstring& tag)
{
    return FileExists(kExitFile) || FileExists(TempDir() + tag + L".exit");
}

void CreateExitSwitch(const std::wstring& tag)
{
    const std::wstring paths[] = {kExitFile, TempDir() + tag + L".exit"};
    for (const std::wstring& p : paths) {
        HANDLE h = CreateFileW(p.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h != INVALID_HANDLE_VALUE) {
            DWORD written = 0;
            WriteFile(h, kMarker, (DWORD)(wcslen(kMarker) * sizeof(wchar_t)), &written, nullptr);
            CloseHandle(h);
        }
    }
}

struct FoundProc
{
    DWORD pid;
    std::wstring path;
};

// 找出 %TEMP% 下名字形如 <tag>_xxxx.exe 的同类进程（排除自己）
std::vector<FoundProc> CampaignProcesses(const std::wstring& tag)
{
    std::vector<FoundProc> found;
    const std::wstring temp = Lower(TempDir());
    const std::wstring prefix = tag + L"_";
    DWORD self = GetCurrentProcessId();

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return found;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (pe.th32ProcessID == self)
                continue;
            std::wstring name = pe.szExeFile;
            if (!StartsWithI(name, prefix) || !EndsWithI(name, L".exe"))
                continue;

            HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
            if (!h)
                continue;
            std::vector<wchar_t> buf(MAX_PATH * 4);
            DWORD len = (DWORD)buf.size();
            if (QueryFullProcessImageNameW(h, 0, buf.data(), &len)) {
                std::wstring full(buf.data(), len);
                if (StartsWithI(full, temp)) {   // 必须是 %TEMP% 下的副本，避免误伤同名文件
                    FoundProc fp{};
                    fp.pid = pe.th32ProcessID;
                    fp.path = full;
                    found.push_back(fp);
                }
            }
            CloseHandle(h);
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return found;
}

// ---------------------------------------------------------------- 拉起副本

bool SpawnCopy(const std::wstring& exe, const std::wstring& tag, bool show, bool solo,
               DWORD& pidOut, std::wstring& error)
{
    std::wstring cmd = L"\"" + exe + L"\" --child \"" + tag + L"\"";
    if (solo)
        cmd += L" --solo";
    if (show)
        cmd += L" --show";

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    DWORD flags = CREATE_NEW_PROCESS_GROUP | (show ? 0 : CREATE_NO_WINDOW);

    if (!CreateProcessW(exe.c_str(), cmd.data(), nullptr, nullptr, FALSE, flags,
                        nullptr, TempDir().c_str(), &si, &pi)) {
        error = L"CreateProcessW 失败, GetLastError=" + std::to_wstring(GetLastError());
        return false;
    }
    pidOut = pi.dwProcessId;
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return true;
}

// ---------------------------------------------------------------- 子进程主循环

bool IsSelfInTemp(const std::wstring& tag)
{
    std::wstring self = ExePath();
    std::wstring name = self.substr(self.find_last_of(L"\\/") + 1);
    return StartsWithI(self, TempDir()) && StartsWithI(name, tag + L"_") && EndsWithI(name, L".exe");
}

int ChildLoop(const std::wstring& tag, bool show, bool solo, int maxRestarts,
              int maxSeconds, int spawnLimit)
{
    std::wstring self = ExePath();
    ULONGLONG deadline = (maxSeconds > 0)
                             ? GetTickCount64() + (ULONGLONG)maxSeconds * 1000ULL
                             : 0;

    Log(tag, L"child start: " + self + L" (solo=" + (solo ? L"1" : L"0")
                 + L", budget=" + std::to_wstring(maxRestarts)
                 + L", maxSeconds=" + std::to_wstring(maxSeconds)
                 + L", spawnLimit=" + std::to_wstring(spawnLimit) + L")", true);

    int budget = maxRestarts;
    while (true) {
        if (ExitRequested(tag)) {
            Log(tag, L"exit switch detected -> exiting", true);
            break;
        }
        if (deadline != 0 && GetTickCount64() >= deadline) {
            Log(tag, L"time budget reached -> exiting", true);
            break;
        }

        std::vector<FoundProc> peers = CampaignProcesses(tag);
        if (peers.empty()) {
            if (solo) {                     // --once：单副本只守着退出开关，不互守
                Sleep(kPollMs);
                continue;
            }
            if (budget <= 0) {
                Log(tag, L"no peer and restart budget exhausted -> exiting", true);
                break;
            }
            if (!ReserveSpawn(tag, spawnLimit)) {
                Log(tag, L"total spawn limit reached -> exiting", true);
                break;
            }
            DWORD pid = 0;
            std::wstring err;
            if (SpawnCopy(self, tag, show, solo, pid, err)) {
                --budget;
                Log(tag, L"peer missing -> respawned pid=" + std::to_wstring(pid)
                             + L" (budget left=" + std::to_wstring(budget) + L")", true);
            } else {
                Log(tag, L"respawn failed: " + err, true);
                Sleep(2000);
            }
            Sleep(500);
            continue;
        }

        DWORD peerPid = peers[0].pid;
        HANDLE h = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, peerPid);
        if (!h) {
            Sleep(kPollMs);
            continue;
        }
        DWORD wait = WaitForSingleObject(h, kPollMs);
        CloseHandle(h);
        if (wait != WAIT_OBJECT_0)
            continue;

        if (ExitRequested(tag)) {
            Log(tag, L"peer exited and exit switch present -> exiting", true);
            break;
        }

        // 关键：只有「被杀之后一个同类都不剩」才补一个；
        // 若还有别的副本活着，就改看它、不新增进程 —— 否则每杀一个都会多出一个（3→4→5…）。
        std::vector<FoundProc> rest = CampaignProcesses(tag);
        if (!rest.empty()) {
            Log(tag, L"peer pid=" + std::to_wstring(peerPid) + L" died -> now watching pid="
                         + std::to_wstring(rest[0].pid) + L" (no respawn needed)", true);
            Sleep(200);
            continue;
        }
        if (solo) {
            Sleep(kPollMs);
            continue;
        }
        if (budget <= 0) {
            Log(tag, L"peer pid=" + std::to_wstring(peerPid)
                         + L" died, restart budget exhausted -> exiting", true);
            break;
        }
        if (!ReserveSpawn(tag, spawnLimit)) {
            Log(tag, L"total spawn limit reached -> exiting", true);
            break;
        }
        DWORD pid = 0;
        std::wstring err;
        if (SpawnCopy(self, tag, show, solo, pid, err)) {
            --budget;
            Log(tag, L"last peer pid=" + std::to_wstring(peerPid) + L" died -> respawned pid="
                         + std::to_wstring(pid) + L" (budget left=" + std::to_wstring(budget) + L")",
                true);
        } else {
            Log(tag, L"respawn after peer death failed: " + err, true);
        }
        Sleep(300);
    }
    return 0;
}

// ---------------------------------------------------------------- 清理

int DoCleanup(const std::wstring& tag, bool purge)
{
    Echo(L"[cleanup] 先放退出开关，让副本自己退...");
    CreateExitSwitch(tag);
    Sleep(3000);

    std::vector<FoundProc> procs = CampaignProcesses(tag);
    for (const FoundProc& p : procs) {
        HANDLE h = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, p.pid);
        if (!h)
            continue;
        TerminateProcess(h, 0);
        WaitForSingleObject(h, 3000);
        CloseHandle(h);
        Echo(L"[cleanup] killed pid=" + std::to_wstring(p.pid) + L" " + p.path);
    }
    Sleep(500);
    const std::wstring temp = TempDir();
    WIN32_FIND_DATAW fd{};
    HANDLE find = FindFirstFileW((temp + tag + L"_*.exe").c_str(), &fd);
    if (find != INVALID_HANDLE_VALUE) {
        do {
            std::wstring victim = temp + fd.cFileName;
            if (DeleteFileW(victim.c_str()))
                Echo(L"[cleanup] deleted " + victim);
            else
                Echo(L"[cleanup] 删除失败(可能仍被占用) " + victim);
        } while (FindNextFileW(find, &fd));
        FindClose(find);
    }

    DeleteFileW(kExitFile);
    DeleteFileW((temp + tag + L".exit").c_str());
    DeleteFileW((temp + tag + L".count").c_str());
    if (purge) {
        if (DeleteFileW((temp + tag + L".log").c_str()))
            Echo(L"[cleanup] deleted " + temp + tag + L".log");
    } else {
        Echo(L"[cleanup] 日志保留: " + temp + tag + L".log （要一起删就加 --purge）");
    }
    Echo(L"[cleanup] done");
    return 0;
}

void PrintUsage()
{
    Echo(
        L"av_watchdog_sample - AV 行为测试样本（%TEMP% 自复制 + 双进程互守 + 退出开关）\n"
        L"\n"
        L"  --child <tag>      内部参数（由父进程拉起副本时使用）\n"
        L"  --solo             内部参数：单副本，不互守\n"
        L"  --tag <name>       活动前缀，用于区分不同测试，默认 avb\n"
        L"  --once             只留 1 个副本（不互守）\n"
        L"  --show             子进程带可见窗口（默认无窗口）\n"
        L"  --stop             只创建退出开关 C:\\exit.exit\n"
        L"  --cleanup          放开关 -> 等 3 秒 -> 强杀残留 -> 删副本文件\n"
        L"  --purge            配合 --cleanup：连日志一起删\n"
        L"  --help             显示本帮助\n"
        L"\n"
        L"  环境变量 AVB_MAX_RESTARTS=20（每副本重启上限）\n"
        L"           AVB_MAX_SECONDS=1800（每副本最长存活秒数，0=不限）\n"
        L"           AVB_MAX_TOTAL_SPAWNS=100（整个活动累计创建进程上限）\n"
        L"\n"
        L"  退出开关: C:\\exit.exit 或 %TEMP%\\<tag>.exit 出现即全部退出\n"
        L"  日志:     %TEMP%\\<tag>.log\n"
        L"  互守:     稳定 2 个进程；只杀一个会看到它被重新拉起，同时杀掉两个才会停\n");
}

int EnvInt(const wchar_t* name, int fallback)
{
    wchar_t buf[32]{};
    DWORD n = GetEnvironmentVariableW(name, buf, 32);
    if (n == 0 || n >= 32)
        return fallback;
    int v = _wtoi(buf);
    return v < 0 ? fallback : v;
}

}  // namespace

int wmain(int argc, wchar_t** argv)
{
    std::wstring tag = kDefaultTag;
    bool child = false, once = false, show = false, stop = false, cleanup = false;
    bool purge = false, solo = false;

    for (int i = 1; i < argc; ++i) {
        std::wstring a = argv[i];
        if (a == L"--help" || a == L"-h") {
            PrintUsage();
            return 0;
        } else if (a == L"--child" && i + 1 < argc) {
            child = true;
            tag = argv[++i];
        } else if (a == L"--tag" && i + 1 < argc) {
            tag = argv[++i];
        } else if (a == L"--once") {
            once = true;
        } else if (a == L"--show") {
            show = true;
        } else if (a == L"--stop") {
            stop = true;
        } else if (a == L"--cleanup") {
            cleanup = true;
        } else if (a == L"--purge") {
            purge = true;
        } else if (a == L"--solo") {
            solo = true;
        } else {
            Echo(L"未知参数: " + a + L"（用 --help 查看用法）");
            return 2;
        }
    }
    if (tag.empty())
        tag = kDefaultTag;

    int maxRestarts = EnvInt(L"AVB_MAX_RESTARTS", 20);
    int maxSeconds  = EnvInt(L"AVB_MAX_SECONDS", 1800);
    int spawnLimit  = EnvInt(L"AVB_MAX_TOTAL_SPAWNS", 100);

    if (cleanup) {
        Echo(L"[sample] marker=" + std::wstring(kMarker) + L" tag=" + tag);
        return DoCleanup(tag, purge);
    }
    if (stop) {
        CreateExitSwitch(tag);
        Echo(L"[sample] 退出开关已创建: C:\\exit.exit 与 " + TempDir() + tag + L".exit");
        Echo(L"[sample] 副本会在 1 秒内自行退出；残留进程/文件用 --cleanup 收尾");
        return 0;
    }

    Echo(L"[sample] " + std::wstring(kMarker) + L"  (仅用于本地 AV 行为测试)");
    Echo(L"[sample] tag=" + tag + L"  temp=" + TempDir());
    Echo(L"[sample] 退出开关: C:\\exit.exit   日志: " + TempDir() + tag + L".log");

    // 已经在 %TEMP% 里的副本：直接进入互守循环，避免自我复制成链
    if (child || IsSelfInTemp(tag))
        return ChildLoop(tag, show, solo, maxRestarts, maxSeconds, spawnLimit);

    // 原始进程：复制自身到 %TEMP%，只拉起 1 个副本后退出。
    // 该副本发现自己没有同伴时会自己再拉一个 —— 最终稳定在 2 个互守进程，
    // 不会像「父进程一次起两个」那样出现 3 个（起两个时先起来的那个会误判没有同伴）。
    std::wstring self = ExePath();
    std::wstring copy = TempDir() + RandomName(tag);
    if (!CopyFileW(self.c_str(), copy.c_str(), FALSE)) {
        Echo(L"[sample] 复制失败, GetLastError=" + std::to_wstring(GetLastError()));
        return 1;
    }
    Log(tag, L"launcher copied self -> " + copy, true);

    DWORD pid = 0;
    std::wstring err;
    int started = SpawnCopy(copy, tag, show, once, pid, err) ? 1 : 0;
    if (started)
        Log(tag, L"launcher spawned pid=" + std::to_wstring(pid) + L" from " + copy, true);
    else
        Log(tag, L"launcher spawn failed: " + err, true);

    Echo(L"[sample] 已拉起 1 个副本: " + copy);
    if (once) {
        Echo(L"[sample] --once：单副本模式，不互守，只等退出开关/时长上限");
    } else {
        Echo(L"[sample] 它会在 1 秒内自己再拉一个同伴，最终稳定为 2 个互守进程");
        Echo(L"[sample] 杀掉其中一个，另一个会在 1 秒内把它拉起来；同时杀掉两个才会真正停");
    }
    Echo(L"[sample] 收工: 创建 C:\\exit.exit，或运行 av_watchdog_sample.exe --cleanup --purge");
    return started > 0 ? 0 : 1;
}
