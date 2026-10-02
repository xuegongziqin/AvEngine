/*
 * install.c - AvEngine one-click installer (Windows / C + Win32 API)
 *
 * Steps performed:
 *   1. Locate the project root and create runtime dirs (logs/, quarantine/)
 *   2. Check administrator privileges (required by the ClamAV service and Sysmon)
 *   3. Python environment: create venv, install requirements.txt / requirements-dev.txt
 *      (yara-python, pyclamd, pywin32, colorama, PyYAML, pytest)
 *   4. ClamAV: install bina\clamav.msi -> write configs -> freshclam signature update
 *      -> register + start the "clamd" Windows service
 *   5. Sysmon: install/update using scripts\sysmon_config.xml
 *   6. Generate config.yaml and verify the whole environment
 *      (dependency imports, YARA rule compilation, clamd connectivity)
 *
 * Build:
 *   scripts\build_installer.bat
 *   or manually:
 *     gcc -O2 -municode -o installer\AvInstaller.exe installer\install.c -ladvapi32
 *     cl /nologo /O2 /DUNICODE /D_UNICODE installer\install.c /link /OUT:installer\AvInstaller.exe advapi32.lib
 *
 * Usage:
 *   AvInstaller.exe [--no-python] [--no-clamav] [--no-sysmon] [--no-verify] [--dry-run]
 */

#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <wchar.h>

/* ---------------- constants ---------------- */

#define MAX_STEPS 8
#define CMD_LEN   4096

#define STATUS_OK   0
#define STATUS_WARN 1
#define STATUS_FAIL 2
#define STATUS_SKIP 3

#define CLAMAV_URL "https://www.clamav.net/downloads"
#define SYSMON_URL "https://learn.microsoft.com/sysinternals/downloads/sysmon"
#define PYTHON_URL "https://www.python.org/downloads/"

/* ---------------- global state ---------------- */

static wchar_t g_root[MAX_PATH];     /* project root */
static wchar_t g_log_path[MAX_PATH]; /* logs\install.log */
static FILE   *g_log;
static int     g_dry_run;

static struct {
    const char *name;
    int status;
} g_results[MAX_STEPS];
static int g_result_count;

/* ---------------- console helpers ---------------- */

static void set_color(WORD color)
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    if (h != INVALID_HANDLE_VALUE)
        SetConsoleTextAttribute(h, color);
}

/* ---------------- logging ---------------- */

static void log_write(const char *text, size_t len)
{
    if (g_log) {
        fwrite(text, 1, len, g_log);
        fflush(g_log);
    }
}

static void log_printf(const char *fmt, ...)
{
    char buf[4096];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n < 0)
        return;
    if ((size_t)n >= sizeof(buf))
        n = (int)sizeof(buf) - 1;
    log_write(buf, (size_t)n);
}

/* print a status-prefixed line to console and log */
static void print_status(int status, const char *fmt, ...)
{
    char body[4096];
    char line[4600];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(body, sizeof(body), fmt, ap);
    va_end(ap);
    if (n < 0)
        return;

    const char *tag;
    WORD color;
    switch (status) {
    case STATUS_OK:   tag = "[ OK ]"; color = FOREGROUND_GREEN | FOREGROUND_INTENSITY; break;
    case STATUS_WARN: tag = "[WARN]"; color = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY; break;
    case STATUS_FAIL: tag = "[FAIL]"; color = FOREGROUND_RED | FOREGROUND_INTENSITY; break;
    default:          tag = "[SKIP]"; color = FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY; break;
    }

    snprintf(line, sizeof(line), "       %s %s\n", tag, body);
    set_color(color);
    fputs(line, stdout);
    set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    fflush(stdout);

    log_printf("%s %s", tag, body);
}

static void step_begin(int index, int total, const char *title)
{
    char line[512];
    snprintf(line, sizeof(line), "\n[%d/%d] %s\n", index, total, title);
    set_color(FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    fputs(line, stdout);
    set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    fflush(stdout);
    log_printf("\n%s", line);
}

static void record(const char *name, int status)
{
    if (g_result_count < MAX_STEPS) {
        g_results[g_result_count].name = name;
        g_results[g_result_count].status = status;
        g_result_count++;
    }
}

/* ---------------- basic utilities ---------------- */

static int path_exists(const wchar_t *path)
{
    return GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES;
}

static int is_dir(const wchar_t *path)
{
    DWORD attr = GetFileAttributesW(path);
    return attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY);
}

/*
 * Wide string helpers.
 * The wide printf family (swprintf) is deliberately NOT used for paths and
 * command lines: behaviour differs between C runtimes and has been observed
 * to mangle %s arguments.  Building strings from plain fragments (wjoin)
 * and printing through the narrow printf family (narrow) is portable.
 */

/* join up to 5 wide fragments into dst (NULL terminates the list);
   returns 0 and empties dst when the result does not fit into cap. */
static int wjoin(wchar_t *dst, size_t cap,
                 const wchar_t *a, const wchar_t *b, const wchar_t *c,
                 const wchar_t *d, const wchar_t *e)
{
    const wchar_t *parts[5];
    size_t used = 0;

    parts[0] = a; parts[1] = b; parts[2] = c; parts[3] = d; parts[4] = e;
    if (cap == 0)
        return 0;
    for (int i = 0; i < 5; i++) {
        size_t add;
        if (!parts[i])
            break;
        add = wcslen(parts[i]);
        if (used + add + 1 > cap) {
            dst[0] = L'\0';
            return 0;
        }
        memcpy(dst + used, parts[i], add * sizeof(wchar_t));
        used += add;
    }
    dst[used] = L'\0';
    return 1;
}

#define NARROW_SLOTS 4
#define NARROW_LEN   (CMD_LEN * 3)

/* convert wide text to the console code page for the narrow printf family */
static const char *narrow(const wchar_t *w)
{
    static char buf[NARROW_SLOTS][NARROW_LEN];
    static int next;
    char *out = buf[next];

    next = (next + 1) % NARROW_SLOTS;
    if (!w) {
        out[0] = '\0';
        return out;
    }
    if (!WideCharToMultiByte(CP_ACP, 0, w, -1, out, NARROW_LEN, NULL, NULL)) {
        out[0] = '?';
        out[1] = '\0';
    }
    return out;
}

/* create a directory tree (multi level) */
static int make_dirs(const wchar_t *path)
{
    wchar_t tmp[MAX_PATH];
    size_t len;

    if (wcslen(path) >= MAX_PATH)
        return 0;
    wcsncpy(tmp, path, MAX_PATH - 1);
    tmp[MAX_PATH - 1] = L'\0';
    len = wcslen(tmp);
    while (len > 0 && (tmp[len - 1] == L'\\' || tmp[len - 1] == L'/'))
        tmp[--len] = L'\0';

    for (wchar_t *p = tmp + 1; *p; p++) {
        if (*p == L'\\' || *p == L'/') {
            wchar_t saved = *p;
            *p = L'\0';
            if (!is_dir(tmp))
                CreateDirectoryW(tmp, NULL);
            *p = saved;
        }
    }
    if (!is_dir(tmp))
        CreateDirectoryW(tmp, NULL);
    return is_dir(tmp);
}

/* write a UTF-8/ASCII buffer to a file, path may contain non-ASCII chars */
static int write_text_file(const wchar_t *path, const char *content)
{
    HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE)
        return 0;
    DWORD written = 0;
    DWORD len = (DWORD)strlen(content);
    BOOL ok = WriteFile(h, content, len, &written, NULL);
    CloseHandle(h);
    return ok && written == len;
}

static int is_admin(void)
{
    BOOL member = FALSE;
    SID_IDENTIFIER_AUTHORITY nt_auth = SECURITY_NT_AUTHORITY;
    PSID group = NULL;

    if (!AllocateAndInitializeSid(&nt_auth, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                  DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &group))
        return 0;
    CheckTokenMembership(NULL, group, &member);
    FreeSid(group);
    return member ? 1 : 0;
}

/* ---------------- process execution ---------------- */

/*
 * Run a command line, capture stdout/stderr and mirror it to console + log.
 * Returns 1 if the process was started; *exit_code holds the exit code.
 */
static int run_cmd(const wchar_t *cmd, const wchar_t *cwd, DWORD *exit_code,
                   int quiet)
{
    *exit_code = 0;

    log_printf("> %s\n", narrow(cmd));
    if (g_dry_run) {
        log_printf("  (dry-run: skipped)\n");
        return 1;
    }

    SECURITY_ATTRIBUTES sa;
    ZeroMemory(&sa, sizeof(sa));
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    HANDLE out_read = NULL, out_write = NULL;
    if (!CreatePipe(&out_read, &out_write, &sa, 0)) {
        print_status(STATUS_FAIL, "CreatePipe failed (%lu)", GetLastError());
        return 0;
    }
    SetHandleInformation(out_read, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = out_write;
    si.hStdError = out_write;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));

    wchar_t *cmdline = _wcsdup(cmd);
    if (!cmdline) {
        CloseHandle(out_read);
        CloseHandle(out_write);
        return 0;
    }

    BOOL created = CreateProcessW(NULL, cmdline, NULL, NULL, TRUE,
                                  CREATE_NO_WINDOW, NULL, cwd, &si, &pi);
    DWORD create_err = created ? 0 : GetLastError();
    free(cmdline);
    CloseHandle(out_write); /* parent closes its copy so the reader sees EOF */

    if (!created) {
        CloseHandle(out_read);
        print_status(STATUS_FAIL, "cannot run command (error %lu): %s",
                     create_err, narrow(cmd));
        return 0;
    }

    char buf[4096];
    DWORD nread;
    while (ReadFile(out_read, buf, sizeof(buf) - 1, &nread, NULL) && nread > 0) {
        buf[nread] = '\0';
        if (!quiet)
            fwrite(buf, 1, nread, stdout);
        log_write(buf, nread);
    }
    CloseHandle(out_read);

    WaitForSingleObject(pi.hProcess, INFINITE);
    GetExitCodeProcess(pi.hProcess, exit_code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    if (!quiet)
        fflush(stdout);
    log_printf("  (exit code: %lu)\n", *exit_code);
    return 1;
}

static int run_ok(const wchar_t *cmd, const wchar_t *cwd, int quiet)
{
    DWORD code = 1;
    if (g_dry_run)
        return 1;
    if (!run_cmd(cmd, cwd, &code, quiet))
        return 0;
    return code == 0;
}

/* run "venv python -c <code>" in the project root, return the exit code */
static int run_python(const wchar_t *python, const wchar_t *cwd,
                      const char *code, int quiet)
{
    wchar_t cmd[CMD_LEN];
    wchar_t wcode[1024];
    DWORD exit_code = 1;

    if (MultiByteToWideChar(CP_ACP, 0, code, -1, wcode, 1024) == 0) {
        print_status(STATUS_FAIL, "internal error: command text too long");
        return -1;
    }
    if (!wjoin(cmd, CMD_LEN, L"\"", python, L"\" -c \"", wcode, L"\""))
        return -1;
    if (g_dry_run)
        return 0;
    if (!run_cmd(cmd, cwd, &exit_code, quiet))
        return -1;
    return (int)exit_code;
}

/* ---------------- project root ---------------- */

static wchar_t g_exe_path[MAX_PATH]; /* remembered for error messages */

/* a directory is the project root when one of the marker files exists in it */
static int is_project_root(const wchar_t *dir)
{
    static const wchar_t *markers[] = {
        L"\\config.example.yaml",
        L"\\pyproject.toml",
        L"\\requirements.txt",
    };
    wchar_t probe[MAX_PATH];
    size_t count = sizeof markers / sizeof markers[0];

    for (size_t i = 0; i < count; i++) {
        if (wjoin(probe, MAX_PATH, dir, markers[i], NULL, NULL, NULL) &&
            path_exists(probe))
            return 1;
    }
    return 0;
}

static int locate_root(wchar_t *out, size_t cap)
{
    wchar_t module[MAX_PATH];
    wchar_t probe[MAX_PATH];
    DWORD n = GetModuleFileNameW(NULL, module, MAX_PATH);

    if (n == 0 || n >= MAX_PATH)
        module[0] = L'\0';
    wcsncpy(g_exe_path, module, MAX_PATH - 1);
    g_exe_path[MAX_PATH - 1] = L'\0';

    /* walk up from the executable directory looking for a project marker */
    for (int i = 0; i < 6; i++) {
        wcsncpy(probe, module, MAX_PATH - 1);
        probe[MAX_PATH - 1] = L'\0';
        for (int j = 0; j < i + 1; j++) {
            wchar_t *sep = wcsrchr(probe, L'\\');
            if (!sep) {
                probe[0] = L'\0';
                break;
            }
            *sep = L'\0';
        }
        if (probe[0] && is_project_root(probe)) {
            if (wcslen(probe) + 1 > cap)
                return 0;
            wcscpy(out, probe);
            return 1;
        }
    }

    /* fallback: current working directory */
    if (GetCurrentDirectoryW(MAX_PATH, probe) && is_dir(probe)) {
        while (probe[0]) {
            if (is_project_root(probe)) {
                if (wcslen(probe) + 1 > cap)
                    return 0;
                wcscpy(out, probe);
                return 1;
            }
            wchar_t *sep = wcsrchr(probe, L'\\');
            if (!sep)
                break;
            *sep = L'\0';
        }
    }
    return 0;
}

/* ---------------- step 1: environment ---------------- */

static int step_environment(void)
{
    if (!locate_root(g_root, MAX_PATH)) {
        wchar_t cwd[MAX_PATH];
        set_color(FOREGROUND_RED | FOREGROUND_INTENSITY);
        printf("Cannot locate the project root.\n");
        printf("  executable : %s\n", narrow(g_exe_path));
        if (GetCurrentDirectoryW(MAX_PATH, cwd))
            printf("  working dir: %s\n", narrow(cwd));
        printf("  expected   : <project>\\config.example.yaml (or pyproject.toml)\n");
        printf("Keep AvInstaller.exe inside the project directory.\n");
        set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        return 0;
    }
    printf("Project root: %s\n", narrow(g_root));

    wchar_t logs[MAX_PATH], quarantine[MAX_PATH];
    if (!wjoin(logs, MAX_PATH, g_root, L"\\logs", NULL, NULL, NULL) ||
        !wjoin(quarantine, MAX_PATH, g_root, L"\\quarantine", NULL, NULL, NULL) ||
        !wjoin(g_log_path, MAX_PATH, logs, L"\\install.log", NULL, NULL, NULL)) {
        printf("project path is too long\n");
        return 0;
    }
    if (!g_dry_run) {
        make_dirs(logs);
        make_dirs(quarantine);
    }

    if (!g_dry_run) {
        g_log = _wfopen(g_log_path, L"ab");
        if (!g_log) {
            printf("Warning: cannot create log file %s\n", narrow(g_log_path));
        } else {
            SYSTEMTIME st;
            GetLocalTime(&st);
            log_printf("\n========== AvInstaller %04d-%02d-%02d %02d:%02d:%02d ==========\n",
                       st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
            log_printf("root: %s\n", narrow(g_root));
        }
    }
    print_status(STATUS_OK, "log file: %s", narrow(g_log_path));
    return 1;
}

/* ---------------- step 2: administrator ---------------- */

static int step_admin(void)
{
    if (is_admin()) {
        print_status(STATUS_OK, "running with administrator privileges");
        return 1;
    }
    if (g_dry_run) {
        print_status(STATUS_WARN, "not elevated (allowed in dry-run mode)");
        return 1;
    }
    print_status(STATUS_FAIL, "administrator rights required: right-click -> Run as administrator");
    print_status(STATUS_FAIL, "the ClamAV service registration and Sysmon install need them");
    return 0;
}

/* ---------------- step 3: python environment ---------------- */

static int find_python_base(wchar_t *out, size_t cap)
{
    if (run_ok(L"py -3 -c \"import sys; sys.exit(0 if sys.version_info>=(3,8) else 1)\"",
               g_root, 1)) {
        wcsncpy(out, L"py -3", cap - 1);
        out[cap - 1] = L'\0';
        return 1;
    }
    if (run_ok(L"python -c \"import sys; sys.exit(0 if sys.version_info>=(3,8) else 1)\"",
               g_root, 1)) {
        wcsncpy(out, L"python", cap - 1);
        out[cap - 1] = L'\0';
        return 1;
    }
    if (run_ok(L"python3 -c \"import sys; sys.exit(0 if sys.version_info>=(3,8) else 1)\"",
               g_root, 1)) {
        wcsncpy(out, L"python3", cap - 1);
        out[cap - 1] = L'\0';
        return 1;
    }
    return 0;
}

static int step_python(void)
{
    wchar_t venv_py[MAX_PATH];
    wchar_t cmd[CMD_LEN];
    if (!wjoin(venv_py, MAX_PATH, g_root, L"\\venv\\Scripts\\python.exe",
               NULL, NULL, NULL))
        return STATUS_FAIL;

    if (!path_exists(venv_py)) {
        wchar_t base[64];
        if (!find_python_base(base, 64)) {
            print_status(STATUS_FAIL, "Python 3.8+ not found, install from %s", PYTHON_URL);
            print_status(STATUS_FAIL, "make sure \"Add python.exe to PATH\" is checked");
            return STATUS_FAIL;
        }
        print_status(STATUS_OK, "python launcher: %s", narrow(base));
        if (!wjoin(cmd, CMD_LEN, base, L" -m venv \"", g_root, L"\\venv\"", NULL))
            return STATUS_FAIL;
        if (!run_ok(cmd, g_root, 0)) {
            print_status(STATUS_FAIL, "failed to create the virtual environment");
            return STATUS_FAIL;
        }
        print_status(STATUS_OK, "virtual environment created: venv\\");
    } else {
        print_status(STATUS_OK, "reusing existing virtual environment: venv\\");
    }

    if (!path_exists(venv_py)) {
        print_status(STATUS_FAIL, "missing %s", narrow(venv_py));
        return STATUS_FAIL;
    }

    if (!wjoin(cmd, CMD_LEN, L"\"", venv_py, L"\" -m pip install --upgrade pip",
               NULL, NULL))
        return STATUS_FAIL;
    if (!run_ok(cmd, g_root, 0))
        print_status(STATUS_WARN, "pip self-upgrade failed, continuing");

    if (!wjoin(cmd, CMD_LEN, L"\"", venv_py, L"\" -m pip install -r \"",
               g_root, L"\\requirements.txt\""))
        return STATUS_FAIL;
    if (!run_ok(cmd, g_root, 0)) {
        print_status(STATUS_FAIL, "runtime dependency install failed (yara-python/pyclamd/pywin32)");
        return STATUS_FAIL;
    }
    print_status(STATUS_OK, "installed requirements.txt (yara-python, pyclamd, pywin32, ...)");

    if (!wjoin(cmd, CMD_LEN, L"\"", venv_py, L"\" -m pip install -r \"",
               g_root, L"\\requirements-dev.txt\""))
        return STATUS_FAIL;
    if (!run_ok(cmd, g_root, 0)) {
        print_status(STATUS_WARN, "dev dependency install failed (pytest), tests unavailable");
        return STATUS_WARN;
    }
    print_status(STATUS_OK, "installed requirements-dev.txt (pytest)");

    return STATUS_OK;
}

/* ---------------- step 4: ClamAV ---------------- */

static int write_clamav_configs(const wchar_t *clamav_dir, int port)
{
    wchar_t path[MAX_PATH];
    char content[4096];
    char dir_utf8[MAX_PATH * 4];
    int ok_all = 1;

    WideCharToMultiByte(CP_UTF8, 0, clamav_dir, -1, dir_utf8, sizeof(dir_utf8), NULL, NULL);

    /* clamd.conf - bind to loopback only */
    snprintf(content, sizeof(content),
             "TCPSocket %d\n"
             "TCPAddr 127.0.0.1\n"
             "MaxThreads 50\n"
             "LogFile %s\\clamd.log\n"
             "LogTime yes\n"
             "DatabaseDirectory %s\\db\n",
             port, dir_utf8, dir_utf8);
    if (!wjoin(path, MAX_PATH, clamav_dir, L"\\clamd.conf", NULL, NULL, NULL))
        return 0;
    if (path_exists(path)) {
        wchar_t bak[MAX_PATH];
        if (wjoin(bak, MAX_PATH, path, L".bak", NULL, NULL, NULL))
            CopyFileW(path, bak, FALSE);
    }
    if (write_text_file(path, content))
        print_status(STATUS_OK, "wrote clamd.conf (port %d, 127.0.0.1 only)", port);
    else {
        print_status(STATUS_FAIL, "cannot write clamd.conf");
        ok_all = 0;
    }

    /* freshclam.conf */
    snprintf(content, sizeof(content),
             "DatabaseMirror database.clamav.net\n"
             "DatabaseDirectory %s\\db\n"
             "UpdateLogFile %s\\freshclam.log\n"
             "LogTime yes\n",
             dir_utf8, dir_utf8);
    if (!wjoin(path, MAX_PATH, clamav_dir, L"\\freshclam.conf", NULL, NULL, NULL))
        return 0;
    if (path_exists(path)) {
        wchar_t bak[MAX_PATH];
        if (wjoin(bak, MAX_PATH, path, L".bak", NULL, NULL, NULL))
            CopyFileW(path, bak, FALSE);
    }
    if (write_text_file(path, content))
        print_status(STATUS_OK, "wrote freshclam.conf");
    else {
        print_status(STATUS_FAIL, "cannot write freshclam.conf");
        ok_all = 0;
    }

    return ok_all;
}

static int ensure_clamd_service(const wchar_t *clamd_exe, const wchar_t *clamd_conf)
{
    if (g_dry_run) {
        log_printf("> (dry-run) register Windows service \"clamd\" -> \"%s\" --config-file=\"%s\"\n",
                   narrow(clamd_exe), narrow(clamd_conf));
        return 1;
    }

    wchar_t binpath[CMD_LEN];
    if (!wjoin(binpath, CMD_LEN, L"\"", clamd_exe, L"\" --config-file=\"",
               clamd_conf, L"\""))
        return 0;

    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!scm) {
        print_status(STATUS_FAIL, "OpenSCManager failed (%lu)", GetLastError());
        return 0;
    }

    SC_HANDLE svc = OpenServiceW(scm, L"clamd", SERVICE_ALL_ACCESS);
    if (svc) {
        if (ChangeServiceConfigW(svc, SERVICE_NO_CHANGE, SERVICE_AUTO_START,
                                 SERVICE_NO_CHANGE, binpath, NULL, NULL,
                                 NULL, NULL, NULL, L"ClamAV Daemon"))
            print_status(STATUS_OK, "updated clamd service (auto start)");
        else
            print_status(STATUS_WARN, "cannot update service config (%lu)", GetLastError());
    } else {
        svc = CreateServiceW(scm, L"clamd", L"ClamAV Daemon", SERVICE_ALL_ACCESS,
                             SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START,
                             SERVICE_ERROR_NORMAL, binpath,
                             NULL, NULL, NULL, NULL, NULL);
        if (!svc) {
            print_status(STATUS_FAIL, "CreateService failed (%lu)", GetLastError());
            CloseServiceHandle(scm);
            return 0;
        }
        print_status(STATUS_OK, "created clamd service (auto start)");
    }

    SERVICE_STATUS_PROCESS status;
    DWORD bytes = 0;
    int running = 0;
    if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, (LPBYTE)&status,
                             sizeof(status), &bytes))
        running = (status.dwCurrentState == SERVICE_RUNNING);

    if (!running) {
        if (StartServiceW(svc, 0, NULL))
            print_status(STATUS_OK, "starting clamd service...");
        else {
            DWORD err = GetLastError();
            if (err != ERROR_SERVICE_ALREADY_RUNNING)
                print_status(STATUS_WARN, "StartService returned %lu, polling status...", err);
        }
        for (int i = 0; i < 30; i++) {
            if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, (LPBYTE)&status,
                                     sizeof(status), &bytes) &&
                status.dwCurrentState == SERVICE_RUNNING)
                break;
            Sleep(1000);
        }
    }

    running = QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, (LPBYTE)&status,
                                   sizeof(status), &bytes) &&
              status.dwCurrentState == SERVICE_RUNNING;

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);

    if (running) {
        print_status(STATUS_OK, "clamd service running (127.0.0.1:3310)");
        return 1;
    }
    print_status(STATUS_WARN, "clamd service not running, check Program Files\\ClamAV\\clamd.log");
    return 0;
}

static int step_clamav(void)
{
    wchar_t program_files[MAX_PATH];
    wchar_t clamav_dir[MAX_PATH];
    wchar_t clamd_exe[MAX_PATH];
    wchar_t clamd_conf[MAX_PATH];
    wchar_t freshclam_exe[MAX_PATH];
    wchar_t msi[MAX_PATH];
    wchar_t db_dir[MAX_PATH];
    wchar_t cmd[CMD_LEN];
    DWORD n;

    n = GetEnvironmentVariableW(L"ProgramFiles", program_files, MAX_PATH);
    if (n == 0 || n >= MAX_PATH)
        wcscpy(program_files, L"C:\\Program Files");
    if (!wjoin(clamav_dir, MAX_PATH, program_files, L"\\ClamAV", NULL, NULL, NULL) ||
        !wjoin(clamd_exe, MAX_PATH, clamav_dir, L"\\clamd.exe", NULL, NULL, NULL) ||
        !wjoin(clamd_conf, MAX_PATH, clamav_dir, L"\\clamd.conf", NULL, NULL, NULL) ||
        !wjoin(freshclam_exe, MAX_PATH, clamav_dir, L"\\freshclam.exe", NULL, NULL, NULL) ||
        !wjoin(db_dir, MAX_PATH, clamav_dir, L"\\db", NULL, NULL, NULL) ||
        !wjoin(msi, MAX_PATH, g_root, L"\\bina\\clamav.msi", NULL, NULL, NULL))
        return STATUS_FAIL;

    /* 1) install MSI */
    if (!path_exists(clamd_exe)) {
        if (!path_exists(msi)) {
            print_status(STATUS_FAIL, "missing installer: %s", narrow(msi));
            print_status(STATUS_FAIL, "download the Windows package from %s -> bina\\clamav.msi",
                         CLAMAV_URL);
            return STATUS_FAIL;
        }
        print_status(STATUS_OK, "installing ClamAV (msiexec /quiet)...");
        if (!wjoin(cmd, CMD_LEN, L"msiexec.exe /i \"", msi, L"\" /quiet /norestart",
                   NULL, NULL))
            return STATUS_FAIL;
        if (!run_ok(cmd, g_root, 1))
            print_status(STATUS_WARN, "msiexec returned non-zero, checking install dir...");
        if (!path_exists(clamd_exe)) {
            print_status(STATUS_FAIL, "ClamAV install failed, %s not found",
                         narrow(clamd_exe));
            return STATUS_FAIL;
        }
        print_status(STATUS_OK, "ClamAV installed: %s", narrow(clamav_dir));
    } else {
        print_status(STATUS_OK, "ClamAV already installed, skipping the MSI");
    }

    /* 2) configuration files */
    if (g_dry_run) {
        log_printf("> (dry-run) write %s\\clamd.conf and freshclam.conf\n",
                   narrow(clamav_dir));
    } else {
        make_dirs(db_dir);
        if (!write_clamav_configs(clamav_dir, 3310))
            return STATUS_FAIL;
    }

    /* 3) signature database update */
    int db_ok = g_dry_run ? 1 : 0;
    if (!g_dry_run) {
        print_status(STATUS_OK, "updating signature database (freshclam, first run takes minutes)...");
        for (int attempt = 1; attempt <= 3 && !db_ok; attempt++) {
            if (!wjoin(cmd, CMD_LEN, L"\"", freshclam_exe, L"\"", NULL, NULL))
                return STATUS_FAIL;
            DWORD code = 1;
            if (run_cmd(cmd, clamav_dir, &code, 0) && code == 0) {
                db_ok = 1;
                break;
            }
            print_status(STATUS_WARN, "freshclam attempt %d failed (exit %lu)", attempt, code);
            if (attempt < 3) {
                print_status(STATUS_WARN, "retrying in 5 seconds...");
                Sleep(5000);
            }
        }
    } else {
        log_printf("> (dry-run) run freshclam in %s (3 attempts)\n", narrow(clamav_dir));
    }
    if (db_ok)
        print_status(STATUS_OK, "signature database ready");
    else
        print_status(STATUS_WARN, "signature update failed, run freshclam manually later");

    /* 4) register + start service */
    if (!ensure_clamd_service(clamd_exe, clamd_conf))
        return STATUS_WARN;

    return STATUS_OK;
}

/* ---------------- step 5: Sysmon ---------------- */

static int reg_key_exists(HKEY root, const wchar_t *subkey)
{
    HKEY h;
    LONG r = RegOpenKeyExW(root, subkey, 0, KEY_READ, &h);
    if (r == ERROR_SUCCESS) {
        RegCloseKey(h);
        return 1;
    }
    return 0;
}

static int step_sysmon(void)
{
    wchar_t exe[MAX_PATH];
    wchar_t cfg[MAX_PATH];
    wchar_t cmd[CMD_LEN];

    if (!wjoin(exe, MAX_PATH, g_root, L"\\bina\\Sysmon\\Sysmon.exe",
               NULL, NULL, NULL))
        return STATUS_WARN;
    if (!path_exists(exe) &&
        !wjoin(exe, MAX_PATH, g_root, L"\\Sysmon.exe", NULL, NULL, NULL))
        return STATUS_WARN;
    if (!wjoin(cfg, MAX_PATH, g_root, L"\\scripts\\sysmon_config.xml",
               NULL, NULL, NULL))
        return STATUS_WARN;

    if (!path_exists(exe)) {
        print_status(STATUS_WARN, "Sysmon.exe not found, skipping (realtime monitor unavailable)");
        print_status(STATUS_WARN, "download it from %s into bina\\Sysmon\\", SYSMON_URL);
        return STATUS_WARN;
    }
    if (!path_exists(cfg)) {
        print_status(STATUS_WARN, "missing %s, skipping Sysmon setup", narrow(cfg));
        return STATUS_WARN;
    }

    int installed = reg_key_exists(HKEY_LOCAL_MACHINE,
                                   L"SYSTEM\\CurrentControlSet\\Services\\SysmonDrv");
    if (installed) {
        print_status(STATUS_OK, "Sysmon already installed, applying configuration...");
        if (!wjoin(cmd, CMD_LEN, L"\"", exe, L"\" -accepteula -c \"", cfg, L"\""))
            return STATUS_FAIL;
    } else {
        print_status(STATUS_OK, "installing Sysmon with the project configuration...");
        if (!wjoin(cmd, CMD_LEN, L"\"", exe, L"\" -accepteula -i \"", cfg, L"\""))
            return STATUS_FAIL;
    }

    if (!run_ok(cmd, g_root, 1)) {
        print_status(STATUS_FAIL, "Sysmon install/config failed (check administrator rights)");
        return STATUS_FAIL;
    }

    if (reg_key_exists(HKEY_LOCAL_MACHINE,
                       L"SYSTEM\\CurrentControlSet\\Services\\SysmonDrv")) {
        print_status(STATUS_OK, "Sysmon driver loaded, event channel available");
        return STATUS_OK;
    }
    print_status(STATUS_WARN, "Sysmon driver not detected, verify manually");
    return STATUS_WARN;
}

/* ---------------- step 6: config + verification ---------------- */

static int step_verify(int verify_clamav)
{
    wchar_t example[MAX_PATH];
    wchar_t config[MAX_PATH];
    wchar_t venv_py[MAX_PATH];

    if (!wjoin(example, MAX_PATH, g_root, L"\\config.example.yaml",
               NULL, NULL, NULL) ||
        !wjoin(config, MAX_PATH, g_root, L"\\config.yaml", NULL, NULL, NULL) ||
        !wjoin(venv_py, MAX_PATH, g_root, L"\\venv\\Scripts\\python.exe",
               NULL, NULL, NULL))
        return STATUS_FAIL;

    if (!path_exists(config)) {
        if (g_dry_run) {
            log_printf("> (dry-run) copy %s -> %s\n", narrow(example), narrow(config));
            print_status(STATUS_OK, "config.yaml would be created from config.example.yaml");
        } else if (path_exists(example) && CopyFileW(example, config, FALSE)) {
            print_status(STATUS_OK, "created config.yaml from config.example.yaml");
        } else {
            print_status(STATUS_WARN, "could not create config.yaml");
        }
    } else {
        print_status(STATUS_OK, "config.yaml already present");
    }

    if (g_dry_run) {
        print_status(STATUS_SKIP, "dry-run mode, verification skipped");
        return STATUS_OK;
    }
    if (!path_exists(venv_py)) {
        print_status(STATUS_FAIL, "virtual environment missing, cannot verify");
        return STATUS_FAIL;
    }

    /* 1) dependency imports */
    int rc = run_python(venv_py, g_root,
                        "import yara, pyclamd, yaml, colorama; print('deps ok')", 0);
    if (rc == 0) {
        print_status(STATUS_OK, "imports OK (yara / pyclamd / yaml / colorama)");
    } else {
        print_status(STATUS_FAIL, "import failed, check the pip output above");
        return STATUS_FAIL;
    }

    /* 2) YARA rule compilation */
    rc = run_python(venv_py, g_root,
                    "import sys; from avengine.yara_scanner import YaraScanner as S; "
                    "s = S('rules'); "
                    "print('yara rule files:', s.rules_count, 'skipped:', s.skipped_count); "
                    "sys.exit(0 if s.is_available else 1)", 0);
    if (rc == 0) {
        print_status(STATUS_OK, "YARA rule set compiled");
    } else {
        print_status(STATUS_FAIL, "YARA rule compilation failed (check the rules/ directory)");
        return STATUS_FAIL;
    }

    /* 3) clamd connectivity */
    if (verify_clamav) {
        rc = run_python(venv_py, g_root,
                        "from avengine.clamav_scanner import ClamavScanner as C; "
                        "c = C(); "
                        "print('clamd:', c.get_version() or 'unavailable'); "
                        "import sys; sys.exit(0 if c.is_available else 1)", 0);
        if (rc == 0) {
            print_status(STATUS_OK, "ClamAV (clamd) reachable");
        } else {
            print_status(STATUS_WARN,
                         "ClamAV unreachable, try scripts\\start_clamav.bat later");
            return STATUS_WARN;
        }
    }

    return STATUS_OK;
}

/* ---------------- summary ---------------- */

static void print_summary(void)
{
    static const char *status_text[] = {"OK", "WARNING", "FAILED", "SKIPPED"};
    static const WORD status_color[] = {
        FOREGROUND_GREEN | FOREGROUND_INTENSITY,
        FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY,
        FOREGROUND_RED | FOREGROUND_INTENSITY,
        FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY,
    };

    printf("\n============================================================\n");
    printf(" Installation summary\n");
    printf("============================================================\n");
    for (int i = 0; i < g_result_count; i++) {
        printf("  %-12s : ", g_results[i].name);
        set_color(status_color[g_results[i].status]);
        printf("%s\n", status_text[g_results[i].status]);
        set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        log_printf("summary: %s = %s\n", g_results[i].name,
                   status_text[g_results[i].status]);
    }
    printf("============================================================\n");

    int failed = 0;
    for (int i = 0; i < g_result_count; i++)
        if (g_results[i].status == STATUS_FAIL)
            failed++;

    if (failed == 0) {
        printf(" Environment ready. Start the engine with:\n");
        printf("   venv\\Scripts\\python.exe -m avengine\n");
    } else {
        printf(" %d step(s) failed, fix the [FAIL] messages above and rerun.\n", failed);
    }
    printf(" Log: %s\n", narrow(g_log_path));
    printf("============================================================\n");
}

/* ---------------- entry point ---------------- */

static void print_usage(void)
{
    printf("AvEngine one-click installer\n"
           "\n"
           "Usage: AvInstaller.exe [options]\n"
           "\n"
           "Options:\n"
           "  --no-python    Skip the Python venv and dependency installation\n"
           "  --no-clamav    Skip ClamAV install / signature update / service\n"
           "  --no-sysmon    Skip Sysmon installation\n"
           "  --no-verify    Skip post-install verification\n"
           "  --dry-run      Print the commands without changing anything\n"
           "  --help         Show this help\n"
           "\n"
           "Notes:\n"
           "  * Run as administrator (ClamAV service + Sysmon require it)\n"
           "  * Missing artifacts: bina\\clamav.msi  (%s)\n"
           "                       bina\\Sysmon\\Sysmon.exe (%s)\n",
           CLAMAV_URL, SYSMON_URL);
}

int wmain(int argc, wchar_t **argv)
{
    int no_python = 0, no_clamav = 0, no_sysmon = 0, no_verify = 0;

    for (int i = 1; i < argc; i++) {
        if (!wcscmp(argv[i], L"--help") || !wcscmp(argv[i], L"-h")) {
            print_usage();
            return 0;
        } else if (!wcscmp(argv[i], L"--no-python")) {
            no_python = 1;
        } else if (!wcscmp(argv[i], L"--no-clamav")) {
            no_clamav = 1;
        } else if (!wcscmp(argv[i], L"--no-sysmon")) {
            no_sysmon = 1;
        } else if (!wcscmp(argv[i], L"--no-verify")) {
            no_verify = 1;
        } else if (!wcscmp(argv[i], L"--dry-run")) {
            g_dry_run = 1;
        } else {
            fprintf(stderr, "unknown argument: %s (see --help)\n", narrow(argv[i]));
            return 2;
        }
    }

    printf("============================================================\n");
    printf(" AvEngine one-click installer (ClamAV + YARA + Sysmon)\n");
    printf("============================================================\n");
    if (g_dry_run)
        printf(" *** dry-run: commands are printed, nothing is modified ***\n");

    const int total = 6;

    step_begin(1, total, "Locate project root");
    if (!step_environment())
        return 1;
    record("Environment", STATUS_OK);

    step_begin(2, total, "Check administrator privileges");
    int admin_ok = step_admin();
    record("Admin", admin_ok ? STATUS_OK : STATUS_FAIL);
    if (!admin_ok) {
        print_summary();
        if (g_log)
            fclose(g_log);
        return 1;
    }

    step_begin(3, total, "Python environment (venv + yara-python + pyclamd + pytest)");
    int st;
    if (no_python) {
        print_status(STATUS_SKIP, "--no-python: skipped");
        st = STATUS_SKIP;
    } else {
        st = step_python();
    }
    record("Python", st);

    step_begin(4, total, "ClamAV (install / config / signatures / service)");
    if (no_clamav) {
        print_status(STATUS_SKIP, "--no-clamav: skipped");
        st = STATUS_SKIP;
    } else {
        st = step_clamav();
    }
    record("ClamAV", st);

    step_begin(5, total, "Sysmon (install and apply sysmon_config.xml)");
    if (no_sysmon) {
        print_status(STATUS_SKIP, "--no-sysmon: skipped");
        st = STATUS_SKIP;
    } else {
        st = step_sysmon();
    }
    record("Sysmon", st);

    step_begin(6, total, "Generate config and verify the environment");
    if (no_verify) {
        print_status(STATUS_SKIP, "--no-verify: skipped");
        st = STATUS_SKIP;
    } else {
        st = step_verify(!no_clamav);
    }
    record("Verify", st);

    print_summary();

    int failed = 0;
    for (int i = 0; i < g_result_count; i++)
        if (g_results[i].status == STATUS_FAIL)
            failed++;

    if (g_log)
        fclose(g_log);
    return failed ? 1 : 0;
}
