// ai_tools_fs.cpp - AI 工具扩展库：文件取证组
// （目录枚举 / 文件元数据 / NTFS 备用数据流与 Zone.Identifier / USN 日志时间线）
// 实现契约见 ai_tools_ext.h 第二节；共享基础设施见 ai_tools_ext.cpp。
// 审计由 ai_execute_tool 统一完成，本文件不调用 aiext::audit_log。

#include "ai_tools_ext.h"

#include "ai_util.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwctype>
#include <filesystem>
#include <string>
#include <utility>
#include <vector>

// windows.h 已由 ai_util.h 引入；USN 控制码需要 winioctl.h，文件属主查询需要 aclapi.h
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winioctl.h>
#include <aclapi.h>

namespace fs = std::filesystem;

using nlohmann::json;

namespace {

std::string ERR(const std::string& m) { return "ERROR: " + m; }

std::string lower_copy(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

// ---------------- 参数安全取值（模型可能传字符串/浮点，绝不抛异常） ----------------

bool arg_bool(const json& a, const char* key, bool def) {
    const auto it = a.find(key);
    if (it == a.end() || it->is_null()) return def;
    if (it->is_boolean()) return it->get<bool>();
    if (it->is_number_integer()) return it->get<long long>() != 0;
    if (it->is_string()) {
        const std::string v = lower_copy(it->get<std::string>());
        return v == "true" || v == "1" || v == "yes" || v == "on";
    }
    return def;
}

long long arg_int(const json& a, const char* key, long long def) {
    const auto it = a.find(key);
    if (it == a.end() || it->is_null()) return def;
    if (it->is_number_integer()) return it->get<long long>();
    if (it->is_number_float()) return static_cast<long long>(it->get<double>());
    if (it->is_string()) {
        const std::string v = it->get<std::string>();
        char* endp = nullptr;
        const long long r = std::strtoll(v.c_str(), &endp, 10);
        if (endp != nullptr && endp != v.c_str()) return r;
    }
    return def;
}

double arg_num(const json& a, const char* key, double def) {
    const auto it = a.find(key);
    if (it == a.end() || it->is_null()) return def;
    if (it->is_number()) return it->get<double>();
    if (it->is_string()) {
        const std::string v = it->get<std::string>();
        char* endp = nullptr;
        const double r = std::strtod(v.c_str(), &endp);
        if (endp != nullptr && endp != v.c_str()) return r;
    }
    return def;
}

std::string arg_str(const json& a, const char* key, const char* def) {
    const auto it = a.find(key);
    if (it == a.end() || it->is_null() || !it->is_string()) return std::string(def);
    return it->get<std::string>();
}

// ---------------- 通用小工具 ----------------

// FILETIME(64bit)：hi<<32 | lo（hi 是 32 位 DWORD，必须先提升到 64 位再移位）
long long ft64(const FILETIME& ft) {
    return static_cast<long long>((static_cast<unsigned long long>(ft.dwHighDateTime) << 32) |
                                  ft.dwLowDateTime);
}

// 长路径（>= 240 字符）加 \\?\ 前缀（仅对绝对路径调用）
std::wstring extended_path(const std::wstring& p) {
    if (p.size() < 240) return p;
    if (p.size() >= 4 && p.compare(0, 4, L"\\\\?\\") == 0) return p;
    return L"\\\\?\\" + p;
}

// 文件属性位 -> 小写逗号分隔字符串，如 "archive,hidden"
std::string attrs_string(DWORD a) {
    static const std::pair<DWORD, const char*> kAttrs[] = {
        {FILE_ATTRIBUTE_ARCHIVE, "archive"},
        {FILE_ATTRIBUTE_HIDDEN, "hidden"},
        {FILE_ATTRIBUTE_READONLY, "readonly"},
        {FILE_ATTRIBUTE_SYSTEM, "system"},
        {FILE_ATTRIBUTE_DIRECTORY, "directory"},
        {FILE_ATTRIBUTE_COMPRESSED, "compressed"},
        {FILE_ATTRIBUTE_ENCRYPTED, "encrypted"},
        {FILE_ATTRIBUTE_REPARSE_POINT, "reparse_point"},
        {FILE_ATTRIBUTE_SPARSE_FILE, "sparse"},
        {FILE_ATTRIBUTE_OFFLINE, "offline"},
        {FILE_ATTRIBUTE_TEMPORARY, "temporary"},
        {FILE_ATTRIBUTE_DEVICE, "device"},
    };
    std::string out;
    for (const auto& k : kAttrs) {
        if ((a & k.first) != 0) {
            if (!out.empty()) out += ",";
            out += k.second;
        }
    }
    if (out.empty()) out = "normal";
    return out;
}

// 自写通配符匹配（仅 * 与 ?，大小写不敏感；迭代式回溯，无递归、不抛异常）
bool wildcard_match_w(const std::wstring& text, const std::wstring& pat) {
    auto lower_c = [](wchar_t c) -> wchar_t { return static_cast<wchar_t>(towlower(c)); };
    size_t t = 0, p = 0;
    size_t star = std::wstring::npos, mark = 0;
    while (t < text.size()) {
        if (p < pat.size() && (pat[p] == L'?' || lower_c(pat[p]) == lower_c(text[t]))) {
            ++p;
            ++t;
        } else if (p < pat.size() && pat[p] == L'*') {
            star = p++;
            mark = t;
        } else if (star != std::wstring::npos) {
            p = star + 1;
            t = ++mark;
        } else {
            return false;
        }
    }
    while (p < pat.size() && pat[p] == L'*') ++p;
    return p == pat.size();
}

// 前 8 字节魔数：已知格式给名字，否则给 hex
std::string detect_magic(const unsigned char* d, size_t n) {
    if (n >= 2 && d[0] == 'M' && d[1] == 'Z') return "MZ (PE executable)";
    if (n >= 2 && d[0] == '#' && d[1] == '!') return "shebang (#!)";
    if (n >= 4 && d[0] == 'P' && d[1] == 'K' && d[2] == 0x03 && d[3] == 0x04)
        return "PK (ZIP/Office)";
    if (n >= 4 && std::memcmp(d, "%PDF", 4) == 0) return "PDF document";
    if (n >= 4 && d[0] == 0x7F && d[1] == 'E' && d[2] == 'L' && d[3] == 'F')
        return "ELF executable";
    if (n >= 5 && std::memcmp(d, "<?php", 5) == 0) return "PHP script";
    if (n >= 7 && std::memcmp(d, "<script", 7) == 0) return "HTML/script";
    if (n >= 5 && std::memcmp(d, "{\\rtf", 5) == 0) return "RTF document";
    if (n >= 4 && d[0] == 0xD0 && d[1] == 0xCF && d[2] == 0x11 && d[3] == 0xE0)
        return "OLE compound (MS Office)";
    static const char* hexd = "0123456789abcdef";
    std::string out;
    const size_t k = std::min<size_t>(n, 8);
    for (size_t i = 0; i < k; ++i) {
        if (i != 0) out += ' ';
        out += hexd[d[i] >> 4];
        out += hexd[d[i] & 0xF];
    }
    return out;
}

// USN reason 位 -> 字符串数组；未识别的位用 hex 说明
json usn_reason_array(DWORD reason) {
    static const std::pair<DWORD, const char*> kReasons[] = {
        {0x00000001, "data_overwrite"},
        {0x00000002, "data_extend"},
        {0x00000004, "data_truncation"},
        {0x00000010, "named_data_overwrite"},
        {0x00000020, "named_data_extend"},
        {0x00000040, "named_data_truncation"},
        {0x00000100, "file_create"},
        {0x00000200, "file_delete"},
        {0x00000400, "ea_change"},
        {0x00000800, "security_change"},
        {0x00001000, "rename_old_name"},
        {0x00002000, "rename_new_name"},
        {0x00004000, "indexable_change"},
        {0x00008000, "basic_info_change"},
        {0x00010000, "hard_link_change"},
        {0x00020000, "compression_change"},
        {0x00040000, "encryption_change"},
        {0x00080000, "object_id_change"},
        {0x00100000, "reparse_point_change"},
        {0x00200000, "stream_change"},
        {0x00400000, "transacted_change"},
        {0x00800000, "integrity_change"},
        {0x80000000, "close"},
    };
    json arr = json::array();
    DWORD rest = reason;
    for (const auto& k : kReasons) {
        if ((reason & k.first) != 0) {
            arr.push_back(k.second);
            rest &= ~k.first;
        }
    }
    char buf[16];
    for (int bit = 0; bit < 32 && rest != 0; ++bit) {
        const DWORD b = 1u << bit;
        if ((rest & b) != 0) {
            rest &= ~b;
            std::snprintf(buf, sizeof(buf), "0x%08X", static_cast<unsigned>(b));
            arr.push_back(buf);
        }
    }
    return arr;
}

// 读 ADS 文本（UTF-16LE BOM / 无 BOM UTF-16LE 启发 / UTF-8、ANSI 尽力）
std::string read_ads_text_utf8(const std::wstring& wstream_path, size_t max_bytes) {
    HANDLE h = CreateFileW(wstream_path.c_str(), GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return "";
    std::string raw;
    char buf[4096];
    DWORD got = 0;
    while (raw.size() < max_bytes && ReadFile(h, buf, sizeof(buf), &got, nullptr) && got > 0)
        raw.append(buf, static_cast<size_t>(got));
    CloseHandle(h);
    if (raw.size() < 2) return raw;

    const auto* b = reinterpret_cast<const unsigned char*>(raw.data());
    // UTF-16LE BOM
    if (b[0] == 0xFF && b[1] == 0xFE) {
        std::wstring w((raw.size() - 2) / 2, L'\0');
        std::memcpy(&w[0], raw.data() + 2, w.size() * 2);
        return aiutil::to_utf8(w);
    }
    // 无 BOM：奇数位多为 0 -> UTF-16LE（Windows 写 Zone.Identifier 的常见形态）
    size_t zeros = 0, checks = 0;
    for (size_t i = 1; i + 1 < raw.size() && checks < 16; i += 2, ++checks)
        if (b[i] == 0) ++zeros;
    if (checks > 0 && zeros * 2 > checks) {
        std::wstring w(raw.size() / 2, L'\0');
        std::memcpy(&w[0], raw.data(), w.size() * 2);
        return aiutil::to_utf8(w);
    }
    return raw;  // UTF-8/ANSI 尽力
}

// 逐行解析 ZoneId=、HostUrl=、ReferrerUrl=、LastWriterPackageFamilyName=
void parse_zone_fields(const std::string& text, long long& zone_id, std::string& hosturl,
                       std::string& referrervalue, std::string& last_writer_package) {
    size_t pos = 0;
    while (pos <= text.size()) {
        const size_t eol = text.find('\n', pos);
        std::string line =
            text.substr(pos, (eol == std::string::npos ? text.size() : eol) - pos);
        pos = (eol == std::string::npos) ? text.size() + 1 : eol + 1;
        while (!line.empty() &&
               (line.back() == '\r' || line.back() == ' ' || line.back() == '\t'))
            line.pop_back();
        size_t start = 0;
        while (start < line.size() && (line[start] == ' ' || line[start] == '\t')) ++start;
        if (start > 0) line = line.substr(start);
        const size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        const std::string key = lower_copy(line.substr(0, eq));
        const std::string value = line.substr(eq + 1);
        if (key == "zoneid" && zone_id < 0) {
            char* endp = nullptr;
            const long long v = std::strtoll(value.c_str(), &endp, 10);
            if (endp != nullptr && endp != value.c_str()) zone_id = v;
        } else if (key == "hosturl" && hosturl.empty()) {
            hosturl = value;
        } else if (key == "referrerurl" && referrervalue.empty()) {
            referrervalue = value;
        } else if (key == "lastwriterpackagefamilyname" && last_writer_package.empty()) {
            last_writer_package = value;
        }
    }
}

}  // namespace

namespace aiext {

// ---------------- t_list_files ----------------
// {"dir","recursive","filter","limit","sort"} -> {"dir","count","truncated","files":[...]}
std::string t_list_files(const json& args, AiContext& /*ctx*/) {
    const std::string dir = arg_str(args, "dir", "");
    if (dir.empty()) return ERR("目录不存在: （缺少 dir 参数）");
    const bool recursive = arg_bool(args, "recursive", false);
    std::string filter = arg_str(args, "filter", "*");
    if (filter.empty()) filter = "*";
    const long long limit_ll = std::min(std::max(arg_int(args, "limit", 200), 1LL), 1000LL);
    const std::string sort_key = arg_str(args, "sort", "modified");

    std::error_code ec;
    fs::path root(aiutil::to_wide_sys(dir));
    if (!fs::is_directory(root, ec)) return ERR("目录不存在: " + dir);
    ec.clear();
    fs::path abs = fs::absolute(root, ec);  // 长路径前缀只对绝对路径有效
    if (!ec) root = abs;
    ec.clear();

    const std::wstring wfilter = aiutil::to_wide(filter);
    std::vector<json> items;
    // 硬上限：最多收集 limit*8 条（排序后仍截断到 limit，防止撑爆上下文）
    const size_t cap = static_cast<size_t>(limit_ll) * 8;

    auto add_entry = [&](const fs::path& p, bool hint_dir) {
        const std::wstring wp = p.wstring();
        WIN32_FILE_ATTRIBUTE_DATA fdata{};
        const bool got_attrs =
            GetFileAttributesExW(extended_path(wp).c_str(), GetFileExInfoStandard, &fdata) != 0;
        const bool is_dir =
            got_attrs ? ((fdata.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) : hint_dir;
        // filter 只对文件名匹配；目录项始终保留（is_dir 标注）
        if (!is_dir && !wildcard_match_w(p.filename().wstring(), wfilter)) return;
        json j = json::object();
        j["path"] = aiutil::to_utf8(wp);
        j["size"] = got_attrs
                        ? ((static_cast<unsigned long long>(fdata.nFileSizeHigh) << 32) |
                           fdata.nFileSizeLow)
                        : 0ULL;
        j["created"] = aiext::iso_from_filetime(got_attrs ? ft64(fdata.ftCreationTime) : 0LL);
        j["modified"] = aiext::iso_from_filetime(got_attrs ? ft64(fdata.ftLastWriteTime) : 0LL);
        j["accessed"] = aiext::iso_from_filetime(got_attrs ? ft64(fdata.ftLastAccessTime) : 0LL);
        j["attrs"] = got_attrs ? attrs_string(fdata.dwFileAttributes) : "unknown";
        j["is_dir"] = is_dir;
        items.push_back(std::move(j));
    };

    if (recursive) {
        fs::recursive_directory_iterator it(root, fs::directory_options::skip_permission_denied,
                                            ec);
        if (ec) return ERR("无法枚举目录（错误 " + std::to_string(ec.value()) + "）: " + dir);
        for (; it != fs::recursive_directory_iterator(); it.increment(ec)) {
            if (ec) break;  // 迭代错误不抛：中断即可（skip_permission_denied 已跳过无权限子目录）
            std::error_code sec;
            add_entry(it->path(), it->is_directory(sec));
            if (items.size() >= cap) break;
        }
    } else {
        fs::directory_iterator it(root, ec);
        if (ec) return ERR("无法枚举目录（错误 " + std::to_string(ec.value()) + "）: " + dir);
        for (; it != fs::directory_iterator(); it.increment(ec)) {
            if (ec) break;
            std::error_code sec;
            add_entry(it->path(), it->is_directory(sec));
            if (items.size() >= cap) break;
        }
    }

    // 排序（created/modified/size 新/大在前，name 按路径字典序升序）后截断 limit
    if (sort_key == "size") {
        std::sort(items.begin(), items.end(), [](const json& x, const json& y) {
            return x["size"].get<unsigned long long>() > y["size"].get<unsigned long long>();
        });
    } else if (sort_key == "name") {
        std::sort(items.begin(), items.end(), [](const json& x, const json& y) {
            return x["path"].get<std::string>() < y["path"].get<std::string>();
        });
    } else if (sort_key == "created") {
        std::sort(items.begin(), items.end(), [](const json& x, const json& y) {
            return x["created"].get<std::string>() > y["created"].get<std::string>();
        });
    } else {  // modified（默认）
        std::sort(items.begin(), items.end(), [](const json& x, const json& y) {
            return x["modified"].get<std::string>() > y["modified"].get<std::string>();
        });
    }

    const size_t take = std::min(items.size(), static_cast<size_t>(limit_ll));
    json files = json::array();
    for (size_t i = 0; i < take; ++i) files.push_back(items[i]);
    const bool truncated = items.size() > take;

    return aiutil::dump_json(json{{"dir", dir},
                                  {"count", items.size()},
                                  {"truncated", truncated},
                                  {"files", files}});
}

// ---------------- t_get_file_metadata ----------------
// {"path"} -> {"path","size","created","modified","accessed","attrs","hard_links",
//              "volume_serial","owner","domain","entropy","magic"}
std::string t_get_file_metadata(const json& args, AiContext& /*ctx*/) {
    const std::string path = arg_str(args, "path", "");
    if (path.empty()) return ERR("文件不存在: （缺少 path 参数）");

    const std::wstring wpath = aiutil::to_wide_sys(path);
    WIN32_FILE_ATTRIBUTE_DATA fdata{};
    if (GetFileAttributesExW(extended_path(wpath).c_str(), GetFileExInfoStandard, &fdata) == 0)
        return ERR("文件不存在: " + path);
    const bool is_dir = (fdata.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;

    // 硬链接数 + 卷序列号 + 属主（目录用 FILE_FLAG_BACKUP_SEMANTICS 也能打开；
    // 先用 READ_CONTROL 读安全描述符，失败退回 0 访问权只查基本信息）
    HANDLE h = CreateFileW(extended_path(wpath).c_str(), READ_CONTROL | FILE_READ_ATTRIBUTES,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                           OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        h = CreateFileW(extended_path(wpath).c_str(), 0,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    }
    const bool have_handle = h != INVALID_HANDLE_VALUE;

    DWORD hard_links = 0, volume_serial = 0;
    if (have_handle) {
        BY_HANDLE_FILE_INFORMATION bi{};
        if (GetFileInformationByHandle(h, &bi)) {
            hard_links = bi.nNumberOfLinks;
            volume_serial = bi.dwVolumeSerialNumber;
        }
    }

    std::string owner, domain;
    bool have_owner = false;
    if (have_handle) {
        PSID sid = nullptr;
        PSECURITY_DESCRIPTOR sd = nullptr;
        if (GetSecurityInfo(h, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, &sid, nullptr,
                            nullptr, nullptr, &sd) == ERROR_SUCCESS &&
            sid != nullptr) {
            wchar_t name[256] = {}, dom[256] = {};
            DWORD nlen = 256, dlen = 256;
            SID_NAME_USE use = SidTypeUnknown;
            if (LookupAccountSidW(nullptr, sid, name, &nlen, dom, &dlen, &use)) {
                owner = aiutil::to_utf8(std::wstring(name, nlen));
                domain = aiutil::to_utf8(std::wstring(dom, dlen));
                have_owner = true;
            }
        }
        if (sd != nullptr) LocalFree(sd);
    }
    if (have_handle) CloseHandle(h);

    // 熵 + 魔数（读前 1MB；目录或独占锁定的文件读不到时给 0/空）
    std::vector<unsigned char> data;
    if (!is_dir) {
        std::string rerr;
        data = aiext::read_file_bytes(path, 1u << 20, rerr);
    }
    double entropy = 0.0;
    if (!data.empty()) entropy = aiext::shannon_entropy(data.data(), data.size());
    std::string magic;
    if (!data.empty()) magic = detect_magic(data.data(), std::min<size_t>(data.size(), 8));

    json out = json::object();
    out["path"] = path;
    out["size"] =
        (static_cast<unsigned long long>(fdata.nFileSizeHigh) << 32) | fdata.nFileSizeLow;
    out["created"] = aiext::iso_from_filetime(ft64(fdata.ftCreationTime));
    out["modified"] = aiext::iso_from_filetime(ft64(fdata.ftLastWriteTime));
    out["accessed"] = aiext::iso_from_filetime(ft64(fdata.ftLastAccessTime));
    out["attrs"] = attrs_string(fdata.dwFileAttributes);
    out["hard_links"] = have_handle ? json(hard_links) : json(nullptr);
    out["volume_serial"] = have_handle ? json(volume_serial) : json(nullptr);
    out["owner"] = have_owner ? json(owner) : json(nullptr);
    out["domain"] = have_owner ? json(domain) : json(nullptr);
    out["entropy"] = entropy;
    out["magic"] = magic;
    return aiutil::dump_json(out);
}

// ---------------- t_get_ads ----------------
// {"path"} -> {"path","streams":[{name,size}],"zone":{...},"note"?}
// NTFS 备用数据流 + Zone.Identifier（判断下载/邮件来源）；无 Zone 流不是错误
std::string t_get_ads(const json& args, AiContext& /*ctx*/) {
    const std::string path = arg_str(args, "path", "");
    if (path.empty()) return ERR("文件不存在: （缺少 path 参数）");
    const std::wstring wpath = aiutil::to_wide_sys(path);
    WIN32_FILE_ATTRIBUTE_DATA fdata{};
    if (GetFileAttributesExW(extended_path(wpath).c_str(), GetFileExInfoStandard, &fdata) == 0)
        return ERR("文件不存在: " + path);

    json streams = json::array();
    std::string note;
    bool zone_exists = false;
    long long zone_id = -1;
    std::string hosturl, referrervalue, last_writer_package, zone_raw;

    WIN32_FIND_STREAM_DATA fsd{};
    HANDLE sh = FindFirstStreamW(wpath.c_str(), FindStreamInfoStandard, &fsd, 0);
    if (sh == INVALID_HANDLE_VALUE) {
        const DWORD e = GetLastError();
        if (e == static_cast<DWORD>(ERROR_HANDLE_EOF) || e == ERROR_NOT_SUPPORTED ||
            e == ERROR_INVALID_FUNCTION)
            note = "文件系统不支持 ADS";
        else
            note = "枚举流失败（错误 " + std::to_string(e) + "）";
    } else {
        size_t guard = 0;
        for (;;) {
            // cStreamName 形如 ":stream:$DATA"
            const std::wstring wname(fsd.cStreamName);
            json s = json::object();
            s["name"] = aiutil::to_utf8(wname);
            s["size"] = static_cast<unsigned long long>(fsd.StreamSize.QuadPart);
            streams.push_back(std::move(s));
            // 名字含 Zone.Identifier 的流读内容（下载来源证据）
            if (lower_copy(aiutil::to_utf8(wname)).find(":zone.identifier") != std::string::npos) {
                const std::string raw = read_ads_text_utf8(wpath + L":Zone.Identifier", 64 * 1024);
                if (!raw.empty()) {
                    zone_exists = true;
                    zone_raw = raw;
                    parse_zone_fields(raw, zone_id, hosturl, referrervalue, last_writer_package);
                }
            }
            if (++guard >= 128) break;  // 硬上限：最多 128 个流
            if (!FindNextStreamW(sh, &fsd)) break;
        }
        FindClose(sh);
    }

    json zone = json::object();
    zone["exists"] = zone_exists;
    if (zone_exists) {
        if (zone_id >= 0) zone["zone_id"] = zone_id;
        zone["hosturl"] = hosturl;
        zone["referrervalue"] = referrervalue;
        if (!last_writer_package.empty()) zone["last_writer_package"] = last_writer_package;
    }

    json out = json::object();
    out["path"] = path;
    out["streams"] = streams;
    out["zone"] = zone;
    out["zone_identifier"] = zone;  // 兼容 ai_tools_ext.h 注释里的旧键名
    if (!zone_raw.empty())
        out["ads_content"] = aiutil::utf8_truncate(zone_raw, 2000);
    else
        out["ads_content"] = nullptr;
    if (!note.empty()) out["note"] = note;
    return aiutil::dump_json(out);
}

// ---------------- t_get_recent_files ----------------
// {"hours","volumes","limit","event"} -> {"count","truncated","volumes":[...],"files":[...]}
// USN 日志枚举（FSCTL_ENUM_USN_DATA，需要管理员；失败给明确原因）
std::string t_get_recent_files(const json& args, AiContext& /*ctx*/) {
    double hours = arg_num(args, "hours", 24.0);
    if (hours < 0) hours = 0;
    if (hours > 24.0 * 365.0) hours = 24.0 * 365.0;
    const long long limit_ll = std::min(std::max(arg_int(args, "limit", 100), 1LL), 1000LL);
    const std::string event = lower_copy(arg_str(args, "event", "all"));

    // Reason 过滤位：create -> FILE_CREATE，rename -> RENAME_NEW_NAME，all -> 两者
    DWORD mask = 0;
    if (event == "create")
        mask = USN_REASON_FILE_CREATE;
    else if (event == "rename")
        mask = USN_REASON_RENAME_NEW_NAME;
    else
        mask = USN_REASON_FILE_CREATE | USN_REASON_RENAME_NEW_NAME;

    // 逗号分隔的卷列表（默认 C:\）。接受 C / C: / C:\ / \\.\C: 等写法，
    // 统一规范成盘符；非法写法直接拒绝——否则会拼出 \\.\C:: 这种设备路径，
    // CreateFileW 返回错误 2（找不到文件），看起来像"卷打不开"，很难排查。
    std::vector<std::string> vols;
    {
        const std::string vols_arg = arg_str(args, "volumes", "C:\\");
        size_t start = 0;
        while (start <= vols_arg.size()) {
            const size_t comma = vols_arg.find(',', start);
            std::string part = vols_arg.substr(
                start, (comma == std::string::npos ? vols_arg.size() : comma) - start);
            const std::string original = part;
            // 去空白与引号
            size_t b = 0, e = part.size();
            while (b < e && (part[b] == ' ' || part[b] == '\t' || part[b] == '"')) ++b;
            while (e > b && (part[e - 1] == ' ' || part[e - 1] == '\t' || part[e - 1] == '"')) --e;
            part = part.substr(b, e - b);
            // 去设备前缀（长路径前缀 / 设备命名空间前缀共 4 个字符）
            if (part.rfind("\\\\?\\", 0) == 0) {
                part = part.substr(4);
            } else if (part.rfind("\\\\.\\", 0) == 0) {
                part = part.substr(4);
            }
            // 去尾部 \ / :
            while (!part.empty() && (part.back() == '\\' || part.back() == '/' ||
                                     part.back() == ':' || part.back() == ' '))
                part.pop_back();

            if (!part.empty()) {
                if (part.find_first_of(":\\/") != std::string::npos)
                    return ERR("volumes 只接受盘符（如 C 或 C,D 或 C:\\,D:\\），收到: " + original);
                vols.push_back(part);
            }
            if (comma == std::string::npos) break;
            start = comma + 1;
        }
    }
    if (vols.empty()) return ERR("卷参数为空（示例: C 或 C,D 或 C:\\,D:\\）");

    // 时间过滤：只保留 now - hours*3600 秒之后（FILETIME，100ns 单位）
    FILETIME now_ft{};
    GetSystemTimeAsFileTime(&now_ft);
    const unsigned long long now64 =
        (static_cast<unsigned long long>(now_ft.dwHighDateTime) << 32) | now_ft.dwLowDateTime;
    const unsigned long long span =
        static_cast<unsigned long long>(hours * 3600.0 * 10000000.0);
    const unsigned long long cutoff = (now64 > span) ? now64 - span : 0;

    const size_t collect_cap = static_cast<size_t>(limit_ll) * 8;  // 硬上限：单卷收集量
    std::vector<unsigned char> buf(1u << 20);                      // 1MB 枚举缓冲

    json files = json::array();
    json volumes_out = json::array();
    bool truncated = false;

    for (const std::string& vol : vols) {
        // 0 访问权即可发 USN 控制码（\\.\C: 形式的卷设备路径）；
        // 个别系统上 0 访问权会被拒，再补一次 FILE_READ_ATTRIBUTES
        const std::wstring wdev = L"\\\\.\\" + aiutil::to_wide(vol) + L":";
        HANDLE hv = CreateFileW(wdev.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                OPEN_EXISTING, 0, nullptr);
        if (hv == INVALID_HANDLE_VALUE)
            hv = CreateFileW(wdev.c_str(), FILE_READ_ATTRIBUTES,
                             FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0,
                             nullptr);
        if (hv == INVALID_HANDLE_VALUE) {
            const DWORD e = GetLastError();
            if (e == 5) return ERR("枚举 USN 日志需要管理员（错误 5）：请以管理员身份运行 "
                                   "avengine.exe；非管理员可改用 list_files 或 get_file_metadata");
            json v = json::object();
            v["volume"] = vol + ":";
            v["device"] = aiutil::to_utf8(wdev);
            std::string reason = "打开卷失败（错误 " + std::to_string(e) + "）";
            if (e == 2) reason += "：卷设备路径无效，volumes 只接受盘符（如 C）";
            else if (e == 3) reason += "：路径无效";
            else if (e == 5) reason += "：需要管理员";
            v["error"] = reason;
            volumes_out.push_back(std::move(v));
            continue;
        }

        // MFT_ENUM_DATA：StartFileReferenceID=0、LowUsn=0、HighUsn=最大；
        // 首次调用输出首 8 字节即当前最大 USN，同时作为后续枚举的续点
        MFT_ENUM_DATA med{};
        med.StartFileReferenceNumber = 0;
        med.LowUsn = 0;
        med.HighUsn = 0x7FFFFFFFFFFFFFFFLL;

        unsigned long long scanned = 0, collected = 0;
        bool first = true, vol_failed = false;
        std::string vol_error;

        while (collected < collect_cap) {
            DWORD got = 0;
            if (!DeviceIoControl(hv, FSCTL_ENUM_USN_DATA, &med, sizeof(med), buf.data(),
                                 static_cast<DWORD>(buf.size()), &got, nullptr)) {
                const DWORD e = GetLastError();
                if (e == 5) {
                    CloseHandle(hv);
                    return ERR("枚举 USN 日志需要管理员（错误 5）");
                }
                if (e == static_cast<DWORD>(ERROR_HANDLE_EOF)) break;  // 枚举正常结束
                if (first) {
                    std::string hint;
                    if (e == static_cast<DWORD>(ERROR_JOURNAL_NOT_ACTIVE))
                        hint = "，该卷未启用 USN 日志（可执行 fsutil usn createjournal m=0x1000000 a=0x100000 C:）";
                    else if (e == 1)  // ERROR_INVALID_FUNCTION
                        hint = "，通常是没有管理员权限（FSCTL_ENUM_USN_DATA 被拒），"
                               "或该卷文件系统不支持 USN（FAT32/exFAT 不支持）";
                    else if (e == 5)
                        hint = "，需要管理员权限";
                    vol_error = std::string("枚举 USN 失败（错误 ") + std::to_string(e) + hint + "）";
                    vol_failed = true;
                }
                break;
            }
            if (got <= sizeof(ULONGLONG)) break;  // 没有更多记录
            first = false;

            // 输出布局：首 8 字节为续点 USN，其后是记录
            ULONGLONG next = 0;
            std::memcpy(&next, buf.data(), sizeof(next));
            med.StartFileReferenceNumber = next;

            const unsigned char* p = buf.data() + sizeof(ULONGLONG);
            const unsigned char* end = buf.data() + got;
            while (p + 8 <= end) {
                DWORD rec_len = 0;
                std::memcpy(&rec_len, p, 4);
                if (rec_len < 8 || p + rec_len > end) break;
                WORD major = 0;
                std::memcpy(&major, p + 4, 2);

                unsigned long long usn = 0, ts64 = 0;
                DWORD reason = 0;
                size_t name_off = 0, name_bytes = 0;
                if (major == 3) {  // USN_RECORD_V3（64 位卷）：按 V3 布局解析
                    if (rec_len < 80) {
                        p += rec_len;
                        continue;
                    }
                    std::memcpy(&usn, p + 40, 8);         // Usn
                    std::memcpy(&ts64, p + 48, 8);        // TimeStamp
                    std::memcpy(&reason, p + 56, 4);      // Reason
                    std::memcpy(&name_bytes, p + 72, 4);  // FileNameLength（字节）
                    std::memcpy(&name_off, p + 76, 4);    // FileNameOffset
                } else {  // USN_RECORD_V2（32 位卷）与其他版本按 V2 布局解析
                    if (rec_len < 60) {
                        p += rec_len;
                        continue;
                    }
                    std::memcpy(&usn, p + 24, 8);        // Usn
                    std::memcpy(&ts64, p + 32, 8);       // TimeStamp
                    std::memcpy(&reason, p + 40, 4);     // Reason
                    WORD nl = 0, no = 0;
                    std::memcpy(&nl, p + 56, 2);         // FileNameLength（字节）
                    std::memcpy(&no, p + 58, 2);         // FileNameOffset
                    name_bytes = nl;
                    name_off = no;
                }

                if ((reason & mask) != 0 && ts64 >= cutoff && name_off > 0 && name_bytes > 0 &&
                    p + name_off + name_bytes <= p + rec_len) {
                    std::wstring wname(name_bytes / 2, L'\0');  // 文件名是 UTF-16
                    std::memcpy(&wname[0], p + name_off, (name_bytes / 2) * 2);
                    json f = json::object();
                    f["volume"] = vol + ":\\";
                    f["usn"] = usn;
                    f["name"] = aiutil::to_utf8(wname);
                    f["reason"] = usn_reason_array(reason);
                    f["ts"] = aiext::iso_from_filetime(static_cast<long long>(ts64));
                    files.push_back(std::move(f));
                    ++collected;
                }
                ++scanned;
                p += rec_len;
                if (collected >= collect_cap) break;
            }
        }
        CloseHandle(hv);

        json v = json::object();
        v["volume"] = vol + ":\\";
        v["records_scanned"] = scanned;
        v["matched"] = collected;
        if (vol_failed) v["error"] = vol_error;
        volumes_out.push_back(std::move(v));
    }

    // 全局截断到 limit（单卷收集已被 limit*8 硬上限约束）
    const size_t total_collected = files.size();
    if (total_collected > static_cast<size_t>(limit_ll)) {
        json keep = json::array();
        for (size_t i = 0; i < static_cast<size_t>(limit_ll); ++i) keep.push_back(files[i]);
        files = std::move(keep);
        truncated = true;
    }

    return aiutil::dump_json(json{{"count", total_collected},
                                  {"truncated", truncated},
                                  {"volumes", volumes_out},
                                  {"files", files}});
}

}  // namespace aiext
