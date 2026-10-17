// ai_tools_ext.h - AI 工具扩展库（对应 todolist.txt 的 36 项）
//
// 声明 + 共享小工具。实现分散在：
//   ai_tools_ext.cpp      共享基础设施（审计日志 / dry-run / 子进程捕获 / 熵 / 订阅槽）
//   ai_tools_process.cpp  进程/线程/句柄/内存/签名
//   ai_tools_fs.cpp       文件取证与时间线
//   ai_tools_reg.cpp      注册表与持久化专项
//   ai_tools_net.cpp      网络侧
//   ai_tools_logs.cpp     日志与脚本侧
//   ai_tools_intel.cpp    情报与元工具
//
// 给实现者的硬性约定：
//   1) 所有函数签名：std::string t_xxx(const nlohmann::json& args, AiContext& ctx)；
//      成功返回 UTF-8 JSON 文本，失败返回 "ERROR: 原因" 文本（不抛异常）。
//   2) 任何 nlohmann::json 序列化必须用 aiutil::dump_json(j)，绝不能用 j.dump()
//      （默认 dump 遇非法 UTF-8 会抛 type_error.316，见 ai_util.h 注释）。
//   3) 文件路径进 std::filesystem / Win32 时用 aiutil::to_wide_sys()。
//   4) 输出必须带上限：所有 list 类工具接受 limit（默认值写进 description），
//      并设置硬上限，防止把模型上下文撑爆。
//   5) 处置类（改系统状态）工具：先 aiext::dry_run_requested(args, ctx) 判断，
//      dry-run 时只返回「将要执行的命令/动作」并把 "dry_run": true 写进结果，不要改系统。
//      审计由 ai_execute_tool 统一完成（写入 ctx.audit_log_file），工具内**不要**重复调用。
//   6) 需要管理员的操作（服务/驱动/Security 日志/USN 等）失败时给出明确原因
//      （ERROR: ...，提示需要管理员），不要静默返回空。
//   7) 不要用 getaddrinfo 之外的网络请求做情报查询；HTTP 只在配置了端点时使用。
#pragma once

#include <nlohmann/json.hpp>

#include <string>
#include <vector>

#include "ai_tools.h"   // AiContext

namespace aiext {

// ---------------- 共享基础设施（实现见 ai_tools_ext.cpp） ----------------

// 处置类工具是否按 dry-run 执行：显式 args.dry_run 优先，否则取 ctx.dry_run
bool dry_run_requested(const nlohmann::json& args, AiContext& ctx);

/*
 * 操作审计：追加一行到 ctx.audit_log_file（logs\ai_audit.log）。
 * 行格式（UTF-8）：ts | tool | args(JSON) | outcome | user
 * 带哈希链：每行含 prev_hash 与本行 hash=sha256(prev_hash+payload)，防篡改可校验。
 * 任何失败静默忽略（审计绝不影响工具本身）。
 */
void audit_log(AiContext& ctx, const std::string& tool, const nlohmann::json& args,
               const std::string& outcome);

// 运行一条命令行并捕获 stdout+stderr（CREATE_NO_WINDOW，UTF-8 返回，按 max_chars 截断）
std::string run_capture(const std::string& cmd_utf8, int timeout_ms = 30000,
                        size_t max_chars = 8000);

std::string now_iso();
std::string iso_from_filetime(long long ft64);   // FILETIME(64bit) -> ISO 字符串

double shannon_entropy(const unsigned char* data, size_t len);

std::vector<unsigned char> read_file_bytes(const std::string& path_utf8, size_t max_bytes,
                                           std::string& err);

// 缓冲区 SHA256（BCrypt），十六进制小写；空输入返回空串
std::string sha256_buffer(const unsigned char* data, size_t len);

// ---------------- 事件订阅（单槽位，实现见 ai_tools_ext.cpp） ----------------

// 开始订阅（wevtapi EvtSubscribe）；重复调用会替换当前订阅。返回 0 成功。
int  event_sub_start(const std::string& channel_utf8, const std::string& keyword, std::string& err);
// 取走自上次以来新到达的事件（紧凑单行文本数组，最多 max_items 条）
std::vector<std::string> event_sub_poll(int max_items);
bool event_sub_stop();
bool event_sub_active();

// ---------------- 工具声明（实现见 ai_tools_*.cpp，均在 namespace aiext 内定义） ----------------

// ============================================================
// 一、进程 / 线程 / 句柄 / 内存 / 签名（ai_tools_process.cpp）
// ============================================================

// {"pid":N,"depth":N,"limit":N} -> {"root":pid,"count":N,"tree":[{pid,ppid,name,exe,depth,children:[...]}]}
std::string t_get_process_tree(const nlohmann::json& args, AiContext& ctx);

// {"pid":N,"limit":N} -> {"chain":[{pid,ppid,name,exe,started?}...],"depth":N}（从目标回溯到根）
std::string t_get_parent_chain(const nlohmann::json& args, AiContext& ctx);

// {"pid":N} -> {"pid","exe","commandline","current_dir","integrity","user","domain","is_elevated","wow64"}
// 通过读 PEB->ProcessParameters（x64 与 WOW64 32 位都支持）；失败给明确原因
std::string t_get_process_commandline(const nlohmann::json& args, AiContext& ctx);

// {"pid":N,"limit":N} -> {"pid","count","env":{"KEY":"VALUE",...}}（截断过的环境变量块）
std::string t_get_process_env(const nlohmann::json& args, AiContext& ctx);

// {"pid":N,"limit":N} -> {"pid","count","threads":[{tid,start_address,start_module,in_image,backed_by,suspicious}]}
// in_image=false 且 backed_by=private/mapped 的可执行起始地址是注入/反射加载证据
std::string t_list_threads(const nlohmann::json& args, AiContext& ctx);

// {"tid":N} -> {"tid","pid","start_address","module","in_image","backed_by","suspicious"}
std::string t_get_thread_start_address(const nlohmann::json& args, AiContext& ctx);

// {"pid":N,"limit":N,"type":"File|Mutant|Section|..."} -> {"pid","count","handles":[{handle,type,name?}]}
// 句柄类型全列；名字只对 File（GetFinalPathNameByHandle）查询，其他类型只报类型（避免 NtQueryObject 卡死）
std::string t_list_handles(const nlohmann::json& args, AiContext& ctx);

/*
 * {"pid":N,"max_mb":32,"max_regions":64,"rules_path":可选,"yara":bool}
 * -> {"pid","regions_total","executable_private","scanned","skipped","matches":[...],
 *     "regions":[{addr,size,protect,state,backed_by,entropy}]}
 * 枚举 MEM_COMMIT + PAGE_EXECUTE_* 的私有/无映像区域，读出来做熵与（可选）YARA 扫描。
 */
std::string t_scan_memory_regions(const nlohmann::json& args, AiContext& ctx);

// {"pid":N} -> 挂起进程（NtSuspendProcess）；处置类，支持 dry_run
std::string t_suspend_process(const nlohmann::json& args, AiContext& ctx);

// {"pid":N} -> 恢复进程（NtResumeProcess）；处置类，支持 dry_run
std::string t_resume_process(const nlohmann::json& args, AiContext& ctx);

// {"pid":N,"include_self":bool,"dry_run":bool} -> 先杀全部后代（叶子优先）再杀自己，防互守复活；处置类
std::string t_kill_process_tree(const nlohmann::json& args, AiContext& ctx);

// {"path":P,"check_revocation":bool} -> Authenticode 校验：
// {"path","signed","status","result_code","signer","issuer","timestamp","revocation"}
std::string t_verify_signature(const nlohmann::json& args, AiContext& ctx);

// ============================================================
// 二、文件取证与时间线（ai_tools_fs.cpp）
// ============================================================

// {"dir":D,"recursive":bool,"filter":"*.exe","limit":200,"sort":"created|modified|size"}
// -> {"dir","count","truncated","files":[{path,size,created,modified,accessed,attrs}]}
std::string t_list_files(const nlohmann::json& args, AiContext& ctx);

// {"path":P} -> {"path","size","created","modified","accessed","attrs","hard_links","owner","entropy","magic"}
std::string t_get_file_metadata(const nlohmann::json& args, AiContext& ctx);

// {"path":P} -> {"path","streams":[{name,size}],"zone_identifier":{"exists","hosturl","referrervalue"},"ads_content":...}
// 备用数据流（ADS）+ Zone.Identifier（判断下载/邮件来源）
std::string t_get_ads(const nlohmann::json& args, AiContext& ctx);

// {"hours":24,"volumes":"C:\\","limit":100,"event":"create|rename|all"}
// -> {"count","truncated","files":[{volume,usn,name,reason,ts}]}
// USN 日志枚举（FSCTL_ENUM_USN_DATA，需要管理员；失败给明确原因）
std::string t_get_recent_files(const nlohmann::json& args, AiContext& ctx);

// ============================================================
// 三、注册表与持久化专项（ai_tools_reg.cpp）
// ============================================================

// {"key":"HKLM/SOFTWARE/...","depth":2,"values":bool,"limit":200}
// -> {"key","count","truncated","items":[{type:key|value,path,name,data}]}
std::string t_enumerate_registry_tree(const nlohmann::json& args, AiContext& ctx);

/*
 * {} -> {"count","findings":[{location,value,data,suspicion,note}]}
 * 聚合检查：HKLM/HKCU Run 与 RunOnce、Winlogon Shell/Userinit、AppInit_DLLs(32/64)、
 * IFEO Debugger、Services 的非标准 ImagePath、HKCU COM InprocServer32 劫持、
 * LSA Security Providers、Print Monitor、WMI __EventFilter 订阅。
 */
std::string t_check_persistence(const nlohmann::json& args, AiContext& ctx);

// {"limit":50} -> {"count","subscriptions":[{filter_name,query,consumer_name,consumer_type,command}]}
// WMI 永久订阅（root\subscription：__EventFilter / __EventConsumer / __FilterToConsumerBinding）
std::string t_list_wmi_subscriptions(const nlohmann::json& args, AiContext& ctx);

// {} -> {"folders":[{path,files:[...]}],"count"}
// 用户 + 公共启动文件夹（shell:startup / shell:common startup）
std::string t_list_startup_folders(const nlohmann::json& args, AiContext& ctx);

// {"limit":200} -> {"count","drivers":[{name,base,address}]}
// EnumDeviceDrivers 枚举已加载内核驱动（用户态可枚举）
std::string t_list_drivers_loaded(const nlohmann::json& args, AiContext& ctx);

// ============================================================
// 四、网络侧（ai_tools_net.cpp）
// ============================================================

// {"limit":200} -> {"count","entries":[{name,type,data,ttl}]}
// 本机 DNS 解析缓存（dnsapi DnsGetCacheDataTable），补历史 C2 域名
std::string t_get_dns_cache(const nlohmann::json& args, AiContext& ctx);

// {"limit":200,"pid":可选} -> {"count","endpoints":[{local,remote,pid,process,state}]}
std::string t_list_udp_endpoints(const nlohmann::json& args, AiContext& ctx);

// {"limit":200,"pid":可选} -> {"count","listeners":[{local,port,pid,process,modules?}]}
std::string t_list_listeners(const nlohmann::json& args, AiContext& ctx);

// {"ip":"1.2.3.4"} -> {"ip","domains":[...],"count"}
// 用 DNS 缓存把远端 IP 反查成最近解析过的域名（SNI 抓包的替代方案）
std::string t_resolve_ip_domains(const nlohmann::json& args, AiContext& ctx);

// {"limit":100} -> {"count","routes":[{dest,mask,gateway,metric,if_index}]}
std::string t_get_route_table(const nlohmann::json& args, AiContext& ctx);

// {"limit":200} -> {"count","arp":[{ip,mac,type,if_index}]}
std::string t_get_arp_cache(const nlohmann::json& args, AiContext& ctx);

// {"profile":"domain|private|public|all","limit":100}
// -> {"count","rules_text":"...","truncated"}（netsh advfirewall 只读查询）
std::string t_list_firewall_rules(const nlohmann::json& args, AiContext& ctx);

// {} -> {"winhttp":{"proxy","bypass"},"wininet":{"proxy_enable","proxy_server","autoconfig_url","proxy_override"}}
std::string t_get_proxy_config(const nlohmann::json& args, AiContext& ctx);

// {"ip":"1.2.3.4","name":可选,"direction":"out|in","dry_run":bool} -> 防火墙封禁；处置类，支持 dry_run
std::string t_block_ip(const nlohmann::json& args, AiContext& ctx);

// {"domain":"evil.com","dry_run":bool} -> 先解析再封禁解析出的 IP；处置类，支持 dry_run
std::string t_block_domain(const nlohmann::json& args, AiContext& ctx);

// ============================================================
// 五、日志与脚本侧（ai_tools_logs.cpp）
// ============================================================

// {"hours":24,"limit":50,"channel":可选} -> {"count","events":[{time,context_info,script_text}]}
// PowerShell 4104 脚本块日志（Microsoft-Windows-PowerShell/Operational）
std::string t_get_script_block_log(const nlohmann::json& args, AiContext& ctx);

// {"limit":20} -> {"count","transcripts":[{path,size,modified,preview}]}
// 查找 PowerShell 转录文件（Documents 下，仅在启用转录时存在）
std::string t_get_powershell_transcript(const nlohmann::json& args, AiContext& ctx);

/*
 * {"text":"...","encodings":"auto|base64|base64_utf16|hex|xor","key":可选,"limit":4000}
 * -> {"decoded":"...","encoding":"...","notes":[...]}
 * 还原 -EncodedCommand（base64+UTF-16LE）、hex、单字节/密钥 XOR、连接与空白剥离；
 * gzip 不支持（返回明确说明）。
 */
std::string t_decode_script(const nlohmann::json& args, AiContext& ctx);

// {"source":"sysmon|...","keyword":可选} -> 开始实时订阅，返回 {"subscription":1,"channel":...}
std::string t_subscribe_events(const nlohmann::json& args, AiContext& ctx);

// {"max":50} -> {"count","events":[...]}（自上次 tail 以来新到达的事件）
std::string t_tail_events(const nlohmann::json& args, AiContext& ctx);

// {} -> 停止当前订阅 {"stopped":true}
std::string t_unsubscribe_events(const nlohmann::json& args, AiContext& ctx);

// {"channel":"Microsoft-Windows-DNS-Client/Operational","hours":1,"limit":50,"level":可选}
// -> 按显式通道名查询事件（query_events 的任意通道版）
std::string t_get_etw(const nlohmann::json& args, AiContext& ctx);

// {"limit":50} -> AMSI 相关事件（Threat-Intelligence 通道通常需要 PPL，读不到时给明确说明并回退 4104）
std::string t_get_amsi_events(const nlohmann::json& args, AiContext& ctx);

// {"hours":24,"limit":50,"event_id":可选} -> {"count","events":[{time,eid,user,domain,logon_type,process}]}
// Security 日志 4624/4625/4672/4688（读 Security 通道需要管理员；失败给明确原因）
std::string t_get_security_log(const nlohmann::json& args, AiContext& ctx);

// ============================================================
// 六、处置闭环（ai_tools_reg.cpp / ai_tools_process.cpp）
// ============================================================

// {"type":"registry|service|task|wmi","target":"...","dry_run":bool} -> 按类型删除持久化项；处置类
std::string t_remove_persistence(const nlohmann::json& args, AiContext& ctx);

// {"name":"...","force":bool,"dry_run":bool} -> 停止服务；处置类
std::string t_stop_service(const nlohmann::json& args, AiContext& ctx);

// {"name":"...","dry_run":bool} -> 删除服务（先停再删）；处置类
std::string t_delete_service(const nlohmann::json& args, AiContext& ctx);

// {"name":"...","dry_run":bool} -> 删除计划任务（schtasks /delete /f）；处置类
std::string t_delete_scheduled_task(const nlohmann::json& args, AiContext& ctx);

// {"key":"HKCU/...","value_name":"...","dry_run":bool} -> 删除注册表值；处置类
std::string t_delete_registry_value(const nlohmann::json& args, AiContext& ctx);

// ============================================================
// 七、情报与元工具（ai_tools_intel.cpp）
// ============================================================

// {"value":"hash/ip/domain/url","type":可选} -> {"value","type","local":{"..."},"provider":{...}|null}
// 本地启发式（私网/可疑 TLD/本地黑名单文件）+ 可选配置端点查询（未配置则不联网）
std::string t_reputation_lookup(const nlohmann::json& args, AiContext& ctx);

// {"path":P} -> 聚合静态报告：哈希/PE/熵/签名/字符串摘要/YARA+ClamAV 结论，一份 JSON
std::string t_build_static_report(const nlohmann::json& args, AiContext& ctx);

// {"name":"...","strings":["..."],"condition":可选,"description":可选} ->
// 校验规则可编译后写入 rules\yara\<name>.yar，返回 {"path","compiled":true}
std::string t_write_yara_rule(const nlohmann::json& args, AiContext& ctx);

// {"rule":"<yara 源文本或 rules\yara 下文件名>","target":P,"limit":50}
// -> 用给定规则（临时编译）扫描文件/目录，返回 {"matches":[{path,rules}],"scanned":N}
std::string t_scan_with_rule(const nlohmann::json& args, AiContext& ctx);

// {"kind":"process|service|task|startup|all"} -> {"kind","saved_to","count"}（基线快照存 logs/baselines/）
std::string t_save_baseline(const nlohmann::json& args, AiContext& ctx);

// {"kind":...,"baseline":可选} -> {"kind","added":[...],"removed":[...],"unchanged":N}
// 当前状态与基线 diff（没存过基线时给明确提示）
std::string t_compare_baseline(const nlohmann::json& args, AiContext& ctx);

// {"dry_run":可选,"max_tool_result_chars":可选} -> 查看/设置本会话安全参数
std::string t_set_safety(const nlohmann::json& args, AiContext& ctx);

// ---------------- 第九节：窗口（ai_tools_window.cpp） ----------------
// {"scope":"auto|desktop|session|all","title_contains","class_contains","pid","visible_only","limit"}
//   -> {"count","matched","truncated","scope","windows":[{hwnd,class,title,pid,tid,process,
//       process_path,rect,visible,style,ex_style,style_flags,station,desktop,
//       class_module:{base,module,path,in_module_list,signed},
//       wndproc:{addr,module,in_module_list,signed,backed_by,protect},
//       findings:[...]}],"diagnostics":{...}}
//   auto：Win10+ 走 EnumWindowStations→OpenDesktop→EnumDesktopWindows；Win7/8 只枚举当前桌面。
//   关键点：class_module 是"注册该窗口类的模块"，wndproc 是"真正处理消息的代码"，
//   两者都不在目标 loader 列表里 → 手工映射/被隐藏（findings 会标出来）。
std::string t_list_windows(const nlohmann::json& args, AiContext& ctx);

// {"hwnd":"0x00010A2C"} -> 单窗口完整画像（父/属主链、窗口线程起始地址与内存属性、
//   模块签名抽样、hung、next_steps）
std::string t_get_window_detail(const nlohmann::json& args, AiContext& ctx);

// {"hwnd":"0x...","method":"wm_close|end_task","dry_run":可选} -> 关闭窗口（处置类）
//   WM_DESTROY 不能跨进程投递（DestroyWindow 的内部通知），会明确拒绝并给出替代方式
std::string t_close_window(const nlohmann::json& args, AiContext& ctx);

}  // namespace aiext

// 全局作用域可见（ai_tools.cpp 的注册表直接用这些名字）
using aiext::t_get_process_tree;
using aiext::t_get_parent_chain;
using aiext::t_get_process_commandline;
using aiext::t_get_process_env;
using aiext::t_list_threads;
using aiext::t_get_thread_start_address;
using aiext::t_list_handles;
using aiext::t_scan_memory_regions;
using aiext::t_suspend_process;
using aiext::t_resume_process;
using aiext::t_kill_process_tree;
using aiext::t_verify_signature;
using aiext::t_list_files;
using aiext::t_get_file_metadata;
using aiext::t_get_ads;
using aiext::t_get_recent_files;
using aiext::t_enumerate_registry_tree;
using aiext::t_check_persistence;
using aiext::t_list_wmi_subscriptions;
using aiext::t_list_startup_folders;
using aiext::t_list_drivers_loaded;
using aiext::t_delete_registry_value;
using aiext::t_remove_persistence;
using aiext::t_stop_service;
using aiext::t_delete_service;
using aiext::t_delete_scheduled_task;
using aiext::t_get_dns_cache;
using aiext::t_list_udp_endpoints;
using aiext::t_list_listeners;
using aiext::t_resolve_ip_domains;
using aiext::t_get_route_table;
using aiext::t_get_arp_cache;
using aiext::t_list_firewall_rules;
using aiext::t_get_proxy_config;
using aiext::t_block_ip;
using aiext::t_block_domain;
using aiext::t_get_script_block_log;
using aiext::t_get_powershell_transcript;
using aiext::t_decode_script;
using aiext::t_subscribe_events;
using aiext::t_tail_events;
using aiext::t_unsubscribe_events;
using aiext::t_get_etw;
using aiext::t_get_amsi_events;
using aiext::t_get_security_log;
using aiext::t_reputation_lookup;
using aiext::t_build_static_report;
using aiext::t_write_yara_rule;
using aiext::t_scan_with_rule;
using aiext::t_save_baseline;
using aiext::t_compare_baseline;
using aiext::t_set_safety;
using aiext::t_list_windows;
using aiext::t_get_window_detail;
using aiext::t_close_window;
