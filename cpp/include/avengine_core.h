/*
 * avengine_core.h - AvEngine C++ 内核的稳定 C ABI
 *
 * 供 Python(ctypes) 等调用方使用。所有返回的 char* 均为 UTF-8 JSON 字符串，
 * 调用方必须用 avc_free() 释放。返回 NULL 表示失败，可用 avc_last_error() 取原因。
 */
#ifndef AVENGINE_CORE_H
#define AVENGINE_CORE_H

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32)
#define AVC_API __declspec(dllexport)
#else
#define AVC_API
#endif

/* 版本号字符串，静态内存，无需释放 */
AVC_API const char* avc_version(void);

/* 最近一次错误（线程内），静态/线程局部内存，无需释放；无错误返回空串 */
AVC_API const char* avc_last_error(void);

/* 计算文件 SHA256，返回 {"path":..., "sha256":...} */
AVC_API char* avc_sha256(const char* path);

/*
 * 扫描单个文件（YARA + ClamAV）。
 * rules_path 为 YARA 规则目录（可为 NULL/空则不启 YARA）；
 * clam_host 为 NULL/空 或 clam_port<=0 则不启用 ClamAV。
 * 返回: {"path","size","sha256","yara":{"available","matches":[]},
 *        "clamav":{"available","virus"},"verdict"}
 */
AVC_API char* avc_scan_path(const char* path, const char* rules_path,
                            const char* clam_host, int clam_port, int clam_timeout);

/*
 * 递归扫描目录，返回:
 * {"scanned":N,"infected":[...],"yara":{path:[rules]},"clamav":{path:virus}}
 */
AVC_API char* avc_scan_dir(const char* dir, const char* rules_path,
                           const char* clam_host, int clam_port, int clam_timeout);

/* clamd VERSION，返回 {"available":bool,"version":str,"error":str} */
AVC_API char* avc_clam_version(const char* host, int port, int timeout);

/* 通知 clamd 重载病毒库，返回 {"ok":bool,"error":str} */
AVC_API char* avc_clam_reload(const char* host, int port, int timeout);

/* 引擎状态 {"yara":{available,rules_count,skipped},"clamav":{available,version}} */
AVC_API char* avc_engine_status(const char* rules_path, const char* clam_host, int clam_port,
                                int clam_timeout);

/*
 * 常驻实时监控（Sysmon 文件事件 + 可选定时目录扫描）。
 * monitor_paths 为分号分隔的目录列表（用于定时扫描）；timer_interval<=0 关闭定时。
 * rules_path/clam_* 同 scan。成功返回 0，失败 -1（详见 avc_last_error）。
 */
AVC_API int avc_monitor_start(const char* rules_path, const char* quar_dir, const char* clam_host,
                              int clam_port, int clam_timeout, const char* channel,
                              const char* monitor_paths, int timer_interval, int on_access);

/* 停止监控并等待线程退出 */
AVC_API void avc_monitor_stop(void);

/* 监控是否在运行（1/0） */
AVC_API int avc_monitor_running(void);

/* 取最多 max_items 条威胁事件（JSON 数组，无事件为 "[]"） */
AVC_API char* avc_monitor_poll(int max_items);

/* 监控状态 {"running","error","scanned","threats"} */
AVC_API char* avc_monitor_status(void);

/*
 * ---- AI 分析 ----
 * config_json 为 UTF-8 JSON 字符串，包含:
 *   base_url/api_key/model/timeout/max_rounds/interval/max_events_per_batch/
 *   max_event_chars/max_tool_result_chars/scan_analysis/batch_sources[]/
 *   rules_path/quarantine_dir/clam_host/clam_port/clam_timeout/log_file/dump_dir/project_root
 * 返回值均为 SessionResult JSON（含 ended_by/final_text/rounds/tool_calls/trace）。
 */
AVC_API char* avc_ai_test(const char* config_json);
AVC_API char* avc_ai_run_batch(const char* config_json, int minutes);
AVC_API char* avc_ai_ask(const char* config_json, const char* question);
AVC_API char* avc_ai_analyze_detection(const char* config_json, const char* detection_json);

/*
 * 流式事件回调：会话进行中同步回调（与调用线程相同），event_json 为 UTF-8 JSON 对象，
 * 生命周期仅限本次回调，需要保留请自行拷贝。事件 kind 见 ai_session.h 的 AiSessionHooks 注释：
 *   session_info/session_start/round_start/thinking/content/tool_call/tool_result/round_end/
 *   note/error/final/done
 * 回调里不要长阻塞（会拖慢会话）；抛出的异常由实现方吞掉，不影响会话。
 * user 原样回传，可用于传 Python 侧的对象指针。
 */
typedef void (*avc_ai_event_cb)(const char* event_json, void* user);

/* 与上面三个函数语义完全一致，只是额外把过程中的增量通过 cb 实时抛出来 */
AVC_API char* avc_ai_ask_stream(const char* config_json, const char* question,
                                avc_ai_event_cb cb, void* user);
AVC_API char* avc_ai_run_batch_stream(const char* config_json, int minutes,
                                      avc_ai_event_cb cb, void* user);
AVC_API char* avc_ai_analyze_detection_stream(const char* config_json, const char* detection_json,
                                              avc_ai_event_cb cb, void* user);

/* 后台定时批次线程（每 interval 秒一次）；成功返回 0 */
AVC_API int avc_ai_start_background(const char* config_json);
AVC_API void avc_ai_stop_background(void);
AVC_API int avc_ai_background_running(void);

/* 取最多 max_items 条后台批次结果（JSON 数组） */
AVC_API char* avc_ai_poll(int max_items);

/* 释放本库返回的字符串 */
AVC_API void avc_free(char* p);

#ifdef __cplusplus
}
#endif

#endif /* AVENGINE_CORE_H */
