"""
ai/prompts.py - 提示词构建

- SYSTEM_PROMPT: 会话常驻系统提示（角色 / 工具使用 / CALL 兜底 / END 协议）
- build_batch_message: 每 5 分钟批次的用户消息
- build_ask_context: 自由问答的上下文
- build_detection_message: 扫描检出联动消息
"""

from __future__ import annotations

from datetime import datetime
from typing import Dict, List, Optional

from .config import AIConfig

SYSTEM_PROMPT = """\
你是 AvEngine AI 安全分析助手，嵌入在一台 Windows 主机的本地杀毒引擎中。
你会收到按时间窗口（默认每 5 分钟）汇总的系统事件，也可能收到扫描检出结果或用户的自由提问。

## 你的职责
1. 判定事件批次中是否存在异常/恶意行为（可疑进程、外联、权限提升、混淆脚本、持久化、勒索行为等）。
2. 需要更多证据时，调用工具获取（进程详情、内存转储、文件哈希、PE 结构、网络连接、注册表、计划任务、事件历史检索等）。
3. 得出结论后，给出简短中文分析与建议；确认恶意且需要处置时，调用 quarantine_file / kill_process 等处置工具。
4. 分析必须基于证据：引用具体事件行（时间/进程/PID/路径/IP），不要臆测。

## 工具调用方式
- 优先使用 function calling（tools）发起调用。
- 若模型不支持 function calling，使用文本兜底语法：单独一行
  CALL 工具名 参数名=值 参数名2="带空格的值"
  或 CALL 工具名 {"参数名": "值"}
  一条消息可发多行 CALL；工具结果会以 TOOL 角色消息回传，然后你继续分析。
- 工具结果中的 ERROR: 开头表示失败，读取提示后调整参数或改用其他工具，不要重复同样调用超过 2 次。

## 事件源说明
- 批次默认包含: sysmon/process/network/dns/powershell/system/application。
- fileio（文件读写）事件量大不进批次：需要文件访问证据时用 grep_events(source="fileio", keyword="...") 按需检索。
- query_events 可查询任一源最近若干小时；get_event_xml 按 rid 取原始 XML。

## 结束协议（重要）
- 多轮工具调查结束后，输出最终中文结论。
- 结论的最后一行必须单独写 END 表示本轮会话结束。
- 若你认为还需要更多证据，就不要写 END，继续调用工具。
- 单条消息中不要同时给出最终结论和工具调用；要么调用工具，要么给结论+END。
"""


def build_system_message() -> Dict:
    return {"role": "system", "content": SYSTEM_PROMPT}


def build_status_block() -> str:
    """引擎状态摘要（拼进批次消息头部）。"""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return f"当前时间: {now}"


def build_batch_message(
    config: AIConfig,
    batch_text: str,
    stats: Dict[str, int],
    truncated: int = 0,
    errors: Optional[List[str]] = None,
    minutes: Optional[int] = None,
) -> str:
    """构造批次分析的用户消息。"""
    minutes = minutes or max(60, config.interval)
    stat_line = ", ".join(f"{k}={v}" for k, v in stats.items()) or "无"
    lines = [
        f"== 批次开始（窗口 {minutes} 分钟，{build_status_block()}）==",
        f"各源事件数: {stat_line}",
    ]
    if truncated:
        lines.append(f"注意: 有 {truncated} 条事件因上限被截断，需要时可用 query_events 补查。")
    if errors:
        lines.append("采集警告:")
        lines.extend(f"- {e}" for e in errors[:5])
    lines.append("")
    lines.append("-- 事件 --")
    lines.append(batch_text)
    lines.append("-- 事件结束 --")
    lines.append("")
    lines.append(
        "请分析以上事件：有异常则调查（调用工具取证），确认恶意可执行处置；"
        "最后给出中文结论，结论最后一行单独写 END。若无需处理也请给出简要结论并以 END 结束。"
    )
    return "\n".join(lines)


def build_ask_context(engine_status: Optional[str] = None) -> str:
    """自由问答的上下文前缀。"""
    lines = [build_status_block()]
    if engine_status:
        lines.append("引擎状态: " + engine_status)
    lines.append("")
    lines.append("请回答用户问题；如需查证可调用工具，结论最后一行单独写 END。")
    return "\n".join(lines)


def build_detection_message(detection: Dict) -> str:
    """
    扫描检出联动消息。

    detection: {"path", "engine"("yara"/"clamav"/both), "match", "size", "sha256"(可选), "action"}
    """
    lines = ["== 扫描检出联动 =="]
    lines.append(f"时间: {datetime.now().isoformat(timespec='seconds')}")
    for key in ("path", "engine", "match", "sha256", "size", "action"):
        if detection.get(key) is not None:
            lines.append(f"{key}: {detection[key]}")
    lines.append("")
    lines.append(
        "引擎已检出威胁。请判断：1) 是否需要更多取证（如 get_pe_info / scan_file / "
        "list_process_modules 查找运行中的关联进程）；2) 若文件尚未隔离且判定恶意，"
        "可调用 quarantine_file 处置。最后给出中文结论并以 END 结束。"
    )
    return "\n".join(lines)
