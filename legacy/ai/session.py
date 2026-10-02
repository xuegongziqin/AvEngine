"""
ai/session.py - 一次 AI 会话的多轮工具调用循环

流程: system + 用户消息 -> chat() -> 有工具调用则执行并回传 -> 继续
     -> 直到 AI 输出 END / 给出无工具的最终回复 / 轮数上限 / 请求出错。

- Function Calling 调用用 assistant(tool_calls) + tool 消息回传
- 文本兜底 CALL 行用 assistant(content) + user(TOOL ...) 消息回传
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Dict, List, Optional

from .client import AIClient, AIError, parse_text_calls, split_end_tag
from .config import AIConfig
from .prompts import build_system_message
from .tools import ToolContext, execute, schemas_for_api

logger = logging.getLogger(__name__)

# on_event(kind, payload) 回调类型；kind: assistant/tool_call/tool_result/done
EventCallback = Callable[[str, Dict], None]


@dataclass
class SessionResult:
    """一次会话的最终结果。"""

    ended_by: str = "error"  # end_tag | final_text | max_rounds | error
    final_text: str = ""
    rounds: int = 0
    tool_calls: int = 0
    error: str = ""
    started_at: str = ""
    finished_at: str = ""

    @property
    def ok(self) -> bool:
        return self.ended_by in ("end_tag", "final_text")


class AISession:
    """管理一次多轮 AI 会话。"""

    def __init__(
        self,
        config: AIConfig,
        tool_ctx: ToolContext,
        client: Optional[AIClient] = None,
        on_event: Optional[EventCallback] = None,
    ):
        self.config = config
        self.tool_ctx = tool_ctx
        self.client = client or AIClient(config)
        self.on_event = on_event
        self._call_counts: Dict[str, int] = {}

    # ---- 内部助手 ----

    def _emit(self, kind: str, payload: Dict) -> None:
        if self.on_event:
            try:
                self.on_event(kind, payload)
            except Exception:
                logger.debug("on_event 回调异常", exc_info=True)

    def _run_tool(self, name: str, arguments: Dict, seq: int) -> str:
        """执行一次工具调用，带重复失败护栏。"""
        sig = name + "|" + json.dumps(arguments, sort_keys=True, ensure_ascii=False, default=str)
        self._call_counts[sig] = self._call_counts.get(sig, 0) + 1
        if self._call_counts[sig] > 3:
            return (
                "ERROR: 同一调用已重复 3 次均失败，请勿重试；"
                "请调整参数、换用其他工具，或直接给出结论。"
            )
        self._emit("tool_call", {"seq": seq, "name": name, "arguments": arguments})
        result = execute(name, arguments, self.tool_ctx)
        self._emit("tool_result", {"seq": seq, "name": name, "result": result})
        return result

    # ---- 主循环 ----

    def run(self, user_message: str, extra_messages: Optional[List[Dict]] = None) -> SessionResult:
        """
        运行一个会话。

        Args:
            user_message: 首条用户消息（批次文本 / 问题 / 检出信息）。
            extra_messages: 插在 system 与 user_message 之间的补充消息（可选）。

        Returns:
            SessionResult。
        """
        result = SessionResult(started_at=datetime.now().isoformat(timespec="seconds"))
        messages: List[Dict] = [build_system_message()]
        if extra_messages:
            messages.extend(extra_messages)
        messages.append({"role": "user", "content": user_message})

        tools_schema = schemas_for_api()
        max_rounds = max(1, self.config.max_rounds)
        seq = 0

        for round_no in range(1, max_rounds + 1):
            result.rounds = round_no
            try:
                reply = self.client.chat(messages, tools_schema=tools_schema)
            except AIError as e:
                result.ended_by = "error"
                result.error = str(e)
                logger.warning("AI 第 %d 轮请求失败: %s", round_no, e)
                break

            content = reply.content or ""
            text_calls, stripped = parse_text_calls(content)
            fc_calls = list(reply.tool_calls)
            all_calls = [(c.id, c.name, c.arguments, "fc") for c in fc_calls]
            all_calls += [(c.id, c.name, c.arguments, "text") for c in text_calls]

            # 1) 无任何工具调用 -> 结束判定
            if not all_calls:
                body, has_end = split_end_tag(content)
                if has_end:
                    result.ended_by = "end_tag"
                    result.final_text = body
                elif content.strip():
                    result.ended_by = "final_text"
                    result.final_text = content.strip()
                else:
                    # 空回复：提示一次，若继续为空则按 max_rounds 兜底
                    messages.append({"role": "assistant", "content": content})
                    messages.append(
                        {"role": "user", "content": "（无内容）请给出最终中文结论，最后一行单独写 END。"}
                    )
                    continue
                break

            # 2) 有工具调用：先落 assistant 消息
            if fc_calls:
                assistant_msg: Dict = {"role": "assistant", "content": content or None}
                assistant_msg["tool_calls"] = [
                    {
                        "id": c.id,
                        "type": "function",
                        "function": {
                            "name": c.name,
                            "arguments": json.dumps(c.arguments, ensure_ascii=False),
                        },
                    }
                    for c in fc_calls
                ]
                messages.append(assistant_msg)
            elif stripped or content:
                messages.append(
                    {"role": "assistant", "content": stripped or "（发起工具调用）"}
                )

            # 3) 执行并回传结果
            for call_id, name, arguments, origin in all_calls:
                seq += 1
                result.tool_calls += 1
                tool_output = self._run_tool(name, arguments, seq)
                if origin == "fc":
                    messages.append(
                        {"role": "tool", "tool_call_id": call_id, "name": name, "content": tool_output}
                    )
                else:
                    messages.append(
                        {
                            "role": "user",
                            "content": f"TOOL {name} 结果:\n{tool_output}\n\n（继续分析；"
                                       f"证据充分则给出结论并以 END 结束，否则继续调用工具）",
                        }
                    )

            # 4) 文本兜底与 FC 结果交替回传后进入下一轮
            time.sleep(0.1)  # 轻微限速，避免压垮本地模型
        else:
            result.ended_by = "max_rounds"
            result.final_text = (
                f"（已达到最大轮数 {max_rounds}，会话被截断。"
                f"以上为第 {max_rounds} 轮的中间过程。）"
            )

        result.finished_at = datetime.now().isoformat(timespec="seconds")
        self._emit(
            "done",
            {
                "ended_by": result.ended_by,
                "rounds": result.rounds,
                "tool_calls": result.tool_calls,
                "error": result.error,
            },
        )
        if result.ended_by == "error" and not result.final_text:
            result.final_text = f"（AI 请求失败: {result.error}）"
        return result
