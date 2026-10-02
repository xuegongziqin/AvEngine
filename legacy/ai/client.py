"""
ai/client.py - OpenAI 兼容 HTTP 客户端

- POST {base_url}/chat/completions（Function Calling: tools/tool_calls）
- 纯文本兜底语法解析: 独占行 `CALL toolname key=value ...` 或 `CALL toolname {json}`
- 使用标准库 urllib，无额外 HTTP 依赖
"""

from __future__ import annotations

import json
import logging
import re
import socket
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .config import AIConfig

logger = logging.getLogger(__name__)


class AIError(Exception):
    """AI 请求失败（网络、HTTP 状态、响应格式）。"""


@dataclass
class ToolCall:
    """一次工具调用（来自 function calling 或文本语法）。"""

    id: str
    name: str
    arguments: Dict = field(default_factory=dict)


@dataclass
class AIReply:
    """AI 的一次回复。"""

    content: str = ""
    tool_calls: List[ToolCall] = field(default_factory=list)


_CALL_LINE = re.compile(r"^\s*CALL\s+([A-Za-z_][A-Za-z0-9_]*)\s*(.*)$")


def _parse_call_args(rest: str, call_id: str) -> Dict:
    """
    解析 CALL 行的参数部分。

    支持两种形式:
      key=value key2="value with spaces"   (shlex 处理引号，Windows 反斜杠保留)
      {"key": "value"}                      (JSON)
    """
    rest = rest.strip()
    if not rest:
        return {}
    if rest.startswith("{"):
        try:
            data = json.loads(rest)
            if isinstance(data, dict):
                return data
        except json.JSONDecodeError:
            return {"_raw": rest}
    try:
        import shlex

        tokens = shlex.split(rest, posix=False)
    except ValueError:
        tokens = rest.split()
    args: Dict = {}
    for token in tokens:
        if "=" not in token:
            continue
        key, _, value = token.partition("=")
        key = key.strip().strip('"')
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] == '"':
            value = value[1:-1]
        if key:
            args[key] = value
    return args


def parse_text_calls(text: str) -> Tuple[List[ToolCall], str]:
    """
    从纯文本回复中提取兜底语法的 CALL 行。

    Returns:
        (工具调用列表, 移除 CALL 行后的文本)。
    """
    calls: List[ToolCall] = []
    kept: List[str] = []
    seq = 0
    for line in (text or "").splitlines():
        m = _CALL_LINE.match(line)
        if m:
            seq += 1
            name = m.group(1)
            args = _parse_call_args(m.group(2), f"text_{seq}")
            calls.append(ToolCall(id=f"text_{seq}", name=name, arguments=args))
        else:
            kept.append(line)
    return calls, "\n".join(kept).strip()


_END_LINE = re.compile(r"^(?:.*\s)?END$", re.IGNORECASE)
_END_TAIL = re.compile(r"^(.*?)\s*END$", re.IGNORECASE)


def split_end_tag(text: str) -> Tuple[str, bool]:
    """
    检查回复是否以结束标记 END 结尾。

    最后一行形如 `END` 或 `结论文字 END` 均视为标记（该行 20 字符以内）；
    标记行中 END 之前的文字保留为正文的一部分。

    Returns:
        (去掉 END 标记的正文, 是否包含 END)。
    """
    if not text:
        return "", False
    lines = text.rstrip().splitlines()
    while lines and not lines[-1].strip():
        lines.pop()
    if not lines:
        return text.rstrip(), False
    last = lines[-1].strip()
    if _END_LINE.match(last) and len(last) <= 20:
        match = _END_TAIL.match(last)
        prefix = match.group(1).strip() if match else ""
        body_lines = lines[:-1] + ([prefix] if prefix else [])
        return "\n".join(body_lines).rstrip(), True
    return text.rstrip(), False


class AIClient:
    """OpenAI 兼容的 chat/completions 客户端。"""

    def __init__(self, config: AIConfig):
        self.config = config
        self.base_url = config.base_url.rstrip("/")

    def _endpoint(self) -> str:
        if self.base_url.endswith("/chat/completions"):
            return self.base_url
        return self.base_url + "/chat/completions"

    def _headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        return headers

    def chat(self, messages: List[Dict], tools_schema: Optional[List[Dict]] = None) -> AIReply:
        """
        发送一轮对话。

        Args:
            messages: OpenAI 格式的消息列表。
            tools_schema: OpenAI tools 数组；None 表示不携带工具（纯文本）。

        Returns:
            AIReply（文本和/或工具调用）。

        Raises:
            AIError: 网络或响应错误。
        """
        if not self.config.configured:
            raise AIError("AI 未配置：请在 config.ini 中填写 base_url 与 model")

        payload: Dict = {
            "model": self.config.model,
            "messages": messages,
            "temperature": 0.2,
            "stream": False,
        }
        if tools_schema:
            payload["tools"] = tools_schema
            payload["tool_choice"] = "auto"

        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        request = urllib.request.Request(
            self._endpoint(), data=data, headers=self._headers(), method="POST"
        )

        try:
            with urllib.request.urlopen(request, timeout=self.config.timeout) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as e:
            body = ""
            try:
                body = e.read().decode("utf-8", errors="replace")
            except Exception:
                pass
            msg = ""
            try:
                msg = json.loads(body).get("error", {}).get("message", "")
            except (json.JSONDecodeError, AttributeError):
                msg = body[:300]
            raise AIError(f"HTTP {e.code}: {msg or e.reason}") from e
        except urllib.error.URLError as e:
            raise AIError(f"网络错误: {e.reason}") from e
        except socket.timeout as e:
            raise AIError(f"请求超时（>{self.config.timeout}s）") from e
        except OSError as e:
            raise AIError(f"连接失败: {e}") from e

        try:
            data = json.loads(raw.decode("utf-8", errors="replace"))
            message = data["choices"][0]["message"]
        except (json.JSONDecodeError, KeyError, IndexError, TypeError) as e:
            raise AIError(f"响应格式异常: {raw[:200]!r}") from e

        reply = AIReply(content=message.get("content") or "")
        for item in message.get("tool_calls") or []:
            func = item.get("function") or {}
            raw_args = func.get("arguments") or "{}"
            try:
                args = json.loads(raw_args) if isinstance(raw_args, str) else dict(raw_args)
                if not isinstance(args, dict):
                    args = {"_raw": args}
            except json.JSONDecodeError:
                args = {"_raw": str(raw_args)}
            reply.tool_calls.append(
                ToolCall(id=item.get("id") or "call_0", name=func.get("name") or "", arguments=args)
            )
        return reply

    def test_connection(self) -> Tuple[bool, str]:
        """
        轻量连通性测试（GET {base_url}/models）。

        Returns:
            (是否连通, 描述文本)。
        """
        if not self.config.configured:
            return False, "未配置（config.ini 缺少 base_url/model）"
        url = self.base_url
        if not url.endswith("/models"):
            url = url + "/models"
        request = urllib.request.Request(url, headers=self._headers(), method="GET")
        try:
            with urllib.request.urlopen(request, timeout=5) as resp:
                if resp.status == 200:
                    return True, "连通"
                return False, f"HTTP {resp.status}"
        except urllib.error.HTTPError as e:
            # 401/403 说明网络可达但密钥无效；404 说明端点不提供 /models 但可能可用
            if e.code in (401, 403):
                return False, f"HTTP {e.code}（密钥无效）"
            if e.code == 404:
                return True, "端点可达（无 /models 接口）"
            return False, f"HTTP {e.code}"
        except (urllib.error.URLError, socket.timeout, OSError) as e:
            reason = getattr(e, "reason", e)
            return False, f"不可达（{reason}）"
