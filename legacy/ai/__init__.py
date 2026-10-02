"""
avengine.ai - AI 分析子包

- config: config.ini 配置加载
- client: OpenAI 兼容 HTTP 客户端（Function Calling + CALL 文本兜底）
- collectors: ETW/WinEvent 按需采集（批次 + 工具查询）
- prompts: 系统提示与消息构建
- tools: 七类工具库（进程/文件/网络/系统/事件/处置/情报）
- session: 多轮工具调用会话
- service: 服务层（批次/问答/检出联动/后台定时）

快速使用:
    from avengine.ai import AIService
    svc = AIService()
    result = svc.run_batch(minutes=5)
    print(result.final_text)
"""

from __future__ import annotations

from .client import AIClient, AIError
from .config import AIConfig, load_ai_config
from .service import AIService, read_state, state_summary
from .session import AISession, SessionResult

__all__ = [
    "AIClient",
    "AIError",
    "AIConfig",
    "load_ai_config",
    "AIService",
    "AISession",
    "SessionResult",
    "read_state",
    "state_summary",
]
