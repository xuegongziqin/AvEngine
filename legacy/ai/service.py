"""
ai/service.py - AI 服务层

- run_batch(): 采集一个时间窗口的事件 -> 多轮会话分析 -> 落盘状态
- ask(): 自由问答
- analyze_detection(): 扫描检出联动
- start_background(): 每 config.interval 秒在后台线程跑一次批次
- 状态写入 logs/ai_state.json（供 status 展示）
"""

from __future__ import annotations

import json
import logging
import threading
from datetime import datetime
from typing import Callable, Dict, Optional

from ..config import load_config
from ..paths import AI_STATE_FILE
from .client import AIClient
from .collectors import ensure_channels, query_batch, supported as events_supported
from .config import AIConfig, load_ai_config
from .prompts import (
    build_ask_context,
    build_batch_message,
    build_detection_message,
)
from .session import AISession, SessionResult
from .tools import ToolContext

logger = logging.getLogger(__name__)

EventCallback = Callable[[str, Dict], None]


class AIService:
    """AI 分析服务（每次调用创建独立会话）。"""

    def __init__(
        self,
        config: Optional[AIConfig] = None,
        engine_config: Optional[Dict] = None,
        on_event: Optional[EventCallback] = None,
    ):
        self.config = config or load_ai_config()
        self.engine_config = engine_config if engine_config is not None else load_config()
        self.on_event = on_event
        self.client = AIClient(self.config)
        self._tool_ctx = ToolContext(engine_config=self.engine_config, ai_config=self.config)
        self._state_lock = threading.Lock()
        self._bg_thread: Optional[threading.Thread] = None
        self._bg_stop = threading.Event()
        self._bg_running = False

    # -------------------- 可用性 --------------------

    @property
    def available(self) -> bool:
        return self.config.active

    def availability_hint(self) -> str:
        if not self.config.exists:
            return "未配置（缺少 config.ini，参考 config.ini.example）"
        if not self.config.enabled:
            return "已禁用（config.ini [ai] enabled=false）"
        if not self.config.configured:
            return "配置不完整（config.ini 缺少 base_url 或 model）"
        return "已启用"

    def test(self):
        """连通性测试，返回 (ok, text)。"""
        return self.client.test_connection()

    # -------------------- 会话执行 --------------------

    def _session(self) -> AISession:
        return AISession(self.config, self._tool_ctx, client=self.client, on_event=self.on_event)

    def _write_state(self, kind: str, result: SessionResult, extra: Optional[Dict] = None) -> None:
        state: Dict = {}
        with self._state_lock:
            try:
                if AI_STATE_FILE.is_file():
                    state = json.loads(AI_STATE_FILE.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                state = {}
            runs = state.get("runs") or []
            entry = {
                "kind": kind,
                "time": datetime.now().isoformat(timespec="seconds"),
                "ended_by": result.ended_by,
                "rounds": result.rounds,
                "tool_calls": result.tool_calls,
                "error": result.error,
            }
            if extra:
                entry.update(extra)
            runs.append(entry)
            state["runs"] = runs[-20:]
            state["last"] = entry
            state["last_final_text"] = (result.final_text or "")[:4000]
            state["total_runs"] = int(state.get("total_runs") or 0) + 1
            try:
                AI_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
                AI_STATE_FILE.write_text(
                    json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8"
                )
            except OSError as e:
                logger.warning("写入 AI 状态失败: %s", e)

    # -------------------- 公开 API --------------------

    def run_batch(self, minutes: Optional[int] = None) -> SessionResult:
        """采集窗口事件并进行一次多轮分析会话。"""
        if not self.available:
            result = SessionResult(ended_by="error", error=self.availability_hint())
            result.final_text = f"（AI 未启用: {result.error}）"
            return result

        minutes = minutes or max(1, self.config.interval // 60)
        stats: Dict[str, int] = {}
        errors = []
        batch_text = "（事件采集不可用：需要 Windows + pywin32）"
        if events_supported():
            failed = ensure_channels(self.config)
            if failed:
                errors.append("通道未启用: " + ", ".join(failed[:4]))
            batch_text, stats, truncated, errors = query_batch(self.config, minutes)
        else:
            truncated = 0

        message = build_batch_message(
            self.config, batch_text, stats, truncated=truncated, errors=errors, minutes=minutes
        )
        logger.info(
            "AI 批次开始: 窗口=%dmin 事件数=%s 截断=%s", minutes, stats, truncated
        )
        result = self._session().run(message)
        self._write_state(
            "batch",
            result,
            {"minutes": minutes, "events": stats, "truncated": truncated},
        )
        return result

    def ask(self, question: str) -> SessionResult:
        """自由问答（带引擎状态上下文）。"""
        if not self.available:
            result = SessionResult(ended_by="error", error=self.availability_hint())
            result.final_text = f"（AI 未启用: {result.error}）"
            return result

        engine_status = None
        if events_supported():
            engine_status = "Sysmon/事件采集可用"
        message = build_ask_context(engine_status) + "\n\n用户问题: " + question
        result = self._session().run(message)
        self._write_state("ask", result, {"question": question[:200]})
        return result

    def analyze_detection(self, detection: Dict) -> SessionResult:
        """扫描检出联动分析（config [ai] scan_analysis=false 时跳过）。"""
        if not self.config.scan_analysis:
            return SessionResult(ended_by="error", error="scan_analysis 已禁用")
        if not self.available:
            result = SessionResult(ended_by="error", error=self.availability_hint())
            result.final_text = f"（AI 未启用: {result.error}）"
            return result

        message = build_detection_message(detection)
        result = self._session().run(message)
        self._write_state("detection", result, {"path": str(detection.get("path", ""))[:300]})
        return result

    def maybe_analyze_detection(self, detection: Dict) -> Optional[SessionResult]:
        """按配置决定是否联动（供 scan 流程静默调用）。"""
        try:
            if not (self.config.active and self.config.scan_analysis):
                return None
            return self.analyze_detection(detection)
        except Exception:
            logger.exception("检出联动分析失败")
            return None

    # -------------------- 后台定时 --------------------

    def start_background(self) -> bool:
        """
        启动后台批次线程（每 config.interval 秒一次）。

        Returns:
            是否成功启动（已启动/未配置时返回 False）。
        """
        if not self.available:
            logger.info("AI 后台分析未启动: %s", self.availability_hint())
            return False
        if self._bg_thread and self._bg_thread.is_alive():
            return False

        self._bg_stop.clear()
        self._bg_running = True

        def _loop() -> None:
            logger.info(
                "AI 后台分析已启动: 每 %d 秒一批, 模型=%s", self.config.interval, self.config.model
            )
            while not self._bg_stop.is_set():
                if not self._bg_running:
                    break
                try:
                    self.run_batch()
                except Exception:
                    logger.exception("AI 后台批次异常")
                if self._bg_stop.wait(self.config.interval):
                    break
            logger.info("AI 后台分析已停止")

        self._bg_thread = threading.Thread(target=_loop, name="ai-batch", daemon=True)
        self._bg_thread.start()
        return True

    def stop_background(self) -> None:
        """停止后台批次线程。"""
        self._bg_running = False
        self._bg_stop.set()
        thread = self._bg_thread
        if thread and thread.is_alive() and thread is not threading.current_thread():
            thread.join(timeout=5)

    @property
    def background_alive(self) -> bool:
        return bool(self._bg_thread and self._bg_thread.is_alive() and self._bg_running)


def read_state() -> Dict:
    """读取 logs/ai_state.json（不存在返回空字典）。"""
    try:
        if AI_STATE_FILE.is_file():
            data = json.loads(AI_STATE_FILE.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return data
    except (OSError, json.JSONDecodeError):
        pass
    return {}


def state_summary() -> str:
    """给 status 用的一行摘要。"""
    data = read_state()
    last = data.get("last")
    if not last:
        return "尚无分析记录"
    text = (
        f"上次 {last.get('kind')} @ {last.get('time')} -> {last.get('ended_by')} "
        f"({last.get('rounds')}轮/{last.get('tool_calls')}次工具)"
    )
    if last.get("error"):
        text += f" 错误: {last['error']}"
    return text
